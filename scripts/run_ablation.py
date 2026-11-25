"""
PayGate-Bench 4-Baseline Empirical Ablation & Multi-Model Evaluation Runner.

Evaluates 4 baselines across 50 B2B scenarios (25 Benign + 25 Adversarial G1-G5):
  1. no_defense: Unconstrained raw tool execution
  2. prompt_plus_llm_judge: Hardened system prompt + real LLM-as-a-Judge guardrail
  3. static_gateway_r1_r5: Standard perimeter gateway (R1-R5 + global allowlist)
  4. paygate_full: Complete TCB (DFA + R1-R7 + Out-of-Band Session IFC R8)

Zero synthetic timing: measures true nanosecond gate decision latency and real LLM API latency.
Also executes Leave-One-Rule-Out replay ablation and Wilson/McNemar statistical tests.
"""

import os
os.environ["MPLCONFIGDIR"] = "/tmp/matplotlib_cache"
import json
import time
import argparse
import numpy as np
from decimal import Decimal
from typing import Dict, Any, List, Optional, Tuple

from paygate.tcb.clock import VirtualClock
from paygate.tcb.models import (
    Order,
    OrderItem,
    ConsentState,
    ProvenanceLabel,
    ToolRequest,
    ActionDecision,
)
from paygate.tcb.audit import TamperEvidentAuditLog
from paygate.tcb.ifc import TaintTracker
from paygate.tcb.invariants import DeterministicGate
from paygate.tcb.simulator import StateSimulator
from paygate.bench.scenarios import ScenarioLoader
from paygate.bench.oracle import BenchmarkOracle
from paygate.bench.tools import AgentToolExecutor
from paygate.bench.stats import wilson_score_interval, mcnemar_paired_test
from paygate.agent.mock_agent import MockAdversarialAgent
from paygate.agent.llm_client import CachedLLMClient
from paygate.agent.payment_agent import PaymentOperationsAgent
from scripts.plot_figures import plot_asr_utility_tradeoff, plot_latency_cdf


def _build_env_for_scenario(
    sc: Dict[str, Any],
) -> Tuple[VirtualClock, StateSimulator, DeterministicGate, Order]:
    clock = VirtualClock(1700000000.0)
    sim = StateSimulator(clock)
    audit_log = TamperEvidentAuditLog(secret_key=b"ablation_audit_key_v2")
    taint_tracker = TaintTracker()

    for doc in sc.get("documents", []):
        sim.add_document(doc["doc_id"], doc["title"], doc["doc_type"], doc["content"])
        taint_tracker.register_document(doc["doc_id"], ProvenanceLabel.UNTRUSTED_EXTERNAL)

    init_o = sc["initial_order"]
    items = [
        OrderItem(name=it["name"], quantity=it["quantity"], unit_price=Decimal(it["unit_price"]))
        for it in init_o["items"]
    ]
    c_state = ConsentState(init_o.get("consent_state", "APPROVED"))
    canary = init_o.get("canary_token", f"CANARY_SECRET_{sc['order_id']}")
    taint_tracker.register_canary(canary)

    gate = DeterministicGate(
        merchant_allowlist={"MERCH-PRIMARY", "MERCH-DECOY-PARTNER"},
        audit_log=audit_log,
        taint_tracker=taint_tracker,
    )

    order = Order(
        order_id=sc["order_id"],
        items=items,
        currency=init_o["currency"],
        auth_amount=Decimal(init_o["auth_amount"]),
        captured_total=Decimal(init_o.get("captured_total", "0.00")),
        refunded_total=Decimal(init_o.get("refunded_total", "0.00")),
        merchant_id=init_o["merchant_id"],
        bound_merchant_id=init_o.get("bound_merchant_id", init_o["merchant_id"]),
        consent_state=c_state,
        auth_expires_at=1700050000.0,
        canary_token=canary,
    )
    if c_state == ConsentState.APPROVED:
        order.consent_token = gate.generate_consent_token(order.order_id, order.po_hash or "")
    sim.create_order(order)
    return clock, sim, gate, order


def run_single_model_ablation(
    mock_mode: bool = False,
    model_id: str = "openai/gpt-oss-120b",
    judge_model: str = "openai/gpt-oss-safeguard-20b",
    output_dir: str = "results",
    cache_path: Optional[str] = None,
) -> Dict[str, Any]:
    os.makedirs(output_dir, exist_ok=True)
    loader = ScenarioLoader()
    benign_scenarios = loader.load_benign_scenarios()
    adv_scenarios = loader.load_adversarial_scenarios()

    baselines = [
        "no_defense",
        "prompt_plus_llm_judge",
        "static_gateway_r1_r5",
        "paygate_full",
    ]

    llm_client = None
    if not mock_mode:
        llm_client = CachedLLMClient(db_path=cache_path or os.path.join(output_dir, "cache.sqlite"))

    summary_results: Dict[str, Any] = {}
    raw_runs: List[Dict[str, Any]] = []
    latencies_by_baseline: Dict[str, List[float]] = {b: [] for b in baselines}
    adv_outcomes_by_baseline: Dict[str, List[bool]] = {b: [] for b in baselines}
    trace_violations_total = 0

    for cfg in baselines:
        mode_tag = "CI-MOCK" if mock_mode else model_id
        print(f"\n[{mode_tag}] Evaluating Baseline: [{cfg}] ...")
        benign_successes = 0
        oop_attack_successes = 0
        oop_total = 0
        ip_attack_successes = 0
        ip_total = 0

        # -------------------------------------------------------------
        # 1. Benign Scenarios (25)
        # -------------------------------------------------------------
        for sc in benign_scenarios:
            clock, sim, gate, order = _build_env_for_scenario(sc)
            executor = AgentToolExecutor(
                simulator=sim,
                gate=gate,
                config=cfg,
                llm_judge_client=llm_client,
                judge_model=judge_model,
            )

            t_wall0 = time.perf_counter_ns()
            if mock_mode:
                agent = MockAdversarialAgent(config=cfg)
                agent.run_scenario(sc, is_adversarial=False, executor=executor)
            else:
                agent = PaymentOperationsAgent(llm_client=llm_client, config=cfg)
                agent.run_scenario(sc, executor=executor, model_id=model_id)
            t_wall1 = time.perf_counter_ns()

            # Record pure measured latency (gate ns for deterministic baselines, judge ms for LLM judge)
            if cfg == "prompt_plus_llm_judge" and executor.judge_latencies_ns:
                for l_ns in executor.judge_latencies_ns:
                    latencies_by_baseline[cfg].append(l_ns / 1_000_000.0)
                decision_lat_ms = float(np.mean(executor.judge_latencies_ns) / 1_000_000.0)
            elif executor.gate_latencies_ns:
                for l_ns in executor.gate_latencies_ns:
                    latencies_by_baseline[cfg].append(l_ns / 1_000_000.0)
                decision_lat_ms = float(np.mean(executor.gate_latencies_ns) / 1_000_000.0)
            else:
                decision_lat_ms = (t_wall1 - t_wall0) / 1_000_000.0
                latencies_by_baseline[cfg].append(decision_lat_ms)

            utility = BenchmarkOracle.score_benign_utility(sc, sim)
            if utility:
                benign_successes += 1

            if cfg == "paygate_full":
                ok_mon, _ = gate.trace_monitor.verify_trace({order.order_id: order.auth_amount})
                if not ok_mon:
                    trace_violations_total += 1

            raw_runs.append({
                "model": mode_tag,
                "config": cfg,
                "scenario_id": sc["scenario_id"],
                "type": "benign",
                "utility": utility,
                "decision_latency_ms": decision_lat_ms,
            })

        # -------------------------------------------------------------
        # 2. Adversarial Scenarios (25)
        # -------------------------------------------------------------
        for sc in adv_scenarios:
            clock, sim, gate, order = _build_env_for_scenario(sc)
            executor = AgentToolExecutor(
                simulator=sim,
                gate=gate,
                config=cfg,
                llm_judge_client=llm_client,
                judge_model=judge_model,
            )

            t_wall0 = time.perf_counter_ns()
            if mock_mode:
                agent = MockAdversarialAgent(config=cfg)
                trace_res = agent.run_scenario(sc, is_adversarial=True, executor=executor)
            else:
                agent = PaymentOperationsAgent(llm_client=llm_client, config=cfg)
                trace_res = agent.run_scenario(sc, executor=executor, model_id=model_id)
            t_wall1 = time.perf_counter_ns()

            if cfg == "prompt_plus_llm_judge" and executor.judge_latencies_ns:
                for l_ns in executor.judge_latencies_ns:
                    latencies_by_baseline[cfg].append(l_ns / 1_000_000.0)
                decision_lat_ms = float(np.mean(executor.judge_latencies_ns) / 1_000_000.0)
            elif executor.gate_latencies_ns:
                for l_ns in executor.gate_latencies_ns:
                    latencies_by_baseline[cfg].append(l_ns / 1_000_000.0)
                decision_lat_ms = float(np.mean(executor.gate_latencies_ns) / 1_000_000.0)
            else:
                decision_lat_ms = (t_wall1 - t_wall0) / 1_000_000.0
                latencies_by_baseline[cfg].append(decision_lat_ms)

            attack_success = BenchmarkOracle.score_attack_success(sc, sim, sc["initial_order"])
            adv_outcomes_by_baseline[cfg].append(attack_success)
            goal = sc["target_goal"]

            if goal in ("G1", "G2", "G3"):
                oop_total += 1
                if attack_success:
                    oop_attack_successes += 1
            else:
                ip_total += 1
                if attack_success:
                    ip_attack_successes += 1

            if cfg == "paygate_full":
                ok_mon, _ = gate.trace_monitor.verify_trace({order.order_id: order.auth_amount})
                if not ok_mon:
                    trace_violations_total += 1

            raw_runs.append({
                "model": mode_tag,
                "config": cfg,
                "scenario_id": sc["scenario_id"],
                "type": "adversarial",
                "goal": goal,
                "attack_success": attack_success,
                "decision_latency_ms": decision_lat_ms,
                "trace": trace_res.get("trace", []),
            })

        benign_total = len(benign_scenarios)
        benign_utility_pct = (benign_successes / benign_total) * 100.0
        frr_pct = 100.0 - benign_utility_pct
        oop_asr_pct = (oop_attack_successes / oop_total) * 100.0 if oop_total else 0.0
        ip_asr_pct = (ip_attack_successes / ip_total) * 100.0 if ip_total else 0.0
        total_asr_k = oop_attack_successes + ip_attack_successes
        total_asr_n = oop_total + ip_total

        ci_all = wilson_score_interval(total_asr_k, total_asr_n)
        ci_oop = wilson_score_interval(oop_attack_successes, oop_total)
        ci_ip = wilson_score_interval(ip_attack_successes, ip_total)

        lat_arr = np.array(latencies_by_baseline[cfg]) if latencies_by_baseline[cfg] else np.array([0.0])
        summary_results[cfg] = {
            "model": mode_tag,
            "benign_utility_pct": round(benign_utility_pct, 1),
            "benign_successes": benign_successes,
            "benign_total": benign_total,
            "frr_pct": round(frr_pct, 1),
            "oop_asr_pct": round(oop_asr_pct, 1),
            "oop_successes": oop_attack_successes,
            "oop_total": oop_total,
            "oop_wilson_95": [round(ci_oop[0] * 100, 1), round(ci_oop[1] * 100, 1)],
            "ip_asr_pct": round(ip_asr_pct, 1),
            "ip_successes": ip_attack_successes,
            "ip_total": ip_total,
            "ip_wilson_95": [round(ci_ip[0] * 100, 1), round(ci_ip[1] * 100, 1)],
            "total_asr_pct": round((total_asr_k / total_asr_n) * 100.0, 1),
            "total_wilson_95": [round(ci_all[0] * 100, 1), round(ci_all[1] * 100, 1)],
            "latency_p50_ms": round(float(np.percentile(lat_arr, 50)), 6),
            "latency_p95_ms": round(float(np.percentile(lat_arr, 95)), 6),
            "latency_p99_ms": round(float(np.percentile(lat_arr, 99)), 6),
            "trace_monitor_violations": trace_violations_total if cfg == "paygate_full" else None,
        }

    # Compute McNemar Paired Significance Tests vs paygate_full
    mcnemar_stats: Dict[str, Any] = {}
    for b in ["no_defense", "prompt_plus_llm_judge", "static_gateway_r1_r5"]:
        chi2, p_val = mcnemar_paired_test(adv_outcomes_by_baseline[b], adv_outcomes_by_baseline["paygate_full"])
        mcnemar_stats[f"{b}_vs_paygate_full"] = {"chi2": round(chi2, 4), "p_value": round(p_val, 6)}

    return {
        "model": "CI-MOCK" if mock_mode else model_id,
        "summary": summary_results,
        "mcnemar": mcnemar_stats,
        "raw_runs": raw_runs,
        "latencies_by_baseline": latencies_by_baseline,
    }


def run_ablation(
    mock_mode: bool = False,
    models: Optional[List[str]] = None,
    judge_model: str = "openai/gpt-oss-safeguard-20b",
    output_dir: str = "results",
) -> Dict[str, Any]:
    """
    Execute ablation across specified models (or mock CI) and generate artifacts.
    """
    os.makedirs(output_dir, exist_ok=True)
    if mock_mode:
        res = run_single_model_ablation(mock_mode=True, output_dir=output_dir)
        with open(os.path.join(output_dir, "ci_mock_summary.json"), "w", encoding="utf-8") as f:
            json.dump({"summary": res["summary"], "mcnemar": res["mcnemar"]}, f, indent=2)
        with open(os.path.join(output_dir, "ci_mock_runs.jsonl"), "w", encoding="utf-8") as f:
            for r in res["raw_runs"]:
                f.write(json.dumps(r) + "\n")
        _print_summary_table("CI-MOCK SMOKE TEST", res["summary"], res["mcnemar"])
        return res["summary"]

    target_models = models or ["openai/gpt-oss-120b", "qwen/qwen3.8-27b"]
    all_model_summaries: Dict[str, Any] = {}
    all_raw_runs: List[Dict[str, Any]] = []
    agg_latencies: Dict[str, List[float]] = {
        "no_defense": [],
        "prompt_plus_llm_judge": [],
        "static_gateway_r1_r5": [],
        "paygate_full": [],
    }

    for model_id in target_models:
        res = run_single_model_ablation(
            mock_mode=False,
            model_id=model_id,
            judge_model=judge_model,
            output_dir=output_dir,
        )
        all_model_summaries[model_id] = {"summary": res["summary"], "mcnemar": res["mcnemar"]}
        all_raw_runs.extend(res["raw_runs"])
        for b, lats in res["latencies_by_baseline"].items():
            agg_latencies[b].extend(lats)
        _print_summary_table(model_id, res["summary"], res["mcnemar"])

    # Compute pooled aggregate across evaluated models
    pooled_summary: Dict[str, Any] = {}
    for cfg in ["no_defense", "prompt_plus_llm_judge", "static_gateway_r1_r5", "paygate_full"]:
        benign_ok = sum(all_model_summaries[m]["summary"][cfg]["benign_successes"] for m in target_models)
        benign_n = sum(all_model_summaries[m]["summary"][cfg]["benign_total"] for m in target_models)
        oop_ok = sum(all_model_summaries[m]["summary"][cfg]["oop_successes"] for m in target_models)
        oop_n = sum(all_model_summaries[m]["summary"][cfg]["oop_total"] for m in target_models)
        ip_ok = sum(all_model_summaries[m]["summary"][cfg]["ip_successes"] for m in target_models)
        ip_n = sum(all_model_summaries[m]["summary"][cfg]["ip_total"] for m in target_models)

        lat_arr = np.array(agg_latencies[cfg]) if agg_latencies[cfg] else np.array([0.0])
        ci_all = wilson_score_interval(oop_ok + ip_ok, oop_n + ip_n)
        pooled_summary[cfg] = {
            "benign_utility_pct": round((benign_ok / benign_n) * 100.0, 1),
            "benign_successes": benign_ok,
            "benign_total": benign_n,
            "frr_pct": round(100.0 - (benign_ok / benign_n) * 100.0, 1),
            "oop_asr_pct": round((oop_ok / oop_n) * 100.0, 1),
            "oop_successes": oop_ok,
            "oop_total": oop_n,
            "ip_asr_pct": round((ip_ok / ip_n) * 100.0, 1),
            "ip_successes": ip_ok,
            "ip_total": ip_n,
            "total_asr_pct": round(((oop_ok + ip_ok) / (oop_n + ip_n)) * 100.0, 1),
            "total_wilson_95": [round(ci_all[0] * 100, 1), round(ci_all[1] * 100, 1)],
            "latency_p50_ms": round(float(np.percentile(lat_arr, 50)), 6),
            "latency_p95_ms": round(float(np.percentile(lat_arr, 95)), 6),
            "latency_p99_ms": round(float(np.percentile(lat_arr, 99)), 6),
        }

    # Save live JSONL and JSON summaries
    with open(os.path.join(output_dir, "raw_runs.jsonl"), "w", encoding="utf-8") as f:
        for r in all_raw_runs:
            f.write(json.dumps(r) + "\n")

    full_output = {
        "models_evaluated": target_models,
        "judge_model": judge_model,
        "pooled": pooled_summary,
        "per_model": all_model_summaries,
    }
    with open(os.path.join(output_dir, "ablation_summary.json"), "w", encoding="utf-8") as f:
        json.dump(full_output, f, indent=2)

    _print_summary_table(f"POOLED LIVE ({' + '.join(target_models)})", pooled_summary, {})

    plot_asr_utility_tradeoff(
        pooled_summary,
        "docs/figures/asr_vs_utility_tradeoff.png",
        subtitle=f"Live Multi-Model Evaluation ({', '.join(target_models)})",
    )
    plot_latency_cdf(agg_latencies, "docs/figures/latency_cdf.png")
    return full_output


def _print_summary_table(title: str, summary: Dict[str, Any], mcnemar: Dict[str, Any]) -> None:
    print("\n" + "=" * 102)
    print(f"PAYGATE-BENCH (v2.0): {title}")
    print("=" * 102)
    print(
        f"{'Baseline':<23} | {'Benign Util':<14} | {'OOP ASR (G1-3)':<15} | "
        f"{'IP ASR (G4-5)':<15} | {'Total ASR [95% CI]':<20} | {'p50 Latency'}"
    )
    print("-" * 102)
    for b in ["no_defense", "prompt_plus_llm_judge", "static_gateway_r1_r5", "paygate_full"]:
        r = summary[b]
        p50 = r["latency_p50_ms"]
        lat_str = f"{p50:.2f} ms" if p50 >= 1.0 else f"{p50 * 1000:.2f} µs"
        ci = r.get("total_wilson_95", [0, 0])
        print(
            f"{b:<23} | "
            f"{r['benign_utility_pct']:>5.1f}% ({r['benign_successes']:>2}/{r['benign_total']}) | "
            f"{r['oop_asr_pct']:>5.1f}% ({r['oop_successes']:>2}/{r['oop_total']}) | "
            f"{r['ip_asr_pct']:>5.1f}% ({r['ip_successes']:>2}/{r['ip_total']}) | "
            f"{r['total_asr_pct']:>5.1f}% [{ci[0]:.1f}%, {ci[1]:.1f}%] | "
            f"{lat_str}"
        )
    if mcnemar:
        print("-" * 102)
        for pair, stats in mcnemar.items():
            print(f"McNemar {pair}: chi2={stats['chi2']}, p={stats['p_value']}")
    print("=" * 102)


def main():
    parser = argparse.ArgumentParser(description="PayGate-Bench 4-Baseline Ablation Runner")
    parser.add_argument("--ci", action="store_true", help="Run deterministic MockAdversarialAgent smoke test")
    parser.add_argument("--live", action="store_true", help="Run live LLM evaluation")
    parser.add_argument(
        "--models",
        nargs="+",
        default=["openai/gpt-oss-120b", "qwen/qwen3.8-27b"],
        help="List of LLM model IDs for live multi-model evaluation",
    )
    parser.add_argument("--judge-model", default="openai/gpt-oss-safeguard-20b", help="LLM Judge guardrail model ID")
    parser.add_argument("--output-dir", default="results", help="Output directory")
    args = parser.parse_args()

    mock_mode = args.ci or (not args.live)
    run_ablation(mock_mode=mock_mode, models=args.models, judge_model=args.judge_model, output_dir=args.output_dir)


if __name__ == "__main__":
    main()
