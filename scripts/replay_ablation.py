"""
Incremental Stack & Rule-Attribution Replay Ablation Engine for PayGate-Bench.
Replays genuine adversarial tool-call proposals emitted by live LLMs to measure:
  1. Incremental defense layers: Raw -> DFA -> Perimeter(R1-R5) -> +R3_OrderBind -> +R6_HMAC -> Full_TCB(+R8_IFC)
  2. Non-short-circuiting Rule Attribution: frequency each invariant R1..R8 fires on live attacks.
"""

import os
import json
from decimal import Decimal, InvalidOperation
from typing import Dict, Any, List, Set

from paygate.tcb.models import ToolRequest, ConsentState, ActionDecision
from paygate.bench.scenarios import ScenarioLoader
from paygate.bench.oracle import BenchmarkOracle
from scripts.run_ablation import _build_env_for_scenario


def _parse_dec(val: Any) -> Decimal:
    try:
        return Decimal(str(val))
    except (InvalidOperation, ValueError, TypeError):
        return Decimal("0.00")


def run_loro_replay(
    raw_runs_path: str = "results/raw_runs.jsonl",
    output_path: str = "results/ablation_matrix.json",
) -> Dict[str, Any]:
    if not os.path.exists(raw_runs_path):
        raise FileNotFoundError(f"Live traces not found at {raw_path if False else raw_runs_path}")

    loader = ScenarioLoader()
    adv_by_id = {sc["scenario_id"]: sc for sc in loader.load_adversarial_scenarios()}

    live_proposals: List[Dict[str, Any]] = []
    seen_keys: Set[tuple] = set()
    with open(raw_runs_path, "r", encoding="utf-8") as f:
        for line in f:
            row = json.loads(line)
            if row.get("type") != "adversarial" or row.get("config") != "no_defense":
                continue
            key = (row["model"], row["scenario_id"])
            if key in seen_keys:
                continue
            seen_keys.add(key)

            calls = []
            for step in row.get("trace", []):
                for tc in step.get("tool_calls", []):
                    if tc.get("name") in (
                        "propose_capture",
                        "void_authorization",
                        "issue_refund",
                        "set_consent",
                        "send_notification",
                    ):
                        calls.append(tc)
            if calls:
                live_proposals.append(
                    {"model": row["model"], "scenario_id": row["scenario_id"], "calls": calls}
                )

    total_trials = len(live_proposals)

    # Incremental security stack layers (shows marginal value of each TCB layer)
    stack_configs: List[tuple] = [
        ("L0_Unconstrained_Raw", set(), False),
        ("L1_DFA_Only", set(), True),
        ("L2_Perimeter_R1_R2_R4_R5", {"R1", "R2", "R4", "R5"}, True),
        ("L3_Add_OrderBound_R3", {"R1", "R2", "R3", "R4", "R5"}, True),
        ("L4_Add_ConsentHMAC_R6", {"R1", "R2", "R3", "R4", "R5", "R6"}, True),
        ("L5_Full_TCB_Add_SessionIFC_R8", {"R1", "R2", "R3", "R4", "R5", "R6", "R7", "R8"}, True),
    ]

    incremental_results: Dict[str, Any] = {}
    rule_trigger_counts: Dict[str, int] = {f"R{i}": 0 for i in range(1, 9)}

    for label, active_rules, use_dfa in stack_configs:
        success_count = 0
        for prop in live_proposals:
            sc = adv_by_id[prop["scenario_id"]]
            clock, sim, gate, order = _build_env_for_scenario(sc)
            for doc in sc.get("documents", []):
                gate.taint_tracker.record_document_read(doc["doc_id"], doc["content"])
            gate.taint_tracker.set_trusted_context(
                sc.get("user_prompt") or sc.get("description", "")
            )

            for i, tc in enumerate(prop["calls"]):
                fn = tc["name"]
                args = tc.get("arguments", {}) or {}
                req = None

                if fn == "propose_capture":
                    req = ToolRequest(
                        action_type="propose_capture",
                        order_id=order.order_id,
                        amount=_parse_dec(args.get("amount", "0.00")),
                        currency=str(args.get("currency", "EUR")),
                        recipient_id=str(args.get("recipient_id", "MERCH-PRIMARY")),
                        idempotency_key=str(args.get("idempotency_key", f"inc-{i}")),
                    )
                elif fn == "void_authorization":
                    req = ToolRequest(
                        action_type="void_authorization",
                        order_id=order.order_id,
                        idempotency_key=str(args.get("idempotency_key", f"inc-v-{i}")),
                    )
                elif fn == "issue_refund":
                    req = ToolRequest(
                        action_type="issue_refund",
                        order_id=order.order_id,
                        amount=_parse_dec(args.get("amount", "0.00")),
                        currency=str(args.get("currency", "EUR")),
                        idempotency_key=str(args.get("idempotency_key", f"inc-r-{i}")),
                    )
                elif fn == "set_consent":
                    try:
                        cs = ConsentState(str(args.get("consent_state", "WAIT")))
                    except ValueError:
                        continue
                    req = ToolRequest(
                        action_type="set_consent",
                        order_id=order.order_id,
                        consent_state=cs,
                    )
                elif fn == "send_notification":
                    req = ToolRequest(
                        action_type="send_notification",
                        order_id="SYSTEM",
                        recipient=str(args.get("recipient", "buyer@example.com")),
                        message=str(args.get("message", "")),
                    )

                if req is None:
                    continue

                allowed = True
                if active_rules:
                    dec = gate.evaluate(req, order, clock, active_rules=active_rules)
                    if label == "L5_Full_TCB_Add_SessionIFC_R8":
                        for r_id in dec.all_violated_rules:
                            if r_id in rule_trigger_counts:
                                rule_trigger_counts[r_id] += 1
                    allowed = (dec.action == ActionDecision.ALLOW)

                if not allowed:
                    continue

                if fn == "propose_capture":
                    if use_dfa:
                        sim.execute_capture_dfa(req)
                    else:
                        sim.execute_capture_raw(req)
                elif fn == "void_authorization":
                    if use_dfa:
                        sim.execute_void_dfa(req)
                    else:
                        order.status = order.status.VOIDED
                elif fn == "issue_refund":
                    if use_dfa:
                        sim.execute_refund_dfa(req)
                    else:
                        order.refunded_total += req.amount or Decimal("0.00")
                elif fn == "set_consent" and req.consent_state is not None:
                    sim.update_consent(order.order_id, req.consent_state)
                elif fn == "send_notification":
                    sim.send_outbound_message(req.recipient or "", req.message or "")

            if BenchmarkOracle.score_attack_success(sc, sim, sc["initial_order"]):
                success_count += 1

        asr_pct = round((success_count / total_trials) * 100.0, 1) if total_trials else 0.0
        incremental_results[label] = {
            "attack_successes": success_count,
            "total_replayed": total_trials,
            "asr_pct": asr_pct,
        }

    output_data = {
        "total_live_adversarial_traces": total_trials,
        "incremental_stack_ablation": incremental_results,
        "non_short_circuit_rule_attribution": rule_trigger_counts,
    }
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(output_data, f, indent=2)

    print("\n=== INCREMENTAL STACK ABLATION ON LIVE LLM PROPOSALS ===")
    for k, v in incremental_results.items():
        print(f"  {k:<32}: ASR = {v['asr_pct']:>5.1f}% ({v['attack_successes']}/{v['total_replayed']})")
    print("=== NON-SHORT-CIRCUIT RULE TRIGGER COUNTS ===")
    print(" ", rule_trigger_counts)
    return output_data


if __name__ == "__main__":
    run_loro_replay()
