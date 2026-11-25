# PayGate-Bench (v2.0)

**A Systems-Security Benchmark and Deterministic Policy Gate for Tool-Augmented Payment Agents under Indirect Prompt Injection**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python: 3.11+](https://img.shields.io/badge/Python-3.11+-brightgreen.svg)](pyproject.toml)
[![Tests: 45 Passed](https://img.shields.io/badge/Tests-45%20Passed%20(Hypothesis%20Fuzzed)-success.svg)](tests/)
[![TCB Isolation: Verified](https://img.shields.io/badge/TCB%20Isolation-AST%20Verified-blueviolet.svg)](paygate/tcb/)

---

## Abstract

Autonomous Large Language Model (LLM) agents are increasingly tasked with enterprise back-office workflows, including supplier invoice reconciliation, shipping notice processing, and accounts settlement. When reading untrusted external documents containing **Indirect Prompt Injections (IPI)**, probabilistic LLM agents can be coerced into issuing unauthorized financial operations.

`PayGate-Bench` implements an out-of-band, zero-trust **Trusted Computing Base (TCB)** operating under the systems-security thesis:
$$\text{"AI proposes, deterministic code enforces."}$$
The agent may ingest untrusted third-party documents and propose multi-stage payment operations, but possesses zero execution authority. Every proposed state mutation must satisfy a formal payment lifecycle **Deterministic Finite Automaton (DFA)**, 7 formal runtime payment/cryptographic invariants ($R_1$–$R_7$), **Out-of-Band Session Information-Flow Control ($R_8$)**, and an MFOTL-inspired **Temporal Trace Monitor**.

---

## Architecture & Trust Boundaries

```
                      UNTRUSTED BOUNDARY
  [Supplier Invoices]  [Shipping Emails]  [Customs Notices] (UNTRUSTED_EXTERNAL)
            │                    │                  │
            ▼                    ▼                  ▼
   ┌─────────────────────────────────────────────────────────────┐
   │             Untrusted Computation Layer                     │
   │  ┌───────────────────────────────────────────────────────┐  │
   │  │   LLM Payment Operations Agent (Tool-Calling Loop)    │  │
   │  │   - Reads documents, reconciles PO line items         │  │
   │  │   - Proposes state-mutating tool requests             │  │
   │  └───────────────────────────────────────────────────────┘  │
   └──────────────────────────────┬──────────────────────────────┘
                                  │ Proposed Tool Calls
  ════════════════════════════════╪═══════════════════════════════════
                      TRUSTED COMPUTING BASE (TCB)
   ┌──────────────────────────────▼──────────────────────────────┐
   │  Out-of-Band Policy Gate (paygate/tcb/invariants.py)         │
   │  ├── R1: Authorization Cap & Non-Negative Bound             │
   │  ├── R2: Currency Invariant Matching                        │
   │  ├── R3: Order-Bound Merchant Allowlist                     │
   │  ├── R4: Metric Sliding-Window Velocity & Volume Limits     │
   │  ├── R5: Strict SHA-256 Request Idempotency                 │
   │  ├── R6: Cryptographic HMAC Consent Binding & Kill-Switch   │
   │  ├── R7: Append-Only HMAC-SHA256 Tamper-Evident Hash Chain  │
   │  ├── R8: Out-of-Band Session IFC & Capability Separation    │
   │  └── Trace Monitor: Temporal Safety Predicates (P1-P5)      │
   ├──────────────────────────────┬──────────────────────────────┤
   │                              │ Validated State Transitions  │
   │  ┌───────────────────────────▼───────────────────────────┐  │
   │  │   Payment Lifecycle DFA (paygate/tcb/dfa.py)          │  │
   │  │   CREATED -> AUTHORIZED -> PARTIALLY_CAPTURED         │  │
   │  │                          -> SETTLED -> REFUNDED       │  │
   │  │                 AUTHORIZED -> VOIDED | EXPIRED        │  │
   │  └───────────────────────────┬───────────────────────────┘  │
   │                              │ Mutates State                │
   │  ┌───────────────────────────▼───────────────────────────┐  │
   │  │   Two-Layer Deterministic State Simulator             │  │
   │  │   - Layer 1: ERP State (Orders, Consents, PO Hashes)  │  │
   │  │   - Layer 2: Payment Rail State (Captures, Refunds)   │  │
   │  └───────────────────────────────────────────────────────┘  │
   └─────────────────────────────────────────────────────────────┘
```

> **Strict TCB Isolation Guarantee:** `paygate/tcb/` enforces zero external HTTP, agent, or LLM library dependencies (statically checked by AST traversal in `tests/test_tcb_isolation.py`).

---

## Formal Invariant Specifications ($R_1$–$R_8$)

Every state mutation proposal $req = \langle \text{action}, order\_id, amount, curr, recip, key, tok \rangle$ against order $O$ is evaluated across 8 non-short-circuiting predicates:

* **$R_1$ (Authorization Cap):**
  $$\text{For capture: } 0 < req.amount \le O.auth\_amount - O.captured\_total$$
  $$\text{For refund: } 0 < req.amount \le O.captured\_total - O.refunded\_total$$
* **$R_2$ (Currency Binding):** $req.currency = O.currency$.
* **$R_3$ (Order-Bound Merchant Allowlist):**
  $$req.recipient\_id \in \mathcal{A}_{\text{global}} \quad \land \quad req.recipient\_id = O.bound\_merchant\_id$$
* **$R_4$ (Sliding-Window Velocity & Volume):**
  $$\forall t \in [now - W, now] \ (W = 60\text{s}): \quad \sum \mathbf{1}_{tx} \le 10 \quad \land \quad \sum req.amount \le 5000.00$$
* **$R_5$ (Strict Idempotency):** Identical canonical SHA-256 request hashes yield `REPLAY_CACHED`; altered parameters under a reused key yield `BLOCK`.
* **$R_6$ (Cryptographic Consent Binding & Kill Switch):**
  $$O.consent\_state = APPROVED \quad \land \quad req.token = \text{HMAC-SHA256}(K_{erp}, O.order\_id \mathbin{\Vert} O.po\_hash) \quad \land \quad \neg KillSwitch$$
* **$R_7$ (Tamper-Evident Audit Chain):**
  $$h_t = \text{HMAC-SHA256}(K_{audit}, h_{t-1} \mathbin{\Vert} canonical(e_t))$$
* **$R_8$ (Out-of-Band Session IFC & Capability Separation):**
  Tracked strictly inside the TCB (`TaintTracker.record_document_read`): once an `UNTRUSTED_EXTERNAL` document enters the session, untrusted external inputs cannot exercise unapproved `void`/`refund`/`set_consent` capabilities, redirect `recipient_id`, or transmit `CONFIDENTIAL_ERP` canary tokens to untrusted external sinks.

---

## Verification & Evaluation Results

### 1. Deterministic CI Worst-Case Adversary Verification (`make run-ci`, $N=50$ Scenarios)

Evaluated with `MockAdversarialAgent` (worst-case agent following 100% of adversarial injections; genuine nanosecond timings):

| Baseline Configuration | Benign Utility | OOP ASR ($G_1$–$G_3$) | IP ASR ($G_4$–$G_5$) | Total ASR [Wilson 95% CI] | Measured p50 Latency |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **`no_defense`** | 100.0% (25/25) | 100.0% (15/15) | 100.0% (10/10) | 100.0% `[86.7%, 100.0%]` | 12.88 µs |
| **`static_gateway_r1_r5`** | 100.0% (25/25) | 40.0% (6/15) | 100.0% (10/10) | 64.0% `[44.5%, 79.8%]` | 9.65 µs |
| **`paygate_full` (Ours)** | **100.0% (25/25)** | **0.0% (0/15)** | **0.0% (0/10)** | **0.0% `[0.0%, 13.3%]`** | **18.44 µs** |

*Paired McNemar significance (`static_gateway_r1_r5` vs `paygate_full`): $\chi^2 = 14.0625$, $p = 3.1 \times 10^{-5}$.*

### 2. High-Resolution TCB Latency Microbenchmark (`make bench-latency`, 2,000 iterations)
* **Decision Only ($R_1$–$R_6$, $R_8$):** `p50 = 79.67 µs`, `p95 = 132.04 µs`, `p99 = 139.93 µs`
* **Full TCB + HMAC Audit Chain + Trace Monitor ($R_1$–$R_8$):** `p50 = 202.33 µs`, `p95 = 256.13 µs`, `p99 = 270.97 µs`

### 3. Live Multi-Model LLM Evaluation (`make run-live`)
* Live evaluation across `openai/gpt-oss-120b` and `qwen/qwen3.8-27b` with real LLM-as-a-Judge guardrail (`openai/gpt-oss-safeguard-20b`) is run via `python scripts/run_ablation.py --live`. *(Live aggregate results and incremental replay tables are populated directly from `results/raw_runs.jsonl`.)*

---

## Positioning & Related Work

1. **Dynamic Agent Security Benchmarks:** Extends `AgentDojo` (Debenedetti et al., NeurIPS 2024) and `InjecAgent` (Zou et al., ACL 2024) from single-step transfers to stateful multi-stage B2B payment lifecycles (`authorize -> partial_capture -> void -> refund -> expiry`) and evaluates against a realistic perimeter gateway baseline (`static_gateway_r1_r5`).
2. **Capability-Based & Information-Flow Defenses:** Aligns with `CaMeL` (Debenedetti et al., 2025) by enforcing deterministic out-of-band provenance and capability separation ($R_8$) inside the TCB without relying on probabilistic judges.
3. **Runtime Verification & Formal Trace Monitoring:** Connects programmatic execution guardrails (`Invariant`, Beurer-Kellner et al., 2024–2025) and MFOTL runtime trace monitors (`MonPoly`, Basin et al.) to temporal financial invariants (`TemporalTraceMonitor`) and Hypothesis stateful property fuzzing.

---

## Repository Structure

```
paygate/
├── tcb/                      # Trusted Computing Base (ZERO external HTTP/LLM imports)
│   ├── clock.py              # Monotonic VirtualClock for hold-expiry and velocity limits
│   ├── models.py             # Strict Pydantic models with Decimal financial arithmetic
│   ├── dfa.py                # Formal multi-stage payment lifecycle DFA
│   ├── ifc.py                # Out-of-band session IFC & capability separation (Rule R8)
│   ├── invariants.py         # Pure deterministic policy gate enforcing R1-R8
│   ├── monitor.py            # MFOTL-inspired TemporalTraceMonitor (predicates P1-P5)
│   ├── audit.py              # Tamper-evident HMAC-SHA256 append-only audit log
│   └── simulator.py          # Two-layer deterministic state simulator (ERP + Rails)
├── agent/                    # Untrusted Computation Layer
│   ├── llm_client.py         # OpenAI/Groq-compatible client + LLM judge + SQLite cache
│   ├── payment_agent.py      # Multi-turn tool-calling payment agent loop
│   ├── mock_agent.py         # Deterministic worst-case mock agent for CI smoke tests
│   └── tools_spec.py         # Function-calling schemas
└── bench/                    # Evaluation Benchmark Suite
    ├── benign.yaml           # 25 realistic enterprise B2B workflows
    ├── adversarial.yaml      # 25 structured adversarial IPI attacks (Goals G1-G5)
    ├── scenarios.py          # Dataset loader
    ├── oracle.py             # Exact state-inspection scoring oracle
    ├── stats.py              # Wilson 95% CIs & exact McNemar paired tests
    └── tools.py              # Tool execution & real latency profiling across 4 baselines
scripts/
├── run_ablation.py           # 4-baseline ablation runner (--ci and --live modes)
├── replay_ablation.py        # Incremental stack & non-short-circuiting rule attribution replay
├── latency_bench.py          # 2,000-iteration high-resolution gate latency benchmark
└── plot_figures.py           # Data-driven matplotlib figure generator
tests/                        # 46 unit, Hypothesis stateful fuzzing, monitor, and AST tests
```

---

## Quickstart & Reproduction

```bash
# 1. Run all unit, Hypothesis stateful fuzzing, trace monitor, and AST TCB isolation tests
make test

# 2. Run deterministic CI worst-case adversary verification
make run-ci

# 3. Run high-resolution TCB latency benchmark
make bench-latency

# 4. Run live multi-model evaluation (requires GROQ_API_KEY or OPENAI_API_KEY)
make run-live && make replay
```
