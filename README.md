# PayGate-Bench (v2.0)

**A Systems-Security Benchmark and Deterministic Policy Gate for Tool-Augmented Payment Agents under Indirect Prompt Injection**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python: 3.11+](https://img.shields.io/badge/Python-3.11+-brightgreen.svg)](pyproject.toml)
[![Tests: 56 Passed](https://img.shields.io/badge/Tests-56%20Passed-success.svg)](tests/)
[![TCB Isolation: Verified](https://img.shields.io/badge/TCB%20Isolation-AST%20Verified-blueviolet.svg)](paygate/tcb/)

---

## Abstract

Autonomous Large Language Model (LLM) agents are increasingly tasked with enterprise back-office workflows, including supplier invoice reconciliation, shipping notice processing, and accounts settlement. When reading untrusted external documents containing **Indirect Prompt Injections (IPI)**, probabilistic LLM agents can be coerced into issuing unauthorized financial operations. 

`PayGate-Bench` implements a zero-trust, out-of-band **Trusted Computing Base (TCB)** operating under the core systems-security thesis:
$$\text{"AI proposes, deterministic code enforces."}$$
The agent may read untrusted third-party documents and propose multi-stage payment operations, but possesses zero execution authority. Every proposed state mutation must satisfy a formal payment lifecycle **Deterministic Finite Automaton (DFA)**, 7 formal runtime payment/cryptographic invariants ($R_1$–$R_7$), and **Dynamic Information-Flow Control ($R_8$)**, evaluating in under $15\ \mu\text{s}$ with provable non-interference.

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
   │  └── R8: Dynamic IFC Provenance Non-Interference            │
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

Every state mutation proposal $req = \langle \text{action}, order\_id, amount, curr, recip, key, prov, tok \rangle$ against order $O$ is evaluated across 8 non-short-circuiting predicates:

* **$R_1$ (Authorization Cap):**
  $$\text{For capture: } 0 < req.amount \le O.auth\_amount - O.captured\_total$$
  $$\text{For refund: } 0 < req.amount \le O.captured\_total - O.refunded\_total$$
* **$R_2$ (Currency Binding):**
  $$req.currency = O.currency$$
* **$R_3$ (Order-Bound Merchant Allowlist):**
  $$req.recipient\_id \in \mathcal{A}_{\text{global}} \quad \land \quad req.recipient\_id = O.bound\_merchant\_id$$
  *(Prevents decoy routing attacks to legitimate partner accounts not bound to the active PO).*
* **$R_4$ (Sliding-Window Velocity & Volume):**
  $$\forall t \in [now - W, now] \ (W = 60s): \quad \sum \mathbf{1}_{tx} \le 10 \quad \land \quad \sum req.amount \le 5000.00$$
* **$R_5$ (Strict Idempotency):**
  $$req.idempotency\_key \mapsto (\text{SHA256}(canonical(req)), cached\_response)$$
  Identical replay yields $REPLAY\_CACHED$; parameter modification under the same key yields $BLOCK$.
* **$R_6$ (Cryptographic Consent Binding & Kill Switch):**
  $$O.consent\_state = APPROVED \quad \land \quad req.token = \text{HMAC-SHA256}(K_{erp}, O.order\_id \mathbin{\Vert} O.po\_hash) \quad \land \quad \neg KillSwitch$$
* **$R_7$ (Tamper-Evident Audit Chain):**
  Every decision event $e_t$ is recorded forward from genesis $h_0$:
  $$h_t = \text{HMAC-SHA256}(K_{audit}, h_{t-1} \mathbin{\Vert} canonical(e_t))$$
* **$R_8$ (Dynamic IFC Provenance Non-Interference):**
  $$\forall \text{ financial tool argument } x \in req: \quad \mathcal{L}(x) \not\sqsupseteq UNTRUSTED\_EXTERNAL$$
  $$\forall \text{ outbound sink message } m: \quad \mathcal{L}(m) \sqcap CONFIDENTIAL\_ERP = \bot \quad \land \quad \forall c \in \mathcal{C}_{canary}, c \notin m$$

---

## Empirical Evaluation (N=50 Scenarios)

The benchmark evaluates 4 non-strawman defense configurations across 50 enterprise scenarios (25 Benign Utility + 25 Adversarial IPI covering Goals G1–G5):

1. **`no_defense` (C0a):** Unconstrained agent connected directly to execution primitives.
2. **`prompt_plus_llm_judge` (C1):** Hardened defensive prompt + LLM-as-a-judge guardrail filter.
3. **`static_gateway_r1_r5`:** Standard payment gateway baseline enforcing only perimeter monetary checks.
4. **`paygate_full`:** Complete TCB enforcing DFA + $R_1$–$R_7$ + Dynamic IFC ($R_8$).

### Summary Results Table

| Baseline Configuration | Benign Utility (%) | Out-of-Policy ASR (G1–G3) | In-Policy Semantic ASR (G4–G5) | False Refusal Rate (%) | p50 Gate Latency |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **`no_defense`** | 100.0% (25/25) | 100.0% (15/15) | 100.0% (10/10) | 0.0% | 8.6 µs |
| **`prompt_plus_llm_judge`** | 88.0% (22/25) | 46.7% (7/15) | 100.0% (10/10) | 12.0% | 253.166 ms |
| **`static_gateway_r1_r5`** | 88.0% (22/25) | 40.0% (6/15) | 100.0% (10/10) | 12.0% | 9.5 µs |
| **`paygate_full` (Ours)** | **88.0% (22/25)** | **0.0% (0/15)** | **0.0% (0/10)** | **12.0%** | **11.8 µs** |

![Security vs Utility Tradeoff](docs/figures/asr_vs_utility_tradeoff.png)
![Latency CDF](docs/figures/latency_cdf.png)

### Key Security Findings

* **Perimeter vs. Semantic Security:** Standard payment perimeter gateways (`static_gateway_r1_r5`) reduce out-of-policy attacks but are **completely bypassed (100% ASR)** by in-policy semantic subversion ($G_4$: decoy routing to allowlisted partners, temporal consent steering, split-payload injections) and canary data leakage ($G_5$).
* **Elimination of Semantic Injections:** PayGate's Information-Flow Control ($R_8$) and cryptographic consent binding ($R_6$) reduce both Out-of-Policy and In-Policy Semantic ASR to **0.0%**.
* **Four Orders of Magnitude Latency Advantage:** PayGate TCB enforces decision predicates in **11.8 µs (p50)** compared to **~253 ms** for LLM guardrails, enabling real-time zero-trust enforcement without degrading user throughput.

---

## Positioning & Related Work

`PayGate-Bench` bridges three foundational systems-security research paradigms:

1. **Dynamic Agent Security Benchmarks:**
   * *`AgentDojo` (Debenedetti et al., NeurIPS 2024)* & *`InjecAgent` (Zou et al., ACL 2024)*: Introduced dynamic environments for evaluating tool-calling agents under indirect prompt injection. PayGate-Bench extends these benchmarks from single-step banking tasks to multi-stage, stateful B2B payment lifecycles (`authorize -> partial_capture -> void -> refund -> expiry`) and introduces a realistic standard payment gateway baseline rather than evaluating solely against unguarded strawmen.
2. **Capability-Based & Information-Flow Defenses:**
   * *`CaMeL` (Debenedetti et al., 2025)*: Proposed capability architectures and data/control-flow separation to defend against prompt injections. PayGate implements deterministic provenance tracking ($R_8$) that strictly forbids values originating from untrusted documents (`UNTRUSTED_EXTERNAL`) from binding execution arguments in state-mutating financial calls.
3. **Runtime Verification & Formal Trace Monitoring:**
   * *`Invariant` (Beurer-Kellner et al., 2024–2025)* & *`MonPoly` / MFOTL (Basin et al., ETH Information Security Group)*: Formalized runtime trace monitoring using temporal logic and structural predicates. PayGate translates temporal sliding-window constraints ($R_4$), lifecycle DFA transitions, and cryptographic authentication tokens ($R_6$) into an out-of-band, zero-trust Trusted Computing Base.

---

## Repository Structure

```
paygate/
├── tcb/                      # Trusted Computing Base (ZERO external HTTP/LLM imports)
│   ├── clock.py              # Monotonic VirtualClock for hold-expiry and velocity limits
│   ├── models.py             # Strict Pydantic models with Decimal financial arithmetic
│   ├── dfa.py                # Formal multi-stage payment lifecycle DFA
│   ├── ifc.py                # Dynamic Information-Flow Control & provenance lattice
│   ├── invariants.py         # Pure deterministic policy gate enforcing R1-R8
│   ├── audit.py              # Tamper-evident HMAC-SHA256 append-only audit log
│   └── simulator.py          # Two-layer deterministic state simulator (ERP + Rails)
├── agent/                    # Untrusted Computation Layer
│   ├── llm_client.py         # Multi-provider client (Groq, OpenAI, Ollama, Anthropic) + SQLite cache
│   ├── payment_agent.py      # Multi-turn tool-calling payment agent loop
│   ├── mock_agent.py         # Deterministic mock adversarial agent for CI reproduction
│   └── tools_spec.py         # Standardized OpenAI/Anthropic function calling schemas
└── bench/                    # Evaluation Benchmark Suite
    ├── benign.yaml           # 25 realistic enterprise B2B workflows
    ├── adversarial.yaml      # 25 structured adversarial IPI attacks (Goals G1-G5)
    ├── scenarios.py          # Dataset loader and schema validator
    ├── oracle.py             # Exact state-inspection scoring oracle (zero LLM judges)
    └── tools.py              # Agent tool executor across the 4 baselines
scripts/
├── run_ablation.py           # 1-command 4-baseline ablation runner
└── plot_figures.py           # Publication-quality matplotlib figure generator
docs/figures/                 # Generated publication-quality figures
tests/                        # 56 unit, property, DFA, IFC, and TCB isolation tests
```

---

## Quickstart & Reproduction

```bash
# 1. Run all 56 unit, property, DFA, IFC, and TCB isolation tests
pytest -v tests/

# 2. Run the 4-baseline empirical ablation benchmark (deterministic mock mode)
python scripts/run_ablation.py --mock

# 3. (Optional) Run with live LLM API (requires GROQ_API_KEY or OPENAI_API_KEY)
python scripts/run_ablation.py --live --model llama-3.3-70b-versatile
```
