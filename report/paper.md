# PayGate-Bench (v2.0): Evaluating Out-of-Band Policy Gates and Session Information-Flow Control for Tool-Augmented Payment Agents

**Parth Bhagwat Kharat**  
Department of Computer Engineering, Dr. D. Y. Patil Institute of Technology, Pimpri, Pune  

---

## Abstract

Tool-augmented Large Language Model (LLM) agents are increasingly deployed in enterprise workflows to automate invoice processing, logistics matching, and supply-chain settlements. When ingesting untrusted external documents (vendor invoices, shipping notices, customs memos), agents are vulnerable to Indirect Prompt Injection (IPI). Existing benchmarks often evaluate shallow single-step actions against unguarded strawman baselines.

In this work, we present **PayGate-Bench (v2.0)**, an evaluation suite and out-of-band **Trusted Computing Base (TCB)** engineered around the thesis: *"AI proposes, deterministic code enforces."* PayGate combines:
1. A stateful multi-stage B2B payment lifecycle **Deterministic Finite Automaton (DFA)** (`CREATED -> AUTHORIZED -> PARTIALLY_CAPTURED -> SETTLED -> REFUNDED | VOIDED | EXPIRED`).
2. Eight non-short-circuiting invariants ($R_1$–$R_8$) integrating order-bound merchant allowlists ($R_3$), HMAC-SHA256 consent tokens ($R_6$), append-only tamper-evident logging ($R_7$), and **out-of-band session Information-Flow Control ($R_8$)**.
3. An MFOTL-inspired **Temporal Trace Monitor** (`P1`–`P5`) and stateful `Hypothesis` property fuzzing.
4. A 50-scenario benchmark (25 benign workflows + 25 adversarial IPI scenarios across Goals $G_1$–$G_5$, including multi-document split-payload attacks).

---

## 1. Architecture & Formal Guarantees

See [THREAT_MODEL.md](../THREAT_MODEL.md) and [PROTOCOL.md](../PROTOCOL.md) for the complete trust-boundary specification, formal definitions of $R_1$–$R_8$, and statistical methodology (Wilson 95% confidence intervals and paired exact McNemar tests).

---

## 2. Verification & Baseline Results

### 2.1 Deterministic Worst-Case CI Verification ($N=50$)
Under worst-case injection compliance (`scripts/run_ablation.py --ci`):
* **`no_defense`:** 100.0% Benign Utility (25/25), 100.0% Total ASR (`[86.7%, 100.0%]`).
* **`static_gateway_r1_r5`:** 100.0% Benign Utility (25/25), 40.0% Out-of-Policy ASR (6/15), 100.0% In-Policy Semantic ASR (10/10), 64.0% Total ASR (`[44.5%, 79.8%]`).
* **`paygate_full`:** **100.0% Benign Utility (25/25)**, **0.0% Out-of-Policy ASR (0/15)**, **0.0% In-Policy Semantic ASR (0/10)**, Total ASR **0.0% `[0.0%, 13.3%]`** (McNemar vs `static_gateway_r1_r5`: $\chi^2 = 14.0625, p = 3.1 \times 10^{-5}$).

### 2.2 Gate Latency Microbenchmark (`scripts/latency_bench.py`)
Measured over 2,000 iterations on Apple Silicon (`arm64`):
* **Decision Only ($R_1$–$R_6, R_8$):** $\text{p50} = 79.67\ \mu\text{s}$, $\text{p95} = 132.04\ \mu\text{s}$, $\text{p99} = 139.93\ \mu\text{s}$.
* **Full TCB + HMAC-SHA256 Audit Chain + Trace Monitor ($R_1$–$R_8$):** $\text{p50} = 202.33\ \mu\text{s}$, $\text{p95} = 256.13\ \mu\text{s}$, $\text{p99} = 270.97\ \mu\text{s}$.

### 2.3 Live Multi-Model LLM Evaluation
*[Results from live multi-model evaluation (`openai/gpt-oss-120b`, `qwen/qwen3.8-27b`, and `openai/gpt-oss-safeguard-20b` judge) will be appended directly from `results/ablation_summary.json` upon sweep completion.]*

---

## 3. Limitations
See [LIMITATIONS.md](../LIMITATIONS.md) for explicit disclosures on simulator scope, physical non-delivery ground truth, and empirical testing vs. machine-checked formal proofs.
