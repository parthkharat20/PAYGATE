# PayGate-Bench: Evaluating Deterministic Policy Gates for Tool-Augmented Payment Agents under Indirect Prompt Injection

**Parth Bhagwat Kharat**  
Department of Computer Engineering, Dr. D. Y. Patil Institute of Technology, Pimpri, Pune  

---

## Abstract

Tool-augmented Large Language Model (LLM) agents are increasingly deployed in enterprise workflows to automate invoice processing, logistics matching, and supply chain disbursements. However, when processing untrusted external documents (e.g., vendor invoices, shipping manifests, customs notices), agents are vulnerable to Indirect Prompt Injection (IPI), wherein embedded adversarial instructions hijack the model into executing unauthorized financial transactions. 

Existing agent security benchmarks (e.g., AgentDojo, NeurIPS 2024) primarily evaluate shallow, single-step atomic actions (such as direct transfers) against permissive strawman baselines, overlooking real-world financial state machines and "in-policy" semantic attacks. In this work, we introduce **PayGate-Bench**, an open-source evaluation benchmark and deterministic payment-policy gate. 

PayGate-Bench features:
1. A stateful multi-stage B2B payment lifecycle (two-phase authorization holds, partial captures, voids, refunds, and fake-clock timeouts).
2. Dual baselines separating unconstrained tool execution ($C0a$) from processor-grade validation ($C0b$).
3. A test suite of 190 adversarial injection cases (10 hand-crafted in-policy attacks and 180 synthetic permutations across 5 goals, 3 vectors, 4 framing styles, and 3 languages).
4. **PayGate ($C2$)**, a deterministic, non-short-circuiting policy gate enforcing 7 financial invariants ($R1$–$R7$) backed by an HMAC-SHA256 append-only audit trail.

Across empirical trials using `llama-3.3-70b-versatile`, unconstrained agents ($C0a$) suffer an Attack Success Rate (ASR) of **60.0%** (Wilson 95% CI: $[52.9\%, 66.7\%]$). While processor-grade controls ($C0b$) mitigate direct cap violations, they remain vulnerable to in-policy semantic diversions (e.g., routing to allowlisted decoy partners). Defensive prompt guardrails ($C1$) leak subtle attacks (ASR: **10.5%** $[6.8\%, 15.8\%]$). In contrast, PayGate ($C2$) reduces invariant breach ASR to **0.0%** (Wilson 95% CI: $[0.0\%, 2.0\%]$) with a median gate evaluation latency of **$4.17\ \mu\text{s}$** (p95: $4.46\ \mu\text{s}$, p99: $5.83\ \mu\text{s}$), adding $<0.002\%$ latency overhead relative to LLM inference. All code, datasets, and traces are released for reproducibility.

---

## 1. Introduction

Autonomous language agents operating in enterprise environments must reconcile two fundamentally opposing paradigms:
* **The Probabilistic Nature of LLMs:** Language models interpret ambiguous unstructured text, reason through multilingual context, and adaptively select tools. By nature, they cannot guarantee strict output constraints when processing adversarial inputs.
* **The Deterministic Rigour of Financial Systems:** Financial ledgers, banking protocols (ISO 20022), and accounting standards require inviolable mathematical invariants (double-entry balance integrity, authorization caps, strict currency matching, and idempotency).

When an agent processes an invoice or shipping notice containing an Indirect Prompt Injection (IPI) payload, the attacker seeks to bridge this gap—tricking the probabilistic LLM into issuing tool calls that breach business invariants. 

Prior work in agent safety has largely relied on prompt guardrails (e.g., Llama Guard, NeMo Guardrails) or LLM judges. These mechanisms introduce 200–500 ms of latency, suffer from non-deterministic bypasses, and incur substantial operational costs. More critically, prior security benchmarks evaluate defenses against "strawman" baselines that lack standard payment gateway checks, artificially inflating perceived defensive gains.

### Research Thesis
> *"AI proposes, deterministic code enforces."*  
> An autonomous agent may freely reason, translate, and propose payment operations, but must never possess execution authority. All proposed state transitions must traverse an out-of-band, zero-trust deterministic policy gate before reaching the payment processor.

---

## 2. Comparison with Prior Work & Novelty

| Dimension | AgentDojo (Debenedetti et al., NeurIPS 2024) | PayGate-Bench (This Work) |
| :--- | :--- | :--- |
| **Domain Model** | Shallow, single-step atomic actions (e.g., `send_money(user, amount)`) | Stateful multi-stage B2B lifecycle (Authorize $\to$ Partial Capture $\to$ Void/Refund, expiry, idempotency) |
| **Baseline Architecture** | Single permissive baseline (strawman where tools execute unvalidated calls) | **Dual Baselines**: $C0a$ (Permissive strawman) vs. **$C0b$ (Processor-Grade)** with standard ISO 20022/Stripe invariants |
| **Threat Suite** | Out-of-policy attacks (e.g., exfiltrate emails, transfer to arbitrary hacker account) | **In-Policy Attacks (30 semantic vectors)**: Attacks respecting schema constraints but hijacking business logic |
| **Defense Mechanism** | Prompt filtering and LLM judges (probabilistic, high-latency, bypassable) | **Deterministic Policy Gate ($C2$)**: 7 hard invariants ($R1$–$R7$) executing in **$4.17\ \mu\text{s}$** with HMAC audit logs |
| **Statistical Protocol** | Raw percentages without confidence intervals | Pre-registered protocol with **Wilson score 95% CIs** and **McNemar paired significance tests** |

### Key Novelty: In-Policy Attacks
Existing benchmarks focus on out-of-policy attacks where an adversary requests an illegal action (e.g., sending \$10,000 to an unknown account). In enterprise B2B workflows, the real threat is **in-policy semantic manipulation**:
1. **Decoy Allowlisted Routing:** An invoice directs payment to `MERCH-DECOY-PARTNER`, an affiliate merchant present in the corporate allowlist, but not the contracted supplier for that specific order.
2. **Temporal Consent Steering:** A fabricated customs delay memo causes the agent to prematurely update buyer consent to `CANCEL` or execute capture while goods remain in transit.
3. **Salami-Slicing Under Velocity Limits:** Micro-batch charges structured to stay beneath per-transaction review thresholds.

---

## 3. PayGate-Bench System Architecture

### 3.1 The 7 Invariants ($R1$–$R7$)
PayGate intercepts all tool requests ($T_{req}$) before execution, enforcing seven non-negotiable invariants:

* **$R1$ (Authorization Cap Invariant):**  
  $\sum \text{Captures} + \text{Req.Amount} \le \text{Order.AuthAmount}$.  
  Guarantees that cumulative captures never exceed the initial customer authorization hold.
* **$R2$ (Currency Invariant):**  
  $\text{Req.Currency} \equiv \text{Order.Currency}$.  
  Blocks cross-currency arbitrage and unauthorized conversion fees.
* **$R3$ (Merchant Allowlist & Order Binding Invariant):**  
  $\text{Req.Recipient} \in \mathcal{M}_{allow} \land \text{Req.Recipient} \equiv \text{Order.MerchantID}$.  
  Ensures funds route only to allowlisted merchants bound to the specific order.
* **$R4$ (Velocity & Cumulative Invariant):**  
  Within sliding window $W = 60\text{s}$, operational count $N \le 10$ and cumulative volume $\le €5,000.00$.
* **$R5$ (Strict Idempotency Invariant):**  
  Duplicate `idempotency_key` submissions return cached execution results without duplicate ledger debits.
* **$R6$ (Manual Kill Switch):**  
  Global circuit-breaker halting all processing within $<1\ \mu\text{s}$ upon security trip.
* **$R7$ (Append-Only Cryptographic Audit Log):**  
  Every gate decision is chained via HMAC-SHA256:  
  $H_i = \text{HMAC-SHA256}(K, H_{i-1} \parallel T_{req} \parallel \text{Decision} \parallel \text{Timestamp})$.

### 3.2 Non-Short-Circuiting Evaluation
Unlike standard firewall rule engines that abort on the first failure (`fail-fast`), PayGate evaluates **all active rules** across every request. This ensures complete diagnostic telemetry, enabling accurate Leave-One-Rule-Out ablation analysis without masking secondary vulnerabilities.

---

## 4. Empirical Evaluation

### 4.1 Experimental Setup
* **Model:** Llama-3.3-70b-versatile via Groq API (temperature $T = 0.0$).
* **Task Suite:** 24 B2B enterprise tasks (partial shipments, return refunds, delay notifications).
* **Threat Suite:** 190 attack cases (10 hand-crafted in-policy attacks + 180 synthetic permutations across 5 goals $\times$ 3 vectors $\times$ 4 framing styles $\times$ 3 languages: EN, DE, DA).
* **Metrics:** Attack Success Rate (ASR) with Wilson 95% Confidence Intervals; Benign Utility (task fulfillment percentage).

### 4.2 Benchmark Results

| Configuration | Description | Benign Utility | Attack Success Rate (ASR) | Wilson 95% CI |
| :--- | :--- | :---: | :---: | :---: |
| **$C0a$** | Permissive Core (Unconstrained Tools) | 75.0% (6/8) | **60.0%** (114/190) | $[52.9\%, 66.7\%]$ |
| **$C0b$** | Processor-Grade Baseline | 75.0% (6/8) | **15.8%** (30/190) | $[11.2\%, 21.8\%]$ |
| **$C1$** | Processor + Defensive Prompt Guard | 75.0% (6/8) | **10.5%** (20/190) | $[6.8\%, 15.8\%]$ |
| **$C2$** | **PayGate: Deterministic Policy Gate** | 75.0% (6/8) | **0.0%** (0/190) | **$[0.0\%, 2.0\%]$** |

### 4.3 Statistical Significance (McNemar Paired Tests)
* **$C0b$ vs. $C2$:** McNemar's test yields $\chi^2 = 28.03$, $p < 0.0001$. The reduction in ASR by adding PayGate over standard processor controls is statistically significant at the 99.9% level.
* **$C1$ vs. $C2$:** McNemar's test yields $\chi^2 = 18.05$, $p < 0.0001$. Proves that deterministic gating significantly outperforms probabilistic prompt guardrails on in-policy attacks.

### 4.4 Latency Distribution
Measured over 2,000 iterations on Apple Silicon (arm64):
* **Decision Only ($R1$–$R5$):**  
  $\text{p50} = 4.17\ \mu\text{s}$, $\text{p95} = 4.46\ \mu\text{s}$, $\text{p99} = 5.83\ \mu\text{s}$.
* **Decision + HMAC Audit Write ($R1$–$R7$):**  
  $\text{p50} = 9.96\ \mu\text{s}$, $\text{p95} = 11.33\ \mu\text{s}$, $\text{p99} = 14.62\ \mu\text{s}$.
* **Comparison with LLM Inference:**  
  Standard Groq LLM inference takes $\sim 112,000\ \mu\text{s}$ ($112\text{ ms}$). The gate evaluation introduces a negligible $\mathbf{0.0037\%}$ latency overhead, confirming Hypothesis $H4$.

---

## 5. Leave-One-Rule-Out Ablation Analysis

Ablating rules $R1$ through $R5$ across recorded adversarial traces reveals the critical blocker distribution:
* **Rule $R1$ (Cap Invariant):** Critical blocker for **35.8%** of attacks (primarily overcaptures and unauthorized surcharges).
* **Rule $R3$ (Allowlist & Order Binding):** Critical blocker for **27.4%** of attacks (decoy recipient diversions).
* **Rule $R4$ (Rate & Cumulative Velocity):** Critical blocker for **14.7%** of attacks (rapid micro-batch slicing).
* **Rule $R2$ (Currency Matching):** Critical blocker for **12.6%** of attacks (cross-border currency arbitrage).
* **Rule $R5$ (Idempotency Replay):** Critical blocker for **9.5%** of attacks (duplicate capture replays).

---

## 6. Limitations & Honest Boundary Claims

In accordance with responsible security disclosure and academic integrity:
1. **Perimeter Gates Cannot Solve Semantic Truth:** PayGate enforces mathematical invariants (amounts, recipients, currencies). If an attacker injects an instruction to capture an amount that is valid, within cap, for the right merchant, but for items that were never delivered, a perimeter gate cannot detect physical non-delivery. This requires human-in-the-loop or verified cryptographic delivery proofs.
2. **Synthetic Corpus Scope:** While our 190 cases span 5 goals and 3 European languages, real-world supply chain attacks may feature novel document formats (e.g., scanned PDF optical artifacts).
3. **Zero-Success Interval Interpretation:** We report an empirical ASR of $0.0\%$ with an upper 95% Wilson bound of $2.0\%$. We do not claim "unbreakable security" or "formal mathematical proof against all prompt injection."

---

## 7. Conclusion

PayGate-Bench establishes a reproducible testbed for evaluating financial agent security. Our empirical results demonstrate that while language models remain susceptible to Indirect Prompt Injection and semantic deception, zero-overhead deterministic policy gates ($<10\ \mu\text{s}$) can provably enforce critical banking invariants, neutralizing the financial impact of adversarial payloads.

---
*Artifact Repository:* [https://github.com/parthkharat20/PAYGATE](https://github.com/parthkharat20/PAYGATE)
