# Pre-Registered Protocol: PayGate-Bench

**Author:** Parth Bhagwat Kharat  
**Status:** Pre-Registered Protocol (`PROTOCOL.md`)  
**Commit Requirement:** This specification is committed to version control before executing formal evaluation test runs.

---

## 1. Research Question

> **Against prompt injection hidden in untrusted business documents, how much does a deterministic payment-policy gate reduce attack success compared with a prompt-only guardrail and with no defense, at what cost to legitimate tasks and latency, and which attacks still succeed inside the gate's own rules?**

---

## 2. Pre-Registered Hypotheses (Falsifiable)

* **`H1`:** The deterministic gate (`C2`) achieves a lower Attack Success Rate than permissive no-defense (`C0a`) and prompt guardrails (`C1`) on direct injection attacks. The processor-grade baseline (`C0b`) establishes the floor of standard rail checks; the gate's value is quantified by what it adds beyond `C0b`.
* **`H2`:** The deterministic gate (`C2`) is not at zero on in-policy attacks: semantic manipulations that satisfy every syntactic invariant (`R1`–`R5`) can still alter intended business outcomes.
* **`H3`:** A well-crafted prompt-only guardrail (`C1`) leaves a non-trivial Attack Success Rate, particularly on multilingual (German, Danish) and format-mimicking injection styles.
* **`H4`:** Gate decision time is small compared with a single LLM API call (the exact ratio $T_{\text{gate}} / T_{\text{LLM}}$ is reported empirically without assumption).

---

## 3. Defense Configurations

| Config | Description | Invariant Enforcement |
|---|---|---|
| **`C0a`** | **Permissive Core** | Raw baseline. Executes actions with basic type and sign validation only. Overcaptures and invalid recipients execute. |
| **`C0b`** | **Processor Layer** | Enforces standard payment-rail rules: captures $\le$ authorized remaining, currency match, positive amounts. |
| **`C1`** | **Prompt Guardrail** | System prompt instructions prohibiting policy violations. Tuned strictly on **Dev Split**, then frozen for **Test Split**. |
| **`C2`** | **Deterministic Gate** | External deterministic rule engine enforcing rules `R1` through `R7` before committing state mutations. |
| **`C3`** | **Schema Gate (Target)** | Schema-constrained extraction + deterministic policy gate (AuthHorizon architecture). |

---

## 4. Gate Rules (`R1`–`R7`)

* **`R1` (Cap Invariant):** Captured total never exceeds order authorization; capture never exceeds remaining authorized.
* **`R2` (Currency Invariant):** Operation currency strictly equals order currency.
* **`R3` (Allowlist Invariant):** Recipient exists in the pre-configured merchant allowlist.
* **`R4` (Rate/Cumulative Limits):** Velocity caps on transaction count and cumulative amount within a sliding temporal window.
* **`R5` (Idempotency Invariant):** Unique execution per key. Repeated identical key returns cached response; duplicate key with conflicting parameters is blocked.
* **`R6` (Kill Switch):** Global circuit breaker. Tested separately in dedicated kill-switch scenarios.
* **`R7` (HMAC Audit Chain):** Immutable append-only log. Tested separately via tamper-detection verification.

**Analysis Rule:** In the analysis path, every rule is evaluated on every proposal, and all violated rules are recorded. Rule ablation is applied to `R1`–`R5` only.

---

## 5. Statistical Formulations

### 5.1. Wilson Score Confidence Intervals
For $k$ successes in $n$ trials ($\hat{p} = k/n$) at 95% confidence ($z = 1.96$):

$$\text{Centre} = \frac{\hat{p} + \frac{z^2}{2n}}{1 + \frac{z^2}{n}}, \quad \text{Half-Width} = \frac{z}{1 + \frac{z^2}{n}} \sqrt{\frac{\hat{p}(1-\hat{p})}{n} + \frac{z^2}{4n^2}}$$

**Zero-Success Edge Case:** When $k = 0$, the interval is $[0.0, \; \frac{z^2}{n + z^2}]$. For $n = 150$, the upper bound is $\approx 2.5\%$. This is reported honestly as $[0.0\%, 2.5\%]$, never as $0\%$.

### 5.2. Paired McNemar Test
Paired comparisons on identical test cases between configurations use the continuity-corrected McNemar statistic:

$$\chi^2 = \frac{(|b - c| - 1)^2}{b + c}$$

Exact binomial test is applied when $b + c < 25$.
