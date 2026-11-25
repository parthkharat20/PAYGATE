# Pre-Registered Evaluation Protocol: PayGate-Bench (v2.0)

**Author:** Parth Bhagwat Kharat  
**Status:** Specification (`PROTOCOL.md`)  

---

## 1. Research Question

> **Against Indirect Prompt Injection (IPI) embedded in untrusted B2B documents, how much does an out-of-band Trusted Computing Base (TCB) enforcing stateful DFA transitions, cryptographic consent binding ($R_6$), and session-level Information-Flow Control ($R_8$) reduce attack success compared with unconstrained execution, LLM-as-a-Judge guardrails, and standard perimeter gateways ($R_1$–$R_5$)—and at what utility cost and latency overhead?**

---

## 2. Falsifiable Hypotheses

* **`H1` (Perimeter vs. Unconstrained):** Both standard perimeter gateways (`static_gateway_r1_r5`) and `paygate_full` reduce Out-of-Policy Attack Success Rate ($G_1$–$G_3$) relative to `no_defense` and `prompt_plus_llm_judge`.
* **`H2` (Perimeter Blindspot on Semantic Subversion):** `static_gateway_r1_r5` exhibits non-zero vulnerability on In-Policy Semantic Subversion ($G_4$: decoy allowlisted routing, temporal consent steering) and Canary Data Exfiltration ($G_5$).
* **`H3` (TCB + Dynamic IFC Closure):** `paygate_full` (enforcing DFA + $R_1$–$R_8$) reduces both Out-of-Policy ($G_1$–$G_3$) and In-Policy Semantic ($G_4$–$G_5$) ASR to near-zero while preserving benign workflow utility.
* **`H4` (Latency Separation):** Pure deterministic TCB gate overhead ($T_{\text{gate}}$) remains sub-millisecond ($\le 50\ \mu\text{s}$ p50), orders of magnitude faster than LLM-as-a-Judge inference ($T_{\text{judge}} \sim 10^2\text{--}10^3\text{ ms}$).

---

## 3. Defense Configurations

| Configuration | Description | Enforcement Scope |
|:--|:--|:--|
| **`no_defense`** | Unconstrained Baseline | Raw execution without DFA or policy gate checks. |
| **`prompt_plus_llm_judge`** | Defensive Prompt + LLM Guardrail | Guarded system prompt + real LLM-as-a-Judge classifier before tool execution + DFA. |
| **`static_gateway_r1_r5`** | Perimeter Gateway Baseline | Enforces $R_1$ (Cap), $R_2$ (Currency), global allowlist membership, $R_4$ (Velocity), $R_5$ (Idempotency) + DFA. |
| **`paygate_full`** | Complete Out-of-Band TCB | Enforces DFA + $R_1$–$R_7$ (Order-bound $R_3$, HMAC consent $R_6$, audit chain $R_7$) + Out-of-Band Session IFC ($R_8$) + Temporal Trace Monitor. |

---

## 4. Invariants ($R_1$–$R_8$) & Non-Short-Circuiting Analysis

* **`R1` (Authorization Cap):** Capture $\le$ remaining authorized; refund $\le$ refundable captured.
* **`R2` (Currency Binding):** Operation currency strictly matches order currency.
* **`R3` (Order-Bound Allowlist):** Recipient exists in global allowlist AND equals `order.bound_merchant_id`.
* **`R4` (Metric Sliding-Window Velocity):** Over sliding window $W=60\text{s}$, tx count $\le 10$ and cumulative volume $\le 5000.00$.
* **`R5` (Strict Idempotency):** Identical canonical request hashes return cached decision; conflicting arguments under a reused key are blocked.
* **`R6` (Cryptographic Consent & Kill-Switch):** Mutations require `APPROVED` consent + valid $\text{HMAC-SHA256}(K_{\text{erp}}, \text{order\_id} \mathbin{\Vert} \text{po\_hash})$ + disarmed kill switch.
* **`R7` (Tamper-Evident Audit Chain):** Append-only HMAC-SHA256 hash chain over all gate decisions.
* **`R8` (Out-of-Band Session IFC):** Tracks untrusted document reads inside the TCB; blocks untrusted void/refund/consent capabilities and outbound canary/untrusted sink exfiltration.

**Analysis Rule:** Every gate evaluation checks all active rules without short-circuiting so rule attribution statistics remain unbiased.

---

## 5. Statistical Formulations

* **Wilson Score 95% Confidence Intervals:** Exact binomial interval handling $k=0$ edge cases honestly as $[0.0, \frac{z^2}{n + z^2}]$.
* **Paired Exact McNemar Tests:** Continuity-corrected $\chi^2$ and exact two-sided binomial $p$-values on matched scenario pairs across configurations.
