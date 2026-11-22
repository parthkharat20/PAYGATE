# Limitations of PayGate-Bench

**Author:** Parth Bhagwat Kharat  
**Document Status:** Public Disclosure Specification (`LIMITATIONS.md`)

---

To ensure scientific honesty and transparency, the following limitations govern the interpretation of all `PayGate-Bench` results:

---

## 1. Simulated Environment vs. Real Payment Rails
* **No Real-World Financial Rails:** The environment is an offline simulator with an in-memory recording stub. It does not execute live monetary transactions or interface with real-world payment processors (e.g., Stripe, Adyen, SEPA, SWIFT).
* **Omitted Payment Complexities:** The simulator abstracts away asynchronous settlement latency, multi-currency conversion spread, bank clearing windows, and chargeback arbitration.

## 2. Model and Provider Scope
* **Hosted Model Drift:** Evaluations are conducted against specific model checkpoints on specific dates. Results reflect the model behavior at evaluation time; future provider updates may alter prompt vulnerability or instruction-following fidelity.
* **Sampling Temperature:** Experiments use temperature $0.0$ to maximize reproducibility. Minor non-determinism across runs is treated as noise and measured across multiple repeats.

## 3. Attack Space Coverage
* **Template Matrix:** While the 180 synthetic injection cases span 5 goals, 3 vectors, 4 styles, and 3 languages, real-world human adversaries may employ novel socio-technical techniques not captured in these templates.
* **Adaptive Suite:** The 30 hand-crafted in-policy cases represent scenarios designed under knowledge of the gate rules by the benchmark author. They do not constitute an exhaustive penetration test by an independent red team.

## 4. Replay and Interaction Dynamics
* **Single-Pass Evaluation:** In the primary benchmark, the agent does not receive gate rejection feedback and does not retry alternative tool calls in the same turn. While this facilitates offline leave-one-out ablation, real interactive systems might expose additional surface area if agents iteratively adapt upon rejection.

## 5. Scope of Formal Verification
* **Tested Invariants vs. Formal Proofs:** Gate invariants are validated through unit testing and stateful property-based testing (Hypothesis). They are described as **empirically tested**, never as "formally verified," as they have not been machine-checked in a proof assistant (such as Lean or Coq).
