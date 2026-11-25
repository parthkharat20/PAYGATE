# Limitations of PayGate-Bench (v2.0)

**Author:** Parth Bhagwat Kharat  
**Document Status:** Public Disclosure Specification (`LIMITATIONS.md`)

---

To ensure scientific transparency, the following limitations govern interpretation of all `PayGate-Bench` results:

1. **Simulated Financial Environment:**
   * All experiments execute against an offline, two-layer deterministic simulator (`paygate/tcb/simulator.py`). No live payment processors (Stripe, Adyen, SEPA, SWIFT) or real monetary assets are connected.
   * Asynchronous clearing delays, chargeback disputes, and FX conversion spreads are abstracted away.

2. **Physical Ground-Truth Limitation:**
   * Deterministic invariants and IFC cannot verify physical world truth outside the ERP. If an untrusted packing slip claims 5 units shipped when only 2 were physically delivered—and the corresponding amount stays within `auth_amount` and routes to `bound_merchant_id` under `APPROVED` consent—a deterministic software gate cannot detect physical fraud without signed logistics telemetry (e.g., cryptographic carrier proofs).

3. **Model Coverage & Prompt Sensitivity:**
   * Live benchmarks reflect the specific hosted model checkpoints evaluated at experiment time (temperature $0.0$). Results across additional proprietary or local models may vary.

4. **Dataset Scope:**
   * The 50-scenario benchmark (25 benign, 25 adversarial across $G_1$–$G_5$ including multi-document split-payload attacks) represents structured B2B workflows curated by the author rather than an exhaustive open-ended red-team penetration test.

5. **Tested Invariants vs. Machine-Checked Proofs:**
   * The Payment DFA, double-entry ledger, HMAC audit chain, and TCB isolation invariants are validated through unit tests, AST import checks, and stateful property-based fuzzing (`Hypothesis` `RuleBasedStateMachine`). They are described accurately as **empirically tested and property-fuzzed**, not formally proved in a theorem prover (e.g. Lean, Isabelle, or Coq).
