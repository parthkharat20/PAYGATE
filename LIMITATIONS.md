# Limitations of PayGate-Bench (v2.0)

**Author:** Parth Bhagwat Kharat  
**Document Status:** Public Disclosure Specification (`LIMITATIONS.md`)

---

To ensure scientific transparency, the following limitations govern interpretation of all `PayGate-Bench` results:

1. **Simulated Financial Environment:**
   * All experiments execute against an offline, two-layer deterministic simulator (`paygate/tcb/simulator.py`) and an isolated `AgentDojo`-style banking adapter (`paygate/bench/agentdojo_adapter.py`). No live payment processors (Stripe, Adyen, SEPA, SWIFT) or real monetary assets are connected.
   * Asynchronous clearing delays, chargeback disputes, and FX conversion spreads are abstracted away.

2. **Physical Ground-Truth Limitation:**
   * Deterministic invariants and IFC cannot verify physical world truth outside the ERP. If an untrusted packing slip claims 5 units shipped when only 2 were physically delivered—and the corresponding amount stays within `auth_amount` and routes to `bound_merchant_id` under `APPROVED` consent—a deterministic software gate cannot detect physical fraud without signed logistics telemetry (e.g., cryptographic carrier proofs).

3. **Model Coverage, Rate Quotas & Fail-Closed Sink False Positives:**
   * Live benchmarks reflect the specific hosted model checkpoints evaluated at experiment time (`openai/gpt-oss-120b`, `qwen/qwen3.8-27b`, with `openai/gpt-oss-20b` LLM judge, at temperature `0.0`).
   * Strict fail-closed outbound sink allowlisting (`R8`) produced an empirical benign utility reduction of `2/25` on `qwen/qwen3.8-27b` (`92.0%` vs `100.0%` on `openai/gpt-oss-120b`; `96.0%` pooled). Trace inspection of `BENIGN-02` and `BENIGN-23` shows Qwen synthesized unregistered recipient addresses (`buyer@ord-b02.example.com`, `buyer@ORD-B23`) after ingesting `UNTRUSTED_EXTERNAL` supplier notices rather than using registered buyer addresses (`buyer@example.com`), causing the TCB to fail closed safely. Schema-registered buyer addresses eliminate this usability gap without weakening non-interference.

4. **Dataset Scope:**
   * The 55-scenario benchmark (`25` benign, `25` adversarial across Goals `G1`–`G5` including multi-document split-payload attacks, and `5` dual-use Utility-Under-Attack workflows) represents curated enterprise B2B workflows rather than an exhaustive open-ended red-team test.

5. **Tested Invariants vs. Machine-Checked Proofs:**
   * The Payment DFA, double-entry ledger, HMAC audit chain, online `TemporalTraceMonitor`, and TCB isolation invariants are validated through 49 offline unit/integration tests, AST import checks, and stateful property-based fuzzing (`Hypothesis` `RuleBasedStateMachine`). They are described accurately as **empirically tested and property-fuzzed**, not formally proved in a theorem prover (e.g. Lean, Isabelle, or Coq).
