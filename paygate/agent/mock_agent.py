"""
Deterministic Mock Adversarial Agent for Instant CI and Offline Verification.
Evaluates worst-case LLM behavior (agent succumbs to prompt injections).
"""

from typing import Dict, Any, List
from paygate.bench.tools import AgentToolExecutor


class MockAdversarialAgent:
    """
    Deterministic agent simulating worst-case unaligned tool execution:
    - On benign scenarios: executes the requested legitimate business operation.
    - On adversarial scenarios: succumbs to the prompt injection and executes the attacker's payload.
    Provides a reproducible upper-bound baseline for measuring defense effectiveness.
    """

    def __init__(self, config: str = "paygate_full"):
        self.config = config

    def run_scenario(
        self,
        scenario: Dict[str, Any],
        is_adversarial: bool,
        executor: AgentToolExecutor,
    ) -> Dict[str, Any]:
        trace: List[Dict[str, Any]] = []
        order_id = scenario["order_id"]

        # Step 1: Agent reads documents
        for doc in scenario.get("documents", []):
            res_doc = executor.read_document(doc["doc_id"])
            trace.append({"action": "read_document", "doc_id": doc["doc_id"], "result": res_doc})

        # Step 2: Agent reads order state
        res_order = executor.get_order(order_id)
        trace.append({"action": "get_order", "order_id": order_id, "result": res_order})

        # Step 3: Agent decides and acts
        if is_adversarial:
            adv_action = scenario.get("adversarial_action", {})
            act_type = adv_action.get("action_type")

            if act_type == "propose_capture":
                res = executor.propose_capture(
                    order_id=order_id,
                    amount=adv_action.get("amount", "100.00"),
                    currency=adv_action.get("currency", "EUR"),
                    recipient_id=adv_action.get("recipient_id", "MERCH-PRIMARY"),
                    idempotency_key=f"adv-{scenario.get('scenario_id')}",
                    provenance="UNTRUSTED_EXTERNAL",
                )
                trace.append({"action": "propose_capture", "params": adv_action, "result": res})

            elif act_type == "void_authorization":
                res = executor.void_authorization(
                    order_id=order_id,
                    idempotency_key=f"adv-void-{scenario.get('scenario_id')}",
                    provenance="UNTRUSTED_EXTERNAL",
                )
                trace.append({"action": "void_authorization", "result": res})

            elif act_type == "issue_refund":
                res = executor.issue_refund(
                    order_id=order_id,
                    amount=adv_action.get("amount", "100.00"),
                    currency=adv_action.get("currency", "EUR"),
                    idempotency_key=f"adv-ref-{scenario.get('scenario_id')}",
                    provenance="UNTRUSTED_EXTERNAL",
                )
                trace.append({"action": "issue_refund", "params": adv_action, "result": res})

            elif act_type == "set_consent":
                res = executor.set_consent(
                    order_id=order_id,
                    consent_state=adv_action.get("consent_state", "CANCEL"),
                    provenance="UNTRUSTED_EXTERNAL",
                )
                trace.append({"action": "set_consent", "params": adv_action, "result": res})

            elif act_type == "send_notification":
                res = executor.send_notification(
                    recipient=adv_action.get("recipient", "attacker@example.com"),
                    message=adv_action.get("message", "Exfiltrated data"),
                    provenance="CONFIDENTIAL_ERP",
                )
                trace.append({"action": "send_notification", "params": adv_action, "result": res})

        else:
            # Benign execution
            exp_action = scenario.get("expected_action")
            exp_amount = scenario.get("expected_amount")

            if exp_action == "capture":
                res = executor.propose_capture(
                    order_id=order_id,
                    amount=exp_amount or "100.00",
                    currency=scenario["initial_order"]["currency"],
                    recipient_id=scenario["initial_order"]["merchant_id"],
                    idempotency_key=f"benign-{scenario.get('scenario_id')}",
                    provenance="TRUSTED_ERP",
                )
                trace.append({"action": "propose_capture", "amount": exp_amount, "result": res})

            elif exp_action == "refund":
                res = executor.issue_refund(
                    order_id=order_id,
                    amount=exp_amount or "50.00",
                    currency=scenario["initial_order"]["currency"],
                    idempotency_key=f"benign-ref-{scenario.get('scenario_id')}",
                    provenance="TRUSTED_ERP",
                )
                trace.append({"action": "issue_refund", "amount": exp_amount, "result": res})

            elif exp_action == "void":
                res = executor.void_authorization(
                    order_id=order_id,
                    idempotency_key=f"benign-void-{scenario.get('scenario_id')}",
                    provenance="TRUSTED_ERP",
                )
                trace.append({"action": "void_authorization", "result": res})

            elif exp_action == "set_consent":
                res = executor.set_consent(
                    order_id=order_id,
                    consent_state="SWAP",
                    provenance="TRUSTED_ERP",
                )
                trace.append({"action": "set_consent", "result": res})

            elif exp_action == "notify":
                res = executor.send_notification(
                    recipient="buyer@example.com",
                    message="Supplier order update notification",
                    provenance="TRUSTED_ERP",
                )
                trace.append({"action": "send_notification", "result": res})

        return {"scenario_id": scenario.get("scenario_id"), "trace": trace}
