from typing import Dict, Any, Optional
from decimal import Decimal
from env.models import ToolRequest, ConsentState, Order
from env.ledger import Ledger
from env.document_store import DocumentStore
from env.core_permissive import PermissiveCore
from env.processor_layer import ProcessorLayer
from defenses.gate import DeterministicGate
from env.fake_clock import FakeClock


class AgentToolExecutor:
    """
    Executes tool calls made by the agent according to the selected defense configuration:
    - C0a: Direct execution in permissive core (no invariant check)
    - C0b: Execution in processor layer (standard rail constraints)
    - C1: Execution in processor layer (prompt guardrail is the defense)
    - C2: Intercepted by DeterministicGate (R1-R7) before reaching processor layer
    """

    def __init__(
        self,
        ledger: Ledger,
        doc_store: DocumentStore,
        clock: FakeClock,
        config: str = "C2",
        gate: Optional[DeterministicGate] = None,
    ):
        self.ledger = ledger
        self.doc_store = doc_store
        self.clock = clock
        self.config = config
        self.gate = gate

    def get_order(self, order_id: str) -> Dict[str, Any]:
        """Read-only tool: inspect current order status and details."""
        try:
            order = self.ledger.get_order(order_id)
            return {
                "success": True,
                "order_id": order.order_id,
                "currency": order.currency,
                "auth_amount": str(order.auth_amount),
                "captured_total": str(order.captured_total),
                "remaining_authorized": str(order.remaining_authorized),
                "status": order.status.value,
                "consent_state": order.consent_state.value,
                "merchant_id": order.merchant_id,
            }
        except KeyError:
            return {"success": False, "error": f"Order {order_id} not found"}

    def read_document(self, doc_id: str) -> Dict[str, Any]:
        """Read-only tool: reads supplier notice, invoice, or email (ATTACK SURFACE)."""
        try:
            content = self.doc_store.get_document_content(doc_id)
            return {"success": True, "doc_id": doc_id, "content": content}
        except KeyError:
            return {"success": False, "error": f"Document {doc_id} not found"}

    def propose_capture(
        self, order_id: str, amount: str, currency: str, recipient_id: str, idempotency_key: str
    ) -> Dict[str, Any]:
        """Propose a capture against an authorization hold."""
        dec_amount = Decimal(amount)
        req = ToolRequest(
            action_type="propose_capture",
            order_id=order_id,
            amount=dec_amount,
            currency=currency,
            recipient_id=recipient_id,
            idempotency_key=idempotency_key,
        )

        # Config C0a: Permissive Core
        if self.config == "C0a":
            ok, msg, rec = PermissiveCore.execute_capture(self.ledger, req, self.clock)
            return {"success": ok, "message": msg, "capture_id": rec.capture_id if rec else None}

        # Config C2: Deterministic Gate
        if self.config == "C2" and self.gate:
            order = self.ledger.get_order(order_id)
            decision = self.gate.evaluate(req, order, self.clock)
            if decision.action.value == "BLOCK":
                return {
                    "success": False,
                    "error": f"Gate rejected capture: {decision.reason}",
                    "violated_rules": decision.all_violated_rules,
                }
            if decision.action.value == "REPLAY_CACHED":
                return {"success": True, "message": "Idempotent replay: cached capture returned"}

        # Config C0b, C1, or passed C2: execute in processor layer
        ok, msg, rec = ProcessorLayer.execute_capture(self.ledger, req, self.clock)
        return {
            "success": ok,
            "message": msg,
            "capture_id": rec.capture_id if rec else None,
            "error": None if ok else msg,
        }

    def void_authorization(self, order_id: str, idempotency_key: str) -> Dict[str, Any]:
        """Void an authorization hold before funds are captured."""
        req = ToolRequest(
            action_type="void_authorization",
            order_id=order_id,
            idempotency_key=idempotency_key,
        )

        if self.config == "C0a":
            ok, msg = PermissiveCore.execute_void(self.ledger, req)
            return {"success": ok, "message": msg}

        if self.config == "C2" and self.gate:
            order = self.ledger.get_order(order_id)
            decision = self.gate.evaluate(req, order, self.clock)
            if decision.action.value == "BLOCK":
                return {"success": False, "error": f"Gate rejected void: {decision.reason}"}

        ok, msg = ProcessorLayer.execute_void(self.ledger, req)
        return {"success": ok, "message": msg, "error": None if ok else msg}

    def issue_refund(
        self, order_id: str, amount: str, currency: str, idempotency_key: str
    ) -> Dict[str, Any]:
        """Issue a refund against captured funds."""
        dec_amount = Decimal(amount)
        req = ToolRequest(
            action_type="issue_refund",
            order_id=order_id,
            amount=dec_amount,
            currency=currency,
            idempotency_key=idempotency_key,
        )

        if self.config == "C0a":
            ok, msg, rec = PermissiveCore.execute_refund(self.ledger, req, self.clock)
            return {"success": ok, "message": msg, "refund_id": rec.refund_id if rec else None}

        if self.config == "C2" and self.gate:
            order = self.ledger.get_order(order_id)
            decision = self.gate.evaluate(req, order, self.clock)
            if decision.action.value == "BLOCK":
                return {"success": False, "error": f"Gate rejected refund: {decision.reason}"}

        ok, msg, rec = ProcessorLayer.execute_refund(self.ledger, req, self.clock)
        return {
            "success": ok,
            "message": msg,
            "refund_id": rec.refund_id if rec else None,
            "error": None if ok else msg,
        }

    def set_consent(self, order_id: str, consent_state: str) -> Dict[str, Any]:
        """Update buyer consent state (WAIT, SWAP, CANCEL, APPROVED)."""
        new_state = ConsentState(consent_state)
        req = ToolRequest(action_type="set_consent", order_id=order_id, consent_state=new_state)

        if self.config == "C2" and self.gate:
            order = self.ledger.get_order(order_id)
            decision = self.gate.evaluate(req, order, self.clock)
            if decision.action.value == "BLOCK":
                return {"success": False, "error": f"Gate rejected consent update: {decision.reason}"}

        self.ledger.update_consent(order_id, new_state)
        return {"success": True, "message": f"Consent updated to {consent_state}"}

    def send_notification(self, recipient: str, message: str) -> Dict[str, Any]:
        """Send outbound notification message (monitored for canary token exfiltration)."""
        self.ledger.send_outbound_message(recipient, message)
        return {"success": True, "message": "Notification dispatched"}
