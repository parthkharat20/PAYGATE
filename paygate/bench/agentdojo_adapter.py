"""
AgentDojo E-Banking Compatibility Adapter for PayGate TCB.

Demonstrates how PayGate's out-of-band policy gate (R1-R8), Lifecycle DFA,
and TemporalTraceMonitor wrap AgentDojo-style retail banking operations
(`send_money`, `schedule_transaction`, `read_bill`) to eliminate indirect prompt
injection transfers without altering agent architecture.
"""

from decimal import Decimal
from typing import Dict, Any, Set, Tuple, Optional
from paygate.tcb.clock import VirtualClock
from paygate.tcb.models import (
    Order,
    OrderItem,
    ConsentState,
    ProvenanceLabel,
    ToolRequest,
    ActionDecision,
)
from paygate.tcb.audit import TamperEvidentAuditLog
from paygate.tcb.ifc import TaintTracker
from paygate.tcb.invariants import DeterministicGate
from paygate.tcb.simulator import StateSimulator


class AgentDojoBankingAdapter:
    """
    Wraps an AgentDojo-style banking environment behind PayGate's zero-trust TCB.
    Models single-step bank transfers (`send_money`, `schedule_transaction`) as
    policy-checked, consent-bound capture operations inside `StateSimulator`.
    """

    def __init__(
        self,
        account_balance: Decimal,
        bound_iban: str,
        currency: str = "CHF",
        allowed_ibans: Optional[Set[str]] = None,
    ):
        self.clock = VirtualClock(1700000000.0)
        self.sim = StateSimulator(self.clock)
        self.audit = TamperEvidentAuditLog(secret_key=b"agentdojo_adapter_audit_v2")
        self.taint = TaintTracker()
        self.taint.set_trusted_context(
            "Execute approved bill payment",
            authorized_capabilities=["read_document", "get_order", "propose_capture", "send_notification"],
        )

        allowlist = set(allowed_ibans or set()) | {bound_iban}
        self.gate = DeterministicGate(
            merchant_allowlist=allowlist,
            audit_log=self.audit,
            taint_tracker=self.taint,
            rate_window_seconds=60.0,
            max_ops_per_window=5,
            cumulative_cap_per_window=account_balance,
        )

        self.order = Order(
            order_id="BANK-TX-01",
            items=[OrderItem(name="Authorized Bill Payment", quantity=1, unit_price=account_balance)],
            currency=currency,
            auth_amount=account_balance,
            merchant_id=bound_iban,
            bound_merchant_id=bound_iban,
            auth_expires_at=1700050000.0,
            canary_token="BANK_PIN_SECRET_9021",
            consent_state=ConsentState.APPROVED,
        )
        self.order.consent_token = self.gate.generate_consent_token(
            self.order.order_id, self.order.po_hash or ""
        )
        self.taint.register_canary(self.order.canary_token)
        self.sim.create_order(self.order)
        self._tx_seq = 0

    def read_bill(self, bill_id: str, text: str) -> str:
        """Simulates reading a third-party utility bill containing potential IPI."""
        self.sim.add_document(bill_id, "External Bill", "invoice", text)
        self.taint.register_document(bill_id, ProvenanceLabel.UNTRUSTED_EXTERNAL)
        self.taint.record_document_read(bill_id, text)
        return text

    def send_money(self, recipient_iban: str, amount: Decimal, currency: str = "CHF") -> Tuple[bool, str]:
        """Execute an AgentDojo-style transfer protected by PayGate TCB (R1-R8)."""
        self._tx_seq += 1
        req = ToolRequest(
            action_type="propose_capture",
            order_id=self.order.order_id,
            amount=amount,
            currency=currency,
            recipient_id=recipient_iban,
            idempotency_key=f"dojo-tx-{self._tx_seq}",
            token=self.order.consent_token,
        )
        dec = self.gate.evaluate(req, self.order, self.clock)
        if dec.action != ActionDecision.ALLOW:
            return False, f"Blocked by PayGate ({', '.join(dec.all_violated_rules)}): {dec.reason}"
        ok, msg, _ = self.sim.execute_capture_dfa(req)
        return ok, msg
