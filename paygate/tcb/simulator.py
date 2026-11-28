"""
Two-Layer Deterministic State Simulator (ERP State + Payment Rail State).
Integrates PaymentDFA, Invariants, and Double-Entry Consistency.
"""

from decimal import Decimal
from typing import Dict, List, Optional, Tuple, Any
from paygate.tcb.models import (
    Order,
    OrderStatus,
    ConsentState,
    CaptureRecord,
    RefundRecord,
    ToolRequest,
    GateDecision,
    ActionDecision,
    ProvenanceLabel,
)
from paygate.tcb.clock import VirtualClock
from paygate.tcb.dfa import PaymentDFA, DFAStateTransitionError
from paygate.tcb.invariants import DeterministicGate


class StateSimulator:
    """
    Two-Layer Deterministic State Simulator:
    - Layer 1 (ERP State): Purchase orders, buyer consents, line items, external documents, outbound messages.
    - Layer 2 (Payment Rail State): Authorizations, settlement captures, refunds, DFA state transitions.
    """

    def __init__(self, clock: Optional[VirtualClock] = None):
        self.clock: VirtualClock = clock or VirtualClock()
        self.orders: Dict[str, Order] = {}
        self.captures: Dict[str, List[CaptureRecord]] = {}
        self.refunds: Dict[str, List[RefundRecord]] = {}
        self.documents: Dict[str, Dict[str, Any]] = {}
        self.outbound_messages: List[Dict[str, str]] = []
        self._cap_seq: int = 0
        self._ref_seq: int = 0

    def add_document(self, doc_id: str, title: str, doc_type: str, content: str) -> None:
        self.documents[doc_id] = {
            "doc_id": doc_id,
            "title": title,
            "doc_type": doc_type,
            "content": content,
        }

    def get_document(self, doc_id: str) -> Optional[Dict[str, Any]]:
        return self.documents.get(doc_id)

    def create_order(self, order: Order) -> None:
        if order.order_id in self.orders:
            raise ValueError(f"Order {order.order_id} already exists.")
        self.orders[order.order_id] = order
        self.captures[order.order_id] = []
        self.refunds[order.order_id] = []

        # Seed historical records for consistency if initialized with pre-existing balance
        if order.captured_total > Decimal("0.00"):
            self.captures[order.order_id].append(
                CaptureRecord(
                    capture_id=f"hist_cap_{order.order_id}",
                    order_id=order.order_id,
                    amount=order.captured_total,
                    currency=order.currency,
                    recipient_id=order.merchant_id,
                    idempotency_key=f"hist_idem_{order.order_id}",
                    timestamp=0.0,
                    gate_decision=GateDecision(
                        action=ActionDecision.ALLOW,
                        rule="HISTORICAL_SEED",
                        reason="Pre-existing captured balance",
                        all_violated_rules=[],
                    ),
                )
            )

        if order.refunded_total > Decimal("0.00"):
            self.refunds[order.order_id].append(
                RefundRecord(
                    refund_id=f"hist_ref_{order.order_id}",
                    order_id=order.order_id,
                    amount=order.refunded_total,
                    currency=order.currency,
                    idempotency_key=f"hist_ref_idem_{order.order_id}",
                    timestamp=0.0,
                    gate_decision=GateDecision(
                        action=ActionDecision.ALLOW,
                        rule="HISTORICAL_SEED",
                        reason="Pre-existing refunded balance",
                        all_violated_rules=[],
                    ),
                )
            )

    def get_order(self, order_id: str) -> Order:
        if order_id not in self.orders:
            raise KeyError(f"Order {order_id} not found in simulator.")
        return self.orders[order_id]

    def tick(self, seconds: float = 1.0) -> None:
        """Advance time and trigger DFA expiration checks on all active holds."""
        self.clock.advance(seconds)
        for order in self.orders.values():
            PaymentDFA.check_and_expire(order, self.clock)

    def execute_capture_raw(
        self, request: ToolRequest
    ) -> Tuple[bool, str, Optional[CaptureRecord]]:
        """Raw capture without invariants or DFA checks (used by permissive C0a baseline)."""
        order = self.get_order(request.order_id)
        amount = request.amount or Decimal("0.00")
        order.captured_total += amount

        self._cap_seq += 1
        rec = CaptureRecord(
            capture_id=f"cap_raw_{self._cap_seq:06d}",
            order_id=request.order_id,
            amount=amount,
            currency=request.currency or order.currency,
            recipient_id=request.recipient_id or order.merchant_id,
            idempotency_key=request.idempotency_key or "no_key",
            timestamp=self.clock.now(),
            gate_decision=GateDecision(
                action=ActionDecision.ALLOW,
                rule="RAW_C0A",
                reason="Unconstrained execution",
                all_violated_rules=[],
            ),
        )
        self.captures[request.order_id].append(rec)
        return True, "Raw capture recorded", rec

    def execute_capture_dfa(
        self, request: ToolRequest
    ) -> Tuple[bool, str, Optional[CaptureRecord]]:
        """Standard processor execution enforcing state machine and monetary bounds."""
        order = self.get_order(request.order_id)
        if request.amount is None or request.amount <= Decimal("0.00"):
            return False, "Capture amount must be strictly positive", None
        if request.currency != order.currency:
            return False, f"Currency mismatch: {request.currency} != {order.currency}", None

        try:
            PaymentDFA.transition_capture(order, request.amount, self.clock)
        except DFAStateTransitionError as e:
            return False, str(e), None

        order.captured_total += request.amount

        self._cap_seq += 1
        rec = CaptureRecord(
            capture_id=f"cap_dfa_{self._cap_seq:06d}",
            order_id=request.order_id,
            amount=request.amount,
            currency=request.currency,
            recipient_id=request.recipient_id or order.merchant_id,
            idempotency_key=request.idempotency_key or f"idem_{self._cap_seq:06d}",
            timestamp=self.clock.now(),
            gate_decision=GateDecision(
                action=ActionDecision.ALLOW,
                rule="DFA_PROCESSOR",
                reason="DFA transition allowed",
                all_violated_rules=[],
            ),
        )
        self.captures[request.order_id].append(rec)
        return True, "Capture approved and settled in DFA", rec

    def execute_void_dfa(self, request: ToolRequest) -> Tuple[bool, str]:
        order = self.get_order(request.order_id)
        try:
            PaymentDFA.transition_void(order, self.clock)
            return True, "Authorization voided successfully"
        except DFAStateTransitionError as e:
            return False, str(e)

    def execute_refund_dfa(
        self, request: ToolRequest
    ) -> Tuple[bool, str, Optional[RefundRecord]]:
        order = self.get_order(request.order_id)
        if request.amount is None or request.amount <= Decimal("0.00"):
            return False, "Refund amount must be strictly positive", None
        if request.currency != order.currency:
            return False, f"Currency mismatch: {request.currency} != {order.currency}", None

        try:
            PaymentDFA.transition_refund(order, request.amount, self.clock)
        except DFAStateTransitionError as e:
            return False, str(e), None

        order.refunded_total += request.amount

        self._ref_seq += 1
        rec = RefundRecord(
            refund_id=f"ref_{self._ref_seq:06d}",
            order_id=request.order_id,
            amount=request.amount,
            currency=request.currency,
            idempotency_key=request.idempotency_key or f"idem_ref_{self._ref_seq:06d}",
            timestamp=self.clock.now(),
            gate_decision=GateDecision(
                action=ActionDecision.ALLOW,
                rule="DFA_PROCESSOR",
                reason="DFA refund transition allowed",
                all_violated_rules=[],
            ),
        )
        self.refunds[request.order_id].append(rec)
        return True, "Refund processed", rec

    def update_consent(self, order_id: str, new_state: ConsentState) -> None:
        order = self.get_order(order_id)
        order.consent_state = new_state

    def send_outbound_message(self, recipient: str, body: str) -> None:
        self.outbound_messages.append({"recipient": recipient, "body": body})

    def get_outbound_messages(self) -> List[Dict[str, str]]:
        return list(self.outbound_messages)
