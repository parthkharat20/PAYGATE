from decimal import Decimal
from typing import Dict, List
from env.models import Order, OrderStatus, ConsentState, CaptureRecord, RefundRecord


class Ledger:
    """
    In-memory transactional order store and double-entry balance ledger.
    Guarantees state invariants and maintains an outbound message sink
    for data exfiltration checks (canary token leakage).
    """

    def __init__(self):
        self.orders: Dict[str, Order] = {}
        self.captures: Dict[str, List[CaptureRecord]] = {}
        self.refunds: Dict[str, List[RefundRecord]] = {}
        self.outbound_messages: List[Dict[str, str]] = []

    def create_order(self, order: Order) -> None:
        """Add an order to the ledger and seed historical records if balance exists."""
        if order.order_id in self.orders:
            raise ValueError(f"Order {order.order_id} already exists in ledger")
        self.orders[order.order_id] = order
        self.captures[order.order_id] = []
        self.refunds[order.order_id] = []

        # If order starts with prior captured funds, seed historical record for double-entry consistency
        if order.captured_total > Decimal("0.00"):
            from env.models import GateDecision, ActionDecision
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

        # If order starts with prior refunded funds, seed historical record
        if order.refunded_total > Decimal("0.00"):
            from env.models import GateDecision, ActionDecision
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
        """Retrieve an order by ID or raise KeyError."""
        if order_id not in self.orders:
            raise KeyError(f"Order {order_id} not found in ledger")
        return self.orders[order_id]

    def record_capture(self, capture: CaptureRecord) -> None:
        """Record a successful capture, update order captured total and status, and assert invariants."""
        order = self.get_order(capture.order_id)
        order.captured_total += capture.amount
        
        if order.captured_total == order.auth_amount:
            order.status = OrderStatus.FULLY_CAPTURED
        else:
            order.status = OrderStatus.PARTIALLY_CAPTURED

        self.captures[capture.order_id].append(capture)

        # Invariant check
        recorded_sum = sum(c.amount for c in self.captures[capture.order_id])
        assert order.captured_total == recorded_sum, (
            f"Ledger invariant violation: order.captured_total ({order.captured_total}) "
            f"!= recorded captures sum ({recorded_sum})"
        )

    def record_refund(self, refund: RefundRecord) -> None:
        """Record a refund, update order refunded total, and assert invariants."""
        order = self.get_order(refund.order_id)
        order.refunded_total += refund.amount
        self.refunds[refund.order_id].append(refund)

        # Invariant check
        recorded_refunds = sum(r.amount for r in self.refunds[refund.order_id])
        assert order.refunded_total == recorded_refunds, (
            f"Ledger invariant violation: order.refunded_total ({order.refunded_total}) "
            f"!= recorded refunds sum ({recorded_refunds})"
        )

    def update_consent(self, order_id: str, new_consent: ConsentState) -> None:
        """Update buyer consent state on an order."""
        order = self.get_order(order_id)
        order.consent_state = new_consent

    def void_order(self, order_id: str) -> None:
        """Mark an order as VOIDED."""
        order = self.get_order(order_id)
        order.status = OrderStatus.VOIDED

    def get_captures(self, order_id: str) -> List[CaptureRecord]:
        """Return all capture records for an order."""
        return list(self.captures.get(order_id, []))

    def get_refunds(self, order_id: str) -> List[RefundRecord]:
        """Return all refund records for an order."""
        return list(self.refunds.get(order_id, []))

    def send_outbound_message(self, recipient: str, body: str) -> None:
        """Record an outbound message in the sink for exfiltration analysis."""
        self.outbound_messages.append({"recipient": recipient, "body": body})

    def get_outbound_messages(self) -> List[Dict[str, str]]:
        """Return all messages sent by the agent."""
        return list(self.outbound_messages)
