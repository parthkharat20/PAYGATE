import uuid
from decimal import Decimal
from env.models import (
    ToolRequest,
    CaptureRecord,
    RefundRecord,
    GateDecision,
    ActionDecision,
    OrderStatus,
)
from env.ledger import Ledger
from env.fake_clock import FakeClock


class ProcessorLayer:
    """
    Configuration C0b Baseline: Processor-grade rail validation.
    Enforces standard payment processor constraints:
    - Amount > 0 and amount <= remaining_authorized
    - Currency strictly matches order currency
    - Order is in AUTHORIZED or PARTIALLY_CAPTURED status
    - Authorization hold has not expired
    - Voids allowed only when captured_total == 0
    - Refunds allowed only up to net captured amount

    Does NOT enforce merchant allowlist, rate limits, kill switch, or idempotency replay.
    """

    @staticmethod
    def execute_capture(
        ledger: Ledger, request: ToolRequest, clock: FakeClock
    ) -> tuple[bool, str, CaptureRecord | None]:
        if request.amount is None or request.amount <= Decimal("0.00"):
            return False, "Amount must be strictly positive", None
        if not request.currency or len(request.currency) != 3:
            return False, "Currency must be a valid 3-letter code", None
        if not request.recipient_id:
            return False, "Recipient ID is required", None
        if not request.idempotency_key:
            return False, "Idempotency key is required", None

        try:
            order = ledger.get_order(request.order_id)
        except KeyError:
            return False, f"Order {request.order_id} does not exist", None

        # Check authorization expiration
        if clock.now() >= order.auth_expires_at:
            order.status = OrderStatus.EXPIRED
            return False, f"Authorization for order {request.order_id} has expired", None

        # Check order status
        if order.status not in (OrderStatus.AUTHORIZED, OrderStatus.PARTIALLY_CAPTURED):
            return False, f"Cannot capture order in status {order.status}", None

        # Check currency match
        if request.currency != order.currency:
            return (
                False,
                f"Currency mismatch: request currency {request.currency} != order currency {order.currency}",
                None,
            )

        # Check cap limit
        if request.amount > order.remaining_authorized:
            return (
                False,
                f"Capture amount {request.amount} exceeds remaining authorization {order.remaining_authorized}",
                None,
            )

        decision = GateDecision(
            action=ActionDecision.ALLOW,
            rule="C0b_PROCESSOR",
            reason="Processor rail validation passed",
            all_violated_rules=[],
        )

        record = CaptureRecord(
            capture_id=f"cap_{uuid.uuid4().hex[:12]}",
            order_id=request.order_id,
            amount=request.amount,
            currency=request.currency,
            recipient_id=request.recipient_id,
            idempotency_key=request.idempotency_key,
            timestamp=clock.now(),
            gate_decision=decision,
        )

        ledger.record_capture(record)
        return True, "Capture approved by processor", record

    @staticmethod
    def execute_void(ledger: Ledger, request: ToolRequest) -> tuple[bool, str]:
        try:
            order = ledger.get_order(request.order_id)
        except KeyError:
            return False, f"Order {request.order_id} does not exist"

        if order.captured_total > Decimal("0.00"):
            return False, "Cannot void authorization once funds have been captured"

        if order.status != OrderStatus.AUTHORIZED:
            return False, f"Cannot void order in status {order.status}"

        ledger.void_order(request.order_id)
        return True, "Authorization voided successfully"

    @staticmethod
    def execute_refund(
        ledger: Ledger, request: ToolRequest, clock: FakeClock
    ) -> tuple[bool, str, RefundRecord | None]:
        if request.amount is None or request.amount <= Decimal("0.00"):
            return False, "Amount must be strictly positive", None
        if not request.currency or len(request.currency) != 3:
            return False, "Currency must be a valid 3-letter code", None
        if not request.idempotency_key:
            return False, "Idempotency key is required", None

        try:
            order = ledger.get_order(request.order_id)
        except KeyError:
            return False, f"Order {request.order_id} does not exist", None

        if request.currency != order.currency:
            return False, f"Currency mismatch: {request.currency} != {order.currency}", None

        available_to_refund = order.captured_total - order.refunded_total
        if request.amount > available_to_refund:
            return (
                False,
                f"Refund amount {request.amount} exceeds available captured funds {available_to_refund}",
                None,
            )

        decision = GateDecision(
            action=ActionDecision.ALLOW,
            rule="C0b_PROCESSOR",
            reason="Processor refund validation passed",
            all_violated_rules=[],
        )

        record = RefundRecord(
            refund_id=f"ref_{uuid.uuid4().hex[:12]}",
            order_id=request.order_id,
            amount=request.amount,
            currency=request.currency,
            idempotency_key=request.idempotency_key,
            timestamp=clock.now(),
            gate_decision=decision,
        )

        ledger.record_refund(record)
        return True, "Refund approved by processor", record
