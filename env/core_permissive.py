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


class PermissiveCore:
    """
    Configuration C0a Baseline: Permissive execution engine.
    Executes whatever the agent proposes with only basic type and sign checks.
    Does NOT enforce cap limits, currency matches, allowlists, or consent states.
    Allows overcaptures and unapproved transfers to succeed so the baseline is not rigged.
    """

    @staticmethod
    def execute_capture(
        ledger: Ledger, request: ToolRequest, clock: FakeClock
    ) -> tuple[bool, str, CaptureRecord | None]:
        if request.amount is None or request.amount <= Decimal("0.00"):
            return False, "Amount must be strictly positive", None
        if not request.currency or len(request.currency) != 3:
            return False, "Currency must be a 3-letter code", None
        if not request.recipient_id:
            return False, "Recipient ID is required", None
        if not request.idempotency_key:
            return False, "Idempotency key is required", None

        # Permissive: does not check order remaining balance or currency match
        decision = GateDecision(
            action=ActionDecision.ALLOW,
            rule="C0a_PERMISSIVE",
            reason="Permissive baseline allowed action",
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

        # Mutate ledger directly without cap validation
        order = ledger.get_order(request.order_id)
        order.captured_total += record.amount
        if order.captured_total >= order.auth_amount:
            order.status = OrderStatus.FULLY_CAPTURED
        else:
            order.status = OrderStatus.PARTIALLY_CAPTURED
        ledger.captures[request.order_id].append(record)

        return True, "Executed in permissive core", record

    @staticmethod
    def execute_void(ledger: Ledger, request: ToolRequest) -> tuple[bool, str]:
        ledger.void_order(request.order_id)
        return True, "Order marked void in permissive core"

    @staticmethod
    def execute_refund(
        ledger: Ledger, request: ToolRequest, clock: FakeClock
    ) -> tuple[bool, str, RefundRecord | None]:
        if request.amount is None or request.amount <= Decimal("0.00"):
            return False, "Amount must be strictly positive", None
        if not request.currency or len(request.currency) != 3:
            return False, "Currency must be a 3-letter code", None
        if not request.idempotency_key:
            return False, "Idempotency key is required", None

        decision = GateDecision(
            action=ActionDecision.ALLOW,
            rule="C0a_PERMISSIVE",
            reason="Permissive baseline allowed refund",
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

        order = ledger.get_order(request.order_id)
        order.refunded_total += record.amount
        ledger.refunds[request.order_id].append(record)

        return True, "Executed refund in permissive core", record
