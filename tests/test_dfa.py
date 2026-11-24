"""
Formal Property Tests for the Payment Lifecycle DFA.
"""

import pytest
from decimal import Decimal
from paygate.tcb.clock import VirtualClock
from paygate.tcb.models import Order, OrderStatus, OrderItem, ConsentState
from paygate.tcb.dfa import PaymentDFA, DFAStateTransitionError


@pytest.fixture
def base_order():
    return Order(
        order_id="ORD-DFA-01",
        items=[OrderItem(name="Sensor", quantity=2, unit_price=Decimal("100.00"))],
        currency="EUR",
        auth_amount=Decimal("200.00"),
        merchant_id="MERCH-PRIMARY",
        auth_expires_at=1700010000.0,
        canary_token="canary_123",
        status=OrderStatus.AUTHORIZED,
        consent_state=ConsentState.APPROVED,
    )


def test_dfa_partial_capture_to_settled(base_order):
    clock = VirtualClock(1700000000.0)

    # 1st capture: 50 EUR -> PARTIALLY_CAPTURED
    s1 = PaymentDFA.transition_capture(base_order, Decimal("50.00"), clock)
    base_order.captured_total += Decimal("50.00")
    assert s1 == OrderStatus.PARTIALLY_CAPTURED
    assert base_order.status == OrderStatus.PARTIALLY_CAPTURED

    # 2nd capture: 150 EUR -> SETTLED
    s2 = PaymentDFA.transition_capture(base_order, Decimal("150.00"), clock)
    base_order.captured_total += Decimal("150.00")
    assert s2 == OrderStatus.SETTLED
    assert base_order.status == OrderStatus.SETTLED


def test_dfa_overcapture_rejected(base_order):
    clock = VirtualClock(1700000000.0)
    with pytest.raises(DFAStateTransitionError, match="exceeds remaining authorization"):
        PaymentDFA.transition_capture(base_order, Decimal("250.00"), clock)


def test_dfa_void_from_authorized(base_order):
    clock = VirtualClock(1700000000.0)
    assert base_order.captured_total == Decimal("0.00")
    s = PaymentDFA.transition_void(base_order, clock)
    assert s == OrderStatus.VOIDED


def test_dfa_void_fails_if_captured(base_order):
    clock = VirtualClock(1700000000.0)
    PaymentDFA.transition_capture(base_order, Decimal("50.00"), clock)
    base_order.captured_total += Decimal("50.00")

    # Void fails because status is now PARTIALLY_CAPTURED (and captured_total > 0)
    with pytest.raises(DFAStateTransitionError, match="Illegal void transition|Cannot void order"):
        PaymentDFA.transition_void(base_order, clock)


def test_dfa_refund_lifecycle(base_order):
    clock = VirtualClock(1700000000.0)
    # Fully settle order first
    PaymentDFA.transition_capture(base_order, Decimal("200.00"), clock)
    base_order.captured_total += Decimal("200.00")
    assert base_order.status == OrderStatus.SETTLED

    # Partial refund 50 EUR
    PaymentDFA.transition_refund(base_order, Decimal("50.00"), clock)
    base_order.refunded_total += Decimal("50.00")
    assert base_order.status == OrderStatus.SETTLED  # still settled until fully refunded

    # Over-refund fails
    with pytest.raises(DFAStateTransitionError, match="exceeds net refundable"):
        PaymentDFA.transition_refund(base_order, Decimal("200.00"), clock)

    # Remaining refund 150 EUR -> REFUNDED
    s_final = PaymentDFA.transition_refund(base_order, Decimal("150.00"), clock)
    base_order.refunded_total += Decimal("150.00")
    assert s_final == OrderStatus.REFUNDED
    assert base_order.status == OrderStatus.REFUNDED


def test_dfa_clock_expiry(base_order):
    clock = VirtualClock(1700000000.0)
    # Advance clock past auth_expires_at (1700010000.0)
    clock.set(1700010001.0)

    # Attempt capture should fail and transition order to EXPIRED
    with pytest.raises(DFAStateTransitionError, match="EXPIRED|expired"):
        PaymentDFA.transition_capture(base_order, Decimal("50.00"), clock)

    assert base_order.status == OrderStatus.EXPIRED
