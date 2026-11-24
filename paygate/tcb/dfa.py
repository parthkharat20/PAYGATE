"""
Deterministic Finite Automaton (DFA) for B2B Payment Lifecycles.
Formal state machine enforcing state-transition invariants out-of-band.
"""

from decimal import Decimal
from typing import Tuple
from paygate.tcb.models import Order, OrderStatus
from paygate.tcb.clock import VirtualClock


class DFAStateTransitionError(Exception):
    """Raised when an illegal lifecycle transition is attempted."""
    pass


class PaymentDFA:
    """
    Formal State Machine for Payment Authorizations:
      CREATED -> AUTHORIZED -> PARTIALLY_CAPTURED -> SETTLED -> REFUNDED
                            ↘ VOIDED              ↘ REFUNDED (if partial refund equals captured)
            AUTHORIZED -> EXPIRED (on clock tick past auth_expires_at)
    """

    VALID_TRANSITIONS = {
        OrderStatus.CREATED: {"authorize"},
        OrderStatus.AUTHORIZED: {"capture", "void", "expire"},
        OrderStatus.PARTIALLY_CAPTURED: {"capture", "refund"},
        OrderStatus.SETTLED: {"refund"},
        OrderStatus.VOIDED: set(),
        OrderStatus.EXPIRED: set(),
        OrderStatus.REFUNDED: set(),
    }

    @classmethod
    def check_and_expire(cls, order: Order, clock: VirtualClock) -> bool:
        """
        Check if an AUTHORIZED order has expired based on the VirtualClock.
        Transitions state to EXPIRED if past deadline.
        Returns True if transition occurred.
        """
        if order.status == OrderStatus.AUTHORIZED:
            if clock.now() > order.auth_expires_at:
                order.status = OrderStatus.EXPIRED
                return True
        return False

    @classmethod
    def transition_authorize(
        cls, order: Order, auth_amount: Decimal, ttl_seconds: float, clock: VirtualClock
    ) -> OrderStatus:
        if order.status != OrderStatus.CREATED:
            raise DFAStateTransitionError(
                f"Cannot authorize order in status {order.status}. Must be CREATED."
            )
        if auth_amount <= Decimal("0.00"):
            raise DFAStateTransitionError("Authorization amount must be strictly positive.")

        order.auth_amount = auth_amount
        order.auth_expires_at = clock.now() + ttl_seconds
        order.status = OrderStatus.AUTHORIZED
        return order.status

    @classmethod
    def transition_capture(
        cls, order: Order, amount: Decimal, clock: VirtualClock
    ) -> OrderStatus:
        cls.check_and_expire(order, clock)

        if order.status not in (OrderStatus.AUTHORIZED, OrderStatus.PARTIALLY_CAPTURED):
            raise DFAStateTransitionError(
                f"Illegal DFA capture transition from status {order.status}. "
                f"Capture allowed ONLY from AUTHORIZED or PARTIALLY_CAPTURED."
            )

        if clock.now() > order.auth_expires_at:
            order.status = OrderStatus.EXPIRED
            raise DFAStateTransitionError(
                f"Authorization expired at t={order.auth_expires_at} (current t={clock.now()})."
            )

        if amount <= Decimal("0.00"):
            raise DFAStateTransitionError(f"Capture amount must be > 0. Received: {amount}")

        new_captured = order.captured_total + amount
        if new_captured > order.auth_amount:
            raise DFAStateTransitionError(
                f"Capture amount {amount} exceeds remaining authorization {order.remaining_authorized}."
            )

        if new_captured == order.auth_amount:
            order.status = OrderStatus.SETTLED
        else:
            order.status = OrderStatus.PARTIALLY_CAPTURED

        return order.status

    @classmethod
    def transition_void(cls, order: Order, clock: VirtualClock) -> OrderStatus:
        cls.check_and_expire(order, clock)

        if order.status != OrderStatus.AUTHORIZED:
            raise DFAStateTransitionError(
                f"Illegal void transition from status {order.status}. Void allowed ONLY from AUTHORIZED."
            )

        if order.captured_total > Decimal("0.00"):
            raise DFAStateTransitionError(
                f"Cannot void order with non-zero captured total ({order.captured_total})."
            )

        order.status = OrderStatus.VOIDED
        return order.status

    @classmethod
    def transition_refund(
        cls, order: Order, amount: Decimal, clock: VirtualClock
    ) -> OrderStatus:
        cls.check_and_expire(order, clock)

        if order.status not in (OrderStatus.PARTIALLY_CAPTURED, OrderStatus.SETTLED):
            raise DFAStateTransitionError(
                f"Illegal refund transition from status {order.status}. "
                f"Refund allowed ONLY from PARTIALLY_CAPTURED or SETTLED."
            )

        if amount <= Decimal("0.00"):
            raise DFAStateTransitionError(f"Refund amount must be > 0. Received: {amount}")

        new_refunded = order.refunded_total + amount
        if new_refunded > order.captured_total:
            raise DFAStateTransitionError(
                f"Refund amount {amount} exceeds net refundable captured funds {order.refundable_amount}."
            )

        if new_refunded == order.captured_total:
            order.status = OrderStatus.REFUNDED
        # Else remains in current PARTIALLY_CAPTURED or SETTLED

        return order.status
