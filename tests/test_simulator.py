"""
Unit and Integration Tests for Two-Layer State Simulator.
"""

import pytest
from decimal import Decimal
from paygate.tcb.clock import VirtualClock
from paygate.tcb.models import Order, OrderItem, ToolRequest, ConsentState, OrderStatus
from paygate.tcb.simulator import StateSimulator


def test_simulator_order_creation_and_dfa_capture():
    clock = VirtualClock(1700000000.0)
    sim = StateSimulator(clock)

    order = Order(
        order_id="ORD-SIM-01",
        items=[OrderItem(name="Device", quantity=2, unit_price=Decimal("150.00"))],
        currency="EUR",
        auth_amount=Decimal("300.00"),
        merchant_id="MERCH-PRIMARY",
        auth_expires_at=1700050000.0,
        canary_token="canary_xyz",
        consent_state=ConsentState.APPROVED,
    )
    sim.create_order(order)

    # Execute DFA capture
    req = ToolRequest(
        action_type="propose_capture",
        order_id="ORD-SIM-01",
        amount=Decimal("150.00"),
        currency="EUR",
        recipient_id="MERCH-PRIMARY",
        idempotency_key="sim_cap_1",
    )
    ok, msg, rec = sim.execute_capture_dfa(req)
    assert ok is True
    assert rec is not None
    assert rec.amount == Decimal("150.00")
    assert order.captured_total == Decimal("150.00")
    assert order.status == OrderStatus.PARTIALLY_CAPTURED


def test_simulator_tick_and_expiry():
    clock = VirtualClock(1700000000.0)
    sim = StateSimulator(clock)

    order = Order(
        order_id="ORD-SIM-02",
        items=[OrderItem(name="Device", quantity=1, unit_price=Decimal("100.00"))],
        currency="EUR",
        auth_amount=Decimal("100.00"),
        merchant_id="MERCH-PRIMARY",
        auth_expires_at=1700001000.0,
        canary_token="canary_xyz",
        consent_state=ConsentState.APPROVED,
    )
    sim.create_order(order)

    # Tick clock forward past 1700001000.0
    sim.tick(2000.0)
    assert order.status == OrderStatus.EXPIRED

    # Capture should now be rejected by DFA
    req = ToolRequest(
        action_type="propose_capture",
        order_id="ORD-SIM-02",
        amount=Decimal("100.00"),
        currency="EUR",
        recipient_id="MERCH-PRIMARY",
        idempotency_key="sim_cap_2",
    )
    ok, msg, _ = sim.execute_capture_dfa(req)
    assert ok is False
    assert "expired" in msg.lower() or "illegal dfa capture transition" in msg.lower()
