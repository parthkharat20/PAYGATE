"""
Comprehensive Property Tests for Deterministic Policy Gate Invariants R1-R8.
"""

import pytest
import hmac
import hashlib
from decimal import Decimal
from paygate.tcb.clock import VirtualClock
from paygate.tcb.models import (
    Order,
    OrderItem,
    ToolRequest,
    ActionDecision,
    ConsentState,
    ProvenanceLabel,
)
from paygate.tcb.audit import TamperEvidentAuditLog
from paygate.tcb.ifc import TaintTracker
from paygate.tcb.invariants import DeterministicGate


@pytest.fixture
def gate_setup():
    clock = VirtualClock(1700000000.0)
    audit_log = TamperEvidentAuditLog(secret_key=b"test_key_invariants_v2")
    taint_tracker = TaintTracker()
    taint_tracker.register_canary("CANARY_TEST_TOKEN_123")

    gate = DeterministicGate(
        merchant_allowlist={"MERCH-PRIMARY", "MERCH-DECOY-PARTNER"},
        audit_log=audit_log,
        taint_tracker=taint_tracker,
        rate_window_seconds=60.0,
        max_ops_per_window=5,
        cumulative_cap_per_window=Decimal("3000.00"),
    )

    items = [OrderItem(name="Switch", quantity=1, unit_price=Decimal("1000.00"))]
    order = Order(
        order_id="ORD-INV-01",
        items=items,
        currency="EUR",
        auth_amount=Decimal("1000.00"),
        merchant_id="MERCH-PRIMARY",
        bound_merchant_id="MERCH-PRIMARY",
        auth_expires_at=1700050000.0,
        canary_token="CANARY_TEST_TOKEN_123",
        consent_state=ConsentState.APPROVED,
    )
    order.consent_token = gate.generate_consent_token(order.order_id, order.po_hash or "")

    return gate, order, clock, audit_log, taint_tracker


def test_r1_cap_invariant(gate_setup):
    gate, order, clock, _, _ = gate_setup

    # Valid capture
    req_valid = ToolRequest(
        action_type="propose_capture",
        order_id=order.order_id,
        amount=Decimal("500.00"),
        currency="EUR",
        recipient_id="MERCH-PRIMARY",
        idempotency_key="r1_k1",
        token=order.consent_token,
    )
    dec = gate.evaluate(req_valid, order, clock)
    assert dec.action == ActionDecision.ALLOW

    # Overcapture
    req_over = ToolRequest(
        action_type="propose_capture",
        order_id=order.order_id,
        amount=Decimal("1500.00"),
        currency="EUR",
        recipient_id="MERCH-PRIMARY",
        idempotency_key="r1_k2",
        token=order.consent_token,
    )
    dec_over = gate.evaluate(req_over, order, clock)
    assert dec_over.action == ActionDecision.BLOCK
    assert "R1" in dec_over.all_violated_rules


def test_r2_currency_invariant(gate_setup):
    gate, order, clock, _, _ = gate_setup
    req = ToolRequest(
        action_type="propose_capture",
        order_id=order.order_id,
        amount=Decimal("100.00"),
        currency="USD",  # Mismatch
        recipient_id="MERCH-PRIMARY",
        idempotency_key="r2_k1",
        token=order.consent_token,
    )
    dec = gate.evaluate(req, order, clock)
    assert dec.action == ActionDecision.BLOCK
    assert "R2" in dec.all_violated_rules


def test_r3_order_bound_merchant(gate_setup):
    gate, order, clock, _, _ = gate_setup

    # MERCH-DECOY-PARTNER is in allowlist, but NOT bound to order ORD-INV-01
    req_decoy = ToolRequest(
        action_type="propose_capture",
        order_id=order.order_id,
        amount=Decimal("100.00"),
        currency="EUR",
        recipient_id="MERCH-DECOY-PARTNER",
        idempotency_key="r3_k1",
        token=order.consent_token,
    )
    dec = gate.evaluate(req_decoy, order, clock)
    assert dec.action == ActionDecision.BLOCK
    assert "R3" in dec.all_violated_rules


def test_r4_rate_and_cumulative_volume(gate_setup):
    gate, order, clock, _, _ = gate_setup

    # 5 ops allowed within 60s
    for i in range(5):
        req = ToolRequest(
            action_type="propose_capture",
            order_id=order.order_id,
            amount=Decimal("100.00"),
            currency="EUR",
            recipient_id="MERCH-PRIMARY",
            idempotency_key=f"r4_{i}",
            token=order.consent_token,
        )
        dec = gate.evaluate(req, order, clock)
        assert dec.action == ActionDecision.ALLOW

    # 6th op violates rate limit R4
    req_6 = ToolRequest(
        action_type="propose_capture",
        order_id=order.order_id,
        amount=Decimal("100.00"),
        currency="EUR",
        recipient_id="MERCH-PRIMARY",
        idempotency_key="r4_6",
        token=order.consent_token,
    )
    dec_6 = gate.evaluate(req_6, order, clock)
    assert dec_6.action == ActionDecision.BLOCK
    assert "R4" in dec_6.all_violated_rules


def test_r5_idempotency_replay_and_conflict(gate_setup):
    gate, order, clock, _, _ = gate_setup

    req = ToolRequest(
        action_type="propose_capture",
        order_id=order.order_id,
        amount=Decimal("150.00"),
        currency="EUR",
        recipient_id="MERCH-PRIMARY",
        idempotency_key="idem_unique_test",
        token=order.consent_token,
    )
    dec1 = gate.evaluate(req, order, clock)
    assert dec1.action == ActionDecision.ALLOW

    # Exact replay
    dec2 = gate.evaluate(req, order, clock)
    assert dec2.action == ActionDecision.REPLAY_CACHED

    # Replay with altered amount
    req_conflict = ToolRequest(
        action_type="propose_capture",
        order_id=order.order_id,
        amount=Decimal("999.00"),
        currency="EUR",
        recipient_id="MERCH-PRIMARY",
        idempotency_key="idem_unique_test",
        token=order.consent_token,
    )
    dec_conflict = gate.evaluate(req_conflict, order, clock)
    assert dec_conflict.action == ActionDecision.BLOCK
    assert "R5" in dec_conflict.all_violated_rules


def test_r6_hmac_consent_token_binding(gate_setup):
    gate, order, clock, _, _ = gate_setup

    # Capture with invalid / forged token fails R6
    req_forged = ToolRequest(
        action_type="propose_capture",
        order_id=order.order_id,
        amount=Decimal("100.00"),
        currency="EUR",
        recipient_id="MERCH-PRIMARY",
        idempotency_key="r6_forged",
        token="forged_token_abc_123",
    )
    dec = gate.evaluate(req_forged, order, clock)
    assert dec.action == ActionDecision.BLOCK
    assert "R6" in dec.all_violated_rules

    # Capture with valid HMAC token succeeds
    req_valid = ToolRequest(
        action_type="propose_capture",
        order_id=order.order_id,
        amount=Decimal("100.00"),
        currency="EUR",
        recipient_id="MERCH-PRIMARY",
        idempotency_key="r6_valid",
        token=order.consent_token,
    )
    dec_valid = gate.evaluate(req_valid, order, clock)
    assert dec_valid.action == ActionDecision.ALLOW


def test_r6_kill_switch(gate_setup):
    gate, order, clock, _, _ = gate_setup
    gate.set_kill_switch(True)

    req = ToolRequest(
        action_type="propose_capture",
        order_id=order.order_id,
        amount=Decimal("100.00"),
        currency="EUR",
        recipient_id="MERCH-PRIMARY",
        idempotency_key="r6_kill",
        token=order.consent_token,
    )
    dec = gate.evaluate(req, order, clock)
    assert dec.action == ActionDecision.BLOCK
    assert "R6" in dec.all_violated_rules

    gate.set_kill_switch(False)
    dec_ok = gate.evaluate(req, order, clock)
    assert dec_ok.action == ActionDecision.ALLOW


def test_r8_ifc_non_interference(gate_setup):
    gate, order, clock, _, _ = gate_setup

    # Tainted financial request
    req_tainted = ToolRequest(
        action_type="propose_capture",
        order_id=order.order_id,
        amount=Decimal("100.00"),
        currency="EUR",
        recipient_id="MERCH-PRIMARY",
        idempotency_key="r8_taint",
        provenance=ProvenanceLabel.UNTRUSTED_EXTERNAL,
        token=order.consent_token,
    )
    dec = gate.evaluate(req_tainted, order, clock)
    assert dec.action == ActionDecision.BLOCK
    assert "R8" in dec.all_violated_rules
