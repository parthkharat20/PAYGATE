"""
Unit and Property Tests for the MFOTL-Inspired Temporal Trace Monitor.
"""

from decimal import Decimal
from paygate.tcb.monitor import TemporalTraceMonitor, TraceEvent


def test_trace_monitor_clean_trace():
    mon = TemporalTraceMonitor(window_seconds=60.0, max_ops_per_window=5, max_volume_per_window=Decimal("1000.00"))
    mon.record(TraceEvent(timestamp=10.0, event_type="capture", order_id="ORD-1", amount=Decimal("200.00"), decision="ALLOW"))
    mon.record(TraceEvent(timestamp=20.0, event_type="refund", order_id="ORD-1", amount=Decimal("50.00"), decision="ALLOW"))

    ok, violations = mon.verify_trace({"ORD-1": Decimal("500.00")})
    assert ok is True
    assert violations == []


def test_trace_monitor_detects_post_void_capture():
    mon = TemporalTraceMonitor()
    mon.record(TraceEvent(timestamp=10.0, event_type="void", order_id="ORD-1", decision="ALLOW"))
    mon.record(TraceEvent(timestamp=15.0, event_type="capture", order_id="ORD-1", amount=Decimal("100.00"), decision="ALLOW"))

    ok, violations = mon.verify_trace({"ORD-1": Decimal("500.00")})
    assert ok is False
    assert any("P3 Violation" in v for v in violations)


def test_trace_monitor_detects_untrusted_escalation():
    mon = TemporalTraceMonitor()
    mon.record(TraceEvent(timestamp=10.0, event_type="read_untrusted", order_id="SESSION", decision="ALLOW"))
    mon.record(TraceEvent(timestamp=12.0, event_type="set_consent", order_id="ORD-1", consent_state="APPROVED", decision="ALLOW"))

    ok, violations = mon.verify_trace({"ORD-1": Decimal("500.00")})
    assert ok is False
    assert any("P5 Violation" in v for v in violations)


def test_trace_monitor_detects_sliding_window_breach():
    mon = TemporalTraceMonitor(window_seconds=60.0, max_ops_per_window=2, max_volume_per_window=Decimal("500.00"))
    mon.record(TraceEvent(timestamp=10.0, event_type="capture", order_id="ORD-1", amount=Decimal("300.00"), decision="ALLOW"))
    mon.record(TraceEvent(timestamp=20.0, event_type="capture", order_id="ORD-1", amount=Decimal("300.00"), decision="ALLOW"))

    ok, violations = mon.verify_trace({"ORD-1": Decimal("1000.00")})
    assert ok is False
    assert any("P4 Violation" in v for v in violations)


def test_trace_monitor_online_check_step_blocks_post_void_capture():
    from paygate.tcb.clock import VirtualClock
    from paygate.tcb.models import Order, OrderItem, ConsentState, ToolRequest, ActionDecision
    from paygate.tcb.audit import TamperEvidentAuditLog
    from paygate.tcb.ifc import TaintTracker
    from paygate.tcb.invariants import DeterministicGate

    clock = VirtualClock(1000.0)
    taint = TaintTracker()
    taint.set_trusted_context("void capture", authorized_capabilities=["void_authorization", "propose_capture"])
    gate = DeterministicGate(merchant_allowlist={"MERCH-PRIMARY"}, audit_log=TamperEvidentAuditLog(), taint_tracker=taint)
    order = Order(
        order_id="ORD-MON-1",
        items=[OrderItem(name="Item", quantity=1, unit_price=Decimal("500.00"))],
        currency="EUR",
        auth_amount=Decimal("500.00"),
        merchant_id="MERCH-PRIMARY",
        auth_expires_at=2000.0,
        canary_token="c1",
        consent_state=ConsentState.APPROVED,
    )
    order.consent_token = gate.generate_consent_token(order.order_id, order.po_hash or "")

    dec_void = gate.evaluate(ToolRequest(action_type="void_authorization", order_id="ORD-MON-1", idempotency_key="v1", token=order.consent_token), order, clock)
    assert dec_void.action == ActionDecision.ALLOW

    # Subsequent capture must be caught online by TemporalTraceMonitor (P3)
    dec_cap = gate.evaluate(
        ToolRequest(action_type="propose_capture", order_id="ORD-MON-1", amount=Decimal("100.00"), currency="EUR", recipient_id="MERCH-PRIMARY", idempotency_key="c1", token=order.consent_token),
        order,
        clock,
    )
    assert dec_cap.action == ActionDecision.BLOCK
    assert "TRACE_MONITOR" in dec_cap.all_violated_rules
