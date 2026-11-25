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
