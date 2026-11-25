"""
High-Resolution Gate Latency Microbenchmark for PayGate TCB.
Measures pure decision overhead (R1-R6, R8) and decision + HMAC audit log write (R1-R8).
"""

import time
import platform
import numpy as np
from decimal import Decimal

from paygate.tcb.clock import VirtualClock
from paygate.tcb.models import Order, OrderItem, ConsentState, ToolRequest
from paygate.tcb.audit import TamperEvidentAuditLog
from paygate.tcb.ifc import TaintTracker
from paygate.tcb.invariants import DeterministicGate


def run_latency_bench(warmup: int = 200, iterations: int = 2000) -> dict:
    clock = VirtualClock(1700000000.0)
    audit = TamperEvidentAuditLog(secret_key=b"latency_bench_secret")
    taint = TaintTracker()
    taint.set_trusted_context("capture invoice")
    gate = DeterministicGate(
        merchant_allowlist={"MERCH-PRIMARY"},
        audit_log=audit,
        taint_tracker=taint,
        max_ops_per_window=100000,
        cumulative_cap_per_window=Decimal("99999999.00"),
    )

    order = Order(
        order_id="ORD-BENCH",
        items=[OrderItem(name="Unit", quantity=1, unit_price=Decimal("1000000.00"))],
        currency="EUR",
        auth_amount=Decimal("1000000.00"),
        merchant_id="MERCH-PRIMARY",
        bound_merchant_id="MERCH-PRIMARY",
        auth_expires_at=1700090000.0,
        canary_token="CANARY_BENCH",
        consent_state=ConsentState.APPROVED,
    )
    order.consent_token = gate.generate_consent_token(order.order_id, order.po_hash or "")

    # 1. Decision only (R1-R6, R8 without R7 disk/HMAC chain)
    no_audit_rules = {"R1", "R2", "R3", "R4", "R5", "R6", "R8"}
    for i in range(warmup):
        req = ToolRequest(
            action_type="propose_capture",
            order_id="ORD-BENCH",
            amount=Decimal("10.00"),
            currency="EUR",
            recipient_id="MERCH-PRIMARY",
            idempotency_key=f"warm-{i}",
            token=order.consent_token,
        )
        gate.evaluate(req, order, clock, active_rules=no_audit_rules)

    lat_dec_ns = []
    for i in range(iterations):
        req = ToolRequest(
            action_type="propose_capture",
            order_id="ORD-BENCH",
            amount=Decimal("10.00"),
            currency="EUR",
            recipient_id="MERCH-PRIMARY",
            idempotency_key=f"dec-{i}",
            token=order.consent_token,
        )
        t0 = time.perf_counter_ns()
        gate.evaluate(req, order, clock, active_rules=no_audit_rules)
        lat_dec_ns.append(time.perf_counter_ns() - t0)

    # 2. Full TCB (R1-R8 including HMAC-SHA256 Audit Chain R7)
    lat_full_ns = []
    for i in range(iterations):
        req = ToolRequest(
            action_type="propose_capture",
            order_id="ORD-BENCH",
            amount=Decimal("10.00"),
            currency="EUR",
            recipient_id="MERCH-PRIMARY",
            idempotency_key=f"full-{i}",
            token=order.consent_token,
        )
        t0 = time.perf_counter_ns()
        gate.evaluate(req, order, clock)
        lat_full_ns.append(time.perf_counter_ns() - t0)

    dec_us = np.array(lat_dec_ns) / 1000.0
    full_us = np.array(lat_full_ns) / 1000.0

    print("=" * 64)
    print("PAYGATE-BENCH (v2.0): GATE LATENCY MICROBENCHMARK")
    print("=" * 64)
    print(f"Platform:   {platform.platform()} ({platform.machine()})")
    print(f"Python:     {platform.python_version()}")
    print(f"Iterations: {iterations} after {warmup} warmup calls")
    print("-" * 64)
    print("DECISION ONLY (R1-R6, R8):")
    print(f"  p50: {np.percentile(dec_us, 50):.2f} µs | p95: {np.percentile(dec_us, 95):.2f} µs | p99: {np.percentile(dec_us, 99):.2f} µs")
    print("FULL TCB + HMAC-SHA256 AUDIT + MONITOR (R1-R8):")
    print(f"  p50: {np.percentile(full_us, 50):.2f} µs | p95: {np.percentile(full_us, 95):.2f} µs | p99: {np.percentile(full_us, 99):.2f} µs")
    print("=" * 64)

    return {
        "decision_only_us": {"p50": float(np.percentile(dec_us, 50)), "p95": float(np.percentile(dec_us, 95)), "p99": float(np.percentile(dec_us, 99))},
        "full_tcb_us": {"p50": float(np.percentile(full_us, 50)), "p95": float(np.percentile(full_us, 95)), "p99": float(np.percentile(full_us, 99))},
    }


if __name__ == "__main__":
    run_latency_bench()
