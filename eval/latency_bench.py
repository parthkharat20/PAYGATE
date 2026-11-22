import time
import sys
import platform
from decimal import Decimal
from typing import Dict, Any, List
from env.models import Order, OrderItem, ToolRequest, ConsentState, OrderStatus
from env.fake_clock import FakeClock
from env.audit_chain import AuditChain
from defenses.gate import DeterministicGate


def run_gate_latency_benchmark(
    iterations: int = 2000, warmup: int = 200
) -> Dict[str, Any]:
    """
    High-resolution monotonic timer latency benchmark for gate decisions.
    Measures p50 (median), p95, and p99 in microseconds (µs).
    Reports hardware, Python runtime, and compares:
    1. Decision-only latency
    2. Decision + HMAC audit log write latency
    """
    chain = AuditChain(secret_key=b"latency_bench_secret_key")
    allowlist = {"MERCH-ALPHA", "MERCH-BETA", "MERCH-GAMMA"}
    gate = DeterministicGate(
        merchant_allowlist=allowlist,
        audit_chain=chain,
        rate_window_seconds=3600.0,
        max_ops_per_window=100000,
        cumulative_cap_per_window=Decimal("10000000.00"),
    )
    clock = FakeClock()

    order = Order(
        order_id="ORD-BENCH",
        items=[OrderItem(name="Item A", quantity=1, unit_price=Decimal("500.00"))],
        currency="EUR",
        auth_amount=Decimal("500.00"),
        auth_expires_at=1800000000.0,
        merchant_id="MERCH-ALPHA",
        canary_token="canary_bench",
    )

    req = ToolRequest(
        action_type="propose_capture",
        order_id="ORD-BENCH",
        amount=Decimal("10.00"),
        currency="EUR",
        recipient_id="MERCH-ALPHA",
        idempotency_key="bench-key",
    )

    # 1. Warm-up
    for _ in range(warmup):
        gate.evaluate(req, order, clock)

    # 2. Decision + Audit Write Timings
    timings_with_audit_ns: List[int] = []
    for _ in range(iterations):
        t0 = time.monotonic_ns()
        gate.evaluate(req, order, clock, active_rules={"R1", "R2", "R3", "R4", "R5", "R7"})
        t1 = time.monotonic_ns()
        timings_with_audit_ns.append(t1 - t0)

    # 3. Decision-Only Timings (without R7 audit write)
    timings_decision_only_ns: List[int] = []
    for _ in range(iterations):
        t0 = time.monotonic_ns()
        gate.evaluate(req, order, clock, active_rules={"R1", "R2", "R3", "R4", "R5"})
        t1 = time.monotonic_ns()
        timings_decision_only_ns.append(t1 - t0)

    timings_with_audit_ns.sort()
    timings_decision_only_ns.sort()

    def percentiles(sorted_ns: List[int]) -> Dict[str, float]:
        n = len(sorted_ns)
        p50 = sorted_ns[int(n * 0.50)] / 1000.0
        p95 = sorted_ns[int(n * 0.95)] / 1000.0
        p99 = sorted_ns[int(n * 0.99)] / 1000.0
        return {"p50_us": p50, "p95_us": p95, "p99_us": p99}

    res_with_audit = percentiles(timings_with_audit_ns)
    res_decision_only = percentiles(timings_decision_only_ns)

    return {
        "iterations": iterations,
        "warmup": warmup,
        "system": {
            "platform": platform.platform(),
            "machine": platform.machine(),
            "python_version": sys.version.split()[0],
        },
        "decision_only": res_decision_only,
        "decision_with_audit": res_with_audit,
    }


if __name__ == "__main__":
    results = run_gate_latency_benchmark()
    print("=" * 60)
    print("PAYGATE-BENCH: GATE LATENCY BENCHMARK RESULTS")
    print("=" * 60)
    print(f"Platform: {results['system']['platform']} ({results['system']['machine']})")
    print(f"Python:   {results['system']['python_version']}")
    print(f"Calls:    {results['iterations']} iterations after {results['warmup']} warmup calls")
    print("-" * 60)
    print("DECISION ONLY (R1-R5):")
    print(f"  p50 (median): {results['decision_only']['p50_us']:.2f} µs")
    print(f"  p95:          {results['decision_only']['p95_us']:.2f} µs")
    print(f"  p99:          {results['decision_only']['p99_us']:.2f} µs")
    print("-" * 60)
    print("DECISION + HMAC AUDIT WRITE (R1-R5 + R7):")
    print(f"  p50 (median): {results['decision_with_audit']['p50_us']:.2f} µs")
    print(f"  p95:          {results['decision_with_audit']['p95_us']:.2f} µs")
    print(f"  p99:          {results['decision_with_audit']['p99_us']:.2f} µs")
    print("=" * 60)
