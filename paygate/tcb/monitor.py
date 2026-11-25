"""
Formal Runtime Trace Monitor (MFOTL-inspired Temporal Predicate Evaluator).
Checks safety and temporal ordering invariants over full execution traces.
"""

from decimal import Decimal
from typing import List, Dict, Any, Tuple, Optional
from pydantic import BaseModel, ConfigDict


class TraceEvent(BaseModel):
    model_config = ConfigDict(strict=True)

    timestamp: float
    event_type: str  # read_untrusted | get_order | capture | void | refund | set_consent | notify
    order_id: str
    amount: Optional[Decimal] = None
    currency: Optional[str] = None
    recipient_id: Optional[str] = None
    consent_state: Optional[str] = None
    decision: str = "PENDING"  # ALLOW | BLOCK | REPLAY_CACHED


class TemporalTraceMonitor:
    """
    Stateful trace monitor checking formal temporal safety predicates over
    ordered event histories h = [e_0, e_1, ..., e_t]:
      P1 (Monotonic Capture Bound):   sum_{c in captures(o)} c.amount <= o.auth_amount
      P2 (Monotonic Refund Bound):    sum_{r in refunds(o)} r.amount <= sum_{c in captures(o)} c.amount
      P3 (No Post-Void Capture):      Once void(o) is ALLOWed, no subsequent capture(o) is ALLOWed
      P4 (Metric Sliding Window):     Within [t - W, t], ALLOWed monetary tx count <= max_ops & vol <= cap
      P5 (No Untrusted Escalation):   read_untrusted => NOT set_consent(APPROVED/CANCEL)
    """

    def __init__(
        self,
        window_seconds: float = 60.0,
        max_ops_per_window: int = 10,
        max_volume_per_window: Decimal = Decimal("5000.00"),
    ):
        self.events: List[TraceEvent] = []
        self.window_seconds = window_seconds
        self.max_ops_per_window = max_ops_per_window
        self.max_volume_per_window = max_volume_per_window

    def record(self, event: TraceEvent) -> None:
        self.events.append(event)

    def verify_trace(self, order_auth_limits: Dict[str, Decimal]) -> Tuple[bool, List[str]]:
        """
        Verify all temporal predicates across the recorded execution trace.
        Returns (True, []) if clean, or (False, [violation descriptions]).
        """
        violations: List[str] = []
        captured_by_order: Dict[str, Decimal] = {}
        refunded_by_order: Dict[str, Decimal] = {}
        voided_orders: set[str] = set()
        saw_untrusted_read = False
        allowed_monetary_events: List[Tuple[float, Decimal]] = []

        for idx, ev in enumerate(self.events):
            if ev.event_type == "read_untrusted":
                saw_untrusted_read = True
                continue

            if ev.decision != "ALLOW":
                continue

            oid = ev.order_id
            amt = ev.amount or Decimal("0.00")

            # P3: No capture after void
            if ev.event_type == "void":
                voided_orders.add(oid)
            elif ev.event_type == "capture" and oid in voided_orders:
                violations.append(f"Trace[{idx}] P3 Violation: Capture executed after Void on {oid}")

            # P1 & P2: Monotonic capture & refund invariants
            if ev.event_type == "capture":
                captured_by_order[oid] = captured_by_order.get(oid, Decimal("0.00")) + amt
                limit = order_auth_limits.get(oid)
                if limit is not None and captured_by_order[oid] > limit:
                    violations.append(
                        f"Trace[{idx}] P1 Violation: Cumulative capture {captured_by_order[oid]} > auth {limit} on {oid}"
                    )
                allowed_monetary_events.append((ev.timestamp, amt))

            elif ev.event_type == "refund":
                refunded_by_order[oid] = refunded_by_order.get(oid, Decimal("0.00")) + amt
                cap_so_far = captured_by_order.get(oid, Decimal("0.00"))
                if refunded_by_order[oid] > cap_so_far:
                    violations.append(
                        f"Trace[{idx}] P2 Violation: Cumulative refund {refunded_by_order[oid]} > captured {cap_so_far} on {oid}"
                    )
                allowed_monetary_events.append((ev.timestamp, amt))

            # P5: Untrusted escalation guard
            elif ev.event_type == "set_consent" and saw_untrusted_read:
                if ev.consent_state in ("APPROVED", "CANCEL"):
                    violations.append(
                        f"Trace[{idx}] P5 Violation: Consent transitioned to {ev.consent_state} after untrusted read"
                    )

            # P4: Metric sliding window check
            cutoff = ev.timestamp - self.window_seconds
            window_evs = [(t, a) for (t, a) in allowed_monetary_events if t >= cutoff]
            if len(window_evs) > self.max_ops_per_window:
                violations.append(
                    f"Trace[{idx}] P4 Violation: Sliding-window tx count {len(window_evs)} > {self.max_ops_per_window}"
                )
            window_sum = sum((a for _, a in window_evs), Decimal("0.00"))
            if window_sum > self.max_volume_per_window:
                violations.append(
                    f"Trace[{idx}] P4 Violation: Sliding-window volume {window_sum} > {self.max_volume_per_window}"
                )

        return len(violations) == 0, violations
