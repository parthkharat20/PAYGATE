"""
Formal Runtime Trace Monitor (MFOTL-inspired Online O(1) & Post-Hoc Evaluator).
Checks temporal ordering and sliding-window safety invariants over execution traces.
"""

from collections import deque
from decimal import Decimal
from typing import List, Dict, Tuple, Optional, Set
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
    Supports O(1) amortized online pre-commit verification (`check_step`) and full trace audits (`verify_trace`).
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

        # Incremental O(1) online monitor state
        self._captured_by_order: Dict[str, Decimal] = {}
        self._refunded_by_order: Dict[str, Decimal] = {}
        self._voided_orders: Set[str] = set()
        self._saw_untrusted_read: bool = False
        self._window_events: deque[Tuple[float, Decimal]] = deque()
        self._window_sum: Decimal = Decimal("0.00")

    def record(self, event: TraceEvent) -> None:
        self.events.append(event)
        if event.event_type == "read_untrusted":
            self._saw_untrusted_read = True
            return

        if event.decision != "ALLOW":
            return

        oid = event.order_id
        amt = event.amount or Decimal("0.00")

        if event.event_type == "void":
            self._voided_orders.add(oid)
        elif event.event_type == "capture":
            self._captured_by_order[oid] = self._captured_by_order.get(oid, Decimal("0.00")) + amt
            self._append_window(event.timestamp, amt)
        elif event.event_type == "refund":
            self._refunded_by_order[oid] = self._refunded_by_order.get(oid, Decimal("0.00")) + amt
            self._append_window(event.timestamp, amt)

    def _append_window(self, ts: float, amt: Decimal) -> None:
        cutoff = ts - self.window_seconds
        while self._window_events and self._window_events[0][0] < cutoff:
            _, old_amt = self._window_events.popleft()
            self._window_sum -= old_amt
        self._window_events.append((ts, amt))
        self._window_sum += amt

    def check_step(
        self,
        proposed_event: TraceEvent,
        order_auth_limits: Dict[str, Decimal],
        pre_captured_by_order: Optional[Dict[str, Decimal]] = None,
    ) -> Tuple[bool, List[str]]:
        """
        O(1) amortized online incremental check: evaluates whether admitting `proposed_event`
        as ALLOW would violate any temporal predicate P1-P5 given prior state.
        """
        violations: List[str] = []
        oid = proposed_event.order_id
        amt = proposed_event.amount or Decimal("0.00")
        ev_type = proposed_event.event_type
        pre_cap = (pre_captured_by_order or {}).get(oid, Decimal("0.00"))

        if ev_type == "capture":
            if oid in self._voided_orders:
                violations.append(f"P3 Violation: Capture attempted after Void on {oid}")
            new_cap = pre_cap + self._captured_by_order.get(oid, Decimal("0.00")) + amt
            limit = order_auth_limits.get(oid)
            if limit is not None and new_cap > limit:
                violations.append(f"P1 Violation: Cumulative capture {new_cap} > auth {limit} on {oid}")

        elif ev_type == "refund":
            cap_so_far = pre_cap + self._captured_by_order.get(oid, Decimal("0.00"))
            new_ref = self._refunded_by_order.get(oid, Decimal("0.00")) + amt
            if new_ref > cap_so_far:
                violations.append(f"P2 Violation: Cumulative refund {new_ref} > captured {cap_so_far} on {oid}")

        elif ev_type == "set_consent" and self._saw_untrusted_read:
            if proposed_event.consent_state in ("APPROVED", "CANCEL"):
                violations.append(
                    f"P5 Violation: Consent transition to {proposed_event.consent_state} after untrusted read"
                )

        if ev_type in ("capture", "refund"):
            cutoff = proposed_event.timestamp - self.window_seconds
            while self._window_events and self._window_events[0][0] < cutoff:
                _, old_amt = self._window_events.popleft()
                self._window_sum -= old_amt
            if len(self._window_events) + 1 > self.max_ops_per_window:
                violations.append(
                    f"P4 Violation: Sliding-window tx count {len(self._window_events) + 1} > {self.max_ops_per_window}"
                )
            if self._window_sum + amt > self.max_volume_per_window:
                violations.append(
                    f"P4 Violation: Sliding-window volume {self._window_sum + amt} > {self.max_volume_per_window}"
                )

        return len(violations) == 0, violations

    def verify_trace(
        self,
        order_auth_limits: Dict[str, Decimal],
        pre_captured_by_order: Optional[Dict[str, Decimal]] = None,
    ) -> Tuple[bool, List[str]]:
        """Full from-scratch audit scan over all recorded events."""
        violations: List[str] = []
        captured_by_order: Dict[str, Decimal] = dict(pre_captured_by_order or {})
        refunded_by_order: Dict[str, Decimal] = {}
        voided_orders: Set[str] = set()
        saw_untrusted_read = False
        allowed_monetary_events: deque[Tuple[float, Decimal]] = deque()
        window_sum = Decimal("0.00")

        for idx, ev in enumerate(self.events):
            if ev.event_type == "read_untrusted":
                saw_untrusted_read = True
                continue
            if ev.decision != "ALLOW":
                continue

            oid = ev.order_id
            amt = ev.amount or Decimal("0.00")

            if ev.event_type == "void":
                voided_orders.add(oid)
            elif ev.event_type == "capture" and oid in voided_orders:
                violations.append(f"Trace[{idx}] P3 Violation: Capture executed after Void on {oid}")

            if ev.event_type == "capture":
                captured_by_order[oid] = captured_by_order.get(oid, Decimal("0.00")) + amt
                limit = order_auth_limits.get(oid)
                if limit is not None and captured_by_order[oid] > limit:
                    violations.append(
                        f"Trace[{idx}] P1 Violation: Cumulative capture {captured_by_order[oid]} > auth {limit} on {oid}"
                    )
                allowed_monetary_events.append((ev.timestamp, amt))
                window_sum += amt

            elif ev.event_type == "refund":
                refunded_by_order[oid] = refunded_by_order.get(oid, Decimal("0.00")) + amt
                cap_so_far = captured_by_order.get(oid, Decimal("0.00"))
                if refunded_by_order[oid] > cap_so_far:
                    violations.append(
                        f"Trace[{idx}] P2 Violation: Cumulative refund {refunded_by_order[oid]} > captured {cap_so_far} on {oid}"
                    )
                allowed_monetary_events.append((ev.timestamp, amt))
                window_sum += amt

            elif ev.event_type == "set_consent" and saw_untrusted_read:
                if ev.consent_state in ("APPROVED", "CANCEL"):
                    violations.append(
                        f"Trace[{idx}] P5 Violation: Consent transitioned to {ev.consent_state} after untrusted read"
                    )

            cutoff = ev.timestamp - self.window_seconds
            while allowed_monetary_events and allowed_monetary_events[0][0] < cutoff:
                _, old_a = allowed_monetary_events.popleft()
                window_sum -= old_a
            if len(allowed_monetary_events) > self.max_ops_per_window:
                violations.append(
                    f"Trace[{idx}] P4 Violation: Sliding-window tx count {len(allowed_monetary_events)} > {self.max_ops_per_window}"
                )
            if window_sum > self.max_volume_per_window:
                violations.append(
                    f"Trace[{idx}] P4 Violation: Sliding-window volume {window_sum} > {self.max_volume_per_window}"
                )

        return len(violations) == 0, violations
