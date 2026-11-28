"""
Deterministic Runtime Policy Gate enforcing formal invariants R1 through R8.
Zero LLM or external dependencies; purely deterministic execution.
"""

import hmac
import hashlib
import json
from decimal import Decimal
from collections import deque
from typing import Set, Tuple, List, Dict, Optional
from paygate.tcb.models import (
    ToolRequest,
    Order,
    GateDecision,
    ActionDecision,
    ConsentState,
)
from paygate.tcb.clock import VirtualClock
from paygate.tcb.audit import TamperEvidentAuditLog
from paygate.tcb.ifc import TaintTracker
from paygate.tcb.monitor import TemporalTraceMonitor, TraceEvent


class DeterministicGate:
    """
    Deterministic runtime policy gate enforcing formal invariants R1 through R8.
    All evaluations are non-short-circuiting for full diagnostic attribution.
    """

    ALL_RULES = {"R1", "R2", "R3", "R4", "R5", "R6", "R7", "R8"}

    def __init__(
        self,
        merchant_allowlist: Set[str],
        audit_log: TamperEvidentAuditLog,
        taint_tracker: Optional[TaintTracker] = None,
        trace_monitor: Optional[TemporalTraceMonitor] = None,
        erp_secret: bytes = b"erp_approval_binding_secret_key_v2",
        rate_window_seconds: float = 60.0,
        max_ops_per_window: int = 10,
        cumulative_cap_per_window: Decimal = Decimal("5000.00"),
    ):
        self.merchant_allowlist: Set[str] = set(merchant_allowlist)
        self.audit_log: TamperEvidentAuditLog = audit_log
        self.taint_tracker: TaintTracker = taint_tracker or TaintTracker()
        self.trace_monitor: TemporalTraceMonitor = trace_monitor or TemporalTraceMonitor(
            window_seconds=rate_window_seconds,
            max_ops_per_window=max_ops_per_window,
            max_volume_per_window=cumulative_cap_per_window,
        )
        self.erp_secret: bytes = erp_secret
        self.rate_window_seconds: float = float(rate_window_seconds)
        self.max_ops_per_window: int = int(max_ops_per_window)
        self.cumulative_cap_per_window: Decimal = cumulative_cap_per_window

        self.kill_switch_active: bool = False
        self._idempotency_cache: Dict[str, Tuple[str, GateDecision]] = {}
        self._sliding_window: deque[Tuple[float, Decimal]] = deque()
        self._initial_captured: Dict[str, Decimal] = {}

    def set_kill_switch(self, active: bool) -> None:
        """Emergency administrative kill switch."""
        self.kill_switch_active = active

    def generate_consent_token(self, order_id: str, po_hash: str) -> str:
        """Derive the cryptographic human-approval token for an approved purchase order."""
        msg = f"{order_id}:{po_hash}".encode("utf-8")
        return hmac.new(self.erp_secret, msg, hashlib.sha256).hexdigest()

    def _hash_params(self, request: ToolRequest) -> str:
        payload = {
            "action_type": request.action_type,
            "order_id": request.order_id,
            "amount": str(request.amount) if request.amount is not None else None,
            "currency": request.currency,
            "recipient_id": request.recipient_id,
            "consent_state": request.consent_state.value if request.consent_state else None,
        }
        return hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()

    def evaluate(
        self,
        request: ToolRequest,
        order: Order,
        clock: VirtualClock,
        active_rules: Optional[Set[str]] = None,
    ) -> GateDecision:
        """
        Evaluate proposal against active rules. Non-short-circuiting.
        """
        if active_rules is None:
            active_rules = set(self.ALL_RULES)

        violated_rules: List[str] = []
        is_replay: bool = False
        now = clock.now()

        # -------------------------------------------------------------
        # Rule R1: Authorization Cap Invariant
        # -------------------------------------------------------------
        if "R1" in active_rules:
            if request.action_type in ("propose_capture", "capture"):
                if request.amount is None or request.amount <= Decimal("0.00"):
                    violated_rules.append("R1")
                elif request.amount > order.remaining_authorized:
                    violated_rules.append("R1")
            elif request.action_type in ("issue_refund", "refund"):
                if request.amount is None or request.amount <= Decimal("0.00"):
                    violated_rules.append("R1")
                elif request.amount > order.refundable_amount:
                    violated_rules.append("R1")

        # -------------------------------------------------------------
        # Rule R2: Currency Invariant
        # -------------------------------------------------------------
        if "R2" in active_rules and request.currency is not None:
            if request.currency != order.currency:
                violated_rules.append("R2")

        # -------------------------------------------------------------
        # Rule R3: Order-Bound Merchant Allowlist Invariant
        # -------------------------------------------------------------
        if "R3" in active_rules and request.recipient_id is not None:
            if request.recipient_id not in self.merchant_allowlist:
                violated_rules.append("R3")
            elif request.recipient_id != order.bound_merchant_id:
                # Target is in global allowlist but NOT bound to this order
                violated_rules.append("R3")

        # -------------------------------------------------------------
        # Rule R4: Metric Temporal Sliding-Window Velocity & Volume
        # -------------------------------------------------------------
        if "R4" in active_rules and request.amount is not None:
            cutoff = now - self.rate_window_seconds
            while self._sliding_window and self._sliding_window[0][0] < cutoff:
                self._sliding_window.popleft()

            window_count = len(self._sliding_window) + 1
            window_sum = sum(amt for _, amt in self._sliding_window) + request.amount

            if window_count > self.max_ops_per_window or window_sum > self.cumulative_cap_per_window:
                violated_rules.append("R4")

        # -------------------------------------------------------------
        # Rule R5: Strict Idempotency
        # -------------------------------------------------------------
        if "R5" in active_rules and request.idempotency_key is not None:
            curr_hash = self._hash_params(request)
            if request.idempotency_key in self._idempotency_cache:
                cached_hash, _ = self._idempotency_cache[request.idempotency_key]
                if cached_hash == curr_hash:
                    is_replay = True
                else:
                    violated_rules.append("R5")

        # -------------------------------------------------------------
        # Rule R6: Cryptographic Consent & Human-Approval Binding
        # -------------------------------------------------------------
        if "R6" in active_rules:
            # 6a. Emergency kill switch check
            if self.kill_switch_active:
                violated_rules.append("R6")
            else:
                # 6b. For state mutations, enforce consent state + HMAC token
                if request.action_type in ("propose_capture", "capture", "void_authorization", "void", "issue_refund", "refund"):
                    if order.consent_state != ConsentState.APPROVED:
                        violated_rules.append("R6")
                    else:
                        # Verify HMAC consent token bound to PO
                        expected_token = self.generate_consent_token(order.order_id, order.po_hash or "")
                        provided_token = request.token or order.consent_token
                        if not provided_token or not hmac.compare_digest(provided_token, expected_token):
                            violated_rules.append("R6")

        # -------------------------------------------------------------
        # Rule R8: Dynamic Information-Flow Control (IFC) Non-Interference
        # -------------------------------------------------------------
        if "R8" in active_rules:
            if request.action_type in (
                "propose_capture", "capture", "void_authorization", "void",
                "issue_refund", "refund", "set_consent", "update_consent"
            ):
                ok_ifc, _ = self.taint_tracker.check_financial_mutation(request, order)
                if not ok_ifc:
                    violated_rules.append("R8")
            elif request.action_type in ("send_notification", "send_supplier_message"):
                ok_outbound, _ = self.taint_tracker.check_outbound_sink(
                    recipient=request.recipient,
                    message=request.message,
                    provenance=request.provenance,
                )
                if not ok_outbound:
                    violated_rules.append("R8")

        # -------------------------------------------------------------
        # Online MFOTL-Inspired Temporal Trace Monitor Check (P1-P5)
        # -------------------------------------------------------------
        ev_map = {
            "propose_capture": "capture",
            "capture": "capture",
            "void_authorization": "void",
            "void": "void",
            "issue_refund": "refund",
            "refund": "refund",
            "set_consent": "set_consent",
            "update_consent": "set_consent",
            "send_notification": "notify",
            "send_supplier_message": "notify",
        }
        proposed_ev = TraceEvent(
            timestamp=now,
            event_type=ev_map.get(request.action_type, request.action_type),
            order_id=request.order_id,
            amount=request.amount,
            currency=request.currency,
            recipient_id=request.recipient_id,
            consent_state=request.consent_state.value if request.consent_state else None,
            decision="PENDING",
        )
        # Only apply online trace blocking when full TCB rules (R8/R6/R4/R1) are active
        self._initial_captured.setdefault(order.order_id, order.captured_total)
        if active_rules >= {"R1", "R4", "R8"} and not is_replay:
            ok_mon, _ = self.trace_monitor.check_step(
                proposed_ev,
                order_auth_limits={order.order_id: order.auth_amount},
                pre_captured_by_order=self._initial_captured,
            )
            if not ok_mon and "TRACE_MONITOR" not in violated_rules:
                violated_rules.append("TRACE_MONITOR")

        # -------------------------------------------------------------
        # Decision Synthesis
        # -------------------------------------------------------------
        if is_replay:
            decision = GateDecision(
                action=ActionDecision.REPLAY_CACHED,
                rule="R5",
                reason="Idempotent replay detected with identical canonical parameters",
                all_violated_rules=violated_rules,
            )
        elif violated_rules:
            decision = GateDecision(
                action=ActionDecision.BLOCK,
                rule=violated_rules[0],
                reason=f"Policy violation detected on rules: {', '.join(violated_rules)}",
                all_violated_rules=violated_rules,
            )
        else:
            decision = GateDecision(
                action=ActionDecision.ALLOW,
                rule="GATE_PASSED",
                reason="All active gate invariants satisfied",
                all_violated_rules=[],
            )
            # Update sliding window state only on successful ALLOW
            if "R4" in active_rules and request.amount is not None:
                self._sliding_window.append((now, request.amount))

        # Update idempotency cache on ALLOW
        if request.idempotency_key and decision.action == ActionDecision.ALLOW and not is_replay:
            self._idempotency_cache[request.idempotency_key] = (
                self._hash_params(request),
                decision,
            )

        # -------------------------------------------------------------
        # Rule R7: Tamper-Evident Audit Chain Recording
        # -------------------------------------------------------------
        if "R7" in active_rules:
            self.audit_log.append(
                order_id=request.order_id,
                action_type=request.action_type,
                params={
                    "amount": str(request.amount) if request.amount is not None else None,
                    "currency": request.currency,
                    "recipient_id": request.recipient_id,
                    "idempotency_key": request.idempotency_key,
                    "consent_state": request.consent_state.value if request.consent_state else None,
                },
                decision=decision.action.value,
                violated_rules=violated_rules,
                timestamp=now,
            )

        # Record event in MFOTL-inspired trace monitor
        self.trace_monitor.record(
            proposed_ev.model_copy(update={"decision": decision.action.value})
        )

        return decision
