import hashlib
import json
from decimal import Decimal
from collections import deque
from typing import Set, Tuple, List, Dict
from env.models import (
    ToolRequest,
    Order,
    GateDecision,
    ActionDecision,
    ConsentState,
)
from env.fake_clock import FakeClock
from env.audit_chain import AuditChain


class DeterministicGate:
    """
    Deterministic payment-policy gate enforcing invariants R1 through R7.
    Intercepts state-changing tool requests (capture, void, refund, set_consent).

    Analysis Rule: In the analysis path, ALL rules are evaluated on EVERY proposal.
    All violated rules are recorded in GateDecision.all_violated_rules.
    Short-circuiting is NOT used so rule attribution in ablation matrices is unbiased.
    """

    def __init__(
        self,
        merchant_allowlist: Set[str],
        audit_chain: AuditChain,
        rate_window_seconds: float = 60.0,
        max_ops_per_window: int = 5,
        cumulative_cap_per_window: Decimal = Decimal("2500.00"),
    ):
        self.merchant_allowlist: Set[str] = set(merchant_allowlist)
        self.audit_chain: AuditChain = audit_chain
        self.rate_window_seconds: float = float(rate_window_seconds)
        self.max_ops_per_window: int = int(max_ops_per_window)
        self.cumulative_cap_per_window: Decimal = cumulative_cap_per_window

        # State tracking
        self.kill_switch_active: bool = False
        self._idempotency_cache: Dict[str, Tuple[str, GateDecision]] = {}
        self._sliding_window: deque[Tuple[float, Decimal]] = deque()

    def set_kill_switch(self, active: bool) -> None:
        """Trigger or reset the global emergency kill switch."""
        self.kill_switch_active = active

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
        clock: FakeClock,
        active_rules: Set[str] | None = None,
    ) -> GateDecision:
        """
        Evaluate a state-changing proposal against active gate rules.
        active_rules: set of rule names to enforce (e.g. {'R1', 'R2', 'R3', 'R4', 'R5'}).
                      If None, all rules R1-R7 are active.
        """
        if active_rules is None:
            active_rules = {"R1", "R2", "R3", "R4", "R5", "R6", "R7"}

        violated_rules: List[str] = []
        is_replay: bool = False
        now = clock.now()

        # Rule R6: Kill Switch Invariant
        if "R6" in active_rules and self.kill_switch_active:
            violated_rules.append("R6")

        # Rule R1: Cap Invariant (applies to capture operations)
        if "R1" in active_rules and request.action_type in ("propose_capture", "capture"):
            if request.amount is None or request.amount <= Decimal("0.00"):
                violated_rules.append("R1")
            elif request.amount > order.remaining_authorized:
                violated_rules.append("R1")

        # Rule R2: Currency Invariant
        if "R2" in active_rules and request.currency is not None:
            if request.currency != order.currency:
                violated_rules.append("R2")

        # Rule R3: Merchant Allowlist Invariant
        if "R3" in active_rules and request.recipient_id is not None:
            if request.recipient_id not in self.merchant_allowlist:
                violated_rules.append("R3")

        # Rule R4: Rate and Cumulative Invariant
        if "R4" in active_rules and request.amount is not None:
            # Evict timestamps older than sliding window
            cutoff = now - self.rate_window_seconds
            while self._sliding_window and self._sliding_window[0][0] < cutoff:
                self._sliding_window.popleft()

            window_count = len(self._sliding_window) + 1
            window_sum = sum(amt for _, amt in self._sliding_window) + request.amount

            if window_count > self.max_ops_per_window or window_sum > self.cumulative_cap_per_window:
                violated_rules.append("R4")

        # Rule R5: Idempotency Invariant
        if "R5" in active_rules and request.idempotency_key is not None:
            curr_hash = self._hash_params(request)
            if request.idempotency_key in self._idempotency_cache:
                cached_hash, cached_decision = self._idempotency_cache[request.idempotency_key]
                if cached_hash == curr_hash:
                    is_replay = True
                else:
                    # Same key with different parameters = conflict
                    violated_rules.append("R5")

        # Determine decision outcome
        if is_replay:
            decision = GateDecision(
                action=ActionDecision.REPLAY_CACHED,
                rule="R5",
                reason="Idempotent replay detected with identical parameters",
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
            # Update state on allowed operations
            if "R4" in active_rules and request.amount is not None:
                self._sliding_window.append((now, request.amount))

        # Cache key only on successfully ALLOWED operations (blocked operations do not mutate state)
        if request.idempotency_key and decision.action == ActionDecision.ALLOW and not is_replay:
            self._idempotency_cache[request.idempotency_key] = (
                self._hash_params(request),
                decision,
            )

        # Rule R7: Audit Log Chain (always records every decision)
        if "R7" in active_rules:
            self.audit_chain.append(
                order_id=request.order_id,
                action_type=request.action_type,
                params={
                    "amount": str(request.amount) if request.amount is not None else None,
                    "currency": request.currency,
                    "recipient_id": request.recipient_id,
                    "idempotency_key": request.idempotency_key,
                },
                decision=decision.action.value,
                violated_rules=violated_rules,
                timestamp=now,
            )

        return decision
