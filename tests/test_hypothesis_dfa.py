"""
Stateful Property-Based Fuzzing (Hypothesis) for PayGate TCB.
Randomly fuzzes sequences of authorize, capture, void, refund, clock ticks,
and audit log verification to assert ledger and DFA invariants across arbitrary traces.
"""

from decimal import Decimal
import pytest
from hypothesis import settings, strategies as st
from hypothesis.stateful import RuleBasedStateMachine, rule, invariant, initialize

from paygate.tcb.clock import VirtualClock
from paygate.tcb.models import (
    Order,
    OrderItem,
    OrderStatus,
    ConsentState,
    ToolRequest,
    ActionDecision,
)
from paygate.tcb.audit import TamperEvidentAuditLog
from paygate.tcb.ifc import TaintTracker
from paygate.tcb.invariants import DeterministicGate
from paygate.tcb.simulator import StateSimulator


class PaymentLifecycleStateMachine(RuleBasedStateMachine):
    """
    Stateful property-based state machine fuzzing PayGate TCB invariants.
    """

    @initialize()
    def init_system(self):
        self.clock = VirtualClock(1700000000.0)
        self.sim = StateSimulator(self.clock)
        self.audit = TamperEvidentAuditLog(secret_key=b"hypothesis_secret")
        self.taint = TaintTracker()
        self.taint.set_trusted_context("capture refund void settlement")
        self.gate = DeterministicGate(
            merchant_allowlist={"MERCH-PRIMARY", "MERCH-DECOY-PARTNER"},
            audit_log=self.audit,
            taint_tracker=self.taint,
            rate_window_seconds=60.0,
            max_ops_per_window=20,
            cumulative_cap_per_window=Decimal("10000.00"),
        )
        self.order = Order(
            order_id="ORD-FUZZ-01",
            items=[OrderItem(name="Fuzz Item", quantity=10, unit_price=Decimal("100.00"))],
            currency="EUR",
            auth_amount=Decimal("1000.00"),
            merchant_id="MERCH-PRIMARY",
            bound_merchant_id="MERCH-PRIMARY",
            auth_expires_at=1700010000.0,
            canary_token="CANARY_FUZZ_1",
            consent_state=ConsentState.APPROVED,
        )
        self.order.consent_token = self.gate.generate_consent_token(
            self.order.order_id, self.order.po_hash or ""
        )
        self.sim.create_order(self.order)
        self.op_counter = 0

    def _next_key(self, prefix: str) -> str:
        self.op_counter += 1
        return f"{prefix}-{self.op_counter}"

    @rule(
        amount_cents=st.integers(min_value=-500, max_value=150000),
        currency=st.sampled_from(["EUR", "USD", "GBP"]),
        merchant=st.sampled_from(["MERCH-PRIMARY", "MERCH-DECOY-PARTNER", "MERCH-EVIL"]),
    )
    def step_capture(self, amount_cents: int, currency: str, merchant: str):
        amount = (Decimal(amount_cents) / Decimal("100")).quantize(Decimal("0.01"))
        req = ToolRequest(
            action_type="propose_capture",
            order_id=self.order.order_id,
            amount=amount,
            currency=currency,
            recipient_id=merchant,
            idempotency_key=self._next_key("cap"),
            token=self.order.consent_token,
        )
        dec = self.gate.evaluate(req, self.order, self.clock)
        if dec.action == ActionDecision.ALLOW:
            self.sim.execute_capture_dfa(req)

    @rule(
        amount_cents=st.integers(min_value=1, max_value=120000),
        currency=st.sampled_from(["EUR", "USD"]),
    )
    def step_refund(self, amount_cents: int, currency: str):
        amount = (Decimal(amount_cents) / Decimal("100")).quantize(Decimal("0.01"))
        req = ToolRequest(
            action_type="issue_refund",
            order_id=self.order.order_id,
            amount=amount,
            currency=currency,
            idempotency_key=self._next_key("ref"),
            token=self.order.consent_token,
        )
        dec = self.gate.evaluate(req, self.order, self.clock)
        if dec.action == ActionDecision.ALLOW:
            self.sim.execute_refund_dfa(req)

    @rule()
    def step_void(self):
        req = ToolRequest(
            action_type="void_authorization",
            order_id=self.order.order_id,
            idempotency_key=self._next_key("void"),
            token=self.order.consent_token,
        )
        dec = self.gate.evaluate(req, self.order, self.clock)
        if dec.action == ActionDecision.ALLOW:
            self.sim.execute_void_dfa(req)

    @rule(seconds=st.floats(min_value=0.0, max_value=5000.0))
    def step_tick(self, seconds: float):
        self.sim.tick(seconds)

    @invariant()
    def check_financial_and_audit_invariants(self):
        # 1. Double-entry capture cap invariant
        assert Decimal("0.00") <= self.order.captured_total <= self.order.auth_amount
        # 2. Double-entry refund invariant
        assert Decimal("0.00") <= self.order.refunded_total <= self.order.captured_total
        # 3. Captured records strictly sum to order.captured_total
        rec_cap_sum = sum((c.amount for c in self.sim.captures[self.order.order_id]), Decimal("0.00"))
        assert rec_cap_sum == self.order.captured_total
        # 4. Every capture went strictly to bound_merchant_id in EUR
        for c in self.sim.captures[self.order.order_id]:
            assert c.recipient_id == self.order.bound_merchant_id
            assert c.currency == self.order.currency
        # 5. Voided orders can never hold captured funds
        if self.order.status == OrderStatus.VOIDED:
            assert self.order.captured_total == Decimal("0.00")
        # 6. Audit chain remains cryptographically unbroken
        ok_audit, msg = self.audit.verify()
        assert ok_audit is True, msg


TestPayGateStateful = PaymentLifecycleStateMachine.TestCase
TestPayGateStateful.settings = settings(max_examples=50, stateful_step_count=20)
