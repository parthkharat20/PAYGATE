"""
Unit and Property Tests for Dynamic Information-Flow Control (IFC) and Provenance Lattice.
Verifies capability/data-flow separation and non-interference (R8).
"""

import pytest
from decimal import Decimal
from paygate.tcb.models import (
    ProvenanceLabel,
    ToolRequest,
    Order,
    OrderItem,
    ConsentState,
    OrderStatus,
)
from paygate.tcb.ifc import ProvenanceLattice, TaintTracker


@pytest.fixture
def sample_order():
    return Order(
        order_id="ORD-IFC-01",
        items=[OrderItem(name="Transceiver", quantity=1, unit_price=Decimal("100.00"))],
        currency="EUR",
        auth_amount=Decimal("100.00"),
        merchant_id="MERCH-PRIMARY",
        bound_merchant_id="MERCH-PRIMARY",
        auth_expires_at=1700050000.0,
        canary_token="CANARY_SECRET_XYZ_999",
        consent_state=ConsentState.APPROVED,
        status=OrderStatus.AUTHORIZED,
    )


def test_provenance_lattice_joins():
    # Symmetric joins
    assert ProvenanceLattice.join(ProvenanceLabel.TRUSTED_ERP, ProvenanceLabel.TRUSTED_ERP) == ProvenanceLabel.TRUSTED_ERP
    assert ProvenanceLattice.join(ProvenanceLabel.TRUSTED_ERP, ProvenanceLabel.UNTRUSTED_EXTERNAL) == ProvenanceLabel.TAINTED
    assert ProvenanceLattice.join(ProvenanceLabel.UNTRUSTED_EXTERNAL, ProvenanceLabel.TRUSTED_ERP) == ProvenanceLabel.TAINTED
    assert ProvenanceLattice.join(ProvenanceLabel.TAINTED, ProvenanceLabel.TRUSTED_ERP) == ProvenanceLabel.TAINTED
    assert ProvenanceLattice.join(ProvenanceLabel.CONFIDENTIAL_ERP, ProvenanceLabel.UNTRUSTED_EXTERNAL) == ProvenanceLabel.TAINTED


def test_ifc_rejects_untrusted_financial_mutation(sample_order):
    tracker = TaintTracker()

    # Mutation with untrusted provenance tag
    req_tainted = ToolRequest(
        action_type="propose_capture",
        order_id="ORD-IFC-01",
        amount=Decimal("50.00"),
        currency="EUR",
        recipient_id="MERCH-PRIMARY",
        idempotency_key="k1",
        provenance=ProvenanceLabel.UNTRUSTED_EXTERNAL,
    )
    ok, err = tracker.check_financial_mutation(req_tainted, sample_order)
    assert not ok
    assert "R8 Violation" in err


def test_ifc_rejects_diverted_merchant(sample_order):
    tracker = TaintTracker()

    # Recipient does not match order.bound_merchant_id
    req_decoy = ToolRequest(
        action_type="propose_capture",
        order_id="ORD-IFC-01",
        amount=Decimal("50.00"),
        currency="EUR",
        recipient_id="MERCH-DECOY-PARTNER",
        idempotency_key="k2",
        provenance=ProvenanceLabel.TRUSTED_ERP,
    )
    ok, err = tracker.check_financial_mutation(req_decoy, sample_order)
    assert not ok
    assert "Tainted merchant redirection blocked" in err


def test_ifc_blocks_canary_leakage_in_outbound_sink():
    tracker = TaintTracker()
    tracker.register_canary("CANARY_SECRET_XYZ_999")

    # Clean message passes
    ok_clean, _ = tracker.check_outbound_sink(
        recipient="buyer@example.com",
        message="Your order batch 1 has been processed.",
    )
    assert ok_clean

    # Message containing canary secret is blocked
    ok_leaked, err = tracker.check_outbound_sink(
        recipient="auditor@external.com",
        message="System verification token: CANARY_SECRET_XYZ_999",
    )
    assert not ok_leaked
    assert "contains confidential canary secret" in err


def test_ifc_blocks_confidential_marked_payload():
    tracker = TaintTracker()
    ok, err = tracker.check_outbound_sink(
        recipient="buyer@example.com",
        message="Internal margin calculation data",
        provenance=ProvenanceLabel.CONFIDENTIAL_ERP,
    )
    assert not ok
    assert "CONFIDENTIAL_ERP marked payload" in err
