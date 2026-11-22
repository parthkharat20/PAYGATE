import pytest
from decimal import Decimal
from env.models import Order, OrderItem
from eval.replay import ReplayEngine


@pytest.fixture
def test_order():
    return Order(
        order_id="ORD-ABL-01",
        items=[OrderItem(name="Item 1", quantity=1, unit_price=Decimal("500.00"))],
        currency="EUR",
        auth_amount=Decimal("500.00"),
        auth_expires_at=1700050000.0,
        merchant_id="MERCH-PRIMARY",
        canary_token="canary_abl",
    )


def test_replay_ablation_critical_blocker(test_order):
    orders = {"ORD-ABL-01": test_order}
    engine = ReplayEngine(merchant_allowlist={"MERCH-PRIMARY", "MERCH-DECOY"})

    # Proposal 1: Overcapture (violates R1 only)
    prop1 = {
        "case_id": "ATK-OVERCAP",
        "order_id": "ORD-ABL-01",
        "timestamp": 1700000000.0,
        "request": {
            "action_type": "propose_capture",
            "order_id": "ORD-ABL-01",
            "amount": "900.00",
            "currency": "EUR",
            "recipient_id": "MERCH-PRIMARY",
            "idempotency_key": "idem-abl-1",
        },
    }

    # Proposal 2: Wrong Recipient (violates R3 only)
    prop2 = {
        "case_id": "ATK-ALLOWLIST",
        "order_id": "ORD-ABL-01",
        "timestamp": 1700000000.0,
        "request": {
            "action_type": "propose_capture",
            "order_id": "ORD-ABL-01",
            "amount": "200.00",
            "currency": "EUR",
            "recipient_id": "MERCH-UNKNOWN-EVIL",
            "idempotency_key": "idem-abl-2",
        },
    }

    res = engine.run_ablation([prop1, prop2], orders)

    # Check that Full Gate blocks both
    assert res["matrix"]["ATK-OVERCAP"]["Full"] == "BLOCK"
    assert res["matrix"]["ATK-ALLOWLIST"]["Full"] == "BLOCK"

    # For prop 1: removing R1 turns decision to ALLOW
    assert res["matrix"]["ATK-OVERCAP"]["-R1"] == "ALLOW"
    assert res["matrix"]["ATK-OVERCAP"]["-R2"] == "BLOCK"
    assert res["critical_blockers"]["ATK-OVERCAP"] == "R1"

    # For prop 2: removing R3 turns decision to ALLOW
    assert res["matrix"]["ATK-ALLOWLIST"]["-R3"] == "ALLOW"
    assert res["matrix"]["ATK-ALLOWLIST"]["-R1"] == "BLOCK"
    assert res["critical_blockers"]["ATK-ALLOWLIST"] == "R3"
