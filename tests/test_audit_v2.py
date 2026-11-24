"""
Cryptographic Tamper-Detection Tests for the HMAC-SHA256 Audit Log.
"""

import pytest
from paygate.tcb.audit import TamperEvidentAuditLog


def test_audit_log_clean_verification():
    log = TamperEvidentAuditLog(secret_key=b"audit_secret_test_123")
    for i in range(10):
        log.append(
            order_id=f"ORD-{i}",
            action_type="propose_capture",
            params={"amount": "100.00", "currency": "EUR"},
            decision="ALLOW",
            violated_rules=[],
            timestamp=1700000000.0 + i,
        )

    valid, msg = log.verify()
    assert valid is True
    assert msg == "Chain verified successfully"


def test_audit_log_detects_single_bit_payload_modification():
    log = TamperEvidentAuditLog(secret_key=b"audit_secret_test_123")
    for i in range(5):
        log.append(
            order_id=f"ORD-{i}",
            action_type="propose_capture",
            params={"amount": "100.00"},
            decision="ALLOW",
            violated_rules=[],
            timestamp=1700000000.0 + i,
        )

    # Tamper with entry 2 parameters
    log.entries[2].params["amount"] = "999.00"

    valid, msg = log.verify()
    assert valid is False
    assert "Tamper detected at position 2" in msg


def test_audit_log_detects_entry_deletion():
    log = TamperEvidentAuditLog(secret_key=b"audit_secret_test_123")
    for i in range(5):
        log.append(
            order_id=f"ORD-{i}",
            action_type="propose_capture",
            params={"amount": "100.00"},
            decision="ALLOW",
            violated_rules=[],
            timestamp=1700000000.0 + i,
        )

    # Delete entry at position 2
    del log.entries[2]

    valid, msg = log.verify()
    assert valid is False
    assert "Index mismatch" in msg or "Chain break" in msg


def test_audit_log_detects_reordering():
    log = TamperEvidentAuditLog(secret_key=b"audit_secret_test_123")
    for i in range(4):
        log.append(
            order_id=f"ORD-{i}",
            action_type="propose_capture",
            params={"amount": "100.00"},
            decision="ALLOW",
            violated_rules=[],
            timestamp=1700000000.0 + i,
        )

    # Swap entries 1 and 2
    log.entries[1], log.entries[2] = log.entries[2], log.entries[1]

    valid, msg = log.verify()
    assert valid is False
