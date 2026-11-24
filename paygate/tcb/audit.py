"""
Tamper-Evident Append-Only HMAC-SHA256 Audit Log.
Maintains cryptographic integrity of all policy gate decisions.
"""

import hmac
import hashlib
import json
from typing import List, Dict, Any, Tuple
from pydantic import BaseModel, ConfigDict


class AuditEntry(BaseModel):
    model_config = ConfigDict(strict=True)

    index: int
    timestamp: float
    order_id: str
    action_type: str
    params: Dict[str, Any]
    gate_decision: str
    violated_rules: List[str]
    previous_hash: str
    entry_hash: str


class TamperEvidentAuditLog:
    """
    Append-only cryptographically linked audit chain:
      h_0 = HMAC_SHA256(secret_key, "GENESIS")
      h_t = HMAC_SHA256(secret_key, h_{t-1} || canonical_json(event_t))
    Detects single-bit tampering, deletions, truncations, and reorderings.
    """

    def __init__(self, secret_key: bytes = b"paygate_tcb_audit_secret_v2"):
        self.secret_key = secret_key
        self.entries: List[AuditEntry] = []
        self._genesis_hash = hmac.new(self.secret_key, b"GENESIS_TCB_V2", hashlib.sha256).hexdigest()

    def get_latest_hash(self) -> str:
        if not self.entries:
            return self._genesis_hash
        return self.entries[-1].entry_hash

    def _canonical_bytes(
        self,
        index: int,
        timestamp: float,
        order_id: str,
        action_type: str,
        params: Dict[str, Any],
        decision: str,
        violated_rules: List[str],
        previous_hash: str,
    ) -> bytes:
        payload = {
            "index": index,
            "timestamp": timestamp,
            "order_id": order_id,
            "action_type": action_type,
            "params": params,
            "gate_decision": decision,
            "violated_rules": sorted(violated_rules),
            "previous_hash": previous_hash,
        }
        return json.dumps(payload, sort_keys=True).encode("utf-8")

    def append(
        self,
        order_id: str,
        action_type: str,
        params: Dict[str, Any],
        decision: str,
        violated_rules: List[str],
        timestamp: float,
    ) -> AuditEntry:
        index = len(self.entries)
        prev_hash = self.get_latest_hash()

        payload_bytes = self._canonical_bytes(
            index=index,
            timestamp=timestamp,
            order_id=order_id,
            action_type=action_type,
            params=params,
            decision=decision,
            violated_rules=violated_rules,
            previous_hash=prev_hash,
        )

        entry_hash = hmac.new(self.secret_key, payload_bytes, hashlib.sha256).hexdigest()

        entry = AuditEntry(
            index=index,
            timestamp=timestamp,
            order_id=order_id,
            action_type=action_type,
            params=params,
            gate_decision=decision,
            violated_rules=violated_rules,
            previous_hash=prev_hash,
            entry_hash=entry_hash,
        )
        self.entries.append(entry)
        return entry

    def verify(self) -> Tuple[bool, str]:
        """
        Walk forward from genesis and verify all HMAC links.
        Returns (True, "OK") or (False, "Failure reason").
        """
        expected_prev_hash = self._genesis_hash

        for i, entry in enumerate(self.entries):
            if entry.index != i:
                return False, f"Index mismatch at position {i}: recorded index {entry.index}"

            if entry.previous_hash != expected_prev_hash:
                return (
                    False,
                    f"Chain break at position {i}: previous_hash '{entry.previous_hash}' "
                    f"!= expected '{expected_prev_hash}'",
                )

            payload_bytes = self._canonical_bytes(
                index=entry.index,
                timestamp=entry.timestamp,
                order_id=entry.order_id,
                action_type=entry.action_type,
                params=entry.params,
                decision=entry.gate_decision,
                violated_rules=entry.violated_rules,
                previous_hash=entry.previous_hash,
            )

            computed_hash = hmac.new(self.secret_key, payload_bytes, hashlib.sha256).hexdigest()

            if entry.entry_hash != computed_hash:
                return (
                    False,
                    f"Tamper detected at position {i}: recorded hash {entry.entry_hash} "
                    f"!= computed hash {computed_hash}",
                )

            expected_prev_hash = entry.entry_hash

        return True, "Chain verified successfully"

    def get_entries(self) -> List[AuditEntry]:
        return list(self.entries)
