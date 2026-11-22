import hmac
import hashlib
import json
from pydantic import BaseModel, ConfigDict, Field


class AuditEntry(BaseModel):
    model_config = ConfigDict(strict=True)

    index: int
    timestamp: float
    order_id: str
    action_type: str
    params: dict
    gate_decision: str
    violated_rules: list[str] = Field(default_factory=list)
    previous_hash: str
    entry_hash: str


class AuditChain:
    """
    Append-only cryptographic audit chain using HMAC-SHA256.
    Detects modification, insertion, and reordering of earlier entries.
    Note: Tail truncation or head deletion cannot be detected locally without an external anchor.
    """

    def __init__(self, secret_key: bytes = b"paygate_audit_secret_key_v1"):
        self.secret_key = secret_key
        self.entries: list[AuditEntry] = []
        # Genesis hash
        self._genesis_hash = hmac.new(
            self.secret_key, b"GENESIS", hashlib.sha256
        ).hexdigest()

    def get_latest_hash(self) -> str:
        if not self.entries:
            return self._genesis_hash
        return self.entries[-1].entry_hash

    def append(
        self,
        order_id: str,
        action_type: str,
        params: dict,
        decision: str,
        violated_rules: list[str],
        timestamp: float,
    ) -> AuditEntry:
        index = len(self.entries)
        prev_hash = self.get_latest_hash()

        # Deterministic serialization of the entry payload
        payload = json.dumps(
            {
                "index": index,
                "timestamp": timestamp,
                "order_id": order_id,
                "action_type": action_type,
                "params": params,
                "gate_decision": decision,
                "violated_rules": sorted(violated_rules),
                "previous_hash": prev_hash,
            },
            sort_keys=True,
        ).encode("utf-8")

        entry_hash = hmac.new(self.secret_key, payload, hashlib.sha256).hexdigest()

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

    def verify(self) -> tuple[bool, str]:
        """
        Walk the chain forward and verify every hash link.
        Returns (True, "OK") or (False, "Failure description").
        """
        expected_prev_hash = self._genesis_hash

        for i, entry in enumerate(self.entries):
            if entry.index != i:
                return False, f"Index mismatch at position {i}: entry has index {entry.index}"

            if entry.previous_hash != expected_prev_hash:
                return (
                    False,
                    f"Chain break at position {i}: previous_hash {entry.previous_hash} "
                    f"!= expected {expected_prev_hash}",
                )

            # Recompute hash
            payload = json.dumps(
                {
                    "index": entry.index,
                    "timestamp": entry.timestamp,
                    "order_id": entry.order_id,
                    "action_type": entry.action_type,
                    "params": entry.params,
                    "gate_decision": entry.gate_decision,
                    "violated_rules": sorted(entry.violated_rules),
                    "previous_hash": entry.previous_hash,
                },
                sort_keys=True,
            ).encode("utf-8")

            computed_hash = hmac.new(self.secret_key, payload, hashlib.sha256).hexdigest()

            if entry.entry_hash != computed_hash:
                return (
                    False,
                    f"Tamper detected at position {i}: recorded hash {entry.entry_hash} "
                    f"!= computed hash {computed_hash}",
                )

            expected_prev_hash = entry.entry_hash

        return True, "Chain verified successfully"

    def get_entries(self) -> list[AuditEntry]:
        return list(self.entries)
