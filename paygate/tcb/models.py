"""
Strict Pydantic models and Enums for the PayGate Trusted Computing Base.
Enforces double-entry precision with Decimal and deterministic serialization.
"""

from enum import Enum
from decimal import Decimal
import hashlib
import json
from typing import List, Optional
from pydantic import BaseModel, ConfigDict, Field, model_validator


class OrderStatus(str, Enum):
    CREATED = "CREATED"
    AUTHORIZED = "AUTHORIZED"
    PARTIALLY_CAPTURED = "PARTIALLY_CAPTURED"
    SETTLED = "SETTLED"
    VOIDED = "VOIDED"
    EXPIRED = "EXPIRED"
    REFUNDED = "REFUNDED"


class ConsentState(str, Enum):
    WAIT = "WAIT"
    SWAP = "SWAP"
    CANCEL = "CANCEL"
    APPROVED = "APPROVED"


class ActionDecision(str, Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    REPLAY_CACHED = "REPLAY_CACHED"


class ProvenanceLabel(str, Enum):
    TRUSTED_ERP = "TRUSTED_ERP"
    UNTRUSTED_EXTERNAL = "UNTRUSTED_EXTERNAL"
    CONFIDENTIAL_ERP = "CONFIDENTIAL_ERP"
    TAINTED = "TAINTED"


class OrderItem(BaseModel):
    model_config = ConfigDict(strict=True)

    name: str
    quantity: int = Field(gt=0)
    unit_price: Decimal = Field(gt=Decimal("0.00"))

    def canonical_dict(self) -> dict:
        return {
            "name": self.name,
            "quantity": self.quantity,
            "unit_price": str(self.unit_price),
        }


class GateDecision(BaseModel):
    model_config = ConfigDict(strict=True)

    action: ActionDecision
    rule: str
    reason: str
    all_violated_rules: List[str] = Field(default_factory=list)


class Order(BaseModel):
    model_config = ConfigDict(strict=True)

    order_id: str
    items: List[OrderItem]
    currency: str = Field(min_length=3, max_length=3)
    auth_amount: Decimal = Field(gt=Decimal("0.00"))
    captured_total: Decimal = Field(default=Decimal("0.00"), ge=Decimal("0.00"))
    refunded_total: Decimal = Field(default=Decimal("0.00"), ge=Decimal("0.00"))
    status: OrderStatus = Field(default=OrderStatus.AUTHORIZED)
    consent_state: ConsentState = Field(default=ConsentState.WAIT)
    auth_expires_at: float
    merchant_id: str
    bound_merchant_id: Optional[str] = None
    canary_token: str
    po_hash: Optional[str] = None
    consent_token: Optional[str] = None

    @model_validator(mode="after")
    def populate_defaults(self) -> "Order":
        if self.bound_merchant_id is None:
            self.bound_merchant_id = self.merchant_id
        if self.po_hash is None:
            items_repr = json.dumps([item.canonical_dict() for item in self.items], sort_keys=True)
            self.po_hash = hashlib.sha256(
                f"{self.order_id}:{self.currency}:{str(self.auth_amount)}:{items_repr}".encode("utf-8")
            ).hexdigest()
        return self

    @property
    def remaining_authorized(self) -> Decimal:
        return self.auth_amount - self.captured_total

    @property
    def refundable_amount(self) -> Decimal:
        return self.captured_total - self.refunded_total


class CaptureRecord(BaseModel):
    model_config = ConfigDict(strict=True)

    capture_id: str
    order_id: str
    amount: Decimal = Field(gt=Decimal("0.00"))
    currency: str = Field(min_length=3, max_length=3)
    recipient_id: str
    idempotency_key: str
    timestamp: float
    gate_decision: GateDecision


class RefundRecord(BaseModel):
    model_config = ConfigDict(strict=True)

    refund_id: str
    order_id: str
    amount: Decimal = Field(gt=Decimal("0.00"))
    currency: str = Field(min_length=3, max_length=3)
    idempotency_key: str
    timestamp: float
    gate_decision: GateDecision


class ToolRequest(BaseModel):
    model_config = ConfigDict(strict=True)

    action_type: str
    order_id: str
    amount: Optional[Decimal] = None
    currency: Optional[str] = None
    recipient_id: Optional[str] = None
    idempotency_key: Optional[str] = None
    consent_state: Optional[ConsentState] = None
    recipient: Optional[str] = None
    message: Optional[str] = None
    timestamp: Optional[float] = None
    provenance: Optional[ProvenanceLabel] = None
    token: Optional[str] = None
