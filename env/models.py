from enum import Enum
from decimal import Decimal
from pydantic import BaseModel, ConfigDict, Field


class OrderStatus(str, Enum):
    CREATED = "CREATED"
    AUTHORIZED = "AUTHORIZED"
    PARTIALLY_CAPTURED = "PARTIALLY_CAPTURED"
    FULLY_CAPTURED = "FULLY_CAPTURED"
    VOIDED = "VOIDED"
    EXPIRED = "EXPIRED"
    FAILED = "FAILED"


class ConsentState(str, Enum):
    WAIT = "WAIT"
    SWAP = "SWAP"
    CANCEL = "CANCEL"
    APPROVED = "APPROVED"


class ActionDecision(str, Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    REPLAY_CACHED = "REPLAY_CACHED"


class OrderItem(BaseModel):
    model_config = ConfigDict(strict=True)

    name: str
    quantity: int = Field(gt=0)
    unit_price: Decimal = Field(gt=Decimal("0.00"))


class GateDecision(BaseModel):
    model_config = ConfigDict(strict=True)

    action: ActionDecision
    rule: str
    reason: str
    all_violated_rules: list[str] = Field(default_factory=list)


class Order(BaseModel):
    model_config = ConfigDict(strict=True)

    order_id: str
    items: list[OrderItem]
    currency: str = Field(min_length=3, max_length=3)
    auth_amount: Decimal = Field(gt=Decimal("0.00"))
    captured_total: Decimal = Field(default=Decimal("0.00"), ge=Decimal("0.00"))
    refunded_total: Decimal = Field(default=Decimal("0.00"), ge=Decimal("0.00"))
    status: OrderStatus = Field(default=OrderStatus.AUTHORIZED)
    consent_state: ConsentState = Field(default=ConsentState.WAIT)
    auth_expires_at: float
    merchant_id: str
    canary_token: str

    @property
    def remaining_authorized(self) -> Decimal:
        return self.auth_amount - self.captured_total


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
    amount: Decimal | None = None
    currency: str | None = None
    recipient_id: str | None = None
    idempotency_key: str | None = None
    consent_state: ConsentState | None = None
    recipient: str | None = None
    message: str | None = None
    timestamp: float | None = None
