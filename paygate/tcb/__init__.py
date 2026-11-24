"""
PayGate Trusted Computing Base (TCB).

STRICT ISOLATION INVARIANT:
This package must contain ZERO dependencies on LLM clients, agent frameworks,
network I/O, or HTTP libraries (e.g. openai, anthropic, langchain, requests, httpx).
All modules here represent purely deterministic state machines, formal policy gates,
cryptographic hash chains, and in-memory execution engines.
"""

from paygate.tcb.clock import VirtualClock
from paygate.tcb.models import (
    OrderStatus,
    ConsentState,
    ActionDecision,
    ProvenanceLabel,
    OrderItem,
    Order,
    ToolRequest,
    GateDecision,
    CaptureRecord,
    RefundRecord,
)
from paygate.tcb.dfa import PaymentDFA, DFAStateTransitionError
from paygate.tcb.ifc import ProvenanceLattice, TaintTracker
from paygate.tcb.audit import TamperEvidentAuditLog, AuditEntry
from paygate.tcb.invariants import DeterministicGate
from paygate.tcb.simulator import StateSimulator

__all__ = [
    "VirtualClock",
    "OrderStatus",
    "ConsentState",
    "ActionDecision",
    "ProvenanceLabel",
    "OrderItem",
    "Order",
    "ToolRequest",
    "GateDecision",
    "CaptureRecord",
    "RefundRecord",
    "PaymentDFA",
    "DFAStateTransitionError",
    "ProvenanceLattice",
    "TaintTracker",
    "TamperEvidentAuditLog",
    "AuditEntry",
    "DeterministicGate",
    "StateSimulator",
]
