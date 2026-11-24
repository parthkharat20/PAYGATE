"""
Dynamic Information-Flow Control (IFC) and Provenance Lattice.
Implements capability/data-flow separation and non-interference enforcement (Rule R8).
"""

from typing import Dict, Set, List, Tuple, Optional
from paygate.tcb.models import ProvenanceLabel, ToolRequest, Order


class ProvenanceLattice:
    """
    Security Lattice for B2B Agent Computation:
             TAINTED (Top / Untrusted Execution)
            /       \\
    UNTRUSTED_EXT   CONFIDENTIAL_ERP
            \\       /
            TRUSTED_ERP (Bottom / High Integrity)
    """

    @staticmethod
    def join(l1: ProvenanceLabel, l2: ProvenanceLabel) -> ProvenanceLabel:
        if l1 == l2:
            return l1
        if l1 == ProvenanceLabel.TAINTED or l2 == ProvenanceLabel.TAINTED:
            return ProvenanceLabel.TAINTED
        if (l1 == ProvenanceLabel.UNTRUSTED_EXTERNAL and l2 == ProvenanceLabel.CONFIDENTIAL_ERP) or \
           (l2 == ProvenanceLabel.UNTRUSTED_EXTERNAL and l1 == ProvenanceLabel.CONFIDENTIAL_ERP):
            return ProvenanceLabel.TAINTED
        if l1 == ProvenanceLabel.UNTRUSTED_EXTERNAL or l2 == ProvenanceLabel.UNTRUSTED_EXTERNAL:
            return ProvenanceLabel.TAINTED
        if l1 == ProvenanceLabel.CONFIDENTIAL_ERP or l2 == ProvenanceLabel.CONFIDENTIAL_ERP:
            return ProvenanceLabel.CONFIDENTIAL_ERP
        return ProvenanceLabel.TRUSTED_ERP


class TaintTracker:
    """
    Tracks lineage and taint labels for values across agent execution.
    Enforces Rule R8 (Provenance Non-Interference) on financial mutations and outbound sinks.
    """

    def __init__(self):
        self._doc_provenance: Dict[str, ProvenanceLabel] = {}
        self._field_provenance: Dict[str, ProvenanceLabel] = {}
        self._active_canary_tokens: Set[str] = set()

    def register_document(self, doc_id: str, label: ProvenanceLabel) -> None:
        self._doc_provenance[doc_id] = label

    def get_document_provenance(self, doc_id: str) -> ProvenanceLabel:
        return self._doc_provenance.get(doc_id, ProvenanceLabel.UNTRUSTED_EXTERNAL)

    def register_canary(self, canary_token: str) -> None:
        if canary_token:
            self._active_canary_tokens.add(canary_token)

    def check_financial_mutation(
        self,
        request: ToolRequest,
        order: Order,
    ) -> Tuple[bool, Optional[str]]:
        """
        Enforce R8 for financial mutations (capture, void, refund, set_consent).
        - Rejects any recipient_id derived from UNTRUSTED_EXTERNAL / TAINTED.
        - Rejects consent state changes triggered by UNTRUSTED_EXTERNAL / TAINTED.
        - Ensures merchant_id is strictly bound to order.bound_merchant_id (TRUSTED_ERP).
        """
        # If the request explicitly carries an untrusted/tainted provenance tag
        if request.provenance in (ProvenanceLabel.UNTRUSTED_EXTERNAL, ProvenanceLabel.TAINTED):
            return False, f"R8 Violation: Financial action {request.action_type} tainted by UNTRUSTED_EXTERNAL source"

        # Merchant ID provenance check
        if request.recipient_id is not None:
            if request.recipient_id != order.bound_merchant_id:
                # Any redirect away from bound merchant is an untrusted steering attempt
                return False, (
                    f"R8 Violation: recipient_id '{request.recipient_id}' not bound to ERP order "
                    f"'{order.bound_merchant_id}'. Tainted merchant redirection blocked."
                )

        # Consent change provenance check
        if request.action_type in ("set_consent", "update_consent"):
            if request.provenance == ProvenanceLabel.UNTRUSTED_EXTERNAL:
                return False, "R8 Violation: Cannot update consent based on untrusted external notice"

        return True, None

    def check_outbound_sink(
        self,
        recipient: Optional[str],
        message: Optional[str],
        provenance: Optional[ProvenanceLabel] = None,
    ) -> Tuple[bool, Optional[str]]:
        """
        Enforce R8 for outbound messaging (e.g. send_notification, send_supplier_message).
        - Blocks leakage of CONFIDENTIAL_ERP tokens (canary secrets).
        - Blocks messaging to arbitrary untrusted external recipients.
        """
        if message:
            for canary in self._active_canary_tokens:
                if canary in message:
                    return False, f"R8 Violation: Outbound message contains confidential canary secret '{canary}'"

        if provenance == ProvenanceLabel.CONFIDENTIAL_ERP:
            return False, "R8 Violation: Attempted exfiltration of CONFIDENTIAL_ERP marked payload"

        return True, None
