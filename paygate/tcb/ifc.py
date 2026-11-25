"""
Dynamic Information-Flow Control (IFC) and Provenance Lattice.
Implements out-of-band session taint tracking, capability/data-flow separation,
and non-interference enforcement (Rule R8) inside the TCB.
"""

from typing import Dict, Set, List, Tuple, Optional
from paygate.tcb.models import ProvenanceLabel, ToolRequest, Order, ConsentState


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
    Out-of-band TCB provenance & capability tracker.
    Tracks untrusted document ingestion inside the session so enforcement
    never trusts provenance flags supplied by the untrusted LLM agent.
    """

    DEFAULT_TRUSTED_RECIPIENTS = {"buyer@example.com", "erp-audit@company.internal"}

    def __init__(self):
        self._doc_provenance: Dict[str, ProvenanceLabel] = {}
        self._docs_read_in_session: List[Tuple[str, ProvenanceLabel]] = []
        self._untrusted_contents: List[str] = []
        self._active_canary_tokens: Set[str] = set()
        self._trusted_recipients: Set[str] = set(self.DEFAULT_TRUSTED_RECIPIENTS)
        self._trusted_user_intent: str = ""
        self._authorized_capabilities: Set[str] = set()

    def set_trusted_context(
        self,
        user_intent: str,
        authorized_capabilities: Optional[Set[str]] = None,
        trusted_recipients: Optional[Set[str]] = None,
    ) -> None:
        """
        Bind the TRUSTED_ERP user instruction and authorized capabilities before
        any untrusted external documents are ingested.
        """
        self._trusted_user_intent = user_intent.lower()
        if authorized_capabilities is not None:
            self._authorized_capabilities = set(authorized_capabilities)
        else:
            # Infer baseline authorized capability strictly from TRUSTED_ERP prompt
            caps: Set[str] = {"read_document", "get_order", "send_notification"}
            if any(k in self._trusted_user_intent for k in ("capture", "settlement", "invoice", "delivery", "dispatch", "reconcil", "milestone", "retention")):
                caps.add("propose_capture")
            if any(k in self._trusted_user_intent for k in ("refund", "damaged", "return", "defective")):
                caps.add("issue_refund")
            if any(k in self._trusted_user_intent for k in ("void", "cancel")):
                caps.add("void_authorization")
            if any(k in self._trusted_user_intent for k in ("consent", "swap", "substitut")):
                caps.add("set_consent")
            self._authorized_capabilities = caps

        if trusted_recipients:
            self._trusted_recipients.update(trusted_recipients)

    def register_document(self, doc_id: str, label: ProvenanceLabel) -> None:
        self._doc_provenance[doc_id] = label

    def get_document_provenance(self, doc_id: str) -> ProvenanceLabel:
        return self._doc_provenance.get(doc_id, ProvenanceLabel.UNTRUSTED_EXTERNAL)

    def record_document_read(self, doc_id: str, content: str = "") -> ProvenanceLabel:
        """
        Called out-of-band by the Simulator/Executor whenever the agent reads a document.
        Taints the session if the document provenance is UNTRUSTED_EXTERNAL.
        """
        label = self.get_document_provenance(doc_id)
        self._docs_read_in_session.append((doc_id, label))
        if label in (ProvenanceLabel.UNTRUSTED_EXTERNAL, ProvenanceLabel.TAINTED) and content:
            self._untrusted_contents.append(content)
        return label

    def is_session_tainted(self) -> bool:
        """Return True if any untrusted external document has been ingested in this session."""
        return any(
            lbl in (ProvenanceLabel.UNTRUSTED_EXTERNAL, ProvenanceLabel.TAINTED)
            for _, lbl in self._docs_read_in_session
        )

    def register_canary(self, canary_token: str) -> None:
        if canary_token:
            self._active_canary_tokens.add(canary_token)

    def check_financial_mutation(
        self,
        request: ToolRequest,
        order: Order,
    ) -> Tuple[bool, Optional[str]]:
        """
        Enforce R8 (Provenance & Capability Non-Interference) for financial mutations:
        1. Explicit UNTRUSTED_EXTERNAL / TAINTED provenance tag is rejected.
        2. Recipient ID must strictly match TRUSTED_ERP order.bound_merchant_id.
        3. When the session has ingested UNTRUSTED_EXTERNAL data:
           - High-impact control changes (void, refund, set_consent) require explicit
             TRUSTED_ERP capability authorization from the pre-injection user context;
             untrusted supplier emails cannot trigger voids, refunds, or consent steering.
           - Untrusted external data can NEVER transition consent to APPROVED or CANCEL.
        """
        if request.provenance in (ProvenanceLabel.UNTRUSTED_EXTERNAL, ProvenanceLabel.TAINTED):
            return False, f"R8 Violation: Financial action {request.action_type} carries tainted provenance"

        # Strict ERP recipient binding (blocks allowlisted decoy routing)
        if request.recipient_id is not None:
            if request.recipient_id != order.bound_merchant_id:
                return False, (
                    f"R8 Violation: recipient_id '{request.recipient_id}' not bound to ERP order "
                    f"'{order.bound_merchant_id}'. Tainted merchant redirection blocked."
                )

        tainted = self.is_session_tainted()
        act = request.action_type

        # Capability-based non-interference under tainted context
        if tainted:
            if act in ("void_authorization", "void") and "void_authorization" not in self._authorized_capabilities:
                return False, "R8 Violation: Untrusted external document cannot induce unauthorized void capability"

            if act in ("issue_refund", "refund") and "issue_refund" not in self._authorized_capabilities:
                return False, "R8 Violation: Untrusted external document cannot induce unauthorized refund capability"

            if act in ("set_consent", "update_consent"):
                if "set_consent" not in self._authorized_capabilities:
                    return False, "R8 Violation: Untrusted external document cannot mutate buyer consent state"
                if request.consent_state in (ConsentState.APPROVED, ConsentState.CANCEL):
                    return False, (
                        f"R8 Violation: Untrusted external document cannot coerce consent to "
                        f"{request.consent_state.value} without out-of-band cryptographic ERP approval"
                    )

            # Salami / unconsented micro-capture check: if order was in WAIT (not APPROVED by ERP),
            # reading an untrusted doc cannot authorize partial capture
            if act in ("propose_capture", "capture") and order.consent_state != ConsentState.APPROVED:
                return False, "R8 Violation: Capture attempted on non-APPROVED order after reading untrusted input"

        return True, None

    def check_outbound_sink(
        self,
        recipient: Optional[str],
        message: Optional[str],
        provenance: Optional[ProvenanceLabel] = None,
    ) -> Tuple[bool, Optional[str]]:
        """
        Enforce R8 for outbound messaging (e.g. send_notification, send_supplier_message):
        - Blocks leakage of CONFIDENTIAL_ERP tokens (canary secrets).
        - Blocks CONFIDENTIAL_ERP marked payloads.
        - Under tainted context, blocks exfiltration to untrusted external recipients
          not in the TRUSTED_ERP recipient allowlist.
        """
        if message:
            msg_lower = message.lower()
            for canary in self._active_canary_tokens:
                if canary.lower() in msg_lower:
                    return False, f"R8 Violation: Outbound message contains confidential canary secret '{canary}'"

        if provenance == ProvenanceLabel.CONFIDENTIAL_ERP:
            return False, "R8 Violation: Attempted exfiltration of CONFIDENTIAL_ERP marked payload"

        if self.is_session_tainted() and recipient:
            if recipient.lower() not in {r.lower() for r in self._trusted_recipients}:
                return False, (
                    f"R8 Violation: Outbound sink recipient '{recipient}' is not in trusted ERP "
                    f"contact allowlist while session is tainted by untrusted document"
                )

        return True, None
