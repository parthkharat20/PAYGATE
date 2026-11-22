from typing import List, Dict, Any, Set
from decimal import Decimal
from env.models import Order, ToolRequest, ActionDecision, GateDecision
from env.fake_clock import FakeClock
from env.audit_chain import AuditChain
from defenses.gate import DeterministicGate


class ReplayEngine:
    """
    Offline Leave-One-Rule-Out Ablation Engine.
    Replays recorded agent proposals through gate variants offline with zero API calls.
    Ablates rules R1 through R5. (R6 and R7 are evaluated in dedicated tests).
    """

    def __init__(self, merchant_allowlist: Set[str]):
        self.merchant_allowlist = set(merchant_allowlist)
        self.rules_to_ablate = ["R1", "R2", "R3", "R4", "R5"]

    def run_ablation(
        self,
        proposals: List[Dict[str, Any]],
        orders: Dict[str, Order],
    ) -> Dict[str, Any]:
        """
        Evaluate each proposal across:
        - Full Gate (R1-R5)
        - -R1 (Cap removed)
        - -R2 (Currency removed)
        - -R3 (Allowlist removed)
        - -R4 (Rate limit removed)
        - -R5 (Idempotency removed)

        Identifies the critical blocker rule for each attack case.
        """
        results: Dict[str, Dict[str, str]] = {}
        critical_blockers: Dict[str, str] = {}

        for item in proposals:
            case_id = item["case_id"]
            order_id = item["order_id"]
            order = orders[order_id]
            req_data = dict(item["request"])
            if "amount" in req_data and req_data["amount"] is not None and not isinstance(req_data["amount"], Decimal):
                req_data["amount"] = Decimal(str(req_data["amount"]))
            req = ToolRequest(**req_data)

            # 1. Full Gate
            full_chain = AuditChain(secret_key=b"ablation_key")
            full_gate = DeterministicGate(self.merchant_allowlist, full_chain)
            clock = FakeClock(item.get("timestamp", 1700000000.0))
            full_dec = full_gate.evaluate(req, order, clock, active_rules=set(self.rules_to_ablate))

            case_decisions: Dict[str, str] = {"Full": full_dec.action.value}
            dropped_allowing_rules: List[str] = []

            # 2. Leave one rule out
            for rule in self.rules_to_ablate:
                ablated_rules = set(self.rules_to_ablate) - {rule}
                ablated_chain = AuditChain(secret_key=b"ablation_key")
                gate = DeterministicGate(self.merchant_allowlist, ablated_chain)
                dec = gate.evaluate(req, order, clock, active_rules=ablated_rules)
                case_decisions[f"-{rule}"] = dec.action.value

                # If full gate blocked, but removing this rule allows, it is a critical blocker
                if full_dec.action == ActionDecision.BLOCK and dec.action == ActionDecision.ALLOW:
                    dropped_allowing_rules.append(rule)

            results[case_id] = case_decisions

            if len(dropped_allowing_rules) == 1:
                critical_blockers[case_id] = dropped_allowing_rules[0]
            elif len(dropped_allowing_rules) > 1:
                critical_blockers[case_id] = f"Multiple ({', '.join(dropped_allowing_rules)})"
            else:
                critical_blockers[case_id] = "None (in-policy / multi-violation)"

        return {
            "matrix": results,
            "critical_blockers": critical_blockers,
        }
