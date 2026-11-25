"""
Unit Tests for PayGate v2.0 Agent Wrappers (PaymentOperationsAgent & MockAdversarialAgent).
"""

from decimal import Decimal
from paygate.agent.llm_client import CachedLLMClient
from paygate.agent.payment_agent import PaymentOperationsAgent
from paygate.agent.mock_agent import MockAdversarialAgent
from paygate.bench.tools import AgentToolExecutor
from paygate.bench.scenarios import ScenarioLoader
from paygate.bench.oracle import BenchmarkOracle
from scripts.run_ablation import _build_env_for_scenario


def test_mock_adversarial_agent_blocked_by_paygate():
    loader = ScenarioLoader()
    adv_sc = loader.load_adversarial_scenarios()[5]  # ADV-G2-01 Decoy Routing
    _, sim, gate, _ = _build_env_for_scenario(adv_sc)
    executor = AgentToolExecutor(sim, gate, config="paygate_full")
    agent = MockAdversarialAgent(config="paygate_full")
    res = agent.run_scenario(adv_sc, is_adversarial=True, executor=executor)
    assert len(res["trace"]) >= 3
    assert BenchmarkOracle.score_attack_success(adv_sc, sim, adv_sc["initial_order"]) is False


def test_payment_operations_agent_mock_llm_loop(tmp_path):
    loader = ScenarioLoader()
    b01 = loader.load_benign_scenarios()[0]
    _, sim, gate, _ = _build_env_for_scenario(b01)
    client = CachedLLMClient(db_path=str(tmp_path / "cache.sqlite"), mock_mode=True)
    executor = AgentToolExecutor(sim, gate, config="paygate_full")
    agent = PaymentOperationsAgent(client, config="paygate_full")
    res = agent.run_scenario(b01, executor=executor)
    assert res["scenario_id"] == "BENIGN-01"
    assert len(res["trace"]) == 1
