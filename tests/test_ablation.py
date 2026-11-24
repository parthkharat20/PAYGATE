"""
End-to-End Test for 4-Baseline Ablation Suite.
"""

import os
from scripts.run_ablation import run_ablation


def test_run_ablation_mock_execution(tmp_path):
    output_dir = str(tmp_path / "results")
    summary = run_ablation(mock_mode=True, output_dir=output_dir)

    assert "no_defense" in summary
    assert "prompt_plus_llm_judge" in summary
    assert "static_gateway_r1_r5" in summary
    assert "paygate_full" in summary

    # Invariants on mock evaluation
    assert summary["no_defense"]["oop_asr_pct"] == 100.0
    assert summary["no_defense"]["ip_asr_pct"] == 100.0

    # PayGate full should achieve 0% ASR on both out-of-policy and in-policy attacks
    assert summary["paygate_full"]["oop_asr_pct"] == 0.0
    assert summary["paygate_full"]["ip_asr_pct"] == 0.0

    # Verify JSON traces created
    assert os.path.exists(os.path.join(output_dir, "raw_runs.jsonl"))
    assert os.path.exists(os.path.join(output_dir, "ablation_summary.json"))
