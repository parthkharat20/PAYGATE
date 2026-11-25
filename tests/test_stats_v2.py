"""
Statistical Evaluation Tests (Wilson 95% CIs and McNemar Paired Tests).
"""

from paygate.bench.stats import wilson_score_interval, mcnemar_paired_test


def test_wilson_zero_successes():
    lo, hi = wilson_score_interval(0, 100)
    assert lo == 0.0
    assert 0.03 < hi < 0.045  # ~3.7% upper bound at n=100


def test_wilson_standard_proportion():
    lo, hi = wilson_score_interval(50, 100)
    assert 0.39 < lo < 0.42
    assert 0.58 < hi < 0.61


def test_mcnemar_paired_significance():
    # Baseline A has 15 attacks succeed, PayGate B has 0 attacks succeed
    a = [True] * 15 + [False] * 10
    b = [False] * 25
    chi2, p_val = mcnemar_paired_test(a, b)
    assert chi2 > 10.0
    assert p_val < 0.001
