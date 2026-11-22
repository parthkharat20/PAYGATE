import sys
from decimal import Decimal
from eval.stats import wilson_score_interval, mcnemar_paired_test


def test_wilson_zero_successes():
    low, high = wilson_score_interval(successes=0, total=150, confidence=0.95)
    assert low == 0.0
    # For n=150 and z=1.96: z^2 / (n + z^2) = 3.8416 / (153.8416) ~ 0.02497
    assert 0.024 < high < 0.026
    print(f"PASS: Wilson zero successes interval for n=150 is [{low:.4f}, {high:.4f}]")


def test_wilson_standard_cases():
    low, high = wilson_score_interval(successes=50, total=100, confidence=0.95)
    assert 0.40 < low < 0.41
    assert 0.59 < high < 0.61
    print(f"PASS: Wilson 50/100 interval is [{low:.4f}, {high:.4f}]")


def test_mcnemar_test():
    # Config A blocks 25 cases where Config B failed (b=25)
    # Config B blocks 2 cases where Config A failed (c=2)
    res = mcnemar_paired_test(table_b=25, table_c=2)
    assert res["table_b"] == 25
    assert res["table_c"] == 2
    assert res["statistic"] > 15.0
    assert res["p_value"] < 0.001
    assert res["odds_ratio"] == 12.5
    print(f"PASS: McNemar paired test p-value: {res['p_value']:.6f}, odds-ratio: {res['odds_ratio']}")


if __name__ == "__main__":
    test_wilson_zero_successes()
    test_wilson_standard_cases()
    test_mcnemar_test()
    print("ALL STATS TESTS PASSED SUCCESSFULLY!")
