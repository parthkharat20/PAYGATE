"""
Statistical evaluation helpers for PayGate-Bench:
- Exact Wilson score 95% confidence intervals (handles k=0 edge case honestly)
- Continuity-corrected paired McNemar chi-squared & exact binomial tests
"""

import math
from typing import Tuple, List
from scipy.stats import binomtest


def wilson_score_interval(successes: int, total: int, z: float = 1.96) -> Tuple[float, float]:
    """
    Compute Wilson score confidence interval for binomial proportion k/n.
    Returns (lower_bound, upper_bound) in [0.0, 1.0].
    """
    if total <= 0:
        return 0.0, 0.0
    p = successes / total
    z2 = z * z
    denom = 1.0 + z2 / total
    center = (p + z2 / (2.0 * total)) / denom
    half_width = (z / denom) * math.sqrt((p * (1.0 - p) / total) + (z2 / (4.0 * total * total)))
    return max(0.0, center - half_width), min(1.0, center + half_width)


def mcnemar_paired_test(outcomes_a: List[bool], outcomes_b: List[bool]) -> Tuple[float, float]:
    """
    Compute paired McNemar test comparing configuration A vs configuration B
    on identical scenarios (True = attack succeeded / event occurred).
    Returns (chi2_statistic, exact_two_sided_p_value).
    """
    if len(outcomes_a) != len(outcomes_b):
        raise ValueError("Paired outcome lists must have identical length")

    b = 0  # A True, B False
    c = 0  # A False, B True
    for a_val, b_val in zip(outcomes_a, outcomes_b):
        if a_val and not b_val:
            b += 1
        elif not a_val and b_val:
            c += 1

    n_disc = b + c
    if n_disc == 0:
        return 0.0, 1.0

    chi2 = ((abs(b - c) - 1.0) ** 2) / n_disc if abs(b - c) >= 1 else 0.0
    p_val = float(binomtest(min(b, c), n=n_disc, p=0.5, alternative="two-sided").pvalue)
    return chi2, p_val
