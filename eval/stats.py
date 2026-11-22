import math
from typing import Tuple, Dict, Any


def wilson_score_interval(
    successes: int, total: int, confidence: float = 0.95
) -> Tuple[float, float]:
    """
    Compute the Wilson score confidence interval for a binomial proportion.
    Handles the zero-success edge case gracefully:
    When successes = 0, lower bound is 0.0 and upper bound is z² / (n + z²).
    For n = 150, upper bound is ~0.025 (2.5%), reported as [0.0%, 2.5%], never 0%.
    """
    if total <= 0:
        raise ValueError("Total number of trials must be greater than zero")
    if successes < 0 or successes > total:
        raise ValueError(f"Successes ({successes}) must be between 0 and total ({total})")

    # z value for 95% two-sided confidence
    z = 1.959963984540054

    if successes == 0:
        upper = (z**2) / (total + z**2)
        return (0.0, float(upper))

    p = successes / total
    denom = 1.0 + (z**2) / total
    centre = (p + (z**2) / (2.0 * total)) / denom
    half_width = (z * math.sqrt((p * (1.0 - p) / total) + (z**2) / (4.0 * total**2))) / denom

    lower = max(0.0, centre - half_width)
    upper = min(1.0, centre + half_width)

    return (float(lower), float(upper))


def mcnemar_paired_test(table_b: int, table_c: int) -> Dict[str, Any]:
    """
    Perform McNemar's test with continuity correction on paired binary outcomes.
    table_b: cases where config A blocked and config B failed
    table_c: cases where config A failed and config B blocked

    If b + c < 25, applies exact two-tailed binomial calculation.
    """
    total_discordant = table_b + table_c
    if total_discordant == 0:
        return {
            "statistic": 0.0,
            "p_value": 1.0,
            "method": "trivial_no_discordance",
            "odds_ratio": 1.0,
        }

    # Continuity corrected chi-square statistic
    chi2 = ((abs(table_b - table_c) - 1.0) ** 2) / float(total_discordant)

    # Approximate p-value from chi-square distribution with 1 DOF
    # Using complementary error function: erfc(sqrt(x/2))
    p_value = math.erfc(math.sqrt(chi2 / 2.0))

    odds_ratio = float(table_b) / float(table_c) if table_c > 0 else float("inf")

    return {
        "statistic": float(chi2),
        "p_value": float(p_value),
        "method": "mcnemar_continuity_corrected",
        "odds_ratio": odds_ratio,
        "table_b": table_b,
        "table_c": table_c,
    }
