"""
Publication-Quality Matplotlib Figure Generator for PayGate-Bench.
Generates:
1. docs/figures/asr_vs_utility_tradeoff.png: Grouped bar chart comparing Utility, OOP ASR, and IP ASR.
2. docs/figures/latency_cdf.png: Empirical CDF comparing TCB overhead (<1 ms) vs LLM Guardrails (~250 ms).
"""

import os
import json
import numpy as np
import matplotlib.pyplot as plt
from typing import Dict, Any, List


def plot_asr_utility_tradeoff(summary_data: Dict[str, Any], output_path: str = "docs/figures/asr_vs_utility_tradeoff.png") -> None:
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    baselines = ["no_defense", "prompt_plus_llm_judge", "static_gateway_r1_r5", "paygate_full"]
    labels = ["No Defense\n(C0a)", "Prompt + Judge\n(C1)", "Static Gateway\n(R1–R5)", "PayGate Full\n(TCB + R1–R8)"]

    utility_vals = [summary_data[b]["benign_utility_pct"] for b in baselines]
    oop_asr_vals = [summary_data[b]["oop_asr_pct"] for b in baselines]
    ip_asr_vals = [summary_data[b]["ip_asr_pct"] for b in baselines]

    x = np.arange(len(baselines))
    width = 0.25

    plt.style.use("seaborn-v0_8-whitegrid" if "seaborn-v0_8-whitegrid" in plt.style.available else "default")
    fig, ax = plt.subplots(figsize=(10, 5.5), dpi=300)

    rects1 = ax.bar(x - width, utility_vals, width, label="Benign Utility (%)", color="#1b9e77", edgecolor="black", linewidth=0.8)
    rects2 = ax.bar(x, oop_asr_vals, width, label="Out-of-Policy ASR (G1–G3) (%)", color="#d95f02", edgecolor="black", linewidth=0.8)
    rects3 = ax.bar(x + width, ip_asr_vals, width, label="In-Policy Semantic ASR (G4–G5) (%)", color="#7570b3", edgecolor="black", linewidth=0.8)

    ax.set_ylabel("Rate (%)", fontsize=12, fontweight="bold")
    ax.set_title("PayGate-Bench: Security & Utility Tradeoff Across Defense Baselines (N=50)", fontsize=13, fontweight="bold", pad=14)
    ax.set_xticks(x)
    ax.set_xticklabels(labels, fontsize=11)
    ax.set_ylim(0, 115)
    ax.legend(loc="upper right", frameon=True, fontsize=10)

    # Value labels on bars
    for rects in (rects1, rects2, rects3):
        for rect in rects:
            height = rect.get_height()
            ax.annotate(
                f"{height:.1f}%",
                xy=(rect.get_x() + rect.get_width() / 2, height),
                xytext=(0, 3),
                textcoords="offset points",
                ha="center",
                va="bottom",
                fontsize=9,
                fontweight="semibold",
            )

    plt.tight_layout()
    plt.savefig(output_path)
    plt.close()
    print(f"Generated tradeoff figure at: {output_path}")


def plot_latency_cdf(latencies_by_baseline: Dict[str, List[float]], output_path: str = "docs/figures/latency_cdf.png") -> None:
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    fig, ax = plt.subplots(figsize=(9, 5), dpi=300)
    plt.style.use("seaborn-v0_8-whitegrid" if "seaborn-v0_8-whitegrid" in plt.style.available else "default")

    colors = {
        "static_gateway_r1_r5": ("#386cb0", "Static Gateway (R1-R5)"),
        "paygate_full": ("#1b9e77", "PayGate Full TCB (R1-R8)"),
        "prompt_plus_llm_judge": ("#d95f02", "LLM-as-a-Judge Guardrail"),
    }

    for key, (color, label) in colors.items():
        data = latencies_by_baseline.get(key, [])
        if not data:
            continue
        sorted_data = np.sort(data)
        y = np.linspace(0, 1, len(sorted_data))
        ax.plot(sorted_data, y, label=label, color=color, linewidth=2.2)

    ax.set_xscale("log")
    ax.set_xlabel("Decision Latency Overhead (ms) [Log Scale]", fontsize=12, fontweight="bold")
    ax.set_ylabel("Cumulative Empirical Probability (CDF)", fontsize=12, fontweight="bold")
    ax.set_title("Runtime Policy Gate Latency CDF vs. LLM Guardrail Overhead", fontsize=13, fontweight="bold", pad=12)
    ax.axvline(x=1.0, color="gray", linestyle="--", alpha=0.7, label="1 ms Sub-millisecond SLA")
    ax.legend(loc="lower right", frameon=True, fontsize=10)
    ax.set_ylim(-0.02, 1.02)

    plt.tight_layout()
    plt.savefig(output_path)
    plt.close()
    print(f"Generated latency CDF figure at: {output_path}")
