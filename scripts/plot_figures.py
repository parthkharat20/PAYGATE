"""
Publication-Quality Matplotlib Figure Generator for PayGate-Bench.
All figures are strictly data-driven from recorded JSONL / JSON measurements.
Generates:
1. docs/figures/asr_vs_utility_tradeoff.png: Grouped bar chart comparing Clean Utility, Utility Under Attack, OOP ASR, and IP ASR.
2. docs/figures/latency_cdf.png: Empirical CDF comparing measured TCB gate overhead vs. real LLM Judge latency.
"""

import os
os.environ.setdefault("MPLCONFIGDIR", "/tmp/matplotlib_cache")
import numpy as np
import matplotlib.pyplot as plt
from typing import Dict, Any, List


def plot_asr_utility_tradeoff(
    summary_data: Dict[str, Any],
    output_path: str = "docs/figures/asr_vs_utility_tradeoff.png",
    subtitle: str = "Live Multi-Model Evaluation",
) -> None:
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    baselines = ["no_defense", "prompt_plus_llm_judge", "static_gateway_r1_r5", "paygate_full"]
    labels = ["No Defense\n(Unconstrained)", "Prompt +\nLLM Judge", "Static Gateway\n(R1–R5)", "PayGate Full\n(TCB R1–R8)"]

    utility_vals = [summary_data[b]["benign_utility_pct"] for b in baselines]
    dual_vals = [summary_data[b].get("dual_utility_pct", 0.0) for b in baselines]
    oop_asr_vals = [summary_data[b]["oop_asr_pct"] for b in baselines]
    ip_asr_vals = [summary_data[b]["ip_asr_pct"] for b in baselines]

    x = np.arange(len(baselines))
    width = 0.20

    plt.style.use("seaborn-v0_8-whitegrid" if "seaborn-v0_8-whitegrid" in plt.style.available else "default")
    fig, ax = plt.subplots(figsize=(11.5, 5.8), dpi=300)

    rects1 = ax.bar(x - 1.5 * width, utility_vals, width, label="Benign Utility (Clean) (%)", color="#1b9e77", edgecolor="black", linewidth=0.7)
    rects2 = ax.bar(x - 0.5 * width, dual_vals, width, label="Utility Under Attack (Dual) (%)", color="#66c2a5", edgecolor="black", linewidth=0.7)
    rects3 = ax.bar(x + 0.5 * width, oop_asr_vals, width, label="Out-of-Policy ASR (G1–G3) (%)", color="#d95f02", edgecolor="black", linewidth=0.7)
    rects4 = ax.bar(x + 1.5 * width, ip_asr_vals, width, label="In-Policy Semantic ASR (G4–G5) (%)", color="#7570b3", edgecolor="black", linewidth=0.7)

    ax.set_ylabel("Rate (%)", fontsize=12, fontweight="bold")
    ax.set_title(f"PayGate-Bench: Security & Utility Under Attack Tradeoff\n{subtitle}", fontsize=13, fontweight="bold", pad=14)
    ax.set_xticks(x)
    ax.set_xticklabels(labels, fontsize=11)
    ax.set_ylim(0, 120)
    ax.legend(loc="upper right", frameon=True, fontsize=9.5, ncol=2)

    for rects in (rects1, rects2, rects3, rects4):
        for rect in rects:
            height = rect.get_height()
            ax.annotate(
                f"{height:.0f}%",
                xy=(rect.get_x() + rect.get_width() / 2, height),
                xytext=(0, 3),
                textcoords="offset points",
                ha="center",
                va="bottom",
                fontsize=8,
                fontweight="bold",
            )

    plt.tight_layout()
    plt.savefig(output_path)
    plt.close()
    print(f"Generated tradeoff figure at: {output_path}")


def plot_latency_cdf(
    latencies_by_baseline: Dict[str, List[float]],
    output_path: str = "docs/figures/latency_cdf.png",
) -> None:
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    plt.style.use("seaborn-v0_8-whitegrid" if "seaborn-v0_8-whitegrid" in plt.style.available else "default")
    fig, ax = plt.subplots(figsize=(9.5, 5.2), dpi=300)

    colors = {
        "static_gateway_r1_r5": ("#386cb0", "Static Gateway (R1–R5) [Measured]"),
        "paygate_full": ("#1b9e77", "PayGate Full TCB (R1–R8 + HMAC) [Measured]"),
        "prompt_plus_llm_judge": ("#d95f02", "LLM-as-a-Judge Guardrail [Measured]"),
    }

    for key, (color, label) in colors.items():
        data = [v for v in latencies_by_baseline.get(key, []) if v > 0]
        if not data:
            continue
        sorted_data = np.sort(data)
        y = np.linspace(0, 1, len(sorted_data))
        ax.plot(sorted_data, y, label=label, color=color, linewidth=2.2)

    ax.set_xscale("log")
    ax.set_xlabel("Measured Decision Overhead (ms) [Log Scale]", fontsize=12, fontweight="bold")
    ax.set_ylabel("Empirical Cumulative Probability (CDF)", fontsize=12, fontweight="bold")
    ax.set_title("Measured Policy Gate Latency CDF vs. LLM Guardrail Overhead", fontsize=13, fontweight="bold", pad=12)
    ax.axvline(x=1.0, color="gray", linestyle="--", alpha=0.75, label="1 ms Sub-Millisecond SLA")
    ax.legend(loc="lower right", frameon=True, fontsize=9.5)
    ax.set_ylim(-0.02, 1.02)

    plt.tight_layout()
    plt.savefig(output_path)
    plt.close()
    print(f"Generated latency CDF figure at: {output_path}")
