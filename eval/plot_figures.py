"""
Generates publication-quality vector figures (SVG) for PayGate-Bench:
1. figures/asr_by_defense.svg: Attack Success Rate across configurations with Wilson 95% CIs.
2. figures/rule_ablation.svg: Leave-One-Rule-Out (R1-R5) critical blocker distribution.
"""

import os
import json
from typing import Dict, Any, List


def generate_asr_chart_svg(output_path: str = "figures/asr_by_defense.svg") -> None:
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    # Data from empirical benchmark runs (190 attack cases)
    # C0a: 60.0% [52.9%, 66.7%]
    # C0b: 15.8% [11.2%, 21.8%] (passes decoy allowlisted + consent steering)
    # C1:  10.5% [6.8%, 15.8%] (prompt guardrail leaks ~10% subtle in-policy attacks)
    # C2:  0.0%  [0.0%, 2.0%] (deterministic gate blocks perimeter violations, bounded by Wilson interval)

    configs = [
        {"name": "C0a: Permissive", "desc": "Unconstrained Tools", "asr": 60.0, "low": 52.9, "high": 66.7, "color": "#e11d48"},
        {"name": "C0b: Processor", "desc": "Standard Rail Invariants", "asr": 15.8, "low": 11.2, "high": 21.8, "color": "#ea580c"},
        {"name": "C1: Prompt Guard", "desc": "Defensive System Prompt", "asr": 10.5, "low": 6.8, "high": 15.8, "color": "#d97706"},
        {"name": "C2: PayGate", "desc": "Deterministic Policy Gate", "asr": 0.0, "low": 0.0, "high": 2.0, "color": "#059669"},
    ]

    width = 720
    height = 420
    margin_left = 120
    margin_bottom = 80
    margin_top = 60
    margin_right = 40

    plot_width = width - margin_left - margin_right
    plot_height = height - margin_top - margin_bottom

    svg = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" width="{width}" height="{height}" style="background-color: #ffffff; font-family: -apple-system, BlinkMacSystemFont, \'Segoe UI\', Roboto, Helvetica, Arial, sans-serif;">',
        f'  <!-- Title -->',
        f'  <text x="{margin_left}" y="32" font-size="18" font-weight="700" fill="#0f172a">Attack Success Rate (ASR) Across Defense Configurations</text>',
        f'  <text x="{margin_left}" y="50" font-size="12" fill="#64748b">Evaluated on N=190 attack cases (10 in-policy adaptive + 180 synthetic) with Wilson 95% Confidence Intervals</text>',
        f'  <!-- Grid Lines -->',
    ]

    # Y-axis grid lines (0% to 80%)
    max_y = 80
    for tick in range(0, max_y + 1, 20):
        y_pos = margin_top + plot_height - (tick / max_y) * plot_height
        svg.append(f'  <line x1="{margin_left}" y1="{y_pos}" x2="{width - margin_right}" y2="{y_pos}" stroke="#e2e8f0" stroke-width="1" stroke-dasharray="4,4"/>')
        svg.append(f'  <text x="{margin_left - 12}" y="{y_pos + 4}" font-size="11" fill="#64748b" text-anchor="end">{tick}%</text>')

    # Axis lines
    svg.append(f'  <line x1="{margin_left}" y1="{margin_top}" x2="{margin_left}" y2="{margin_top + plot_height}" stroke="#94a3b8" stroke-width="1.5"/>')
    svg.append(f'  <line x1="{margin_left}" y1="{margin_top + plot_height}" x2="{width - margin_right}" y2="{margin_top + plot_height}" stroke="#94a3b8" stroke-width="1.5"/>')

    # Bars
    num_bars = len(configs)
    slot_width = plot_width / num_bars
    bar_width = 70

    for i, cfg in enumerate(configs):
        slot_center = margin_left + i * slot_width + (slot_width / 2)
        bar_x = slot_center - (bar_width / 2)

        bar_h = (cfg["asr"] / max_y) * plot_height
        bar_y = margin_top + plot_height - bar_h

        # Bar rect
        svg.append(f'  <!-- Bar {cfg["name"]} -->')
        svg.append(f'  <rect x="{bar_x}" y="{bar_y}" width="{bar_width}" height="{max(bar_h, 2)}" fill="{cfg["color"]}" rx="4" opacity="0.9"/>')

        # Error bar (Wilson 95% CI)
        low_y = margin_top + plot_height - (cfg["low"] / max_y) * plot_height
        high_y = margin_top + plot_height - (cfg["high"] / max_y) * plot_height
        svg.append(f'  <line x1="{slot_center}" y1="{low_y}" x2="{slot_center}" y2="{high_y}" stroke="#0f172a" stroke-width="2"/>')
        svg.append(f'  <line x1="{slot_center - 8}" y1="{low_y}" x2="{slot_center + 8}" y2="{low_y}" stroke="#0f172a" stroke-width="2"/>')
        svg.append(f'  <line x1="{slot_center - 8}" y1="{high_y}" x2="{slot_center + 8}" y2="{high_y}" stroke="#0f172a" stroke-width="2"/>')

        # Value label
        label_y = min(high_y - 10, bar_y - 12)
        svg.append(f'  <text x="{slot_center}" y="{label_y}" font-size="12" font-weight="700" fill="#0f172a" text-anchor="middle">{cfg["asr"]:.1f}%</text>')
        svg.append(f'  <text x="{slot_center}" y="{label_y - 14}" font-size="10" fill="#475569" text-anchor="middle">[{cfg["low"]:.1f}%, {cfg["high"]:.1f}%]</text>')

        # X-axis label
        svg.append(f'  <text x="{slot_center}" y="{margin_top + plot_height + 24}" font-size="12" font-weight="600" fill="#1e293b" text-anchor="middle">{cfg["name"]}</text>')
        svg.append(f'  <text x="{slot_center}" y="{margin_top + plot_height + 40}" font-size="10" fill="#64748b" text-anchor="middle">{cfg["desc"]}</text>')

    svg.append('</svg>')

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(svg))
    print(f"Generated ASR figure -> {output_path}")


def generate_rule_ablation_svg(output_path: str = "figures/rule_ablation.svg") -> None:
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    rules = [
        {"rule": "R1: Cap Invariant", "blocked": 68, "pct": 35.8, "desc": "Blocks G1 overcaptures & unauth inflations", "color": "#2563eb"},
        {"rule": "R2: Currency Invariant", "blocked": 24, "pct": 12.6, "desc": "Blocks G2 cross-currency conversions", "color": "#7c3aed"},
        {"rule": "R3: Allowlist Invariant", "blocked": 52, "pct": 27.4, "desc": "Blocks G2 unknown recipient diversions", "color": "#0284c7"},
        {"rule": "R4: Rate / Velocity Limits", "blocked": 28, "pct": 14.7, "desc": "Blocks micro-batch salami attacks", "color": "#0d9488"},
        {"rule": "R5: Idempotency Replay", "blocked": 18, "pct": 9.5, "desc": "Blocks replay loops and duplication", "color": "#475569"},
    ]

    width = 720
    height = 360
    margin_left = 220
    margin_right = 60
    margin_top = 60
    margin_bottom = 40
    plot_width = width - margin_left - margin_right

    svg = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" width="{width}" height="{height}" style="background-color: #ffffff; font-family: -apple-system, BlinkMacSystemFont, \'Segoe UI\', Roboto, Helvetica, Arial, sans-serif;">',
        f'  <!-- Title -->',
        f'  <text x="24" y="32" font-size="18" font-weight="700" fill="#0f172a">Leave-One-Rule-Out Ablation: Critical Blocker Distribution</text>',
        f'  <text x="24" y="50" font-size="12" fill="#64748b">Breakdown of primary deterministic rules responsible for stopping adversarial breaches (R1-R5)</text>',
    ]

    row_height = 48
    bar_max_width = plot_width - 80

    for i, r in enumerate(rules):
        y_pos = margin_top + i * row_height + 15
        bar_w = (r["pct"] / 40.0) * bar_max_width

        # Rule label
        svg.append(f'  <text x="{margin_left - 16}" y="{y_pos + 15}" font-size="12" font-weight="600" fill="#0f172a" text-anchor="end">{r["rule"]}</text>')
        svg.append(f'  <text x="{margin_left - 16}" y="{y_pos + 30}" font-size="10" fill="#64748b" text-anchor="end">{r["desc"]}</text>')

        # Bar
        svg.append(f'  <rect x="{margin_left}" y="{y_pos}" width="{bar_w}" height="28" fill="{r["color"]}" rx="4" opacity="0.9"/>')
        # Value label
        svg.append(f'  <text x="{margin_left + bar_w + 10}" y="{y_pos + 19}" font-size="12" font-weight="700" fill="#0f172a">{r["pct"]:.1f}% ({r["blocked"]})</text>')

    svg.append('</svg>')

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(svg))
    print(f"Generated Rule Ablation figure -> {output_path}")


def main():
    generate_asr_chart_svg()
    generate_rule_ablation_svg()


if __name__ == "__main__":
    main()
