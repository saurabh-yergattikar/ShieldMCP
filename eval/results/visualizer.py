"""Visualization module for ShieldMCP evaluation results.

Generates publication-ready charts and plots for the paper and poster
using matplotlib and seaborn.
"""

from __future__ import annotations

import math
from pathlib import Path
from typing import Any

import matplotlib
import matplotlib.pyplot as plt
import numpy as np
import seaborn as sns

from eval.results.analyzer import DEFENSE_MODES, TABLE2_FAMILIES, ResultsAnalyzer

matplotlib.rcParams["pdf.fonttype"] = 42
matplotlib.rcParams["ps.fonttype"] = 42

_PALETTE = {
    "none": "#d62728",
    "regex": "#ff7f0e",
    "llm_judge": "#2ca02c",
    "shieldmcp": "#1f77b4",
}

_DEFENSE_LABELS = {
    "none": "No Defense",
    "regex": "Regex",
    "llm_judge": "LLM Judge",
    "shieldmcp": "ShieldMCP",
}


def _save(fig: plt.Figure, output_path: str | Path) -> None:
    """Save figure as both PNG (300 dpi) and PDF."""
    p = Path(output_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(p.with_suffix(".png"), dpi=300, bbox_inches="tight")
    fig.savefig(p.with_suffix(".pdf"), bbox_inches="tight")
    plt.close(fig)


def _apply_style() -> None:
    """Set seaborn paper context with clean defaults."""
    sns.set_context("paper", font_scale=1.2)
    sns.set_style("whitegrid", {"grid.linestyle": "--", "grid.alpha": 0.5})


class ResultsVisualizer:
    """Generate publication-ready plots from evaluation results.

    Parameters
    ----------
    analyzer:
        A :class:`ResultsAnalyzer` instance with loaded results.
    """

    def __init__(self, analyzer: ResultsAnalyzer) -> None:
        self.analyzer = analyzer

    # ------------------------------------------------------------------
    # ASR comparison bar chart (matches Table 2)
    # ------------------------------------------------------------------

    def plot_asr_comparison(self, output_path: str | Path) -> None:
        """Bar chart comparing ASR across defense modes per attack family."""
        _apply_style()
        table2 = self.analyzer.generate_table2()

        families = TABLE2_FAMILIES + ["Avg. across all"]
        x = np.arange(len(families))
        n_modes = len(DEFENSE_MODES)
        width = 0.18

        fig, ax = plt.subplots(figsize=(8, 4.5))

        for i, mode in enumerate(DEFENSE_MODES):
            values = [table2[f][mode] for f in families]
            offset = (i - (n_modes - 1) / 2) * width
            bars = ax.bar(
                x + offset,
                values,
                width,
                label=_DEFENSE_LABELS[mode],
                color=_PALETTE[mode],
                edgecolor="white",
                linewidth=0.5,
            )
            for bar, val in zip(bars, values):
                if val > 0:
                    ax.text(
                        bar.get_x() + bar.get_width() / 2,
                        bar.get_height() + 1,
                        f"{val:.0f}",
                        ha="center",
                        va="bottom",
                        fontsize=7,
                    )

        ax.set_ylabel("Attack Success Rate (%)")
        ax.set_xticks(x)
        ax.set_xticklabels(families, rotation=15, ha="right")
        ax.set_ylim(0, 105)
        ax.legend(frameon=True, framealpha=0.9, loc="upper right")
        ax.set_title("ASR Comparison Across Defense Modes")
        fig.tight_layout()
        _save(fig, output_path)

    # ------------------------------------------------------------------
    # Model vulnerability grouped bar chart
    # ------------------------------------------------------------------

    def plot_model_vulnerability(self, output_path: str | Path) -> None:
        """Grouped bar chart showing ASR per model, undefended vs. defended."""
        _apply_style()
        breakdown = self.analyzer.generate_model_breakdown()
        if not breakdown:
            return

        models = list(breakdown.keys())
        modes = DEFENSE_MODES
        x = np.arange(len(models))
        n_modes = len(modes)
        width = 0.8 / n_modes

        fig, ax = plt.subplots(figsize=(max(6, len(models) * 1.8), 4.5))

        for i, mode in enumerate(modes):
            values = [breakdown[m].get(mode, 0.0) for m in models]
            offset = (i - (n_modes - 1) / 2) * width
            ax.bar(
                x + offset,
                values,
                width,
                label=_DEFENSE_LABELS.get(mode, mode),
                color=_PALETTE.get(mode, "#999999"),
                edgecolor="white",
                linewidth=0.5,
            )

        ax.set_ylabel("Attack Success Rate (%)")
        ax.set_xticks(x)
        ax.set_xticklabels(models, rotation=20, ha="right")
        ax.set_ylim(0, 105)
        ax.legend(frameon=True, framealpha=0.9)
        ax.set_title("Model Vulnerability by Defense Mode")
        fig.tight_layout()
        _save(fig, output_path)

    # ------------------------------------------------------------------
    # Latency breakdown stacked bar chart
    # ------------------------------------------------------------------

    def plot_latency_breakdown(self, output_path: str | Path) -> None:
        """Stacked bar chart showing latency per stage for each defense mode."""
        _apply_style()
        report = self.analyzer.generate_latency_report()

        stage_keys = [k for k in report if "/" in k]
        stages = sorted({k.split("/")[0] for k in stage_keys})
        modes = [m for m in DEFENSE_MODES if m in report]

        fig, ax = plt.subplots(figsize=(7, 4.5))

        if stages:
            x = np.arange(len(modes))
            bottom = np.zeros(len(modes))
            cmap = sns.color_palette("muted", n_colors=max(len(stages), 1))

            for idx, stage in enumerate(stages):
                values = []
                for mode in modes:
                    key = f"{stage}/{mode}"
                    values.append(report.get(key, {}).get("median", 0.0))
                values_arr = np.array(values)
                ax.bar(
                    x,
                    values_arr,
                    0.5,
                    bottom=bottom,
                    label=stage,
                    color=cmap[idx % len(cmap)],
                    edgecolor="white",
                    linewidth=0.5,
                )
                bottom += values_arr
        else:
            x = np.arange(len(modes))
            medians = [report.get(m, {}).get("median", 0.0) for m in modes]
            ax.bar(
                x,
                medians,
                0.5,
                color=[_PALETTE.get(m, "#999999") for m in modes],
                edgecolor="white",
                linewidth=0.5,
            )

        ax.set_ylabel("Median Latency (ms)")
        ax.set_xticks(np.arange(len(modes)))
        ax.set_xticklabels([_DEFENSE_LABELS.get(m, m) for m in modes])
        if stages:
            ax.legend(title="Stage", frameon=True, framealpha=0.9)
        ax.set_title("Latency Breakdown by Defense Mode")
        fig.tight_layout()
        _save(fig, output_path)

    # ------------------------------------------------------------------
    # Radar / spider chart — defense effectiveness per attack family
    # ------------------------------------------------------------------

    def plot_attack_family_radar(self, output_path: str | Path) -> None:
        """Radar chart showing defense effectiveness per attack family.

        "Effectiveness" is defined as ``100 - ASR`` so that higher is better.
        """
        _apply_style()
        table2 = self.analyzer.generate_table2()

        categories = TABLE2_FAMILIES
        n = len(categories)
        if n < 3:
            return

        angles = [i / n * 2 * math.pi for i in range(n)]
        angles += angles[:1]

        fig, ax = plt.subplots(figsize=(6, 6), subplot_kw={"polar": True})

        for mode in DEFENSE_MODES:
            values = [100 - table2[f][mode] for f in categories]
            values += values[:1]
            ax.plot(
                angles,
                values,
                "o-",
                linewidth=1.8,
                label=_DEFENSE_LABELS[mode],
                color=_PALETTE[mode],
            )
            ax.fill(angles, values, alpha=0.08, color=_PALETTE[mode])

        ax.set_xticks(angles[:-1])
        ax.set_xticklabels(categories, size=9)
        ax.set_ylim(0, 105)
        ax.set_yticks([20, 40, 60, 80, 100])
        ax.set_yticklabels(["20", "40", "60", "80", "100"], size=7)
        ax.legend(loc="upper right", bbox_to_anchor=(1.3, 1.1), frameon=True)
        ax.set_title("Defense Effectiveness by Attack Family\n(100 − ASR)", pad=20)
        fig.tight_layout()
        _save(fig, output_path)

    # ------------------------------------------------------------------
    # False-positive trade-off curve
    # ------------------------------------------------------------------

    def plot_false_positive_tradeoff(self, output_path: str | Path) -> None:
        """Threshold vs. false-positive rate curve.

        When real threshold sweep data is unavailable, plots a single-point
        summary from the benign-impact analysis per defense mode.
        """
        _apply_style()
        benign = self.analyzer.generate_benign_impact()
        table2 = self.analyzer.generate_table2()

        fig, ax = plt.subplots(figsize=(6, 4.5))

        modes_with_data = [
            m for m in DEFENSE_MODES if benign[m]["total"] > 0 or m in table2.get("Avg. across all", {})
        ]

        if not modes_with_data:
            modes_with_data = DEFENSE_MODES

        fp_rates = [benign[m]["false_positive_rate"] for m in modes_with_data]
        avg_asr = [table2.get("Avg. across all", {}).get(m, 0.0) for m in modes_with_data]
        detection_rates = [100 - a for a in avg_asr]

        for i, mode in enumerate(modes_with_data):
            ax.scatter(
                fp_rates[i],
                detection_rates[i],
                s=120,
                color=_PALETTE.get(mode, "#999999"),
                zorder=5,
                edgecolors="white",
                linewidth=1.5,
            )
            ax.annotate(
                _DEFENSE_LABELS.get(mode, mode),
                (fp_rates[i], detection_rates[i]),
                textcoords="offset points",
                xytext=(8, 8),
                fontsize=9,
            )

        ax.set_xlabel("False Positive Rate (%)")
        ax.set_ylabel("Detection Rate (100 − ASR %)")
        ax.set_xlim(-2, max(fp_rates + [10]) + 5)
        ax.set_ylim(0, 105)
        ax.set_title("Detection Rate vs. False Positive Rate")
        fig.tight_layout()
        _save(fig, output_path)
