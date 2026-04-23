"""Results analysis for ShieldMCP evaluation.

Loads JSON results produced by the eval runner and generates analysis
matching the paper's Table 2 (ASR per attack family x defense mode),
model breakdowns, latency reports, and benign-impact statistics.
"""

from __future__ import annotations

import csv
import json
import statistics
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from shieldmcp.core.models import AttackFamily

ATTACK_FAMILY_LABELS: dict[str, str] = {
    AttackFamily.TOOL_POISONING.value: "Tool Poisoning",
    AttackFamily.INDIRECT_PROMPT_INJECTION.value: "IPI via Response",
    AttackFamily.CROSS_TOOL_CHAIN.value: "Cross-Tool Chain",
    AttackFamily.SUPPLY_CHAIN.value: "Supply Chain",
    AttackFamily.RUG_PULL.value: "Rug Pull",
}

TABLE2_FAMILIES = [
    "Tool Poisoning",
    "IPI via Response",
    "Cross-Tool Chain",
]

DEFENSE_MODES = ["none", "regex", "llm_judge", "shieldmcp"]


@dataclass
class _BucketStats:
    """Accumulator for attack-success counts."""

    total: int = 0
    succeeded: int = 0

    @property
    def asr(self) -> float:
        if self.total == 0:
            return 0.0
        return (self.succeeded / self.total) * 100.0


class ResultsAnalyzer:
    """Analyse evaluation results exported by :class:`eval.harness.runner.EvalRunner`.

    Parameters
    ----------
    results_path:
        Path to the JSON file written by ``EvalRunner.export_results``.
    scenarios_path:
        Optional path to the scenarios JSON (carries ``attack_family`` per
        ``scenario_id``).  When provided the analyser can group by family
        even if the result records lack that field.
    """

    def __init__(
        self,
        results_path: str | Path,
        scenarios_path: str | Path | None = None,
    ) -> None:
        self.results_path = Path(results_path)
        self.results: list[dict[str, Any]] = self._load(self.results_path)

        self._scenario_meta: dict[str, dict[str, Any]] = {}
        if scenarios_path is not None:
            for s in self._load(Path(scenarios_path)):
                self._scenario_meta[s["scenario_id"]] = s

    @staticmethod
    def _load(path: Path) -> list[dict[str, Any]]:
        with open(path) as f:
            data = json.load(f)
        if isinstance(data, list):
            return data
        raise ValueError(f"Expected a JSON array in {path}")

    def _attack_family_for(self, result: dict[str, Any]) -> str:
        """Resolve the attack family label for a result record."""
        sid = result.get("scenario_id", "")

        if sid in self._scenario_meta:
            raw = self._scenario_meta[sid].get("attack_family", "")
        else:
            raw = result.get("attack_family", sid.split("-")[0] if "-" in sid else "")

        return ATTACK_FAMILY_LABELS.get(raw, raw)

    def _is_benign(self, result: dict[str, Any]) -> bool:
        """Return True when the scenario is a benign (non-adversarial) test."""
        family = self._attack_family_for(result)
        return family.lower() in ("benign", "none", "")

    # ------------------------------------------------------------------
    # Table 2: ASR per attack_family x defense_mode
    # ------------------------------------------------------------------

    def generate_table2(self) -> dict[str, dict[str, float]]:
        """Return a dict matching the paper's Table 2 format.

        Returns
        -------
        ``{attack_type: {defense_mode: asr_percentage}}``

        Attack types: ``"Tool Poisoning"``, ``"IPI via Response"``,
        ``"Cross-Tool Chain"``, ``"Avg. across all"``.
        Defense modes: ``"none"``, ``"regex"``, ``"llm_judge"``,
        ``"shieldmcp"``.
        """
        buckets: dict[str, dict[str, _BucketStats]] = {}
        for family in TABLE2_FAMILIES:
            buckets[family] = {m: _BucketStats() for m in DEFENSE_MODES}

        for r in self.results:
            family = self._attack_family_for(r)
            mode = r.get("defense_mode", "")
            if family not in buckets or mode not in DEFENSE_MODES:
                continue
            buckets[family][mode].total += 1
            if r.get("attack_succeeded"):
                buckets[family][mode].succeeded += 1

        table: dict[str, dict[str, float]] = {}
        for family in TABLE2_FAMILIES:
            table[family] = {m: round(buckets[family][m].asr, 1) for m in DEFENSE_MODES}

        avg_row: dict[str, float] = {}
        for m in DEFENSE_MODES:
            values = [table[f][m] for f in TABLE2_FAMILIES]
            avg_row[m] = round(statistics.mean(values) if values else 0.0, 1)
        table["Avg. across all"] = avg_row

        return table

    # ------------------------------------------------------------------
    # Model breakdown: ASR per model x defense_mode
    # ------------------------------------------------------------------

    def generate_model_breakdown(self) -> dict[str, dict[str, float]]:
        """ASR per ``model_name`` per ``defense_mode``.

        Returns ``{model_name: {defense_mode: asr_percentage}}``.
        """
        buckets: dict[str, dict[str, _BucketStats]] = {}

        for r in self.results:
            if self._is_benign(r):
                continue
            model = r.get("model_name", "unknown")
            mode = r.get("defense_mode", "")
            buckets.setdefault(model, {}).setdefault(mode, _BucketStats())
            buckets[model][mode].total += 1
            if r.get("attack_succeeded"):
                buckets[model][mode].succeeded += 1

        return {
            model: {m: round(stats.asr, 1) for m, stats in modes.items()}
            for model, modes in sorted(buckets.items())
        }

    # ------------------------------------------------------------------
    # Latency report
    # ------------------------------------------------------------------

    def generate_latency_report(self) -> dict[str, dict[str, float]]:
        """Median / P95 / P99 latency (ms) per defense_mode.

        Also includes per-stage latencies when alert records carry a
        ``stage`` field.

        Returns ``{defense_mode: {"median": …, "p95": …, "p99": …}}``,
        plus ``{stage/defense_mode: {…}}`` entries when stage data exists.
        """
        per_mode: dict[str, list[float]] = {}
        per_stage_mode: dict[str, list[float]] = {}

        for r in self.results:
            mode = r.get("defense_mode", "none")
            lat = r.get("latency_ms", 0.0)
            per_mode.setdefault(mode, []).append(lat)

            for alert in r.get("alerts_raised", []):
                stage = alert.get("stage", "")
                if stage:
                    key = f"{stage}/{mode}"
                    per_stage_mode.setdefault(key, []).append(lat)

        def _stats(values: list[float]) -> dict[str, float]:
            if not values:
                return {"median": 0.0, "p95": 0.0, "p99": 0.0}
            s = sorted(values)
            return {
                "median": round(statistics.median(s), 2),
                "p95": round(s[int(len(s) * 0.95)], 2),
                "p99": round(s[int(len(s) * 0.99)], 2),
            }

        report: dict[str, dict[str, float]] = {}
        for mode in DEFENSE_MODES:
            report[mode] = _stats(per_mode.get(mode, []))
        for key, values in sorted(per_stage_mode.items()):
            report[key] = _stats(values)

        return report

    # ------------------------------------------------------------------
    # Benign impact / false-positive analysis
    # ------------------------------------------------------------------

    def generate_benign_impact(self) -> dict[str, dict[str, float]]:
        """Task completion rate with and without defense.

        Returns ``{defense_mode: {"total": N, "blocked": N, "warned": N,
        "completion_rate": pct, "false_positive_rate": pct}}``.
        """
        buckets: dict[str, dict[str, int]] = {
            m: {"total": 0, "blocked": 0, "warned": 0} for m in DEFENSE_MODES
        }

        for r in self.results:
            if not self._is_benign(r):
                continue
            mode = r.get("defense_mode", "")
            if mode not in buckets:
                continue
            buckets[mode]["total"] += 1
            details = r.get("details", {})
            if details.get("blocked_by_defense"):
                buckets[mode]["blocked"] += 1
            elif any(
                a.get("action") == "warn" for a in r.get("alerts_raised", [])
            ):
                buckets[mode]["warned"] += 1

        report: dict[str, dict[str, float]] = {}
        for mode in DEFENSE_MODES:
            b = buckets[mode]
            total = b["total"]
            blocked = b["blocked"]
            warned = b["warned"]
            fp = blocked + warned
            report[mode] = {
                "total": float(total),
                "blocked": float(blocked),
                "warned": float(warned),
                "completion_rate": round(
                    ((total - blocked) / total * 100) if total else 100.0, 1
                ),
                "false_positive_rate": round(
                    (fp / total * 100) if total else 0.0, 1
                ),
            }
        return report

    # ------------------------------------------------------------------
    # Console summary
    # ------------------------------------------------------------------

    def print_summary(self) -> None:
        """Pretty-print all analysis tables to the console using *rich*."""
        try:
            from rich.console import Console
            from rich.table import Table as RichTable
        except ImportError:
            self._print_summary_plain()
            return

        console = Console()

        # -- Table 2 --
        t2 = self.generate_table2()
        tbl = RichTable(title="Table 2 — ASR (%) per Attack Family × Defense")
        tbl.add_column("Attack Type", style="bold")
        for m in DEFENSE_MODES:
            tbl.add_column(m, justify="right")
        for family, row in t2.items():
            style = "bold green" if family == "Avg. across all" else None
            tbl.add_row(family, *[f"{row[m]:.1f}" for m in DEFENSE_MODES], style=style)
        console.print(tbl, "\n")

        # -- Model breakdown --
        mb = self.generate_model_breakdown()
        if mb:
            tbl = RichTable(title="ASR (%) per Model × Defense")
            tbl.add_column("Model", style="bold")
            all_modes = sorted({m for row in mb.values() for m in row})
            for m in all_modes:
                tbl.add_column(m, justify="right")
            for model, row in mb.items():
                tbl.add_row(model, *[f"{row.get(m, 0.0):.1f}" for m in all_modes])
            console.print(tbl, "\n")

        # -- Latency --
        lr = self.generate_latency_report()
        tbl = RichTable(title="Latency (ms)")
        tbl.add_column("Scope", style="bold")
        for stat in ("median", "p95", "p99"):
            tbl.add_column(stat, justify="right")
        for scope, stats in lr.items():
            tbl.add_row(scope, *[f"{stats[s]:.2f}" for s in ("median", "p95", "p99")])
        console.print(tbl, "\n")

        # -- Benign impact --
        bi = self.generate_benign_impact()
        tbl = RichTable(title="Benign Task Impact")
        tbl.add_column("Defense", style="bold")
        for col in ("total", "blocked", "warned", "completion_rate", "false_positive_rate"):
            tbl.add_column(col, justify="right")
        for mode in DEFENSE_MODES:
            row = bi[mode]
            tbl.add_row(
                mode,
                f"{row['total']:.0f}",
                f"{row['blocked']:.0f}",
                f"{row['warned']:.0f}",
                f"{row['completion_rate']:.1f}%",
                f"{row['false_positive_rate']:.1f}%",
            )
        console.print(tbl)

    def _print_summary_plain(self) -> None:
        """Fallback summary when *rich* is not installed."""
        sep = "-" * 72

        print("Table 2 — ASR (%) per Attack Family × Defense")
        print(sep)
        t2 = self.generate_table2()
        header = f"{'Attack Type':<22}" + "".join(f"{m:>12}" for m in DEFENSE_MODES)
        print(header)
        print(sep)
        for family, row in t2.items():
            line = f"{family:<22}" + "".join(f"{row[m]:>12.1f}" for m in DEFENSE_MODES)
            print(line)
        print()

        mb = self.generate_model_breakdown()
        if mb:
            print("ASR (%) per Model × Defense")
            print(sep)
            all_modes = sorted({m for row in mb.values() for m in row})
            header = f"{'Model':<22}" + "".join(f"{m:>12}" for m in all_modes)
            print(header)
            print(sep)
            for model, row in mb.items():
                line = f"{model:<22}" + "".join(
                    f"{row.get(m, 0.0):>12.1f}" for m in all_modes
                )
                print(line)
            print()

        lr = self.generate_latency_report()
        print("Latency (ms)")
        print(sep)
        print(f"{'Scope':<30}{'median':>12}{'p95':>12}{'p99':>12}")
        print(sep)
        for scope, stats in lr.items():
            print(
                f"{scope:<30}{stats['median']:>12.2f}"
                f"{stats['p95']:>12.2f}{stats['p99']:>12.2f}"
            )
        print()

        bi = self.generate_benign_impact()
        print("Benign Task Impact")
        print(sep)
        print(
            f"{'Defense':<14}{'total':>8}{'blocked':>8}{'warned':>8}"
            f"{'compl%':>10}{'fp%':>10}"
        )
        print(sep)
        for mode in DEFENSE_MODES:
            row = bi[mode]
            print(
                f"{mode:<14}{row['total']:>8.0f}{row['blocked']:>8.0f}"
                f"{row['warned']:>8.0f}{row['completion_rate']:>9.1f}%"
                f"{row['false_positive_rate']:>9.1f}%"
            )

    # ------------------------------------------------------------------
    # LaTeX export
    # ------------------------------------------------------------------

    def export_latex_tables(self, path: str | Path) -> None:
        """Export all analysis tables as LaTeX for the paper.

        Writes a ``.tex`` file that can be ``\\input{}``-ed directly.
        """
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        lines: list[str] = []

        # -- Table 2 --
        t2 = self.generate_table2()
        lines.append("% Table 2 — ASR per Attack Family × Defense")
        lines.append("\\begin{table}[t]")
        lines.append("\\centering")
        lines.append("\\caption{Attack Success Rate (\\%) per attack family and defense mode.}")
        lines.append("\\label{tab:asr-comparison}")
        col_spec = "l" + "r" * len(DEFENSE_MODES)
        lines.append(f"\\begin{{tabular}}{{{col_spec}}}")
        lines.append("\\toprule")
        header = "Attack Type & " + " & ".join(
            m.replace("_", "\\_") for m in DEFENSE_MODES
        )
        lines.append(header + " \\\\")
        lines.append("\\midrule")
        for family, row in t2.items():
            if family == "Avg. across all":
                lines.append("\\midrule")
            cells = " & ".join(f"{row[m]:.1f}" for m in DEFENSE_MODES)
            label = family.replace("_", "\\_")
            if family == "Avg. across all":
                label = f"\\textbf{{{label}}}"
                cells_parts = [f"\\textbf{{{row[m]:.1f}}}" for m in DEFENSE_MODES]
                cells = " & ".join(cells_parts)
            lines.append(f"{label} & {cells} \\\\")
        lines.append("\\bottomrule")
        lines.append("\\end{tabular}")
        lines.append("\\end{table}")
        lines.append("")

        # -- Model breakdown --
        mb = self.generate_model_breakdown()
        if mb:
            all_modes = sorted({m for row in mb.values() for m in row})
            lines.append("% Model breakdown")
            lines.append("\\begin{table}[t]")
            lines.append("\\centering")
            lines.append(
                "\\caption{ASR (\\%) per model and defense mode.}"
            )
            lines.append("\\label{tab:model-breakdown}")
            col_spec = "l" + "r" * len(all_modes)
            lines.append(f"\\begin{{tabular}}{{{col_spec}}}")
            lines.append("\\toprule")
            header = "Model & " + " & ".join(
                m.replace("_", "\\_") for m in all_modes
            )
            lines.append(header + " \\\\")
            lines.append("\\midrule")
            for model, row in mb.items():
                cells = " & ".join(f"{row.get(m, 0.0):.1f}" for m in all_modes)
                lines.append(f"{model.replace('_', chr(92) + '_')} & {cells} \\\\")
            lines.append("\\bottomrule")
            lines.append("\\end{tabular}")
            lines.append("\\end{table}")
            lines.append("")

        # -- Latency --
        lr = self.generate_latency_report()
        lines.append("% Latency report")
        lines.append("\\begin{table}[t]")
        lines.append("\\centering")
        lines.append("\\caption{Latency (ms) per defense mode.}")
        lines.append("\\label{tab:latency}")
        lines.append("\\begin{tabular}{lrrr}")
        lines.append("\\toprule")
        lines.append("Scope & Median & P95 & P99 \\\\")
        lines.append("\\midrule")
        for scope, stats in lr.items():
            label = scope.replace("_", "\\_")
            lines.append(
                f"{label} & {stats['median']:.2f} & {stats['p95']:.2f}"
                f" & {stats['p99']:.2f} \\\\"
            )
        lines.append("\\bottomrule")
        lines.append("\\end{tabular}")
        lines.append("\\end{table}")

        path.write_text("\n".join(lines) + "\n")

    # ------------------------------------------------------------------
    # CSV export
    # ------------------------------------------------------------------

    def export_csv(self, path: str | Path) -> None:
        """Export the raw result records as a flat CSV file."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)

        fieldnames = [
            "scenario_id",
            "model_name",
            "defense_mode",
            "attack_family",
            "attack_succeeded",
            "latency_ms",
            "blocked_by_defense",
            "num_tool_calls",
            "num_alerts",
        ]

        with open(path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for r in self.results:
                details = r.get("details", {})
                writer.writerow(
                    {
                        "scenario_id": r.get("scenario_id", ""),
                        "model_name": r.get("model_name", ""),
                        "defense_mode": r.get("defense_mode", ""),
                        "attack_family": self._attack_family_for(r),
                        "attack_succeeded": r.get("attack_succeeded", False),
                        "latency_ms": r.get("latency_ms", 0.0),
                        "blocked_by_defense": details.get("blocked_by_defense", False),
                        "num_tool_calls": details.get("num_tool_calls", 0),
                        "num_alerts": len(r.get("alerts_raised", [])),
                    }
                )
