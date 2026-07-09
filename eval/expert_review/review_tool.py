"""Expert review scaffolding for ShieldMCP evaluation.

Presents sampled alerts to a human reviewer for binary agreement judgments,
computes inter-annotator agreement across reviewers, and exports results.

Usage:
    python eval/expert_review/review_tool.py \
        --results eval/results/output/framework_eval_results.json \
        --reviewer "expert1" \
        --num-samples 50
"""

from __future__ import annotations

import argparse
import json
import random
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table

console = Console()


def _load_results(path: Path) -> dict:
    with open(path) as f:
        return json.load(f)


def _sample_alerts(
    results: dict,
    num_true_positives: int,
    num_false_positives: int,
) -> list[dict]:
    """Sample a balanced set of TP and FP alerts from evaluation results."""
    true_positives: list[dict] = []
    false_positives: list[dict] = []

    for r in results.get("attack_results", []):
        if r.get("detected", False):
            true_positives.append({**r, "ground_truth": "true_positive", "source": "attack"})
        else:
            false_positives.append({**r, "ground_truth": "false_negative", "source": "attack"})

    for r in results.get("benign_results", []):
        if r.get("blocked", False) or r.get("warned", False):
            false_positives.append({**r, "ground_truth": "false_positive", "source": "benign"})

    random.shuffle(true_positives)
    random.shuffle(false_positives)

    sampled = (
        true_positives[:num_true_positives]
        + false_positives[:num_false_positives]
    )
    random.shuffle(sampled)

    if len(sampled) < num_true_positives + num_false_positives:
        console.print(
            f"[yellow]Warning: only {len(sampled)} alerts available "
            f"(requested {num_true_positives + num_false_positives})[/yellow]"
        )

    return sampled


def _present_alert(alert: dict, index: int, total: int) -> dict:
    """Display an alert and collect the reviewer's judgment."""
    console.print(f"\n[bold]Alert {index + 1}/{total}[/bold]")
    console.print("─" * 60)

    source = alert.get("source", "unknown")
    if source == "attack":
        panel_content = (
            f"[bold]Scenario:[/bold] {alert.get('scenario_id', 'N/A')}\n"
            f"[bold]Attack Family:[/bold] {alert.get('attack_family', 'N/A')}\n"
            f"[bold]Detected:[/bold] {alert.get('detected', 'N/A')}\n"
            f"[bold]Defense Mode:[/bold] {alert.get('defense_mode', 'N/A')}\n"
            f"[bold]Alerts Raised:[/bold] {alert.get('alerts_count', 'N/A')}"
        )
    else:
        panel_content = (
            f"[bold]Scenario:[/bold] {alert.get('scenario_id', 'N/A')}\n"
            f"[bold]Category:[/bold] {alert.get('server_category', 'N/A')}\n"
            f"[bold]Blocked:[/bold] {alert.get('blocked', 'N/A')}\n"
            f"[bold]Warned:[/bold] {alert.get('warned', 'N/A')}\n"
            f"[bold]Defense Mode:[/bold] {alert.get('defense_mode', 'N/A')}"
        )

    ground_truth = alert.get("ground_truth", "unknown")
    panel_content += f"\n\n[dim]Ground truth classification: {ground_truth}[/dim]"

    console.print(Panel(panel_content, title="Alert Details", border_style="blue"))

    agrees = Confirm.ask("Do you agree with the ground truth classification?")
    notes = Prompt.ask("Notes (optional, press Enter to skip)", default="")

    return {
        "scenario_id": alert.get("scenario_id"),
        "ground_truth": ground_truth,
        "reviewer_agrees": agrees,
        "notes": notes if notes else None,
        "timestamp": time.time(),
    }


def _compute_agreement(review_dir: Path) -> dict | None:
    """Compute inter-annotator agreement if multiple review files exist."""
    review_files = list(review_dir.glob("review_*.json"))
    if len(review_files) < 2:
        return None

    reviewer_judgments: dict[str, dict[str, bool]] = {}
    for rf in review_files:
        with open(rf) as f:
            data = json.load(f)
        reviewer = data.get("reviewer", rf.stem)
        judgments = {}
        for j in data.get("judgments", []):
            sid = j.get("scenario_id")
            if sid is not None:
                judgments[sid] = j.get("reviewer_agrees", False)
        reviewer_judgments[reviewer] = judgments

    reviewers = list(reviewer_judgments.keys())
    pairs_total = 0
    pairs_agree = 0

    for i in range(len(reviewers)):
        for j in range(i + 1, len(reviewers)):
            j1 = reviewer_judgments[reviewers[i]]
            j2 = reviewer_judgments[reviewers[j]]
            common = set(j1.keys()) & set(j2.keys())
            for sid in common:
                pairs_total += 1
                if j1[sid] == j2[sid]:
                    pairs_agree += 1

    if pairs_total == 0:
        return None

    percent_agreement = pairs_agree / pairs_total * 100

    return {
        "num_reviewers": len(reviewers),
        "reviewers": reviewers,
        "common_judgments": pairs_total,
        "agreements": pairs_agree,
        "percent_agreement": round(percent_agreement, 1),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="ShieldMCP Expert Review Tool")
    parser.add_argument(
        "--results", type=str, required=True,
        help="Path to framework evaluation results JSON",
    )
    parser.add_argument(
        "--reviewer", type=str, required=True,
        help="Reviewer identifier (e.g. 'expert1')",
    )
    parser.add_argument(
        "--num-samples", type=int, default=50,
        help="Total number of alerts to review (default: 50, split evenly TP/FP)",
    )
    parser.add_argument(
        "--output-dir", type=str, default="eval/results/output/expert_reviews",
        help="Directory for review output files",
    )
    args = parser.parse_args()

    results_path = Path(args.results)
    if not results_path.exists():
        console.print(f"[red]Results file not found: {results_path}[/red]")
        sys.exit(1)

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    console.print(Panel(
        f"[bold]ShieldMCP Expert Review[/bold]\n"
        f"Reviewer: {args.reviewer}\n"
        f"Samples: {args.num_samples}\n"
        f"Source: {results_path}",
        border_style="cyan",
    ))

    results = _load_results(results_path)
    num_tp = args.num_samples // 2
    num_fp = args.num_samples - num_tp
    alerts = _sample_alerts(results, num_tp, num_fp)

    if not alerts:
        console.print("[red]No alerts available for review.[/red]")
        sys.exit(1)

    console.print(f"\n[bold]Starting review of {len(alerts)} alerts...[/bold]")
    console.print("[dim]Press Ctrl+C at any time to save progress and exit.[/dim]\n")

    judgments: list[dict] = []
    try:
        for i, alert in enumerate(alerts):
            judgment = _present_alert(alert, i, len(alerts))
            judgments.append(judgment)
    except KeyboardInterrupt:
        console.print(f"\n\n[yellow]Review interrupted. Saving {len(judgments)} judgments...[/yellow]")

    agreed = sum(1 for j in judgments if j["reviewer_agrees"])
    total = len(judgments)

    if total > 0:
        table = Table(title="Review Summary")
        table.add_column("Metric", style="bold")
        table.add_column("Value", justify="right")
        table.add_row("Total reviewed", str(total))
        table.add_row("Agreed with ground truth", f"[green]{agreed}[/green]")
        table.add_row("Disagreed", f"[red]{total - agreed}[/red]")
        table.add_row("Agreement rate", f"{agreed / total * 100:.1f}%")
        console.print(table)

    review_output = {
        "reviewer": args.reviewer,
        "source_file": str(results_path),
        "num_samples_requested": args.num_samples,
        "num_reviewed": total,
        "agreement_rate": round(agreed / total * 100, 1) if total > 0 else 0.0,
        "timestamp": time.time(),
        "judgments": judgments,
    }

    output_file = output_dir / f"review_{args.reviewer}.json"
    with open(output_file, "w") as f:
        json.dump(review_output, f, indent=2)
    console.print(f"\n[dim]Review saved to {output_file}[/dim]")

    inter_agreement = _compute_agreement(output_dir)
    if inter_agreement:
        console.print()
        iat = Table(title="Inter-Annotator Agreement")
        iat.add_column("Metric", style="bold")
        iat.add_column("Value", justify="right")
        iat.add_row("Reviewers", ", ".join(inter_agreement["reviewers"]))
        iat.add_row("Common judgments", str(inter_agreement["common_judgments"]))
        iat.add_row("Agreements", str(inter_agreement["agreements"]))
        iat.add_row("Percent agreement", f"{inter_agreement['percent_agreement']}%")
        console.print(iat)

        agreement_file = output_dir / "inter_annotator_agreement.json"
        with open(agreement_file, "w") as f:
            json.dump(inter_agreement, f, indent=2)
        console.print(f"[dim]Agreement stats saved to {agreement_file}[/dim]")


if __name__ == "__main__":
    main()
