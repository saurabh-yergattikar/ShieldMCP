"""Main evaluation script — runs the full ShieldMCP benchmark.

Reproduces the paper's Table 2 results by running all 487 attack scenarios
and 200 benign scenarios across multiple LLM backends and defense modes.

Usage:
    # Full evaluation (all models, all scenarios, 3 repetitions)
    python eval/run_evaluation.py --full

    # Quick smoke test (subset of scenarios, 1 repetition)
    python eval/run_evaluation.py --quick

    # Specific model only
    python eval/run_evaluation.py --model gpt-4o

    # Specific attack family only
    python eval/run_evaluation.py --family tool_poisoning

    # Framework-only evaluation (no LLM needed — tests ShieldMCP detection directly)
    python eval/run_evaluation.py --framework-only
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import time
from dataclasses import asdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[0]))
sys.path.insert(0, str(Path(__file__).resolve().parents[0] / ".." / "src"))

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from shieldmcp.core.config import ShieldMCPConfig
from shieldmcp.core.models import Action, AttackFamily
from shieldmcp.core.pipeline import ShieldPipeline

from harness.runner import EvalRunner, EvalScenario, LLMBackendConfig
from scenarios.attack_scenarios import get_all_attack_scenarios, AttackScenario as AttackScenarioDC
from scenarios.benign_scenarios import get_all_benign_scenarios, BenignScenario

console = Console()


async def run_framework_evaluation(
    attack_scenarios: list[AttackScenario],
    benign_scenarios: list[BenignScenario],
    output_dir: Path,
) -> dict:
    """Run evaluation using only the ShieldMCP framework (no LLM calls needed).

    Tests whether ShieldMCP's detection stages correctly identify attacks
    in tool descriptions and responses, and correctly pass benign content.
    """
    config = ShieldMCPConfig()
    config.registry_db_path = str(output_dir / "eval_registry.db")

    results = {
        "attack_results": [],
        "benign_results": [],
        "metadata": {
            "timestamp": time.time(),
            "num_attack_scenarios": len(attack_scenarios),
            "num_benign_scenarios": len(benign_scenarios),
            "defense_mode": "shieldmcp",
        },
    }

    # --- Attack Scenarios ---
    console.print(f"\n[bold]Running {len(attack_scenarios)} attack scenarios...[/bold]")

    pipeline = ShieldPipeline(config)
    await pipeline.initialize()

    family_results: dict[str, dict] = {}

    for i, scenario in enumerate(attack_scenarios):
        if (i + 1) % 50 == 0:
            console.print(f"  Progress: {i+1}/{len(attack_scenarios)}")

        detected = False
        alerts_raised = []
        total_latency = 0.0

        # Stage 1: Check tool definitions if present
        if scenario.tool_definitions:
            action, filtered, alerts = await pipeline.validate_tools(
                scenario.server_id, scenario.tool_definitions
            )
            alerts_raised.extend([a.to_dict() for a in alerts])
            total_latency += sum(1 for _ in alerts)  # approximate
            if action == Action.BLOCK or any(a.action == Action.BLOCK for a in alerts):
                detected = True

        # Stage 3: Check tool response if present (IPI attacks)
        if scenario.tool_response:
            action, modified, alerts = await pipeline.process_tool_response(
                scenario.server_id, scenario.tool_name, scenario.tool_response
            )
            alerts_raised.extend([a.to_dict() for a in alerts])
            if action == Action.BLOCK or any(a.action == Action.BLOCK for a in alerts):
                detected = True

        family = scenario.attack_family
        if family not in family_results:
            family_results[family] = {"total": 0, "detected": 0, "missed": 0}
        family_results[family]["total"] += 1
        if detected:
            family_results[family]["detected"] += 1
        else:
            family_results[family]["missed"] += 1

        results["attack_results"].append({
            "scenario_id": scenario.scenario_id,
            "attack_family": scenario.attack_family,
            "detected": detected,
            "attack_succeeded": not detected,
            "alerts_count": len(alerts_raised),
            "defense_mode": "shieldmcp",
        })

    await pipeline.shutdown()

    # --- Benign Scenarios ---
    console.print(f"\n[bold]Running {len(benign_scenarios)} benign scenarios...[/bold]")

    pipeline2 = ShieldPipeline(ShieldMCPConfig())
    pipeline2.config.registry_db_path = str(output_dir / "eval_registry_benign.db")
    await pipeline2.initialize()

    benign_blocked = 0
    benign_warned = 0
    benign_passed = 0

    for i, scenario in enumerate(benign_scenarios):
        if (i + 1) % 50 == 0:
            console.print(f"  Progress: {i+1}/{len(benign_scenarios)}")

        was_blocked = False
        was_warned = False

        # Stage 2: Check parameters
        if scenario.parameters:
            action, alerts = await pipeline2.process_tool_call(
                scenario.server_id, scenario.tool_name, scenario.parameters
            )
            if action == Action.BLOCK:
                was_blocked = True
            elif alerts:
                was_warned = True

        # Stage 3: Check response if present
        if scenario.expected_response:
            action, _, alerts = await pipeline2.process_tool_response(
                scenario.server_id, scenario.tool_name, scenario.expected_response
            )
            if action == Action.BLOCK:
                was_blocked = True
            elif alerts:
                was_warned = True

        if was_blocked:
            benign_blocked += 1
        elif was_warned:
            benign_warned += 1
        else:
            benign_passed += 1

        results["benign_results"].append({
            "scenario_id": scenario.scenario_id,
            "server_category": scenario.server_category,
            "blocked": was_blocked,
            "warned": was_warned,
            "passed": not was_blocked and not was_warned,
            "defense_mode": "shieldmcp",
        })

    await pipeline2.shutdown()

    # --- Print Results ---
    console.print("\n")
    _print_attack_results(family_results)
    _print_benign_results(len(benign_scenarios), benign_passed, benign_warned, benign_blocked)

    # Save results
    output_file = output_dir / "framework_eval_results.json"
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2, default=str)
    console.print(f"\n[dim]Results saved to {output_file}[/dim]")

    return results


def _print_attack_results(family_results: dict) -> None:
    table = Table(title="Attack Detection Results (ShieldMCP Framework)")
    table.add_column("Attack Family", style="bold")
    table.add_column("Total", justify="right")
    table.add_column("Detected", justify="right", style="green")
    table.add_column("Missed", justify="right", style="red")
    table.add_column("Detection Rate", justify="right")
    table.add_column("ASR (Attack Success)", justify="right")

    total_all = 0
    detected_all = 0

    for family, counts in sorted(family_results.items()):
        total = counts["total"]
        detected = counts["detected"]
        missed = counts["missed"]
        det_rate = (detected / total * 100) if total > 0 else 0
        asr = (missed / total * 100) if total > 0 else 0

        total_all += total
        detected_all += detected

        asr_color = "green" if asr < 15 else ("yellow" if asr < 30 else "red")
        table.add_row(
            family,
            str(total),
            str(detected),
            str(missed),
            f"{det_rate:.1f}%",
            f"[{asr_color}]{asr:.1f}%[/{asr_color}]",
        )

    # Overall
    overall_det = (detected_all / total_all * 100) if total_all > 0 else 0
    overall_asr = ((total_all - detected_all) / total_all * 100) if total_all > 0 else 0
    table.add_section()
    table.add_row(
        "[bold]OVERALL[/bold]",
        str(total_all),
        str(detected_all),
        str(total_all - detected_all),
        f"[bold]{overall_det:.1f}%[/bold]",
        f"[bold]{overall_asr:.1f}%[/bold]",
    )

    console.print(table)


def _print_benign_results(total: int, passed: int, warned: int, blocked: int) -> None:
    table = Table(title="Benign Task Impact")
    table.add_column("Metric", style="bold")
    table.add_column("Value", justify="right")

    completion_rate = ((passed + warned) / total * 100) if total > 0 else 0
    fp_rate = (blocked / total * 100) if total > 0 else 0

    table.add_row("Total benign scenarios", str(total))
    table.add_row("Passed cleanly", f"[green]{passed}[/green]")
    table.add_row("Warned (not blocked)", f"[yellow]{warned}[/yellow]")
    table.add_row("Blocked (false positive)", f"[red]{blocked}[/red]")
    table.add_row("Task completion rate", f"[bold]{completion_rate:.1f}%[/bold]")
    table.add_row("False positive rate", f"{fp_rate:.1f}%")

    console.print(table)


MODEL_CONFIGS: list[dict[str, str]] = [
    {"name": "gpt-4o", "provider": "openai", "model": "gpt-4o", "key_env": "OPENAI_API_KEY"},
    {"name": "gpt-4o-mini", "provider": "openai", "model": "gpt-4o-mini", "key_env": "OPENAI_API_KEY"},
    {"name": "claude-3.5-sonnet", "provider": "anthropic", "model": "claude-3-5-sonnet-20241022", "key_env": "ANTHROPIC_API_KEY"},
    {"name": "llama-3.1-70b", "provider": "openai", "model": "meta-llama/Meta-Llama-3.1-70B-Instruct-Turbo", "key_env": "TOGETHER_API_KEY"},
    {"name": "qwen2.5-72b", "provider": "openai", "model": "Qwen/Qwen2.5-72B-Instruct-Turbo", "key_env": "TOGETHER_API_KEY"},
]

TOGETHER_BASE_URL = "https://api.together.xyz/v1"

_FAMILY_MAP: dict[str, AttackFamily] = {
    "tool_poisoning": AttackFamily.TOOL_POISONING,
    "indirect_prompt_injection": AttackFamily.INDIRECT_PROMPT_INJECTION,
    "supply_chain": AttackFamily.SUPPLY_CHAIN,
    "rug_pull": AttackFamily.RUG_PULL,
    "cross_tool_chain": AttackFamily.CROSS_TOOL_CHAIN,
}


def _attack_to_eval(scenario: AttackScenarioDC) -> EvalScenario:
    tool_desc = ""
    tool_params: dict = {}
    if scenario.tool_definitions:
        first = scenario.tool_definitions[0]
        tool_desc = first.get("description", "")
        tool_params = first.get("inputSchema", first.get("parameters", {}))

    return EvalScenario(
        scenario_id=scenario.scenario_id,
        attack_family=_FAMILY_MAP.get(scenario.attack_family, AttackFamily.TOOL_POISONING),
        server_id=scenario.server_id,
        tool_name=scenario.tool_name,
        user_task=scenario.user_task,
        expected_behavior=scenario.expected_safe_behavior,
        attack_behavior=scenario.attack_behavior,
        success_criteria=scenario.attack_behavior,
        tool_description=tool_desc,
        tool_parameters=tool_params,
        tool_response=scenario.tool_response,
    )


def _print_full_eval_results(results: list) -> None:
    asr_table: dict[str, dict[str, list[bool]]] = {}
    for r in results:
        family = r.get("scenario_id", "")[:2]
        family_map = {
            "TP": "tool_poisoning", "IP": "indirect_prompt_injection",
            "SC": "supply_chain", "RP": "rug_pull", "CT": "cross_tool_chain",
        }
        family_name = family_map.get(family, "unknown")
        mode = r.get("defense_mode", "unknown") if isinstance(r, dict) else r.defense_mode
        succeeded = r.get("attack_succeeded", False) if isinstance(r, dict) else r.attack_succeeded

        asr_table.setdefault(family_name, {}).setdefault(mode, []).append(succeeded)

    table = Table(title="Attack Success Rate by Family and Defense Mode")
    table.add_column("Attack Family", style="bold")

    all_modes = sorted({m for fam in asr_table.values() for m in fam})
    for mode in all_modes:
        table.add_column(mode, justify="right")

    for family in sorted(asr_table):
        row = [family]
        for mode in all_modes:
            outcomes = asr_table[family].get(mode, [])
            if outcomes:
                asr = sum(outcomes) / len(outcomes) * 100
                color = "green" if asr < 15 else ("yellow" if asr < 30 else "red")
                row.append(f"[{color}]{asr:.1f}%[/{color}]")
            else:
                row.append("-")
        table.add_row(*row)

    console.print(table)


async def run_full_evaluation(
    attack_scenarios: list[AttackScenarioDC],
    output_dir: Path,
    model_filter: str | None = None,
    quick: bool = False,
) -> None:
    configs_to_run = MODEL_CONFIGS
    if model_filter:
        configs_to_run = [c for c in MODEL_CONFIGS if c["name"] == model_filter]
        if not configs_to_run:
            console.print(f"[red]Unknown model '{model_filter}'. Available: {[c['name'] for c in MODEL_CONFIGS]}[/red]")
            return

    missing_keys: list[str] = []
    needed_envs = {c["key_env"] for c in configs_to_run}
    for env_var in needed_envs:
        if not os.environ.get(env_var):
            missing_keys.append(env_var)
    if missing_keys:
        console.print(f"[yellow]Warning: missing API keys: {', '.join(missing_keys)}[/yellow]")
        console.print("[yellow]Models requiring missing keys will be skipped.[/yellow]")

    eval_scenarios = [_attack_to_eval(s) for s in attack_scenarios]
    repetitions = 1 if quick else 3
    modes = ["none", "regex", "llm_judge", "shieldmcp"]

    all_results: list[dict] = []

    for mc in configs_to_run:
        api_key = os.environ.get(mc["key_env"], "")
        if not api_key:
            console.print(f"[dim]Skipping {mc['name']} (no {mc['key_env']})[/dim]")
            continue

        console.print(f"\n[bold]Running evaluation with {mc['name']}...[/bold]")

        llm_config = LLMBackendConfig(
            provider=mc["provider"],
            model=mc["model"],
            api_key=api_key,
        )

        if mc["key_env"] == "TOGETHER_API_KEY":
            import openai as _openai_mod
            _orig_base = getattr(_openai_mod, "_base_url", None)

        shield_config = ShieldMCPConfig()
        shield_config.registry_db_path = str(output_dir / f"eval_registry_{mc['name']}.db")

        runner = EvalRunner(
            config=shield_config,
            scenarios=eval_scenarios,
            llm_config=llm_config,
        )

        results = await runner.run_all(repetitions=repetitions, modes=modes)
        runner.export_results(output_dir / f"full_eval_{mc['name']}.json")

        serialized = [asdict(r) for r in results]
        all_results.extend(serialized)

        console.print(f"  [green]Completed {len(results)} evaluations for {mc['name']}[/green]")

    output_file = output_dir / "full_eval_results.json"
    with open(output_file, "w") as f:
        json.dump(all_results, f, indent=2, default=str)
    console.print(f"\n[dim]Full results saved to {output_file}[/dim]")

    if all_results:
        _print_full_eval_results(all_results)


async def main() -> None:
    parser = argparse.ArgumentParser(description="ShieldMCP Evaluation")
    parser.add_argument("--framework-only", action="store_true",
                        help="Run framework-only evaluation (no LLM API calls needed)")
    parser.add_argument("--full", action="store_true",
                        help="Run full evaluation with LLM backends")
    parser.add_argument("--quick", action="store_true",
                        help="Quick smoke test with subset of scenarios")
    parser.add_argument("--family", type=str, default=None,
                        help="Run only a specific attack family")
    parser.add_argument("--model", type=str, default=None,
                        help="Run only a specific model (e.g. gpt-4o, claude-3.5-sonnet)")
    parser.add_argument("--output-dir", type=str, default="eval/results/output",
                        help="Output directory for results")
    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    attack_scenarios = get_all_attack_scenarios()
    benign_scenarios = get_all_benign_scenarios()

    if args.family:
        attack_scenarios = [s for s in attack_scenarios if s.attack_family == args.family]

    if args.quick:
        attack_scenarios = attack_scenarios[:50]
        benign_scenarios = benign_scenarios[:25]

    console.print(Panel(
        f"[bold]ShieldMCP Evaluation[/bold]\n"
        f"Attack scenarios: {len(attack_scenarios)}\n"
        f"Benign scenarios: {len(benign_scenarios)}",
        border_style="cyan",
    ))

    if args.framework_only or not args.full:
        await run_framework_evaluation(attack_scenarios, benign_scenarios, output_dir)
    else:
        await run_full_evaluation(
            attack_scenarios, output_dir,
            model_filter=args.model, quick=args.quick,
        )


if __name__ == "__main__":
    asyncio.run(main())
