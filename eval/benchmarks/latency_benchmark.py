"""Formal latency benchmarking for ShieldMCP's three validation stages.

Measures per-stage and end-to-end latency over realistic attack and benign
scenarios, computing min/max/mean/median/P95/P99/stddev statistics.

Usage:
    python eval/benchmarks/latency_benchmark.py --iterations 1000 --warmup 10
"""

from __future__ import annotations

import argparse
import asyncio
import json
import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from shieldmcp.core.config import ShieldMCPConfig
from shieldmcp.core.pipeline import ShieldPipeline

from scenarios.attack_scenarios import get_all_attack_scenarios
from scenarios.benign_scenarios import get_all_benign_scenarios

console = Console()


def _percentile(data: list[float], pct: float) -> float:
    """Return the *pct*-th percentile of *data* (0–100 scale)."""
    if not data:
        return 0.0
    sorted_data = sorted(data)
    k = (pct / 100) * (len(sorted_data) - 1)
    f = int(k)
    c = f + 1
    if c >= len(sorted_data):
        return sorted_data[-1]
    return sorted_data[f] + (k - f) * (sorted_data[c] - sorted_data[f])


def _compute_stats(timings_ms: list[float]) -> dict[str, float]:
    if not timings_ms:
        return {k: 0.0 for k in ["min", "max", "mean", "median", "p95", "p99", "stddev"]}
    return {
        "min": min(timings_ms),
        "max": max(timings_ms),
        "mean": statistics.mean(timings_ms),
        "median": statistics.median(timings_ms),
        "p95": _percentile(timings_ms, 95),
        "p99": _percentile(timings_ms, 99),
        "stddev": statistics.stdev(timings_ms) if len(timings_ms) > 1 else 0.0,
    }


def _build_test_data() -> dict:
    """Assemble realistic test payloads from scenario definitions."""
    attacks = get_all_attack_scenarios()
    benign = get_all_benign_scenarios()

    tool_defs: list[tuple[str, list[dict]]] = []
    for s in attacks:
        if s.tool_definitions:
            tool_defs.append((s.server_id, s.tool_definitions))
    for s in benign:
        tool_defs.append((
            s.server_id,
            [{"name": s.tool_name, "description": s.expected_behavior,
              "inputSchema": {"type": "object", "properties": {}}}],
        ))

    param_sets: list[tuple[str, str, dict]] = []
    for s in benign:
        if s.parameters:
            param_sets.append((s.server_id, s.tool_name, s.parameters))
    for s in attacks:
        param_sets.append((s.server_id, s.tool_name, {"input": "test value"}))

    responses: list[tuple[str, str, str]] = []
    for s in attacks:
        if s.tool_response:
            responses.append((s.server_id, s.tool_name, s.tool_response))
    for s in benign:
        if s.expected_response:
            responses.append((s.server_id, s.tool_name, s.expected_response))

    return {
        "tool_defs": tool_defs,
        "param_sets": param_sets,
        "responses": responses,
    }


async def _benchmark_stage1(
    pipeline: ShieldPipeline,
    data: list[tuple[str, list[dict]]],
    iterations: int,
) -> list[float]:
    timings: list[float] = []
    for i in range(iterations):
        server_id, tool_def = data[i % len(data)]
        start = time.perf_counter()
        await pipeline.validate_tools(server_id, tool_def)
        timings.append((time.perf_counter() - start) * 1000)
    return timings


async def _benchmark_stage2(
    pipeline: ShieldPipeline,
    data: list[tuple[str, str, dict]],
    iterations: int,
) -> list[float]:
    timings: list[float] = []
    for i in range(iterations):
        server_id, tool_name, params = data[i % len(data)]
        start = time.perf_counter()
        await pipeline.validate_call(server_id, tool_name, params)
        timings.append((time.perf_counter() - start) * 1000)
    return timings


async def _benchmark_stage3(
    pipeline: ShieldPipeline,
    data: list[tuple[str, str, str]],
    iterations: int,
) -> list[float]:
    timings: list[float] = []
    for i in range(iterations):
        server_id, tool_name, content = data[i % len(data)]
        start = time.perf_counter()
        await pipeline.validate_response(server_id, tool_name, content)
        timings.append((time.perf_counter() - start) * 1000)
    return timings


async def _benchmark_e2e(
    pipeline: ShieldPipeline,
    test_data: dict,
    iterations: int,
) -> list[float]:
    tool_defs = test_data["tool_defs"]
    param_sets = test_data["param_sets"]
    responses = test_data["responses"]
    timings: list[float] = []
    for i in range(iterations):
        start = time.perf_counter()
        sid1, td = tool_defs[i % len(tool_defs)]
        await pipeline.validate_tools(sid1, td)
        sid2, tn2, params = param_sets[i % len(param_sets)]
        await pipeline.validate_call(sid2, tn2, params)
        sid3, tn3, content = responses[i % len(responses)]
        await pipeline.validate_response(sid3, tn3, content)
        timings.append((time.perf_counter() - start) * 1000)
    return timings


def _print_results(all_stats: dict[str, dict[str, float]]) -> None:
    table = Table(title="ShieldMCP Latency Benchmark (ms)")
    table.add_column("Stage", style="bold")
    table.add_column("Min", justify="right")
    table.add_column("Max", justify="right")
    table.add_column("Mean", justify="right")
    table.add_column("Median", justify="right", style="cyan")
    table.add_column("P95", justify="right", style="yellow")
    table.add_column("P99", justify="right", style="red")
    table.add_column("StdDev", justify="right", style="dim")

    for stage, stats in all_stats.items():
        table.add_row(
            stage,
            f"{stats['min']:.2f}",
            f"{stats['max']:.2f}",
            f"{stats['mean']:.2f}",
            f"{stats['median']:.2f}",
            f"{stats['p95']:.2f}",
            f"{stats['p99']:.2f}",
            f"{stats['stddev']:.2f}",
        )

    console.print(table)


async def run_benchmark(iterations: int, warmup: int, output_dir: Path) -> dict:
    config = ShieldMCPConfig()
    config.registry_db_path = str(output_dir / "bench_registry.db")

    console.print(Panel(
        f"[bold]ShieldMCP Latency Benchmark[/bold]\n"
        f"Iterations: {iterations}  |  Warmup: {warmup}",
        border_style="cyan",
    ))

    console.print("[dim]Building test data from scenarios...[/dim]")
    test_data = _build_test_data()
    console.print(
        f"  Tool definitions: {len(test_data['tool_defs'])}  |  "
        f"Parameter sets: {len(test_data['param_sets'])}  |  "
        f"Responses: {len(test_data['responses'])}"
    )

    pipeline = ShieldPipeline(config)
    await pipeline.initialize()

    if warmup > 0:
        console.print(f"\n[dim]Running {warmup} warmup iterations...[/dim]")
        await _benchmark_stage1(pipeline, test_data["tool_defs"], warmup)
        await _benchmark_stage2(pipeline, test_data["param_sets"], warmup)
        await _benchmark_stage3(pipeline, test_data["responses"], warmup)

    console.print(f"\n[bold]Running {iterations} measured iterations per stage...[/bold]")

    console.print("  Stage 1: Tool Description Validation...")
    s1_timings = await _benchmark_stage1(pipeline, test_data["tool_defs"], iterations)

    console.print("  Stage 2: Parameter Sanitization...")
    s2_timings = await _benchmark_stage2(pipeline, test_data["param_sets"], iterations)

    console.print("  Stage 3: Response Analysis...")
    s3_timings = await _benchmark_stage3(pipeline, test_data["responses"], iterations)

    console.print("  End-to-End (all 3 stages)...")
    e2e_timings = await _benchmark_e2e(pipeline, test_data, iterations)

    await pipeline.shutdown()

    all_stats = {
        "Stage 1 (Tool Desc)": _compute_stats(s1_timings),
        "Stage 2 (Params)": _compute_stats(s2_timings),
        "Stage 3 (Response)": _compute_stats(s3_timings),
        "End-to-End": _compute_stats(e2e_timings),
    }

    console.print()
    _print_results(all_stats)

    results = {
        "config": {"iterations": iterations, "warmup": warmup},
        "stages": {
            "stage1": {"stats": all_stats["Stage 1 (Tool Desc)"], "raw_count": len(s1_timings)},
            "stage2": {"stats": all_stats["Stage 2 (Params)"], "raw_count": len(s2_timings)},
            "stage3": {"stats": all_stats["Stage 3 (Response)"], "raw_count": len(s3_timings)},
            "end_to_end": {"stats": all_stats["End-to-End"], "raw_count": len(e2e_timings)},
        },
        "test_data_sizes": {
            "tool_definitions": len(test_data["tool_defs"]),
            "parameter_sets": len(test_data["param_sets"]),
            "responses": len(test_data["responses"]),
        },
    }

    output_file = output_dir / "latency_results.json"
    output_file.parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)
    console.print(f"\n[dim]Results saved to {output_file}[/dim]")

    return results


def main() -> None:
    parser = argparse.ArgumentParser(description="ShieldMCP Latency Benchmark")
    parser.add_argument(
        "--iterations", type=int, default=1000,
        help="Number of measured iterations per stage (default: 1000)",
    )
    parser.add_argument(
        "--warmup", type=int, default=10,
        help="Warmup iterations before measurement (default: 10)",
    )
    parser.add_argument(
        "--output-dir", type=str, default="eval/results/output",
        help="Output directory for results JSON",
    )
    args = parser.parse_args()
    asyncio.run(run_benchmark(args.iterations, args.warmup, Path(args.output_dir)))


if __name__ == "__main__":
    main()
