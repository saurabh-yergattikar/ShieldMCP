"""Replay workload for evaluating response caching under a security pipeline.

Replays a Zipf-distributed stream of tool calls drawn from the benchmark
scenarios and measures how three cache policies interact with response
validation:

- ``none``    : no cache; every response is validated.
- ``unsafe``  : transport-layer cache with no security awareness. Responses
                are cached raw before validation and cache hits are served
                without re-validation (the naive pattern), with one shared
                namespace across principals.
- ``gated``   : the governed cache. Responses are validated first, only
                clean verdicts are admitted, and keys are principal-isolated.

An *unsafe serve* is a poisoned response delivered to the caller without a
blocking verdict on that delivery. The interesting quantity is how a cache
policy amplifies or bounds detector misses across repeated traffic.

Usage:
    python eval/benchmarks/cache_workload.py --requests 5000 --seed 7 \
        --backend tiered --policy gated --output-dir eval/results/cache
"""

from __future__ import annotations

import argparse
import asyncio
import json
import random
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from rich.console import Console
from rich.table import Table

from shieldmcp.core.config import ShieldMCPConfig
from shieldmcp.core.pipeline import ShieldPipeline
from shieldmcp.governance import GovernedResponseCache, ResponseCacheConfig

from scenarios.attack_scenarios import get_all_attack_scenarios
from scenarios.benign_scenarios import get_all_benign_scenarios

console = Console()

PRINCIPALS = ["alice", "bob"]


def build_population() -> list[dict]:
    """Items = every scenario that carries a response payload."""
    items: list[dict] = []
    for s in get_all_attack_scenarios():
        if s.tool_response:
            items.append({
                "server_id": s.server_id,
                "tool_name": s.tool_name,
                "params": {"query": s.scenario_id},
                "response": s.tool_response,
                "poisoned": True,
                "scenario_id": s.scenario_id,
            })
    for s in get_all_benign_scenarios():
        if s.expected_response:
            items.append({
                "server_id": s.server_id,
                "tool_name": s.tool_name,
                "params": s.parameters or {"query": s.scenario_id},
                "response": s.expected_response,
                "poisoned": False,
                "scenario_id": s.scenario_id,
            })
    return items


def zipf_ranks(n_items: int, n_requests: int, s: float, rng: random.Random) -> list[int]:
    """Sample item ranks from a Zipf(s) distribution over n_items."""
    weights = [1.0 / (rank ** s) for rank in range(1, n_items + 1)]
    total = sum(weights)
    probs = [w / total for w in weights]
    return rng.choices(range(n_items), weights=probs, k=n_requests)


async def run_workload(
    requests: int,
    seed: int,
    backend: str,
    policy: str,
    zipf_s: float,
    output_dir: Path,
    band_low: float | None = None,
    min_words: int | None = None,
) -> dict:
    rng = random.Random(seed)
    population = build_population()
    # Shuffle so poisoned items are spread across the popularity ranking
    # rather than concentrated at the head or tail.
    rng.shuffle(population)

    ranks = zipf_ranks(len(population), requests, zipf_s, rng)
    principals = [rng.choice(PRINCIPALS) for _ in range(requests)]

    cfg = ShieldMCPConfig()
    cfg.stage1.semantic_backend = backend
    cfg.stage3.instruction_detection_backend = backend
    if band_low is not None:
        cfg.stage1.tiered_band_low = band_low
    if min_words is not None:
        cfg.stage3.tiered_min_words = min_words
    output_dir.mkdir(parents=True, exist_ok=True)
    cfg.registry_db_path = str(output_dir / f"wl_{policy}_{backend}.db")

    pipeline = ShieldPipeline(cfg)
    await pipeline.initialize()

    cache = None
    if policy == "unsafe":
        cache = GovernedResponseCache(ResponseCacheConfig(
            per_principal=False, require_clean_verdict=False, ttl_seconds=1e9,
        ))
    elif policy == "gated":
        cache = GovernedResponseCache(ResponseCacheConfig(
            per_principal=True, require_clean_verdict=True, ttl_seconds=1e9,
        ))

    from shieldmcp.stage3 import response_analyzer as _s3
    _s3.reset_tier_stats()

    served = 0
    blocked = 0
    unsafe_serves = 0
    unsafe_from_cache = 0
    validations = 0
    latencies_ms: list[float] = []

    t_start = time.perf_counter()
    for i in range(requests):
        item = population[ranks[i]]
        principal = principals[i]
        t0 = time.perf_counter()

        if cache is not None:
            key = cache.make_key(
                item["server_id"], item["tool_name"], item["params"], principal
            )
            entry = cache.get(key)
            if entry is not None:
                # unsafe policy serves hits without re-validation; gated
                # entries were validated clean before admission.
                served += 1
                if item["poisoned"]:
                    unsafe_serves += 1
                    unsafe_from_cache += 1
                latencies_ms.append((time.perf_counter() - t0) * 1000)
                continue

        if policy == "unsafe" and cache is not None:
            # Naive transport cache: store the raw response before validation.
            cache.put(key, item["response"], verdict_passed=True, principal=principal)

        action, _modified, alerts = await pipeline.process_tool_response(
            item["server_id"], item["tool_name"], item["response"]
        )
        validations += 1
        was_blocked = any(a.action.value in ("block", "quarantine") for a in alerts)

        if was_blocked:
            blocked += 1
        else:
            served += 1
            if item["poisoned"]:
                unsafe_serves += 1

        if policy == "gated" and cache is not None:
            cache.put(key, item["response"], verdict_passed=not was_blocked,
                      principal=principal)

        latencies_ms.append((time.perf_counter() - t0) * 1000)

    wall_s = time.perf_counter() - t_start
    await pipeline.shutdown()

    lat_sorted = sorted(latencies_ms)

    def pct(p: float) -> float:
        k = int(round((p / 100) * (len(lat_sorted) - 1)))
        return lat_sorted[k]

    poisoned_items = sum(1 for it in population if it["poisoned"])
    results = {
        "config": {
            "requests": requests, "seed": seed, "backend": backend,
            "policy": policy, "zipf_s": zipf_s,
            "population": len(population), "poisoned_items": poisoned_items,
            "principals": len(PRINCIPALS),
            "band_low": cfg.stage1.tiered_band_low,
            "min_words": cfg.stage3.tiered_min_words,
            "date": time.strftime("%Y-%m-%d %H:%M:%S"),
        },
        "outcomes": {
            "served": served,
            "blocked": blocked,
            "unsafe_serves": unsafe_serves,
            "unsafe_from_cache": unsafe_from_cache,
            "validations": validations,
            "validations_saved": requests - validations,
            "cache_stats": cache.stats.as_dict() if cache else None,
            "tier_stats_stage3": _s3.get_tier_stats(),
        },
        "latency_ms": {
            "p50": pct(50), "p95": pct(95), "p99": pct(99),
            "mean": sum(latencies_ms) / len(latencies_ms),
            "wall_seconds": wall_s,
        },
    }

    output_dir.mkdir(parents=True, exist_ok=True)
    out = output_dir / f"workload_{policy}_{backend}.json"
    with open(out, "w") as f:
        json.dump(results, f, indent=2)

    hit_rate = (cache.stats.hits / max(cache.stats.lookups, 1)) if cache else 0.0
    table = Table(title=f"Cache workload: policy={policy} backend={backend}")
    for col in ["Requests", "Hit rate", "Validations", "Unsafe serves",
                "(from cache)", "p50 ms", "p95 ms"]:
        table.add_column(col, justify="right")
    table.add_row(
        str(requests), f"{hit_rate*100:.1f}%", str(validations),
        str(unsafe_serves), str(unsafe_from_cache),
        f"{pct(50):.2f}", f"{pct(95):.2f}",
    )
    console.print(table)
    console.print(f"[dim]Saved to {out}[/dim]")
    return results


def main() -> None:
    parser = argparse.ArgumentParser(description="Response-cache replay workload")
    parser.add_argument("--requests", type=int, default=5000)
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--zipf-s", type=float, default=1.1)
    parser.add_argument("--backend", type=str, default="heuristic",
                        choices=["heuristic", "classifier", "tiered"])
    parser.add_argument("--policy", type=str, default="gated",
                        choices=["none", "unsafe", "gated"])
    parser.add_argument("--band-low", type=float, default=None)
    parser.add_argument("--min-words", type=int, default=None)
    parser.add_argument("--output-dir", type=str, default="eval/results/cache")
    args = parser.parse_args()
    asyncio.run(run_workload(
        args.requests, args.seed, args.backend, args.policy, args.zipf_s,
        Path(args.output_dir), band_low=args.band_low, min_words=args.min_words,
    ))


if __name__ == "__main__":
    main()
