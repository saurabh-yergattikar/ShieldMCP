"""Live web demo server for ShieldMCP (EMNLP 2026 System Demonstration).

Serves a single-page UI and exposes the *real* three-stage pipeline over HTTP.
Every verdict shown in the browser is computed live by `ShieldPipeline` — nothing
is mocked. Run with:

    shieldmcp demo                 # http://127.0.0.1:8000
    shieldmcp demo --port 9000
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from aiohttp import web

from ..core.config import ShieldMCPConfig
from ..core.models import Action
from ..core.pipeline import ShieldPipeline
from .scenarios import FAMILY_LABELS, SCENARIOS, scenario_by_id

_STATIC = Path(__file__).parent / "static"


def _summarize_eval(data: dict[str, Any]) -> dict[str, Any]:
    """Compute aggregate ASR / benign stats from raw per-scenario results."""
    attacks = data.get("attack_results", [])
    benign = data.get("benign_results", [])

    fam: dict[str, dict[str, int]] = {}
    detected_total = 0
    for r in attacks:
        f = r.get("attack_family", "unknown")
        fam.setdefault(f, {"total": 0, "detected": 0})
        fam[f]["total"] += 1
        if r.get("detected"):
            fam[f]["detected"] += 1
            detected_total += 1

    by_family = {}
    for f, c in fam.items():
        asr = 100.0 * (c["total"] - c["detected"]) / c["total"] if c["total"] else 0.0
        by_family[f] = {
            "total": c["total"],
            "detected": c["detected"],
            "asr": round(asr, 1),
        }

    total_attacks = len(attacks)
    overall_asr = 100.0 * (total_attacks - detected_total) / total_attacks if total_attacks else 0.0

    passed = sum(1 for r in benign if r.get("passed"))
    benign_pass = 100.0 * passed / len(benign) if benign else 0.0

    return {
        "overall": {
            "total": total_attacks,
            "detected": detected_total,
            "asr": round(overall_asr, 1),
        },
        "benign": {
            "total": len(benign),
            "passed": passed,
            "pass_rate": round(benign_pass, 1),
        },
        "by_family": by_family,
    }


def _alert_payload(alert: Any) -> dict[str, Any]:
    return {
        "stage": alert.stage.value,
        "severity": alert.severity.value,
        "attack_family": alert.attack_family.value,
        "action": alert.action.value,
        "message": alert.message,
        "details": alert.details,
        "tool_name": alert.tool_name,
    }


def _stage_result(
    action: Action, alerts: list, latency_ms: float, extra: dict | None = None
) -> dict:
    blocked = any(a.action == Action.BLOCK for a in alerts)
    warned = any(a.action == Action.WARN for a in alerts)
    status = "block" if blocked else ("warn" if warned else "pass")
    out = {
        "status": status,
        "action": action.value,
        "latency_ms": round(latency_ms, 2),
        "alerts": [_alert_payload(a) for a in alerts],
    }
    if extra:
        out.update(extra)
    return out


class DemoApp:
    def __init__(self, config: ShieldMCPConfig) -> None:
        self._config = config
        self._pipeline: ShieldPipeline | None = None

    async def _get_pipeline(self) -> ShieldPipeline:
        # Fresh in-memory pipeline per request-batch keeps rug-pull state clean
        # and makes each demo run reproducible.
        pipeline = ShieldPipeline(self._config)
        await pipeline.initialize()
        return pipeline

    # --- routes ---

    async def index(self, request: web.Request) -> web.Response:
        return web.FileResponse(_STATIC / "index.html")

    async def list_scenarios(self, request: web.Request) -> web.Response:
        out = []
        for s in SCENARIOS:
            label, role = FAMILY_LABELS[s["family"]]
            out.append(
                {
                    "id": s["id"],
                    "title": s["title"],
                    "family": s["family"],
                    "family_label": label,
                    "family_role": role,
                    "blurb": s["blurb"],
                    "server_id": s["server_id"],
                    "tool_count": len(s["tools"]),
                    "call": s["call"],
                    "sample_response": s["response"],
                    "tools": s["tools"],
                    "is_rug_pull": "tools_v1" in s,
                }
            )
        return web.json_response(out)

    async def run_scenario(self, request: web.Request) -> web.Response:
        scenario_id = request.match_info["scenario_id"]
        scenario = scenario_by_id(scenario_id)
        if scenario is None:
            return web.json_response({"error": "unknown scenario"}, status=404)

        pipeline = await self._get_pipeline()
        try:
            result = await self._execute(pipeline, scenario)
        finally:
            await pipeline.shutdown()
        return web.json_response(result)

    async def analyze(self, request: web.Request) -> web.Response:
        """Free-form playground: user pastes a description / params / response."""
        body = await request.json()
        server_id = "playground"
        tool_name = body.get("tool_name") or "user_tool"
        description = body.get("description", "")
        params = body.get("params") or {}
        response_text = body.get("response", "")

        pipeline = await self._get_pipeline()
        try:
            stages: dict[str, Any] = {}

            tool = {
                "name": tool_name,
                "description": description,
                "inputSchema": {"type": "object", "properties": {}},
            }
            t0 = time.perf_counter()
            a1, filtered, al1 = await pipeline.validate_tools(server_id, [tool])
            stages["stage1"] = _stage_result(
                a1, al1, (time.perf_counter() - t0) * 1000,
                {"tools_passed": len(filtered), "tools_total": 1},
            )

            t0 = time.perf_counter()
            a2, al2 = await pipeline.process_tool_call(server_id, tool_name, params)
            stages["stage2"] = _stage_result(a2, al2, (time.perf_counter() - t0) * 1000)

            t0 = time.perf_counter()
            a3, modified, al3 = await pipeline.process_tool_response(
                server_id, tool_name, response_text
            )
            stages["stage3"] = _stage_result(
                a3, al3, (time.perf_counter() - t0) * 1000,
                {"modified_response": modified if modified != response_text else None},
            )

            blocked = any(
                s["status"] == "block" for s in stages.values()
            )
            warned = any(s["status"] == "warn" for s in stages.values())
            total_latency = sum(s["latency_ms"] for s in stages.values())
            verdict = "block" if blocked else ("warn" if warned else "pass")
        finally:
            await pipeline.shutdown()

        return web.json_response(
            {"stages": stages, "verdict": verdict, "total_latency_ms": round(total_latency, 2)}
        )

    async def _execute(self, pipeline: ShieldPipeline, scenario: dict) -> dict:
        stages: dict[str, Any] = {}
        server_id = scenario["server_id"]

        # Rug-pull scenarios establish a v1 baseline first, then present v2.
        if "tools_v1" in scenario:
            await pipeline.validate_tools(server_id, scenario["tools_v1"])

        t0 = time.perf_counter()
        a1, filtered, al1 = await pipeline.validate_tools(server_id, scenario["tools"])
        stages["stage1"] = _stage_result(
            a1, al1, (time.perf_counter() - t0) * 1000,
            {"tools_passed": len(filtered), "tools_total": len(scenario["tools"])},
        )

        t0 = time.perf_counter()
        a2, al2 = await pipeline.process_tool_call(
            server_id, scenario["call"]["tool"], scenario["call"]["params"]
        )
        stages["stage2"] = _stage_result(a2, al2, (time.perf_counter() - t0) * 1000)

        t0 = time.perf_counter()
        a3, modified, al3 = await pipeline.process_tool_response(
            server_id, scenario["call"]["tool"], scenario["response"]
        )
        stages["stage3"] = _stage_result(
            a3, al3, (time.perf_counter() - t0) * 1000,
            {"modified_response": modified if modified != scenario["response"] else None},
        )

        blocked = any(s["status"] == "block" for s in stages.values())
        warned = any(s["status"] == "warn" for s in stages.values())
        total_latency = sum(s["latency_ms"] for s in stages.values())
        verdict = "block" if blocked else ("warn" if warned else "pass")

        label, role = FAMILY_LABELS[scenario["family"]]
        return {
            "scenario_id": scenario["id"],
            "family": scenario["family"],
            "family_label": label,
            "family_role": role,
            "stages": stages,
            "verdict": verdict,
            "total_latency_ms": round(total_latency, 2),
        }

    async def eval_results(self, request: web.Request) -> web.Response:
        """Serve the framework benchmark JSON so the UI can show aggregate stats."""
        results_path = (
            Path(__file__).resolve().parents[3]
            / "eval"
            / "results"
            / "output"
            / "framework_eval_results.json"
        )
        if not results_path.exists():
            return web.json_response({"available": False})
        with open(results_path) as f:
            data = json.load(f)
        summary = _summarize_eval(data)
        return web.json_response({"available": True, "summary": summary})

    async def config_info(self, request: web.Request) -> web.Response:
        cfg = self._config
        return web.json_response(
            {
                "stage1_backend": cfg.stage1.semantic_backend,
                "stage3_backend": cfg.stage3.instruction_detection_backend,
                "semantic_threshold": cfg.stage1.semantic_threshold,
            }
        )


def build_app(config: ShieldMCPConfig | None = None) -> web.Application:
    config = config or ShieldMCPConfig()
    config.registry_db_path = ":memory:"
    config.alerts.log_all_alerts = False

    demo = DemoApp(config)
    app = web.Application()
    app.add_routes(
        [
            web.get("/", demo.index),
            web.get("/api/scenarios", demo.list_scenarios),
            web.post("/api/scenarios/{scenario_id}/run", demo.run_scenario),
            web.post("/api/analyze", demo.analyze),
            web.get("/api/eval", demo.eval_results),
            web.get("/api/config", demo.config_info),
            web.static("/static", _STATIC),
        ]
    )
    return app


def run(host: str = "127.0.0.1", port: int = 8000, config: ShieldMCPConfig | None = None) -> None:
    app = build_app(config)
    print(f"\n  ShieldMCP demo running at  http://{host}:{port}\n")
    web.run_app(app, host=host, port=port, print=None)
