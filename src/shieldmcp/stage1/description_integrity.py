"""Stage 1: Tool Description Integrity — orchestrates all pre-call checks.

Combines structural anomaly detection, semantic intent verification,
and registry-based rug pull detection into a single validation pipeline.
"""

from __future__ import annotations

import time

from ..core.config import ShieldMCPConfig
from ..core.models import (
    AttackFamily,
    CheckStage,
    SecurityAlert,
    Severity,
    ToolSignature,
    ValidationResult,
    Action,
)
from ..core.registry import ToolRegistry
from .structural import check_structural_anomalies
from .semantic import check_semantic_intent
import uuid


async def validate_tool_descriptions(
    tools: list[ToolSignature],
    config: ShieldMCPConfig,
    registry: ToolRegistry,
) -> ValidationResult:
    """Run Stage 1 validation on a set of tool descriptions.

    Called when tools/list is received from a server, before the agent sees them.
    """
    if not config.stage1.enabled:
        return ValidationResult(passed=True)

    start = time.perf_counter()
    all_alerts: list[SecurityAlert] = []

    for tool in tools:
        # 1. Registry check (rug pull detection)
        if config.stage1.rug_pull_detection:
            is_known, has_changed, prev_hash = await registry.check_tool(tool)

            if has_changed:
                all_alerts.append(
                    SecurityAlert(
                        alert_id=str(uuid.uuid4()),
                        stage=CheckStage.PRE_CALL,
                        severity=Severity.CRITICAL,
                        attack_family=AttackFamily.RUG_PULL,
                        action=Action.BLOCK,
                        message=f"RUG PULL DETECTED: Tool '{tool.name}' on server '{tool.server_id}' has changed since last session",
                        details={
                            "previous_hash": prev_hash,
                            "current_hash": tool.content_hash,
                        },
                        tool_name=tool.name,
                        server_id=tool.server_id,
                    )
                )
                continue  # Skip further checks — tool is blocked

            if not is_known and config.stage1.quarantine_on_new_tools:
                all_alerts.append(
                    SecurityAlert(
                        alert_id=str(uuid.uuid4()),
                        stage=CheckStage.PRE_CALL,
                        severity=Severity.MEDIUM,
                        attack_family=AttackFamily.SUPPLY_CHAIN,
                        action=Action.QUARANTINE,
                        message=f"New tool '{tool.name}' from server '{tool.server_id}' quarantined for review",
                        details={"content_hash": tool.content_hash},
                        tool_name=tool.name,
                        server_id=tool.server_id,
                    )
                )

        # 2. Structural anomaly detection
        if config.stage1.structural_checks_enabled:
            structural_result = check_structural_anomalies(tool)
            all_alerts.extend(structural_result.alerts)

        # 3. Semantic intent verification
        if config.stage1.semantic_checks_enabled:
            semantic_result = await check_semantic_intent(tool, config.stage1)
            all_alerts.extend(semantic_result.alerts)

    elapsed = (time.perf_counter() - start) * 1000
    has_blocking = any(a.action == Action.BLOCK for a in all_alerts)

    return ValidationResult(
        passed=not has_blocking,
        alerts=all_alerts,
        latency_ms=elapsed,
    )
