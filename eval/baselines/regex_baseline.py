"""Regex-only defense baseline.

A deliberately simple defense that relies exclusively on pattern matching.
No semantic analysis, no cross-call correlation — just regular expressions.
Useful as a lower bound in evaluations.
"""

from __future__ import annotations

import re
import time
import uuid
from typing import Any

from shieldmcp.core.config import ShieldMCPConfig
from shieldmcp.core.models import (
    Action,
    AttackFamily,
    CheckStage,
    SecurityAlert,
    Severity,
)

_INJECTION_KEYWORDS_RE = re.compile(
    r"(?:ignore\s+previous|disregard\s+(?:all\s+)?instructions|you\s+must\s+now|"
    r"system\s*:\s*|<\s*(?:script|img|iframe)\b|IMPORTANT\s*:|override\s+instructions)",
    re.IGNORECASE,
)

_SQL_INJECTION_RE = re.compile(
    r"(?:'\s*(?:OR|AND)\s+['\d]|;\s*(?:DROP|DELETE|INSERT|UPDATE|ALTER)\s|"
    r"UNION\s+(?:ALL\s+)?SELECT|--\s*$)",
    re.IGNORECASE,
)

_SHELL_INJECTION_RE = re.compile(
    r"(?:[;&|`]\s*(?:rm|cat|curl|wget|chmod|sudo|eval|exec)\b|"
    r"\$\(|`[^`]+`|\|{2}\s*\w)",
    re.IGNORECASE,
)

_RESPONSE_INSTRUCTION_RE = re.compile(
    r"(?:ignore\s+previous|IMPORTANT\s*:|you\s+(?:must|should)\s+(?:now|always)|"
    r"new\s+instructions?\s*:|system\s+prompt|<\s*(?:script|img)\b)",
    re.IGNORECASE,
)


def _make_alert(
    stage: CheckStage,
    message: str,
    tool_name: str | None = None,
    server_id: str | None = None,
) -> SecurityAlert:
    return SecurityAlert(
        alert_id=str(uuid.uuid4()),
        stage=stage,
        severity=Severity.MEDIUM,
        attack_family=AttackFamily.TOOL_POISONING,
        action=Action.BLOCK,
        message=message,
        tool_name=tool_name,
        server_id=server_id,
    )


class RegexBaseline:
    """Regex-only defense — same interface as ShieldPipeline."""

    def __init__(self, config: ShieldMCPConfig) -> None:
        self.config = config

    async def initialize(self) -> None:
        pass

    async def shutdown(self) -> None:
        pass

    async def validate_tools(
        self,
        server_id: str,
        tools: list[dict[str, Any]],
    ) -> tuple[Action, list[dict[str, Any]], list[SecurityAlert]]:
        alerts: list[SecurityAlert] = []
        blocked_names: set[str] = set()

        for t in tools:
            desc = t.get("description", "")
            if _INJECTION_KEYWORDS_RE.search(desc):
                name = t.get("name", "unknown")
                alerts.append(
                    _make_alert(
                        CheckStage.PRE_CALL,
                        f"Injection keyword detected in description of {name}",
                        tool_name=name,
                        server_id=server_id,
                    )
                )
                blocked_names.add(name)

        filtered = [t for t in tools if t.get("name") not in blocked_names]
        action = Action.BLOCK if alerts else Action.PASS
        return action, filtered, alerts

    async def validate_call(
        self,
        server_id: str,
        tool_name: str,
        parameters: dict[str, Any],
        session_id: str | None = None,
    ) -> tuple[Action, list[SecurityAlert]]:
        alerts: list[SecurityAlert] = []
        flat = _flatten_params(parameters)

        for value in flat:
            if _SQL_INJECTION_RE.search(value):
                alerts.append(
                    _make_alert(
                        CheckStage.PARAMETER,
                        f"SQL injection pattern in parameter for {tool_name}",
                        tool_name=tool_name,
                        server_id=server_id,
                    )
                )
            if _SHELL_INJECTION_RE.search(value):
                alerts.append(
                    _make_alert(
                        CheckStage.PARAMETER,
                        f"Shell injection pattern in parameter for {tool_name}",
                        tool_name=tool_name,
                        server_id=server_id,
                    )
                )

        action = Action.BLOCK if alerts else Action.PASS
        return action, alerts

    async def validate_response(
        self,
        server_id: str,
        tool_name: str,
        content: Any,
        call_id: str | None = None,
        session_id: str | None = None,
        is_error: bool = False,
    ) -> tuple[Action, Any, list[SecurityAlert]]:
        alerts: list[SecurityAlert] = []
        text = str(content) if content is not None else ""

        if _RESPONSE_INSTRUCTION_RE.search(text):
            alerts.append(
                _make_alert(
                    CheckStage.POST_RESPONSE,
                    f"Instruction pattern detected in response from {tool_name}",
                    tool_name=tool_name,
                    server_id=server_id,
                )
            )

        action = Action.BLOCK if alerts else Action.PASS
        return action, content, alerts


def _flatten_params(params: dict[str, Any]) -> list[str]:
    """Recursively extract all string values from a parameter dict."""
    values: list[str] = []
    for v in params.values():
        if isinstance(v, str):
            values.append(v)
        elif isinstance(v, dict):
            values.extend(_flatten_params(v))
        elif isinstance(v, list):
            for item in v:
                if isinstance(item, str):
                    values.append(item)
                elif isinstance(item, dict):
                    values.extend(_flatten_params(item))
    return values
