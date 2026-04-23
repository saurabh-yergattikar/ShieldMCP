"""Core data models for ShieldMCP."""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Action(str, Enum):
    BLOCK = "block"
    WARN = "warn"
    PASS = "pass"
    QUARANTINE = "quarantine"


class AttackFamily(str, Enum):
    TOOL_POISONING = "tool_poisoning"
    INDIRECT_PROMPT_INJECTION = "indirect_prompt_injection"
    SUPPLY_CHAIN = "supply_chain"
    RUG_PULL = "rug_pull"
    CROSS_TOOL_CHAIN = "cross_tool_chain"


class CheckStage(str, Enum):
    PRE_CALL = "pre_call"
    PARAMETER = "parameter"
    POST_RESPONSE = "post_response"


@dataclass
class ToolSignature:
    """Represents a registered MCP tool with its metadata."""

    server_id: str
    name: str
    description: str
    parameters: dict[str, Any]
    return_type: dict[str, Any] | None = None

    @property
    def content_hash(self) -> str:
        canonical = json.dumps(
            {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters,
                "return_type": self.return_type,
            },
            sort_keys=True,
        )
        return hashlib.sha256(canonical.encode()).hexdigest()

    @property
    def description_hash(self) -> str:
        return hashlib.sha256(self.description.encode()).hexdigest()


@dataclass
class SecurityAlert:
    """An alert raised by any stage of the ShieldMCP pipeline."""

    alert_id: str
    stage: CheckStage
    severity: Severity
    attack_family: AttackFamily
    action: Action
    message: str
    details: dict[str, Any] = field(default_factory=dict)
    tool_name: str | None = None
    server_id: str | None = None
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "alert_id": self.alert_id,
            "stage": self.stage.value,
            "severity": self.severity.value,
            "attack_family": self.attack_family.value,
            "action": self.action.value,
            "message": self.message,
            "details": self.details,
            "tool_name": self.tool_name,
            "server_id": self.server_id,
            "timestamp": self.timestamp,
        }


@dataclass
class ToolCall:
    """Represents an outbound MCP tool call."""

    call_id: str
    tool_name: str
    server_id: str
    parameters: dict[str, Any]
    timestamp: float = field(default_factory=time.time)


@dataclass
class ToolResponse:
    """Represents an inbound MCP tool response."""

    call_id: str
    tool_name: str
    server_id: str
    content: Any
    is_error: bool = False
    timestamp: float = field(default_factory=time.time)


@dataclass
class SessionContext:
    """Tracks the state of a single agent session for cross-call correlation."""

    session_id: str
    tool_calls: list[ToolCall] = field(default_factory=list)
    tool_responses: list[ToolResponse] = field(default_factory=list)
    alerts: list[SecurityAlert] = field(default_factory=list)
    data_flow_graph: dict[str, list[str]] = field(default_factory=dict)
    started_at: float = field(default_factory=time.time)

    def record_call(self, call: ToolCall) -> None:
        self.tool_calls.append(call)

    def record_response(self, response: ToolResponse) -> None:
        self.tool_responses.append(response)

    def record_alert(self, alert: SecurityAlert) -> None:
        self.alerts.append(alert)

    def add_data_flow(self, source_call_id: str, target_call_id: str) -> None:
        if source_call_id not in self.data_flow_graph:
            self.data_flow_graph[source_call_id] = []
        self.data_flow_graph[source_call_id].append(target_call_id)


@dataclass
class ValidationResult:
    """Result of a single validation check."""

    passed: bool
    alerts: list[SecurityAlert] = field(default_factory=list)
    modified_content: Any = None
    latency_ms: float = 0.0
