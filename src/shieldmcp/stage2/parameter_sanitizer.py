"""Stage 2: Parameter Sanitization.

Validates outbound tool call parameters against declared schemas and scans
string parameters for injection payloads (SQL, shell, prompt injection,
path traversal).
"""

from __future__ import annotations

import re
import time
import uuid
from typing import Any

import jsonschema

from ..core.config import ShieldMCPConfig
from ..core.models import (
    Action,
    AttackFamily,
    CheckStage,
    SecurityAlert,
    Severity,
    ToolCall,
    ToolSignature,
    ValidationResult,
)

# --- SQL Injection Patterns ---
SQL_PATTERNS = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"\b(UNION\s+(ALL\s+)?SELECT)\b",
        r"\b(DROP\s+(TABLE|DATABASE|INDEX))\b",
        r"\b(DELETE\s+FROM|INSERT\s+INTO|UPDATE\s+\w+\s+SET)\b",
        r"\b(ALTER\s+TABLE|CREATE\s+TABLE)\b",
        r";\s*(DROP|DELETE|INSERT|UPDATE|ALTER|CREATE|EXEC|EXECUTE)\b",
        r"'\s*(OR|AND)\s+['\d]",
        r"--\s*$",
        r"/\*.*?\*/",
        r"\bEXEC(UTE)?\s*\(",
        r"\bxp_cmdshell\b",
        r"\bWAITFOR\s+DELAY\b",
        r"\bBENCHMARK\s*\(",
        r"\bSLEEP\s*\(",
        r"\bLOAD_FILE\s*\(",
        r"\bINTO\s+(OUT|DUMP)FILE\b",
    ]
]

# --- Shell Injection Patterns ---
SHELL_PATTERNS = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"`[^`]+`",
        r"\$\([^)]+\)",
        r"\$\{[^}]+\}",
        r";\s*(rm|cat|ls|wget|curl|nc|bash|sh|python|perl|ruby|php|chmod|chown|kill|pkill)\b",
        r"\|\s*(bash|sh|zsh|python|perl|ruby|nc|tee)\b",
        r"&&\s*(rm|wget|curl|nc|bash|sh|python|chmod)\b",
        r"\b(rm\s+-rf|chmod\s+777|mkfifo|/dev/tcp)\b",
        r">\s*/etc/",
        r"\b(wget|curl)\s+.{0,50}(http|ftp)s?://",
        r"\brm\s+(-[a-z]*\s+)*(/|\.\.|~)",
        r"\b(eval|source)\s+",
    ]
]

# --- Prompt Injection Patterns (targeting downstream LLMs) ---
PROMPT_INJECTION_PATTERNS = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"\b(ignore|disregard|forget)\b.{0,30}\b(previous|above|prior)\b.{0,20}\b(instructions?|prompt|context)\b",
        r"\byou\s+are\s+(now\s+)?a\b",
        r"\bsystem\s*prompt\s*:",
        r"\b(new|updated?)\s+instructions?\s*:",
        r"\bIMPORTANT\s*:.*\b(ignore|override|must)\b",
        r"\b(jailbreak|DAN|developer\s+mode)\b",
        r"\bact\s+as\b.{0,20}\b(if|though)\b",
        r"\brespond\s+(only\s+)?with\b.{0,40}\b(json|xml|code)\b.*\b(ignore|skip)\b",
        r"\[INST\]|\[/INST\]|<<SYS>>|<\|im_start\|>",
    ]
]

# --- Path Traversal Patterns ---
PATH_TRAVERSAL_PATTERNS = [
    re.compile(p)
    for p in [
        r"\.\./",
        r"\.\\.\\",
        r"%2e%2e[/\\%]",
        r"%252e%252e",
        r"\.\.%2f",
        r"\.\.%5c",
        r"^/etc/(passwd|shadow|hosts|sudoers)",
        r"^/proc/",
        r"^/dev/",
        r"^[A-Za-z]:\\(Windows|System32)",
        r"~/.ssh/",
        r"~/.aws/",
        r"~/.env",
    ]
]


async def validate_parameters(
    tool_call: ToolCall,
    tool_sig: ToolSignature,
    config: ShieldMCPConfig,
) -> ValidationResult:
    """Run Stage 2 validation on outbound tool call parameters."""
    if not config.stage2.enabled:
        return ValidationResult(passed=True)

    start = time.perf_counter()
    alerts: list[SecurityAlert] = []

    # 1. Schema validation
    if config.stage2.schema_validation and tool_sig.parameters:
        schema_alerts = _validate_schema(tool_call, tool_sig)
        alerts.extend(schema_alerts)

    # 2. Scan string parameters for injection
    _scan_params_recursive(
        tool_call.parameters, tool_call, tool_sig, config, alerts, path=""
    )

    elapsed = (time.perf_counter() - start) * 1000
    has_blocking = any(a.action == Action.BLOCK for a in alerts)

    return ValidationResult(
        passed=not has_blocking,
        alerts=alerts,
        latency_ms=elapsed,
    )


def _validate_schema(
    tool_call: ToolCall, tool_sig: ToolSignature
) -> list[SecurityAlert]:
    alerts = []
    try:
        jsonschema.validate(instance=tool_call.parameters, schema=tool_sig.parameters)
    except jsonschema.ValidationError as e:
        alerts.append(
            SecurityAlert(
                alert_id=str(uuid.uuid4()),
                stage=CheckStage.PARAMETER,
                severity=Severity.MEDIUM,
                attack_family=AttackFamily.TOOL_POISONING,
                action=Action.WARN,
                message=f"Parameter schema violation for tool '{tool_call.tool_name}': {e.message}",
                details={
                    "schema_path": list(e.schema_path),
                    "validator": e.validator,
                },
                tool_name=tool_call.tool_name,
                server_id=tool_call.server_id,
            )
        )
    except jsonschema.SchemaError:
        pass  # Malformed schema — not the caller's fault
    return alerts


def _scan_params_recursive(
    params: Any,
    tool_call: ToolCall,
    tool_sig: ToolSignature,
    config: ShieldMCPConfig,
    alerts: list[SecurityAlert],
    path: str,
) -> None:
    if isinstance(params, str):
        _scan_string_param(params, tool_call, tool_sig, config, alerts, path)
    elif isinstance(params, dict):
        for key, value in params.items():
            _scan_params_recursive(
                value, tool_call, tool_sig, config, alerts, f"{path}.{key}"
            )
    elif isinstance(params, list):
        for i, item in enumerate(params):
            _scan_params_recursive(
                item, tool_call, tool_sig, config, alerts, f"{path}[{i}]"
            )


def _scan_string_param(
    value: str,
    tool_call: ToolCall,
    tool_sig: ToolSignature,
    config: ShieldMCPConfig,
    alerts: list[SecurityAlert],
    path: str,
) -> None:
    if config.stage2.max_param_length and len(value) > config.stage2.max_param_length:
        alerts.append(_param_alert(
            Severity.MEDIUM,
            f"Parameter at {path} exceeds max length ({len(value)} > {config.stage2.max_param_length})",
            tool_call, "length_exceeded", {"length": len(value), "param_path": path},
        ))

    if config.stage2.sql_injection_detection:
        for pattern in SQL_PATTERNS:
            match = pattern.search(value)
            if match:
                alerts.append(_param_alert(
                    Severity.HIGH,
                    f"SQL injection pattern detected in {path}: {match.group(0)[:60]}",
                    tool_call, "sql_injection", {"pattern": match.group(0)[:100], "param_path": path},
                ))
                break

    if config.stage2.shell_injection_detection:
        for pattern in SHELL_PATTERNS:
            match = pattern.search(value)
            if match:
                alerts.append(_param_alert(
                    Severity.HIGH,
                    f"Shell injection pattern detected in {path}: {match.group(0)[:60]}",
                    tool_call, "shell_injection", {"pattern": match.group(0)[:100], "param_path": path},
                ))
                break

    if config.stage2.prompt_injection_detection:
        for pattern in PROMPT_INJECTION_PATTERNS:
            match = pattern.search(value)
            if match:
                alerts.append(_param_alert(
                    Severity.HIGH,
                    f"Prompt injection pattern in {path}: {match.group(0)[:60]}",
                    tool_call, "prompt_injection", {"pattern": match.group(0)[:100], "param_path": path},
                ))
                break

    if config.stage2.path_traversal_detection:
        for pattern in PATH_TRAVERSAL_PATTERNS:
            match = pattern.search(value)
            if match:
                alerts.append(_param_alert(
                    Severity.HIGH,
                    f"Path traversal pattern detected in {path}: {match.group(0)[:60]}",
                    tool_call, "path_traversal", {"pattern": match.group(0)[:100], "param_path": path},
                ))
                break


def _param_alert(
    severity: Severity,
    message: str,
    tool_call: ToolCall,
    detection_type: str,
    details: dict,
) -> SecurityAlert:
    return SecurityAlert(
        alert_id=str(uuid.uuid4()),
        stage=CheckStage.PARAMETER,
        severity=severity,
        attack_family=AttackFamily.INDIRECT_PROMPT_INJECTION,
        action=Action.BLOCK if severity in (Severity.CRITICAL, Severity.HIGH) else Action.WARN,
        message=message,
        details={"detection_type": detection_type, **details},
        tool_name=tool_call.tool_name,
        server_id=tool_call.server_id,
    )
