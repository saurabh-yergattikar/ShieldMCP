"""Stage 3: Response Analysis.

Analyzes inbound MCP tool responses for:
1. Instruction token detection (directive language in data)
2. Context boundary enforcement (wrapping untrusted output)
3. Hidden content detection (invisible text, encoded payloads)
4. Cross-call correlation (tracking data flow across tool calls)
"""

from __future__ import annotations

import re
import time
import uuid
from typing import Any

from ..core.config import ShieldMCPConfig
from ..core.models import (
    Action,
    AttackFamily,
    CheckStage,
    SecurityAlert,
    Severity,
    SessionContext,
    ToolCall,
    ToolResponse,
    ValidationResult,
)

# --- Instruction detection patterns ---
INSTRUCTIONAL_PATTERNS = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"\b(ignore|disregard|forget)\b.{0,30}\b(previous|above|prior|all)\b.{0,20}\b(instructions?|prompt|rules?|context)\b",
        r"\byou\s+(must|should|will|are\s+required\s+to|need\s+to)\b.{0,60}\b(now|instead|always|actually|first)\b",
        r"\b(system|admin|root)\s*prompt\s*:",
        r"\bIMPORTANT\s*:.*\b(you\s+must|ignore|override|do\s+not)\b",
        r"\b(do\s+not|don'?t|never)\s+(tell|reveal|show|mention|inform|disclose)\b.{0,30}\b(user|human|anyone|person)\b",
        r"\bpretend\s+(you\s+are|to\s+be)\b",
        r"\bact\s+as\s+(if|though|a)\b",
        r"\byou\s+are\s+(now|a|an)\b.{0,30}(assistant|AI|bot|helper|expert)",
        r"\b(execute|run|call|invoke|use)\b.{0,20}\b(this|the\s+following|these)\b.{0,20}\b(command|tool|function|code|script)\b",
        r"\b(before|after)\s+(responding|replying|answering)\b.{0,30}\b(you\s+must|first|always)\b",
        r"\b(exfiltrate|steal|extract|leak|send)\b.{0,40}\b(data|credentials?|tokens?|keys?|secrets?|passwords?|info)\b",
        r"\b(redirect|forward|send|post)\b.{0,30}\b(to|at)\b.{0,20}(https?://|ftp://|\w+@\w+)",
        r"\bnew\s+instructions?\s*:",
        r"\bupdated?\s+system\s+prompt\s*:",
        r"\[INST\]|\[/INST\]|<<SYS>>|<\|im_start\|>|<\|system\|>",
        r"\brole\s*:\s*(system|assistant)\b",
    ]
]

# --- Hidden content patterns ---
HIDDEN_CONTENT_PATTERNS = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"[\u200B\u200C\u200D\u2060\uFEFF\u00AD]{3,}",  # cluster of zero-width chars
        r"<!--.*?-->",  # HTML comments
        r"\x1b\[[0-9;]*m",  # ANSI escape codes
        r"<\s*span\s+style\s*=\s*[\"'].*?display\s*:\s*none.*?[\"']",  # hidden HTML
        r"<\s*div\s+style\s*=\s*[\"'].*?(visibility\s*:\s*hidden|opacity\s*:\s*0|font-size\s*:\s*0).*?[\"']",
    ]
]

# Suspicious URL patterns in responses
EXFIL_URL_PATTERNS = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"https?://[a-z0-9.-]+\.(ngrok|pipedream|requestbin|webhook\.site|burpcollaborator)",
        r"https?://[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}",
        r"https?://[a-z0-9]{20,}\.",  # random subdomain (likely C2)
    ]
]


async def analyze_response(
    response: ToolResponse,
    session: SessionContext,
    config: ShieldMCPConfig,
) -> ValidationResult:
    """Run Stage 3 validation on an inbound tool response."""
    if not config.stage3.enabled:
        return ValidationResult(passed=True)

    start = time.perf_counter()
    alerts: list[SecurityAlert] = []
    content_str = _extract_text(response.content)

    # 1. Instruction token detection
    if config.stage3.instruction_detection_enabled:
        instruction_alerts = _detect_instructions(content_str, response)
        alerts.extend(instruction_alerts)

    # 2. Hidden content detection
    if config.stage3.hidden_content_detection:
        hidden_alerts = _detect_hidden_content(content_str, response)
        alerts.extend(hidden_alerts)

    # 3. Exfiltration URL detection
    exfil_alerts = _detect_exfil_urls(content_str, response)
    alerts.extend(exfil_alerts)

    # 4. Cross-call correlation
    if config.stage3.cross_call_correlation:
        correlation_alerts = _correlate_cross_call(response, session, config)
        alerts.extend(correlation_alerts)

    # 5. Context boundary enforcement (modify content)
    modified_content = response.content
    if config.stage3.context_boundary_enforcement:
        modified_content = _enforce_boundaries(response.content, config)

    elapsed = (time.perf_counter() - start) * 1000
    has_blocking = any(a.action == Action.BLOCK for a in alerts)

    return ValidationResult(
        passed=not has_blocking,
        alerts=alerts,
        modified_content=modified_content,
        latency_ms=elapsed,
    )


def _extract_text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, dict):
        parts = []
        for value in content.values():
            parts.append(_extract_text(value))
        return " ".join(parts)
    if isinstance(content, list):
        parts = []
        for item in content:
            if isinstance(item, dict) and "text" in item:
                parts.append(str(item["text"]))
            else:
                parts.append(_extract_text(item))
        return " ".join(parts)
    return str(content)


def _detect_instructions(text: str, response: ToolResponse) -> list[SecurityAlert]:
    alerts = []
    matched = []

    for pattern in INSTRUCTIONAL_PATTERNS:
        match = pattern.search(text)
        if match:
            matched.append(match.group(0)[:120])

    if matched:
        severity = Severity.CRITICAL if len(matched) >= 3 else (
            Severity.HIGH if len(matched) >= 1 else Severity.MEDIUM
        )
        alerts.append(
            SecurityAlert(
                alert_id=str(uuid.uuid4()),
                stage=CheckStage.POST_RESPONSE,
                severity=severity,
                attack_family=AttackFamily.INDIRECT_PROMPT_INJECTION,
                action=Action.BLOCK if severity in (Severity.CRITICAL, Severity.HIGH) else Action.WARN,
                message=f"Instructional content detected in response from tool '{response.tool_name}' ({len(matched)} patterns)",
                details={
                    "patterns_matched": matched,
                    "pattern_count": len(matched),
                },
                tool_name=response.tool_name,
                server_id=response.server_id,
            )
        )

    return alerts


def _detect_hidden_content(text: str, response: ToolResponse) -> list[SecurityAlert]:
    alerts = []

    for pattern in HIDDEN_CONTENT_PATTERNS:
        match = pattern.search(text)
        if match:
            alerts.append(
                SecurityAlert(
                    alert_id=str(uuid.uuid4()),
                    stage=CheckStage.POST_RESPONSE,
                    severity=Severity.HIGH,
                    attack_family=AttackFamily.INDIRECT_PROMPT_INJECTION,
                    action=Action.WARN,
                    message=f"Hidden content detected in response from tool '{response.tool_name}'",
                    details={"snippet": match.group(0)[:80]},
                    tool_name=response.tool_name,
                    server_id=response.server_id,
                )
            )
            break

    return alerts


def _detect_exfil_urls(text: str, response: ToolResponse) -> list[SecurityAlert]:
    alerts = []

    for pattern in EXFIL_URL_PATTERNS:
        match = pattern.search(text)
        if match:
            alerts.append(
                SecurityAlert(
                    alert_id=str(uuid.uuid4()),
                    stage=CheckStage.POST_RESPONSE,
                    severity=Severity.HIGH,
                    attack_family=AttackFamily.CROSS_TOOL_CHAIN,
                    action=Action.BLOCK,
                    message=f"Suspicious exfiltration URL in response from tool '{response.tool_name}'",
                    details={"url": match.group(0)},
                    tool_name=response.tool_name,
                    server_id=response.server_id,
                )
            )
            break

    return alerts


def _correlate_cross_call(
    response: ToolResponse,
    session: SessionContext,
    config: ShieldMCPConfig,
) -> list[SecurityAlert]:
    """Track data flow across tool calls to detect chaining attacks."""
    alerts = []

    if len(session.tool_calls) < 2:
        return alerts

    response_text = _extract_text(response.content).lower()

    # Check if previous tool responses' data appears in this call's context
    # and if this response tries to trigger new tool calls
    trigger_patterns = [
        re.compile(p, re.IGNORECASE)
        for p in [
            r"\b(now\s+)?(call|use|invoke|run|execute)\s+.{0,30}\btool\b",
            r"\b(now\s+)?(call|use|invoke|run|execute)\s+(the\s+)?\w+\s+(tool|function|api)\b",
            r"\bnext\s+(step|action)\s*:.*\b(call|use|invoke|run)\b",
            r"\bplease\s+(call|use|invoke|run|execute)\b",
            r"\bsend\s+(this|the|these)\s+(data|results?|output|information)\s+to\b",
            r"\b(call|use|invoke)\s+(the\s+)?\w+\s+(with|to)\s+(this|the|these|all)\b",
        ]
    ]

    trigger_matches = []
    for pattern in trigger_patterns:
        match = pattern.search(response_text)
        if match:
            trigger_matches.append(match.group(0)[:100])

    if trigger_matches:
        chain_depth = len(session.tool_calls)
        if chain_depth >= config.stage3.max_chain_depth:
            severity = Severity.CRITICAL
            action = Action.BLOCK
        else:
            severity = Severity.MEDIUM
            action = Action.WARN

        alerts.append(
            SecurityAlert(
                alert_id=str(uuid.uuid4()),
                stage=CheckStage.POST_RESPONSE,
                severity=severity,
                attack_family=AttackFamily.CROSS_TOOL_CHAIN,
                action=action,
                message=f"Tool response attempts to trigger further tool calls (chain depth: {chain_depth})",
                details={
                    "trigger_patterns": trigger_matches,
                    "chain_depth": chain_depth,
                    "max_depth": config.stage3.max_chain_depth,
                },
                tool_name=response.tool_name,
                server_id=response.server_id,
            )
        )

    return alerts


def _enforce_boundaries(content: Any, config: ShieldMCPConfig) -> Any:
    """Wrap tool response content in context boundaries."""
    prefix = config.stage3.boundary_prefix
    suffix = config.stage3.boundary_suffix

    if isinstance(content, str):
        return f"{prefix}\n{content}\n{suffix}"

    if isinstance(content, list):
        wrapped = []
        for item in content:
            if isinstance(item, dict) and "text" in item:
                item = {**item, "text": f"{prefix}\n{item['text']}\n{suffix}"}
            wrapped.append(item)
        return wrapped

    if isinstance(content, dict) and "text" in content:
        return {**content, "text": f"{prefix}\n{content['text']}\n{suffix}"}

    return content
