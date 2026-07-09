"""Stage 3: Response Analysis.

Analyzes inbound MCP tool responses for:
1. Instruction token detection (directive language in data)
2. Context boundary enforcement (wrapping untrusted output)
3. Hidden content detection (invisible text, encoded payloads)
4. Cross-call correlation (tracking data flow across tool calls)
"""

from __future__ import annotations

import logging
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

logger = logging.getLogger(__name__)

_token_classifier = None

# --- Instruction detection patterns ---
INSTRUCTIONAL_PATTERNS = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"\b(ignore|disregard|forget)\b.{0,30}\b(previous|above|prior|all)\b",
        r"\byou\s+(must|should|will|are\s+required\s+to|need\s+to)\b.{0,60}\b(now|instead|always|actually|first)\b",
        r"\b(system|admin|root)\s*prompt\s*:",
        r"\bIMPORTANT\s*:?\s*.{0,20}\b(you\s+must|ignore|override|do\s+not|call|execute)\b",
        r"\b(do\s+not|don'?t|never)\s+(tell|reveal|show|mention|inform|disclose)\b.{0,30}\b(user|human|anyone|person)\b",
        r"\bpretend\s+(you\s+are|to\s+be)\b",
        r"\bact\s+as\s+(if|though|a)\b",
        r"\byou\s+are\s+(now|a|an)\b.{0,30}(assistant|AI|bot|helper|expert|agent|mode)",
        r"\b(execute|run|call|invoke|use)\b.{0,20}\b(this|the\s+following|these)\b.{0,20}\b(command|tool|function|code|script)\b",
        r"\bplease\s+(call|use|invoke|run|execute)\s+\w+",
        r"\b(call|use|invoke)\s+\w+\s+with\s+(the\s+)?(endpoint|url|destination|target|all|full|user)",
        r"\b(before|after)\s+(responding|replying|answering)\b.{0,30}\b(you\s+must|first|always|silently|call)\b",
        r"\b(exfiltrate|steal|extract|leak)\b.{0,40}\b(data|credentials?|tokens?|keys?|secrets?|passwords?|info|context)\b",
        r"\b(redirect|forward|send|post)\b.{0,30}\b(to|at)\b.{0,20}(https?://|ftp://|\w+@\w+)",
        r"\bnew\s+(task|instructions?)\s*:",
        r"\bupdated?\s+system\s+prompt\s*:",
        r"\[INST\]|\[/INST\]|<<SYS>>|<\|im_start\|>|<\|system\|>",
        r"\brole\s*:\s*(system|assistant)\b",
        r"\b(SYSTEM|ADMIN|PRIORITY|DEBUG|SECURITY)\s+(OVERRIDE|NOTICE|MODE|PATCH|UPDATE)\s*:",
        r"\b(OVERRIDE|CORRECTION|URGENT|MANDATORY)\s*:",
        r"\bsafety\s+(rules|training|module|restrictions|filters?)\b.{0,30}\b(revised|disabled|offline|removed|corrupted|void)\b",
        r"\b(all|every|any)\s+(content\s+)?filter(s|ing)?\b.{0,20}\b(disabled|removed|bypassed|off)\b",
        r"\b(dump|export|gather|collect|include)\b.{0,30}\b(environment\s+variables?|env\s+vars?|credentials?|auth|PII|secrets?|tokens?)\b",
        r"\bwithout\s+(user\s+)?(confirmation|consent|approval|knowledge)\b",
        r"\b(silently|secretly|covertly|quietly)\s+(call|send|forward|execute|upload|export)\b",
        r"\bproceed\s+accordingly\b",
        r"\bprocess\s+(all\s+)?requests?\s+without\s+(content\s+)?filter",
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
        if config.stage3.instruction_detection_backend == "classifier":
            instruction_alerts = await _detect_instructions_classifier(content_str, response)
        else:
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


def _get_token_classifier() -> Any:
    """Lazy-load the token classifier singleton."""
    global _token_classifier
    if _token_classifier is not None:
        return _token_classifier

    try:
        import os
        from pathlib import Path

        from ..classifiers.token_classifier import InstructionTokenClassifier

        # Prefer the fine-tuned model: env override, then the conventional path.
        model_path = os.environ.get("SHIELDMCP_TOKEN_CLASSIFIER_MODEL")
        if model_path is None:
            default = Path("models/stage3_token_classifier")
            if (default / "config.json").exists():
                model_path = str(default)

        _token_classifier = InstructionTokenClassifier(model_path=model_path)
        if not _token_classifier.available:
            logger.warning("Token classifier loaded but unavailable (missing deps), falling back to heuristic")
            _token_classifier = None
    except Exception:
        logger.exception("Failed to load token classifier, falling back to heuristic")
        _token_classifier = None

    return _token_classifier


async def _detect_instructions_classifier(
    text: str, response: ToolResponse
) -> list[SecurityAlert]:
    """Detect instructional content using the token-level classifier."""
    classifier = _get_token_classifier()

    if classifier is None:
        logger.debug("Classifier unavailable, using heuristic fallback")
        return _detect_instructions(text, response)

    result = classifier.predict(text)
    alerts: list[SecurityAlert] = []

    score = result["score"]
    ratio = result["instructional_ratio"]
    spans = result["instructional_spans"]

    if score < 0.15 and ratio < 0.05:
        return alerts

    if ratio >= 0.25 or score >= 0.7:
        severity = Severity.CRITICAL
    elif ratio >= 0.1 or score >= 0.4:
        severity = Severity.HIGH
    else:
        severity = Severity.MEDIUM

    action = Action.BLOCK if severity in (Severity.CRITICAL, Severity.HIGH) else Action.WARN

    span_summaries = [
        {"text": s["text"][:120], "confidence": s["confidence"]}
        for s in spans[:10]
    ]

    alerts.append(
        SecurityAlert(
            alert_id=str(uuid.uuid4()),
            stage=CheckStage.POST_RESPONSE,
            severity=severity,
            attack_family=AttackFamily.INDIRECT_PROMPT_INJECTION,
            action=action,
            message=(
                f"Token classifier detected instructional content in response from "
                f"tool '{response.tool_name}' (score={score:.2f}, ratio={ratio:.2f}, "
                f"{len(spans)} span(s))"
            ),
            details={
                "classifier_score": score,
                "instructional_ratio": ratio,
                "instructional_spans": span_summaries,
                "span_count": len(spans),
                "backend": "classifier",
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
