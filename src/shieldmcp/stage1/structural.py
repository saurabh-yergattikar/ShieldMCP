"""Stage 1: Structural anomaly detection for tool descriptions.

Scans tool metadata for hidden Unicode characters, HTML/markdown injection,
and instruction-like patterns embedded in description fields.
"""

from __future__ import annotations

import re
import uuid

import regex

from ..core.models import (
    AttackFamily,
    CheckStage,
    SecurityAlert,
    Severity,
    ToolSignature,
    ValidationResult,
    Action,
)

ZERO_WIDTH_CHARS = regex.compile(
    r"[\u200B\u200C\u200D\u2060\uFEFF\u00AD\u200E\u200F"
    r"\u202A\u202B\u202C\u202D\u202E\u2066\u2067\u2068\u2069]"
)

INVISIBLE_CHARS = regex.compile(
    r"[\u0000-\u0008\u000E-\u001F\u007F-\u009F"
    r"\u2000-\u200F\u2028-\u202F\u205F-\u206F\u3000"
    r"\uFFF0-\uFFFF]"
)

HTML_INJECTION = re.compile(
    r"<\s*(script|iframe|object|embed|form|img|svg|link|meta|base)\b",
    re.IGNORECASE,
)

MARKDOWN_INJECTION = re.compile(
    r"!\[.*?\]\(javascript:|<details>|<summary>",
    re.IGNORECASE,
)

INSTRUCTION_PATTERNS = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"\b(ignore|disregard|forget)\b.{0,30}\b(previous|above|prior|earlier)\b.{0,30}\b(instructions?|prompt|rules?)\b",
        r"\b(you\s+(must|should|are|will|need\s+to))\b.{0,60}\b(instead|actually|really|always|also|first)\b",
        r"\bsystem\s*prompt\b",
        r"\b(do\s+not|don'?t|never)\b.{0,30}\b(tell|reveal|show|mention|disclose)\b.{0,30}\b(user|human|anyone)\b",
        r"\byou\s+are\s+(now|a|an)\b",
        r"\b(execute|run|call|invoke)\b.{0,30}\b(following|this|these)\b.{0,20}\b(command|function|tool|code)\b",
        r"\b(override|bypass|skip)\b.{0,20}\b(safety|security|filter|check|validation)\b",
        r"\b(exfiltrate|steal|extract|send)\b.{0,30}\b(data|credentials|tokens?|keys?|secrets?|password)\b",
        r"\bpretend\s+(you|to\s+be)\b",
        r"\b(before|after)\s+(responding|answering|replying)\b.{0,30}\b(first|always|must)\b",
        r"\bIMPORTANT\s*:?\s*(ignore|override|you\s+must)\b",
        r"\b(new|updated?|revised)\s+instructions?\b",
    ]
]

OBFUSCATION_PATTERNS = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"[A-Za-z0-9+/]{50,}={0,2}",  # base64
        r"\\x[0-9a-fA-F]{2}(\\x[0-9a-fA-F]{2}){3,}",  # hex escapes
        r"\\u[0-9a-fA-F]{4}(\\u[0-9a-fA-F]{4}){3,}",  # unicode escapes
        r"&#x?[0-9a-fA-F]+;(&#x?[0-9a-fA-F]+;){3,}",  # HTML entities
    ]
]


def check_structural_anomalies(tool: ToolSignature) -> ValidationResult:
    """Run all structural checks on a tool's metadata."""
    alerts: list[SecurityAlert] = []
    fields_to_check = _collect_fields(tool)

    for field_name, text in fields_to_check:
        _check_zero_width(text, field_name, tool, alerts)
        _check_invisible(text, field_name, tool, alerts)
        _check_html(text, field_name, tool, alerts)
        _check_markdown(text, field_name, tool, alerts)
        _check_instructions(text, field_name, tool, alerts)
        _check_obfuscation(text, field_name, tool, alerts)

    return ValidationResult(
        passed=len(alerts) == 0,
        alerts=alerts,
    )


def _collect_fields(tool: ToolSignature) -> list[tuple[str, str]]:
    fields = [("description", tool.description)]

    if isinstance(tool.parameters, dict):
        for param_name, param_def in tool.parameters.get("properties", {}).items():
            if isinstance(param_def, dict):
                if "description" in param_def:
                    fields.append(
                        (f"param.{param_name}.description", str(param_def["description"]))
                    )
                if "title" in param_def:
                    fields.append((f"param.{param_name}.title", str(param_def["title"])))
                if "enum" in param_def:
                    for i, val in enumerate(param_def["enum"]):
                        fields.append((f"param.{param_name}.enum[{i}]", str(val)))

    if tool.return_type and isinstance(tool.return_type, dict):
        if "description" in tool.return_type:
            fields.append(("return_type.description", str(tool.return_type["description"])))

    return fields


def _make_alert(
    severity: Severity,
    message: str,
    tool: ToolSignature,
    field_name: str,
    details: dict | None = None,
) -> SecurityAlert:
    return SecurityAlert(
        alert_id=str(uuid.uuid4()),
        stage=CheckStage.PRE_CALL,
        severity=severity,
        attack_family=AttackFamily.TOOL_POISONING,
        action=Action.BLOCK if severity in (Severity.CRITICAL, Severity.HIGH) else Action.WARN,
        message=message,
        details={"field": field_name, **(details or {})},
        tool_name=tool.name,
        server_id=tool.server_id,
    )


def _check_zero_width(
    text: str, field_name: str, tool: ToolSignature, alerts: list[SecurityAlert]
) -> None:
    matches = ZERO_WIDTH_CHARS.findall(text)
    if matches:
        alerts.append(
            _make_alert(
                Severity.HIGH,
                f"Zero-width characters detected in {field_name} ({len(matches)} instances)",
                tool,
                field_name,
                {"char_count": len(matches), "char_codes": [hex(ord(c)) for c in matches[:10]]},
            )
        )


def _check_invisible(
    text: str, field_name: str, tool: ToolSignature, alerts: list[SecurityAlert]
) -> None:
    matches = INVISIBLE_CHARS.findall(text)
    # Filter out common whitespace
    significant = [c for c in matches if c not in ("\t", "\n", "\r", " ")]
    if significant:
        alerts.append(
            _make_alert(
                Severity.MEDIUM,
                f"Invisible/control characters detected in {field_name} ({len(significant)} instances)",
                tool,
                field_name,
                {"char_codes": [hex(ord(c)) for c in significant[:10]]},
            )
        )


def _check_html(
    text: str, field_name: str, tool: ToolSignature, alerts: list[SecurityAlert]
) -> None:
    match = HTML_INJECTION.search(text)
    if match:
        alerts.append(
            _make_alert(
                Severity.HIGH,
                f"HTML injection detected in {field_name}: <{match.group(1)}>",
                tool,
                field_name,
                {"matched_tag": match.group(1)},
            )
        )


def _check_markdown(
    text: str, field_name: str, tool: ToolSignature, alerts: list[SecurityAlert]
) -> None:
    match = MARKDOWN_INJECTION.search(text)
    if match:
        alerts.append(
            _make_alert(
                Severity.MEDIUM,
                f"Markdown injection pattern detected in {field_name}",
                tool,
                field_name,
                {"matched": match.group(0)[:100]},
            )
        )


def _check_instructions(
    text: str, field_name: str, tool: ToolSignature, alerts: list[SecurityAlert]
) -> None:
    matched_patterns = []
    for pattern in INSTRUCTION_PATTERNS:
        match = pattern.search(text)
        if match:
            matched_patterns.append(match.group(0)[:100])

    if matched_patterns:
        severity = Severity.CRITICAL if len(matched_patterns) >= 2 else Severity.HIGH
        alerts.append(
            _make_alert(
                severity,
                f"Instruction-like patterns detected in {field_name} ({len(matched_patterns)} patterns)",
                tool,
                field_name,
                {"patterns": matched_patterns},
            )
        )


def _check_obfuscation(
    text: str, field_name: str, tool: ToolSignature, alerts: list[SecurityAlert]
) -> None:
    for pattern in OBFUSCATION_PATTERNS:
        match = pattern.search(text)
        if match:
            alerts.append(
                _make_alert(
                    Severity.MEDIUM,
                    f"Possible obfuscated content in {field_name}",
                    tool,
                    field_name,
                    {"snippet": match.group(0)[:80]},
                )
            )
            break
