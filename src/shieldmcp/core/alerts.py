"""Alert management and logging for ShieldMCP."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from .config import AlertConfig
from .models import Action, SecurityAlert, Severity

logger = logging.getLogger("shieldmcp.alerts")


class AlertManager:
    """Processes, filters, and logs security alerts."""

    def __init__(self, config: AlertConfig) -> None:
        self.config = config
        self._log_file: Path | None = None
        if config.log_all_alerts and config.alert_log_path:
            self._log_file = Path(config.alert_log_path)
            self._log_file.parent.mkdir(parents=True, exist_ok=True)

    def resolve_action(self, alert: SecurityAlert) -> Action:
        """Determine final action for an alert based on severity config."""
        severity_str = alert.severity.value
        action_str = self.config.default_action_by_severity.get(
            severity_str, Action.PASS.value
        )
        configured_action = Action(action_str)

        # Alert's own action takes priority if more restrictive
        if _action_priority(alert.action) > _action_priority(configured_action):
            return alert.action
        return configured_action

    def process_alerts(self, alerts: list[SecurityAlert]) -> tuple[Action, list[SecurityAlert]]:
        """Process a batch of alerts, returning the most restrictive action and all alerts."""
        if not alerts:
            return Action.PASS, []

        max_action = Action.PASS
        for alert in alerts:
            resolved = self.resolve_action(alert)
            alert.action = resolved
            if _action_priority(resolved) > _action_priority(max_action):
                max_action = resolved

        self._log_alerts(alerts)
        return max_action, alerts

    def _log_alerts(self, alerts: list[SecurityAlert]) -> None:
        for alert in alerts:
            log_level = _severity_to_log_level(alert.severity)
            logger.log(
                log_level,
                "[%s] [%s] %s — %s (tool=%s, server=%s)",
                alert.stage.value,
                alert.severity.value.upper(),
                alert.attack_family.value,
                alert.message,
                alert.tool_name,
                alert.server_id,
            )

            if self._log_file and self.config.log_all_alerts:
                with open(self._log_file, "a") as f:
                    f.write(json.dumps(alert.to_dict()) + "\n")


def _action_priority(action: Action) -> int:
    return {
        Action.PASS: 0,
        Action.WARN: 1,
        Action.QUARANTINE: 2,
        Action.BLOCK: 3,
    }[action]


def _severity_to_log_level(severity: Severity) -> int:
    return {
        Severity.CRITICAL: logging.CRITICAL,
        Severity.HIGH: logging.ERROR,
        Severity.MEDIUM: logging.WARNING,
        Severity.LOW: logging.INFO,
        Severity.INFO: logging.DEBUG,
    }[severity]


def setup_logging(level: str = "INFO") -> None:
    """Configure logging for ShieldMCP."""
    numeric_level = getattr(logging, level.upper(), logging.INFO)

    handler = logging.StreamHandler()
    handler.setFormatter(
        logging.Formatter(
            "%(asctime)s [%(name)s] %(levelname)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
    )

    root = logging.getLogger("shieldmcp")
    root.setLevel(numeric_level)
    root.addHandler(handler)
