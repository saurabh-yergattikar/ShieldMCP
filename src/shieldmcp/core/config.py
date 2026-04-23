"""Configuration management for ShieldMCP."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .models import Action, Severity


@dataclass
class Stage1Config:
    """Configuration for Stage 1: Tool Description Integrity."""

    enabled: bool = True
    structural_checks_enabled: bool = True
    semantic_checks_enabled: bool = True
    semantic_threshold: float = 0.72
    semantic_backend: str = "heuristic"  # "heuristic", "llm_judge", "classifier"
    llm_judge_model: str = "gpt-4o-mini"
    rug_pull_detection: bool = True
    quarantine_on_new_tools: bool = False


@dataclass
class Stage2Config:
    """Configuration for Stage 2: Parameter Sanitization."""

    enabled: bool = True
    schema_validation: bool = True
    sql_injection_detection: bool = True
    shell_injection_detection: bool = True
    prompt_injection_detection: bool = True
    path_traversal_detection: bool = True
    max_param_length: int = 10000


@dataclass
class Stage3Config:
    """Configuration for Stage 3: Response Analysis."""

    enabled: bool = True
    instruction_detection_enabled: bool = True
    instruction_detection_backend: str = "heuristic"  # "heuristic", "llm_judge", "classifier"
    context_boundary_enforcement: bool = True
    hidden_content_detection: bool = True
    cross_call_correlation: bool = True
    max_chain_depth: int = 4
    boundary_prefix: str = "[TOOL_RESPONSE_START]"
    boundary_suffix: str = "[TOOL_RESPONSE_END]"


@dataclass
class AlertConfig:
    """Configuration for alert handling."""

    default_action_by_severity: dict[str, str] = field(
        default_factory=lambda: {
            Severity.CRITICAL.value: Action.BLOCK.value,
            Severity.HIGH.value: Action.BLOCK.value,
            Severity.MEDIUM.value: Action.WARN.value,
            Severity.LOW.value: Action.PASS.value,
            Severity.INFO.value: Action.PASS.value,
        }
    )
    log_all_alerts: bool = True
    alert_log_path: str = "shieldmcp_alerts.jsonl"


@dataclass
class ProxyConfig:
    """Configuration for the MCP proxy."""

    transport: str = "stdio"  # "stdio" or "sse"
    host: str = "127.0.0.1"
    port: int = 8765


@dataclass
class ShieldMCPConfig:
    """Top-level configuration for ShieldMCP."""

    stage1: Stage1Config = field(default_factory=Stage1Config)
    stage2: Stage2Config = field(default_factory=Stage2Config)
    stage3: Stage3Config = field(default_factory=Stage3Config)
    alerts: AlertConfig = field(default_factory=AlertConfig)
    proxy: ProxyConfig = field(default_factory=ProxyConfig)
    registry_db_path: str = "shieldmcp_registry.db"
    log_level: str = "INFO"
    allowlisted_servers: list[str] = field(default_factory=list)
    blocklisted_servers: list[str] = field(default_factory=list)

    @classmethod
    def from_yaml(cls, path: str | Path) -> ShieldMCPConfig:
        path = Path(path)
        if not path.exists():
            return cls()
        with open(path) as f:
            data = yaml.safe_load(f) or {}
        return cls._from_dict(data)

    @classmethod
    def _from_dict(cls, data: dict) -> ShieldMCPConfig:
        config = cls()
        if "stage1" in data:
            for k, v in data["stage1"].items():
                if hasattr(config.stage1, k):
                    setattr(config.stage1, k, v)
        if "stage2" in data:
            for k, v in data["stage2"].items():
                if hasattr(config.stage2, k):
                    setattr(config.stage2, k, v)
        if "stage3" in data:
            for k, v in data["stage3"].items():
                if hasattr(config.stage3, k):
                    setattr(config.stage3, k, v)
        if "alerts" in data:
            for k, v in data["alerts"].items():
                if hasattr(config.alerts, k):
                    setattr(config.alerts, k, v)
        if "proxy" in data:
            for k, v in data["proxy"].items():
                if hasattr(config.proxy, k):
                    setattr(config.proxy, k, v)
        for simple_key in [
            "registry_db_path",
            "log_level",
            "allowlisted_servers",
            "blocklisted_servers",
        ]:
            if simple_key in data:
                setattr(config, simple_key, data[simple_key])
        return config

    def to_yaml(self, path: str | Path) -> None:
        import dataclasses

        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            yaml.dump(dataclasses.asdict(self), f, default_flow_style=False, sort_keys=False)
