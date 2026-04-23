"""ShieldMCP validation pipeline — wires all three stages together.

This is the main entry point that the proxy calls for every MCP interaction.
"""

from __future__ import annotations

import logging
import time
import uuid
from typing import Any

from .alerts import AlertManager
from .config import ShieldMCPConfig
from .models import (
    Action,
    SecurityAlert,
    SessionContext,
    ToolCall,
    ToolResponse,
    ToolSignature,
    ValidationResult,
)
from .registry import ToolRegistry
from ..stage1.description_integrity import validate_tool_descriptions
from ..stage2.parameter_sanitizer import validate_parameters
from ..stage3.response_analyzer import analyze_response

logger = logging.getLogger("shieldmcp.pipeline")


class ShieldPipeline:
    """Orchestrates the three-stage validation pipeline."""

    def __init__(self, config: ShieldMCPConfig) -> None:
        self.config = config
        self.registry = ToolRegistry(config.registry_db_path)
        self.alert_manager = AlertManager(config.alerts)
        self._sessions: dict[str, SessionContext] = {}
        self._tool_signatures: dict[str, ToolSignature] = {}  # keyed by "server_id:tool_name"
        self._initialized = False

    async def initialize(self) -> None:
        await self.registry.initialize()
        self._initialized = True
        logger.info("ShieldMCP pipeline initialized")

    async def shutdown(self) -> None:
        await self.registry.close()
        self._initialized = False
        logger.info("ShieldMCP pipeline shut down")

    def get_or_create_session(self, session_id: str | None = None) -> SessionContext:
        if session_id is None:
            session_id = str(uuid.uuid4())
        if session_id not in self._sessions:
            self._sessions[session_id] = SessionContext(session_id=session_id)
        return self._sessions[session_id]

    # --- Stage 1: Tool Description Integrity ---

    async def validate_tools(
        self,
        server_id: str,
        tools: list[dict[str, Any]],
    ) -> tuple[Action, list[dict[str, Any]], list[SecurityAlert]]:
        """Validate tool descriptions from tools/list response.

        Returns (action, filtered_tools, alerts).
        filtered_tools has poisoned/blocked tools removed.
        """
        start = time.perf_counter()

        tool_sigs = []
        for t in tools:
            sig = ToolSignature(
                server_id=server_id,
                name=t.get("name", ""),
                description=t.get("description", ""),
                parameters=t.get("inputSchema", t.get("parameters", {})),
                return_type=t.get("returnType"),
            )
            tool_sigs.append(sig)
            self._tool_signatures[f"{server_id}:{sig.name}"] = sig

        result = await validate_tool_descriptions(tool_sigs, self.config, self.registry)
        action, alerts = self.alert_manager.process_alerts(result.alerts)

        # Filter out blocked tools
        blocked_tools = {a.tool_name for a in alerts if a.action == Action.BLOCK}
        filtered = [t for t in tools if t.get("name") not in blocked_tools]

        elapsed = (time.perf_counter() - start) * 1000
        logger.info(
            "Stage 1 completed: %d tools checked, %d alerts, %d blocked (%.1fms)",
            len(tools), len(alerts), len(blocked_tools), elapsed,
        )

        return action, filtered, alerts

    # --- Stage 2: Parameter Sanitization ---

    async def validate_call(
        self,
        server_id: str,
        tool_name: str,
        parameters: dict[str, Any],
        session_id: str | None = None,
    ) -> tuple[Action, list[SecurityAlert]]:
        """Validate outbound tool call parameters.

        Returns (action, alerts).
        """
        start = time.perf_counter()
        session = self.get_or_create_session(session_id)

        call = ToolCall(
            call_id=str(uuid.uuid4()),
            tool_name=tool_name,
            server_id=server_id,
            parameters=parameters,
        )
        session.record_call(call)

        sig_key = f"{server_id}:{tool_name}"
        sig = self._tool_signatures.get(sig_key)
        if sig is None:
            sig = ToolSignature(
                server_id=server_id,
                name=tool_name,
                description="",
                parameters={},
            )

        result = await validate_parameters(call, sig, self.config)
        action, alerts = self.alert_manager.process_alerts(result.alerts)

        elapsed = (time.perf_counter() - start) * 1000
        logger.info(
            "Stage 2 completed: %s.%s, %d alerts, action=%s (%.1fms)",
            server_id, tool_name, len(alerts), action.value, elapsed,
        )

        return action, alerts

    # --- Stage 3: Response Analysis ---

    async def validate_response(
        self,
        server_id: str,
        tool_name: str,
        content: Any,
        call_id: str | None = None,
        session_id: str | None = None,
        is_error: bool = False,
    ) -> tuple[Action, Any, list[SecurityAlert]]:
        """Validate inbound tool response.

        Returns (action, modified_content, alerts).
        modified_content has context boundaries applied.
        """
        start = time.perf_counter()
        session = self.get_or_create_session(session_id)

        response = ToolResponse(
            call_id=call_id or str(uuid.uuid4()),
            tool_name=tool_name,
            server_id=server_id,
            content=content,
            is_error=is_error,
        )
        session.record_response(response)

        result = await analyze_response(response, session, self.config)
        action, alerts = self.alert_manager.process_alerts(result.alerts)

        for alert in alerts:
            session.record_alert(alert)

        modified = result.modified_content if result.modified_content is not None else content

        elapsed = (time.perf_counter() - start) * 1000
        logger.info(
            "Stage 3 completed: %s.%s, %d alerts, action=%s (%.1fms)",
            server_id, tool_name, len(alerts), action.value, elapsed,
        )

        return action, modified, alerts

    # --- Full pipeline for a single tool call round-trip ---

    async def process_tool_call(
        self,
        server_id: str,
        tool_name: str,
        parameters: dict[str, Any],
        session_id: str | None = None,
    ) -> tuple[Action, list[SecurityAlert]]:
        """Stage 2 check on outbound call."""
        return await self.validate_call(server_id, tool_name, parameters, session_id)

    async def process_tool_response(
        self,
        server_id: str,
        tool_name: str,
        content: Any,
        session_id: str | None = None,
    ) -> tuple[Action, Any, list[SecurityAlert]]:
        """Stage 3 check on inbound response."""
        return await self.validate_response(server_id, tool_name, content, session_id=session_id)
