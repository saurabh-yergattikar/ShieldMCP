"""CLI entry point for ShieldMCP."""

from __future__ import annotations

import argparse
import asyncio
import sys

from .core.alerts import setup_logging
from .core.config import ShieldMCPConfig
from .core.pipeline import ShieldPipeline


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="shieldmcp",
        description="ShieldMCP — Runtime security for MCP tool calls",
    )
    subparsers = parser.add_subparsers(dest="command")

    # --- proxy command (stdio) ---
    proxy_parser = subparsers.add_parser("proxy", help="Run as transparent MCP proxy (stdio)")
    proxy_parser.add_argument(
        "server_command",
        nargs="+",
        help="MCP server command to proxy (e.g., 'python server.py')",
    )
    proxy_parser.add_argument(
        "--config", "-c", default="shieldmcp.yaml", help="Path to config file"
    )
    proxy_parser.add_argument(
        "--server-id", default="default", help="Identifier for this MCP server"
    )
    proxy_parser.add_argument(
        "--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"]
    )
    proxy_parser.add_argument(
        "--transport",
        default="stdio",
        choices=["stdio", "sse"],
        help="Transport type (default: stdio)",
    )

    # --- sse-proxy command ---
    sse_parser = subparsers.add_parser("sse-proxy", help="Run as SSE transport proxy")
    sse_parser.add_argument(
        "--backend-url",
        required=True,
        help="URL of the real MCP server's SSE endpoint (e.g., http://localhost:3000)",
    )
    sse_parser.add_argument("--host", default=None, help="Listen host (default from config)")
    sse_parser.add_argument(
        "--port", type=int, default=None, help="Listen port (default from config)"
    )
    sse_parser.add_argument(
        "--config", "-c", default="shieldmcp.yaml", help="Path to config file"
    )
    sse_parser.add_argument(
        "--server-id", default="default", help="Identifier for this MCP server"
    )
    sse_parser.add_argument(
        "--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"]
    )

    # --- scan command ---
    scan_parser = subparsers.add_parser("scan", help="Scan tool descriptions from a file")
    scan_parser.add_argument("file", help="JSON file with tool descriptions")
    scan_parser.add_argument("--config", "-c", default="shieldmcp.yaml")
    scan_parser.add_argument("--server-id", default="scan-target")

    # --- init command ---
    init_parser = subparsers.add_parser("init", help="Generate default config file")
    init_parser.add_argument("--output", "-o", default="shieldmcp.yaml")

    # --- registry command ---
    registry_parser = subparsers.add_parser("registry", help="Inspect tool registry")
    registry_parser.add_argument("--config", "-c", default="shieldmcp.yaml")
    registry_parser.add_argument("--server-id", default=None)

    args = parser.parse_args()

    if args.command == "proxy":
        setup_logging(args.log_level)
        config = ShieldMCPConfig.from_yaml(args.config)

        if getattr(args, "transport", "stdio") == "sse":
            print("Error: use the 'sse-proxy' command for SSE transport", file=sys.stderr)
            sys.exit(1)

        from .proxy.interceptor import StdioProxy

        proxy = StdioProxy(args.server_command, config, args.server_id)
        asyncio.run(proxy.start())

    elif args.command == "sse-proxy":
        setup_logging(args.log_level)
        config = ShieldMCPConfig.from_yaml(args.config)

        if args.host:
            config.proxy.host = args.host
        if args.port:
            config.proxy.port = args.port

        from .proxy.sse_proxy import SSEProxy

        proxy = SSEProxy(args.backend_url, config, args.server_id)
        asyncio.run(proxy.start())

    elif args.command == "scan":
        setup_logging("INFO")
        asyncio.run(_run_scan(args))

    elif args.command == "init":
        config = ShieldMCPConfig()
        config.to_yaml(args.output)
        print(f"Default config written to {args.output}")

    elif args.command == "registry":
        asyncio.run(_run_registry(args))

    else:
        parser.print_help()
        sys.exit(1)


async def _run_scan(args: argparse.Namespace) -> None:
    """Scan tool descriptions from a JSON file."""
    import json

    from rich.console import Console
    from rich.table import Table

    config = ShieldMCPConfig.from_yaml(args.config)
    pipeline = ShieldPipeline(config)
    await pipeline.initialize()

    with open(args.file) as f:
        tools_data = json.load(f)

    if isinstance(tools_data, dict) and "tools" in tools_data:
        tools = tools_data["tools"]
    elif isinstance(tools_data, list):
        tools = tools_data
    else:
        print("Error: expected a JSON array or object with 'tools' key")
        return

    action, filtered, alerts = await pipeline.validate_tools(args.server_id, tools)
    await pipeline.shutdown()

    console = Console()
    table = Table(title="ShieldMCP Scan Results")
    table.add_column("Severity", style="bold")
    table.add_column("Attack Family")
    table.add_column("Tool")
    table.add_column("Action", style="bold")
    table.add_column("Message")

    severity_colors = {
        "critical": "red",
        "high": "red",
        "medium": "yellow",
        "low": "blue",
        "info": "dim",
    }

    for alert in alerts:
        color = severity_colors.get(alert.severity.value, "white")
        table.add_row(
            f"[{color}]{alert.severity.value.upper()}[/{color}]",
            alert.attack_family.value,
            alert.tool_name or "—",
            alert.action.value.upper(),
            alert.message,
        )

    console.print(table)
    console.print(f"\nOverall action: [bold]{action.value.upper()}[/bold]")
    console.print(f"Tools passed: {len(filtered)}/{len(tools)}")


async def _run_registry(args: argparse.Namespace) -> None:
    """Inspect the tool registry."""
    from rich.console import Console
    from rich.table import Table

    config = ShieldMCPConfig.from_yaml(args.config)
    pipeline = ShieldPipeline(config)
    await pipeline.initialize()

    tools = await pipeline.registry.get_all_tools(args.server_id)
    await pipeline.shutdown()

    console = Console()
    table = Table(title="Tool Registry")
    table.add_column("Server")
    table.add_column("Tool")
    table.add_column("Hash (first 12)")
    table.add_column("Authorized")
    table.add_column("First Seen")
    table.add_column("Last Seen")

    import datetime

    for t in tools:
        table.add_row(
            t["server_id"],
            t["tool_name"],
            t["content_hash"][:12],
            "Yes" if t["authorized"] else "[red]NO[/red]",
            datetime.datetime.fromtimestamp(t["first_seen"]).strftime("%Y-%m-%d %H:%M"),
            datetime.datetime.fromtimestamp(t["last_seen"]).strftime("%Y-%m-%d %H:%M"),
        )

    console.print(table)


if __name__ == "__main__":
    main()
