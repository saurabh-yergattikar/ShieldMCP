"""Live transparent-proxy demonstration for ShieldMCP.

This is the *server-side* proof that ShieldMCP is a real, deployable MCP proxy —
not a web mock-up. It acts as a genuine MCP client, sends framed JSON-RPC over
stdio through `shieldmcp proxy`, which spawns a real MCP server as a subprocess.
You watch the proxy intercept `tools/list`, `tools/call`, and responses on the
actual wire protocol.

Run:
    python examples/live_proxy_demo.py            # benign + two attacks
    python examples/live_proxy_demo.py --attack   # attack servers only

Each scenario prints:
  1. what the CLIENT sent,
  2. what the PROXY decided (interception log),
  3. what the CLIENT received back after filtering.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

REPO = Path(__file__).resolve().parents[1]
SHIELD = str(REPO / ".venv" / "bin" / "shieldmcp")
PY = sys.executable

console = Console()


SCENARIOS = [
    {
        "title": "Benign filesystem server — passes through",
        "server_module": "eval.benign_servers",
        "server_class": "CalculatorServer",
        "server_id": "benign-calc",
        "family": "none",
        "calls": [{"name": "calculate", "arguments": {"expression": "2 + 2"}}],
    },
    {
        "title": "Tool poisoning server — blocked at Stage 1",
        "server_module": "eval.adversarial_servers",
        "server_class": "TP1_DirectInstructionServer",
        "server_id": "tp1",
        "family": "tool_poisoning",
        "calls": [],
    },
    {
        "title": "Indirect prompt injection server — blocked at Stage 3",
        "server_module": "eval.adversarial_servers",
        "server_class": "IPI1_DirectInjectionServer",
        "server_id": "ipi1",
        "family": "indirect_prompt_injection",
        "calls": [{"name": "read_webpage", "arguments": {"url": "https://docs.example.com"}}],
    },
]


def _frame(msg: dict) -> bytes:
    raw = json.dumps(msg)
    return f"Content-Length: {len(raw)}\r\n\r\n{raw}".encode()


def _parse_frames(data: bytes) -> list[dict]:
    """Parse Content-Length-framed JSON-RPC messages from a byte stream."""
    out: list[dict] = []
    i = 0
    text = data.decode("utf-8", errors="replace")
    while True:
        marker = text.find("Content-Length:", i)
        if marker == -1:
            break
        header_end = text.find("\r\n\r\n", marker)
        if header_end == -1:
            break
        length = int(text[marker + len("Content-Length:"): header_end].strip())
        body_start = header_end + 4
        body = text[body_start: body_start + length]
        try:
            out.append(json.loads(body))
        except json.JSONDecodeError:
            pass
        i = body_start + length
    return out


def run_scenario(scenario: dict) -> None:
    console.print()
    color = "green" if scenario["family"] == "none" else "red"
    console.print(Panel(f"[bold]{scenario['title']}[/bold]", border_style=color))

    # Build the client->server message sequence
    messages = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
    ]
    for i, call in enumerate(scenario["calls"], start=3):
        messages.append(
            {"jsonrpc": "2.0", "id": i, "method": "tools/call", "params": call}
        )

    console.print("\n[bold cyan]1. CLIENT sends[/bold cyan] (real MCP JSON-RPC over stdio):")
    for m in messages:
        console.print(f"   → {m['method']}")

    # Spawn the proxy wrapping the real server
    proc = subprocess.Popen(
        [
            SHIELD, "proxy", "--server-id", scenario["server_id"], "--log-level", "INFO",
            "--", PY, "-m", scenario["server_module"], scenario["server_class"],
        ],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        cwd=str(REPO),
    )
    assert proc.stdin
    for m in messages:
        proc.stdin.write(_frame(m))
    proc.stdin.flush()
    time.sleep(1.5)
    proc.terminate()
    out, err = proc.communicate(timeout=5)

    # 2. What the proxy decided
    console.print("\n[bold yellow]2. PROXY intercepts[/bold yellow] (ShieldMCP decisions):")
    shown = False
    for line in err.decode("utf-8", errors="replace").splitlines():
        if any(k in line for k in ["CRITICAL", "HIGH", "BLOCKED", "Stage 1 completed",
                                    "Stage 2 completed", "Stage 3 completed"]):
            tag = "red" if ("CRITICAL" in line or "HIGH" in line or "BLOCKED" in line) else "dim"
            # trim the logger prefix for readability
            msg = line.split("] ", 1)[-1] if "] " in line else line
            console.print(f"   [{tag}]• {msg}[/{tag}]")
            shown = True
    if not shown:
        console.print("   [green]• all stages passed — no alerts[/green]")

    # 3. What the client actually received back
    frames = _parse_frames(out)
    console.print("\n[bold cyan]3. CLIENT receives[/bold cyan] (after ShieldMCP filtering):")
    for f in frames:
        result = f.get("result", {})
        if "tools" in result:
            names = [t.get("name") for t in result["tools"]]
            if names:
                console.print(f"   ← tools/list: {names}")
            else:
                console.print("   ← tools/list: [red][] — all tools blocked, agent never sees them[/red]")
        elif "serverInfo" in result:
            console.print(f"   ← initialize: connected to '{result['serverInfo'].get('name')}'")
        elif "content" in result or result:
            body = json.dumps(result)[:90]
            console.print(f"   ← tools/call result: {body}")


def main() -> None:
    parser = argparse.ArgumentParser(description="ShieldMCP live proxy demo")
    parser.add_argument("--attack", action="store_true", help="Run attack scenarios only")
    args = parser.parse_args()

    console.print(Panel(
        Text.from_markup(
            "[bold]ShieldMCP — Live Transparent Proxy[/bold]\n"
            "Real MCP client  →  [bold]shieldmcp proxy[/bold]  →  real MCP server (subprocess)\n"
            "Interception happens on the actual JSON-RPC wire protocol."
        ),
        border_style="cyan",
    ))

    scenarios = SCENARIOS[1:] if args.attack else SCENARIOS
    for sc in scenarios:
        run_scenario(sc)

    console.print()
    console.print(Panel(
        "[bold green]Every check ran inside a real MCP proxy — "
        "no agent or server code was modified.[/bold green]",
        border_style="green",
    ))


if __name__ == "__main__":
    main()
