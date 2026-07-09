"""Launch an adversarial MCP server standalone over stdio.

Usage:
    python -m eval.adversarial_servers <ServerClassName>

Used by examples/live_proxy_demo.py to spawn real MCP servers behind the proxy.
"""

from __future__ import annotations

import sys

from . import (
    cross_tool_chain,
    indirect_prompt_injection,
    rug_pull,
    supply_chain,
    tool_poisoning,
)

_MODULES = [
    tool_poisoning,
    indirect_prompt_injection,
    supply_chain,
    rug_pull,
    cross_tool_chain,
]


def _find(name: str):
    for mod in _MODULES:
        cls = getattr(mod, name, None)
        if cls is not None:
            return cls
    return None


def main() -> None:
    if len(sys.argv) != 2:
        print("usage: python -m eval.adversarial_servers <ServerClassName>", file=sys.stderr)
        sys.exit(2)
    cls = _find(sys.argv[1])
    if cls is None:
        print(f"unknown server class: {sys.argv[1]}", file=sys.stderr)
        sys.exit(1)
    cls().run()


if __name__ == "__main__":
    main()
