"""Launch a benign MCP server standalone over stdio.

Usage:
    python -m eval.benign_servers <ServerClassName>

Used by examples/live_proxy_demo.py to spawn real MCP servers behind the proxy.
"""

from __future__ import annotations

import sys

from . import servers


def main() -> None:
    if len(sys.argv) != 2:
        print("usage: python -m eval.benign_servers <ServerClassName>", file=sys.stderr)
        sys.exit(2)
    cls = getattr(servers, sys.argv[1], None)
    if cls is None:
        print(f"unknown server class: {sys.argv[1]}", file=sys.stderr)
        sys.exit(1)
    cls().run()


if __name__ == "__main__":
    main()
