# ShieldMCP

**Runtime security framework for Model Context Protocol (MCP) deployments.**

ShieldMCP is a transparent proxy that sits between LLM agents and MCP servers, performing real-time validation of tool descriptions, call parameters, and responses to detect and block attacks — without requiring modifications to either the agent or the server.

## Architecture

```
Agent ──tools/list──→ ShieldMCP [Stage 1: Description Integrity] ──→ Server
Agent ──call(params)──→ ShieldMCP [Stage 2: Parameter Sanitization] ──→ Server
Server ──response──→ ShieldMCP [Stage 3: Response Analysis] ──→ Agent
```

### Three-Stage Validation

| Stage | What It Checks | Attacks Caught |
|-------|---------------|----------------|
| **Stage 1: Description Integrity** | Tool descriptions, parameter schemas, metadata | Tool poisoning, rug pulls, supply chain |
| **Stage 2: Parameter Sanitization** | Outbound call arguments | SQL/shell/prompt injection, path traversal |
| **Stage 3: Response Analysis** | Inbound tool responses | Indirect prompt injection, exfiltration, cross-tool chains |

## Quick Start

```bash
# Install
pip install -e .

# Launch the interactive web demo → http://127.0.0.1:8000
shieldmcp demo

# Generate default config
shieldmcp init

# Scan tool descriptions from a file
shieldmcp scan tools.json

# Run as transparent proxy
shieldmcp proxy -- python your_mcp_server.py

# Inspect the tool registry
shieldmcp registry
```

## Interactive Demo

`shieldmcp demo` starts a local, self-contained web interface that runs the **real**
three-stage pipeline live — no API keys, no external network. Launch curated attacks
from five threat families, watch each validation stage execute with per-token
highlighting of the detected payload, and paste your own tool descriptions,
parameters, or responses into the playground.

```bash
shieldmcp demo --host 127.0.0.1 --port 8000
```

This demonstration accompanies the EMNLP 2026 System Demonstration paper
*"ShieldMCP: An Interactive System for Runtime Security of Model Context Protocol
Tool Calls"* (`paper/`).

### Live proxy demo (server-side, real MCP wire protocol)

Prove it's a real transparent proxy, not a mock-up: a real MCP client sends framed
JSON-RPC through `shieldmcp proxy`, which spawns real MCP servers as subprocesses
and intercepts `tools/list`, `tools/call`, and responses live.

```bash
python examples/live_proxy_demo.py            # benign + two attack servers
python examples/live_proxy_demo.py --attack   # attack servers only
```

You'll see a benign server pass through, a poisoned server have its malicious tools
stripped, and an injection server have its response blocked at Stage 3 — with no
changes to the agent or server. This is the same path deployed via
`shieldmcp proxy -- python your_mcp_server.py`.

### Reproduce the benchmark

```bash
# Framework-only eval (no API keys): 487 attacks + 200 benign, 40 servers
python eval/run_evaluation.py --framework-only              # heuristic → 8.6% ASR
python eval/run_evaluation.py --framework-only --classifier # DistilBERT backend

# Per-call latency
python eval/benchmarks/latency_benchmark.py --iterations 1000
```

## Configuration

See `configs/default.yaml` for all options. Key settings:

```yaml
stage1:
  semantic_threshold: 0.72    # Score above this → quarantine
  semantic_backend: heuristic # heuristic | llm_judge | classifier

stage3:
  cross_call_correlation: true
  max_chain_depth: 4          # Alert on chains deeper than this
```

## Python API

```python
from shieldmcp.core.config import ShieldMCPConfig
from shieldmcp.core.pipeline import ShieldPipeline

config = ShieldMCPConfig.from_yaml("shieldmcp.yaml")
pipeline = ShieldPipeline(config)
await pipeline.initialize()

# Stage 1: Validate tool descriptions
action, filtered_tools, alerts = await pipeline.validate_tools(
    server_id="my-server",
    tools=[{"name": "read_file", "description": "...", "inputSchema": {...}}],
)

# Stage 2: Validate outbound call
action, alerts = await pipeline.process_tool_call(
    server_id="my-server",
    tool_name="read_file",
    parameters={"path": "/etc/passwd"},
)

# Stage 3: Validate inbound response
action, modified_content, alerts = await pipeline.process_tool_response(
    server_id="my-server",
    tool_name="read_file",
    content="file contents here...",
)
```

## Development

```bash
# Install dev dependencies
pip install -e ".[all]"

# Run tests
pytest

# Lint
ruff check src/
```

## License

Apache-2.0
