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

# Generate default config
shieldmcp init

# Scan tool descriptions from a file
shieldmcp scan tools.json

# Run as transparent proxy
shieldmcp proxy -- python your_mcp_server.py

# Inspect the tool registry
shieldmcp registry
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
