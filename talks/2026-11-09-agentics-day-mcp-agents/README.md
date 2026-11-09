# Securing the Agentic Tool Layer: A Runtime Defense Framework for MCP Agent Deployments

**Agentics Day: MCP + Agents**, a CNCF-hosted co-located event at KubeCon + CloudNativeCon North America 2026.
Salt Palace Convention Center, Salt Lake City. Monday, November 9, 2026, 10:40 AM MT.

Speakers: Saurabh Yergattikar and Harshul Jain.

| File | What it is |
|---|---|
| [ShieldMCP_Agentics_Day_2026.pdf](ShieldMCP_Agentics_Day_2026.pdf) | Slides, 21 pages, 16:9 |
| [ShieldMCP_Agentics_Day_2026.pptx](ShieldMCP_Agentics_Day_2026.pptx) | Editable deck |

## What the talk covers

- Why MCP agents are attacked through the tools they trust, not through the user prompt.
- Five public incidents from 2025 where the entry point was a tool description, a tool response, or a malicious server.
- The SAFE-MCP taxonomy (Linux Foundation / OpenSSF): tool poisoning, prompt injection via tool response, rug pull, cross-server shadowing, parameter exfiltration.
- ShieldMCP as a transparent proxy with three stages: description integrity, parameter sanitization, response analysis.
- Verdicts as control flow (pass, warn, quarantine, block) and explicit failure policies.
- Evaluation numbers from the ACL 2026 Industry Track paper and the October 2026 framework check.
- Deployment patterns, trade-offs, and an eight-item checklist for vetting an MCP server.

## Try it

```bash
git clone https://github.com/saurabh-yergattikar/ShieldMCP.git
cd ShieldMCP
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
shieldmcp demo        # offline playground at http://127.0.0.1:8000
```

Related: [SAFE-MCP](https://github.com/SAFE-MCP/safe-mcp), [ACL 2026 paper](https://aclanthology.org/2026.acl-industry.58/).
