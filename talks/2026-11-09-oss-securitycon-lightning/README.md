# Your Agent Trusts Its Tools Too Much: A 10-Minute Tour of MCP Tool-Layer Attacks

**Open Source SecurityCon**, a CNCF-hosted co-located event at KubeCon + CloudNativeCon North America 2026.
Salt Palace Convention Center, Salt Lake City. Monday, November 9, 2026, 5:00 PM MT. Lightning talk.

Speaker: Saurabh Yergattikar.

| File | What it is |
|---|---|
| [ShieldMCP_OSS_SecurityCon_2026_Lightning.pdf](ShieldMCP_OSS_SecurityCon_2026_Lightning.pdf) | Slides, 10 pages, 16:9 |
| [ShieldMCP_OSS_SecurityCon_2026_Lightning.pptx](ShieldMCP_OSS_SecurityCon_2026_Lightning.pptx) | Editable deck |

## What the talk covers

- Three attack patterns against MCP agents: a poisoned tool description (SAFE-T1001), a hidden instruction in a tool response (SAFE-T1102), and a malicious server from a public registry (SAFE-T1201 and supply chain).
- Why prompt-level guardrails, model safety training, and install-time review miss all three.
- ShieldMCP as a runtime proxy with three stages and verdicts as control flow.
- Numbers from the ACL 2026 Industry Track paper.
- Three things to vet before approving any MCP server.

## Try it

```bash
git clone https://github.com/saurabh-yergattikar/ShieldMCP.git
cd ShieldMCP
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
shieldmcp demo        # offline playground at http://127.0.0.1:8000
```

Related: [SAFE-MCP](https://github.com/SAFE-MCP/safe-mcp), [ACL 2026 paper](https://aclanthology.org/2026.acl-industry.58/), [the 25-minute Agentics Day talk](../2026-11-09-agentics-day-mcp-agents/).
