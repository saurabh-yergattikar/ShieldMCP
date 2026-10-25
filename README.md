<div align="center">

# 🛡️ ShieldMCP

**Inspect the tools. Guard the calls. Validate the responses.**

Open-source runtime security at the Model Context Protocol boundary.

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-2563eb?style=flat-square)](LICENSE) [![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-3776ab?style=flat-square&logo=python&logoColor=white)](pyproject.toml) [![Release](https://img.shields.io/badge/Release-v0.1.0--alpha.1-f59e0b?style=flat-square)](https://github.com/saurabh-yergattikar/ShieldMCP/releases/tag/v0.1.0-alpha.1) [![Regression tests: 119 passing](https://img.shields.io/badge/Regression_tests-119_passing-16a34a?style=flat-square)](docs/REVIEW_VERIFICATION.md)

[![ACL 2026 Industry Track: Published](https://img.shields.io/badge/ACL_2026_Industry-Published-2563eb?style=for-the-badge)](https://aclanthology.org/2026.acl-industry.58/) [![EMNLP 2026 System Demonstrations: Accepted](https://img.shields.io/badge/EMNLP_2026_System_Demos-Accepted-7c3aed?style=for-the-badge)](https://2026.emnlp.org/program/)

[![ACL conference: ICORE2026 A*](https://img.shields.io/badge/ACL_venue-ICORE2026_A%2A-d4a017?style=flat-square)](https://portal.core.edu.au/conf-ranks/196/) [![EMNLP conference: ICORE2026 A*](https://img.shields.io/badge/EMNLP_venue-ICORE2026_A%2A-d4a017?style=flat-square)](https://portal.core.edu.au/conf-ranks/448/)

[**Quick start**](#quick-start) · [**Features**](#features) · [**Papers**](#research-papers) · [**Models**](models/README.md) · [**Red-team guide**](docs/RED_TEAMING.md) · [**Citation**](#citation)

</div>

ShieldMCP sits between an agent and its MCP server, checking **tool metadata, outbound arguments, and inbound responses** through one inspectable pipeline. Deploy it as a transparent stdio or legacy SSE proxy, or integrate its asynchronous Python API.

**Apache-2.0 licensed code and released model artifacts, including commercial use and integration under the same license.** The default detector runs locally without model downloads or API keys.

## Research papers

| Venue | Paper | Resources |
|---|---|---|
| **ACL 2026 · Industry Track** <br> Published · **A\* conference** | *Securing the Tool Layer: A Threat Taxonomy and Runtime Defense Framework for Model Context Protocol Deployments* | [Anthology](https://aclanthology.org/2026.acl-industry.58/) · [PDF](https://aclanthology.org/2026.acl-industry.58.pdf) · [DOI](https://doi.org/10.18653/v1/2026.acl-industry.58) |
| **EMNLP 2026 · System Demonstrations** <br> Accepted and scheduled · **A\* conference** | *ShieldMCP: An Interactive System for Runtime Security of Model Context Protocol Tool Calls* | [Camera-ready paper](paper/EMNLP_Paper_Id_69_ShieldMCP_Demo_Track_AclPubCheck_Final.pdf) · [Official program](https://2026.emnlp.org/program/) |

`A*` refers to the **conference venues' ICORE2026 rankings**: [ACL](https://portal.core.edu.au/conf-ranks/196/), [EMNLP](https://portal.core.edu.au/conf-ranks/448/). The EMNLP paper appears as **69-DEMO** in the [official presentation schedule](https://docs.google.com/spreadsheets/d/1aXGTy_7Xeh-OXIs3iJSbDpUsZ6YhbfA76b17kBZH0Yk/edit?gid=943432490); its Anthology link will be added when available.

## Features

| Capability | What ShieldMCP provides | Availability |
|---|---|---|
| 🧬 **Tool integrity** | Description/schema inspection and stored hashes to detect poisoned metadata and tool-definition changes | ![Stage 1](https://img.shields.io/badge/Stage_1-Metadata-2563eb?style=flat-square) |
| 🔎 **Argument validation** | Schema-aware checks for SQL/shell/prompt patterns and path traversal before forwarding a call | ![Stage 2](https://img.shields.io/badge/Stage_2-Arguments-7c3aed?style=flat-square) |
| 🛡️ **Response protection** | Instruction detection, hidden-content checks, context boundaries, and session correlation | ![Stage 3](https://img.shields.io/badge/Stage_3-Responses-e11d48?style=flat-square) |
| 🧠 **Local learned detectors** | Released fine-tuned DistilBERT description and token classifiers; no hosted inference service required | ![Optional models](https://img.shields.io/badge/Optional-Local_models-f59e0b?style=flat-square) |
| ⚡ **Tiered detection** | Heuristics first, with selected ambiguous inputs escalated to local classifiers | ![Optional tiered backend](https://img.shields.io/badge/Optional-Tiered-0d9488?style=flat-square) |
| 🔌 **Proxy or Python API** | Newline/Content-Length stdio framing, legacy SSE, and an async pipeline | ![Core API](https://img.shields.io/badge/Core-Proxy_%2B_API-334155?style=flat-square) |
| 🧪 **Inspect and reproduce** | Browser playground, actual subprocess proxy demo, versioned results, and synthetic attack/benign scenarios | ![Included evaluation](https://img.shields.io/badge/Included-Demos_%2B_Evaluation-16a34a?style=flat-square) |
| 🧭 **Governance and caching** | Failure policies, task scope, schema pinning, and validated cache APIs | ![Experimental APIs](https://img.shields.io/badge/Experimental-Opt--in_APIs-d97706?style=flat-square) |

The distinctive design combines **metadata integrity, call validation, and response analysis at the MCP boundary**, with local detection and reproducible inspection. This is an alpha research framework; test the configured controls against your own agents, tools, and workloads. Experimental governance/cache APIs require explicit integration and are not enabled by the default CLI proxy.

## Quick start

```bash
git clone https://github.com/saurabh-yergattikar/ShieldMCP.git
cd ShieldMCP
python3 -m venv .venv
source .venv/bin/activate
pip install -e .

# Interactive pipeline demo: http://127.0.0.1:8000
shieldmcp demo
```

The default heuristic backend needs no model downloads or API keys. The browser demo computes pipeline verdicts live against curated scenarios and user inputs; it is not a live agent benchmark. For subprocess traffic through the actual stdio proxy:

```bash
python examples/live_proxy_demo.py
```

For an independent review, start with [the red-team guide](docs/RED_TEAMING.md), [model setup and limitations](models/README.md), and the [framework evaluation](eval/run_evaluation.py).

## Architecture

```text
Agent --tools/list--> [Stage 1: metadata integrity] --> MCP server
Agent --tools/call--> [Stage 2: argument checks]    --> MCP server
Agent <--response--- [Stage 3: response analysis]  <-- MCP server
```

| Stage | Checks | Threats addressed |
|---|---|---|
| 1: Description integrity | Tool descriptions, schemas, structural patterns, stored hashes | Tool poisoning, metadata changes / rug pulls, suspicious supply-chain content |
| 2: Parameter sanitization | Schema constraints, SQL/shell/prompt patterns, path traversal | Malicious outbound arguments |
| 3: Response analysis | Instructional spans, hidden content, context boundaries, session correlation | Indirect prompt injection and suspicious cross-tool chains |

Detection is heuristic or model-based, with false positives and false negatives. Stage 3 runs after a tool executes: it can withhold a response, but cannot undo a side effect. Parameter checks do not replace application authorization or a general execution sandbox.

## Proxy and configuration

```bash
shieldmcp init
shieldmcp scan examples/tools.json
shieldmcp proxy --server-id my-server -- python your_mcp_server.py
shieldmcp registry

# Legacy HTTP/SSE transport
shieldmcp sse-proxy --backend-url http://127.0.0.1:3000
```

The stdio proxy accepts newline-delimited JSON-RPC and Content-Length framing. Legacy SSE support is separate; Streamable HTTP is not implemented. See [default configuration](configs/default.yaml).

```yaml
stage1:
  semantic_backend: heuristic  # heuristic | llm_judge | classifier | tiered
  semantic_threshold: 0.72
  tiered_band_low: 0.12
stage3:
  instruction_detection_backend: heuristic  # heuristic | classifier | tiered
  tiered_min_words: 20
```

`classifier` uses local fine-tuned DistilBERT detectors. `tiered` routes selected ambiguous inputs through those classifiers after inexpensive heuristic checks. Download the trained artifacts or train locally using [model setup](models/README.md). The stage wrappers log a heuristic fallback if models/dependencies cannot load; confirm the models are loaded before treating a run as classifier evaluation. The `llm_judge` Stage 1 backend requires external model access.

## Python API

```python
import asyncio
from shieldmcp.core.config import ShieldMCPConfig
from shieldmcp.core.pipeline import ShieldPipeline

async def main():
    pipeline = ShieldPipeline(ShieldMCPConfig())
    await pipeline.initialize()
    try:
        action, tools, alerts = await pipeline.validate_tools("docs", [{
            "name": "read_page",
            "description": "Return the text of a document.",
            "inputSchema": {"type": "object", "properties": {
                "id": {"type": "string"}}, "required": ["id"]},
        }])
        action, alerts = await pipeline.process_tool_call(
            "docs", "read_page", {"id": "guide"}, session_id="review")
        action, content, alerts = await pipeline.process_tool_response(
            "docs", "read_page", "Document contents", session_id="review")
    finally:
        await pipeline.shutdown()

asyncio.run(main())
```

Integrators must honor returned actions before executing a call or giving content to an agent. The command-line proxy does this automatically.

## Experimental governance APIs

[PolicyEnforcedPipeline](src/shieldmcp/governance/enforcement.py) adds explicit failure policies, task-scoped tool exposure, and schema pinning. [GovernedResponseCache](src/shieldmcp/governance/response_cache.py) implements validated response caching with an eligibility predicate. These are opt-in Python APIs with synthetic benchmarks; they are **not wired into the default CLI proxy**. Integrators must provide the policy-aware wrapper and cache lifecycle themselves.

## Evaluation and development

```bash
pip install -e '.[all]'
pytest -q

# Framework detection evaluation: 488 attack + 200 benign scenarios
python eval/run_evaluation.py --framework-only --output-dir /tmp/shieldmcp-heuristic-review

# Requires trained artifacts; use separate output directories
python eval/run_evaluation.py --framework-only --backend classifier --output-dir /tmp/shieldmcp-classifier-review
python eval/run_evaluation.py --framework-only --backend tiered --output-dir /tmp/shieldmcp-tiered-review

python eval/benchmarks/latency_benchmark.py --iterations 1000
```

The framework harness measures detection on fixed synthetic scenarios. The current
corpus adds one curated, synthetic PR-review role-spoofing example to the original
487 attacks; archived paper/review results describe the original corpus and have
not been regenerated for the added example. Its historical default result (8.6% attacks not detected; 95% benign pass) is not a live-agent exploit rate. Classifier validation and benchmark results are within-distribution; independent paraphrased, multilingual, encoded, long-context, and adaptive attacks remain important. [Raw evaluation outputs](eval/results/) and [training scripts](training/) are included for inspection.

[workshop/agent_console.py](workshop/agent_console.py) uses a local Ollama model with simulated page/email tools; blocked content is replaced with a known clean demo page. [examples/trust_issues_ui.py](examples/trust_issues_ui.py) animates a scripted conversation with a real Stage 3 verdict. Neither sends email. Use `examples/live_proxy_demo.py` for actual subprocess proxy traffic.

The [system demonstration paper](paper/EMNLP_Paper_Id_69_ShieldMCP_Demo_Track_AclPubCheck_Final.pdf) describes the research context. [HANDOFF.md](HANDOFF.md) records implementation status and verification boundaries.

## Citation

If ShieldMCP supports your work, please cite the published ACL paper. The EMNLP System Demonstrations paper is linked above; an official proceedings citation will be added with its Anthology entry.

```bibtex
@inproceedings{yergattikar-2026-securing,
  title = "Securing the Tool Layer: A Threat Taxonomy and Runtime Defense Framework for Model Context Protocol Deployments",
  author = "Yergattikar, Saurabh",
  booktitle = "Proceedings of the 64th Annual Meeting of the Association for Computational Linguistics (Volume 6: Industry Track)",
  year = "2026",
  pages = "865--871",
  publisher = "Association for Computational Linguistics",
  doi = "10.18653/v1/2026.acl-industry.58",
  url = "https://aclanthology.org/2026.acl-industry.58/"
}
```

## License

[Apache-2.0](LICENSE) covers ShieldMCP code and released classifier artifacts for research and commercial integration. **No separate ShieldMCP license fee is required**; retain the applicable license and attribution notices. The fine-tuned classifiers derive from the Apache-2.0 [DistilBERT base model](https://huggingface.co/distilbert/distilbert-base-uncased); see [model provenance](models/README.md).
