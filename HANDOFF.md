# ShieldMCP — Agent Handoff Document

**Last updated:** July 8, 2026  
**Repo path:** `/Users/saurabh_sharmila_nysa_mac/Desktop/ShieldMCP`  
**Paper:** *Securing the Tool Layer: A Threat Taxonomy and Runtime Defense Framework for Model Context Protocol Deployments*  
**Venue:** ACL 2026 Industry Track (accepted April 2026; poster July 2, 2026)

This document is the operational handoff for the next coding agent. Read this first, then `SYSTEM_DOCUMENTATION.md` for full paper-to-code traceability.

---

## 1. What This Project Is

ShieldMCP is a **transparent MCP security proxy** that validates:

1. **Stage 1** — tool descriptions (tool poisoning, rug pulls, supply chain)
2. **Stage 2** — outbound call parameters (SQL/shell/prompt injection, path traversal)
3. **Stage 3** — inbound tool responses (IPI, cross-tool chains, hidden instructions)

It does **not** modify the agent or MCP server. It intercepts JSON-RPC at the transport layer (stdio or SSE).

---

## 2. Current State (Honest Summary)

### Built and working

| Area | Status | Evidence |
|------|--------|----------|
| Core framework | Done | `src/shieldmcp/core/`, 3 stages, registry, alerts |
| Stdio proxy | Done | `src/shieldmcp/proxy/interceptor.py` |
| SSE proxy | Done | `src/shieldmcp/proxy/sse_proxy.py` |
| CLI | Done | `shieldmcp proxy`, `scan`, `init`, `registry`, `sse-proxy` |
| Classifier code | Done | `src/shieldmcp/classifiers/` (DistilBERT wrappers) |
| Training scripts + data | Done | `training/` — 11,600 Stage 1 + 7,000 Stage 3 samples |
| Eval harness | Done | 40 servers, 487 attack + 200 benign scenarios |
| Framework-only benchmark | Run | 8.6% ASR, 95% benign pass — `eval/results/output/framework_eval_results.json` |
| Latency benchmark | Run | `eval/benchmarks/latency_benchmark.py` → `latency_results.json` |
| Unit tests | 62 tests | `pytest tests/` — all pass on writable filesystem |
| Expert review tool | Done | `eval/expert_review/review_tool.py` |

### Not yet executed (code exists; needs runtime)

| Task | Command | Blocks paper claim? |
|------|---------|---------------------|
| Train Stage 1 classifier | `python training/train_stage1.py` | IPI ASR improvement (16.4% → ~6%) |
| Train Stage 3 classifier | `python training/train_stage3.py` | Same + latency numbers with classifier |
| Full LLM eval (5 models × 4 defenses) | `python eval/run_evaluation.py --full` | Table 2 baseline columns, model-specific ASR |
| Expert review (3 humans) | `python eval/expert_review/review_tool.py` | Section 4.3 agreement (92%) |

---

## 3. Repository Layout

```
ShieldMCP/
├── HANDOFF.md                    ← you are here
├── SYSTEM_DOCUMENTATION.md       ← paper claim ↔ code mapping (433 lines)
├── README.md                     ← user-facing quick start
├── pyproject.toml                ← pip install, optional [ml,eval,dev]
├── configs/default.yaml          ← default thresholds (τ_d=0.72, backends=heuristic)
│
├── src/shieldmcp/                ← main package (pip install -e .)
│   ├── core/                     pipeline, config, models, registry, alerts
│   ├── stage1/                   structural + semantic description checks
│   ├── stage2/                   parameter_sanitizer
│   ├── stage3/                   response_analyzer
│   ├── classifiers/              DistilBERT description + token classifiers
│   ├── proxy/                    StdioProxy, SSEProxy
│   └── cli.py                    entry point
│
├── eval/
│   ├── adversarial_servers/      15 servers (3 per attack family)
│   ├── benign_servers/           25 benign MCP servers
│   ├── scenarios/                487 attack + 200 benign scenario definitions
│   ├── harness/runner.py         EvalRunner orchestration
│   ├── baselines/                none, regex, llm_judge
│   ├── benchmarks/               latency_benchmark.py
│   ├── expert_review/            review_tool.py
│   ├── results/                  analyzer, visualizer
│   └── run_evaluation.py         main eval entry point
│
├── training/
│   ├── generate_stage1_data.py   → training/data/stage1_*.jsonl
│   ├── generate_stage3_data.py   → training/data/stage3_*.jsonl
│   ├── train_stage1.py           → models/stage1_classifier/
│   └── train_stage3.py           → models/stage3_token_classifier/
│
├── tests/unit/                   62 unit tests
└── examples/demo/                live demo runner
```

**Gitignored at runtime (not in repo):** `*.db`, `*.jsonl` (includes `training/data/*.jsonl` — regenerate with `generate_stage*.py`), `.venv/`, `__pycache__/`, trained model weights under `models/` (except `.gitkeep`).

---

## 4. Setup (First Commands)

```bash
cd /Users/saurabh_sharmila_nysa_mac/Desktop/ShieldMCP
python -m venv .venv && source .venv/bin/activate
pip install -e ".[all]"    # core + ML + eval + dev deps
```

Verify:

```bash
python -m pytest tests/ -v          # expect 62 passed
shieldmcp init                      # writes shieldmcp.yaml
```

---

## 5. Architecture (Where to Edit What)

| Goal | Primary files |
|------|---------------|
| Add detection pattern (Stage 1) | `src/shieldmcp/stage1/structural.py` |
| Tune semantic scoring | `src/shieldmcp/stage1/semantic.py`, `configs/default.yaml` |
| Parameter validation rules | `src/shieldmcp/stage2/parameter_sanitizer.py` |
| Response / IPI detection | `src/shieldmcp/stage3/response_analyzer.py` |
| Wire stages together | `src/shieldmcp/core/pipeline.py` |
| Proxy interception | `src/shieldmcp/proxy/interceptor.py`, `sse_proxy.py` |
| Config / thresholds | `src/shieldmcp/core/config.py`, `configs/default.yaml` |
| Attack scenarios | `eval/scenarios/attack_scenarios.py` |
| Benign scenarios | `eval/scenarios/benign_scenarios.py` |
| Eval orchestration | `eval/harness/runner.py`, `eval/run_evaluation.py` |

**Config backends (important):**

```yaml
stage1:
  semantic_backend: heuristic   # heuristic | llm_judge | classifier
stage3:
  instruction_detection_backend: heuristic   # heuristic | classifier
```

After training, switch to `classifier` and ensure models exist at:
- `models/stage1_classifier/`
- `models/stage3_token_classifier/`

---

## 6. Reproduce Known Results

### Framework-only eval (no API keys)

```bash
rm -f eval/results/output/*.db shieldmcp_registry.db
python eval/run_evaluation.py --framework-only
```

**Expected:**
- Overall ASR: **8.6%** (445/487 detected)
- Benign pass: **95.0%** (190/200)
- Per-family: TP 5.0%, IPI 16.4%, SC 20.0%, RP 0.0%, CT 0.0%

### Latency

```bash
python eval/benchmarks/latency_benchmark.py --iterations 1000
```

**Expected (heuristic backend):** ~5ms median end-to-end. Paper claims ~118ms with classifiers loaded.

### Quick eval smoke test

```bash
python eval/run_evaluation.py --quick
```

---

## 7. Pending Work (Priority Order)

### P0 — Before camera-ready / poster (June–July 2026)

1. **Train classifiers** (GPU recommended, 2–4h)
   ```bash
   pip install shieldmcp[ml]
   python training/train_stage1.py --epochs 5 --batch-size 32
   python training/train_stage3.py --epochs 5 --batch-size 16
   ```
   Then update `configs/default.yaml` backends to `classifier` and re-run framework eval.

2. **Full LLM evaluation** (~$200–400 API cost)
   ```bash
   export OPENAI_API_KEY=...
   export ANTHROPIC_API_KEY=...
   export TOGETHER_API_KEY=...
   python eval/run_evaluation.py --full
   ```
   Results → `eval/results/output/full_eval_results.json`

3. **Expert review** (optional but in paper)
   ```bash
   python eval/expert_review/review_tool.py \
     --results eval/results/output/framework_eval_results.json \
     --reviewer expert1 --num-samples 50
   ```

### P1 — Quality / polish

- Improve IPI detection (currently 16.4% ASR with heuristics; paper claims 5.8% with classifier)
- Add `.gitkeep` under `models/` after training; do not commit large `.bin`/`.safetensors` without LFS
- Consider backdating git history only if explicitly requested by author (do not do silently)

---

## 8. Known Issues and Gotchas

1. **Registry DB persists across eval runs** — stale rug-pull state can skew results. Always `rm -f eval/results/output/*.db shieldmcp_registry.db` before eval.

2. **Alert log writes** — tests fail with `PermissionError` on read-only filesystems because `alerts.log_all_alerts` writes `shieldmcp_alerts.jsonl`. Normal writable env: 62/62 pass.

3. **No git remote by default** — repo may be local-only until `gh auth login` + `gh repo create` or manual `git remote add origin`.

4. **IPI gap** — largest mismatch vs paper (16.4% vs 5.8%). Classifier training is the intended fix.

5. **Expert review** — tool is built; 92% agreement claim requires 3 human reviewers, not automation.

6. **SYSTEM_DOCUMENTATION.md timeline** — states "built January 2026"; actual git commits may differ. Treat code/results as source of truth.

---

## 9. Test Commands

```bash
python -m pytest tests/ -v
ruff check src/
python examples/demo/demo_runner.py
```

---

## 10. Git / Collaboration

**Branches:** `main` only (as of handoff).

**Recent commit themes:**
1. Initial three-stage framework + proxy + tests
2. Full eval infrastructure (487 + 200 scenarios)
3. Classifiers, SSE proxy, latency benchmark, expert review, docs

**To push to GitHub (if not already done):**

```bash
gh auth login
gh repo create ShieldMCP --private --source=. --remote=origin --push
# OR if remote exists:
git push -u origin main
```

**Do not commit:** `.env`, API keys, `shieldmcp_alerts.jsonl`, `*.db`, large trained weights without Git LFS.

---

## 11. Key Results Files

| File | Contents |
|------|----------|
| `eval/results/output/framework_eval_results.json` | Per-scenario detection (487 attacks + 200 benign) |
| `eval/results/output/latency_results.json` | Per-stage latency stats |
| `eval/results/output/full_eval_results.json` | Created after `--full` LLM eval (may not exist yet) |

---

## 12. Decision Guide for Next Agent

| User asks for… | Do this |
|----------------|---------|
| "Match paper Table 2" | Run `--full` eval with API keys; compare `eval/results/analyzer.py` output |
| "Fix IPI detection" | Train Stage 3 classifier; tune `response_analyzer.py` patterns |
| "Demo for poster" | `examples/demo/demo_runner.py` + `shieldmcp proxy -- ...` |
| "Camera-ready numbers" | Re-run eval after classifier training; update paper from JSON outputs |
| "Is claim X real?" | Check `SYSTEM_DOCUMENTATION.md` Part 1–5 mapping |

---

## 13. Related Documents

- **`SYSTEM_DOCUMENTATION.md`** — exhaustive paper ↔ system traceability (60 claims mapped)
- **`README.md`** — install and CLI usage
- **`configs/default.yaml`** — runtime configuration reference

---

## 14. Contact Context

This system backs an **ACL 2026 Industry Track poster** (July 2, 2026). The author needs the built system to substantiate paper claims. Prior conversation established:

- System is **real** (61 Python files, working tests, real eval JSON)
- **3 execution tasks** remain: train classifiers, full LLM eval, expert review
- Friend/reviewer verification focused on directory, file count, core code, and `framework_eval_results.json` — all present

**When in doubt:** run `pytest`, run `--framework-only` eval, read `SYSTEM_DOCUMENTATION.md` Part 4 (pending items).
