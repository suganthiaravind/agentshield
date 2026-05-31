# AgentShield

Pre-production security evaluator for AI agents. Two-tier static analysis (semgrep) + LLM-as-scanner (Copilot).

**Status:** v2 architecture shipped on the `architecture-v2` branch. See [ARCHITECTURE_V2.md](./ARCHITECTURE_V2.md) for the current design; `git log --oneline architecture-v2` shows the phase-by-phase shipped history.

## What it does

- **Tier 1** — semgrep with a 10-family high-precision rule pack (D001, D003–D005, D008–D012, DF003) covering hardcoded LLM credentials, code-execution tools, LLM-output-to-eval sinks, untrusted system prompts, unsanitised user input → LLM, prompt-injection markers in stored prompts, non-HTTPS outbound fetches, and unbounded LLM call timeouts. Python + Java parity.
- **Tier 2** — LLM-as-scanner via GitHub Copilot in your IDE. AgentShield emits a 62-control skill file (OWASP LLM Top 10 v2 + OWASP Agentic AI Top 10 + MITRE ATLAS + CWE first-class + Phase E gaps + Tier 1 cross-check) into `<repo>/.agentshield/`. Copilot reads it, walks every source file, writes findings to `tier2-findings.json`. No AWS dep.
- **Probe** — `agentshield probe` fires live adversarial tests at a running agent endpoint: verify mode (replays static-finding payloads), explore mode (LLM brainstorms 13 attack classes + fires them), and campaign mode (multi-turn attacks with mutation-on-block; agent behaviour emulator runs offline when no live target is configured).
- **Unified report** — `agentshield merge` combines all sources into Markdown / JSON / SARIF, with stale-detection via fingerprint hash, Tier 2's TP/CD/FP cross-check on Tier 1 findings, and probe-discovered / campaign kill-chain sections.

Recognises JPMC's wrapper SDKs (SMARTSDK wrapping Google ADK, RAD SDK wrapping LlamaIndex) plus LangChain, LangGraph, langchain4j, Spring AI, AWS Bedrock direct, Azure OpenAI Java SDK.

## Install

```bash
git clone git@github.com:suganthiaravind/agentshield.git
cd agentshield
git checkout architecture-v2          # until v2 merges to main

python3.11 -m venv .venv               # need Python 3.10+
source .venv/bin/activate

pip install --upgrade pip
pip install -e ".[semgrep,dev]"        # semgrep is mandatory; dev = pytest + ruff + mypy
```

## Quickstart (5 minutes)

**Step-by-step guide:** [run/QUICKSTART.md](./run/QUICKSTART.md) — covers Mac/Linux and Windows/VDI.

See [EXECUTE_AGENTSHIELD.md](./EXECUTE_AGENTSHIELD.md) for flags, CI integration, and troubleshooting. Full v2 flow:

```bash
# 1. Tier 1 scan + emit Tier 2 skill files
agentshield scan /path/to/your-agent-repo \
  --scan-all-files \
  --exclude '**/src/test/**' \
  --exclude '**/tests/**'

# 2. Tier 2 — open the repo in VS Code with Copilot Chat, paste the prompt
#    the CLI just printed. Copilot writes .agentshield/tier2-findings.json.

# 3. (Optional) Probe — live adversarial tests against a running agent
agentshield probe /path/to/your-agent-repo \
  --mode explore \
  --target http://localhost:8080/api/agent

# 4. Unified report (picks up Tier 1 + Tier 2 + any probe results)
agentshield merge /path/to/your-agent-repo --output-markdown report.md
```

For the Copilot Tier 2 step in detail (architectural overview + sample output) see [ARCHITECTURE_V2.md §2.2](./ARCHITECTURE_V2.md). For the probe command see [ARCHITECTURE_V2.md §2.4](./ARCHITECTURE_V2.md). For trouble cases (Copilot misbehaviour, schema errors, etc.) see [EXECUTE_AGENTSHIELD.md §12.3](./EXECUTE_AGENTSHIELD.md).

## CLI reference

| Command | Purpose |
|---|---|
| `agentshield scan <path>` | Run Tier 1 (semgrep) + AST10 and emit Tier 2 skill files into `<path>/.agentshield/` |
| `agentshield merge <path>` | Combine tier1 + tier2 + probe results into a unified report |
| `agentshield probe <path>` | Run live adversarial tests (verify / explore / campaign) against a running agent |
| `agentshield --version` | Print version |

**`scan` flags:**
- `--scan-all-files` — bypass semgrep's `.semgrepignore` (recommended for production scans)
- `--exclude PATTERN` — drop files matching glob (repeatable). `'**/src/test/**'`, `'**/tests/**'`
- `--stage-locally` — copy source to local temp before scan; workaround for Windows UNC / mapped network drives (`H:\fusion\…`)
- `--no-emit` — Tier-1-only mode for diagnostics; skips skill-file emission
- `--output-{sarif,json,markdown}` — Tier-1-only report (the unified report is `agentshield merge --output-*`)
- `--debug` — verbose: rules path, files passed to semgrep, raw rule_ids of every finding

**`merge` flags:**
- `--output-{markdown,json,sarif,html}` — write unified report (Markdown is the primary deliverable; `--output-html` emits both `report.html` and `report-print.html`)
- `--print` — also print the Markdown report to stdout
- `--open` — launch the HTML report in the default browser after writing

**`probe` flags:**
- `--mode {verify,explore,campaign}` — select probe mode (default: `verify`)
- `--target URL` — agent endpoint to attack; required for `verify` and `explore`
- `--debug` — verbose: payloads sent, responses received, verdict per turn

## Project layout

```
agentshield/
├── rules/                # 10 active semgrep rule families (Python + Java)
├── _retired_v2/          # archived rule families (moved to Tier 2 checklist)
│   ├── README.md         #   why each was retired
│   └── rules/            #   YAML kept readable for reference
├── skills/               # bundled Tier 2 skill templates (the v2 product)
│   ├── tier2_bootstrap.md.tmpl
│   ├── tier2_checklist.md.tmpl       # 62 controls
│   └── tier2_output_schema.md.tmpl
├── emitter/              # F.4: copies skills into target, writes tier1-results.json
├── merger/               # F.5: combines tier1 + tier2 + probe results, validates schema
├── probe/                # live adversarial testing (verify / explore / campaign)
│   ├── orchestrator.py   #   probe runner
│   ├── explore.py        #   13-attack exploratory catalogue + adversarial generator
│   └── campaign.py       #   multi-turn campaigns with mutation-on-block
├── runner/               # semgrep subprocess wrapper
├── normalize/            # SARIF → Finding schema
├── report/               # SARIF / JSON / Markdown writers
└── cli.py                # entry point
```

## Documentation map

| Doc | When to read |
|---|---|
| [EXECUTE_AGENTSHIELD.md](./EXECUTE_AGENTSHIELD.md) | Install + execution guide (VDI-friendly); the only doc you need to run AgentShield from scratch |
| [ARCHITECTURE_V2.md](./ARCHITECTURE_V2.md) | The v2 design doc — why the architecture is what it is |
| [research.md](./research.md) | Security frameworks (OWASP / Agentic / ATLAS / CWE / NIST) + how AgentShield maps to them, plus the OSS AI-agent-security tool landscape (Promptfoo, Garak, AgentDojo, Agentic Radar, etc.) |
| **Reference tab in the HTML report** | What every check (Semgrep + Copilot + Manifest) detects, with framework mappings. Auto-generated — run `agentshield merge --output-html report.html` and open the Reference tab; or open `report-print.html` for a printable list. |
| [GLOSSARY.md](./GLOSSARY.md) | Definitions for security terms used across the docs |

## Scope

Static analysis (Tier 1 + AST10) + LLM-as-scanner (Tier 2) + live adversarial probe (Tier 3). Tier 1 languages: Python and Java. Tier 2 (Copilot): any language Copilot can read. Probe (`agentshield probe`): any agent reachable via HTTP. Not a continuous autonomous red-team service — see [ARCHITECTURE_V2.md §10](./ARCHITECTURE_V2.md) for non-goals.

## License

Apache-2.0.
