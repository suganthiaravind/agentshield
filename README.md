# AgentShield

Pre-production security evaluator for AI agents. Two-tier static analysis (semgrep) + LLM-as-scanner (Copilot).

**Status:** v2 architecture shipped (2026-05-06, branch `architecture-v2`). See [ARCHITECTURE_V2.md](./ARCHITECTURE_V2.md) for the design and [ROADMAP.md §3.9](./ROADMAP.md#39-phase-f--architecture-v2-2-tiers-copilot-as-scanner) for what landed in each phase.

## What it does

- **Tier 1** — semgrep with a 6-family high-precision rule pack (D001-fw, D003, D004, D005, D008, DF003) covering hardcoded LLM credentials, code-execution tools, LLM-output-to-eval sinks, untrusted system prompts, unsanitised user input → LLM, and unbounded LLM call timeouts. Python + Java parity.
- **Tier 2** — LLM-as-scanner via GitHub Copilot in your IDE. AgentShield emits a comprehensive 56-check skill file (OWASP LLM Top 10 v2 + OWASP Agentic AI Top 10 + MITRE ATLAS + 10 CWE first-class + 5 Phase E codebase-validated gaps) into `<repo>/.agentshield/`. Copilot reads it, walks every source file, writes findings to `tier2-findings.json`. No AWS dep.
- **Unified report** — `agentshield merge` combines both tiers into Markdown / JSON / SARIF, with stale-detection via fingerprint hash and Tier 2's TP/CD/FP cross-check on Tier 1 findings.

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

See [QUICKSTART_VDI.md](./QUICKSTART_VDI.md) for the focused cheat sheet. Full v2 flow:

```bash
# 1. Tier 1 scan + emit Tier 2 skill files
agentshield scan /path/to/your-agent-repo \
  --scan-all-files \
  --exclude '**/src/test/**' \
  --exclude '**/tests/**'

# 2. Tier 2 — open the repo in VS Code with Copilot Chat, paste the prompt
#    the CLI just printed. Copilot writes .agentshield/tier2-findings.json.

# 3. Unified Tier 1 + Tier 2 report
agentshield merge /path/to/your-agent-repo --output-markdown report.md
```

For the Copilot Tier 2 step in detail (exact prompt, sample output, trouble cases), see [COPILOT_LLM_SCAN_USAGE.md](./COPILOT_LLM_SCAN_USAGE.md).

## CLI reference

| Command | Purpose |
|---|---|
| `agentshield scan <path>` | Run Tier 1 (semgrep) and emit Tier 2 skill files into `<path>/.agentshield/` |
| `agentshield merge <path>` | Combine `tier1-results.json` + `tier2-findings.json` into a unified report |
| `agentshield --version` | Print version |

**`scan` flags:**
- `--scan-all-files` — bypass semgrep's `.semgrepignore` (recommended for production scans)
- `--exclude PATTERN` — drop files matching glob (repeatable). `'**/src/test/**'`, `'**/tests/**'`
- `--stage-locally` — copy source to local temp before scan; workaround for Windows UNC / mapped network drives (`H:\fusion\…`)
- `--no-emit` — Tier-1-only mode for diagnostics; skips skill-file emission
- `--output-{sarif,json,markdown}` — Tier-1-only report (the unified report is `agentshield merge --output-*`)
- `--debug` — verbose: rules path, files passed to semgrep, raw rule_ids of every finding

**`merge` flags:**
- `--output-{markdown,json,sarif}` — write unified report (Markdown is the primary deliverable)
- `--print` — also print the Markdown report to stdout

## Project layout

```
agentshield/
├── rules/                # 6 active semgrep rule families (Python + Java)
├── _retired_v2/          # 8 archived rule families (moved to Tier 2 checklist in F.2)
│   ├── README.md         #   why each was retired
│   └── rules/            #   YAML kept readable for reference
├── skills/               # bundled Tier 2 skill templates (the v2 product)
│   ├── tier2_bootstrap.md.tmpl
│   ├── tier2_checklist.md.tmpl       # 56 checks, 964 lines
│   └── tier2_output_schema.md.tmpl
├── emitter/              # F.4: copies skills into target, writes tier1-results.json
├── merger/               # F.5: combines tier1 + tier2, validates schema, detects stale
├── runner/               # semgrep subprocess wrapper
├── normalize/            # SARIF → Finding schema
├── report/               # SARIF / JSON / Markdown writers
└── cli.py                # entry point
```

## Documentation map

| Doc | When to read |
|---|---|
| [QUICKSTART_VDI.md](./QUICKSTART_VDI.md) | First time running v2 in a JPMC VDI — 5-minute cheat sheet |
| [COPILOT_LLM_SCAN_USAGE.md](./COPILOT_LLM_SCAN_USAGE.md) | Detailed Copilot walkthrough; trouble cases; CI considerations |
| [VDI_TESTING.md](./VDI_TESTING.md) | Comprehensive staged validation playbook with troubleshooting per stage |
| [ARCHITECTURE_V2.md](./ARCHITECTURE_V2.md) | The v2 design doc — why the architecture is what it is |
| [ROADMAP.md](./ROADMAP.md) | Canonical project state, phase-by-phase shipped record, strategic options |
| [research.md](./research.md) | Security frameworks (OWASP / Agentic / ATLAS / CWE / NIST) + how AgentShield maps to them, plus the OSS AI-agent-security tool landscape (Promptfoo, Garak, AgentDojo, Agentic Radar, etc.) |
| **Reference tab in the HTML report** | What every check (Semgrep + Copilot + Manifest) detects, with framework mappings. Auto-generated — run `agentshield merge --output-html report.html` and open the Reference tab; or open `report-print.html` for a printable list. |
| [GLOSSARY.md](./GLOSSARY.md) | Definitions for security terms used across the docs |

## Phase I scope

Static analysis + LLM-as-scanner. No runtime probing of live agents. Tier 1 languages: Python and Java. Tier 2 (Copilot): any language Copilot can read.

## License

Apache-2.0.
