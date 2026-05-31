# AgentShield — Quick Start

Complete end-to-end scan in four steps. Copy-paste each block in order.

---

## Before you begin — clone AgentShield

```bash
git clone git@github.com:suganthiaravind/agentshield.git
cd agentshield
git checkout v6
```

> You are now inside the AgentShield repo. This file is at `run/QUICKSTART.md`.

---

## 0 — Set your target repo path

```bash
export REPO=/absolute/path/to/your-agent-repo
```

> Replace the path with the real location of the agent you want to scan.  
> Every command below reads `$REPO` — set it once, run everything.

---

## 0.1 — Windows / VDI: one-command runner *(optional)*

> Use this if you are on a **Windows VDI** (e.g. JPMC desktop) where roaming-profile PATH restrictions or Unicode encoding issues block the normal CLI flow. On a standard Mac/Linux machine skip this section entirely.

**Pre-requisite:** open the **AgentShield repo** in your IDE (VS Code / JetBrains), not the target repo.

```powershell
# From the AgentShield repo root in a PowerShell terminal:
.\run\run_tier1.ps1 -RepoPath "H:\path\to\your-agent-repo"
```

What it does automatically:

| Step | Action |
|------|--------|
| Preflight | Sets console encoding to UTF-8; relocates `semgrep.exe` from the blocked roaming profile to `%LOCALAPPDATA%\agentshield-bin` |
| Install | `pip install -e ".[semgrep,dev]"` (skipped if already installed) |
| Scan | `agentshield scan <RepoPath> --scan-all-files` |
| Prompts | Calls `generate_copilot_prompts.ps1` and copies the **Tier 2** prompt to your clipboard |

**Done when you see:** `[done] Tier 1 complete.` and `[prompts] Tier 2 prompt copied to clipboard.`

Switch to VS Code → Copilot Chat → paste (Ctrl+V) to run Tier 2 (step 3 below).

To generate the emulator prompt separately:

```powershell
.\run\generate_copilot_prompts.ps1 -RepoPath "H:\path\to\your-agent-repo" -Mode Emulator -CopyToClipboard
```

Flags for `run_tier1.ps1`:

| Flag | Effect |
|------|--------|
| `-SkipInstall` | Skip the `pip install` check |

---

## 1 — Install AgentShield

```bash
agentshield --version 2>/dev/null || pip install -e ".[semgrep,dev]"
```

**Done when you see:** `agentshield 4.x.x`

---

## 2 — Tier 1: static scan

```bash
agentshield scan $REPO --scan-all-files
```

Runs 19 Semgrep rules (Python & Java AST) + 12 Manifest scanner rules (SKILL.md / AGENT.md). Skill files are written to `$REPO/.agentshield/`.

**Done when you see:** `[agentshield] ✓ Skill files → .agentshield/`

---

## 3 — Tier 2: Copilot LLM scan *(VS Code + Copilot Chat)*

1. Open `$REPO` in **VS Code** with **GitHub Copilot Chat** active.
2. Paste this prompt verbatim into Copilot Chat:

```
@workspace Please run AgentShield Tier 2.

Read the checklist at .agentshield/tier2-checklist.md and the
output schema at .agentshield/tier2-output-schema.md. Walk every
source file in this workspace, apply each check that is in scope
for the file's language, and write your findings to
.agentshield/tier2-findings.json following the schema exactly.

Also read .agentshield/tier1-results.json and add a
tier1_fp_callouts section noting any Tier 1 finding you believe
is a false positive, with reasoning.

Important: copy the agentshield_tier1_fingerprint field from
tier1-results.json verbatim into your output. The merger uses it
to detect stale Tier 2 runs.
```

3. Wait for Copilot to finish (single file ~30 s, 10 files ~2 min, 50 files ~10 min).
4. **Done when:** `$REPO/.agentshield/tier2-findings.json` exists.

If the file doesn't appear after Copilot says it's done, follow up:
> "You said you finished but `.agentshield/tier2-findings.json` doesn't exist. Please write the JSON output to that path."

---

## 4 — Phase 2: behaviour emulator *(VS Code + Copilot Chat)*

Still in the same VS Code window. Paste this prompt into Copilot Chat:

```
@workspace Please run the AgentShield agent behaviour emulator.

Read the instructions at
.agentshield/agent-emulator-instructions.md and the output
schema at .agentshield/agent-emulator-output-schema.md.

Step 0 — Enumerate entry points first (mandatory).
Before classifying the agent type, list every distinct entry
point in the codebase: all HTTP route handlers (@app.route,
FastAPI path ops), WebSocket handlers, Lambda handlers,
scheduled-job triggers, and inter-agent receivers. For each
entry point, note whether it has an input filter, whether it
calls chain.invoke, whether it has a system prompt, whether it
has tools, and whether it forwards to a downstream agent.
Group entry points that share an identical pipeline
configuration — entry points with ANY pipeline difference get
their own block.

Then classify the agent type: interactive, batch, sub-agent,
or orchestrator. Map the 8 pipeline steps from source code.
Enumerate every untrusted data source the agent reads (user
input, RAG documents, tool outputs, sub-agent messages).
For each source, trace it through 4 security transitions
(→LLM, →tool-args, →sink, →store) and record a verdict with
file:line evidence. Do not share verdicts across entry points
— a control on one route does not protect a sibling route.
Finally, evaluate the 5 pipeline-level checks.

Write your pipeline emulations to
.agentshield/agent-emulation.json following the schema exactly.
Mark inconclusive when the relevant pipeline step isn't present
— do not fabricate behaviour.
```

Wait for Copilot to finish (1 entry point ~5 min, 3–5 entry points ~15 min).

**Done when:** `$REPO/.agentshield/agent-emulation.json` exists.

If the file doesn't appear:
> "You said you finished but `.agentshield/agent-emulation.json` doesn't exist. Please write the JSON output to that path."

---

## 5 — Merge → unified report

```bash
agentshield merge $REPO
```

Combines Tier 1 + Tier 2 + behaviour emulator into a single report, then automatically runs all 14 health checks. Output lands in a timestamped subfolder inside your **target repo's** `output/` folder:

```
$REPO/output/
├── 20260530-123456/
│   ├── agentshield-report.html            ← interactive (tabs, filter, search, Reference)
│   ├── agentshield-report-print.html      ← printable / stacked view
│   ├── agentshield-findings-fix.md        ← paste into Claude Code to fix all findings
│   └── agentshield-emulator-payloads.md   ← emulator attack walkthroughs per source × transition
└── agentshield-report.html                ← "latest" copy, always reflects the most recent run
```

Open the report:
```bash
open $REPO/output/agentshield-report.html          # macOS
# start %REPO%\output\agentshield-report.html      # Windows
# xdg-open $REPO/output/agentshield-report.html    # Linux
```

**Done when you see:** `✓  Report health: 14/14  —  ALL CHECKS PASSED`

---

## Summary

| Step | What | Where |
|---|---|---|
| 0 | `export REPO=…` (Mac/Linux) | Terminal |
| 0.1 | `.\run\run_tier1.ps1 -RepoPath "…"` **(Windows/VDI only — does steps 1+2 automatically)** | PowerShell |
| 1 | `pip install -e ".[semgrep,dev]"` | Terminal |
| 2 | `agentshield scan $REPO --scan-all-files` | Terminal |
| 3 | Paste **Tier 2 prompt** into Copilot Chat | VS Code |
| 4 | Paste **behaviour emulator prompt** into Copilot Chat | VS Code |
| 5 | `agentshield merge $REPO` → `✓ 14/14` → open `output/agentshield-report.html` | Terminal |

For flags, troubleshooting, CI integration (`--require-fresh`), and full Tier 2 guidance see [EXECUTE_AGENTSHIELD.md](./EXECUTE_AGENTSHIELD.md).
