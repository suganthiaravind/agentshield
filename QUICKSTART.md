# AgentShield — Quick Start

Complete end-to-end scan in four steps. Copy-paste each block in order.

---

## Before you begin — clone AgentShield

```bash
git clone https://github.com/your-org/agentshield.git
cd agentshield
```

> You are now inside the AgentShield repo. This file (`QUICKSTART.md`) is here.

---

## 0 — Set your target repo path

```bash
export REPO=/absolute/path/to/your-agent-repo
```

> Replace the path with the real location of the agent you want to scan.  
> Every command below reads `$REPO` — set it once, run everything.

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

Semgrep runs 70+ security rules. Skill files are written to `$REPO/.agentshield/`.

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

If two or more distinct pipeline configurations exist, use the
entry_points[] schema (see output schema). Each entry point
block must contain all 17 attack-class traces evaluated
independently against that entry point's pipeline. An attack
blocked by a filter on one route may land on a sibling route
without a filter — do not share verdicts across entry points.

Then classify the agent type: interactive, batch, sub-agent,
or orchestrator. Walk each entry point's pipeline from source
code. For each applicable catalogued attack class, identify the
pipeline step(s) it targets, predict the pipeline behaviour
under that attack for each entry point, and cite the file:line
evidence for every prediction.

Use the GENERIC catalogue payloads exactly as shipped — do not
adapt the attacker-side text from source code. The intelligence
comes from what the agent reveals, not from what you read in
the repo.

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

Combines Tier 1 + Tier 2 + behaviour emulator into a single report.  
Output lands in `output/` inside your current working directory:

```
output/
├── agentshield-report.html            ← interactive (tabs, filter, search, Reference)
├── agentshield-report-print.html      ← printable / stacked view
├── agentshield-findings-fix.md        ← paste into Claude Code to fix all findings
└── agentshield-emulator-payloads.md   ← emulator attack walkthroughs per source × transition
```

Open the report:
```bash
open output/agentshield-report.html          # macOS
# start output/agentshield-report.html       # Windows
# xdg-open output/agentshield-report.html    # Linux
```

**Done when you see:** `[agentshield] Wrote unified report(s): output/agentshield-report.html`

---

## 6 — Check report health

```bash
agentshield check $REPO
```

Runs 14 automated checks against the merged artifacts and prints a ✓/✗ checklist:

| # | Check | What it catches |
|---|---|---|
| 1 | Schema validation | Broken tier2-findings.json suppressing all Tier 2 results |
| 2 | Tier 2 present | Merge run before Copilot finished |
| 3 | Fingerprint match | Stale Tier 2 after a re-scan (STALE banner) |
| 4 | Classification complete | `tier1_fp_callouts` covering 0 of N findings (PARTIAL banner) |
| 5 | Callout fields complete | Missing `file` / `line` / `tier1_rule` in any callout |
| 6 | Attack narrative coverage | Findings with no "How it lands" / "What the attacker gets" |
| 7 | Emulator payload count | Header count mismatches actual `###` sections in the `.md` |
| 8 | Emulator payloads purity | Semgrep/Copilot findings leaked into the emulator walkthrough |
| 9–12 | Output files exist | Any of the four output files missing or empty |
| 13 | Actionable count > 0 | Merge ran against the wrong target |
| 14 | Origins recognised | Unknown filter-chip origin values |

**Done when you see:** `✓  Report health: 14/14  —  ALL CHECKS PASSED`

If any check fails the command exits 1 and prints the fix hint:
```
Fix the ✗ items above, then re-run:
  agentshield merge $REPO  &&  agentshield check $REPO
```

> **For the demo agent** the path is `testbed/demo-agent`:
> ```bash
> agentshield check testbed/demo-agent
> ```

---

## Summary

| Step | What | Where |
|---|---|---|
| 0 | `export REPO=…` | Terminal |
| 1 | `pip install -e ".[semgrep,dev]"` | Terminal |
| 2 | `agentshield scan $REPO --scan-all-files` | Terminal |
| 3 | Paste **Tier 2 prompt** into Copilot Chat | VS Code |
| 4 | Paste **behaviour emulator prompt** into Copilot Chat | VS Code |
| 5 | `agentshield merge $REPO` → open `output/agentshield-report.html` | Terminal |
| 6 | `agentshield check $REPO` → all 14 checks green | Terminal |

For flags, troubleshooting, CI integration, and full Tier 2 guidance see [EXECUTE_AGENTSHIELD.md](./EXECUTE_AGENTSHIELD.md).
