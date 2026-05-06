# AgentShield v2 — VDI Quickstart

Status: 2026-05-06 (Phase F architecture v2)
For the comprehensive playbook with troubleshooting, see [VDI_TESTING.md](./VDI_TESTING.md).
For the Copilot Tier 2 walkthrough in detail, see [TIER2_USAGE.md](./TIER2_USAGE.md).

This is the 5-minute cheat sheet — the minimum commands to scan a real agent codebase end-to-end (Tier 1 + Tier 2 + unified report) inside a JPMC VDI.

---

## TL;DR — the full v2 flow

```bash
# 1. install (once per VDI)
git clone git@github.com:suganthiaravind/agentshield.git
cd agentshield && git checkout architecture-v2

python3.11 -m venv .venv && source .venv/bin/activate
pip install --upgrade pip && pip install -e ".[semgrep,dev]"
pytest tests/                              # confirm 123 passed

# 2. Tier 1 scan + emit Tier 2 skill files
agentshield scan /path/to/your-agent-repo \
  --scan-all-files \
  --exclude '**/src/test/**' \
  --exclude '**/tests/**' \
  --stage-locally    # only if the repo is on H:\ or another network drive

# 3. Tier 2 — open the repo in VS Code with Copilot Chat, paste the prompt
#    the CLI just printed. Wait for tier2-findings.json to appear.

# 4. unified report
agentshield merge /path/to/your-agent-repo --output-markdown report.md
less report.md
```

That's it. Three commands and one Copilot Chat paste. Everything below is detail on each step.

---

## Prerequisites (run once per VDI)

```bash
python3 --version          # need 3.10+; if shell default is 3.9, find a newer one:
ls /usr/local/bin/python3.* /opt/homebrew/bin/python3.* 2>/dev/null
git --version
```

For Tier 2: an IDE with GitHub Copilot Chat enabled — VS Code or JetBrains. (No CLI prerequisite for Tier 2 itself; Copilot runs inside your IDE.)

---

## Step 1 — install (once per VDI)

The complete install + verify sequence:

```bash
# Pull the architecture-v2 branch
git clone git@github.com:suganthiaravind/agentshield.git
cd agentshield && git checkout architecture-v2

# Install
python3.11 -m venv .venv && source .venv/bin/activate
pip install --upgrade pip && pip install -e ".[semgrep,dev]"
pytest tests/                              # confirm 123 passed
```

**What each line does:**

- `git clone … && git checkout architecture-v2` — pulls v2 (until it merges to `main`).
- `python3.11 -m venv .venv` — uses Python 3.11 specifically; substitute `python3.10` / `python3.12` if that's what your VDI has. **3.10+ is required.**
- `source .venv/bin/activate` — every subsequent command in this terminal session uses the venv's Python and `agentshield` CLI.
- `pip install -e ".[semgrep,dev]"` — installs AgentShield in editable mode plus semgrep (mandatory for Tier 1) plus dev tools (pytest). ~1-2 min; semgrep is the bulk.
- `pytest tests/` — runs the full test suite. **Must show 123 passed.** If anything fails, stop and report — the install is broken on your VDI; nothing later will work right.

**Additional sanity checks:**

```bash
agentshield --version                  # → agentshield 0.1.0
which agentshield                      # → <repo>/.venv/bin/agentshield
which semgrep                          # → <repo>/.venv/bin/semgrep
```

**Refreshing later:** when new commits land on `architecture-v2` (or v2 merges to `main`):

```bash
cd /path/to/your/agentshield/clone
source .venv/bin/activate
git fetch origin && git pull
pip install -e ".[semgrep,dev]"        # in case dependencies changed
pytest tests/                          # confirm green on your VDI Python
```

---

## Step 2 — Tier 1 scan against your real agent repo

```bash
agentshield scan /path/to/your-agent-repo \
  --scan-all-files \
  --exclude '**/src/test/**' \
  --exclude '**/tests/**'
```

Add `--stage-locally` if `/path/to/your-agent-repo` is on a network drive (e.g. `H:\fusion\<project>`) — semgrep silently fails on UNC paths without it.

**Recommended invocations by repo type:**

| Repo type | Command |
|---|---|
| Python langchain / SMARTSDK on local filesystem | `agentshield scan /path/to/repo --scan-all-files --exclude '**/tests/**'` |
| Java Spring AI / langchain4j on local filesystem | `agentshield scan /path/to/repo --scan-all-files --exclude '**/src/test/**'` |
| Anything on `H:\` or `\\server\share\` | add `--stage-locally` to whichever of the above applies |
| Mixed Python + Java | `agentshield scan ... --exclude '**/src/test/**' --exclude '**/tests/**'` |

**What you'll see (Tier 1 output):**

```
[agentshield] candidate files: N (.py / .java)
[agentshield] Tier 1: invoking semgrep on bundled rule pack (6 families)...
[agentshield] Tier 1: M raw finding(s)
[agentshield] Normalized: M finding(s) detect=A defend=B respond=C

======================================================================
⚠ TIER 2 NOT YET RUN — scanning is INCOMPLETE.
======================================================================

Skill files written:
  - .agentshield/tier2-bootstrap.md
  - .agentshield/tier2-checklist.md
  - .agentshield/tier2-output-schema.md
  - .agentshield/tier1-results.json
  + appended .agentshield/ to /path/to/your-agent-repo/.gitignore

Next step — paste this into Copilot Chat in your IDE:
----------------------------------------------------------------------
@workspace Please run AgentShield Tier 2.
... (full prompt) ...
----------------------------------------------------------------------

Then run:  agentshield merge /path/to/your-agent-repo
```

**Verify Tier 1 output exists:**

```bash
ls /path/to/your-agent-repo/.agentshield/
# Expected: tier1-results.json, tier2-bootstrap.md, tier2-checklist.md, tier2-output-schema.md
```

If `Normalized: 0 finding(s)` and the repo definitely has LLM code: re-check the `--exclude` patterns aren't dropping production files. Pass `--debug` to see exactly which files semgrep scanned.

---

## Step 3 — Tier 2 in Copilot Chat

In your VDI's IDE (VS Code or JetBrains):

1. **Open the repo folder.** Same path you scanned: `/path/to/your-agent-repo`.
2. **Open Copilot Chat.** VS Code: `Ctrl+Shift+I` (or `Cmd+Shift+I` on Mac). JetBrains: AI Assistant tool window.
3. **Paste this prompt** (the CLI also printed it after Step 2):

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

4. **Wait.** Time depends on repo size:
   - 5-10 source files → ~1-2 min
   - 20-50 files → ~5-10 min
   - 100+ files → 15+ min, may need chunking

5. **Verify Copilot wrote the file:**

   ```bash
   ls /path/to/your-agent-repo/.agentshield/tier2-findings.json
   # Should exist and be a JSON file > 1 KB
   ```

**If Copilot says "done" but the file isn't there:** re-prompt explicitly:
> "You said you finished but `.agentshield/tier2-findings.json` doesn't exist. Please write the JSON output to that path."

**If Copilot only scanned the active editor file:** re-prompt:
> "Use `@workspace` to enumerate every `.py`, `.java`, `.ts` file in this repo. Walk them all, not just the open editor file."

For more trouble cases, see [TIER2_USAGE.md "Trouble cases" section](./TIER2_USAGE.md#trouble-cases-and-how-to-handle-them).

---

## Step 4 — merge into the unified report

```bash
agentshield merge /path/to/your-agent-repo \
  --output-markdown report.md \
  --output-json report.json \
  --output-sarif report.sarif
```

**What you'll see:**

```
[agentshield] merge target: /path/to/your-agent-repo
[agentshield] ✓ Tier 1 + Tier 2 fresh; merging.
[agentshield] Net actionable findings: N
[agentshield] Wrote unified report(s): report.md, report.json, report.sarif
```

**Possible alternative banners:**

| Banner | Meaning | Fix |
|---|---|---|
| `⚠ Tier 2 has NOT been run` | `tier2-findings.json` missing | Re-do Step 3 |
| `❌ Tier 2 output failed schema validation` | Copilot's JSON is malformed | Re-prompt Copilot citing the field-path errors the merger printed |
| `⚠ STALE Tier 2: fingerprint mismatch` | Code or rules changed between Steps 2 and 3 | Re-do Step 3 (or rarely: re-prompt Copilot to copy the fingerprint correctly from `tier1-results.json`) |

**Open the report:**

```bash
less report.md
```

The Markdown contains:

1. **Summary** — Tier 1 count, Tier 2 net-new count, FP-marked count, **net actionable**
2. **Tier 1 findings** — each annotated with Tier 2's TP/CD/FP verdict + reasoning
3. **Tier 2 net-new findings** — what static rules missed
4. **Coverage matrix** — which OWASP LLM v2 / Agentic AI / ATLAS / CWE items the scan touched

---

## Step 5 — privacy review before sharing

The reports include code snippets, file paths, variable names, and Copilot's reasoning text. If the codebase is JPMC-internal, redact before sharing externally:

- Internal hostnames / endpoints in code snippets
- Internal package names (e.g. `com.jpmchase.<line-of-business>.<system>`)
- Hardcoded credentials caught by D005 — redact the actual key value before sharing the snippet
- Tier 2 reasoning text (Copilot's interpretation of code intent — review for inadvertent disclosure)

The structural counts (rule fired, finding totals, coverage matrix) are fine to share even from proprietary codebases.

---

## What to capture and share back

For every codebase you scan, share these 4 things:

1. **The unified report Markdown** (`report.md`) — primary deliverable.
2. **The Tier 1 finding count** from Step 2 (CLI output line: `Normalized: N finding(s)`).
3. **The Tier 2 finding count** (visible in the report's Summary section).
4. **Anything weird:** Copilot hallucinations, schema errors that needed re-prompting, fingerprint mismatch causes, files Copilot put in `skipped_files`.

---

## One-pager for terminal cheat sheet

```bash
# Install (once per VDI)
git clone git@github.com:suganthiaravind/agentshield.git
cd agentshield && git checkout architecture-v2
python3.11 -m venv .venv && source .venv/bin/activate
pip install --upgrade pip && pip install -e ".[semgrep,dev]"
pytest tests/                              # confirm 123 passed

# Scan
agentshield scan <repo> --scan-all-files \
  --exclude '**/src/test/**' --exclude '**/tests/**'

# Copilot Chat (in IDE):
#   @workspace Please run AgentShield Tier 2. ... (paste from CLI output)

# Merge
agentshield merge <repo> --output-markdown report.md

# Inspect
less report.md
```

That's the full v2 user journey.
