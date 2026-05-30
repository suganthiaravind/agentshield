# Executing AgentShield — install + run guide (VDI-friendly)

Status: 2026-05-30 — current.
Companion to: [README.md](./README.md) (product overview), [ARCHITECTURE_V2.md](./ARCHITECTURE_V2.md) (how the pieces fit; Tier 2 / Copilot LLM Scan detail in §2.2).

This is the only file you need to install and run AgentShield in a JPMC VDI (or any locked-down environment). Top-to-bottom; copy-paste-able.

---

## 1. At a glance

| Step | What | Time |
|---|---|---|
| §3 | Verify prerequisites (Python 3.10+, git, pip, Copilot Chat) | 1 min |
| §4 | Configure VDI proxy (only if `pip install` is blocked) | 2 min |
| §5 | Install AgentShield (clone, venv, `pip install -e .`) | 3 min |
| §6 | Verify install (`agentshield --version`, optional unit tests) | 1 min |
| §7.1 | Tier 1 scan: Semgrep + AST10 manifest scanner | 1–3 min |
| §7.2 | Tier 2: Copilot LLM Scan (paste prompt into Copilot Chat) | 5–15 min |
| §7.3 | Phase 2: Behaviour emulator (paste prompt into Copilot Chat) | 5–15 min |
| §7.4 | Merge → unified HTML report + auto health check (14/14) | 30 s |
| §7.5 | Open the report in a browser (localhost or `file://`) | 30 s |
| §8 | Privacy review before sharing | 2 min |

Subsequent runs skip §3–§6. The scan-and-merge loop is just §7 + §8.

---

## 2. The architecture in one sentence

AgentShield runs three scanners — **Semgrep** (Python/Java static rules), **AST10 manifest scanner** (`SKILL.md` package checks), and **Copilot LLM Scan** (semantic file-by-file walk via Copilot Chat in your IDE) — and a **merger** that combines all three into a single HTML / Markdown / JSON / SARIF report. The first two run automatically; the third is an IDE step that takes a developer pasting one prompt.

---

## 3. Prerequisites

| Need | Why | Check |
|---|---|---|
| **Python 3.10 or newer** | runtime + Semgrep | `python3.11 --version`, `python3.12 --version`, `py --version` |
| **git** | clone + pull | `git --version` |
| **pip** (matching Python) | install AgentShield | `python3.11 -m pip --version` |
| **~150 MB free disk** | repo + venv + Semgrep + cached dependencies | — |
| **GitHub Copilot Chat in VS Code or JetBrains** | Tier 2 (Copilot LLM Scan) — without it, Tier 2 can't run | open VS Code → ensure the Copilot Chat extension is installed and signed in |
| **Browser** | view the HTML report (Edge / Chrome / Firefox — anything modern) | — |

If `python3.10+` isn't on PATH, ask your VDI admin to provision it. AgentShield fails fast with a clear message if the interpreter is too old.

**No outbound network is required at runtime.** AgentShield never makes API calls. Tier 2 uses your IDE's Copilot license — that traffic is between Copilot and Microsoft, not AgentShield.

---

## 4. VDI proxy / network setup (only if needed)

The only network step in the whole flow is `pip install` reaching PyPI to fetch dependencies. If your VDI requires an HTTPS proxy:

```bash
# Option A — per-command (one-shot)
pip install --proxy http://proxy.jpmchase.net:8080 -e ".[semgrep,dev]"

# Option B — persistent (recommended)
pip config set global.proxy http://proxy.jpmchase.net:8080
pip config set global.cert /path/to/JPMC-CA-bundle.pem    # if HTTPS-inspecting MITM proxy
pip config set global.index-url https://repo.jpmchase.com/artifactory/api/pypi/pypi-virtual/simple/
```

Verify before continuing:
```bash
pip config list      # Shows the values pip will use
pip search numpy     # Quick "can pip reach an index?" smoke test
```

If your VDI uses an internal Artifactory mirror (typical at JPMC), `index-url` above points at it; PyPI itself is usually firewalled.

---

## 5. Install

### 5.1 Clone the repo

```bash
# pick a working directory (anywhere outside .agentshield/)
cd ~/work
git clone git@github.com:suganthiaravind/agentshield.git
cd agentshield
git checkout v6
```

### 5.2 Create a virtual environment

```bash
python3.11 -m venv .venv         # use whichever Python 3.10+ you have
source .venv/bin/activate        # macOS / Linux
# .venv\Scripts\activate         # Windows PowerShell
```

You should see `(.venv)` in your prompt.

### 5.3 Install AgentShield + dependencies

```bash
pip install --upgrade pip
pip install -e ".[semgrep,dev]"
```

Extras explained:
- `semgrep` — installs `semgrep` so Tier 1 can run. **Mandatory.**
- `dev` — installs `pytest`, `ruff`, `mypy` for running tests and linting. Optional but small (~30 MB), and you'll want it for `§6.2`.

This pulls a few packages (Semgrep itself is ~80 MB). On a fast VDI ~3 min; on a slow one expect up to 10 min.

---

## 6. Verify the install

### 6.1 `agentshield --version`

```bash
agentshield --version
# AgentShield 0.1.0
```

If you get `command not found`, the venv isn't activated — re-run `source .venv/bin/activate`.

### 6.2 Unit tests (optional — runs entirely offline, ~30 s)

```bash
pytest -q
# 214 passed in 32s
```

If pytest reports any failures: copy the failing test names, the bottom of the trace, and your Python version into a Slack thread for triage. **Don't proceed with a real scan until this is green.**

### 6.3 Smoke test on the bundled fixture (optional — ~5 s)

```bash
agentshield scan testbed/demo-agent --no-emit
# [agentshield] Tier 1: 9 raw finding(s)
# [agentshield] Normalized: ... detect=7 defend=1 respond=1
```

(The `--no-emit` flag skips the Tier 2 skill files; useful for a quick "is the binary working?" without producing artefacts.)

---

## 7. Run a scan against your real codebase

The full flow has three commands plus two IDE steps.

### 7.1 Tier 1 (Semgrep) + AST10 (manifest scanner) + emit Tier 2 skill files

```bash
agentshield scan /path/to/your-agent-repo \
  --scan-all-files \
  --exclude '**/src/test/**' \
  --exclude '**/tests/**'
```

What this does:
- runs Semgrep on every Python / Java file (with the bundled 10-family rule pack)
- scans every `SKILL.md` against the AST10 rule set
- writes findings to `<your-agent-repo>/.agentshield/tier1-results.json`
- copies the Copilot LLM Scan skill files into `<your-agent-repo>/.agentshield/`
- prints the **exact prompt** to paste into Copilot Chat

Flag explanations (only the ones you'll use day-to-day):
- `--scan-all-files` — bypass Semgrep's `.semgrepignore`. **Recommended for production scans.** Without it, `tests/`, `examples/`, `vendor/` are skipped silently.
- `--exclude PATTERN` — drop files matching a glob (repeatable). `'**/src/test/**'`, `'**/tests/**'`, `'**/build/**'` are typical.
- `--stage-locally` — copy source to a local temp directory before the scan; **workaround for Windows UNC / mapped network drives** (`H:\fusion\…` paths). Use this if your initial scan returns 0 findings on a known-bad codebase.
- `--no-emit` — skip the Tier 2 skill files (Tier 1 + AST10 only). For diagnostics, not real audits.
- `--debug` — verbose: rules path, every file passed to Semgrep, raw rule_ids of every finding.

After this command finishes, your target repo's `.agentshield/` directory contains:

```
.agentshield/
├── tier1-results.json              ← Tier 1 + AST10 findings + fingerprint
├── tier2-bootstrap.md              ← Plain-language entry point for Copilot
├── tier2-checklist.md              ← The 68-check Tier 2 rule pack
├── tier2-output-schema.md          ← The strict JSON shape Copilot must emit
├── agentshield-semgrep-fixes.md    ← Drop into Claude Code → fix any AS-S-* finding
├── agentshield-copilot-fixes.md    ← Drop into Claude Code → fix any AS-C-* finding
└── agentshield-manifest-fixes.md   ← Drop into Claude Code → fix any AS-M-* finding
```

`.agentshield/` is auto-appended to the target's `.gitignore` so these generated artefacts don't get committed.

### 7.2 Tier 2 (Copilot LLM Scan) — runs in the IDE

1. Open `<your-agent-repo>` in **VS Code** (or JetBrains).
2. Open the **Copilot Chat** panel.
3. **Paste the prompt** the CLI just printed verbatim. It looks like:

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

4. Wait for Copilot to finish writing. Time depends on repo size:
   - Single file: ~30 s
   - 10 files: ~2 min
   - 50 files: ~10–15 min
   - 200+ files: may need to chunk by directory; see §12.3 below.

5. Confirm `.agentshield/tier2-findings.json` exists. If it doesn't, follow up in chat:

   > "You said you finished but `.agentshield/tier2-findings.json` doesn't exist. Please write the JSON output to that path."

For everything else that can go wrong with Copilot (it summarised instead of executing, it stopped halfway, the JSON is malformed, etc.), see §12.3 "Tier 2 (Copilot) issues" below.

### 7.3 Phase 2 — Behaviour emulator (Copilot Chat — IDE step)

This step applies 17 OWASP / ATLAS adversary attack classes against every distinct entry point in the agent's pipeline, predicting step-by-step how each attack would propagate through the code.

1. Keep the same repo open in VS Code with Copilot Chat active.
2. Paste this prompt verbatim:

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

3. Wait for Copilot to finish writing. Time depends on entry-point count:
   - 1 entry point: ~3–5 min
   - 3–5 entry points: ~10–20 min
   - 10+ entry points: may need to chunk; see §12.4 below.

4. Confirm `.agentshield/agent-emulation.json` exists. If it doesn't, follow up:

   > "You said you finished but `.agentshield/agent-emulation.json` doesn't exist. Please write the JSON output to that path."

**What this produces:** For each entry point × each attack class, a pipeline trace with step-by-step verdicts (`lands` / `partial` / `blocked` / `inconclusive`) and file:line citations. The merge step renders these as full pipeline-trace cards in the report.

---

### 7.4 Merge → unified report

```bash
agentshield merge /path/to/your-agent-repo
```

The merger reads `tier1-results.json` + `tier2-findings.json` + `agent-emulation.json`, validates schemas, writes the unified report to a timestamped subfolder inside `output/`, and then **automatically runs all 14 health checks** so you see pass/fail in one command:

```
output/
└── 20260530-123456/                         ← timestamped subfolder for this run
    ├── agentshield-report.html              ← interactive (tabs / filter / search / Reference)
    ├── agentshield-report-print.html        ← stacked / printable (all sections visible)
    ├── agentshield-findings-fix.md          ← paste into Claude Code to fix all findings
    └── agentshield-emulator-payloads.md     ← emulator attack walkthroughs per source × transition
output/agentshield-report.html               ← "latest" copy, updated after every merge run
```

Each run writes to a new folder so successive scans don't overwrite previous results. The `output/agentshield-report.html` file at the root always reflects the most recent run.

Do **not** pass `--output-html` — the default already writes to `output/<timestamp>/`.

CLI banners you might see:

| Banner | Meaning | Action |
|---|---|---|
| `✓ Tier 1 + Tier 2 fresh; merging.` | Both present, fingerprint matches | Proceed — health checks run next |
| `⚠ Stale artifacts detected:` | One or more input files older than 7 days | Guidance for a full rescan is printed automatically; merge proceeds with existing data |
| `⚠ Copilot LLM Scan not run.` | `tier2-findings.json` missing | Re-do §7.2 |
| `❌ Copilot LLM Scan output failed schema validation.` | Copilot's JSON is malformed | The merger prints the field paths; paste them into Copilot Chat to fix |
| `⚠ STALE Copilot LLM Scan.` | Tier 1 fingerprint changed since Copilot ran | Re-run §7.2 |
| `✓  Report health: 14/14  —  ALL CHECKS PASSED` | All automated checks passed | Open the report |

**Done when you see:** `✓  Report health: 14/14  —  ALL CHECKS PASSED`

To enforce freshness in CI (abort if any artifact is older than 7 days):
```bash
agentshield merge /path/to/your-agent-repo --require-fresh
```

### 7.5 View the report

#### Option A — open the file directly

Double-click `output/agentshield-report.html` in your file manager. Any modern browser opens it.

#### Option B — serve over localhost (preferred for VDI)

```bash
cd /path/to/your-agent-repo
python3.11 -m http.server 8765 --bind 127.0.0.1
```

Then open in a browser:
- `http://127.0.0.1:8765/output/agentshield-report.html` — interactive view
- `http://127.0.0.1:8765/output/agentshield-report-print.html` — printable / scrollable view

Loopback HTTP is allowed by virtually every VDI policy. Stop the server with `Ctrl+C` when done.

The HTML files are fully self-contained (CSS + JS inlined, no external assets) — you can also email them, drop into Slack, attach to a JIRA, etc.

---

## 8. Per-finding fix guidance

Every finding in the report has a canonical ID like `AS-S-D-LLM01-001` (Semgrep) / `AS-C-DF-LLM06-004` (Copilot) / `AS-M-D-AST03-001` (Manifest). Three places to look up the fix:

1. **Reference tab** in `report.html` — every control the scanner can fire, with what-it-flags + remediation guidance + framework chips. Always in sync with the rule pack.
2. **Fix-skill files** in `<your-agent-repo>/.agentshield/agentshield-{semgrep,copilot,manifest}-fixes.md` — drop the matching one into Claude Code or Copilot Chat, then paste a finding ID and ask "how do I fix this?". The skill auto-triggers on the ID prefix.
3. **The "Fix:" line** below each finding card in the report.

---

## 9. Privacy review before sharing the report

The HTML / Markdown reports include code snippets from your scanned codebase. Before sharing externally:

1. Open `report.html` and skim every finding's snippet panel. Look for:
   - Hardcoded secrets / connection strings (rare but possible if Tier 1 caught them in unexpected files)
   - Customer PII or trade-restricted data in error messages, log lines, or test fixtures
   - Internal hostnames / IPs / DB schemas
2. If anything sensitive surfaces, redact in the source then re-scan — don't edit the report manually (the JSON / SARIF outputs would still leak).
3. Share `report.html` and `report-print.html` rather than the raw JSON unless your reviewer specifically asked for SARIF.
4. The `.agentshield/` directory contains the same content as the report — don't share it as-is unless the receiver also wants the input data.

---

## 10. Refreshing an existing clone

When a new AgentShield version drops:

```bash
cd ~/work/agentshield
source .venv/bin/activate

git fetch origin
git checkout v6
git pull origin v6

# Re-install in case dependencies changed
pip install --upgrade pip
pip install -e ".[semgrep,dev]"

# Verify
agentshield --version
pytest -q
```

The Tier 1 fingerprint will change after a rule-pack update, so the next merge against an older `tier2-findings.json` will surface a STALE banner — just re-do §7.2.

---

## 11. CLI reference

### `agentshield scan <path>`

Run Tier 1 (Semgrep) + AST10 (manifest scanner). Optionally emit Tier 2 skill files.

| Flag | Purpose |
|---|---|
| `--scan-all-files` | Bypass Semgrep's `.semgrepignore`. Recommended for production scans. |
| `--exclude PATTERN` | Drop files matching glob. Repeatable. |
| `--stage-locally` | Copy source to local temp before scan. UNC / network-drive workaround. |
| `--no-emit` | Skip Tier 2 skill-file emission. Tier-1-only mode. |
| `--output-{sarif,json,markdown} PATH` | Write a Tier-1-only report. |
| `--debug` | Verbose diagnostic output. |

### `agentshield merge <path>`

Combine `tier1-results.json` + `tier2-findings.json` + `agent-emulation.json` into a unified report. Automatically runs all 14 health checks after writing output files.

| Flag | Purpose |
|---|---|
| `--output-html PATH` | Write `PATH` (interactive) AND `PATH-print.html` (stacked). |
| `--output-markdown PATH` | Write the Markdown report. |
| `--output-json PATH` | Write the unified JSON. |
| `--output-sarif PATH` | Write SARIF v2.1.0 (two `runs`: Tier 1 + Tier 2). |
| `--print` | Echo the Markdown report to stdout. |
| `--open` | After writing the HTML, launch it in the default browser. |
| `--require-fresh` | Abort with exit code 1 if any artifact is older than 7 days or fingerprints mismatch. Use in CI. |

### `agentshield check <path>`

Re-run the 14-point health check against existing merged output without re-merging. Reads from the most recent timestamped subfolder in `output/` automatically. Useful for verifying a report without triggering a full merge.

Exits `0` if all 14 checks pass, `1` if any fail. No flags.

> **Note:** `agentshield merge` already runs these checks automatically at the end of every merge. Use `agentshield check` only when you need to re-verify an existing report.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Success |
| `1` | Health check failure (`agentshield check` found ✗ items) or `--require-fresh` aborted on stale artifacts |
| `2` | Hard failure (Semgrep missing, target path invalid, malformed input) |

The merger does **not** return non-zero on findings — exit code reflects whether the *tooling* worked, not whether the scanned code was clean. CI gates that want to fail on findings should parse the SARIF / JSON output explicitly.

---

## 12. Troubleshooting

### Install issues

| Symptom | Likely cause | Fix |
|---|---|---|
| `command not found: agentshield` | venv not activated | `source .venv/bin/activate` |
| `ModuleNotFoundError: agentshield` | venv recreated without re-installing | `pip install -e ".[semgrep,dev]"` |
| `ERROR: Could not find a version that satisfies the requirement semgrep` | Behind a corporate proxy / Artifactory mirror | See §4 — set `pip config global.proxy` / `global.index-url` |
| `pip` itself fails | Wrong Python version | Verify `python3.11 --version` returns ≥3.10; check `which python` matches the venv |

### Runtime issues

| Symptom | Likely cause | Fix |
|---|---|---|
| `Tier 1: 0 raw finding(s)` on a known-bad codebase | Target on UNC / mapped network drive (Windows) | Add `--stage-locally` |
| Scan exits with `semgrep binary not found` | Semgrep not installed | `pip install -e ".[semgrep,dev]"` |
| HTML report shows a STALE banner | Re-ran Tier 1 after Tier 2 finished | Re-do §7.2 (Copilot scan) |
| HTML report says `Copilot LLM Scan output failed schema validation` | Copilot's JSON is malformed | Paste the field-path errors into Copilot Chat and ask it to fix |
| `⚠ Stale artifacts detected` on merge | Input files older than 7 days | Follow the printed rescan guidance — run `agentshield scan`, re-do §7.2 and §7.3, then merge again |

### Tier 2 (Copilot) issues

#### "Copilot ignored my prompt and just summarised the codebase"

Some Copilot variants treat `@workspace` requests as a context-load only. Re-prompt explicitly:

> "Don't summarise. Execute the scan: read `.agentshield/tier2-checklist.md`, walk every source file, write findings to `.agentshield/tier2-findings.json` per `.agentshield/tier2-output-schema.md`."

#### "Copilot scanned only the file currently open"

Add explicit file enumeration:

> "Use `@workspace` to enumerate every `.py`, `.java`, `.ts`, `.go` file in this repo. Walk them all, not just the active editor file."

#### "Copilot says it's done but `.agentshield/tier2-findings.json` doesn't exist"

Some Copilot variants don't auto-write to disk. Follow up:

> "You said you finished but `.agentshield/tier2-findings.json` doesn't exist. Please write the JSON output to that path."

#### "Schema validation says my JSON has 12 errors"

The merger's error output names each field path. Paste them straight into Copilot Chat:

> "Your `.agentshield/tier2-findings.json` failed schema validation. Fix these errors:
> - `findings[2].severity: invalid value 'urgent' (allowed: ['critical', 'high', 'medium', 'low', 'info'])`
> - `findings[5].owasp_llm: expected list, got NoneType`
> - ..."

#### "Tier 2 took forever and Copilot stopped"

For large codebases (200+ files), Tier 2 in a single Copilot session can run into context limits. Workarounds:

- **Run in chunks** — prompt by directory: `@workspace Walk only src/api/. Append to existing tier2-findings.json.`
- **Resume from where it stopped** — `"Continue from where you left off. The files you've already scanned are in the existing .agentshield/tier2-findings.json's scanned_files array — process the rest and append findings."`
- **Skip files explicitly** — add files to the `skipped_files` array if you genuinely can't scan them; the merger surfaces these as a coverage gap rather than failing.

#### "Fingerprint mismatch, but nothing changed"

If you didn't re-run `agentshield scan` between Tier 2 finishing and `agentshield merge`, the most likely cause is Copilot copied the wrong fingerprint (or invented one). Re-prompt:

> "Open `.agentshield/tier1-results.json`, read the `agentshield_tier1_fingerprint` field, and update `.agentshield/tier2-findings.json`'s `agentshield_tier1_fingerprint` to that exact value (don't change anything else)."

#### "I want to skip Tier 2 entirely for a quick check"

Use `--no-emit` on `agentshield scan` to suppress the Tier 2 emission. The CLI will warn that scanning is incomplete; the Tier-1-only Markdown / JSON / SARIF outputs from `--output-*` are still produced. **Don't gate CI on Tier-1-only results without understanding what's missing** — see [ARCHITECTURE_V2.md §2.2](./ARCHITECTURE_V2.md) for what Tier 2 catches that Tier 1 can't.

---

## 13. What to capture and share back (post-VDI run)

If you're validating a new AgentShield build on real customer code, share with the maintainer:

1. **The Markdown report** (`report.md`) — primary deliverable. Has all findings + the Tier 1 cross-check verdicts in plain text.
2. **The HTML report** (`report-print.html`) — easier to read, has the Reference tab + framework drill-down.
3. **`.agentshield/tier1-results.json` + `.agentshield/tier2-findings.json`** — the raw inputs the merger consumed. Useful for debugging if a finding looks wrong.
4. **Total scan time + repo size** (LOC + file count). Helps tune the Tier 2 chunking guidance.
5. **Any prompts you had to issue beyond the canonical one** — Copilot needed extra steering. Add to the "Trouble cases" doc.
6. **False-positive examples** — findings the scanner emitted but you'd dismiss in review. The Tier 1 cross-check should catch most of these as `FP`; if it didn't, that's signal to refine the checklist.

---

## 14. What's next

Once §6.2 (`pytest -q`) is green and §7 produces a report, you're done with the install + execution path. For deeper context:

- **[ARCHITECTURE_V2.md](./ARCHITECTURE_V2.md)** — how the three scanners + merger fit together. Read once for orientation.
- **[GLOSSARY.md](./GLOSSARY.md)** — security-term definitions. Reference as needed.
- **The Reference tab in any generated report** — the live, always-current rule list. Replaces the old `RULES_COVERAGE.md` doc.
