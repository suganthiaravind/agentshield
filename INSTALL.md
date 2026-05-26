# AgentShield — Installation & Setup

Pre-production security evaluator for AI agents.  
Four steps from clone to full report.

---

## Prerequisites

| Requirement | Notes |
|---|---|
| Python 3.10+ | `python3 --version` to check |
| Git | Any recent version |
| VS Code | Required for the Copilot steps |
| GitHub Copilot | Active subscription + VS Code extension |
| Semgrep | Auto-installed via `pip install -e ".[semgrep,dev]"` |

---

## Step 01 — Clone & Install

```bash
git clone git@github.com:suganthiaravind/agentshield.git
cd agentshield

python3.11 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate

pip install --upgrade pip
pip install -e ".[semgrep,dev]"    # semgrep is mandatory; dev = pytest + ruff + mypy
```

Verify:

```bash
agentshield --version
```

---

## Step 02 — Tier 1 Scan

Run the static analysis against your agent repo. This triggers Semgrep (70+ security rules) and emits the Copilot skill files for the next step.

```bash
agentshield scan ./your-agent-repo \
  --scan-all-files \
  --exclude "**/tests/**" \
  --exclude "**/src/test/**"
```

**Flags:**

| Flag | When to use |
|---|---|
| `--scan-all-files` | Always recommended — bypasses semgrep's default directory ignores |
| `--exclude PATTERN` | Repeatable. Drop test directories: `'**/tests/**'`, `'**/src/test/**'` |
| `--stage-locally` | Windows UNC / mapped network drives (`H:\fusion\...`) only |
| `--debug` | Verbose: rules path, files scanned, raw rule IDs |

**Outputs written to `./your-agent-repo/.agentshield/`:**

- `tier1-results.json` — raw Semgrep findings
- `SKILL.md` — Tier 2 skill file (paste into Copilot Chat in step 03)
- `AGENT_EMULATOR_SKILL.md` — Behaviour Emulator skill file

---

## Step 03 — Tier 2 + Behaviour Emulator (Copilot step)

> This step runs inside VS Code. No CLI command — Copilot does the work.

1. Open the scanned repo in **VS Code** with the **GitHub Copilot Chat** extension active.
2. Copy the prompt printed at the end of Step 02 (or open `.agentshield/SKILL.md` and copy its contents).
3. Paste into Copilot Chat and send.
4. Copilot reads every source file, validates Tier 1 findings (TP/FP), discovers new issues, and writes:
   - `.agentshield/tier2-findings.json`
5. Next, open `.agentshield/AGENT_EMULATOR_SKILL.md`, copy its contents, paste into Copilot Chat, and send.
6. Copilot maps the 8 pipeline steps, fires 14 attack classes (3 seeds + up to 5 mutations each), and writes:
   - `.agentshield/agent-emulation.json`

**Outputs:**

- `tier2-findings.json` — LLM-validated findings + novel discoveries
- `agent-emulation.json` — adversary emulation results (verdicts, traces, kill chains)

---

## Step 04 — Generate Unified Report

```bash
agentshield merge ./your-agent-repo \
  --output-html report.html
```

**Flags:**

| Flag | Purpose |
|---|---|
| `--output-html PATH` | HTML report (interactive) + print-optimised variant |
| `--output-markdown PATH` | Markdown report |
| `--output-sarif PATH` | SARIF for IDE / CI integration |
| `--output-json PATH` | Machine-readable JSON |
| `--open` | Launch the HTML report in the default browser after writing |

**Outputs:**

- `report.html` — full interactive report (D/D/R findings, fix guidance, framework mappings, behaviour emulator)
- `report-print.html` — print-optimised version

---

## Full 4-step reference

```bash
# 01 — Install
git clone git@github.com:suganthiaravind/agentshield.git
cd agentshield && pip install -e ".[semgrep,dev]"

# 02 — Tier 1 scan
agentshield scan ./your-agent-repo --scan-all-files

# 03 — Tier 2 + Emulator (VS Code + Copilot Chat)
#      Paste .agentshield/SKILL.md → tier2-findings.json
#      Paste .agentshield/AGENT_EMULATOR_SKILL.md → agent-emulation.json

# 04 — Report
agentshield merge ./your-agent-repo --output-html report.html
```

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| `agentshield: command not found` | Activate the venv: `source .venv/bin/activate` |
| Semgrep returns "Scanning 0 files" | Add `--scan-all-files` or `--stage-locally` (Windows) |
| Copilot does not produce `tier2-findings.json` | Ensure the full skill file content was pasted; check Copilot Chat for schema error messages |
| `merge` warns "Tier 2 results missing or stale" | Re-run Step 03 — the fingerprint hash changed since the last scan |
| Report shows 0 emulator entries | Re-run the emulator skill (Step 03, second Copilot paste) |

For detailed troubleshooting see [EXECUTE_AGENTSHIELD.md §12.3](./EXECUTE_AGENTSHIELD.md).
