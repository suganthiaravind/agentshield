# Requirements & VDI Run Guide

Status: 2026-05-06 (Phase F architecture v2 — no AWS dep)
Companion to: [QUICKSTART_VDI.md](./QUICKSTART_VDI.md) (5-min cheat sheet), [VDI_TESTING.md](./VDI_TESTING.md) (staged validation playbook), [README.md](./README.md), [ARCHITECTURE_V2.md](./ARCHITECTURE_V2.md)

This doc covers **what you need installed** and **every command you'll run** to set up and use AgentShield inside a JPMC dev VDI.

> **v2 architecture note.** Phase F (2026-05-06) deleted the in-process LLM judge tier. AgentShield's CLI no longer needs AWS credentials or Bedrock access — Tier 2 LLM execution moved to Copilot in your IDE. The AWS-related sections below are **historical**; you can ignore them on v2.

---

## 1. At a glance

| Layer | Required | Version | Notes |
|---|---|---|---|
| OS | yes | macOS 12+, Linux (any modern distro), Windows 10+ via WSL2 | Native Windows works for most things; WSL2 recommended |
| Python | **yes** | **3.10, 3.11, 3.12, or 3.13** | 3.9 will be rejected by the installer |
| pip | yes | 23.0+ recommended | `python -m pip install --upgrade pip` |
| git | yes | 2.20+ | for cloning the repo |
| Disk | yes | ~300 MB free | semgrep + dev tools (no boto3 in v2) |
| Network | partial | access to internal PyPI mirror OR public PyPI | offline VDIs need an internal mirror or pre-built wheels |
| GitHub Copilot | **yes for Tier 2** | Copilot Chat enabled in VS Code or JetBrains | the v2 Tier 2 LLM-as-scanner runs in your IDE |
| AWS credentials | ~~optional~~ | _no longer needed in v2_ | the in-process judge tier was deleted in Phase F.6 |
| AWS Bedrock model access | ~~optional~~ | _no longer needed in v2_ | same as above |

---

## 2. Detailed requirements

### 2.1 Python interpreter (mandatory)

AgentShield requires **Python 3.10 or newer**. Older versions will be rejected at install time:

```
ERROR: Package 'agentshield' requires a different Python: 3.9.X not in '>=3.10'
```

**How to check what you have on the VDI:**

```bash
python3 --version
which python3
ls /usr/local/bin/python3.* /opt/homebrew/bin/python3.* /usr/bin/python3.* 2>/dev/null
```

If `python3 --version` is < 3.10 but a newer interpreter exists (often `/usr/local/bin/python3.11`), use that explicit path when creating the venv.

**Versions supported and tested:**

| Python version | Status |
|---|---|
| 3.10 | supported |
| 3.11 | supported (smoke-tested locally) |
| 3.12 | supported |
| 3.13 | supported |
| 3.9 or older | not supported — install rejects |

### 2.2 pip (mandatory)

`pip` ships with Python. Upgrade once before installing:

```bash
python -m pip install --upgrade pip
```

You can verify with `pip --version`. AgentShield uses standard PEP 621 metadata; any pip 23.0+ will work.

### 2.3 git (mandatory)

```bash
git --version
```

### 2.4 Disk space

`pip install -e ".[semgrep,dev]"` installs:
- `semgrep` (~200 MB)
- `pydantic` (~5 MB)
- `pytest` + `ruff` + `mypy` (~150 MB)
- AgentShield package (small)

Reserve **~500 MB** free for the venv. The `.git` directory plus source is small (<10 MB).

### 2.5 Network — VDI-specific

**Pip install:** by default `pip` reaches `pypi.org`. JPMC VDIs typically block this and require an internal mirror (Artifactory). Configure with:

```bash
# Option A: per-command flag
pip install --index-url https://<your-internal-pypi>/simple -e ".[semgrep,dev]"

# Option B: persistent config (recommended)
mkdir -p ~/.pip
cat > ~/.pip/pip.conf <<'INI'
[global]
index-url = https://<your-internal-pypi>/simple
trusted-host = <your-internal-pypi-host>
INI
```

If your VDI requires a proxy:

```bash
export HTTP_PROXY="http://<proxy-host>:<port>"
export HTTPS_PROXY="$HTTP_PROXY"
export NO_PROXY="localhost,127.0.0.1,<internal-domains>"
```

**AgentShield runtime:** the v2 scanner runs **fully offline**. Tier 1 (semgrep) does not call out; Tier 2 runs in your IDE via Copilot Chat (Copilot itself uses GitHub's API, but that goes through your IDE's sanctioned auth path — AgentShield itself makes no network calls).

### 2.6 GitHub Copilot Chat (mandatory for Tier 2)

v2's Tier 2 LLM-as-scanner runs in your IDE via Copilot. You need:

| Requirement | How to verify |
|---|---|
| GitHub Copilot license attached to your GitHub identity | check at https://github.com/settings/copilot |
| Copilot Chat enabled in your IDE (VS Code or JetBrains) | open Copilot Chat panel; should accept input |
| Workspace context working — `@workspace` queries should return repo-aware answers | type `@workspace what files are in this repo?` |

If your VDI doesn't have Copilot, you can run **Tier 1 only** with `agentshield scan --no-emit`. The CLI will print a warning that scanning is incomplete; the report will say so prominently. A future Tier 2 backend (Bedrock / SmartSDK) for headless CI is documented as work that could happen if needed (see [`ARCHITECTURE_V2.md` §10](./ARCHITECTURE_V2.md)).

---

## 3. Install on the VDI — step by step

### Step 1 — verify the Python interpreter

```bash
python3 --version
```

**If `python3 --version` is 3.10+:** continue with `python3` in the steps below.

**If `python3 --version` is 3.9 or older:** find a newer one.

```bash
ls /usr/local/bin/python3.* /opt/homebrew/bin/python3.* 2>/dev/null
# Pick the highest 3.10+ entry, e.g. /usr/local/bin/python3.11
```

Substitute that explicit path in Step 3.

### Step 2 — clone the repo

```bash
git clone git@github.com:suganthiaravind/agentshield.git
cd agentshield
```

If your VDI uses HTTPS instead of SSH:

```bash
git clone https://github.com/suganthiaravind/agentshield.git
cd agentshield
```

### Step 3 — create a virtual environment

```bash
python3 -m venv .venv          # or: /usr/local/bin/python3.11 -m venv .venv
source .venv/bin/activate
```

After this, `which python` should point inside `.venv`. Always activate the venv before running `agentshield` or `pytest`.

### Step 4 — upgrade pip and install AgentShield

```bash
pip install --upgrade pip

# Recommended: full install with all extras (semgrep + dev tools)
pip install -e ".[semgrep,dev]"
```

**Lighter install variants** (if disk or network is tight):

| Install command | Includes | Skip if |
|---|---|---|
| `pip install -e .` | core only (no semgrep, no tests) | rare — almost always want at least `[semgrep]` |
| `pip install -e ".[semgrep]"` | + semgrep for Tier 1 scanning | tests not needed |
| `pip install -e ".[semgrep,dev]"` | + pytest, ruff, mypy | recommended |

> **Note:** the v1 `[judge]` extra (boto3 dep) was removed in Phase F.6. v2's Tier 2 runs via Copilot in your IDE; no in-process AWS dep.

### Step 5 — verify the install

```bash
agentshield --version
```

Expected:

```
agentshield 0.1.0
```

If the command isn't found, the venv isn't activated. Run `source .venv/bin/activate` again.

---

## 4. Run AgentShield (v2)

### 4.1 Help text and discovery

```bash
agentshield --help
agentshield scan --help
agentshield merge --help
```

### 4.2 The full v2 flow

See [`QUICKSTART_VDI.md`](./QUICKSTART_VDI.md) for the canonical 5-minute walkthrough. Summary:

```bash
# Tier 1 + emit Tier 2 skill files
agentshield scan ./path/to/target/repo --scan-all-files \
  --exclude '**/src/test/**' --exclude '**/tests/**' \
  --stage-locally    # only if the repo is on H:\ or another network drive

# Tier 2 — open the repo in VS Code with Copilot Chat, paste the prompt
# the CLI just printed. Wait for tier2-findings.json to appear.

# Combine into the unified report
agentshield merge ./path/to/target/repo --output-markdown report.md
```

### 4.3 All CLI flags reference (v2)

**`agentshield scan <path>`:**

| Flag | Argument | Default | Purpose |
|---|---|---|---|
| `<path>` (positional) | required | — | target directory or file to scan |
| `--scan-all-files` | flag | off | enumerate every `.py`/`.java` file explicitly; bypasses semgrep's default directory ignore. Recommended for production scans. |
| `--exclude` | glob | (none) | repeatable. Drop files matching the glob. Most useful with `--scan-all-files` to re-add targeted exclusions. e.g. `--exclude '**/src/test/**'`. |
| `--stage-locally` | flag | off | copy source to local temp before scan. Workaround for Windows UNC / mapped network drives (`H:\fusion\…`). |
| `--no-emit` | flag | off | Tier-1-only mode for diagnostics; skips skill-file emission. Final banner warns scanning is incomplete. |
| `--output-sarif` | path | — | write Tier-1-only SARIF v2.1.0 (the unified report is `agentshield merge`) |
| `--output-json` | path | — | write Tier-1-only JSON |
| `--output-markdown` | path | — | write Tier-1-only Markdown |
| `--debug` | flag | off | verbose: rules path, semgrep binary, files passed, raw rule_ids of every finding |

**`agentshield merge <path>`:**

| Flag | Argument | Default | Purpose |
|---|---|---|---|
| `<path>` (positional) | required | — | path to the target repo (containing `.agentshield/`) |
| `--output-markdown` | path | — | write unified Markdown report (primary) |
| `--output-json` | path | — | write unified JSON report |
| `--output-sarif` | path | — | write unified SARIF v2.1.0 (two `runs` — one per tier) |
| `--print` | flag | off | print the unified Markdown to stdout in addition to writing files |

**Removed in v2 (deleted in Phase F.6):** `--llm-backend`, `--bedrock-model-id`, `--bedrock-region`, `--no-judge`, `--discovery`, `--config`. The v1 config-file mechanism (`agentshield.yaml`) is also gone.

### 4.4 Exit codes

| Code | Meaning |
|---|---|
| 0 | command succeeded (scan or merge produced expected output) |
| 2 | tool error (semgrep crash, missing tier1-results.json on merge, bad CLI args) |

Soft conditions like "Tier 2 not yet run" or "Tier 2 schema-invalid" produce a banner in the report but exit 0 — the unified-report is still useful, just incomplete. CI gating typically runs `scan` (Tier 1 only acceptable in CI without Copilot) and gates on Tier 1 findings while flagging incomplete-scan status to reviewers.

---

## 5. Validate the install

### 5.1 Run the unit test suite (no network)

```bash
pytest tests/
```

Expected:

```
============================= 123 passed in ~25s =============================
```

If anything fails here, **stop and fix** before scanning real repos. The package is broken on your VDI; nothing later will work right.

### 5.2 Smoke-test the CLI on an in-repo fixture

```bash
mkdir -p /tmp/agentshield-smoke
cp tests/fixtures/python/d001_flask_langchain.py /tmp/agentshield-smoke/
agentshield scan /tmp/agentshield-smoke --scan-all-files
ls /tmp/agentshield-smoke/.agentshield/   # should show 4 files (3 skill templates + tier1-results.json)
```

Expected stdout includes the `⚠ TIER 2 NOT YET RUN — scanning is INCOMPLETE.` banner with the Copilot prompt.

### 5.3 End-to-end Tier 2 with Copilot

This needs an IDE — not testable from the CLI alone. See [`TIER2_USAGE.md`](./TIER2_USAGE.md) for the full Copilot walkthrough; [`QUICKSTART_VDI.md`](./QUICKSTART_VDI.md) is the 5-min version.

### 5.4 Staged validation playbook

For a more thorough first-time run-through with explicit checkpoints, follow [`VDI_TESTING.md`](./VDI_TESTING.md) (7 stages, each independently verifiable).

---

## 6. Troubleshooting

### Install issues

| Symptom | Cause | Fix |
|---|---|---|
| `Package 'agentshield' requires a different Python: 3.9.X not in '>=3.10'` | venv created from Python 3.9 | recreate venv with explicit `python3.11 -m venv .venv` |
| `Could not find a version that satisfies the requirement semgrep` | pip can't reach pypi.org | configure internal mirror via `pip config set global.index-url <internal>` |
| `WARNING: Retrying ... ProxyError` | no proxy env vars set | `export HTTPS_PROXY=...` and retry |
| `ERROR: Could not install packages due to an OSError: [Errno 28] No space left on device` | disk full | clear `~/.cache/pip`, `/tmp`, or other venvs |
| `bash: agentshield: command not found` | venv not activated | `source .venv/bin/activate` |

### Runtime issues

| Symptom | Cause | Fix |
|---|---|---|
| `[agentshield] ERROR: semgrep binary not found in PATH` | `[semgrep]` extra not installed, or venv not activated | `pip install -e ".[semgrep]"` and `source .venv/bin/activate` |
| `[agentshield] ERROR: Target path does not exist` | typo in scan path | `ls` the path; use absolute path if relative is ambiguous |
| Scan returns 0 findings on a known-vulnerable repo (or "couldn't identify SMARTSDK / target framework") | semgrep silently skips files under `tests/`, `examples/`, `fixtures/`, `vendor/`, etc. by default | re-run with `--scan-all-files` to enumerate every `.py`/`.java` file explicitly and bypass the directory ignore |
| `[agentshield] ERROR: semgrep failed (exit 2)` | rule parse error or invalid target | re-run with `--quiet` removed from the runner (edit `agentshield/runner/semgrep_runner.py` temporarily) to see semgrep's stderr |

### Tier 2 (Copilot) issues

| Symptom | Cause | Fix |
|---|---|---|
| Copilot Chat doesn't write `tier2-findings.json` | some Copilot variants don't auto-write to disk | re-prompt: *"You said you finished but `.agentshield/tier2-findings.json` doesn't exist. Please write the JSON output to that path."* |
| Copilot only scans the active editor file | `@workspace` not engaged | re-prompt: *"Use `@workspace` to enumerate every `.py`, `.java`, `.ts` file in this repo. Walk them all, not just the open editor file."* |
| `agentshield merge` says `❌ Tier 2 output failed schema validation` | Copilot's JSON shape is off | re-prompt Copilot citing the field-path errors the merger printed (e.g. `findings[2].severity: invalid value 'urgent'`) |
| `agentshield merge` says `⚠ STALE Tier 2: fingerprint mismatch` | code or rule pack changed between scan and merge | re-run Copilot with the same prompt to refresh `tier2-findings.json` |

For more, see [`TIER2_USAGE.md` "Trouble cases"](./TIER2_USAGE.md#trouble-cases-and-how-to-handle-them).

---

## 7. What's not in this build (intentional, planned)

See [`VDI_TESTING.md` "What's in this build" + "What's been retired in v2"](./VDI_TESTING.md#whats-in-this-build) for the up-to-date status tables. Short version: Tier 1 (6-family rule pack) + Tier 2 (Copilot LLM-as-scanner) + 3 unified-report formats are shipped; headless-CI Tier 2 backend, additional language Tier 1 rules (TS/Go/Rust), and Trivy supply-chain are roadmap items. The v1 LLM judge tier (`--llm-backend`, Bedrock backend) was deleted in F.6; the v1 Tier 4 discovery flag was deleted in F.6.

For architectural context: [`ARCHITECTURE_V2.md`](./ARCHITECTURE_V2.md) and [`ARCHITECTURE_RATIONALE.md` (v1 archived)](./docs/_v1_archive/ARCHITECTURE_RATIONALE.md).
