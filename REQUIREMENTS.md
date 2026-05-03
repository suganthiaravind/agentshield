# Requirements & VDI Run Guide

Status: 2026-05-03
Companion to: [VDI_TESTING.md](./VDI_TESTING.md) (staged validation playbook), [README.md](./README.md), [ARCHITECTURE.md](./ARCHITECTURE.md)

This doc covers **what you need installed** and **every command you'll run** to set up and use AgentShield inside a JPMC dev VDI. Use [VDI_TESTING.md](./VDI_TESTING.md) for staged validation after install.

---

## 1. At a glance

| Layer | Required | Version | Notes |
|---|---|---|---|
| OS | yes | macOS 12+, Linux (any modern distro), Windows 10+ via WSL2 | Native Windows works for most things; WSL2 recommended |
| Python | **yes** | **3.10, 3.11, 3.12, or 3.13** | 3.9 will be rejected by the installer |
| pip | yes | 23.0+ recommended | `python -m pip install --upgrade pip` |
| git | yes | 2.20+ | for cloning the repo |
| Disk | yes | ~500 MB free | semgrep + boto3 + dev tools |
| Network | partial | access to internal PyPI mirror OR public PyPI | offline VDIs need an internal mirror or pre-built wheels |
| AWS credentials | optional | only for the judge tier | IAM role / STS preferred over access keys |
| AWS Bedrock model access | optional | only for the judge tier | enabled in the Bedrock console for your account |

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

`pip install -e ".[semgrep,judge,dev]"` installs:
- `semgrep` (~200 MB)
- `boto3` + `botocore` + `pydantic` (~50 MB)
- `pytest` + `ruff` + `mypy` (~150 MB)
- AgentShield package (small)

Reserve **~500 MB** free for the venv. The `.git` directory plus source is small (<10 MB).

### 2.5 Network — VDI-specific

**Pip install:** by default `pip` reaches `pypi.org`. JPMC VDIs typically block this and require an internal mirror (Artifactory). Configure with:

```bash
# Option A: per-command flag
pip install --index-url https://<your-internal-pypi>/simple -e ".[semgrep,judge,dev]"

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

**AgentShield runtime:** the scanner runs **fully offline** for Tier 1+2 (semgrep + normalize + reports). The Tier 3 judge needs outbound access to AWS Bedrock; that goes via your VDI's sanctioned AWS path. No public-internet calls.

### 2.6 AWS / Bedrock (optional — only for the judge tier)

You only need AWS credentials and Bedrock model access if you want to test or use the **Tier 3 LLM judge**. Tiers 1 + 2 work without any AWS setup.

**Requirements for the judge tier:**

| Requirement | How to verify |
|---|---|
| AWS credentials reachable | `aws sts get-caller-identity` |
| IAM permission `bedrock:InvokeModel` (or `bedrock:Converse`) on the target model | check IAM policy attached to your role |
| Bedrock model access enabled in your AWS account | `aws bedrock list-foundation-models --region us-east-1` |
| Model id or inference-profile ARN | record output of the list command above |

**Authentication shape** — JPMC dev environments typically issue credentials via STS / IAM role (not static access keys). `boto3` automatically picks up:
1. `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` / `AWS_SESSION_TOKEN` env vars (if set)
2. `~/.aws/credentials` profile
3. EC2/SSO instance metadata
4. SDK default chain

You don't need to do anything special in AgentShield — it just calls `boto3.client("bedrock-runtime")` and the SDK resolves credentials.

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

# Recommended: full install with all extras (semgrep + judge + dev tools)
pip install -e ".[semgrep,judge,dev]"
```

**Lighter install variants** (if disk or network is tight):

| Install command | Includes | Skip if |
|---|---|---|
| `pip install -e .` | core only (no semgrep, no judge, no tests) | rare — almost always want at least `[semgrep]` |
| `pip install -e ".[semgrep]"` | + semgrep for Tier 1+2 scanning | judge tier not needed AND tests not needed |
| `pip install -e ".[semgrep,judge]"` | + boto3 for Tier 3 judge backend | tests not needed |
| `pip install -e ".[semgrep,judge,dev]"` | + pytest, ruff, mypy | nothing — recommended |
| `pip install -e ".[all,dev]"` | shorthand for the above | (same) |

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

## 4. Run AgentShield

### 4.1 Help text and discovery

```bash
agentshield --help
agentshield scan --help
```

### 4.2 Basic scan — Tier 1+2 only (no LLM, no AWS)

```bash
agentshield scan ./path/to/target/repo --no-judge
```

This prints a finding count to stdout. Add `--output-*` flags to persist:

```bash
agentshield scan ./path/to/target/repo --no-judge \
  --output-sarif report.sarif \
  --output-json  report.json \
  --output-markdown report.md
```

### 4.3 Scan with the LLM judge tier (boto3-Bedrock)

```bash
# pick a model you have access to
export BEDROCK_MODEL_ID="anthropic.claude-3-7-sonnet-20250219-v1:0"
# or for an org inference profile:
# export BEDROCK_MODEL_ID="arn:aws:bedrock:us-east-1:<acct>:application-inference-profile/<id>"

agentshield scan ./path/to/target/repo \
  --llm-backend boto3-bedrock \
  --bedrock-model-id "$BEDROCK_MODEL_ID" \
  --bedrock-region  us-east-1 \
  --output-sarif report.sarif \
  --output-markdown report.md
```

The judge runs **only on Tier 2 fallback findings** (low-confidence catch-net), not on Tier 1 framework rules (high-precision by construction). On most repos the judge will be invoked on a small fraction of findings.

### 4.4 Scan with the discovery pass enabled (Tier 4) — *not yet implemented*

```bash
agentshield scan ./path/to/target/repo --discovery
# Currently prints a TODO stub; full implementation is Track D.
```

### 4.5 Configuration file (optional)

Drop an `agentshield.yaml` into the repo root (or anywhere, then pass `--config`) to set defaults:

```yaml
# agentshield.yaml
llm_backend: boto3-bedrock
bedrock_model_id: arn:aws:bedrock:us-east-1:<acct>:application-inference-profile/<id>
bedrock_region: us-east-1
tiers:
  framework_rules: true
  fallback_rules: true
  judge: true
  discovery: false
ignore:
  - "**/test/**"
  - "**/vendor/**"
output:
  sarif: report.sarif
  json: report.json
  markdown: report.md
```

CLI flags override config-file values. *(Note: config-file loading is wired through to the CLI signature today; the parser is on the implementation roadmap.)*

### 4.6 All CLI flags reference

| Flag | Argument | Default | Purpose |
|---|---|---|---|
| `--version` | — | — | print version and exit |
| `<path>` (positional) | required | — | target directory or file to scan |
| `--config` | path | `./agentshield.yaml` if present | config file |
| `--llm-backend` | `boto3-bedrock` \| `smartsdk` \| `copilot` \| `none` | inferred | judge tier backend |
| `--bedrock-model-id` | string or ARN | — | required for `--llm-backend boto3-bedrock` |
| `--bedrock-region` | AWS region | `us-east-1` | region for the Bedrock client |
| `--no-judge` | flag | off | skip Tier 3 (offline mode) |
| `--discovery` | flag | off | enable Tier 4 discovery pass *(stub)* |
| `--scan-all-files` | flag | off | enumerate every `.py`/`.java` file explicitly; bypasses semgrep's default directory ignore (use when scanning a sample/demo repo where target code lives under `tests/`, `examples/`, etc.) |
| `--output-sarif` | path | — | write SARIF v2.1.0 |
| `--output-json` | path | — | write JSON report |
| `--output-markdown` | path | — | write Markdown report |

### 4.7 Exit codes

| Code | Meaning |
|---|---|
| 0 | scan succeeded (zero findings or below the configured fail threshold) |
| 1 | scan succeeded with findings at/above the configured fail threshold |
| 2 | tool error (semgrep crash, invalid config, bad CLI args) |

CI pipelines should gate merges on exit code while still ingesting the SARIF for trend analysis.

---

## 5. Validate the install

### 5.1 Run the unit test suite (no AWS, no network beyond VDI)

```bash
pytest tests/
```

Expected:

```
============================= 48 passed in ~30s =============================
```

If anything fails here, **stop and fix** before scanning real repos. The MVP is broken on your VDI; nothing later will work right.

### 5.2 Smoke-test the CLI on an in-repo fixture

```bash
agentshield scan tests/fixtures/python/d001_flask_langchain.py --no-judge \
  --output-markdown /tmp/report.md
cat /tmp/report.md
```

Expected stdout:

```
[agentshield] Tier 1+2: 3 raw finding(s)
[agentshield] Normalized: 3 finding(s) (framework=3, fallback=0) detect=1 defend=1 respond=1
[agentshield] Tier 3 judge: skipped (--no-judge); 0 fallback finding(s) untriaged
[agentshield] Wrote: /tmp/report.md
```

### 5.3 End-to-end judge tier (only if AWS / Bedrock are configured)

```bash
agentshield scan tests/fixtures/python/d001_fallback_openai_wrapper.py \
  --llm-backend boto3-bedrock \
  --bedrock-model-id "$BEDROCK_MODEL_ID" \
  --output-json /tmp/judge.json

jq '.findings[0].triage' /tmp/judge.json
```

Should show the verdict block with `verdict`, `confidence`, `reasoning`, `backend`, `model_id`.

### 5.4 Staged validation playbook

For a more thorough first-time run-through with explicit checkpoints, follow [VDI_TESTING.md](./VDI_TESTING.md) (7 stages, each independently verifiable).

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

### Bedrock / judge issues

| Symptom | Cause | Fix |
|---|---|---|
| `[agentshield] Tier 3 judge: skipped — boto3-bedrock backend requires --bedrock-model-id` | flag missing | pass `--bedrock-model-id` or set in config |
| `JudgeBackendError: Bedrock converse failed ... AccessDeniedException` | IAM role lacks `bedrock:InvokeModel` for that model | request the permission, or pick a model your role can call |
| `JudgeBackendError: Bedrock converse failed ... ValidationException: model not enabled` | Bedrock model access not enabled in your AWS account | go to Bedrock console → model access → request access |
| `JudgeBackendError: Bedrock converse failed ... ResourceNotFoundException` | wrong model id or wrong region | verify with `aws bedrock list-foundation-models --region <region>` |
| `JudgeBackendError: Bedrock converse failed ... ThrottlingException` | quota exhausted | retry, or reduce concurrency, or use a different model |
| Verdict comes back `needs_review` with `reasoning: "Backend error: ..."` | orchestrator caught a per-finding error; whole scan still completed | the reasoning field has the underlying error |
| `JudgeBackendError: Model output was not valid JSON` | model didn't follow the system-prompt instructions | usually a non-Claude model with weaker JSON adherence — pin to a Claude model id |

---

## 7. What's not in this build (intentional, planned)

See [VDI_TESTING.md §"What's NOT in this build"](./VDI_TESTING.md#whats-not-in-this-build-intentional) for the up-to-date status table. Short version: Tier 1+2+3 scanning + 3 report formats are shipped; audit log, SMARTSDK / Copilot judge backends, Tier 4 discovery, Trivy supply-chain, and zero-trust gap rules are on the roadmap.

For architectural context: [ARCHITECTURE.md](./ARCHITECTURE.md) and [ARCHITECTURE_RATIONALE.md](./ARCHITECTURE_RATIONALE.md).
