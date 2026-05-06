# VDI Testing Playbook

Status: 2026-05-05
Use after any pull from `origin/main` to validate AgentShield in your VDI before touching real target repos.

This playbook is staged so you can verify each layer independently — if Stage N fails, Stages 1..N-1 are still trustworthy.

---

## Stage 0 — prerequisites

Run all of these on the VDI; each should produce non-empty output.

```bash
python3 --version              # need 3.10+; if shell default is 3.9, find a 3.10/3.11/3.12 explicitly:
ls /usr/local/bin/python3.* /opt/homebrew/bin/python3.* 2>/dev/null
git --version
pip --version
aws sts get-caller-identity    # only required if you'll test the judge tier
```

If `aws sts get-caller-identity` fails, the judge tier won't work but everything else will. Skip Stage 5+ in that case.

---

## Stage 1 — clone, venv, install

```bash
git clone git@github.com:suganthiaravind/agentshield.git
cd agentshield

# Use whichever Python 3.10+ you found in Stage 0
python3.11 -m venv .venv
source .venv/bin/activate

pip install --upgrade pip
pip install -e ".[semgrep,judge,dev]"     # ~1-2 min; semgrep is the bulk
```

**Success markers:**
- No error output
- `which agentshield` returns `<repo>/.venv/bin/agentshield`
- `which semgrep` returns `<repo>/.venv/bin/semgrep`

**Common issues:**
- `Package 'agentshield' requires a different Python: 3.9.X not in '>=3.10'` → use a newer Python interpreter when creating the venv
- semgrep wheel is large; if pip times out, retry once
- corporate proxy: `pip install --index-url <internal-pypi-mirror> -e ...`

---

## Stage 1b — refreshing an existing clone (alternative to Stage 1)

If you've already done Stage 1 once and just want to pull the latest changes (e.g. switching to a feature branch like `phase-b-c-d-polish`, or pulling new commits to `main`):

```bash
cd /path/to/your/agentshield/clone
source .venv/bin/activate          # re-enter the existing venv

git fetch origin
git checkout <branch-name>          # e.g. phase-b-c-d-polish or main
git pull                            # fast-forward to remote tip

pip install -e ".[semgrep,judge,dev]"   # re-install in case dependencies changed
pytest tests/ -v                        # confirm green on your VDI Python before scanning
```

**Why re-run `pip install -e`** — even though `-e` (editable) installs source-mirror by default, if the schema changed (e.g. a new field on `FrameworkMappings` like the `cwe` field added in the polish pass), the package metadata needs to be refreshed. Skipping this can cause silent import errors or pydantic-validation failures on first run.

**Why re-run pytest** — the Stage 3 invocation. Even on a known-green branch, your VDI Python version + installed semgrep version interact with the rule patterns, so confirming green on YOUR machine is the only valid signal that the install transferred cleanly.

**Common issues:**
- `error: detected dubious ownership` (Windows / shared filesystem): `git config --global --add safe.directory /path/to/clone`
- `pip` says "Already satisfied" but pytest fails on missing field — try `pip install --force-reinstall -e ".[semgrep,judge,dev]"`
- pytest fails with rule-golden mismatches — most likely the rule pack on the branch diverges from your local cache; run `pytest tests/test_rules_golden.py --update-golden` only if you're SURE the divergence is intentional, otherwise `git status` to check for accidental local edits.

---

## Stage 2 — `--version`

Trivial sanity check. If this fails, the install is broken — fix Stage 1 before continuing.

```bash
agentshield --version
```

Expected:
```
agentshield 0.1.0
```

---

## Stage 3 — unit tests (no AWS, no network)

This validates all internal logic without any external dependencies. If it passes, the rule patterns, normalizer, writers, judge protocol, orchestrator, and source helpers all work correctly on your VDI Python.

```bash
pytest tests/ -v
```

**Success markers:**
- 86 tests pass (mix of judge backend + orchestrator + normalizer + 45 rule golden + writer tests; rule golden count grew through Phases B-D as fixtures were added)
- Suite finishes in ~30-60s (depends on VDI semgrep performance)

**If anything fails here, stop and report.** The MVP is broken on your VDI; nothing later will work right.

---

## Stage 4 — Tier 1+2 scan (no judge)

Run a full scan against an in-repo fixture with the judge disabled.

```bash
agentshield scan tests/fixtures/python/d001_flask_langchain.py --no-judge \
  --output-sarif /tmp/r.sarif \
  --output-json /tmp/r.json \
  --output-markdown /tmp/r.md
```

Expected stdout:
```
[agentshield] scan target: tests/fixtures/python/d001_flask_langchain.py
[agentshield] Tier 1+2: invoking semgrep on bundled rule pack...
[agentshield] Tier 1+2: 3 raw finding(s)
[agentshield] Normalized: 3 finding(s) (framework=3, fallback=0) detect=1 defend=1 respond=1
[agentshield] Tier 3 judge: skipped (--no-judge); 0 fallback finding(s) untriaged
[agentshield] Wrote: /tmp/r.sarif, /tmp/r.json, /tmp/r.md
```

**Verify all three outputs:**
```bash
jq '.runs[0].results | length' /tmp/r.sarif       # → 3
jq '.summary.total' /tmp/r.json                    # → 3
head -20 /tmp/r.md                                 # human-readable report
```

---

## Stage 4.5 — mock-test the judge tier (no AWS required)

Before configuring AWS access, you can verify the judge tier's CLI plumbing + orchestrator pipeline end-to-end with the **mock backend**. This is useful when:

- You're standing up a VDI without Bedrock access yet.
- You want a fast smoke test that doesn't burn LLM tokens.
- You're debugging whether a judge issue is in the CLI / orchestrator / output-writer path versus the actual Bedrock backend.

The mock backend (`MockJudgeBackend`) returns a deterministic placeholder verdict (`needs_review`, confidence 0.5) on every call without invoking any LLM. The reasoning string says `"Mock backend — no real LLM was called"` so a leaked finding can never be confused with a real triage result.

### 4.5.1 Run the orchestrator unit tests against mocked Bedrock

The repo's existing pytest suite already mocks the boto3-bedrock client end-to-end. If Stage 3 passed, this passed too — but you can run just the judge-related tests for an isolated check:

```bash
pytest tests/test_judge_bedrock.py tests/test_judge_mock.py tests/test_orchestrator.py -v
```

Expected: roughly 30 tests pass (11 boto3-bedrock + 6 mock + 13 orchestrator). All hermetic — no network, no AWS.

### 4.5.2 Run the CLI end-to-end with the mock backend

The repo's fallback fixture is designed to trigger exactly one fallback finding so the orchestrator → backend → verdict-attachment path is exercised:

```bash
agentshield scan tests/fixtures/python/d001_fallback_openai_wrapper.py \
  --llm-backend mock \
  --output-json /tmp/mock_judge.json \
  --output-markdown /tmp/mock_judge.md
```

Expected stdout:
```
[agentshield] scan target: tests/fixtures/python/d001_fallback_openai_wrapper.py
[agentshield] Tier 1+2: invoking semgrep on bundled rule pack...
[agentshield] Tier 1+2: 1 raw finding(s)
[agentshield] Normalized: 1 finding(s) (framework=0, fallback=1) detect=1 defend=0 respond=0
[agentshield] Tier 3 judge: triaging 1 fallback finding(s) via mock backend (no LLM is called — verdicts are placeholders for VDI / smoke-test use)
[agentshield] Tier 3 judge: 1 mock verdict(s) attached as `needs_review`. Re-run with --llm-backend boto3-bedrock for real triage.
[agentshield] Wrote: /tmp/mock_judge.json, /tmp/mock_judge.md
```

**Verify the mock verdict landed in the output:**
```bash
jq '.findings[0].triage' /tmp/mock_judge.json
```

Should show:
```json
{
  "verdict": "needs_review",
  "confidence": 0.5,
  "reasoning": "Mock backend — no real LLM was called. This finding has NOT been triaged. Re-run with `--llm-backend boto3-bedrock` (or another real backend) to triage rule `unsanitized-user-input-to-llm-fallback`. See VDI_TESTING.md Stage 4.5 for the mock-testing playbook.",
  "llm_framework_guess": null,
  "backend": "mock",
  "model_id": "mock-model-no-llm-called"
}
```

### 4.5.3 What this proves

- ✅ The CLI dispatch correctly routes `--llm-backend mock` to a backend instance.
- ✅ The orchestrator iterates over fallback findings and calls `.judge()` on each.
- ✅ The verdict is attached to the finding's `triage` field.
- ✅ Output writers (JSON, Markdown, SARIF) serialise the triage data correctly.
- ✅ The whole pipeline runs hermetically — no network, no AWS, no LLM tokens.

### 4.5.4 What this does NOT prove

- ❌ Real Bedrock API calls work (Stage 6).
- ❌ Bedrock model permissions are correct (Stage 5).
- ❌ The judge prompt template produces sensible verdicts (only real-LLM testing can show that).

If Stage 4.5 passes but Stage 6 fails, the issue is in the boto3-Bedrock backend / AWS layer — not the orchestrator or CLI plumbing.

---

## Stage 5 — AWS / Bedrock readiness (only if you'll test the judge)

Verify your VDI can reach Bedrock and that you have a model id you can use.

```bash
aws sts get-caller-identity
aws bedrock list-foundation-models --region us-east-1 --query 'modelSummaries[?contains(modelId, `claude`)].modelId' --output text
# Or if your org uses inference profiles:
aws bedrock list-inference-profiles --region us-east-1
```

Pick a `modelId` (or inference-profile ARN) you have access to. Save it:
```bash
export BEDROCK_MODEL_ID="anthropic.claude-3-7-sonnet-20250219-v1:0"   # example
# or for an inference profile:
# export BEDROCK_MODEL_ID="arn:aws:bedrock:us-east-1:<acct>:application-inference-profile/<id>"
```

---

## Stage 6 — judge tier end-to-end

The repo includes a fixture specifically designed to trigger the fallback rule:
`tests/fixtures/python/d001_fallback_openai_wrapper.py`. The judge will be called on its 1 fallback finding.

```bash
agentshield scan tests/fixtures/python/d001_fallback_openai_wrapper.py \
  --llm-backend boto3-bedrock \
  --bedrock-model-id "$BEDROCK_MODEL_ID" \
  --output-sarif /tmp/judge.sarif \
  --output-json /tmp/judge.json \
  --output-markdown /tmp/judge.md
```

Expected stdout (the verdict counts depend on what Bedrock decides):
```
[agentshield] scan target: tests/fixtures/python/d001_fallback_openai_wrapper.py
[agentshield] Tier 1+2: invoking semgrep on bundled rule pack...
[agentshield] Tier 1+2: 1 raw finding(s)
[agentshield] Normalized: 1 finding(s) (framework=0, fallback=1) detect=1 defend=0 respond=0
[agentshield] Tier 3 judge: triaging 1 fallback finding(s) via boto3-bedrock (model=...)
[agentshield] Tier 3 judge: 1 confirmed, 0 dismissed, 0 needs_review     # or similar
[agentshield] Wrote: /tmp/judge.sarif, /tmp/judge.json, /tmp/judge.md
```

**Verify the judge verdict landed in the output:**
```bash
jq '.findings[0].triage' /tmp/judge.json
```
Should show:
```json
{
  "verdict": "confirmed",
  "confidence": 0.85,
  "reasoning": "...",
  "llm_framework_guess": "openai",
  "backend": "boto3-bedrock",
  "model_id": "anthropic.claude-3-7-sonnet-..."
}
```

**Common Bedrock issues:**
- `AccessDeniedException` → your IAM role doesn't have `bedrock:InvokeModel` for that model
- `ValidationException: model not enabled` → request access in the Bedrock console first
- `ResourceNotFoundException` → model id typo or wrong region (try `--bedrock-region eu-west-1` etc.)
- `Bedrock converse failed: ThrottlingException` → retry; consider a smaller / cheaper model
- Verdict comes back `needs_review` with reasoning "Backend error: ..." → the orchestrator caught the error per [LLM_JUDGE_DESIGN.md §9](./LLM_JUDGE_DESIGN.md). Check `reasoning` for the underlying cause.

---

## Stage 7 — scan a real target repo

Once Stages 1–6 pass, run against an actual JPMC repo that uses agents.

```bash
cd /path/to/some/agent/repo
agentshield scan . \
  --scan-all-files \
  --llm-backend boto3-bedrock \
  --bedrock-model-id "$BEDROCK_MODEL_ID" \
  --output-sarif agentshield.sarif \
  --output-markdown agentshield.md

# Inspect the markdown
less agentshield.md
```

The Markdown groups findings by Detect / Defend / Respond. SARIF can feed GitHub code-scanning, SonarQube, or any SARIF-aware tool.

**Useful flags:**
- `--scan-all-files` — bypasses semgrep's default `.semgrepignore` (which skips `tests/`, `examples/`, `vendor/`, `fixtures/`, etc.). Recommended for any production scan; without it, you may miss findings in subdirectories that follow common ignore patterns.
- `--stage-locally` — copies source files to a local temp tree before scanning, then rewrites SARIF paths back. Use this when scanning code from a Windows UNC path / mapped network drive (`H:\fusion\…`, `\\server\share\…`); semgrep silently fails on UNC paths without this flag.
- `--no-judge` — skips Tier 3 (Bedrock judge). Use when you don't have AWS credentials configured or you want a faster Tier 1+2-only scan.

---

## Stage 7.5 — scan your own agent repo and share the report for triage

This is where the testbed methodology pays off — running AgentShield against an agent you actually own and sharing the report back lets us classify findings TP / FP and apply Phase B-style rule fixes if your codebase surfaces patterns the OSS testbed didn't.

### 7.5.1 Run against a Python SMARTSDK agent

```bash
agentshield scan /path/to/your-python-smartsdk-agent \
  --scan-all-files \
  --no-judge \
  --output-markdown smartsdk_report.md \
  --output-json smartsdk_report.json \
  --output-sarif smartsdk_report.sarif
```

If the agent code lives on a UNC / network-mapped drive (e.g. `H:\fusion\<project>`), add `--stage-locally`:

```bash
agentshield scan H:\fusion\<your-smartsdk-agent> \
  --scan-all-files --stage-locally --no-judge \
  --output-markdown smartsdk_report.md \
  --output-json smartsdk_report.json
```

### 7.5.2 Run against a Spring AI agent

```bash
agentshield scan /path/to/your-spring-ai-agent \
  --scan-all-files \
  --no-judge \
  --output-markdown springai_report.md \
  --output-json springai_report.json \
  --output-sarif springai_report.sarif
```

The Java rule pack (D001-Java, D002-Java, D003-Java, D004-Java, D005-Java, D006-Java, DF001-Java through DF004-Java, R001-Java, D008-Java) covers Spring AI's `ChatClient` / `ChatModel` / `Prompt` / `UserMessage` / `SystemMessage` shapes natively. See [RULES_COVERAGE.md §3 onward](./RULES_COVERAGE.md#3-detect-rules) for per-rule pattern detail.

### 7.5.3 Privacy review before sharing

The Markdown / JSON / SARIF reports include:
- **File paths** (could reveal directory structure or project naming).
- **Line numbers** (low sensitivity).
- **Code snippets** of each flagged line — typically 1-5 lines around the match.
- **Variable / class / method names** from your code.
- **Rule IDs + standardised remediation guidance** from AgentShield.

If the codebase is JPMC-internal / proprietary, do a quick redaction pass before sharing externally. Specific things to look at:
- Hardcoded internal hostnames / endpoints in code snippets.
- Internal package names (e.g. `com.jpmchase.<line-of-business>.<system>`).
- Business-logic-revealing variable names.
- Any code comments near flagged lines that contain confidential context.
- Hardcoded credentials caught by D005 — those are findings you should already be rotating, but redact the actual key value before sharing the snippet.

The structural information (rule fired, finding count, severity distribution, file count per rule) is fine to share even from proprietary codebases; the **snippets** are the part to look at.

### 7.5.4 What to share for the most useful triage

In order of usefulness for a triage conversation:

1. **Best — share the Markdown report** (`*_report.md`). Human-readable, includes the rule, severity, file:line, code snippet, and remediation per finding. Good for up to ~150 findings before it gets unwieldy. Pasting the relevant section directly into chat is ideal.
2. **Alternatively — share the JSON report** (`*_report.json`). Structured data; easier to programmatically aggregate if there's a long tail.
3. **If files are huge** — share the summary table at the top of the Markdown (counts per rule × severity) plus the first 10-20 findings. The long tail typically follows the same patterns as the head.

### 7.5.5 What the triage will produce

Same Phase B methodology that drove the 291 false-positive eliminations on the OSS testbed, applied to your real code:

- **Per-finding TP / FP / NA classification** — every hit reviewed, categorised as a real positive, a false positive, or context-dependent.
- **Rule-tightening recommendations** — if a rule produces consistent FPs on a pattern in your codebase, applying a `metavariable-type` constraint (Java) or `metavariable-regex` constraint (Python) can eliminate the FP class without losing TPs. Phase B's [PHASE_B_TRIAGE.md](./PHASE_B_TRIAGE.md) demonstrates the pattern across four rules.
- **Coverage-gap recommendations** — if your code uses LLM SDKs / call shapes / patterns the rule pack doesn't recognise, that's the most-valuable signal because it surfaces a gap the OSS testbed couldn't.
- **Remediation prioritisation** — for confirmed TPs, ranked guidance on what to fix first based on severity × exploitability in your specific deployment context.

The output of this triage is typically (a) a small set of rule patches, (b) a list of "real concerns to fix in your code," and (c) optionally one or two new rule families if your codebase surfaces a category the OSS testbed missed.

---

## What to report back

If something breaks in any stage, the most useful info to paste:

1. The full command you ran
2. The full stdout + stderr
3. The Stage number where it failed
4. Output of `agentshield --version` and `python3 --version`
5. If Stage 6: the masked Bedrock model ID and region

Don't try to debug deeply — surface the failure quickly so we can decide whether to fix in code or work around in the playbook.

---

## What's NOT in this build (intentional)

| Capability | Status | Notes |
|---|---|---|
| Tier 1+2 semgrep scan | ✅ shipped | A2 |
| Normalize SARIF → typed Findings | ✅ shipped | A3 |
| SARIF / JSON / Markdown reports | ✅ shipped | A4 |
| Tier 3 judge (boto3-Bedrock) | ✅ shipped | B1, B4 |
| Detect rules (D001 fw + fb, D002, D003, D004, D005, D006, D007, D008) | ✅ shipped | OWASP LLM01-LLM05, LLM07, LLM08 covered |
| Defend rules (DF001, DF002, DF003, DF004) | ✅ shipped | OWASP LLM06, LLM10 covered |
| Respond rules (R001) | ✅ shipped | OWASP LLM10 audit covered. R002 (logged-without-redaction) retired in Phase E — see ROADMAP §3.8. |
| Java parity for D001-D006, DF001-DF004, R001 | ✅ shipped | langchain4j + Spring AI + AWS Bedrock Java SDK + Azure OpenAI Java. DF001-Java + R001-Java tightened in Phase E (Lombok @Slf4j + advisor wiring + CompletableFuture suppressors). |
| OWASP LLM Top 10 coverage | ✅ 9 / 10 | LLM09 Misinformation out of SAST scope |
| OWASP Agentic AI Top 10 coverage | ✅ 8 / 11 | T5 / T7 / T9 out of SAST scope |
| MITRE ATLAS mappings | ✅ 6 techniques | T0010 / T0011 / T0012 / T0019 / T0024 / T0050 / T0051 / T0053 |
| First-class CWE mappings | ✅ 8 distinct CWEs | CWE-78 / 89 / 94 / 200 / 400 / 494 / 532 / 732 / 798 / 829 |
| Testbed validation (10 OSS projects + 2 synthetic vuln apps) | ✅ shipped | See [TESTBED_VALIDATION.md](./TESTBED_VALIDATION.md) |
| Phase B triage (291 FPs eliminated, 0 TPs lost) | ✅ shipped | See [PHASE_B_TRIAGE.md](./PHASE_B_TRIAGE.md) |
| `--stage-locally` flag for Windows UNC paths | ✅ shipped | Workaround for semgrep silently failing on `H:\fusion\…` style mapped drives |
| Audit log to `judge_audit.jsonl` | ⏳ planned | B5 |
| SMARTSDK judge backend | ⏳ planned | B2 |
| GitHub Copilot judge backend | ⏳ planned | B3 |
| Tier 4 discovery pass | ⏳ planned | D |
| Trivy supply-chain scan | ⏳ planned | F |
| TypeScript / JavaScript language support | ⏳ planned | LangChain.js / Vercel AI SDK / Mastra / OpenAI JS SDK |
| Tier 3 judge calibration with Phase B triage labels | ⏳ planned | Force-multiplier on fallback findings |
