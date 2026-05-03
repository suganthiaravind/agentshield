# VDI Testing Playbook

Status: 2026-05-03
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
- 48 tests pass (11 judge backend + 13 orchestrator + 7 normalizer + 5 golden + 12 writer)
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
  --llm-backend boto3-bedrock \
  --bedrock-model-id "$BEDROCK_MODEL_ID" \
  --output-sarif agentshield.sarif \
  --output-markdown agentshield.md

# Inspect the markdown
less agentshield.md
```

The Markdown groups findings by Detect / Defend / Respond. SARIF can feed GitHub code-scanning, SonarQube, or any SARIF-aware tool.

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

| Capability | Status | Track |
|---|---|---|
| Tier 1+2 semgrep scan | ✅ shipped | A2 |
| Normalize SARIF → typed Findings | ✅ shipped | A3 |
| SARIF / JSON / Markdown reports | ✅ shipped | A4 |
| Tier 3 judge (boto3-Bedrock) | ✅ shipped | B1, B4 |
| Audit log to `judge_audit.jsonl` | ⏳ planned | B5 |
| SMARTSDK judge backend | ⏳ planned | B2 |
| GitHub Copilot judge backend | ⏳ planned | B3 |
| Tier 4 discovery pass | ⏳ planned | D |
| Trivy supply-chain scan | ⏳ planned | F |
| Zero-trust gap rules (DF003-DF007, D004-D005) | ⏳ planned | E |
