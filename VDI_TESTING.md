# VDI Testing Playbook (v2)

Status: 2026-05-06 (Phase F architecture v2)
Use after any pull from `origin/main` (or `architecture-v2` until v2 merges) to validate AgentShield in your VDI before touching real target repos.

> **Just want the 5-minute version?** See [QUICKSTART_VDI.md](./QUICKSTART_VDI.md) for the minimum command sequence to scan a real repo end-to-end. This file is the comprehensive staged validation playbook with troubleshooting per stage.

This playbook is staged so you can verify each layer independently — if Stage N fails, Stages 1..N-1 are still trustworthy.

> **v2 architecture quick reference.** AgentShield runs in 2 tiers:
> - **Tier 1** — semgrep with a 6-family rule pack (`agentshield scan`)
> - **Tier 2** — LLM-as-scanner via Copilot in your IDE, using bundled skill files emitted into `<target>/.agentshield/`
>
> Both tiers are mandatory. After Tier 1, you paste a prompt into Copilot Chat; Copilot writes `tier2-findings.json`; `agentshield merge` produces the unified report. **No AWS / Bedrock dependency.** See [TIER2_USAGE.md](./TIER2_USAGE.md) for the Copilot walkthrough.

---

## Stage 0 — prerequisites

Run all of these on the VDI; each should produce non-empty output.

```bash
python3 --version              # need 3.10+; if shell default is 3.9, find a 3.10/3.11/3.12 explicitly:
ls /usr/local/bin/python3.* /opt/homebrew/bin/python3.* 2>/dev/null
git --version
pip --version
```

**For Tier 2:** you need an IDE with GitHub Copilot Chat enabled (VS Code or JetBrains). No CLI prerequisites for Tier 2 — Copilot runs in your IDE.

---

## Stage 1 — clone, venv, install

```bash
git clone git@github.com:suganthiaravind/agentshield.git
cd agentshield

# Use whichever Python 3.10+ you found in Stage 0
python3.11 -m venv .venv
source .venv/bin/activate

pip install --upgrade pip
pip install -e ".[semgrep,dev]"     # ~1-2 min; semgrep is the bulk
```

**Success markers:**
- No error output
- `which agentshield` returns `<repo>/.venv/bin/agentshield`
- `which semgrep` returns `<repo>/.venv/bin/semgrep`

**Common issues:**
- `Package 'agentshield' requires a different Python: 3.9.X not in '>=3.10'` → use a newer Python interpreter
- semgrep wheel is large; if pip times out, retry once
- corporate proxy: `pip install --index-url <internal-pypi-mirror> -e ...`

> **Note:** the v1 `judge` optional dependency (boto3) is gone in v2. If you used to install with `[semgrep,judge,dev]`, drop the `judge` part.

---

## Stage 1b — refreshing an existing clone

If you've already done Stage 1 once and just want to pull the latest:

```bash
cd /path/to/your/agentshield/clone
source .venv/bin/activate
git fetch origin
git checkout architecture-v2          # or main once v2 merges
git pull
pip install -e ".[semgrep,dev]"       # re-install in case dependencies changed
pytest tests/ -v                      # confirm green on your VDI Python
```

---

## Stage 2 — `--version`

```bash
agentshield --version
```

Expected: `agentshield 0.1.0`

---

## Stage 3 — unit tests (no network)

```bash
pytest tests/ -v
```

**Success markers:**
- **123 tests pass** (rule golden + emitter + merger + skill-template invariants + normalizer + writers + CLI exclude)
- Suite finishes in ~25-45s

If anything fails here, stop and report. The package is broken on your VDI; nothing later will work right.

---

## Stage 4 — Tier 1 scan + skill emission

Run a Tier 1 scan against an in-repo fixture. The scan emits skill files into the target's `.agentshield/` so Tier 2 can run.

```bash
mkdir -p /tmp/agentshield-vdi-test
cp tests/fixtures/python/d001_flask_langchain.py /tmp/agentshield-vdi-test/
agentshield scan /tmp/agentshield-vdi-test --scan-all-files
```

**Expected output (key sections):**

```
[agentshield] Tier 1: invoking semgrep on bundled rule pack (6 families)...
[agentshield] Tier 1: 1 raw finding(s)
[agentshield] Normalized: 1 finding(s) detect=1 defend=0 respond=0

======================================================================
⚠ TIER 2 NOT YET RUN — scanning is INCOMPLETE.
======================================================================

Skill files written:
  - .agentshield/tier2-bootstrap.md
  - .agentshield/tier2-checklist.md
  - .agentshield/tier2-output-schema.md
  - .agentshield/tier1-results.json
  + appended .agentshield/ to /tmp/agentshield-vdi-test/.gitignore

Next step — paste this into Copilot Chat in your IDE:
  @workspace Please run AgentShield Tier 2. ...
```

**Verify the skill files exist:**

```bash
ls -la /tmp/agentshield-vdi-test/.agentshield/
# Expected: tier1-results.json, tier2-bootstrap.md, tier2-checklist.md, tier2-output-schema.md

cat /tmp/agentshield-vdi-test/.agentshield/tier1-results.json | head -10
# Should show tier=1, scanned_at, agentshield_tier1_fingerprint, scanned_files, findings
```

**Useful flags for Stage 4:**
- `--scan-all-files` — bypass semgrep's `.semgrepignore` (recommended for production scans)
- `--exclude '**/src/test/**' --exclude '**/tests/**'` — drop test directories under `--scan-all-files`. Repeatable.
- `--stage-locally` — copy source files locally before scan (Windows UNC / mapped network drive workaround for `H:\fusion\…` paths)
- `--no-emit` — Tier-1-only mode for diagnostics; skips skill-file emission. Final banner warns scanning is incomplete.
- `--output-{markdown,json,sarif} <path>` — write Tier-1-only report to disk. **Note:** the unified Tier 1 + Tier 2 report comes from `agentshield merge`, not from this flag.

---

## Stage 5 — Tier 2 via Copilot Chat

This is the new mandatory step in v2. See [TIER2_USAGE.md](./TIER2_USAGE.md) for screenshots / detailed walkthrough.

**Quick version:**

1. Open the target repo in VS Code or JetBrains. For the Stage 4 example: `code /tmp/agentshield-vdi-test` (or open the folder via JetBrains).
2. Open Copilot Chat (`Ctrl+Shift+I` in VS Code; JetBrains: AI Assistant tool window).
3. Paste this prompt:

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

4. Wait for Copilot to finish. Time depends on repo size — single-file demo: <1 min; 50-file repo: 5-15 min.
5. Verify the output exists:

   ```bash
   ls /tmp/agentshield-vdi-test/.agentshield/tier2-findings.json
   cat /tmp/agentshield-vdi-test/.agentshield/tier2-findings.json | python3 -m json.tool | head -20
   ```

   It should be a JSON object with `tier: 2`, `agentshield_tier1_fingerprint` (matching Tier 1's), and `findings: [...]`.

**If Copilot doesn't write the file:** re-prompt it pointing at the missing path, e.g. *"You said you finished but `.agentshield/tier2-findings.json` doesn't exist. Please write the JSON output to that path."* Some Copilot variants need an explicit "write to disk" instruction.

**If Copilot's JSON shape is wrong:** the merger (Stage 6) will print field-path-specific schema errors. Re-prompt Copilot with the specific error.

---

## Stage 6 — `agentshield merge` → unified report

```bash
agentshield merge /tmp/agentshield-vdi-test --output-markdown /tmp/agentshield-vdi-test/report.md
```

**Expected output:**

```
[agentshield] merge target: /tmp/agentshield-vdi-test
[agentshield] ✓ Tier 1 + Tier 2 fresh; merging.
[agentshield] Net actionable findings: <N>
[agentshield] Wrote unified report(s): /tmp/agentshield-vdi-test/report.md
```

**Open the report:**

```bash
less /tmp/agentshield-vdi-test/report.md
```

The Markdown contains:
- **Summary** — Tier 1 / Tier 2 / FP-marked / actionable counts
- **Tier 1 findings** — annotated with Tier 2's TP/CD/FP verdicts where applicable
- **Tier 2 net-new findings** — what rules missed
- **Coverage matrix** — which OWASP / Agentic / ATLAS / CWE items the scan touched

**Other output formats:**

```bash
agentshield merge /tmp/agentshield-vdi-test \
  --output-sarif /tmp/agentshield-vdi-test/report.sarif \
  --output-json /tmp/agentshield-vdi-test/report.json
```

**Banners that may appear:**
- `⚠ Tier 2 has NOT been run` — `tier2-findings.json` is missing. Re-do Stage 5.
- `❌ Tier 2 output failed schema validation` — Copilot's JSON is malformed. Re-prompt with the specific field-path errors printed below.
- `⚠ STALE Tier 2: fingerprint mismatch` — the code or rule pack changed between Tier 1 and Tier 2 runs. Re-run Stage 5 (Copilot Chat with the same prompt) to refresh.

---

## Stage 7 — scan a real target repo

Same workflow as Stages 4–6, applied to your actual agent codebase.

### 7.1 Run against a Python SMARTSDK / langchain agent

```bash
agentshield scan /path/to/your-python-agent \
  --scan-all-files \
  --exclude '**/tests/**' \
  --output-markdown /tmp/python-tier1.md
# Then Stage 5 in your IDE, then Stage 6:
agentshield merge /path/to/your-python-agent \
  --output-markdown /tmp/python-unified.md \
  --output-json /tmp/python-unified.json
```

### 7.2 Run against a Spring AI / langchain4j agent

```bash
agentshield scan /path/to/your-spring-ai-agent \
  --scan-all-files \
  --exclude '**/src/test/**' \
  --output-markdown /tmp/java-tier1.md
# Then Stage 5 in your IDE, then Stage 6:
agentshield merge /path/to/your-spring-ai-agent \
  --output-markdown /tmp/java-unified.md
```

### 7.3 If the codebase is on a network drive (Windows UNC)

Add `--stage-locally` to the scan:

```bash
agentshield scan H:\fusion\<project> \
  --scan-all-files --stage-locally \
  --exclude '**/src/test/**'
```

The skill files still get emitted into `H:\fusion\<project>\.agentshield\` (the staging is just for the semgrep pass).

---

## Stage 7.5 — privacy review before sharing

The reports include:
- **File paths** (could reveal directory structure or project naming)
- **Line numbers** (low sensitivity)
- **Code snippets** of each flagged line — typically 1-5 lines around the match
- **Variable / class / method names** from your code
- **Rule IDs + standardised remediation guidance** from AgentShield

If the codebase is JPMC-internal / proprietary, do a quick redaction pass before sharing externally:
- Hardcoded internal hostnames / endpoints in code snippets
- Internal package names (e.g. `com.jpmchase.<line-of-business>.<system>`)
- Business-logic-revealing variable names
- Any code comments near flagged lines that contain confidential context
- Hardcoded credentials caught by D005 — those are findings you should already be rotating, but redact the actual key value before sharing the snippet
- **Tier 2 findings can include richer reasoning text** (Copilot's interpretation of code intent) — review for inadvertent disclosure

The structural information (rule fired, finding count, severity distribution, coverage matrix) is fine to share even from proprietary codebases; the **snippets and Tier 2 reasoning** are the parts to look at.

---

## What to report back

If something breaks in any stage, the most useful info to paste:

1. The full command you ran
2. The full stdout + stderr
3. The Stage number where it failed
4. Output of `agentshield --version` and `python3 --version`
5. If Stage 5: which IDE + Copilot version, and Copilot's response (or absence thereof)
6. If Stage 6: any schema-error field paths the merger printed

Don't try to debug deeply — surface the failure quickly so we can decide whether to fix in code, fix the skill files, or work around in the playbook.

---

## What's in this build

| Capability | Status | Notes |
|---|---|---|
| Tier 1 semgrep scan (6 rule families) | ✅ shipped | F.2 prune; D001-fw, D003, D004, D005, D008, DF003 (Python + Java) |
| Tier 2 LLM-as-scanner via Copilot | ✅ shipped | F.3 / F.4. 56-check checklist covers OWASP LLM v2 + Agentic Top 10 + ATLAS + CWE + Phase E gaps |
| `agentshield merge` unified report | ✅ shipped | F.5. Markdown / JSON / SARIF. Stale-detection via fingerprint. |
| Skill-file emission into target | ✅ shipped | F.4. Auto-gitignored. |
| Tier 2 schema validation | ✅ shipped | F.5. Field-path errors so Copilot can be re-prompted |
| `--exclude PATTERN` glob filter | ✅ shipped | E.3. Repeatable. |
| `--stage-locally` for Windows UNC paths | ✅ shipped | Workaround for semgrep silently failing on `H:\fusion\…` style mapped drives |
| OWASP LLM Top 10 v2 coverage | ✅ 10 / 10 | Tier 1 covers the testable subset; Tier 2 checklist covers all 10 including LLM09 |
| OWASP Agentic AI Top 10 coverage | ✅ 11 / 11 | Tier 1 covers structural items; Tier 2 covers T5/T7/T9 as reviewer-judgment |
| MITRE ATLAS mappings | ✅ 6 techniques | In Tier 2 checklist |
| First-class CWE mappings | ✅ 10 distinct CWEs | Across both tiers |
| Headless CI Tier 2 backend | ⏳ not built | Future work — would emit `tier2-findings.json` programmatically without Copilot. The merger is backend-agnostic. |
| TypeScript / JavaScript Tier 1 rules | ⏳ not built | Tier 2 (Copilot) reads any language; Tier 1 stays Py/Java |
| Trivy supply-chain scan | ⏳ planned | Track F |

## What's been retired in v2

| Capability | Status | Why |
|---|---|---|
| Tier 3 LLM judge (boto3-Bedrock backend) | ❌ removed in F.6 | Replaced by Tier 2 LLM-as-scanner. v2 has no in-process AWS dep. |
| Mock judge backend (`--llm-backend mock`) | ❌ removed in F.6 | Was for AWS-free smoke testing; no longer needed (Tier 2 doesn't use AWS) |
| Tier 4 discovery pass (`--discovery`) | ❌ removed in F.6 | Folded into Tier 2's whole-repo walk |
| 8 rule families (D001-fb, D002, D006, D007, DF001, DF002, DF004, R001) | ❌ retired in F.2 | Moved to Tier 2 checklist; archived in `agentshield/_retired_v2/` |
| `--no-judge`, `--llm-backend`, `--bedrock-model-id`, `--bedrock-region` flags | ❌ removed in F.6 | Wired to deleted judge tier |
