# Per-Tier Execution Flows

Status: 2026-05-03
Companion to: [ARCHITECTURE.md](./ARCHITECTURE.md) (system view), [ARCHITECTURE_RATIONALE.md](./ARCHITECTURE_RATIONALE.md), [GLOSSARY.md](./GLOSSARY.md)

This doc walks through what happens inside each tier when `agentshield scan <path>` runs — input contracts, transformation steps, output contracts, error paths, and pointers to the exact source files. Read [ARCHITECTURE.md §1](./ARCHITECTURE.md#1-system-diagram) first for the high-level picture.

## Contents

- [0. End-to-end orchestration (CLI scan command)](#0-end-to-end-orchestration-cli-scan-command)
- [1. Tier 1 — framework-specific semgrep rules](#1-tier-1--framework-specific-semgrep-rules)
- [2. Tier 2 — fallback semgrep rules](#2-tier-2--fallback-semgrep-rules)
- [3. Normalization step — SARIF to typed Finding](#3-normalization-step--sarif-to-typed-finding)
- [4. Tier 3 — LLM judge orchestration](#4-tier-3--llm-judge-orchestration)
- [5. Tier 4 — discovery pass (planned)](#5-tier-4--discovery-pass-planned)
- [6. Report writing step](#6-report-writing-step)
- [7. End-to-end example with concrete data](#7-end-to-end-example-with-concrete-data)

---

## 0. End-to-end orchestration (CLI scan command)

The CLI's `scan` subcommand in [`agentshield/cli.py`](./agentshield/cli.py) coordinates every tier in sequence. The full flow:

```
            ┌──────────────────────────────────────────┐
            │ argparse parses CLI args                 │
            │ (path, --llm-backend, --bedrock-model-id │
            │  --no-judge, --output-*, --scan-all-files)│
            └────────────────┬─────────────────────────┘
                             ▼
         ┌─────────────────────────────────────────┐
         │ Tier 1+2: SemgrepRunner.run(target)     │  ── §1, §2
         │   subprocess: semgrep scan --sarif      │
         │   one invocation covers both tiers      │
         │   (single rule pack contains both)      │
         └────────────────┬────────────────────────┘
                          ▼
         ┌─────────────────────────────────────────┐
         │ A3: Normalizer.normalize(sarif)         │  ── §3
         │   SARIF → list[Finding]                 │
         │   tier inferred from rule metadata      │
         │   framework_mappings attached           │
         └────────────────┬────────────────────────┘
                          ▼
         ┌─────────────────────────────────────────┐
         │ Tier 3: JudgeOrchestrator.triage(...)   │  ── §4
         │   filters tier=="fallback"              │
         │   per-finding: build window+imports,    │
         │     call backend, attach TriageVerdict  │
         │   non-fallback findings pass through    │
         │   (skipped if --no-judge or no model id)│
         └────────────────┬────────────────────────┘
                          ▼
         ┌─────────────────────────────────────────┐
         │ Tier 4: Discovery — planned, stub today │  ── §5
         └────────────────┬────────────────────────┘
                          ▼
         ┌─────────────────────────────────────────┐
         │ A4: Report writers                      │  ── §6
         │   SarifWriter / JsonWriter /            │
         │   MarkdownWriter, all reading the same  │
         │   list[Finding] (no drift between views)│
         └────────────────┬────────────────────────┘
                          ▼
                   exit code 0 / 1 / 2
```

Key invariant: **`list[Finding]` is the universal currency between tiers.** Every tier either consumes it or produces it. Report writers, the judge, and the (future) discovery pass all read the same shape, so adding a new input source (e.g. Trivy via Track F) means producing `Finding` objects — not changing any downstream code.

---

## 1. Tier 1 — framework-specific semgrep rules

**Purpose:** detect known LLM/agent invocation patterns in code AgentShield's rule pack explicitly understands. High precision, deterministic, no LLM involvement.

### Inputs

| Name | Source | Contract |
|---|---|---|
| target path | CLI arg `args.path` | filesystem path to a file or directory |
| bundled rule pack | shipped inside the package | `agentshield/rules/{detect,defend,respond}/*.yaml` minus the `*fallback*` files |
| timeout | constructor default 600s | per-invocation hard cap |
| extra flags | constructor or `--scan-all-files` | extra semgrep CLI args |

### Process — step by step

1. **Locate the rule pack**
   - File: [`agentshield/runner/semgrep_runner.py`](./agentshield/runner/semgrep_runner.py)
   - `SemgrepRunner._default_rules_path()` resolves `Path(__file__).resolve().parent.parent / "rules"`
   - Returns the directory shipped with the package (works for editable installs and built wheels).

2. **Locate the semgrep binary**
   - `_semgrep_executable()` checks `shutil.which("semgrep")` first
   - Falls back to `Path(sys.executable).parent / "semgrep"` so a venv install without `source activate` still works
   - Raises `SemgrepRunnerError` if neither resolves

3. **(Optional) Enumerate files explicitly**
   - When `--scan-all-files` is passed, the CLI walks the target tree and passes each `.py`/`.java` file as a positional arg
   - This bypasses semgrep's default `.semgrepignore` (which silently skips `tests/`, `examples/`, `vendor/`, `fixtures/`, etc.)
   - File: [`agentshield/cli.py`](./agentshield/cli.py) `cmd_scan` — the `if args.scan_all_files:` branch

4. **Build the subprocess command**
   ```
   semgrep scan
     --config <bundled-rules-dir>
     --sarif --quiet
     --no-git-ignore
     --metrics off
     --encoding utf-8 (forced via Python subprocess kwargs)
     [--scan-all-files: each file as positional arg, else target dir]
   ```
   - `--no-git-ignore` disables git-based filtering (target may not be a git repo)
   - `--metrics off` keeps semgrep from phoning home (VDI compatibility)

5. **Run, with timeout + error handling**
   - `subprocess.run(...)` with `encoding="utf-8", errors="replace"` (Windows cp1252 fix from VDI testing)
   - On `subprocess.TimeoutExpired` → `SemgrepRunnerError`
   - Exit code ≥ 2 → tool error; raise `SemgrepRunnerError` with stderr captured
   - Exit code 0 or 1 → normal completion (1 just means findings exist, depending on flags)

6. **Parse the JSON output**
   - `json.loads(result.stdout)` → SARIF v2.1.0 dict
   - `JSONDecodeError` → `SemgrepRunnerError` with first 200 chars of stdout for debug

### Outputs

A SARIF dict shaped like:
```json
{
  "version": "2.1.0",
  "runs": [{
    "tool": {"driver": {"name": "Semgrep OSS", "rules": [...]}},
    "results": [
      {
        "ruleId": "agentshield.rules.detect.agentshield.detect.unsanitized-user-input-to-llm",
        "level": "error",
        "message": {"text": "User input from an HTTP request..."},
        "locations": [{"physicalLocation": {
          "artifactLocation": {"uri": "/path/to/file.py"},
          "region": {"startLine": 16, "startColumn": 12, ...}
        }}]
      }
    ]
  }]
}
```

The runner does no domain interpretation — semgrep's raw output flows downstream.

### Tier 1 vs Tier 2 — they share the same engine call

The runner doesn't distinguish tiers. It runs *one* `semgrep scan` command across the entire bundled rule pack. Tier partitioning is the normalizer's job (§3) — it reads each rule's `metadata.tier` field and routes to `framework` or `fallback`.

This is a deliberate design choice: a single subprocess call is faster and lets semgrep optimize across rules. The two tiers are cheap to separate after the fact.

---

## 2. Tier 2 — fallback semgrep rules

**Purpose:** catch LLM/agent invocations in unknown wrappers / internal SDKs the framework rules don't enumerate. Lower precision, gated by import hints + verb-shape regex.

### Same runner, different rules

Tier 2 rules ship in the same `agentshield/rules/` tree:
- `agentshield/rules/detect/D001-fallback-llm-import-and-verb-shape.yaml` (Python)
- `agentshield/rules/detect/D001-fallback-llm-import-and-verb-shape-java.yaml` (Java)

Each carries `metadata.tier: fallback` so the normalizer can route appropriately, plus `metadata.confidence: low` so downstream consumers know to triage these via the LLM judge.

### What makes a fallback rule fire

The rule structure (semgrep YAML, condensed):
```yaml
mode: taint
pattern-sources:
  - <HTTP / CLI input — same as framework D001>
pattern-sinks:
  - patterns:
      # Gating: file imports at least one LLM-adjacent library
      - pattern-either:
          - pattern-inside: |
              import openai
              ...
          - pattern-inside: |
              from openai import $Y
              ...
          # ... 14 more LLM-adjacent imports (anthropic, boto3, vertexai,
          # cohere, mistralai, together, groq, replicate, smart_sdk, etc.)
      # Match: any method call
      - pattern: $X.$VERB($Y, ...)
      # Constraint: verb name looks LLM-shaped
      - metavariable-regex:
          metavariable: $VERB
          regex: "^(invoke|ainvoke|call|run|chat|complete|generate|predict|stream|embed|query|ask|send|respond|create|invoke_model|converse|...)$"
```

So a finding fires when: file has *any* LLM-adjacent import AND there's a method call whose name matches the verb regex AND user input flows into it.

### Why a fallback tier exists

[ARCHITECTURE_RATIONALE.md §2](./ARCHITECTURE_RATIONALE.md#2-why-a-three-tier-semgrep--fallback--llm-judge-architecture) makes the case: the AI ecosystem evolves faster than rule maintenance. Internal wrappers (someone's bespoke `acme_llm.Client().complete(user_input)`) won't show up in any framework-specific rule. The fallback rule's import-gate + verb-regex combo catches them — at the cost of higher false-positive rate, which the LLM judge tier (§4) then triages.

### Outputs

Same SARIF shape as Tier 1; rule ids identify which rule fired. Both tiers' findings flow through the same normalizer.

---

## 3. Normalization step — SARIF to typed Finding

**Purpose:** convert raw SARIF (which doesn't carry our custom metadata) into typed `Finding` objects with framework mappings, severity, tier, and confidence resolved from the rule YAMLs.

### Why this step exists

Semgrep doesn't propagate arbitrary metadata to SARIF. The custom fields we put under `metadata` in each rule (`agentshield_id`, `category`, `tier`, `framework_mappings`, `confidence`, `severity_normalized`) live in the YAML but never appear in the SARIF output.

The normalizer reads those YAMLs at construction time and indexes by canonical rule id, then enriches each SARIF result with the metadata it remembers.

### Inputs

| Name | Source | Contract |
|---|---|---|
| SARIF dict | output of [§1 / §2](#1-tier-1--framework-specific-semgrep-rules) | parsed JSON |
| bundled rules path | constructor default or override | same path used by SemgrepRunner |

### Process

File: [`agentshield/normalize/normalizer.py`](./agentshield/normalize/normalizer.py)

1. **Build the rule index** (`Normalizer._load_rules`)
   - `rules_path.rglob("*.yaml")` — walk the bundled rule pack
   - For each YAML file, parse via PyYAML, extract `rules[*].id` and `rules[*].metadata`
   - Returns `dict[str, dict]` mapping canonical rule id → full rule body

2. **Resolve canonical id from SARIF prefix** (`_canonical_rule_id`)
   - Semgrep prefixes rule ids with the file path: `agentshield.rules.detect.agentshield.detect.unsanitized-user-input-to-llm`
   - Suffix-match against known canonical ids: any canonical id that's a `endswith` match wins
   - Robust to file path changes (no hard-coded prefix stripping)

3. **For each SARIF result, build a Finding**
   - Resolve canonical rule → look up metadata
   - Build `CodeLocation` from `physicalLocation` (uri, region)
   - Resolve `tier` (`metadata.tier == "fallback"` → `fallback`, else `framework`)
   - Resolve `severity` (`metadata.severity_normalized` wins, falls back to YAML severity → ladder map)
   - Resolve `confidence` (explicit `metadata.confidence` wins; fallback rules default to `low`, framework defaults to `high`)
   - Resolve `language` (first entry in `rule.languages`)
   - Build `FrameworkMappings` from `metadata.framework_mappings`
   - Attach `agentshield_id`, message, etc.

4. **Sort deterministically**
   - By `(file_path, start_line, rule_id)` — same input → same output ordering, every run

### Outputs

`list[Finding]` where each Finding has:
```python
class Finding:
    rule_id: str                          # canonical
    rule_id_short: str                    # last segment
    agentshield_id: str                   # AS-D-001
    category: "detect" | "defend" | "respond"
    tier: "framework" | "fallback" | "judge" | "discovery"
    severity: "critical" | "high" | "medium" | "low" | "info"
    confidence: "high" | "medium" | "low"
    location: CodeLocation
    message: str
    language: str | None
    framework_mappings: FrameworkMappings  # OWASP LLM, Agentic, NIST, MITRE, AS-v1
    triage: TriageVerdict | None           # filled in by Tier 3, None for now
```

The dual-mapping pattern (`category` + `framework_mappings`) is the key invariant — see [ARCHITECTURE_RATIONALE.md §4](./ARCHITECTURE_RATIONALE.md#4-why-detect--defend--respond-taxonomy-with-dual-mapping-to-security-frameworks).

---

## 4. Tier 3 — LLM judge orchestration

**Purpose:** triage low-confidence (`tier="fallback"`) findings via an LLM that gets the code context and returns a verdict. Designed per [LLM_JUDGE_DESIGN.md](./LLM_JUDGE_DESIGN.md).

### Inputs

| Name | Source | Contract |
|---|---|---|
| `findings: list[Finding]` | output of [§3 normalize](#3-normalization-step--sarif-to-typed-finding) | typed Finding objects |
| backend | CLI flag `--llm-backend` + model id flags | `JudgeBackend` Protocol implementation |

### When does the judge actually run?

The CLI checks several preconditions before invoking the orchestrator:

```python
fallback_count = JudgeOrchestrator.count_fallback(findings)
if args.no_judge:                       # explicit skip
    ...skip with notice
elif fallback_count == 0:               # nothing to triage
    ...skip with notice
elif backend_choice == "boto3-bedrock":
    if not args.bedrock_model_id:       # missing config
        ...skip with helpful error
    else:
        backend = Boto3BedrockBackend(...)
        orchestrator = JudgeOrchestrator(backend)
        findings = orchestrator.triage(findings)
elif backend_choice in {"smartsdk", "copilot"}:  # B2/B3 — not yet implemented
    ...skip with planned-track notice
```

### Process — step by step

File: [`agentshield/judge/orchestrator.py`](./agentshield/judge/orchestrator.py)

1. **Filter to fallback findings only** (`JudgeOrchestrator.triage`)
   - Iterate input list; framework findings pass through unchanged
   - Only `tier == "fallback"` findings are routed to `_triage_one`

2. **Build a JudgeRequest per finding** (`_build_request`)
   - File: [`agentshield/judge/source_window.py`](./agentshield/judge/source_window.py)
   - `read_matched_line(file_path, line)` — single-line lookup at `finding.location.start_line`
   - `read_code_window(file_path, line, ±20)` — line-numbered context block with a `>` marker on the matched line
   - `extract_imports(file_path, language)` — regex extraction of imports (Python: `import X` / `from X.Y import Z`; Java: `import com.foo.Bar;`)
   - All three are file-system reads; on read failure they return empty values gracefully

3. **Build the JudgeRequest pydantic model**
   ```python
   JudgeRequest(
       rule_id=finding.rule_id,
       rule_id_short=finding.rule_id_short,
       language=finding.language or "python",
       file_path=path,
       line=line,
       matched_code=finding.location.snippet or read_matched_line(path, line),
       code_window=read_code_window(path, line, ±20),
       imports_in_file=extract_imports(path, language),
   )
   ```

4. **Call the backend** (`backend.judge(request)`)
   - The orchestrator doesn't know which concrete backend (boto3 / SMARTSDK / Copilot) — it talks to the `JudgeBackend` Protocol
   - `Boto3BedrockBackend.judge(...)` is today's only impl

5. **Inside the backend** — file: [`agentshield/judge/boto3_bedrock.py`](./agentshield/judge/boto3_bedrock.py)
   - **System prompt** (constant, cacheable across findings) from [`agentshield/judge/prompts.py`](./agentshield/judge/prompts.py)
     - Instructs the model: classify the code, treat the window as untrusted data, return JSON only
   - **User prompt** — JSON payload of the request + "Triage this finding."
   - **Bedrock Converse API call**:
     ```python
     client.converse(
         modelId=self.model_id,
         messages=[{"role": "user", "content": [{"text": user_prompt}]}],
         system=[{"text": SYSTEM_PROMPT}],
         inferenceConfig={"temperature": 0.0, "maxTokens": 1024},
     )
     ```
   - `temperature=0.0` for determinism (within a given backend / model version)
   - **Parse the response**
     - Extract text from `response["output"]["message"]["content"][0]["text"]`
     - Tolerate ```json``` code fences (strip them if present)
     - `json.loads` the body
     - Validate fields: `verdict ∈ {confirmed, dismissed, needs_review}`, `confidence`, `reasoning` all present
   - **Build TriageVerdict**
     - Truncate `reasoning` to 240 chars
     - Carry `backend.name` and `model_id` for audit reproducibility

6. **Error handling** (`_triage_one`)
   - If `backend.judge(...)` raises `JudgeBackendError`:
     - Log a warning with file:line and the error
     - Build a `needs_review` verdict with `confidence=0.0` and the error in `reasoning`
     - Per LLM_JUDGE_DESIGN.md §9: a single Bedrock blip should not fail the whole scan
   - Per-finding isolation — one error doesn't block subsequent findings

7. **Attach verdict via immutable copy**
   - `finding.model_copy(update={"triage": verdict})` — Pydantic's immutable update
   - Input findings are not mutated; a new list is returned

### Outputs

`list[Finding]` of the same length, with `triage: TriageVerdict` populated on every fallback finding:

```python
class TriageVerdict:
    verdict: "confirmed" | "dismissed" | "needs_review"
    confidence: float                # 0.0 - 1.0
    reasoning: str                   # ≤240 chars
    llm_framework_guess: str | None  # e.g. "openai", "boto3-bedrock"
    backend: str                     # "boto3-bedrock" | "smartsdk" | "copilot"
    model_id: str                    # for audit reproducibility
```

### What downstream consumers do with this

- **SARIF writer** ([§6](#6-report-writing-step)): puts the verdict in `properties.triage` on the result
- **JSON writer**: includes the full TriageVerdict in the per-finding dump
- **Markdown writer**: renders `confirmed` findings prominently, surfaces `needs_review` separately, currently shows `dismissed` too (a future filter could suppress them)

---

## 5. Tier 4 — discovery pass (planned)

**Purpose:** for files that import LLM-adjacent libraries but produced *zero* findings, ask the LLM "did we miss any LLM call here?" Catches patterns the framework rules don't enumerate AND that don't match the fallback verb regex (e.g. internal naming like `processWithModel(...)`).

### Status

Stubbed in [`agentshield/discovery/__init__.py`](./agentshield/discovery/__init__.py); full implementation is Track D. The CLI flag `--discovery` is wired through but currently emits a TODO line.

### Planned flow

1. **List candidate files**
   - Walk target tree
   - Filter to files where `extract_imports()` returns a known LLM-adjacent import
   - Filter further: files with zero existing Tier 1+2 findings (otherwise they're already covered)

2. **For each candidate, send the file body to the LLM**
   - Different system prompt from the judge tier (different role: "find LLM calls" vs "triage this finding")
   - File-level scope; chunked if > token limit

3. **Parse the LLM response into Findings**
   - Each suggested LLM call becomes a synthetic `Finding` with `tier="discovery"`
   - `confidence="low"` by default (tier 4 is strictly heuristic)

4. **Optionally route through the judge tier** for verdicts on the suggestions

### Why this is deferred

Validates after Tier 3 has real-world precision data. Discovery has the worst SNR of any tier and benefits from the judge tier being well-calibrated first. See [LLM_JUDGE_DESIGN.md §11](./LLM_JUDGE_DESIGN.md) "Open questions" for related design decisions.

---

## 6. Report writing step

**Purpose:** convert the final `list[Finding]` into the three output formats: SARIF (primary, CI-consumable), JSON (programmatic), Markdown (human review).

All three writers consume the same `list[Finding]` so the views cannot drift. Adding a new format is just a new writer class.

### SarifWriter — file: [`agentshield/report/sarif.py`](./agentshield/report/sarif.py)

1. **Deduplicate rule descriptors**
   - Iterate findings; first sighting of each `rule_id` builds a rule descriptor
   - All AgentShield metadata (agentshield_id, category, tier, framework_mappings, etc.) goes under `properties` on the descriptor — supported by the SARIF spec

2. **Build the SARIF envelope**
   ```json
   {
     "$schema": "...sarif-schema-2.1.0.json",
     "version": "2.1.0",
     "runs": [{
       "tool": {"driver": {"name": "AgentShield", "version": "0.1.0", "rules": [...]}},
       "results": [...]
     }]
   }
   ```

3. **Build each result**
   - Map our `severity` → SARIF `level` (critical/high → error, medium → warning, low/info → note)
   - Original severity preserved in `properties.severity_normalized` for fidelity
   - `triage` block (when present) goes under `properties.triage`

4. **Write with UTF-8 encoding**
   - `output_path.write_text(text, encoding="utf-8")` — Windows cp1252 fix from VDI testing

### JsonWriter — file: [`agentshield/report/json_writer.py`](./agentshield/report/json_writer.py)

Simpler — wraps the full `Finding.model_dump()` plus a summary block:
```json
{
  "agentshield_version": "0.1.0",
  "summary": {
    "total": 3,
    "by_category": {"detect": 1, "defend": 1, "respond": 1},
    "by_tier": {"framework": 3, "fallback": 0, "judge": 0, "discovery": 0},
    "by_severity": {"high": 1, "medium": 2, ...}
  },
  "findings": [...]
}
```

### MarkdownWriter — file: [`agentshield/report/markdown.py`](./agentshield/report/markdown.py)

Human-readable, PR-comment friendly:
- Title + `**N finding(s)**` summary block
- Summary table (category × tier × severity counts)
- One section per D/D/R category that has findings
- Each finding: agentshield_id, severity badge, location as a clickable file:line link, framework mappings inline, message blockquoted

---

## 7. End-to-end example with concrete data

`agentshield scan tests/fixtures/python/d001_flask_langchain.py --no-judge --output-markdown /tmp/r.md`

### Input fixture (11 lines)

```python
"""Fixture: should trigger D001, DF001, R001."""
from flask import Flask, request
from langchain.llms import OpenAI

app = Flask(__name__)
llm = OpenAI()


@app.route("/chat")
def chat():
    user_msg = request.args.get("q")
    return llm.invoke(user_msg)
```

### Tier 1+2 (semgrep)

`SemgrepRunner.run(...)` returns SARIF with 3 results, all on line 16:
- `agentshield.rules.detect.agentshield.detect.unsanitized-user-input-to-llm`
- `agentshield.rules.defend.agentshield.defend.no-guardrails-import-in-llm-module`
- `agentshield.rules.respond.agentshield.respond.llm-call-without-audit-logging`

### Normalize (A3)

`Normalizer.normalize(sarif)` returns 3 `Finding` objects:

| rule_id_short | category | tier | severity | confidence | OWASP LLM | OWASP Agentic |
|---|---|---|---|---|---|---|
| unsanitized-user-input-to-llm | detect | framework | high | high | LLM01 | T6 |
| no-guardrails-import-in-llm-module | defend | framework | medium | high | LLM01, LLM05 | T6 |
| llm-call-without-audit-logging | respond | framework | medium | high | LLM10 | — |

All three have `tier="framework"`, so the judge tier finds 0 fallback findings to triage and skips.

### Tier 3 (judge)

```
[agentshield] Tier 3 judge: skipped (--no-judge); 0 fallback finding(s) untriaged
```

### Tier 4 (discovery)

Skipped — `--discovery` not passed.

### Report writing (A4)

`MarkdownWriter().write(findings, "/tmp/r.md")` produces:

```
# AgentShield Report (v0.1.0)

**3 finding(s)**

| Category | Count | | Tier | Count | | Severity | Count |
|---|---|---|---|---|---|---|---|
| detect | 1 | | framework | 3 | | high | 1 |
| defend | 1 | | fallback | 0 | | medium | 2 |
| respond | 1 | | judge | 0 | | low | 0 |

## Detect — vulnerability surfaces (1)

### AS-D-001 — `unsanitized-user-input-to-llm`

- **Severity:** 🔴 high
- **Tier:** framework | **Confidence:** high
- **Location:** [`tests/fixtures/python/d001_flask_langchain.py:16`](...)
- **Mappings:** OWASP LLM LLM01 · OWASP Agentic T6 · NIST AI RMF MAP-2.3, MEASURE-2.7 · MITRE ATLAS AML.T0051

> User input from an HTTP request flows directly into an LLM/agent/chain/retriever invocation without passing through a known guardrail or sanitization layer. This is the canonical prompt-injection surface (OWASP LLM01).

## Defend — missing controls (1)

### AS-DF-001 — `no-guardrails-import-in-llm-module`
[...]

## Respond — observability gaps (1)

### AS-R-001 — `llm-call-without-audit-logging`
[...]
```

### Exit code

`0` — scan succeeded. (Adjust via configured fail threshold once that's wired in.)

---

## What changes for the SMARTSDK fixture

Same flow, different rules fire. The fixture at [`tests/fixtures/python/d001_smartsdk_runner.py`](./tests/fixtures/python/d001_smartsdk_runner.py) calls `runner.run_stream(agent, user_prompt)`, which matches:
- D001's SMARTSDK sink `$RUNNER.run_stream($AGENT, $X, ...)` (Tier 1)
- DF001's SMARTSDK sink `$RUNNER.run_stream($AGENT, ...)` (Tier 1)

R001 stays silent because the file imports `logging` (R001 is absence-detection: it only fires when no logger is imported).

For the fallback fixture at [`tests/fixtures/python/d001_fallback_openai_wrapper.py`](./tests/fixtures/python/d001_fallback_openai_wrapper.py), the call `llm.ask(user_msg)` matches Tier 2 (because the file imports `openai` and `.ask` is in the verb regex) but NOT Tier 1 (`.ask` isn't in any framework rule's sink list). The single resulting finding has `tier="fallback"` and routes through the LLM judge if Bedrock is configured.
