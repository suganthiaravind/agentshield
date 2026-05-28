# AgentShield Tier 2 — output JSON schema

Copilot writes findings to `.agentshield/tier2-findings.json` following
this schema exactly. The merger validates against this schema and refuses
to combine results if a required field is missing or an enum value is
unrecognised.

## Top-level structure

```json
{
  "tier": 2,
  "scanned_at": "ISO-8601 UTC timestamp",
  "agentshield_tier1_fingerprint": "string (copy verbatim from tier1-results.json)",
  "saige_tier": "non-agent | 0 | 1 | 2 | 3",
  "saige_tier_reasoning": "string — file:line evidence for the classification",
  "scanned_files": ["array of relative paths actually scanned"],
  "skipped_files": [
    {"path": "src/huge.py", "reason": "exceeds context window"}
  ],
  "findings": [],
  "tier1_fp_callouts": []
}
```

### Required top-level fields

| Field | Type | Notes |
|---|---|---|
| `tier` | integer | Always `2`. |
| `scanned_at` | string | ISO-8601 UTC, e.g. `"2026-05-05T22:14:00Z"`. |
| `agentshield_tier1_fingerprint` | string | Copy verbatim from `tier1-results.json`. The merger uses this to detect stale Tier 2 runs. |
| `scanned_files` | array[string] | Repository-relative POSIX paths. |
| `skipped_files` | array[object] | Files Copilot couldn't process; each has `path` + `reason`. Empty array if none. |
| `findings` | array[Finding] | See "Finding object" below. Empty array is valid. |
| `tier1_fp_callouts` | array[Tier1FPCallout] | See "Tier1FPCallout object" below. Empty array is valid. |

### Optional top-level fields (SAIGE classification)

| Field | Type | Notes |
|---|---|---|
| `saige_tier` | enum string | One of `"non-agent"`, `"0"`, `"1"`, `"2"`, `"3"`. JPMC SAIGE Agent Tier classification. Determined per the §8 SAIGE decision tree in the checklist. Optional — emit only when classification is performed. |
| `saige_tier_reasoning` | string | File:line evidence supporting the classification. Required when `saige_tier` is present. May be `"INSUFFICIENT_EVIDENCE: <description>"` if the codebase doesn't give enough signal — in that case, pick the most conservative (highest) tier consistent with the partial evidence. |

## Finding object

Each item in `findings[]`:

```json
{
  "rule_id": "TIER2-LLM01-02",
  "category": "detect",
  "severity": "high",
  "file": "src/controller/ChatController.java",
  "line": 27,
  "snippet": "return chatClient.prompt().user(req.getQ()).call().content();",
  "message": "Unsanitised user input flows directly into ChatClient prompt.",
  "reasoning": "ChatController.java:27 calls chatClient.prompt().user(req.getQ()) with no prior sanitisation. No guardrail import is present in this file or its imports. The raw HTTP query parameter is the only input to the LLM.",
  "owasp_llm": ["LLM01"],
  "owasp_agentic": ["T6"],
  "mitre_atlas": ["AML.T0051"],
  "cwe": ["CWE-94"],
  "remediation": "Wrap req.getQ() with a guardrail call (Lakera, in-house ScrubbingCallAdvisor, or OWASP Encoder) before passing to .user()."
}
```

### Required fields on each Finding

| Field | Type | Notes |
|---|---|---|
| `rule_id` | string | The check ID from the checklist (e.g. `TIER2-LLM01-02`). One finding can quote multiple checks; pick the most specific. |
| `category` | enum | One of `"detect"` (input-side), `"defend"` (preventive control missing), `"respond"` (observability / audit gap). |
| `severity` | enum | One of `"critical"`, `"high"`, `"medium"`, `"low"`, `"info"`. Use the severity from the checklist's check item. |
| `file` | string | Repository-relative POSIX path. |
| `line` | integer | 1-indexed line number of the first line of the matched pattern. |
| `snippet` | string | Verbatim source line(s) — keep short, 1-3 lines max. |
| `message` | string | One-sentence statement of the issue. |
| `reasoning` | string | **Why** you flagged this: cite the specific file:line(s) you read, what was absent (no guardrail, no auth check, etc.), and what made you confident it is a real issue rather than a pattern match. 1–3 sentences. |
| `owasp_llm` | array[string] | OWASP LLM Top 10 v2 IDs (e.g. `["LLM01", "LLM05"]`). Empty array if none apply. |
| `owasp_agentic` | array[string] | OWASP Agentic AI Top 10 IDs (e.g. `["T6"]`). Empty array if none apply. |
| `mitre_atlas` | array[string] | ATLAS technique IDs (e.g. `["AML.T0051"]`). Empty array if none apply. |
| `cwe` | array[string] | CWE IDs (e.g. `["CWE-94"]`). Empty array if none apply. |
| `remediation` | string | One-paragraph fix guidance. Concrete: name the library / function / pattern to use. |

### Optional fields

| Field | Type | Notes |
|---|---|---|
| `confidence` | enum | One of `"high"`, `"medium"`, `"low"`. Default if omitted: `"medium"`. Use `"low"` when you're flagging something but unsure. |
| `related_files` | array[string] | If the finding spans multiple files, list the others. |
| `notes` | string | Additional free-text context beyond `reasoning` (accepted as alias for `reasoning` by the merger). |

## Tier1FPCallout object

Each item in `tier1_fp_callouts[]`:

```json
{
  "tier1_finding_index": 3,
  "file": "src/SchedulingService.java",
  "line": 98,
  "tier1_rule": "agentshield.defend.no-guardrails-import-in-llm-module-java",
  "verdict": "FP",
  "reasoning": "taskExecutor.execute delegates to triageService which uses ScrubbingCallAdvisor — guardrail exists across method boundaries. Tier 1's import-based check can't see this."
}
```

### Required fields

| Field | Type | Notes |
|---|---|---|
| `tier1_finding_index` | integer | 0-indexed position in the Tier 1 results' findings array. |
| `file` | string | Same as the Tier 1 finding's file (for human readability). |
| `line` | integer | Same as the Tier 1 finding's line. |
| `tier1_rule` | string | Tier 1 rule ID (e.g. the semgrep `check_id`). |
| `verdict` | enum | One of `"FP"` (false positive), `"CD"` (context-dependent — code is risky but mitigated elsewhere), `"TP"` (true positive — confirms Tier 1's call). |
| `reasoning` | string | Why you reached this verdict. Cite the file/lines that justify it. |

## Validation rules the merger enforces

1. `tier` must be `2`.
2. `agentshield_tier1_fingerprint` must match the value in `tier1-results.json`. Mismatch = stale Tier 2 = warn loudly, don't merge.
3. Every Finding's `rule_id` must start with `TIER2-`.
4. Every Finding's `severity` must be one of the 5 enum values.
5. Every Finding's `category` must be one of the 3 enum values.
6. Line numbers must be positive integers.
7. Framework arrays may be empty but must be present (no `null`).
8. Tier1FPCallout's `verdict` must be one of the 3 enum values.

If validation fails, the merger prints the offending field path and Copilot can be re-prompted to fix that specific item.

## Why this format

- **Mirrors AgentShield's normalised Finding type** so the merger can treat Tier 1 and Tier 2 findings interchangeably in the unified report.
- **Framework arrays let the merger build a coverage matrix** showing which OWASP / Agentic / ATLAS items the scan touched.
- **Strict enums prevent drift** as different LLMs / Copilot versions emit slightly different output.
- **`tier1_fp_callouts` separated from `findings`** because they describe Tier 1 entries, not new findings — keeping them in their own array makes the merger's job trivial.
