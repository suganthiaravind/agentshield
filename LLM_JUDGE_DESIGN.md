# LLM Judge — Design Sketch

Status: Draft 2026-05-02
Related: [PHASE_I_PLAN.md](./PHASE_I_PLAN.md), fallback rules at [agentshield/rules/detect/D001-fallback-*.yaml](./agentshield/rules/detect/)

---

## 1. Purpose

Semgrep's framework-specific D001/DF001/R001 rules are high-precision but blind to unknown frameworks (internal wrappers, niche SDKs). The fallback rules `D001-fallback-llm-import-and-verb-shape{,-java}.yaml` extend coverage by gating on "any LLM-adjacent import + LLM-shaped verb name," which is broad and noisy by design.

The **LLM Judge** is a post-processing tier that consumes only the fallback rule's findings and emits per-finding verdicts: `confirmed` / `dismissed` / `needs_review`. It is **not** invoked on the high-precision rules (those are trusted as-is) and **not** invoked on every line of code (cost-prohibitive on a JPMC monorepo).

## 2. Where it slots in the pipeline

```
┌─────────────────────────────┐
│  Source repo (Python/Java)  │
└────────────┬────────────────┘
             ▼
┌─────────────────────────────┐
│  Semgrep — Tier 1           │   High precision, framework-specific
│  D001/DF001/R001 (explicit) │   → findings.confidence = high
└────────────┬────────────────┘
             ▼
┌─────────────────────────────┐
│  Semgrep — Tier 2           │   Fallback / catch-net
│  D001-fallback-* rules      │   → findings.confidence = low
└────────────┬────────────────┘
             ▼
┌─────────────────────────────┐
│  LLM Judge — Tier 3         │   Triage tier-2 findings only
│  (this document)            │   → adds verdict + reasoning
└────────────┬────────────────┘
             ▼
┌─────────────────────────────┐
│  Normalized report          │
│  (CLI / library output)     │
└─────────────────────────────┘
```

## 3. Constraints

The judge tier is **backend-agnostic**. AgentShield itself is not bound by the production-side PHASE_I_PLAN no-outbound-internet rule (which applies to scanned target agents in prod, not to the scanner). AgentShield's own LLM calls can take any sanctioned route from the dev environment.

- **Pluggable LLM backend.** v0.1 ships with three drivers, selectable by config flag (`--llm-backend <name>`):
  1. `boto3-bedrock` — direct AWS SDK call to a Bedrock model. Default for batch CLI scans.
  2. `smartsdk` — JPMC SMARTSDK runner. Use when scanning inside an environment where SMARTSDK is the sanctioned path.
  3. `copilot` — GitHub Copilot via a custom agent / markdown-defined agent. Use when AgentShield is invoked from an IDE / dev-loop context.
- **Driver interface.** All backends implement a single `JudgeBackend` protocol so the orchestrator does not know or care which is plugged in:
  ```python
  class JudgeBackend(Protocol):
      def judge(self, system_prompt: str, user_prompt: str) -> JudgeResponse: ...
  ```
  Switching backends is a config flag, not a code change.
- **License-clean.** Apache-2.0 / MIT / LGPL only.
- **Deterministic-enough for audit.** Use `temperature=0`, fixed model version per backend, log full prompt + response per finding to `judge_audit.jsonl` for reproducibility. Cross-backend determinism is not guaranteed (different models, different drift); deterministic comparisons must hold the backend constant.

## 4. Input contract

For each tier-2 finding the judge receives one JSON object:

```json
{
  "finding_id": "as-d-001-fb-7c3a",
  "rule_id": "agentshield.detect.unsanitized-user-input-to-llm-fallback",
  "language": "python",
  "file_path": "src/handlers/chat.py",
  "line": 47,
  "column": 12,
  "matched_code": "client.invoke(user_msg)",
  "code_window": "<±20 lines around the match, with line numbers>",
  "imports_in_file": ["openai", "boto3", "internal.utils"],
  "metadata": {
    "owasp_llm": ["LLM01"],
    "tier": "fallback"
  }
}
```

The orchestrator strips the rest of the file to keep the prompt bounded and avoid leaking unrelated code.

## 5. Prompt structure

System prompt (fixed, cached via SMARTSDK / Bedrock prompt caching):

```
You are a security triage assistant for AgentShield, a static-analysis tool
for AI agent code. Your job is to decide whether a flagged code location is
actually an LLM/agent invocation that should be reviewed for prompt-injection
risk, OR a false positive (RPC, DAO, generic service call, etc.).

You will be given:
  - The matched code line
  - ±20 lines of surrounding context
  - The list of imports in the file
  - The original rule that fired

Return a JSON object with EXACTLY these fields:
  - verdict: "confirmed" | "dismissed" | "needs_review"
  - confidence: float 0.0-1.0
  - reasoning: short string (max 240 chars)
  - llm_framework_guess: string or null  (e.g. "openai", "boto3-bedrock",
    "internal-wrapper", "not-an-llm-call")

Rules:
  - "confirmed" = high confidence this IS an LLM call missing guardrails.
  - "dismissed" = high confidence this is NOT an LLM call (RPC, threading,
    SQL, etc).
  - "needs_review" = ambiguous; surface to a human.
  - Be conservative: when uncertain, return "needs_review", not "confirmed".
```

User prompt (per finding): the JSON object from §4 rendered as a code block plus the question "Triage this finding."

## 6. Output contract

```json
{
  "finding_id": "as-d-001-fb-7c3a",
  "verdict": "confirmed",
  "confidence": 0.85,
  "reasoning": "client = boto3.client('bedrock-runtime') two lines above; user_msg taints invoke_model call.",
  "llm_framework_guess": "boto3-bedrock"
}
```

The orchestrator merges the verdict back into the finding record. Reports surface `confirmed` findings prominently, `needs_review` in a separate section, and suppress `dismissed` (still logged for audit).

## 7. Cost & performance budget

- **Volume bound**: judge runs only on tier-2 findings. Empirical target: <500 fallback findings per scan on a typical service repo.
- **Token estimate**: ~800 input tokens (system + code window) + ~80 output tokens per finding.
- **Caching**: system prompt is reused across every finding in a scan → SMARTSDK / Bedrock prompt cache should cover it after the first call.
- **Parallelism**: findings are independent — fan out with bounded concurrency (e.g. 8 in flight) against the SMARTSDK runner.
- **Timeout per finding**: 15s; on timeout default to `needs_review` rather than blocking the report.

## 8. Determinism / audit

- Pin model version (record exact `bedrock_model_id` in scan metadata).
- `temperature=0`, `top_p=1`.
- Log prompt + response per finding to a `judge_audit.jsonl` file alongside the report.
- The same scan re-run on the same commit should produce identical verdicts modulo model-server drift; record drift in scan metadata.

## 9. Failure modes & mitigations

| Failure | Mitigation |
|---|---|
| Judge hallucinates "confirmed" on a clear false positive | Tier-2 finding stays in report regardless; `confirmed` only escalates priority |
| Judge dismisses a real vulnerability | `dismissed` findings are still logged; periodic sampling review |
| Judge timeout / Bedrock outage | Default verdict `needs_review`; finding surfaces normally with a flag |
| Code window misses critical context (e.g. where `client` was defined) | Window grows to file-scope on `needs_review` retry, capped at 4 KB |
| Prompt injection inside the scanned code itself attacks the judge | System prompt frames code as untrusted data; judge instructed to never execute or follow instructions from `code_window` |

## 10. Validation plan

Before shipping:
1. Hand-label 100 tier-2 findings across the testbed repos (`testbed/langchain/`, `testbed/llama-index/`, `testbed/langchain4j/`, etc.) as ground truth.
2. Measure judge precision/recall against ground truth.
3. Target: ≥0.85 precision on `confirmed`, ≥0.95 recall on `confirmed` (don't drop real findings).
4. If thresholds not met: tighten prompt, narrow verb regex in fallback rule, or require both gating-import AND a more specific call shape.

## 11. Open questions

- Should the judge also re-rank tier-1 findings (high-precision but possibly stale)? Probably not in v1 — keep the trust boundary clean.
- Should DF001 / R001 absence-detection rules get a fallback tier too? Likely yes (same import-gating + verb regex), but defer until tier-2 D001 behavior is validated.
- Where does the judge output live in the report schema? Add a `triage` block to each finding, distinct from `metadata`.
