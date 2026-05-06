> # ⚠ ARCHIVED — v1 doc (kept for historical reference)
>
> v1 architecture (4-tier model with Tier 3 LLM judge + Tier 4 discovery). Superseded by [`ARCHITECTURE_V2.md`](../../ARCHITECTURE_V2.md) (v2 = 2 tiers: semgrep + Copilot-as-scanner). The judge tier code was deleted in Phase F.6 (see [`ROADMAP.md` §3.9](../../ROADMAP.md#39-phase-f--architecture-v2-2-tiers-copilot-as-scanner)).

---

# AgentShield — Architecture

Status: Draft 2026-05-03
Related: [PHASE_I_PLAN.md](./PHASE_I_PLAN.md), [LLM_JUDGE_DESIGN.md](./LLM_JUDGE_DESIGN.md), [ARCHITECTURE_RATIONALE.md](./ARCHITECTURE_RATIONALE.md)

---

## 1. System diagram

```
┌──────────────────────────┐
│  Target repo (Py / Java) │   ← scanned-side, applications usually hosted in AWS
└────────────┬─────────────┘
             ▼
┌──────────────────────────┐
│  AgentShield CLI         │   ← scanner-side, runs in dev VDI
│  (pluggable LLM backend) │     (boto3-Bedrock | SMARTSDK | Copilot)
└────────────┬─────────────┘
             ▼
   ┌─────────┴─────────┐
   ▼                   ▼
┌────────────┐   ┌─────────────────┐
│ Tier 1     │   │ Tier 2          │
│ Semgrep    │   │ Semgrep         │
│ framework- │   │ fallback rules  │
│ specific   │   │ (import-gated + │
│ (high      │   │  verb-shape)    │
│  precision)│   │ (low confidence)│
└─────┬──────┘   └────────┬────────┘
      │                   ▼
      │          ┌─────────────────┐
      │          │ Tier 3: LLM     │
      │          │ Judge — triage  │
      │          │ verdict +       │
      │          │ reasoning       │
      │          └────────┬────────┘
      │                   │
      ▼                   ▼
┌──────────────────────────────────┐
│ Tier 4: Discovery (optional)     │
│ For files w/ LLM imports & 0     │
│ findings → "did we miss any?"    │
└────────────┬─────────────────────┘
             ▼
┌──────────────────────────┐
│ Normalized report        │
│ (SARIF + JSON + MD)      │
└──────────────────────────┘
```

## 2. Module layout

```
agentshield/
├── rules/                       ← detect/defend/respond YAML rule packs (done)
│   ├── detect/                  ← D001 (+ Java + fallback variants), D002, D003
│   ├── defend/                  ← DF001 (+ Java), DF002
│   └── respond/                 ← R001 (+ Java)
├── runner/                      ← semgrep subprocess wrapper
│   └── semgrep_runner.py
├── normalize/                   ← semgrep SARIF → AgentShield finding schema
│   ├── schema.py
│   └── normalizer.py
├── frameworks/                  ← OWASP/NIST/MITRE/AS-v1 mapping tables (done)
│   ├── agentshield_v1.yaml
│   └── owasp_llm.yaml
├── judge/
│   ├── backend.py               ← JudgeBackend protocol
│   ├── boto3_bedrock.py         ← default driver
│   ├── smartsdk.py
│   ├── copilot.py
│   ├── orchestrator.py          ← consumes findings, calls backend, merges verdicts
│   └── audit.py                 ← writes judge_audit.jsonl
├── discovery/                   ← Tier 4 (optional)
│   ├── file_scanner.py
│   └── prompts.py
├── report/
│   ├── sarif.py                 ← primary
│   ├── json.py
│   └── markdown.py
├── config.py                    ← loads agentshield.yaml
└── cli.py                       ← console entry point
```

## 3. Data flow per scan

1. CLI parses `agentshield scan <path>` and loads `agentshield.yaml` (if present) merged with CLI flags.
2. `runner/semgrep_runner.py` invokes `semgrep` subprocess with the bundled rule pack against the target path; collects raw SARIF.
3. `normalize/normalizer.py` converts SARIF to internal `Finding` objects with framework mappings attached.
4. Findings are partitioned by tier: `tier-1` (high-confidence framework rules) vs `tier-2` (fallback rules, `confidence: low`).
5. If LLM backend is configured and reachable, `judge/orchestrator.py` sends each tier-2 finding to the backend; verdicts merged back as `triage` blocks.
6. If discovery enabled, `discovery/file_scanner.py` lists files with LLM-adjacent imports and zero findings; sends to judge for "did we miss anything" pass; new findings created as `tier-4`.
7. `report/sarif.py` writes SARIF v2.1.0; optional JSON and MD writers consume the same finding stream.
8. Exit code: 0 if no `confirmed` findings, 1 if any, 2 on tool error. Configurable per-tier.

## 4. Adjustments accepted (vs §2 of architecture review)

| # | Adjustment | Status |
|---|---|---|
| 1 | SARIF as primary output format | Accepted |
| 2 | Config file `agentshield.yaml` | Accepted |
| 3 | Offline mode (Tiers 1+2 work without LLM) | Accepted |
| 4 | Bundled rule pack (YAMLs inside the wheel) | Accepted |
| 5 | Golden-file tests against `testbed/` | Accepted |

## 5. Parallel development tracks

Track A is the spine. B/C/E/D run alongside A once A1–A2 land.

| Track | Pieces | Depends on | Can start |
|---|---|---|---|
| **A. Core pipeline** | A1 scaffolding (pyproject, package layout, CLI stub) → A2 semgrep runner → A3 normalizer → A4 report writer (SARIF first) → A5 end-to-end smoke test | — | Now |
| **B. LLM judge** | B1 backend protocol + boto3-Bedrock driver → B2 SMARTSDK driver → B3 Copilot driver → B4 orchestrator → B5 audit logger | A1, A2 | After A2 |
| **C. Rule validation** | C1 golden-file tests against testbed → C2 CI workflow (semgrep on every change) → C3 rule-pack bundler | A1 only | After A1 |
| **E. Zero-trust gap rules** | E1 DF003 tool-without-authz → E2 DF004 broad-creds-in-tool → E3 DF005 memory-without-integrity → E4 DF006 inter-agent-without-auth → E5 DF007 side-effect-without-validation → E6 D004 indirect-prompt-injection → E7 D005 system-prompt-exposure → E8 golden tests for E1–E7 | A1, C1 | After C1 |
| **D. Discovery (Tier 4)** | D1 prompt design → D2 file scanner (imports + zero findings) → D3 judge integration | A complete + B4 | Last |

## 6. Hosting / runtime context

- **Target apps**: usually hosted in AWS. Bedrock is the dominant LLM provider; SMARTSDK wraps Bedrock under the hood. boto3-Bedrock direct usage is also common.
- **Scanner**: runs in the dev VDI. Has multiple sanctioned LLM access paths (boto3 direct, SMARTSDK runner, GitHub Copilot custom agents).
- **Default judge backend**: `boto3-bedrock` — same trust boundary as the typical target workload, lowest latency from a dev env close to AWS.

## 7. Output format

Primary: **SARIF v2.1.0** (industry standard; consumed by GitHub code scanning, SonarQube, IDE plugins).
Derived views: JSON (for downstream tooling), Markdown (for human review). Both generated from the same internal `Finding` stream so they cannot drift.

## 8. Configuration

`agentshield.yaml` (per-repo or per-org default) supports:
```yaml
llm_backend: boto3-bedrock     # boto3-bedrock | smartsdk | copilot | none
bedrock_model_id: <arn>        # required when llm_backend = boto3-bedrock
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
CLI flags override config values. Missing config falls back to sensible defaults.

## 9. Exit codes & CI integration

- `0` — no `confirmed` findings (or scan ran with `--no-fail`)
- `1` — at least one `confirmed` finding at or above configured severity
- `2` — tool error (semgrep failed, config invalid, etc.)

GitHub Actions / Jenkins consumers can gate merges on exit code while still ingesting the SARIF for trend analysis.

## 10. What's NOT in scope for Phase I

- Runtime probing of live agents (Phase II — Promptfoo / Garak / AgentDojo / PyRIT)
- Dynamic taint tracking across HTTP boundaries
- Cross-repo / supply-chain analysis
- UI / dashboard (Phase II)
- Languages beyond Python and Java

## 11. Zero-Trust Coverage Matrix

Phase I targets the *static signatures* of zero-trust failures and red-team-relevant exploit surfaces. Active exploitation (sending adversarial prompts to a running agent) is Phase II — the testbed already contains Promptfoo, Garak, AgentDojo, and PyRIT for this. The split is intentional, not a coverage gap (see [ARCHITECTURE_RATIONALE.md §12](./ARCHITECTURE_RATIONALE.md#12-static-vs-dynamic-security-boundary)).

Mapping each zero-trust principle / exploit class to AgentShield rule coverage:

| Zero-trust principle / exploit class | OWASP Agentic | Static signature | AgentShield rule | Status |
|---|---|---|---|---|
| Input is untrusted (prompt injection) | T6, LLM01 | User input → LLM without sanitizer | D001 (+Java +fallback) | ✅ Implemented |
| RAG sources are untrusted | T7, LLM03 | Document loader from untrusted URL | D002 | ✅ Implemented |
| Tool execution is sandboxed | T2 | `eval` / `exec` / shell tool registered without sandbox | D003 | ✅ Implemented |
| Guardrails layered on every LLM call | T6, LLM01/05 | Module invokes LLM with no guardrail import | DF001 (+Java) | ✅ Implemented |
| Tools have typed args schema | T2 | Tool registered without `args_schema` / Pydantic model | DF002 | ✅ Implemented |
| Audit trail on every LLM call | LLM10 | LLM module without logger / tracer setup | R001 (+Java) | ✅ Implemented |
| Tool execution requires authorization | T2, T3 | Tool callable without permission/role check | DF003 | 🔵 Track E (planned) |
| Tools use least-privilege credentials | T3 | Broad IAM role / API key with `*` scopes | DF004 | 🔵 Track E (planned) |
| Memory / state has integrity check | T8 | Agent memory loaded without verification | DF005 | 🔵 Track E (planned) |
| Inter-agent calls re-authenticate | T10 | Multi-agent system without per-call auth | DF006 | 🔵 Track E (planned) |
| Side effects validated before action | T9 | Agent writes DB / sends message without confirmation | DF007 | 🔵 Track E (planned) |
| Tool output is treated as untrusted (indirect prompt injection) | T6, T8 | Tool return value flows back into LLM context unsanitized | D004 | 🔵 Track E (planned) |
| System prompts are not exposed | T1, LLM07 | System prompt accessible via tool / log / error message | D005 | 🔵 Track E (planned) |
| Active red-team probing | (any) | — | (out of scope for Phase I) | 🔶 Phase II |

Legend: ✅ implemented · 🔵 planned (Track E) · 🔶 deferred to Phase II

This matrix is the contract for what static analysis can and cannot deliver. Track E rules are slotted into the parallel plan in §5; Phase II will integrate the testbed red-team tools.
