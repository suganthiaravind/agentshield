# AgentShield Architecture

Status: 2026-05-22 — current.
Companion to: [README.md](./README.md) (install + quickstart), [EXECUTE_AGENTSHIELD.md](./run/EXECUTE_AGENTSHIELD.md) (install + run guide), [GLOSSARY.md](./GLOSSARY.md) (security-term definitions).

This document describes how AgentShield is built today. For the live, always-current rule list, open the **Reference tab** of any HTML report (`agentshield merge --output-html report.html`) — it's auto-generated from the rule pack, so it can never drift.

---

## 1. What AgentShield does

A **pre-production security evaluator for AI agents**. Static analysis + LLM-as-scanner + manifest scanner. Runs on a developer's machine or in a CI / VDI; never makes outbound network calls of its own.

Three scanning surfaces feed a unified report. An optional fourth step — the `probe` command — runs live adversarial tests and feeds its results back into the same merge pipeline:

```
                   ┌──────────────────────────────────────────────┐
                   │             agentshield scan                 │
                   └──────────────────────────────────────────────┘
                              │              │              │
       ┌──────────────────────┘              │              └────────────────────┐
       ▼                                     ▼                                   ▼
┌──────────────┐                    ┌──────────────────┐                ┌────────────────┐
│ Semgrep      │                    │  AST10 Manifest  │                │   tier1-       │
│ static rules │  ◀── 10 families   │     scanner      │  ◀── 10 sub-   │   results.json │
│ (Python+Java)│                    │  (SKILL.md only) │      rules     │ + skill files  │
└──────────────┘                    └──────────────────┘                └────────────────┘
       │                                     │                                   │
       └─────────────────┬───────────────────┘                                   │
                         ▼                                                       │
                ┌──────────────────┐                                              │
                │ Findings emitted │ ◀────── Same Finding shape;                  │
                │ to .agentshield/ │           merger doesn't care which          │
                └──────────────────┘           scanner produced what.             │
                         │                                                        │
                         ▼                                                        │
                ┌──────────────────────────────────────────────┐                  │
                │  Developer pastes the printed prompt into    │                  │
                │     Copilot Chat in their IDE                │                  │
                └──────────────────────────────────────────────┘                  │
                         │                                                        │
                         ▼                                                        │
                ┌──────────────────┐                                              │
                │ Copilot writes   │   62 semantic checks, file-by-file           │
                │ tier2-findings   │   walks every source file in the repo        │
                │ .json            │                                              │
                └──────────────────┘                                              │
                         │                                                        │
                         ▼                                                        │
                   ┌──────────────────────────────────────────────┐                │
                   │             agentshield merge                │  ◀─────────────┘
                   └──────────────────────────────────────────────┘
                                        │
                                        ▼
                   ┌──────────────────────────────────────────────┐
                   │  HTML / Markdown / JSON / SARIF report       │
                   │  + report-print.html (stacked, printable)    │
                   └──────────────────────────────────────────────┘
```

The three CLI commands are `agentshield scan <target>`, `agentshield merge <target>`, and `agentshield probe <target>`. Everything else is library code.

---

## 2. The three scanning surfaces

Each scanner produces `Finding` objects in the same shape (defined in `agentshield/normalize/schema.py`); the merger doesn't care which scanner wrote which. This is the single architectural invariant that makes everything else easy.

### 2.1 Tier 1 — Semgrep static rules

**Lives in** `agentshield/rules/{detect,defend}/*.yaml`. Loaded by `agentshield/runner/semgrep_runner.py`, normalized by `agentshield/normalize/normalizer.py`.

**Targets** Python and Java source files. Each rule is either a narrow `mode: taint` (source / sink / sanitizer) or a narrow regex on call sites. Both shapes are deliberately tight — no heuristic name matching, no absence-detection. The precision target is sub-15% FP on real codebases.

**Rule families** (10 active, all framework-tier):

| Family | What it flags | Primary anchor |
|---|---|---|
| D001 | unsanitized user input → LLM call | OWASP LLM01 |
| D003 | code-execution tool registered | OWASP LLM06 |
| D004 | LLM output → code-execution sink | OWASP LLM05 |
| D005 | hardcoded LLM credentials | CWE-798 |
| D008 | untrusted system prompt (network read → SystemMessage) | OWASP LLM07 |
| D009 | concealment markers in stored prompts | OWASP LLM01 |
| D010 | jailbreak / mode-switch markers in stored prompts | OWASP LLM01 |
| D011 | tool description carrying planner-injection instructions | OWASP LLM05 |
| D012 | non-HTTPS outbound for code / config / RAG fetch | OWASP LLM03 |
| DF003 | no timeout / token cap on LLM call | OWASP LLM10 |

Each rule's YAML carries `metadata.framework_mappings` with multi-axis tags (OWASP LLM, OWASP Agentic, MITRE ATLAS, CWE, AST10) and a human-readable `remediation` string.

### 2.2 Tier 2 — Copilot LLM-as-scanner

**Lives in** `agentshield/skills/tier2_*.md.tmpl` (the rule "pack") + `agentshield/emitter/skill_emitter.py` (drops the templates into the scanned target).

**The handoff:** after `agentshield scan` finishes, the emitter writes a set of skill files into `<target>/.agentshield/` and the CLI prints a Copilot Chat prompt. The developer pastes the prompt into Copilot Chat in VS Code / JetBrains / Claude Code. Copilot reads `tier2-checklist.md` (the rule pack) and `tier2-output-schema.md` (the strict JSON contract), walks every source file in the workspace, and writes `tier2-findings.json` back to `.agentshield/`.

**The checklist** has 62 entries across 8 sections:

1. OWASP LLM Top 10 v2 (LLM01 – LLM10)
2. OWASP Agentic AI Top 10 (T1 – T11)
3. MITRE ATLAS techniques
4. CWE first-class concerns
5. Phase E judge-surfaced gaps (patterns the rule pack alone never had)
6. Retired-rule parity (anti-patterns that used to be Tier 1 rules; live in Tier 2 now because static rules can't see the necessary context)
7. Tier 1 cross-check — Copilot reviews each Tier 1 finding and emits a TP/CD/FP verdict with reasoning
8. JPMC SAIGE Agent Tier classification (Non-Agent / Agentic Tier 0–3) — informational only

**Why Copilot specifically?** Tier 2 needs cross-function reasoning, absence-of-control detection, and intent comprehension — strengths the LLM has and Semgrep doesn't. The IDE handoff means AgentShield itself has no LLM dependency, no API key, no AWS / Bedrock surface, no token cost. Copilot runs against the user's existing IDE license. In the HTML report the Copilot source is labelled **"Copilot LLM-as-a-Judge (Static & Behaviour Emulator) Scan"** — the "Behaviour Emulator" suffix reflects that the same Copilot backend also drives the agent-emulator step when no live target is configured for probe mode.

#### What Tier 2 catches that Tier 1 can't

These are the four shapes of finding that motivated splitting Tier 2 out as a separate scanning surface:

- **Cross-method reasoning** — a guardrail wired in `ChatService`'s constructor protects calls in `SchedulingService`, but Tier 1's per-file taint can't see that.
- **Absence detection that requires context** — "is there an audit log around this LLM call?" depends on whether logging *intent* exists in the file (`@Slf4j`, stdlib `logger = logging.getLogger(...)`, OpenTelemetry imports), not just specific patterns.
- **Anti-patterns that need code-comprehension** — scrubber bypass (`if length > MAX: return original`), SNS / email sinks of LLM output without scrubbing, rate-limit absence on agent loops.
- **Intent reasoning** — does this `chain.invoke(user_input)` look like a guardrailed pipeline (call sites with surrounding sanitisation), or a prompt-injection vector?

#### How Copilot processes the workspace

Per file:

1. **Reads the file** into its context window.
2. **Walks the 62-entry checklist** — for each check whose `Languages:` field matches the file's language (or `any`), decides whether the anti-pattern is present.
3. **Emits a finding** if yes, into `.agentshield/tier2-findings.json` per the strict schema.

After every file has been walked:

4. **Reads `.agentshield/tier1-results.json`** and produces a `tier1_fp_callouts` array — one entry per Tier 1 finding it has an opinion about, with verdict (`TP` / `CD` / `FP`) and reasoning.
5. **Copies the `agentshield_tier1_fingerprint`** field verbatim from `tier1-results.json` into the output (the contract that lets the merger detect stale Tier 2 runs).

Time depends on repo size: ~30 s for one file, ~2 min for ten, ~10–15 min for fifty. 200+ files typically need to chunk by directory.

#### Sample `tier2-findings.json` shape

```json
{
  "tier": 2,
  "scanned_at": "2026-05-06T22:14:00Z",
  "agentshield_tier1_fingerprint": "1d33b903f7d02a04...",
  "scanned_files": ["src/foo.py", "src/bar.java"],
  "skipped_files": [],
  "findings": [
    {
      "rule_id": "AS-C-R-LLM02-002",
      "category": "respond",
      "severity": "high",
      "file": "src/notify.py",
      "line": 17,
      "snippet": "sns.publish(llm_output)",
      "message": "LLM output published to SNS without scrubbing.",
      "owasp_llm": ["LLM02"],
      "owasp_agentic": ["T8"],
      "mitre_atlas": [],
      "cwe": ["CWE-200"],
      "ast": [],
      "remediation": "Pass output through scrubberService.scrubPii() before publish."
    }
  ],
  "tier1_fp_callouts": [
    {
      "tier1_finding_index": 0,
      "file": "src/main/java/SchedulingService.java",
      "line": 98,
      "tier1_rule": "agentshield.detect.unsanitized-user-input-to-llm-java",
      "verdict": "CD",
      "reasoning": "ChatService constructor wires ScrubbingCallAdvisor; sanitiser exists across method boundaries that Tier 1's import-based check can't see."
    }
  ]
}
```

The strict schema (every required field, every enum value, the `verdict` allowed set) lives in [`agentshield/skills/tier2_output_schema.md.tmpl`](./agentshield/skills/tier2_output_schema.md.tmpl) and is validated by `agentshield/merger/schema.py` on every merge.

#### When Tier 2 is wrong

LLM scanners can hallucinate findings and miss real ones. Two safeguards:

1. **Tier 1 is independent.** Both scanners run independently; Tier 2's verdicts on Tier 1 findings are *advisory* — the merger keeps every Tier 1 finding and just annotates it with the verdict. CI gates can choose to honour or ignore Tier 2 FP-marks.
2. **Every Tier 2 finding cites its evidence.** Framework mappings, snippet, remediation. A reviewer can validate a Tier 2 finding against the source the same way they'd validate a Tier 1 finding.

If Tier 2 is consistently wrong on a specific check across multiple codebases, that's signal to refine the check definition in [`agentshield/skills/tier2_checklist.md.tmpl`](./agentshield/skills/tier2_checklist.md.tmpl). The skill file is versioned with the code; updates ship with each AgentShield release.

#### CI considerations

Tier 2 needs Copilot Chat in an IDE. CI runners typically don't have that:

1. **Tier-1-only CI** — `agentshield scan --no-emit --output-sarif sarif.json`. Surfaces the high-signal findings; misses what only Tier 2 catches. Acceptable as a *gate* (block PRs on Tier 1 errors), not as the *audit*.
2. **Local pre-merge audit** — developer runs Tier 2 locally before opening a PR and commits the unified report (or its hash) as evidence. Reviewer can re-run if suspicious.
3. **Future programmatic backend** — the merger is backend-agnostic: anything that writes a schema-valid `tier2-findings.json` works. A headless Bedrock / hosted-Copilot backend would slot in cleanly without any merge-side changes.

### 2.3 AST10 — Manifest scanner

**Lives in** `agentshield/manifest_scanner/`. Pure-Python — no Semgrep, no LLM. Walks `**/SKILL.md` files under the target tree, parses the YAML frontmatter, and applies 10 sub-rules across 5 OWASP-AST10 risks (AST01 / 03 / 04 / 05 / 07).

This is the developer-tooling supply chain layer: skill packages distributed via registries (ClawHub, skills.sh, Claude Skills, Cursor manifests). AST10 differs from the other two scanners in *what it scans*, not how findings flow — its output uses the same `Finding` shape and joins the same merge pipeline.

| AST risk | Sub-rules emitted |
|---|---|
| **AST01** Malicious Skills | Concealment / jailbreak / exfil markers in body prose |
| **AST03** Over-Privileged Skills | `network: true`, wildcard read paths, identity-file writes (SOUL.md / MEMORY.md / AGENTS.md), shell access, wildcard allowlists |
| **AST04** Insecure Metadata | Missing description, missing author identity (DID / signing key) |
| **AST05** Unsafe Deserialization | `yaml.load` (without SafeLoader), `pickle.loads`, `eval`, `exec` inside fenced code blocks |
| **AST07** Update Drift | Missing signature, missing content_hash |

### 2.4 Probe — live adversarial testing

**Lives in** `agentshield/probe/`. An optional fourth path that runs live attacks against a deployed agent endpoint. Output written to `.agentshield/` is picked up automatically by `agentshield merge`.

Three modes:

| Mode | What it does | Output file |
|---|---|---|
| `verify` | Looks up a canned payload for each static finding's `rule_id` and sends it to the target. Confirms whether the vulnerability is exploitable at runtime. | `probe-results.json` |
| `explore` | The adversarial backend (mock or real LLM) brainstorms attacks tuned to the agent's manifest + tool catalogue, fires each one, and classifies responses. Any that land are persisted as new findings. | `probe-discovered.json` |
| `campaign` | Multi-turn goal-directed attacks. When a turn is blocked, a mutate step rewrites the payload and retries. An LLM judge classifies each response (landed / blocked / inconclusive). When no live target is configured, the agent behaviour emulator stands in so campaigns still run offline. | `probe-campaigns.json` |

**Explore-mode attack catalogue (13 bundled classes):**

| Attack name | Category | Severity | Primary frameworks |
|---|---|---|---|
| authority-escalation-via-roleplay | detect | high | LLM01, T6/T9, AML.T0051, CWE-269/287 |
| memory-poisoning-persistent-directive | detect | high | T1, AML.T0018/T0019, CWE-94 |
| tool-chaining-unauthorized-exfil | defend | high | LLM02/LLM06, T2/T5, AML.T0024/T0053, CWE-200/918 |
| tool-description-injection | detect | medium | LLM01, T2, AML.T0051, CWE-94 |
| path-traversal-via-file-tool | detect | high | LLM06, T2, AML.T0024, CWE-22 |
| cross-tenant-data-fishing | detect | high | LLM02/LLM08, T5, AML.T0024, CWE-200/285 |
| runaway-tool-loop | defend | medium | LLM10, T4, AML.T0029/T0034, CWE-400/770 |
| goal-misalignment-redirect | detect | high | LLM01, T6/T7, AML.T0051 |
| repudiation-deny-prior-action | respond | medium | LLM07, T8, AML.T0056, CWE-778 |
| open-redirect-via-url-fetch | detect | medium | LLM06, T2, AML.T0010, CWE-601/918 |
| overreliance-confident-hallucination | detect | medium | LLM09, T7 |
| dynamic-plugin-installation | defend | high | LLM03, T2, AML.T0010, CWE-494/829 |
| insecure-output-handling | detect | high | LLM02, T5, AML.T0048, CWE-79/116 |

The mock backend returns all 13 attacks regardless of prompt; a real LLM backend would generate per-target payloads. The `_CATEGORY_ROLE_LETTER` mapping (`detect→D`, `defend→DF`, `respond→R`) is the canonical source used by both the probe orchestrator and the Reference-tab renderer.

**Agent behaviour emulator:** when no live target URL is provided, the agent-emulator skill (emitted by `agentshield scan` into `.agentshield/agent_emulator_bootstrap.md`) lets Copilot simulate the kill-chain step-by-step against the source code. Emulation output is written to `agent-emulation.json` and surfaces in the report alongside real probe captures.

---

## 3. The merger

**Lives in** `agentshield/merger/`. After scanning surfaces have run, `agentshield merge <target>` reads all available inputs under `<target>/.agentshield/` and produces a unified report.

**Inputs read:**
- `tier1-results.json` — always required
- `tier2-findings.json` — optional; soft-fail with banner if missing
- `probe-discovered.json` — optional; explore-mode findings
- `probe-campaigns.json` — optional; multi-turn campaign kill-chains
- `agent-emulation.json` — optional; behaviour-emulator pipeline traces

Responsibilities:
- **Stale detection** — the emitter writes a SHA-256 fingerprint over Tier 1's `(file, line, rule_id)` tuples; Copilot is told to copy it verbatim into `tier2-findings.json`. Mismatch on merge surfaces a STALE banner (the user re-ran Tier 1 after Tier 2; results are inconsistent).
- **Tier 2 cross-check overlay** — for each Tier 1 finding, if Copilot has emitted a TP/CD/FP verdict, the merger annotates that Tier 1 finding inline. FP-marked Tier 1 findings are excluded from the Net Actionable count and the SARIF Tier 1 run (they don't gate CI).
- **Coverage matrix** — aggregates which framework items (OWASP LLM / OWASP Agentic / MITRE ATLAS / CWE / OWASP AST10) the combined scan touched, including probe-discovered findings.
- **Schema validation** — Tier 2 output validated against the schema in `agentshield/merger/schema.py`. Soft failures (missing Tier 2, schema-invalid Tier 2, stale fingerprint) surface as banners, never raise.

---

## 4. Rule ID scheme

Every rule the scanner can fire has a canonical `agentshield_id`:

```
AS-<source>-<DDR>-<anchor>-<seq>

source ∈ {S, C, M}      Semgrep / Copilot / Manifest
DDR    ∈ {D, DF, R}     Detect / Defend / Respond
anchor                  framework token (LLM01, AGENTIC_T9,
                        ATLAS_T0010, CWE_798, AST01, GAP)
seq    1-up integer     within (source, DDR, anchor)
```

Examples:

| Rule | New ID | Legacy ID (still accepted) |
|---|---|---|
| Unsanitized user input → LLM (Semgrep) | `AS-S-D-LLM01-001` | `AS-D-001` |
| Hardcoded LLM credentials (Semgrep) | `AS-S-D-CWE_798-001` | `AS-D-005` |
| LLM in permission-decision path (Copilot) | `AS-C-DF-LLM06-004` | `TIER2-LLM06-04` |
| Self-promoting agent (Copilot) | `AS-C-DF-AGENTIC_T9-002` | `TIER2-AGENTIC-T9-02` |
| Malicious-skill marker (Manifest) | `AS-M-D-AST01-001` | `AS-AST-001` |

Every `Finding` carries `legacy_ids: list[str]` so customer suppress-comments / SARIF dashboards / GRC docs that reference an older ID still resolve. Tier 2 schema validator accepts both `AS-C-` and legacy `TIER2-` prefixes during transition.

### Choosing the canonical anchor

A rule typically maps to several frameworks at once — OWASP LLM, OWASP Agentic, MITRE ATLAS, CWE — but its AgentShield ID encodes only **one** of them in the `<anchor>` slot. That single token is the rule's *canonical* anchor; the rest live in `metadata.framework_mappings` as cross-references.

The anchor is chosen editorially by the rule author and committed to the rule's YAML in `metadata.agentshield_id`. The selection rule: **pick the framework entry where this rule is the textbook example of that control** — not the highest severity, not alphabetical, not the first listed.

A few worked examples from the live rule pack:

| Rule | All mappings | Anchor | Reasoning |
|---|---|---|---|
| D001 — unsanitised input → LLM | LLM01, T6, AML.T0051 | **LLM01** | LLM01 *is* prompt injection; this rule is its canonical detector |
| D003 — code-execution tool registered | LLM05, LLM06, T2, T11 | **LLM06** | LLM06 *is* excessive agency; registering an eval tool is the textbook case |
| D004 — LLM output → eval sink | LLM05, LLM06, T2, T11 | **LLM05** | LLM05 *is* improper output handling; output→sink is its textbook case |
| D005 — hardcoded credentials | LLM02, T3, CWE-798 | **CWE_798** | CWE-798 is more precise than LLM02; secrets-in-code is older than the LLM Top 10 |

Notice D003 and D004 share an identical mapping set but anchor at different tokens — the discriminator is *which* control a reader would open first to understand why this code is wrong. There is no automated policy or scoring function; the anchor is curated at rule-authoring time and enforced by code review.

Two structural guardrails keep this honest:

- Each rule's `message` field usually names the anchor in plain text (e.g. D001's message ends *"This is the canonical prompt-injection surface (OWASP LLM01)."*).
- The `agentshield_id` namespace is unique per `(source, DDR, anchor, seq)`, so adding a near-duplicate rule under the wrong anchor surfaces an ID collision in the rule loader.

Once written, the anchor is read verbatim by the merger and the Reference tab — neither component re-derives it. The Reference-tab card you see in the HTML report shows three independent pieces of metadata: the **title** is a descriptive English name derived from the rule's filename slug, the **AgentShield ID** carries the canonical anchor, and the **framework chips** below list every taxonomy this finding maps into.

---

## 5. Skill files emitted into `.agentshield/`

After `agentshield scan` runs, the target's `.agentshield/` directory contains seven generated artefacts (the dir is automatically appended to the target's `.gitignore`):

| File | Purpose |
|---|---|
| `tier1-results.json` | Tier 1 + AST10 findings + fingerprint hash |
| `tier2-bootstrap.md` | Plain-language entry point for Copilot Chat |
| `tier2-checklist.md` | The 62-check Tier 2 rule pack |
| `tier2-output-schema.md` | Strict JSON shape Copilot must emit |
| `agentshield-semgrep-fixes.md` | OWASP-UF SKILL.md — drag into Claude Code / Copilot Chat to get fix guidance for any `AS-S-*` finding |
| `agentshield-copilot-fixes.md` | Same for `AS-C-*` |
| `agentshield-manifest-fixes.md` | Same for `AS-M-*` |

The three `agentshield-*-fixes.md` files are read-only OWASP Universal Skill Format packages (`risk_tier: L0`, no shell, no network, no file writes). They're generated from the same `RuleReference` data the Reference tab uses, so they can never drift from the live rule pack.

---

## 6. Reports

`agentshield merge --output-html report.html` produces **two** self-contained HTML files (no external assets, no network deps; emailable / VDI-safe):

- **`report.html`** — interactive: tabbed (Detect / Defend / Respond / Coverage / Frameworks / Reference), with a sticky filter bar (severity / origin / search) and click-to-filter framework chips.
- **`report-print.html`** — stacked: every panel rendered as a `<section>` in scroll order. No tab nav, no JS-driven filtering. Print-friendly; the static doc to attach to a JIRA / email.

Other formats from the same merge:
- `--output-markdown report.md` — the human-readable text report
- `--output-json report.json` — machine-readable, mirrors the markdown structure
- `--output-sarif report.sarif` — SARIF v2.1.0, two `runs` (Tier 1 / Tier 2 toolComponents), excludes FP-marked Tier 1 findings from the Tier 1 run

The HTML **Reference tab** lists every **control** the scanner can fire (Semgrep + Copilot + Manifest), grouped by source + Detect/Defend/Respond category, generated live at render time from the YAML rule pack + checklist template + AST10 registry. It replaces the previous standalone rule-coverage doc — there's no second source of truth to keep in sync.

The Reference tab's "What AgentShield checks" section shows a total control count in the heading. The **AgentShield ↔ Security Framework Mapping** table is nested inside the same collapsible section and shows "Controls Live" vs "Controls Not Yet Live" counters. The solution-diagram panel was removed in this release; the design basis and how-it-works sections replace it.

---

## 7. Repository layout

```
agentshield/
├── cli.py                        # `scan` and `merge` subcommands
├── rules/
│   ├── detect/                   # 9 detect rule families (Python + Java sibs where applicable)
│   └── defend/                   # 1 defend rule family (DF003)
├── _retired_v2/                  # archived Tier 1 rules (read-only, not loaded by Semgrep);
│                                 # the patterns moved into the Tier 2 checklist
├── runner/
│   └── semgrep_runner.py         # Semgrep subprocess wrapper
├── normalize/
│   ├── normalizer.py             # SARIF → Finding objects (loads YAML metadata for enrichment)
│   └── schema.py                 # Finding / FrameworkMappings / CodeLocation pydantic models
├── manifest_scanner/             # AST10 SKILL.md scanner
│   ├── parser.py                 #   YAML frontmatter splitter
│   ├── rules.py                  #   10 AST10 sub-rules + central rule-ID table
│   └── scanner.py                #   walker entry point: scan_manifests(target)
├── skills/                       # bundled skill files (emitted into target/.agentshield/)
│   ├── tier2_bootstrap.md.tmpl
│   ├── tier2_checklist.md.tmpl       # the Tier 2 rule pack (62 entries)
│   ├── tier2_output_schema.md.tmpl
│   ├── agentshield_semgrep_fixes.md  # generated; per-source fix-skill (Semgrep)
│   ├── agentshield_copilot_fixes.md  # generated; per-source fix-skill (Copilot)
│   ├── agentshield_manifest_fixes.md # generated; per-source fix-skill (Manifest)
│   └── _build_fix_skills.py          # generator — re-run after rule changes
├── emitter/
│   └── skill_emitter.py          # copies bundled skills + writes tier1-results.json
├── merger/
│   ├── combine.py                # main merge logic + all 4 report renderers
│   ├── schema.py                 # tier2-findings.json validator
│   ├── reference.py              # rule-data loader (powers Reference tab + fix-skill generator)
│   └── attack_narratives.py      # multi-turn campaign narrative renderer
├── probe/                        # live adversarial testing (verify / explore / campaign)
│   ├── orchestrator.py           # probe runner — dispatches to verify / explore / campaign
│   ├── explore.py                # exploratory mode: LLM brainstorms + fires 13 attack classes
│   ├── campaign.py               # multi-turn goal-directed attacks with mutation-on-block
│   ├── runner.py                 # HTTP request dispatcher to target endpoint
│   ├── classifier.py             # heuristic verdict (substring + JSON-path)
│   ├── llm_classifier.py         # LLM-driven verdict (Copilot / Bedrock)
│   ├── synthesis.py              # LLM-driven payload contextualiser
│   ├── target_adapter.py         # pluggable adapter (agent discovery, auth, mutation)
│   ├── payloads.py               # canned payload catalogue + parametrization
│   ├── harness.py                # safe-mode interception (mock responses)
│   ├── profiles.py               # profile enum + validators
│   └── schema.py                 # ProbeConfig / ProbeResult schema
├── report/                       # legacy single-tier writers (SARIF / JSON / Markdown for `scan`)
└── frameworks/                   # external taxonomy lookup tables (OWASP LLM, AgentShield v1)

tests/
├── test_rules_golden.py          # SARIF goldens per fixture per rule
├── test_normalizer.py            # SARIF → Finding contracts
├── test_emitter.py               # bundled skills emitted correctly
├── test_merger.py                # merge logic + report rendering
├── test_manifest_scanner.py      # AST10 rules + walker
├── test_reference.py             # rule-data loader + fix-skill drift guard
├── test_skills.py                # checklist template structural invariants
├── test_writers.py               # SARIF / JSON / Markdown shape tests
├── test_cli_exclude.py           # --exclude glob handling
├── fixtures/{python,java}/       # positive + negative fixtures per rule
└── golden/{python,java}/         # expected findings per fixture (regenerable)

testbed/
└── demo-agent/                   # synthetic agent with known anti-patterns;
                                  # also serves as the visual demo target for sample-report.html
```

---

## 8. Testing

- **Golden tests** for Tier 1: each fixture under `tests/fixtures/python/<rule>_<scenario>.py` has an expected `tests/golden/python/<rule>_<scenario>.json` snapshot. `pytest tests/test_rules_golden.py --update-golden` regenerates them after intentional rule changes.
- **Drift guard** for the fix-skill files: `test_reference.py` re-runs the generator and asserts byte-equal output vs the on-disk `agentshield_*_fixes.md` files. CI catches stale skills automatically.
- **Schema tests** for the Tier 2 checklist: `test_skills.py` asserts every `### AS-C-…` entry has the required bullets (Severity, Languages, Frameworks, Look for, Skip if, Remediation) and that the section structure matches the documented sections.
- **Merger contracts** in `test_merger.py`: stale-detection, FP-overlay, schema validation, all 4 renderers. ~75 tests covering report structure end-to-end.

Total suite: 214 tests, ~30s on a warm machine.

---

## 9. CI / VDI considerations

AgentShield runs unchanged on CI, locked-down VDIs, air-gapped boxes — provided Semgrep is installed.

- **Tier 1 + AST10** run end-to-end without any IDE / LLM / network dependency. Suitable as a CI gate.
- **Tier 2** needs an IDE with Copilot. CI can either:
  - skip Tier 2 (`agentshield scan --no-emit`) and accept "Copilot LLM Scan not run" banner on the Tier-1-only report, or
  - have a developer run Tier 2 locally pre-PR and commit the unified report (or a hash of it) as evidence
- **VDI** specifics: the report HTML is rendered with VDI-friendly CSS (1.5px borders, mid-saturation severity backgrounds, antialiased fonts, drop shadows) so chroma compression doesn't wash it out. The HTML server pattern (`python -m http.server 8765 --bind 127.0.0.1`) is the standard way to view a generated report in a VDI session.
- **No outbound network** — AgentShield emits files locally, never uploads. The only outbound URLs in the report are the Frameworks-tab "reference →" links, which open in a new tab on click.

---

## 10. Non-goals

- **No fully autonomous red-team platform.** `agentshield probe` fires targeted, structured attacks at a developer-supplied endpoint; it is not a continuous automated red-team service. Sustained autonomous fuzzing (Garak, AgentDojo, PyRIT, Promptfoo) is complementary for depth.
- **No managed service.** AgentShield is a CLI you run locally. There is no hosted endpoint, no agentshield.com, no telemetry.
- **No new languages.** Tier 1 stays Python + Java. Tier 2 (Copilot) reads anything in the workspace incidentally, but parity with Py/Java is not claimed.
- **No Copilot plugin / VS Code extension.** The handoff is via skill files + Copilot Chat slash-prompt, not a custom extension.
- **No prompt-engineering layer for Tier 2.** The checklist *is* the prompt. There is no separate prompt-engineering layer between the checklist and Copilot.
- **No scanner-side LLM dependency.** Tier 2 runs on the user's IDE Copilot license; AgentShield itself does not call any LLM API.
