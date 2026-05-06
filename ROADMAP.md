# Roadmap

Status: 2026-05-05
Companion to: [README.md](./README.md), [PHASE_I_PLAN.md](./PHASE_I_PLAN.md), [PHASE_B_TRIAGE.md](./PHASE_B_TRIAGE.md), [PHASE_C_TRIAGE.md](./PHASE_C_TRIAGE.md), [PHASE_D_TRIAGE.md](./PHASE_D_TRIAGE.md), [VDI_TESTING.md](./VDI_TESTING.md)

This document is the **single canonical source of truth for AgentShield's state** — both what's been delivered and what's still pending. The phase-triage docs (PHASE_B / C / D) are historical records of what each phase did; this file reads top-down so anyone picking up the project sees the current state, the trajectory, and the open questions in one place.

## Contents

- [1. How this relates to the other docs](#1-how-this-relates-to-the-other-docs)
- [2. Current state at a glance](#2-current-state-at-a-glance)
- [3. What's shipped — phase-by-phase](#3-whats-shipped--phase-by-phase)
  - [3.1 v0.1 foundation](#31-v01-foundation)
  - [3.2 Phase A — testbed validation methodology](#32-phase-a--testbed-validation-methodology)
  - [3.3 Phase A.2 — Java apps + synthetic-vuln-java-app](#33-phase-a2--java-apps--synthetic-vuln-java-app)
  - [3.4 Phase B — precision (FP elimination)](#34-phase-b--precision-fp-elimination)
  - [3.5 Phase C — OWASP LLM coverage gap closure](#35-phase-c--owasp-llm-coverage-gap-closure)
  - [3.6 Phase D — polish pass](#36-phase-d--polish-pass)
  - [3.7 Post-Phase-D — roadmap consolidation + mock judge backend](#37-post-phase-d--roadmap-consolidation--mock-judge-backend)
  - [3.8 Phase E — judge-driven FP elimination + R002 retirement](#38-phase-e--judge-driven-fp-elimination--r002-retirement)
  - [3.9 Phase F — architecture v2 (2 tiers, Copilot-as-scanner)](#39-phase-f--architecture-v2-2-tiers-copilot-as-scanner)
- [4. Strategic options — the big bets](#4-strategic-options--the-big-bets)
- [5. Specific tracks from the original plan](#5-specific-tracks-from-the-original-plan)
- [6. Quality improvements](#6-quality-improvements)
- [7. Maintenance](#7-maintenance)
- [8. How to update this doc](#8-how-to-update-this-doc)

## 1. How this relates to the other docs

| Doc | Role |
|---|---|
| **ROADMAP.md** (this file) | Canonical state of project — what's done + what's pending. Maintained continuously. |
| [PHASE_I_PLAN.md](./PHASE_I_PLAN.md) | The original v0.1 / v0.2 plan from 2026-05-02. Strategic context for *why* the project exists. Historical. |
| [PHASE_B_TRIAGE.md](./PHASE_B_TRIAGE.md) | Detailed log of Phase B's 8 triage targets — what was reviewed, classified, fixed. |
| [PHASE_C_TRIAGE.md](./PHASE_C_TRIAGE.md) | Detailed log of Phase C's coverage gap work (D007 / D008 rules added). |
| [PHASE_D_TRIAGE.md](./PHASE_D_TRIAGE.md) | Detailed log of Phase D's polish pass (CWE / ATLAS / SpringApplication fix / synth-vuln-py / heatmap). |
| [TESTBED_VALIDATION.md](./TESTBED_VALIDATION.md) | Testbed methodology + heatmap of findings across 11 projects. |
| [RULES_COVERAGE.md](./RULES_COVERAGE.md) | What each rule detects, language by language. |
| [REMEDIATION_PATTERNS.md](./REMEDIATION_PATTERNS.md) | Worked BAD / GOOD code examples for fixing each rule's finding (Python + Java). |
| [VDI_TESTING.md](./VDI_TESTING.md) | Operational playbook for running AgentShield in a JPMC VDI. |

**Anyone picking up the project should read this file first**, then dive into the linked specifics only when they need historical context.

## 2. Current state at a glance

| Dimension | State |
|---|---|
| **Architecture** | **v2** (Phase F shipped 2026-05-06) — 2 tiers: Tier 1 semgrep + Tier 2 LLM-as-scanner via Copilot |
| **Tier 1 rule families** | **6** narrow high-precision (D001-fw, D003, D004, D005, D008, DF003) — pruned from 14 in F.2 |
| **Tier 2 checks** | **56** comprehensive (covers OWASP LLM v2 + Agentic AI Top 10 + ATLAS + CWE + Phase E gaps + retired-rule parity) — runs via Copilot using bundled skill files |
| **Rule files in `agentshield/rules/`** | 12 (Python + Java parity for all 6 surviving families) |
| **Archived rules in `agentshield/_retired_v2/`** | 15 (8 families retired into Tier 2 checklist) |
| **Languages supported** | Tier 1: Python, Java. Tier 2: any language Copilot can read |
| **OWASP LLM Top 10 coverage** | **10 / 10** (LLM09 Misinformation now covered by Tier 2 checklist as a reviewer-judgment item) |
| **OWASP Agentic AI Top 10 coverage** | **11 / 11** (T5 / T7 / T9 added to Tier 2 checklist as reviewer-judgment items — out of static-rule scope but in scope for LLM-as-scanner) |
| **MITRE ATLAS techniques mapped** | 6 (in Tier 2 checklist) |
| **CWE first-class mappings** | 10 distinct CWEs (78, 89, 94, 200, 400, 494, 532, 732, 798, 829) — covered across Tier 1 + Tier 2 |
| **pytest tests** | **123 passing** (rule golden + emitter + merger + skill-template invariants + normalizer + writers + CLI exclude) |
| **Testbed projects** | 11 (10 OSS frameworks + 2 synthetic vuln apps) |
| **Tier 2 LLM execution** | **Copilot** in user's IDE (default) via `.agentshield/tier2-bootstrap.md` skill file. No AWS dep. |
| **Output formats** | SARIF v2.1.0, JSON, Markdown — both Tier-1-only (`agentshield scan --output-*`) and unified (`agentshield merge --output-*`) |
| **CI integration** | Tier 1 only (Tier 2 needs an IDE with Copilot). Headless CI Tier 2 backend = future work. |
| **Network-share scanning workaround** | `--stage-locally` flag for Windows UNC / mapped-drive paths |

## 3. What's shipped — phase-by-phase

### 3.1 v0.1 foundation

The original sequenced one-week plan from [PHASE_I_PLAN.md](./PHASE_I_PLAN.md) (decided 2026-05-02) — landed across the project's first development sprint.

**Delivered:**
- **Tier 1+2 semgrep scan pipeline** — `agentshield scan <path>` invokes semgrep with the bundled rule pack, captures SARIF, normalises to typed `Finding` objects (`agentshield/normalize/`).
- **Tier 3 LLM judge tier** — boto3-Bedrock backend (`Boto3BedrockBackend`) + `JudgeOrchestrator` that routes fallback findings to the judge for triage. CLI flags `--llm-backend`, `--bedrock-model-id`, `--bedrock-region`.
- **Three output writers** — SARIF v2.1.0 ([agentshield/report/sarif.py](./agentshield/report/sarif.py)), JSON ([agentshield/report/json_writer.py](./agentshield/report/json_writer.py)), Markdown ([agentshield/report/markdown.py](./agentshield/report/markdown.py)).
- **Initial rule pack** — D001 (fw + fb), D002, D003, DF001, DF002, R001 — covering OWASP LLM01 (Prompt Injection), LLM06 (Excessive Agency), LLM10 audit logging side. Python only initially.
- **Documentation** — [README.md](./README.md), [ARCHITECTURE.md](./ARCHITECTURE.md), [ARCHITECTURE_RATIONALE.md](./ARCHITECTURE_RATIONALE.md), [GLOSSARY.md](./GLOSSARY.md), [REQUIREMENTS.md](./REQUIREMENTS.md), [TIER_FLOWS.md](./TIER_FLOWS.md), [LLM_JUDGE_DESIGN.md](./LLM_JUDGE_DESIGN.md), [VDI_TESTING.md](./VDI_TESTING.md).
- **Java rule parity (initial)** — Java versions of D001 / DF001 / R001 for langchain4j + Spring AI + Bedrock direct.

### 3.2 Phase A — testbed validation methodology

**Goal:** validate that the rule pack works on real codebases, not just synthetic fixtures. Establish a repeatable methodology for finding-level triage.

**Delivered:**
- **`testbed/`** directory established (gitignored — each developer clones locally) with 6 OSS projects: langchain, langchain4j, llama-index, langgraph, google-adk-python, plus the synthetic `smartsdk-lambda` (rebuilt from PDF descriptions of a real JPMC Lambda).
- **First breadth-scan heatmap** — finding count per rule × project across all 6 projects (~10K source files, ~5 min compute). 2,417 findings baseline.
- **[TESTBED_VALIDATION.md](./TESTBED_VALIDATION.md)** — the methodology doc. Heatmap, framework-vs-app interpretation (§3.1), Phase B priority targets list.
- **`--scan-all-files` and `--stage-locally` CLI flags** — operational fixes for real-world scanning (semgrep's default ignore behaviour and Windows UNC path silent failure).
- **Discovered + fixed redundant `await` pattern bug** in DF001 / R001 / D004 / D001 (Python). Earlier rule additions had double-fired on awaited LLM calls; semgrep's sub-expression matching meant the explicit `await $X.run(...)` patterns were redundant with the unawaited `$X.run(...)` patterns.

### 3.3 Phase A.2 — Java apps + synthetic-vuln-java-app

**Goal:** every Java rule needs a project that exercises it. Phase A had only `langchain4j` (a *library*, not an *app*) — many Java rules fired zero times.

**Delivered:**
- **3 real Java apps cloned to testbed** — `langchain4j-examples`, `spring-ai-examples`, `aws-bedrock-java-examples` (sparse-cloned subset). 297 + 138 + 59 = 494 Java files added.
- **`synthetic-vuln-java-app`** — 9 hand-written Java files containing every Java anti-pattern (D001-D006 / DF001-DF004 / R001 Java) intentionally. Now a pinned regression target.
- **Coverage status flipped** from 4 / 12 → **11 / 12 Java rules firing** on at least one project.
- **Updated TESTBED_VALIDATION.md heatmap** — 10 projects, 3,281 findings.

### 3.4 Phase B — precision (FP elimination)

**Goal:** triage the actual findings the rules produce on real code. Eliminate false positives without losing true positives.

**Delivered (8 triage targets, 4 rule fixes):**

| # | Target | Outcome |
|---|---|---|
| 1 | D004 Java × langchain4j (34 findings) | Removed bare `$STMT.execute($X)` pattern → 100% FP elimination (34 FPs cleared, 0 TPs lost) |
| 2 | D003 × langchain (2 findings) | Removed bare `from … import ShellTool` patterns (re-export shim FPs) → 2 FPs cleared |
| 3 | D006 (Python + Java) singletons | Python: 1 TP kept; Java: added `metavariable-type: RestTemplate` to suppress `Map.put(...)` collision → 1 FP cleared |
| 4 | DF003 × google-adk-python (2 findings) | Both confirmed TPs — no rule change |
| 5 | D005 Java × langchain4j-examples (1 finding) | TP-educational — no rule change |
| 6 | Real-app Java cluster (D001 + DF002 + DF004) — 9 findings | 9 / 9 TPs — no rule change (validated rule precision on real demo apps) |
| 7 | D001 framework × langchain (sampled 10 / 63) | 10 / 10 sample FPs from framework-internal infrastructure — documented framework-vs-app pattern, no rule change |
| 8 | D002 × llama-index + langchain (189 findings) | Added `metavariable-regex` to `$LOADER_CLASS` requiring `Loader|Reader|Scraper` suffix → **189 FPs cleared** (largest single elimination) |

**Numbers:** **227 false positives eliminated, 0 true positives lost, 0 test regressions.**

**Reusable patterns surfaced:** `metavariable-type` constraints work for Java; `metavariable-regex` constraints work for class-name disambiguation; semgrep auto-taints method parameters in framework code (creates predictable noise on framework scans, invisible to user-app scans).

**Doc:** [PHASE_B_TRIAGE.md](./PHASE_B_TRIAGE.md) — 9 sections including methodology + cumulative numbers + reusable lessons.

### 3.5 Phase C — OWASP LLM coverage gap closure

**Goal:** close the two remaining OWASP LLM Top 10 categories AgentShield didn't cover (LLM04 Data and Model Poisoning, LLM07 System Prompt Leakage).

**Delivered:**
- **D007 (Python)** — `untrusted-model-loading`. Detects HuggingFace `from_pretrained(...)` / `hf_hub_download(...)` / `snapshot_download(...)` calls without `revision=` pin. Maps to OWASP LLM03 + LLM04. Java port intentionally skipped (HuggingFace-style hub-loading is rare in Java; documented as a deferred gap).
- **D008 (Python + Java)** — `untrusted-system-prompt`. Taint-mode rule: sources are network reads (requests / httpx / urlopen / S3 / SSM); sinks are LLM system-prompt slots (Anthropic `system=`, OpenAI Responses `instructions=`, LangChain `SystemMessage`, Bedrock Converse `system=[{"text": …}]`; Java equivalents for langchain4j / Spring AI / Bedrock).
- **Fixtures + goldens** for each. pytest 76 → 82 passing.
- **Real-code validation** — D007 fires 82× across llama-index + langchain (sampled — all TPs); D008 fires 0× (rule appropriately strict; well-curated frameworks bake prompts into source).

**OWASP LLM Top 10 coverage: 7 / 10 → 9 / 10** (LLM09 Misinformation remains out of SAST scope as a content-quality concern).

**Doc:** [PHASE_C_TRIAGE.md](./PHASE_C_TRIAGE.md).

### 3.6 Phase D — polish pass

**Goal:** lock in Phase B + C gains with metadata enrichment, one more FP fix, Python regression parity, and a refreshed full-testbed heatmap.

**Delivered:**

1. **First-class CWE field** added to `FrameworkMappings` schema, picked up by normalizer, rendered in markdown reports. Populated on 10 rules (8 distinct CWEs: 78 / 89 / 94 / 400 / 494 / 532 / 732 / 798 / 829 / 200).
2. **MITRE ATLAS expansion** on 7 rules — D003 / D004 → T0011, D006 / DF002 → T0053, R001 → T0024. Coverage 3 → 6 distinct ATLAS techniques.
3. **SpringApplication.run FP fix** — DF001 / R001 Java's catch-all `$AGENT.run(...)` was matching every Spring Boot main class (`SpringApplication.run(Application.class, args)`). Added `pattern-not: SpringApplication.run(...)`. **64 FPs cleared on spring-ai-examples** (`129 → 65`).
4. **`synthetic-vuln-python-app`** built — Python parity to synthetic-vuln-java-app. 11 files, one per Python anti-pattern. **All 13 Python rules fire** including D004 — which **settles the Phase A.2 question**: D004 Python's continued zero-fire on the OSS testbed was because Python developers genuinely avoid the pattern, not because the rule was too narrow.
5. **Full-testbed breadth re-scan** with the post-Phase-B+C+D rule pack. Refreshed heatmap captures cumulative state: **3,131 findings across 11 projects.**

**Cumulative across A→D: 291 FPs eliminated, 141 new TPs added, 0 TPs lost, 0 test regressions.**

**Doc:** [PHASE_D_TRIAGE.md](./PHASE_D_TRIAGE.md).

### 3.7 Post-Phase-D — roadmap consolidation + mock judge backend

**Delivered:**
- **VDI_TESTING.md refresh** — Stage 7.5 added with specific run commands for Python SMARTSDK + Spring AI agents, privacy-review checklist before sharing reports, and "what to share" / "what the triage produces" guidance.
- **ROADMAP.md** (this file) — consolidates the scattered "what's left" sections from PHASE_B / C / D into a single canonical pending-work list, plus this phase-by-phase shipped record.
- **`MockJudgeBackend` + `--llm-backend mock` flag** ([agentshield/judge/mock_backend.py](./agentshield/judge/mock_backend.py)) — deterministic placeholder backend for VDI / dev smoke-testing the orchestrator pipeline without AWS. Returns a fixed `needs_review` verdict on every call with reasoning that explicitly says "no real LLM was called" so a leaked finding can never be mistaken for a real triage. **Stage 4.5** added to [VDI_TESTING.md](./VDI_TESTING.md) showing the full `agentshield scan ... --llm-backend mock` end-to-end test path. 6 new unit tests in [tests/test_judge_mock.py](./tests/test_judge_mock.py); pytest 86 → 92 passing.

### 3.8 Phase E — judge-driven FP elimination + R002 retirement (Java + Python)

First real-world validation: ran AgentShield against a production Spring AI codebase inside the JPMC VDI, then asked an LLM-as-judge to grade every finding against the source. Result: **62% false-positive rate on Java**, driven by patterns that synthetic fixtures never exercised.

**Strategic shift:** *fewer high-precision rules over many noisy ones.* Better to under-detect with confidence than to flood reviewers with FPs that train them to ignore the report.

**Delivered:**
- **R002 retired entirely** (Python + Java). The "LLM I/O logged without redaction" rule was the largest single FP source — it fired on `SessionController` (logging session UUIDs), `SplunkSAMLController` (SAML auth params), and other non-LLM logging surfaces because the taint-mode tracking can't distinguish "log call near LLM import" from "log call of LLM I/O." Replacement guidance folded into REMEDIATION_PATTERNS.md §R001: when implementing audit logging, use a redactor / hash / length-projection. **2 rule files, 4 fixtures, 4 goldens, all doc references** removed. pytest 92 → 88 passing (6 R002 tests deleted, 0 regressions).
- **DF001-Java + R001-Java FP fixes** based on judge-flagged shapes:
  - Dropped over-broad catch-alls `$AGENT.run(...)`, `$AGENT.invoke(...)`, `$CHAIN.execute(...)` — these matched `CompletableFuture.runAsync`, `taskExecutor.execute`, etc. Replaced SMARTSDK `$RUNNER.run($AGENT, ...)` with the more specific `$RUNNER.run($AGENT, $INPUT, ...)` two-arg form.
  - Added explicit `pattern-not` for `CompletableFuture.runAsync(...)` / `supplyAsync(...)` (Java executor framework, not LLM invocation).
  - Recognised Lombok `@Slf4j` as a logger import in R001-Java (`import lombok.extern.slf4j.Slf4j;` + `lombok.extern.log4j.*`) — Lombok synthesises the SLF4J `log` field at compile time without a direct `org.slf4j.Logger` import.
  - Recognised in-house Spring AI advisor wiring in DF001-Java via metavariable-regex on import class names ending in `Advisor` / `Guardrail` / `Scrubber` / `Sanitizer` — covers JPMC `ScrubbingCallAdvisor` and similar custom `CallAdvisor` subclasses outside `org.springframework.ai.*`.
  - Added inline `$CLIENT.prompt().advisors(...).user(...).call(...)` suppressor for the Spring AI inline-advisor pattern.
- **Coverage preservation verified** — synthetic-vuln-java-app fires identically before/after edits (45 findings across 9 files, no regressions).

**Net:** 1 rule family removed (R002), 5 specific FP shapes eliminated, 0 TPs lost. Coverage is narrower but more trustworthy — the strategic basis for further rule-pack audit (see §4.4).

#### Phase E.2 follow-on — Python rule fixes from second judge run

Second judge protocol on `moip-cost-anomaly-probe-lambda` (Python SMART SDK Lambda, 2026-05-05). Effective post-Phase-E run was 8 medium findings: 2 TP / 6 FP (75% FP). Two FP shapes drove all 6:

- **`$CLIENT.invoke(FunctionName=..., ...)` matched boto3 Lambda self-invocation** (4 FPs in `extract.py`, `handler2.py`). DF001 + R001 catch-all `$X.invoke(...)` was the same root cause as the Java `$AGENT.invoke` issue. Added `pattern-not: $X.invoke(FunctionName=$FN, ...)` and `pattern-not: boto3.client("lambda").invoke(...)` to both Python rules. The `FunctionName=` keyword is a strong disambiguator — LangChain's `chain.invoke(input)` uses a positional first arg.
- **R001 didn't recognise `logger = logging.getLogger(__name__)` setup** (2 FPs on files that DO have audit logging). Original R001 design required *structured* logging (structlog / langsmith / opentelemetry / langchain.callbacks); judge surfaced that this is over-strict on real Lambda code. Relaxed: `$LOGGER = logging.getLogger(...)` and `$LOGGER = getLogger(...)` patterns now suppress R001. Plain `import logging` still does NOT suppress (too weak — used everywhere for error handling).
- **Fixture `d001_smartsdk_asyncio_runner.py` docstring updated** — previously asserted "stdlib logging does NOT silence R001" as design intent; Phase E.2 reverses this. Goldens for `d001_smartsdk_runner.py` + `d001_smartsdk_asyncio_runner.py` updated to drop the now-suppressed R001 fire.
- **New regression fixture `df001_lambda_self_invoke.py`** — pins the boto3 Lambda suppressor; expects zero findings.

Validation: smartsdk-lambda testbed now produces 5 DF001 fires (all TPs — real "no guardrails" concerns) and 0 R001 fires (correctly silent — files have `logger = logging.getLogger(__name__)`). Cross-checks the judge's recommended behaviour. **Effective FP rate on the real Lambda would have dropped from 75% → 25% (2 TP / 0 FP for medium findings; only DF001 remains and both fires are TP).**

#### Phase E.3 follow-on — third judge run + `--exclude` CLI flag + R002 TP-loss documentation

Third judge protocol on `moip-thematic` / `moip-triage-agent` (Java Spring AI thematic-search agent, 2026-05-05). 31 findings on the pre-Phase-E rules: 2 TP / 3 CD / 26 FP (~6% precision). Phase E + E.2 fixes already applied to the rules eliminate roughly 14 of the 31 findings (R002 retirement + CompletableFuture + the dropped `$CHAIN.execute` catch-all that was matching `taskExecutor.execute`).

**Two distinct new signals from this run:**

1. **17 of 31 findings (55%) were `src/test/` test code** — All test-file fires are FPs by definition (test code intentionally exercises LLM classes without production guardrails; `ScrubberServiceTest.java` IS the test suite for the guardrail itself). The user invoked `--scan-all-files` which bypasses semgrep's built-in `.semgrepignore` (the default Maven/Gradle `src/test/**` exclusion). **Fix: added `--exclude PATTERN` repeatable CLI flag.** `agentshield scan ... --scan-all-files --exclude '**/src/test/**' --exclude '**/tests/**'` would have eliminated all 17 test-file FPs in one pass. Glob translator handles `**` semantics correctly (gitignore-style: `**/` at start matches zero-or-more leading components). 7 new pytest tests in `test_cli_exclude.py`; suite 89 → 96 passing.

2. **R002 retirement lost 2 TPs on this codebase** — `SplunkSAMLController:40` (raw SAML assertion logged, CWE-532) and `TriageController:28` (raw user message logged before scrubbing). The first is generic CWE-532 (out of LLM-SAST scope — handled by other security tooling). The second is exactly the LLM02+LLM10 audit-without-redaction pattern R002 was designed for; this is a **real signal loss** from the Phase E retirement. R002's overall FP rate across three codebases (62% Java JpmcTriage / 100% Python SMART SDK Lambda / 22% Java thematic) still justifies retirement, but the gap is documented for the §4.4 audit candidates.

**Net post-Phase-E.3 projection on the thematic codebase:** 31 raw findings → after R002 retirement (~9 gone), CompletableFuture/taskExecutor suppression (~3 gone), and `--exclude '**/src/test/**'` (17 gone) → roughly **2 findings** (both production DF001 fires that are CD because the custom advisor exists in another file). Practical precision after Phase E + E.2 + E.3 + appropriate `--exclude`: meaningfully usable on real Spring AI codebases.

### 3.9 Phase F — architecture v2 (2 tiers, Copilot-as-scanner)

**Shipped:** 2026-05-06. Branch: `architecture-v2` (commits `527d89b` → `14e4292`). The architectural reset documented in [ARCHITECTURE_V2.md](./ARCHITECTURE_V2.md).

**The diagnosis** (from three Phase E judge runs):
- Rule-only architecture had a precision ceiling — 4 rule families (R001, DF001, DF002, DF004) were absence-detection or pure heuristics, FP-prone on real codebases regardless of further tightening.
- The Tier 3 LLM-as-triage model was in the wrong slot. It triaged cherry-picked low-confidence findings from the rule pack but couldn't catch what rules missed (SNS data leak, scrubber bypass, no LLM timeout) and couldn't downgrade FPs from framework rules.
- The LLM was actually most useful when it scanned the **whole repo against a comprehensive checklist** — which is what the manual judge runs were already doing.

**The pivot:** flip the orchestrator's role.
- **Tier 1** stays semgrep with a pruned high-precision rule pack.
- **Tier 2** becomes whole-repo LLM-as-scanner, executed by **Copilot in the user's IDE** using bundled skill files. No AWS / Bedrock dep.
- Both tiers mandatory; soft-warn if Tier 2 hasn't been run.

**Phased rollout (8 commits on `architecture-v2`):**

| Phase | What | Commit |
|---|---|---|
| F.1 | ARCHITECTURE_V2.md design doc + sign-off | `527d89b` |
| F.2 | Rule archival — 14 → 6 families. 8 retired into `agentshield/_retired_v2/` | `8481bf0` |
| F.3 | Bundled skill templates — 56 checks, 964 lines, 7 sections | `8aea906` |
| F.4 | Emitter — copies templates + writes tier1-results.json with fingerprint hash | `bd290c4` |
| F.5 | Merger — combines tier1 + tier2, validates schema, detects stale runs | `9fd2c49` |
| F.6 | CLI rewire (drop 5 judge flags, add `merge` subcommand) + delete `agentshield/judge/` (-1242 LOC) | `14e4292` |
| F.7 | Docs refresh (this commit + downstream) | (current) |
| F.8 | Validate v2 by re-running on the three Phase E codebases | pending |

**Tier 1 surviving rules (6):** D001-fw, D003, D004, D005, D008, DF003. All narrow taint or narrow regex; no absence-detection or pure heuristics.

**Tier 2 checklist coverage:** OWASP LLM Top 10 v2 (22 checks) + OWASP Agentic AI Top 10 (13 checks) + MITRE ATLAS (6) + CWE first-class (10) + Phase E gaps (5) + retired-rule parity references. **56 total checks.** Comprehensive by design — the user explicitly required "all key points from the security frameworks like OWASP Top 10 Agentic AI."

**Stale-detection contract:** `compute_tier1_fingerprint` produces SHA-256 over sorted `(file, line, rule_id)` tuples. Copilot copies the fingerprint from `tier1-results.json` into `tier2-findings.json`. The merger compares — mismatch = stale Tier 2 = banner in the report.

**What we lost:**
- Tier 1 standalone CI gating reaches fewer findings (8 rule families gone). Mitigation: the warning banner makes Tier 2 absence visible; teams should treat unmerged Tier 1 as preliminary, not authoritative.
- No automated Tier 2 in CI today (Copilot Chat needs an IDE). Mitigation: a future Bedrock-based Tier 2 backend is documented as F.x follow-on; the merger architecture is backend-agnostic — anything that produces a schema-valid `tier2-findings.json` works.

**What we gained:**
- LLM-as-scanner catches what rules miss (Phase E surfaced 5 such patterns; the Tier 2 checklist's §5 explicitly names them).
- LLM cross-checks Tier 1 with full file/repo context — every Tier 1 finding can be marked TP/CD/FP by Tier 2 with reasoning. FP-marked findings are dropped from CI gating count.
- Comprehensive framework coverage extends to LLM09, T5/T7/T9 — categories static rules couldn't reach (alignment / misinformation / identity threats).
- Zero AWS dependency for the default execution path.

**Net code delta across F.2–F.6:** −974 LOC. Smaller, sharper rule pack + the v2 product (the comprehensive Tier 2 checklist) replacing the Tier 3 triage stack.

**Pytest:** 92 → 123 passing across the migration. Net +31 tests covering the new modules (emitter, merger, skills) minus the 30 deleted judge tests.

**Doc:** [ARCHITECTURE_V2.md](./ARCHITECTURE_V2.md), [TIER2_USAGE.md](./TIER2_USAGE.md).

## 4. Strategic options — the big bets

The strategic question after Phase D is: **what's actually limiting users?** Without user data, the three options below are equal-weight bets. Pick based on the real bottleneck, not on speculation.

### 4.1 TypeScript / JavaScript language support

**Hypothesis:** "we're not reaching enough users" is the bottleneck. The Node agent ecosystem (LangChain.js, Vercel AI SDK, Mastra, OpenAI / Anthropic JS SDKs) is the largest category of LLM apps AgentShield can't currently scan.

**Scope:** Most existing rules port directly — different syntax, same patterns. Initial cut covering the core 5-7 rules (D001 / DF001 / R001 / D008 / DF003 plus the most-common Java equivalents) is ~1-2 days. Full parity with Python / Java rule pack is ~1 week.

**Effort:** L (multi-session investment).
**Impact:** Doubles addressable codebase population.

### 4.2 Tier 3 LLM judge calibration

**Hypothesis:** "users get too many fallback-rule findings to triage" is the bottleneck. The fallback rule (D001-fb) emits low-confidence findings that flow through the [Tier 3 judge](./LLM_JUDGE_DESIGN.md). Phase B + C + D produced **24+ confirmed-TP and ~291 known-FP examples** that could become labeled few-shot examples in the judge prompt.

**Scope:** Update [agentshield/judge/](./agentshield/judge/) prompts with labeled examples drawn from PHASE_B_TRIAGE.md, plus calibration sweep against the testbed to confirm FPR drops. Existing boto3-Bedrock backend stays the same.

**Effort:** M (~3-5 hours focused work).
**Impact:** Force-multiplier on every fallback finding produced going forward — improves the rule pack's safe-applicability range without writing new rules.

### 4.3 Adoption-layer polish

**Hypothesis:** "users aren't running it at all yet" is the bottleneck. Quality-without-shipping is invisible.

**Concrete items:**
- **PR-comment formatter** — render findings as a Markdown comment via a GitHub Action. AgentShield already emits SARIF + Markdown; this is glue, not a new capability.
- **CI integration recipes** — GitHub Actions / GitLab / Jenkins examples with severity-gated config. Demonstrate the severity ladder we built (e.g. "fail on critical+high, warn on medium, advise on info").
- **5-minute quickstart** in the README with a real before/after on a sample repo.
- **Methodology writeup** — the Phase-A-through-D testbed-validation work is genuinely novel (most SAST teams don't show their FPR-elimination work). A blog-post-shaped summary would be useful both internally and externally.

**Effort:** S-M (each item 2-4 hours; pick the one most-likely to unblock a real user).
**Impact:** Highly user-state-dependent — could be the highest-leverage thing if users are interested but not running it yet, or zero-leverage if no users yet exist.

### 4.4 Broader rule-pack audit (Phase E follow-on)

**Hypothesis:** Phase E's R002 retirement is the first instance of "fewer high-precision rules over many noisy ones." Other rules in the pack may also be net-negative on real codebases — we won't know until we run more user-side validation.

**Concrete approach:**
- **Repeat the LLM-as-judge protocol** on 2-3 additional real production codebases (Python SMARTSDK / langchain / Spring AI / langchain4j). Phase E + E.2 + E.3 have now run it three times — keep going; each round surfaces 2-5 new FP shapes plus surfaces real signal loss (e.g. R002 lost 2 TPs on the thematic codebase, see §3.8 Phase E.3).
- **For each rule, score per-deployment:** does the rule produce ≥ 70% TP-rate on real code? If not, candidates: (a) refine pattern + add suppressors (preferred); (b) downgrade severity from medium → info; (c) retire entirely (R002 precedent).
- **Likely audit candidates** based on synthetic-only validation today: D001-fb (fallback rule, intentionally low-confidence — should it gate behind judge tier mandatorily?); DF002 (`@Tool` arg schema — may FP on framework-internal tools); DF004 (destructive-verb naming — pure heuristic, no taint).

**Specific narrow-rule candidates surfaced by Phase E.3:**
- **R003 — "user input logged before sanitizer" (Java, narrow scope)** — Replace the retired R002's most valuable TP with a narrower rule: source = `@RequestBody` / `@RequestParam` / Spring web request inputs only; sink = SLF4J `log.*()` calls; suppressor = `scrubberService.scrubPii(...)` / `redact(...)` / similar in same flow before the log call. Catches `TriageController:28`-style "log raw user message before scrubbing" without re-firing on the SessionController UUID-logging FPs. Java first; Python equivalent if validated.
- **Data-flow rule for SNS / email sinks** — LLM output flowing to `SnsClient.publish()`, JavaMail `send()`, AWS SES, etc., without a scrubber on the same flow. Surfaced as a "missed real issue" by the thematic-codebase judge — current rule pack doesn't cover sensitive-data egress sinks beyond logs.
- **Scrubber-bypass detection** — Detect the anti-pattern of `if length > MAX: return original_input` in scrubber/sanitizer methods (silently passes oversized inputs through unchanged). Specific to in-house scrubber implementations; narrow but high-precision.

**Effort:** M (per codebase: ~1 hour scan + ~2 hours judge protocol + ~2 hours rule fixes).
**Impact:** Each round shrinks the trust gap between "what the rule pack says" and "what reviewers should act on." Compounding effect — every retired/refined rule reduces noise on every future scan.

## 5. Specific tracks from the original plan

These come from [PHASE_I_PLAN.md](./PHASE_I_PLAN.md)'s sequenced work plan and are referenced in the [VDI_TESTING.md](./VDI_TESTING.md) "What's NOT in this build" table.

> **Phase F supersedes the original Track B (judge backends) and Track D (Tier 4 discovery) entirely.** v2's Tier 2 architecture (LLM-as-scanner via Copilot) replaces the v1 "Tier 3 LLM judge" model. Tracks B2/B3/B5/D below are kept here as historical context but are **not on the roadmap as planned work** — the v2 architecture either obsoletes them or replaces them with different work (e.g. a future Bedrock-based Tier 2 backend would be a new module, not a revival of Track B2).

### 5.1 Track B2 — SMARTSDK judge backend [OBSOLETE]

**Superseded by:** v2 Tier 2 architecture. `agentshield/judge/` deleted in F.6. If a SMARTSDK-based Tier 2 backend is ever needed for headless CI, it would be a new module producing schema-valid `tier2-findings.json`, not a revival of the v1 `JudgeBackend` ABC.

### 5.2 Track B3 — GitHub Copilot judge backend [SHIPPED in F.6, different shape]

**What it became:** v2 Tier 2 uses Copilot via skill-file handoff (in-IDE), not via a programmatic backend. The user pastes the prompt from `.agentshield/tier2-bootstrap.md` into Copilot Chat; Copilot writes `tier2-findings.json`; `agentshield merge` consumes it. No API-level Copilot integration — that surface isn't openly available for arbitrary code-scanning prompts.

### 5.3 Track B5 — Audit log to `judge_audit.jsonl` [OBSOLETE]

**Superseded by:** v2 has no in-process LLM call orchestrator to audit. Copilot's interactions live in the user's IDE history, outside AgentShield's control. If a future headless Tier 2 backend is built, it can persist its own audit log there.

### 5.4 Track D — Tier 4 discovery pass [OBSOLETE in v1 form]

**Superseded by:** v2's Tier 2 inherently does shadow-LLM discovery. The Tier 2 checklist (Section §1: TIER2-LLM01-01) has Copilot scan every source file for LLM call shapes regardless of whether the repo "expects" to have LLM code. The dedicated `--discovery` flag is gone (deleted in F.6); the capability is folded into the comprehensive Tier 2 walk.

### 5.5 Track F — Trivy supply-chain scan

**What:** Run [Trivy](https://github.com/aquasecurity/trivy) against the target repo's dependencies (pip / Poetry / Maven / Gradle) to flag CVEs in the LLM SDKs and adjacent libraries — Open-source vulnerability scanning bolted on to AgentShield's findings pipeline.
**Effort:** M.
**Status:** Planned.

## 6. Quality improvements

Smaller targeted enhancements surfaced by Phase B / C / D triage:

### 6.1 Generic `.run()` collisions in Java

DF001-Java / R001-Java's `$AGENT.run(...)` pattern still collides with non-LLM `.run()` shapes — `scenario.run(state)` (demo runners), `runnable.run()`, `testRunner.run(state)`. The SpringApplication.run case was suppressed in Phase D ([PHASE_D_TRIAGE.md §2](./PHASE_D_TRIAGE.md#2-springapplicationrun-fp-fix--64-fps-eliminated)) but the broader collision class remains.

**Fix shape:** Add `metavariable-type` constraints to require the receiver to be of a known agent type (Google ADK `LlmAgent`, langchain4j `Assistant`, SMARTSDK `Runner`, etc.). Same technique used for D006 Java's `metavariable-type: RestTemplate` ([PHASE_B_TRIAGE.md §3](./PHASE_B_TRIAGE.md#3-d006-singletons-python--java--1-tp-1-fp-java-rule-fixed)).
**Effort:** S.

### 6.2 Triage real-app DF001 / R001 long tails

Phase D eliminated the SpringApplication.run FP class on spring-ai-examples (64 FPs). Remaining ~120 spring-ai-examples + ~70 aws-bedrock-java-examples DF001 / R001 findings are real LLM call sites without guardrails / audit logger imports. They're *probably* TPs (example apps don't wire production observability) but a sample triage of 5-10 from each would confirm and surface any further rule-tightening opportunities.
**Effort:** S (~1 hour).

### 6.3 Async embedding source patterns (Python)

[RULES_COVERAGE.md §8](./RULES_COVERAGE.md#8-known-gaps) Known Gaps notes that DF001 / R001 cover `$MODEL.embed(...)` and `$MODEL.aembed(...)` but not the awaited form `await $X.embed(...)`. Verified-not-firing-on-real-code today; would be a small completeness improvement.
**Effort:** XS.

### 6.4 Java `CompletableFuture`-chained sinks

D004 Java doesn't catch `.thenApply(model::generate)` style composition because the sink pattern matches direct method calls. Real-code prevalence is unknown.
**Effort:** S, but low priority pending demand.

### 6.5 Java DF002 — multi-parameter coverage

DF002 Java currently matches `@Tool` methods with one or two `String` parameters. Three-or-more bare-String params or non-String types would fall through.
**Effort:** XS.

## 7. Maintenance

Recurring work that doesn't fit a phase boundary:

### 7.1 Periodic testbed re-clones

The OSS frameworks in [`testbed/`](./testbed/) (langchain, llama-index, langchain4j, etc.) evolve fast. A quarterly or major-release-aligned re-clone keeps the [TESTBED_VALIDATION.md](./TESTBED_VALIDATION.md) heatmap meaningful.
**Cadence:** quarterly.

### 7.2 TESTBED_VALIDATION.md heatmap re-publish

When new rules ship or fixes land, re-run the breadth scan and update [TESTBED_VALIDATION.md](./TESTBED_VALIDATION.md) §2 heatmap. Phase D demonstrated this; ~30 min compute + ~10 min docs.
**Cadence:** after every batch of rule changes.

### 7.3 Phase doc cross-references

When a future phase ships, audit the previous phase's "What's left" section and add a one-line note pointing forward (e.g. "see PHASE_E_TRIAGE.md / ROADMAP.md for the current state"). Prevents the "5-file chase" problem this very document was created to solve.

## 8. How to update this doc

When you ship something on this list:

1. **Move the item from §4-§7 (pending) into §3 (shipped)** under the appropriate phase subsection — or add a new §3.x for a new phase. Include a short "what was delivered" summary, key numbers, and a link to the triage doc.
2. **Refresh §2 "Current state at a glance"** — rule counts, coverage percentages, test counts, etc., drift as work lands.
3. **If the item was a strategic option (§4)** — once shipped, re-evaluate the remaining options based on whatever user data the shipped item produced. The strategic options are inter-dependent on outcomes.
4. **If a new pending item surfaces** (from triage, from a user, from a phase) — add it to the right pending section (§4 strategic / §5 track / §6 quality / §7 maintenance) rather than starting a new "what's left" section in a phase-triage doc.

When you start a new phase (e.g. Phase E):

1. Reference this doc as the input rather than re-listing pending items in the new phase doc's "What's left" section.
2. The phase-triage doc should focus on **what was triaged in that phase + what's now shipped**, not on duplicating the roadmap.
3. After the phase ships, add a §3.x subsection summarising the phase's deliverables.
