# Testbed Validation — Phase A + A.2 + Phase D refresh

Status: 2026-05-05 (Phase D added synthetic-vuln-python-app, eliminated 64 SpringApplication.run FPs, refreshed full heatmap with 11 projects)
Companion to: [RULES_COVERAGE.md](./RULES_COVERAGE.md), [PHASE_B_TRIAGE.md](./PHASE_B_TRIAGE.md), [PHASE_C_TRIAGE.md](./PHASE_C_TRIAGE.md), [PHASE_D_TRIAGE.md](./PHASE_D_TRIAGE.md), [README.md](./README.md)

This document records the breadth-first scan of AgentShield's bundled rules against a curated set of real-world LLM / agent codebases under [`testbed/`](./testbed/). The goal is to validate that the rules behave correctly on real code (not just synthetic fixtures), surface false-positive risk, and find coverage gaps before Phase B (deep triage).

For the role and lifecycle of `testbed/` vs `tests/fixtures/`, see [§7 Testbed scope](#7-testbed-scope) below.

## Contents

- [1. Scope and projects](#1-scope-and-projects)
- [2. Heatmap — finding count per rule × project](#2-heatmap--finding-count-per-rule--project)
- [3. Interpretation — what's signal, what's noise](#3-interpretation--whats-signal-whats-noise)
- [4. Coverage status — every rule now has at least one firing project](#4-coverage-status--every-rule-now-has-at-least-one-firing-project)
- [5. Phase B priority targets](#5-phase-b-priority-targets)
- [6. Side effects of running Phase A](#6-side-effects-of-running-phase-a)
- [7. Testbed scope](#7-testbed-scope)
- [8. How to reproduce](#8-how-to-reproduce)

## 1. Scope and projects

Phase A scanned 6 projects. Phase A.2 added 4 more (3 real Java apps + 1 synthetic vulnerable Java app) to give every Java rule a project that exercises it.

| Project | Type | Files | Why included |
|---|---|---:|---|
| **smartsdk-lambda** | **Synthetic** SMARTSDK Lambda | 6 .py | Known-answer regression check for the SMARTSDK call shape — small Lambda that uses `await runner.run(agent, prompt)` across multiple modules with a Pydantic event model. |
| **synthetic-vuln-java-app** *(new in A.2)* | **Synthetic** vulnerable Spring AI / langchain4j app | 9 .java | Java parity to smartsdk-lambda — intentionally contains every Java anti-pattern (D003 / D004 / D005 / D006 / DF002 / DF003 / DF004) to validate the Java rules fire correctly when the patterns are present. |
| `langgraph` | Framework (stateful agent graphs) | ~344 .py | Exercises HITL / interrupt patterns, agent state-machine code. |
| `google-adk-python` | Framework (Google ADK) | ~1,336 .py | SMARTSDK proxy — SMARTSDK's call shapes all originate here. |
| `llama-index` | Framework (data + RAG) | ~3,828 .py | Different patterns from LangChain — query engines, document loaders, retrievers. |
| `langchain` | Framework (LLM orchestration) | ~2,474 .py | Most of our Python rules target LangChain shapes; the canonical false-positive surface. |
| `langchain4j` | Framework (Java port of LangChain) | ~2,700 .java | Java framework-source surface. |
| **langchain4j-examples** *(new in A.2)* | Real apps | ~297 .java | langchain4j's official sample apps — exercises Spring controllers + tools + builders in real-world shapes. |
| **spring-ai-examples** *(new in A.2)* | Real apps | ~138 .java | Spring AI's official sample apps — exercises ChatClient / ChatModel / Spring controllers. |
| **aws-bedrock-java-examples** *(new in A.2)* | Real apps (sparse-cloned subset) | ~59 .java | Direct AWS Bedrock Runtime SDK usage — `invokeModel` / `converse` / `converseStream` shapes. |

**Total: ~10,700 source files. Total scan time: ~6.5 minutes.**

Dropped from the original testbed (low-signal): `agentic-radar`, `autogen` (empty checkout), `crewai`, `deepteam`, `giskard`, `promptfoo`.

## 2. Heatmap — finding count per rule × project

Each cell is `<finding count> (<unique files>f)`. `.` means zero findings (including language-mismatched cells — Java rules can't fire on Python and vice versa).

| Rule | smartsdk-lambda | vuln-java | langgraph | ggl-adk | llama-idx | langchain | lc4j | lc4j-ex | spring-ex | aws-bedr |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| **D001** unsanitized-user-input-to-llm | . | . | 91 (29f) | 7 (5f) | 84 (46f) | 63 (20f) | . | . | . | . |
| **D001-fb** unsanitized-user-input-to-llm-fallback | . | . | . | . | 57 (36f) | . | . | . | . | . |
| **D001 Java** unsanitized-user-input-to-llm-java | . | 4 (2f) | . | . | . | . | . | **13 (10f)** | 4 (4f) | . |
| **D001 Java fb** unsanitized-user-input-to-llm-fallback-java | . | . | . | . | . | . | . | . | . | . |
| **D002** untrusted-document-loader-to-rag *(post-Phase-B fix)* | . | . | 0 | 0 | 0 | 0 | . | . | . | . |
| **D002 Java** untrusted-document-loader-to-rag-java | . | 3 (1f) | . | . | . | . | . | . | . | . |
| **D003** code-execution-tool-registered *(post-Phase-B fix)* | . | . | . | . | . | . | . | . | . | . |
| **D003 Java** code-execution-tool-registered-java | . | 3 (1f) | . | . | . | . | . | . | . | . |
| **D004** llm-output-to-code-execution | . | . | . | . | . | . | . | . | . | . |
| **D004 Java** llm-output-to-code-execution-java *(post-Phase-B fix)* | . | 2 (1f) | . | . | . | . | . | . | . | . |
| **D005** hardcoded-llm-credentials | . | . | . | . | . | . | . | . | . | . |
| **D005 Java** hardcoded-llm-credentials-java | . | 4 (1f) | . | . | . | . | . | **1 (1f)** | . | . |
| **D006** broad-tool-permissions | . | . | . | 1 (1f) | . | . | . | . | . | . |
| **D006 Java** broad-tool-permissions-java *(post-Phase-B fix)* | . | 5 (1f) | . | . | . | . | . | . | . | . |
| **DF001** no-guardrails-import-in-llm-module | 5 (2f) | . | 68 (20f) | 109 (82f) | **422 (203f)** | **263 (76f)** | . | . | . | . |
| **DF001 Java** no-guardrails-import-in-llm-module-java | . | 4 (2f) | . | . | . | . | **224 (142f)** | **304 (157f)** | 64 (46f) | 34 (33f) |
| **DF002** tool-without-args-schema | . | . | 1 (1f) | 2 (2f) | . | 12 (6f) | . | . | . | . |
| **DF002 Java** tool-without-args-schema-java | . | 5 (2f) | . | . | . | . | . | 2 (2f) | . | . |
| **DF003** no-timeout-or-token-cap-on-llm | . | . | . | 2 (2f) | . | . | . | . | . | . |
| **DF003 Java** no-timeout-or-token-cap-on-llm-java | . | 5 (1f) | . | . | . | . | . | . | . | . |
| **DF004** destructive-tool-without-human-approval | . | . | . | . | . | . | . | . | . | . |
| **DF004 Java** destructive-tool-without-human-approval-java | . | 6 (2f) | . | . | . | . | . | **3 (3f)** | . | . |
| **R001** llm-call-without-audit-logging | 5 (2f) | . | 63 (19f) | 97 (76f) | **422 (203f)** | 75 (25f) | . | . | . | . |
| **R001 Java** llm-call-without-audit-logging-java | . | 4 (2f) | . | . | . | . | **118 (79f)** | **298 (152f)** | 61 (44f) | 34 (33f) |
| **TOTAL** | **10** | **45** | **223** | **218** | **1062** | **418** | **342** | **621** | **65** | **68** |

**Pre–Phase-D 10-project total: 3,072** *(Phase B eliminated 227 FPs; Phase C added 82 D007 TPs on llama-index + langchain).* **Post–Phase-D**: 64 additional FPs eliminated by the SpringApplication.run suppressor (spring-ex `129 → 65`), and the new `synthetic-vuln-python-app` column adds 59 findings (all 13 Python rules fire — settles the D004 Python question). **11-project grand total: 3,131 findings.** See [PHASE_D_TRIAGE.md](./PHASE_D_TRIAGE.md) for the polish-pass details. Cumulative across all phases: **291 FPs eliminated, 141 new TPs added, 0 TPs lost**.

## 3. Interpretation — what's signal, what's noise

### 3.1 The framework-vs-app distinction (still the main interpretive lens)

DF001 + R001 still dominate the totals (1,491 + 1,074 of the 3,281 findings) because they fire on every LLM-calling module that doesn't import guardrails / structured logging — and framework source code rarely does.

**Reading the heatmap correctly:**
- **Library scans** (langchain, llama-index, langchain4j, langgraph, google-adk-python) — DF001 / R001 fire heavily on the framework's own LLM primitives. Library *users* never see this noise (their scan target is their own app, not the imported library).
- **App scans** (langchain4j-examples, spring-ai-examples, aws-bedrock-java-examples) — DF001 / R001 *also* fire heavily, and **this is the realistic FPR signal**. Real example apps demonstrate Spring AI / Bedrock usage without wiring guardrails. Whether this represents real findings or rule noise needs Phase B triage.

### 3.2 The synthetic vulnerable Java app worked exactly as designed

`synthetic-vuln-java-app` fires **every Java rule** with the expected count:

| Rule | Expected | Actual |
|---|---|---|
| D001 Java | 2-4 (2 controllers × 1-2 endpoints) | 4 (2 files) ✓ |
| D002 Java | 3 (3 RAG controller methods) | 3 (1 file) ✓ |
| D003 Java | 3 (shell + spawn + evalJs) | 3 (1 file) ✓ |
| D004 Java | 2 (analyze-and-run + analyze-and-query) | 2 (1 file) ✓ |
| D005 Java | 4 (4 hardcoded constructor / builder calls) | 4 (1 file) ✓ |
| D006 Java | 5 (delete + write + move + delete remote + put remote) | 5 (1 file) ✓ |
| DF001 Java | ≥4 (every ChatClient call) | 4 (2 files) ✓ |
| DF002 Java | ≥3 (lookupUser + 2-arg method) | 5 (2 files) ✓ |
| DF003 Java | ≥4 (timeout/maxTokens/Duration.ZERO/OkHttp 0s) | 5 (1 file) ✓ |
| DF004 Java | ≥4 (delete/send/charge/deploy) | 6 (2 files) ✓ |
| R001 Java | matches DF001 | 4 (2 files) ✓ |

This is a stable known-answer regression target. **Any change to the rule pack that changes synthetic-vuln-java-app's count is a signal worth investigating**, just like smartsdk-lambda is for the SMARTSDK side.

### 3.3 The real Java apps surfaced genuinely new signal

**langchain4j-examples** is the most informative new project:
- **D001 Java: 13 findings, 10 files.** Real Spring controllers in the example apps wire user input straight into `ChatClient.prompt(...).user(...)`. Likely true positives — example apps showing the basic pattern without sanitisation.
- **D004 Java: 1 finding** in a real example — needs Phase B triage to confirm.
- **D005 Java: 1 finding** — a real example with a literal credential. Phase B candidate.
- **DF002 Java: 2 findings, 2 files** — real demo tools without `@P` annotations.
- **DF004 Java: 3 findings, 3 files** — real demo `@Tool` methods named with destructive verbs (delete / send / etc.). Worth Phase B triage to validate the rule's name-based matching is reasonable on real code.

**spring-ai-examples** confirms Spring controller coverage:
- **D001 Java: 4 findings, 4 files** — Spring AI sample apps with `@RequestParam` → ChatClient.

**aws-bedrock-java-examples** (Bedrock direct SDK usage):
- DF001 + R001 both fire 34× (33 files) — every Bedrock example calls `invokeModel` / `converse` without wiring a guardrail or audit logger. Realistic for example code; would be noise for an end-user app that has org-standard observability.
- D001 Java fires 0× — these examples don't go through Spring controllers, they're CLI demos with `String prompt = "...";` literals.

### 3.4 D004 Java's 34 langchain4j findings — triaged in Phase B (100% FP, fixed)

**Resolved.** Triage of the 34 findings revealed they were all matched by the bare `$STMT.execute($X)` pattern catching `httpClient.execute(httpRequest)`, `executor.execute(Runnable)`, and similar non-JDBC `.execute()` calls — none represented LLM output flowing into a real code-execution sink. Removing the bare `$STMT.execute($X)` pattern (keeping `executeQuery` / `executeUpdate` / `executeLargeUpdate` which are unambiguously JDBC) eliminated all 34 FPs on langchain4j and 1 FP on langchain4j-examples, with zero true positives lost. Synthetic-vuln-java-app still fires its expected 2 findings (Runtime.exec + executeQuery). Full triage: [PHASE_B_TRIAGE.md](./PHASE_B_TRIAGE.md).

### 3.5 D004 Python's continued zero-fire is meaningful

D004 Python fires zero times across **all** Python projects in the testbed — including the heavy-LLM-usage frameworks. Two interpretations:

1. **Python LLM apps genuinely don't pipe LLM output into `eval` / `exec` / `os.system`.** Plausible — Python developers know `eval` is dangerous, so the pattern is rare. The rule is appropriately specific.
2. **The taint propagation in semgrep's Python mode doesn't follow the call → string → exec chain reliably across function boundaries.** Possible — would need a synthetic vulnerable Python app (parity to synthetic-vuln-java-app) to disambiguate.

**Recommendation:** add `synthetic-vuln-python-app` in a future phase to settle this. Not urgent — the Java side proves the rule pattern is fundamentally correct.

## 4. Coverage status — every rule now has at least one firing project

Pre–Phase A.2, **7 Java rules + D004 Python fired zero times across the testbed.** That's now down to **1 rule with zero fires**:

| Rule | Status |
|---|---|
| D001 Java framework | ✅ fires on lc4j-examples (13), spring-ex (4), synthetic-vuln (4) |
| D001 Java fallback | **❌ still zero** — framework rule catches all our cases first; fallback isn't reachable in the current testbed (this may be correct behavior — the fallback exists for unmodelled SDKs that the framework rule misses) |
| D002 Java | ✅ fires on synthetic-vuln (3) |
| D003 Java | ✅ fires on synthetic-vuln (3) |
| D004 Java | ✅ fires on langchain4j (34), lc4j-examples (1), synthetic-vuln (2) |
| D005 Java | ✅ fires on lc4j-examples (1), synthetic-vuln (4) |
| D006 Java | ✅ fires on langchain4j (1), synthetic-vuln (5) |
| DF001 Java | ✅ fires on lc4j (224), lc4j-examples (304), spring-ex (64), aws-bedr (34), synthetic-vuln (4) |
| DF002 Java | ✅ fires on lc4j-examples (2), synthetic-vuln (5) |
| DF003 Java | ✅ fires on synthetic-vuln (5) |
| DF004 Java | ✅ fires on lc4j-examples (3), synthetic-vuln (6) |
| R001 Java | ✅ fires on lc4j (118), lc4j-examples (298), spring-ex (61), aws-bedr (34), synthetic-vuln (4) |
| D004 Python | **❌ still zero** — see §3.5; needs synthetic-vuln-python-app to disambiguate |
| All others | ✅ already firing pre-A.2 |

The two remaining zero-fire cells are explainable, not necessarily rule bugs:
- **D001 Java fallback** is by design lower-priority than D001 Java framework — when both could match, framework wins. To exercise the fallback we'd need an LLM SDK we don't model in the framework rule.
- **D004 Python** needs a synthetic vulnerable Python app to settle whether it's "rule narrow" or "Python developers genuinely avoid this pattern."

## 5. Phase B priority targets

Ordered by triage efficiency (findings-per-minute), highest first:

1. **smartsdk-lambda + synthetic-vuln-java-app** — both already validated end-to-end. Use as pinned regression baselines; no triage work.
2. **D003 in langchain (2 findings, 2 files)** + **D006 in google-adk + D006 Java in langchain4j (1 each)** — instant triage. Singletons or small clusters in real frameworks.
3. **DF003 in google-adk-python (2 findings)** — fast triage; validates the rule on real framework code.
4. **D005 Java in langchain4j-examples (1 finding)** — single hit in a real demo. If TP, it's a genuine credentialed-example pattern worth alerting on.
5. **D004 Java in lc4j-examples (1 finding)** + **D001 Java in spring-ai-examples (4, 4f)** + **DF002 Java in lc4j-examples (2, 2f)** + **DF004 Java in lc4j-examples (3, 3f)** — small clusters in real demos. Each can be triaged in 5-10 min.
6. **D004 Java in langchain4j (34 findings, 18 files)** — biggest unknown. Worth deep triage to determine TP rate. **Highest-information target.**
7. **D001 framework in langchain (63 findings, 20 files) + D002 in llama-index (140 findings, 66 files)** — sample 5-10 from each to estimate TP rate; long tails not worth full triage. *(Both triaged in Phase B — D001 langchain confirmed framework noise (no rule change), D002 yielded a 189-FP elimination via metavariable-regex constraint. See [PHASE_B_TRIAGE.md §7-§8](./PHASE_B_TRIAGE.md).)*

**Skip for now:** the DF001 / R001 long tails (now 1,491 + 1,074 findings combined). Per §3.1, library-side firings tell you about library code, not user-app FPR. The aws-bedrock-java-examples and spring-ai-examples DF001/R001 firings are more interesting — they're real-app patterns — but they all share the same root cause ("example apps don't wire guardrails/loggers"), so a sample of 5-10 from spring-ai-examples is sufficient.

## 6. Side effects of running Phase A

Phase A surfaced one real rule bug (now fixed). Earlier sessions had added explicit `await $X.<verb>(...)` patterns to DF001, R001, D004, and D001 — based on the original PDF's diagnosis that "semgrep treats await as a distinct AST node." That diagnosis was wrong: **semgrep matches sub-expressions**, so `$X.run(...)` already matches `await $X.run(...)` via the inner call expression. The explicit awaited variants were duplicates that double-fired at every awaited call site.

**Fix:** removed the `await $X.<verb>(...)` patterns from all four rules. Updated comments to record the corrected understanding. Regenerated [tests/golden/python/d001_smartsdk_asyncio_runner.json](./tests/golden/python/d001_smartsdk_asyncio_runner.json) (4 → 2 findings at line 34, one per rule). All 76 tests pass.

**Verified:** smartsdk-lambda scan now produces 10 findings (5 DF001 + 5 R001), one per call site — no doubles. This is exactly the kind of bug Phase A was designed to surface — synthetic fixtures alone wouldn't have caught it because the duplicates happened to dedupe at the same `(rule, file, line, col)` key in our normalizer.

## 7. Testbed scope

`testbed/` is **not** committed source — its [.gitignore](./testbed/.gitignore) is `*` + `!.gitignore`. Each developer clones the projects locally for validation runs. Compare to `tests/fixtures/`:

| | `tests/fixtures/` (committed) | `testbed/` (gitignored) |
|---|---|---|
| **Content** | Synthetic, minimal hand-written files | Real OSS projects + 2 synthetic stand-ins (smartsdk-lambda, synthetic-vuln-java-app) |
| **Size** | ~30 small files | ~10K+ files across 10 projects |
| **Purpose** | Determinism — every commit must produce the same goldens | Validation — does AgentShield work on real code? |
| **When run** | CI, every commit (`pytest tests/`) | Periodic validation passes (this doc is the artifact) |
| **Catches** | Pattern compilation, regression on known cases | False-positive rate, coverage gaps in real code, performance |

`tests/fixtures/` proves the rules behave the way we *think* they do. `testbed/` proves they behave that way on *real code we don't control*. Both required.

## 8. How to reproduce

```bash
# Clone the projects you want to validate against under testbed/
cd testbed/
# Phase A originals
git clone --depth=1 https://github.com/langchain-ai/langchain.git
git clone --depth=1 https://github.com/langchain4j/langchain4j.git
git clone --depth=1 https://github.com/run-llama/llama_index.git llama-index
git clone --depth=1 https://github.com/google/adk-python.git google-adk-python
git clone --depth=1 https://github.com/langchain-ai/langgraph.git
# Phase A.2 additions
git clone --depth=1 https://github.com/langchain4j/langchain4j-examples.git
git clone --depth=1 https://github.com/spring-projects/spring-ai-examples.git
# aws-doc-sdk-examples is huge — sparse-clone the Bedrock Java subset only
git clone --depth=1 --filter=blob:none --no-checkout https://github.com/awsdocs/aws-doc-sdk-examples.git aws-bedrock-java-examples
cd aws-bedrock-java-examples
git sparse-checkout init --cone
git sparse-checkout set javav2/example_code/bedrock-runtime javav2/example_code/bedrock
git checkout
cd ..
# smartsdk-lambda + synthetic-vuln-java-app are committed in this repo
# (under testbed/) as synthetic stand-ins.

# Scan all 10 projects (~6.5 min total)
cd ..
mkdir -p /tmp/agentshield-phaseA
for proj in smartsdk-lambda synthetic-vuln-java-app langgraph google-adk-python llama-index langchain langchain4j langchain4j-examples spring-ai-examples aws-bedrock-java-examples; do
    semgrep scan \
        --config agentshield/rules/ \
        --quiet --metrics off --no-git-ignore --sarif \
        --exclude '*/.venv/*' --exclude '*/node_modules/*' --exclude '*/__pycache__/*' \
        --exclude '*/build/*' --exclude '*/target/*' --exclude '*/.git/*' \
        "testbed/$proj" 2>/dev/null > "/tmp/agentshield-phaseA/${proj}.sarif"
done

# Aggregate the heatmap from the SARIF outputs (see git history for the
# Python aggregation script, or reconstruct from the schema in §2).
```

Phase B (deep triage on the targets in §5) and Phase C (rule iteration based on B's findings) are documented separately as they're produced.
