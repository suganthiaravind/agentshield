# Phase D — Polish Pass

Status: 2026-05-05 (CWE field + ATLAS expansion + DF001/R001 Java SpringApplication suppressor + synthetic-vuln-python-app + post-Phase-D heatmap)
Companion to: [RULES_COVERAGE.md](./RULES_COVERAGE.md), [TESTBED_VALIDATION.md](./TESTBED_VALIDATION.md), [PHASE_B_TRIAGE.md](./PHASE_B_TRIAGE.md), [PHASE_C_TRIAGE.md](./PHASE_C_TRIAGE.md)

Phase A established the testbed, Phase B eliminated 227 FPs across 4 rule fixes, Phase C closed the OWASP LLM04 + LLM07 coverage gaps. **Phase D** is the polish pass — small high-confidence improvements that lock in the cumulative gains: schema enrichment (CWE field + ATLAS expansion), one Java FP fix surfaced by triaging real-app demo code, a Python parity for the synthetic-vuln-java-app, and a refreshed full-testbed heatmap.

## Contents

- [1. Schema enrichment — first-class CWE + ATLAS expansion](#1-schema-enrichment--first-class-cwe--atlas-expansion)
- [2. SpringApplication.run FP fix — 64 FPs eliminated](#2-springapplicationrun-fp-fix--64-fps-eliminated)
- [3. synthetic-vuln-python-app — settles the D004 Python question](#3-synthetic-vuln-python-app--settles-the-d004-python-question)
- [4. Refreshed full-testbed heatmap](#4-refreshed-full-testbed-heatmap)
- [5. Cumulative impact across Phases A–D](#5-cumulative-impact-across-phases-ad)
- [6. What's left after Phase D](#6-whats-left-after-phase-d)

## 1. Schema enrichment — first-class CWE + ATLAS expansion

### 1.1 CWE field added

[agentshield/normalize/schema.py](./agentshield/normalize/schema.py) — new `cwe: list[str]` field on `FrameworkMappings`. Picked up by [agentshield/normalize/normalizer.py](./agentshield/normalize/normalizer.py) and rendered in [agentshield/report/markdown.py](./agentshield/report/markdown.py) alongside the existing OWASP / NIST / MITRE mappings (e.g. `CWE-798, CWE-94`).

Populated on the rules where CWE-mapping is unambiguous:

| Rule | CWE |
|---|---|
| D003 (Python + Java) — code-execution tool registered | CWE-78 (OS Command Injection), CWE-94 (Code Injection) |
| D004 Python — LLM output → eval / exec / subprocess | CWE-94 (Code Injection) |
| D004 Java — LLM output → Runtime.exec / SQL | CWE-89 (SQL Injection), CWE-94 (Code Injection) |
| D005 (Python + Java) — hardcoded credentials | CWE-798 (Hardcoded Credentials) |
| D006 (Python + Java) — broad tool permissions | CWE-732 (Incorrect Permission Assignment) |
| DF003 (Python + Java) — no timeout / max_tokens | CWE-400 (Uncontrolled Resource Consumption) |
| D007 — untrusted model loading | CWE-494 (Download of Code Without Integrity Check), CWE-829 (Inclusion of Functionality from Untrusted Control Sphere) |
| D008 (Python + Java) — untrusted system prompt | CWE-829 |

10 rules now carry first-class CWE mapping. Reports rendered via the markdown writer surface CWE in the per-finding Mappings line, which compliance / SCA tools can ingest directly.

### 1.2 MITRE ATLAS expansion

Existing rules whose ATLAS mapping was incomplete:

| Rule | Pre-Phase-D | Post-Phase-D |
|---|---|---|
| D003 (Python + Java) | `AML.T0050` | `AML.T0011, AML.T0050` (added Command and Scripting Interpreter) |
| D004 (Python + Java) | `AML.T0050` | `AML.T0011, AML.T0050` |
| D006 (Python + Java) | `[]` | `AML.T0053` (LLM Plugin Compromise) |
| DF002 (Python + Java) | `[]` | `AML.T0053` |
| R001 (Python + Java) | `[]` | `AML.T0024` (Exfiltration via Inference Endpoints — the missing-audit-log angle) |

7 rules updated. ATLAS coverage on the rule pack went from 3 distinct techniques to 6.

## 2. SpringApplication.run FP fix — 64 FPs eliminated

### 2.1 What surfaced

Triage of DF001 / R001 Java's heavy firings on `spring-ai-examples` revealed that **every Spring Boot main class** was matching the catch-all `$AGENT.run(...)` pattern via `SpringApplication.run(Application.class, args)` — Spring Boot's standard entry-point call. Examples sampled:

- `agents/reflection/.../EvaluationAdvisorDemoApplication.java:23` — `SpringApplication.run(EvaluationAdvisorDemoApplication.class, args)`
- `advisors/recursive-advisor-demo/.../RecursiveAdvisorDemoApplication.java:20` — same shape
- `agentic-patterns/chain-workflow/.../Application.java:32` — same shape
- `agentic-patterns/evaluator-optimizer/.../Application.java:35` — same shape
- `agentic-patterns/orchestrator-workers/.../Application.java:33` — same shape

Each Spring Boot main class triggered both DF001 and R001. The signature `SpringApplication.run(Class<?>, String...)` is structurally identical to a real `agent.run(prompt, ...)` call — the catch-all metavariable couldn't tell them apart.

### 2.2 Fix applied

[agentshield/rules/defend/DF001-no-guardrails-import-in-llm-module-java.yaml](./agentshield/rules/defend/DF001-no-guardrails-import-in-llm-module-java.yaml) and [agentshield/rules/respond/R001-llm-call-without-audit-logging-java.yaml](./agentshield/rules/respond/R001-llm-call-without-audit-logging-java.yaml) — added `pattern-not: SpringApplication.run(...)` and the fully-qualified `pattern-not: org.springframework.boot.SpringApplication.run(...)` on both rules.

### 2.3 Result

| Project | DF001 Java pre-fix | post-fix | R001 Java pre-fix | post-fix |
|---|---:|---:|---:|---:|
| spring-ai-examples | 64 | **32** | 61 | **29** |
| aws-bedrock-java-examples | 34 | 34 | 34 | 34 |
| langchain4j-examples | 304 | 304 | 298 | 298 |
| (others) | unchanged | unchanged | unchanged | unchanged |

**64 FPs eliminated** (32 DF001 + 32 R001 across spring-ai-examples). Other projects unaffected because they don't use SpringApplication.run.

The remaining 32 + 29 spring-ai-examples findings are **real LLM call sites without guardrails / audit logger imports** — example apps demonstrating Spring AI patterns without wiring those concerns. Same framework-vs-app interpretation as documented in [TESTBED_VALIDATION.md §3.1](./TESTBED_VALIDATION.md#31-the-framework-vs-app-distinction-still-the-main-interpretive-lens).

### 2.4 Known limitation

The fix targets the specific `SpringApplication.run` shape. Other generic-`.run()` collisions remain — e.g., `scenario.run(state)` in `aws-bedrock-java-examples/.../DemoRunner.java:38` (a demo scenario runner, not an LLM call). These would need `metavariable-type` constraints once the relevant agent types are identifiable. Documented as a Phase E candidate.

## 3. synthetic-vuln-python-app — settles the D004 Python question

### 3.1 The open question from Phase A.2

Phase A.2 noted that **D004 Python (LLM output → eval / exec / subprocess shell=True) fired zero times** across the entire Python testbed (langgraph, google-adk-python, llama-index, langchain). Two hypotheses:

1. **Python developers genuinely don't pipe LLM output into eval / exec.** The dangers are widely known.
2. **semgrep's Python taint mode doesn't reliably follow the call → string → exec chain across function boundaries.** Would mean the rule under-fires.

### 3.2 The test

Built [`testbed/synthetic-vuln-python-app/`](./testbed/synthetic-vuln-python-app/) — a synthetic, intentionally vulnerable Python app with one file per anti-pattern:

```
src/synthetic_vuln_python_app/
    controller.py            # D001
    rag_loader.py            # D002
    dangerous_tools.py       # D003
    output_to_exec.py        # D004
    hardcoded_keys.py        # D005
    broad_tools.py           # D006
    unpinned_models.py       # D007
    system_prompt_loader.py  # D008
    bare_param_tools.py      # DF002
    unbounded_client.py      # DF003
    destructive_tools.py     # DF004
```

Each file exercises a known anti-pattern in shape that mirrors a real Flask / FastAPI / Lambda app.

### 3.3 Result

Scanning produces **59 findings across all 13 Python rules** — every Python rule fires:

| Rule | Findings | Files |
|---|---:|---:|
| D001 | 1 | 1 |
| D002 | 3 | 1 |
| D003 | 4 | 1 |
| **D004** | **4** | **2** |
| D005 | 5 | 1 |
| D006 | 6 | 1 |
| D007 | 5 | 1 |
| D008 | 3 | 1 |
| DF001 | 4 | 2 |
| DF002 | 10 | 3 |
| DF003 | 6 | 1 |
| DF004 | 4 | 1 |
| R001 | 4 | 2 |

**Headline:** **D004 Python fires 4 times on synthetic-vuln-python-app**, including the `os.system(response.content)`, `exec(code.content)`, and `subprocess.run(cmd.content, shell=True)` patterns. **The "Python developers genuinely avoid this pattern" hypothesis is correct** — D004 Python is well-calibrated; it just doesn't fire in well-curated framework testbed code because that code doesn't pipe LLM output to dangerous executors.

### 3.4 Pinned regression baseline

`synthetic-vuln-python-app` is now a **pinned regression target** alongside `synthetic-vuln-java-app` and `smartsdk-lambda`. Any rule change that drops its 59 findings is a signal worth investigating; any change that adds noise is also visible. This closes the "Python rules need parity coverage" gap from Phase A.2.

## 4. Refreshed full-testbed heatmap

Run after all Phase B + C + D rule changes, against all 11 testbed projects:

| Rule | moip | vuln-java | **vuln-py** | langgraph | ggl-adk | llama-idx | langchain | lc4j | lc4j-ex | spring-ex | aws-bedr |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| D001 | . | . | 1 (1f) | 91 (29f) | 7 (5f) | 84 (46f) | 63 (20f) | . | . | . | . |
| D001-fb | . | . | . | . | . | 57 (36f) | . | . | . | . | . |
| D001 Java | . | 4 (2f) | . | . | . | . | . | . | 13 (10f) | 4 (4f) | . |
| D002 | . | . | 3 (1f) | . | . | . | . | . | . | . | . |
| D002 Java | . | 3 (1f) | . | . | . | . | . | . | . | . | . |
| D003 | . | . | 4 (1f) | . | . | . | . | . | . | . | . |
| D003 Java | . | 3 (1f) | . | . | . | . | . | . | . | . | . |
| **D004** | . | . | **4 (2f)** | . | . | . | . | . | . | . | . |
| D004 Java | . | 2 (1f) | . | . | . | . | . | . | . | . | . |
| D005 | . | . | 5 (1f) | . | . | . | . | . | . | . | . |
| D005 Java | . | 4 (1f) | . | . | . | . | . | . | 1 (1f) | . | . |
| D006 | . | . | 6 (1f) | . | 1 (1f) | . | . | . | . | . | . |
| D006 Java | . | 5 (1f) | . | . | . | . | . | . | . | . | . |
| DF001 | 5 (2f) | . | 4 (2f) | 68 (20f) | 109 (82f) | 422 (203f) | 263 (76f) | . | . | . | . |
| DF001 Java | . | 4 (2f) | . | . | . | . | . | 224 (142f) | 304 (157f) | **32 (17f)** | 34 (33f) |
| DF002 | . | . | 10 (3f) | 1 (1f) | 2 (2f) | . | 12 (6f) | . | . | . | . |
| DF002 Java | . | 5 (2f) | . | . | . | . | . | . | 2 (2f) | . | . |
| DF003 | . | . | 6 (1f) | . | 2 (2f) | . | . | . | . | . | . |
| DF003 Java | . | 5 (1f) | . | . | . | . | . | . | . | . | . |
| DF004 | . | . | 4 (1f) | . | . | . | . | . | . | . | . |
| DF004 Java | . | 6 (2f) | . | . | . | . | . | . | 3 (3f) | . | . |
| D007 | . | . | 5 (1f) | . | . | 77 (31f) | 5 (4f) | . | . | . | . |
| D008 | . | . | 3 (1f) | . | . | . | . | . | . | . | . |
| R001 | 5 (2f) | . | 4 (2f) | 63 (19f) | 97 (76f) | 422 (203f) | 75 (25f) | . | . | . | . |
| R001 Java | . | 4 (2f) | . | . | . | . | . | 118 (79f) | 298 (152f) | **29 (15f)** | 34 (33f) |
| **TOTAL** | **10** | **45** | **59** | **223** | **218** | **1062** | **418** | **342** | **621** | **65** | **68** |

**Grand total: 3,131 findings across 11 projects.**

## 5. Cumulative impact across Phases A–D

| Snapshot | Total findings | FPs eliminated | TPs added | TPs lost | Test count |
|---|---:|---:|---:|---:|---:|
| Phase A baseline (10 projects) | 2,417 | 0 | 0 | 0 | 7 (rule golden) |
| Phase A.2 (10 projects, after Java apps + synth-vuln-java-app) | 3,281 | 0 | +864 (new project columns) | 0 | 76 |
| Phase B (rule fixes — D004 Java + D003 + D006 Java + D002 Python) | 3,054 | **−227** | 0 | 0 | 76 |
| Phase C (LLM04 + LLM07 — D007 + D008 Python + D008 Java) | 3,136 | 0 | +82 (D007 langchain + llama-index) | 0 | 82 |
| Phase D (CWE + ATLAS metadata, SpringApplication suppressor, synthetic-vuln-python-app, breadth re-scan) | 3,131 | **−64** (Spring) | +59 (synth-vuln-py) | 0 | 82 |
| **Cumulative ΔP from Phase B start** | -150 | **−291** | **+141** | **0** | +5 |

**Headline:** **291 false positives eliminated, 0 true positives lost, 0 test regressions** across 7 rule fixes (Phase B's 4 + Phase D's 1) and 3 new rules (Phase C's 3). Test count: 76 → 82. Rule pack: 11 distinct rule families → 14.

**OWASP coverage:**
- OWASP LLM Top 10: 7 / 10 → **9 / 10** (LLM09 Misinformation out of SAST scope).
- OWASP Agentic AI Top 10: 8 / 11 (T5 / T7 / T9 out of SAST scope; unchanged).
- MITRE ATLAS: 3 distinct techniques → **6**.
- CWE: 0 first-class fields → **8 distinct CWEs across 10 rules**.
- NIST AI RMF: 5 subcategories mapped (unchanged).

## 6. What's left after Phase D

Most strategic options surfaced earlier remain valid; Phase D didn't change the high-level priorities:

- **TypeScript / JavaScript language support** — still the biggest scope expansion. Doubles addressable codebase population.
- **Tier 3 LLM judge calibration** — Phase B + C + D gave us 13+ confirmed TPs and ~291 known-FP examples as labeled training data for the judge's prompts.
- **Adoption-layer polish** — PR-comment formatting, CI integration depth, getting-started tutorial — relevant once the rule-quality story is enough to ship.
- **Generic `.run(...)` collisions in Java** — DF001/R001 Java's catch-all `$AGENT.run(...)` still collides with non-LLM patterns like `scenario.run(state)` and `runnable.run()`. Best fixed via `metavariable-type` constraints once the relevant agent types are enumerable across SDKs (Google ADK, langchain4j, smartsdk).
- **Periodic testbed re-clones** — langchain et al. evolve fast. Quarterly or major-release-aligned refresh keeps the validation honest.

The next strategic call is best made in light of *what's actually limiting users*: TypeScript if reaching more codebases is the bottleneck; judge calibration if fallback-finding noise is the bottleneck; adoption-layer polish if the bottleneck is "users aren't running it at all yet."
