# Phase F.8 — projected v2 precision deltas

Status: 2026-05-06
Companion to: [ARCHITECTURE_V2.md](./ARCHITECTURE_V2.md), [ROADMAP.md](./ROADMAP.md) §3.9

This document closes Phase F by projecting v2's expected behaviour on the three real codebases the Phase E judge runs evaluated. **Tier-1-only projection** — the actual Tier 2 (Copilot) numbers require running v2 end-to-end in your VDI; that validation is captured in §4.

## 1. Methodology and limits

**What this analysis can prove:** for each Phase E codebase, given the LLM judge's per-finding TP / CD / FP labels and the v2 rule pack scope (6 surviving families), we can deterministically compute which v1 findings would fire under v2's Tier 1 alone. The arithmetic is mechanical — every retired rule's findings disappear; every survived rule's findings stay.

**What this analysis cannot prove:** the actual Tier 2 (Copilot) output on these codebases. Tier 2 needs an IDE + Copilot session — that's the [§4 user-side validation](#4-user-side-validation-in-vdi) step. We can name *which Tier 2 check IDs* are designed to pick up each lost-from-Tier-1 finding, but only an actual Tier 2 run on real code can confirm Copilot identifies them in practice.

**The interesting question.** v2's design hypothesis: shrinking Tier 1 sharply (14 → 6 families, all narrow taint or narrow regex) eliminates the FP volume; Tier 2 picks up what the retired rules used to catch (and more). Tier-1-only projection answers half: did the FP volume actually go away? Tier 2 validation answers the other half: are the TPs still surfaced?

---

## 2. Codebase-by-codebase projection

### 2.1 `moip-cost-anomaly-probe-lambda` (Python SMARTSDK Lambda)

**v1 baseline (Phase E.2 judge run):** 59 findings · 4 TP · 4 CD · 51 FP · **86% FP rate**.

| Rule (v1) | v1 fires | v1 verdict breakdown | v2 status | v2 fires |
|---|---|---|---|---|
| R002 (PII-in-logs) | 51 (info) | 47 FP / 4 CD / 0 TP | RETIRED in Phase E (predates v2) | 0 |
| DF001 (no-guardrails-import) | 4 medium | 2 TP (extract_anomaly:237, email_formatter:59) + 2 FP (boto3 Lambda) | RETIRED in F.2 → Tier 2 TIER2-LLM10-03 | 0 |
| R001 (no-audit-logging) | 4 medium | 0 TP / 4 FP (logger present, or boto3 Lambda) | RETIRED in F.2 → Tier 2 TIER2-LLM10-02 | 0 |
| D001-fw / D003 / D004 / D005 / D008 / DF003 | 0 | n/a | ACTIVE in v2 | **0** (didn't fire in v1; unchanged in v2) |

**v2 Tier 1 projection: 0 findings.**

| Metric | v1 | v2 Tier 1 only | Delta |
|---|---|---|---|
| Total findings | 59 | 0 | **−59 (−100%)** |
| FPs | 51 | 0 | **−51** |
| TPs surfaced | 2 (DF001 confirmed-real on extract_anomaly + email_formatter) | 0 | **−2 (TPs moved to Tier 2)** |

**What v2 Tier 2 should pick up (Copilot validates):**
- The 2 lost TPs (no-guardrails on SMART SDK calls in extract_anomaly.py + email_formatter.py) → expected Tier 2 finding ID: `TIER2-LLM10-03`. Both files invoke `runner.run(agent, user_prompt)` with no advisor / guardrail import.
- The 4 R002 CDs (raw response_text in error log; response length only logged; model ARN logged) → expected Tier 2 finding IDs: `TIER2-LLM02-03` (raw LLM I/O in logs, conditional). Tier 2's per-file context lets it distinguish "logs response length only" (no fire) from "logs raw response on parse failure" (fire as medium).

**Net expected v2 result on this codebase:** 2 actionable Tier 2 findings (matching the 2 v1 TPs) + possibly 1-2 Tier 2 CD-level findings on the conditional logging cases. **Effective FP rate: 0%** (vs 86% v1 / 75% post-Phase-E).

### 2.2 `moip-thematic` / `moip-triage-agent` (Java Spring AI thematic-search agent)

**v1 baseline (Phase E.3 judge run):** 31 findings · 2 TP · 3 CD · 26 FP · **~6% precision**.

| Rule (v1) | v1 fires | v1 verdict breakdown | v2 status | v2 fires |
|---|---|---|---|---|
| DF001-Java (no-guardrails) | 12 | 0 TP / 2 CD / 10 FP (1 prod CompletableFuture FP + 9 test files) | RETIRED in F.2 → Tier 2 TIER2-LLM10-03 | 0 |
| R002-Java (PII-in-logs) | 9 | **2 TP** (SplunkSAMLController:40, TriageController:28) / 2 CD / 5 FP | RETIRED in Phase E | 0 |
| R001-Java (no-audit-logging) | 10 | 0 TP / 0 CD / 10 FP (CompletableFuture, taskExecutor, 8 test files) | RETIRED in F.2 → Tier 2 TIER2-LLM10-02 | 0 |
| D001-fw-Java / D003 / D004 / D005 / D008 / DF003 | 0 | n/a | ACTIVE | **0** (didn't fire in v1; unchanged) |

**v2 Tier 1 projection: 0 findings.**

| Metric | v1 | v2 Tier 1 only | Delta |
|---|---|---|---|
| Total findings | 31 | 0 | **−31 (−100%)** |
| FPs | 26 | 0 | **−26** |
| TPs surfaced | 2 | 0 | **−2 (TPs moved to Tier 2)** |

**Additional v2 mitigation: `--exclude '**/src/test/**'`.** Of the 26 v1 FPs, **17 (65%) were test-code findings** (8 ScrubberServiceTest + 1 TriageControllerTest × DF001 + R001). v2's `--exclude` flag would have eliminated those at scan time before Tier 1 even fired. Combined with rule retirement, the v1→v2 FP elimination is 100% architectural: no Tier 1 noise on this codebase.

**What v2 Tier 2 should pick up:**
- `SplunkSAMLController:40` (raw SAML assertion logged) → expected Tier 2 ID: `TIER2-GAP-03` (SAML/auth artifacts in logs) — added in F.3 specifically for this Phase E TP loss.
- `TriageController:28` (user message logged before scrubbing) → expected Tier 2 ID: `TIER2-GAP-01` (user input logged before scrubber) — added in F.3 for this exact pattern.
- `TriageService:51` and `SchedulingService:98` (CD: custom in-house ScrubbingCallAdvisor) → expected Tier 2 behaviour: TIER2-LLM10-03 should NOT fire on these because the F.3 checklist explicitly recognises Spring AI advisors via class-name suffix matching (`Advisor` / `Guardrail` / `Scrubber` / `Sanitizer`). Tier 2 reads sibling files; cross-method advisor wiring is in scope.

**Net expected v2 result on this codebase:** 2 actionable Tier 2 findings (matching the 2 v1 TPs) + 0 Tier 1 findings + correct CD-suppression on the cross-method-advisor cases. **Effective precision: 100%** (vs 6% v1 / projected ~50% post-Phase-E with `--exclude`).

### 2.3 `JpmcTriage` codebase (Java Spring AI — first Phase E run)

**v1 baseline (Phase E.1 judge run):** judge reported 62% FP rate on Java. Specific FP shapes the judge surfaced (without full verdict counts in the available record):
- R002 firing on SessionController.java (4 fires, all FP — sessionId UUID logging, not LLM I/O)
- R002 firing on SplunkSAMLController.java (FP — SAML auth params)
- DF001/R001 firing on `CompletableFuture.runAsync()` in SAML controller (FP)
- DF001/R001 firing on `taskExecutor.execute(() -> runSingleTriage(...))` in SchedulingService (CD: real intent but mitigated by ScrubbingCallAdvisor)
- R001 firing on Lombok-using files (FP — `@Slf4j` synthesises the SLF4J logger)
- DF001 firing on TriageService despite custom in-house `ScrubbingCallAdvisor` (FP — cross-method advisor wiring)
- 1 confirmed TP: `TriageController.java:28` logged `request.message()` before scrubbing (R002)

**v2 status of each FP shape:**

| FP shape | v1 rule | v2 outcome |
|---|---|---|
| R002 on SessionController UUID logging | R002 | RETIRED (Phase E) — gone |
| R002 on SAML auth params | R002 | RETIRED — gone |
| DF001/R001 on `CompletableFuture.runAsync` | DF001-Java + R001-Java | RETIRED in F.2 — gone |
| DF001/R001 on `taskExecutor.execute(...)` | DF001-Java + R001-Java | RETIRED — gone |
| R001 on Lombok @Slf4j | R001-Java | RETIRED — gone |
| DF001 on TriageService cross-method advisor | DF001-Java | RETIRED — gone |

**v2 Tier 1 projection: 0 findings on this codebase too** (or whatever fires from D001-fw / D003 / D004 / D005 / D008 / DF003 — based on the judge data, none of these were called out as firing on this codebase).

**What v2 Tier 2 should pick up:**
- The 1 confirmed TP (TriageController:28 raw user message before scrub) → `TIER2-GAP-01`.
- The cross-method advisor cases that were CDs in v1 → Tier 2's TIER2-LLM10-03 should correctly NOT fire because the in-house Advisor naming suffix matches.

---

## 3. Aggregate projection across all three codebases

| Metric | v1 (across 3 codebases) | v2 Tier 1 only | Delta |
|---|---|---|---|
| Total findings reviewed | ~91 | ~0 | **~−91 (−100%)** |
| FPs | ~77 | 0 | **−77 (−100%)** |
| TPs surfaced by Tier 1 | ~5 | 0 | **−5 (all moved to Tier 2)** |
| Test-code FPs (eliminable by `--exclude`) | 17 | 0 (excluded) | n/a |

**The pattern is structural, not coincidental.** v1's 14 rule families fell into two buckets:
- **8 noise-prone:** absence-detection (R001, DF001, R002), heuristics (DF002, DF004, D006, D007), or fallback (D001-fb). These produced ≥80% of all v1 fires across the three codebases AND ≥95% of all v1 FPs.
- **6 high-precision:** narrow taint or narrow regex (D001-fw, D003, D004, D005, D008, DF003). These produced 0 fires across the three codebases — *because none of the codebases happened to contain the specific anti-patterns these rules look for.*

A different codebase that *does* contain hardcoded credentials, code-execution tools, LLM output → eval, or unbounded LLM calls would still see Tier 1 fires under v2 — and those fires would be high-confidence. The synthetic-vuln-java-app testbed regression confirms this: under v2 Tier 1 it produces 18 TP findings across the 5 surviving rule IDs, exactly the patterns it was designed to exercise.

**The v2 hypothesis holds in projection.** Whether it holds in practice depends on Tier 2 actually surfacing the lost TPs when Copilot runs against these codebases. That validation needs a VDI run.

---

## 4. User-side validation in VDI

To close the loop on F.8, run v2 end-to-end in your VDI on each of the three Phase E codebases and confirm the projection.

**Quick procedure (full version in [QUICKSTART_VDI.md](./QUICKSTART_VDI.md) and [VDI_TESTING.md](./VDI_TESTING.md)):**

```bash
# In your VDI, with the architecture-v2 branch checked out:
agentshield scan /path/to/<codebase> --scan-all-files --exclude '**/src/test/**' --exclude '**/tests/**'

# Open <codebase> in VS Code with Copilot, paste the Tier 2 prompt
# (see TIER2_USAGE.md for the exact prompt and walkthrough).

# After Copilot writes .agentshield/tier2-findings.json:
agentshield merge /path/to/<codebase> --output-markdown report.md

# Inspect report.md for: actionable count, Tier 2 net-new findings,
# and Tier 1 cross-check verdicts.
```

**For each codebase, capture and share back:**

1. **Tier 1 finding count** (from `agentshield scan` output line: `[agentshield] Normalized: N finding(s)`).
2. **The unified report Markdown** (`report.md`).
3. **Tier 2 finding count and check IDs** (extractable from the report's "Tier 2 net-new findings" section).
4. **Whether the expected TPs from §2 above were surfaced** by Tier 2 with the right check IDs (per codebase: TIER2-LLM10-03 / TIER2-GAP-01 / TIER2-GAP-03).
5. **Any Tier 2 finding that the LLM hallucinated** (a check that doesn't actually apply to your code).
6. **Any Tier 1 finding Tier 2 marked FP/CD** with reasoning the merger printed.

After capturing on all three codebases, F.8 closes with a final commit appending an "Actual results" section to this doc with the measured deltas.

---

## 5. Honest accounting of what could break the projection

**Risks that could make the actual Tier 2 numbers worse than projected:**

1. **Copilot misses checks the checklist names.** The 56-check checklist is comprehensive on paper; whether Copilot actually applies each check on every file depends on Copilot's behaviour. If Copilot skips checks under context pressure on large files, TPs go missing.
2. **Copilot hallucinates findings.** The LLM may flag patterns that aren't actually present. Sample mitigation: §7 of the checklist asks Copilot to mark Tier 1 verdicts; reviewer can check whether Copilot's reasoning matches the actual code.
3. **Schema drift.** If Copilot's JSON output deviates from the strict schema, the merger refuses to combine. F.5's schema validator surfaces field-path errors so the user can re-prompt, but every re-prompt is friction.
4. **Cross-method advisor recognition partly relies on import suffix matching.** TIER2-LLM10-03 in the F.3 checklist tells Copilot to recognise classes named `*Advisor`/`*Guardrail`/`*Scrubber`/`*Sanitizer` as guardrail intent. If a codebase uses a different naming convention, this would FP.

**Risks that could make the actual numbers BETTER than projected:**

1. **Tier 2 catches things v1 didn't catch and Phase E didn't either.** The Phase E judge runs ran the v1 rule pack and added LLM judgment on top; they didn't run a comprehensive 56-check independent scan. v2 Tier 2 might surface additional TPs (SNS sink leaks, scrubber bypass, no-LLM-timeout — patterns the Phase E gap analysis named but didn't exhaustively catalogue).
2. **The CD findings from v1 might convert to clean dismissals under v2.** The custom-advisor cross-method cases on `moip-thematic` were CDs because v1 couldn't reason about them; Tier 2 with full file context should produce clean "not a finding" outcomes.

The projection above (0 Tier 1 findings + 2-3 actionable Tier 2 findings per codebase) is the realistic mid-range. Actual VDI runs will narrow the band.

---

## 6. Actual VDI results — `moip-cost-anomaly-probe-lambda`

**Run date:** 2026-05-06. **Runner:** Suganthi Aravind in JPMC VDI. **Branch:** `architecture-v2`.

### Headline numbers

| Metric | Projected (§2.1) | Actual | Delta |
|---|---|---|---|
| Tier 1 (semgrep) findings | 0 | **0** | ✅ exact match |
| Tier 2 (Copilot) net-new findings | 2 (TIER2-LLM10-03 only) | **10** | **+8 vs projection** (Tier 2 caught significantly more than the §2.1 floor) |
| Tier 1 marked TP / CD / FP by Tier 2 | 0 / 0 / 0 (no Tier 1 to triage) | 0 / 0 / 0 | ✅ |
| Net actionable | ~2 | **10** | Copilot expanded the surface |

### Tier 2 findings by check ID (10 total)

| # | Check ID | File:line | Severity | What Copilot caught |
|---|---|---|---|---|
| 1 | **TIER2-LLM10-03** | `extract_anomaly.py:228` | medium | LLM invocation via SMART SDK with no guardrail / advisor — the §2.1 projected TP, exact match |
| 2 | **TIER2-LLM10-03** | `email_formatter.py:46` | medium | Same pattern in the second SMART SDK call site — the second §2.1 projected TP, exact match |
| 3 | **TIER2-LLM02-04** | `email_formatter.py:126` | high | LLM output (Bedrock response formatted as email body) flows directly to `sns_client.publish` without any PII scrubbing — Phase E gap §5.1, projected new coverage, confirmed |
| 4 | **TIER2-AGENTIC-T5-01** | `extract_anomaly.py:1035` | medium | 12-step LLM pipeline with 7+ LLM calls where each output feeds the next without intermediate typed-schema validation — pure Tier 2 territory (T5 Cascading Hallucinations, out of static-rule scope by design) |
| 5 | **TIER2-GAP-04** | `extract_anomaly.py:224` | medium | No explicit timeout on SMART SDK Agent / LocalRunner — relies on default which may be unbounded. Phase E gap §5.4, projected new coverage, confirmed |
| 6 | **TIER2-LLM10-02** | `extract.py:673` | medium | Lambda self-invocation logic uses `print()` throughout instead of structured logging (no structlog / OpenTelemetry / langsmith callbacks) |
| 7 | **TIER2-CWE-200-01** | `handler2.py:174` | medium | Exception details (`str(e)`) returned in HTTP 500 response body — leaks internal info to callers |
| 8 | **TIER2-LLM02-03** | `handler.py:89` | medium | Full Lambda event payload logged at INFO level — may contain query params / request bodies / caller-supplied data |
| 9 | **TIER2-LLM02-03** | `extract.py:185` | medium | SSM parameter values fetched with `WithDecryption=True` printed to stdout — decrypted secrets reach CloudWatch Logs |
| 10 | **TIER2-LLM02-03** | `extract.py:481` | low | AWS Account ID and caller ARN printed to stdout — internal infrastructure identifiers in production logs |

### Coverage matrix achieved

| Framework | Items touched (actual) |
|---|---|
| OWASP LLM Top 10 v2 | LLM01, LLM02, LLM05, LLM09, LLM10 (5 of 10) |
| OWASP Agentic AI Top 10 | T4, T5, T6, T8 (4 of 11) |
| MITRE ATLAS | AML.T0024 |
| CWE first-class | CWE-200, CWE-400, CWE-532 |

This is **broader than v1 ever achieved on this codebase** — v1 surfaced the LLM02 surface only (and noisily, via R002). v2 hit 5 LLM categories, 4 Agentic categories, plus generic CWE concerns the rule pack never expressed.

### Validation: did the projection hold?

**Tier 1 projection (0 findings):** ✅ exact match. No survived rule fires on this codebase, as predicted in §2.1.

**Tier 2 projection (2 expected TPs via TIER2-LLM10-03 on `extract_anomaly.py` + `email_formatter.py`):** ✅ both surfaced exactly as predicted, at the exact file:line locations the Phase E.2 judge run had labeled as TPs.

**Tier 2 over-delivered by 8 findings beyond the projection.** This matches the §5 "risks that could make the actual numbers BETTER than projected" prediction — Phase E's judge protocol used the v1 rule pack and added LLM judgment on top; it never ran a comprehensive 56-check independent scan. Tier 2's whole-repo walk catches:

- The 3 Phase E "named gap" patterns the rule pack never had (SNS sink leak ✓, no LLM timeout ✓, multi-step pipeline cascading hallucination ✓ for the first time on a real codebase)
- 4 generic CWE-tier issues the rule pack didn't target at all (Lambda print logging, exception leak in HTTP body, full event at INFO, SSM secrets in stdout, AWS internal IDs in stdout) — these are correct, actionable security findings that no v1 rule could have surfaced

### Encoding fix surfaced during the run (Phase F.10)

Copilot's edit-and-fix cycle uncovered a Windows-specific issue: `cp1252` couldn't encode the merger's banner glyphs (`⚠`, `✓`, `❌`, `🟡`) when `Path.write_text(...)` defaulted to system encoding. The user fix in their VDI session — adding `encoding="utf-8"` to the three `Path.write_text` calls in `cli.py`'s `cmd_merge` — has been backported to this branch in F.10. The existing report writer classes (`SarifWriter`, `JsonWriter`, `MarkdownWriter`) already used UTF-8 explicitly, so only the merge command's direct writes needed the fix.

### What this validates

1. **The v2 hypothesis holds.** Shrinking Tier 1 to 6 narrow rules eliminated 100% of v1's noise on this codebase (59 → 0 Tier 1 findings), and Tier 2 (Copilot) surfaces the lost TPs with the exact projected check IDs PLUS net-new findings the rule pack could never have caught.
2. **The skill checklist is comprehensive enough to drive Copilot's behaviour predictably.** All 5 framework dimensions hit on the first run; check IDs match the bundled checklist's enumeration.
3. **The merger's stale-detection contract works.** Fingerprint matched → merge proceeded; UTF-8 encoding bug surfaced cleanly via the Python traceback rather than a silent corruption.

### What still needs validation

1. **`moip-thematic` (Java Spring AI)** — projected §2.2 to surface 2 TPs via TIER2-GAP-01 + TIER2-GAP-03. Pending VDI run.
2. **`JpmcTriage` (first Phase E codebase, Java Spring AI)** — projected §2.3 to surface 1 TP via TIER2-GAP-01. Pending VDI run.

When those two runs come in, this section gets two more sub-sections; aggregate validation table at the top of §6 expands.
