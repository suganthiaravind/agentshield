# AgentShield Architecture v2 — design doc (Phase F)

**Status:** Draft for review, 2026-05-05. No code changes yet.
**Branch:** `architecture-v2`. Predecessor: `phase-b-c-d-polish` (Phase E.3 shipped).
**Decision needed before implementation:** §3 rule-pruning list, §4 skill-file scope, §10 open questions.

---

## 1. Why this exists

Three real-world VDI judge runs (Phase E / E.2 / E.3) showed two structural truths:

1. **Rule-only architecture has a precision ceiling on real codebases.** Even after Phase E's surgical fixes, ≥4 rule families are absence-detection or heuristic-based and FP-prone (R001, DF001, DF002, DF004) — they will never reach >70% precision on production code without losing real signal.
2. **The LLM-as-triage model is in the wrong slot.** Tier 3 today triages cherry-picked low-confidence findings from the rule pack. It can't catch what the rules *missed* (the thematic-codebase run surfaced SNS data leak, scrubber bypass, no LLM timeout — none in the rule pack), and it can't downgrade FPs from the framework rules. The LLM is most useful when it scans the **whole repo against a comprehensive checklist** — which is exactly what the manual judge runs have been doing.

v2 flips the orchestrator's role: the rule pack becomes a small high-precision Tier 1, and the LLM becomes a comprehensive Tier 2 that scans the entire repo against a curated skill checklist.

## 2. What changes vs v1

| Concept | v1 (today) | v2 (proposed) |
|---|---|---|
| Tiers | 4 (Tier 1 framework rules / Tier 2 fallback rules / Tier 3 LLM judge / Tier 4 discovery) | 2 (Tier 1 semgrep / Tier 2 LLM-as-scanner) |
| Rule pack | 14 rule families | 6 high-precision families |
| LLM role | Triage low-confidence findings | Scan whole repo against comprehensive skill checklist |
| LLM execution | boto3-Bedrock (default) / SMARTSDK / Copilot / mock | Copilot via skill-file handoff (default); boto3 + mock retained as alternates |
| Mandatory tiers | None (each gated by flag) | Both Tier 1 and Tier 2 mandatory; soft-warn if Tier 2 skipped |
| Output formats | SARIF / JSON / Markdown | Same (no change) |
| AWS dependency | Required for default judge | None — Copilot uses the user's IDE license |

## 3. Tier 1 — pruned rule pack

### Survives (6 families)

All narrow-taint or narrow-regex. None are absence-based. None rely on heuristic name matching.

| Rule | Lang | Why it survives |
|---|---|---|
| **D001-fw** | Py + Java | Narrow taint; user input → LLM with explicit framework sinks. Genuinely high-precision after Phase B. |
| **D003** | Py + Java | Single-purpose: `@tool` wrapping `exec` / `Runtime.exec` / `ScriptEngine.eval`. Narrow + correct. |
| **D004** | Py + Java | Narrow taint: LLM output → exec sink. Tight source/sink list. |
| **D005** | Py + Java | Narrow regex: hardcoded credential strings in known SDK constructors. High signal. |
| **D008** | Py + Java | Narrow taint: untrusted network read → system prompt. Phase C addition; clean shape. |
| **DF003** | Py + Java | Narrow: explicit `timeout=None` / `Duration.ZERO`. Anti-pattern is unambiguous. |

### Retires into Tier 2 skill checklist (8 families)

These move from rule-pack enforcement to LLM-checked guidance. The rule files get archived to `agentshield/rules/_retired_v2/` (kept readable, not loaded by semgrep) so the patterns stay searchable as historical reference.

| Rule | Why it retires | Tier 2 replacement |
|---|---|---|
| **D001-fb** (fallback) | Intentionally low-confidence; designed to be triaged by Tier 3. With Tier 3 retired, fallback rules have no consumer. | Whole-repo scan covers the same surface contextually. |
| **D002** | Narrow but rarely TPs in OSS testbed (5 phases of validation: 0 TPs found). | Tier 2 checklist item: "look for document loaders fetching from untrusted URLs." |
| **D006** | Heuristic on tool-permission breadth — FP-prone on framework-internal tools. | Tier 2 checklist item: "look for `@Tool` methods wrapping destructive Files/HTTP ops." |
| **D007** | Version-string check on HuggingFace `from_pretrained` — false-confident; can't tell if the unpinned model is the application's or a vendored test fixture. | Tier 2 checklist item: "look for `from_pretrained(...)` without `revision=` pin." |
| **DF001** | Absence-detection (no guardrails import). Phase E required 5 rounds of fixes and still misses cross-method advisor wiring. | Tier 2 checklist item — the LLM can read the full file/repo context. |
| **DF002** | Heuristic on `@Tool` arg schema — FPs on framework tools. | Tier 2 checklist item. |
| **DF004** | Pure name-based heuristic ("delete*" / "send*" / "charge*" methods) — no taint, high FP. | Tier 2 checklist item: "look for destructive-verb tool methods without an approval gate." |
| **R001** | Absence-detection (no audit logging) — Phase E.2 had to relax it twice to handle Lombok @Slf4j and stdlib `logger = logging.getLogger(...)`. The judge runs showed it still FPs ~50% of the time. | Tier 2 checklist item: "look for LLM calls without surrounding structured audit logs." |

**Net:** Tier 1 goes from 14 → 6 rule families, all narrow-taint/regex. Estimated FP rate on real codebases: <15% (vs ~60% on rules being retired).

## 4. Tier 2 — LLM-as-scanner via Copilot skill files

### 4.1 Workflow

```
$ agentshield scan ./my-agent
[1/2] Tier 1 (semgrep) — 3 finding(s)
[2/2] Tier 2 (LLM-as-scanner) — emitting skill files...
      ✓ ./my-agent/.github/copilot-instructions.md
      ✓ ./my-agent/.agentshield/tier2-checklist.md
      ✓ ./my-agent/.agentshield/tier2-output-schema.md
      ✓ ./my-agent/.agentshield/tier1-results.json (Tier 1 output for context)

⚠ Tier 2 not yet executed. Scanning is INCOMPLETE.

NEXT STEP — run Copilot Chat in your IDE:
  1. Open ./my-agent in VS Code or JetBrains
  2. In Copilot Chat: @workspace /agentshield-tier2
  3. Wait for Copilot to write .agentshield/tier2-findings.json
  4. Run: agentshield merge ./my-agent --output-markdown report.md
```

### 4.2 File-by-file execution model

Copilot processes one source file at a time per the checklist. For each file it:
1. Reads the file content
2. Walks the checklist (Section §4.4) line by line, deciding apply / not-apply
3. For each apply, looks for the anti-pattern; if found, emits a finding
4. Writes incrementally to `.agentshield/tier2-findings.json`

This keeps each Copilot invocation in a small context window (one file ≈ 500-1000 LOC vs the whole repo) and lets it resume on failure.

### 4.3 Skill files (3 files, all Markdown)

#### `.github/copilot-instructions.md` (bootstrap)
Tells Copilot what `@workspace /agentshield-tier2` means. Short — points at the checklist + output schema.

#### `.agentshield/tier2-checklist.md` (the comprehensive checklist)
The heart of v2. Sections:

1. **OWASP LLM Top 10 v2** — LLM01 through LLM10, each with concrete patterns to look for in code
2. **OWASP Agentic AI Top 10** — T1 through T11, with code-level checks per threat
3. **MITRE ATLAS techniques** — relevant techniques (T0010, T0011, T0012, T0019, T0024, T0050, T0051, T0053)
4. **CWE first-class concerns** — CWE-78, 89, 94, 200, 400, 494, 532, 732, 798, 829
5. **Retired-rule anti-patterns** — covers everything Tier 1 dropped (R001 audit, DF001 guardrails, DF002 tool args, DF004 destructive verbs, D006 broad perms, D007 unpinned models, D002 doc loaders)
6. **Phase E judge findings** — surfaced gaps the rule pack never had:
   - SNS / email sink data leaks (LLM output → `SnsClient.publish` / JavaMail without scrubber)
   - Scrubber-bypass on oversized inputs (`if length > MAX: return original`)
   - No explicit LLM call timeout (Spring AI / Bedrock default-timeout reliance)
   - User input logged before scrubber (R002's lost TPs)
   - SAML / auth artifacts in logs (CWE-532)
7. **Tier 1 cross-check section** — reads `tier1-results.json` and asks Copilot to mark any Tier 1 finding it believes is FP, with reasoning

Estimated size: ~600-800 lines markdown. Comprehensive by design.

#### `.agentshield/tier2-output-schema.md`
The required JSON shape for `tier2-findings.json`:

```json
{
  "tier": 2,
  "scanned_at": "2026-05-05T22:14:00Z",
  "scanned_files": ["src/foo.py", "src/bar.java"],
  "findings": [
    {
      "rule_id": "TIER2-USER-INPUT-LOGGED-PRE-SCRUB",
      "category": "respond",
      "severity": "medium",
      "file": "src/controller/TriageController.java",
      "line": 28,
      "snippet": "log.info(\"Received chat request | message={}\", request.message())",
      "message": "Raw user message logged before any PII scrubbing.",
      "owasp_llm": ["LLM02", "LLM10"],
      "owasp_agentic": ["T8"],
      "cwe": ["CWE-532"],
      "remediation": "Move log call after scrubberService.scrubPii(...) or log only message length / hash."
    }
  ],
  "tier1_fp_callouts": [
    {
      "tier1_finding_index": 2,
      "file": "src/SchedulingService.java",
      "line": 98,
      "tier1_rule": "agentshield.defend.no-guardrails-import-in-llm-module-java",
      "verdict": "FP",
      "reasoning": "taskExecutor.execute delegates to triageService which uses ScrubbingCallAdvisor — guardrail exists across method boundaries."
    }
  ]
}
```

### 4.4 Comprehensive checklist coverage (target)

The checklist is the v2 product. It MUST cover:

| Framework | Items | Status today |
|---|---|---|
| OWASP LLM Top 10 v2 | 10 | 9 covered by rules; 1 (LLM09 Misinformation) noted as out-of-SAST-scope but Tier 2 can attempt |
| OWASP Agentic AI Top 10 | 11 | 8 covered today; T5 / T7 / T9 added to checklist for Tier 2 contextual review (Tier 2 can do what static rules can't) |
| MITRE ATLAS | 6 techniques | All 6 in checklist |
| CWE first-class | 10 | All 10 in checklist |
| Phase E judge gaps | 5 | All 5 in checklist (this is net-new vs v1 rules) |

**This is a hard requirement.** The user explicitly called it out: "skill file has to be comprehensive — LLM will be able to do a good validation against all key points from the security frameworks like OWASP Top 10 Agentic AI."

## 5. Combined report (the merger)

`agentshield merge <path>` reads:
- Tier 1 SARIF / JSON output (from previous `agentshield scan`)
- `<path>/.agentshield/tier2-findings.json` (from Copilot)

Produces:
- Unified Markdown / JSON / SARIF
- Section structure:
  1. **Summary** — Tier 1 count, Tier 2 count, Tier 2-marked-FP count, net actionable
  2. **Tier 1 findings** — same shape as today, with per-finding annotation if Tier 2 marked it FP ("⚠ Tier 2 verdict: FP — <reasoning>")
  3. **Tier 2 net-new findings** — things rules missed
  4. **Coverage report** — which OWASP / Agentic / CWE items the scan touched
- Stale-warning if `tier2-findings.json` was generated before the latest Tier 1 run (compare timestamps + file content hash)

## 6. CLI changes

### Added
```
agentshield scan <path>
  # Runs Tier 1 + emits Tier 2 skill files. Default behaviour.
  # Prints prominent "now run Copilot Chat" instructions.
  # Exits 0 even though scan is "incomplete" — Tier 2 is async by design.

agentshield scan <path> --tier1-only
  # Skip skill-file emission. Final report includes
  # "⚠ TIER 2 NOT RUN — scanning incomplete" banner.

agentshield merge <path>
  # New subcommand. Reads tier1 + tier2 outputs, writes unified report.
  # Same --output-{sarif,json,markdown} flags as scan.

agentshield scan <path> --emit-only
  # Emit skill files without re-running Tier 1. Useful for
  # iterating on the checklist on a previously-scanned repo.
```

### Removed
- `--no-judge` — concept retired (Tier 2 isn't a "judge" anymore; it's a scanner)
- `--llm-backend` — Copilot is the default surface; no in-process LLM call
- `--bedrock-model-id`, `--bedrock-region` — no AWS dep
- `--discovery` — Tier 4 retired

### Retained
- `--scan-all-files`, `--exclude PATTERN`, `--stage-locally`, `--debug`
- `--output-sarif`, `--output-json`, `--output-markdown`

## 7. Repository layout

```
agentshield/
  cli.py                          [updated]
  rules/                          [pruned to 6 families]
    detect/D001-*.yaml            [keep both fw variants]
    detect/D003-*.yaml            [keep Py + Java]
    detect/D004-*.yaml            [keep Py + Java]
    detect/D005-*.yaml            [keep Py + Java]
    detect/D008-*.yaml            [keep Py + Java]
    defend/DF003-*.yaml           [keep Py + Java]
    _retired_v2/                  [NEW — archived rules, not loaded]
      D001-fallback-*.yaml
      D002-*.yaml
      D006-*.yaml
      D007-*.yaml
      DF001-*.yaml
      DF002-*.yaml
      DF004-*.yaml
      R001-*.yaml
      R001-*-java.yaml
  runner/semgrep_runner.py        [unchanged]
  normalizer/                     [unchanged]
  writers/                        [unchanged]
  skills/                         [NEW — bundled skill markdown templates]
    tier2_bootstrap.md.tmpl       [becomes .github/copilot-instructions.md]
    tier2_checklist.md.tmpl       [becomes .agentshield/tier2-checklist.md]
    tier2_output_schema.md.tmpl   [becomes .agentshield/tier2-output-schema.md]
  emitter/                        [NEW]
    skill_emitter.py              [renders templates into target repo]
  merger/                         [NEW]
    combine.py                    [reads tier1 + tier2, writes combined]
    schema.py                     [validates tier2-findings.json]
  judge/                          [DELETED — kept in git history]
tests/
  test_cli_exclude.py             [keep]
  test_judge_*.py                 [DELETED]
  test_normalizer.py              [keep]
  test_orchestrator.py            [DELETED]
  test_rules_golden.py            [pruned to 6-family fixtures]
  test_writers.py                 [keep]
  test_emitter.py                 [NEW]
  test_merger.py                  [NEW]
  test_skills.py                  [NEW — schema validation of bundled checklist]
  fixtures/                       [pruned matching rules]
  golden/                         [pruned matching rules]
testbed/                          [unchanged — same regression targets]
docs/
  ARCHITECTURE_V2.md              [this file]
  ROADMAP.md                      [Phase F section added]
  REMEDIATION_PATTERNS.md         [updated for 6 families]
  COPILOT_LLM_SCAN_USAGE.md       [Copilot workflow walkthrough — was TIER2_USAGE.md]
  VDI_TESTING.md                  [updated for v2 commands]
```

## 8. Migration plan

Phased rollout on `architecture-v2` branch. Each phase is a separate commit; user can review at each step.

| Phase | What | Commit |
|---|---|---|
| **F.1** | This doc + sign-off | (this commit) |
| **F.2** | Rule pruning — move 8 retired rules + their fixtures + goldens to `_retired_v2/`. Tests still green on the 6 surviving rules. | next |
| **F.3** | Skill files — write all 3 templates (checklist is the big one — comprehensive coverage of OWASP / Agentic / MITRE / CWE / Phase E gaps). Add `test_skills.py` for schema validation. | |
| **F.4** | Emitter — `agentshield/emitter/skill_emitter.py` + tests. Renders templates into target repo. | |
| **F.5** | Merger — `agentshield/merger/combine.py` + tests. Reads tier1 + tier2 outputs, produces combined report. | |
| **F.6** | CLI rewire — drop `--no-judge`, `--llm-backend`, `--bedrock-*`, `--discovery`. Add `agentshield merge` subcommand. Add Tier-2-not-run warning. Delete `agentshield/judge/` + its tests. | |
| **F.7** | Docs — update ROADMAP §3.X (Phase F shipped), RULES_COVERAGE, REMEDIATION_PATTERNS, VDI_TESTING. Write the Copilot LLM Scan walkthrough. | |
| **F.8** | Validation — re-run on the three Phase E codebases (Java thematic, Python SMARTSDK Lambda, Java JpmcTriage if available) and document precision deltas. | |

## 9. What stays the same

Worth saying explicitly so we don't accidentally break things:
- **All output formats** — SARIF v2.1.0, JSON, Markdown — same writers
- **Normalizer** — Tier 2 findings normalize into the same `Finding` type
- **Test infrastructure** — pytest, golden-file methodology, testbed regression targets
- **CLI surface for retained flags** — `--scan-all-files`, `--exclude`, `--stage-locally`, `--debug`, `--output-*`
- **Phase A→E.3 documentation trail** — historical context preserved; v2 work is additive

## 10. Open questions / decisions still needed

These need a decision before I start implementing F.2.

1. **Where does Copilot write `tier2-findings.json`?**
   - **Proposed:** `<target-repo>/.agentshield/tier2-findings.json` — same dir as the input skill files. Symmetric, easy for the user to find.
   - **Alternative:** path provided to `agentshield merge` CLI — more flexible, less convention.
2. **Should `.agentshield/` be added to target's `.gitignore` automatically?**
   - **Proposed:** Yes — emitter checks for `.gitignore`, appends if missing. Skill files are generated artifacts, not committed.
3. **Tier 2 stale-detection** — if user re-runs Tier 1 after Tier 2:
   - **Proposed:** merger writes a Tier 1 fingerprint (sorted finding tuple hash) into the combined report; on next merge, warns if fingerprint mismatches.
4. **Java vs Python in the checklist** — split or combined?
   - **Proposed:** combined single checklist. Each item notes "language: Java only" / "Python only" / "both" inline. Simpler than maintaining two parallel docs.
5. **Languages outside Py/Java** — Tier 1 ignores TS/Go/Rust today. Does Tier 2's Copilot scan them?
   - **Proposed:** Yes. Tier 2 reads any source file Copilot can open. Tier 1 stays Py/Java-only.
6. **Bundled vs pluggable checklist** — should the checklist be one fixed file shipped with AgentShield, or layered (default + user-customizable overlay)?
   - **Proposed:** Bundled-only for v2. Layering can come later if users need it.
7. **Boto3-Bedrock backend retirement** — Copilot becomes the default. Do we keep boto3 + mock as alternates for headless / CI use?
   - **Proposed:** Keep both as alternates behind `--tier2-mode {copilot,bedrock,mock}`. Copilot is default. CI users with no Copilot license fall back to bedrock or mock.

## 11. Non-goals (explicit)

- **Not adding new languages** — TS / Go / Rust support stays out of v2. (Tier 2 may incidentally cover them via Copilot, but we don't claim parity.)
- **Not building a Copilot plugin** — the handoff is via skill files + Copilot Chat slash command, not a custom Copilot extension.
- **Not building a managed service** — AgentShield stays a CLI you run locally. No hosted Tier 2 endpoint.
- **Not changing the judge prompt format** — the comprehensive checklist IS the prompt. No separate prompt-engineering layer.

## 12. What we lose by doing this

Honest cost accounting — not everything is upside.

- **8 rule families gone from CI gating** — projects that gate CI on Tier 1 only will see fewer fires. Mitigation: the warning banner makes Tier 2 absence visible.
- **No automated Tier 2 in CI** — Copilot Chat needs an IDE. CI runs default to Tier 1 + Tier-2-not-run warning. Mitigation: bedrock backend as alternate for CI.
- **Tier 2 quality depends on Copilot's output discipline** — if Copilot doesn't follow the JSON schema, the merger can't consume it. Mitigation: schema validator in merger; clear error message points back at the schema doc.
- **Skill checklist is now a maintenance surface** — it's a 600-line markdown doc that needs updating as OWASP versions move and new attack patterns emerge. Mitigation: it lives in the repo, versioned with the code; updates are a normal PR.
- **The "thematic-codebase R002 TPs" gap stays open** — until / unless the comprehensive Tier 2 checklist actually catches them in practice. Validation in F.8 will tell us.

---

**Decision points for sign-off:**
1. ✅ / ❌ rule-pruning list (§3) — keep 6, retire 8?
2. ✅ / ❌ skill-checklist scope (§4.4) — comprehensive OWASP LLM + Agentic + MITRE + CWE + Phase E gaps?
3. ✅ / ❌ Copilot-via-skill-files as default Tier 2 execution (§4.1)?
4. ✅ / ❌ migration plan ordering (§8) — phased commits on `architecture-v2` branch?
5. Open questions in §10 — your call on each.

Once these are confirmed I'll start F.2 (rule pruning). Nothing destructive happens before sign-off.
