# AgentShield Architecture v2 — design doc (Phase F)

**Status:** ✅ **Shipped.** All phases F.1–F.35 landed on the `architecture-v2` branch (last commit: `bd25e5b`, 2026-05-07). This doc is the design snapshot from the planning step (2026-05-05); see [§13 Post-F.6 evolution](#13-post-f6-evolution) at the bottom for what landed beyond the original phase plan.
**Branch:** `architecture-v2`. Predecessor: `phase-b-c-d-polish` (Phase E.3 shipped).
**For current state:** open the **Reference tab** of any HTML report (`agentshield merge --output-html report.html`) — it's auto-generated from the live rule pack, so it's always accurate. This doc is preserved for the "why we built it this way" history.

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

> **What actually shipped:** the original 6 families below were the F.2 baseline. **F.23 added 4 more rules** (D009 / D010 / D011 / D012, all framework-tier, all Python-only) — see §13. The current Tier 1 rule count is **10 families**. F.27 also renamed every rule's `agentshield_id` to the uniform `AS-S-<DDR>-<framework>-<seq>` form (legacy IDs preserved as aliases). The narrow-taint / narrow-regex precision bar is unchanged.

### Survives (6 families — the F.2 baseline)

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

### 4.3 Skill files (3 files at F.4; **6 files** post-F.34b — see §13)

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
    tier2_bootstrap.md.tmpl       [becomes .agentshield/tier2-bootstrap.md]
    tier2_checklist.md.tmpl       [becomes .agentshield/tier2-checklist.md]
    tier2_output_schema.md.tmpl   [becomes .agentshield/tier2-output-schema.md]
    agentshield_semgrep_fixes.md  [F.34 — per-source remediation skill]
    agentshield_copilot_fixes.md  [F.34]
    agentshield_manifest_fixes.md [F.34]
    _build_fix_skills.py          [F.34 generator — re-run after rule changes]
  emitter/                        [NEW]
    skill_emitter.py              [renders templates into target repo]
  merger/                         [NEW]
    combine.py                    [reads tier1 + tier2, writes combined]
    schema.py                     [validates tier2-findings.json]
    reference.py                  [F.26 — rule-data loader for the Reference tab + fix-skills]
  manifest_scanner/               [F.24 — NEW]
    scanner.py                    [walks SKILL.md files; emits AS-M-* findings]
    rules.py                      [10 AST10 sub-rules: AST01/03/04/05/07]
    parser.py                     [YAML frontmatter splitter]
  judge/                          [DELETED in F.6 — kept in git history]
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

Phased rollout on `architecture-v2` branch. Each phase is a separate commit; the table below was the original plan, all rows now ✅ shipped.

| Phase | What | Status |
|---|---|---|
| **F.1** | This doc + sign-off | ✅ shipped |
| **F.2** | Rule pruning — move 8 retired rules + their fixtures + goldens to `_retired_v2/`. Tests still green on the 6 surviving rules. | ✅ shipped |
| **F.3** | Skill files — write all 3 templates (checklist is the big one — comprehensive coverage of OWASP / Agentic / MITRE / CWE / Phase E gaps). Add `test_skills.py` for schema validation. | ✅ shipped |
| **F.4** | Emitter — `agentshield/emitter/skill_emitter.py` + tests. Renders templates into target repo. | ✅ shipped |
| **F.5** | Merger — `agentshield/merger/combine.py` + tests. Reads tier1 + tier2 outputs, produces combined report. | ✅ shipped |
| **F.6** | CLI rewire — drop `--no-judge`, `--llm-backend`, `--bedrock-*`, `--discovery`. Add `agentshield merge` subcommand. Add Tier-2-not-run warning. Delete `agentshield/judge/` + its tests. | ✅ shipped |
| **F.7** | Docs — update ROADMAP §3.X (Phase F shipped), REMEDIATION_PATTERNS, VDI_TESTING. Write the Copilot LLM Scan walkthrough. | ✅ shipped |
| **F.8** | Validation — re-run on Phase E codebases. | ✅ shipped (VDI runs validated F.6 → F.21 chain) |
| **F.9–F.21** | Cleanup, doc consolidation, HTML report iteration. | ✅ shipped — see §13 |
| **F.22–F.35** | Reference tab, AST10 manifest scanner, uniform rule IDs, fix-skills, VDI polish. | ✅ shipped — see §13 |

## 9. What stays the same

Worth saying explicitly so we don't accidentally break things:
- **All output formats** — SARIF v2.1.0, JSON, Markdown — same writers
- **Normalizer** — Tier 2 findings normalize into the same `Finding` type
- **Test infrastructure** — pytest, golden-file methodology, testbed regression targets
- **CLI surface for retained flags** — `--scan-all-files`, `--exclude`, `--stage-locally`, `--debug`, `--output-*`
- **Phase A→E.3 documentation trail** — historical context preserved; v2 work is additive

## 10. Open questions / decisions — RESOLVED

All decisions below were locked in during F.2–F.6 implementation. Recording the resolutions for history:

1. **Where does Copilot write `tier2-findings.json`?** → ✅ `<target-repo>/.agentshield/tier2-findings.json`. Same dir as input skill files. Symmetric, conventional.
2. **`.agentshield/` auto-gitignored?** → ✅ Yes. Emitter idempotently appends `.agentshield/` to the target's `.gitignore`.
3. **Tier 2 stale-detection?** → ✅ Fingerprint-based. Merger writes a SHA-256 over sorted `(file, line, rule_id)` tuples; mismatch on subsequent merge surfaces a STALE banner.
4. **Java vs Python checklist split?** → ✅ Combined. Each entry has a `**Languages:**` bullet (`any` / `python` / `java`).
5. **Languages outside Py/Java in Tier 2?** → ✅ Yes. Copilot reads anything in the workspace; Tier 1 stays Py/Java-only.
6. **Bundled vs pluggable checklist?** → ✅ Bundled. Layering deferred until customer demand arrives.
7. **Boto3-Bedrock backend retirement?** → ✅ Retired entirely (F.6). Copilot is the only Tier 2 surface. The `[judge]` extra was removed from `pyproject.toml`. Schema is backend-agnostic — anything that produces a schema-valid `tier2-findings.json` works (the merger doesn't care what wrote it).

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

**Decision points (originally for sign-off, now historical):**
1. ✅ rule-pruning list (§3) — keep 6, retire 8.
2. ✅ skill-checklist scope (§4.4) — comprehensive OWASP LLM + Agentic + MITRE + CWE + Phase E gaps.
3. ✅ Copilot-via-skill-files as default Tier 2 execution (§4.1).
4. ✅ migration plan ordering (§8) — phased commits on `architecture-v2`.
5. ✅ Open questions in §10 — all resolved (see updated §10).

---

## 13. Post-F.6 evolution

The original phase plan (§8 above) ended at F.8. Validation confirmed the architecture, and 27 more phases shipped on top of the F.6 baseline — they're additive (no v1 reversal) but materially expand what AgentShield does and what the report looks like. Captured here so this design doc remains a useful reference instead of going stale.

| Phase | Headline | What it changed |
|---|---|---|
| **F.9–F.10** | Cleanup + UTF-8 fix | Pruned dead types (`tier`, `confidence`, `triage` shrunk to v2-only). Fixed Windows cp1252 encoding crash on the merger's banner glyphs (caught in VDI run). |
| **F.11–F.16** | Doc consolidation + SAIGE classification | Deleted v1-era docs (PHASE_*.md, ARCHITECTURE.md v1, LLM_JUDGE_DESIGN.md, etc.). Folded F8_VALIDATION.md → ROADMAP §3.9. Folded project.md + research-notes → research.md. Added §8 SAIGE Agent Tier classification to the Tier 2 checklist (Non-Agent / Tier 0–3, informational only). |
| **F.17–F.21** | HTML report + interactivity | New `render_combined_html()` produces a single self-contained `.html` with embedded CSS + vanilla JS. D/D/R-led layout, Lucide-MIT SVG icons, severity pills. F.21 added the filter bar (severity / origin / search), framework-tag click-to-filter, expand/collapse, and `--open` CLI flag. |
| **F.22** | Tabbed report layout | 5 tabs (Detect / Defend / Respond / Coverage / Frameworks). Tabs hide content not relevant to the current section; live tab counts update with filter state. |
| **F.23** | +4 Tier 1 rules + 6 Tier 2 entries | D009 (concealment markers in stored prompts), D010 (jailbreak markers), D011 (tool-description injection), D012 (non-HTTPS outbound). Plus 6 Tier 2 entries covering ASI-04/05/07/08/10. Lifted from the OWASP-AST10 + Cisco-skill-scanner reference bundles. |
| **F.24** | AST10 manifest scanner | New `agentshield/manifest_scanner/` module: pure-Python parser walks `**/SKILL.md`, runs 10 AST10 sub-rules (AST01/03/04/05/07). Findings emit in the same `Finding` shape — flow through the existing emit / merge / report pipeline unchanged. New `framework_mappings.ast` field on every `Finding`. |
| **F.25** | Section-header severity breakdown | Each D/D/R section subheader now shows per-severity pills (`2 critical · 4 high · 2 medium · 3 info`) that live-update with filter state. |
| **F.26** | Reference tab | 6th tab in the HTML report. Lists every check the scanner can fire (Semgrep + Copilot + Manifest), grouped by source, generated live at render time from the YAML rule pack + Tier 2 checklist + AST10 registry — so the doc surface is always in sync with the rule pack. |
| **F.27** | Uniform rule-ID naming | Renamed every rule's `agentshield_id` to `AS-<source>-<DDR>-<anchor>-<seq>` form. Examples: `AS-D-001` → `AS-S-D-LLM01-001`; `TIER2-LLM01-01` → `AS-C-D-LLM01-001`; `AS-AST-001` → `AS-M-D-AST01-001`. Legacy IDs preserved on `Finding.legacy_ids: list[str]` so customer suppress-comments / SARIF dashboards keep working. Tier 2 schema validator accepts both `AS-C-` and legacy `TIER2-` prefixes. |
| **F.28** | Reference D/D/R sub-grouping + UI cleanup | Within each source on the Reference tab, cards now sub-group by D/D/R inside `<details>` for click-to-expand. Removed the per-finding chevron from D/D/R tabs (redundant with new Reference grouping). Fixed broken OWASP Agentic AI URL across 3 places. Dropped tier-numbering from Reference source blurbs. |
| **F.29** | Static / printable HTML | `render_combined_html(static=True)` emits `<sample>-print.html` alongside the interactive one — every panel rendered as a stacked `<section>`, no tabs, no filter bar. CLI auto-emits both files for one `--output-html` flag. Print-friendly + good for emailing to stakeholders. |
| **F.30** | Docs cleanup | Deleted `RULES_COVERAGE.md` (688-line stale doc; superseded by Reference tab). Deleted `agentshield/judge/` (dead `__pycache__/` after F.6). Rewrote stale "today's rules" lines in `GLOSSARY.md`. Fixed `<TBD>` URL placeholder in `agentshield_v1.yaml`. |
| **F.31** | Copilot friendly slugs | Copilot finding cards in the report now show the human-readable slug (e.g. `indirect-prompt-injection-via-document-loader`) instead of the raw `AS-C-D-LLM01-002` ID. Looked up from the bundled checklist titles. |
| **F.32** | VDI-readable polish | Severity-pill backgrounds bumped ~30% darker; card borders 1px → 1.5px + box-shadow; `--text-muted` darkened; pill / chip font-weight 600 → 700; added `-webkit-font-smoothing: antialiased`. Survives VDI chroma compression / lo-DPI without losing local-display clarity. |
| **F.33** | Hero metrics row | Restructured the 4-card metrics row: 3 input cards + dashed divider + hero "Net Actionable" card on the right (40px value, accent-tinted background). Subtitles in parallel "what …" form. The math (`Semgrep + Copilot − FP = Actionable`) lives in the Net Actionable card's `title=` tooltip. |
| **F.34 + F.34b** | Per-source fix-skills | Three OWASP-Universal-Skill-Format SKILL.md files generated from the same rule data the Reference tab uses — `agentshield_semgrep_fixes.md` (16 rules), `agentshield_copilot_fixes.md` (62 entries), `agentshield_manifest_fixes.md` (10 sub-rules). Risk-tier L0 (no shell, no network, no writes). Emitter (F.34b) drops them into `<target>/.agentshield/` alongside the existing 3 templates so a developer can drag the matching skill straight into Claude Code / Copilot Chat to get fix guidance for any finding ID. |
| **F.35** | Doc rename | `TIER2_USAGE.md` → `COPILOT_LLM_SCAN_USAGE.md` (matches user-visible naming). Refreshed stale rule counts (6→10), file counts (4→7), example IDs (`TIER2-LLM02-04` → `AS-C-R-LLM02-002`), coverage matrix (4→5 framework axes). |
| **F.36** | This update | Updated the design doc itself to reflect shipped state. |

### Net architectural deltas vs the F.6 baseline

- **Rule pack:** 6 Tier 1 families → **10** Tier 1 families. **+ AST10 manifest scanner** (10 sub-rules). 56 Tier 2 checks → **62**.
- **Output:** 3 emitted skill files → **6** (the 3 new fix-skills are auto-emitted alongside).
- **Report formats:** Markdown / JSON / SARIF → **+ HTML** (interactive + static / print variants).
- **Rule IDs:** flat `AS-D-001` / `TIER2-LLM01-01` / `AS-AST-001` → uniform `AS-<source>-<DDR>-<anchor>-<seq>` (legacy IDs aliased for back-compat).
- **Framework axes:** OWASP LLM / Agentic / ATLAS / CWE → **+ OWASP AST10** (5 axes).
- **Doc surface:** Per-rule reference moved from a hand-maintained `RULES_COVERAGE.md` (deleted in F.30) to the auto-generated **Reference tab** in every HTML report.

The original 2-tier design (§2) is unchanged. Everything above is additive.
