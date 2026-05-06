# AgentShield Tier 2 — Copilot walkthrough

Status: 2026-05-06 (Phase F architecture v2)
Companion to: [ARCHITECTURE_V2.md](./ARCHITECTURE_V2.md), [VDI_TESTING.md](./VDI_TESTING.md), [README.md](./README.md)

This document walks through the Tier 2 step in detail — what Copilot actually does when you paste the prompt, what the output looks like, and what to do when something goes wrong.

> **TL;DR.** After `agentshield scan`, your target repo has a `.agentshield/` folder. Open the repo in VS Code or JetBrains. Open Copilot Chat. Paste the prompt the CLI printed. Copilot writes `tier2-findings.json` over a few minutes. Run `agentshield merge .` to get the unified report.

---

## Why Tier 2 exists

Tier 1 (semgrep) catches narrow, high-precision patterns: hardcoded credentials, untrusted user input flowing into LLM calls, code-execution sinks, etc. Six rule families, all narrow taint or narrow regex. By design it ships with a small surface and high signal.

The trade-off: a lot of important security concerns can't be expressed as semgrep patterns:

- **Cross-method reasoning** — a guardrail wired in `ChatService`'s constructor protects calls in `SchedulingService`, but Tier 1 can't see that.
- **Absence detection that requires context** — "is there an audit log around this LLM call?" depends on whether logging *intent* exists in the file (Lombok `@Slf4j`, stdlib `logger = logging.getLogger(...)`, OpenTelemetry imports), not just specific patterns.
- **Anti-patterns that need code-comprehension** — scrubber bypass (`if length > MAX: return original`), SNS/email sinks of LLM output without scrubbing, rate-limit absence on agent loops.
- **Reasoning about intent** — does this `chain.invoke(user_input)` look like a legitimate guardrailed pipeline, or a prompt-injection vector?

Tier 2 is the LLM doing what the LLM is good at: reading a file, understanding the intent, and reasoning about whether each anti-pattern in the comprehensive checklist applies.

---

## What's in `.agentshield/` after `agentshield scan`

```
<your-repo>/
├── .agentshield/
│   ├── tier1-results.json          ← Tier 1 findings + fingerprint hash (input for Copilot)
│   ├── tier2-bootstrap.md          ← Plain-language explanation of Tier 2
│   ├── tier2-checklist.md          ← The 56-check comprehensive checklist
│   └── tier2-output-schema.md      ← Strict JSON shape Copilot must emit
└── .gitignore                      ← `.agentshield/` appended (idempotent)
```

All four are generated artifacts; the gitignore append keeps them out of commits.

---

## The prompt Copilot needs

The CLI prints this verbatim after every `agentshield scan`:

```
@workspace Please run AgentShield Tier 2.

Read the checklist at .agentshield/tier2-checklist.md and the
output schema at .agentshield/tier2-output-schema.md. Walk every
source file in this workspace, apply each check that is in scope
for the file's language, and write your findings to
.agentshield/tier2-findings.json following the schema exactly.

Also read .agentshield/tier1-results.json and add a
tier1_fp_callouts section noting any Tier 1 finding you believe
is a false positive, with reasoning.

Important: copy the agentshield_tier1_fingerprint field from
tier1-results.json verbatim into your output. The merger uses it
to detect stale Tier 2 runs.
```

The `@workspace` prefix tells Copilot to load the whole repo into its working context, not just the current file.

### Why this exact wording

- **"Walk every source file in this workspace"** — Copilot defaults to acting on the active file. Without explicit "walk every," you'd get a partial scan.
- **"in scope for the file's language"** — the checklist tags each check with `Languages: any | python | java`. Skipping irrelevant checks per file keeps Copilot's per-file pass tractable.
- **"following the schema exactly"** — Copilot is more reliable when given a strict shape. The schema file has explicit enum values and required fields.
- **"copy the agentshield_tier1_fingerprint verbatim"** — this is the contract that lets the merger detect stale Tier 2 runs (you re-ran Tier 1 after Tier 2; results no longer correlate).

### If Copilot needs more help

Some Copilot variants don't auto-write to disk. If after Copilot says it's done you still don't see `.agentshield/tier2-findings.json`, follow up with:

> "You said you finished but `.agentshield/tier2-findings.json` doesn't exist. Please write the JSON output to that path."

If Copilot stops mid-scan (context-window pressure on large repos), prompt:

> "Continue from where you left off. The files you've already scanned are in the existing `.agentshield/tier2-findings.json`'s `scanned_files` array — process the rest and append findings."

---

## What Copilot will do

For each source file in your workspace, Copilot:

1. **Reads the file** into its context window.
2. **Walks the checklist** — 56 checks across 7 sections (OWASP LLM Top 10 v2, OWASP Agentic AI Top 10, MITRE ATLAS, CWE first-class, Phase E gaps, retired-rule parity, Tier 1 cross-check).
3. **For each check that's in scope** for the file's language, decides whether the anti-pattern is present.
4. **Emits a finding** if yes, into `.agentshield/tier2-findings.json` per the strict schema.
5. **At the end**, reads `.agentshield/tier1-results.json` and produces a `tier1_fp_callouts` array marking each Tier 1 finding TP / CD / FP with reasoning.

Time depends on repo size:
- Single file: ~30 seconds
- 10 files: ~2 minutes
- 50 files: ~10-15 minutes
- 200+ files: may need to run in chunks; ask Copilot to checkpoint by saving incrementally

---

## What `tier2-findings.json` looks like

```json
{
  "tier": 2,
  "scanned_at": "2026-05-06T22:14:00Z",
  "agentshield_tier1_fingerprint": "1d33b903f7d02a04...",
  "scanned_files": ["src/foo.py", "src/bar.java"],
  "skipped_files": [],
  "findings": [
    {
      "rule_id": "TIER2-LLM02-04",
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

The full schema with required fields, enum values, and validation rules is in `.agentshield/tier2-output-schema.md` (and in [`agentshield/skills/tier2_output_schema.md.tmpl`](./agentshield/skills/tier2_output_schema.md.tmpl)).

---

## Running `agentshield merge`

Once `tier2-findings.json` exists:

```bash
agentshield merge /path/to/your-repo --output-markdown report.md
```

Possible CLI banners:

| Banner | Meaning | Action |
|---|---|---|
| `✓ Tier 1 + Tier 2 fresh; merging.` | Both present, fingerprint matches | None — open the report |
| `⚠ Tier 2 has NOT been run` | `tier2-findings.json` missing | Re-do the Copilot step |
| `❌ Tier 2 output failed schema validation` | Copilot's JSON is malformed | Re-prompt Copilot citing the field paths the merger printed |
| `⚠ STALE Tier 2: fingerprint mismatch` | Code or rule pack changed between runs | Re-run Copilot with the same prompt |

The unified report sections:

1. **Summary** — Tier 1 count, Tier 2 count, FP-marked Tier 1 count, **net actionable** (Tier 1 minus FP-marked + Tier 2)
2. **Tier 1 findings** — each one annotated with Tier 2's verdict + reasoning where applicable
3. **Tier 2 net-new findings** — what static rules missed
4. **Coverage matrix** — which OWASP / Agentic / ATLAS / CWE items the combined scan touched

---

## Trouble cases and how to handle them

### "Copilot ignored my prompt and just summarised the codebase"

Some Copilot variants treat `@workspace` requests as a context-load only. Re-prompt explicitly:

> "Don't summarise. Execute the scan: read `.agentshield/tier2-checklist.md`, walk every source file, write findings to `.agentshield/tier2-findings.json` per `.agentshield/tier2-output-schema.md`."

### "Copilot scanned only the file currently open"

Add explicit file enumeration:

> "Use `@workspace` to enumerate every `.py`, `.java`, `.ts`, `.go` file in this repo. Walk them all, not just the active editor file."

### "Schema validation says my JSON has 12 errors"

The merger's error output names each field path. Paste them into Copilot Chat:

> "Your `.agentshield/tier2-findings.json` failed schema validation. Fix these errors:
> - `findings[2].severity: invalid value 'urgent' (allowed: ['critical', 'high', 'medium', 'low', 'info'])`
> - `findings[5].owasp_llm: expected list, got NoneType`
> - ..."

### "Tier 2 took forever and Copilot stopped"

For large codebases (200+ files), Tier 2 in a single Copilot session can run into context limits. Workarounds:

- Run Copilot in chunks: prompt by directory (`@workspace Walk only src/api/. Append to existing tier2-findings.json.`)
- Add files to `skipped_files` array if you genuinely can't scan them; the merger surfaces these as a coverage gap rather than failing
- For programmatic / CI use without an IDE, a future Bedrock-based Tier 2 backend is documented as work that could happen if needed (the merger is backend-agnostic — anything that produces a schema-valid `tier2-findings.json` works)

### "Fingerprint mismatch, nothing changed"

If you didn't re-run `agentshield scan` between Tier 2 finishing and `agentshield merge`, but you still see a stale banner, the most likely cause is Copilot copied the wrong fingerprint (or invented one). Re-prompt:

> "Open `.agentshield/tier1-results.json`, read the `agentshield_tier1_fingerprint` field, and update `.agentshield/tier2-findings.json`'s `agentshield_tier1_fingerprint` to that exact value (don't change anything else)."

### "I want to skip Tier 2 entirely for a quick check"

Use `--no-emit` on `agentshield scan` to suppress the Tier 2 emission. The CLI will warn that scanning is incomplete; the Tier-1-only Markdown / JSON / SARIF outputs from `--output-*` are still produced. **Don't gate CI on Tier-1-only results without understanding what's missing** — see [ARCHITECTURE_V2.md §12 "What we lose"](./ARCHITECTURE_V2.md#12-what-we-lose-by-doing-this).

---

## CI considerations

Tier 2 needs Copilot Chat in an IDE. CI runners typically don't have that. Practical options today:

1. **Tier-1-only CI** — `agentshield scan --no-emit --output-sarif sarif.json`. Surfaces the high-signal findings; misses what only Tier 2 catches. Acceptable as a *gate*; not as the *audit*.
2. **Local pre-merge audit** — developer runs Tier 2 locally before opening a PR and commits the unified report (or a hash of it) as evidence. Reviewer can re-run if suspicious.
3. **Future:** a programmatic Tier 2 backend (Bedrock / SmartSDK / hosted Copilot) that emits schema-valid `tier2-findings.json` without an IDE. The merger architecture supports this — only the Copilot bootstrap needs replacing.

---

## When Tier 2 is wrong

Tier 2 findings are not infallible. The LLM can hallucinate findings (a check that doesn't actually apply) or miss real ones (didn't recognise the pattern in your specific code shape). Two safeguards:

1. **Tier 1 is independent.** Both tiers run; Tier 2's verdicts on Tier 1 findings are advisory — the merger keeps the original Tier 1 finding and just annotates it. CI gating can choose to honour or ignore Tier 2 FP-marks.
2. **The combined report cites everything.** Tier 2 findings include framework mappings, snippets, and remediation guidance. A reviewer can validate each Tier 2 finding against the source the same way they'd validate a Tier 1 finding.

If Tier 2 is consistently wrong on a specific check across multiple codebases, that's signal to refine the check definition in [`agentshield/skills/tier2_checklist.md.tmpl`](./agentshield/skills/tier2_checklist.md.tmpl). The skill file is versioned with the code; updates ship with each AgentShield release.
