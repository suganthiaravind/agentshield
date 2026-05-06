# `_retired_v2/` — archived rules from architecture v1

These 8 rule families were **retired in Phase F.2** as part of the v1→v2
architecture shift documented in [`ARCHITECTURE_V2.md`](../../ARCHITECTURE_V2.md).
They live here, not in `agentshield/rules/`, because:

- **Semgrep loads from `agentshield/rules/` only** — files here will not be
  picked up by the semgrep runner. The `.yaml` extension is preserved so
  the patterns stay greppable / syntax-highlightable as historical reference.
- **Their fixtures and goldens** moved here too, under `fixtures/` and
  `goldens/`. They are also outside the `tests/` tree, so pytest's
  fixture discovery (`tests/fixtures/`) doesn't load them either.

## Why each rule was retired

| Rule | Retirement reason |
|---|---|
| **D001-fb** (fallback) | Intentionally low-confidence; designed to be triaged by Tier 3 LLM judge. With Tier 3 retired, fallback rules have no consumer. |
| **D002** (untrusted document loader) | Narrow but rarely TPs in OSS testbed (5 phases of validation: 0 TPs found). |
| **D006** (broad tool permissions) | Heuristic on tool-permission breadth — FP-prone on framework-internal tools. |
| **D007** (untrusted model loading) | Version-string check on HuggingFace `from_pretrained` — false-confident; can't tell if the unpinned model is the application's or a vendored test fixture. |
| **DF001** (no guardrails import) | Absence-detection. Phase E required 5 rounds of fixes and still misses cross-method advisor wiring. |
| **DF002** (`@Tool` arg schema) | Heuristic on `@Tool` + bare `String` parameters — FPs on framework tools. |
| **DF004** (destructive tool naming) | Pure name-based heuristic ("delete*" / "send*" / "charge*") — no taint, high FP. |
| **R001** (no audit logging) | Absence-detection. Phase E.2 had to relax it twice (Lombok @Slf4j, stdlib `logger = logging.getLogger(...)`); judge runs showed it still FPs ~50% of the time. |

## Where the coverage lives now

These checks **moved into the Tier 2 skill checklist** —
`agentshield/skills/tier2_checklist.md` (built in Phase F.3). The LLM-as-scanner
covers each retired rule's anti-pattern with full file context, which is more
expressive than the rule pack ever was for absence-detection / heuristic rules.

See [`ARCHITECTURE_V2.md` §3](../../ARCHITECTURE_V2.md#3-tier-1--pruned-rule-pack)
for the full retirement rationale.

## Resurrection policy

If real-world signal proves a retired rule should come back (e.g. Tier 2
consistently misses a pattern this rule caught), it can be moved back to
`agentshield/rules/` — but it must come back with at least one
high-precision narrowing (not the pre-retirement form). The retirement is
an admission that the original shape was net-negative on real codebases.
