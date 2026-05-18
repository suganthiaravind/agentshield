"""Combine Tier 1 + Tier 2 findings into a unified report (Phase F.5).

Reads:
- `<target>/.agentshield/tier1-results.json` — written by emitter (F.4)
- `<target>/.agentshield/tier2-findings.json` — written by Copilot

Produces:
- Markdown (primary, human-readable)
- JSON (machine-readable, mirrors the unified structure)
- SARIF (CI tooling — two `runs` for Tier 1 and Tier 2 toolComponents)

Behaviour:
- Validates Tier 2 against the schema; refuses to merge on schema errors.
- Compares fingerprints; if mismatch, writes the report with a STALE
  banner but still produces output (don't block — flag).
- If `tier2-findings.json` is missing, produces a Tier-1-only report with
  an "INCOMPLETE: Tier 2 not run" banner.
- Annotates each Tier 1 finding with Tier 2's TP/FP/CD verdict (if any).
- Builds a coverage matrix across OWASP LLM / Agentic / ATLAS / CWE.

The CLI (rewired in F.6) calls `merge(target_root)` and pipes the result
through `render_combined_*` writers. The merger module has no CLI deps.
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from agentshield.merger.attack_narratives import (
    ProbeLine,
    ProbeRun,
    narrative_for,
)
from agentshield.merger.schema import SchemaError, validate_tier2_findings


class MergeError(Exception):
    """Raised when the merger cannot produce any output (missing inputs,
    unparseable JSON, schema-invalid Tier 2). Soft conditions like a
    missing Tier 2 file or stale fingerprint are surfaced via flags on
    `MergeResult`, not exceptions.
    """


@dataclass
class Tier1FindingAnnotated:
    """A Tier 1 finding plus optional Tier 2 verdict on it."""

    finding: dict
    tier2_verdict: str | None = None  # one of TP/CD/FP, None if Tier 2 didn't comment
    tier2_reasoning: str | None = None


@dataclass
class CoverageMatrix:
    """Which framework items the combined scan touched.

    Each set holds the IDs that appeared in at least one finding's
    framework_mappings (Tier 1) or framework array (Tier 2).
    """

    owasp_llm: set[str] = field(default_factory=set)
    owasp_agentic: set[str] = field(default_factory=set)
    mitre_atlas: set[str] = field(default_factory=set)
    cwe: set[str] = field(default_factory=set)
    ast: set[str] = field(default_factory=set)  # F.24: OWASP Agentic Skills Top 10

    def to_dict(self) -> dict[str, list[str]]:
        return {
            "owasp_llm": sorted(self.owasp_llm),
            "owasp_agentic": sorted(self.owasp_agentic),
            "mitre_atlas": sorted(self.mitre_atlas),
            "cwe": sorted(self.cwe),
            "ast": sorted(self.ast),
        }


@dataclass
class CombinedReport:
    """The data the renderers consume. Keep this pure-data; rendering is
    the renderer's job."""

    tier1_path: Path
    tier2_path: Path | None  # None if Tier 2 not run
    tier1_findings: list[Tier1FindingAnnotated]
    tier2_findings: list[dict]
    tier1_fp_callouts: list[dict]
    coverage: CoverageMatrix
    tier1_fingerprint: str
    tier2_fingerprint: str | None
    tier2_scanned_at: str | None
    tier2_skipped_files: list[dict]
    tier2_scanned_files: list[str]
    saige_tier: str | None = None  # F.16: optional JPMC SAIGE classification
    saige_tier_reasoning: str | None = None


@dataclass
class MergeResult:
    """Return type of `merge()`. Always returned (never raises for soft
    failures); CLI inspects the flags to decide what banner to print."""

    report: CombinedReport
    tier2_present: bool  # False if .agentshield/tier2-findings.json is missing
    fingerprint_match: bool  # True only if Tier 2 present AND fingerprint matches
    schema_errors: list[SchemaError]  # populated only if Tier 2 was present but invalid

    @property
    def stale(self) -> bool:
        """Tier 2 was run, but against an older Tier 1 state."""
        return self.tier2_present and not self.fingerprint_match

    @property
    def actionable_finding_count(self) -> int:
        """Findings the user should act on: Tier 1 (excluding FP-marked) + Tier 2."""
        tier1_actionable = sum(
            1 for f in self.report.tier1_findings if f.tier2_verdict != "FP"
        )
        return tier1_actionable + len(self.report.tier2_findings)


# ---------- core merge ----------

def merge(target_root: Path) -> MergeResult:
    """Read tier1-results.json + tier2-findings.json from
    `<target>/.agentshield/` and produce a unified MergeResult.

    Raises MergeError only on hard failures: missing tier1-results.json
    (the emitter should always have produced this), unparseable JSON in
    either file. Soft failures (missing Tier 2, schema errors,
    fingerprint mismatch) are flagged on the result.
    """
    target_root = Path(target_root)
    out = target_root / ".agentshield"
    tier1_path = out / "tier1-results.json"
    tier2_path = out / "tier2-findings.json"

    if not tier1_path.exists():
        raise MergeError(
            f"Tier 1 results not found: {tier1_path}. "
            "Run `agentshield scan` first to produce it."
        )

    try:
        tier1 = json.loads(tier1_path.read_text())
    except json.JSONDecodeError as e:
        raise MergeError(f"tier1-results.json is not valid JSON: {e}") from e

    tier1_findings_raw = tier1.get("findings", [])
    tier1_fingerprint = tier1.get("agentshield_tier1_fingerprint", "")

    tier2_present = tier2_path.exists()
    tier2: dict[str, Any] = {}
    schema_errors: list[SchemaError] = []
    fingerprint_match = False

    if tier2_present:
        try:
            tier2 = json.loads(tier2_path.read_text())
        except json.JSONDecodeError as e:
            raise MergeError(f"tier2-findings.json is not valid JSON: {e}") from e

        validation = validate_tier2_findings(tier2)
        schema_errors = validation.errors
        if validation.ok:
            fingerprint_match = (
                tier2.get("agentshield_tier1_fingerprint") == tier1_fingerprint
            )

    # Build annotated Tier 1 list with Tier 2 verdicts overlaid by index.
    callouts_by_index = {}
    if tier2_present and not schema_errors:
        for callout in tier2.get("tier1_fp_callouts", []):
            idx = callout.get("tier1_finding_index")
            if isinstance(idx, int) and 0 <= idx < len(tier1_findings_raw):
                callouts_by_index[idx] = callout

    annotated: list[Tier1FindingAnnotated] = []
    for i, f in enumerate(tier1_findings_raw):
        callout = callouts_by_index.get(i)
        annotated.append(
            Tier1FindingAnnotated(
                finding=f,
                tier2_verdict=callout.get("verdict") if callout else None,
                tier2_reasoning=callout.get("reasoning") if callout else None,
            )
        )

    coverage = _build_coverage(
        tier1_findings_raw, tier2.get("findings", []) if tier2_present else []
    )

    # F.16: SAIGE classification — only surface if Tier 2 ran AND schema-valid.
    # Both fields are optional; if Copilot didn't classify, they stay None.
    saige_tier = (
        tier2.get("saige_tier")
        if tier2_present and not schema_errors
        else None
    )
    saige_tier_reasoning = (
        tier2.get("saige_tier_reasoning")
        if tier2_present and not schema_errors
        else None
    )

    report = CombinedReport(
        tier1_path=tier1_path,
        tier2_path=tier2_path if tier2_present else None,
        tier1_findings=annotated,
        tier2_findings=tier2.get("findings", []) if tier2_present and not schema_errors else [],
        tier1_fp_callouts=tier2.get("tier1_fp_callouts", []) if tier2_present and not schema_errors else [],
        coverage=coverage,
        tier1_fingerprint=tier1_fingerprint,
        tier2_fingerprint=tier2.get("agentshield_tier1_fingerprint") if tier2_present else None,
        tier2_scanned_at=tier2.get("scanned_at") if tier2_present else None,
        tier2_skipped_files=tier2.get("skipped_files", []) if tier2_present else [],
        tier2_scanned_files=tier2.get("scanned_files", []) if tier2_present else [],
        saige_tier=saige_tier,
        saige_tier_reasoning=saige_tier_reasoning,
    )

    return MergeResult(
        report=report,
        tier2_present=tier2_present,
        fingerprint_match=fingerprint_match,
        schema_errors=schema_errors,
    )


def _ddr_counts(report: CombinedReport) -> dict[str, dict[str, int]]:
    """Count findings per Detect/Defend/Respond category, broken out by tier.

    Tier 1 findings carry `category` from the rule's YAML metadata (always
    one of detect/defend/respond — Pydantic-enforced upstream). Tier 2
    findings carry `category` from the schema's required enum field.
    Unknowns get bucketed under 'detect' as a safe default since the
    schema validator should already have caught invalid values.
    """
    out = {
        "tier1": {"detect": 0, "defend": 0, "respond": 0},
        "tier2": {"detect": 0, "defend": 0, "respond": 0},
    }
    for ann in report.tier1_findings:
        cat = ann.finding.get("category")
        if cat in out["tier1"]:
            out["tier1"][cat] += 1
    for f in report.tier2_findings:
        cat = f.get("category")
        if cat in out["tier2"]:
            out["tier2"][cat] += 1
    return out


def _build_coverage(
    tier1_findings: list[dict], tier2_findings: list[dict]
) -> CoverageMatrix:
    """Aggregate framework IDs from both tiers."""
    cov = CoverageMatrix()
    for f in tier1_findings:
        # Tier 1 findings store framework_mappings as a nested object (per
        # agentshield.normalize.Finding) when written via the JSON writer.
        # Fall back to flat keys if Copilot or a hand-edit reshapes them.
        fm = f.get("framework_mappings") or f
        for key, target in (
            ("owasp_llm", cov.owasp_llm),
            ("owasp_agentic", cov.owasp_agentic),
            ("mitre_atlas", cov.mitre_atlas),
            ("ast", cov.ast),
        ):
            for v in (fm.get(key) or []):
                target.add(v)
        # CWE on Tier 1 lives under framework_mappings.cwe usually.
        for v in (fm.get("cwe") or []):
            cov.cwe.add(v)

    for f in tier2_findings:
        for v in f.get("owasp_llm") or []:
            cov.owasp_llm.add(v)
        for v in f.get("owasp_agentic") or []:
            cov.owasp_agentic.add(v)
        for v in f.get("mitre_atlas") or []:
            cov.mitre_atlas.add(v)
        for v in f.get("cwe") or []:
            cov.cwe.add(v)
        for v in f.get("ast") or []:
            cov.ast.add(v)
    return cov


def _framework_finding_counts(report: CombinedReport) -> dict[str, int]:
    """Count findings per "<framework_field>:<item>" key, both tiers combined.

    Used by the Frameworks tab in the HTML report — every clickable item
    shows how many findings carry that framework tag, matching the same
    `<field>:<value>` key the per-finding `data-framework-key` JS filter
    uses. Returning a flat dict keeps the renderer one .get() per item.
    """
    counts: Counter[str] = Counter()
    for ann in report.tier1_findings:
        fm = ann.finding.get("framework_mappings") or ann.finding
        for k_field in ("owasp_llm", "owasp_agentic", "mitre_atlas", "cwe", "ast"):
            for v in (fm.get(k_field) or []):
                counts[f"{k_field}:{v}"] += 1
    for f in report.tier2_findings:
        for k_field in ("owasp_llm", "owasp_agentic", "mitre_atlas", "cwe", "ast"):
            for v in (f.get(k_field) or []):
                counts[f"{k_field}:{v}"] += 1
    return dict(counts)


# ---------- renderers ----------

_DDR_LABELS = {
    # (emoji_label, subtitle, section_desc, hero_question)
    "detect": (
        "🔴 Detect",
        "vulnerability surfaces",
        "Where the agent is exploitable",
        "Where is the agent exploitable?",
    ),
    "defend": (
        "🟡 Defend",
        "missing controls",
        "What active defences are missing",
        "What defenses are missing?",
    ),
    "respond": (
        "🔵 Respond",
        "observability gaps",
        "Whether incidents can be detected and recovered",
        "If something goes wrong, will you see it and stop it?",
    ),
}

_DDR_ORDER = ("detect", "defend", "respond")

# Inline SVG icons for the D/D/R hero cards (Lucide MIT-licensed paths,
# embedded so the report renders fully offline — no external network or
# font dependencies). 16×16 viewBox; CSS sizes them.
_DDR_ICON_SVG = {
    "detect": (
        '<svg class="ddr-icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" '
        'fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" '
        'stroke-linejoin="round">'
        '<circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/></svg>'
    ),
    "defend": (
        '<svg class="ddr-icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" '
        'fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" '
        'stroke-linejoin="round">'
        '<path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/>'
        '<path d="m9 12 2 2 4-4"/>'
        '</svg>'
    ),
    "respond": (
        '<svg class="ddr-icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" '
        'fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" '
        'stroke-linejoin="round">'
        '<path d="M4 14a1 1 0 0 1-.78-1.63l9.9-10.2a.5.5 0 0 1 .86.46l-1.92 6.02A1 1 0 0 0 13 10h7a1 1 0 0 1 .78 1.63l-9.9 10.2a.5.5 0 0 1-.86-.46l1.92-6.02A1 1 0 0 0 11 14z"/>'
        '</svg>'
    ),
}

_VERDICT_BADGE = {
    "TP": "✅ TP",
    "CD": "🟡 CD",
    "FP": "⚠ FP",
}

# Hover tooltip text for severity pills. Severity is curated per-rule
# by the rule author (no dynamic CVSS-style score) — these strings
# explain the implicit rubric so a reader knows what each level means
# without leaving the report. Surfaced on every `pill <sev>` element:
# header dashboard, severity distribution bar, D/D/R section headers,
# per-finding card, Reference tab rule cards.
_SEVERITY_MEANINGS = {
    "critical": (
        "Critical — opens a path to running attacker-controlled code "
        "on the agent host. Fix before ship."
    ),
    "high": (
        "High — Exploitable with bounded impact (data leak, role "
        "takeover, attacker-driven tool calls)."
    ),
    "medium": (
        "Medium — Missing safety net (timeout / input validation / "
        "permission check). Fix it now; future bugs will hit this "
        "guard instead of going past it."
    ),
    "low": (
        "Low — Observability or hygiene gap. Helps detection / "
        "response after an incident, not prevention."
    ),
    "info": (
        "Info — Best-practice nudge. Doesn't increase attack "
        "surface on its own."
    ),
}


# Hover tooltip text for the Copilot cross-check verdicts on
# Tier 1 findings. Three states by design — collapsing CD into TP causes
# alert fatigue ("you fix 100 'TPs' but 60 were already mitigated");
# collapsing it into FP hides real risk ("we said FP but the mitigation
# got removed in a later refactor"). See
# agentshield/skills/tier2_output_schema.md.tmpl §verdict for the
# canonical schema definition.
_VERDICT_MEANINGS = {
    "TP": (
        "True Positive — pattern is present and unmitigated. Real issue, "
        "fix it."
    ),
    "CD": (
        "Context-Dependent — pattern is present but mitigated elsewhere "
        "(sanitiser, auth check, feature flag). Defensible; verify the "
        "mitigation stays in place."
    ),
    "FP": (
        "False Positive — pattern isn't actually there (test fixture, "
        "mock, unreachable path). Safe to suppress."
    ),
}


def _findings_grouped_by_ddr(report: CombinedReport) -> dict[str, list[dict]]:
    """Group Tier 1 + Tier 2 findings by D/D/R category.

    Each finding gets a `_origin` field ("tier1" or "tier2") so the renderer
    can show a tier badge per finding without losing the D/D/R-led grouping.
    Tier 1 findings additionally carry `_tier2_verdict` + `_tier2_reasoning`
    when Tier 2 cross-checked them.
    """
    grouped: dict[str, list[dict]] = {"detect": [], "defend": [], "respond": []}
    for ann in report.tier1_findings:
        f = dict(ann.finding)
        f["_origin"] = "tier1"
        f["_tier2_verdict"] = ann.tier2_verdict
        f["_tier2_reasoning"] = ann.tier2_reasoning
        cat = f.get("category")
        if cat in grouped:
            grouped[cat].append(f)
    for f in report.tier2_findings:
        ff = dict(f)
        ff["_origin"] = "tier2"
        cat = ff.get("category")
        if cat in grouped:
            grouped[cat].append(ff)
    # Sort each bucket by severity (critical → info), then by file path
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    for bucket in grouped.values():
        bucket.sort(key=lambda f: (
            sev_order.get(f.get("severity", "info"), 99),
            f.get("file", ""),
            f.get("line", 0),
        ))
    return grouped


def render_combined_markdown(result: MergeResult) -> str:
    """Human-readable unified report. The primary v2 deliverable.

    Layout (F.17 — D/D/R-led, professional dashboard shape):
      1. Title + scan metadata
      2. Status banner (only if Tier 2 missing / schema-invalid / stale)
      3. **D/D/R hero strip** — 3 columns, one per category, with severity counts
      4. Summary + severity-distribution
      5. SAIGE classification (if present)
      6. **Findings sections led by D/D/R** (🔴 Detect → 🟡 Defend → 🔵 Respond),
         with [Tier 1] / [Tier 2] badges on each finding
      7. Coverage matrix
      8. Tier 2 skipped files (if any)
    """
    r = result.report
    ddr_counts = _ddr_counts(r)
    grouped = _findings_grouped_by_ddr(r)

    lines: list[str] = []

    # 1. Title
    lines.append("# AgentShield Pre-Production Review")
    lines.append("")
    lines.append(f"_Rules-engine Static Scan + Copilot LLM-as-a-Judge Scan · scanned {r.tier2_scanned_at or '(Semgrep only — Copilot LLM-as-a-Judge Scan not run)'}_")
    lines.append("")
    lines.append("---")
    lines.append("")

    # 2. Status banners
    if not result.tier2_present:
        lines.append(
            "> ⚠ **INCOMPLETE: Copilot LLM-as-a-Judge Scan not run.** This report contains "
            "Rules-engine Static Scan findings only. Run the Copilot LLM-as-a-Judge Scan "
            "against this repo and re-merge for full coverage. See "
            "`.agentshield/tier2-bootstrap.md` for the prompt."
        )
        lines.append("")
    elif result.schema_errors:
        lines.append(
            "> ❌ **Copilot LLM-as-a-Judge Scan output failed schema validation.** Showing "
            "Rules-engine Static Scan only. Validation errors below — "
            "re-prompt Copilot to fix and re-merge."
        )
        lines.append("")
        lines.append("### Schema errors")
        lines.append("")
        for err in result.schema_errors:
            lines.append(f"- `{err.field_path}` — {err.message}")
        lines.append("")
    elif result.stale:
        lines.append(
            "> ⚠ **STALE Copilot LLM-as-a-Judge Scan.** The Semgrep fingerprint changed "
            "since the Copilot LLM-as-a-Judge Scan was run; the code (or rule pack) changed "
            "in between. Re-run the Copilot LLM-as-a-Judge Scan in Copilot Chat for fresh "
            "results."
        )
        lines.append(f"> - Semgrep fingerprint (current):  `{r.tier1_fingerprint[:16]}...`")
        lines.append(f"> - Copilot fingerprint (recorded): `{(r.tier2_fingerprint or '')[:16]}...`")
        lines.append("")

    # 3. D/D/R HERO STRIP — 3 columns, severity counts per category.
    #    The lead element of the report (per F.17 design). Renders as a
    #    Markdown table because that's the closest text equivalent of
    #    side-by-side cards while staying readable in plain Markdown.
    lines.append("## Detect / Defend / Respond")
    lines.append("")
    lines.append("AgentShield's organising spine. Every finding belongs to exactly one category.")
    lines.append("")
    headers = []
    bodies = []
    for cat in _DDR_ORDER:
        emoji_label, subtitle, _desc, _question = _DDR_LABELS[cat]
        total = len(grouped[cat])
        sev_counts: dict[str, int] = {}
        for f in grouped[cat]:
            s = f.get("severity", "info")
            sev_counts[s] = sev_counts.get(s, 0) + 1
        headers.append(f"**{emoji_label}** _{subtitle}_")
        body_lines = [f"**{total} finding{'s' if total != 1 else ''}**"]
        for sev in ("critical", "high", "medium", "low", "info"):
            n = sev_counts.get(sev, 0)
            if n:
                body_lines.append(f"{_severity_badge(sev)} &times; {n}")
        if total == 0:
            body_lines.append("_(no findings)_")
        bodies.append("<br>".join(body_lines))
    lines.append("| " + " | ".join(headers) + " |")
    lines.append("|" + "|".join("---" for _ in headers) + "|")
    lines.append("| " + " | ".join(bodies) + " |")
    lines.append("")

    # 4. Summary + severity distribution
    tier1_total = len(r.tier1_findings)
    tier2_total = len(r.tier2_findings)
    fp_marked = sum(1 for f in r.tier1_findings if f.tier2_verdict == "FP")
    cd_marked = sum(1 for f in r.tier1_findings if f.tier2_verdict == "CD")
    tp_marked = sum(1 for f in r.tier1_findings if f.tier2_verdict == "TP")

    lines.append("## Summary")
    lines.append("")
    lines.append("| Metric | Count |")
    lines.append("|---|---|")
    lines.append(f"| Rules-engine Static Scan findings | {tier1_total} |")
    lines.append(f"| Copilot LLM-as-a-Judge Scan net-new findings | {tier2_total} |")
    if result.tier2_present and not result.schema_errors:
        lines.append(f"| Semgrep findings marked True Positive by Copilot | {tp_marked} |")
        lines.append(f"| Semgrep findings marked Context-Dependent by Copilot | {cd_marked} |")
        lines.append(f"| Semgrep findings marked False Positive by Copilot | {fp_marked} |")
    lines.append(f"| **Net actionable** | **{result.actionable_finding_count}** |")
    lines.append("")

    # 5. SAIGE classification (if present)
    if r.saige_tier:
        tier_label = (
            "Non Agent" if r.saige_tier == "non-agent"
            else f"Agentic Tier {r.saige_tier}"
        )
        lines.append("## JPMC SAIGE Agent Tier classification")
        lines.append("")
        lines.append(f"**Classified as:** {tier_label}")
        lines.append("")
        lines.append("**Rationale:**")
        lines.append("")
        lines.append(f"> {r.saige_tier_reasoning or '_(no reasoning provided)_'}")
        lines.append("")
        lines.append(
            "_Informational only — AgentShield does not filter or prioritise "
            "findings based on this classification. See [research.md §5]"
            "(./research.md#5-jpmc-saige-agent-tier-classification) for the "
            "category definitions._"
        )
        lines.append("")

    # 6. FINDINGS — D/D/R-LED. Each section is one D/D/R bucket; per-finding
    #    [Tier 1] / [Tier 2] badge replaces the old "Tier 1 vs Tier 2" split.
    for cat in _DDR_ORDER:
        emoji_label, subtitle, desc, _question = _DDR_LABELS[cat]
        bucket = grouped[cat]
        lines.append(f"## {emoji_label} — {subtitle}  ({len(bucket)} finding{'s' if len(bucket) != 1 else ''})")
        lines.append("")
        lines.append(f"_{desc}._")
        lines.append("")
        if not bucket:
            lines.append(f"_No {cat} findings._")
            lines.append("")
            continue
        for f in bucket:
            origin = f["_origin"]
            origin_badge = "**[Semgrep]**" if origin == "tier1" else "**[Copilot]**"
            sev = f.get("severity", "n/a")
            sev_badge = _severity_badge(sev)
            rule = (
                f.get("rule_id_short")
                or f.get("rule_id")
                or "?"
            )
            file_ = f.get("file") or "?"
            line_ = f.get("line") or "?"
            verdict_tag = ""
            if origin == "tier1" and f.get("_tier2_verdict"):
                v = f["_tier2_verdict"]
                verdict_tag = f"  ·  Copilot verdict: {_VERDICT_BADGE.get(v, v)}"
            lines.append(f"### {origin_badge} {sev_badge} `{rule}`{verdict_tag}")
            lines.append("")
            lines.append(f"- **Location:** `{file_}:{line_}`")
            if f.get("message"):
                lines.append(f"- **Message:** {f['message']}")
            mappings = []
            # Tier 2 findings have flat keys; Tier 1 findings have framework_mappings nested.
            fm = f.get("framework_mappings") or f
            for k_label, k_field in (
                ("OWASP LLM", "owasp_llm"),
                ("OWASP Agentic", "owasp_agentic"),
                ("MITRE ATLAS", "mitre_atlas"),
                ("CWE", "cwe"),
                ("OWASP AST10", "ast"),
            ):
                vals = fm.get(k_field) or []
                if vals:
                    mappings.append(f"{k_label} {', '.join(vals)}")
            if mappings:
                lines.append(f"- **Frameworks:** {' · '.join(mappings)}")
            if f.get("snippet"):
                lines.append(f"- **Snippet:** `{f['snippet']}`")
            if f.get("remediation"):
                lines.append(f"- **Remediation:** {f['remediation']}")
            if origin == "tier1" and f.get("_tier2_reasoning"):
                lines.append(f"- **Copilot reasoning:** {f['_tier2_reasoning']}")
            lines.append("")

    # 7. Coverage matrix
    lines.append("## Coverage matrix")
    lines.append("")
    cov = r.coverage.to_dict()
    lines.append("| Framework | Items touched |")
    lines.append("|---|---|")
    for k, vs in cov.items():
        lines.append(f"| {k} | {', '.join(vs) if vs else '_(none)_'} |")
    lines.append("")

    # 8. Skipped files (transparency)
    if r.tier2_skipped_files:
        lines.append("## Copilot LLM-as-a-Judge Scan skipped files")
        lines.append("")
        for s in r.tier2_skipped_files:
            lines.append(f"- `{s.get('path', '?')}` — {s.get('reason', 'no reason given')}")
        lines.append("")

    return "\n".join(lines) + "\n"


_SEVERITY_ICON = {
    "critical": "🟥",
    "high": "🟧",
    "medium": "🟨",
    "low": "🟩",
    "info": "🟦",
}


def _severity_badge(severity: str) -> str:
    """Coloured square + label, used inline in finding headers + D/D/R hero."""
    icon = _SEVERITY_ICON.get(severity.lower(), "⬜")
    return f"{icon} {severity.upper()}"


def render_combined_json(result: MergeResult) -> str:
    """Machine-readable unified report. Mirrors the markdown structure 1:1."""
    r = result.report
    payload = {
        "agentshield_version": "v2",
        "tier1_present": True,
        "tier2_present": result.tier2_present,
        "fingerprint_match": result.fingerprint_match,
        "stale": result.stale,
        "schema_errors": [
            {"field_path": e.field_path, "message": e.message}
            for e in result.schema_errors
        ],
        "actionable_finding_count": result.actionable_finding_count,
        "summary": {
            "tier1_total": len(r.tier1_findings),
            "tier2_net_new": len(r.tier2_findings),
            "tier1_marked_tp": sum(1 for f in r.tier1_findings if f.tier2_verdict == "TP"),
            "tier1_marked_cd": sum(1 for f in r.tier1_findings if f.tier2_verdict == "CD"),
            "tier1_marked_fp": sum(1 for f in r.tier1_findings if f.tier2_verdict == "FP"),
            "by_category": _ddr_counts(r),
        },
        "tier1_fingerprint": r.tier1_fingerprint,
        "tier2_fingerprint": r.tier2_fingerprint,
        "tier2_scanned_at": r.tier2_scanned_at,
        "saige_tier": r.saige_tier,
        "saige_tier_reasoning": r.saige_tier_reasoning,
        "tier1_findings": [
            {
                **ann.finding,
                "tier2_verdict": ann.tier2_verdict,
                "tier2_reasoning": ann.tier2_reasoning,
            }
            for ann in r.tier1_findings
        ],
        "tier2_findings": r.tier2_findings,
        "tier1_fp_callouts": r.tier1_fp_callouts,
        "coverage": r.coverage.to_dict(),
        "tier2_skipped_files": r.tier2_skipped_files,
        "tier2_scanned_files": r.tier2_scanned_files,
    }
    return json.dumps(payload, indent=2) + "\n"


# ---------- HTML renderer (F.17) ----------

_HTML_CSS = """
:root {
  --bg: #fafaf7;
  --panel: #ffffff;
  /* F.32: bumped border darkness so 1.5px lines stay visible after VDI
     chroma-compression. Was #e5e3dc — too close to --bg on lo-DPI. */
  --border: #d6d3c7;
  --text: #1f2933;
  /* F.32: muted text darkened from #6b7280 → #4b5563 for contrast on
     96-ppi VDI displays. Still distinct from --text. */
  --text-muted: #4b5563;
  --accent: #2c5f7e;

  --detect: #c54040;
  --detect-bg: #fdecea;
  --defend: #b8830f;
  --defend-bg: #fbf3dc;
  --respond: #2c5f7e;
  --respond-bg: #e3eef4;

  --critical: #b3261e;
  --high: #d27800;
  --medium: #b8830f;
  --low: #4f7a4f;
  --info: #5a7a8c;

  /* F.32: severity-pill backgrounds bumped ~30% darker so the pills
     stay visible against white after VDI compression. The text colors
     above are unchanged — the contrast ratio improves. */
  --critical-bg: #f8c9c4;
  --high-bg: #f9d7a8;
  --medium-bg: #f3d680;
  --low-bg: #c9e0c2;
  --info-bg: #c5d4dd;
}

* { box-sizing: border-box; }

body {
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto,
               Helvetica, Arial, sans-serif;
  background: var(--bg);
  color: var(--text);
  margin: 0;
  padding: 32px 40px 80px;
  line-height: 1.5;
  font-size: 14px;
  /* F.32: keep glyph edges crisp on lo-DPI VDI displays where the OS
     might disable subpixel AA — these hint to the browser to render
     the text antialiased anyway. */
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
  text-rendering: optimizeLegibility;
}

h1, h2, h3 { color: var(--text); margin: 0; font-weight: 600; }
h1 { font-size: 22px; letter-spacing: -0.01em; }
h2 { font-size: 16px; letter-spacing: 0.04em; text-transform: uppercase;
     color: var(--text-muted); margin: 32px 0 12px; }
h3 { font-size: 15px; }

.report-header { padding-bottom: 8px; margin-bottom: 14px; }
.report-header .subtitle { color: var(--text-muted); font-size: 13px; margin-top: 4px; }

.banner {
  border-radius: 8px;
  padding: 12px 16px;
  margin: 16px 0;
  font-size: 13px;
  border-left: 4px solid;
}
.banner.warn  { background: #fbf3dc; border-color: var(--defend); color: #5a3f00; }
.banner.error { background: var(--critical-bg); border-color: var(--critical); color: #5e1a16; }
.banner.stale { background: var(--info-bg); border-color: var(--info); color: #2c4250; }

.ddr-row {
  display: grid;
  grid-template-columns: 1fr 1fr 1fr;
  gap: 16px;
  margin-bottom: 32px;
}
.ddr-card {
  background: var(--panel);
  border: 1.5px solid var(--border);
  border-radius: 12px;
  padding: 20px;
  border-top: 4px solid;
  /* F.32: subtle shadow so the card stays visually distinct from the
     page background after VDI compression eats the 1.5px border. */
  box-shadow: 0 1px 2px rgba(0,0,0,0.04);
}
.ddr-card.detect  { border-top-color: var(--detect); }
.ddr-card.defend  { border-top-color: var(--defend); }
.ddr-card.respond { border-top-color: var(--respond); }

.ddr-card .ddr-label-row {
  display: flex; align-items: center; gap: 6px; margin-bottom: 10px;
}
.ddr-card .ddr-icon {
  width: 14px; height: 14px;
  color: var(--text-muted);
  flex-shrink: 0;
}
.ddr-card .ddr-label {
  font-size: 11px; letter-spacing: 0.1em; text-transform: uppercase;
  color: var(--text-muted); font-weight: 600;
}
.ddr-card.detect  .ddr-icon, .ddr-card.detect  .ddr-label { color: var(--detect); }
.ddr-card.defend  .ddr-icon, .ddr-card.defend  .ddr-label { color: var(--defend); }
.ddr-card.respond .ddr-icon, .ddr-card.respond .ddr-label { color: var(--respond); }
.ddr-card .ddr-title { font-size: 15px; font-weight: 600; margin-bottom: 2px; }
.ddr-card .ddr-subtitle { font-size: 13px; color: var(--text-muted); margin-bottom: 14px; }
.ddr-card .ddr-question {
  font-size: 13px;
  font-style: italic;
  color: var(--text-muted);
  border-left: 3px solid;
  padding: 2px 0 2px 12px;
  margin: 0 0 18px 12px;
  line-height: 1.45;
}
.ddr-card.detect  .ddr-question { border-left-color: var(--detect); }
.ddr-card.defend  .ddr-question { border-left-color: var(--defend); }
.ddr-card.respond .ddr-question { border-left-color: var(--respond); }
.ddr-card .ddr-count { font-size: 36px; font-weight: 700; line-height: 1; }
.ddr-card .sev-pills { display: flex; flex-wrap: wrap; gap: 6px; }
/* v4: count + severity-pills on the same baseline-aligned row so the
   D/D/R card collapses vertically and frees space below it. */
.ddr-card .ddr-count-row {
  display: flex; align-items: baseline; gap: 14px; flex-wrap: wrap;
}

.pill {
  display: inline-block;
  padding: 3px 10px;
  border-radius: 999px;
  font-size: 11px;
  /* F.32: bumped 600 → 700 so small caps survive VDI subpixel-rendering
     loss without enlarging the pill. */
  font-weight: 700;
  letter-spacing: 0.02em;
  text-transform: uppercase;
}
.pill.critical { background: var(--critical-bg); color: var(--critical); }
.pill.high     { background: var(--high-bg);     color: var(--high); }
.pill.medium   { background: var(--medium-bg);   color: var(--medium); }
.pill.low      { background: var(--low-bg);      color: var(--low); }
.pill.info     { background: var(--info-bg);     color: var(--info); }
.pill.tier1    { background: #efe7d7; color: #5a4413; }
.pill.tier2    { background: #d8e5ed; color: #1f4a63; }
.pill.tp       { background: #d6e7d6; color: #2f5a2f; }
.pill.cd       { background: #fbf3dc; color: var(--defend); }
.pill.fp       { background: var(--high-bg); color: var(--high); }
/* v4: 0-count severity pills — visually dimmed so a reader can tell
   "low: 0" apart from active pills without losing the signal that
   that severity bucket exists. */
.pill.pill-zero { opacity: 0.45; }

.metrics-row {
  /* F.33: 3 input cards (1fr each) + a thin separator + 1 hero card
     (1.4fr) so the headline number visually outweighs its inputs.
     The CSS-only divider is a 1px column the user reads as
     "everything left = inputs; everything right = result". */
  display: grid;
  grid-template-columns: 1fr 1fr 1fr 8px 1.4fr;
  gap: 12px;
  margin-bottom: 24px;
  align-items: stretch;
}
.metrics-row .metrics-divider {
  align-self: stretch;
  border-left: 1px dashed var(--border);
  margin: 4px 0;
}
.metric {
  background: var(--panel);
  border: 1.5px solid var(--border);
  border-radius: 10px;
  padding: 14px 18px;
  box-shadow: 0 1px 2px rgba(0,0,0,0.04);  /* F.32 */
  display: flex; flex-direction: column;
}
.metric .metric-label { font-size: 11px; letter-spacing: 0.08em; text-transform: uppercase;
                        color: var(--text-muted); margin-bottom: 6px; font-weight: 600; }
.metric .metric-value { font-size: 28px; font-weight: 700; line-height: 1; }
.metric .metric-value.actionable { color: var(--accent); }
/* F.33: subtitle row under the big number — explains what the count
   means in plain English (raw findings / net-new / excluded / to
   address) so a stakeholder can scan the row and understand it
   without consulting the docs. */
.metric .metric-subtitle {
  font-size: 13px; color: var(--text-muted); margin-top: 6px;
  font-style: italic; line-height: 1.45;
}
/* v4: small per-source subtotal under the metric value (e.g. the
   Copilot card's "5 code · 1 skill" split). Keep visually quieter
   than the main value but louder than the subtitle so it reads as
   data, not commentary. */
.metric .metric-breakdown {
  display: flex; align-items: baseline; gap: 6px;
  margin-top: 4px;
  font-size: 12px; font-weight: 600;
  color: var(--text);
  font-variant-numeric: tabular-nums;
}
.metric .metric-bd-sep { color: var(--text-muted); font-weight: 400; }
.metric .metric-bd-item { white-space: nowrap; }
/* F.33: hero treatment for the Net Actionable card. Bigger value,
   accent border, accent-tinted background — the conclusion card. */
.metric.metric-hero {
  border-color: var(--accent);
  border-left-width: 4px;
  background: linear-gradient(180deg, #f4f8fb 0%, #ffffff 100%);
}
.metric.metric-hero .metric-label { color: var(--accent); }
.metric.metric-hero .metric-value { font-size: 40px; }

.severity-bar {
  display: flex;
  width: 100%;
  height: 10px;
  border-radius: 999px;
  overflow: hidden;
  background: var(--border);
  margin-top: 4px;
}
.severity-bar > div { height: 100%; }
.severity-bar .critical { background: var(--critical); }
.severity-bar .high     { background: var(--high); }
.severity-bar .medium   { background: var(--medium); }
.severity-bar .low      { background: var(--low); }
.severity-bar .info     { background: var(--info); }

.saige-card {
  background: var(--panel);
  border: 1.5px solid var(--border);
  border-left: 4px solid var(--accent);
  border-radius: 10px;
  padding: 18px 22px;
  margin-bottom: 28px;
  box-shadow: 0 1px 2px rgba(0,0,0,0.04);  /* F.32 */
}
.saige-card .saige-label { font-size: 11px; letter-spacing: 0.08em; text-transform: uppercase;
                           color: var(--text-muted); font-weight: 600; }
.saige-card .saige-tier { font-size: 22px; font-weight: 700; margin: 4px 0 12px; color: var(--accent); }
.saige-card .saige-rationale { color: var(--text); font-size: 13px; line-height: 1.6; }
.saige-card .saige-footer { font-size: 11px; color: var(--text-muted); margin-top: 12px; font-style: italic; }

.section { margin-bottom: 28px; }

.findings-section {
  background: var(--panel);
  border: 1.5px solid var(--border);
  border-radius: 12px;
  margin-bottom: 24px;
  overflow: hidden;
  box-shadow: 0 1px 2px rgba(0,0,0,0.04);  /* F.32 */
}
.findings-section .section-header {
  padding: 16px 20px 12px;
  border-bottom: 1px solid var(--border);
  display: flex;
  align-items: baseline;
  gap: 12px;
}
.findings-section.detect  .section-header { background: var(--detect-bg); }
.findings-section.defend  .section-header { background: var(--defend-bg); }
.findings-section.respond .section-header { background: var(--respond-bg); }
.findings-section .section-title { font-size: 16px; font-weight: 600; }
.findings-section .section-subtitle { font-size: 12px; color: var(--text-muted); flex: 1; }
.findings-section .section-count { font-size: 12px; font-weight: 600; color: var(--text-muted); }
.findings-section .section-severity {
  display: inline-flex; flex-wrap: wrap; gap: 4px;
  margin-left: 10px;
}
.sev-mini {
  display: inline-block;
  padding: 1px 7px;
  border-radius: 999px;
  font-size: 10px;
  font-weight: 700;  /* F.32 */
  letter-spacing: 0.02em;
  text-transform: uppercase;
}
.sev-mini.critical { background: var(--critical-bg); color: var(--critical); }
.sev-mini.high     { background: var(--high-bg);     color: var(--high); }
.sev-mini.medium   { background: var(--medium-bg);   color: var(--medium); }
.sev-mini.low      { background: var(--low-bg);      color: var(--low); }
.sev-mini.info     { background: var(--info-bg);     color: var(--info); }

.finding {
  padding: 16px 20px;
  border-bottom: 1px solid var(--border);
}
.finding:last-child { border-bottom: none; }
.finding-header { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; margin-bottom: 8px; }
.finding-rule { font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
                font-size: 12px; color: var(--text); font-weight: 600; }
.finding-meta { color: var(--text-muted); font-size: 12px; margin-bottom: 6px;
                font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
.finding-message { color: var(--text); font-size: 13px; margin-bottom: 8px; }
.finding-tags { display: flex; flex-wrap: wrap; gap: 4px; margin-bottom: 6px; }
.finding-tag { font-size: 10px; font-weight: 700; padding: 2px 8px; border-radius: 4px;  /* F.32 */
               background: #f1eee5; color: #5a5547; letter-spacing: 0.02em; }
.finding-snippet { font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
                   font-size: 12px; background: #f5f3ec; padding: 6px 10px;
                   border-radius: 4px; margin: 6px 0; color: #2a2620; overflow-x: auto; }
.finding-remediation { font-size: 12px; color: var(--text-muted); margin-top: 6px;
                       padding-left: 12px; border-left: 2px solid var(--border); }

/* v4: per-finding static attack narrative — collapsed by default in the
   interactive HTML, forced open in the static / print variant. Tinted
   warning palette so it reads as "here's what bad looks like" without
   being mistaken for an actual incident alert. */
.finding-attack-scenario {
  margin-top: 10px;
  border: 1px solid #e9c8a5;
  border-radius: 8px;
  background: #fcf5ec;
  overflow: hidden;
}
.finding-attack-scenario > summary {
  cursor: pointer; user-select: none;
  padding: 8px 12px;
  font-size: 12.5px; font-weight: 600;
  color: #7a4a18;
  display: flex; align-items: center; gap: 6px;
}
.finding-attack-scenario > summary::marker,
.finding-attack-scenario > summary::-webkit-details-marker { color: #b67a3a; }
.finding-attack-scenario > summary:hover { background: #f7ebd8; }
.finding-attack-scenario .attack-icon {
  display: inline-block;
  font-size: 13px; color: #b86a1a;
  margin-right: 2px;
}
.finding-attack-scenario[open] > summary {
  border-bottom: 1px solid #e9c8a5;
  background: #f7ebd8;
}
.finding-attack-scenario .attack-body { padding: 10px 14px 12px; }
.finding-attack-scenario .attack-section { margin-bottom: 10px; }
.finding-attack-scenario .attack-section:last-of-type { margin-bottom: 6px; }
.finding-attack-scenario .attack-label {
  font-size: 10.5px; font-weight: 700;
  text-transform: uppercase; letter-spacing: 0.06em;
  color: #7a4a18; margin-bottom: 3px;
}
.finding-attack-scenario .attack-text {
  font-size: 12.5px; color: var(--text); line-height: 1.55;
}
.finding-attack-scenario .attack-payload {
  margin: 0;
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 12px;
  background: #2a2620; color: #f5f0e6;
  padding: 8px 12px; border-radius: 4px;
  white-space: pre-wrap; word-break: break-word; overflow-x: auto;
  line-height: 1.5;
}
.finding-attack-scenario .attack-disclaimer {
  margin-top: 8px;
  font-size: 11px; color: var(--text-muted); font-style: italic;
}
/* Path B+: live-probe disclaimer reads as "payloads were sent" rather
   than "no payloads were sent", so style it as informational
   (accent-toned) rather than purely cautionary. */
.finding-attack-scenario .attack-disclaimer-live {
  color: var(--accent); font-style: normal; font-weight: 500;
}
.finding-attack-scenario .attack-disclaimer-live code {
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-weight: 600; color: var(--accent);
}
/* Path B+: static-only finding — no probe was attached because the
   rule has no runtime attack vector (at-rest disclosure, manifest
   config, observability gap). Painted neutral-informational so it
   reads as "by design" rather than "we forgot to build this." */
.finding-attack-scenario .attack-disclaimer-static {
  color: var(--text); font-style: normal;
  background: #f4f1e8;
  border-left: 3px solid var(--info);
  padding: 8px 12px;
  border-radius: 0 4px 4px 0;
  font-size: 12px;
  line-height: 1.5;
}
/* Path B+: inline probe-state badge inside the <summary>, visible
   while the attack-scenario is collapsed. Three variants mirror the
   three disclaimer states. */
.finding-attack-scenario .attack-probe-badge {
  display: inline-block;
  font-size: 10px; font-weight: 700;
  letter-spacing: 0.04em;
  padding: 2px 8px;
  border-radius: 3px;
  margin: 0 4px;
  vertical-align: 1px;
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
}
.finding-attack-scenario .attack-probe-badge-probe {
  background: var(--accent); color: white;
}
.finding-attack-scenario .attack-probe-badge-static {
  background: #c5d4dd; color: #2c4250;
}
/* v4: attack walkthrough — ordered steps with ▶ Play animation. */
.finding-attack-scenario .attack-steps-section {
  padding-top: 10px;
  border-top: 1px dashed var(--border);
}
.finding-attack-scenario .attack-steps-section .attack-label {
  display: flex; align-items: center; gap: 10px;
}
.finding-attack-scenario .attack-play-btn {
  padding: 3px 10px;
  font-size: 11px; font-weight: 600;
  border: 1px solid var(--accent);
  background: transparent;
  color: var(--accent);
  border-radius: 4px;
  cursor: pointer;
  font-family: inherit;
}
.finding-attack-scenario .attack-play-btn:hover {
  background: var(--accent); color: white;
}
.finding-attack-scenario .attack-play-btn:disabled {
  opacity: 0.5; cursor: not-allowed;
}
ol.attack-steps {
  margin: 8px 0 0; padding-left: 24px;
  font-size: 13px; line-height: 1.55;
  color: var(--text);
}
ol.attack-steps li.attack-step { margin-bottom: 6px; }
ol.attack-steps li.attack-step::marker { color: var(--accent); font-weight: 700; }
/* Playing mode: steps start hidden and reveal sequentially via JS. */
ol.attack-steps.attack-steps-playing li.attack-step {
  opacity: 0;
  transform: translateY(4px);
  transition: opacity 0.4s ease, transform 0.4s ease;
}
ol.attack-steps.attack-steps-playing li.attack-step.attack-step-visible {
  opacity: 1;
  transform: translateY(0);
}

/* v4: visual attack-flow simulation — actor → target scenes per step. */
.attack-sim-list {
  display: flex; flex-direction: column;
  gap: 10px;
  margin-top: 10px;
}
.attack-sim-scene {
  padding: 12px 14px;
  border: 1px solid var(--border);
  border-radius: 8px;
  background: var(--panel);
  position: relative;
}
.attack-sim-scene .attack-sim-step-num {
  position: absolute; top: -7px; left: 12px;
  background: var(--bg);
  font-size: 10px; font-weight: 700; letter-spacing: 0.05em;
  text-transform: uppercase; color: var(--text-muted);
  padding: 0 6px;
}
.attack-sim-row {
  display: flex; align-items: center; gap: 10px;
  margin-top: 4px;
}
.attack-sim-actor {
  display: flex; flex-direction: column; align-items: center;
  min-width: 90px;
  padding: 8px 10px;
  border: 1.5px solid var(--border);
  border-radius: 6px;
  background: var(--bg);
  text-align: center;
}
.attack-sim-actor .actor-icon { font-size: 22px; line-height: 1; margin-bottom: 4px; }
.attack-sim-actor .actor-label {
  font-size: 11px; font-weight: 600; color: var(--text);
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  line-height: 1.2;
  word-break: break-word;
}
.attack-sim-arrow {
  flex: 1; position: relative; height: 28px;
  display: flex; align-items: center; min-width: 80px;
}
.attack-sim-arrow-label {
  position: absolute; top: 0; left: 50%;
  transform: translateX(-50%);
  font-size: 10px; font-weight: 700;
  letter-spacing: 0.05em; text-transform: uppercase;
  color: var(--accent);
  background: var(--panel);
  padding: 0 8px; white-space: nowrap;
}
.attack-sim-arrow-line {
  flex: 1; height: 2px;
  background: var(--text-muted);
  position: relative;
}
.attack-sim-arrow-line::after {
  content: ''; position: absolute; right: -1px; top: -4px;
  width: 0; height: 0;
  border: 5px solid transparent;
  border-left-color: var(--text-muted);
}
.attack-sim-payload {
  margin-top: 10px;
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 11.5px; color: var(--text);
  background: #f4f1e8;
  border-left: 3px solid var(--accent);
  padding: 6px 10px;
  border-radius: 0 4px 4px 0;
  word-break: break-word;
}
.attack-sim-note {
  margin-top: 6px;
  font-size: 11.5px; color: var(--text-muted);
  font-style: italic; line-height: 1.5;
}
/* Impact scene — terminal beat, no target, painted critical. */
.attack-sim-scene.attack-sim-impact {
  background: linear-gradient(180deg, #fdecea 0%, #fbf3dc 100%);
  border-color: var(--critical);
}
.attack-sim-scene.attack-sim-impact .attack-sim-row {
  justify-content: center;
}
.attack-sim-scene.attack-sim-impact .attack-sim-actor {
  border-color: var(--critical);
  background: var(--panel);
  min-width: 120px;
}
.attack-sim-scene.attack-sim-impact .attack-sim-note {
  text-align: center; color: var(--text); font-style: normal; font-weight: 500;
}
/* Playing mode — scenes start hidden, fade in sequentially, the
   currently-active scene gets an accent ring + lift. */
.attack-sim-list.attack-sim-playing .attack-sim-scene {
  opacity: 0;
  transform: translateY(8px);
  transition: opacity 0.5s ease, transform 0.5s ease, box-shadow 0.3s ease;
}
.attack-sim-list.attack-sim-playing .attack-sim-scene.attack-sim-visible {
  opacity: 1;
  transform: translateY(0);
}
.attack-sim-list.attack-sim-playing .attack-sim-scene.attack-sim-current {
  box-shadow: 0 0 0 2px rgba(44, 95, 126, 0.25);
}
.attack-sim-list.attack-sim-playing .attack-sim-scene.attack-sim-impact.attack-sim-current {
  box-shadow: 0 0 0 2px rgba(179, 38, 30, 0.35);
}
/* v4: per-scene choreography — source pulse, packet travels along arrow,
   target pulse on arrival, payload+note reveal on receipt. Only runs
   while the parent list is in playing mode; static view shows
   everything at once. */
.attack-sim-packet {
  position: absolute; top: 50%; left: 0;
  width: 12px; height: 12px;
  border-radius: 50%;
  background: var(--accent);
  box-shadow: 0 0 8px rgba(44, 95, 126, 0.55);
  transform: translate(-50%, -50%);
  opacity: 0; pointer-events: none;
  z-index: 2;
}
.attack-sim-list.attack-sim-playing .attack-sim-scene .attack-sim-payload,
.attack-sim-list.attack-sim-playing .attack-sim-scene .attack-sim-note {
  opacity: 0;
  transition: opacity 0.45s ease;
}
.attack-sim-list.attack-sim-playing .attack-sim-scene.received .attack-sim-payload,
.attack-sim-list.attack-sim-playing .attack-sim-scene.received .attack-sim-note {
  opacity: 1;
}
.attack-sim-list.attack-sim-playing .attack-sim-scene.source-pulsing
  .attack-sim-row > .attack-sim-actor:first-child {
  animation: agentshield-actor-pulse 0.55s ease;
}
.attack-sim-list.attack-sim-playing .attack-sim-scene.received
  .attack-sim-row > .attack-sim-actor:last-child {
  animation: agentshield-actor-pulse 0.55s ease;
}
.attack-sim-list.attack-sim-playing .attack-sim-scene.packet-flying
  .attack-sim-packet {
  animation: agentshield-packet-fly 0.75s ease-out forwards;
}
.attack-sim-list.attack-sim-playing .attack-sim-scene.attack-sim-impact.impact-active {
  animation: agentshield-impact-flash 0.9s ease;
}
.attack-sim-list.attack-sim-playing .attack-sim-scene.attack-sim-impact.impact-active
  .attack-sim-actor .actor-icon {
  animation: agentshield-impact-icon 0.8s ease;
}
@keyframes agentshield-actor-pulse {
  0%, 100% { transform: scale(1); box-shadow: 0 0 0 0 rgba(44,95,126,0); }
  50% { transform: scale(1.07); box-shadow: 0 0 0 5px rgba(44,95,126,0.2); }
}
@keyframes agentshield-packet-fly {
  0% { left: 0%; opacity: 0; }
  10% { opacity: 1; }
  85% { opacity: 1; }
  100% { left: 100%; opacity: 0.5; }
}
@keyframes agentshield-impact-flash {
  0% { box-shadow: 0 0 0 0 rgba(179,38,30,0); }
  40% { box-shadow: 0 0 0 10px rgba(179,38,30,0.45); }
  100% { box-shadow: 0 0 0 2px rgba(179,38,30,0.35); }
}
@keyframes agentshield-impact-icon {
  0% { transform: scale(0.6); opacity: 0.3; }
  60% { transform: scale(1.3); opacity: 1; }
  100% { transform: scale(1); opacity: 1; }
}
/* v4: mocked red-team probe — looks like watching a live attack run. */
.attack-probe-btn {
  padding: 3px 10px;
  font-size: 11px; font-weight: 600;
  border: 1px solid var(--critical);
  background: transparent;
  color: var(--critical);
  border-radius: 4px;
  cursor: pointer;
  font-family: inherit;
  margin-left: 4px;
}
.attack-probe-btn:hover { background: var(--critical); color: white; }
.attack-probe-btn:disabled { opacity: 0.5; cursor: not-allowed; }
.attack-probe-btn .probe-mode {
  font-weight: 500; opacity: 0.8; font-size: 10px;
}
/* Path B: LIVE mode badge — the probe data came from a real run, not the
   canned narratives library. Bright green to clearly distinguish from
   the (simulated) tag. */
.attack-probe-btn .probe-mode-live {
  font-weight: 700; opacity: 1;
  background: #2f5a2f; color: white;
  padding: 1px 6px; border-radius: 3px;
  letter-spacing: 0.05em;
}
.probe-panel {
  margin-top: 14px;
  border: 1px solid var(--border);
  border-radius: 8px;
  overflow: hidden;
  background: #fafaf7;
}
.probe-meta {
  display: flex; flex-wrap: wrap; gap: 16px;
  padding: 8px 14px;
  background: #f4f1e8;
  border-bottom: 1px solid var(--border);
  font-size: 11px;
}
.probe-meta-row { display: flex; align-items: center; gap: 6px; }
.probe-meta-label {
  font-size: 10px; text-transform: uppercase; letter-spacing: 0.06em;
  color: var(--text-muted); font-weight: 700;
}
.probe-meta code {
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 11px; color: var(--text);
}
.probe-terminal {
  padding: 12px 16px;
  background: #1f2933;
  color: #d4d2c8;
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 12px; line-height: 1.55;
  max-height: 320px; overflow-y: auto;
}
.probe-terminal::-webkit-scrollbar { width: 6px; }
.probe-terminal::-webkit-scrollbar-thumb { background: #4b5563; border-radius: 3px; }
.probe-line {
  padding: 2px 0;
  opacity: 0;
  animation: agentshield-probe-line-in 0.18s ease forwards;
}
.probe-ts { color: #8a8b80; }
.probe-level {
  display: inline-block; min-width: 70px;
  font-weight: 700; text-transform: uppercase; font-size: 10px;
  letter-spacing: 0.05em;
}
.probe-level-info { color: #93b8c8; }
.probe-level-request { color: #c8a86b; }
.probe-level-response { color: #a8c89c; }
.probe-level-success { color: #6fc36f; }
.probe-level-warn { color: #e8b04b; }
.probe-level-error { color: #e88475; }
.probe-level-verdict { color: #ffffff; }
.probe-msg { color: #d4d2c8; word-break: break-word; }
.probe-level-verdict + .probe-msg { font-weight: 700; }

.probe-verdict {
  padding: 14px 16px;
  border-top: 2px solid;
  text-align: center;
}
.probe-verdict-landed {
  background: linear-gradient(180deg, #fdecea 0%, #fbf3dc 100%);
  border-top-color: var(--critical);
}
.probe-verdict-blocked {
  background: linear-gradient(180deg, #d6e7d6 0%, #f0f6ee 100%);
  border-top-color: #2f5a2f;
}
.probe-verdict-inconclusive {
  background: linear-gradient(180deg, #fbf3dc 0%, #faf6e9 100%);
  border-top-color: var(--high);
}
.probe-verdict-badge {
  display: inline-block;
  font-size: 15px; font-weight: 800; letter-spacing: 0.04em;
  padding: 6px 16px;
  border-radius: 999px;
  background: var(--panel);
}
.probe-verdict-landed .probe-verdict-badge { color: var(--critical); }
.probe-verdict-blocked .probe-verdict-badge { color: #2f5a2f; }
.probe-verdict-inconclusive .probe-verdict-badge { color: var(--high); }
.probe-verdict-meta {
  margin-top: 8px;
  font-size: 12px; color: var(--text-muted);
}
.probe-verdict-meta strong {
  font-variant-numeric: tabular-nums; color: var(--text);
}
.probe-verdict-summary {
  margin-top: 8px;
  font-size: 12px; color: var(--text);
  max-width: 540px; margin-left: auto; margin-right: auto;
  line-height: 1.55;
}
@keyframes agentshield-probe-line-in {
  from { opacity: 0; transform: translateY(2px); }
  to   { opacity: 1; transform: translateY(0); }
}
/* Path B+: LLM judge reasoning + harness marker, only rendered when
   the verdict came from a real probe run that used one or both. */
.probe-llm-reasoning {
  margin-top: 10px;
  padding: 10px 14px;
  background: #f0f4f8;
  border-left: 3px solid var(--accent);
  border-radius: 0 4px 4px 0;
  text-align: left;
}
.probe-llm-label {
  font-size: 11px; font-weight: 700;
  color: var(--accent);
  letter-spacing: 0.04em;
  margin-bottom: 6px;
}
.probe-llm-text {
  font-size: 12px; color: var(--text); line-height: 1.55;
}
.probe-harness-note {
  margin-top: 10px;
  padding: 8px 14px;
  background: #fbf3dc;
  border-left: 3px solid var(--defend);
  border-radius: 0 4px 4px 0;
  font-size: 11px; color: #5a3f00;
  text-align: left;
}
.probe-harness-note code {
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-weight: 700;
}

.coverage-grid {
  display: grid;
  grid-template-columns: 160px 1fr;
  gap: 8px 20px;
  align-items: baseline;
}
.coverage-label { font-size: 12px; color: var(--text-muted);
                  text-transform: uppercase; letter-spacing: 0.06em; font-weight: 600; }
.coverage-items { display: flex; flex-wrap: wrap; gap: 4px; }
.coverage-item { font-size: 11px; padding: 2px 8px; border-radius: 4px;
                 background: #ebe7d8; color: #5a4413; font-weight: 600; }
.coverage-empty { font-style: italic; color: var(--text-muted); font-size: 12px; }

footer {
  margin-top: 40px;
  padding-top: 16px;
  border-top: 1px solid var(--border);
  font-size: 11px;
  color: var(--text-muted);
  text-align: center;
}

/* F.21: interactive filter bar + expand-collapse */
.filter-bar {
  position: sticky;
  top: 0;
  z-index: 10;
  background: var(--panel);
  border: 1.5px solid var(--border);
  border-radius: 12px;
  padding: 14px 18px;
  margin-bottom: 20px;
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 10px 16px;
  box-shadow: 0 1px 3px rgba(0,0,0,0.06);  /* F.32: slightly stronger */
}
.filter-bar .filter-group {
  display: flex; align-items: center; flex-wrap: wrap; gap: 6px;
}
.filter-bar .filter-search-group { flex: 1; min-width: 240px; gap: 8px; }
.filter-bar .filter-label {
  font-size: 11px; letter-spacing: 0.08em; text-transform: uppercase;
  color: var(--text-muted); font-weight: 600; margin-right: 4px;
}
.filter-chip {
  display: inline-flex; align-items: center; gap: 5px;
  padding: 3px 9px;
  border-radius: 999px;
  font-size: 11px;
  font-weight: 600;
  letter-spacing: 0.02em;
  text-transform: uppercase;
  cursor: pointer;
  user-select: none;
  background: #ebe7d8;
  color: #5a5547;
  transition: opacity 0.12s ease, transform 0.12s ease;
}
.filter-chip input[type="checkbox"] { display: none; }
.filter-chip:not(.active) { opacity: 0.45; text-decoration: line-through; }
.filter-chip.critical.active { background: var(--critical-bg); color: var(--critical); }
.filter-chip.high.active     { background: var(--high-bg); color: var(--high); }
.filter-chip.medium.active   { background: var(--medium-bg); color: var(--medium); }
.filter-chip.low.active      { background: var(--low-bg); color: var(--low); }
.filter-chip.info.active     { background: var(--info-bg); color: var(--info); }
.filter-chip.cat-detect.active  { background: var(--detect-bg); color: var(--detect); }
.filter-chip.cat-defend.active  { background: var(--defend-bg); color: var(--defend); }
.filter-chip.cat-respond.active { background: var(--respond-bg); color: var(--respond); }
.filter-chip.tier1.active    { background: #efe7d7; color: #5a4413; }
.filter-chip.tier2.active    { background: #d8e5ed; color: #1f4a63; }

.filter-search {
  flex: 1;
  min-width: 200px;
  padding: 6px 12px;
  border: 1px solid var(--border);
  border-radius: 6px;
  font-size: 13px;
  font-family: inherit;
  background: #fafaf7;
  color: var(--text);
  outline: none;
  transition: border-color 0.12s ease;
}
.filter-search:focus { border-color: var(--accent); }
.filter-reset {
  padding: 6px 12px;
  border: 1px solid var(--border);
  border-radius: 6px;
  background: #fafaf7;
  color: var(--text);
  font-size: 12px;
  font-weight: 600;
  cursor: pointer;
  font-family: inherit;
  transition: background 0.12s ease;
}
.filter-reset:hover { background: var(--border); }
.filter-status {
  flex: 1 0 100%;
  font-size: 12px;
  color: var(--text-muted);
  margin-top: 2px;
  min-height: 16px;
}
.filter-status.active { color: var(--accent); font-weight: 600; }

/* hidden by filter (F.28a: per-finding collapse removed —
   Reference-tab groups are the only remaining collapsible UX) */
.finding.filtered-out,
.findings-section.empty-by-filter {
  display: none;
}

/* framework chips become clickable filter triggers */
.finding-tag[role="button"] {
  cursor: pointer;
  transition: background 0.12s ease, color 0.12s ease, transform 0.12s ease;
}
.finding-tag[role="button"]:hover {
  background: var(--accent);
  color: white;
}
.finding-tag.framework-active {
  background: var(--accent);
  color: white;
  box-shadow: 0 0 0 2px rgba(44, 95, 126, 0.18);
}

/* F.22: tabbed layout — D/D/R + Coverage + Reference panels. */
.tab-nav {
  display: flex;
  flex-wrap: wrap;
  gap: 4px;
  border-bottom: 1px solid var(--border);
  margin-bottom: 20px;
  padding: 0 4px;
}
.tab-btn {
  background: transparent;
  border: 1px solid transparent;
  border-radius: 8px;
  padding: 9px 16px;
  font-size: 13px;
  font-weight: 600;
  font-family: inherit;
  color: var(--text-muted);
  cursor: pointer;
  display: inline-flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 2px;
  transition: color 0.12s ease, background 0.12s ease, border-color 0.12s ease;
}
.tab-btn:hover { color: var(--text); background: rgba(0,0,0,0.03); }
/* Active tab: soft accent-tinted background, no border, no card-pull-up
   chrome. Linear / Notion-style. Tint is a low-opacity wash of the
   accent colour so it reads as "this tab is on" without competing
   with the panel content below. */
.tab-btn.active {
  color: var(--accent);
  background: rgba(44, 95, 126, 0.10);
  border-color: transparent;
}
.tab-btn.active:hover { background: rgba(44, 95, 126, 0.14); }

/* Inline SVG tab icons (e.g. the Coverage grid) inherit the tab's
   text colour — muted by default, accent when active — and align
   on the button's text baseline. */
.tab-btn .tab-icon {
  display: inline-block;
  vertical-align: -2px;
  flex-shrink: 0;
}

/* Reference tab pushes to the far right via auto margin — it's
   tool-level reference material, conceptually distinct from anything
   tied to this scan. Coverage sits flush with the D/D/R cluster on
   the left. */
.tab-btn[data-tab="reference"] {
  margin-left: auto;
}
.tab-btn .tab-count {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  min-width: 22px;
  height: 18px;
  padding: 0 6px;
  border-radius: 999px;
  background: #ebe7d8;
  color: #5a5547;
  font-size: 11px;
  font-weight: 700;
  letter-spacing: 0.02em;
}
.tab-btn.active .tab-count { background: var(--accent); color: white; }

/* Instant CSS tooltip — fires on hover with no delay, styled to match
   the report. Used wherever `data-tip="..."` is present (severity
   pills, verdict pills, etc.). The native `title` tooltip is dropped
   in favour of this — `aria-label` carries the same text for screen
   readers, so accessibility is preserved. */
[data-tip] { position: relative; }
[data-tip]:hover::after,
[data-tip]:focus-visible::after {
  content: attr(data-tip);
  position: absolute;
  bottom: calc(100% + 8px);
  left: 50%;
  transform: translateX(-50%);
  z-index: 100;
  min-width: 200px; max-width: 320px;
  padding: 8px 12px;
  background: #1f2933;
  color: #f5f0e6;
  font-size: 12px; font-weight: 400; line-height: 1.5;
  text-transform: none; letter-spacing: 0;
  white-space: normal; text-align: left;
  border-radius: 6px;
  box-shadow: 0 4px 12px rgba(31, 41, 51, 0.22);
  pointer-events: none;
}
/* Small downward arrow under the tooltip pointing at the target. */
[data-tip]:hover::before,
[data-tip]:focus-visible::before {
  content: "";
  position: absolute;
  bottom: calc(100% + 2px);
  left: 50%;
  transform: translateX(-50%);
  z-index: 100;
  border: 6px solid transparent;
  border-top-color: #1f2933;
  pointer-events: none;
}

.tab-panel { display: none; }
.tab-panel.active { display: block; }

/* F.29: static / printable variant — every section visible, stacked. */
.static-section {
  display: block;
  margin: 32px 0;
  scroll-margin-top: 16px;
}
.static-section:first-of-type { margin-top: 0; }
.static-report > .static-section + .static-section {
  border-top: 1px dashed var(--border);
  padding-top: 32px;
}
@media print {
  /* If someone prints the interactive report (Ctrl+P), unfold all
     panels too so the hard-copy isn't just the active tab. */
  .tab-nav, .filter-bar { display: none !important; }
  .tab-panel { display: block !important; page-break-before: always; }
}

.coverage-card {
  background: var(--panel);
  border: 1.5px solid var(--border);
  border-radius: 12px;
  padding: 22px 24px;
  box-shadow: 0 1px 2px rgba(0,0,0,0.04);  /* F.32 */
}
.coverage-card .panel-title { font-size: 16px; font-weight: 600; margin: 0 0 4px; color: var(--text); }
.coverage-card .panel-subtitle {
  font-size: 12px; color: var(--text-muted); margin: 0 0 18px; line-height: 1.5;
}

.framework-group { margin-bottom: 22px; }
.framework-group:last-child { margin-bottom: 0; }
.framework-group-header {
  display: flex; align-items: baseline; justify-content: space-between;
  border-bottom: 1px solid var(--border);
  padding-bottom: 6px;
  margin-bottom: 10px;
}
.framework-group-name {
  font-size: 12px; font-weight: 600; letter-spacing: 0.06em;
  text-transform: uppercase; color: var(--text);
}
.framework-group-link {
  font-size: 11px; color: var(--accent); text-decoration: none; font-weight: 600;
}
.framework-group-link:hover { text-decoration: underline; }
.framework-empty { font-size: 12px; color: var(--text-muted); font-style: italic; }
.framework-items {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(220px, 1fr));
  gap: 6px 8px;
}
.framework-item {
  display: flex; align-items: center; justify-content: space-between;
  gap: 8px;
  padding: 8px 12px;
  border: 1px solid var(--border);
  border-radius: 6px;
  background: var(--bg);
  cursor: pointer;
  font-family: inherit;
  text-align: left;
  transition: background 0.12s ease, border-color 0.12s ease, color 0.12s ease;
}
.framework-item:hover { background: var(--panel); border-color: var(--accent); }
.framework-item.framework-active {
  background: var(--accent); color: white; border-color: var(--accent);
}
.framework-item.framework-active .framework-item-count {
  background: rgba(255,255,255,0.22); color: white;
}
.framework-item-id { font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
                     font-size: 12px; font-weight: 600; }
.framework-item-count {
  font-size: 11px; font-weight: 600;
  padding: 2px 8px; border-radius: 999px;
  background: #ebe7d8; color: #5a5547;
}

/* Coverage Matrix — 3-state chips (issues / clean / not-scanned).
   Separate from the Frameworks tab's clickable-filter chips. */
.coverage-summary {
  display: flex; flex-wrap: wrap; align-items: baseline;
  gap: 6px 14px; margin-bottom: 10px;
  font-size: 12px; color: var(--text-muted);
}
.coverage-summary .cov-headline {
  font-size: 13px; font-weight: 600; color: var(--text);
}
.coverage-summary .cov-stat { font-variant-numeric: tabular-nums; }
.coverage-summary .cov-stat-issues  { color: #b8261d; font-weight: 600; }
.coverage-summary .cov-stat-clean   { color: #1f6b3a; font-weight: 600; }
.coverage-summary .cov-stat-gap     { color: #6e6655; font-weight: 600; }

.coverage-chips {
  display: flex; flex-wrap: wrap; gap: 6px 6px;
  margin-bottom: 4px;
}
.coverage-chip {
  display: inline-flex; align-items: center; gap: 6px;
  padding: 5px 10px;
  border: 1px solid transparent;
  border-radius: 999px;
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 11.5px; font-weight: 600;
  cursor: help;
}
.coverage-chip .cov-chip-count {
  font-variant-numeric: tabular-nums;
  font-size: 10.5px; font-weight: 700;
  padding: 0 6px; border-radius: 999px;
  background: rgba(0,0,0,0.08);
}
.coverage-chip-issues {
  background: #fbe6e3; border-color: #e9b4ad; color: #8a1d15;
}
.coverage-chip-issues .cov-chip-count { background: #b8261d; color: white; }
.coverage-chip-clean {
  background: #e3f1e5; border-color: #b3d6b9; color: #1f6b3a;
}
.coverage-chip-gap {
  background: #f0ede4; border-color: #d9d2bf; color: #6e6655;
  opacity: 0.85;
}
.coverage-legend {
  display: flex; flex-wrap: wrap; gap: 6px 14px;
  font-size: 11px; color: var(--text-muted);
  margin-bottom: 14px;
}
.coverage-legend .leg-swatch {
  display: inline-block; width: 10px; height: 10px;
  border-radius: 999px; margin-right: 5px; vertical-align: -1px;
}
.coverage-legend .leg-swatch-issues { background: #b8261d; }
.coverage-legend .leg-swatch-clean  { background: #1f6b3a; }
.coverage-legend .leg-swatch-gap    { background: #b3aa92; }
.coverage-fw-note {
  font-size: 11px; color: var(--text-muted);
  font-style: italic; margin-top: -2px; margin-bottom: 10px;
}

/* Per-framework "why N items are not scanned" disclosure. Tooltips on
   gray chips give the same info, but tooltips don't render in print /
   PDF — this details block does. Stays collapsed by default to keep
   the matrix dense. */
.coverage-gap-details {
  margin-top: 6px; margin-bottom: 0;
  font-size: 11.5px; color: var(--text-muted);
}
.coverage-gap-details summary {
  cursor: pointer; display: inline-flex; align-items: baseline; gap: 6px;
  padding: 4px 10px;
  border: 1px dashed var(--border); border-radius: 6px;
  background: transparent;
  font-size: 11px; font-weight: 600;
  color: var(--text-muted);
  user-select: none;
}
.coverage-gap-details summary:hover { color: var(--text); border-color: var(--accent); }
.coverage-gap-details[open] summary { margin-bottom: 8px; }
.coverage-gap-list {
  margin: 0; padding-left: 18px;
  list-style: disc;
  line-height: 1.55;
}
.coverage-gap-list li { margin-bottom: 4px; }
.coverage-gap-list code {
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 11px; font-weight: 600;
  padding: 1px 6px; border-radius: 4px;
  background: #f0ede4; color: #6e6655;
}
/* In the static / print variant the details block is rendered with the
   `open` attribute so the gap reasons are part of the hard-copy without
   relying on @media print hacks. */
.static-report .coverage-gap-details[open] summary { margin-bottom: 6px; }

/* v4: Input & Output tab — what was scanned, where results were written. */
.io-summary {
  font-size: 11px; color: var(--text-muted); font-weight: 500;
  font-variant-numeric: tabular-nums;
}
.io-subsection { margin-bottom: 14px; }
.io-subsection:last-child { margin-bottom: 0; }
.io-subtitle {
  font-size: 11px; color: var(--text-muted); font-weight: 600;
  text-transform: uppercase; letter-spacing: 0.06em;
  margin-bottom: 6px;
}
.io-list {
  list-style: none; padding: 0; margin: 0;
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
  gap: 4px 8px;
}
.io-list li {
  font-size: 12px;
  padding: 7px 10px;
  border: 1px solid var(--border);
  border-radius: 6px;
  background: var(--bg);
  line-height: 1.4;
}
.io-list li.io-file {
  display: flex; flex-direction: column; gap: 4px;
}
.io-list code {
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 12px;
  color: var(--text);
}
.io-list .io-desc { color: var(--text-muted); font-size: 11px; }
.io-count {
  font-size: 11px; font-weight: 600; color: var(--high);
  display: inline-flex; align-items: center; gap: 6px;
}
.io-count .io-dot {
  width: 7px; height: 7px; border-radius: 50%;
  background: currentColor; display: inline-block;
}
.io-count-clean { color: var(--low); font-weight: 500; }
.io-count-clean .io-dot {
  background: transparent;
  border: 1.5px solid currentColor;
  width: 6px; height: 6px;
}

/* v4: pipeline view — 3 columns (Input → Engines → Output) with arrows. */
.io-pipeline {
  display: grid;
  grid-template-columns: 1fr auto 1fr auto 1fr;
  gap: 0;
  align-items: stretch;
  margin-top: 8px;
}
.io-pipeline-col {
  background: var(--bg);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 16px 18px;
  display: flex; flex-direction: column;
  min-width: 0;
}
.io-pipeline-col.io-col-engine {
  background: linear-gradient(180deg, #f4f8fb 0%, #fafaf7 100%);
  border-color: var(--accent);
}
.io-pipeline-arrow {
  display: flex; align-items: center; justify-content: center;
  padding: 0 14px;
  font-size: 22px; color: var(--text-muted);
  font-weight: 300;
}
.io-col-title {
  font-size: 11px; text-transform: uppercase; letter-spacing: 0.08em;
  color: var(--text-muted); font-weight: 700;
}
.io-col-engine .io-col-title { color: var(--accent); }
.io-col-subtitle {
  font-size: 12px; color: var(--text-muted); margin-top: 2px;
}
.io-col-summary {
  font-size: 18px; font-weight: 700; color: var(--text);
  margin-top: 10px; margin-bottom: 4px;
  font-variant-numeric: tabular-nums;
}
.io-col-summary-sub {
  font-size: 12px; color: var(--text-muted); font-weight: 500;
}
.io-col-section {
  font-size: 10px; text-transform: uppercase; letter-spacing: 0.06em;
  color: var(--text-muted); font-weight: 600;
  margin-top: 14px; margin-bottom: 6px;
  padding-top: 10px; border-top: 1px dashed var(--border);
}
.io-col-list {
  list-style: none; padding: 0; margin: 0;
  display: flex; flex-direction: column; gap: 4px;
}
.io-col-list li {
  font-size: 12px;
  padding: 6px 8px;
  border: 1px solid var(--border);
  border-radius: 5px;
  background: var(--panel);
  display: flex; justify-content: space-between; align-items: baseline;
  gap: 10px;
  flex-wrap: wrap;
}
.io-col-list li code {
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 11.5px; color: var(--text);
}
.io-col-list .io-desc { font-size: 11px; color: var(--text-muted); }
.io-col-engine-rows {
  margin-top: 10px;
  display: flex; flex-direction: column; gap: 6px;
}
.io-col-engine-row {
  display: flex; justify-content: space-between; align-items: baseline;
  font-size: 13px;
  padding: 4px 0;
}
.io-col-engine-val {
  font-weight: 700; font-variant-numeric: tabular-nums;
  font-size: 14px;
}
.io-col-engine-net {
  display: flex; justify-content: space-between; align-items: baseline;
  margin-top: 8px;
  padding-top: 10px;
  border-top: 1.5px solid var(--accent);
  font-size: 16px; font-weight: 700; color: var(--accent);
}
.io-col-sev-bar {
  display: flex; gap: 4px; flex-wrap: wrap;
}
.io-col-sev-bar .pill { padding: 3px 9px; font-size: 10px; }

.io-engine-list {
  list-style: none; padding: 0; margin: 8px 0 0;
  display: flex; flex-direction: column; gap: 10px;
}
.io-engine-phase {
  margin-top: 16px;
  font-size: 11px; font-weight: 700;
  letter-spacing: 0.06em; text-transform: uppercase;
  color: var(--accent);
  padding-bottom: 4px;
  border-bottom: 1px dashed var(--border);
}
.io-engine-phase:first-of-type { margin-top: 12px; }
.io-engine-phase-probe { color: var(--critical); }
.io-engine-list li {
  padding: 12px 14px;
  border: 1px solid var(--border);
  border-radius: 6px;
  background: var(--panel);
}
.io-engine-name {
  font-size: 13px; font-weight: 700; color: var(--text);
  margin-bottom: 4px;
}
.io-engine-desc { font-size: 11px; color: var(--text-muted); line-height: 1.4; }

.io-col-list-fix li.io-fix-item {
  flex-direction: column; align-items: stretch; gap: 6px;
}
.io-fix-head { display: flex; justify-content: space-between; gap: 8px; flex-wrap: wrap; }
.io-fix-target {
  font-size: 11px; font-weight: 600; color: var(--high);
  display: inline-flex; align-items: baseline; gap: 6px;
  flex-wrap: wrap;
}
.io-fix-target .io-dot {
  width: 7px; height: 7px; border-radius: 50%;
  background: currentColor; display: inline-block; align-self: center;
}
.io-fix-target code.io-fix-files {
  font-weight: 500; font-size: 11px;
  color: var(--text); background: transparent;
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
}

@media (max-width: 1100px) {
  .io-pipeline { grid-template-columns: 1fr; gap: 10px; }
  .io-pipeline-arrow { transform: rotate(90deg); padding: 4px 0; }
}

/* F.26: Reference tab — "what AgentShield checks for" cards. */
.reference-card {
  background: var(--panel);
  border: 1.5px solid var(--border);
  border-radius: 12px;
  padding: 22px 24px;
  box-shadow: 0 1px 2px rgba(0,0,0,0.04);  /* F.32 */
}
.ref-source-group { margin-bottom: 28px; }
.ref-source-group:last-child { margin-bottom: 0; }
.ref-source-header {
  border-bottom: 1px solid var(--border);
  padding-bottom: 8px;
  margin-bottom: 14px;
}
.ref-source-name {
  display: flex; align-items: baseline; gap: 8px;
  font-size: 13px; font-weight: 700; letter-spacing: 0.06em;
  text-transform: uppercase; color: var(--text);
}
.ref-source-count {
  font-size: 11px; font-weight: 600;
  padding: 2px 9px; border-radius: 999px;
  background: var(--accent); color: white;
  letter-spacing: 0.02em; text-transform: none;
}
.ref-source-blurb {
  display: block; margin-top: 4px;
  font-size: 12px; color: var(--text-muted); font-weight: 400;
  text-transform: none; letter-spacing: 0; line-height: 1.5;
}
.ref-empty {
  font-size: 12px; color: var(--text-muted); font-style: italic;
  padding: 8px 0;
}
.ref-cards {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(360px, 1fr));
  gap: 12px;
}

/* F.28: collapsible D/D/R sub-group inside each source */
.ref-group {
  border: 1px solid var(--border);
  border-radius: 8px;
  margin-bottom: 8px;
  background: var(--bg);
}
.ref-group:last-child { margin-bottom: 0; }
.ref-group-summary {
  cursor: pointer;
  user-select: none;
  padding: 10px 14px;
  display: flex; align-items: baseline; gap: 12px;
  font-size: 13px;
  list-style: none;
  border-radius: 8px;
  transition: background 0.12s ease;
}
.ref-group-summary::-webkit-details-marker { display: none; }
.ref-group-summary:hover { background: rgba(0,0,0,0.02); }
.ref-group-summary::before {
  content: "▸";
  display: inline-block;
  color: var(--text-muted);
  font-size: 11px;
  width: 12px;
  transition: transform 0.18s ease;
}
.ref-group[open] > .ref-group-summary::before { transform: rotate(90deg); }
.ref-group-name { font-weight: 600; }
.ref-group-sub { color: var(--text-muted); font-size: 12px; flex: 1; }
.ref-group-count {
  font-size: 11px; font-weight: 600;
  padding: 2px 9px; border-radius: 999px;
  background: #ebe7d8; color: #5a5547;
  letter-spacing: 0.02em;
}
.ref-group.ref-group-detect  > .ref-group-summary { border-left: 4px solid var(--detect); }
.ref-group.ref-group-defend  > .ref-group-summary { border-left: 4px solid var(--defend); }
.ref-group.ref-group-respond > .ref-group-summary { border-left: 4px solid var(--respond); }
.ref-group .ref-cards { padding: 12px 14px 14px; }
.ref-card-item {
  background: var(--bg);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 14px 16px;
}
.ref-card-head {
  display: flex; flex-wrap: wrap; align-items: center; gap: 6px;
  margin-bottom: 6px;
}
.ref-id {
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 12px; font-weight: 600; color: var(--text);
}
.ref-legacy {
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 10px; color: var(--text-muted);
  font-style: italic; opacity: 0.75;
}
.ref-langs {
  font-size: 11px; color: var(--text-muted);
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
}
.ref-cat {
  font-size: 10px; font-weight: 600; padding: 2px 8px;
  border-radius: 4px; letter-spacing: 0.04em; text-transform: uppercase;
}
.ref-cat-detect  { background: var(--detect-bg);  color: var(--detect); }
.ref-cat-defend  { background: var(--defend-bg);  color: var(--defend); }
.ref-cat-respond { background: var(--respond-bg); color: var(--respond); }

.ref-card-item .ref-title {
  font-size: 13px; font-weight: 600; color: var(--text);
  margin: 4px 0 6px;
}
.ref-desc { font-size: 12px; color: var(--text); line-height: 1.5; margin-bottom: 8px; }
/* Path B+: SDK coverage footnote — "Covers: OpenAI, Anthropic, …" */
.ref-sdks {
  font-size: 11px; color: var(--text-muted);
  margin-bottom: 8px; line-height: 1.5;
}
.ref-sdks-label {
  font-weight: 700; color: var(--text);
  text-transform: uppercase; letter-spacing: 0.05em;
  font-size: 10px; margin-right: 4px;
}
.ref-sdks-agnostic { font-style: italic; }
.ref-fw { display: flex; flex-wrap: wrap; gap: 4px; margin-bottom: 8px; }
.ref-skip { margin-bottom: 8px; }
.ref-skip summary {
  font-size: 11px; color: var(--text-muted); cursor: pointer;
  font-weight: 600; letter-spacing: 0.02em; text-transform: uppercase;
}
.ref-skip summary:hover { color: var(--text); }
.ref-skip p {
  font-size: 12px; color: var(--text-muted);
  margin: 6px 0 0; padding-left: 12px;
  border-left: 2px solid var(--border); line-height: 1.5;
}
.ref-remediation {
  font-size: 12px; color: var(--text-muted);
  padding-left: 12px; border-left: 2px solid var(--border);
  line-height: 1.5;
}

/* v4: "How AgentShield works" flowchart at the bottom of the
   Reference tab. Pure HTML/CSS — no SVG, prints cleanly. Five
   numbered stage cards stacked vertically with chevron arrows
   between them. Stages 2 and 3 split into two parallel sub-boxes
   for the rules / LLM and orchestrator / classifier pairs. */
.how-it-works {
  margin-top: 32px; padding-top: 24px;
  border-top: 2px dashed var(--border);
}
.how-title {
  font-size: 18px; font-weight: 700;
  color: var(--text); margin: 0 0 4px;
}
.how-subtitle {
  font-size: 13px; color: var(--text-muted);
  margin: 0 0 20px; line-height: 1.55;
}
.how-subtitle code {
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 12px; padding: 1px 5px;
  background: #f4f1e8; border-radius: 3px;
}
.how-stages {
  display: flex; flex-direction: column; align-items: stretch;
  gap: 0;
}
.how-stage {
  background: var(--panel);
  border: 1.5px solid var(--border);
  border-left: 4px solid var(--accent);
  border-radius: 8px;
  padding: 14px 18px;
  box-shadow: 0 1px 2px rgba(0,0,0,0.04);
}
.how-stage-input   { border-left-color: var(--info); }
.how-stage-static  { border-left-color: var(--accent); }
.how-stage-runtime { border-left-color: var(--critical); }
.how-stage-merge   { border-left-color: var(--low); }
.how-stage-output  { border-left-color: var(--text-muted); }
.how-stage-head {
  display: flex; align-items: center; gap: 12px;
  margin-bottom: 8px;
}
.how-stage-num {
  display: inline-flex; align-items: center; justify-content: center;
  width: 26px; height: 26px;
  border-radius: 50%;
  background: var(--accent); color: white;
  font-weight: 700; font-size: 13px;
  font-variant-numeric: tabular-nums;
}
.how-stage-input   .how-stage-num { background: var(--info); }
.how-stage-runtime .how-stage-num { background: var(--critical); }
.how-stage-merge   .how-stage-num { background: var(--low); }
.how-stage-output  .how-stage-num { background: var(--text-muted); }
.how-stage-title {
  font-size: 14px; font-weight: 700;
  color: var(--text);
  display: inline-flex; align-items: baseline; gap: 10px;
}
.how-stage-phase {
  font-size: 10px; font-weight: 600;
  letter-spacing: 0.06em; text-transform: uppercase;
  color: var(--accent);
  padding: 2px 8px; border-radius: 3px;
  background: rgba(44, 95, 126, 0.10);
}
.how-stage-phase-optional {
  color: var(--critical);
  background: rgba(179, 38, 30, 0.10);
}
.how-stage-body { padding-left: 38px; }
.how-list {
  margin: 0; padding-left: 18px;
  font-size: 12.5px; color: var(--text); line-height: 1.65;
}
.how-list li { margin-bottom: 4px; }
.how-list code, .how-sub-list code, .how-sub-out code {
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 11.5px;
  background: #f4f1e8; padding: 1px 5px; border-radius: 3px;
  color: var(--text);
}
.how-substages {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 12px;
}
.how-sub-box {
  background: var(--bg);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 10px 14px;
}
.how-sub-title {
  font-size: 12px; font-weight: 700;
  color: var(--text); margin-bottom: 6px;
}
.how-sub-list {
  margin: 0; padding-left: 16px;
  font-size: 12px; color: var(--text); line-height: 1.55;
}
.how-sub-list li { margin-bottom: 3px; }
.how-sub-out {
  margin-top: 8px;
  font-size: 11px; color: var(--text-muted);
  font-style: italic;
}
.how-arrow {
  align-self: center;
  margin: 4px 0;
  font-size: 18px;
  color: var(--text-muted);
  line-height: 1;
}
.how-arrow-optional { color: var(--critical); opacity: 0.7; }
.how-stage-note {
  margin: 14px 0 0;
  padding: 10px 14px;
  background: #f4f1e8; border-left: 3px solid var(--info);
  border-radius: 0 4px 4px 0;
  font-size: 11.5px; color: var(--text);
  line-height: 1.55;
}
.how-stage-note code {
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 11px; padding: 1px 5px;
  background: var(--panel); border-radius: 3px;
}

@media (max-width: 800px) {
  .how-substages { grid-template-columns: 1fr; }
  .how-stage-body { padding-left: 0; }
}
"""


_HTML_JS = """
(function () {
  // ----- DOM lookup -----
  var findings = Array.prototype.slice.call(document.querySelectorAll('.finding[data-severity]'));
  var sections = Array.prototype.slice.call(document.querySelectorAll('.findings-section[data-section]'));
  var filterCheckboxes = Array.prototype.slice.call(document.querySelectorAll('.filter-chip input[data-filter]'));
  var searchBox = document.getElementById('finding-search');
  var resetBtn = document.getElementById('filter-reset');
  var statusEl = document.getElementById('filter-status');

  // Mark each filter-chip with .active mirroring its checkbox state.
  function syncChipClass(input) {
    var chip = input.closest('.filter-chip');
    if (chip) chip.classList.toggle('active', input.checked);
  }
  filterCheckboxes.forEach(syncChipClass);

  // ----- single source of truth: framework filter (set of "field:value") -----
  var activeFrameworkFilters = new Set();

  // ----- compute visibility for one finding -----
  function findingMatches(f) {
    // Severity / category / origin: must be in active set.
    var sev = f.getAttribute('data-severity');
    var cat = f.getAttribute('data-category');
    var origin = f.getAttribute('data-origin');
    if (!isChecked('severity', sev)) return false;
    if (!isChecked('category', cat)) return false;
    if (!isChecked('origin', origin)) return false;
    // Framework drill-down: if any framework filter is active, the finding
    // must carry at least one of those framework keys.
    if (activeFrameworkFilters.size > 0) {
      var fw = (f.getAttribute('data-frameworks') || '').split(/\\s+/);
      var hit = false;
      activeFrameworkFilters.forEach(function (k) { if (fw.indexOf(k) !== -1) hit = true; });
      if (!hit) return false;
    }
    // Search: case-insensitive substring on the prebuilt search blob.
    var q = (searchBox.value || '').trim().toLowerCase();
    if (q && (f.getAttribute('data-search') || '').indexOf(q) === -1) return false;
    return true;
  }

  function isChecked(filterName, value) {
    var input = document.querySelector('.filter-chip input[data-filter="' + filterName + '"][value="' + value + '"]');
    return input ? input.checked : true;
  }

  // ----- apply filter: hide non-matching findings, hide empty sections,
  //       update D/D/R hero counts + section counts + status line -----
  function applyFilter() {
    var visiblePerCat = { detect: 0, defend: 0, respond: 0 };
    // F.25: track per-category per-severity visible counts, used to
    // re-render the section-severity pills live as filters change.
    var visiblePerCatSev = {
      detect:  { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
      defend:  { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
      respond: { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
    };
    findings.forEach(function (f) {
      var visible = findingMatches(f);
      f.classList.toggle('filtered-out', !visible);
      if (visible) {
        var c = f.getAttribute('data-category');
        var s = f.getAttribute('data-severity');
        visiblePerCat[c]++;
        if (visiblePerCatSev[c] && (s in visiblePerCatSev[c])) {
          visiblePerCatSev[c][s]++;
        }
      }
    });

    sections.forEach(function (s) {
      var cat = s.getAttribute('data-section');
      // Hide section entirely if no visible non-empty findings AND no
      // .finding-empty placeholder (keep the "No findings" placeholder
      // visible if every real finding is filtered out — feels less
      // jarring than the section vanishing).
      var visible = visiblePerCat[cat];
      var totalCard = s.querySelector('[data-section-count]');
      if (totalCard) {
        var total = parseInt(totalCard.getAttribute('data-section-total'), 10);
        if (visible === total) {
          totalCard.textContent = total + ' finding' + (total === 1 ? '' : 's');
        } else {
          totalCard.textContent = visible + ' of ' + total + ' finding' + (total === 1 ? '' : 's');
        }
      }
      // F.25: rebuild severity-pill breakdown from visiblePerCatSev. We
      // wipe and re-render rather than toggling display on per-pill nodes
      // so counts stay accurate as the visible set shrinks/grows.
      var sevSpan = s.querySelector('[data-section-severity]');
      if (sevSpan) {
        var sevs = ['critical','high','medium','low','info'];
        var sevHtml = '';
        sevs.forEach(function (sev) {
          var n = (visiblePerCatSev[cat] || {})[sev] || 0;
          var totN = parseInt(sevSpan.getAttribute('data-section-total-' + sev) || '0', 10);
          if (n === 0 && totN === 0) return;
          if (n === 0) return;  // hide pills with zero-after-filter
          var label = (n === totN) ? (n + ' ' + sev) : (n + '/' + totN + ' ' + sev);
          sevHtml += '<span class="sev-mini ' + sev + '" data-section-sev="' + sev + '">'
                  +  label + '</span>';
        });
        sevSpan.innerHTML = sevHtml;
      }
    });

    // Update D/D/R hero cards.
    Object.keys(visiblePerCat).forEach(function (cat) {
      var el = document.querySelector('[data-ddr-count="' + cat + '"]');
      if (!el) return;
      var total = parseInt(el.getAttribute('data-ddr-total'), 10);
      el.textContent = visiblePerCat[cat] === total
        ? total
        : visiblePerCat[cat] + '/' + total;
    });

    // F.22: update tab-count pills next to each D/D/R tab button.
    Object.keys(visiblePerCat).forEach(function (cat) {
      var tabCount = document.querySelector('[data-tab-count="' + cat + '"]');
      if (!tabCount) return;
      var total = parseInt(tabCount.getAttribute('data-tab-total'), 10);
      tabCount.textContent = visiblePerCat[cat] === total
        ? total
        : visiblePerCat[cat] + '/' + total;
    });

    // Status line.
    var totalVisible = visiblePerCat.detect + visiblePerCat.defend + visiblePerCat.respond;
    var grandTotal = findings.length;
    var anyFilterActive = (
      filterCheckboxes.some(function (c) { return !c.checked; }) ||
      (searchBox.value || '').trim().length > 0 ||
      activeFrameworkFilters.size > 0
    );
    if (anyFilterActive) {
      var bits = ['Showing ' + totalVisible + ' of ' + grandTotal + ' findings'];
      if (activeFrameworkFilters.size > 0) {
        bits.push('framework: ' + Array.from(activeFrameworkFilters).join(', '));
      }
      statusEl.textContent = bits.join(' · ');
      statusEl.classList.add('active');
    } else {
      statusEl.textContent = '';
      statusEl.classList.remove('active');
    }
  }

  // ----- wire chip clicks -----
  filterCheckboxes.forEach(function (input) {
    input.addEventListener('change', function () {
      syncChipClass(input);
      applyFilter();
    });
  });

  // ----- wire search input -----
  searchBox.addEventListener('input', applyFilter);

  // ----- wire reset button -----
  resetBtn.addEventListener('click', function () {
    filterCheckboxes.forEach(function (c) {
      c.checked = true;
      syncChipClass(c);
    });
    searchBox.value = '';
    activeFrameworkFilters.clear();
    document.querySelectorAll('.finding-tag.framework-active').forEach(function (t) {
      t.classList.remove('framework-active');
    });
    applyFilter();
  });

  // ----- wire framework drill-down (per-finding tags + Frameworks-panel buttons) -----
  function toggleFrameworkFilter(key) {
    if (activeFrameworkFilters.has(key)) {
      activeFrameworkFilters.delete(key);
    } else {
      activeFrameworkFilters.add(key);
    }
    // Sync visual state on every clickable framework-key node — both the
    // small per-finding chips and the bigger Frameworks-tab buttons share
    // the same `data-framework-key` attribute and `framework-active` class.
    document.querySelectorAll('[data-framework-key]').forEach(function (t) {
      var k = t.getAttribute('data-framework-key');
      t.classList.toggle('framework-active', activeFrameworkFilters.has(k));
    });
    applyFilter();
    // F.22: when filtering from the Frameworks tab, jump straight to Detect
    // so the user immediately sees the filter outcome — otherwise the
    // numbers update silently behind a tab they're not looking at.
    if (activeFrameworkFilters.size > 0) {
      var anyDdrVisible = ['detect', 'defend', 'respond'].some(function (cat) {
        var btn = document.querySelector('.tab-btn[data-tab="' + cat + '"]');
        return btn && btn.classList.contains('active');
      });
      if (!anyDdrVisible) activateTab('detect');
    }
  }
  document.querySelectorAll('[data-framework-key]').forEach(function (t) {
    t.addEventListener('click', function (e) {
      e.stopPropagation();
      toggleFrameworkFilter(t.getAttribute('data-framework-key'));
    });
    t.addEventListener('keydown', function (e) {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        toggleFrameworkFilter(t.getAttribute('data-framework-key'));
      }
    });
  });

  // ----- F.22: tab switching -----
  var tabButtons = Array.prototype.slice.call(document.querySelectorAll('.tab-btn[data-tab]'));
  var tabPanels = Array.prototype.slice.call(document.querySelectorAll('.tab-panel[data-panel]'));
  function activateTab(name) {
    tabButtons.forEach(function (b) {
      var on = b.getAttribute('data-tab') === name;
      b.classList.toggle('active', on);
      b.setAttribute('aria-selected', on ? 'true' : 'false');
    });
    tabPanels.forEach(function (p) {
      p.classList.toggle('active', p.getAttribute('data-panel') === name);
    });
  }
  tabButtons.forEach(function (b) {
    b.addEventListener('click', function () { activateTab(b.getAttribute('data-tab')); });
  });

  // F.28a: per-finding expand/collapse removed. Reference-tab D/D/R
  // sub-groups are now the only collapsible UX in the report.

  // ----- v4: ▶ Play simulation — animate attack walkthrough.
  // Two render modes:
  //   1. Visual scenes (.attack-sim-list)  → preferred. Scenes are hidden
  //      while playing; each fades in on a cadence and gets an "active"
  //      ring; the previous scene loses the ring when the next appears.
  //   2. Prose <ol> (.attack-steps)        → fallback for narratives
  //      without structured simulation data. Lines just fade in.
  // v4: mocked red-team probe — when 'Run probe' is pressed, slide the
  // panel open and stream the canned trace lines, then reveal the
  // verdict. Looks like watching a live probe; entirely client-side.
  document.querySelectorAll('.attack-probe-btn').forEach(function (btn) {
    btn.addEventListener('click', function () {
      var section = btn.closest('.attack-steps-section');
      if (!section) return;
      var panel = section.querySelector('.probe-panel');
      if (!panel) return;
      var lines = panel.querySelectorAll('.probe-line');
      var verdict = panel.querySelector('.probe-verdict');
      // Reset
      lines.forEach(function (l) { l.hidden = true; });
      if (verdict) verdict.hidden = true;
      panel.hidden = false;
      btn.disabled = true;
      btn.innerHTML = '⏵ Probing…';
      // v4 (Path B+): scroll the panel into view so the streaming
      // terminal is visible immediately. Defer one frame so the
      // browser registers `hidden=false` before measuring layout.
      requestAnimationFrame(function () {
        panel.scrollIntoView({ behavior: 'smooth', block: 'start' });
      });
      // Random-ish cadence to feel like real probe traffic.
      var t = 0;
      lines.forEach(function (line, i) {
        var delay = 200 + Math.floor(Math.random() * 250);
        // Slow down briefly after request/response lines so the eye
        // can track them.
        var level = line.getAttribute('data-level');
        if (level === 'request' || level === 'response') delay += 150;
        if (level === 'verdict') delay += 300;
        t += delay;
        setTimeout(function () {
          line.hidden = false;
          var term = panel.querySelector('.probe-terminal');
          if (term) term.scrollTop = term.scrollHeight;
        }, t);
      });
      setTimeout(function () {
        if (verdict) verdict.hidden = false;
        verdict.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        btn.disabled = false;
        btn.innerHTML = '↻ Re-run probe <span class="probe-mode">(simulated)</span>';
      }, t + 500);
    });
  });

  document.querySelectorAll('.attack-play-btn').forEach(function (btn) {
    btn.addEventListener('click', function () {
      var section = btn.closest('.attack-steps-section');
      if (!section) return;
      var simList = section.querySelector('.attack-sim-list');
      var proseList = section.querySelector('.attack-steps');
      btn.disabled = true;
      btn.textContent = '⏵ Playing…';

      if (simList) {
        var scenes = simList.querySelectorAll('.attack-sim-scene');
        var SCENE_CADENCE = 1900;  // ms per scene — long enough to let
                                   // the choreography finish before the
                                   // next scene begins.
        simList.classList.add('attack-sim-playing');
        // Reset every scene to its pre-play state.
        scenes.forEach(function (s) {
          s.classList.remove('attack-sim-visible');
          s.classList.remove('attack-sim-current');
          s.classList.remove('source-pulsing');
          s.classList.remove('packet-flying');
          s.classList.remove('received');
          s.classList.remove('impact-active');
        });
        scenes.forEach(function (scene, i) {
          setTimeout(function () {
            if (i > 0) {
              scenes[i - 1].classList.remove('attack-sim-current');
            }
            scene.classList.add('attack-sim-visible');
            scene.classList.add('attack-sim-current');
            scene.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
            var isImpact = scene.classList.contains('attack-sim-impact');
            if (isImpact) {
              // Impact: full-card flash + icon punch-in + note reveal.
              setTimeout(function () { scene.classList.add('impact-active'); }, 50);
              setTimeout(function () { scene.classList.add('received'); }, 250);
            } else {
              // Normal scene choreography:
              //   100ms — source actor pulses
              //   350ms — packet leaves source
              //  1100ms — packet has arrived → target pulses, payload reveals
              setTimeout(function () { scene.classList.add('source-pulsing'); }, 100);
              setTimeout(function () { scene.classList.add('packet-flying'); }, 350);
              setTimeout(function () { scene.classList.add('received'); }, 1100);
            }
            if (i === scenes.length - 1) {
              setTimeout(function () {
                btn.disabled = false;
                btn.textContent = '↻ Replay simulation';
              }, 1400);
            }
          }, i * SCENE_CADENCE);
        });
      } else if (proseList) {
        var steps = proseList.querySelectorAll('.attack-step');
        proseList.classList.add('attack-steps-playing');
        steps.forEach(function (s) { s.classList.remove('attack-step-visible'); });
        steps.forEach(function (step, i) {
          setTimeout(function () {
            step.classList.add('attack-step-visible');
            if (i === steps.length - 1) {
              setTimeout(function () {
                btn.disabled = false;
                btn.textContent = '↻ Replay simulation';
              }, 600);
            }
          }, (i + 1) * 700);
        });
      } else {
        btn.disabled = false;
        btn.textContent = '▶ Play simulation';
      }
    });
  });

  // initial render
  applyFilter();
})();
"""


def _html_escape(s: str) -> str:
    """Minimal HTML escape. We don't import html.escape at module level
    just for one tiny call site — keep dep surface small."""
    return (
        str(s)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def _tier2_display_slugs() -> dict[str, str]:
    """F.31: build `rule_id → display-slug` for Tier 2 entries.

    Copilot writes findings with a canonical `AS-C-D-LLM01-002` rule_id
    but no `rule_id_short`. To match the Semgrep card layout (which
    shows the human-readable slug `unsanitized-user-input-to-llm`),
    we look up each Tier 2 entry's title from the bundled checklist
    and slugify it. Returns `{}` if the checklist file is missing.
    Cached implicitly by the merger's per-call render path — cheap.
    """
    from agentshield.merger.reference import parse_tier2_checklist

    if not _DEFAULT_CHECKLIST_PATH.exists():
        return {}
    refs = parse_tier2_checklist(
        _DEFAULT_CHECKLIST_PATH.read_text(encoding="utf-8")
    )
    out: dict[str, str] = {}
    for ref in refs:
        slug = _slugify_title(ref.title)
        if slug:
            out[ref.rule_id] = slug
            for legacy in ref.legacy_ids:
                # Legacy rule_id (TIER2-LLM01-01) also maps to the slug
                # so an in-flight Copilot output written before F.27
                # still renders with a friendly name.
                out[legacy] = slug
    return out


def _slugify_title(title: str) -> str:
    """`Indirect prompt injection via document loader` → `indirect-prompt-injection-via-document-loader`."""
    import re as _re
    s = title.strip().lower()
    # Strip common arrow / dash glyphs that show up in titles.
    s = s.replace("→", " ").replace("—", " ").replace("/", " ")
    s = _re.sub(r"[^a-z0-9]+", "-", s)
    return s.strip("-")


def _render_severity_bar(sev_total: dict[str, int], parts: list[str]) -> None:
    """Render the stacked severity-distribution bar (label + counts + bar).

    No-op when there are no findings. Extracted so the SAIGE-first variant
    can surface it alongside the classification card at the top of the
    report instead of below the metrics row.
    """
    total_findings = sum(sev_total.values())
    if not total_findings:
        return
    parts.append('<div class="section">')
    parts.append('<div style="display:flex;justify-content:space-between;align-items:baseline;margin-bottom:6px;">')
    parts.append('<span style="font-size:12px;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.06em;font-weight:600;">Severity distribution</span>')
    # Always emit a pill for every severity bucket — readers expect to
    # see all five (critical / high / medium / low / info) and a
    # zero count is informative ("low: 0" reads as "we have a story
    # about lows; there just aren't any this run"). The 0-count pills
    # render slightly dimmed via the .pill-zero modifier.
    sev_text = " &middot; ".join(
        f'<span class="pill {sev}'
        f'{" pill-zero" if not sev_total.get(sev, 0) else ""}" '
        f'data-tip="{_html_escape(_SEVERITY_MEANINGS[sev])}" '
        f'aria-label="{_html_escape(_SEVERITY_MEANINGS[sev])}">'
        f'{sev_total.get(sev, 0)} {sev}</span>'
        for sev in ("critical", "high", "medium", "low", "info")
    )
    # v4: prefix the breakdown with the total so the reader doesn't have
    # to add four numbers in their head.
    parts.append(f'<span><strong style="color:var(--text);font-size:13px;">Findings {total_findings}</strong> &middot; {sev_text}</span>')
    parts.append("</div>")
    parts.append('<div class="severity-bar">')
    for sev in ("critical", "high", "medium", "low", "info"):
        n = sev_total.get(sev, 0)
        if n:
            pct = (n / total_findings) * 100
            parts.append(f'<div class="{sev}" style="width:{pct:.1f}%"></div>')
    parts.append("</div></div>")


def _render_saige_block(r: Any, parts: list[str]) -> None:
    """Render the JPMC SAIGE Agent Tier classification card if present.

    Extracted so both the standard (after metrics) and saige-first (top of
    report) layouts use the same markup.
    """
    if not r.saige_tier:
        return
    tier_label = "Non Agent" if r.saige_tier == "non-agent" else f"Agentic Tier {r.saige_tier}"
    parts.append('<div class="saige-card">')
    parts.append('<div class="saige-label">JPMC SAIGE Agent Tier classification</div>')
    parts.append(f'<div class="saige-tier">{_html_escape(tier_label)}</div>')
    parts.append(f'<div class="saige-rationale">{_html_escape(r.saige_tier_reasoning or "(no reasoning provided)")}</div>')
    parts.append(
        '<div class="saige-footer">Informational only — AgentShield does not '
        "filter or prioritise findings based on this classification.</div>"
    )
    parts.append("</div>")


def render_combined_html(result: MergeResult, *, static: bool = False) -> str:
    """Standalone HTML report — single file, embedded CSS, no external deps.

    F.29: when `static=True`, drops the filter bar and the tab navigation;
    every panel renders as a stacked `<section>` with its own heading. Use
    this mode for distribution-ready (printable / emailable / read-without-
    clicking) reports. Default `static=False` keeps the interactive UX.

    Layout:
      1. Report header (title + scan timestamp)
      2. Status banner if applicable (incomplete / schema-error / stale)
      3. **SAIGE Agent Tier classification card** (if Tier 2 classified) —
         hoisted to the top so the agent's autonomy tier frames every
         subsequent section
      4. Stacked severity-distribution bar — at-a-glance "how bad is it",
         paired with SAIGE as the exec-summary header
      5. **D/D/R hero row** — three cards, one per category, with severity pills
      6. Metrics row — Tier 1 / Tier 2 / FP-marked / Net actionable
      7. Findings — three sections led by 🔴 Detect / 🟡 Defend / 🔵 Respond,
         each finding showing a [Tier 1]/[Tier 2] pill + severity pill +
         file:line + framework chips + remediation
      8. Coverage matrix
      9. Footer with version

    Designed to render cleanly in any modern browser without internet
    access (matches AgentShield's offline-first stance — runs from H:\\
    mapped drives just as well as locally).
    """
    r = result.report
    grouped = _findings_grouped_by_ddr(r)
    # F.31: rule_id → friendly slug for Tier 2 (Copilot) findings, so the
    # finding card shows `indirect-prompt-injection-via-document-loader`
    # instead of `AS-C-D-LLM01-002`. Built once per render.
    tier2_slugs = _tier2_display_slugs()
    # Path B: when `.agentshield/probe-results.json` exists, real probe
    # runs override the canned `scenario.probe` per finding. Index keyed
    # on (agentshield_id, file, line). Empty when no real probe has run.
    live_probe_index = _load_live_probe_index(r)
    sev_total: dict[str, int] = {}
    for bucket in grouped.values():
        for f in bucket:
            s = f.get("severity", "info")
            sev_total[s] = sev_total.get(s, 0) + 1

    parts: list[str] = []
    parts.append("<!doctype html>")
    parts.append('<html lang="en"><head><meta charset="utf-8">')
    parts.append("<title>AgentShield Pre-Production Review</title>")
    parts.append(f"<style>{_HTML_CSS}</style>")
    parts.append("</head><body>")

    # 1. Header
    # v4: subtitle is a single line of scan provenance (target, commit, time,
    # duration, total findings) so a reader sees the scan's identity and
    # headline result without scrolling. Repo/branch/commit/duration are
    # demo-hardcoded — TODO: wire through from the scan invocation.
    scanned_display = ""
    if r.tier2_scanned_at:
        try:
            _ts = datetime.fromisoformat(r.tier2_scanned_at.replace("Z", "+00:00"))
            scanned_display = f"{_ts.day} {_ts.strftime('%b %Y, %H:%M')} UTC"
        except ValueError:
            scanned_display = r.tier2_scanned_at
    repo_target = "agentshield-demo / customer-support-agent"
    branch = "main"
    commit = "7a3c1f2"
    scan_duration = "42s"
    total_findings = sum(sev_total.values())
    parts.append('<div class="report-header">')
    parts.append("<h1>AgentShield Pre-Production Review</h1>")
    if r.tier2_scanned_at:
        subtitle = (
            f"Scanned: {_html_escape(repo_target)} "
            f"branch {_html_escape(branch)} "
            f"&middot; commit {_html_escape(commit)} "
            f"&middot; {_html_escape(scanned_display)} "
            f"&middot; scan took {_html_escape(scan_duration)}. "
            f"<strong>Findings in this scan: {total_findings}</strong>"
        )
    else:
        subtitle = (
            f"Scanned: {_html_escape(repo_target)} "
            f"branch {_html_escape(branch)} "
            f"&middot; commit {_html_escape(commit)} "
            f"&middot; Copilot LLM-as-a-Judge Scan not run. "
            f"<strong>Findings in this scan: {total_findings}</strong>"
        )
    parts.append(f'<div class="subtitle">{subtitle}</div>')
    parts.append("</div>")

    # 2. Status banners
    if not result.tier2_present:
        parts.append(
            '<div class="banner warn"><strong>INCOMPLETE — Copilot LLM-as-a-Judge Scan not run.</strong> '
            "This report shows Rules-engine Static Scan findings only. Run the "
            "Copilot LLM-as-a-Judge Scan and re-merge for full coverage.</div>"
        )
    elif result.schema_errors:
        parts.append(
            '<div class="banner error"><strong>Copilot LLM-as-a-Judge Scan output failed schema validation.</strong> '
            "Showing Rules-engine Static Scan only. Re-prompt Copilot to fix the validation errors below.</div>"
        )
        parts.append('<div class="section"><h2>Schema errors</h2><ul>')
        for err in result.schema_errors:
            parts.append(f"<li><code>{_html_escape(err.field_path)}</code> &mdash; {_html_escape(err.message)}</li>")
        parts.append("</ul></div>")
    elif result.stale:
        parts.append(
            '<div class="banner stale"><strong>STALE Copilot LLM-as-a-Judge Scan.</strong> '
            "The Semgrep fingerprint changed since the Copilot LLM-as-a-Judge Scan was run; results may be inconsistent. "
            "Re-run the Copilot LLM-as-a-Judge Scan for fresh results.</div>"
        )

    # Exec-summary header: SAIGE classification card + severity-distribution
    # bar above D/D/R so the agent's autonomy tier + at-a-glance "how bad
    # is it" framing leads everything that follows.
    _render_saige_block(r, parts)
    _render_severity_bar(sev_total, parts)

    # 3. D/D/R HERO ROW
    parts.append('<div class="ddr-row">')
    for cat in _DDR_ORDER:
        emoji_label, subtitle, _desc, question = _DDR_LABELS[cat]
        bucket = grouped[cat]
        sev_counts: dict[str, int] = {}
        for f in bucket:
            s = f.get("severity", "info")
            sev_counts[s] = sev_counts.get(s, 0) + 1
        category_label = emoji_label.split(" ", 1)[1]  # strip leading colored circle
        parts.append(f'<div class="ddr-card {cat}" data-ddr-card="{cat}">')
        # Icon + uppercase category label row
        parts.append('<div class="ddr-label-row">')
        parts.append(_DDR_ICON_SVG[cat])
        parts.append(f'<span class="ddr-label">{_html_escape(category_label)}</span>')
        parts.append("</div>")
        # Title + subtitle
        parts.append(f'<div class="ddr-title">{_html_escape(category_label)}</div>')
        parts.append(f'<div class="ddr-subtitle">{_html_escape(subtitle)}</div>')
        # Orienting question (block-quote with colored vertical bar)
        parts.append(f'<div class="ddr-question">"{_html_escape(question)}"</div>')
        # Big finding count + severity pills on one baseline-aligned row.
        parts.append('<div class="ddr-count-row">')
        parts.append(f'<div class="ddr-count" data-ddr-count="{cat}" data-ddr-total="{len(bucket)}">{len(bucket)}</div>')
        parts.append('<div class="sev-pills">')
        if not bucket:
            parts.append('<span style="color:var(--text-muted);font-size:12px;">No findings</span>')
        else:
            for sev in ("critical", "high", "medium", "low", "info"):
                n = sev_counts.get(sev, 0)
                if n:
                    meaning = _html_escape(_SEVERITY_MEANINGS[sev])
                    parts.append(
                        f'<span class="pill {sev}" '
                        f'data-tip="{meaning}" aria-label="{meaning}">'
                        f'{sev} {n}</span>'
                    )
        parts.append("</div>")
        parts.append("</div>")  # /ddr-count-row
        parts.append("</div>")
    parts.append("</div>")

    # 4. Metrics row
    tier1_total = len(r.tier1_findings)
    tier2_total = len(r.tier2_findings)
    fp_marked = sum(1 for f in r.tier1_findings if f.tier2_verdict == "FP")
    # v4: split each tier's count by source file. Findings on agent-
    # loaded markdown (SKILL.md, AGENT.md, AGENTS.md, INSTRUCTION(S).md,
    # PROMPT(S).md, CLAUDE.md) come from the markdown-side scanner
    # (Tier 1) or the LLM judging the same files (Tier 2). Everything
    # else (.py / .java / ...) is code-side. Surfaced as a small
    # subtotal inside each metric card so the reader sees at a glance
    # how much of the scan landed where.
    from agentshield.manifest_scanner.scanner import RECOGNIZED_AGENT_MD_FILENAMES

    def _is_markdown_file(path: str) -> bool:
        name = path.rsplit("/", 1)[-1].rsplit("\\", 1)[-1].lower()
        return name in RECOGNIZED_AGENT_MD_FILENAMES

    def _markdown_count(findings, file_getter):
        return sum(
            1 for f in findings
            if _is_markdown_file(str(file_getter(f) or ""))
        )

    tier1_markdown = _markdown_count(r.tier1_findings, lambda f: f.finding.get("file"))
    tier1_code = tier1_total - tier1_markdown
    tier2_markdown = _markdown_count(r.tier2_findings, lambda f: f.get("file"))
    tier2_code = tier2_total - tier2_markdown
    # Same code/markdown split for the FP card so all three input metrics
    # carry the same breakdown shape — keeps the row scannable.
    fp_findings_iter = [f for f in r.tier1_findings if f.tier2_verdict == "FP"]
    fp_markdown = _markdown_count(fp_findings_iter, lambda f: f.finding.get("file"))
    fp_code = fp_marked - fp_markdown
    # F.33: redesigned metrics row.
    # 3 input cards (left of divider) -> 1 hero "Net Actionable" card
    # (right). Each card carries a one-line subtitle so the number is
    # legible without external context. FP card stays neutral — a zero
    # there is ambiguous (could mean "nothing to exclude" or "Copilot
    # didn't run thoroughly"), so a green/positive tint would mislead.
    parts.append('<div class="metrics-row">')
    parts.append(
        f'<div class="metric">'
        f'<div class="metric-label">Rules-engine Static Scan</div>'
        f'<div class="metric-value">{tier1_total}</div>'
        f'<div class="metric-breakdown" '
        f'title="Findings on .py / .java source (Semgrep) vs findings '
        f'on agent-loaded markdown (manifest scanner) — both are Tier '
        f'1 static rule engines">'
        f'<span class="metric-bd-item">{tier1_code} code</span>'
        f'<span class="metric-bd-sep">·</span>'
        f'<span class="metric-bd-item">{tier1_markdown} markdown</span>'
        f'</div>'
        f'<div class="metric-subtitle">what static rules caught</div>'
        f'</div>'
    )
    parts.append(
        f'<div class="metric">'
        f'<div class="metric-label">Copilot LLM-as-a-Judge Scan</div>'
        f'<div class="metric-value">{tier2_total}</div>'
        f'<div class="metric-breakdown" '
        f'title="Findings on .py / .java source vs findings on agent-'
        f'loaded markdown (SKILL.md, AGENT.md, AGENTS.md, INSTRUCTION(S).md, '
        f'PROMPT(S).md, CLAUDE.md)">'
        f'<span class="metric-bd-item">{tier2_code} code</span>'
        f'<span class="metric-bd-sep">·</span>'
        f'<span class="metric-bd-item">{tier2_markdown} markdown</span>'
        f'</div>'
        f'<div class="metric-subtitle">what LLM found</div>'
        f'</div>'
    )
    parts.append(
        f'<div class="metric">'
        f'<div class="metric-label">False Positives</div>'
        f'<div class="metric-value">{fp_marked}</div>'
        f'<div class="metric-breakdown" '
        f'title="FP-marked Tier 1 findings on .py / .java source vs '
        f'findings on agent-loaded markdown (SKILL.md, AGENT.md, AGENTS.md, '
        f'INSTRUCTION(S).md, PROMPT(S).md, CLAUDE.md)">'
        f'<span class="metric-bd-item">{fp_code} code</span>'
        f'<span class="metric-bd-sep">·</span>'
        f'<span class="metric-bd-item">{fp_markdown} markdown</span>'
        f'</div>'
        f'<div class="metric-subtitle">what was ruled out</div>'
        f'</div>'
    )
    parts.append('<div class="metrics-divider" aria-hidden="true"></div>')
    # Net Actionable's tooltip carries the formula; the subtitle stays
    # in the "what …" parallel structure of the three input cards.
    parts.append(
        f'<div class="metric metric-hero" '
        f'title="Net Actionable = Semgrep + Copilot − False Positives '
        f'(= {tier1_total} + {tier2_total} − {fp_marked})">'
        f'<div class="metric-label">Net Actionable</div>'
        f'<div class="metric-value actionable">{result.actionable_finding_count}</div>'
        f'<div class="metric-subtitle">what\'s left to address</div>'
        f'</div>'
    )
    parts.append("</div>")

    # SAIGE card + severity bar were already rendered above (exec-summary
    # header); nothing more to emit at the post-metrics position.

    # 7. Findings — D/D/R-led
    # F.21: filter bar — sits above the three findings sections, drives the
    # JS at the bottom of the page. Severity / category / origin checkboxes
    # default to all-on; search box matches across rule_id + file + message.
    # F.29: skip in static mode — no JS, no filtering, just stacked sections.
    if not static:
        parts.append('<div class="filter-bar" id="filter-bar">')
        parts.append('<div class="filter-group">')
        parts.append('<span class="filter-label">Severity</span>')
        for sev in ("critical", "high", "medium", "low", "info"):
            parts.append(
                f'<label class="filter-chip {sev}"><input type="checkbox" '
                f'data-filter="severity" value="{sev}" checked>'
                f'<span>{sev}</span></label>'
            )
        parts.append("</div>")
        # F.27: Category chip group removed — each D/D/R tab already
        # constrains visible category, so a global category chip is redundant
        # (and confusing if you toggle "detect" off while on the Detect tab).
        # The JS still defaults category filters to "checked" via the
        # `isChecked` fallback, so findings of any category pass through.
        parts.append('<div class="filter-group">')
        parts.append('<span class="filter-label">Origin</span>')
        for origin_key, origin_label in (("tier1", "Semgrep"), ("tier2", "Copilot")):
            parts.append(
                f'<label class="filter-chip {origin_key}"><input type="checkbox" '
                f'data-filter="origin" value="{origin_key}" checked>'
                f'<span>{origin_label}</span></label>'
            )
        parts.append("</div>")
        parts.append('<div class="filter-group filter-search-group">')
        parts.append(
            '<input type="search" id="finding-search" class="filter-search" '
            'placeholder="Search rule_id / file / message…" autocomplete="off">'
        )
        parts.append('<button type="button" id="filter-reset" class="filter-reset">Reset</button>')
        parts.append("</div>")
        parts.append('<div id="filter-status" class="filter-status"></div>')
        parts.append("</div>")

        # F.22: tab navigation — D/D/R panels + Coverage + Reference. The
        # filter bar above applies globally; tab counts update live with
        # the filter state. Initial active tab = Detect.
        parts.append('<div class="tab-nav" role="tablist">')
        for cat in _DDR_ORDER:
            emoji_label, _sub, _desc, _q = _DDR_LABELS[cat]
            bucket = grouped[cat]
            active = " active" if cat == "detect" else ""
            parts.append(
                f'<button type="button" class="tab-btn{active}" role="tab" '
                f'data-tab="{cat}" aria-selected="{"true" if cat == "detect" else "false"}">'
                f'{_html_escape(emoji_label)} '
                f'<span class="tab-count" data-tab-count="{cat}" '
                f'data-tab-total="{len(bucket)}">{len(bucket)}</span>'
                f'</button>'
            )
        parts.append(
            '<button type="button" class="tab-btn" role="tab" data-tab="coverage" '
            'aria-selected="false">'
            '<svg class="tab-icon" width="14" height="14" viewBox="0 0 24 24" '
            'fill="none" stroke="currentColor" stroke-width="2" '
            'stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">'
            # Lucide-style "Layers" icon — stacked diamonds. Reads as
            # "framework coverage stratified across layers".
            '<path d="M12 2 2 7l10 5 10-5-10-5z"/>'
            '<polyline points="2 17 12 22 22 17"/>'
            '<polyline points="2 12 12 17 22 12"/>'
            '</svg>'
            'Coverage'
            '</button>'
        )
        parts.append(
            '<button type="button" class="tab-btn" role="tab" data-tab="inputoutput" '
            'aria-selected="false">'
            '<svg class="tab-icon" width="14" height="14" viewBox="0 0 24 24" '
            'fill="none" stroke="currentColor" stroke-width="2" '
            'stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">'
            # Lucide-style "list" icon — three rows with bullets, reads as
            # "list of files".
            '<line x1="8" y1="6" x2="21" y2="6"/>'
            '<line x1="8" y1="12" x2="21" y2="12"/>'
            '<line x1="8" y1="18" x2="21" y2="18"/>'
            '<circle cx="4" cy="6" r="1"/>'
            '<circle cx="4" cy="12" r="1"/>'
            '<circle cx="4" cy="18" r="1"/>'
            '</svg>'
            'Input &amp; Output'
            '</button>'
        )
        parts.append(
            '<button type="button" class="tab-btn" role="tab" data-tab="reference" '
            'aria-selected="false">'
            '<svg class="tab-icon" width="14" height="14" viewBox="0 0 24 24" '
            'fill="none" stroke="currentColor" stroke-width="2" '
            'stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">'
            # Lucide-style "Info" icon — lowercase "i" inside a circle.
            '<circle cx="12" cy="12" r="10"/>'
            '<line x1="12" y1="11" x2="12" y2="17"/>'
            '<line x1="12" y1="7" x2="12" y2="7.5"/>'
            '</svg>'
            'Reference: About AgentShield'
            '</button>'
        )
        parts.append("</div>")

    # F.29: in static mode each panel renders as a stand-alone <section>
    # with a visible heading; in interactive mode they all live inside a
    # tab-panels container.
    if static:
        parts.append('<div class="static-report">')
    else:
        parts.append('<div class="tab-panels">')

    # ---- D/D/R panels (one per category) ----
    for cat in _DDR_ORDER:
        emoji_label, subtitle, desc, _question = _DDR_LABELS[cat]
        bucket = grouped[cat]
        active = " active" if cat == "detect" else ""
        if static:
            parts.append(f'<section class="static-section" data-panel="{cat}">')
        else:
            parts.append(
                f'<div class="tab-panel{active}" role="tabpanel" data-panel="{cat}">'
            )
        parts.append(f'<div class="findings-section {cat}" data-section="{cat}">')
        parts.append('<div class="section-header">')
        parts.append(f'<span class="section-title">{_html_escape(emoji_label)} &mdash; {_html_escape(subtitle)}</span>')
        parts.append(f'<span class="section-subtitle">{_html_escape(desc)}</span>')
        parts.append(
            f'<span class="section-count" data-section-count="{cat}" '
            f'data-section-total="{len(bucket)}">{len(bucket)} finding{"s" if len(bucket) != 1 else ""}</span>'
        )
        # F.25: per-severity breakdown next to the count. Re-rendered live by
        # the JS as filters change (only severities present in the visible
        # subset show up). data-section-total-{sev} preserves the unfiltered
        # totals so the JS can decide between "5 high" and "3 of 5 high".
        sev_counts_section: dict[str, int] = {}
        for f in bucket:
            s = f.get("severity", "info")
            sev_counts_section[s] = sev_counts_section.get(s, 0) + 1
        parts.append(f'<span class="section-severity" data-section-severity="{cat}"')
        for sev_key in ("critical", "high", "medium", "low", "info"):
            parts.append(f' data-section-total-{sev_key}="{sev_counts_section.get(sev_key, 0)}"')
        parts.append(">")
        for sev_key in ("critical", "high", "medium", "low", "info"):
            n = sev_counts_section.get(sev_key, 0)
            if n:
                meaning = _html_escape(_SEVERITY_MEANINGS[sev_key])
                parts.append(
                    f'<span class="sev-mini {sev_key}" '
                    f'data-section-sev="{sev_key}" '
                    f'data-tip="{meaning}" aria-label="{meaning}">'
                    f'{n} {sev_key}</span>'
                )
        parts.append("</span>")
        parts.append("</div>")
        if not bucket:
            parts.append(
                f'<div class="finding finding-empty"><span style="color:var(--text-muted);'
                f'font-style:italic;">No {cat} findings.</span></div>'
            )
        else:
            for f in bucket:
                origin = f["_origin"]
                sev = f.get("severity", "info")
                # F.31: prefer the human-readable slug. Semgrep findings
                # already carry `rule_id_short` (e.g. `unsanitized-user-
                # input-to-llm`); Copilot findings only have `rule_id`
                # like `AS-C-D-LLM01-002`, so we look up the title from
                # the bundled checklist and slugify it. Manifest scanner
                # findings carry `rule_id_short` (`ast03-network-...`).
                rule = (
                    f.get("rule_id_short")
                    or tier2_slugs.get(f.get("rule_id", ""))
                    or f.get("rule_id")
                    or "?"
                )
                file_ = f.get("file") or "?"
                line_ = f.get("line") or "?"
                fm = f.get("framework_mappings") or f
                fw_keys: list[str] = []
                tags: list[str] = []
                for k_label, k_field in (
                    ("OWASP LLM", "owasp_llm"), ("OWASP Agentic", "owasp_agentic"),
                    ("ATLAS", "mitre_atlas"), ("CWE", "cwe"),
                    ("AST10", "ast"),
                ):
                    for v in (fm.get(k_field) or []):
                        tags.append(f"{k_label} {v}")
                        fw_keys.append(f"{k_field}:{v}")
                # F.21 search index: lowercase concat of searchable fields.
                search_blob = " ".join(
                    str(x).lower() for x in [rule, file_, f.get("message", "")]
                )
                # Data attributes drive the JS filter — keep them on the
                # outer .finding so the show/hide logic is one query selector.
                fw_attr = " ".join(fw_keys)
                parts.append(
                    f'<div class="finding" data-severity="{sev}" '
                    f'data-category="{cat}" data-origin="{origin}" '
                    f'data-frameworks="{_html_escape(fw_attr)}" '
                    f'data-search="{_html_escape(search_blob)}">'
                )
                parts.append('<div class="finding-header">')
                parts.append(f'<span class="pill {origin}">{"Semgrep" if origin == "tier1" else "Copilot"}</span>')
                sev_meaning = _html_escape(_SEVERITY_MEANINGS.get(sev, ""))
                parts.append(
                    f'<span class="pill {sev}" '
                    f'data-tip="{sev_meaning}" aria-label="{sev_meaning}">'
                    f'{sev}</span>'
                )
                parts.append(f'<span class="finding-rule">{_html_escape(rule)}</span>')
                if origin == "tier1" and f.get("_tier2_verdict"):
                    v_raw = f["_tier2_verdict"]
                    v = v_raw.lower()
                    meaning = _html_escape(_VERDICT_MEANINGS.get(v_raw, ""))
                    parts.append(
                        f'<span class="pill {v}" '
                        f'data-tip="{meaning}" aria-label="{meaning}">'
                        f'Copilot: {v_raw}</span>'
                    )
                parts.append("</div>")
                parts.append(f'<div class="finding-meta">{_html_escape(file_)}:{_html_escape(str(line_))}</div>')
                if f.get("message"):
                    parts.append(f'<div class="finding-message">{_html_escape(f["message"])}</div>')
                # Body: collapsible. Frameworks + snippet + remediation +
                # Copilot reasoning live inside .finding-body so they hide
                # when the user collapses the card.
                parts.append('<div class="finding-body">')
                if tags:
                    parts.append('<div class="finding-tags">')
                    for k_label, k_field in (
                        ("OWASP LLM", "owasp_llm"), ("OWASP Agentic", "owasp_agentic"),
                        ("ATLAS", "mitre_atlas"), ("CWE", "cwe"),
                    ):
                        for v in (fm.get(k_field) or []):
                            tag_text = f"{k_label} {v}"
                            tag_key = f"{k_field}:{v}"
                            parts.append(
                                f'<span class="finding-tag" '
                                f'data-framework-key="{_html_escape(tag_key)}" '
                                f'role="button" tabindex="0" '
                                f'title="Click to filter by {_html_escape(tag_text)}">'
                                f'{_html_escape(tag_text)}</span>'
                            )
                    parts.append("</div>")
                if f.get("snippet"):
                    parts.append(f'<div class="finding-snippet">{_html_escape(f["snippet"])}</div>')
                if f.get("remediation"):
                    parts.append(f'<div class="finding-remediation"><strong>Fix:</strong> {_html_escape(f["remediation"])}</div>')
                if origin == "tier1" and f.get("_tier2_reasoning"):
                    parts.append(f'<div class="finding-remediation"><strong>Copilot reasoning:</strong> {_html_escape(f["_tier2_reasoning"])}</div>')
                # v4: static attack narrative — what an attack on this
                # finding looks like in practice. Pure documentation; no
                # execution. Rendered only when the rule has a curated
                # narrative entry — silent for others.
                # Tier 1 findings carry both legacy `rule_id` (e.g.
                # `agentshield.detect.unsanitized-user-input-to-llm`) and
                # canonical `agentshield_id` (e.g. `AS-S-D-LLM01-001`).
                # Prefer the canonical ID since the narrative library is
                # keyed off it; Tier 2 / manifest findings have rule_id
                # already in canonical form.
                scenario = narrative_for(
                    f.get("agentshield_id") or f.get("rule_id") or ""
                )
                # Path B: if a real probe ran for this finding, swap its
                # ProbeRun in for the canned one. Match key is
                # (agentshield_id, file, line) — same shape the
                # orchestrator emitted.
                effective_probe = scenario.probe if scenario else None
                is_live_probe = False
                if scenario is not None and live_probe_index:
                    _key = (
                        f.get("agentshield_id") or f.get("rule_id") or "",
                        f.get("file") or "",
                        int(f.get("line", 0) or 0),
                    )
                    if _key in live_probe_index:
                        effective_probe = live_probe_index[_key]
                        is_live_probe = True
                if scenario is not None:
                    open_attr = " open" if static else ""
                    parts.append(
                        f'<details class="finding-attack-scenario"{open_attr}>'
                    )
                    # Path B+: visible-while-collapsed probe-state badge.
                    # Two states, framed from the report-viewer's POV:
                    #   [ Static scan ]    — no probe attached; finding
                    #                        is from static analysis.
                    #   [ Simulated Probe ]— probe data attached (live
                    #                        OR canned). The click-time
                    #                        experience is always a
                    #                        playback, so "simulated"
                    #                        accurately describes what
                    #                        the user sees. The live vs
                    #                        canned distinction stays
                    #                        inside the panel itself.
                    if effective_probe is not None:
                        badge_title = (
                            "Click 🎯 Run probe to play back the captured "
                            "trace. The data is "
                            + ("from a real probe run."
                               if is_live_probe else "canned narrative data.")
                        )
                        badge_html = (
                            f'<span class="attack-probe-badge '
                            f'attack-probe-badge-probe" '
                            f'title="{_html_escape(badge_title)}">'
                            f'[ Simulated Probe ]</span>'
                        )
                    else:
                        badge_html = (
                            '<span class="attack-probe-badge '
                            'attack-probe-badge-static" '
                            'title="Static analysis only — no runtime probe '
                            'attached for this rule">[ Static scan ]</span>'
                        )
                    parts.append(
                        f'<summary><span class="attack-icon" aria-hidden="true">'
                        f'&#9888;</span> Attack scenario {badge_html} '
                        f'&mdash; {_html_escape(scenario.title)}</summary>'
                    )
                    parts.append('<div class="attack-body">')
                    parts.append(
                        f'<div class="attack-section">'
                        f'<div class="attack-label">What the attacker sends</div>'
                        f'<pre class="attack-payload">'
                        f'{_html_escape(scenario.attacker_input)}'
                        f'</pre></div>'
                    )
                    parts.append(
                        f'<div class="attack-section">'
                        f'<div class="attack-label">How it lands</div>'
                        f'<div class="attack-text">'
                        f'{_html_escape(scenario.code_path)}'
                        f'</div></div>'
                    )
                    parts.append(
                        f'<div class="attack-section">'
                        f'<div class="attack-label">What the attacker gets</div>'
                        f'<div class="attack-text">'
                        f'{_html_escape(scenario.impact)}'
                        f'</div></div>'
                    )
                    # v4: walkthrough rendering. When the narrative has a
                    # structured `simulation` (actor → target scenes), we
                    # render the visual flow and animate scene-by-scene.
                    # Otherwise we fall back to the prose `steps` list.
                    if scenario.simulation:
                        parts.append(
                            '<div class="attack-section attack-steps-section">'
                        )
                        parts.append(
                            '<div class="attack-label">'
                            'Attack simulation'
                            '<button type="button" class="attack-play-btn" '
                            'data-action="play">▶ Play simulation</button>'
                        )
                        if effective_probe is not None:
                            mode_label = (
                                'LIVE' if is_live_probe else '(simulated)'
                            )
                            mode_class = (
                                'probe-mode probe-mode-live'
                                if is_live_probe else 'probe-mode'
                            )
                            parts.append(
                                f'<button type="button" class="attack-probe-btn" '
                                f'data-action="probe">🎯 Run probe '
                                f'<span class="{mode_class}">{mode_label}</span>'
                                f'</button>'
                            )
                        parts.append('</div>')
                        parts.append('<div class="attack-sim-list">')
                        for i, scene in enumerate(scenario.simulation):
                            is_impact = not scene.target
                            klass = (
                                "attack-sim-scene attack-sim-impact"
                                if is_impact
                                else "attack-sim-scene"
                            )
                            parts.append(
                                f'<div class="{klass}" data-step="{i}">'
                            )
                            parts.append(
                                f'<div class="attack-sim-step-num">'
                                f'Step {i + 1}</div>'
                            )
                            parts.append('<div class="attack-sim-row">')
                            parts.append(
                                f'<div class="attack-sim-actor">'
                                f'<span class="actor-icon">'
                                f'{_html_escape(scene.icon)}</span>'
                                f'<span class="actor-label">'
                                f'{_html_escape(scene.actor)}</span></div>'
                            )
                            if not is_impact:
                                parts.append('<div class="attack-sim-arrow">')
                                if scene.action:
                                    parts.append(
                                        f'<span class="attack-sim-arrow-label">'
                                        f'{_html_escape(scene.action)}</span>'
                                    )
                                parts.append(
                                    '<div class="attack-sim-arrow-line"></div>'
                                )
                                # v4: data packet — animated dot that
                                # travels from source to target while
                                # playing.
                                parts.append(
                                    '<span class="attack-sim-packet" '
                                    'aria-hidden="true"></span>'
                                )
                                parts.append('</div>')
                                parts.append(
                                    f'<div class="attack-sim-actor">'
                                    f'<span class="actor-icon">'
                                    f'{_html_escape(scene.target_icon)}</span>'
                                    f'<span class="actor-label">'
                                    f'{_html_escape(scene.target)}</span></div>'
                                )
                            parts.append('</div>')  # /attack-sim-row
                            if scene.payload:
                                parts.append(
                                    f'<div class="attack-sim-payload">'
                                    f'{_html_escape(scene.payload)}</div>'
                                )
                            if scene.note:
                                parts.append(
                                    f'<div class="attack-sim-note">'
                                    f'{_html_escape(scene.note)}</div>'
                                )
                            parts.append('</div>')  # /attack-sim-scene
                        parts.append('</div>')  # /attack-sim-list

                        # v4: mocked red-team probe — terminal-style panel
                        # that streams a canned trace and ends with a
                        # verdict badge. Looks like watching a live
                        # probe; client-side script-only.
                        if effective_probe is not None:
                            probe = effective_probe
                            live_attr = ' data-live="true"' if is_live_probe else ''
                            parts.append(
                                '<div class="probe-panel" hidden '
                                f'data-verdict="{_html_escape(probe.verdict)}"'
                                f'{live_attr}>'
                            )
                            parts.append('<div class="probe-meta">')
                            parts.append(
                                f'<span class="probe-meta-row">'
                                f'<span class="probe-meta-label">target</span>'
                                f'<code>{_html_escape(probe.target)}</code>'
                                f'</span>'
                            )
                            parts.append(
                                f'<span class="probe-meta-row">'
                                f'<span class="probe-meta-label">profile</span>'
                                f'<code>{_html_escape(probe.profile)}</code>'
                                f'</span>'
                            )
                            # Path B+: surface the absolute date/time/TZ
                            # of the probe run. Per-line timestamps in
                            # the terminal stay HH:MM:SS for readability;
                            # the date + TZ live here once.
                            if probe.ran_at:
                                parts.append(
                                    f'<span class="probe-meta-row">'
                                    f'<span class="probe-meta-label">ran at</span>'
                                    f'<code>{_html_escape(probe.ran_at)}</code>'
                                    f'</span>'
                                )
                            parts.append('</div>')
                            parts.append('<div class="probe-terminal">')
                            for line in probe.trace:
                                parts.append(
                                    f'<div class="probe-line" '
                                    f'data-level="{_html_escape(line.level)}" '
                                    f'hidden>'
                                    f'<span class="probe-ts">[{_html_escape(line.timestamp)}]</span>'
                                    f' <span class="probe-level probe-level-{_html_escape(line.level)}">'
                                    f'{_html_escape(line.level)}</span>'
                                    f' <span class="probe-msg">{_html_escape(line.message)}</span>'
                                    f'</div>'
                                )
                            parts.append('</div>')  # /probe-terminal
                            verdict_label = {
                                "landed": "🔴 ATTACK LANDED",
                                "blocked": "🟢 ATTACK BLOCKED",
                                "inconclusive": "🟡 INCONCLUSIVE",
                            }.get(probe.verdict, probe.verdict.upper())
                            parts.append(
                                f'<div class="probe-verdict probe-verdict-{_html_escape(probe.verdict)}" hidden>'
                                f'<div class="probe-verdict-badge">{_html_escape(verdict_label)}</div>'
                            )
                            if probe.time_to_compromise:
                                parts.append(
                                    f'<div class="probe-verdict-meta">'
                                    f'time-to-compromise '
                                    f'<strong>{_html_escape(probe.time_to_compromise)}</strong>'
                                    f'</div>'
                                )
                            if probe.summary:
                                parts.append(
                                    f'<div class="probe-verdict-summary">'
                                    f'{_html_escape(probe.summary)}</div>'
                                )
                            # Path B+: surface the LLM judge's reasoning
                            # + confidence when the verdict came from
                            # the LLM classifier; surface the harness
                            # marker when the response was synthesised
                            # rather than fetched.
                            if probe.verdict_source == "llm" and probe.verdict_reasoning:
                                conf_str = ""
                                if probe.verdict_confidence is not None:
                                    conf_str = (
                                        f' &middot; confidence '
                                        f'<strong>{probe.verdict_confidence:.2f}</strong>'
                                    )
                                parts.append(
                                    f'<div class="probe-llm-reasoning">'
                                    f'<div class="probe-llm-label">'
                                    f'🤖 LLM judge{conf_str}</div>'
                                    f'<div class="probe-llm-text">'
                                    f'{_html_escape(probe.verdict_reasoning)}'
                                    f'</div></div>'
                                )
                            if probe.harness_used:
                                parts.append(
                                    f'<div class="probe-harness-note">'
                                    f'🛡️ Response synthesised by '
                                    f'<code>{_html_escape(probe.harness_used)}</code> '
                                    f'harness — no HTTP traffic left the '
                                    f'process for this payload.'
                                    f'</div>'
                                )
                            parts.append('</div>')  # /probe-verdict
                            parts.append('</div>')  # /probe-panel

                        parts.append('</div>')  # /attack-section
                    elif scenario.steps:
                        parts.append(
                            '<div class="attack-section attack-steps-section">'
                        )
                        parts.append(
                            '<div class="attack-label">'
                            'Attack walkthrough'
                            '<button type="button" class="attack-play-btn" '
                            'data-action="play">▶ Play simulation</button>'
                            '</div>'
                        )
                        parts.append('<ol class="attack-steps">')
                        for i, step in enumerate(scenario.steps):
                            parts.append(
                                f'<li class="attack-step" data-step="{i}">'
                                f'{_html_escape(step)}</li>'
                            )
                        parts.append('</ol>')
                        parts.append('</div>')
                    # Disclaimer has three states, matching the actual
                    # provenance of the block:
                    #   (a) live probe ran          → payloads WERE sent
                    #   (b) canned probe attached   → simulated walkthrough
                    #   (c) no probe at all         → static-only finding
                    # The (c) case applies to at-rest disclosure rules
                    # (hardcoded credentials), manifest-config rules, and
                    # observability gaps — anything without a runtime
                    # attack vector the HTTP-probe model can exercise.
                    if is_live_probe and effective_probe is not None:
                        parts.append(
                            f'<div class="attack-disclaimer attack-disclaimer-live">'
                            f'Walkthrough above is illustrative; the probe '
                            f'panel reflects an actual run against '
                            f'<code>{_html_escape(effective_probe.target)}</code>'
                            f' &mdash; payloads were sent and responses '
                            f'captured.'
                            f'</div>'
                        )
                    elif effective_probe is not None:
                        parts.append(
                            '<div class="attack-disclaimer">'
                            'Simulated walkthrough &mdash; no payloads were '
                            'sent to your system.'
                            '</div>'
                        )
                    else:
                        parts.append(
                            '<div class="attack-disclaimer attack-disclaimer-static">'
                            '&#8505; Static-only finding &mdash; no runtime '
                            'probe attached for this rule. The finding above '
                            'comes from static analysis; this attack class '
                            '(at-rest disclosure, manifest config, or '
                            'observability gap) doesn\'t have a runtime '
                            'vector AgentShield\'s HTTP probe can exercise.'
                            '</div>'
                        )
                    parts.append('</div>')  # /attack-body
                    parts.append('</details>')
                parts.append("</div>")  # /finding-body
                parts.append("</div>")  # /finding
        parts.append("</div>")  # /findings-section
        parts.append("</section>" if static else "</div>")  # /tab-panel (D/D/R)

    # ---- Coverage tab panel ----
    # Three-state matrix: for every framework item in the curated universe,
    # show whether THIS run produced findings for it (red), the scanner
    # has a rule for it but found nothing this run (green), or the rule
    # pack has no coverage at all (gray gap). Lets a reader instantly tell
    # apart "we checked and you're clean" from "we never looked."
    from agentshield.merger.coverage_universe import (
        FRAMEWORK_UNIVERSES,
        compute_scanner_coverage,
        gap_reason,
    )
    from agentshield.merger.reference import build_all_references

    _all_refs = build_all_references(
        tier1_rules_path=_DEFAULT_RULES_PATH,
        tier2_checklist_path=_DEFAULT_CHECKLIST_PATH,
    )
    scanner_cov = compute_scanner_coverage(_all_refs)
    fw_counts = _framework_finding_counts(r)

    if static:
        parts.append('<section class="static-section" data-panel="coverage">')
    else:
        parts.append('<div class="tab-panel" role="tabpanel" data-panel="coverage">')
    parts.append('<div class="coverage-card">')
    parts.append('<h3 class="panel-title">Coverage by Security Frameworks</h3>')
    parts.append(
        '<p class="panel-subtitle">Per-framework view of what AgentShield '
        '<em>checked</em>, and what it <em>found</em>. Each chip is one '
        'framework item — its colour shows whether this run produced '
        'findings (red), the rule pack covers it but nothing fired '
        '(green), or it sits outside the scanner’s current coverage '
        '(gray).</p>'
    )
    parts.append('<div class="coverage-legend">')
    parts.append(
        '<span><span class="leg-swatch leg-swatch-issues"></span>'
        'Scanned &mdash; with findings</span>'
        '<span><span class="leg-swatch leg-swatch-clean"></span>'
        'Scanned &mdash; clean this run</span>'
        '<span><span class="leg-swatch leg-swatch-gap"></span>'
        'Not scanned (no rule covers this item yet)</span>'
    )
    parts.append('</div>')

    _CURATED_NOTE = {
        "owasp_llm": (
            "Curated to the 6 call-site / agent-layer items (LLM01, LLM02, "
            "LLM05, LLM06, LLM07, LLM10). LLM03 / LLM04 / LLM08 / LLM09 are "
            "model-layer."
        ),
        "mitre_atlas": (
            "MITRE ATLAS is too large to enumerate in full; the universe "
            "below is a curated LLM/agent-relevant subset."
        ),
        "cwe": (
            "CWE has 1000+ weaknesses; the universe below is a curated "
            "subset most relevant to LLM/agent app code. Generic AppSec "
            "items (path traversal, TLS validation, credential transit) "
            "are out of scope by design — they belong to a general-"
            "purpose static scanner (semgrep-pro, CodeQL, Snyk)."
        ),
    }

    for k_label, k_key, k_url in (
        ("OWASP LLM Top 10 v2 (curated)", "owasp_llm",
         "https://genai.owasp.org/llm-top-10/"),
        ("OWASP Agentic AI Top 10", "owasp_agentic",
         "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/"),
        ("MITRE ATLAS (curated)", "mitre_atlas", "https://atlas.mitre.org/"),
        ("CWE (curated)", "cwe", "https://cwe.mitre.org/"),
        ("OWASP Agentic Skills Top 10", "ast",
         "https://github.com/OWASP/www-project-agentic-skills-top-10"),
    ):
        universe = FRAMEWORK_UNIVERSES[k_key]
        scanner_set = scanner_cov.get(k_key, set())
        findings_set = set(getattr(r.coverage, k_key))

        # State buckets (declaration order, not alphabetical, so the chips
        # read in the framework's own numbering, e.g. LLM01 → LLM10).
        items_issues: list[tuple[str, int]] = []
        items_clean: list[str] = []
        items_gap: list[str] = []
        for item in universe:
            if item in findings_set:
                count = fw_counts.get(f"{k_key}:{item}", 0)
                items_issues.append((item, count))
            elif item in scanner_set:
                items_clean.append(item)
            else:
                items_gap.append(item)
        # Items in scanner_set or findings_set but NOT in the curated
        # universe — surface them too so coverage stays honest if a rule
        # references a new ID the universe hasn't caught up with.
        extras = sorted((scanner_set | findings_set) - set(universe))
        for item in extras:
            if item in findings_set:
                count = fw_counts.get(f"{k_key}:{item}", 0)
                items_issues.append((item, count))
            else:
                items_clean.append(item)

        in_scope = len(items_issues) + len(items_clean)
        total = in_scope + len(items_gap)

        parts.append('<div class="framework-group">')
        parts.append(
            f'<div class="framework-group-header">'
            f'<span class="framework-group-name">{_html_escape(k_label)}</span>'
            f'<a href="{_html_escape(k_url)}" class="framework-group-link" '
            f'target="_blank" rel="noopener">reference &rarr;</a>'
            f'</div>'
        )
        parts.append('<div class="coverage-summary">')
        parts.append(
            f'<span class="cov-headline">'
            f'{in_scope}/{total} in scope</span>'
        )
        parts.append(
            f'<span class="cov-stat cov-stat-issues">'
            f'{len(items_issues)} with issues</span>'
        )
        parts.append(
            f'<span class="cov-stat cov-stat-clean">'
            f'{len(items_clean)} clean</span>'
        )
        parts.append(
            f'<span class="cov-stat cov-stat-gap">'
            f'{len(items_gap)} not scanned</span>'
        )
        parts.append('</div>')
        if k_key in _CURATED_NOTE:
            parts.append(
                f'<div class="coverage-fw-note">'
                f'{_html_escape(_CURATED_NOTE[k_key])}'
                f'</div>'
            )
        parts.append('<div class="coverage-chips">')
        for item, count in items_issues:
            # v4: "with issues" chips double as framework filters — same
            # `data-framework-key` contract as the per-finding tags, so
            # the existing toggle handler picks them up without changes.
            # Clicking an issue chip scopes the D/D/R findings to that
            # item. Clean / gap chips stay informational (no findings to
            # filter to).
            fkey = f"{k_key}:{item}"
            parts.append(
                f'<button type="button" '
                f'class="coverage-chip coverage-chip-issues" '
                f'data-framework-key="{_html_escape(fkey)}" '
                f'title="{_html_escape(item)}: {count} finding'
                f'{"s" if count != 1 else ""} this run — click to '
                f'filter the D/D/R findings to this item.">'
                f'{_html_escape(item)}'
                f'<span class="cov-chip-count">{count}</span>'
                f'</button>'
            )
        for item in items_clean:
            parts.append(
                f'<span class="coverage-chip coverage-chip-clean" '
                f'title="{_html_escape(item)}: covered by the rule pack, '
                f'no findings this run">'
                f'{_html_escape(item)}'
                f'</span>'
            )
        for item in items_gap:
            reason = gap_reason(k_key, item)
            parts.append(
                f'<span class="coverage-chip coverage-chip-gap" '
                f'title="{_html_escape(item)}: {_html_escape(reason)}">'
                f'{_html_escape(item)}'
                f'</span>'
            )
        parts.append('</div>')
        # Print-friendly fallback: tooltips don't render in print / PDF,
        # so emit a compact reasons list when the framework has gaps.
        if items_gap:
            open_attr = " open" if static else ""
            parts.append(f'<details class="coverage-gap-details"{open_attr}>')
            parts.append(
                f'<summary>Why {len(items_gap)} '
                f'item{"s are" if len(items_gap) != 1 else " is"} '
                f'not scanned</summary>'
            )
            parts.append('<ul class="coverage-gap-list">')
            for item in items_gap:
                reason = gap_reason(k_key, item)
                parts.append(
                    f'<li><code>{_html_escape(item)}</code> &mdash; '
                    f'{_html_escape(reason)}</li>'
                )
            parts.append('</ul>')
            parts.append('</details>')
        parts.append('</div>')  # /framework-group
    parts.append("</div>")  # /coverage-card
    parts.append("</section>" if static else "</div>")  # /tab-panel

    # v4: Frameworks tab removed — its per-item click-to-filter
    # functionality moved onto the Coverage Matrix's "with issues" chips
    # (they now carry `data-framework-key` and the same toggle handler
    # picks them up). The redundant "Findings by Security framework"
    # panel was a near-duplicate of the matrix; this consolidation
    # gives the Coverage Matrix one job (state + filter) and drops a
    # tab from the nav.

    # ---- Input & Output tab panel (v4) ----
    # Surfaces scan provenance: which files were fed to the scanner and which
    # artifacts the merger wrote. Helps a reader confirm scope without
    # opening the underlying JSON.
    if static:
        parts.append('<section class="static-section" data-panel="inputoutput">')
    else:
        parts.append('<div class="tab-panel" role="tabpanel" data-panel="inputoutput">')
    _render_input_output_panel(r, parts)
    parts.append("</section>" if static else "</div>")  # /tab-panel

    # ---- Reference tab panel (F.26) ----
    # Renders every check the scanner can fire, grouped by source. Pulled
    # at render-time from the YAML rule pack + checklist template + the
    # AST10 manifest-rule registry, so the documentation surface is always
    # in sync with what's actually shipping.
    if static:
        parts.append('<section class="static-section" data-panel="reference">')
    else:
        parts.append('<div class="tab-panel" role="tabpanel" data-panel="reference">')
    _render_reference_panel(parts)
    parts.append("</section>" if static else "</div>")  # /tab-panel

    parts.append("</div>")  # /tab-panels (or /static-report)

    # Footer
    parts.append("<footer>")
    parts.append("AgentShield v2 &middot; ")
    if r.tier1_fingerprint:
        parts.append(f'Semgrep fingerprint <code>{_html_escape(r.tier1_fingerprint[:16])}…</code>')
    parts.append("</footer>")

    # F.21: client-side interactivity. Vanilla JS, no framework, no network
    # calls. Filters severity / category / origin via checkbox-style chips,
    # full-text search across rule_id+file+message, click-to-filter on
    # framework tags, expand-collapse per-finding card, and live-updating
    # D/D/R hero card + section counts. Initial state is everything visible.
    parts.append('<script>')
    parts.append(_HTML_JS)
    parts.append('</script>')
    parts.append("</body></html>")
    return "\n".join(parts) + "\n"


# ---------- Reference tab (F.26) ----------

# Default paths for the reference loader — the bundled rule pack and
# checklist template ship inside the agentshield package. Resolved at
# render time so adding a new rule YAML or editing the checklist
# automatically updates the Reference tab on the next render.
_DEFAULT_RULES_PATH = Path(__file__).resolve().parent.parent / "rules"
_DEFAULT_CHECKLIST_PATH = (
    Path(__file__).resolve().parent.parent / "skills" / "tier2_checklist.md.tmpl"
)

# Friendly labels for the framework keys when rendered as small chips.
_FRAMEWORK_LABEL = {
    "owasp_llm": "OWASP LLM",
    "owasp_agentic": "OWASP Agentic",
    "mitre_atlas": "ATLAS",
    "cwe": "CWE",
    "ast": "AST10",
}


def _load_live_probe_index(r: Any) -> dict[tuple[str, str, int], ProbeRun]:
    """Load `.agentshield/probe-results.json` if present and key it by
    (agentshield_id, finding_file, finding_line) so the renderer can swap
    real probe data in place of the curated `scenario.probe`.

    Returns an empty dict when the file doesn't exist or fails to parse —
    the canned `ProbeRun` from attack_narratives.py then renders as-is.
    """
    if r.tier1_path is None:
        return {}
    probe_path = r.tier1_path.parent / "probe-results.json"
    if not probe_path.exists():
        return {}
    try:
        raw = json.loads(probe_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}

    index: dict[tuple[str, str, int], ProbeRun] = {}
    for result in raw.get("results", []):
        asid = result.get("agentshield_id") or ""
        file_ = result.get("finding_file") or ""
        try:
            line_ = int(result.get("finding_line") or 0)
        except (TypeError, ValueError):
            line_ = 0
        if not asid:
            continue
        # The live trace uses ISO timestamps + dict-shaped attempts; the
        # renderer expects HH:MM:SS + ProbeLine. Convert here.
        trace = tuple(
            ProbeLine(
                timestamp=_iso_to_hms(att.get("timestamp", "")),
                level=att.get("level", "info"),
                message=att.get("message", ""),
            )
            for att in result.get("attempts", [])
        )
        ttc_ms = result.get("time_to_compromise_ms")
        ttc_str = ""
        if isinstance(ttc_ms, int) and ttc_ms >= 0:
            ttc_str = f"{ttc_ms / 1000:.1f}s" if ttc_ms >= 1000 else f"{ttc_ms}ms"
        confidence_raw = result.get("verdict_confidence")
        try:
            confidence: float | None = (
                float(confidence_raw) if confidence_raw is not None else None
            )
        except (TypeError, ValueError):
            confidence = None
        # "ran at" — use the first attempt's ISO timestamp. Falls back
        # to the run-level started_at if attempts are empty for any
        # reason. UTC because the orchestrator emits datetime.now(utc).
        first_ts = ""
        attempts_list = result.get("attempts") or []
        if attempts_list:
            first_ts = attempts_list[0].get("timestamp", "")
        if not first_ts:
            first_ts = raw.get("started_at", "")
        ran_at_display = _iso_to_display(first_ts) if first_ts else ""
        index[(asid, file_, line_)] = ProbeRun(
            target=result.get("target", ""),
            profile=result.get("profile", ""),
            trace=trace,
            verdict=result.get("verdict", "inconclusive"),
            time_to_compromise=ttc_str,
            summary=result.get("summary", ""),
            verdict_source=result.get("verdict_source", "heuristic"),
            verdict_reasoning=result.get("verdict_reasoning", "") or "",
            verdict_confidence=confidence,
            harness_used=result.get("harness_used", "") or "",
            ran_at=ran_at_display,
        )
    return index


def _iso_to_hms(iso: str) -> str:
    """Per-line probe timestamp formatter.

    - ISO with trailing Z  → 'YYYY-MM-DD HH:MM:SS UTC' (full date + zone).
    - ISO without Z        → 'YYYY-MM-DD HH:MM:SS' (zone unknown).
    - Anything else        → returned verbatim (canned narratives in
      attack_narratives.py emit pre-formatted 'HH:MM:SS' strings; those
      have no real wall-clock and aren't a Live trace).

    Surfacing the full timestamp per line means a reader doesn't have
    to glance back at the panel header to confirm WHEN the probe ran —
    forensically more useful, and the extra ~14 chars fit comfortably
    in the terminal panel's width.
    """
    if "T" in iso and len(iso) >= 19 and iso.endswith("Z"):
        return f"{iso[:10]} {iso[11:19]} UTC"
    if "T" in iso and len(iso) >= 19:
        return f"{iso[:10]} {iso[11:19]}"
    return iso


def _iso_to_display(iso: str) -> str:
    """'YYYY-MM-DDTHH:MM:SSZ' → 'YYYY-MM-DD HH:MM:SS UTC'.

    The probe orchestrator always emits UTC (datetime.now(timezone.utc)),
    so attaching the literal 'UTC' is honest. If the input doesn't match
    the expected shape, return it verbatim — the renderer will surface
    whatever's there.
    """
    if "T" in iso and len(iso) >= 19 and iso.endswith("Z"):
        return f"{iso[:10]} {iso[11:19]} UTC"
    if "T" in iso and len(iso) >= 19:
        return f"{iso[:10]} {iso[11:19]}"
    return iso


def _findings_per_file(r: Any) -> dict[str, int]:
    """Count findings per file, normalized to basename for cross-tier match.

    Tier 1 findings carry repo-relative paths (`testbed/.../tools.py`);
    Tier 2 carries bare filenames (`tools.py`). Normalizing to basename
    keeps the counts unified for the Input panel display.
    """
    from os.path import basename
    counts: dict[str, int] = {}
    for f in r.tier1_findings:
        p = f.finding.get("file") or ""
        if p:
            bn = basename(p)
            counts[bn] = counts.get(bn, 0) + 1
    for f in r.tier2_findings:
        p = f.get("file") or ""
        if p:
            bn = basename(p)
            counts[bn] = counts.get(bn, 0) + 1
    return counts


def _fix_file_targets(r: Any) -> dict[str, tuple[int, list[str]]]:
    """For each fix.md, return (total_findings_addressed, files_addressed).

    - semgrep-fixes.md: tier 1 findings on non-markdown source
    - manifest-fixes.md: tier 1 findings on markdown manifests
    - copilot-fixes.md: tier 2 LLM-judge findings

    Files in each list are sorted by count desc so the noisiest target
    appears first.
    """
    from os.path import basename
    semgrep: dict[str, int] = {}
    manifest: dict[str, int] = {}
    copilot: dict[str, int] = {}
    for f in r.tier1_findings:
        p = f.finding.get("file") or ""
        if not p:
            continue
        bn = basename(p)
        if bn.lower().endswith(".md"):
            manifest[bn] = manifest.get(bn, 0) + 1
        else:
            semgrep[bn] = semgrep.get(bn, 0) + 1
    for f in r.tier2_findings:
        p = f.get("file") or ""
        if p:
            bn = basename(p)
            copilot[bn] = copilot.get(bn, 0) + 1

    def _summarize(d: dict[str, int]) -> tuple[int, list[str]]:
        return sum(d.values()), sorted(d.keys(), key=lambda k: (-d[k], k))

    return {
        "agentshield-semgrep-fixes.md": _summarize(semgrep),
        "agentshield-manifest-fixes.md": _summarize(manifest),
        "agentshield-copilot-fixes.md": _summarize(copilot),
    }


def _render_input_output_panel(r: Any, parts: list[str]) -> None:
    """Render the Input & Output panel as a pipeline diagram:
    INPUT (scanned files) → AGENTSHIELD (engines + totals) → OUTPUT (artifacts).

    Per-file finding counts appear in the Input column so the reader sees at
    a glance which files are noisy. The middle column mirrors the headline
    metrics-row math (Static + LLM − FPs = Net). Output paths are fixed by
    the writer's naming convention (TODO: derive from writer config).
    """
    from os.path import basename

    # ---- Input: scanned files grouped by kind, sorted by finding-count
    # desc within each group. The set of "scanned" files is the union of
    # `tier2_scanned_files` (the canonical list) and any file path
    # referenced by a Tier 1 finding — that way new rules with new code
    # fixtures (orchestrator.py for T12/T13, config.yaml for AST06)
    # appear here without needing a tier2 rescan. ----
    _CODE_EXTS = {".py", ".java", ".ts", ".tsx", ".js", ".go", ".rb"}
    _BUNDLE_CONFIG_EXTS = {
        ".yaml", ".yml", ".json", ".toml", ".ini", ".conf", ".config",
        ".properties", ".env", ".cfg",
    }
    # Tier 2 reports bare basenames, Tier 1 reports full paths. Dedupe
    # by path-suffix: bare `config.py` is dropped when
    # `testbed/.../config.py` also exists (same file, two reporters),
    # but `testbed/.../SKILL.md` and `testbed/.../skills/billing/SKILL.md`
    # both survive (distinct files that happen to share a basename).
    _all_paths: set[str] = set()
    for p in r.tier2_scanned_files or []:
        if p:
            _all_paths.add(p.strip())
    for f in r.tier1_findings:
        p = (f.finding.get("file") or "").strip()
        if p:
            _all_paths.add(p)
    scanned_paths: set[str] = {
        p for p in _all_paths
        if not any(other != p and other.endswith("/" + p) for other in _all_paths)
    }

    code_files: list[str] = []
    md_files: list[str] = []
    bundle_files: list[str] = []
    for path in scanned_paths:
        bn = basename(path).lower()
        suffix = "." + bn.rsplit(".", 1)[-1] if "." in bn else ""
        if suffix == ".md":
            md_files.append(path)
        elif suffix in _CODE_EXTS:
            code_files.append(path)
        elif suffix in _BUNDLE_CONFIG_EXTS:
            bundle_files.append(path)
        else:
            # Anything else still belongs in the Code group as the
            # most likely default — keeps mystery files visible.
            code_files.append(path)

    file_counts = _findings_per_file(r)
    code_files.sort(key=lambda p: (-file_counts.get(basename(p), 0), p))
    md_files.sort(key=lambda p: (-file_counts.get(basename(p), 0), p))
    bundle_files.sort(key=lambda p: (-file_counts.get(basename(p), 0), p))
    md_sorted = md_files  # back-compat alias for the rendering loop
    total_input = len(code_files) + len(md_sorted) + len(bundle_files)

    # ---- Output: fixed by writer naming convention. Fix-files carry the
    # per-file targets they address (count + which input files); HTML
    # reports don't "address" findings so they get a simpler caption. ----
    fix_targets = _fix_file_targets(r)
    html_outputs = [
        ("output/agentshield-report.html", "Interactive HTML report"),
        ("output/agentshield-report-print.html", "Print variant"),
    ]
    md_outputs = [
        ("output/agentshield-semgrep-fixes.md", "Semgrep fix recommendations",
         fix_targets["agentshield-semgrep-fixes.md"]),
        ("output/agentshield-manifest-fixes.md", "Manifest fix recommendations",
         fix_targets["agentshield-manifest-fixes.md"]),
        ("output/agentshield-copilot-fixes.md", "Copilot fix recommendations",
         fix_targets["agentshield-copilot-fixes.md"]),
    ]
    # v4: red-team handoff — one curated walkthrough per finding that has a
    # narrative in the library. Files covered = unique files referenced by
    # findings whose rule_id maps to a narrative with backfilled steps.
    from os.path import basename as _bn
    rt_files: dict[str, int] = {}
    rt_total = 0
    for f in r.tier1_findings:
        scenario = narrative_for(
            f.finding.get("agentshield_id") or f.finding.get("rule_id") or ""
        )
        if scenario and scenario.steps:
            p = f.finding.get("file") or ""
            if p:
                rt_files[_bn(p)] = rt_files.get(_bn(p), 0) + 1
                rt_total += 1
    for f in r.tier2_findings:
        scenario = narrative_for(f.get("agentshield_id") or f.get("rule_id") or "")
        if scenario and scenario.steps:
            p = f.get("file") or ""
            if p:
                rt_files[_bn(p)] = rt_files.get(_bn(p), 0) + 1
                rt_total += 1
    rt_outputs = [
        ("output/agentshield-redteam-payloads.md", "Red-team attack walkthroughs",
         (rt_total, sorted(rt_files.keys(), key=lambda k: (-rt_files[k], k)))),
    ]
    total_output = len(html_outputs) + len(md_outputs) + len(rt_outputs)

    def _file_li(path: str) -> str:
        n = file_counts.get(basename(path), 0)
        if n:
            badge = (
                f'<span class="io-count"><span class="io-dot"></span>'
                f'{n} finding{"s" if n != 1 else ""}</span>'
            )
        else:
            badge = (
                '<span class="io-count io-count-clean">'
                '<span class="io-dot"></span>clean</span>'
            )
        return f'<li><code>{_html_escape(path)}</code>{badge}</li>'

    parts.append('<div class="coverage-card">')
    parts.append('<h3 class="panel-title">Scan pipeline &mdash; Input → Engines → Output</h3>')
    parts.append(
        '<p class="panel-subtitle">What AgentShield ingested, what each '
        'engine produced, and where the results were written.</p>'
    )
    parts.append('<div class="io-pipeline">')

    # ===== Column 1: INPUT =====
    parts.append('<div class="io-pipeline-col">')
    parts.append('<div class="io-col-title">Input</div>')
    parts.append('<div class="io-col-subtitle">scanned files</div>')
    summary_bits = [f"{len(code_files)} code", f"{len(md_sorted)} markdown"]
    if bundle_files:
        summary_bits.append(f"{len(bundle_files)} bundle config")
    parts.append(
        f'<div class="io-col-summary">{total_input} files '
        f'<span class="io-col-summary-sub">&middot; '
        f'{" &middot; ".join(summary_bits)}</span></div>'
    )
    parts.append(f'<div class="io-col-section">Python source ({len(code_files)})</div>')
    parts.append('<ul class="io-col-list">')
    for path in code_files:
        parts.append(_file_li(path))
    parts.append('</ul>')
    parts.append(
        f'<div class="io-col-section">Manifest / markdown ({len(md_sorted)})</div>'
    )
    parts.append('<ul class="io-col-list">')
    if md_sorted:
        for path in md_sorted:
            parts.append(_file_li(path))
    else:
        parts.append('<li><span class="io-desc">No markdown files scanned</span></li>')
    parts.append('</ul>')
    # Path B+ AST06: bundled config files (YAML / JSON / .env / etc.)
    # are now in scope when there's a SKILL.md in the same directory.
    # Only render the section when something was actually scanned.
    if bundle_files:
        parts.append(
            f'<div class="io-col-section">Bundle config '
            f'({len(bundle_files)})</div>'
        )
        parts.append('<ul class="io-col-list">')
        for path in bundle_files:
            parts.append(_file_li(path))
        parts.append('</ul>')
    parts.append('</div>')  # /io-pipeline-col input

    # ===== Arrow =====
    parts.append('<div class="io-pipeline-arrow" aria-hidden="true">→</div>')

    # ===== Column 2: AGENTSHIELD ENGINES =====
    # Two phases, surfaced separately so the dual role of Copilot's LLM
    # (judges findings in phase 1, classifies probe verdicts in phase 2)
    # is visible at a glance. Phase 2 only renders when a probe actually
    # ran for this scan — detected by probe-results.json presence.
    probe_ran = (
        r.tier1_path is not None
        and (r.tier1_path.parent / "probe-results.json").exists()
    )
    parts.append('<div class="io-pipeline-col io-col-engine">')
    parts.append('<div class="io-col-title">AgentShield</div>')
    parts.append('<div class="io-col-subtitle">engines</div>')

    parts.append('<div class="io-engine-phase">Phase 1 &middot; Static analysis</div>')
    parts.append('<ul class="io-engine-list">')
    parts.append(
        '<li><div class="io-engine-name">Rules-engine Static Scan</div>'
        '<div class="io-engine-desc">Semgrep on source code + manifest '
        'scanner on agent-loaded markdown</div></li>'
    )
    parts.append(
        '<li><div class="io-engine-name">LLM-as-a-Judge Scan</div>'
        '<div class="io-engine-desc">Copilot reviews code and markdown '
        'manifests for agentic-AI risks (judges what static rules flagged + '
        'finds new ones)</div></li>'
    )
    parts.append('</ul>')

    if probe_ran:
        parts.append(
            '<div class="io-engine-phase io-engine-phase-probe">'
            'Phase 2 &middot; Runtime probe (red-team)</div>'
        )
        parts.append('<ul class="io-engine-list">')
        parts.append(
            '<li><div class="io-engine-name">HTTP probe execution</div>'
            '<div class="io-engine-desc">Real payloads sent against the '
            'configured target; per-finding HTTP responses, timing, and '
            'verdicts captured</div></li>'
        )
        parts.append(
            '<li><div class="io-engine-name">LLM-assisted probe classifier</div>'
            '<div class="io-engine-desc">Copilot judges each probe response '
            '&mdash; verdict + plain-text reasoning + confidence per finding '
            '(same LLM as Phase 1, different role)</div></li>'
        )
        parts.append('</ul>')
    parts.append('</div>')  # /io-pipeline-col engine

    # ===== Arrow =====
    parts.append('<div class="io-pipeline-arrow" aria-hidden="true">→</div>')

    # ===== Column 3: OUTPUT =====
    parts.append('<div class="io-pipeline-col">')
    parts.append('<div class="io-col-title">Output</div>')
    parts.append('<div class="io-col-subtitle">generated artifacts</div>')
    parts.append(f'<div class="io-col-summary">{total_output} files written</div>')
    parts.append(f'<div class="io-col-section">Report (HTML, {len(html_outputs)})</div>')
    parts.append('<ul class="io-col-list">')
    for path, desc in html_outputs:
        parts.append(
            f'<li><code>{_html_escape(path)}</code>'
            f'<span class="io-desc">{_html_escape(desc)}</span></li>'
        )
    parts.append('</ul>')
    def _render_fix_block(label: str, items: list) -> None:
        parts.append(f'<div class="io-col-section">{_html_escape(label)}</div>')
        parts.append('<ul class="io-col-list io-col-list-fix">')
        for path, desc, (n, files) in items:
            if n == 0:
                target_line = (
                    '<span class="io-fix-target io-count-clean">'
                    '<span class="io-dot"></span>no findings to address</span>'
                )
            else:
                files_str = ", ".join(files)
                target_line = (
                    f'<span class="io-fix-target">'
                    f'<span class="io-dot"></span>'
                    f'{n} finding{"s" if n != 1 else ""} &middot; '
                    f'<code class="io-fix-files">{_html_escape(files_str)}</code>'
                    f'</span>'
                )
            parts.append(
                f'<li class="io-fix-item">'
                f'<div class="io-fix-head"><code>{_html_escape(path)}</code>'
                f'<span class="io-desc">{_html_escape(desc)}</span></div>'
                f'{target_line}'
                f'</li>'
            )
        parts.append('</ul>')

    _render_fix_block(f"Fix recommendations ({len(md_outputs)})", md_outputs)
    _render_fix_block(f"Red-team handoff ({len(rt_outputs)})", rt_outputs)
    parts.append('</div>')  # /io-pipeline-col output

    parts.append('</div>')  # /io-pipeline
    parts.append('</div>')  # /coverage-card


def _render_reference_panel(parts: list[str]) -> None:
    """Emit the inner HTML of the Reference tab panel into `parts`."""
    from agentshield.merger.reference import build_all_references

    refs = build_all_references(
        tier1_rules_path=_DEFAULT_RULES_PATH,
        tier2_checklist_path=_DEFAULT_CHECKLIST_PATH,
    )

    grouped: dict[str, list] = {"Semgrep": [], "Copilot": [], "Markdown": []}
    for ref in refs:
        grouped.setdefault(ref.source, []).append(ref)

    # Long-form display labels mirror the metric-card naming: each
    # source group header reads as a complete scanner description so
    # the Reference tab is self-explanatory without the dashboard.
    source_display = {
        "Semgrep": "Semgrep Rules-engine Static Scan",
        "Copilot": "Copilot LLM-as-a-Judge Scan",
        "Markdown": "Manifest Static Scanner",
    }

    parts.append('<div class="reference-card">')
    parts.append('<h3 class="panel-title">What AgentShield checks for</h3>')
    parts.append(
        '<p class="panel-subtitle">This page lists everything the scanner '
        "is capable of catching, taken straight from its current ruleset. "
        "Use it to understand the tool's full coverage.</p>"
    )

    # F.28c: dropped tier numbering. The three sources catch different
    # classes of bug, not different severities of the same class —
    # describe each by what it is rather than imposing a false hierarchy.
    source_blurbs = {
        "Semgrep": (
            "Static rule scan. High-precision Python/Java AST + taint "
            "rules. Low false-positive bar; finds concrete call-site "
            "vulnerabilities."
        ),
        "Copilot": (
            "LLM-driven checklist. Walks every file in the user's IDE "
            "via Copilot Chat. Catches cross-function and absence-of-"
            "control patterns the static rules can't see."
        ),
        "Markdown": (
            "Agent-loaded markdown scan (preview). Checks SKILL.md, "
            "AGENT.md, AGENTS.md, INSTRUCTION(S).md, PROMPT(S).md, and "
            "CLAUDE.md for malicious content, over-broad permissions, "
            "missing integrity metadata, and jailbreak / concealment "
            "markers in body prose. Maps to OWASP Agentic Skills Top "
            "10 (AST10)."
        ),
    }

    for source in ("Semgrep", "Copilot", "Markdown"):
        bucket = grouped.get(source) or []
        parts.append('<div class="ref-source-group">')
        parts.append('<div class="ref-source-header">')
        parts.append(
            f'<span class="ref-source-name">'
            f'{_html_escape(source_display.get(source, source))} '
            f'<span class="ref-source-count">{len(bucket)} '
            f'check{"s" if len(bucket) != 1 else ""}</span></span>'
        )
        parts.append(
            f'<span class="ref-source-blurb">{_html_escape(source_blurbs[source])}</span>'
        )
        parts.append("</div>")

        if not bucket:
            parts.append('<div class="ref-empty">(no checks registered)</div>')
            parts.append("</div>")  # /ref-source-group
            continue

        # F.28: sub-group within each source by D/D/R category. Each
        # sub-group is a `<details>` element — collapsed by default so
        # the user gets a compact overview first and clicks to expand.
        # `<details>/<summary>` is native HTML, no JS required.
        for cat in _DDR_ORDER:
            sub_bucket = [r for r in bucket if (r.category or "detect").lower() == cat]
            if not sub_bucket:
                continue
            cat_label, cat_subtitle, _desc, _q = _DDR_LABELS[cat]
            parts.append(
                f'<details class="ref-group ref-group-{cat}">'
                f'<summary class="ref-group-summary">'
                f'<span class="ref-group-name">{_html_escape(cat_label)}</span>'
                f'<span class="ref-group-sub">{_html_escape(cat_subtitle)}</span>'
                f'<span class="ref-group-count">{len(sub_bucket)} '
                f'check{"s" if len(sub_bucket) != 1 else ""}</span>'
                f'</summary>'
            )
            parts.append('<div class="ref-cards">')
            for ref in sub_bucket:
                _render_reference_card(parts, ref)
            parts.append("</div>")  # /ref-cards
            parts.append("</details>")  # /ref-group
        parts.append("</div>")  # /ref-source-group
    parts.append("</div>")  # /reference-card
    _render_how_it_works(parts)


def _render_how_it_works(parts: list[str]) -> None:
    """Render the "How AgentShield works" staged flowchart.

    Lives at the bottom of the Reference tab so a reader who's just
    scanned the rule catalogue gets the end-to-end mental model in the
    same place. Pure HTML/CSS — no SVG dependency, prints cleanly.
    """
    parts.append('<div class="how-it-works">')
    parts.append('<h3 class="how-title">How AgentShield works</h3>')
    parts.append(
        '<p class="how-subtitle">End-to-end pipeline. Phase 1 (static) '
        'always runs; Phase 2 (runtime probe) is opt-in via '
        '<code>agentshield probe</code> when a target endpoint is '
        'available.</p>'
    )
    parts.append('<div class="how-stages">')

    # Stage 1 — Input
    parts.append(
        '<div class="how-stage how-stage-input">'
        '<div class="how-stage-head">'
        '<span class="how-stage-num">1</span>'
        '<span class="how-stage-title">Input &mdash; target repository</span>'
        '</div>'
        '<div class="how-stage-body">'
        '<ul class="how-list">'
        '<li>Source code &mdash; <code>.py</code>, <code>.java</code>, '
        '<code>.ts</code>, <code>.js</code></li>'
        '<li>Skill manifests &mdash; <code>SKILL.md</code>, '
        '<code>AGENT.md</code>, <code>AGENTS.md</code>, '
        '<code>CLAUDE.md</code>, &hellip;</li>'
        '<li>Bundled config &mdash; <code>.yaml</code>, <code>.json</code>, '
        '<code>.toml</code>, <code>.env</code> in the same directory as '
        'a skill manifest</li>'
        '</ul>'
        '</div>'
        '</div>'
    )
    parts.append('<div class="how-arrow" aria-hidden="true">&#9660;</div>')

    # Stage 2 — Static analysis
    parts.append(
        '<div class="how-stage how-stage-static">'
        '<div class="how-stage-head">'
        '<span class="how-stage-num">2</span>'
        '<span class="how-stage-title">Static analysis '
        '<span class="how-stage-phase">Phase 1 &mdash; always runs</span>'
        '</span>'
        '</div>'
        '<div class="how-stage-body">'
        '<div class="how-substages">'
        '<div class="how-sub-box">'
        '<div class="how-sub-title">Rules-engine Scan</div>'
        '<ul class="how-sub-list">'
        '<li>Semgrep against <code>.py</code> / <code>.java</code> '
        'with the bundled rule pack</li>'
        '<li>Manifest scanner (AST01&ndash;AST09) against agent '
        '<code>.md</code> + bundled config</li>'
        '<li>Cross-skill correlation pass (AST08) when ≥2 manifests</li>'
        '</ul>'
        '<div class="how-sub-out">&rarr; '
        '<code>.agentshield/tier1-results.json</code></div>'
        '</div>'
        '<div class="how-sub-box">'
        '<div class="how-sub-title">LLM-as-a-Judge Scan (Copilot)</div>'
        '<ul class="how-sub-list">'
        '<li>Reviews Tier 1 findings &mdash; verdict + reasoning</li>'
        '<li>Adds Tier 2 findings the static rules missed</li>'
        '<li>Reads code and markdown manifests as a domain expert</li>'
        '</ul>'
        '<div class="how-sub-out">&rarr; '
        '<code>.agentshield/tier2-findings.json</code></div>'
        '</div>'
        '</div>'
        '</div>'
        '</div>'
    )
    parts.append('<div class="how-arrow how-arrow-optional" aria-hidden="true">&#9660;</div>')

    # Stage 3 — Runtime probe (optional)
    parts.append(
        '<div class="how-stage how-stage-runtime">'
        '<div class="how-stage-head">'
        '<span class="how-stage-num">3</span>'
        '<span class="how-stage-title">Runtime probe '
        '<span class="how-stage-phase how-stage-phase-optional">'
        'Phase 2 &mdash; runs when <code>agentshield probe</code> '
        'is invoked</span>'
        '</span>'
        '</div>'
        '<div class="how-stage-body">'
        '<div class="how-substages">'
        '<div class="how-sub-box">'
        '<div class="how-sub-title">Probe orchestrator</div>'
        '<ul class="how-sub-list">'
        '<li>Reads each finding, looks up payloads by rule_id</li>'
        '<li>Walks payload variants until one lands</li>'
        '<li>Sends payloads to the agent\'s normal application '
        'surface &mdash; no target cooperation needed</li>'
        '<li>Mock harness intercepts destructive payloads &mdash; '
        'no HTTP egress for those</li>'
        '</ul>'
        '</div>'
        '<div class="how-sub-box">'
        '<div class="how-sub-title">Classifier</div>'
        '<ul class="how-sub-list">'
        '<li>Heuristic: JSON-path + substring on response</li>'
        '<li>LLM judge (Copilot-shaped, swappable Bedrock backend) '
        '&mdash; verdict + reasoning + confidence</li>'
        '<li>Defensive HTTP codes (401/403/429/451) &rarr; blocked</li>'
        '</ul>'
        '<div class="how-sub-out">&rarr; '
        '<code>.agentshield/probe-results.json</code></div>'
        '</div>'
        '</div>'
        '<p class="how-stage-note">Rules whose runtime check would '
        'need the target to expose dedicated introspection endpoints '
        '(AST02 loaded-skill drift, AST09 logging enforcement) stay '
        'static-only by default &mdash; standard agent runtimes don\'t '
        'ship those endpoints, so we don\'t pretend a probe can run. '
        'If a host runtime adopts the convention, the static rule '
        'graduates to live verification automatically.</p>'
        '</div>'
        '</div>'
    )
    parts.append('<div class="how-arrow" aria-hidden="true">&#9660;</div>')

    # Stage 4 — Merge & render
    parts.append(
        '<div class="how-stage how-stage-merge">'
        '<div class="how-stage-head">'
        '<span class="how-stage-num">4</span>'
        '<span class="how-stage-title">Merge &amp; render</span>'
        '</div>'
        '<div class="how-stage-body">'
        '<ul class="how-list">'
        '<li>Combines Tier 1 + Tier 2 findings; tags Tier 1 with '
        'Tier 2 verdicts (TP / CD / FP)</li>'
        '<li>Reads <code>probe-results.json</code> if present and '
        'attaches the live trace to each finding (LIVE badge)</li>'
        '<li>D/D/R categorisation &mdash; Detect (surfaces) / Defend '
        '(missing controls) / Respond (observability gaps)</li>'
        '<li>Builds the framework-coverage matrix &mdash; OWASP LLM, '
        'OWASP Agentic, MITRE ATLAS, CWE, AST10</li>'
        '</ul>'
        '</div>'
        '</div>'
    )
    parts.append('<div class="how-arrow" aria-hidden="true">&#9660;</div>')

    # Stage 5 — Outputs
    parts.append(
        '<div class="how-stage how-stage-output">'
        '<div class="how-stage-head">'
        '<span class="how-stage-num">5</span>'
        '<span class="how-stage-title">Output artifacts</span>'
        '</div>'
        '<div class="how-stage-body">'
        '<ul class="how-list">'
        '<li><code>output/agentshield-report.html</code> &mdash; '
        'interactive dashboard (this page)</li>'
        '<li><code>output/agentshield-report-print.html</code> &mdash; '
        'static / printable variant</li>'
        '<li><code>output/agentshield-{semgrep,manifest,copilot}-fixes.md</code> '
        '&mdash; per-tier remediation handoffs</li>'
        '<li><code>output/agentshield-redteam-payloads.md</code> &mdash; '
        'attack walkthroughs for red-team engagement</li>'
        '</ul>'
        '</div>'
        '</div>'
    )

    parts.append('</div>')  # /how-stages
    parts.append('</div>')  # /how-it-works


def _render_reference_card(parts: list[str], ref: Any) -> None:
    """Emit one rule's reference card. Split out so the sub-grouping
    code in F.28 can call it without nested-list indentation getting
    out of hand."""
    sev = (ref.severity or "info").lower()
    parts.append('<div class="ref-card-item">')
    parts.append('<div class="ref-card-head">')
    parts.append(
        f'<span class="ref-id">{_html_escape(ref.agentshield_id)}</span>'
    )
    if ref.legacy_ids:
        legacy_str = ", ".join(ref.legacy_ids)
        parts.append(
            f'<span class="ref-legacy" title="Pre-rename ID(s)">'
            f'was {_html_escape(legacy_str)}</span>'
        )
    sev_meaning = _html_escape(_SEVERITY_MEANINGS.get(sev, ""))
    parts.append(
        f'<span class="pill {sev}" '
        f'data-tip="{sev_meaning}" aria-label="{sev_meaning}">'
        f'{_html_escape(sev)}</span>'
    )
    if ref.languages:
        parts.append(
            f'<span class="ref-langs">{_html_escape(ref.languages)}</span>'
        )
    cat = (ref.category or "detect").lower()
    parts.append(
        f'<span class="ref-cat ref-cat-{cat}">{_html_escape(cat)}</span>'
    )
    parts.append("</div>")
    parts.append(f'<div class="ref-title">{_html_escape(ref.title)}</div>')
    parts.append(f'<div class="ref-desc">{_html_escape(ref.description)}</div>')
    # Path B+: list the SDKs whose call-site patterns this rule covers.
    # Three states:
    #   non-empty list   → comma-separated names
    #   empty + Tier 1   → SDK-agnostic note (the rule matches string
    #                      literals or generic patterns rather than
    #                      specific SDK constructors)
    #   empty + Copilot  → skip entirely (no patterns to scan)
    if getattr(ref, "sdks_covered", None):
        parts.append(
            f'<div class="ref-sdks"><span class="ref-sdks-label">Covers:</span> '
            f'{_html_escape(", ".join(ref.sdks_covered))}</div>'
        )
    elif ref.source == "Semgrep":
        parts.append(
            '<div class="ref-sdks ref-sdks-agnostic">'
            '<span class="ref-sdks-label">Covers:</span> '
            'SDK-agnostic &mdash; matches string-literal content / '
            'generic patterns, fires on any code path regardless of '
            'which LLM SDK or framework wraps it.'
            '</div>'
        )
    if ref.frameworks:
        parts.append('<div class="ref-fw">')
        for k_field, items in ref.frameworks.items():
            label = _FRAMEWORK_LABEL.get(k_field, k_field)
            for item in items:
                parts.append(
                    f'<span class="finding-tag">'
                    f'{_html_escape(label)} {_html_escape(item)}</span>'
                )
        parts.append("</div>")
    if ref.skip_if:
        parts.append(
            f'<details class="ref-skip"><summary>Skip if</summary>'
            f'<p>{_html_escape(ref.skip_if)}</p></details>'
        )
    if ref.remediation:
        parts.append(
            f'<div class="ref-remediation"><strong>Fix:</strong> '
            f'{_html_escape(ref.remediation)}</div>'
        )
    parts.append("</div>")  # /ref-card-item


def render_combined_sarif(result: MergeResult) -> str:
    """SARIF v2.1.0 with two `runs`: one per tier (Tier 1 toolComponent +
    Tier 2 toolComponent). Lets CI tooling (GitHub code-scanning, etc.)
    distinguish the source while still ingesting both.
    """
    r = result.report

    def _to_sarif_result(f: dict, rule_prefix: str) -> dict:
        rule_id = f.get("rule_id") or f.get("rule_id_short") or "unknown"
        return {
            "ruleId": f"{rule_prefix}/{rule_id}",
            "level": _severity_to_sarif_level(f.get("severity") or "medium"),
            "message": {"text": f.get("message", "")},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.get("file", "")},
                        "region": {"startLine": int(f.get("line", 1) or 1)},
                    }
                }
            ],
        }

    runs = [
        {
            "tool": {
                "driver": {
                    "name": "AgentShield-Tier1-semgrep",
                    "version": "v2",
                    "informationUri": "https://github.com/suganthiaravind/agentshield",
                }
            },
            "results": [
                _to_sarif_result(ann.finding, "tier1")
                for ann in r.tier1_findings
                if ann.tier2_verdict != "FP"  # FP-marked findings excluded from CI gating
            ],
            "properties": {
                "tier": 1,
                "fingerprint": r.tier1_fingerprint,
                "tier1_marked_fp_excluded": sum(
                    1 for ann in r.tier1_findings if ann.tier2_verdict == "FP"
                ),
            },
        }
    ]
    if result.tier2_present and not result.schema_errors:
        runs.append(
            {
                "tool": {
                    "driver": {
                        "name": "AgentShield-Tier2-Copilot",
                        "version": "v2",
                        "informationUri": "https://github.com/suganthiaravind/agentshield",
                    }
                },
                "results": [
                    _to_sarif_result(f, "tier2") for f in r.tier2_findings
                ],
                "properties": {
                    "tier": 2,
                    "fingerprint": r.tier2_fingerprint,
                    "stale": result.stale,
                },
            }
        )
    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": runs,
    }
    return json.dumps(sarif, indent=2) + "\n"


def _severity_to_sarif_level(sev: str) -> str:
    """SARIF allows: error / warning / note / none. Map AgentShield severities."""
    return {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
        "info": "note",
    }.get(sev.lower(), "warning")
