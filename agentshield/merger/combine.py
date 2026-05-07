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
from pathlib import Path
from typing import Any

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
        "If the agent misbehaves, will you see it and stop it?",
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
    lines.append("# AgentShield Detection Report")
    lines.append("")
    lines.append(f"_Semgrep Rules-engine Scan + Copilot LLM Scan · scanned {r.tier2_scanned_at or '(Semgrep only — Copilot LLM Scan not run)'}_")
    lines.append("")
    lines.append("---")
    lines.append("")

    # 2. Status banners
    if not result.tier2_present:
        lines.append(
            "> ⚠ **INCOMPLETE: Copilot LLM Scan not run.** This report contains "
            "Semgrep Rules-engine Scan findings only. Run the Copilot LLM Scan "
            "against this repo and re-merge for full coverage. See "
            "`.agentshield/tier2-bootstrap.md` for the prompt."
        )
        lines.append("")
    elif result.schema_errors:
        lines.append(
            "> ❌ **Copilot LLM Scan output failed schema validation.** Showing "
            "Semgrep Rules-engine Scan only. Validation errors below — "
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
            "> ⚠ **STALE Copilot LLM Scan.** The Semgrep fingerprint changed "
            "since the Copilot LLM Scan was run; the code (or rule pack) changed "
            "in between. Re-run the Copilot LLM Scan in Copilot Chat for fresh "
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
    lines.append(f"| Semgrep Rules-engine Scan findings | {tier1_total} |")
    lines.append(f"| Copilot LLM Scan net-new findings | {tier2_total} |")
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
        lines.append("## Copilot LLM Scan skipped files")
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
  --border: #e5e3dc;
  --text: #1f2933;
  --text-muted: #6b7280;
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

  --critical-bg: #fdecea;
  --high-bg: #fdf0e0;
  --medium-bg: #fbf3dc;
  --low-bg: #e9f1e7;
  --info-bg: #e8eef2;
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
}

h1, h2, h3 { color: var(--text); margin: 0; font-weight: 600; }
h1 { font-size: 22px; letter-spacing: -0.01em; }
h2 { font-size: 16px; letter-spacing: 0.04em; text-transform: uppercase;
     color: var(--text-muted); margin: 32px 0 12px; }
h3 { font-size: 15px; }

.report-header { padding-bottom: 20px; border-bottom: 1px solid var(--border); margin-bottom: 24px; }
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
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 20px;
  border-top: 4px solid;
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
.ddr-card .ddr-count { font-size: 36px; font-weight: 700; line-height: 1; margin-bottom: 12px; }
.ddr-card .sev-pills { display: flex; flex-wrap: wrap; gap: 6px; }

.pill {
  display: inline-block;
  padding: 3px 10px;
  border-radius: 999px;
  font-size: 11px;
  font-weight: 600;
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

.metrics-row {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 12px;
  margin-bottom: 24px;
}
.metric {
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 14px 18px;
}
.metric .metric-label { font-size: 11px; letter-spacing: 0.08em; text-transform: uppercase;
                        color: var(--text-muted); margin-bottom: 6px; font-weight: 600; }
.metric .metric-value { font-size: 28px; font-weight: 700; line-height: 1; }
.metric .metric-value.actionable { color: var(--accent); }

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
  border: 1px solid var(--border);
  border-left: 4px solid var(--accent);
  border-radius: 10px;
  padding: 18px 22px;
  margin-bottom: 28px;
}
.saige-card .saige-label { font-size: 11px; letter-spacing: 0.08em; text-transform: uppercase;
                           color: var(--text-muted); font-weight: 600; }
.saige-card .saige-tier { font-size: 22px; font-weight: 700; margin: 4px 0 12px; color: var(--accent); }
.saige-card .saige-rationale { color: var(--text); font-size: 13px; line-height: 1.6; }
.saige-card .saige-footer { font-size: 11px; color: var(--text-muted); margin-top: 12px; font-style: italic; }

.section { margin-bottom: 28px; }

.findings-section {
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: 12px;
  margin-bottom: 24px;
  overflow: hidden;
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
  font-weight: 600;
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
.finding-tag { font-size: 10px; font-weight: 600; padding: 2px 8px; border-radius: 4px;
               background: #f1eee5; color: #5a5547; letter-spacing: 0.02em; }
.finding-snippet { font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
                   font-size: 12px; background: #f5f3ec; padding: 6px 10px;
                   border-radius: 4px; margin: 6px 0; color: #2a2620; overflow-x: auto; }
.finding-remediation { font-size: 12px; color: var(--text-muted); margin-top: 6px;
                       padding-left: 12px; border-left: 2px solid var(--border); }

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
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 14px 18px;
  margin-bottom: 20px;
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 10px 16px;
  box-shadow: 0 1px 3px rgba(0,0,0,0.04);
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

/* F.22: tabbed layout — D/D/R + Coverage + Frameworks panels. */
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
  border-bottom: none;
  border-radius: 8px 8px 0 0;
  padding: 9px 16px;
  font-size: 13px;
  font-weight: 600;
  font-family: inherit;
  color: var(--text-muted);
  cursor: pointer;
  display: inline-flex;
  align-items: center;
  gap: 8px;
  margin-bottom: -1px;
  transition: color 0.12s ease, background 0.12s ease, border-color 0.12s ease;
}
.tab-btn:hover { color: var(--text); background: rgba(0,0,0,0.02); }
.tab-btn.active {
  color: var(--accent);
  background: var(--panel);
  border-color: var(--border);
  border-bottom-color: var(--panel);
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
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 22px 24px;
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

/* F.26: Reference tab — "what AgentShield checks for" cards. */
.reference-card {
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 22px 24px;
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


def render_combined_html(result: MergeResult, *, static: bool = False) -> str:
    """Standalone HTML report — single file, embedded CSS, no external deps.

    F.29: when `static=True`, drops the filter bar and the tab navigation;
    every panel renders as a stacked `<section>` with its own heading. Use
    this mode for distribution-ready (printable / emailable / read-without-
    clicking) reports. Default `static=False` keeps the interactive UX.

    Layout (F.17):
      1. Report header (title + scan timestamp)
      2. Status banner if applicable (incomplete / schema-error / stale)
      3. **D/D/R hero row** — three cards, one per category, with severity pills
      4. Metrics row — Tier 1 / Tier 2 / FP-marked / Net actionable
      5. Stacked severity bar
      6. SAIGE classification card (if Tier 2 classified)
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
    sev_total: dict[str, int] = {}
    for bucket in grouped.values():
        for f in bucket:
            s = f.get("severity", "info")
            sev_total[s] = sev_total.get(s, 0) + 1

    parts: list[str] = []
    parts.append("<!doctype html>")
    parts.append('<html lang="en"><head><meta charset="utf-8">')
    parts.append("<title>AgentShield Detection Report</title>")
    parts.append(f"<style>{_HTML_CSS}</style>")
    parts.append("</head><body>")

    # 1. Header
    parts.append('<div class="report-header">')
    parts.append("<h1>AgentShield Detection Report</h1>")
    parts.append(
        '<div class="subtitle">Semgrep Rules-engine Scan + Copilot LLM Scan'
        + (f' &middot; scanned {_html_escape(r.tier2_scanned_at)}' if r.tier2_scanned_at else " &middot; Copilot LLM Scan not run")
        + "</div>"
    )
    parts.append("</div>")

    # 2. Status banners
    if not result.tier2_present:
        parts.append(
            '<div class="banner warn"><strong>INCOMPLETE — Copilot LLM Scan not run.</strong> '
            "This report shows Semgrep Rules-engine Scan findings only. Run the "
            "Copilot LLM Scan and re-merge for full coverage.</div>"
        )
    elif result.schema_errors:
        parts.append(
            '<div class="banner error"><strong>Copilot LLM Scan output failed schema validation.</strong> '
            "Showing Semgrep Rules-engine Scan only. Re-prompt Copilot to fix the validation errors below.</div>"
        )
        parts.append('<div class="section"><h2>Schema errors</h2><ul>')
        for err in result.schema_errors:
            parts.append(f"<li><code>{_html_escape(err.field_path)}</code> &mdash; {_html_escape(err.message)}</li>")
        parts.append("</ul></div>")
    elif result.stale:
        parts.append(
            '<div class="banner stale"><strong>STALE Copilot LLM Scan.</strong> '
            "The Semgrep fingerprint changed since the Copilot LLM Scan was run; results may be inconsistent. "
            "Re-run the Copilot LLM Scan for fresh results.</div>"
        )

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
        # Big finding count
        parts.append(f'<div class="ddr-count" data-ddr-count="{cat}" data-ddr-total="{len(bucket)}">{len(bucket)}</div>')
        # Severity pills
        parts.append('<div class="sev-pills">')
        if not bucket:
            parts.append('<span style="color:var(--text-muted);font-size:12px;">No findings</span>')
        else:
            for sev in ("critical", "high", "medium", "low", "info"):
                n = sev_counts.get(sev, 0)
                if n:
                    parts.append(f'<span class="pill {sev}">{sev} {n}</span>')
        parts.append("</div>")
        parts.append("</div>")
    parts.append("</div>")

    # 4. Metrics row
    tier1_total = len(r.tier1_findings)
    tier2_total = len(r.tier2_findings)
    fp_marked = sum(1 for f in r.tier1_findings if f.tier2_verdict == "FP")
    parts.append('<div class="metrics-row">')
    parts.append(f'<div class="metric"><div class="metric-label">Semgrep Rules-engine Scan</div><div class="metric-value">{tier1_total}</div></div>')
    parts.append(f'<div class="metric"><div class="metric-label">Copilot LLM Scan</div><div class="metric-value">{tier2_total}</div></div>')
    parts.append(f'<div class="metric"><div class="metric-label">Marked False Positive by Copilot</div><div class="metric-value">{fp_marked}</div></div>')
    parts.append(f'<div class="metric"><div class="metric-label">Net actionable</div><div class="metric-value actionable">{result.actionable_finding_count}</div></div>')
    parts.append("</div>")

    # 5. Stacked severity bar
    total_findings = sum(sev_total.values())
    if total_findings:
        parts.append('<div class="section">')
        parts.append('<div style="display:flex;justify-content:space-between;align-items:baseline;margin-bottom:6px;">')
        parts.append('<span style="font-size:12px;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.06em;font-weight:600;">Severity distribution</span>')
        sev_text = " &middot; ".join(
            f'<span class="pill {sev}">{sev_total.get(sev, 0)} {sev}</span>'
            for sev in ("critical", "high", "medium", "low", "info") if sev_total.get(sev, 0)
        )
        parts.append(f"<span>{sev_text}</span>")
        parts.append("</div>")
        parts.append('<div class="severity-bar">')
        for sev in ("critical", "high", "medium", "low", "info"):
            n = sev_total.get(sev, 0)
            if n:
                pct = (n / total_findings) * 100
                parts.append(f'<div class="{sev}" style="width:{pct:.1f}%"></div>')
        parts.append("</div></div>")

    # 6. SAIGE classification
    if r.saige_tier:
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

        # F.22: tab navigation — D/D/R panels + Coverage + Frameworks. The filter
        # bar above applies globally; tab counts update live with the filter
        # state. Initial active tab = Detect.
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
            'aria-selected="false">Coverage</button>'
        )
        parts.append(
            '<button type="button" class="tab-btn" role="tab" data-tab="frameworks" '
            'aria-selected="false">Frameworks</button>'
        )
        parts.append(
            '<button type="button" class="tab-btn" role="tab" data-tab="reference" '
            'aria-selected="false">Reference</button>'
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
                parts.append(
                    f'<span class="sev-mini {sev_key}" data-section-sev="{sev_key}">'
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
                parts.append(f'<span class="pill {sev}">{sev}</span>')
                parts.append(f'<span class="finding-rule">{_html_escape(rule)}</span>')
                if origin == "tier1" and f.get("_tier2_verdict"):
                    v = f["_tier2_verdict"].lower()
                    parts.append(f'<span class="pill {v}">Copilot: {f["_tier2_verdict"]}</span>')
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
                parts.append("</div>")  # /finding-body
                parts.append("</div>")  # /finding
        parts.append("</div>")  # /findings-section
        parts.append("</section>" if static else "</div>")  # /tab-panel (D/D/R)

    # ---- Coverage tab panel ----
    if static:
        parts.append('<section class="static-section" data-panel="coverage">')
    else:
        parts.append('<div class="tab-panel" role="tabpanel" data-panel="coverage">')
    parts.append('<div class="coverage-card">')
    parts.append('<h3 class="panel-title">Coverage matrix</h3>')
    parts.append(
        '<p class="panel-subtitle">Frameworks the unified scan touched. '
        'Click any item in the Frameworks tab to filter findings down to that item.</p>'
    )
    parts.append('<div class="coverage-grid">')
    for k_label, k_key in (
        ("OWASP LLM", "owasp_llm"), ("OWASP Agentic", "owasp_agentic"),
        ("MITRE ATLAS", "mitre_atlas"), ("CWE", "cwe"),
        ("OWASP AST10", "ast"),
    ):
        items = sorted(getattr(r.coverage, k_key))
        parts.append(f'<div class="coverage-label">{_html_escape(k_label)}</div>')
        if items:
            chips = "".join(f'<span class="coverage-item">{_html_escape(i)}</span>' for i in items)
            parts.append(f'<div class="coverage-items">{chips}</div>')
        else:
            parts.append('<div class="coverage-empty">(none touched)</div>')
    parts.append("</div>")
    parts.append("</div>")  # /coverage-card
    parts.append("</section>" if static else "</div>")  # /tab-panel

    # ---- Frameworks tab panel ----
    # Per-framework drill-down: each item shows count + clickable chip that
    # activates the same framework filter the per-finding tags use.
    if static:
        parts.append('<section class="static-section" data-panel="frameworks">')
    else:
        parts.append('<div class="tab-panel" role="tabpanel" data-panel="frameworks">')
    parts.append('<div class="coverage-card">')
    parts.append('<h3 class="panel-title">Findings by Security framework</h3>')
    parts.append(
        '<p class="panel-subtitle">The same findings, regrouped per framework '
        'item, with a per-item count. Click any item to filter the D/D/R '
        'tabs down to findings tagged with it.</p>'
    )
    fw_counts = _framework_finding_counts(r)
    for k_label, k_key, k_url in (
        ("OWASP LLM Top 10 v2", "owasp_llm",
         "https://genai.owasp.org/llm-top-10/"),
        ("OWASP Agentic AI Top 10", "owasp_agentic",
         "https://owasp.org/www-project-agentic-ai-threats/"),
        ("MITRE ATLAS", "mitre_atlas", "https://atlas.mitre.org/"),
        ("CWE first-class", "cwe", "https://cwe.mitre.org/"),
        ("OWASP Agentic Skills Top 10 (preview)", "ast",
         "https://github.com/OWASP/www-project-agentic-skills-top-10"),
    ):
        items = sorted(getattr(r.coverage, k_key))
        parts.append('<div class="framework-group">')
        parts.append(
            f'<div class="framework-group-header">'
            f'<span class="framework-group-name">{_html_escape(k_label)}</span>'
            f'<a href="{_html_escape(k_url)}" class="framework-group-link" '
            f'target="_blank" rel="noopener">reference &rarr;</a>'
            f'</div>'
        )
        if not items:
            parts.append('<div class="framework-empty">(no findings hit this framework)</div>')
        else:
            parts.append('<div class="framework-items">')
            for item in items:
                key = f"{k_key}:{item}"
                count = fw_counts.get(key, 0)
                parts.append(
                    f'<button type="button" class="framework-item" '
                    f'data-framework-key="{_html_escape(key)}" '
                    f'title="Filter findings to those tagged {_html_escape(item)}">'
                    f'<span class="framework-item-id">{_html_escape(item)}</span>'
                    f'<span class="framework-item-count">{count} '
                    f'finding{"s" if count != 1 else ""}</span>'
                    f'</button>'
                )
            parts.append("</div>")
        parts.append("</div>")  # /framework-group
    parts.append("</div>")  # /coverage-card
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


def _render_reference_panel(parts: list[str]) -> None:
    """Emit the inner HTML of the Reference tab panel into `parts`."""
    from agentshield.merger.reference import build_all_references

    refs = build_all_references(
        tier1_rules_path=_DEFAULT_RULES_PATH,
        tier2_checklist_path=_DEFAULT_CHECKLIST_PATH,
    )

    grouped: dict[str, list] = {"Semgrep": [], "Copilot": [], "Manifest": []}
    for ref in refs:
        grouped.setdefault(ref.source, []).append(ref)

    parts.append('<div class="reference-card">')
    parts.append('<h3 class="panel-title">What AgentShield checks for</h3>')
    parts.append(
        '<p class="panel-subtitle">Every rule and checklist entry the '
        "scanner can fire, pulled live from the bundled rule pack. Use this "
        "as a product-coverage reference — independent of what the most "
        "recent scan happened to find.</p>"
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
        "Manifest": (
            "SKILL.md manifest scan (preview). Checks the skill-package "
            "distribution layer for malicious content, over-broad "
            "permissions, and missing integrity metadata. Maps to OWASP "
            "Agentic Skills Top 10 (AST10)."
        ),
    }

    for source in ("Semgrep", "Copilot", "Manifest"):
        bucket = grouped.get(source) or []
        parts.append('<div class="ref-source-group">')
        parts.append('<div class="ref-source-header">')
        parts.append(
            f'<span class="ref-source-name">{_html_escape(source)} '
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
    parts.append(f'<span class="pill {sev}">{_html_escape(sev)}</span>')
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
