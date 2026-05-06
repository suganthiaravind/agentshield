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

    def to_dict(self) -> dict[str, list[str]]:
        return {
            "owasp_llm": sorted(self.owasp_llm),
            "owasp_agentic": sorted(self.owasp_agentic),
            "mitre_atlas": sorted(self.mitre_atlas),
            "cwe": sorted(self.cwe),
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
    return cov


# ---------- renderers ----------

_DDR_LABELS = {
    "detect": ("🔴 Detect", "vulnerability surfaces", "Where the agent is exploitable"),
    "defend": ("🟡 Defend", "missing controls", "What active defences are missing"),
    "respond": ("🔵 Respond", "observability gaps", "Whether incidents can be detected and recovered"),
}

_DDR_ORDER = ("detect", "defend", "respond")

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
    lines.append("# AgentShield combined report")
    lines.append("")
    lines.append(f"_Semgrep Rules-engine Scan + Copilot AI Scan · scanned {r.tier2_scanned_at or '(Semgrep only — Copilot AI Scan not run)'}_")
    lines.append("")
    lines.append("---")
    lines.append("")

    # 2. Status banners
    if not result.tier2_present:
        lines.append(
            "> ⚠ **INCOMPLETE: Copilot AI Scan not run.** This report contains "
            "Semgrep Rules-engine Scan findings only. Run the Copilot AI Scan "
            "against this repo and re-merge for full coverage. See "
            "`.agentshield/tier2-bootstrap.md` for the prompt."
        )
        lines.append("")
    elif result.schema_errors:
        lines.append(
            "> ❌ **Copilot AI Scan output failed schema validation.** Showing "
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
            "> ⚠ **STALE Copilot AI Scan.** The Semgrep fingerprint changed "
            "since the Copilot AI Scan was run; the code (or rule pack) changed "
            "in between. Re-run the Copilot AI Scan in Copilot Chat for fresh "
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
        emoji_label, subtitle, _desc = _DDR_LABELS[cat]
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
    lines.append(f"| Copilot AI Scan net-new findings | {tier2_total} |")
    if result.tier2_present and not result.schema_errors:
        lines.append(f"| Semgrep findings marked TP by Copilot | {tp_marked} |")
        lines.append(f"| Semgrep findings marked CD by Copilot | {cd_marked} |")
        lines.append(f"| Semgrep findings marked FP by Copilot | {fp_marked} |")
    lines.append(f"| **Net actionable** | **{result.actionable_finding_count}** |")
    lines.append("")

    # 5. SAIGE classification (if present)
    if r.saige_tier:
        tier_label = (
            "Non-Agent" if r.saige_tier == "non-agent"
            else f"Tier {r.saige_tier}"
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
        emoji_label, subtitle, desc = _DDR_LABELS[cat]
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
        lines.append("## Tier 2 skipped files")
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

.ddr-card .ddr-label {
  font-size: 11px; letter-spacing: 0.1em; text-transform: uppercase;
  color: var(--text-muted); margin-bottom: 8px; font-weight: 600;
}
.ddr-card.detect  .ddr-label { color: var(--detect); }
.ddr-card.defend  .ddr-label { color: var(--defend); }
.ddr-card.respond .ddr-label { color: var(--respond); }
.ddr-card .ddr-title { font-size: 15px; font-weight: 600; margin-bottom: 4px; }
.ddr-card .ddr-subtitle { font-size: 13px; color: var(--text-muted); margin-bottom: 16px; }
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


def render_combined_html(result: MergeResult) -> str:
    """Standalone HTML report — single file, embedded CSS, no external deps.

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
    sev_total: dict[str, int] = {}
    for bucket in grouped.values():
        for f in bucket:
            s = f.get("severity", "info")
            sev_total[s] = sev_total.get(s, 0) + 1

    parts: list[str] = []
    parts.append("<!doctype html>")
    parts.append('<html lang="en"><head><meta charset="utf-8">')
    parts.append("<title>AgentShield combined report</title>")
    parts.append(f"<style>{_HTML_CSS}</style>")
    parts.append("</head><body>")

    # 1. Header
    parts.append('<div class="report-header">')
    parts.append("<h1>AgentShield combined report</h1>")
    parts.append(
        '<div class="subtitle">Semgrep Rules-engine Scan + Copilot AI Scan'
        + (f' &middot; scanned {_html_escape(r.tier2_scanned_at)}' if r.tier2_scanned_at else " &middot; Copilot AI Scan not run")
        + "</div>"
    )
    parts.append("</div>")

    # 2. Status banners
    if not result.tier2_present:
        parts.append(
            '<div class="banner warn"><strong>INCOMPLETE — Copilot AI Scan not run.</strong> '
            "This report shows Semgrep Rules-engine Scan findings only. Run the "
            "Copilot AI Scan and re-merge for full coverage.</div>"
        )
    elif result.schema_errors:
        parts.append(
            '<div class="banner error"><strong>Copilot AI Scan output failed schema validation.</strong> '
            "Showing Semgrep Rules-engine Scan only. Re-prompt Copilot to fix the validation errors below.</div>"
        )
        parts.append('<div class="section"><h2>Schema errors</h2><ul>')
        for err in result.schema_errors:
            parts.append(f"<li><code>{_html_escape(err.field_path)}</code> &mdash; {_html_escape(err.message)}</li>")
        parts.append("</ul></div>")
    elif result.stale:
        parts.append(
            '<div class="banner stale"><strong>STALE Copilot AI Scan.</strong> '
            "The Semgrep fingerprint changed since the Copilot AI Scan was run; results may be inconsistent. "
            "Re-run the Copilot AI Scan for fresh results.</div>"
        )

    # 3. D/D/R HERO ROW
    parts.append('<div class="ddr-row">')
    for cat in _DDR_ORDER:
        emoji_label, subtitle, _desc = _DDR_LABELS[cat]
        bucket = grouped[cat]
        sev_counts: dict[str, int] = {}
        for f in bucket:
            s = f.get("severity", "info")
            sev_counts[s] = sev_counts.get(s, 0) + 1
        parts.append(f'<div class="ddr-card {cat}">')
        parts.append(f'<div class="ddr-label">{_html_escape(emoji_label.split(" ", 1)[1])}</div>')
        parts.append(f'<div class="ddr-title">{_html_escape(cat.capitalize())}</div>')
        parts.append(f'<div class="ddr-subtitle">{_html_escape(subtitle)}</div>')
        parts.append(f'<div class="ddr-count">{len(bucket)}</div>')
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
    parts.append(f'<div class="metric"><div class="metric-label">Copilot AI Scan</div><div class="metric-value">{tier2_total}</div></div>')
    parts.append(f'<div class="metric"><div class="metric-label">Marked FP by Copilot</div><div class="metric-value">{fp_marked}</div></div>')
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
        tier_label = "Non-Agent" if r.saige_tier == "non-agent" else f"Tier {r.saige_tier}"
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
    for cat in _DDR_ORDER:
        emoji_label, subtitle, desc = _DDR_LABELS[cat]
        bucket = grouped[cat]
        parts.append(f'<div class="findings-section {cat}">')
        parts.append('<div class="section-header">')
        parts.append(f'<span class="section-title">{_html_escape(emoji_label)} &mdash; {_html_escape(subtitle)}</span>')
        parts.append(f'<span class="section-subtitle">{_html_escape(desc)}</span>')
        parts.append(f'<span class="section-count">{len(bucket)} finding{"s" if len(bucket) != 1 else ""}</span>')
        parts.append("</div>")
        if not bucket:
            parts.append(f'<div class="finding"><span style="color:var(--text-muted);font-style:italic;">No {cat} findings.</span></div>')
        else:
            for f in bucket:
                origin = f["_origin"]
                sev = f.get("severity", "info")
                rule = f.get("rule_id_short") or f.get("rule_id") or "?"
                file_ = f.get("file") or "?"
                line_ = f.get("line") or "?"
                parts.append('<div class="finding">')
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
                fm = f.get("framework_mappings") or f
                tags: list[str] = []
                for k_label, k_field in (
                    ("OWASP LLM", "owasp_llm"), ("OWASP Agentic", "owasp_agentic"),
                    ("ATLAS", "mitre_atlas"), ("CWE", "cwe"),
                ):
                    for v in (fm.get(k_field) or []):
                        tags.append(f"{k_label} {v}")
                if tags:
                    parts.append('<div class="finding-tags">')
                    for t in tags:
                        parts.append(f'<span class="finding-tag">{_html_escape(t)}</span>')
                    parts.append("</div>")
                if f.get("snippet"):
                    parts.append(f'<div class="finding-snippet">{_html_escape(f["snippet"])}</div>')
                if f.get("remediation"):
                    parts.append(f'<div class="finding-remediation"><strong>Fix:</strong> {_html_escape(f["remediation"])}</div>')
                if origin == "tier1" and f.get("_tier2_reasoning"):
                    parts.append(f'<div class="finding-remediation"><strong>Copilot reasoning:</strong> {_html_escape(f["_tier2_reasoning"])}</div>')
                parts.append("</div>")
        parts.append("</div>")

    # 8. Coverage matrix
    parts.append('<h2>Coverage matrix</h2>')
    parts.append('<div class="coverage-grid">')
    for k_label, k_key in (
        ("OWASP LLM", "owasp_llm"), ("OWASP Agentic", "owasp_agentic"),
        ("MITRE ATLAS", "mitre_atlas"), ("CWE", "cwe"),
    ):
        items = sorted(getattr(r.coverage, k_key))
        parts.append(f'<div class="coverage-label">{_html_escape(k_label)}</div>')
        if items:
            chips = "".join(f'<span class="coverage-item">{_html_escape(i)}</span>' for i in items)
            parts.append(f'<div class="coverage-items">{chips}</div>')
        else:
            parts.append('<div class="coverage-empty">(none touched)</div>')
    parts.append("</div>")

    # 9. Footer
    parts.append("<footer>")
    parts.append("AgentShield v2 &middot; ")
    if r.tier1_fingerprint:
        parts.append(f'Tier 1 fingerprint <code>{_html_escape(r.tier1_fingerprint[:16])}…</code>')
    parts.append("</footer>")

    parts.append("</body></html>")
    return "\n".join(parts) + "\n"


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
