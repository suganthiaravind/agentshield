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

def render_combined_markdown(result: MergeResult) -> str:
    """Human-readable unified report. The primary v2 deliverable."""
    r = result.report
    lines: list[str] = ["# AgentShield combined report (Tier 1 + Tier 2)\n"]

    # Banner section
    if not result.tier2_present:
        lines.append(
            "> ⚠ **INCOMPLETE: Tier 2 not run.** This report contains Tier 1\n"
            "> (semgrep) findings only. Run Copilot Tier 2 against this repo\n"
            "> and re-merge for full coverage. See\n"
            "> `.agentshield/tier2-bootstrap.md` for the prompt.\n"
        )
    elif result.schema_errors:
        lines.append(
            "> ❌ **Tier 2 output failed schema validation.** Showing Tier 1\n"
            "> only. Validation errors below — re-prompt Copilot to fix and\n"
            "> re-merge.\n"
        )
        lines.append("### Schema errors\n")
        for err in result.schema_errors:
            lines.append(f"- `{err.field_path}` — {err.message}")
        lines.append("")
    elif result.stale:
        lines.append(
            "> ⚠ **STALE Tier 2.** The Tier 1 fingerprint changed since\n"
            "> Tier 2 was run, meaning the code (or Tier 1 rule pack)\n"
            "> changed in between. Re-run Tier 2 in Copilot Chat for fresh\n"
            "> results.\n>\n"
            f"> - Tier 1 fingerprint (current):  `{r.tier1_fingerprint[:16]}...`\n"
            f"> - Tier 2 fingerprint (recorded): `{(r.tier2_fingerprint or '')[:16]}...`\n"
        )

    # Summary
    tier1_total = len(r.tier1_findings)
    tier2_total = len(r.tier2_findings)
    fp_marked = sum(1 for f in r.tier1_findings if f.tier2_verdict == "FP")
    cd_marked = sum(1 for f in r.tier1_findings if f.tier2_verdict == "CD")
    tp_marked = sum(1 for f in r.tier1_findings if f.tier2_verdict == "TP")

    # DDR (Detect / Defend / Respond) breakdown — AgentShield's organising
    # spine. Tier 1 findings carry `category` from rule metadata; Tier 2
    # findings carry it from the schema's `category` enum field.
    ddr_counts = _ddr_counts(r)

    lines.append("## Summary\n")
    lines.append("| Metric | Count |")
    lines.append("|---|---|")
    lines.append(f"| Tier 1 (semgrep) findings | {tier1_total} |")
    lines.append(f"| Tier 2 (Copilot) net-new findings | {tier2_total} |")
    if result.tier2_present and not result.schema_errors:
        lines.append(f"| Tier 1 marked TP by Tier 2 | {tp_marked} |")
        lines.append(f"| Tier 1 marked CD by Tier 2 | {cd_marked} |")
        lines.append(f"| Tier 1 marked FP by Tier 2 | {fp_marked} |")
    lines.append(f"| **Net actionable** | **{result.actionable_finding_count}** |")
    lines.append("")

    lines.append("### Findings by Detect / Defend / Respond category\n")
    lines.append("| Category | Tier 1 | Tier 2 | Total |")
    lines.append("|---|---|---|---|")
    for cat in ("detect", "defend", "respond"):
        t1 = ddr_counts["tier1"][cat]
        t2 = ddr_counts["tier2"][cat]
        lines.append(f"| {cat} | {t1} | {t2} | {t1 + t2} |")
    lines.append("")

    # Tier 1 section
    lines.append("## Tier 1 findings (semgrep)\n")
    if not r.tier1_findings:
        lines.append("_No Tier 1 findings._\n")
    else:
        for i, ann in enumerate(r.tier1_findings):
            f = ann.finding
            verdict_tag = ""
            if ann.tier2_verdict == "FP":
                verdict_tag = " ⚠ **Tier 2 verdict: FP**"
            elif ann.tier2_verdict == "CD":
                verdict_tag = " 🟡 **Tier 2 verdict: CD**"
            elif ann.tier2_verdict == "TP":
                verdict_tag = " ✅ **Tier 2 verdict: TP**"
            severity = f.get("severity") or f.get("severity_normalized") or "n/a"
            rule = f.get("rule_id") or f.get("rule_id_short") or "?"
            file_ = f.get("file") or "?"
            line_ = f.get("line") or "?"
            category = f.get("category") or "n/a"
            lines.append(f"### [{i}] {rule}{verdict_tag}")
            lines.append(f"- **Category:** {category} (D/D/R)")
            lines.append(f"- **Severity:** {severity}")
            lines.append(f"- **Location:** `{file_}:{line_}`")
            if f.get("message"):
                lines.append(f"- **Message:** {f['message']}")
            if ann.tier2_reasoning:
                lines.append(f"- **Tier 2 reasoning:** {ann.tier2_reasoning}")
            lines.append("")

    # Tier 2 net-new section
    lines.append("## Tier 2 net-new findings (Copilot)\n")
    if not result.tier2_present:
        lines.append("_Tier 2 not run._\n")
    elif result.schema_errors:
        lines.append("_Tier 2 output invalid — see schema errors above._\n")
    elif not r.tier2_findings:
        lines.append("_No Tier 2 net-new findings._\n")
    else:
        for f in r.tier2_findings:
            sev = f.get("severity", "n/a")
            rid = f.get("rule_id", "?")
            file_ = f.get("file", "?")
            line_ = f.get("line", "?")
            category = f.get("category", "n/a")
            lines.append(f"### {rid}")
            lines.append(f"- **Category:** {category} (D/D/R)")
            lines.append(f"- **Severity:** {sev}")
            lines.append(f"- **Location:** `{file_}:{line_}`")
            if f.get("message"):
                lines.append(f"- **Message:** {f['message']}")
            mappings = []
            for k in ("owasp_llm", "owasp_agentic", "mitre_atlas", "cwe"):
                if f.get(k):
                    mappings.append(f"{k}={','.join(f[k])}")
            if mappings:
                lines.append(f"- **Frameworks:** {' · '.join(mappings)}")
            if f.get("snippet"):
                lines.append(f"- **Snippet:** `{f['snippet']}`")
            if f.get("remediation"):
                lines.append(f"- **Remediation:** {f['remediation']}")
            lines.append("")

    # Coverage matrix
    lines.append("## Coverage matrix\n")
    cov = r.coverage.to_dict()
    lines.append("| Framework | Items touched |")
    lines.append("|---|---|")
    for k, vs in cov.items():
        lines.append(f"| {k} | {', '.join(vs) if vs else '_(none)_'} |")
    lines.append("")

    # Skipped files (transparency)
    if r.tier2_skipped_files:
        lines.append("## Tier 2 skipped files\n")
        for s in r.tier2_skipped_files:
            lines.append(f"- `{s.get('path', '?')}` — {s.get('reason', 'no reason given')}")
        lines.append("")

    return "\n".join(lines) + "\n"


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
