"""Markdown writer for human review.

Groups findings by D/D/R category, surfaces framework mappings
inline, and renders the location as a clickable file:line link.
Designed to read well in a PR comment, GitHub Issue, or email.
"""

from __future__ import annotations

from pathlib import Path

from agentshield import __version__
from agentshield.normalize import Finding, FrameworkMappings

_CATEGORY_TITLES = {
    "detect": "Detect — vulnerability surfaces",
    "defend": "Defend — missing controls",
    "respond": "Respond — observability gaps",
}

_SEVERITY_BADGE = {
    "critical": "🔴 critical",
    "high": "🔴 high",
    "medium": "🟡 medium",
    "low": "🟢 low",
    "info": "ℹ️  info",
}


class MarkdownWriter:
    """Render Findings as a structured Markdown report."""

    def write(self, findings: list[Finding], output_path: Path | None = None) -> str:
        text = self._build(findings)
        if output_path is not None:
            output_path.write_text(text)
        return text

    def _build(self, findings: list[Finding]) -> str:
        lines: list[str] = []
        lines.append(f"# AgentShield Report (v{__version__})")
        lines.append("")
        lines.extend(self._summary_block(findings))
        lines.append("")

        for category in ("detect", "defend", "respond"):
            cat_findings = [f for f in findings if f.category == category]
            if not cat_findings:
                continue
            lines.append(f"## {_CATEGORY_TITLES[category]} ({len(cat_findings)})")
            lines.append("")
            for f in cat_findings:
                lines.extend(self._finding_block(f))
                lines.append("")

        return "\n".join(lines).rstrip() + "\n"

    @staticmethod
    def _summary_block(findings: list[Finding]) -> list[str]:
        if not findings:
            return ["No findings.", ""]
        cat_count: dict[str, int] = {}
        tier_count: dict[str, int] = {}
        sev_count: dict[str, int] = {}
        for f in findings:
            cat_count[f.category] = cat_count.get(f.category, 0) + 1
            tier_count[f.tier] = tier_count.get(f.tier, 0) + 1
            sev_count[f.severity] = sev_count.get(f.severity, 0) + 1
        return [
            f"**{len(findings)} finding(s)**",
            "",
            "| Category | Count | | Tier | Count | | Severity | Count |",
            "|---|---|---|---|---|---|---|---|",
            f"| detect | {cat_count.get('detect', 0)} | | framework | {tier_count.get('framework', 0)} | | high | {sev_count.get('high', 0)} |",
            f"| defend | {cat_count.get('defend', 0)} | | fallback | {tier_count.get('fallback', 0)} | | medium | {sev_count.get('medium', 0)} |",
            f"| respond | {cat_count.get('respond', 0)} | | judge | {tier_count.get('judge', 0)} | | low | {sev_count.get('low', 0)} |",
        ]

    @staticmethod
    def _finding_block(f: Finding) -> list[str]:
        loc = f"{f.location.file_path}:{f.location.start_line}"
        badge = _SEVERITY_BADGE.get(f.severity, f.severity)
        return [
            f"### {f.agentshield_id} — `{f.rule_id_short}`",
            "",
            f"- **Severity:** {badge}",
            f"- **Tier:** {f.tier} | **Confidence:** {f.confidence}",
            f"- **Location:** [`{loc}`]({loc})",
            f"- **Mappings:** {MarkdownWriter._render_mappings(f.framework_mappings)}",
            "",
            f"> {f.message}",
        ]

    @staticmethod
    def _render_mappings(m: FrameworkMappings) -> str:
        parts: list[str] = []
        if m.owasp_llm:
            parts.append(f"OWASP LLM {', '.join(m.owasp_llm)}")
        if m.owasp_agentic:
            parts.append(f"OWASP Agentic {', '.join(m.owasp_agentic)}")
        if m.nist_ai_rmf:
            parts.append(f"NIST AI RMF {', '.join(m.nist_ai_rmf)}")
        if m.mitre_atlas:
            parts.append(f"MITRE ATLAS {', '.join(m.mitre_atlas)}")
        if m.agentshield_v1:
            parts.append(f"AS-v1 {', '.join(m.agentshield_v1)}")
        return " · ".join(parts) if parts else "_(no external mappings)_"
