"""JSON writer for downstream programmatic consumers.

Simpler than SARIF — emits the full Finding model dump plus a
summary block. Use this when the consumer is a custom dashboard /
ETL pipeline rather than a SARIF-aware tool.
"""

from __future__ import annotations

import json
from pathlib import Path

from agentshield import __version__
from agentshield.normalize import Finding


class JsonWriter:
    """Render Findings as a structured JSON document."""

    def write(self, findings: list[Finding], output_path: Path | None = None) -> str:
        payload = {
            "agentshield_version": __version__,
            "summary": self._summary(findings),
            "findings": [f.model_dump() for f in findings],
        }
        text = json.dumps(payload, indent=2, default=str)
        if output_path is not None:
            # Force UTF-8 — finding messages can contain non-ASCII glyphs that
            # don't fit in Windows cp1252.
            output_path.write_text(text, encoding="utf-8")
        return text

    @staticmethod
    def _summary(findings: list[Finding]) -> dict:
        # Phase F.9: by_tier collapsed to single "framework" bucket — v2's
        # active rule pack is framework-only. Kept as a dict (not just a
        # count) to keep the JSON output schema stable for downstream
        # consumers that already key off `summary.by_tier.framework`.
        by_category: dict[str, int] = {"detect": 0, "defend": 0, "respond": 0}
        by_tier: dict[str, int] = {"framework": 0}
        by_severity: dict[str, int] = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }
        for f in findings:
            by_category[f.category] = by_category.get(f.category, 0) + 1
            by_tier[f.tier] = by_tier.get(f.tier, 0) + 1
            by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
        return {
            "total": len(findings),
            "by_category": by_category,
            "by_tier": by_tier,
            "by_severity": by_severity,
        }
