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
            output_path.write_text(text)
        return text

    @staticmethod
    def _summary(findings: list[Finding]) -> dict:
        by_category: dict[str, int] = {"detect": 0, "defend": 0, "respond": 0}
        by_tier: dict[str, int] = {"framework": 0, "fallback": 0, "judge": 0, "discovery": 0}
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
