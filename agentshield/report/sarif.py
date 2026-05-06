"""SARIF v2.1.0 writer — primary AgentShield output format.

Industry standard consumed by GitHub code scanning, SonarQube, Azure
DevOps, IntelliJ, VS Code, etc. Hand-built (no external SARIF lib)
to keep the dependency footprint minimal — SARIF is a well-defined
JSON schema and we only need the subset semgrep already taught us.

Custom AgentShield fields (agentshield_id, tier, confidence,
framework_mappings) live under `properties` on results and rule
descriptors — supported by the SARIF spec without breaking standard
consumers.
"""

from __future__ import annotations

import json
from pathlib import Path

from agentshield import __version__
from agentshield.normalize import Finding

SARIF_SCHEMA = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/schemas/sarif-schema-2.1.0.json"
SARIF_VERSION = "2.1.0"
TOOL_NAME = "AgentShield"
TOOL_INFO_URI = "https://github.com/suganthiaravind/agentshield"

# Map our internal severity ladder to SARIF's `level` field. SARIF only
# defines 4 levels (none/note/warning/error); we stash the original
# severity in properties for fidelity.
_SARIF_LEVEL: dict[str, str] = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


class SarifWriter:
    """Render a list of Findings as SARIF v2.1.0 JSON."""

    def write(self, findings: list[Finding], output_path: Path | None = None) -> str:
        sarif = self._build(findings)
        text = json.dumps(sarif, indent=2)
        if output_path is not None:
            # Force UTF-8 — SARIF preserves snippets and messages verbatim from
            # source files / rule descriptions, which may contain non-ASCII.
            output_path.write_text(text, encoding="utf-8")
        return text

    def _build(self, findings: list[Finding]) -> dict:
        # Deduplicate rule descriptors by canonical rule_id; the rule list is
        # the SARIF "tool.driver.rules" schema field.
        rules_by_id: dict[str, dict] = {}
        for f in findings:
            if f.rule_id not in rules_by_id:
                rules_by_id[f.rule_id] = self._rule_descriptor(f)

        return {
            "$schema": SARIF_SCHEMA,
            "version": SARIF_VERSION,
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": TOOL_NAME,
                            "version": __version__,
                            "informationUri": TOOL_INFO_URI,
                            "rules": list(rules_by_id.values()),
                        }
                    },
                    "results": [self._result(f, list(rules_by_id).index(f.rule_id)) for f in findings],
                }
            ],
        }

    @staticmethod
    def _rule_descriptor(f: Finding) -> dict:
        return {
            "id": f.rule_id,
            "name": f.rule_id_short,
            "shortDescription": {"text": f.rule_id_short},
            "fullDescription": {"text": f.message[:400]},
            "defaultConfiguration": {"level": _SARIF_LEVEL.get(f.severity, "warning")},
            "properties": {
                "agentshield_id": f.agentshield_id,
                "category": f.category,
                "tier": f.tier,
                "severity_normalized": f.severity,
                "confidence": f.confidence,
                "language": f.language or "",
                "framework_mappings": f.framework_mappings.model_dump(),
            },
        }

    @staticmethod
    def _result(f: Finding, rule_index: int) -> dict:
        region: dict = {"startLine": f.location.start_line}
        if f.location.start_column is not None:
            region["startColumn"] = f.location.start_column
        if f.location.end_line is not None:
            region["endLine"] = f.location.end_line
        if f.location.end_column is not None:
            region["endColumn"] = f.location.end_column
        if f.location.snippet:
            region["snippet"] = {"text": f.location.snippet}

        result: dict = {
            "ruleId": f.rule_id,
            "ruleIndex": rule_index,
            "level": _SARIF_LEVEL.get(f.severity, "warning"),
            "message": {"text": f.message},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.location.file_path},
                        "region": region,
                    }
                }
            ],
            "properties": {
                "agentshield_id": f.agentshield_id,
                "category": f.category,
                "tier": f.tier,
                "severity_normalized": f.severity,
                "confidence": f.confidence,
                "framework_mappings": f.framework_mappings.model_dump(),
            },
        }
        return result
