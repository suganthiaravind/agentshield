"""Convert raw semgrep SARIF into typed Finding objects.

Semgrep doesn't propagate our custom rule metadata (category,
agentshield_id, framework_mappings, tier) to SARIF output, so the
normalizer reads the bundled YAML rule pack at construction time
and indexes by canonical rule id.

When semgrep emits a SARIF result, its `ruleId` is prefixed with
the file path (e.g. "agentshield.rules.detect.agentshield.detect.
unsanitized-user-input-to-llm"). We resolve back to the canonical
id by suffix-matching against the known YAML rule ids.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from agentshield.normalize.schema import (
    CodeLocation,
    Confidence,
    Finding,
    FrameworkMappings,
    Severity,
    Tier,
)


class NormalizerError(RuntimeError):
    """Raised when SARIF input is malformed or a rule's metadata is missing."""


# Map semgrep's YAML-level severity to our normalized severity ladder.
# Rule files may also set `metadata.severity_normalized` which takes priority.
_SEMGREP_SEVERITY_MAP: dict[str, Severity] = {
    "ERROR": "high",
    "WARNING": "medium",
    "INFO": "low",
}


class Normalizer:
    """SARIF → list[Finding] using bundled rule metadata for enrichment."""

    def __init__(self, rules_path: Path | None = None) -> None:
        self.rules_path = rules_path or self._default_rules_path()
        self._rules_by_id = self._load_rules(self.rules_path)

    @staticmethod
    def _default_rules_path() -> Path:
        # agentshield/normalize/normalizer.py → agentshield/rules/
        rules = Path(__file__).resolve().parent.parent / "rules"
        if not rules.is_dir():
            raise NormalizerError(f"Bundled rules directory not found at {rules}")
        return rules

    @staticmethod
    def _load_rules(rules_path: Path) -> dict[str, dict[str, Any]]:
        """Build canonical-rule-id → full rule dict from the bundled YAMLs."""
        index: dict[str, dict[str, Any]] = {}
        for yaml_path in rules_path.rglob("*.yaml"):
            try:
                data = yaml.safe_load(yaml_path.read_text()) or {}
            except yaml.YAMLError as exc:
                raise NormalizerError(f"Failed to parse {yaml_path}: {exc}") from exc
            for rule in data.get("rules") or []:
                rule_id = rule.get("id")
                if rule_id:
                    index[rule_id] = rule
        return index

    def _canonical_rule_id(self, semgrep_rule_id: str) -> str | None:
        """Suffix-match semgrep's prefixed rule_id back to a known canonical id."""
        if semgrep_rule_id in self._rules_by_id:
            return semgrep_rule_id
        for canonical in self._rules_by_id:
            if semgrep_rule_id.endswith(canonical):
                return canonical
        return None

    @staticmethod
    def _resolve_severity(rule: dict[str, Any]) -> Severity:
        normalized = (rule.get("metadata") or {}).get("severity_normalized")
        if normalized in {"critical", "high", "medium", "low", "info"}:
            return normalized  # type: ignore[return-value]
        sev = (rule.get("severity") or "").upper()
        return _SEMGREP_SEVERITY_MAP.get(sev, "medium")

    @staticmethod
    def _resolve_tier(rule: dict[str, Any]) -> Tier:
        meta_tier = (rule.get("metadata") or {}).get("tier")
        if meta_tier == "fallback":
            return "fallback"
        return "framework"

    @staticmethod
    def _resolve_confidence(rule: dict[str, Any]) -> Confidence:
        confidence = (rule.get("metadata") or {}).get("confidence")
        if confidence in {"high", "medium", "low"}:
            return confidence  # type: ignore[return-value]
        # Fallback rules default to low; framework rules default to high.
        if (rule.get("metadata") or {}).get("tier") == "fallback":
            return "low"
        return "high"

    @staticmethod
    def _resolve_language(rule: dict[str, Any]) -> str | None:
        languages = rule.get("languages") or []
        return languages[0] if languages else None

    @staticmethod
    def _build_framework_mappings(rule: dict[str, Any]) -> FrameworkMappings:
        mappings = ((rule.get("metadata") or {}).get("framework_mappings")) or {}
        return FrameworkMappings(
            owasp_llm=list(mappings.get("owasp_llm") or []),
            owasp_agentic=list(mappings.get("owasp_agentic") or []),
            nist_ai_rmf=list(mappings.get("nist_ai_rmf") or []),
            mitre_atlas=list(mappings.get("mitre_atlas") or []),
            cwe=list(mappings.get("cwe") or []),
            agentshield_v1=list(mappings.get("agentshield_v1") or []),
        )

    @staticmethod
    def _build_location(sarif_result: dict[str, Any]) -> CodeLocation | None:
        locations = sarif_result.get("locations") or []
        if not locations:
            return None
        physical = locations[0].get("physicalLocation") or {}
        artifact = physical.get("artifactLocation") or {}
        region = physical.get("region") or {}
        uri = artifact.get("uri")
        start_line = region.get("startLine")
        if not uri or start_line is None:
            return None
        return CodeLocation(
            file_path=uri,
            start_line=start_line,
            start_column=region.get("startColumn"),
            end_line=region.get("endLine"),
            end_column=region.get("endColumn"),
            snippet=(region.get("snippet") or {}).get("text"),
        )

    def normalize(self, sarif: dict[str, Any]) -> list[Finding]:
        """Convert SARIF to a list of typed Findings.

        Skips results whose ruleId can't be matched to a bundled rule
        (this should never happen in practice — would indicate a rule
        was deleted between scan and normalize). Skips results with
        unparseable locations.

        Deduplicates on (rule_id, file_path, start_line, start_column,
        end_line, end_column). Two distinct calls on the same line at
        different columns survive (different start_column); the same
        call matched by multiple alternative patterns inside one rule's
        `pattern-either` collapses to a single Finding.
        """
        findings: list[Finding] = []
        seen: set[tuple[str, str, int, int | None, int | None, int | None]] = set()
        for run in sarif.get("runs") or []:
            for result in run.get("results") or []:
                semgrep_id = result.get("ruleId") or ""
                canonical = self._canonical_rule_id(semgrep_id)
                if not canonical:
                    continue
                rule = self._rules_by_id[canonical]
                metadata = rule.get("metadata") or {}
                location = self._build_location(result)
                if location is None:
                    continue
                category = metadata.get("category")
                if category not in {"detect", "defend", "respond"}:
                    continue
                dedup_key = (
                    canonical,
                    location.file_path,
                    location.start_line,
                    location.start_column,
                    location.end_line,
                    location.end_column,
                )
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)
                agentshield_id = metadata.get("agentshield_id") or canonical
                message = (result.get("message") or {}).get("text") or ""
                findings.append(
                    Finding(
                        rule_id=canonical,
                        rule_id_short=canonical.rsplit(".", 1)[-1],
                        agentshield_id=agentshield_id,
                        category=category,
                        tier=self._resolve_tier(rule),
                        severity=self._resolve_severity(rule),
                        confidence=self._resolve_confidence(rule),
                        location=location,
                        message=message.strip(),
                        language=self._resolve_language(rule),
                        framework_mappings=self._build_framework_mappings(rule),
                    )
                )
        # Stable order: by file, then by line, then by rule id.
        findings.sort(key=lambda f: (f.location.file_path, f.location.start_line, f.rule_id))
        return findings

    @staticmethod
    def partition_by_tier(findings: list[Finding]) -> dict[Tier, list[Finding]]:
        """Group findings by tier — useful for routing to the judge or report writer."""
        buckets: dict[Tier, list[Finding]] = {
            "framework": [],
            "fallback": [],
            "judge": [],
            "discovery": [],
        }
        for f in findings:
            buckets[f.tier].append(f)
        return buckets
