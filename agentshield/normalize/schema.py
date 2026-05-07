"""Internal Finding schema. The single source of truth that downstream
report writers and the merger (F.5) consume.

Designed to outlive any one input format — currently fed by SARIF
from semgrep, but a future runtime-analysis component (e.g. dynamic
red-teaming) could produce Finding objects too.

Phase F.9 cleanup (2026-05-06):
- `Tier` narrowed to "framework" only. v1's "fallback"/"judge"/"discovery"
  values have no producer in v2 (D001-fb retired in F.2; judge/discovery
  tiers deleted in F.6).
- `Confidence` field on Finding kept on the type but always "high" in
  v2 — semgrep rules in the active pack are all narrow taint or narrow
  regex by construction.
- `TriageVerdict` class + `triage` field deleted. Tier 2's TP/CD/FP
  cross-check verdicts on Tier 1 findings live in the merger's
  separate Tier1FPCallout shape, not on the Finding type.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

Category = Literal["detect", "defend", "respond"]
Tier = Literal["framework"]  # narrowed in F.9; v1 had 4 values
Severity = Literal["critical", "high", "medium", "low", "info"]
Confidence = Literal["high", "medium", "low"]


class FrameworkMappings(BaseModel):
    """Pointers into external security taxonomies. Many-to-one with a Finding."""

    owasp_llm: list[str] = Field(default_factory=list)
    owasp_agentic: list[str] = Field(default_factory=list)
    nist_ai_rmf: list[str] = Field(default_factory=list)
    mitre_atlas: list[str] = Field(default_factory=list)
    cwe: list[str] = Field(default_factory=list)
    # F.24: OWASP Agentic Skills Top 10 (AST01–AST10). Tagged on findings
    # produced by the manifest scanner (which targets SKILL.md files); also
    # available for code-scan rules where an AST mapping is meaningful.
    ast: list[str] = Field(default_factory=list)
    agentshield_v1: list[str] = Field(default_factory=list)


class CodeLocation(BaseModel):
    """Where in the scanned source the finding was raised."""

    file_path: str
    start_line: int
    start_column: int | None = None
    end_line: int | None = None
    end_column: int | None = None
    snippet: str | None = None


class Finding(BaseModel):
    """A single security finding, normalized from any input source."""

    # Identity.
    rule_id: str  # full canonical id, e.g. agentshield.detect.unsanitized-user-input-to-llm
    rule_id_short: str  # last segment
    agentshield_id: str  # e.g. AS-D-001

    # Categorization — the dual mapping pattern: exactly one D/D/R category,
    # plus many framework_mappings.
    category: Category
    tier: Tier  # always "framework" in v2; field retained for output-schema stability
    severity: Severity
    confidence: Confidence

    # Location and message.
    location: CodeLocation
    message: str
    language: str | None = None

    # External taxonomy mappings.
    framework_mappings: FrameworkMappings = Field(default_factory=FrameworkMappings)
