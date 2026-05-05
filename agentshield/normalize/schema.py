"""Internal Finding schema. The single source of truth that downstream
report writers (Track A4) and the LLM judge (Track B) consume.

Designed to outlive any one input format — currently fed by SARIF
from semgrep, but a future runtime tier (Phase II) can produce
Finding objects too.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

Category = Literal["detect", "defend", "respond"]
Tier = Literal["framework", "fallback", "judge", "discovery"]
Severity = Literal["critical", "high", "medium", "low", "info"]
Confidence = Literal["high", "medium", "low"]


class FrameworkMappings(BaseModel):
    """Pointers into external security taxonomies. Many-to-one with a Finding."""

    owasp_llm: list[str] = Field(default_factory=list)
    owasp_agentic: list[str] = Field(default_factory=list)
    nist_ai_rmf: list[str] = Field(default_factory=list)
    mitre_atlas: list[str] = Field(default_factory=list)
    cwe: list[str] = Field(default_factory=list)
    agentshield_v1: list[str] = Field(default_factory=list)


class CodeLocation(BaseModel):
    """Where in the scanned source the finding was raised."""

    file_path: str
    start_line: int
    start_column: int | None = None
    end_line: int | None = None
    end_column: int | None = None
    snippet: str | None = None


class TriageVerdict(BaseModel):
    """LLM-judge output, attached to fallback findings by Track B."""

    verdict: Literal["confirmed", "dismissed", "needs_review"]
    confidence: float
    reasoning: str
    llm_framework_guess: str | None = None
    backend: str  # boto3-bedrock | smartsdk | copilot
    model_id: str


class Finding(BaseModel):
    """A single security finding, normalized from any input source."""

    # Identity — both the canonical AgentShield ID (AS-D-001) and the rule id.
    rule_id: str  # full canonical id, e.g. agentshield.detect.unsanitized-user-input-to-llm
    rule_id_short: str  # last segment, e.g. unsanitized-user-input-to-llm
    agentshield_id: str  # e.g. AS-D-001 (or AS-D-001-FALLBACK)

    # Categorization — the dual mapping pattern (see ARCHITECTURE_RATIONALE §4):
    # exactly one D/D/R category, plus many framework_mappings.
    category: Category
    tier: Tier
    severity: Severity
    confidence: Confidence

    # Location and message.
    location: CodeLocation
    message: str
    language: str | None = None

    # External taxonomy mappings.
    framework_mappings: FrameworkMappings = Field(default_factory=FrameworkMappings)

    # Triage verdict from Track B; None until the judge tier runs.
    triage: TriageVerdict | None = None
