"""Request type for judge backends. Response is the existing TriageVerdict
from agentshield.normalize.schema (so it can attach directly to a Finding).
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class JudgeRequest(BaseModel):
    """Per-finding context the judge needs to render a verdict.

    Built by the orchestrator (Track B4) from a Finding plus the
    surrounding code window and imports. The backend itself only
    consumes this object and emits a TriageVerdict.
    """

    rule_id: str
    rule_id_short: str
    language: str
    file_path: str
    line: int
    matched_code: str
    code_window: str  # ±20 lines around the match, with line numbers
    imports_in_file: list[str] = Field(default_factory=list)


class JudgeBackendError(RuntimeError):
    """Raised by a backend when it cannot produce a verdict.

    Distinct from "model returned a verdict of needs_review" — that
    is a valid result, not an error. This exception covers transport
    failures (network, throttling, auth) and unparseable model output.
    """
