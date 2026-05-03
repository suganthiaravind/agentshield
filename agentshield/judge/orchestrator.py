"""Tier 3 judge orchestrator (Track B4).

Routes every fallback-tier Finding through a JudgeBackend and
attaches the resulting TriageVerdict. Framework-tier findings pass
through unchanged — they're high-precision by construction and
don't need triage.

Backend errors are caught per finding and converted to a
needs_review verdict so a single Bedrock blip doesn't fail the
whole scan (LLM_JUDGE_DESIGN.md §9 — "default to needs_review on
timeout / outage rather than blocking the report").
"""

from __future__ import annotations

import logging

from agentshield.judge.backend import JudgeBackend
from agentshield.judge.source_window import (
    extract_imports,
    read_code_window,
    read_matched_line,
)
from agentshield.judge.types import JudgeBackendError, JudgeRequest
from agentshield.normalize.schema import Finding, TriageVerdict

logger = logging.getLogger(__name__)


class JudgeOrchestrator:
    """Apply a JudgeBackend to every tier-2 fallback Finding."""

    DEFAULT_CONTEXT_LINES = 20

    def __init__(
        self,
        backend: JudgeBackend,
        context_lines: int = DEFAULT_CONTEXT_LINES,
    ) -> None:
        self.backend = backend
        self.context_lines = context_lines

    def triage(self, findings: list[Finding]) -> list[Finding]:
        """Return a new list with TriageVerdict attached to each fallback Finding.

        Non-fallback findings pass through unchanged. Backend errors are
        caught per finding and converted to a low-confidence needs_review
        verdict so the report still surfaces the finding for a human.
        """
        out: list[Finding] = []
        for finding in findings:
            if finding.tier != "fallback":
                out.append(finding)
                continue
            verdict = self._triage_one(finding)
            out.append(finding.model_copy(update={"triage": verdict}))
        return out

    def _triage_one(self, finding: Finding) -> TriageVerdict:
        request = self._build_request(finding)
        try:
            return self.backend.judge(request)
        except JudgeBackendError as exc:
            logger.warning(
                "Judge backend error on %s:%s — defaulting to needs_review (%s)",
                finding.location.file_path,
                finding.location.start_line,
                exc,
            )
            return TriageVerdict(
                verdict="needs_review",
                confidence=0.0,
                reasoning=f"Backend error: {exc}"[:240],
                llm_framework_guess=None,
                backend=self.backend.name,
                model_id=self.backend.model_id,
            )

    def _build_request(self, finding: Finding) -> JudgeRequest:
        path = finding.location.file_path
        line = finding.location.start_line
        language = finding.language or "python"
        return JudgeRequest(
            rule_id=finding.rule_id,
            rule_id_short=finding.rule_id_short,
            language=language,
            file_path=path,
            line=line,
            matched_code=finding.location.snippet or read_matched_line(path, line),
            code_window=read_code_window(path, line, self.context_lines),
            imports_in_file=extract_imports(path, language),
        )

    @staticmethod
    def count_fallback(findings: list[Finding]) -> int:
        return sum(1 for f in findings if f.tier == "fallback")
