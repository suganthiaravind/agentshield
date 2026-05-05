"""Mock judge backend — for testing the Tier-3 code path without AWS.

The intended user is a VDI / dev-environment validator who wants to
confirm the orchestrator → backend → verdict-attachment pipeline works
before they have AWS Bedrock access (or want to avoid burning real
LLM tokens during smoke tests). It is NOT a triage backend — every
verdict is a deterministic placeholder, never a real assessment.

CLI: `agentshield scan <path> --llm-backend mock`. The output verdict
is always `needs_review` with a clearly-labelled "mock backend" reason
so it can never be mistaken for a real triage result if it leaks into
a downstream report. See VDI_TESTING.md Stage 4.5 for the playbook.
"""

from __future__ import annotations

from agentshield.judge.types import JudgeRequest
from agentshield.normalize.schema import TriageVerdict


class MockJudgeBackend:
    """Deterministic mock implementation of the JudgeBackend protocol.

    Returns a fixed `needs_review` verdict on every call. Useful for
    smoke-testing the orchestrator + CLI plumbing without depending on
    AWS Bedrock credentials. The reasoning text explicitly says "mock"
    so a reader can never confuse a mocked finding with a real verdict.
    """

    name: str = "mock"

    def __init__(self, model_id: str = "mock-model-no-llm-called") -> None:
        self.model_id = model_id

    def is_available(self) -> bool:
        """Always available — no external dependencies."""
        return True

    def judge(self, request: JudgeRequest) -> TriageVerdict:
        """Return a fixed-shape verdict; ignore the request content.

        We do read the request only to surface the rule_id_short in the
        reasoning string — this lets a reader confirm the backend was
        actually invoked on the expected finding (versus silently
        skipped). No LLM is called.
        """
        return TriageVerdict(
            verdict="needs_review",
            confidence=0.5,
            reasoning=(
                "Mock backend — no real LLM was called. This finding has "
                "NOT been triaged. Re-run with `--llm-backend boto3-bedrock` "
                f"(or another real backend) to triage rule "
                f"`{request.rule_id_short}`. See VDI_TESTING.md "
                "Stage 4.5 for the mock-testing playbook."
            ),
            llm_framework_guess=None,
            backend=self.name,
            model_id=self.model_id,
        )
