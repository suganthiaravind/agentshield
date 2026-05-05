"""Unit tests for the mock judge backend.

Validates that the mock backend conforms to the JudgeBackend protocol,
returns deterministic `needs_review` verdicts on every call, and never
makes any external (network / LLM) call. The mock is shipped so VDI /
dev users can smoke-test the orchestrator pipeline before they have
AWS Bedrock access.
"""

from __future__ import annotations

from agentshield.judge import (
    JudgeBackend,
    JudgeRequest,
    MockJudgeBackend,
)
from agentshield.normalize.schema import TriageVerdict


def _request(rule_short: str = "unsanitized-user-input-to-llm-fallback") -> JudgeRequest:
    return JudgeRequest(
        rule_id=f"agentshield.detect.{rule_short}",
        rule_id_short=rule_short,
        language="python",
        file_path="src/handlers/chat.py",
        line=47,
        matched_code="client.invoke(user_msg)",
        code_window="...20 lines around the match...",
        imports_in_file=["openai", "boto3"],
    )


def test_mock_backend_satisfies_judge_backend_protocol() -> None:
    backend = MockJudgeBackend()
    assert isinstance(backend, JudgeBackend)
    assert backend.name == "mock"
    assert backend.model_id == "mock-model-no-llm-called"


def test_mock_backend_is_always_available() -> None:
    """No external dependency → is_available() is always True."""
    assert MockJudgeBackend().is_available() is True


def test_mock_backend_returns_needs_review_verdict() -> None:
    backend = MockJudgeBackend()
    verdict = backend.judge(_request())
    assert isinstance(verdict, TriageVerdict)
    assert verdict.verdict == "needs_review"
    assert verdict.confidence == 0.5
    assert verdict.backend == "mock"
    assert verdict.model_id == "mock-model-no-llm-called"
    assert verdict.llm_framework_guess is None


def test_mock_backend_reasoning_includes_rule_id_and_disclaimer() -> None:
    """Reasoning must (a) name the rule so the user can confirm the
    backend was actually invoked and (b) clearly say 'mock' so a leaked
    finding can never be confused with a real triage result."""
    backend = MockJudgeBackend()
    verdict = backend.judge(_request("untrusted-document-loader-to-rag-fallback"))
    assert "untrusted-document-loader-to-rag-fallback" in verdict.reasoning
    assert "mock" in verdict.reasoning.lower()
    assert "no real LLM was called" in verdict.reasoning.lower() or \
           "no real llm" in verdict.reasoning.lower()


def test_mock_backend_is_deterministic() -> None:
    """Two calls with different requests both return the fixed verdict
    shape — the mock isn't trying to simulate a real triage, it's
    smoke-testing the pipeline."""
    backend = MockJudgeBackend()
    v1 = backend.judge(_request("rule-one"))
    v2 = backend.judge(_request("rule-two"))
    assert v1.verdict == v2.verdict == "needs_review"
    assert v1.confidence == v2.confidence == 0.5
    assert v1.backend == v2.backend == "mock"


def test_mock_backend_accepts_custom_model_id() -> None:
    """For audit reproducibility tests — same convention as Boto3BedrockBackend."""
    backend = MockJudgeBackend(model_id="custom-tag-v2")
    assert backend.model_id == "custom-tag-v2"
    verdict = backend.judge(_request())
    assert verdict.model_id == "custom-tag-v2"
