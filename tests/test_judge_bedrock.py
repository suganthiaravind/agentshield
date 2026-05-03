"""Unit tests for the boto3-Bedrock judge backend (B1).

Uses a MagicMock-based fake bedrock-runtime client so tests are
hermetic — no AWS credentials, no network. The contract under test:
backend → JudgeRequest → TriageVerdict, with correct error handling
on transport failure and unparseable model output.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest

from agentshield.judge import (
    Boto3BedrockBackend,
    JudgeBackend,
    JudgeBackendError,
    JudgeRequest,
)
from agentshield.normalize.schema import TriageVerdict


def _request() -> JudgeRequest:
    return JudgeRequest(
        rule_id="agentshield.detect.unsanitized-user-input-to-llm-fallback",
        rule_id_short="unsanitized-user-input-to-llm-fallback",
        language="python",
        file_path="src/handlers/chat.py",
        line=47,
        matched_code="client.invoke(user_msg)",
        code_window="...20 lines around the match...",
        imports_in_file=["openai", "boto3", "internal.utils"],
    )


def _bedrock_response(text: str) -> dict:
    """Shape mirrors the real Bedrock Converse API output."""
    return {"output": {"message": {"content": [{"text": text}]}}}


def _confirmed_json() -> str:
    return json.dumps(
        {
            "verdict": "confirmed",
            "confidence": 0.85,
            "reasoning": "boto3.client('bedrock-runtime') two lines above; user_msg taints invoke call.",
            "llm_framework_guess": "boto3-bedrock",
        }
    )


# --- Protocol conformance --------------------------------------------------


def test_boto3bedrock_satisfies_judge_backend_protocol() -> None:
    backend = Boto3BedrockBackend(model_id="anthropic.claude-3-7-sonnet-20250219-v1:0")
    assert isinstance(backend, JudgeBackend)
    assert backend.name == "boto3-bedrock"
    assert backend.model_id == "anthropic.claude-3-7-sonnet-20250219-v1:0"


# --- Happy path ------------------------------------------------------------


def test_judge_returns_triage_verdict_on_valid_response() -> None:
    fake_client = MagicMock()
    fake_client.converse.return_value = _bedrock_response(_confirmed_json())
    backend = Boto3BedrockBackend(model_id="m1", client=fake_client)
    verdict = backend.judge(_request())
    assert isinstance(verdict, TriageVerdict)
    assert verdict.verdict == "confirmed"
    assert verdict.confidence == 0.85
    assert verdict.backend == "boto3-bedrock"
    assert verdict.model_id == "m1"
    assert verdict.llm_framework_guess == "boto3-bedrock"


def test_judge_passes_temperature_zero_and_system_prompt() -> None:
    fake_client = MagicMock()
    fake_client.converse.return_value = _bedrock_response(_confirmed_json())
    backend = Boto3BedrockBackend(model_id="m1", client=fake_client)
    backend.judge(_request())
    call = fake_client.converse.call_args
    assert call.kwargs["modelId"] == "m1"
    assert call.kwargs["inferenceConfig"]["temperature"] == 0.0
    assert call.kwargs["system"] and "AgentShield" in call.kwargs["system"][0]["text"]


def test_judge_strips_markdown_code_fences() -> None:
    fake_client = MagicMock()
    wrapped = f"```json\n{_confirmed_json()}\n```"
    fake_client.converse.return_value = _bedrock_response(wrapped)
    backend = Boto3BedrockBackend(model_id="m1", client=fake_client)
    verdict = backend.judge(_request())
    assert verdict.verdict == "confirmed"


def test_reasoning_truncated_to_240_chars() -> None:
    long_reasoning = "x" * 500
    fake_client = MagicMock()
    fake_client.converse.return_value = _bedrock_response(
        json.dumps(
            {
                "verdict": "confirmed",
                "confidence": 0.7,
                "reasoning": long_reasoning,
                "llm_framework_guess": None,
            }
        )
    )
    backend = Boto3BedrockBackend(model_id="m1", client=fake_client)
    verdict = backend.judge(_request())
    assert len(verdict.reasoning) == 240


# --- Error paths -----------------------------------------------------------


def test_judge_raises_on_invalid_json() -> None:
    fake_client = MagicMock()
    fake_client.converse.return_value = _bedrock_response("this is not json at all")
    backend = Boto3BedrockBackend(model_id="m1", client=fake_client)
    with pytest.raises(JudgeBackendError, match="not valid JSON"):
        backend.judge(_request())


def test_judge_raises_on_missing_required_field() -> None:
    fake_client = MagicMock()
    fake_client.converse.return_value = _bedrock_response(
        json.dumps({"verdict": "confirmed", "confidence": 0.5})  # missing reasoning
    )
    backend = Boto3BedrockBackend(model_id="m1", client=fake_client)
    with pytest.raises(JudgeBackendError, match="missing required field"):
        backend.judge(_request())


def test_judge_raises_on_invalid_verdict() -> None:
    fake_client = MagicMock()
    fake_client.converse.return_value = _bedrock_response(
        json.dumps({"verdict": "maybe", "confidence": 0.5, "reasoning": "x"})
    )
    backend = Boto3BedrockBackend(model_id="m1", client=fake_client)
    with pytest.raises(JudgeBackendError, match="invalid verdict"):
        backend.judge(_request())


def test_judge_raises_on_bedrock_transport_error() -> None:
    fake_client = MagicMock()
    fake_client.converse.side_effect = Exception("ThrottlingException")
    backend = Boto3BedrockBackend(model_id="m1", client=fake_client)
    with pytest.raises(JudgeBackendError, match="Bedrock converse failed"):
        backend.judge(_request())


def test_judge_raises_on_malformed_response_shape() -> None:
    fake_client = MagicMock()
    fake_client.converse.return_value = {"unexpected": "shape"}
    backend = Boto3BedrockBackend(model_id="m1", client=fake_client)
    with pytest.raises(JudgeBackendError):
        backend.judge(_request())


# --- Availability ----------------------------------------------------------


def test_is_available_true_when_client_injected() -> None:
    backend = Boto3BedrockBackend(model_id="m1", client=MagicMock())
    assert backend.is_available() is True
