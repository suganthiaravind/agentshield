"""boto3-Bedrock judge backend — the default concrete JudgeBackend.

Uses the Bedrock Runtime Converse API (works with any Converse-
capable model: Claude family, Llama, Mistral, Titan). Calls go
directly to AWS Bedrock without a wrapper SDK — appropriate for
AgentShield's scanner-side LLM access where we have direct boto3
credentials. Per ARCHITECTURE_RATIONALE §3, this is one of three
interchangeable backends; SMARTSDK and Copilot drivers will follow
in subsequent B-track commits and implement the same protocol.

Determinism contract (LLM_JUDGE_DESIGN.md §8): temperature=0,
fixed model_id per scan, full prompt + response loggable to
judge_audit.jsonl by the orchestrator.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from agentshield.judge.prompts import SYSTEM_PROMPT, build_user_prompt
from agentshield.judge.types import JudgeBackendError, JudgeRequest
from agentshield.normalize.schema import TriageVerdict

logger = logging.getLogger(__name__)


class Boto3BedrockBackend:
    """Sends judge requests to AWS Bedrock via boto3."""

    name = "boto3-bedrock"

    def __init__(
        self,
        model_id: str,
        region_name: str = "us-east-1",
        max_tokens: int = 1024,
        client: Any = None,
    ) -> None:
        """Construct a backend pointed at a specific Bedrock model.

        `model_id` is a model identifier or inference-profile ARN
        (e.g. "anthropic.claude-3-7-sonnet-20250219-v1:0" or
        "arn:aws:bedrock:us-east-1:...:application-inference-profile/...").
        `client` is an injection seam for tests — pass a pre-built
        boto3 client (or mock) and the backend will use it instead
        of constructing one. None means construct on first use.
        """
        self.model_id = model_id
        self.region_name = region_name
        self.max_tokens = max_tokens
        self._client = client

    def _get_client(self) -> Any:
        if self._client is None:
            try:
                import boto3
            except ImportError as exc:
                raise JudgeBackendError(
                    "boto3 not installed. Install with: pip install 'agentshield[judge]'"
                ) from exc
            self._client = boto3.client("bedrock-runtime", region_name=self.region_name)
        return self._client

    def is_available(self) -> bool:
        """Quick liveness check — returns True if a client can be obtained."""
        try:
            self._get_client()
            return True
        except JudgeBackendError:
            return False

    def judge(self, request: JudgeRequest) -> TriageVerdict:
        """Render a verdict for one fallback finding.

        Raises JudgeBackendError on transport failure or unparseable model
        output. The orchestrator (Track B4) decides whether to default to
        a needs_review verdict on error or propagate.
        """
        client = self._get_client()
        try:
            response = client.converse(
                modelId=self.model_id,
                messages=[
                    {
                        "role": "user",
                        "content": [{"text": build_user_prompt(request)}],
                    }
                ],
                system=[{"text": SYSTEM_PROMPT}],
                inferenceConfig={
                    "temperature": 0.0,
                    "maxTokens": self.max_tokens,
                },
            )
        except Exception as exc:
            raise JudgeBackendError(
                f"Bedrock converse failed for {request.file_path}:{request.line}: {exc}"
            ) from exc

        text = self._extract_text(response)
        verdict_data = self._parse_verdict(text)
        return TriageVerdict(
            verdict=verdict_data["verdict"],
            confidence=float(verdict_data["confidence"]),
            reasoning=verdict_data["reasoning"][:240],
            llm_framework_guess=verdict_data.get("llm_framework_guess"),
            backend=self.name,
            model_id=self.model_id,
        )

    @staticmethod
    def _extract_text(response: dict[str, Any]) -> str:
        try:
            content = response["output"]["message"]["content"]
            for block in content:
                if "text" in block:
                    return block["text"]
        except (KeyError, TypeError) as exc:
            raise JudgeBackendError(f"Bedrock response shape unexpected: {exc}") from exc
        raise JudgeBackendError("Bedrock response had no text block")

    @staticmethod
    def _parse_verdict(text: str) -> dict[str, Any]:
        """Extract the JSON object the model was instructed to return.

        Tolerates markdown code fences in case the model wraps the JSON
        despite the system prompt asking it not to.
        """
        cleaned = text.strip()
        if cleaned.startswith("```"):
            # strip ```json ... ``` or ``` ... ```
            cleaned = cleaned.split("```", 2)[1]
            if cleaned.startswith("json"):
                cleaned = cleaned[len("json"):]
            cleaned = cleaned.rsplit("```", 1)[0]
            cleaned = cleaned.strip()
        try:
            data = json.loads(cleaned)
        except json.JSONDecodeError as exc:
            raise JudgeBackendError(
                f"Model output was not valid JSON: {exc}. First 200 chars: {text[:200]!r}"
            ) from exc
        for required in ("verdict", "confidence", "reasoning"):
            if required not in data:
                raise JudgeBackendError(
                    f"Model output missing required field {required!r}: {data}"
                )
        if data["verdict"] not in {"confirmed", "dismissed", "needs_review"}:
            raise JudgeBackendError(
                f"Model returned invalid verdict: {data['verdict']!r}"
            )
        return data
