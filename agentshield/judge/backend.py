"""Pluggable judge backend protocol — see ARCHITECTURE_RATIONALE §3.

Concrete implementations: Boto3BedrockBackend (this commit), plus
SMARTSDKBackend and CopilotBackend in subsequent B-track commits.
The orchestrator (B4) holds one backend instance per scan and
calls .judge() on every tier-2 fallback finding.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from agentshield.judge.types import JudgeRequest
from agentshield.normalize.schema import TriageVerdict


@runtime_checkable
class JudgeBackend(Protocol):
    """All concrete backends implement this protocol.

    `name` is the short identifier used in CLI flags and config:
    "boto3-bedrock", "smartsdk", "copilot".
    `model_id` is the specific model (e.g. a Bedrock inference-profile
    ARN); recorded in the TriageVerdict for audit reproducibility.
    """

    name: str
    model_id: str

    def judge(self, request: JudgeRequest) -> TriageVerdict: ...

    def is_available(self) -> bool: ...
