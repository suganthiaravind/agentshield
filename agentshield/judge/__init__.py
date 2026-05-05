"""Tier 3 LLM judge — pluggable backends + orchestrator. Track B.

Currently implemented: Boto3BedrockBackend (B1), MockJudgeBackend (testing),
JudgeOrchestrator (B4). Planned: SMARTSDKBackend (B2), CopilotBackend (B3),
audit logger (B5).

See LLM_JUDGE_DESIGN.md for protocol, prompt design, and audit contract.
"""

from agentshield.judge.backend import JudgeBackend
from agentshield.judge.boto3_bedrock import Boto3BedrockBackend
from agentshield.judge.mock_backend import MockJudgeBackend
from agentshield.judge.orchestrator import JudgeOrchestrator
from agentshield.judge.types import JudgeBackendError, JudgeRequest

__all__ = [
    "Boto3BedrockBackend",
    "JudgeBackend",
    "JudgeBackendError",
    "JudgeOrchestrator",
    "JudgeRequest",
    "MockJudgeBackend",
]
