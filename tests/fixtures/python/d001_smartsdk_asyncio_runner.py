"""Fixture: SMARTSDK with awaited runner — matches the
testbed/smartsdk-lambda extract_anomaly.py shape.

The SMARTSDK runner is typically invoked via `await runner.run(agent,
prompt)` (or async-for over run_stream). semgrep matches sub-expressions,
so the unawaited `$X.run(...)` patterns in DF001 / R001 also match
inside `await ...` wrappers — this fixture pins that behaviour so any
future regression where awaited SMARTSDK calls stop matching is caught
in CI.

Expected goldens:
  - DF001 fires on the awaited runner.run line — file imports
    smart_sdk and has no guardrails library
  - R001 stays silent — file has `logger = logging.getLogger(__name__)`
    setup which Phase E.2 recognises as audit-logging intent. The
    earlier R001 design required structured logging (structlog /
    langsmith / opentelemetry / langchain.callbacks); a real-world
    SMART SDK Lambda judge run showed that was over-strict, FP-ing on
    every Lambda that uses stdlib logging for audit. Relaxed in Phase E.2.
  - D001 does NOT fire because cross-procedural taint isn't tracked
    (user_prompt is in a separate function from the runner.run call).
"""
import asyncio
import logging

from smart_sdk.agents import Agent
from smart_sdk.runners import LocalRunner

logger = logging.getLogger(__name__)


async def _invoke(runner, agent, prompt):
    # Awaited SMARTSDK call — the canonical JPMC shape
    return await runner.run(agent, prompt)


def invoke_bedrock_model(user_prompt: str, system_prompt: str) -> str:
    agent = Agent(name="x", description="y", model=None, system_message=system_prompt)
    runner = LocalRunner(app_name="demo", user_id="u", session_id="s")
    return asyncio.run(_invoke(runner, agent, user_prompt))
