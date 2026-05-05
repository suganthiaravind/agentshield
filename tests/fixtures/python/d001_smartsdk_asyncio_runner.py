"""Fixture: SMARTSDK with awaited runner — matches the
testbed/smartsdk-lambda extract_anomaly.py shape.

The SMARTSDK runner is typically invoked via `await runner.run(agent,
prompt)` (or async-for over run_stream). semgrep matches sub-expressions,
so the unawaited `$X.run(...)` patterns in DF001 / R001 also match
inside `await ...` wrappers — this fixture pins that behaviour so any
future regression where awaited SMARTSDK calls stop matching is caught
in CI.

Expected goldens (after the await-pattern fix):
  - DF001 fires on the awaited runner.run line — file imports
    smart_sdk and has no guardrails library
  - R001 fires on the same line — file imports stdlib `logging`
    for error handling but has no structured LLM audit trail
    (structlog / langsmith / opentelemetry / langchain.callbacks).
    The R001 rule was tightened: plain `import logging` no longer
    silences it
  - D001 may also fire if user_prompt taints to the sink, but
    cross-procedural taint isn't supported, so realistically only
    DF001 + R001 fire here
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
