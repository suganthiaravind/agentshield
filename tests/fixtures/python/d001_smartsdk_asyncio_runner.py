"""Fixture: SMARTSDK with awaited runner — matches the JPMC
moip-cost-anomaly-probe-lambda extract_anomaly.py shape.

Diagnosed against real prod code: the SMARTSDK runner is invoked via
`await runner.run(agent, prompt)` (or async-for over run_stream).
Semgrep treats `await expr` as a distinct AST node, so without
explicit `await` patterns in the rules, these calls silently don't
match. Without these fixtures, scans of real SMARTSDK code returned
0 findings — see commit message for the diagnosis trail.

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
