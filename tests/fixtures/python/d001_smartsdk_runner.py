"""Fixture: SMARTSDK runner.run_stream sink — should trigger DF001 + (taint allowing) D001.

This mirrors the JPMC SMARTSDK target shape:
- imports from smart_sdk.agents and smart_sdk.runners
- builds an Agent + LocalRunner
- streams responses from runner.run_stream(agent, user_prompt)
- has a logger (so R001 stays silent — by design, we can't tell statically
  whether the logger actually audits LLM calls)
- imports NO guardrail library — DF001 should fire

User input enters via Flask, which IS a recognized D001 taint source. The
SMARTSDK runner.run_stream(...) sink is in our D001 sink list so the full
source→sink path should be detected.
"""
import logging

from flask import Flask, request
from smart_sdk.agents import Agent
from smart_sdk.runners import LocalRunner

logger = logging.getLogger(__name__)
app = Flask(__name__)


def build_agent() -> Agent:
    return Agent(name="MortgageSpecialist", description="...", model=None)


@app.route("/chat")
def chat():
    user_prompt = request.args.get("q")
    agent = build_agent()
    runner = LocalRunner(app_name="demo", user_id="u1", session_id="s1")
    logger.info("invoking agent")
    return runner.run_stream(agent, user_prompt)
