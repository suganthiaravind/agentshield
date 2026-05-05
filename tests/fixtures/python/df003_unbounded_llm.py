"""Fixture: should trigger DF003 (no timeout / max_tokens cap).

Each construction below explicitly disables a bound — timeout=None or
max_tokens=None — exposing the worker to indefinite hangs and runaway
output. OWASP LLM10 Unbounded Consumption.

Suppresses DF001 / R001 with nemoguardrails + structlog so the golden
shows DF003 alone.
"""
import nemoguardrails  # noqa: F401  (suppresses DF001)
import structlog  # noqa: F401  (suppresses R001)

import os

import httpx
import openai
import anthropic
from langchain_openai import ChatOpenAI
from langchain_anthropic import ChatAnthropic


def main() -> None:
    # Disabled timeout on direct SDK clients
    a = openai.OpenAI(api_key=os.environ["OPENAI_API_KEY"], timeout=None)  # DF003
    b = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"], timeout=None)  # DF003

    # Disabled max_tokens on LangChain wrappers
    c = ChatOpenAI(model="gpt-4o-mini", max_tokens=None)  # DF003
    d = ChatAnthropic(model="claude-sonnet-4-5", max_tokens=None)  # DF003

    # Disabled timeout on httpx client used as transport
    transport = httpx.Client(timeout=None)  # DF003
    e = openai.OpenAI(api_key=os.environ["OPENAI_API_KEY"], http_client=transport)

    # Disabled max_tokens on a direct API call
    response = a.chat.completions.create(  # DF003
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": "hi"}],
        max_tokens=None,
    )
