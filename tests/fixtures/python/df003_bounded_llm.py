"""Fixture: should NOT trigger DF003.

Every LLM construction either sets a finite timeout / max_tokens, or
omits the kwarg entirely (relying on the SDK default — typically 600s
timeout for OpenAI / Anthropic, model-specific max_tokens default).
DF003 only fires on EXPLICIT None — defaults are out of scope.
"""
import nemoguardrails  # noqa: F401  (suppresses DF001)
import structlog  # noqa: F401  (suppresses R001)

import os

import httpx
import openai
import anthropic
from langchain_openai import ChatOpenAI


def main() -> None:
    # Default timeout (600s SDK default) — no explicit None.
    a = openai.OpenAI(api_key=os.environ["OPENAI_API_KEY"])
    # Finite timeout in seconds.
    b = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"], timeout=30.0)
    # Finite max_tokens.
    c = ChatOpenAI(model="gpt-4o-mini", max_tokens=512)
    # httpx with finite timeout.
    transport = httpx.Client(timeout=httpx.Timeout(20.0))
    d = openai.OpenAI(api_key=os.environ["OPENAI_API_KEY"], http_client=transport)
    # API call with finite max_tokens.
    response = a.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": "hi"}],
        max_tokens=256,
        timeout=15.0,
    )
