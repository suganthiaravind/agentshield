"""DF003 — explicit timeout=None / max_tokens=None on LLM clients."""

import os

import httpx
import openai
import anthropic
from langchain_openai import ChatOpenAI
from langchain_anthropic import ChatAnthropic


def build_unbounded_clients():
    a = openai.OpenAI(api_key=os.environ["OPENAI_API_KEY"], timeout=None)
    b = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"], timeout=None)
    c = ChatOpenAI(model="gpt-4o-mini", max_tokens=None)
    d = ChatAnthropic(model="claude-sonnet-4-5", max_tokens=None)
    transport = httpx.Client(timeout=None)
    e = openai.OpenAI(api_key=os.environ["OPENAI_API_KEY"], http_client=transport)
    response = a.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": "hi"}],
        max_tokens=None,
    )
    return a, b, c, d, e, response
