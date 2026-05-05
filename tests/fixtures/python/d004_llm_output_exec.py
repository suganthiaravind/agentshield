"""Fixture: should trigger D004 (LLM output -> code execution).

LLM output flows into os.system / exec / subprocess shell=True
without sanitization. Classic LLM05 Improper Output Handling.

Suppresses DF001 via nemoguardrails import and R001 via structlog import,
so the golden cleanly shows D004 alone.
"""
import nemoguardrails  # noqa: F401  (suppresses DF001)
import structlog  # noqa: F401  (suppresses R001)

import os
import subprocess

from langchain_openai import ChatOpenAI


def main() -> None:
    llm = ChatOpenAI()

    response = llm.invoke("write me a shell command")
    os.system(response.content)  # D004 should fire here

    result = llm.invoke("compute pi as python code")
    exec(result.content)  # D004 should fire here

    cmd = llm.invoke("ls /tmp")
    subprocess.run(cmd.content, shell=True, check=True)  # D004 should fire here
