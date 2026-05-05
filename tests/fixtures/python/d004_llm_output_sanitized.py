"""Fixture: should NOT trigger D004.

LLM output is either sanitized (shlex.split / shlex.quote / ast.literal_eval)
or fed to a non-shell sink (subprocess WITHOUT shell=True), so the rule
should not fire even though LLM output reaches a subprocess / eval-shaped
call.

Suppresses DF001 / R001 the same way as the positive fixture so the golden
shows zero findings for this file.
"""
import nemoguardrails  # noqa: F401  (suppresses DF001)
import structlog  # noqa: F401  (suppresses R001)

import ast
import shlex
import subprocess

from langchain_openai import ChatOpenAI


def main() -> None:
    llm = ChatOpenAI()

    # shlex.split + list-form subprocess: no shell interpretation.
    response = llm.invoke("write me a shell command")
    subprocess.run(shlex.split(response.content), check=True)

    # ast.literal_eval only evaluates literals, never arbitrary code.
    literal = llm.invoke("a python literal value")
    _ = ast.literal_eval(literal.content)

    # subprocess without shell=True with list args: argv-style, safe.
    parts = llm.invoke("first arg")
    subprocess.run([parts.content, "--flag"], check=False)
