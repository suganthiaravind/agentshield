"""Fixture: should trigger R002 (LLM I/O logged without redaction).

User input + LLM completion both flow into log statements with no
intermediate redactor / hasher / length-only projection. OWASP LLM02.

Suppresses DF001 + R001 (existing rules) by importing nemoguardrails
+ structlog so the golden cleanly shows R002 alone.
"""
import nemoguardrails  # noqa: F401  (suppresses DF001)
import structlog  # noqa: F401  (suppresses R001)

import logging

from flask import Flask, request
from langchain_openai import ChatOpenAI

app = Flask(__name__)
log = logging.getLogger(__name__)
chain = ChatOpenAI(model="gpt-4o-mini")


@app.route("/chat", methods=["POST"])
def chat():
    prompt = request.json["q"]
    log.info(f"User asked: {prompt}")  # R002

    response = chain.invoke(prompt)
    log.info(f"Model returned: {response.content}")  # R002

    log.debug("debug detail prompt=%s response=%s", prompt, response.content)  # R002

    print(f"console: prompt={prompt}")  # R002

    logging.warning(f"Audit: user submitted {prompt}")  # R002

    return response.content
