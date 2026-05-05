"""Fixture: should NOT trigger R002.

Each log call passes through a redactor / hasher / length projection
before reaching the log sink, OR logs structured fields the developer
controls (no raw user / LLM content).
"""
import nemoguardrails  # noqa: F401  (suppresses DF001)
import structlog  # noqa: F401  (suppresses R001)

import hashlib
import logging

from flask import Flask, request
from langchain_openai import ChatOpenAI


app = Flask(__name__)
log = logging.getLogger(__name__)
chain = ChatOpenAI(model="gpt-4o-mini")


def redact(s: str) -> str:
    """In-house redactor — strips PII before logging."""
    return s  # implementation elided; pattern-name is the signal


@app.route("/chat-hash", methods=["POST"])
def chat_hash():
    prompt = request.json["q"]
    prompt_hash = hashlib.sha256(prompt.encode()).hexdigest()
    log.info(f"User asked (hash={prompt_hash})")  # OK — hash, not content

    response = chain.invoke(prompt)
    response_hash = hashlib.sha256(response.content.encode()).hexdigest()
    log.info(f"Model returned (hash={response_hash})")  # OK
    return response.content


@app.route("/chat-redact", methods=["POST"])
def chat_redact():
    prompt = request.json["q"]
    log.info(f"User asked: {redact(prompt)}")  # OK — redactor on the path

    response = chain.invoke(prompt)
    log.info(f"Model returned: {redact(response.content)}")  # OK
    return response.content


@app.route("/chat-len", methods=["POST"])
def chat_len():
    prompt = request.json["q"]
    log.info(f"prompt len={len(prompt)}")  # OK — length only, content lost

    response = chain.invoke(prompt)
    log.info("response_len=%d", len(response.content))  # OK
    return response.content


@app.route("/chat-fields", methods=["POST"])
def chat_fields():
    prompt = request.json["q"]
    response = chain.invoke(prompt)
    # Logging structured fields we control — no raw prompt/completion content.
    log.info({"role": "user", "msg_id": "abc-123", "model": "gpt-4o-mini"})
    return response.content
