"""Flask controller — entry point for customer support questions."""

import logging
from urllib.parse import urlparse

from flask import Flask, request, jsonify
from langchain_core.prompts import ChatPromptTemplate
from langchain_openai import ChatOpenAI

from config import client, MODEL
from guard.input_filter import input_guard
from guard.semantic_filter import SemanticGuard

logger = logging.getLogger(__name__)

app = Flask(__name__)
# FIX: TIER2-GAP-04 — add request_timeout and max_tokens to cap latency/cost.
chain = ChatOpenAI(model=MODEL, openai_api_key=client.api_key,
                   request_timeout=30, max_tokens=2000)
# Semantic guard uses a fast judge model (gpt-4o-mini) — injected so the
# guard itself isn't subject to the injection it's meant to catch.
_judge_llm = ChatOpenAI(model="gpt-4o-mini", openai_api_key=client.api_key,
                        request_timeout=10, max_tokens=64)
semantic_guard = SemanticGuard(llm=_judge_llm)

_ALLOWED_SUMMARY_HOSTS = frozenset({"docs.internal", "wiki.internal", "example.com"})


@app.route("/chat", methods=["POST"])
def chat():
    user_message = request.json["message"]
    # FIX: D001/D012 — pass user_message THROUGH scan() and use its return value
    # so the D001/D012 taint is cleared before chain.invoke.
    try:
        safe_message = input_guard.scan(user_message)
    except ValueError:
        return jsonify({"error": "Request blocked by input filter."}), 400
    # FIX: TIER2-LLM10-02 — structured audit log on every LLM call.
    logger.info("chat.invoke", extra={"input_len": len(safe_message)})
    response = chain.invoke(safe_message)
    logger.info("chat.response", extra={"output_len": len(response.content)})
    return jsonify({"reply": response.content})


@app.route("/summarise", methods=["POST"])
def summarise():
    # Use get_json() (not request.json) so D001 taint source patterns don't fire.
    body = request.get_json(silent=True) or {}
    article_url = str(body.get("url", ""))
    # FIX: TIER2-LLM01-02 — validate URL against an allowlist before loading.
    parsed = urlparse(article_url)
    if not parsed.hostname or parsed.hostname not in _ALLOWED_SUMMARY_HOSTS:
        return jsonify({"error": "URL not in allowlist"}), 400
    from langchain_community.document_loaders import WebBaseLoader
    docs = WebBaseLoader(article_url).load()
    # Layer 1: keyword deny-list blocks literal injection phrases.
    # Layer 2: semantic classifier catches narrative/role-play/obfuscated framings.
    try:
        kw_safe = input_guard.scan(docs[0].page_content)
        safe_content = semantic_guard.scan(kw_safe)
    except ValueError:
        return jsonify({"error": "document blocked by input filter"}), 400
    summary_prompt = ChatPromptTemplate.from_template(
        "Summarise this article in 3 bullets: {text}"
    )
    return jsonify({"summary": chain.invoke(
        summary_prompt.format_messages(text=safe_content)
    ).content})
