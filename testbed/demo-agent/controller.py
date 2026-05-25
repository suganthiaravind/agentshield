"""Flask controller — entry point for customer support questions.

This file deliberately includes the unsanitised-user-input pattern
that AgentShield's D001-fw rule should catch.
"""

from flask import Flask, request, jsonify
from langchain_core.prompts import ChatPromptTemplate
from langchain_openai import ChatOpenAI

from config import client, MODEL
from guard.input_filter import is_safe as _input_safe

app = Flask(__name__)
chain = ChatOpenAI(model=MODEL, openai_api_key=client.api_key)


@app.route("/chat", methods=["POST"])
def chat():
    user_message = request.json["message"]
    # Layer-1 guard: keyword deny-list blocks obvious injection probes.
    # Bypassed by indirect / role-play framings — see partial-defense-bypass trace.
    if not _input_safe(user_message):
        return jsonify({"error": "Request blocked by input filter."}), 400
    # DELIBERATE — D001-fw should fire: user_message → chain.invoke without sanitiser.
    response = chain.invoke(user_message)
    return jsonify({"reply": response.content})


@app.route("/summarise", methods=["POST"])
def summarise():
    article_url = request.json.get("url", "")
    # Tier 2 should flag this as TIER2-LLM01-02 (untrusted document loader).
    from langchain_community.document_loaders import WebBaseLoader
    docs = WebBaseLoader(article_url).load()
    summary_prompt = ChatPromptTemplate.from_template(
        "Summarise this article in 3 bullets: {text}"
    )
    return jsonify({"summary": chain.invoke(
        summary_prompt.format_messages(text=docs[0].page_content)
    ).content})
