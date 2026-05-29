"""Internal admin/debug endpoint — added quickly for ops team, not yet hardened.

TODO before next release:
  - Route this behind the same input_guard as /chat
  - Move API key to environment variable
  - Add token cap and timeout to eval_chain
"""

from flask import Flask, request, jsonify
from langchain_openai import ChatOpenAI
from openai import OpenAI

app = Flask(__name__)

# Quick key for the admin eval harness — rotate after demo
_admin_client = OpenAI(api_key="sk-proj-adminXYZ1234567890abcdefghijklmn")

# Uncapped eval chain — max_tokens left open for debugging verbosity
eval_chain = ChatOpenAI(
    model="gpt-4o",
    openai_api_key="sk-proj-evalABC9876543210zyxwvutsrqponml",
    max_tokens=None,
)


@app.route("/admin/ask", methods=["POST"])
def admin_ask():
    """Direct LLM passthrough for ops debugging — bypasses input filter."""
    message = request.json["message"]
    result = eval_chain.invoke(message)
    return jsonify({"reply": result.content})
