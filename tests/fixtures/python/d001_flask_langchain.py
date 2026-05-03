"""Fixture: should trigger D001, DF001, R001.

User input from Flask flows directly into a LangChain LLM with no
guardrail import and no logger setup.
"""
from flask import Flask, request
from langchain.llms import OpenAI

app = Flask(__name__)
llm = OpenAI()


@app.route("/chat")
def chat():
    user_msg = request.args.get("q")
    return llm.invoke(user_msg)
