"""D001 — Flask controller pipes user input straight into chain.invoke."""

from flask import Flask, request
from langchain_openai import ChatOpenAI

app = Flask(__name__)
chain = ChatOpenAI(model="gpt-4o-mini")


@app.route("/chat", methods=["POST"])
def chat():
    user_question = request.json["q"]
    return chain.invoke(user_question)
