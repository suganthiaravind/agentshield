"""Fixture: should trigger the D001 FALLBACK rule (Tier 2).

A custom wrapper class uses openai under the hood but exposes its
own .ask() method. Framework D001 doesn't know about .ask() — but
the fallback rule catches it because:
  1. The file imports openai (gating import)
  2. `llm.ask(user_msg)` matches $X.$VERB($Y, ...) with $VERB = "ask"
     ("ask" is in the fallback verb regex but NOT in framework D001's
     explicit sink list)

This is the realistic "internal wrapper" pattern the fallback rule
exists to catch. Use this fixture to exercise the LLM judge tier
end-to-end:

    agentshield scan tests/fixtures/python/d001_fallback_openai_wrapper.py \\
      --llm-backend boto3-bedrock \\
      --bedrock-model-id <your-bedrock-model-id-or-arn>
"""
import openai
from flask import Flask, request


class CustomLLM:
    def __init__(self) -> None:
        self._client = openai.OpenAI()

    def ask(self, prompt: str) -> str:
        return (
            self._client.chat.completions.create(
                model="gpt-4",
                messages=[{"role": "user", "content": prompt}],
            )
            .choices[0]
            .message.content
        )


app = Flask(__name__)
llm = CustomLLM()


@app.route("/chat")
def chat():
    user_msg = request.args.get("q")
    return llm.ask(user_msg)
