"""Fixture: should trigger D008 (untrusted source -> LLM system prompt).

Each system prompt below is loaded from a network read (requests.get,
S3 get_object, SSM parameter store) and flows directly into an LLM
system-role argument with no signature verification or guardrail.
"""
import nemoguardrails  # noqa: F401  (suppresses DF001)
import structlog  # noqa: F401  (suppresses R001)

import boto3
import requests

import anthropic
from langchain_core.messages import SystemMessage
from openai import OpenAI


def main() -> None:
    anthropic_client = anthropic.Anthropic()
    openai_client = OpenAI()
    s3 = boto3.client("s3")
    ssm = boto3.client("ssm")
    bedrock = boto3.client("bedrock-runtime")

    # 1. Anthropic — system prompt fetched from arbitrary URL
    remote_prompt = requests.get("https://prompts.example/system.txt").text
    anthropic_client.messages.create(
        model="claude-sonnet-4-5",
        max_tokens=512,
        system=remote_prompt,  # D008
        messages=[{"role": "user", "content": "hi"}],
    )

    # 2. OpenAI Responses API — instructions from S3
    s3_prompt = s3.get_object(Bucket="prompts", Key="system.txt")["Body"].read().decode()
    openai_client.responses.create(
        model="gpt-4o-mini",
        instructions=s3_prompt,  # D008
        input="hi",
    )

    # 3. LangChain SystemMessage from SSM parameter
    ssm_prompt = ssm.get_parameter(Name="/agent/system-prompt")["Parameter"]["Value"]
    msg = SystemMessage(content=ssm_prompt)  # D008

    # 4. Bedrock Converse — system from network
    bedrock_prompt = requests.get("https://prompts.example/bedrock.txt").text
    bedrock.converse(
        modelId="anthropic.claude-sonnet-4-5",
        system=[{"text": bedrock_prompt}],  # D008
        messages=[{"role": "user", "content": [{"text": "hi"}]}],
    )
