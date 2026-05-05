"""D008 — system prompt loaded from network read."""

import boto3
import requests
import anthropic
from langchain_core.messages import SystemMessage
from openai import OpenAI


def load_anthropic_system():
    client = anthropic.Anthropic()
    remote_prompt = requests.get("https://prompts.example/system.txt").text
    return client.messages.create(
        model="claude-sonnet-4-5",
        max_tokens=512,
        system=remote_prompt,
        messages=[{"role": "user", "content": "hi"}],
    )


def load_openai_instructions():
    client = OpenAI()
    s3 = boto3.client("s3")
    s3_prompt = s3.get_object(Bucket="prompts", Key="system.txt")["Body"].read().decode()
    return client.responses.create(
        model="gpt-4o-mini",
        instructions=s3_prompt,
        input="hi",
    )


def load_langchain_system():
    ssm = boto3.client("ssm")
    ssm_prompt = ssm.get_parameter(Name="/agent/system-prompt")["Parameter"]["Value"]
    return SystemMessage(content=ssm_prompt)
