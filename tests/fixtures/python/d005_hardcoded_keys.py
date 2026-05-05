"""Fixture: should trigger D005 (hardcoded LLM credentials).

Each constructor below passes a literal string as the API key — CWE-798.
Suppresses DF001 / R001 with nemoguardrails + structlog imports so the
golden cleanly shows D005 alone.
"""
import nemoguardrails  # noqa: F401  (suppresses DF001)
import structlog  # noqa: F401  (suppresses R001)

import boto3
import openai
import anthropic
import cohere
from langchain_openai import ChatOpenAI
from langchain_anthropic import ChatAnthropic


def main() -> None:
    client_a = openai.OpenAI(api_key="sk-proj-AAAAAAAAAAAAAAAAAAAAAAAAAAAA")  # D005
    client_b = anthropic.Anthropic(api_key="sk-ant-api03-XXXXXXXXXXXXXXXXX")  # D005
    client_c = cohere.Client("co-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")  # D005
    bedrock = boto3.client(  # D005
        "bedrock-runtime",
        region_name="us-east-1",
        aws_access_key_id="AKIAIOSFODNN7EXAMPLE",
        aws_secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    )
    chat_a = ChatOpenAI(api_key="sk-proj-BBBBBBBBBBBBBBBBBBBBBBBBBBBB")  # D005
    chat_b = ChatAnthropic(anthropic_api_key="sk-ant-api03-YYYYYYYYYYYYYYY")  # D005
