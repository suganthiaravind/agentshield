"""Fixture: should NOT trigger D005.

Every credential is sourced from env / secrets manager / config object
or omitted entirely (default credential resolver). Validates that D005
only fires on string literals, not on lookups.
"""
import nemoguardrails  # noqa: F401  (suppresses DF001)
import structlog  # noqa: F401  (suppresses R001)

import os

import boto3
import openai
import anthropic
import cohere
from langchain_openai import ChatOpenAI


def get_api_key() -> str:
    return os.environ["OPENAI_API_KEY"]


def main() -> None:
    # Env-var lookup: not a literal.
    client_a = openai.OpenAI(api_key=os.environ["OPENAI_API_KEY"])
    # Helper function returning a string at runtime.
    client_b = openai.AsyncOpenAI(api_key=get_api_key())
    # Default credential resolver: no api_key kwarg at all.
    client_c = anthropic.Anthropic()
    # Cohere via env var.
    client_d = cohere.Client(os.environ["COHERE_API_KEY"])
    # Boto3 default credential chain (IAM role / instance profile).
    bedrock = boto3.client("bedrock-runtime", region_name="us-east-1")
    # LangChain wrapper using env var.
    chat = ChatOpenAI(api_key=os.environ["OPENAI_API_KEY"])
