"""D005 — hardcoded API keys in LLM client constructors."""

import boto3
import openai
import anthropic
import cohere
from langchain_openai import ChatOpenAI


def make_clients():
    a = openai.OpenAI(api_key="sk-proj-AAAAAAAAAAAAAAAAAAAAAAAAAAAA")
    b = anthropic.Anthropic(api_key="sk-ant-api03-XXXXXXXXXXXXXXXXX")
    c = cohere.Client("co-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
    bedrock = boto3.client(
        "bedrock-runtime",
        region_name="us-east-1",
        aws_access_key_id="AKIAIOSFODNN7EXAMPLE",
        aws_secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    )
    chat = ChatOpenAI(api_key="sk-proj-BBBBBBBBBBBBBBBBBBBBBBBBBBBB")
    return a, b, c, bedrock, chat
