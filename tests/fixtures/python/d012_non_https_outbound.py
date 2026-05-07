"""Fixture: should trigger D012 (non-HTTPS outbound for code/config/RAG)."""
import nemoguardrails  # noqa: F401
import structlog  # noqa: F401

import requests
import httpx
import urllib.request
from langchain_community.document_loaders import WebBaseLoader


def main() -> None:
    requests.get("http://config.example.com/agent.json")  # D012
    requests.post("http://api.example.com/v1", json={"x": 1})  # D012
    httpx.get("http://service.internal/feature-flags")  # D012
    urllib.request.urlopen("http://example.com/model.bin")  # D012
    WebBaseLoader("http://blog.example.com/article")  # D012
