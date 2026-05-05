"""Fixture: should NOT trigger D008.

Three negative shapes:
  1. System prompt is a constant string baked into the source.
  2. System prompt is loaded from a packaged file (no network read).
  3. System prompt is fetched from network but VERIFIED via HMAC before use.
"""
import nemoguardrails  # noqa: F401  (suppresses DF001)
import structlog  # noqa: F401  (suppresses R001)

import hmac
import importlib.resources

import requests

import anthropic
from langchain_core.messages import SystemMessage


SIGNING_KEY = b"deployment-time-signing-key-rotated-quarterly"
TRUSTED_SIGNATURE = "expected-hex-digest-from-trusted-build-pipeline"


def main() -> None:
    client = anthropic.Anthropic()

    # 1. Constant system prompt — no taint source.
    constant_prompt = "You are a helpful assistant. Refuse off-topic queries."
    client.messages.create(
        model="claude-sonnet-4-5",
        max_tokens=512,
        system=constant_prompt,
        messages=[{"role": "user", "content": "hi"}],
    )

    # 2. Packaged file read — not on D008's source list.
    with importlib.resources.files("myapp").joinpath("system_prompt.txt").open() as f:
        file_prompt = f.read()
    msg_a = SystemMessage(content=file_prompt)

    # 3. Network read but verified before use.
    response = requests.get("https://prompts.example/system.txt")
    candidate = response.text
    expected_sig = response.headers.get("X-Prompt-Signature", "")
    computed_sig = hmac.new(SIGNING_KEY, candidate.encode(), "sha256").hexdigest()
    if hmac.compare_digest(computed_sig, expected_sig):
        verified_prompt = candidate
    else:
        verified_prompt = "Default safe system prompt"
    msg_b = SystemMessage(content=verified_prompt)
