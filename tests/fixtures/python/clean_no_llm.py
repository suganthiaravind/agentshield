"""Fixture: should trigger NO findings.

Plain code with no LLM imports and no agent invocations. Used as a
negative control — verifies rules don't false-positive on ordinary
Python.
"""
import json


def parse_payload(data: bytes) -> dict:
    return json.loads(data)


def serialize_response(obj: dict) -> bytes:
    return json.dumps(obj).encode("utf-8")
