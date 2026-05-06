"""Fixture: boto3 Lambda self-invocation — should NOT fire DF001 or R001.

Phase E.2 regression target. The first VDI run on
moip-cost-anomaly-probe-lambda surfaced 4 FPs from DF001 + R001 firing
on `client.invoke(FunctionName=..., InvocationType="Event", ...)` — the
canonical boto3.client("lambda").invoke() shape used for async
self-invocation. That is NOT an LLM call.

The required `FunctionName=` keyword arg is the disambiguator from the
LLM SDK invoke() shape (LangChain's chain.invoke(input) takes a
positional first arg, not FunctionName=).

This fixture pins the suppressor: zero findings expected.
"""
import boto3

lambda_client = boto3.client("lambda")


def fan_out(payload: dict) -> None:
    # Async self-invoke another Lambda — NOT an LLM call.
    lambda_client.invoke(
        FunctionName="downstream-handler",
        InvocationType="Event",
        Payload=b'{"k": "v"}',
    )


def chained_call(function_name: str, payload: bytes) -> bytes:
    # Synchronous Lambda invoke — also NOT an LLM call.
    response = lambda_client.invoke(
        FunctionName=function_name,
        InvocationType="RequestResponse",
        Payload=payload,
    )
    return response["Payload"].read()
