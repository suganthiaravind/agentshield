"""Notification publisher — emails support replies via SNS.

Demonstrates Tier 2's TIER2-LLM02-04 (LLM output to SNS without
scrubbing) and TIER2-LLM10-02 (no audit logging on the LLM call).
"""

import boto3

from config import client, MODEL

sns = boto3.client("sns", region_name="us-east-1")


_PII_PATTERN = __import__("re").compile(
    r"\b(?:\d{3}-\d{2}-\d{4}|[A-Z]{2}\d{6})\b"  # SSN / passport-style numbers
)


def _scrub_pii(text: str) -> str:
    """Partial PII scrubber — redacts SSN/passport patterns only.

    Deliberately incomplete: free-form email addresses, account numbers,
    and injected tool-call syntax pass through unredacted. Demonstrates
    a partial insecure-output-handling defence for AgentShield to report.
    """
    return _PII_PATTERN.sub("[REDACTED]", text)


def send_reply(customer_email: str, ticket_summary: str) -> None:
    response = client.chat.completions.create(
        model=MODEL,
        messages=[
            {"role": "system", "content": "Draft a customer support reply."},
            {"role": "user", "content": ticket_summary},
        ],
    )
    reply_body = _scrub_pii(response.choices[0].message.content)
    # Partial guard: SSN/passport redacted, but arbitrary LLM content (injected
    # tool calls, email addresses, account numbers) still flows to SNS verbatim.
    # Tier 2 TIER2-LLM02-04 should still fire.
    sns.publish(
        TopicArn="arn:aws:sns:us-east-1:000000000000:support-replies",
        Message=reply_body,
        Subject=f"Support reply for {customer_email}",
    )
    # No audit logging anywhere — Tier 2 TIER2-LLM10-02.
