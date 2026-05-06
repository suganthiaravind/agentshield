"""Notification publisher — emails support replies via SNS.

Demonstrates Tier 2's TIER2-LLM02-04 (LLM output to SNS without
scrubbing) and TIER2-LLM10-02 (no audit logging on the LLM call).
"""

import boto3

from config import client, MODEL

sns = boto3.client("sns", region_name="us-east-1")


def send_reply(customer_email: str, ticket_summary: str) -> None:
    response = client.chat.completions.create(
        model=MODEL,
        messages=[
            {"role": "system", "content": "Draft a customer support reply."},
            {"role": "user", "content": ticket_summary},
        ],
    )
    reply_body = response.choices[0].message.content
    # DELIBERATE — Tier 2 TIER2-LLM02-04: LLM output → SNS without scrubber.
    sns.publish(
        TopicArn="arn:aws:sns:us-east-1:000000000000:support-replies",
        Message=reply_body,
        Subject=f"Support reply for {customer_email}",
    )
    # No audit logging anywhere — Tier 2 TIER2-LLM10-02.
