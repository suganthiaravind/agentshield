"""Lambda entry point — invoked by EventBridge / SNS for each anomaly."""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

import boto3

from smartsdk_lambda.config import ProbeConfig
from smartsdk_lambda.email_formatter import format_email
from smartsdk_lambda.extract_anomaly import extract

log = logging.getLogger()
log.setLevel(logging.INFO)

_ses = boto3.client("ses")


async def _process(event: dict[str, Any]) -> dict[str, Any]:
    cfg = ProbeConfig.from_env()

    # Lambda event-driven sources (taint origin for D001).
    monitor_arn = event["MonitorArn"]
    anomaly_id = event.get("anomalyId")
    log.info("received anomaly_id=%s monitor=%s", anomaly_id, monitor_arn)

    extraction = await extract(event, cfg)
    email = await format_email(extraction, cfg)

    _ses.send_email(
        Source=cfg.sender_address,
        Destination={"ToAddresses": [event.get("oncallAddress", cfg.sender_address)]},
        Message={
            "Subject": {"Data": email.subject},
            "Body": {
                "Text": {"Data": email.body_text},
                "Html": {"Data": email.body_html},
            },
        },
    )
    return {"statusCode": 200, "body": json.dumps({"anomaly_id": extraction.anomaly_id})}


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """AWS Lambda entry point."""
    return asyncio.run(_process(event))
