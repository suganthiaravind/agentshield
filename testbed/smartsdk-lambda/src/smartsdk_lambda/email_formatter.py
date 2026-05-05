"""Format an outbound email body / subject from an extracted anomaly."""

from __future__ import annotations

import logging
from dataclasses import dataclass

from smart_sdk import Agent, Runner
from smart_sdk.types import AgentConfig

from smartsdk_lambda.config import ProbeConfig
from smartsdk_lambda.extract_anomaly import AnomalyExtraction

log = logging.getLogger(__name__)


@dataclass
class FormattedEmail:
    subject: str
    body_text: str
    body_html: str


def _build_subject_agent(cfg: ProbeConfig) -> Agent:
    return Agent(
        config=AgentConfig(
            name=cfg.email_template_agent_name,
            model_id=cfg.bedrock_model_id,
            instructions=(
                "You receive a structured cost anomaly summary. Return a "
                "single email subject line under 80 characters. Start with "
                "'[COST ANOMALY]'. No markdown."
            ),
        )
    )


def _build_body_agent(cfg: ProbeConfig) -> Agent:
    return Agent(
        config=AgentConfig(
            name=f"{cfg.email_template_agent_name}-body",
            model_id=cfg.bedrock_model_id,
            instructions=(
                "You receive a structured cost anomaly summary. Return a "
                "plain-text email body addressing the on-call engineer with "
                "the anomaly headline, expected vs actual spend, and the top "
                "three contributing factors. End with the monitor ARN."
            ),
        )
    )


async def format_email(extraction: AnomalyExtraction, cfg: ProbeConfig) -> FormattedEmail:
    log.info("formatting email for anomaly id=%s", extraction.anomaly_id)
    runner = Runner()
    subject_agent = _build_subject_agent(cfg)
    body_agent = _build_body_agent(cfg)

    summary_prompt = (
        f"Headline: {extraction.headline}\n"
        f"Summary: {extraction.structured_summary}\n"
        f"Monitor ARN: {extraction.monitor_arn}"
    )

    subject_text = await runner.run(subject_agent, summary_prompt)

    body_text = await runner.run(body_agent, summary_prompt)

    return FormattedEmail(
        subject=subject_text.strip(),
        body_text=body_text.strip(),
        body_html=f"<pre>{body_text.strip()}</pre>",
    )
