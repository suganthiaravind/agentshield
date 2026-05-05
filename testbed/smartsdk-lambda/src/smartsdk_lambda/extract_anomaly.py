"""Extract a structured anomaly summary from a Cost Anomaly Detection event.

The flow is two SMARTSDK runner invocations: first the extractor agent
turns the raw event into a structured summary, then a verifier agent
sanity-checks the extraction. A third call surfaces a one-line headline
for downstream consumers.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any

from smart_sdk import Agent, Runner
from smart_sdk.types import AgentConfig

from smartsdk_lambda.config import ProbeConfig
from smartsdk_lambda.models import AnomalyEvent

log = logging.getLogger(__name__)


@dataclass
class AnomalyExtraction:
    """Structured output of the extraction pipeline."""

    anomaly_id: str
    monitor_arn: str
    headline: str
    structured_summary: dict[str, Any]
    verification_notes: str


def _build_extractor_agent(cfg: ProbeConfig) -> Agent:
    return Agent(
        config=AgentConfig(
            name=cfg.agent_name,
            model_id=cfg.bedrock_model_id,
            instructions=(
                "You receive an AWS Cost Anomaly Detection event payload and "
                "return a JSON object with: service, region, observed_spend, "
                "expected_spend, percent_over, contributing_factors[]. Output "
                "ONLY the JSON object, no prose."
            ),
        )
    )


def _build_verifier_agent(cfg: ProbeConfig) -> Agent:
    return Agent(
        config=AgentConfig(
            name=f"{cfg.agent_name}-verifier",
            model_id=cfg.bedrock_model_id,
            instructions=(
                "You receive a structured anomaly summary and the original "
                "event. Verify that every numeric value in the summary is "
                "consistent with the event. Reply with one line: 'OK' or "
                "'MISMATCH: <reason>'."
            ),
        )
    )


def _build_headline_agent(cfg: ProbeConfig) -> Agent:
    return Agent(
        config=AgentConfig(
            name=f"{cfg.agent_name}-headline",
            model_id=cfg.bedrock_model_id,
            instructions=(
                "You receive a structured anomaly summary. Reply with a single "
                "sentence under 120 characters describing the anomaly for an "
                "on-call engineer. No markdown, no quotes."
            ),
        )
    )


def _serialise_event_for_prompt(event: AnomalyEvent) -> str:
    return json.dumps(event.model_dump(by_alias=True), indent=2)


def _parse_summary(raw_text: str) -> dict[str, Any]:
    try:
        return json.loads(raw_text)
    except json.JSONDecodeError as exc:
        log.error("extractor returned non-JSON: %s", exc)
        raise


async def extract(event_dict: dict[str, Any], cfg: ProbeConfig) -> AnomalyExtraction:
    """Run the three-stage extraction pipeline against a Lambda event payload."""
    log.info("extracting anomaly id=%s", event_dict.get("anomalyId"))
    event = AnomalyEvent.from_event_dict(event_dict)
    serialised_event = _serialise_event_for_prompt(event)

    runner = Runner()
    extractor = _build_extractor_agent(cfg)
    verifier = _build_verifier_agent(cfg)
    headline_agent = _build_headline_agent(cfg)

    extractor_prompt = (
        "Extract the structured anomaly summary from the following AWS Cost "
        f"Anomaly Detection event:\n\n{serialised_event}"
    )
    verifier_prompt = (
        "Verify this structured summary against the original event.\n\n"
        f"Original event:\n{serialised_event}\n\nStructured summary:\n"
    )

    # Two consecutive SMARTSDK calls — extraction + verification. These two
    # are the most expensive calls in the pipeline; the headline is much shorter.
    extraction_text = await runner.run(extractor, extractor_prompt)
    verification_text = await runner.run(verifier, verifier_prompt + extraction_text)

    structured = _parse_summary(extraction_text)

    headline_text = await runner.run(headline_agent, json.dumps(structured))

    return AnomalyExtraction(
        anomaly_id=event.anomaly_id,
        monitor_arn=event.monitor_arn,
        headline=headline_text.strip(),
        structured_summary=structured,
        verification_notes=verification_text.strip(),
    )
