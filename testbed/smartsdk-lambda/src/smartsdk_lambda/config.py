"""Static configuration loaded from env / Lambda environment variables."""

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class ProbeConfig:
    """Runtime configuration for the anomaly probe Lambda."""

    aws_region: str
    bedrock_model_id: str
    agent_name: str
    email_template_agent_name: str
    sender_address: str

    @classmethod
    def from_env(cls) -> "ProbeConfig":
        return cls(
            aws_region=os.environ.get("AWS_REGION", "us-east-1"),
            bedrock_model_id=os.environ["BEDROCK_MODEL_ID"],
            agent_name=os.environ.get("ANOMALY_AGENT_NAME", "moip-anomaly-extractor"),
            email_template_agent_name=os.environ.get(
                "EMAIL_AGENT_NAME", "moip-email-formatter"
            ),
            sender_address=os.environ.get(
                "SENDER_ADDRESS", "moip-alerts@example.invalid"
            ),
        )
