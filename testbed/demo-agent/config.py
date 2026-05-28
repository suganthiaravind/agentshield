"""Configuration for the demo support agent."""

import os
from openai import OpenAI

# FIX: hardcoded-llm-credentials — use env var instead of literal key.
# Rotate any previously committed key — git history is permanent.
client = OpenAI(api_key=os.environ.get("OPENAI_API_KEY", ""))

MODEL = "gpt-4o-mini"
MAX_HISTORY_TURNS = 10

# FIX: TIER2-LLM02-01 — DB credentials out of source, into env var.
DATABASE_URL = os.environ.get("DATABASE_URL", "")

# Loaded properly from env (this one should NOT trigger D005).
SLACK_WEBHOOK = os.environ.get("SLACK_WEBHOOK_URL", "")
