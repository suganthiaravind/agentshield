"""Configuration for the demo support agent."""

import os
from openai import OpenAI

# DELIBERATE — D005 hardcoded credentials should fire on this line.
client = OpenAI(api_key="sk-proj-DEMO1234567890abcdef")

MODEL = "gpt-4o-mini"
MAX_HISTORY_TURNS = 10

# DB connection string also hardcoded — additional D005 candidate.
DATABASE_URL = "postgresql://demo:demo@internal-pg.local:5432/support"

# Loaded properly from env (this one should NOT trigger D005).
SLACK_WEBHOOK = os.environ.get("SLACK_WEBHOOK_URL", "")
