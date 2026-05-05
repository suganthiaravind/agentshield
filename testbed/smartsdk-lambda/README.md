# smartsdk-lambda (synthetic SMARTSDK Lambda)

> **Synthetic AWS Lambda using SMARTSDK (Google ADK wrapper) for cost-anomaly
> analysis.** Hand-written as a known-answer regression target for AgentShield's
> SMARTSDK call-shape rules. Do not deploy. The business logic is illustrative
> only.

## Purpose

This directory exists as a Python parity to `synthetic-vuln-java-app` — a
small, hand-written Lambda app that exercises the SMARTSDK call shape
(`await runner.run(agent, prompt)`) in a realistic context. It was first
built when validating that AgentShield's SMARTSDK detection works on
production-shaped code (multiple modules, async handler, Pydantic models,
Lambda event-driven input) rather than just synthetic minimal fixtures.

## Expected AgentShield findings

When scanned with the current bundled rule pack:

| Rule | Where | Why |
|---|---|---|
| DF001 | every SMARTSDK `await runner.run(...)` call | no `nemoguardrails` / `lakera` / `rebuff` / `guardrails` / `presidio` import |
| R001 | every SMARTSDK `await runner.run(...)` call | no `structlog` / `langsmith` / `opentelemetry` / `langchain.callbacks` import (plain `import logging` deliberately does NOT suppress — see R001 rule for rationale) |

Total: **5 SMARTSDK call sites × 2 rules = 10 findings.** Stable; any rule
change that alters this count is a regression signal.

D001 does NOT fire on this app. The taint flow goes Lambda `event` →
`AnomalyEvent.from_event_dict(...)` → JSON-serialised → string-interpolated
into a prompt across module boundaries. Semgrep's intra-procedural taint
mode doesn't follow that chain. This matches the documented limitation —
not a bug.

## Layout

```
src/smartsdk_lambda/
    __init__.py
    handler.py          # Lambda entry — receives event, dispatches
    extract_anomaly.py  # Calls SMARTSDK runner to extract anomaly summary
    email_formatter.py  # Calls SMARTSDK runner to format outbound email
    config.py           # Region / model id / agent name configuration
    models.py           # Pydantic data models for event shape
requirements.txt
```

The `requirements.txt` lists `smart-sdk` and `google-adk` — these names
match the shape of SMARTSDK's public surface but the package itself is
not pip-installable from PyPI; the Lambda is for static-analysis
validation only.
