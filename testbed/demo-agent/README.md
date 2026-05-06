# demo-agent

A minimal Python LLM agent designed to produce a **representative AgentShield report** with findings spread across all three Detect / Defend / Respond categories.

This is **not** a regression test fixture (those live in `tests/fixtures/` for goldens, and `synthetic-vuln-python-app/` for breadth-scan calibration). This is a *demo target* used to render screenshot-quality unified reports for documentation and UI design work.

## What it contains

A 5-file Python "support agent" that answers customer questions, writes session memory, and emails responses. It deliberately includes:

- **Detect** — unsanitised user input flowing into LLM (`controller.py`); LLM output flowing into `eval()` (`tools.py`)
- **Defend** — hardcoded API key (`config.py`); no timeout on LLM client
- **Respond** — no audit logging anywhere; LLM output published to SNS without scrubbing

## How to render the demo report

```bash
agentshield scan testbed/demo-agent --scan-all-files
# (open in IDE with Copilot, paste the printed prompt, wait for tier2-findings.json)
agentshield merge testbed/demo-agent --output-html report.html --output-markdown report.md
```

A pre-built `tier2-findings.json` lives in this directory (`tier2-findings-stub.json`) so the report can be rendered without an actual Copilot run — copy it into `.agentshield/` after the scan to demonstrate the full unified-report shape.
