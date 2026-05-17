"""Runtime probe — Path B of AgentShield's red-team layer.

Static analysis (the rest of AgentShield) tells you *where* an attack
could land. This package actually *runs* the attack against a configured
target endpoint and tells you whether it landed.

Entry point: `agentshield probe <repo> --target <url>`. Reads findings
from `<repo>/.agentshield/`, looks up payloads by rule_id in the payload
library, sends them via the runner, classifies each response, and writes
`<repo>/.agentshield/probe-results.json`. The merger picks that file up
on the next `agentshield merge` and the HTML report renders REAL probe
traces in place of the canned ones.
"""
