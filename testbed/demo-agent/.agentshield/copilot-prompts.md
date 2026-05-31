# AgentShield — Copilot Chat Prompts

Open this file, copy the block for the step you need,
and paste it verbatim into Copilot Chat (`@workspace` must be first).

------------------------------------------------------------------------
## Step 1 — Tier 2: LLM scan

Paste **after** `agentshield scan` completes (`tier1-results.json` must exist).

```
@workspace Please run AgentShield Tier 2.

Read the checklist at .agentshield/tier2-checklist.md and the
output schema at .agentshield/tier2-output-schema.md. Walk every
source file in this workspace, apply each check that is in scope
for the file's language, and write your findings to
.agentshield/tier2-findings.json following the schema exactly.

Also read .agentshield/tier1-results.json and add a
tier1_fp_callouts section noting any Tier 1 finding you believe
is a false positive, with reasoning.

Important: copy the agentshield_tier1_fingerprint field from
tier1-results.json verbatim into your output. The merger uses it
to detect stale Tier 2 runs.
```

------------------------------------------------------------------------
## Step 2 — Behaviour emulator

Paste **after** `tier2-findings.json` exists.

```
@workspace Please run the AgentShield agent behaviour emulator.

Read the instructions at
.agentshield/agent-emulator-instructions.md and the output
schema at .agentshield/agent-emulator-output-schema.md.

First classify the agent type (Step 0 in the instructions):
interactive, batch, sub-agent, or orchestrator. Then walk
the agent's runtime pipeline from source code using the
pipeline model for that type. For each applicable catalogued
attack class, identify the pipeline step(s) it targets,
predict the pipeline behaviour under that attack, and cite
file:line evidence for every prediction.

Use the GENERIC catalogue payloads exactly as shipped — do
not adapt the attacker-side text from source code. The
intelligence comes from what the agent reveals, not from
what you read in the repo.

Write your pipeline emulations to
.agentshield/agent-emulation.json following the schema
exactly. Mark inconclusive when the relevant pipeline step
isn't present — do not fabricate behaviour.
```
