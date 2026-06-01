# AgentShield — Copilot Chat Prompts

Target repo: `/Users/suganthichandrasekaran/AgentShield/testbed/demo-agent`

Paste each block verbatim into Copilot Chat. The prompts use absolute paths so they work from any open workspace.

------------------------------------------------------------------------
## Step 1 — Tier 2: LLM scan

Paste **after** `agentshield scan` completes (`tier1-results.json` must exist).

```
Please run AgentShield Tier 2.

Read the checklist at /Users/suganthichandrasekaran/AgentShield/testbed/demo-agent/.agentshield/tier2-checklist.md and the
output schema at /Users/suganthichandrasekaran/AgentShield/testbed/demo-agent/.agentshield/tier2-output-schema.md. Walk every
source file in /Users/suganthichandrasekaran/AgentShield/testbed/demo-agent, apply each check that is in scope
for the file's language, and write your findings to
/Users/suganthichandrasekaran/AgentShield/testbed/demo-agent/.agentshield/tier2-findings.json following the schema exactly.

Also read /Users/suganthichandrasekaran/AgentShield/testbed/demo-agent/.agentshield/tier1-results.json and add a
tier1_fp_callouts section noting any Tier 1 finding you believe
is a false positive, with reasoning.

Important: copy the agentshield_tier1_fingerprint field from
tier1-results.json verbatim into your output. The merger uses it
to detect stale Tier 2 runs.
```

------------------------------------------------------------------------
## Step 2 — Behaviour emulator

Paste **after** `tier2-findings.json` exists. Writes `agent-emulation-raw.json`.

```
Please run the AgentShield agent behaviour emulator.

Read the instructions at /Users/suganthichandrasekaran/AgentShield/testbed/demo-agent/.agentshield/agent-emulator-instructions.md
and the output schema at /Users/suganthichandrasekaran/AgentShield/testbed/demo-agent/.agentshield/agent-emulator-output-schema.md.

Step 0 — Classify the agent type (interactive, batch, sub-agent,
or orchestrator).

Step 1 — Map the pipeline. First enumerate every distinct handler

The following entry points were discovered deterministically from the codebase by AgentShield's AST scanner. Use exactly these IDs in entry_points[] and entry_point_id fields. Only add an entry point if you find a handler clearly missing from this list:

  - id: "ask", route: "POST /admin/ask", handler: "admin.py:admin_ask"
  - id: "chat", route: "POST /chat", handler: "controller.py:chat"
  - id: "summarise", route: "POST /summarise", handler: "controller.py:summarise"
  - id: "delegate", route: "POST /api/orchestrator/delegate", handler: "orchestrator.py:delegate"
  - id: "receive", route: "POST /api/orchestrator/receive", handler: "orchestrator.py:receive_from_peer"
  - id: "debug", route: "POST /api/orchestrator/debug", handler: "orchestrator.py:debug_endpoint"

or runtime entry surface as entry_points[] (one item per handler,
not per source). Then locate the code that implements each of the
8 standard pipeline steps.

Step 2 — Enumerate untrusted data sources. Identify every place
where external data enters the system and classify it. Each source
must reference one of the entry_point_id values from Step 1.

Step 3 — For each source, evaluate four transitions using the seed
→ mutation sequences in the instructions:
  §T1: Source → LLM (injection check)
  §T2: LLM output → tool arguments (argument injection check)
  §T3: Source / LLM → sink (output handling check)
  §T4: Source → persistent store (memory poisoning check)

Step 4 — Pipeline-level checks (§P1–§P5): audit trail, destructive
tool gates, loop termination, agent authentication, system prompt
confidentiality.

Step 5 — Write ALL findings (including uncertain ones) to
/Users/suganthichandrasekaran/AgentShield/testbed/demo-agent/.agentshield/agent-emulation-raw.json using the output schema.
This is the only file you write — a separate judge prompt (Step 3 in
copilot-prompts.md) will review this output and produce the final
agent-emulation-judged.json. Do not self-filter or omit findings here.

Cite file:line for every prediction. Do not speculate about downstream
consumers outside this repo.
```

------------------------------------------------------------------------
## Step 3 — Emulator judge

Paste **after** `agent-emulation-raw.json` exists. Writes `agent-emulation-judged.json` used by `agentshield merge`.

```
Please run the AgentShield emulator judge.

Read the instructions at
/Users/suganthichandrasekaran/AgentShield/testbed/demo-agent/.agentshield/agent-emulator-judge-instructions.md and the output
schema at /Users/suganthichandrasekaran/AgentShield/testbed/demo-agent/.agentshield/agent-emulator-judge-output-schema.md.
Read the raw emulator output at
/Users/suganthichandrasekaran/AgentShield/testbed/demo-agent/.agentshield/agent-emulation-raw.json.

For every actionable finding (untrusted source transitions with
verdict lands or partial, plus pipeline checks with ungated /
bypassable / exposed / absent verdict), decide:
  1. Is it a genuine finding with a file:line code citation?
  2. Is it a within-file duplicate of another finding here?

Apply the sink-overclaiming and tool-arg-overclaiming suppression
rules from the instructions before calling a finding genuine.

Write your decisions to
/Users/suganthichandrasekaran/AgentShield/testbed/demo-agent/.agentshield/agent-emulation-judged.json following the output
schema exactly. Do not modify agent-emulation-raw.json.
```
