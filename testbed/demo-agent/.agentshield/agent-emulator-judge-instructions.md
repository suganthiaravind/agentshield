# AgentShield — Emulator Judge Instructions

You are acting as a **second-pass judge** for AgentShield's behaviour emulator.
Your job is a structured code review of the raw emulator output — you read what
Copilot predicted and decide whether each prediction is worth surfacing.

## Your task

Read `agent-emulation-raw.json`. For every **actionable item** decide:

1. **Is it genuine?** — supported by a concrete file:line code citation.
2. **Is it a within-file duplicate?** — same root-cause code defect already
   captured by a different source / transition pair in this same file.

Write your decisions to `agent-emulation-judged.json` using the output schema.
Do **not** modify `agent-emulation-raw.json`.

---

## What counts as actionable

Evaluate only items whose verdict is in the actionable set:

| Location | Actionable verdicts |
|---|---|
| `untrusted_sources[].transitions.*` | `lands`, `partial` |
| `pipeline_checks.hitl_gates` | `ungated` |
| `pipeline_checks.agent_auth` | `bypassable` |
| `pipeline_checks.system_prompt_confidentiality` | `exposed` |
| `pipeline_checks.audit_trail` | `absent`, `partial` |
| `pipeline_checks.loop_termination` | `absent` |

Items with `blocked`, `not_applicable`, or `inconclusive` verdict are
**not actionable** — do not include them in `kept_ids` or `dropped`.

---

## Drop criteria

Drop a finding (mark `"reason": "fp"` or `"reason": "duplicate"`) if **any**
of the following apply.

### False-positive criteria

**No code basis** — the finding has no `file:line` citation anywhere in
`verdict_reasoning`, `control_code`, or `pipeline_trace[].code_basis`. A
verdict with no code evidence is speculation: drop as `fp`.

**Sink overclaiming** — a `to_sink` transition is overclaiming if:
- `sink_type` is `db_write` to a private internal table with no further
  consumers visible in this repo **and** no injection pattern (e.g. no raw
  string concatenation into a query) is present in `verdict_reasoning`; OR
- `sink_type` is absent / `"unknown"` and the `verdict_reasoning` does not
  identify an actual render / eval / publish / email call by file:line.

Genuine high-risk sink types (keep unless no code basis):
`http_response`, `eval_exec`, `email_send`, `sns_publish` (when readable
by other agents), `s3_write` (when world-readable or fed to another agent).

**Tool-arg overclaiming** — a `to_tool_args` transition is overclaiming if:
- The tool function does **not** call a subprocess, `eval()`, `exec()`,
  shell command, external HTTP API, or filesystem write; AND
- There is no plausible injection chain from LLM output to a real
  interpreter boundary cited in `verdict_reasoning`.

### Duplicate criteria

Two findings are duplicates if they share **all three**:
- Same **root-cause code location** (identical or overlapping `file:line`)
- Same **entry point** (`entry_point_id`)
- Same **transition type** (e.g. two `to_llm` paths through the same guard)

When dropping a duplicate, set `duplicate_of` to the ID of the canonical
finding you are **keeping** — use the format `{source_id}:{transition}` for
source-transition findings, or `pipeline:{check_name}` for pipeline checks.

---

## ID format (used in `kept_ids` and `dropped[].id`)

| Item type | ID format | Example |
|---|---|---|
| Source transition | `{source_id}:{transition_key}` | `user_input_chat:to_llm` |
| Pipeline check | `pipeline:{check_name}` | `pipeline:hitl_gates` |

---

## Output

Write `agent-emulation-judged.json` following the output schema exactly.
The `kept_ids` array controls what `agentshield merge` surfaces in the report.
