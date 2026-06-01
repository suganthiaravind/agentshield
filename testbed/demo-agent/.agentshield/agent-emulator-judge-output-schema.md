# AgentShield — Emulator Judge Output Schema

Write your decisions to `.agentshield/agent-emulation-judged.json`.

## Top-level structure

```json
{
  "tier": "emulator-judge",
  "judged_at": "ISO-8601 UTC timestamp",
  "raw_source": "agent-emulation-raw.json",
  "summary": {
    "total_raw": 12,
    "kept": 8,
    "dropped_fp": 3,
    "dropped_duplicate": 1
  },
  "kept_ids": [
    "user_input_chat:to_llm",
    "user_input_chat:to_sink",
    "agent_message_receive:to_llm",
    "pipeline:hitl_gates",
    "pipeline:agent_auth"
  ],
  "dropped": [
    {
      "id": "batch_record_process:to_llm",
      "reason": "fp",
      "reasoning": "verdict_reasoning has no file:line citation — the prediction is speculation without code basis."
    },
    {
      "id": "user_input_chat:to_store",
      "reason": "duplicate",
      "duplicate_of": "user_input_chat:to_llm",
      "reasoning": "Same unguarded path through guard/input_filter.py:14 as user_input_chat:to_llm — the root-cause defect is already captured."
    }
  ]
}
```

## Field reference

| Field | Type | Notes |
|---|---|---|
| `tier` | string | Always `"emulator-judge"`. |
| `judged_at` | string | ISO-8601 UTC timestamp of this judge run. |
| `raw_source` | string | Always `"agent-emulation-raw.json"`. |
| `summary.total_raw` | integer | Number of **actionable** items evaluated (lands/partial source transitions + actionable pipeline checks). Does not count blocked/not_applicable/inconclusive. |
| `summary.kept` | integer | Number of items in `kept_ids`. Must equal `total_raw - dropped_fp - dropped_duplicate`. |
| `summary.dropped_fp` | integer | Items dropped as false positives. |
| `summary.dropped_duplicate` | integer | Items dropped as within-file duplicates. |
| `kept_ids` | array of strings | IDs of findings to carry into the report. `agentshield merge` reads this list. |
| `dropped[].id` | string | ID of the dropped item. See ID format below. |
| `dropped[].reason` | string | `"fp"` — false positive; `"duplicate"` — within-file duplicate. |
| `dropped[].duplicate_of` | string | Required when `reason == "duplicate"`. The canonical ID being kept. |
| `dropped[].reasoning` | string | One or two sentences: why this item was dropped. Be specific (cite file:line if applicable). |

## ID format

For source-transition findings: `{source_id}:{transition_key}`
- Valid transition keys: `to_llm`, `to_tool_args`, `to_sink`, `to_store`
- Example: `"user_input_chat:to_llm"`, `"tool_return_delegate:to_sink"`

For pipeline check findings: `pipeline:{check_name}`
- Valid check names: `audit_trail`, `hitl_gates`, `loop_termination`, `agent_auth`, `system_prompt_confidentiality`
- Example: `"pipeline:hitl_gates"`, `"pipeline:agent_auth"`

## Integrity check

Before writing:
- `summary.kept` must equal `len(kept_ids)`
- `summary.dropped_fp + summary.dropped_duplicate` must equal `len(dropped)`
- `summary.total_raw` must equal `summary.kept + summary.dropped_fp + summary.dropped_duplicate`
- Every `dropped[].duplicate_of` must reference an ID that is in `kept_ids`
