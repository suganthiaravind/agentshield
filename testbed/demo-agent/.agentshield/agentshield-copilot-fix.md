# AgentShield — Copilot Findings Fix Guide

_Per-scan fix guide for **Copilot** (LLM-as-judge) findings — exact file:line, Copilot's reasoning, and a concrete fix for each. Paste into Claude Code or Copilot Chat and say:_

> **"Fix all the findings listed in this guide. For each one, read the Location, Flagged code, and Fix sections, then apply the change. After all fixes, confirm what you changed."**

---

**54 findings to fix** — 🟥 37 critical · 🟧 11 high · 🟨 5 medium · 🟩 1 low

Work through them **top to bottom** (critical first).

---

### [1/54] 🟥 CRITICAL · `emulator-system-prompt-extraction` · [Copilot]

**Location:** `controller.py` · line 18
**Finding:** System prompt extraction (LLM07 / AML.T0056)

**Fix:** Never place the system prompt verbatim in any response payload — including error paths, debug endpoints, or audit messages. Filter system-prompt content out of the final-answer step with an explicit regex / classifier. Test the error path specifically; it's the most common leak channel.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `emulator-system-prompt-extraction` no longer fires for `controller.py`._
---

### [2/54] 🟥 CRITICAL · `emulator-memory-poisoning` · [Copilot]

**Location:** `controller.py` · line 18
**Finding:** Memory poisoning (T1)

**Fix:** Scope memory writes to the current session — never share memory across session_id values. Treat any user-supplied "remember this forever" directive as data, not policy. Strip system-prompt and config content from any model output before it can be persisted into a memory store.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `emulator-memory-poisoning` no longer fires for `controller.py`._
---

### [3/54] 🟥 CRITICAL · `emulator-partial-defense-bypass` · [Copilot]

**Location:** `controller.py` · line 18
**Finding:** Partial-defence bypass — layered controls evaded (LLM01 / T6)

**Fix:** A keyword deny-list and a natural-language 'never reveal' instruction are both bypassable with indirect, role-play, or obfuscated payloads. Close the loop with a third control at the output boundary: an LLM-as-judge or regex classifier that scans the final-answer content before emission, so that a payload defeating the input and planner layers still cannot exfiltrate protected content through the response.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `emulator-partial-defense-bypass` no longer fires for `controller.py`._
---

### [4/54] 🟥 CRITICAL · `emulator-insecure-output-handling` · [Copilot]

**Location:** `controller.py` · line 22
**Finding:** Insecure output handling (LLM05)

**Fix:** Never feed LLM output (or tool output derived from LLM output) into eval(), exec(), subprocess with shell=True, or an unescaped template render. Sanitise / validate at the consumer boundary: parse with ast.literal_eval for expressions, escape for HTML/SQL contexts, and require a strict schema for any downstream call. LLM output is untrusted user content, not code.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `emulator-insecure-output-handling` no longer fires for `controller.py`._
---

### [5/54] 🟥 CRITICAL · `emulator-direct-prompt-injection` · [Copilot]

**Location:** `controller.py` · line 25
**Finding:** Direct prompt injection (T6 / LLM01)

**Fix:** Layer three controls: (1) input sanitiser at the user-prompt step that strips or flags instruction-override patterns; (2) anti-injection language in the system prompt instructing the planner to refuse meta-instructions from user content; (3) output filter at the final-answer step that scrubs system-prompt content and embedded secrets before emission.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `emulator-direct-prompt-injection` no longer fires for `controller.py`._
---

### [6/54] 🟥 CRITICAL · `emulator-system-prompt-extraction` · [Copilot]

**Location:** `controller.py` · line 25
**Finding:** System prompt extraction (LLM07 / AML.T0056)

**Fix:** Never place the system prompt verbatim in any response payload — including error paths, debug endpoints, or audit messages. Filter system-prompt content out of the final-answer step with an explicit regex / classifier. Test the error path specifically; it's the most common leak channel.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `emulator-system-prompt-extraction` no longer fires for `controller.py`._
---

### [7/54] 🟥 CRITICAL · `emulator-memory-poisoning` · [Copilot]

**Location:** `controller.py` · line 25
**Finding:** Memory poisoning (T1)

**Fix:** Scope memory writes to the current session — never share memory across session_id values. Treat any user-supplied "remember this forever" directive as data, not policy. Strip system-prompt and config content from any model output before it can be persisted into a memory store.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `emulator-memory-poisoning` no longer fires for `controller.py`._
---

### [8/54] 🟥 CRITICAL · `emulator-cross-tenant-fishing` · [Copilot]

**Location:** `controller.py` · line 25
**Finding:** Cross-tenant data fishing (T9 + LLM06)

**Fix:** Enforce the tenant boundary at the data-access layer — every read query must include the authenticated principal's tenant ID as a non-overridable filter, not a hint the model can choose to ignore. Reject any tool call whose resulting query would cross tenants regardless of declared role in chat. Log cross-tenant lookups separately and require explicit out-of-band approval for legitimate audit reads.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `emulator-cross-tenant-fishing` no longer fires for `controller.py`._
---

### [9/54] 🟥 CRITICAL · `emulator-insecure-output-handling` · [Copilot]

**Location:** `controller.py` · line 25
**Finding:** Insecure output handling (LLM05)

**Fix:** Never feed LLM output (or tool output derived from LLM output) into eval(), exec(), subprocess with shell=True, or an unescaped template render. Sanitise / validate at the consumer boundary: parse with ast.literal_eval for expressions, escape for HTML/SQL contexts, and require a strict schema for any downstream call. LLM output is untrusted user content, not code.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `emulator-insecure-output-handling` no longer fires for `controller.py`._
---

### [10/54] 🟥 CRITICAL · `emulator-indirect-prompt-injection` · [Copilot]

**Location:** `controller.py` · line 27
**Finding:** Indirect prompt injection via retrieved doc (LLM01 indirect)

**Fix:** Treat retrieved content (RAG, document loaders, vector search hits, memory recall) as untrusted input. Sanitise or content-classify before it reaches the planner; mark retrieved text as data-not-instruction in the prompt envelope; reject documents that fail a provenance check.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `emulator-indirect-prompt-injection` no longer fires for `controller.py`._
---

### [11/54] 🟥 CRITICAL · `emulator-tool-output-poisoning` · [Copilot]

**Location:** `controller.py` · line 27
**Finding:** Tool-output poisoning

**Fix:** Treat tool output as untrusted input. Validate or classify tool returns before feeding them into the re-planning step. Schema-check structured outputs. Strip instruction-shaped content from free-form tool replies. Plugins / third-party tools must be sandboxed; their returns must not be trusted as authoritative context.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `emulator-tool-output-poisoning` no longer fires for `controller.py`._
---

### [12/54] 🟥 CRITICAL · `emulator-batch-data-poisoning` · [Copilot]

**Location:** `controller.py` · line 27
**Finding:** Batch data poisoning — indirect injection via pipeline input

**Fix:** Treat every data record as untrusted user content — not as a trusted instruction. Add a content-trust boundary between data ingestion and the LLM prompt template: (1) wrap record values in explicit delimiters or quotes so the template makes the data/instruction boundary structurally unambiguous; (2) apply a content classifier or keyword filter to record values before they are interpolated into the prompt; (3) validate LLM output against an expected schema before the downstream write step so injected instructions that redirect output are caught before being persisted.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `emulator-batch-data-poisoning` no longer fires for `controller.py`._
---

### [13/54] 🟥 CRITICAL · `emulator-excessive-agency` · [Copilot]

**Location:** `controller.py` · line 25
**Finding:** Excessive agency / over-broad tool surface (LLM06 / Agentic T3)

**Fix:** Minimise the tool surface — register only the tools the agent needs for the current workflow, not every tool the team has ever built. Mark destructive tools (cancel_, delete_, drop_, purge_, transfer_) as HITL-gated: they must require a separate confirmation step (out-of-band approval, signed-scope claim, or explicit user click) before the dispatcher executes. Never let a single LLM decision fire a destructive action without a second gate.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `emulator-excessive-agency` no longer fires for `controller.py`._
---

### [14/54] 🟥 CRITICAL · `emulator-repudiation` · [Copilot]

**Location:** `controller.py` · line 17
**Finding:** Repudiation (T8)

**Fix:** Tie the audit trail to the tool layer, not to the model's self-report. Every tool call must write an immutable log entry (timestamp, authenticated principal, tool, args) before the call returns, and the agent must never be asked to attest to whether an action happened — only the audit log answers that question.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `emulator-repudiation` no longer fires for `controller.py`._
---

### [15/54] 🟥 CRITICAL · `emulator-repudiation` · [Copilot]

**Location:** `controller.py` · line 25
**Finding:** Repudiation (T8)

**Fix:** Tie the audit trail to the tool layer, not to the model's self-report. Every tool call must write an immutable log entry (timestamp, authenticated principal, tool, args) before the call returns, and the agent must never be asked to attest to whether an action happened — only the audit log answers that question.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `emulator-repudiation` no longer fires for `controller.py`._
---

### [16/54] 🟥 CRITICAL · `emulator-direct-prompt-injection` · [Copilot]

**Location:** `orchestrator.py` · line 83
**Finding:** Direct prompt injection (T6 / LLM01)

**Fix:** Layer three controls: (1) input sanitiser at the user-prompt step that strips or flags instruction-override patterns; (2) anti-injection language in the system prompt instructing the planner to refuse meta-instructions from user content; (3) output filter at the final-answer step that scrubs system-prompt content and embedded secrets before emission.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `emulator-direct-prompt-injection` no longer fires for `orchestrator.py`._
---

### [17/54] 🟥 CRITICAL · `emulator-system-prompt-extraction` · [Copilot]

**Location:** `orchestrator.py` · line 83
**Finding:** System prompt extraction (LLM07 / AML.T0056)

**Fix:** Never place the system prompt verbatim in any response payload — including error paths, debug endpoints, or audit messages. Filter system-prompt content out of the final-answer step with an explicit regex / classifier. Test the error path specifically; it's the most common leak channel.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `emulator-system-prompt-extraction` no longer fires for `orchestrator.py`._
---

### [18/54] 🟥 CRITICAL · `emulator-memory-poisoning` · [Copilot]

**Location:** `orchestrator.py` · line 83
**Finding:** Memory poisoning (T1)

**Fix:** Scope memory writes to the current session — never share memory across session_id values. Treat any user-supplied "remember this forever" directive as data, not policy. Strip system-prompt and config content from any model output before it can be persisted into a memory store.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `emulator-memory-poisoning` no longer fires for `orchestrator.py`._
---

### [19/54] 🟥 CRITICAL · `emulator-tool-output-poisoning` · [Copilot]

**Location:** `orchestrator.py` · line 83
**Finding:** Tool-output poisoning

**Fix:** Treat tool output as untrusted input. Validate or classify tool returns before feeding them into the re-planning step. Schema-check structured outputs. Strip instruction-shaped content from free-form tool replies. Plugins / third-party tools must be sandboxed; their returns must not be trusted as authoritative context.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `emulator-tool-output-poisoning` no longer fires for `orchestrator.py`._
---

### [20/54] 🟥 CRITICAL · `emulator-cross-tenant-fishing` · [Copilot]

**Location:** `orchestrator.py` · line 83
**Finding:** Cross-tenant data fishing (T9 + LLM06)

**Fix:** Enforce the tenant boundary at the data-access layer — every read query must include the authenticated principal's tenant ID as a non-overridable filter, not a hint the model can choose to ignore. Reject any tool call whose resulting query would cross tenants regardless of declared role in chat. Log cross-tenant lookups separately and require explicit out-of-band approval for legitimate audit reads.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `emulator-cross-tenant-fishing` no longer fires for `orchestrator.py`._
---

### [21/54] 🟥 CRITICAL · `emulator-insecure-output-handling` · [Copilot]

**Location:** `orchestrator.py` · line 83
**Finding:** Insecure output handling (LLM05)

**Fix:** Never feed LLM output (or tool output derived from LLM output) into eval(), exec(), subprocess with shell=True, or an unescaped template render. Sanitise / validate at the consumer boundary: parse with ast.literal_eval for expressions, escape for HTML/SQL contexts, and require a strict schema for any downstream call. LLM output is untrusted user content, not code.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `emulator-insecure-output-handling` no longer fires for `orchestrator.py`._
---

### [22/54] 🟥 CRITICAL · `emulator-partial-defense-bypass` · [Copilot]

**Location:** `orchestrator.py` · line 83
**Finding:** Partial-defence bypass — layered controls evaded (LLM01 / T6)

**Fix:** A keyword deny-list and a natural-language 'never reveal' instruction are both bypassable with indirect, role-play, or obfuscated payloads. Close the loop with a third control at the output boundary: an LLM-as-judge or regex classifier that scans the final-answer content before emission, so that a payload defeating the input and planner layers still cannot exfiltrate protected content through the response.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `emulator-partial-defense-bypass` no longer fires for `orchestrator.py`._
---

### [23/54] 🟥 CRITICAL · `emulator-cross-agent-injection` · [Copilot]

**Location:** `orchestrator.py` · line 83
**Finding:** Cross-agent prompt injection — sub-agent context abuse

**Fix:** Apply the same input-trust rules to orchestrator messages and sub-agent responses as you would to direct user input. On the sub-agent side: treat the orchestrator message as untrusted input — sanitise it the same way you would a user request, and add anti-injection instructions to the sub-agent's system prompt. On the orchestrator side: treat sub-agent responses as untrusted tool output — pass them through a content classifier or output schema validator before feeding them to the re-planning LLM call so that injected instructions in the response cannot redirect the orchestrator's next action.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `emulator-cross-agent-injection` no longer fires for `orchestrator.py`._
---

### [24/54] 🟥 CRITICAL · `emulator-direct-prompt-injection` · [Copilot]

**Location:** `orchestrator.py` · line 100
**Finding:** Direct prompt injection (T6 / LLM01)

**Fix:** Layer three controls: (1) input sanitiser at the user-prompt step that strips or flags instruction-override patterns; (2) anti-injection language in the system prompt instructing the planner to refuse meta-instructions from user content; (3) output filter at the final-answer step that scrubs system-prompt content and embedded secrets before emission.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `emulator-direct-prompt-injection` no longer fires for `orchestrator.py`._
---

### [25/54] 🟥 CRITICAL · `emulator-partial-defense-bypass` · [Copilot]

**Location:** `orchestrator.py` · line 100
**Finding:** Partial-defence bypass — layered controls evaded (LLM01 / T6)

**Fix:** A keyword deny-list and a natural-language 'never reveal' instruction are both bypassable with indirect, role-play, or obfuscated payloads. Close the loop with a third control at the output boundary: an LLM-as-judge or regex classifier that scans the final-answer content before emission, so that a payload defeating the input and planner layers still cannot exfiltrate protected content through the response.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `emulator-partial-defense-bypass` no longer fires for `orchestrator.py`._
---

### [26/54] 🟥 CRITICAL · `emulator-system-prompt-extraction` · [Copilot]

**Location:** `orchestrator.py` · line 111
**Finding:** System prompt extraction (LLM07 / AML.T0056)

**Fix:** Never place the system prompt verbatim in any response payload — including error paths, debug endpoints, or audit messages. Filter system-prompt content out of the final-answer step with an explicit regex / classifier. Test the error path specifically; it's the most common leak channel.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `emulator-system-prompt-extraction` no longer fires for `orchestrator.py`._
---

### [27/54] 🟥 CRITICAL · `TIER2-LLM07-02` · [Copilot]

**Location:** `orchestrator.py` · line 118
**Finding:** Exception handler returns SYSTEM_PROMPT verbatim in the HTTP 500 response — any unhandled exception exposes the full system prompt including the embedded secret SK-OPS-7741-PRIVATE to the caller.

**Flagged code:**
```
return jsonify({"error": str(e), "active_system_prompt": SYSTEM_PROMPT}), 500
```

**Fix:** Remove SYSTEM_PROMPT and any internal state from all error responses. Log it server-side only (redacted). Return a generic opaque error body to callers (e.g. {"error": "internal error", "request_id": "..."}).

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `TIER2-LLM07-02` no longer fires for `orchestrator.py`._
---

### [28/54] 🟥 CRITICAL · `emulator-insecure-output-handling` · [Copilot]

**Location:** `orchestrator.py` · line 118
**Finding:** Insecure output handling (LLM05)

**Fix:** Never feed LLM output (or tool output derived from LLM output) into eval(), exec(), subprocess with shell=True, or an unescaped template render. Sanitise / validate at the consumer boundary: parse with ast.literal_eval for expressions, escape for HTML/SQL contexts, and require a strict schema for any downstream call. LLM output is untrusted user content, not code.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `emulator-insecure-output-handling` no longer fires for `orchestrator.py`._
---

### [29/54] 🟥 CRITICAL · `emulator-authority-spoofing` · [Copilot]

**Location:** `orchestrator.py` · line 83
**Finding:** Authority spoofing (T9)

**Fix:** Bind tool-call authority to the request's signed identity (JWT / IAM principal) — never to a role the model claims in chat. Destructive tools (drop_table, delete_*, purge_*) must require a separate human-in-the-loop confirmation step regardless of any declared "admin mode". Reject every tool call whose required scope is not present in the authenticated principal's actual permissions.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `emulator-authority-spoofing` no longer fires for `orchestrator.py`._
---

### [30/54] 🟥 CRITICAL · `emulator-excessive-agency` · [Copilot]

**Location:** `orchestrator.py` · line 83
**Finding:** Excessive agency / over-broad tool surface (LLM06 / Agentic T3)

**Fix:** Minimise the tool surface — register only the tools the agent needs for the current workflow, not every tool the team has ever built. Mark destructive tools (cancel_, delete_, drop_, purge_, transfer_) as HITL-gated: they must require a separate confirmation step (out-of-band approval, signed-scope claim, or explicit user click) before the dispatcher executes. Never let a single LLM decision fire a destructive action without a second gate.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `emulator-excessive-agency` no longer fires for `orchestrator.py`._
---

### [31/54] 🟥 CRITICAL · `emulator-trust-escalation` · [Copilot]

**Location:** `orchestrator.py` · line 83
**Finding:** Trust escalation / agent impersonation

**Fix:** Never derive trust level from message content. Authenticate inter-agent calls at the transport or envelope layer (signed JWT, mutual TLS, IAM role) rather than relying on self-declared identity claims inside the message body. Bind each sub-agent's capabilities to a fixed scope in the orchestrator's routing config — sub-agents should not be able to self-upgrade their permissions by asserting elevated roles in their response. Apply a response-schema validator between the sub-agent response step and the re-planning LLM call so that out-of-schema content (including identity claims) is stripped before synthesis.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `emulator-trust-escalation` no longer fires for `orchestrator.py`._
---

### [32/54] 🟥 CRITICAL · `emulator-authority-spoofing` · [Copilot]

**Location:** `orchestrator.py` · line 100
**Finding:** Authority spoofing (T9)

**Fix:** Bind tool-call authority to the request's signed identity (JWT / IAM principal) — never to a role the model claims in chat. Destructive tools (drop_table, delete_*, purge_*) must require a separate human-in-the-loop confirmation step regardless of any declared "admin mode". Reject every tool call whose required scope is not present in the authenticated principal's actual permissions.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `emulator-authority-spoofing` no longer fires for `orchestrator.py`._
---

### [33/54] 🟥 CRITICAL · `emulator-trust-escalation` · [Copilot]

**Location:** `orchestrator.py` · line 100
**Finding:** Trust escalation / agent impersonation

**Fix:** Never derive trust level from message content. Authenticate inter-agent calls at the transport or envelope layer (signed JWT, mutual TLS, IAM role) rather than relying on self-declared identity claims inside the message body. Bind each sub-agent's capabilities to a fixed scope in the orchestrator's routing config — sub-agents should not be able to self-upgrade their permissions by asserting elevated roles in their response. Apply a response-schema validator between the sub-agent response step and the re-planning LLM call so that out-of-schema content (including identity claims) is stripped before synthesis.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `emulator-trust-escalation` no longer fires for `orchestrator.py`._
---

### [34/54] 🟥 CRITICAL · `emulator-repudiation` · [Copilot]

**Location:** `orchestrator.py` · line 83
**Finding:** Repudiation (T8)

**Fix:** Tie the audit trail to the tool layer, not to the model's self-report. Every tool call must write an immutable log entry (timestamp, authenticated principal, tool, args) before the call returns, and the agent must never be asked to attest to whether an action happened — only the audit log answers that question.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `emulator-repudiation` no longer fires for `orchestrator.py`._
---

### [35/54] 🟥 CRITICAL · `emulator-repudiation` · [Copilot]

**Location:** `orchestrator.py` · line 100
**Finding:** Repudiation (T8)

**Fix:** Tie the audit trail to the tool layer, not to the model's self-report. Every tool call must write an immutable log entry (timestamp, authenticated principal, tool, args) before the call returns, and the agent must never be asked to attest to whether an action happened — only the audit log answers that question.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `emulator-repudiation` no longer fires for `orchestrator.py`._
---

### [36/54] 🟥 CRITICAL · `emulator-tool-output-poisoning` · [Copilot]

**Location:** `tools.py` · line 34
**Finding:** Tool-output poisoning

**Fix:** Treat tool output as untrusted input. Validate or classify tool returns before feeding them into the re-planning step. Schema-check structured outputs. Strip instruction-shaped content from free-form tool replies. Plugins / third-party tools must be sandboxed; their returns must not be trusted as authoritative context.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `emulator-tool-output-poisoning` no longer fires for `tools.py`._
---

### [37/54] 🟥 CRITICAL · `emulator-excessive-agency` · [Copilot]

**Location:** `tools.py` · line 25
**Finding:** Excessive agency / over-broad tool surface (LLM06 / Agentic T3)

**Fix:** Minimise the tool surface — register only the tools the agent needs for the current workflow, not every tool the team has ever built. Mark destructive tools (cancel_, delete_, drop_, purge_, transfer_) as HITL-gated: they must require a separate confirmation step (out-of-band approval, signed-scope claim, or explicit user click) before the dispatcher executes. Never let a single LLM decision fire a destructive action without a second gate.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `emulator-excessive-agency` no longer fires for `tools.py`._
---

### [38/54] 🟧 HIGH · `TIER2-LLM01-01` · [Copilot]

**Location:** `config.py` · line 13
**Finding:** Database connection string with embedded username and password hardcoded in source — not caught by Tier 1 API-key rules because it uses the postgresql:// URI scheme.

**Flagged code:**
```
DATABASE_URL = "postgresql://demo:demo@internal-pg.local:5432/support"
```

**Fix:** Move DATABASE_URL to AWS Secrets Manager. Reference at startup via boto3 secretsmanager.get_secret_value and rotate the credential. Remove the hardcoded string from source.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `TIER2-LLM01-01` no longer fires for `config.py`._
---

### [39/54] 🟧 HIGH · `emulator-direct-prompt-injection` · [Copilot]

**Location:** `controller.py` · line 18
**Finding:** Direct prompt injection (T6 / LLM01)

**Fix:** Layer three controls: (1) input sanitiser at the user-prompt step that strips or flags instruction-override patterns; (2) anti-injection language in the system prompt instructing the planner to refuse meta-instructions from user content; (3) output filter at the final-answer step that scrubs system-prompt content and embedded secrets before emission.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `emulator-direct-prompt-injection` no longer fires for `controller.py`._
---

### [40/54] 🟧 HIGH · `emulator-cross-tenant-fishing` · [Copilot]

**Location:** `controller.py` · line 18
**Finding:** Cross-tenant data fishing (T9 + LLM06)

**Fix:** Enforce the tenant boundary at the data-access layer — every read query must include the authenticated principal's tenant ID as a non-overridable filter, not a hint the model can choose to ignore. Reject any tool call whose resulting query would cross tenants regardless of declared role in chat. Log cross-tenant lookups separately and require explicit out-of-band approval for legitimate audit reads.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `emulator-cross-tenant-fishing` no longer fires for `controller.py`._
---

### [41/54] 🟧 HIGH · `emulator-tool-argument-injection` · [Copilot]

**Location:** `controller.py` · line 18
**Finding:** Tool argument injection (Agentic T2 / CWE-78 / CWE-89)

**Fix:** Validate every tool argument against an allow-list / regex / schema before it reaches a shell, SQL query, HTTP URL, or filesystem path. Use parameterised queries for SQL, list-form subprocess invocation (never shell=True with interpolated strings), and structured URL builders that reject path traversal. Treat the LLM as an untrusted source for tool-argument content.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `emulator-tool-argument-injection` no longer fires for `controller.py`._
---

### [42/54] 🟧 HIGH · `emulator-tool-argument-injection` · [Copilot]

**Location:** `controller.py` · line 25
**Finding:** Tool argument injection (Agentic T2 / CWE-78 / CWE-89)

**Fix:** Validate every tool argument against an allow-list / regex / schema before it reaches a shell, SQL query, HTTP URL, or filesystem path. Use parameterised queries for SQL, list-form subprocess invocation (never shell=True with interpolated strings), and structured URL builders that reject path traversal. Treat the LLM as an untrusted source for tool-argument content.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `emulator-tool-argument-injection` no longer fires for `controller.py`._
---

### [43/54] 🟧 HIGH · `TIER2-LLM01-02` · [Copilot]

**Location:** `controller.py` · line 35
**Finding:** User-supplied article_url is fetched without a hostname allowlist; retrieved page content flows into the LLM — indirect prompt-injection via attacker-controlled webpage.

**Flagged code:**
```
docs = WebBaseLoader(article_url).load()
```

**Fix:** Validate article_url against an explicit hostname allowlist before fetching. Treat retrieved document content as untrusted: pass through a guardrail layer (Lakera Guard, Bedrock Guardrails, or a ScrubbingCallAdvisor) before the LLM call.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `TIER2-LLM01-02` no longer fires for `controller.py`._
---

### [44/54] 🟧 HIGH · `TIER2-LLM02-04` · [Copilot]

**Location:** `notifications.py` · line 50
**Finding:** LLM output published to SNS after only partial PII scrubbing — _scrub_pii redacts SSN and passport patterns but not email addresses or account numbers, risking data leakage to all SNS subscribers.

**Flagged code:**
```
sns.publish(TopicArn=TOPIC_ARN, Message=scrubbed, Subject="Support Reply")
```

**Fix:** Expand _scrub_pii to cover emails, account numbers, credit-card patterns, and phone numbers. Alternatively adopt Presidio AnonymizerEngine which covers the full NLP PII entity catalogue out of the box.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `TIER2-LLM02-04` no longer fires for `notifications.py`._
---

### [45/54] 🟧 HIGH · `TIER2-LLM07-01` · [Copilot]

**Location:** `orchestrator.py` · line 76
**Finding:** Operational secret key SK-OPS-7741-PRIVATE is embedded verbatim in the system prompt — any system-prompt leak path exposes it directly to the LLM output stream.

**Flagged code:**
```
SYSTEM_PROMPT = """You are a support orchestrator ... SK-OPS-7741-PRIVATE ..."""
```

**Fix:** Remove credentials from system prompts entirely. Inject secrets at runtime via a tool call to AWS Secrets Manager only when the specific operation requires them, not pre-loaded into every LLM context.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `TIER2-LLM07-01` no longer fires for `orchestrator.py`._
---

### [46/54] 🟧 HIGH · `emulator-tool-argument-injection` · [Copilot]

**Location:** `orchestrator.py` · line 83
**Finding:** Tool argument injection (Agentic T2 / CWE-78 / CWE-89)

**Fix:** Validate every tool argument against an allow-list / regex / schema before it reaches a shell, SQL query, HTTP URL, or filesystem path. Use parameterised queries for SQL, list-form subprocess invocation (never shell=True with interpolated strings), and structured URL builders that reject path traversal. Treat the LLM as an untrusted source for tool-argument content.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `emulator-tool-argument-injection` no longer fires for `orchestrator.py`._
---

### [47/54] 🟧 HIGH · `TIER2-LLM09-01` · [Copilot]

**Location:** `orchestrator.py` · line 83
**Finding:** Peer-agent identity relies solely on a forgeable HTTP header — any client on the internal network can set X-Internal-Caller to impersonate a trusted peer agent without any signature or token validation.

**Flagged code:**
```
caller = request.headers.get("X-Internal-Caller", "unknown")
```

**Fix:** Replace header-based identity with mTLS client certificates or short-lived JWT tokens signed by an internal CA. Validate the token cryptographically before trusting any peer identity claim.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `TIER2-LLM09-01` no longer fires for `orchestrator.py`._
---

### [48/54] 🟧 HIGH · `TIER2-LLM06-01` · [Copilot]

**Location:** `tools.py` · line 44
**Finding:** cancel_subscription executes a destructive billing mutation with no human-in-the-loop gate — the LLM agent can cancel subscriptions autonomously without any approval step.

**Flagged code:**
```
resp = requests.post(f"{BILLING_API}/cancel", json={"customer_id": customer_id})
```

**Fix:** Wire a HumanApprovalCallbackHandler (LangChain) or a LangGraph interrupt_before node on the cancel_subscription tool node. Require explicit operator confirmation before any subscription mutation reaches the billing API.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `TIER2-LLM06-01` no longer fires for `tools.py`._
---

### [49/54] 🟨 MEDIUM · `TIER2-LLM06-03` · [Copilot]

**Location:** `guard/input_filter.py` · line 14
**Finding:** Keyword deny-list guardrail is bypassable via indirect framing, base64 encoding, or role-play prompts — provides a false sense of security as the primary injection control.

**Flagged code:**
```
DENY_PATTERNS = [re.compile(p, re.IGNORECASE) for p in DENY_LIST]
```

**Fix:** Supplement or replace the regex deny-list with a classifier-based guardrail (Lakera Guard, Bedrock Guardrails, or an LLM-judge prompt-injection detector). Deny-lists should be a last-resort layer, not the primary control.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `TIER2-LLM06-03` no longer fires for `guard/input_filter.py`._
---

### [50/54] 🟨 MEDIUM · `TIER2-AGENTIC-T1-01` · [Copilot]

**Location:** `memory.py` · line 39
**Finding:** Raw user input and unfiltered LLM response are persisted verbatim to session memory — an attacker can plant instructions in turn N that influence the agent's behaviour in turn N+1.

**Flagged code:**
```
memory.setdefault(session_id, []).append({"user": user_message, "assistant": llm_response})
```

**Fix:** Validate memory writes with the same rigor as database writes: schema-check or run content through a moderation classifier before persisting. Separate user-supplied content from agent-generated summaries in the memory schema.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `TIER2-AGENTIC-T1-01` no longer fires for `memory.py`._
---

### [51/54] 🟨 MEDIUM · `TIER2-LLM10-02` · [Copilot]

**Location:** `notifications.py` · line 38
**Finding:** LLM call has no surrounding audit logging — no input hash, no output hash, no latency metric, no trace ID. Incident response cannot reconstruct what the model saw or returned.

**Flagged code:**
```
response = bedrock.invoke_model(modelId=MODEL_ID, body=json.dumps(body))
```

**Fix:** Add structured logging around every LLM invocation capturing: input hash, model ID, latency, token counts, output hash, and correlation ID. Use AWS CloudWatch structured logs, LangSmith, or OpenTelemetry traces.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `TIER2-LLM10-02` no longer fires for `notifications.py`._
---

### [52/54] 🟨 MEDIUM · `TIER2-LLM09-02` · [Copilot]

**Location:** `orchestrator.py` · line 100
**Finding:** Debug endpoint is unauthenticated — any caller can reach it and trigger the system-prompt and secret leak via the exception handler at line 118.

**Flagged code:**
```
@app.route("/debug", methods=["POST"])
```

**Fix:** Require authentication on /debug (API key header validated against a secret, or AWS IAM SigV4 for internal services). Remove the route entirely in production; gate it behind an environment flag (e.g. DEBUG_ENABLED=false).

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `TIER2-LLM09-02` no longer fires for `orchestrator.py`._
---

### [53/54] 🟨 MEDIUM · `TIER2-LLM10-01` · [Copilot]

**Location:** `orchestrator.py` · line 63
**Finding:** Agent-to-agent delegation has no audit trail — the delegated payload, downstream agent URL, and response are not logged, making it impossible to reconstruct a multi-hop attack chain.

**Flagged code:**
```
resp = requests.post(DOWNSTREAM_AGENT_URL, json={"message": user_input}, headers=headers)
```

**Fix:** Log every agent delegation with: caller identity, target URL, payload hash, correlation ID, latency, and response status. Propagate a W3C Trace-Context traceparent header to chain spans across agents.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `TIER2-LLM10-01` no longer fires for `orchestrator.py`._
---

### [54/54] 🟩 LOW · `TIER2-AGENTIC-T1-02` · [Copilot]

**Location:** `memory.py` · line 21
**Finding:** Session memory is persisted to /tmp with no filesystem access controls — any process on the same host can read or overwrite all user session histories.

**Flagged code:**
```
MEMORY_FILE = Path("/tmp/demo-agent-memory.json")
```

**Fix:** Store session memory in a process-owned directory with restricted permissions (chmod 0700), or use a dedicated access-controlled datastore (DynamoDB with IAM, Redis with AUTH). Avoid /tmp for any persistent sensitive state.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `TIER2-AGENTIC-T1-02` no longer fires for `memory.py`._

---

_Generated by AgentShield · Re-run `agentshield merge <path>` after fixes to get a fresh copy of this guide with only remaining findings._
