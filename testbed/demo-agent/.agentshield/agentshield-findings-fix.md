# AgentShield — Findings Fix Guide

_Per-scan fix guide — every finding with its exact file, line, flagged code, and a concrete fix. Paste this file into Claude Code or Copilot Chat and say:_

> **"Fix all the findings listed in this guide. For each one, read the Location, Flagged code, and Fix sections, then apply the change. After all fixes, confirm what you changed."**

---

**80 findings to fix** — 🟥 39 critical · 🟧 27 high · 🟨 7 medium · 🟩 1 low · 🟦 6 info

Work through them **top to bottom** (critical first).

---

### [1/80] 🟥 CRITICAL · `emulator-system-prompt-extraction` · [Copilot]

**Location:** `controller.py` · line 18
**Finding:** System prompt extraction (LLM07 / AML.T0056)

**Fix:** Never place the system prompt verbatim in any response payload — including error paths, debug endpoints, or audit messages. Filter system-prompt content out of the final-answer step with an explicit regex / classifier. Test the error path specifically; it's the most common leak channel.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `emulator-system-prompt-extraction` no longer fires for `controller.py`._
---

### [2/80] 🟥 CRITICAL · `emulator-memory-poisoning` · [Copilot]

**Location:** `controller.py` · line 18
**Finding:** Memory poisoning (T1)

**Fix:** Scope memory writes to the current session — never share memory across session_id values. Treat any user-supplied "remember this forever" directive as data, not policy. Strip system-prompt and config content from any model output before it can be persisted into a memory store.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `emulator-memory-poisoning` no longer fires for `controller.py`._
---

### [3/80] 🟥 CRITICAL · `emulator-partial-defense-bypass` · [Copilot]

**Location:** `controller.py` · line 18
**Finding:** Partial-defence bypass — layered controls evaded (LLM01 / T6)

**Fix:** A keyword deny-list and a natural-language 'never reveal' instruction are both bypassable with indirect, role-play, or obfuscated payloads. Close the loop with a third control at the output boundary: an LLM-as-judge or regex classifier that scans the final-answer content before emission, so that a payload defeating the input and planner layers still cannot exfiltrate protected content through the response.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `emulator-partial-defense-bypass` no longer fires for `controller.py`._
---

### [4/80] 🟥 CRITICAL · `emulator-insecure-output-handling` · [Copilot]

**Location:** `controller.py` · line 22
**Finding:** Insecure output handling (LLM05)

**Fix:** Never feed LLM output (or tool output derived from LLM output) into eval(), exec(), subprocess with shell=True, or an unescaped template render. Sanitise / validate at the consumer boundary: parse with ast.literal_eval for expressions, escape for HTML/SQL contexts, and require a strict schema for any downstream call. LLM output is untrusted user content, not code.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `emulator-insecure-output-handling` no longer fires for `controller.py`._
---

### [5/80] 🟥 CRITICAL · `emulator-direct-prompt-injection` · [Copilot]

**Location:** `controller.py` · line 25
**Finding:** Direct prompt injection (T6 / LLM01)

**Fix:** Layer three controls: (1) input sanitiser at the user-prompt step that strips or flags instruction-override patterns; (2) anti-injection language in the system prompt instructing the planner to refuse meta-instructions from user content; (3) output filter at the final-answer step that scrubs system-prompt content and embedded secrets before emission.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `emulator-direct-prompt-injection` no longer fires for `controller.py`._
---

### [6/80] 🟥 CRITICAL · `emulator-system-prompt-extraction` · [Copilot]

**Location:** `controller.py` · line 25
**Finding:** System prompt extraction (LLM07 / AML.T0056)

**Fix:** Never place the system prompt verbatim in any response payload — including error paths, debug endpoints, or audit messages. Filter system-prompt content out of the final-answer step with an explicit regex / classifier. Test the error path specifically; it's the most common leak channel.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `emulator-system-prompt-extraction` no longer fires for `controller.py`._
---

### [7/80] 🟥 CRITICAL · `emulator-memory-poisoning` · [Copilot]

**Location:** `controller.py` · line 25
**Finding:** Memory poisoning (T1)

**Fix:** Scope memory writes to the current session — never share memory across session_id values. Treat any user-supplied "remember this forever" directive as data, not policy. Strip system-prompt and config content from any model output before it can be persisted into a memory store.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `emulator-memory-poisoning` no longer fires for `controller.py`._
---

### [8/80] 🟥 CRITICAL · `emulator-cross-tenant-fishing` · [Copilot]

**Location:** `controller.py` · line 25
**Finding:** Cross-tenant data fishing (T9 + LLM06)

**Fix:** Enforce the tenant boundary at the data-access layer — every read query must include the authenticated principal's tenant ID as a non-overridable filter, not a hint the model can choose to ignore. Reject any tool call whose resulting query would cross tenants regardless of declared role in chat. Log cross-tenant lookups separately and require explicit out-of-band approval for legitimate audit reads.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `emulator-cross-tenant-fishing` no longer fires for `controller.py`._
---

### [9/80] 🟥 CRITICAL · `emulator-insecure-output-handling` · [Copilot]

**Location:** `controller.py` · line 25
**Finding:** Insecure output handling (LLM05)

**Fix:** Never feed LLM output (or tool output derived from LLM output) into eval(), exec(), subprocess with shell=True, or an unescaped template render. Sanitise / validate at the consumer boundary: parse with ast.literal_eval for expressions, escape for HTML/SQL contexts, and require a strict schema for any downstream call. LLM output is untrusted user content, not code.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `emulator-insecure-output-handling` no longer fires for `controller.py`._
---

### [10/80] 🟥 CRITICAL · `emulator-indirect-prompt-injection` · [Copilot]

**Location:** `controller.py` · line 27
**Finding:** Indirect prompt injection via retrieved doc (LLM01 indirect)

**Fix:** Treat retrieved content (RAG, document loaders, vector search hits, memory recall) as untrusted input. Sanitise or content-classify before it reaches the planner; mark retrieved text as data-not-instruction in the prompt envelope; reject documents that fail a provenance check.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `emulator-indirect-prompt-injection` no longer fires for `controller.py`._
---

### [11/80] 🟥 CRITICAL · `emulator-tool-output-poisoning` · [Copilot]

**Location:** `controller.py` · line 27
**Finding:** Tool-output poisoning

**Fix:** Treat tool output as untrusted input. Validate or classify tool returns before feeding them into the re-planning step. Schema-check structured outputs. Strip instruction-shaped content from free-form tool replies. Plugins / third-party tools must be sandboxed; their returns must not be trusted as authoritative context.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `emulator-tool-output-poisoning` no longer fires for `controller.py`._
---

### [12/80] 🟥 CRITICAL · `emulator-batch-data-poisoning` · [Copilot]

**Location:** `controller.py` · line 27
**Finding:** Batch data poisoning — indirect injection via pipeline input

**Fix:** Treat every data record as untrusted user content — not as a trusted instruction. Add a content-trust boundary between data ingestion and the LLM prompt template: (1) wrap record values in explicit delimiters or quotes so the template makes the data/instruction boundary structurally unambiguous; (2) apply a content classifier or keyword filter to record values before they are interpolated into the prompt; (3) validate LLM output against an expected schema before the downstream write step so injected instructions that redirect output are caught before being persisted.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `emulator-batch-data-poisoning` no longer fires for `controller.py`._
---

### [13/80] 🟥 CRITICAL · `emulator-excessive-agency` · [Copilot]

**Location:** `controller.py` · line 25
**Finding:** Excessive agency / over-broad tool surface (LLM06 / Agentic T3)

**Fix:** Minimise the tool surface — register only the tools the agent needs for the current workflow, not every tool the team has ever built. Mark destructive tools (cancel_, delete_, drop_, purge_, transfer_) as HITL-gated: they must require a separate confirmation step (out-of-band approval, signed-scope claim, or explicit user click) before the dispatcher executes. Never let a single LLM decision fire a destructive action without a second gate.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `emulator-excessive-agency` no longer fires for `controller.py`._
---

### [14/80] 🟥 CRITICAL · `emulator-repudiation` · [Copilot]

**Location:** `controller.py` · line 17
**Finding:** Repudiation (T8)

**Fix:** Tie the audit trail to the tool layer, not to the model's self-report. Every tool call must write an immutable log entry (timestamp, authenticated principal, tool, args) before the call returns, and the agent must never be asked to attest to whether an action happened — only the audit log answers that question.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `emulator-repudiation` no longer fires for `controller.py`._
---

### [15/80] 🟥 CRITICAL · `emulator-repudiation` · [Copilot]

**Location:** `controller.py` · line 25
**Finding:** Repudiation (T8)

**Fix:** Tie the audit trail to the tool layer, not to the model's self-report. Every tool call must write an immutable log entry (timestamp, authenticated principal, tool, args) before the call returns, and the agent must never be asked to attest to whether an action happened — only the audit log answers that question.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `emulator-repudiation` no longer fires for `controller.py`._
---

### [16/80] 🟥 CRITICAL · `emulator-direct-prompt-injection` · [Copilot]

**Location:** `orchestrator.py` · line 83
**Finding:** Direct prompt injection (T6 / LLM01)

**Fix:** Layer three controls: (1) input sanitiser at the user-prompt step that strips or flags instruction-override patterns; (2) anti-injection language in the system prompt instructing the planner to refuse meta-instructions from user content; (3) output filter at the final-answer step that scrubs system-prompt content and embedded secrets before emission.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `emulator-direct-prompt-injection` no longer fires for `orchestrator.py`._
---

### [17/80] 🟥 CRITICAL · `emulator-system-prompt-extraction` · [Copilot]

**Location:** `orchestrator.py` · line 83
**Finding:** System prompt extraction (LLM07 / AML.T0056)

**Fix:** Never place the system prompt verbatim in any response payload — including error paths, debug endpoints, or audit messages. Filter system-prompt content out of the final-answer step with an explicit regex / classifier. Test the error path specifically; it's the most common leak channel.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `emulator-system-prompt-extraction` no longer fires for `orchestrator.py`._
---

### [18/80] 🟥 CRITICAL · `emulator-memory-poisoning` · [Copilot]

**Location:** `orchestrator.py` · line 83
**Finding:** Memory poisoning (T1)

**Fix:** Scope memory writes to the current session — never share memory across session_id values. Treat any user-supplied "remember this forever" directive as data, not policy. Strip system-prompt and config content from any model output before it can be persisted into a memory store.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `emulator-memory-poisoning` no longer fires for `orchestrator.py`._
---

### [19/80] 🟥 CRITICAL · `emulator-tool-output-poisoning` · [Copilot]

**Location:** `orchestrator.py` · line 83
**Finding:** Tool-output poisoning

**Fix:** Treat tool output as untrusted input. Validate or classify tool returns before feeding them into the re-planning step. Schema-check structured outputs. Strip instruction-shaped content from free-form tool replies. Plugins / third-party tools must be sandboxed; their returns must not be trusted as authoritative context.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `emulator-tool-output-poisoning` no longer fires for `orchestrator.py`._
---

### [20/80] 🟥 CRITICAL · `emulator-cross-tenant-fishing` · [Copilot]

**Location:** `orchestrator.py` · line 83
**Finding:** Cross-tenant data fishing (T9 + LLM06)

**Fix:** Enforce the tenant boundary at the data-access layer — every read query must include the authenticated principal's tenant ID as a non-overridable filter, not a hint the model can choose to ignore. Reject any tool call whose resulting query would cross tenants regardless of declared role in chat. Log cross-tenant lookups separately and require explicit out-of-band approval for legitimate audit reads.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `emulator-cross-tenant-fishing` no longer fires for `orchestrator.py`._
---

### [21/80] 🟥 CRITICAL · `emulator-insecure-output-handling` · [Copilot]

**Location:** `orchestrator.py` · line 83
**Finding:** Insecure output handling (LLM05)

**Fix:** Never feed LLM output (or tool output derived from LLM output) into eval(), exec(), subprocess with shell=True, or an unescaped template render. Sanitise / validate at the consumer boundary: parse with ast.literal_eval for expressions, escape for HTML/SQL contexts, and require a strict schema for any downstream call. LLM output is untrusted user content, not code.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `emulator-insecure-output-handling` no longer fires for `orchestrator.py`._
---

### [22/80] 🟥 CRITICAL · `emulator-partial-defense-bypass` · [Copilot]

**Location:** `orchestrator.py` · line 83
**Finding:** Partial-defence bypass — layered controls evaded (LLM01 / T6)

**Fix:** A keyword deny-list and a natural-language 'never reveal' instruction are both bypassable with indirect, role-play, or obfuscated payloads. Close the loop with a third control at the output boundary: an LLM-as-judge or regex classifier that scans the final-answer content before emission, so that a payload defeating the input and planner layers still cannot exfiltrate protected content through the response.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `emulator-partial-defense-bypass` no longer fires for `orchestrator.py`._
---

### [23/80] 🟥 CRITICAL · `emulator-cross-agent-injection` · [Copilot]

**Location:** `orchestrator.py` · line 83
**Finding:** Cross-agent prompt injection — sub-agent context abuse

**Fix:** Apply the same input-trust rules to orchestrator messages and sub-agent responses as you would to direct user input. On the sub-agent side: treat the orchestrator message as untrusted input — sanitise it the same way you would a user request, and add anti-injection instructions to the sub-agent's system prompt. On the orchestrator side: treat sub-agent responses as untrusted tool output — pass them through a content classifier or output schema validator before feeding them to the re-planning LLM call so that injected instructions in the response cannot redirect the orchestrator's next action.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `emulator-cross-agent-injection` no longer fires for `orchestrator.py`._
---

### [24/80] 🟥 CRITICAL · `emulator-direct-prompt-injection` · [Copilot]

**Location:** `orchestrator.py` · line 100
**Finding:** Direct prompt injection (T6 / LLM01)

**Fix:** Layer three controls: (1) input sanitiser at the user-prompt step that strips or flags instruction-override patterns; (2) anti-injection language in the system prompt instructing the planner to refuse meta-instructions from user content; (3) output filter at the final-answer step that scrubs system-prompt content and embedded secrets before emission.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `emulator-direct-prompt-injection` no longer fires for `orchestrator.py`._
---

### [25/80] 🟥 CRITICAL · `emulator-partial-defense-bypass` · [Copilot]

**Location:** `orchestrator.py` · line 100
**Finding:** Partial-defence bypass — layered controls evaded (LLM01 / T6)

**Fix:** A keyword deny-list and a natural-language 'never reveal' instruction are both bypassable with indirect, role-play, or obfuscated payloads. Close the loop with a third control at the output boundary: an LLM-as-judge or regex classifier that scans the final-answer content before emission, so that a payload defeating the input and planner layers still cannot exfiltrate protected content through the response.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `emulator-partial-defense-bypass` no longer fires for `orchestrator.py`._
---

### [26/80] 🟥 CRITICAL · `emulator-system-prompt-extraction` · [Copilot]

**Location:** `orchestrator.py` · line 111
**Finding:** System prompt extraction (LLM07 / AML.T0056)

**Fix:** Never place the system prompt verbatim in any response payload — including error paths, debug endpoints, or audit messages. Filter system-prompt content out of the final-answer step with an explicit regex / classifier. Test the error path specifically; it's the most common leak channel.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `emulator-system-prompt-extraction` no longer fires for `orchestrator.py`._
---

### [27/80] 🟥 CRITICAL · `TIER2-LLM07-02` · [Copilot]

**Location:** `orchestrator.py` · line 118
**Finding:** Exception handler returns SYSTEM_PROMPT verbatim in the HTTP 500 response — any unhandled exception exposes the full system prompt including the embedded secret SK-OPS-7741-PRIVATE to the caller.

**Flagged code:**
```
return jsonify({"error": str(e), "active_system_prompt": SYSTEM_PROMPT}), 500
```

**Fix:** Remove SYSTEM_PROMPT and any internal state from all error responses. Log it server-side only (redacted). Return a generic opaque error body to callers (e.g. {"error": "internal error", "request_id": "..."}).

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `TIER2-LLM07-02` no longer fires for `orchestrator.py`._
---

### [28/80] 🟥 CRITICAL · `emulator-insecure-output-handling` · [Copilot]

**Location:** `orchestrator.py` · line 118
**Finding:** Insecure output handling (LLM05)

**Fix:** Never feed LLM output (or tool output derived from LLM output) into eval(), exec(), subprocess with shell=True, or an unescaped template render. Sanitise / validate at the consumer boundary: parse with ast.literal_eval for expressions, escape for HTML/SQL contexts, and require a strict schema for any downstream call. LLM output is untrusted user content, not code.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `emulator-insecure-output-handling` no longer fires for `orchestrator.py`._
---

### [29/80] 🟥 CRITICAL · `emulator-authority-spoofing` · [Copilot]

**Location:** `orchestrator.py` · line 83
**Finding:** Authority spoofing (T9)

**Fix:** Bind tool-call authority to the request's signed identity (JWT / IAM principal) — never to a role the model claims in chat. Destructive tools (drop_table, delete_*, purge_*) must require a separate human-in-the-loop confirmation step regardless of any declared "admin mode". Reject every tool call whose required scope is not present in the authenticated principal's actual permissions.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `emulator-authority-spoofing` no longer fires for `orchestrator.py`._
---

### [30/80] 🟥 CRITICAL · `emulator-excessive-agency` · [Copilot]

**Location:** `orchestrator.py` · line 83
**Finding:** Excessive agency / over-broad tool surface (LLM06 / Agentic T3)

**Fix:** Minimise the tool surface — register only the tools the agent needs for the current workflow, not every tool the team has ever built. Mark destructive tools (cancel_, delete_, drop_, purge_, transfer_) as HITL-gated: they must require a separate confirmation step (out-of-band approval, signed-scope claim, or explicit user click) before the dispatcher executes. Never let a single LLM decision fire a destructive action without a second gate.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `emulator-excessive-agency` no longer fires for `orchestrator.py`._
---

### [31/80] 🟥 CRITICAL · `emulator-trust-escalation` · [Copilot]

**Location:** `orchestrator.py` · line 83
**Finding:** Trust escalation / agent impersonation

**Fix:** Never derive trust level from message content. Authenticate inter-agent calls at the transport or envelope layer (signed JWT, mutual TLS, IAM role) rather than relying on self-declared identity claims inside the message body. Bind each sub-agent's capabilities to a fixed scope in the orchestrator's routing config — sub-agents should not be able to self-upgrade their permissions by asserting elevated roles in their response. Apply a response-schema validator between the sub-agent response step and the re-planning LLM call so that out-of-schema content (including identity claims) is stripped before synthesis.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `emulator-trust-escalation` no longer fires for `orchestrator.py`._
---

### [32/80] 🟥 CRITICAL · `emulator-authority-spoofing` · [Copilot]

**Location:** `orchestrator.py` · line 100
**Finding:** Authority spoofing (T9)

**Fix:** Bind tool-call authority to the request's signed identity (JWT / IAM principal) — never to a role the model claims in chat. Destructive tools (drop_table, delete_*, purge_*) must require a separate human-in-the-loop confirmation step regardless of any declared "admin mode". Reject every tool call whose required scope is not present in the authenticated principal's actual permissions.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `emulator-authority-spoofing` no longer fires for `orchestrator.py`._
---

### [33/80] 🟥 CRITICAL · `emulator-trust-escalation` · [Copilot]

**Location:** `orchestrator.py` · line 100
**Finding:** Trust escalation / agent impersonation

**Fix:** Never derive trust level from message content. Authenticate inter-agent calls at the transport or envelope layer (signed JWT, mutual TLS, IAM role) rather than relying on self-declared identity claims inside the message body. Bind each sub-agent's capabilities to a fixed scope in the orchestrator's routing config — sub-agents should not be able to self-upgrade their permissions by asserting elevated roles in their response. Apply a response-schema validator between the sub-agent response step and the re-planning LLM call so that out-of-schema content (including identity claims) is stripped before synthesis.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `emulator-trust-escalation` no longer fires for `orchestrator.py`._
---

### [34/80] 🟥 CRITICAL · `emulator-repudiation` · [Copilot]

**Location:** `orchestrator.py` · line 83
**Finding:** Repudiation (T8)

**Fix:** Tie the audit trail to the tool layer, not to the model's self-report. Every tool call must write an immutable log entry (timestamp, authenticated principal, tool, args) before the call returns, and the agent must never be asked to attest to whether an action happened — only the audit log answers that question.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `emulator-repudiation` no longer fires for `orchestrator.py`._
---

### [35/80] 🟥 CRITICAL · `emulator-repudiation` · [Copilot]

**Location:** `orchestrator.py` · line 100
**Finding:** Repudiation (T8)

**Fix:** Tie the audit trail to the tool layer, not to the model's self-report. Every tool call must write an immutable log entry (timestamp, authenticated principal, tool, args) before the call returns, and the agent must never be asked to attest to whether an action happened — only the audit log answers that question.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `emulator-repudiation` no longer fires for `orchestrator.py`._
---

### [36/80] 🟥 CRITICAL · `hardcoded-llm-credentials` · [Semgrep]

**Location:** `testbed/demo-agent/config.py` · line 7
**Finding:** Hardcoded credential string passed to an LLM client constructor (OpenAI, Anthropic, Cohere, Mistral, Together, Groq, HuggingFace, Google generative AI, AWS Bedrock). Secrets in source code are CWE-798 (Use of Hard-coded Credentials) — they end up in git history, container images, and CI logs. Use environment variables, a secrets manager (AWS Secrets Manager, HashiCorp Vault, Azure Key Vault), or the SDK's default credential resolver instead.
**Copilot verdict:** ✅ Confirmed real
**Copilot reasoning:** client = OpenAI(api_key="sk-proj-DEMO...") — literal API key passed to constructor, no env-var indirection, no secrets manager. Real credential exposure if config.py ships.

**Fix:** Move the credential out of source. Options, ranked by safety: (1) the SDK's default credential resolver — for OpenAI / Anthropic / Cohere / Mistral, omit `api_key=` and the SDK reads the standard env var (OPENAI_API_KEY, ANTHROPIC_API_KEY, etc.); for boto3, omit aws_access_key_id and let the default chain (IAM role, instance profile, env, ~/.aws/credentials) resolve. (2) A secrets manager looked up at startup (AWS Secrets Manager, HashiCorp Vault, Azure Key Vault) — `api_key=secrets.get_secret_value(...)["SecretString"]`. (3) Environment variable read explicitly — `api_key=os.environ["OPENAI_API_KEY"]`. Rotate any credential that has been committed to git (it must be treated as compromised — git history exposes it forever even if you delete it from HEAD).

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `hardcoded-llm-credentials` no longer fires for `testbed/demo-agent/config.py`._
---

### [37/80] 🟥 CRITICAL · `llm-output-to-code-execution` · [Semgrep]

**Location:** `testbed/demo-agent/tools.py` · line 21
**Finding:** Output from an LLM call flows into a dangerous code-execution sink (eval / exec / os.system / subprocess with shell=True). LLM output is attacker-controllable via prompt injection — feeding it to a code executor is arbitrary code execution on the host. OWASP LLM05 Improper Output Handling, OWASP Agentic T11.
**Copilot verdict:** ✅ Confirmed real
**Copilot reasoning:** tools.py:21 calls eval(code) where code = response.choices[0].message.content (line 19) — LLM output is fed directly into Python's eval() with no validation, AST allowlist, or sandbox. Direct RCE primitive.

**Fix:** Never pass raw LLM output to eval / exec / os.system or shell=True subprocess. If you must execute generated code, run it in an isolated sandbox (Docker, Firecracker, gVisor, SessionsPythonREPLTool, restricted-python) with no host access. For shell commands, parse with shlex.split and pass argv to subprocess without shell=True. For arithmetic / config evaluation, prefer ast.literal_eval. For SQL, use parameterized queries — never format LLM output into a query string.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `llm-output-to-code-execution` no longer fires for `testbed/demo-agent/tools.py`._
---

### [38/80] 🟥 CRITICAL · `emulator-tool-output-poisoning` · [Copilot]

**Location:** `tools.py` · line 34
**Finding:** Tool-output poisoning

**Fix:** Treat tool output as untrusted input. Validate or classify tool returns before feeding them into the re-planning step. Schema-check structured outputs. Strip instruction-shaped content from free-form tool replies. Plugins / third-party tools must be sandboxed; their returns must not be trusted as authoritative context.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `emulator-tool-output-poisoning` no longer fires for `tools.py`._
---

### [39/80] 🟥 CRITICAL · `emulator-excessive-agency` · [Copilot]

**Location:** `tools.py` · line 25
**Finding:** Excessive agency / over-broad tool surface (LLM06 / Agentic T3)

**Fix:** Minimise the tool surface — register only the tools the agent needs for the current workflow, not every tool the team has ever built. Mark destructive tools (cancel_, delete_, drop_, purge_, transfer_) as HITL-gated: they must require a separate confirmation step (out-of-band approval, signed-scope claim, or explicit user click) before the dispatcher executes. Never let a single LLM decision fire a destructive action without a second gate.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `emulator-excessive-agency` no longer fires for `tools.py`._
---

### [40/80] 🟧 HIGH · `ast03-network-unrestricted` · [Semgrep]

**Location:** `SKILL.md` · line 1
**Finding:** Skill declares unrestricted network egress (`network: true`). AST03 — should be a domain allowlist (`network.allow: [api.example.com]`) with default-deny.
**Copilot verdict:** ✅ Confirmed real
**Copilot reasoning:** Frontmatter declares permissions.network: true with no network.allow allowlist — unrestricted outbound network access.

**Fix:** Use a domain allowlist with default-deny: `network.allow: [api.example.com]`.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `ast03-network-unrestricted` no longer fires for `SKILL.md`._
---

### [41/80] 🟧 HIGH · `ast08-permission-combo-across-skills` · [Semgrep]

**Location:** `SKILL.md` · line 1
**Finding:** Two skills loaded together grant a dangerous permission combination that neither holds alone. /Users/suganthichandrasekaran/AgentShield/testbed/demo-agent/SKILL.md contributes ['network_egress'], /Users/suganthichandrasekaran/AgentShield/testbed/demo-agent/skills/billing/SKILL.md contributes ['shell']. Shell access paired with network egress turns the agent into a general-purpose attack tool — exec anything, send results out. AST08 — Permission Bleed.
**Copilot verdict:** ✅ Confirmed real
**Copilot reasoning:** Combined permissions across the two manifests: demo-agent-helper grants network: true + filesystem read/write; billing grants shell: true. The compound (network egress + shell exec + filesystem write) is the RCE-to-exfil pair AST08 watches for — neither skill on its own grants the dangerous combo, but together they do.

**Fix:** Audit the cross-skill permission set. Either tighten each skill's grant so the dangerous combo no longer materialises (e.g. remove network from the skill that doesn't need it), or isolate the skills into separate runtime contexts so a compromise of one can't leverage the other's privileges. Document the intentional combo in the manifest if it's load-bearing — silent privilege bleed is the failure mode.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `ast08-permission-combo-across-skills` no longer fires for `SKILL.md`._
---

### [42/80] 🟧 HIGH · `ast08-permission-combo-across-skills` · [Semgrep]

**Location:** `SKILL.md` · line 1
**Finding:** Two skills loaded together grant a dangerous permission combination that neither holds alone. /Users/suganthichandrasekaran/AgentShield/testbed/demo-agent/SKILL.md contributes ['files_write'], /Users/suganthichandrasekaran/AgentShield/testbed/demo-agent/skills/billing/SKILL.md contributes ['shell']. Shell access paired with file write means the agent can drop arbitrary scripts onto the host and run them. AST08 — Permission Bleed.
**Copilot verdict:** ✅ Confirmed real
**Copilot reasoning:** Second emission of the same cross-skill compound permission reported from the billing-side perspective. Either fix (drop network from the helper OR drop shell from billing OR split the skills across separate agents) resolves both.

**Fix:** Audit the cross-skill permission set. Either tighten each skill's grant so the dangerous combo no longer materialises (e.g. remove network from the skill that doesn't need it), or isolate the skills into separate runtime contexts so a compromise of one can't leverage the other's privileges. Document the intentional combo in the manifest if it's load-bearing — silent privilege bleed is the failure mode.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `ast08-permission-combo-across-skills` no longer fires for `SKILL.md`._
---

### [43/80] 🟧 HIGH · `TIER2-LLM01-01` · [Copilot]

**Location:** `config.py` · line 13
**Finding:** Database connection string with embedded username and password hardcoded in source — not caught by Tier 1 API-key rules because it uses the postgresql:// URI scheme.

**Flagged code:**
```
DATABASE_URL = "postgresql://demo:demo@internal-pg.local:5432/support"
```

**Fix:** Move DATABASE_URL to AWS Secrets Manager. Reference at startup via boto3 secretsmanager.get_secret_value and rotate the credential. Remove the hardcoded string from source.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `TIER2-LLM01-01` no longer fires for `config.py`._
---

### [44/80] 🟧 HIGH · `ast06-credential-in-bundle` · [Semgrep]

**Location:** `config.yaml` · line 17
**Finding:** Anthropic API key hard-coded in skill-bundle file `config.yaml`. Skill bundles ship verbatim to every consumer — anyone who can read the bundle (registry, cache, developer clone) reads the secret. AST06 — Secrets in Skill Bundles. Move to a secrets manager or runtime-injected env var; never ship secrets inside the bundle itself.
**Copilot verdict:** ✅ Confirmed real
**Copilot reasoning:** Literal Anthropic API key sk-ant-api03-AbCdEf... hard-coded in the bundled YAML. Ships verbatim to every consumer (registry pulls, git clones, container images, CI logs).

**Fix:** Move secrets to a secrets manager (AWS Secrets Manager, HashiCorp Vault, Azure Key Vault) and reference them by name from the manifest. If runtime injection isn't an option, at minimum keep credentials in a separate file outside the bundle and load them via environment variable.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `ast06-credential-in-bundle` no longer fires for `config.yaml`._
---

### [45/80] 🟧 HIGH · `ast06-credential-in-bundle` · [Semgrep]

**Location:** `config.yaml` · line 21
**Finding:** OpenAI project key hard-coded in skill-bundle file `config.yaml`. Skill bundles ship verbatim to every consumer — anyone who can read the bundle (registry, cache, developer clone) reads the secret. AST06 — Secrets in Skill Bundles. Move to a secrets manager or runtime-injected env var; never ship secrets inside the bundle itself.
**Copilot verdict:** ✅ Confirmed real
**Copilot reasoning:** Literal OpenAI API key sk-proj-AbCdEf... hard-coded in the bundled YAML. Same shipping path as line 17.

**Fix:** Move secrets to a secrets manager (AWS Secrets Manager, HashiCorp Vault, Azure Key Vault) and reference them by name from the manifest. If runtime injection isn't an option, at minimum keep credentials in a separate file outside the bundle and load them via environment variable.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `ast06-credential-in-bundle` no longer fires for `config.yaml`._
---

### [46/80] 🟧 HIGH · `ast06-credential-in-bundle` · [Semgrep]

**Location:** `config.yaml` · line 25
**Finding:** AWS access-key ID hard-coded in skill-bundle file `config.yaml`. Skill bundles ship verbatim to every consumer — anyone who can read the bundle (registry, cache, developer clone) reads the secret. AST06 — Secrets in Skill Bundles. Move to a secrets manager or runtime-injected env var; never ship secrets inside the bundle itself.
**Copilot verdict:** ✅ Confirmed real
**Copilot reasoning:** Literal AWS access_key_id AKIAIOSFODNN7EXAMPLE hard-coded in the bundled YAML. The rule correctly flags the shape — production credentials with the same pattern leak the same way.

**Fix:** Move secrets to a secrets manager (AWS Secrets Manager, HashiCorp Vault, Azure Key Vault) and reference them by name from the manifest. If runtime injection isn't an option, at minimum keep credentials in a separate file outside the bundle and load them via environment variable.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `ast06-credential-in-bundle` no longer fires for `config.yaml`._
---

### [47/80] 🟧 HIGH · `ast06-credential-in-bundle` · [Semgrep]

**Location:** `config.yaml` · line 29
**Finding:** Generic credential assignment hard-coded in skill-bundle file `config.yaml`. Skill bundles ship verbatim to every consumer — anyone who can read the bundle (registry, cache, developer clone) reads the secret. AST06 — Secrets in Skill Bundles. Move to a secrets manager or runtime-injected env var; never ship secrets inside the bundle itself.
**Copilot verdict:** ✅ Confirmed real
**Copilot reasoning:** Literal database password support_db_password: 2v8XyZ4qPmA9rT6wKn3eRfBhJ5sLcGdU hard-coded in the bundled YAML.

**Fix:** Move secrets to a secrets manager (AWS Secrets Manager, HashiCorp Vault, Azure Key Vault) and reference them by name from the manifest. If runtime injection isn't an option, at minimum keep credentials in a separate file outside the bundle and load them via environment variable.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `ast06-credential-in-bundle` no longer fires for `config.yaml`._
---

### [48/80] 🟧 HIGH · `ast06-credential-in-bundle` · [Semgrep]

**Location:** `config.yaml` · line 30
**Finding:** Slack token hard-coded in skill-bundle file `config.yaml`. Skill bundles ship verbatim to every consumer — anyone who can read the bundle (registry, cache, developer clone) reads the secret. AST06 — Secrets in Skill Bundles. Move to a secrets manager or runtime-injected env var; never ship secrets inside the bundle itself.
**Copilot verdict:** ✅ Confirmed real
**Copilot reasoning:** Literal Slack bot token xoxb-1234567890123-... hard-coded in the bundled YAML. Slack tokens grant write access to channels — exfil pivot if leaked.

**Fix:** Move secrets to a secrets manager (AWS Secrets Manager, HashiCorp Vault, Azure Key Vault) and reference them by name from the manifest. If runtime injection isn't an option, at minimum keep credentials in a separate file outside the bundle and load them via environment variable.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `ast06-credential-in-bundle` no longer fires for `config.yaml`._
---

### [49/80] 🟧 HIGH · `emulator-direct-prompt-injection` · [Copilot]

**Location:** `controller.py` · line 18
**Finding:** Direct prompt injection (T6 / LLM01)

**Fix:** Layer three controls: (1) input sanitiser at the user-prompt step that strips or flags instruction-override patterns; (2) anti-injection language in the system prompt instructing the planner to refuse meta-instructions from user content; (3) output filter at the final-answer step that scrubs system-prompt content and embedded secrets before emission.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `emulator-direct-prompt-injection` no longer fires for `controller.py`._
---

### [50/80] 🟧 HIGH · `emulator-cross-tenant-fishing` · [Copilot]

**Location:** `controller.py` · line 18
**Finding:** Cross-tenant data fishing (T9 + LLM06)

**Fix:** Enforce the tenant boundary at the data-access layer — every read query must include the authenticated principal's tenant ID as a non-overridable filter, not a hint the model can choose to ignore. Reject any tool call whose resulting query would cross tenants regardless of declared role in chat. Log cross-tenant lookups separately and require explicit out-of-band approval for legitimate audit reads.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `emulator-cross-tenant-fishing` no longer fires for `controller.py`._
---

### [51/80] 🟧 HIGH · `emulator-tool-argument-injection` · [Copilot]

**Location:** `controller.py` · line 18
**Finding:** Tool argument injection (Agentic T2 / CWE-78 / CWE-89)

**Fix:** Validate every tool argument against an allow-list / regex / schema before it reaches a shell, SQL query, HTTP URL, or filesystem path. Use parameterised queries for SQL, list-form subprocess invocation (never shell=True with interpolated strings), and structured URL builders that reject path traversal. Treat the LLM as an untrusted source for tool-argument content.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `emulator-tool-argument-injection` no longer fires for `controller.py`._
---

### [52/80] 🟧 HIGH · `emulator-tool-argument-injection` · [Copilot]

**Location:** `controller.py` · line 25
**Finding:** Tool argument injection (Agentic T2 / CWE-78 / CWE-89)

**Fix:** Validate every tool argument against an allow-list / regex / schema before it reaches a shell, SQL query, HTTP URL, or filesystem path. Use parameterised queries for SQL, list-form subprocess invocation (never shell=True with interpolated strings), and structured URL builders that reject path traversal. Treat the LLM as an untrusted source for tool-argument content.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `emulator-tool-argument-injection` no longer fires for `controller.py`._
---

### [53/80] 🟧 HIGH · `TIER2-LLM01-02` · [Copilot]

**Location:** `controller.py` · line 35
**Finding:** User-supplied article_url is fetched without a hostname allowlist; retrieved page content flows into the LLM — indirect prompt-injection via attacker-controlled webpage.

**Flagged code:**
```
docs = WebBaseLoader(article_url).load()
```

**Fix:** Validate article_url against an explicit hostname allowlist before fetching. Treat retrieved document content as untrusted: pass through a guardrail layer (Lakera Guard, Bedrock Guardrails, or a ScrubbingCallAdvisor) before the LLM call.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `TIER2-LLM01-02` no longer fires for `controller.py`._
---

### [54/80] 🟧 HIGH · `TIER2-LLM02-04` · [Copilot]

**Location:** `notifications.py` · line 50
**Finding:** LLM output published to SNS after only partial PII scrubbing — _scrub_pii redacts SSN and passport patterns but not email addresses or account numbers, risking data leakage to all SNS subscribers.

**Flagged code:**
```
sns.publish(TopicArn=TOPIC_ARN, Message=scrubbed, Subject="Support Reply")
```

**Fix:** Expand _scrub_pii to cover emails, account numbers, credit-card patterns, and phone numbers. Alternatively adopt Presidio AnonymizerEngine which covers the full NLP PII entity catalogue out of the box.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `TIER2-LLM02-04` no longer fires for `notifications.py`._
---

### [55/80] 🟧 HIGH · `TIER2-LLM07-01` · [Copilot]

**Location:** `orchestrator.py` · line 76
**Finding:** Operational secret key SK-OPS-7741-PRIVATE is embedded verbatim in the system prompt — any system-prompt leak path exposes it directly to the LLM output stream.

**Flagged code:**
```
SYSTEM_PROMPT = """You are a support orchestrator ... SK-OPS-7741-PRIVATE ..."""
```

**Fix:** Remove credentials from system prompts entirely. Inject secrets at runtime via a tool call to AWS Secrets Manager only when the specific operation requires them, not pre-loaded into every LLM context.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `TIER2-LLM07-01` no longer fires for `orchestrator.py`._
---

### [56/80] 🟧 HIGH · `emulator-tool-argument-injection` · [Copilot]

**Location:** `orchestrator.py` · line 83
**Finding:** Tool argument injection (Agentic T2 / CWE-78 / CWE-89)

**Fix:** Validate every tool argument against an allow-list / regex / schema before it reaches a shell, SQL query, HTTP URL, or filesystem path. Use parameterised queries for SQL, list-form subprocess invocation (never shell=True with interpolated strings), and structured URL builders that reject path traversal. Treat the LLM as an untrusted source for tool-argument content.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `emulator-tool-argument-injection` no longer fires for `orchestrator.py`._
---

### [57/80] 🟧 HIGH · `TIER2-LLM09-01` · [Copilot]

**Location:** `orchestrator.py` · line 83
**Finding:** Peer-agent identity relies solely on a forgeable HTTP header — any client on the internal network can set X-Internal-Caller to impersonate a trusted peer agent without any signature or token validation.

**Flagged code:**
```
caller = request.headers.get("X-Internal-Caller", "unknown")
```

**Fix:** Replace header-based identity with mTLS client certificates or short-lived JWT tokens signed by an internal CA. Validate the token cryptographically before trusting any peer identity claim.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `TIER2-LLM09-01` no longer fires for `orchestrator.py`._
---

### [58/80] 🟧 HIGH · `unsanitized-user-input-to-llm` · [Semgrep]

**Location:** `testbed/demo-agent/controller.py` · line 26
**Finding:** User input from an HTTP request flows directly into an LLM/agent/chain/retriever invocation without passing through a known guardrail or sanitization layer. This is the canonical prompt-injection surface (OWASP LLM01).
**Copilot verdict:** ✅ Confirmed real
**Copilot reasoning:** request.json['message'] flows directly into chain.invoke(user_message) at controller.py:21 with no sanitiser between them — classic untrusted-input-to-LLM sink.

**Fix:** Wrap LLM calls with an input guardrail (NeMo Guardrails, Lakera Guard, Rebuff, Llama Guard, or an equivalent). Validate and sanitize user input before it reaches the prompt template. Use structured prompting that strictly delimits user content from instructions.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `unsanitized-user-input-to-llm` no longer fires for `testbed/demo-agent/controller.py`._
---

### [59/80] 🟧 HIGH · `unsanitized-user-input-to-llm` · [Semgrep]

**Location:** `testbed/demo-agent/controller.py` · line 39
**Finding:** User input from an HTTP request flows directly into an LLM/agent/chain/retriever invocation without passing through a known guardrail or sanitization layer. This is the canonical prompt-injection surface (OWASP LLM01).
**Copilot verdict:** ✅ Confirmed real
**Copilot reasoning:** User-controlled article_url (request.json.get('url', '')) is fetched by WebBaseLoader and its content flows into chain.invoke() — indirect prompt-injection sink via the retrieved document body.

**Fix:** Wrap LLM calls with an input guardrail (NeMo Guardrails, Lakera Guard, Rebuff, Llama Guard, or an equivalent). Validate and sanitize user input before it reaches the prompt template. Use structured prompting that strictly delimits user content from instructions.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `unsanitized-user-input-to-llm` no longer fires for `testbed/demo-agent/controller.py`._
---

### [60/80] 🟧 HIGH · `agent-communication-poisoning` · [Semgrep]

**Location:** `testbed/demo-agent/orchestrator.py` · line 63
**Finding:** User-controlled input is forwarded verbatim to another agent's HTTP endpoint without sanitisation or trust-boundary enforcement. The downstream agent receives the attacker's payload as if it came from a trusted internal caller — the upstream agent's authority is laundered onto the downstream call (OWASP Agentic T12 — Agent Communication Poisoning). Pair this rule with the behaviour emulator (Phase 2) to verify the downstream agent actually accepts and acts on the forwarded payload.
**Copilot verdict:** ✅ Confirmed real
**Copilot reasoning:** delegate() at orchestrator.py:63 forwards raw user_input verbatim to DOWNSTREAM_AGENT_URL with no sanitiser. The comment block at lines 54-61 explicitly documents the T12 Agent Communication Poisoning pattern — exactly the trust-boundary failure this rule catches.

**Fix:** Sanitise or structurally validate inter-agent payloads before forwarding. Strip instruction-shaped content from the user message (e.g. via a guardrail) before placing it in the downstream request body. Authenticate the downstream call with a signed token that binds the request to a specific user identity, so the downstream agent can apply per-user policy instead of trusting the upstream agent unconditionally.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `agent-communication-poisoning` no longer fires for `testbed/demo-agent/orchestrator.py`._
---

### [61/80] 🟧 HIGH · `unsanitized-user-input-to-llm` · [Semgrep]

**Location:** `testbed/demo-agent/orchestrator.py` · line 87
**Finding:** User input from an HTTP request flows directly into an LLM/agent/chain/retriever invocation without passing through a known guardrail or sanitization layer. This is the canonical prompt-injection surface (OWASP LLM01).
**Copilot verdict:** ✅ Confirmed real
**Copilot reasoning:** peer_message (request.json.get('message', '')) flows directly into chain.invoke({'input': peer_message}) at line 87 with no sanitiser. Untrusted-input-to-LLM holds regardless of whether the input is user-typed or peer-supplied.

**Fix:** Wrap LLM calls with an input guardrail (NeMo Guardrails, Lakera Guard, Rebuff, Llama Guard, or an equivalent). Validate and sanitize user input before it reaches the prompt template. Use structured prompting that strictly delimits user content from instructions.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `unsanitized-user-input-to-llm` no longer fires for `testbed/demo-agent/orchestrator.py`._
---

### [62/80] 🟧 HIGH · `unvalidated-peer-agent-input` · [Semgrep]

**Location:** `testbed/demo-agent/orchestrator.py` · line 87
**Finding:** Handler accepts a request claiming to come from a trusted internal agent (via a header signal like X-Internal-Caller / X-Agent-Source) and forwards the payload to an LLM without per-call authentication or input validation. Any peer on the internal network that can set the header is implicitly trusted — there is no cryptographic proof the caller is the agent it claims to be (OWASP Agentic T13 — Rogue Agents in Multi-Agent Systems). Pair with the behaviour emulator (Phase 2) to confirm the LLM acts on attacker-controlled "peer" input.
**Copilot verdict:** ✅ Confirmed real
**Copilot reasoning:** receive_from_peer() trusts the X-Internal-Caller header as proof of peer identity (lines 82-83) with no signature, JWT, or mTLS verification — anyone on the internal network can set the header. Payload then flows to chain.invoke at line 87. Textbook T13 Rogue Agents pattern.

**Fix:** Require cryptographic proof that the caller is the agent it claims to be — a short-lived signed token (JWT with mTLS-anchored claims or a peer-key HMAC) carried per request, not a static header. Treat peer input the same way you treat user input: route through a guardrail and a structural validator before it reaches the LLM prompt. Log the verified caller identity on every invocation so a rogue agent's traffic is attributable later.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `unvalidated-peer-agent-input` no longer fires for `testbed/demo-agent/orchestrator.py`._
---

### [63/80] 🟧 HIGH · `unsanitized-user-input-to-llm` · [Semgrep]

**Location:** `testbed/demo-agent/orchestrator.py` · line 110
**Finding:** User input from an HTTP request flows directly into an LLM/agent/chain/retriever invocation without passing through a known guardrail or sanitization layer. This is the canonical prompt-injection surface (OWASP LLM01).
**Copilot verdict:** ✅ Confirmed real
**Copilot reasoning:** debug_endpoint() reads user_input from request.json and feeds it to chain.invoke({'input': user_input}) at line 110 with no sanitiser. The accompanying TIER2-LLM07-02 system-prompt leak at line 118 amplifies the impact of any injection.

**Fix:** Wrap LLM calls with an input guardrail (NeMo Guardrails, Lakera Guard, Rebuff, Llama Guard, or an equivalent). Validate and sanitize user input before it reaches the prompt template. Use structured prompting that strictly delimits user content from instructions.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `unsanitized-user-input-to-llm` no longer fires for `testbed/demo-agent/orchestrator.py`._
---

### [64/80] 🟧 HIGH · `unvalidated-peer-agent-input` · [Semgrep]

**Location:** `testbed/demo-agent/orchestrator.py` · line 110
**Finding:** Handler accepts a request claiming to come from a trusted internal agent (via a header signal like X-Internal-Caller / X-Agent-Source) and forwards the payload to an LLM without per-call authentication or input validation. Any peer on the internal network that can set the header is implicitly trusted — there is no cryptographic proof the caller is the agent it claims to be (OWASP Agentic T13 — Rogue Agents in Multi-Agent Systems). Pair with the behaviour emulator (Phase 2) to confirm the LLM acts on attacker-controlled "peer" input.
**Copilot verdict:** ⚠ Context-dependent
**Copilot reasoning:** debug_endpoint() does not consult X-Internal-Caller — input is direct user HTTP, not a peer-agent surface, so the peer-agent rule misfires on the trust pattern. However, the endpoint is entirely unauthenticated (TIER2-LLM09-02), meaning any external caller can reach it and trigger the system-prompt leak at line 118. The code is risky even though the specific peer-agent pattern does not apply; TIER2-LLM09-02 is the correct finding here.

**Fix:** Require cryptographic proof that the caller is the agent it claims to be — a short-lived signed token (JWT with mTLS-anchored claims or a peer-key HMAC) carried per request, not a static header. Treat peer input the same way you treat user input: route through a guardrail and a structural validator before it reaches the LLM prompt. Log the verified caller identity on every invocation so a rogue agent's traffic is attributable later.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `unvalidated-peer-agent-input` no longer fires for `testbed/demo-agent/orchestrator.py`._
---

### [65/80] 🟧 HIGH · `system-prompt-leak-via-tool-output` · [Semgrep]

**Location:** `testbed/demo-agent/orchestrator.py` · line 116
**Finding:** A code path exposes the agent's system prompt (or any variable named like a prompt template) in a user-reachable response — typically an error handler that includes the active prompt for "debugging". The prompt itself often carries secrets (escalation keys, internal IDs, tool descriptions) and is by definition meant to stay opaque to the user. Pair with the behaviour emulator (Phase 2) to confirm the model accepts the extraction request (MITRE ATLAS AML.T0056 — System Prompt Disclosure; OWASP LLM07 — System Prompt Leakage).
**Copilot verdict:** ✅ Confirmed real
**Copilot reasoning:** Exception handler at line 116 returns `active_system_prompt: SYSTEM_PROMPT` directly in the JSON response. SYSTEM_PROMPT (lines 91-95) contains the embedded key SK-OPS-7741-PRIVATE — both the system prompt and the secret leak to anyone who triggers an exception. Confirmed by TIER2-LLM07-02.

**Fix:** Never include the system prompt in user-visible responses or logs. Redact prompt-shaped variables from error responses (return a generic error code, log the prompt separately to a non-user- reachable destination). If you must surface debugging context to operators, gate it behind authenticated /admin routes and never on the user-facing endpoint. Treat the system prompt as a secret: rotate the embedded keys if it has ever leaked.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `system-prompt-leak-via-tool-output` no longer fires for `testbed/demo-agent/orchestrator.py`._
---

### [66/80] 🟧 HIGH · `TIER2-LLM06-01` · [Copilot]

**Location:** `tools.py` · line 44
**Finding:** cancel_subscription executes a destructive billing mutation with no human-in-the-loop gate — the LLM agent can cancel subscriptions autonomously without any approval step.

**Flagged code:**
```
resp = requests.post(f"{BILLING_API}/cancel", json={"customer_id": customer_id})
```

**Fix:** Wire a HumanApprovalCallbackHandler (LangChain) or a LangGraph interrupt_before node on the cancel_subscription tool node. Require explicit operator confirmation before any subscription mutation reaches the billing API.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `TIER2-LLM06-01` no longer fires for `tools.py`._
---

### [67/80] 🟨 MEDIUM · `ast03-wildcard-file-read` · [Semgrep]

**Location:** `SKILL.md` · line 1
**Finding:** Wildcard read permission on `~/.config/demo-agent/**`. AST03 — skill manifests must declare explicit paths; wildcards defeat least-privilege review.
**Copilot verdict:** ✅ Confirmed real
**Copilot reasoning:** permissions.files.read pattern `~/.config/demo-agent/**` uses the recursive ** glob — wildcard file-read access covering every file under the config directory.

**Fix:** Declare explicit paths; no wildcards.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `ast03-wildcard-file-read` no longer fires for `SKILL.md`._
---

### [68/80] 🟨 MEDIUM · `TIER2-LLM06-03` · [Copilot]

**Location:** `guard/input_filter.py` · line 14
**Finding:** Keyword deny-list guardrail is bypassable via indirect framing, base64 encoding, or role-play prompts — provides a false sense of security as the primary injection control.

**Flagged code:**
```
DENY_PATTERNS = [re.compile(p, re.IGNORECASE) for p in DENY_LIST]
```

**Fix:** Supplement or replace the regex deny-list with a classifier-based guardrail (Lakera Guard, Bedrock Guardrails, or an LLM-judge prompt-injection detector). Deny-lists should be a last-resort layer, not the primary control.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `TIER2-LLM06-03` no longer fires for `guard/input_filter.py`._
---

### [69/80] 🟨 MEDIUM · `TIER2-AGENTIC-T1-01` · [Copilot]

**Location:** `memory.py` · line 39
**Finding:** Raw user input and unfiltered LLM response are persisted verbatim to session memory — an attacker can plant instructions in turn N that influence the agent's behaviour in turn N+1.

**Flagged code:**
```
memory.setdefault(session_id, []).append({"user": user_message, "assistant": llm_response})
```

**Fix:** Validate memory writes with the same rigor as database writes: schema-check or run content through a moderation classifier before persisting. Separate user-supplied content from agent-generated summaries in the memory schema.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `TIER2-AGENTIC-T1-01` no longer fires for `memory.py`._
---

### [70/80] 🟨 MEDIUM · `TIER2-LLM10-02` · [Copilot]

**Location:** `notifications.py` · line 38
**Finding:** LLM call has no surrounding audit logging — no input hash, no output hash, no latency metric, no trace ID. Incident response cannot reconstruct what the model saw or returned.

**Flagged code:**
```
response = bedrock.invoke_model(modelId=MODEL_ID, body=json.dumps(body))
```

**Fix:** Add structured logging around every LLM invocation capturing: input hash, model ID, latency, token counts, output hash, and correlation ID. Use AWS CloudWatch structured logs, LangSmith, or OpenTelemetry traces.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `TIER2-LLM10-02` no longer fires for `notifications.py`._
---

### [71/80] 🟨 MEDIUM · `TIER2-LLM09-02` · [Copilot]

**Location:** `orchestrator.py` · line 100
**Finding:** Debug endpoint is unauthenticated — any caller can reach it and trigger the system-prompt and secret leak via the exception handler at line 118.

**Flagged code:**
```
@app.route("/debug", methods=["POST"])
```

**Fix:** Require authentication on /debug (API key header validated against a secret, or AWS IAM SigV4 for internal services). Remove the route entirely in production; gate it behind an environment flag (e.g. DEBUG_ENABLED=false).

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `TIER2-LLM09-02` no longer fires for `orchestrator.py`._
---

### [72/80] 🟨 MEDIUM · `TIER2-LLM10-01` · [Copilot]

**Location:** `orchestrator.py` · line 63
**Finding:** Agent-to-agent delegation has no audit trail — the delegated payload, downstream agent URL, and response are not logged, making it impossible to reconstruct a multi-hop attack chain.

**Flagged code:**
```
resp = requests.post(DOWNSTREAM_AGENT_URL, json={"message": user_input}, headers=headers)
```

**Fix:** Log every agent delegation with: caller identity, target URL, payload hash, correlation ID, latency, and response status. Propagate a W3C Trace-Context traceparent header to chain spans across agents.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `TIER2-LLM10-01` no longer fires for `orchestrator.py`._
---

### [73/80] 🟨 MEDIUM · `ast03-shell-access` · [Semgrep]

**Location:** `skills/billing/SKILL.md` · line 1
**Finding:** Skill declares shell access (`shell: true`). AST03 — should only be granted when the skill's core function requires it; document why in the description.
**Copilot verdict:** ✅ Confirmed real
**Copilot reasoning:** billing skill frontmatter declares permissions.shell: true. The static permission grant is what AST03 catches — granting shell access is a coarse capability; even narrowed scripts can be attacked via argument injection.

**Fix:** Grant shell access only when the skill's core function requires it; document why in the description.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `ast03-shell-access` no longer fires for `skills/billing/SKILL.md`._
---

### [74/80] 🟩 LOW · `TIER2-AGENTIC-T1-02` · [Copilot]

**Location:** `memory.py` · line 21
**Finding:** Session memory is persisted to /tmp with no filesystem access controls — any process on the same host can read or overwrite all user session histories.

**Flagged code:**
```
MEMORY_FILE = Path("/tmp/demo-agent-memory.json")
```

**Fix:** Store session memory in a process-owned directory with restricted permissions (chmod 0700), or use a dedicated access-controlled datastore (DynamoDB with IAM, Redis with AUTH). Avoid /tmp for any persistent sensitive state.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `TIER2-AGENTIC-T1-02` no longer fires for `memory.py`._
---

### [75/80] 🟦 INFO · `ast04-missing-author-identity` · [Semgrep]

**Location:** `SKILL.md` · line 1
**Finding:** Skill manifest has no `author.identity` (DID / signing-key anchor). AST04 — without a verifiable identity anchor, registry consumers cannot detect impersonation or typosquats; this is the foothold the ClawHub fake-Google skill exploited.
**Copilot verdict:** ✅ Confirmed real
**Copilot reasoning:** Author block has only `name: Demo Co` — no DID, no signed handle, no public-key reference. Provenance is unverifiable; an attacker republishing the bundle as 'Demo Co' is indistinguishable from the legitimate publisher.

**Fix:** Add `author.identity: did:web:<your-domain>` and a `signing_key:` field.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `ast04-missing-author-identity` no longer fires for `SKILL.md`._
---

### [76/80] 🟦 INFO · `ast07-missing-content-hash` · [Semgrep]

**Location:** `SKILL.md` · line 1
**Finding:** SKILL.md frontmatter has no `content_hash` field. AST07 — Merkle-root verification at install time requires a SHA-256 over the canonical skill payload.
**Copilot verdict:** ✅ Confirmed real
**Copilot reasoning:** Frontmatter declares no content_hash / checksum / integrity field — the loader has no way to verify the bundle payload matches what the manifest describes.

**Fix:** Add `content_hash: sha256:<digest>` over the canonical skill payload.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `ast07-missing-content-hash` no longer fires for `SKILL.md`._
---

### [77/80] 🟦 INFO · `ast07-missing-signature` · [Semgrep]

**Location:** `SKILL.md` · line 1
**Finding:** SKILL.md frontmatter has no `signature` field. AST07 — without an ed25519 signature the registry cannot verify the skill on update; ClawJacked-style update-drift attacks become viable.
**Copilot verdict:** ✅ Confirmed real
**Copilot reasoning:** Frontmatter declares no signature field — bundle authenticity is unverifiable independent of integrity. Companion to the missing content_hash finding.

**Fix:** Sign the canonical skill payload with an ed25519 key and publish the signature in the manifest.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `ast07-missing-signature` no longer fires for `SKILL.md`._
---

### [78/80] 🟦 INFO · `ast04-missing-author-identity` · [Semgrep]

**Location:** `skills/billing/SKILL.md` · line 1
**Finding:** Skill manifest has no `author.identity` (DID / signing-key anchor). AST04 — without a verifiable identity anchor, registry consumers cannot detect impersonation or typosquats; this is the foothold the ClawHub fake-Google skill exploited.
**Copilot verdict:** ⚠ Context-dependent
**Copilot reasoning:** Author block has `did: did:example:demo-team` — the did:example: method is documented as a non-production placeholder (RFC), not a real verifiable identity. The presence of a DID field is a step toward compliance, but the placeholder method leaves provenance unverifiable. Mitigatable by switching to a real DID method (did:web, did:key) — hence CD rather than TP.

**Fix:** Add `author.identity: did:web:<your-domain>` and a `signing_key:` field.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `ast04-missing-author-identity` no longer fires for `skills/billing/SKILL.md`._
---

### [79/80] 🟦 INFO · `ast07-missing-content-hash` · [Semgrep]

**Location:** `skills/billing/SKILL.md` · line 1
**Finding:** SKILL.md frontmatter has no `content_hash` field. AST07 — Merkle-root verification at install time requires a SHA-256 over the canonical skill payload.
**Copilot verdict:** ✅ Confirmed real
**Copilot reasoning:** billing skill frontmatter has no content_hash / checksum / integrity field — identical defect to the demo-agent-helper SKILL.md case.

**Fix:** Add `content_hash: sha256:<digest>` over the canonical skill payload.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `ast07-missing-content-hash` no longer fires for `skills/billing/SKILL.md`._
---

### [80/80] 🟦 INFO · `ast07-missing-signature` · [Semgrep]

**Location:** `skills/billing/SKILL.md` · line 1
**Finding:** SKILL.md frontmatter has no `signature` field. AST07 — without an ed25519 signature the registry cannot verify the skill on update; ClawJacked-style update-drift attacks become viable.
**Copilot verdict:** ✅ Confirmed real
**Copilot reasoning:** billing skill frontmatter has no signature field — identical defect to the demo-agent-helper SKILL.md case.

**Fix:** Sign the canonical skill payload with an ed25519 key and publish the signature in the manifest.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `ast07-missing-signature` no longer fires for `skills/billing/SKILL.md`._

---

_Generated by AgentShield · Re-run `agentshield merge <path>` after fixes to get a fresh copy of this guide with only remaining findings._
