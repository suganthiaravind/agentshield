# AgentShield — Semgrep Findings Fix Guide

_Per-scan fix guide for **Semgrep** (static code analysis) findings — exact file:line, flagged code, and a concrete fix for each. Paste into Claude Code or Copilot Chat and say:_

> **"Fix all the findings listed in this guide. For each one, read the Location, Flagged code, and Fix sections, then apply the change. After all fixes, confirm what you changed."**

---

**15 findings to fix** — 🟥 2 critical · 🟧 13 high

Work through them **top to bottom** (critical first).

---

### [1/15] 🟥 CRITICAL · `hardcoded-llm-credentials` · [Semgrep]

**Location:** `testbed/demo-agent/config.py` · line 7
**Finding:** Hardcoded credential string passed to an LLM client constructor (OpenAI, Anthropic, Cohere, Mistral, Together, Groq, HuggingFace, Google generative AI, AWS Bedrock). Secrets in source code are CWE-798 (Use of Hard-coded Credentials) — they end up in git history, container images, and CI logs. Use environment variables, a secrets manager (AWS Secrets Manager, HashiCorp Vault, Azure Key Vault), or the SDK's default credential resolver instead.
**Copilot verdict:** ✅ Confirmed real
**Copilot reasoning:** client = OpenAI(api_key="sk-proj-DEMO...") — literal API key passed to constructor, no env-var indirection, no secrets manager. Real credential exposure if config.py ships.

**Fix:** Move the credential out of source. Options, ranked by safety: (1) the SDK's default credential resolver — for OpenAI / Anthropic / Cohere / Mistral, omit `api_key=` and the SDK reads the standard env var (OPENAI_API_KEY, ANTHROPIC_API_KEY, etc.); for boto3, omit aws_access_key_id and let the default chain (IAM role, instance profile, env, ~/.aws/credentials) resolve. (2) A secrets manager looked up at startup (AWS Secrets Manager, HashiCorp Vault, Azure Key Vault) — `api_key=secrets.get_secret_value(...)["SecretString"]`. (3) Environment variable read explicitly — `api_key=os.environ["OPENAI_API_KEY"]`. Rotate any credential that has been committed to git (it must be treated as compromised — git history exposes it forever even if you delete it from HEAD).

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `hardcoded-llm-credentials` no longer fires for `testbed/demo-agent/config.py`._
---

### [2/15] 🟥 CRITICAL · `llm-output-to-code-execution` · [Semgrep]

**Location:** `testbed/demo-agent/tools.py` · line 21
**Finding:** Output from an LLM call flows into a dangerous code-execution sink (eval / exec / os.system / subprocess with shell=True). LLM output is attacker-controllable via prompt injection — feeding it to a code executor is arbitrary code execution on the host. OWASP LLM05 Improper Output Handling, OWASP Agentic T11.
**Copilot verdict:** ✅ Confirmed real
**Copilot reasoning:** tools.py:21 calls eval(code) where code = response.choices[0].message.content (line 19) — LLM output is fed directly into Python's eval() with no validation, AST allowlist, or sandbox. Direct RCE primitive.

**Fix:** Never pass raw LLM output to eval / exec / os.system or shell=True subprocess. If you must execute generated code, run it in an isolated sandbox (Docker, Firecracker, gVisor, SessionsPythonREPLTool, restricted-python) with no host access. For shell commands, parse with shlex.split and pass argv to subprocess without shell=True. For arithmetic / config evaluation, prefer ast.literal_eval. For SQL, use parameterized queries — never format LLM output into a query string.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `llm-output-to-code-execution` no longer fires for `testbed/demo-agent/tools.py`._
---

### [3/15] 🟧 HIGH · `ast06-credential-in-bundle` · [Semgrep]

**Location:** `config.yaml` · line 17
**Finding:** Anthropic API key hard-coded in skill-bundle file `config.yaml`. Skill bundles ship verbatim to every consumer — anyone who can read the bundle (registry, cache, developer clone) reads the secret. AST06 — Secrets in Skill Bundles. Move to a secrets manager or runtime-injected env var; never ship secrets inside the bundle itself.
**Copilot verdict:** ✅ Confirmed real
**Copilot reasoning:** Literal Anthropic API key sk-ant-api03-AbCdEf... hard-coded in the bundled YAML. Ships verbatim to every consumer (registry pulls, git clones, container images, CI logs).

**Fix:** Move secrets to a secrets manager (AWS Secrets Manager, HashiCorp Vault, Azure Key Vault) and reference them by name from the manifest. If runtime injection isn't an option, at minimum keep credentials in a separate file outside the bundle and load them via environment variable.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `ast06-credential-in-bundle` no longer fires for `config.yaml`._
---

### [4/15] 🟧 HIGH · `ast06-credential-in-bundle` · [Semgrep]

**Location:** `config.yaml` · line 21
**Finding:** OpenAI project key hard-coded in skill-bundle file `config.yaml`. Skill bundles ship verbatim to every consumer — anyone who can read the bundle (registry, cache, developer clone) reads the secret. AST06 — Secrets in Skill Bundles. Move to a secrets manager or runtime-injected env var; never ship secrets inside the bundle itself.
**Copilot verdict:** ✅ Confirmed real
**Copilot reasoning:** Literal OpenAI API key sk-proj-AbCdEf... hard-coded in the bundled YAML. Same shipping path as line 17.

**Fix:** Move secrets to a secrets manager (AWS Secrets Manager, HashiCorp Vault, Azure Key Vault) and reference them by name from the manifest. If runtime injection isn't an option, at minimum keep credentials in a separate file outside the bundle and load them via environment variable.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `ast06-credential-in-bundle` no longer fires for `config.yaml`._
---

### [5/15] 🟧 HIGH · `ast06-credential-in-bundle` · [Semgrep]

**Location:** `config.yaml` · line 25
**Finding:** AWS access-key ID hard-coded in skill-bundle file `config.yaml`. Skill bundles ship verbatim to every consumer — anyone who can read the bundle (registry, cache, developer clone) reads the secret. AST06 — Secrets in Skill Bundles. Move to a secrets manager or runtime-injected env var; never ship secrets inside the bundle itself.
**Copilot verdict:** ✅ Confirmed real
**Copilot reasoning:** Literal AWS access_key_id AKIAIOSFODNN7EXAMPLE hard-coded in the bundled YAML. The rule correctly flags the shape — production credentials with the same pattern leak the same way.

**Fix:** Move secrets to a secrets manager (AWS Secrets Manager, HashiCorp Vault, Azure Key Vault) and reference them by name from the manifest. If runtime injection isn't an option, at minimum keep credentials in a separate file outside the bundle and load them via environment variable.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `ast06-credential-in-bundle` no longer fires for `config.yaml`._
---

### [6/15] 🟧 HIGH · `ast06-credential-in-bundle` · [Semgrep]

**Location:** `config.yaml` · line 29
**Finding:** Generic credential assignment hard-coded in skill-bundle file `config.yaml`. Skill bundles ship verbatim to every consumer — anyone who can read the bundle (registry, cache, developer clone) reads the secret. AST06 — Secrets in Skill Bundles. Move to a secrets manager or runtime-injected env var; never ship secrets inside the bundle itself.
**Copilot verdict:** ✅ Confirmed real
**Copilot reasoning:** Literal database password support_db_password: 2v8XyZ4qPmA9rT6wKn3eRfBhJ5sLcGdU hard-coded in the bundled YAML.

**Fix:** Move secrets to a secrets manager (AWS Secrets Manager, HashiCorp Vault, Azure Key Vault) and reference them by name from the manifest. If runtime injection isn't an option, at minimum keep credentials in a separate file outside the bundle and load them via environment variable.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `ast06-credential-in-bundle` no longer fires for `config.yaml`._
---

### [7/15] 🟧 HIGH · `ast06-credential-in-bundle` · [Semgrep]

**Location:** `config.yaml` · line 30
**Finding:** Slack token hard-coded in skill-bundle file `config.yaml`. Skill bundles ship verbatim to every consumer — anyone who can read the bundle (registry, cache, developer clone) reads the secret. AST06 — Secrets in Skill Bundles. Move to a secrets manager or runtime-injected env var; never ship secrets inside the bundle itself.
**Copilot verdict:** ✅ Confirmed real
**Copilot reasoning:** Literal Slack bot token xoxb-1234567890123-... hard-coded in the bundled YAML. Slack tokens grant write access to channels — exfil pivot if leaked.

**Fix:** Move secrets to a secrets manager (AWS Secrets Manager, HashiCorp Vault, Azure Key Vault) and reference them by name from the manifest. If runtime injection isn't an option, at minimum keep credentials in a separate file outside the bundle and load them via environment variable.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `ast06-credential-in-bundle` no longer fires for `config.yaml`._
---

### [8/15] 🟧 HIGH · `unsanitized-user-input-to-llm` · [Semgrep]

**Location:** `testbed/demo-agent/controller.py` · line 26
**Finding:** User input from an HTTP request flows directly into an LLM/agent/chain/retriever invocation without passing through a known guardrail or sanitization layer. This is the canonical prompt-injection surface (OWASP LLM01).
**Copilot verdict:** ✅ Confirmed real
**Copilot reasoning:** request.json['message'] flows directly into chain.invoke(user_message) at controller.py:21 with no sanitiser between them — classic untrusted-input-to-LLM sink.

**Fix:** Wrap LLM calls with an input guardrail (NeMo Guardrails, Lakera Guard, Rebuff, Llama Guard, or an equivalent). Validate and sanitize user input before it reaches the prompt template. Use structured prompting that strictly delimits user content from instructions.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `unsanitized-user-input-to-llm` no longer fires for `testbed/demo-agent/controller.py`._
---

### [9/15] 🟧 HIGH · `unsanitized-user-input-to-llm` · [Semgrep]

**Location:** `testbed/demo-agent/controller.py` · line 39
**Finding:** User input from an HTTP request flows directly into an LLM/agent/chain/retriever invocation without passing through a known guardrail or sanitization layer. This is the canonical prompt-injection surface (OWASP LLM01).
**Copilot verdict:** ✅ Confirmed real
**Copilot reasoning:** User-controlled article_url (request.json.get('url', '')) is fetched by WebBaseLoader and its content flows into chain.invoke() — indirect prompt-injection sink via the retrieved document body.

**Fix:** Wrap LLM calls with an input guardrail (NeMo Guardrails, Lakera Guard, Rebuff, Llama Guard, or an equivalent). Validate and sanitize user input before it reaches the prompt template. Use structured prompting that strictly delimits user content from instructions.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `unsanitized-user-input-to-llm` no longer fires for `testbed/demo-agent/controller.py`._
---

### [10/15] 🟧 HIGH · `agent-communication-poisoning` · [Semgrep]

**Location:** `testbed/demo-agent/orchestrator.py` · line 63
**Finding:** User-controlled input is forwarded verbatim to another agent's HTTP endpoint without sanitisation or trust-boundary enforcement. The downstream agent receives the attacker's payload as if it came from a trusted internal caller — the upstream agent's authority is laundered onto the downstream call (OWASP Agentic T12 — Agent Communication Poisoning). Pair this rule with the behaviour emulator (Phase 2) to verify the downstream agent actually accepts and acts on the forwarded payload.
**Copilot verdict:** ✅ Confirmed real
**Copilot reasoning:** delegate() at orchestrator.py:63 forwards raw user_input verbatim to DOWNSTREAM_AGENT_URL with no sanitiser. The comment block at lines 54-61 explicitly documents the T12 Agent Communication Poisoning pattern — exactly the trust-boundary failure this rule catches.

**Fix:** Sanitise or structurally validate inter-agent payloads before forwarding. Strip instruction-shaped content from the user message (e.g. via a guardrail) before placing it in the downstream request body. Authenticate the downstream call with a signed token that binds the request to a specific user identity, so the downstream agent can apply per-user policy instead of trusting the upstream agent unconditionally.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `agent-communication-poisoning` no longer fires for `testbed/demo-agent/orchestrator.py`._
---

### [11/15] 🟧 HIGH · `unsanitized-user-input-to-llm` · [Semgrep]

**Location:** `testbed/demo-agent/orchestrator.py` · line 87
**Finding:** User input from an HTTP request flows directly into an LLM/agent/chain/retriever invocation without passing through a known guardrail or sanitization layer. This is the canonical prompt-injection surface (OWASP LLM01).
**Copilot verdict:** ✅ Confirmed real
**Copilot reasoning:** peer_message (request.json.get('message', '')) flows directly into chain.invoke({'input': peer_message}) at line 87 with no sanitiser. Untrusted-input-to-LLM holds regardless of whether the input is user-typed or peer-supplied.

**Fix:** Wrap LLM calls with an input guardrail (NeMo Guardrails, Lakera Guard, Rebuff, Llama Guard, or an equivalent). Validate and sanitize user input before it reaches the prompt template. Use structured prompting that strictly delimits user content from instructions.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `unsanitized-user-input-to-llm` no longer fires for `testbed/demo-agent/orchestrator.py`._
---

### [12/15] 🟧 HIGH · `unvalidated-peer-agent-input` · [Semgrep]

**Location:** `testbed/demo-agent/orchestrator.py` · line 87
**Finding:** Handler accepts a request claiming to come from a trusted internal agent (via a header signal like X-Internal-Caller / X-Agent-Source) and forwards the payload to an LLM without per-call authentication or input validation. Any peer on the internal network that can set the header is implicitly trusted — there is no cryptographic proof the caller is the agent it claims to be (OWASP Agentic T13 — Rogue Agents in Multi-Agent Systems). Pair with the behaviour emulator (Phase 2) to confirm the LLM acts on attacker-controlled "peer" input.
**Copilot verdict:** ✅ Confirmed real
**Copilot reasoning:** receive_from_peer() trusts the X-Internal-Caller header as proof of peer identity (lines 82-83) with no signature, JWT, or mTLS verification — anyone on the internal network can set the header. Payload then flows to chain.invoke at line 87. Textbook T13 Rogue Agents pattern.

**Fix:** Require cryptographic proof that the caller is the agent it claims to be — a short-lived signed token (JWT with mTLS-anchored claims or a peer-key HMAC) carried per request, not a static header. Treat peer input the same way you treat user input: route through a guardrail and a structural validator before it reaches the LLM prompt. Log the verified caller identity on every invocation so a rogue agent's traffic is attributable later.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `unvalidated-peer-agent-input` no longer fires for `testbed/demo-agent/orchestrator.py`._
---

### [13/15] 🟧 HIGH · `unsanitized-user-input-to-llm` · [Semgrep]

**Location:** `testbed/demo-agent/orchestrator.py` · line 110
**Finding:** User input from an HTTP request flows directly into an LLM/agent/chain/retriever invocation without passing through a known guardrail or sanitization layer. This is the canonical prompt-injection surface (OWASP LLM01).
**Copilot verdict:** ✅ Confirmed real
**Copilot reasoning:** debug_endpoint() reads user_input from request.json and feeds it to chain.invoke({'input': user_input}) at line 110 with no sanitiser. The accompanying TIER2-LLM07-02 system-prompt leak at line 118 amplifies the impact of any injection.

**Fix:** Wrap LLM calls with an input guardrail (NeMo Guardrails, Lakera Guard, Rebuff, Llama Guard, or an equivalent). Validate and sanitize user input before it reaches the prompt template. Use structured prompting that strictly delimits user content from instructions.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `unsanitized-user-input-to-llm` no longer fires for `testbed/demo-agent/orchestrator.py`._
---

### [14/15] 🟧 HIGH · `unvalidated-peer-agent-input` · [Semgrep]

**Location:** `testbed/demo-agent/orchestrator.py` · line 110
**Finding:** Handler accepts a request claiming to come from a trusted internal agent (via a header signal like X-Internal-Caller / X-Agent-Source) and forwards the payload to an LLM without per-call authentication or input validation. Any peer on the internal network that can set the header is implicitly trusted — there is no cryptographic proof the caller is the agent it claims to be (OWASP Agentic T13 — Rogue Agents in Multi-Agent Systems). Pair with the behaviour emulator (Phase 2) to confirm the LLM acts on attacker-controlled "peer" input.
**Copilot verdict:** ⚠ Context-dependent
**Copilot reasoning:** debug_endpoint() does not consult X-Internal-Caller — input is direct user HTTP, not a peer-agent surface, so the peer-agent rule misfires on the trust pattern. However, the endpoint is entirely unauthenticated (TIER2-LLM09-02), meaning any external caller can reach it and trigger the system-prompt leak at line 118. The code is risky even though the specific peer-agent pattern does not apply; TIER2-LLM09-02 is the correct finding here.

**Fix:** Require cryptographic proof that the caller is the agent it claims to be — a short-lived signed token (JWT with mTLS-anchored claims or a peer-key HMAC) carried per request, not a static header. Treat peer input the same way you treat user input: route through a guardrail and a structural validator before it reaches the LLM prompt. Log the verified caller identity on every invocation so a rogue agent's traffic is attributable later.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `unvalidated-peer-agent-input` no longer fires for `testbed/demo-agent/orchestrator.py`._
---

### [15/15] 🟧 HIGH · `system-prompt-leak-via-tool-output` · [Semgrep]

**Location:** `testbed/demo-agent/orchestrator.py` · line 116
**Finding:** A code path exposes the agent's system prompt (or any variable named like a prompt template) in a user-reachable response — typically an error handler that includes the active prompt for "debugging". The prompt itself often carries secrets (escalation keys, internal IDs, tool descriptions) and is by definition meant to stay opaque to the user. Pair with the behaviour emulator (Phase 2) to confirm the model accepts the extraction request (MITRE ATLAS AML.T0056 — System Prompt Disclosure; OWASP LLM07 — System Prompt Leakage).
**Copilot verdict:** ✅ Confirmed real
**Copilot reasoning:** Exception handler at line 116 returns `active_system_prompt: SYSTEM_PROMPT` directly in the JSON response. SYSTEM_PROMPT (lines 91-95) contains the embedded key SK-OPS-7741-PRIVATE — both the system prompt and the secret leak to anyone who triggers an exception. Confirmed by TIER2-LLM07-02.

**Fix:** Never include the system prompt in user-visible responses or logs. Redact prompt-shaped variables from error responses (return a generic error code, log the prompt separately to a non-user- reachable destination). If you must surface debugging context to operators, gate it behind authenticated /admin routes and never on the user-facing endpoint. Treat the system prompt as a secret: rotate the embedded keys if it has ever leaked.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `system-prompt-leak-via-tool-output` no longer fires for `testbed/demo-agent/orchestrator.py`._

---

_Generated by AgentShield · Re-run `agentshield merge <path>` after fixes to get a fresh copy of this guide with only remaining findings._
