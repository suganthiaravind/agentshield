# AgentShield Pre-Production Review Report

_Rules-engine Static Scan + Copilot LLM-as-a-Judge Scan · scanned 2026-05-25T17:40:00Z_

---

## Detect / Defend / Respond

AgentShield's organising spine. Every finding belongs to exactly one category.

| **🔴 Detect** _vulnerability surfaces_ | **🟡 Defend** _missing controls_ | **🔵 Respond** _observability gaps_ |
|---|---|---|
| **33 findings**<br>🟥 CRITICAL &times; 5<br>🟧 HIGH &times; 19<br>🟨 MEDIUM &times; 3<br>🟦 INFO &times; 6 | **4 findings**<br>🟥 CRITICAL &times; 2<br>🟧 HIGH &times; 1<br>🟨 MEDIUM &times; 1 | **3 findings**<br>🟥 CRITICAL &times; 1<br>🟧 HIGH &times; 1<br>🟨 MEDIUM &times; 1 |

## Summary

| Metric | Count |
|---|---|
| Rules-engine Static Scan findings | 28 |
| Copilot LLM-as-a-Judge Scan net-new findings | 6 |
| Semgrep findings marked True Positive by Copilot | 24 |
| Semgrep findings marked Context-Dependent by Copilot | 1 |
| Semgrep findings marked False Positive by Copilot | 3 |
| **Net actionable** | **40** |

## JPMC SAIGE Agent Tier classification

**Classified as:** Agentic Tier 2

**Rationale:**

> Autonomous LLM-driven control flow at controller.py:21 (chain.invoke with user-supplied input) and at tools.py:14 (LLM output drives a Python eval branch). State-changing operations confirmed at notifications.py:24 (sns.publish — outbound notification) and tools.py:32 (POST to billing-api cancel endpoint — modifies subscription state). All targets are internal services (internal-pg.local, billing-api.internal, support-replies SNS topic). No customer-facing endpoint reached directly. Classified Tier 2 because state changes are internal-only; would be Tier 3 if the SNS topic delivered to customer email.

_Informational only — AgentShield does not filter or prioritise findings based on this classification. See [research.md §5](./research.md#5-jpmc-saige-agent-tier-classification) for the category definitions._

## 🔴 Detect — vulnerability surfaces  (33 findings)

_Where the agent is exploitable._

### **[Copilot]** 🟥 CRITICAL `emulator-direct-prompt-injection`

- **Location:** `(behaviour emulator — pipeline trace):?`
- **Message:** Direct prompt injection (T6 / LLM01)
- **Frameworks:** OWASP LLM LLM01, LLM07 · OWASP Agentic T6 · MITRE ATLAS AML.T0051, AML.T0056 · CWE CWE-200
- **Remediation:** Layer three controls: (1) input sanitiser at the user-prompt step that strips or flags instruction-override patterns; (2) anti-injection language in the system prompt instructing the planner to refuse meta-instructions from user content; (3) output filter at the final-answer step that scrubs system-prompt content and embedded secrets before emission.

### **[Copilot]** 🟥 CRITICAL `emulator-indirect-prompt-injection`

- **Location:** `(behaviour emulator — pipeline trace):?`
- **Message:** Indirect prompt injection via retrieved doc (LLM01 indirect)
- **Frameworks:** OWASP LLM LLM01 · OWASP Agentic T6 · MITRE ATLAS AML.T0051 · CWE CWE-79
- **Remediation:** Treat retrieved content (RAG, document loaders, vector search hits, memory recall) as untrusted input. Sanitise or content-classify before it reaches the planner; mark retrieved text as data-not-instruction in the prompt envelope; reject documents that fail a provenance check.

### **[Copilot]** 🟥 CRITICAL `emulator-system-prompt-extraction`

- **Location:** `(behaviour emulator — pipeline trace):?`
- **Message:** System prompt extraction (LLM07 / AML.T0056)
- **Frameworks:** OWASP LLM LLM07 · OWASP Agentic T6 · MITRE ATLAS AML.T0056 · CWE CWE-200
- **Remediation:** Never place the system prompt verbatim in any response payload — including error paths, debug endpoints, or audit messages. Filter system-prompt content out of the final-answer step with an explicit regex / classifier. Test the error path specifically; it's the most common leak channel.

### **[Semgrep]** 🟥 CRITICAL `hardcoded-llm-credentials`  ·  Copilot verdict: ✅ TP

- **Location:** `testbed/demo-agent/config.py:7`
- **Message:** Hardcoded credential string passed to an LLM client constructor (OpenAI, Anthropic, Cohere, Mistral, Together, Groq, HuggingFace, Google generative AI, AWS Bedrock). Secrets in source code are CWE-798 (Use of Hard-coded Credentials) — they end up in git history, container images, and CI logs. Use environment variables, a secrets manager (AWS Secrets Manager, HashiCorp Vault, Azure Key Vault), or the SDK's default credential resolver instead.
- **Frameworks:** OWASP LLM LLM02 · MITRE ATLAS AML.T0055 · CWE CWE-798
- **Remediation:** Move the credential out of source. Options, ranked by safety: (1) the SDK's default credential resolver — for OpenAI / Anthropic / Cohere / Mistral, omit `api_key=` and the SDK reads the standard env var (OPENAI_API_KEY, ANTHROPIC_API_KEY, etc.); for boto3, omit aws_access_key_id and let the default chain (IAM role, instance profile, env, ~/.aws/credentials) resolve. (2) A secrets manager looked up at startup (AWS Secrets Manager, HashiCorp Vault, Azure Key Vault) — `api_key=secrets.get_secret_value(...)["SecretString"]`. (3) Environment variable read explicitly — `api_key=os.environ["OPENAI_API_KEY"]`. Rotate any credential that has been committed to git (it must be treated as compromised — git history exposes it forever even if you delete it from HEAD).
- **Copilot reasoning:** client = OpenAI(api_key="sk-proj-DEMO...") — literal API key passed to constructor, no env-var indirection, no secrets manager. Real credential exposure if config.py ever ships.

### **[Semgrep]** 🟥 CRITICAL `llm-output-to-code-execution`  ·  Copilot verdict: ✅ TP

- **Location:** `testbed/demo-agent/tools.py:21`
- **Message:** Output from an LLM call flows into a dangerous code-execution sink (eval / exec / os.system / subprocess with shell=True). LLM output is attacker-controllable via prompt injection — feeding it to a code executor is arbitrary code execution on the host. OWASP LLM05 Improper Output Handling, OWASP Agentic T11.
- **Frameworks:** OWASP LLM LLM05 · OWASP Agentic T11 · MITRE ATLAS AML.T0050 · CWE CWE-94
- **Remediation:** Never pass raw LLM output to eval / exec / os.system or shell=True subprocess. If you must execute generated code, run it in an isolated sandbox (Docker, Firecracker, gVisor, SessionsPythonREPLTool, restricted-python) with no host access. For shell commands, parse with shlex.split and pass argv to subprocess without shell=True. For arithmetic / config evaluation, prefer ast.literal_eval. For SQL, use parameterized queries — never format LLM output into a query string.
- **Copilot reasoning:** tools.py:21 calls eval(code) where code = response.choices[0].message.content (line 19) — LLM output is fed directly into Python's eval() with no validation, no AST allowlist, no sandbox. Direct RCE primitive.

### **[Copilot]** 🟧 HIGH `emulator-tool-argument-injection`

- **Location:** `(behaviour emulator — pipeline trace):?`
- **Message:** Tool argument injection (Agentic T2 / CWE-78 / CWE-89)
- **Frameworks:** OWASP LLM LLM05 · OWASP Agentic T2 · MITRE ATLAS AML.T0050 · CWE CWE-78, CWE-89, CWE-22
- **Remediation:** Validate every tool argument against an allow-list / regex / schema before it reaches a shell, SQL query, HTTP URL, or filesystem path. Use parameterised queries for SQL, list-form subprocess invocation (never shell=True with interpolated strings), and structured URL builders that reject path traversal. Treat the LLM as an untrusted source for tool-argument content.

### **[Copilot]** 🟧 HIGH `emulator-insecure-output-handling`

- **Location:** `(behaviour emulator — pipeline trace):?`
- **Message:** Insecure output handling (LLM05)
- **Frameworks:** OWASP LLM LLM05, LLM02 · OWASP Agentic T6 · MITRE ATLAS AML.T0050 · CWE CWE-94, CWE-95
- **Remediation:** Never feed LLM output (or tool output derived from LLM output) into eval(), exec(), subprocess with shell=True, or an unescaped template render. Sanitise / validate at the consumer boundary: parse with ast.literal_eval for expressions, escape for HTML/SQL contexts, and require a strict schema for any downstream call. LLM output is untrusted user content, not code.

### **[Copilot]** 🟧 HIGH `emulator-partial-defense-bypass`

- **Location:** `(behaviour emulator — pipeline trace):?`
- **Message:** Partial-defence bypass — layered controls evaded (LLM01 / T6)
- **Frameworks:** OWASP LLM LLM01, LLM07 · OWASP Agentic T6 · MITRE ATLAS AML.T0051, AML.T0056 · CWE CWE-200
- **Remediation:** A keyword deny-list and a natural-language 'never reveal' instruction are both bypassable with indirect, role-play, or obfuscated payloads. Close the loop with a third control at the output boundary: an LLM-as-judge or regex classifier that scans the final-answer content before emission, so that a payload defeating the input and planner layers still cannot exfiltrate protected content through the response.

### **[Semgrep]** 🟧 HIGH `ast03-network-unrestricted`  ·  Copilot verdict: ✅ TP

- **Location:** `SKILL.md:1`
- **Message:** Skill declares unrestricted network egress (`network: true`). AST03 — should be a domain allowlist (`network.allow: [api.example.com]`) with default-deny.
- **Frameworks:** OWASP LLM LLM06 · OWASP Agentic T2, T3 · CWE CWE-732, CWE-918 · OWASP AST10 AST03
- **Remediation:** Use a domain allowlist with default-deny: `network.allow: [api.example.com]`.
- **Copilot reasoning:** Frontmatter declares `permissions.network: true` with no `network.allow:` allow-list — unrestricted outbound network access. AST03 correctly fires.

### **[Semgrep]** 🟧 HIGH `ast08-permission-combo-across-skills`  ·  Copilot verdict: ✅ TP

- **Location:** `SKILL.md:1`
- **Message:** Two skills loaded together grant a dangerous permission combination that neither holds alone. /Users/suganthichandrasekaran/AgentShield/testbed/demo-agent/SKILL.md contributes ['network_egress'], /Users/suganthichandrasekaran/AgentShield/testbed/demo-agent/skills/billing/SKILL.md contributes ['shell']. Shell access paired with network egress turns the agent into a general-purpose attack tool — exec anything, send results out. AST08 — Permission Bleed.
- **Frameworks:** OWASP LLM LLM06 · OWASP Agentic T2, T6 · CWE CWE-269 · OWASP AST10 AST08
- **Remediation:** Audit the cross-skill permission set. Either tighten each skill's grant so the dangerous combo no longer materialises (e.g. remove network from the skill that doesn't need it), or isolate the skills into separate runtime contexts so a compromise of one can't leverage the other's privileges. Document the intentional combo in the manifest if it's load-bearing — silent privilege bleed is the failure mode.
- **Copilot reasoning:** Combined permissions across the two manifests: demo-agent-helper grants `network: true` + filesystem read/write; billing grants `shell: true`. The compound (network egress + shell exec + filesystem write) is the RCE-to-exfil pair AST08 watches for — neither skill on its own grants the dangerous combo, but together they do.

### **[Semgrep]** 🟧 HIGH `ast08-permission-combo-across-skills`  ·  Copilot verdict: ✅ TP

- **Location:** `SKILL.md:1`
- **Message:** Two skills loaded together grant a dangerous permission combination that neither holds alone. /Users/suganthichandrasekaran/AgentShield/testbed/demo-agent/SKILL.md contributes ['files_write'], /Users/suganthichandrasekaran/AgentShield/testbed/demo-agent/skills/billing/SKILL.md contributes ['shell']. Shell access paired with file write means the agent can drop arbitrary scripts onto the host and run them. AST08 — Permission Bleed.
- **Frameworks:** OWASP LLM LLM06 · OWASP Agentic T2, T6 · CWE CWE-269 · OWASP AST10 AST08
- **Remediation:** Audit the cross-skill permission set. Either tighten each skill's grant so the dangerous combo no longer materialises (e.g. remove network from the skill that doesn't need it), or isolate the skills into separate runtime contexts so a compromise of one can't leverage the other's privileges. Document the intentional combo in the manifest if it's load-bearing — silent privilege bleed is the failure mode.
- **Copilot reasoning:** Second emission of the same cross-skill combo, reported from the billing-side perspective. Both reports describe the same compound permission; either fix (drop network from the helper OR drop shell from billing OR split the skills across separate agents) resolves both.

### **[Semgrep]** 🟧 HIGH `ast06-credential-in-bundle`  ·  Copilot verdict: ✅ TP

- **Location:** `config.yaml:17`
- **Message:** Anthropic API key hard-coded in skill-bundle file `config.yaml`. Skill bundles ship verbatim to every consumer — anyone who can read the bundle (registry, cache, developer clone) reads the secret. AST06 — Secrets in Skill Bundles. Move to a secrets manager or runtime-injected env var; never ship secrets inside the bundle itself.
- **Frameworks:** OWASP LLM LLM06 · OWASP Agentic T2 · CWE CWE-798 · OWASP AST10 AST06
- **Remediation:** Move secrets to a secrets manager (AWS Secrets Manager, HashiCorp Vault, Azure Key Vault) and reference them by name from the manifest. If runtime injection isn't an option, at minimum keep credentials in a separate file outside the bundle and load them via environment variable.
- **Copilot reasoning:** Literal Anthropic API key `sk-ant-api03-AbCdEf...` hard-coded in the bundled YAML. Ships verbatim to every consumer of the bundle (registry pulls, git clones, container images, CI logs). Rotation is forever — bundle history exposes it.

### **[Semgrep]** 🟧 HIGH `ast06-credential-in-bundle`  ·  Copilot verdict: ✅ TP

- **Location:** `config.yaml:21`
- **Message:** OpenAI project key hard-coded in skill-bundle file `config.yaml`. Skill bundles ship verbatim to every consumer — anyone who can read the bundle (registry, cache, developer clone) reads the secret. AST06 — Secrets in Skill Bundles. Move to a secrets manager or runtime-injected env var; never ship secrets inside the bundle itself.
- **Frameworks:** OWASP LLM LLM06 · OWASP Agentic T2 · CWE CWE-798 · OWASP AST10 AST06
- **Remediation:** Move secrets to a secrets manager (AWS Secrets Manager, HashiCorp Vault, Azure Key Vault) and reference them by name from the manifest. If runtime injection isn't an option, at minimum keep credentials in a separate file outside the bundle and load them via environment variable.
- **Copilot reasoning:** Literal OpenAI API key `sk-proj-AbCdEf...` hard-coded in the bundled YAML. Same shipping path as line 17.

### **[Semgrep]** 🟧 HIGH `ast06-credential-in-bundle`  ·  Copilot verdict: ✅ TP

- **Location:** `config.yaml:25`
- **Message:** AWS access-key ID hard-coded in skill-bundle file `config.yaml`. Skill bundles ship verbatim to every consumer — anyone who can read the bundle (registry, cache, developer clone) reads the secret. AST06 — Secrets in Skill Bundles. Move to a secrets manager or runtime-injected env var; never ship secrets inside the bundle itself.
- **Frameworks:** OWASP LLM LLM06 · OWASP Agentic T2 · CWE CWE-798 · OWASP AST10 AST06
- **Remediation:** Move secrets to a secrets manager (AWS Secrets Manager, HashiCorp Vault, Azure Key Vault) and reference them by name from the manifest. If runtime injection isn't an option, at minimum keep credentials in a separate file outside the bundle and load them via environment variable.
- **Copilot reasoning:** Literal AWS access_key_id `AKIAIOSFODNN7EXAMPLE` hard-coded in the bundled YAML. Even if this is the AWS documentation example key, the rule correctly flags the pattern — production credentials matching the same shape leak the same way.

### **[Semgrep]** 🟧 HIGH `ast06-credential-in-bundle`  ·  Copilot verdict: ✅ TP

- **Location:** `config.yaml:29`
- **Message:** Generic credential assignment hard-coded in skill-bundle file `config.yaml`. Skill bundles ship verbatim to every consumer — anyone who can read the bundle (registry, cache, developer clone) reads the secret. AST06 — Secrets in Skill Bundles. Move to a secrets manager or runtime-injected env var; never ship secrets inside the bundle itself.
- **Frameworks:** OWASP LLM LLM06 · OWASP Agentic T2 · CWE CWE-798 · OWASP AST10 AST06
- **Remediation:** Move secrets to a secrets manager (AWS Secrets Manager, HashiCorp Vault, Azure Key Vault) and reference them by name from the manifest. If runtime injection isn't an option, at minimum keep credentials in a separate file outside the bundle and load them via environment variable.
- **Copilot reasoning:** Literal database password `support_db_password: 2v8XyZ4qPmA9rT6wKn3eRfBhJ5sLcGdU` hard-coded in the bundled YAML.

### **[Semgrep]** 🟧 HIGH `ast06-credential-in-bundle`  ·  Copilot verdict: ✅ TP

- **Location:** `config.yaml:30`
- **Message:** Slack token hard-coded in skill-bundle file `config.yaml`. Skill bundles ship verbatim to every consumer — anyone who can read the bundle (registry, cache, developer clone) reads the secret. AST06 — Secrets in Skill Bundles. Move to a secrets manager or runtime-injected env var; never ship secrets inside the bundle itself.
- **Frameworks:** OWASP LLM LLM06 · OWASP Agentic T2 · CWE CWE-798 · OWASP AST10 AST06
- **Remediation:** Move secrets to a secrets manager (AWS Secrets Manager, HashiCorp Vault, Azure Key Vault) and reference them by name from the manifest. If runtime injection isn't an option, at minimum keep credentials in a separate file outside the bundle and load them via environment variable.
- **Copilot reasoning:** Literal Slack bot token `xoxb-1234567890123-...` hard-coded in the bundled YAML. Slack tokens grant write access to channels — exfil pivot if leaked.

### **[Semgrep]** 🟧 HIGH `unsanitized-user-input-to-llm`  ·  Copilot verdict: ✅ TP

- **Location:** `testbed/demo-agent/controller.py:26`
- **Message:** User input from an HTTP request flows directly into an LLM/agent/chain/retriever invocation without passing through a known guardrail or sanitization layer. This is the canonical prompt-injection surface (OWASP LLM01).
- **Frameworks:** OWASP LLM LLM01 · MITRE ATLAS AML.T0051
- **Remediation:** Wrap LLM calls with an input guardrail (NeMo Guardrails, Lakera Guard, Rebuff, Llama Guard, or an equivalent). Validate and sanitize user input before it reaches the prompt template. Use structured prompting that strictly delimits user content from instructions.
- **Copilot reasoning:** request.json['message'] flows directly into chain.invoke(user_message) at controller.py:21 with no sanitiser between them — classic untrusted-input-to-LLM sink.

### **[Copilot]** 🟧 HIGH `AS-C-D-LLM01-002`

- **Location:** `testbed/demo-agent/controller.py:30`
- **Message:** Untrusted document loader: article_url is user-supplied (from request body) and fetched without an allowlist. Indirect prompt-injection surface — attacker-controlled webpage content flows into the LLM via the summarise prompt.
- **Frameworks:** OWASP LLM LLM01 · OWASP Agentic T1, T6 · CWE CWE-94
- **Snippet:** `docs = WebBaseLoader(article_url).load()`
- **Remediation:** Validate article_url against an explicit hostname allowlist before fetching. Treat retrieved document content as untrusted user input — pass through a guardrail layer before the LLM call.

### **[Semgrep]** 🟧 HIGH `unsanitized-user-input-to-llm`  ·  Copilot verdict: ✅ TP

- **Location:** `testbed/demo-agent/controller.py:39`
- **Message:** User input from an HTTP request flows directly into an LLM/agent/chain/retriever invocation without passing through a known guardrail or sanitization layer. This is the canonical prompt-injection surface (OWASP LLM01).
- **Frameworks:** OWASP LLM LLM01 · MITRE ATLAS AML.T0051
- **Remediation:** Wrap LLM calls with an input guardrail (NeMo Guardrails, Lakera Guard, Rebuff, Llama Guard, or an equivalent). Validate and sanitize user input before it reaches the prompt template. Use structured prompting that strictly delimits user content from instructions.
- **Copilot reasoning:** User-controlled article_url (request.json.get('url', '')) is fetched by WebBaseLoader and its content flows into chain.invoke() at line 34 — indirect prompt-injection sink via the retrieved document body.

### **[Semgrep]** 🟧 HIGH `agent-communication-poisoning`  ·  Copilot verdict: ✅ TP

- **Location:** `testbed/demo-agent/orchestrator.py:63`
- **Message:** User-controlled input is forwarded verbatim to another agent's HTTP endpoint without sanitisation or trust-boundary enforcement. The downstream agent receives the attacker's payload as if it came from a trusted internal caller — the upstream agent's authority is laundered onto the downstream call (OWASP Agentic T12 — Agent Communication Poisoning). Pair this rule with the behaviour emulator (Phase 2) to verify the downstream agent actually accepts and acts on the forwarded payload.
- **Frameworks:** OWASP LLM LLM01 · OWASP Agentic T12 · MITRE ATLAS AML.T0051
- **Remediation:** Sanitise or structurally validate inter-agent payloads before forwarding. Strip instruction-shaped content from the user message (e.g. via a guardrail) before placing it in the downstream request body. Authenticate the downstream call with a signed token that binds the request to a specific user identity, so the downstream agent can apply per-user policy instead of trusting the upstream agent unconditionally.
- **Copilot reasoning:** delegate() at orchestrator.py:63 forwards raw user_input verbatim to DOWNSTREAM_AGENT_URL with no sanitiser. Comment block at lines 54-61 explicitly calls this out as the T12 Agent Communication Poisoning pattern — exactly the trust-boundary failure the rule catches.

### **[Semgrep]** 🟧 HIGH `unsanitized-user-input-to-llm`  ·  Copilot verdict: ✅ TP

- **Location:** `testbed/demo-agent/orchestrator.py:87`
- **Message:** User input from an HTTP request flows directly into an LLM/agent/chain/retriever invocation without passing through a known guardrail or sanitization layer. This is the canonical prompt-injection surface (OWASP LLM01).
- **Frameworks:** OWASP LLM LLM01 · MITRE ATLAS AML.T0051
- **Remediation:** Wrap LLM calls with an input guardrail (NeMo Guardrails, Lakera Guard, Rebuff, Llama Guard, or an equivalent). Validate and sanitize user input before it reaches the prompt template. Use structured prompting that strictly delimits user content from instructions.
- **Copilot reasoning:** peer_message (request.json.get('message', '')) flows directly into chain.invoke({'input': peer_message}) at line 87 with no sanitiser. Untrusted-input-to-LLM holds regardless of whether the input is user-typed or peer-supplied.

### **[Semgrep]** 🟧 HIGH `unvalidated-peer-agent-input`  ·  Copilot verdict: ✅ TP

- **Location:** `testbed/demo-agent/orchestrator.py:87`
- **Message:** Handler accepts a request claiming to come from a trusted internal agent (via a header signal like X-Internal-Caller / X-Agent-Source) and forwards the payload to an LLM without per-call authentication or input validation. Any peer on the internal network that can set the header is implicitly trusted — there is no cryptographic proof the caller is the agent it claims to be (OWASP Agentic T13 — Rogue Agents in Multi-Agent Systems). Pair with the behaviour emulator (Phase 2) to confirm the LLM acts on attacker-controlled "peer" input.
- **Frameworks:** OWASP LLM LLM01 · OWASP Agentic T13 · MITRE ATLAS AML.T0051 · CWE CWE-345
- **Remediation:** Require cryptographic proof that the caller is the agent it claims to be — a short-lived signed token (JWT with mTLS-anchored claims or a peer-key HMAC) carried per request, not a static header. Treat peer input the same way you treat user input: route through a guardrail and a structural validator before it reaches the LLM prompt. Log the verified caller identity on every invocation so a rogue agent's traffic is attributable later.
- **Copilot reasoning:** receive_from_peer() trusts the X-Internal-Caller header as proof of peer identity (lines 82-83) with no signature/JWT/mTLS verification — anyone on the internal network can set the header. Payload then flows to chain.invoke at line 87. Textbook T13 Rogue Agents pattern.

### **[Semgrep]** 🟧 HIGH `unsanitized-user-input-to-llm`  ·  Copilot verdict: ✅ TP

- **Location:** `testbed/demo-agent/orchestrator.py:110`
- **Message:** User input from an HTTP request flows directly into an LLM/agent/chain/retriever invocation without passing through a known guardrail or sanitization layer. This is the canonical prompt-injection surface (OWASP LLM01).
- **Frameworks:** OWASP LLM LLM01 · MITRE ATLAS AML.T0051
- **Remediation:** Wrap LLM calls with an input guardrail (NeMo Guardrails, Lakera Guard, Rebuff, Llama Guard, or an equivalent). Validate and sanitize user input before it reaches the prompt template. Use structured prompting that strictly delimits user content from instructions.
- **Copilot reasoning:** debug_endpoint() reads user_input from request.json and feeds it to chain.invoke({'input': user_input}) at line 110 — user-input-to-LLM with no sanitiser. The accompanying LLM07 leak at line 116 amplifies the impact.

### **[Semgrep]** 🟧 HIGH `system-prompt-leak-via-tool-output`  ·  Copilot verdict: ✅ TP

- **Location:** `testbed/demo-agent/orchestrator.py:116`
- **Message:** A code path exposes the agent's system prompt (or any variable named like a prompt template) in a user-reachable response — typically an error handler that includes the active prompt for "debugging". The prompt itself often carries secrets (escalation keys, internal IDs, tool descriptions) and is by definition meant to stay opaque to the user. Pair with the behaviour emulator (Phase 2) to confirm the model accepts the extraction request (MITRE ATLAS AML.T0056 — System Prompt Disclosure; OWASP LLM07 — System Prompt Leakage).
- **Frameworks:** OWASP LLM LLM07 · MITRE ATLAS AML.T0056 · CWE CWE-200
- **Remediation:** Never include the system prompt in user-visible responses or logs. Redact prompt-shaped variables from error responses (return a generic error code, log the prompt separately to a non-user- reachable destination). If you must surface debugging context to operators, gate it behind authenticated /admin routes and never on the user-facing endpoint. Treat the system prompt as a secret: rotate the embedded keys if it has ever leaked.
- **Copilot reasoning:** Exception handler at line 116 returns `active_system_prompt: SYSTEM_PROMPT` directly in the JSON response. SYSTEM_PROMPT (lines 91-95) contains the embedded escalation key SK-OPS-7741-PRIVATE — both the system prompt and the secret leak to anyone who can trigger an exception.

### **[Semgrep]** 🟨 MEDIUM `ast03-wildcard-file-read`  ·  Copilot verdict: ✅ TP

- **Location:** `SKILL.md:1`
- **Message:** Wildcard read permission on `~/.config/demo-agent/**`. AST03 — skill manifests must declare explicit paths; wildcards defeat least-privilege review.
- **Frameworks:** CWE CWE-732 · OWASP AST10 AST03
- **Remediation:** Declare explicit paths; no wildcards.
- **Copilot reasoning:** permissions.files.read pattern `~/.config/demo-agent/**` uses the recursive `**` glob — wildcard file-read access covering every file under the config directory. AST03 wildcard-read variant.

### **[Semgrep]** 🟨 MEDIUM `ast03-shell-access`  ·  Copilot verdict: ✅ TP

- **Location:** `skills/billing/SKILL.md:1`
- **Message:** Skill declares shell access (`shell: true`). AST03 — should only be granted when the skill's core function requires it; document why in the description.
- **Frameworks:** OWASP LLM LLM06 · OWASP Agentic T2 · CWE CWE-78 · OWASP AST10 AST03
- **Remediation:** Grant shell access only when the skill's core function requires it; document why in the description.
- **Copilot reasoning:** billing skill frontmatter declares `permissions.shell: true`. The skill calls subprocess.run on vetted billing scripts (line 29-30 prose), but the static permission grant is what AST03 catches — granting shell access is a coarse capability; even narrowed scripts can be attacked via arg injection.

### **[Copilot]** 🟨 MEDIUM `AS-C-D-AGENTIC_T1-001`

- **Location:** `testbed/demo-agent/memory.py:17`
- **Message:** Memory poisoning surface: both user input and raw LLM output are persisted to session memory without validation. Future turns retrieve this content as 'trusted context'; an attacker can plant instructions in turn N that influence turn N+1.
- **Frameworks:** OWASP Agentic T1
- **Snippet:** `memory.setdefault(session_id, []).append({"user": user_message, "assistant": llm_response})`
- **Remediation:** Validate memory writes the same way you'd validate database writes — schema-check or pass through a content moderation classifier on persistence.

### **[Semgrep]** 🟦 INFO `ast04-missing-author-identity`  ·  Copilot verdict: ✅ TP

- **Location:** `SKILL.md:1`
- **Message:** Skill manifest has no `author.identity` (DID / signing-key anchor). AST04 — without a verifiable identity anchor, registry consumers cannot detect impersonation or typosquats; this is the foothold the ClawHub fake-Google skill exploited.
- **Frameworks:** OWASP AST10 AST04
- **Remediation:** Add `author.identity: did:web:<your-domain>` and a `signing_key:` field.
- **Copilot reasoning:** Author block has only `name: Demo Co` — no DID, no signed handle, no public-key reference. Provenance is unverifiable; an attacker republishing the bundle as 'Demo Co' is indistinguishable from the legitimate publisher.

### **[Semgrep]** 🟦 INFO `ast07-missing-content-hash`  ·  Copilot verdict: ✅ TP

- **Location:** `SKILL.md:1`
- **Message:** SKILL.md frontmatter has no `content_hash` field. AST07 — Merkle-root verification at install time requires a SHA-256 over the canonical skill payload.
- **Frameworks:** CWE CWE-345 · OWASP AST10 AST07
- **Remediation:** Add `content_hash: sha256:<digest>` over the canonical skill payload.
- **Copilot reasoning:** Frontmatter declares no `content_hash` / `checksum` / `integrity` field — loader has no way to verify the bundle payload matches what the manifest describes. AST07 integrity gap.

### **[Semgrep]** 🟦 INFO `ast07-missing-signature`  ·  Copilot verdict: ✅ TP

- **Location:** `SKILL.md:1`
- **Message:** SKILL.md frontmatter has no `signature` field. AST07 — without an ed25519 signature the registry cannot verify the skill on update; ClawJacked-style update-drift attacks become viable.
- **Frameworks:** CWE CWE-345 · OWASP AST10 AST07
- **Remediation:** Sign the canonical skill payload with an ed25519 key and publish the signature in the manifest.
- **Copilot reasoning:** Frontmatter declares no `signature` field — bundle authenticity is unverifiable independent of integrity. Companion to the missing content_hash finding.

### **[Semgrep]** 🟦 INFO `ast04-missing-author-identity`  ·  Copilot verdict: 🟡 CD

- **Location:** `skills/billing/SKILL.md:1`
- **Message:** Skill manifest has no `author.identity` (DID / signing-key anchor). AST04 — without a verifiable identity anchor, registry consumers cannot detect impersonation or typosquats; this is the foothold the ClawHub fake-Google skill exploited.
- **Frameworks:** OWASP AST10 AST04
- **Remediation:** Add `author.identity: did:web:<your-domain>` and a `signing_key:` field.
- **Copilot reasoning:** Author block has `did: did:example:demo-team` — the `did:example:` method is documented as a non-production placeholder, not a real verifiable identity. The presence of a DID field is closer to compliance than the demo-agent-helper case (which has only `name`), but the placeholder method means provenance is still unverifiable. Mitigatable by switching to a real DID method (did:web, did:key) — hence CD rather than TP.

### **[Semgrep]** 🟦 INFO `ast07-missing-content-hash`  ·  Copilot verdict: ✅ TP

- **Location:** `skills/billing/SKILL.md:1`
- **Message:** SKILL.md frontmatter has no `content_hash` field. AST07 — Merkle-root verification at install time requires a SHA-256 over the canonical skill payload.
- **Frameworks:** CWE CWE-345 · OWASP AST10 AST07
- **Remediation:** Add `content_hash: sha256:<digest>` over the canonical skill payload.
- **Copilot reasoning:** billing skill frontmatter has no content_hash / checksum / integrity field — identical defect to the demo-agent-helper SKILL.md case.

### **[Semgrep]** 🟦 INFO `ast07-missing-signature`  ·  Copilot verdict: ✅ TP

- **Location:** `skills/billing/SKILL.md:1`
- **Message:** SKILL.md frontmatter has no `signature` field. AST07 — without an ed25519 signature the registry cannot verify the skill on update; ClawJacked-style update-drift attacks become viable.
- **Frameworks:** CWE CWE-345 · OWASP AST10 AST07
- **Remediation:** Sign the canonical skill payload with an ed25519 key and publish the signature in the manifest.
- **Copilot reasoning:** billing skill frontmatter has no signature field — identical defect to the demo-agent-helper SKILL.md case.

## 🟡 Defend — missing controls  (4 findings)

_What active defences are missing._

### **[Copilot]** 🟥 CRITICAL `emulator-excessive-agency`

- **Location:** `(behaviour emulator — pipeline trace):?`
- **Message:** Excessive agency / over-broad tool surface (LLM06 / Agentic T3)
- **Frameworks:** OWASP LLM LLM06 · OWASP Agentic T3, T9 · MITRE ATLAS AML.T0049 · CWE CWE-285
- **Remediation:** Minimise the tool surface — register only the tools the agent needs for the current workflow, not every tool the team has ever built. Mark destructive tools (cancel_, delete_, drop_, purge_, transfer_) as HITL-gated: they must require a separate confirmation step (out-of-band approval, signed-scope claim, or explicit user click) before the dispatcher executes. Never let a single LLM decision fire a destructive action without a second gate.

### **[Copilot]** 🟥 CRITICAL `emulator-authority-spoofing`

- **Location:** `(behaviour emulator — pipeline trace):?`
- **Message:** Authority spoofing (T9)
- **Frameworks:** OWASP LLM LLM06 · OWASP Agentic T9 · MITRE ATLAS AML.T0049 · CWE CWE-285
- **Remediation:** Bind tool-call authority to the request's signed identity (JWT / IAM principal) — never to a role the model claims in chat. Destructive tools (drop_table, delete_*, purge_*) must require a separate human-in-the-loop confirmation step regardless of any declared "admin mode". Reject every tool call whose required scope is not present in the authenticated principal's actual permissions.

### **[Copilot]** 🟧 HIGH `AS-C-DF-LLM06-001`

- **Location:** `testbed/demo-agent/tools.py:26`
- **Message:** Destructive tool registered without a human-in-the-loop approval gate. The `cancel_subscription` tool name starts with a destructive verb and the body POSTs to a billing API; the agent can invoke it autonomously if the planner decides to.
- **Frameworks:** OWASP LLM LLM06 · OWASP Agentic T2, T10
- **Snippet:** `@tool def cancel_subscription(customer_id: str)`
- **Remediation:** Wire a HumanApprovalCallbackHandler (LangChain) or LangGraph interrupt_before on this tool node. Require explicit confirmation before any subscription mutation.

### **[Copilot]** 🟨 MEDIUM `AS-C-DF-LLM10-001`

- **Location:** `testbed/demo-agent/controller.py:14`
- **Message:** ChatOpenAI client instantiated without explicit timeout or max_tokens cap. A slow or runaway model call has no upper bound — DoS / cost exposure.
- **Frameworks:** OWASP LLM LLM10 · OWASP Agentic T4 · CWE CWE-400
- **Snippet:** `chain = ChatOpenAI(model=MODEL, openai_api_key=client.api_key)`
- **Remediation:** Pass timeout=30 (or whatever per-call ceiling fits your latency budget) and max_tokens=2000 to the ChatOpenAI constructor.

## 🔵 Respond — observability gaps  (3 findings)

_Whether incidents can be detected and recovered._

### **[Copilot]** 🟥 CRITICAL `emulator-repudiation`

- **Location:** `(behaviour emulator — pipeline trace):?`
- **Message:** Repudiation (T8)
- **Frameworks:** OWASP Agentic T8 · CWE CWE-778
- **Remediation:** Tie the audit trail to the tool layer, not to the model's self-report. Every tool call must write an immutable log entry (timestamp, authenticated principal, tool, args) before the call returns, and the agent must never be asked to attest to whether an action happened — only the audit log answers that question.

### **[Copilot]** 🟧 HIGH `AS-C-R-LLM02-002`

- **Location:** `testbed/demo-agent/notifications.py:24`
- **Message:** LLM output published to SNS without scrubbing. The reply_body is a Bedrock-generated string that may inadvertently include PII echoed from the customer ticket, internal identifiers from the system prompt, or hallucinated content. SNS subscribers receive it unfiltered.
- **Frameworks:** OWASP LLM LLM02 · OWASP Agentic T8 · MITRE ATLAS AML.T0057 · CWE CWE-200
- **Snippet:** `sns.publish(TopicArn="...", Message=reply_body, ...)`
- **Remediation:** Apply an output scrubber (Presidio AnonymizerEngine, or a regex-based redactor for the specific patterns you handle) on reply_body before sns.publish. Apply at the publisher edge, not at the LLM call site, since the call site is far from the eventual recipient.

### **[Copilot]** 🟨 MEDIUM `AS-C-R-LLM10-001`

- **Location:** `testbed/demo-agent/notifications.py:14`
- **Message:** LLM call has no surrounding audit logging. No structured logger setup (no structlog / langsmith / OpenTelemetry / langchain.callbacks); no logger.info around the call. Without an audit trail, incident response can't reconstruct what the model saw or returned.
- **Frameworks:** OWASP LLM LLM10 · OWASP Agentic T8 · MITRE ATLAS AML.T0024
- **Snippet:** `response = client.chat.completions.create(...)`
- **Remediation:** Add structured logging around every LLM invocation. Capture: input prompt (hashed), model id, latency, token counts, output (hashed). Recommended: LangSmith or OpenTelemetry traces.

## Coverage matrix

| Framework | Items touched |
|---|---|
| owasp_llm | LLM01, LLM02, LLM05, LLM06, LLM07, LLM10 |
| owasp_agentic | T1, T10, T11, T12, T13, T2, T3, T4, T6, T8 |
| mitre_atlas | AML.T0024, AML.T0050, AML.T0051, AML.T0055, AML.T0056, AML.T0057 |
| cwe | CWE-200, CWE-269, CWE-345, CWE-400, CWE-732, CWE-78, CWE-798, CWE-918, CWE-94 |
| ast | AST03, AST04, AST06, AST07, AST08 |

