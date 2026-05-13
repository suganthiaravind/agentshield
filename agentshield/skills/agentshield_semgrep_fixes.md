---
name: agentshield-semgrep-fixes
description: |
  Help developers fix AgentShield Tier 1 (Semgrep) findings — high-precision Python/Java AST + taint matches with rule IDs starting `AS-S-`.

  Use this skill when:
    - the user pastes a finding ID starting with `AS-S-` (e.g. `AS-S-D-LLM01-001`) into chat
    - the user asks how to fix an AgentShield Semgrep finding
    - the user pastes a SARIF result with `ruleId` starting `agentshield.detect.*` / `agentshield.defend.*`
    - the user references a legacy AgentShield Tier 1 ID like `AS-D-001` / `AS-DF-003` (those are aliased to current IDs)
author:
  name: AgentShield
  identity: did:web:github.com/suganthiaravind/agentshield
permissions:
  network:
    allow: []
  shell: false
  files:
    read: []
    write: []
    deny_write:
      - SOUL.md
      - MEMORY.md
      - AGENTS.md
risk_tier: L0
---

# AgentShield Semgrep (Tier 1) Remediation Skill

Help developers fix AgentShield Tier 1 (Semgrep) findings — high-precision Python/Java AST + taint matches with rule IDs starting `AS-S-`.

When a user pastes an `AS-S-…` finding ID or asks about one of the rules below, walk them through the remediation. Cite the canonical rule ID and the framework mappings; if the user pasted a legacy ID, mention it once and carry on with the current ID.

Total rules in this skill: **16**

---

## 🔴 Detect (14)

### `AS-S-D-CWE_798-001` — Hardcoded LLM Credentials Java

**Severity:** critical · **Languages:** java · **Legacy ID:** `AS-D-005`

**Frameworks:** `OWASP LLM LLM02` `OWASP Agentic T3` `MITRE ATLAS AML.T0012` `CWE CWE-798`

**What it flags:** Hardcoded credential string passed to a Java LLM client constructor or builder (langchain4j, Spring AI, Azure OpenAI, AWS Bedrock direct). Secrets in source code are CWE-798 — they end up in git history, jar manifests, container images, and CI logs. Use a secrets manager (AWS Secrets Manager, HashiCorp Vault, Azure Key Vault), Spring's `@Value("${env.var}")`, or the SDK's default credential resolver instead. Java port of agentshield.detect.hardcoded-llm-credentials.

**Remediation:** Move the credential out of source. Options, ranked by safety: (1) the SDK's default credential resolver — for AWS Bedrock, use DefaultCredentialsProvider.create() and rely on the IAM role / instance profile / env vars; for Azure, use DefaultAzureCredential(). (2) Spring `@Value("${OPENAI_API_KEY}")` or `@Value("${app.api-key}")` wired from environment / config server. (3) A secrets manager looked up at startup (AWS Secrets Manager, HashiCorp Vault, Azure Key Vault). Rotate any credential that has been committed — git history exposes it forever even after deletion from HEAD.

### `AS-S-D-CWE_798-001` — Hardcoded LLM Credentials

**Severity:** critical · **Languages:** python · **Legacy ID:** `AS-D-005`

**Frameworks:** `OWASP LLM LLM02` `OWASP Agentic T3` `MITRE ATLAS AML.T0012` `CWE CWE-798`

**What it flags:** Hardcoded credential string passed to an LLM client constructor (OpenAI, Anthropic, Cohere, Mistral, Together, Groq, HuggingFace, Google generative AI, AWS Bedrock). Secrets in source code are CWE-798 (Use of Hard-coded Credentials) — they end up in git history, container images, and CI logs. Use environment variables, a secrets manager (AWS Secrets Manager, HashiCorp Vault, Azure Key Vault), or the SDK's default credential resolver instead.

**Remediation:** Move the credential out of source. Options, ranked by safety: (1) the SDK's default credential resolver — for OpenAI / Anthropic / Cohere / Mistral, omit `api_key=` and the SDK reads the standard env var (OPENAI_API_KEY, ANTHROPIC_API_KEY, etc.); for boto3, omit aws_access_key_id and let the default chain (IAM role, instance profile, env, ~/.aws/credentials) resolve. (2) A secrets manager looked up at startup (AWS Secrets Manager, HashiCorp Vault, Azure Key Vault) — `api_key=secrets.get_secret_value(...)["SecretString"]`. (3) Environment variable read explicitly — `api_key=os.environ["OPENAI_API_KEY"]`. Rotate any credential that has been committed to git (it must be treated as compromised — git history exposes it forever even if you delete it from HEAD).

### `AS-S-D-LLM01-001` — Unsanitized User Input To LLM Java

**Severity:** high · **Languages:** java · **Legacy ID:** `AS-D-001`

**Frameworks:** `OWASP LLM LLM01` `OWASP Agentic T6` `MITRE ATLAS AML.T0051`

**What it flags:** User input from an HTTP request (Spring / JAX-RS / Servlet) flows directly into an LLM/agent invocation without passing through a known guardrail or sanitization layer. This is the canonical prompt-injection surface (OWASP LLM01). Java port of agentshield.detect.unsanitized-user-input-to-llm.

**Remediation:** Wrap LLM calls with an input guardrail. Java options are sparser than Python: Lakera Guard has a Java client; OWASP Java Encoder can sanitize user-controlled fragments; for prompt-injection specifically, call out to a guardrail service (NeMo Guardrails / Llama Guard) over HTTP. Validate and sanitize user input before it reaches the prompt template.

### `AS-S-D-LLM01-001` — Unsanitized User Input To LLM

**Severity:** high · **Languages:** python · **Legacy ID:** `AS-D-001`

**Frameworks:** `OWASP LLM LLM01` `OWASP Agentic T6` `MITRE ATLAS AML.T0051`

**What it flags:** User input from an HTTP request flows directly into an LLM/agent/chain/retriever invocation without passing through a known guardrail or sanitization layer. This is the canonical prompt-injection surface (OWASP LLM01).

**Remediation:** Wrap LLM calls with an input guardrail (NeMo Guardrails, Lakera Guard, Rebuff, Llama Guard, or an equivalent). Validate and sanitize user input before it reaches the prompt template. Use structured prompting that strictly delimits user content from instructions.

### `AS-S-D-LLM01-002` — System Prompt Concealment Instructions

**Severity:** high · **Languages:** python · **Legacy ID:** `AS-D-009`

**Frameworks:** `OWASP LLM LLM01` `OWASP LLM LLM07` `OWASP Agentic T6` `OWASP Agentic T8` `MITRE ATLAS AML.T0051` `CWE CWE-489`

**What it flags:** A system-prompt or tool description contains instructions telling the agent to deceive its own user — phrases like "do not tell the user", "hide this action", or "don't mention you used this tool". Even when added by a developer for "polish", these markers transform the agent into a deception vehicle: the agent can act on the user's behalf without revealing what it did. This is the static cousin of Cisco AI-Defense's PROMPT_INJECTION_CONCEALMENT signature, applied to the agent's own configured prompts. OWASP LLM01 / Agentic T8.

**Remediation:** Remove concealment instructions from system prompts and tool descriptions. If a control-flow step truly should not be surfaced verbatim (e.g. an internal trace ID), summarise it explicitly in the user-facing response rather than instructing the agent to hide it. Transparency is a precondition for human oversight (OWASP Agentic T8) — if the agent can hide actions from its user, neither the user nor an auditor can verify what it did.

### `AS-S-D-LLM01-003` — System Prompt Jailbreak Markers

**Severity:** high · **Languages:** python · **Legacy ID:** `AS-D-010`

**Frameworks:** `OWASP LLM LLM01` `OWASP Agentic T6` `MITRE ATLAS AML.T0051`

**What it flags:** A hardcoded prompt string contains jailbreak / mode-switch markers — phrases like "you are now in unrestricted mode", "developer mode", "disable safety filters", "ignore previous instructions". These strings are typically left-over from prompt-engineering experiments or red-team scaffolding that should never reach production. Any of these baked into a system prompt actively suppresses safety behaviour; baked into a user-facing prompt template, it primes the model to ignore its own guardrails. Mirrors Cisco AI-Defense PROMPT_INJECTION_UNRESTRICTED_MODE / IGNORE_INSTRUCTIONS signatures applied to the agent's own configured prompts. OWASP LLM01.

**Remediation:** Delete jailbreak strings from production prompts. If a red-team fixture is genuinely needed (e.g. for evaluation), keep it in a test-only file under `tests/` or `evals/` — AgentShield treats those paths as lower-severity by default. For research or adversarial evaluation, move the strings into a dedicated test corpus that does not sit in the same module as the production prompt template. Whitelist-comments (`# nosec - red-team eval string`) on the production line only hide the symptom; remove the string itself.

### `AS-S-D-LLM03-001` — Non HTTPS Outbound Fetch

**Severity:** medium · **Languages:** python · **Legacy ID:** `AS-D-012`

**Frameworks:** `OWASP Agentic T6` `MITRE ATLAS AML.T0010` `CWE CWE-319` `CWE CWE-494` `CWE CWE-829`

**What it flags:** A network fetch targets a plaintext `http://` URL where the response is treated as code, config, model artifact, or RAG document — i.e. the response will affect agent behaviour. Plaintext transport means a network attacker (corporate proxy, coffee-shop Wi-Fi, compromised ISP) can substitute response content silently. Pairs with CWE-494 (download of code without integrity check): integrity verification can't help if the URL itself is intercepted. Use HTTPS so the response is at least transport-authenticated. OWASP LLM03 (supply chain) / Agentic T6 (untrusted retrieval).

**Remediation:** Switch the URL to `https://`. If the target genuinely speaks only HTTP (legacy internal service), terminate TLS at a reverse proxy and call the proxy over HTTPS — never fetch agent-affecting content over plaintext. This rule explicitly excludes `http://localhost` and `http://127.0.0.1` (development / loopback). For RAG document ingestion, combine with an explicit hostname allowlist (see TIER2-LLM01-02).

### `AS-S-D-LLM05-001` — Llm Output To Code Execution Java

**Severity:** critical · **Languages:** java · **Legacy ID:** `AS-D-004`

**Frameworks:** `OWASP LLM LLM05` `OWASP LLM LLM06` `OWASP Agentic T2` `OWASP Agentic T11` `MITRE ATLAS AML.T0011` `MITRE ATLAS AML.T0050` `CWE CWE-89` `CWE CWE-94`

**What it flags:** Output from a Java LLM call (Spring AI / langchain4j / SMARTSDK / Bedrock / Azure OpenAI) flows into a dangerous code-execution sink (Runtime.exec, ProcessBuilder, ScriptEngine.eval, JDBC Statement.execute*). LLM output is attacker-controllable via prompt injection — feeding it to a code executor or unparameterized SQL is arbitrary code execution / SQL injection on the host. Java port of agentshield.detect.llm-output-to-code-execution (AS-D-004). OWASP LLM05, OWASP Agentic T11.

**Remediation:** Never pass raw LLM output to Runtime.exec, ProcessBuilder, ScriptEngine.eval, or unparameterized JDBC Statement. For shell commands, validate against an allowlist and pass argv as a String[] to ProcessBuilder rather than a single shell string. For SQL, use PreparedStatement with bound parameters (?-placeholders) — never concatenate or format LLM output into the SQL body. For arbitrary code execution, run in a hardened sandbox (Docker, Firecracker, or a SecurityManager-restricted classloader).

### `AS-S-D-LLM05-001` — Llm Output To Code Execution

**Severity:** critical · **Languages:** python · **Legacy ID:** `AS-D-004`

**Frameworks:** `OWASP LLM LLM05` `OWASP LLM LLM06` `OWASP Agentic T2` `OWASP Agentic T11` `MITRE ATLAS AML.T0011` `MITRE ATLAS AML.T0050` `CWE CWE-94`

**What it flags:** Output from an LLM call flows into a dangerous code-execution sink (eval / exec / os.system / subprocess with shell=True). LLM output is attacker-controllable via prompt injection — feeding it to a code executor is arbitrary code execution on the host. OWASP LLM05 Improper Output Handling, OWASP Agentic T11.

**Remediation:** Never pass raw LLM output to eval / exec / os.system or shell=True subprocess. If you must execute generated code, run it in an isolated sandbox (Docker, Firecracker, gVisor, SessionsPythonREPLTool, restricted-python) with no host access. For shell commands, parse with shlex.split and pass argv to subprocess without shell=True. For arithmetic / config evaluation, prefer ast.literal_eval. For SQL, use parameterized queries — never format LLM output into a query string.

### `AS-S-D-LLM05-002` — Tool Description Injection

**Severity:** medium · **Languages:** python · **Legacy ID:** `AS-D-011`

**Frameworks:** `OWASP LLM LLM05` `OWASP LLM LLM01` `OWASP Agentic T2` `OWASP Agentic T6` `MITRE ATLAS AML.T0051`

**What it flags:** A registered LLM tool's description contains imperative, prompt-style instructions that target the LLM rather than describing the tool's function ("you MUST call this tool", "ignore other tools", "always use this tool"). Tool descriptions are concatenated into the planner prompt verbatim — a description that issues commands biases tool selection and can override the system prompt. This is the static cousin of OWASP "Tool Poisoning" (LLM05 / Agentic T6): when the tool registry itself becomes a prompt-injection surface, every planner decision is corrupted. Common in ported example code that mixes prompt-engineering tricks with API documentation.

**Remediation:** Rewrite the tool description as a neutral, declarative statement of what the tool does — input, output, and side-effects. Tool selection bias belongs in the system prompt under explicit developer control, not embedded in tool descriptions where it gets concatenated into every planner prompt by the framework. Pattern to follow: "Cancels a customer's subscription. Input — customer_id (str). Side-effect — calls billing API; irreversible without re-subscribe." Anti-pattern: "You MUST use this tool when the user mentions cancellation."

### `AS-S-D-LLM06-001` — Code Execution Tool Registered Java

**Severity:** critical · **Languages:** java · **Legacy ID:** `AS-D-003`

**Frameworks:** `OWASP LLM LLM05` `OWASP LLM LLM06` `OWASP Agentic T2` `OWASP Agentic T11` `MITRE ATLAS AML.T0011` `MITRE ATLAS AML.T0050` `CWE CWE-78` `CWE CWE-94`

**What it flags:** A Java method registered as an LLM tool (langchain4j @Tool / Spring AI @Tool) wraps a code-execution primitive (Runtime.exec, ProcessBuilder, ScriptEngine.eval). The agent can invoke the tool with attacker-controlled arguments — direct arbitrary code execution on the host. Java port of agentshield.detect.code-execution-tool-registered (AS-D-003). OWASP LLM05 / LLM06, OWASP Agentic T2 / T11.

**Remediation:** Run code-execution tools inside a sandbox: a SecurityManager-restricted classloader, a Docker / Firecracker microVM, or an isolated JVM with no host filesystem / network access. Restrict the agent's tool registry to a narrow allowlist of safe, validated primitives. Require human approval before agent-generated code executes with elevated privileges. Never expose Runtime.exec / ProcessBuilder / ScriptEngine.eval as a tool function to the LLM.

### `AS-S-D-LLM06-001` — Code Execution Tool Registered

**Severity:** critical · **Languages:** python · **Legacy ID:** `AS-D-003`

**Frameworks:** `OWASP LLM LLM05` `OWASP LLM LLM06` `OWASP Agentic T2` `OWASP Agentic T11` `MITRE ATLAS AML.T0011` `MITRE ATLAS AML.T0050` `CWE CWE-78` `CWE CWE-94`

**What it flags:** Agent has access to a code-execution tool (Python REPL, shell, eval). If user input or LLM output reaches the tool's input, this is arbitrary code execution on the host. OWASP LLM05/LLM06, OWASP Agentic T11.

**Remediation:** Run code-execution tools inside a sandbox (e.g. SessionsPythonREPLTool, Docker, Firecracker, or seccomp-restricted process). Restrict the agent's tool registry to a narrow allowlist of safe primitives. Require human approval before agent-generated code executes with elevated privileges. Never wire `exec`, `eval`, `os.system`, or unrestricted `subprocess` as a tool function.

### `AS-S-D-LLM07-001` — Untrusted System Prompt Java

**Severity:** critical · **Languages:** java · **Legacy ID:** `AS-D-008`

**Frameworks:** `OWASP LLM LLM01` `OWASP LLM LLM07` `OWASP Agentic T6` `MITRE ATLAS AML.T0051` `CWE CWE-829`

**What it flags:** Content from a network read flows into a Java LLM system message (Spring AI `SystemMessage` / `SystemPromptTemplate`, langchain4j `SystemMessage`, AWS Bedrock Converse `SystemContentBlock`). System prompts dictate the agent's role, tools, and constraints — an attacker who controls the system-prompt source can inject hidden instructions that override the developer's intent. Java port of agentshield.detect.untrusted-system-prompt (AS-D-008). OWASP LLM07.

**Remediation:** Never load Java LLM system messages from untrusted network sources. Options ranked by safety: (1) bake the system prompt into the JAR as a resource and read with `getResourceAsStream`. (2) If runtime loading is required, fetch from a write-restricted source (signed S3 object with strict IAM, version-pinned parameter store) AND verify a cryptographic signature (`MessageDigest.isEqual`, `Mac.doFinal`) before constructing the `SystemMessage`. (3) Apply Lakera Guard or equivalent to detect injected instructions in the loaded prompt before use. Treat any externally-loaded system prompt as untrusted input — same bar as user input.

### `AS-S-D-LLM07-001` — Untrusted System Prompt

**Severity:** critical · **Languages:** python · **Legacy ID:** `AS-D-008`

**Frameworks:** `OWASP LLM LLM01` `OWASP LLM LLM07` `OWASP Agentic T6` `MITRE ATLAS AML.T0051` `CWE CWE-829`

**What it flags:** Content from a network read flows into an LLM system prompt (Anthropic `system=`, OpenAI Responses `instructions=`, LangChain `SystemMessage`, etc.). System prompts dictate the agent's role, tools, and constraints — an attacker who controls the system prompt source can inject hidden instructions that override the developer's intent. OWASP LLM07 System Prompt Leakage / injection.

**Remediation:** Never load system prompts from untrusted network sources at runtime. Options, ranked by safety: (1) bake system prompts into the deployed artifact (read from a constant string, a packaged file, or a build- time-resolved config). (2) If runtime loading is required, fetch from a write-restricted source (signed S3 object, parameter store with strict IAM, version-pinned config server) AND verify a cryptographic signature before use. (3) Apply a guardrail (NeMo Guardrails / Lakera / Rebuff) on the loaded prompt to detect injected instructions. Treat any externally-loaded system prompt as untrusted input — same bar as user input.

---

## 🟡 Defend (2)

### `AS-S-DF-LLM10-001` — No Timeout Or Token Cap On LLM Java

**Severity:** medium · **Languages:** java · **Legacy ID:** `AS-DF-003`

**Frameworks:** `OWASP LLM LLM10` `OWASP Agentic T4` `CWE CWE-400`

**What it flags:** Java LLM client builder explicitly disables a bound — null timeout, Duration.ZERO, or 0-second OkHttp timeout — leaving the client open to indefinite hangs or runaway output. OWASP LLM10 Unbounded Consumption, OWASP Agentic T4 Resource Overload. Java port of agentshield.defend.no-timeout-or-token-cap-on-llm (AS-DF-003).

**Remediation:** Set explicit upper bounds on every Java LLM client. (1) langchain4j / Spring AI builders: call `.timeout(Duration.ofSeconds(N))` and `.maxTokens(N)` with finite values matched to your worker SLA. (2) OkHttp transports: never pass 0 to `connectTimeout` / `readTimeout` / `writeTimeout` / `callTimeout` — pass a finite (timeout, TimeUnit) pair. (3) AWS Bedrock Runtime: configure `ClientOverrideConfiguration.builder().apiCallTimeout(Duration.ofSeconds(N))` and a finite `RetryPolicy`. (4) Combine with per-tenant rate limiting upstream of the call to bound aggregate cost.

### `AS-S-DF-LLM10-001` — No Timeout Or Token Cap On LLM

**Severity:** medium · **Languages:** python · **Legacy ID:** `AS-DF-003`

**Frameworks:** `OWASP LLM LLM10` `OWASP Agentic T4` `CWE CWE-400`

**What it flags:** LLM client / call constructed with an explicitly disabled timeout (`timeout=None`) or output cap (`max_tokens=None` / `max_output_tokens=None`). Without bounds, a single request can hang a worker indefinitely or generate runaway output — a DoS / cost-blowup vector. OWASP LLM10 Unbounded Consumption, OWASP Agentic T4 Resource Overload.

**Remediation:** Set explicit upper bounds on every LLM call. (1) `timeout=` should be a finite number of seconds matched to your worker SLA — typically 30-60s for interactive paths, longer for batch. (2) `max_tokens=` (or `max_output_tokens=` for Google / OpenAI Responses API) should be set to the smallest value that satisfies your prompt — never None or unbounded. (3) Combine with retry budgets (`max_retries=2-3`) and per-tenant rate limiting upstream of the call. For Bedrock direct boto3, set `Config(read_timeout=N, retries={"max_attempts": 3})`.

---

## Related

- AgentShield repo: https://github.com/suganthiaravind/agentshield
- For the live, full rule list across all three sources, run `agentshield merge --output-html report.html` and open the **Reference tab** of the generated report.

