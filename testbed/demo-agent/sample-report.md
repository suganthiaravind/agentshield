# AgentShield Detection Report

_Semgrep Rules-engine Scan + Copilot AI Scan · scanned 2026-05-06T14:00:00Z_

---

## Detect / Defend / Respond

AgentShield's organising spine. Every finding belongs to exactly one category.

| **🔴 Detect** _vulnerability surfaces_ | **🟡 Defend** _missing controls_ | **🔵 Respond** _observability gaps_ |
|---|---|---|
| **11 findings**<br>🟥 CRITICAL &times; 2<br>🟧 HIGH &times; 4<br>🟨 MEDIUM &times; 2<br>🟦 INFO &times; 3 | **2 findings**<br>🟧 HIGH &times; 1<br>🟨 MEDIUM &times; 1 | **2 findings**<br>🟧 HIGH &times; 1<br>🟨 MEDIUM &times; 1 |

## Summary

| Metric | Count |
|---|---|
| Semgrep Rules-engine Scan findings | 9 |
| Copilot AI Scan net-new findings | 6 |
| Semgrep findings marked True Positive by Copilot | 1 |
| Semgrep findings marked Context-Dependent by Copilot | 0 |
| Semgrep findings marked False Positive by Copilot | 0 |
| **Net actionable** | **15** |

## JPMC SAIGE Agent Tier classification

**Classified as:** Agentic Tier 2

**Rationale:**

> Autonomous LLM-driven control flow at controller.py:21 (chain.invoke with user-supplied input) and at tools.py:14 (LLM output drives a Python eval branch). State-changing operations confirmed at notifications.py:24 (sns.publish — outbound notification) and tools.py:32 (POST to billing-api cancel endpoint — modifies subscription state). All targets are internal services (internal-pg.local, billing-api.internal, support-replies SNS topic). No customer-facing endpoint reached directly. Classified Tier 2 because state changes are internal-only; would be Tier 3 if the SNS topic delivered to customer email.

_Informational only — AgentShield does not filter or prioritise findings based on this classification. See [research.md §5](./research.md#5-jpmc-saige-agent-tier-classification) for the category definitions._

## 🔴 Detect — vulnerability surfaces  (11 findings)

_Where the agent is exploitable._

### **[Semgrep]** 🟥 CRITICAL `hardcoded-llm-credentials`

- **Location:** `testbed/demo-agent/config.py:7`
- **Message:** Hardcoded credential string passed to an LLM client constructor (OpenAI, Anthropic, Cohere, Mistral, Together, Groq, HuggingFace, Google generative AI, AWS Bedrock). Secrets in source code are CWE-798 (Use of Hard-coded Credentials) — they end up in git history, container images, and CI logs. Use environment variables, a secrets manager (AWS Secrets Manager, HashiCorp Vault, Azure Key Vault), or the SDK's default credential resolver instead.
- **Frameworks:** OWASP LLM LLM02, LLM03 · OWASP Agentic T3 · MITRE ATLAS AML.T0012 · CWE CWE-798

### **[Semgrep]** 🟥 CRITICAL `llm-output-to-code-execution`

- **Location:** `testbed/demo-agent/tools.py:21`
- **Message:** Output from an LLM call flows into a dangerous code-execution sink (eval / exec / os.system / subprocess with shell=True). LLM output is attacker-controllable via prompt injection — feeding it to a code executor is arbitrary code execution on the host. OWASP LLM05 Improper Output Handling, OWASP Agentic T11.
- **Frameworks:** OWASP LLM LLM05, LLM06 · OWASP Agentic T2, T11 · MITRE ATLAS AML.T0011, AML.T0050 · CWE CWE-94

### **[Semgrep]** 🟧 HIGH `ast03-network-unrestricted`

- **Location:** `SKILL.md:1`
- **Message:** Skill declares unrestricted network egress (`network: true`). AST03 — should be a domain allowlist (`network.allow: [api.example.com]`) with default-deny.
- **Frameworks:** OWASP LLM LLM03, LLM06 · OWASP Agentic T2, T3 · CWE CWE-732 · OWASP AST10 AST03

### **[Semgrep]** 🟧 HIGH `unsanitized-user-input-to-llm`

- **Location:** `testbed/demo-agent/controller.py:21`
- **Message:** User input from an HTTP request flows directly into an LLM/agent/chain/retriever invocation without passing through a known guardrail or sanitization layer. This is the canonical prompt-injection surface (OWASP LLM01).
- **Frameworks:** OWASP LLM LLM01 · OWASP Agentic T6 · MITRE ATLAS AML.T0051

### **[Copilot]** 🟧 HIGH `TIER2-LLM01-02`

- **Location:** `testbed/demo-agent/controller.py:30`
- **Message:** Untrusted document loader: article_url is user-supplied (from request body) and fetched without an allowlist. Indirect prompt-injection surface — attacker-controlled webpage content flows into the LLM via the summarise prompt.
- **Frameworks:** OWASP LLM LLM01 · OWASP Agentic T1, T6 · CWE CWE-94
- **Snippet:** `docs = WebBaseLoader(article_url).load()`
- **Remediation:** Validate article_url against an explicit hostname allowlist before fetching. Treat retrieved document content as untrusted user input — pass through a guardrail layer before the LLM call.

### **[Semgrep]** 🟧 HIGH `unsanitized-user-input-to-llm`

- **Location:** `testbed/demo-agent/controller.py:34`
- **Message:** User input from an HTTP request flows directly into an LLM/agent/chain/retriever invocation without passing through a known guardrail or sanitization layer. This is the canonical prompt-injection surface (OWASP LLM01).
- **Frameworks:** OWASP LLM LLM01 · OWASP Agentic T6 · MITRE ATLAS AML.T0051

### **[Semgrep]** 🟨 MEDIUM `ast03-wildcard-file-read`  ·  Copilot verdict: ✅ TP

- **Location:** `SKILL.md:1`
- **Message:** Wildcard read permission on `~/.config/demo-agent/**`. AST03 — skill manifests must declare explicit paths; wildcards defeat least-privilege review.
- **Frameworks:** CWE CWE-732 · OWASP AST10 AST03
- **Copilot reasoning:** request.json["message"] is user-controlled and flows directly into chain.invoke with no guardrail wrapper or sanitiser between source and sink. Confirmed prompt-injection surface.

### **[Copilot]** 🟨 MEDIUM `TIER2-AGENTIC-T1-01`

- **Location:** `testbed/demo-agent/memory.py:17`
- **Message:** Memory poisoning surface: both user input and raw LLM output are persisted to session memory without validation. Future turns retrieve this content as 'trusted context'; an attacker can plant instructions in turn N that influence turn N+1.
- **Frameworks:** OWASP LLM LLM04 · OWASP Agentic T1
- **Snippet:** `memory.setdefault(session_id, []).append({"user": user_message, "assistant": llm_response})`
- **Remediation:** Validate memory writes the same way you'd validate database writes — schema-check or pass through a content moderation classifier on persistence.

### **[Semgrep]** 🟦 INFO `ast04-missing-author-identity`

- **Location:** `SKILL.md:1`
- **Message:** Skill manifest has no `author.identity` (DID / signing-key anchor). AST04 — without a verifiable identity anchor, registry consumers cannot detect impersonation or typosquats; this is the foothold the ClawHub fake-Google skill exploited.
- **Frameworks:** OWASP AST10 AST04

### **[Semgrep]** 🟦 INFO `ast07-missing-content-hash`

- **Location:** `SKILL.md:1`
- **Message:** SKILL.md frontmatter has no `content_hash` field. AST07 — Merkle-root verification at install time requires a SHA-256 over the canonical skill payload.
- **Frameworks:** CWE CWE-345 · OWASP AST10 AST07

### **[Semgrep]** 🟦 INFO `ast07-missing-signature`

- **Location:** `SKILL.md:1`
- **Message:** SKILL.md frontmatter has no `signature` field. AST07 — without an ed25519 signature the registry cannot verify the skill on update; ClawJacked-style update-drift attacks become viable.
- **Frameworks:** OWASP LLM LLM03 · CWE CWE-345 · OWASP AST10 AST07

## 🟡 Defend — missing controls  (2 findings)

_What active defences are missing._

### **[Copilot]** 🟧 HIGH `TIER2-LLM06-01`

- **Location:** `testbed/demo-agent/tools.py:26`
- **Message:** Destructive tool registered without a human-in-the-loop approval gate. The `cancel_subscription` tool name starts with a destructive verb and the body POSTs to a billing API; the agent can invoke it autonomously if the planner decides to.
- **Frameworks:** OWASP LLM LLM06 · OWASP Agentic T2, T10
- **Snippet:** `@tool def cancel_subscription(customer_id: str)`
- **Remediation:** Wire a HumanApprovalCallbackHandler (LangChain) or LangGraph interrupt_before on this tool node. Require explicit confirmation before any subscription mutation.

### **[Copilot]** 🟨 MEDIUM `TIER2-LLM10-01`

- **Location:** `testbed/demo-agent/controller.py:14`
- **Message:** ChatOpenAI client instantiated without explicit timeout or max_tokens cap. A slow or runaway model call has no upper bound — DoS / cost exposure.
- **Frameworks:** OWASP LLM LLM10 · OWASP Agentic T4 · CWE CWE-400
- **Snippet:** `chain = ChatOpenAI(model=MODEL, openai_api_key=client.api_key)`
- **Remediation:** Pass timeout=30 (or whatever per-call ceiling fits your latency budget) and max_tokens=2000 to the ChatOpenAI constructor.

## 🔵 Respond — observability gaps  (2 findings)

_Whether incidents can be detected and recovered._

### **[Copilot]** 🟧 HIGH `TIER2-LLM02-04`

- **Location:** `testbed/demo-agent/notifications.py:24`
- **Message:** LLM output published to SNS without scrubbing. The reply_body is a Bedrock-generated string that may inadvertently include PII echoed from the customer ticket, internal identifiers from the system prompt, or hallucinated content. SNS subscribers receive it unfiltered.
- **Frameworks:** OWASP LLM LLM02 · OWASP Agentic T8 · CWE CWE-200
- **Snippet:** `sns.publish(TopicArn="...", Message=reply_body, ...)`
- **Remediation:** Apply an output scrubber (Presidio AnonymizerEngine, or a regex-based redactor for the specific patterns you handle) on reply_body before sns.publish. Apply at the publisher edge, not at the LLM call site, since the call site is far from the eventual recipient.

### **[Copilot]** 🟨 MEDIUM `TIER2-LLM10-02`

- **Location:** `testbed/demo-agent/notifications.py:14`
- **Message:** LLM call has no surrounding audit logging. No structured logger setup (no structlog / langsmith / OpenTelemetry / langchain.callbacks); no logger.info around the call. Without an audit trail, incident response can't reconstruct what the model saw or returned.
- **Frameworks:** OWASP LLM LLM10 · OWASP Agentic T8 · MITRE ATLAS AML.T0024
- **Snippet:** `response = client.chat.completions.create(...)`
- **Remediation:** Add structured logging around every LLM invocation. Capture: input prompt (hashed), model id, latency, token counts, output (hashed). Recommended: LangSmith or OpenTelemetry traces.

## Coverage matrix

| Framework | Items touched |
|---|---|
| owasp_llm | LLM01, LLM02, LLM03, LLM04, LLM05, LLM06, LLM10 |
| owasp_agentic | T1, T10, T11, T2, T3, T4, T6, T8 |
| mitre_atlas | AML.T0011, AML.T0012, AML.T0024, AML.T0050, AML.T0051 |
| cwe | CWE-200, CWE-345, CWE-400, CWE-732, CWE-798, CWE-94 |
| ast | AST03, AST04, AST07 |

