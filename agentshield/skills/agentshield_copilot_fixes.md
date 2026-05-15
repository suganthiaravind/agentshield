---
name: agentshield-copilot-fixes
description: |
  Help developers fix AgentShield Tier 2 (Copilot LLM-as-scanner) findings — semantic / cross-function checks with rule IDs starting `AS-C-`.

  Use this skill when:
    - the user pastes a finding ID starting with `AS-C-` (e.g. `AS-C-DF-LLM06-004`) into chat
    - the user asks how to fix an AgentShield Copilot finding
    - the user references a legacy `TIER2-LLM..-..` / `TIER2-AGENTIC-T..-..` / `TIER2-CWE-..-..` ID — they alias to current `AS-C-*` IDs
    - the user has just run `agentshield merge` and asks about Tier 2 entries in the report
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

# AgentShield Copilot (Tier 2) Remediation Skill

Help developers fix AgentShield Tier 2 (Copilot LLM-as-scanner) findings — semantic / cross-function checks with rule IDs starting `AS-C-`.

When a user pastes an `AS-C-…` finding ID or asks about one of the rules below, walk them through the remediation. Cite the canonical rule ID and the framework mappings; if the user pasted a legacy ID, mention it once and carry on with the current ID.

Total rules in this skill: **62**

---

## 🔴 Detect (28)

### `AS-C-D-AGENTIC_T1-001` — Memory poisoning via persistent store

**Severity:** high · **Languages:** any · **Legacy ID:** `TIER2-AGENTIC-T1-01`

**Frameworks:** `OWASP Agentic T1`

**What it flags:** Long-term memory writes (vector store, Redis, DB) where the value being persisted contains user input or LLM output without a trust boundary. `memory.add(user_message)`, `vectorstore.add_texts([response])`, `redis.set(f"user:{uid}:context", llm_output)`.

**Skip if:** Persisted content is a hash, a typed-schema-validated object, or passes through a moderation classifier first.

**Remediation:** Validate memory writes the same way you'd validate database writes. Schema-check, classify, hash where feasible.

### `AS-C-D-AGENTIC_T11-001` — RCE via deserialisation

**Severity:** critical · **Languages:** java, python, any · **Legacy ID:** `TIER2-AGENTIC-T11-01`

**Frameworks:** `OWASP Agentic T11` `CWE CWE-94` `CWE CWE-502`

**What it flags:** `pickle.loads(...)`, Java `ObjectInputStream.readObject()`, YAML `yaml.load(...)` (without SafeLoader), where the input is from the network / LLM output / user upload.

**Skip if:** Input is `yaml.safe_load`, JSON only, or a typed-schema parser.

**Remediation:** Never deserialise untrusted data. Use JSON + schema validation. --- # §3. MITRE ATLAS techniques ML-attack-specific techniques. Use the `mitre_atlas` array.

### `AS-C-D-AGENTIC_T2-001` — Code-execution tool registered (was D003)

**Severity:** critical · **Languages:** any · **Legacy ID:** `TIER2-AGENTIC-T2-01`

**Frameworks:** `OWASP Agentic T2` `OWASP Agentic T11` `OWASP LLM LLM05` `OWASP LLM LLM06` `MITRE ATLAS AML.T0050` `CWE CWE-78` `CWE CWE-94`

**What it flags:** A tool/plugin function exposed to the agent whose body calls `exec`, `eval`, `os.system`, `subprocess.*` with `shell=True`, `Runtime.exec`, `ProcessBuilder`, `ScriptEngine.eval`, or any other arbitrary-code interpreter. LangChain `PythonREPLTool`, `ShellTool`, `BashProcess`, langchain4j @Tool wrapping shell exec.

**Skip if:** The tool is a sandboxed REPL with no host-system access (e.g. `RestrictedPython`, isolated container with no mounts).

**Remediation:** Remove the tool or sandbox it strictly. Use LangChain's `SessionsPythonREPLTool` (Azure-managed sandbox) instead of raw `PythonREPLTool`.

### `AS-C-D-AGENTIC_T2-002` — Tool argument injection

**Severity:** high · **Languages:** any · **Legacy ID:** `TIER2-AGENTIC-T2-02`

**Frameworks:** `OWASP Agentic T2` `OWASP LLM LLM05` `CWE CWE-78`

**What it flags:** Tool that accepts a string arg and concatenates it into a shell command, SQL query, or HTTP URL without escaping/parameterising. E.g. `@tool def lookup(q): return os.popen(f"grep {q} /data/*")`.

**Skip if:** Args go through `shlex.quote()`, parameterised query, or URL-encoded.

**Remediation:** Always parameterise. Never f-string user/LLM input into a shell command or SQL.

### `AS-C-D-AGENTIC_T5-001` — Cascading hallucination — output of one LLM feeds another without verification

**Severity:** medium · **Languages:** any · **Legacy ID:** `TIER2-AGENTIC-T5-01`

**Frameworks:** `OWASP Agentic T5`

**What it flags:** Multi-step pipelines where LLM-A's output becomes LLM-B's input directly with no schema check, no verification step, no "is this answer right" eval. Common in extract→summarise→email pipelines.

**Skip if:** Intermediate outputs are typed-schema-validated and a semantic check (eval agent, classifier, regex assertion) gates the next step.

**Remediation:** Add a verification step between LLM hand-offs. Classifier, schema check, or human-eligible review for high-stakes outputs.

### `AS-C-D-AGENTIC_T6-001` — Goal manipulation via tool description

**Severity:** medium · **Languages:** any · **Legacy ID:** `TIER2-AGENTIC-T6-01`

**Frameworks:** `OWASP Agentic T6` `OWASP LLM LLM01`

**What it flags:** Tool descriptions (`@tool(description=...)`, `Tool(description=...)`, langchain4j `@P(description=...)`) that contain user-controllable substrings. Description should be hardcoded.

**Skip if:** Description is a string literal.

**Remediation:** Tool descriptions are code-shipped constants.

### `AS-C-D-ATLAS_T0010-001` — ML supply chain compromise

**Severity:** high · **Languages:** any · **Legacy ID:** `TIER2-ATLAS-T0010-01`

**Frameworks:** `MITRE ATLAS AML.T0010` `CWE CWE-829` `CWE CWE-494`

**What it flags:** Model artifacts, embedding models, or ML libraries pulled from non-pinned sources. Cross-references LLM03-01 / LLM08-01 but at the supply-chain level.

**Skip if:** All ML deps pinned + checksum-verified.

**Remediation:** Mirror critical artifacts internally. Verify checksums.

### `AS-C-D-ATLAS_T0011-001` — User execution via LLM plugin

**Severity:** high · **Languages:** any · **Legacy ID:** `TIER2-ATLAS-T0011-01`

**Frameworks:** `MITRE ATLAS AML.T0011` `OWASP LLM LLM06`

**What it flags:** Plugins / tools that the LLM can invoke without user consent for each invocation, where the plugin has side-effects. Cross-references LLM06-01.

**Remediation:** Per-invocation consent for side-effecting plugins.

### `AS-C-D-ATLAS_T0019-001` — Publish poisoned datasets

**Severity:** high · **Languages:** any · **Legacy ID:** `TIER2-ATLAS-T0019-01`

**Frameworks:** `MITRE ATLAS AML.T0019`

**What it flags:** Pipelines that publish datasets / fine-tuning corpora to shared registries (HuggingFace Hub, internal Artifactory, shared S3) without a signing / approval step.

**Remediation:** Sign published datasets. Require human approval for HF Hub pushes from CI.

### `AS-C-D-ATLAS_T0050-001` — Command and scripting interpreter via LLM

**Severity:** critical · **Languages:** any · **Legacy ID:** `TIER2-ATLAS-T0050-01`

**Frameworks:** `MITRE ATLAS AML.T0050` `OWASP LLM LLM05` `CWE CWE-78`

**What it flags:** Cross-references LLM05-01 / AGENTIC-T2-01. Same shape: LLM output → command interpreter.

**Remediation:** As LLM05-01.

### `AS-C-D-ATLAS_T0053-001` — LLM plugin compromise

**Severity:** high · **Languages:** any · **Legacy ID:** `TIER2-ATLAS-T0053-01`

**Frameworks:** `MITRE ATLAS AML.T0053`

**What it flags:** Plugin loading from third-party registries without pinning / signature verification.

**Remediation:** Pin plugin versions. Verify signatures. --- # §4. CWE first-class concerns Cross-language CWE checks. Use the `cwe` array.

### `AS-C-D-CWE_494-001` — Download of code without integrity check

**Severity:** high · **Languages:** any · **Legacy ID:** `TIER2-CWE-494-01`

**Frameworks:** `CWE CWE-494`

**What it flags:** Cross-references LLM03-01. Models / packages / binaries downloaded without checksum verification.

**Remediation:** Verify SHA / signature before loading.

### `AS-C-D-CWE_78-001` — OS Command Injection

**Severity:** critical · **Languages:** any · **Legacy ID:** `TIER2-CWE-78-01`

**Frameworks:** `CWE CWE-78` `OWASP LLM LLM05`

**What it flags:** `os.system`, `subprocess.run(..., shell=True)`, `Runtime.exec(String)`, where the command string is built by concatenating untrusted input.

**Remediation:** Use array-form `subprocess.run([cmd, arg])`, `ProcessBuilder(List<String>)`. Never shell=True with user input.

### `AS-C-D-CWE_798-001` — Hardcoded Credentials

**Severity:** critical · **Languages:** any · **Legacy ID:** `TIER2-CWE-798-01`

**Frameworks:** `CWE CWE-798` `OWASP LLM LLM02`

**What it flags:** Cross-references LLM02-01.

**Remediation:** Externalise to env / secrets manager.

### `AS-C-D-CWE_829-001` — Inclusion of Functionality from Untrusted Source

**Severity:** high · **Languages:** any · **Legacy ID:** `TIER2-CWE-829-01`

**Frameworks:** `CWE CWE-829`

**What it flags:** Cross-references LLM03-01 / LLM08-01. Models / plugins / packages from untrusted sources.

**Remediation:** Allowlist sources. Pin versions. --- # §5. Phase E judge-surfaced gaps Patterns the rule pack never had, surfaced by real-world LLM-as-judge runs in Phase E. These are NEW coverage in v2.

### `AS-C-D-CWE_89-001` — SQL Injection

**Severity:** critical · **Languages:** any · **Legacy ID:** `TIER2-CWE-89-01`

**Frameworks:** `CWE CWE-89`

**What it flags:** `cursor.execute(f"SELECT * FROM x WHERE id={uid}")`, Java `Statement.executeQuery("SELECT ... " + input)`.

**Skip if:** Parameterised queries used (`?` placeholders, prepared statements, ORM with bound params).

**Remediation:** Always parameterise. ORM-managed queries are safest.

### `AS-C-D-CWE_94-001` — Code Injection

**Severity:** critical · **Languages:** any · **Legacy ID:** `TIER2-CWE-94-01`

**Frameworks:** `CWE CWE-94` `OWASP LLM LLM05`

**What it flags:** `eval`, `exec`, `compile()` of untrusted strings; Java `ScriptEngine.eval(input)`; template engines with autoescape off processing user-controlled templates.

**Remediation:** Don't eval untrusted code. Use proper parsers.

### `AS-C-D-LLM01-001` — Unsanitised user input → LLM call

**Severity:** high · **Languages:** any · **Legacy ID:** `TIER2-LLM01-01`

**Frameworks:** `OWASP LLM LLM01` `OWASP Agentic T6` `MITRE ATLAS AML.T0051` `CWE CWE-94`

**What it flags:** Data from a user-controlled source (HTTP request body / query / form, FastAPI/Spring `@RequestBody`/`@RequestParam`, AWS Lambda `event`, CLI `input()`/`sys.argv`, WebSocket frame, gRPC request) flowing **directly** into an LLM/agent invocation (`chain.invoke`, `runner.run`, `chatClient.prompt().user(...).call()`, `client.invokeModel(...)`, `bedrock.converse(...)`, OpenAI / Anthropic / Gemini / Cohere SDK calls) with no sanitiser between source and sink.

**Skip if:** A guardrail wrapper is called on the input first (Lakera `guard.guard(...)`, NeMo Guardrails `LLMRails.generate(...)`, Rebuff `detect_injection(...)`, Presidio analyse-then-anonymise, Guardrails-AI, in-house `ScrubbingCallAdvisor` or `scrubberService.scrubPii(...)`).

**Remediation:** Wrap the user input with a guardrail call (input filter for prompt-injection, output filter for PII / toxic content) before passing it to the LLM. For Spring AI, attach a `CallAdvisor` via `.advisors(...)` or builder `.defaultAdvisors(...)`.

### `AS-C-D-LLM01-002` — Indirect prompt injection via document loader

**Severity:** high · **Languages:** any · **Legacy ID:** `TIER2-LLM01-02`

**Frameworks:** `OWASP LLM LLM01` `OWASP Agentic T1` `OWASP Agentic T6` `CWE CWE-94`

**What it flags:** RAG document loaders fetching from URLs or files outside an explicit allowlist (`WebBaseLoader(url)`, `UnstructuredURLLoader`, `RecursiveUrlLoader`, langchain4j `UrlDocumentLoader.load(url)`, Spring AI `TikaDocumentReader(new UrlResource(url))`) where `url` is not validated against a hostname allowlist.

**Skip if:** URL is hardcoded, derived from a checked-in config file, or validated against an explicit allowlist before the fetch.

**Remediation:** Allowlist source domains. For corporate use, fetch only from internal document stores (SharePoint, Confluence) with auth.

### `AS-C-D-LLM01-003` — System-prompt override via untrusted source

**Severity:** critical · **Languages:** any · **Legacy ID:** `TIER2-LLM01-03`

**Frameworks:** `OWASP LLM LLM01` `OWASP LLM LLM02` `OWASP LLM LLM07` `CWE CWE-94`

**What it flags:** System prompt or system message constructed from a network read, environment variable populated at runtime, S3 object, SSM parameter, or HTTP response. Code shapes: `requests.get(...).text` flowing into Anthropic `system=`, OpenAI Responses `instructions=`, LangChain `SystemMessage(...)`, ChatPromptTemplate `("system", $X)`, Bedrock Converse `system=[{"text": $X}]`, Spring AI `SystemMessage(...)`.

**Skip if:** System prompt is a string literal, loaded from a bundled resource file shipped in the deploy artifact, or read from a checksummed config.

**Remediation:** System prompts should be code-shipped constants or loaded from versioned, signed config. Never from user-controllable network reads.

### `AS-C-D-LLM02-001` — Hardcoded API credentials in source

**Severity:** critical · **Languages:** any · **Legacy ID:** `TIER2-LLM02-01`

**Frameworks:** `OWASP LLM LLM02` `CWE CWE-798`

**What it flags:** Literal credential strings passed to LLM SDK constructors or builders. Patterns include OpenAI `api_key="sk-..."`, Anthropic `api_key="sk-ant-..."`, AWS `aws_access_key_id="AKIA..."`, Azure `AzureKeyCredential("...")`, Google `genai.configure(api_key="...")`, langchain4j builder `.apiKey("...")`, Spring AI `OpenAiApi("...")`, HuggingFace `token="hf_..."`.

**Skip if:** Credential is loaded from `os.environ`, AWS Secrets Manager, Azure Key Vault, GCP Secret Manager, HashiCorp Vault, or a Spring `@Value` bean from `application.yml` (which is itself externalised).

**Remediation:** Environment variables for dev / Secrets Manager for prod. Add a CI step that scans for credential patterns (gitleaks, trufflehog).

### `AS-C-D-LLM02-002` — Sensitive data in LLM prompt

**Severity:** high · **Languages:** any · **Legacy ID:** `TIER2-LLM02-02`

**Frameworks:** `OWASP LLM LLM02` `OWASP Agentic T8` `CWE CWE-200`

**What it flags:** Database rows, customer records, PII fields (SSN, credit-card, account number, email, address), session tokens, or internal-system identifiers being concatenated into a prompt without scrubbing. Flag if you see column names like `ssn`, `pan`, `cvv`, `password_hash`, `oauth_token`, `email`, `phone`, `dob`, `routing_number` flowing into prompt construction.

**Skip if:** Field is hashed, masked (`****1234`), or replaced via a scrubber before prompt construction.

**Remediation:** Scrub PII before prompt construction. Pass only the minimum data the LLM needs to do its task.

### `AS-C-D-LLM03-001` — Unpinned model loading (was D007)

**Severity:** medium · **Languages:** python, any · **Legacy ID:** `TIER2-LLM03-01`

**Frameworks:** `CWE CWE-494` `CWE CWE-829`

**What it flags:** `from_pretrained(...)` / `hf_hub_download(...)` / `snapshot_download(...)` from `transformers`, `diffusers`, `sentence_transformers`, `huggingface_hub` without a `revision=` git SHA pin. `AutoModel.from_pretrained("org/model")` without revision.

**Skip if:** A `revision=<sha>` keyword is passed; or the model name is a local file path; or the call is in test code (pytest fixtures).

**Remediation:** Pin to a git SHA. Mirror critical models to internal S3 / Artifactory and load from there.

### `AS-C-D-LLM03-002` — Untrusted plugin / tool registration

**Severity:** high · **Languages:** any · **Legacy ID:** `TIER2-LLM03-02`

**Frameworks:** `OWASP LLM LLM06` `OWASP Agentic T2` `OWASP Agentic T11` `MITRE ATLAS AML.T0053`

**What it flags:** Tool/plugin loaded by URL or runtime-discovered from an external registry. Patterns: `load_tools(["plugin-name"])` from an external manifest, `MCPServer(url=...)` where URL is dynamic, langchain4j `ToolSpecification` populated from a remote schema fetch.

**Skip if:** Tools are explicit imports / class declarations in this same codebase.

**Remediation:** Allowlist plugin sources. Pin plugin versions. Treat every plugin as security-critical code in your own repo.

### `AS-C-D-LLM04-001` — Training-data / fine-tuning input poisoning

**Severity:** high · **Languages:** any · **Legacy ID:** `TIER2-LLM04-01`

**Frameworks:** `MITRE ATLAS AML.T0019`

**What it flags:** Fine-tuning, embeddings indexing, or RAG corpus build pulling from user-uploaded files, public web scrapes, or untrusted S3 prefixes without provenance checks. `OpenAIFineTuningJob`, `Bedrock CustomModel`, vector-store `add_documents(...)` with user-supplied docs.

**Skip if:** Documents go through a content moderation / classifier step before ingestion.

**Remediation:** Allowlist document sources. Run a classifier on ingestion. Keep an audit trail of every document that touched the training set.

### `AS-C-D-LLM05-001` — LLM output → code execution sink

**Severity:** critical · **Languages:** any · **Legacy ID:** `TIER2-LLM05-01`

**Frameworks:** `OWASP LLM LLM05` `OWASP Agentic T2` `OWASP Agentic T11` `MITRE ATLAS AML.T0050` `CWE CWE-78` `CWE CWE-89` `CWE CWE-94`

**What it flags:** LLM response (return value of a chain / model / agent call) flowing into `eval()`, `exec()`, `os.system()`, `subprocess.*` with `shell=True`, `Runtime.exec(...)`, `ProcessBuilder(...).start()`, `ScriptEngine.eval(...)`, `Statement.executeQuery()` / `.executeUpdate()` with string-concat SQL, or any other code/command interpreter.

**Skip if:** Output is parsed through a typed schema (`pydantic`, `BaseModel`, JSON-schema validator, `RootCauseOutput(**parsed)`) before reaching the sink, AND the sink only sees declared-type fields.

**Remediation:** Never pass LLM output to any interpreter. Parse to a strict schema first. For SQL, use parameterised queries — never string-concat.

### `AS-C-D-LLM05-002` — LLM output rendered as HTML / Markdown without escaping

**Severity:** high · **Languages:** any · **Legacy ID:** `TIER2-LLM05-02`

**Frameworks:** `OWASP LLM LLM05` `CWE CWE-79` `CWE CWE-94`

**What it flags:** LLM response inserted into HTML template (`{{ response }}` in Jinja2 with autoescape disabled, Spring `@ResponseBody String` with HTML content-type, React `dangerouslySetInnerHTML={{ __html: response }}`).

**Skip if:** Output is sanitised with `bleach.clean()`, `html.escape()`, `OWASPEncoder.forHtml()`, DOMPurify, or a CSP-locked iframe.

**Remediation:** Treat LLM output as untrusted user input. Apply the same escaping you'd apply to a form submission.

### `AS-C-D-LLM08-001` — Embedding model unpinned or untrusted

**Severity:** medium · **Languages:** any · **Legacy ID:** `TIER2-LLM08-01`

**Frameworks:** `CWE CWE-829`

**What it flags:** `SentenceTransformer("...")`, `HuggingFaceEmbeddings(model_name="...")`, OpenAI `embeddings.create(model="text-embedding-3-small")` without pinning; or model name read from runtime env without validation.

**Skip if:** Embedding model is pinned to a SHA / known-good version.

**Remediation:** Pin embedding model versions. Periodically validate retrieval quality on a known-answer eval set.

---

## 🟡 Defend (21)

### `AS-C-DF-AGENTIC_T10-001` — High-volume HITL request fatigue

**Severity:** low · **Languages:** any · **Legacy ID:** `TIER2-AGENTIC-T10-01`

**Frameworks:** `OWASP Agentic T10`

**What it flags:** HITL approval gates wired on routine actions (e.g. every read query needs approval). Reviewers will rubber-stamp.

**Skip if:** HITL is reserved for destructive / high-impact actions.

**Remediation:** Reserve HITL for actions with real stakes. Use rate-limiting and policy auto-approval for routine reads.

### `AS-C-DF-AGENTIC_T3-001` — Agent runs with broader perms than user

**Severity:** high · **Languages:** any · **Legacy ID:** `TIER2-AGENTIC-T3-01`

**Frameworks:** `OWASP Agentic T3` `OWASP LLM LLM06` `CWE CWE-732`

**What it flags:** Agent / service-account credentials with write access to resources beyond what the requesting user has. Hardcoded admin / root tokens, IAM roles with `*` resource ARNs, DB connections with `superuser` privileges.

**Skip if:** Agent uses the requesting user's identity (delegated auth, on-behalf-of token).

**Remediation:** Run agents with least-privilege service accounts. Use delegated auth (OAuth on-behalf-of, AWS STS AssumeRoleWithWebIdentity).

### `AS-C-DF-AGENTIC_T4-001` — Unbounded recursion / agent loops

**Severity:** high · **Languages:** any · **Legacy ID:** `TIER2-AGENTIC-T4-01`

**Frameworks:** `OWASP Agentic T4` `OWASP LLM LLM10` `CWE CWE-400`

**What it flags:** Agent loops without a max-iterations cap. LangChain `AgentExecutor(max_iterations=None)` or no max set, LangGraph `Graph(recursion_limit=None)`, custom while-loops calling LLM with no break condition tied to step count.

**Skip if:** Explicit `max_iterations` / `recursion_limit` is set to a finite integer ≤ 50.

**Remediation:** Set explicit recursion / iteration caps. Alert on agents that hit the cap.

### `AS-C-DF-AGENTIC_T4-002` — No timeout on tool call

**Severity:** medium · **Languages:** any · **Legacy ID:** `TIER2-AGENTIC-T4-02`

**Frameworks:** `OWASP Agentic T4` `CWE CWE-400`

**What it flags:** Tools that call external APIs / DBs / LLMs without a timeout on the underlying call. Especially: HTTP `requests.get(url)` without `timeout=`, JDBC `executeQuery()` without `setQueryTimeout`.

**Skip if:** Timeout set explicitly.

**Remediation:** Always set timeouts. Use circuit breakers for external dependencies.

### `AS-C-DF-AGENTIC_T4-003` — No circuit breaker / kill switch on agent loop

**Severity:** medium · **Languages:** any · **Legacy ID:** `TIER2-AGENTIC-T4-03`

**Frameworks:** `OWASP Agentic T4` `OWASP Agentic T8` `OWASP LLM LLM10`

**What it flags:** An agent loop / planner / `while`-style retry that has no failure-counting circuit breaker and no externally-triggerable kill switch. Symptoms: LangGraph graph with no `recursion_limit=`; custom `while True:` planner with no consecutive-failure cap; no `agent.stop()` / `kill_switch` / `cancellation_token` reachable from outside the loop; no degraded-mode fallback when a downstream tool repeatedly errors.

**Skip if:** A circuit-breaker library is in use (`pybreaker`, Resilience4j) on the tool calls AND a graph-level recursion limit is set AND an out-of-band stop signal is wired (SIGTERM handler, feature flag, queue-drain on toggle).

**Remediation:** Wrap tool calls in a circuit breaker that opens after N consecutive failures. Set graph `recursion_limit=` (LangGraph) or planner-iteration cap. Expose a kill switch (feature-flag / SQS-drain / SIGTERM handler) that drains in-flight calls and refuses new ones. Decay agent trust scores over time so silent failure modes (no traffic, no errors) don't accumulate permission.

### `AS-C-DF-AGENTIC_T9-001` — Agent-to-system auth uses static token

**Severity:** medium · **Languages:** any · **Legacy ID:** `TIER2-AGENTIC-T9-01`

**Frameworks:** `OWASP Agentic T9` `OWASP Agentic T3` `CWE CWE-798`

**What it flags:** Agent identifies to downstream systems via a static shared token / API key rather than per-request signed credentials or short-lived tokens.

**Skip if:** Agent uses STS / OIDC / mTLS / signed JWT with short TTL.

**Remediation:** Use STS AssumeRole, OIDC tokens, or signed JWTs with TTL ≤ 1h.

### `AS-C-DF-AGENTIC_T9-002` — Self-promoting agent (modifies its own role / trust)

**Severity:** high · **Languages:** any · **Legacy ID:** `TIER2-AGENTIC-T9-02`

**Frameworks:** `OWASP Agentic T9` `OWASP Agentic T3` `OWASP LLM LLM06` `CWE CWE-269`

**What it flags:** Code where an agent / agent loop writes to its own role, trust score, capability list, or scope without external attestation. Symptoms: `self.role = ...`, `agent.permissions.add(...)`, `trust_registry.set(self.id, ...)`, `self.capabilities += ...`, agent code calling its own `/api/grant-role` or equivalent. The decisive question: who is the *writer*? If the same agent that's bound to the identity can mutate the identity's authority, the privilege model is broken.

**Skip if:** Privilege/role changes go through a separate identity service that requires a signed attestation (human approval, SRE witness, OIDC step-up, hardware-key). If the writer is a different process with its own credentials, it's not self-promotion.

**Remediation:** Privilege state lives in an external authority (IAM, OPA, identity service) that the agent reads but cannot write. Promotions require an attestation from a different principal (human + hardware key, or a deterministic policy that the agent cannot influence). Log every promotion attempt, even denied ones.

### `AS-C-DF-AGENTIC_T9-003` — Inter-agent message accepted without identity verification

**Severity:** high · **Languages:** any · **Legacy ID:** `TIER2-AGENTIC-T9-03`

**Frameworks:** `OWASP Agentic T9` `OWASP Agentic T5` `OWASP LLM LLM06`

**What it flags:** Multi-agent code (CrewAI `Crew(...)`, LangGraph supervisor / handoffs, AutoGen `GroupChat`, custom `accept_task` / `dispatch` / `handle_message` handlers) where one agent processes a task / plan / instruction from another agent without checking who sent it. Specifically: no signature verification, no trust score check, no allowlist of accepted senders, no scope-narrowing on delegation.

**Skip if:** Inter-agent messages are signed (Ed25519, JWT, mTLS) AND the receiver verifies the signature AND a trust-threshold check exists before the action runs. Single-process toy demos (`if __name__ == "__main__"`) get a pass.

**Remediation:** Each agent gets its own identity (DID / signed token / mTLS cert). Receivers verify the sender's signature before acting. Delegation must narrow scope: a child task's capability set ⊆ parent's. Reject (with audit log) any message from an unknown or low-trust sender.

### `AS-C-DF-AGENTIC_T9-004` — Agent identified by string name, not crypto identity

**Severity:** medium · **Languages:** any · **Legacy ID:** `TIER2-AGENTIC-T9-04`

**Frameworks:** `OWASP Agentic T9` `CWE CWE-287` `CWE CWE-322`

**What it flags:** Agent identity carried as a bare string — `agent_name = "billing-agent"`, `Agent(name="research-bot")`, audit-log `agent_id` populated from a config string with no cryptographic backing. No DID (`did:web:`, `did:key:`), no per-agent key material, no signing of inter-agent messages or audit entries.

**Skip if:** The agent has a unique cryptographic identity (Ed25519 keypair, JWK, mTLS cert) AND tool calls / audit entries / inter- agent messages are signed with that key.

**Remediation:** Issue per-agent keypairs at provisioning. Sign audit entries (hash-chained) and inter-agent messages with the agent's key. Verify on receipt. Treat the keypair as the source of truth for identity; the human-readable name is a label for operators, not a security primitive.

### `AS-C-DF-CWE_400-001` — Resource Consumption

**Severity:** medium · **Languages:** any · **Legacy ID:** `TIER2-CWE-400-01`

**Frameworks:** `CWE CWE-400` `OWASP LLM LLM10` `OWASP Agentic T4`

**What it flags:** Cross-references LLM10-01 / AGENTIC-T4-01 / T4-02. No timeouts, no token caps, no recursion limits.

**Remediation:** Set limits everywhere external calls happen.

### `AS-C-DF-CWE_732-001` — Incorrect Permission Assignment

**Severity:** medium · **Languages:** any · **Legacy ID:** `TIER2-CWE-732-01`

**Frameworks:** `CWE CWE-732` `OWASP LLM LLM06` `OWASP Agentic T3`

**What it flags:** Cross-references LLM06-02. Tools / agents over-permissioned.

**Remediation:** Least privilege.

### `AS-C-DF-GAP-001` — No explicit LLM call timeout

**Severity:** medium · **Languages:** any · **Legacy ID:** `TIER2-GAP-04`

**Frameworks:** `OWASP LLM LLM10` `CWE CWE-400`

**What it flags:** LLM call sites that rely on framework / SDK default timeouts rather than setting one explicitly. For Spring AI: missing `spring.ai.<provider>.timeout` in `application.yml` or no `.requestTimeout(...)` on the builder. Same for langchain4j / Bedrock.

**Skip if:** Explicit timeout set anywhere in the call's setup chain.

**Remediation:** Set explicit per-call or per-builder timeouts.

### `AS-C-DF-LLM06-001` — Tool registered with destructive verb / no approval gate

**Severity:** high · **Languages:** any · **Legacy ID:** `TIER2-LLM06-01`

**Frameworks:** `OWASP LLM LLM06` `OWASP Agentic T2` `OWASP Agentic T10`

**What it flags:** `@tool`, `@Tool`, `Tool(...)`, `StructuredTool(...)` decorated functions/methods whose name starts with destructive verbs (`delete_*`, `send_*`, `charge_*`, `deploy_*`, `transfer_*`, `revoke_*`, `purge_*`, `cancel_*`) and whose body has no `confirm()` / `requireApproval()` / `HumanApprovalCallbackHandler` / LangGraph `interrupt_before=` gate.

**Skip if:** A confirmation step is present, or the tool's side-effects are reversible (read-only, idempotent puts).

**Remediation:** Require approval before destructive actions. For LangChain, wire a `HumanApprovalCallbackHandler`. For LangGraph, use `interrupt_before` on destructive nodes.

### `AS-C-DF-LLM06-002` — Broad tool permissions (was D006)

**Severity:** medium · **Languages:** any · **Legacy ID:** `TIER2-LLM06-02`

**Frameworks:** `OWASP LLM LLM06` `OWASP Agentic T2` `OWASP Agentic T3` `CWE CWE-732`

**What it flags:** Tools registered with broad filesystem / HTTP / shell access. Patterns: `FileManagementToolkit` without `selected_tools=`, `RequestsToolkit(allow_dangerous_requests=True)`, `ShellTool`, `BashProcess`, langchain4j @Tool wrapping `Files.delete` / `Files.write` / unrestricted `RestTemplate.put` / `RestTemplate.delete`.

**Skip if:** The toolkit is constrained (`selected_tools=[ReadOnlyTool]`, filesystem rooted to a sandbox dir, HTTP host allowlist applied before request).

**Remediation:** Constrain toolkits to the minimum verbs the agent needs. Use sandbox roots for file ops. Allowlist hosts for HTTP.

### `AS-C-DF-LLM06-003` — Tool without args schema (was DF002)

**Severity:** low · **Languages:** any · **Legacy ID:** `TIER2-LLM06-03`

**Frameworks:** `OWASP LLM LLM06` `OWASP Agentic T2`

**What it flags:** Langchain `Tool(...)` / `StructuredTool(...)` / `@tool`-decorated function with no `args_schema=` Pydantic model. Java langchain4j / Spring AI `@Tool` methods with bare `String` parameters and no `@P(description=...)` / `@ToolParam` annotation.

**Skip if:** Schema is provided, or the tool is internal (not exposed to LLM-driven planning).

**Remediation:** Always provide an args schema. Pydantic for langchain Python; `@P` / `@ToolParam` for Java.

### `AS-C-DF-LLM06-004` — LLM call inside the permission-decision path

**Severity:** high · **Languages:** any · **Legacy ID:** `TIER2-LLM06-04`

**Frameworks:** `OWASP LLM LLM06` `OWASP Agentic T2` `OWASP Agentic T9`

**What it flags:** A function whose name or return value indicates an authorisation gate (`is_allowed`, `can_<verb>`, `check_permission`, `authorize`, returns `bool` / `Decision` / "allow"|"deny") that internally calls an LLM (`chat.completions.create`, `chain.invoke`, `client.messages.create`, `bedrock.invoke_model`) to make the decision. Includes "ask the LLM if this action is safe" patterns.

**Skip if:** The LLM call is for *explanation* of an already-made deterministic decision (e.g. "tell the user why this was denied"), or the LLM result is one signal among many fed into a deterministic rule.

**Remediation:** Move authorisation to a deterministic rules engine (OPA, Cedar, hand-rolled predicate). The LLM may *propose* an action; a non-LLM gate must *approve* it. If you need natural-language reasoning in the audit trail, log it as rationale alongside the deterministic decision — don't let it be the decision.

### `AS-C-DF-LLM06-005` — Lookalike / shadow tool names registered

**Severity:** medium · **Languages:** any · **Legacy ID:** `TIER2-LLM06-05`

**Frameworks:** `OWASP LLM LLM06` `OWASP Agentic T2` `OWASP Agentic T6`

**What it flags:** Two or more tools registered to the same agent whose names differ only by a typosquat-shaped suffix or character swap (`cancel_subscription` + `cancel_subscription_v2`, `read_file` + `read__file`, `send_email` + `send_email_internal`). Especially suspicious when the lookalike has broader permissions than the original. Borrowed from Cisco AI-Defense's "tool shadowing" category.

**Skip if:** The two tools are clearly versioned (`v1` is deprecated and unregistered before runtime) or one is gated behind a different capability flag and unreachable from the planner.

**Remediation:** Enforce unique tool names at registration time (`assert name not in registry`). Run a Levenshtein-distance check in CI on the registered tool list. Remove deprecated versions rather than leaving them registered alongside their replacement.

### `AS-C-DF-LLM08-001` — Vector store query without auth boundary

**Severity:** medium · **Languages:** any · **Legacy ID:** `TIER2-LLM08-02`

**Frameworks:** `OWASP Agentic T3` `CWE CWE-200`

**What it flags:** Pinecone / Weaviate / Chroma / OpenSearch / Postgres pgvector queries that don't filter by tenant / user / authorisation scope. `collection.query(query=embedding, k=5)` with no `filter=` arg in a multi-tenant codebase.

**Skip if:** Filter expression includes `tenant_id` / `user_id` / `org_id` / namespace / schema scoping.

**Remediation:** Always include the requesting user/tenant in the vector query filter. Test with adversarial tenant IDs.

### `AS-C-DF-LLM09-001` — Confidence not surfaced to consumer

**Severity:** info · **Languages:** any · **Legacy ID:** `TIER2-LLM09-01`

**Frameworks:** `OWASP Agentic T5`

**What it flags:** LLM response returned to a downstream consumer (UI, another service, automated decision pipeline) without any uncertainty signal — no `logprobs` capture, no self-evaluation prompt, no "I'm not sure" parser. This is harder to detect statically; flag if (a) the call is in a high-stakes context (medical, financial, legal) AND (b) the output is treated as ground truth.

**Skip if:** Output is reviewed by a human before action, or evaluated by a second LLM/classifier.

**Remediation:** Capture and propagate confidence (logprobs / scoring). Use a separate verification model for high-stakes outputs.

### `AS-C-DF-LLM10-001` — No timeout / token cap on LLM call

**Severity:** medium · **Languages:** any · **Legacy ID:** `TIER2-LLM10-01`

**Frameworks:** `OWASP LLM LLM10` `OWASP Agentic T4` `CWE CWE-400`

**What it flags:** LLM SDK clients constructed with `timeout=None`, `max_tokens=None`, `Duration.ZERO`, OkHttp `connectTimeout(0, SECONDS)`, Spring AI without `spring.ai.<provider>.timeout` set, AWS Bedrock `apiCallTimeout(Duration.ZERO)`.

**Skip if:** Explicit timeout > 0 and `max_tokens` set to a finite value.

**Remediation:** Set explicit timeouts (5-60s typical) and `max_tokens` (~2000-8000 typical).

### `AS-C-DF-LLM10-002` — Missing guardrails import (was DF001)

**Severity:** medium · **Languages:** any · **Legacy ID:** `TIER2-LLM10-03`

**Frameworks:** `OWASP LLM LLM01` `OWASP LLM LLM05` `OWASP LLM LLM10` `OWASP Agentic T6`

**What it flags:** A file that invokes an LLM AND has no guardrail mechanism visible across the file. "Guardrail mechanism" includes: import of NeMo Guardrails / Lakera / Rebuff / Guardrails-AI / Presidio / Llama Guard, OWASP Encoder / Apache Commons Text in Java, Spring AI `.advisors(...)` / `.defaultAdvisors(...)` wiring, in-house classes whose name ends in `Advisor` / `Guardrail` / `Scrubber` / `Sanitizer`, or a `callbacks=...` kwarg with a guardrail callback class.

**Skip if:** ANY of the above is present in the file OR an obviously related file in the same package (e.g. ChatService.java has the advisor wiring; SchedulingService.java just calls chatService — inherit the guardrail intent).

**Remediation:** Add a guardrail layer at the LLM call site or via a configuration-time advisor wiring. --- # §2. OWASP Agentic AI Top 10 Specific to multi-step agent codebases (planners, tool callers, memory). Use the `owasp_agentic` array to mark T1–T11. ---

---

## 🔵 Respond (13)

### `AS-C-R-AGENTIC_T7-001` — No alignment evaluation hook (LLM-as-a-judge)

**Severity:** info · **Languages:** any · **Legacy ID:** `TIER2-AGENTIC-T7-01`

**Frameworks:** `OWASP Agentic T7`

**What it flags:** Agent loop with no internal evaluation hook — no LLM-as-a-judge step, no eval-agent callback, no langsmith / langfuse trace, no rubric-scored regression set, no "did the agent's actions match the user's intent" check. Hard to detect statically; flag in high-stakes contexts.

**Skip if:** An internal LLM-as-a-judge (or second LLM / classifier) scores the agent's plan or output before it is acted on, OR a scheduled offline eval set is run pre-deploy.

**Remediation:** Add an internal LLM-as-a-judge (a second LLM that scores each agent run against an intent/safety rubric), or stand up a scheduled offline eval suite. If neither exists yet, plan for one — even sampling outputs into a manual review queue is a valid first step.

### `AS-C-R-AGENTIC_T8-001` — No audit trail of agent decisions

**Severity:** medium · **Languages:** any · **Legacy ID:** `TIER2-AGENTIC-T8-01`

**Frameworks:** `OWASP Agentic T8` `OWASP LLM LLM10` `MITRE ATLAS AML.T0024`

**What it flags:** Agent step (planner output, tool call decision, tool result) not logged anywhere. The audit trail must include WHAT the agent decided, not just WHEN it called the LLM.

**Skip if:** A trace library (langsmith, opentelemetry, custom audit logger) captures planner decisions + tool args.

**Remediation:** Log every planner decision, tool call (with args), tool result. Structured JSON; queryable.

### `AS-C-R-ATLAS_T0024-001` — Exfiltration via ML inference API

**Severity:** high · **Languages:** any · **Legacy ID:** `TIER2-ATLAS-T0024-01`

**Frameworks:** `MITRE ATLAS AML.T0024` `OWASP LLM LLM02` `CWE CWE-200`

**What it flags:** Inference API endpoints that return raw model internals (logprobs, hidden states, embeddings) to untrusted callers, enabling model-extraction attacks.

**Remediation:** Don't return raw model internals to untrusted clients. Add rate limits + cost caps to inference endpoints.

### `AS-C-R-CWE_200-001` — Information Exposure

**Severity:** medium · **Languages:** any · **Legacy ID:** `TIER2-CWE-200-01`

**Frameworks:** `CWE CWE-200` `OWASP LLM LLM02`

**What it flags:** Verbose error responses returned to clients with stack traces, internal hostnames, DB connection strings, file paths.

**Skip if:** Errors filtered through a sanitiser before response serialisation.

**Remediation:** Generic error messages to clients; full detail to server logs only.

### `AS-C-R-CWE_532-001` — Log Information Exposure

**Severity:** medium · **Languages:** any · **Legacy ID:** `TIER2-CWE-532-01`

**Frameworks:** `CWE CWE-532` `OWASP LLM LLM02`

**What it flags:** Cross-references LLM02-03. Sensitive data in log statements.

**Remediation:** Redact / hash before logging.

### `AS-C-R-GAP-001` — User input logged before scrubbing

**Severity:** medium · **Languages:** any · **Legacy ID:** `TIER2-GAP-01`

**Frameworks:** `OWASP LLM LLM02` `OWASP LLM LLM10` `OWASP Agentic T8` `CWE CWE-532`

**What it flags:** Web controllers that log the request body / message field BEFORE passing it to a scrubber. Specifically: `log.info("Received chat request | message={}", request.message())` in a method that LATER calls `scrubberService.scrubPii(...)`.

**Skip if:** Log call comes after scrub, or logs only message length / hash.

**Remediation:** Move the log call after the scrub, or log only `message_length=` / `message_hash=`.

### `AS-C-R-GAP-002` — Scrubber bypass on oversized inputs

**Severity:** high · **Languages:** any · **Legacy ID:** `TIER2-GAP-02`

**Frameworks:** `OWASP LLM LLM02` `CWE CWE-200`

**What it flags:** Scrubber / sanitiser methods with a "skip if too big" branch: `if len(text) > MAX_LEN: return text` (or `text[:MAX_LEN]` without scrubbing). Detection focus: methods named `scrub*`, `sanitize*`, `redact*`, `filter*`, `clean*`.

**Skip if:** Oversized input is rejected (raise / throw / return None) rather than passed through unscrubbed.

**Remediation:** Reject or chunk-and-scrub. Never pass through unscrubbed because it was too big.

### `AS-C-R-GAP-003` — SAML / auth artifacts in logs

**Severity:** high · **Languages:** any · **Legacy ID:** `TIER2-GAP-03`

**Frameworks:** `CWE CWE-532` `CWE CWE-200`

**What it flags:** SAML assertions, OAuth tokens, session cookies, JWT bearer tokens being logged. `log.info("assertion={}", samlAssertion)`, `log.info("token={}", bearerToken)`.

**Skip if:** Logged value is a short fingerprint / hash rather than the raw artifact.

**Remediation:** Log auth-artifact metadata (issuer, expiry, subject) not raw token/assertion values.

### `AS-C-R-GAP-004` — LLM output → SNS / email / webhook without scrubbing

**Severity:** high · **Languages:** any · **Legacy ID:** `TIER2-GAP-05`

**Frameworks:** `OWASP LLM LLM02` `CWE CWE-200`

**What it flags:** Cross-references LLM02-04. Specifically: in agent pipelines, the FINAL step (notification, alerting, ticket creation) often takes raw LLM output. `SnsClient.publish(llmOutput)`, `mailer.send(subject, llmOutput)`.

**Skip if:** Output passes through `scrubPii` or equivalent before the publish call.

**Remediation:** Output scrubber called immediately before any external publish. --- # §6. Retired Tier 1 anti-patterns Coverage equivalent to the 8 rule families retired in Phase F.2, kept here so Tier 2 doesn't lose ground when Tier 1 narrows. Most are already covered in §1–§4 above (cross-referenced). This section just lists the rule-family-level checks for the retired rules so coverage parity is auditable. | Retired rule | Covered by | |---|---| | D001-fb (fallback verb shape) | TIER2-LLM01-01 | | D002 (untrusted document loader) | TIER2-LLM01-02 | | D006 (broad tool permissions) | TIER2-LLM06-02 | | D007 (unpinned model) | TIER2-LLM03-01 | | DF001 (no guardrails import) | TIER2-LLM10-03 | | DF002 (no @Tool args schema) | TIER2-LLM06-03 | | DF004 (destructive verb naming) | TIER2-LLM06-01 | | R001 (no audit logging) | TIER2-LLM10-02 | If you find an instance of a retired-rule anti-pattern that doesn't match the cross-referenced check above, emit it under the retired-rule ID with a `notes` field explaining why none of the cross-refs applied. --- # §7. Tier 1 cross-check After scanning every file, read `.agentshield/tier1-results.json`. For each finding in Tier 1, decide: - **TP** (true positive) — Tier 1 is right; the issue is real. Don't emit a callout (Tier 1 already reported it).

### `AS-C-R-LLM02-001` — Raw LLM I/O in logs (was R002)

**Severity:** medium · **Languages:** any · **Legacy ID:** `TIER2-LLM02-03`

**Frameworks:** `OWASP LLM LLM02` `OWASP LLM LLM10` `OWASP Agentic T8` `CWE CWE-532`

**What it flags:** `log.info(...)`, `logger.warn(...)`, `print(...)`, `System.out.println(...)`, structured logger calls where the value being logged is (a) the user prompt, (b) the LLM response, (c) any field carrying user-supplied content. Particularly: `log.info("User asked: {}", request.message())` style.

**Skip if:** The logged value is a hash, length, or output of a scrubber (`redact()`, `mask()`, `anonymize()`, `scrubPii()`, Presidio `AnonymizerEngine`, `MessageDigest.digest`, `len()`, `.length()`).

**Remediation:** Hash, length-only-project, or redact via Presidio before logging. For Spring AI, use the `ScrubbingCallAdvisor` pattern on both directions of the chain.

### `AS-C-R-LLM02-002` — Sensitive data egress via SNS/email/HTTP sink

**Severity:** high · **Languages:** any · **Legacy ID:** `TIER2-LLM02-04`

**Frameworks:** `OWASP LLM LLM02` `OWASP Agentic T8` `CWE CWE-200`

**What it flags:** LLM output flowing into an external sink without scrubbing. Sinks: AWS `SnsClient.publish()`, JavaMail `Transport.send()`, AWS SES `send_email()`, Slack/Teams webhook POSTs, generic HTTP POST to external host, queueing systems (Kafka producer, RabbitMQ publish). This is what the rule pack didn't cover and Phase E judge surfaced.

**Skip if:** A scrubber call (`scrubPii`, `redact`, `mask`) is in the same flow before the sink call.

**Remediation:** Apply output scrubbing before any external publish. Apply at the edge (publishers) not at the LLM call site, since the call site is far from the eventual recipient.

### `AS-C-R-LLM07-001` — System prompt logged or returned in response

**Severity:** medium · **Languages:** any · **Legacy ID:** `TIER2-LLM07-01`

**Frameworks:** `OWASP LLM LLM07` `CWE CWE-200`

**What it flags:** System prompt string ending up in (a) a log line, (b) an HTTP response body, (c) an error message returned to the user, (d) a stack trace propagated outward.

**Skip if:** System prompt is referenced only for debug-mode logging guarded by a feature flag.

**Remediation:** Never log the system prompt at INFO. Strip it from error responses. Treat it as a secret.

### `AS-C-R-LLM10-001` — No audit logging around LLM call (was R001)

**Severity:** medium · **Languages:** any · **Legacy ID:** `TIER2-LLM10-02`

**Frameworks:** `OWASP LLM LLM10` `OWASP Agentic T8` `MITRE ATLAS AML.T0024`

**What it flags:** LLM call (`chain.invoke`, `runner.run`, `chatClient...call()`, `client.invokeModel`, etc.) in a method that has no surrounding logger setup or call. Look for: any `logger.info/warn/error` near the call, structured-logging library imports (structlog, langsmith, opentelemetry, langchain.callbacks), Lombok `@Slf4j`, stdlib `logger = logging.getLogger(__name__)`, or `callbacks=...` kwarg.

**Skip if:** Any logger setup or call is present in the file. R001 was retired as a Tier 1 rule because it kept FP-ing on files that DID have logging — Tier 2 reads context, so be lenient here.

**Remediation:** Add structured logging around every LLM call: prompt (hashed), model id, latency, token counts, tool calls made, output (hashed). Use OpenTelemetry traces for distributed apps.

---

## Related

- AgentShield repo: https://github.com/suganthiaravind/agentshield
- For the live, full rule list across all three sources, run `agentshield merge --output-html report.html` and open the **Reference tab** of the generated report.

