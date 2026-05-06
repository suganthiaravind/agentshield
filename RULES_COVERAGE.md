# Rules Coverage

Status: 2026-05-06 (Phase F architecture v2 shipped)
Companion to: [ARCHITECTURE_V2.md](./ARCHITECTURE_V2.md), [GLOSSARY.md](./GLOSSARY.md), [REMEDIATION_PATTERNS.md](./REMEDIATION_PATTERNS.md), [TIER2_USAGE.md](./TIER2_USAGE.md), [README.md](./README.md)

> ## ⚠ v2 architecture note
>
> Phase F (2026-05-06) collapsed the rule pack from **14 → 6 high-precision families** and moved the rest into the **Tier 2 LLM-as-scanner checklist** at [`agentshield/skills/tier2_checklist.md.tmpl`](./agentshield/skills/tier2_checklist.md.tmpl).
>
> This doc still describes the patterns each rule looked for — useful as historical reference and for understanding the v2 Tier 2 checks (which inherit each retired rule's anti-pattern). Sections below are tagged:
>
> - 🟢 **[ACTIVE]** — Tier 1 semgrep rule, loaded by `agentshield scan`
> - 🔴 **[RETIRED in F.2]** — moved to `agentshield/_retired_v2/` + folded into Tier 2 checklist (see [ARCHITECTURE_V2.md §3](./ARCHITECTURE_V2.md#3-tier-1--pruned-rule-pack) for retirement reasoning)
>
> **Want to know what Tier 2 covers?** See the bundled checklist for OWASP LLM v2 (10 items) + OWASP Agentic AI Top 10 (11 items) + MITRE ATLAS + CWE first-class — 56 checks total. The cross-reference table in §6 of this doc maps retired rules to their Tier 2 successor IDs.

> **Need to fix a finding?** [REMEDIATION_PATTERNS.md](./REMEDIATION_PATTERNS.md) shows worked BAD / GOOD code examples for every rule in this doc, in both Python and Java.

This document lists every bundled AgentShield rule and the LLM frameworks, SDKs, and libraries it knows how to recognize. Use it to answer: *"if my repo uses framework X, will AgentShield catch the things it should?"*

Source of truth is the YAML under [agentshield/rules/](./agentshield/rules/) for active rules and [agentshield/_retired_v2/rules/](./agentshield/_retired_v2/rules/) for archived ones — this doc summarizes the patterns; if a rule is updated and this doc isn't, the rule wins.

## Contents

- [1. How to read this doc](#1-how-to-read-this-doc)
- [2. Coverage at a glance](#2-coverage-at-a-glance)
- [3. Detect rules](#3-detect-rules)
  - 🟢 [D001 (Python, framework) — unsanitized user input → LLM](#d001-python-framework--unsanitized-user-input--llm)
  - 🔴 [D001 (Python, fallback)](#d001-python-fallback--llm-shaped-verb-in-an-llm-importing-file) — retired in F.2
  - 🟢 [D001 (Java, framework) — unsanitized user input → LLM](#d001-java-framework--unsanitized-user-input--llm)
  - 🔴 [D001 (Java, fallback)](#d001-java-fallback--llm-shaped-verb-in-an-llm-importing-file) — retired in F.2
  - 🔴 [D002](#d002-python--untrusted-document-loader--rag) — retired in F.2 (Tier 2: TIER2-LLM01-02)
  - 🟢 [D003 (Python) — code-execution tool registered](#d003-python--code-execution-tool-registered)
  - 🟢 [D003 (Java) — code-execution tool registered](#d003-java--code-execution-tool-registered)
  - 🟢 [D004 (Python) — LLM output → code execution](#d004-python--llm-output--code-execution)
  - 🟢 [D004 (Java) — LLM output → code execution / SQL](#d004-java--llm-output--code-execution--sql)
  - 🟢 [D005 (Python) — hardcoded LLM credentials](#d005-python--hardcoded-llm-credentials)
  - 🟢 [D005 (Java) — hardcoded LLM credentials](#d005-java--hardcoded-llm-credentials)
  - 🔴 [D006](#d006-python--broad-tool-permissions) — retired in F.2 (Tier 2: TIER2-LLM06-02)
  - 🔴 [D007](#d007-python--untrusted-model-loading) — retired in F.2 (Tier 2: TIER2-LLM03-01)
  - 🟢 [D008 (Python) — untrusted system prompt](#d008-python--untrusted-system-prompt)
  - 🟢 [D008 (Java) — untrusted system prompt](#d008-java--untrusted-system-prompt)
- [4. Defend rules](#4-defend-rules)
  - 🔴 [DF001](#df001-python--llm-call-with-no-guardrails-import) — retired in F.2 (Tier 2: TIER2-LLM10-03)
  - 🔴 [DF002](#df002-python--tool-without-args-schema) — retired in F.2 (Tier 2: TIER2-LLM06-03)
  - 🟢 [DF003 (Python) — no timeout / max_tokens cap](#df003-python--no-timeout--max_tokens-cap)
  - 🟢 [DF003 (Java) — no timeout / max_tokens cap](#df003-java--no-timeout--max_tokens-cap)
  - 🔴 [DF004](#df004-python--destructive-tool-without-human-approval) — retired in F.2 (Tier 2: TIER2-LLM06-01)
- [5. Respond rules](#5-respond-rules)
  - 🔴 [R001](#r001-python--llm-call-without-audit-logging) — retired in F.2 (Tier 2: TIER2-LLM10-02)
  - 🔴 R002 — retired in Phase E (predates v2; superseded by Tier 2 TIER2-LLM02-03 + the Phase E gap checks)
- [6. Retired-rule → Tier 2 cross-reference](#6-retired-rule--tier-2-cross-reference)
- [7. OWASP Agentic AI Top 10 coverage](#7-owasp-agentic-ai-top-10-coverage)
- [8. Library cross-reference](#8-library-cross-reference)
- [9. Known gaps](#9-known-gaps)

## 1. How to read this doc

Each rule section lists:

- **What it flags** — the security gap it fires on, in one sentence.
- **Frameworks / libraries detected** — concrete SDKs, plus the call shapes the rule recognises for each.
- **Suppressors / sanitizers** — imports or call patterns that make the rule *not* fire (a sign that the gap is already addressed).
- **Known gaps** — call shapes the rule misses today.

A "framework" rule means the rule pattern is specific to a known SDK call shape (high confidence). A "fallback" rule is broader — it fires on any method whose name *looks* LLM-shaped inside a file that imports an LLM library (lower confidence; routed to the LLM judge tier for triage).

## 2. Coverage at a glance

Each row scopes to one language — semgrep filters rules by `languages:`, so a Python file only matches the Python rows and a Java file only matches the Java rows. Java-only frameworks (Spring AI, langchain4j, AWS Bedrock Runtime Java SDK) appear in the Java rows; Python-only frameworks (LangChain, LlamaIndex, boto3) appear in the Python rows. SMARTSDK appears in both because it has both a Python and a Java distribution.

| Rule | Lang | Tier | Frameworks recognised |
|---|---|---|---|
| D001 | Python | framework | LangChain, LangChain async, LlamaIndex, OpenAI SDK, Anthropic SDK, AWS Bedrock (boto3), Google Generative AI / Vertex AI, Cohere, Mistral, SMARTSDK / Google ADK (sync + awaited), generic embeddings |
| D001 | Python | fallback | openai, anthropic, boto3, google.generativeai, vertexai, cohere, mistralai, together, groq, replicate, huggingface_hub, azure.ai.openai, smart_sdk, llama_index |
| D001 | Java | framework | SMARTSDK Java, langchain4j, Spring AI (ChatClient + ChatModel + Prompt + UserMessage), AWS Bedrock Runtime (Java SDK v2), Azure OpenAI Java SDK, Google ADK Java |
| D001 | Java | fallback | com.openai, com.anthropic, software.amazon.awssdk.services.bedrockruntime, com.azure.ai.openai, com.google.cloud.vertexai, dev.langchain4j, org.springframework.ai, com.jpmchase.smartsdk, com.jpmchase.cdaosmart |
| D002 | Python | framework | LangChain document loaders (WebBaseLoader, UnstructuredURLLoader, SeleniumURLLoader, PlaywrightURLLoader, AsyncHtmlLoader, RecursiveUrlLoader, SitemapLoader) |
| D002 | Java | framework | langchain4j UrlDocumentLoader, Spring AI TikaDocumentReader / JsoupDocumentReader with UrlResource, Apache Tika direct URL fetch |
| D003 | Python | framework | LangChain PythonREPL / PythonAstREPLTool / PythonREPLTool / ShellTool / BashProcess / SessionsPythonREPLTool, `@tool` decorator wrapping `exec`/`os.system`/`subprocess.*`, `Tool(func=eval/exec)` |
| D003 | Java | framework | langchain4j / Spring AI `@Tool` annotated methods wrapping `Runtime.exec` / `ProcessBuilder` / `ScriptEngine.eval` |
| D004 | Python | framework | LLM output (LangChain / LlamaIndex / OpenAI / Anthropic / Bedrock direct + awaited variants) flowing into `eval` / `exec` / `os.system` / `subprocess.*` with `shell=True` |
| D004 | Java | framework | LLM output (Spring AI / langchain4j / SMARTSDK / Bedrock / Azure OpenAI / Google ADK) flowing into `Runtime.exec` / `ProcessBuilder` / `ScriptEngine.eval` / unparameterized JDBC `Statement.execute*` |
| D005 | Python | framework | Hardcoded credential strings in OpenAI / Anthropic / Cohere / Mistral / Together / Groq / HuggingFace / Google generative AI / Bedrock direct / Azure OpenAI / LangChain wrappers (ChatOpenAI / ChatAnthropic / ChatCohere) |
| D005 | Java | framework | Hardcoded credentials in langchain4j / Spring AI builders (`.apiKey("…")`), Azure `AzureKeyCredential`, AWS `AwsBasicCredentials.create` / `BasicAWSCredentials`, Spring AI `OpenAiApi` / `AnthropicApi` / `MistralAiApi` constructors |
| D006 | Python | framework | LangChain `FileManagementToolkit` (without `selected_tools=`), `WriteFileTool` / `DeleteFileTool` / `MoveFileTool` / `CopyFileTool`, `Requests*Tool(allow_dangerous_requests=True)` |
| D006 | Java | framework | langchain4j / Spring AI `@Tool` annotated methods wrapping `Files.delete` / `Files.deleteIfExists` / `Files.write` / `Files.move`, or destructive HTTP (`RestTemplate.delete` / `RestTemplate.put` constrained via `metavariable-type: RestTemplate`) |
| D007 | Python | framework | HuggingFace `from_pretrained(...)` / `hf_hub_download(...)` / `snapshot_download(...)` without `revision=` pin (transformers, diffusers, sentence-transformers, raw huggingface_hub) |
| D008 | Python | framework | Network reads (`requests.get(...).text`, `httpx.get(...).text`, `urlopen(...).read()`, `S3.get_object(...)["Body"].read()`, `SSM.get_parameter(...)["Parameter"]["Value"]`) flowing into Anthropic `system=`, OpenAI Responses `instructions=`, LangChain `SystemMessage(...)`, ChatPromptTemplate `("system", $X)`, Bedrock Converse `system=[{"text": $X}]` |
| D008 | Java | framework | RestTemplate / WebClient / OkHttp / S3 / SSM reads flowing into langchain4j `SystemMessage.from(...)`, Spring AI `SystemMessage(...)`, Bedrock `SystemContentBlock.builder().text(...).build()` |
| DF001 | Python | framework | LangChain, LangChain async, LlamaIndex, OpenAI / Anthropic / Bedrock-style clients (generic verbs), SMARTSDK / Google ADK (sync + awaited), generic embeddings; boto3 `client.invoke(FunctionName=...)` Lambda calls excluded (Phase E.2) |
| DF001 | Java | framework | SMARTSDK Java, langchain4j, Spring AI, AWS Bedrock Runtime (Java SDK v2), Azure OpenAI Java SDK, Google ADK Java, embeddings |
| DF002 | Python | framework | LangChain `Tool(...)` / `StructuredTool(...)` / `@tool` decorator without `args_schema=` Pydantic model |
| DF002 | Java | framework | langchain4j / Spring AI `@Tool` methods with bare `String` parameters (no `@P` / `@ToolParam` annotation) |
| DF003 | Python | framework | OpenAI / Anthropic / Azure OpenAI / Cohere / Mistral / Groq / Together direct + LangChain wrappers (ChatOpenAI / ChatAnthropic / ChatBedrock / ChatVertexAI / ChatGoogleGenerativeAI) + httpx clients with explicit `timeout=None` or `max_tokens=None` |
| DF003 | Java | framework | langchain4j / Spring AI builders with `.timeout(null)` / `.maxTokens(null)` / `Duration.ZERO`; OkHttp transports with 0-second `connectTimeout` / `readTimeout` / `writeTimeout` / `callTimeout`; AWS Bedrock `apiCallTimeout(Duration.ZERO)` |
| DF004 | Python | framework | LangChain `@tool` decorated functions named with destructive verbs (delete / send / charge / deploy / …) without HumanApprovalCallbackHandler / LangGraph `interrupt_before=` / inline `input(...)` confirmation |
| DF004 | Java | framework | langchain4j / Spring AI `@Tool` methods named with destructive verbs without an injected `confirm()` / `requireApproval()` call |
| R001 | Python | framework | Same coverage as DF001 (Python) — `logger = logging.getLogger(...)` recognised as audit-logging intent (Phase E.2); boto3 `client.invoke(FunctionName=...)` Lambda calls excluded |
| R001 | Java | framework | Same coverage as DF001 (Java) — Lombok `@Slf4j` recognised as logger (Phase E) |

## 3. Detect rules

### D001 (Python, framework) — unsanitized user input → LLM

Source: [agentshield/rules/detect/D001-unsanitized-user-input-to-llm.yaml](./agentshield/rules/detect/D001-unsanitized-user-input-to-llm.yaml). Mode: `taint`.

**What it flags.** Data that originates from a user-controlled source (HTTP request body / query / form, AWS Lambda event, stdin, CLI args) flows into an LLM/agent invocation without passing through a sanitizer. Canonical prompt-injection surface (OWASP LLM01).

**Frameworks / libraries detected (sinks):**

- **LangChain (sync + async)** — `chain.invoke(prompt, ...)`, `chain.ainvoke(...)`, `chain.run(...)`, `chain.arun(...)`, `chain.predict(...)`, `chain.apredict(...)`, `chain.stream(...)`, `chain.astream(...)`, `chain.batch(...)`, `chain.generate(...)`, `chain.agenerate(...)`, `agent.execute(...)`.
- **LlamaIndex** — `qe.query(...)`, `qe.aquery(...)`, `ce.chat(...)`, `ce.achat(...)`.
- **OpenAI / Anthropic / Bedrock-style direct SDK clients** — `client.invoke(...)`, `client.run(...)`, `client.predict(...)`, `client.generate(...)`, `client.chat(...)` (covered by the generic `$LLM.<verb>($X, ...)` patterns).
- **SMARTSDK / Google ADK (sync)** — `runner.run(agent, prompt, ...)`, `runner.run_stream(agent, prompt, ...)`, `runner.run_async(agent, prompt, ...)`. User input is the **2nd positional arg**, which is why D001 has SMARTSDK-specific patterns: `$RUNNER.run($AGENT, $X, ...)`.
- **SMARTSDK Content/Part-wrapped form** — `runner.run(agent, Content(parts=[Part(text=user_input)], ...), ...)` is recognised; taint binds to the `text=$X` slot inside the wrapper.
- **SMARTSDK awaited** — `await runner.run(agent, prompt, ...)`, `await runner.run_stream(...)`, `await runner.run_async(...)`. Awaited variants are kept as separate patterns because semgrep treats `await expr` as a distinct AST node.
- **`Console(...)` REPL wrapper** — `await Console(runner.run_stream(agent, prompt))` (SMARTSDK CLI helper).
- **Generic embeddings** — `model.embed(data=$X, ...)`, `model.embed($X, ...)`, `model.aembed(data=$X, ...)`, `model.aembed($X, ...)`.

**Sources (where tainted input comes from):**

- **Flask / Django / generic WSGI request objects** — `request.json[k]`, `request.json.get(...)`, `request.form[k]`, `request.form.get(...)`, `request.args.get(...)`, `request.args[k]`, `request.values.get(...)`, `request.data`.
- **FastAPI / Starlette / async frameworks** — `req.json()`, `req.body`, `await req.json()`, `await req.body()`.
- **CLI / interactive** — `input(...)`, `sys.argv[i]`.
- **AWS Lambda event-driven** — `event[k]`, `event.get(k)`, `event.get(k, default)`. Added because Lambda functions don't see HTTP request objects; user-controlled fields arrive in the `event` dict.

**Sanitizers (what suppresses the finding):**

- Guardrail wrappers: `guard.guard(x, ...)`, `guard.scan(x, ...)`, `guard.detect_injection(x, ...)`, `guard.is_safe(x, ...)`.
- NeMo Guardrails: `nemoguardrails.LLMRails(...).generate(...)`.
- Lakera Guard: `lakera_guard.detect(...)`.
- Rebuff: `rebuff.detect_injection(...)`.
- Presidio: `presidio_analyzer.AnalyzerEngine().analyze(...)`.
- Generic escapers: `bleach.clean(...)`, `html.escape(...)`.

### D001 (Python, fallback) — LLM-shaped verb in an LLM-importing file

Source: [agentshield/rules/detect/D001-fallback-llm-import-and-verb-shape.yaml](./agentshield/rules/detect/D001-fallback-llm-import-and-verb-shape.yaml). Mode: `taint`. Confidence: **low** (routed to the LLM-judge tier).

**What it flags.** The same source → sink shape as the framework rule, but the sink is matched purely on (a) the file imports a known LLM library and (b) the call's method name matches an LLM-shaped verb regex. Catches LLM SDKs that aren't explicitly modeled.

**LLM-adjacent libraries that activate the rule (`pattern-inside`):**

`openai`, `anthropic`, `boto3`, `google.generativeai`, `vertexai`, `cohere`, `mistralai`, `together`, `groq`, `replicate`, `huggingface_hub`, `azure.ai.openai`, `smart_sdk`, `llama_index`.

**Verb regex (the `$VERB` in `$X.$VERB($Y, ...)`):**

`invoke | ainvoke | call | acall | run | arun | chat | achat | complete | completion | completions | generate | agenerate | predict | apredict | stream | astream | embed | aembed | query | aquery | ask | send | respond | create | acreate | invoke_model | invoke_model_with_response_stream | converse | converse_stream`.

**Sources / sanitizers:** identical to the framework D001 rule.

### D001 (Java, framework) — unsanitized user input → LLM

Source: [agentshield/rules/detect/D001-unsanitized-user-input-to-llm-java.yaml](./agentshield/rules/detect/D001-unsanitized-user-input-to-llm-java.yaml). Mode: `taint`.

**What it flags.** Java port of D001 — user input from a Spring / JAX-RS / Servlet / CLI source flows into a Java LLM SDK call without sanitization.

**Frameworks / libraries detected (sinks):**

- **SMARTSDK Java (wraps Google ADK)** — `runner.run(agent, prompt, ...)`, `runner.runStream(...)`, `runner.runAsync(...)`. User input is the 2nd positional arg.
- **langchain4j** — `model.generate(prompt, ...)`, `model.chat(prompt, ...)`, `chain.execute(prompt, ...)`, `assistant.chat(prompt, ...)`.
- **Spring AI (fluent ChatClient + ChatModel)** — `client.prompt().user(x).call(...)`, `client.prompt(x).call(...)`, `model.call(new Prompt(x, ...))`, `model.call(new UserMessage(x, ...))`, `model.stream(new Prompt(x, ...))`.
- **AWS Bedrock Runtime (Java SDK v2, direct usage, not via SMARTSDK)** — `client.invokeModel(x, ...)`, `client.invokeModelWithResponseStream(x, ...)`, `client.converse(x, ...)`, `client.converseStream(x, ...)`.
- **Azure OpenAI Java SDK** — `client.getChatCompletions(x, ...)`, `client.getChatCompletionsStream(x, ...)`, `client.getCompletions(x, ...)`.
- **Google ADK Java (direct, not via SMARTSDK)** — `agent.invoke(x, ...)`, `agent.run(x, ...)`.
- **Embeddings** — `model.embed(x, ...)`, `embedding.embedAll(x, ...)`, `embedding.embed(x, ...)`, `client.getEmbeddings(x, ...)`.

**Sources:**

- **Spring MVC / WebFlux annotations on method parameters** — `@RequestParam`, `@RequestBody`, `@PathVariable`, `@RequestHeader`. Taint binds to the parameter name via a `pattern-inside` on the method signature.
- **JAX-RS annotations** — `@QueryParam(k)`, `@FormParam(k)`, `@PathParam(k)`.
- **Servlet API** — `req.getParameter(...)`, `req.getParameterValues(...)`, `req.getHeader(...)`, `req.getReader()`, `req.getInputStream()`.
- **CLI / interactive** — `args[i]`, `System.console().readLine(...)`, `scanner.nextLine(...)`.

**Sanitizers:**

- **OWASP Java Encoder** — `Encode.forJava(...)`, `Encode.forHtml(...)` (qualified or unqualified).
- **Lakera Guard Java SDK** — `guard.detect(...)`, `guard.scan(...)`, `guard.guard(...)`, `guard.isSafe(...)`.
- **Apache Commons Text** — `StringEscapeUtils.escapeHtml4(...)`, `StringEscapeUtils.escapeJava(...)`.

### D001 (Java, fallback) — LLM-shaped verb in an LLM-importing file

Source: [agentshield/rules/detect/D001-fallback-llm-import-and-verb-shape-java.yaml](./agentshield/rules/detect/D001-fallback-llm-import-and-verb-shape-java.yaml). Mode: `taint`. Confidence: **low**.

**LLM-adjacent imports that activate the rule:**

`com.openai`, `com.anthropic`, `software.amazon.awssdk.services.bedrockruntime`, `com.azure.ai.openai`, `com.google.cloud.vertexai`, `dev.langchain4j`, `org.springframework.ai`, `com.jpmchase.smartsdk`, `com.jpmchase.cdaosmart`.

**Verb regex:**

`invoke | invokeModel | invokeModelWithResponseStream | converse | converseStream | call | run | runStream | runAsync | chat | complete | completion | getChatCompletions | getChatCompletionsStream | getCompletions | getEmbeddings | generate | predict | stream | embed | embedAll | query | ask | send | respond | execute`.

**Sources / sanitizers:** identical to the Java framework D001.

### D002 (Python) — untrusted document loader → RAG

Source: [agentshield/rules/detect/D002-untrusted-document-loader-to-rag.yaml](./agentshield/rules/detect/D002-untrusted-document-loader-to-rag.yaml).

**What it flags.** A document/web loader that fetches content from URLs is feeding into a vector store / retriever without URL allowlisting or content sanitization. Indirect prompt injection / RAG poisoning surface (OWASP LLM01 indirect, LLM08 vector weakness).

**Loaders recognised:**

- LangChain — `WebBaseLoader(...)`, `UnstructuredURLLoader(...)`, `SeleniumURLLoader(...)`, `PlaywrightURLLoader(...)`, `AsyncHtmlLoader(...)`, `RecursiveUrlLoader(...)`, `SitemapLoader(...)`.
- Generic `<Class>(url=$URL, ...)` — any loader class instantiated with a `url=` kwarg.
- `loader.load()` / `loader.lazy_load()` / `loader.aload()` calls when `loader` was assigned from a `WebBaseLoader(...)` constructor in scope.

**Suppressors (an allowlist guard in the same scope silences the rule):**

- `if $URL in $ALLOWLIST: …`
- `if $URL.startswith($PREFIX): …`
- `assert $URL in $ALLOWLIST`

### D002 (Java) — untrusted document loader → RAG

Source: [agentshield/rules/detect/D002-untrusted-document-loader-to-rag-java.yaml](./agentshield/rules/detect/D002-untrusted-document-loader-to-rag-java.yaml).

**What it flags.** Java port of D002 — a Java document/web loader fetches content from a URL and feeds it into a vector store / retriever without URL allowlisting.

**Loaders recognised:**

- langchain4j — `UrlDocumentLoader.load(...)` (qualified or unqualified).
- Spring AI — `new TikaDocumentReader(new UrlResource(...))`, `new JsoupDocumentReader(new UrlResource(...))`.
- Apache Tika — `new Tika().parseToString(new URL(...))`.
- Generic — `new Document(URL.openStream(...))`.

### D003 (Python) — code-execution tool registered

Source: [agentshield/rules/detect/D003-code-execution-tool-registered.yaml](./agentshield/rules/detect/D003-code-execution-tool-registered.yaml).

**What it flags.** Agent has access to a code-execution tool (Python REPL, shell, eval). If user input or LLM output reaches the tool's input, this is arbitrary code execution on the host. OWASP LLM05 / LLM06, OWASP Agentic T2 / T11.

**Tool shapes recognised:**

- LangChain code-exec tool classes — `PythonREPL(...)`, `PythonAstREPLTool(...)`, `PythonREPLTool(...)`, `ShellTool(...)`, `BashProcess(...)`, `SessionsPythonREPLTool(...)`.
- Imports of code-exec tool classes — `from langchain_experimental.tools import PythonREPLTool`, `from langchain_community.tools import ShellTool`, `from langchain.tools.python.tool import PythonREPLTool`.
- `Tool(..., func=exec, ...)` and `Tool(..., func=eval, ...)` — wrapping the bare `exec` / `eval` builtins as a tool function.
- `@tool` decorated function whose body calls `exec(...)`, `os.system(...)`, or `subprocess.<method>(...)`.

### D003 (Java) — code-execution tool registered

Source: [agentshield/rules/detect/D003-code-execution-tool-registered-java.yaml](./agentshield/rules/detect/D003-code-execution-tool-registered-java.yaml).

**What it flags.** Java port of D003 — a method registered as an LLM tool wraps a code-execution primitive.

**Tool shapes recognised:**

- `@Tool` annotated method (langchain4j / Spring AI) whose body calls `Runtime.getRuntime().exec(...)`.
- `@Tool` annotated method whose body constructs `new ProcessBuilder(...)`.
- `@Tool` annotated method whose body calls `$ENGINE.eval(...)` (Nashorn / Rhino / GraalJS).
- Both bare `@Tool` and `@Tool("description")` forms are matched.

### D004 (Python) — LLM output → code execution

Source: [agentshield/rules/detect/D004-llm-output-to-code-execution.yaml](./agentshield/rules/detect/D004-llm-output-to-code-execution.yaml). Mode: `taint`.

**What it flags.** Output from an LLM call flows into a dangerous code-execution sink. LLM output is attacker-controllable via prompt injection — feeding it to a code executor is arbitrary code execution. OWASP LLM05 Improper Output Handling.

**Sources (LLM call return values):**

- Generic LLM/agent/chain verbs — `$LLM.invoke(...)`, `$LLM.ainvoke(...)`, `$LLM.run(...)`, `$LLM.arun(...)`, `$LLM.run_stream(...)`, `$LLM.run_async(...)`, `$LLM.predict(...)`, `$LLM.apredict(...)`, `$LLM.generate(...)`, `$LLM.agenerate(...)`, `$LLM.chat(...)`, `$LLM.achat(...)`, `$LLM.query(...)`, `$LLM.aquery(...)`, `$LLM.complete(...)`, `$LLM.acomplete(...)`.
- Awaited variants of the same verbs.
- OpenAI SDK — `$CLIENT.chat.completions.create(...)`, `$CLIENT.completions.create(...)`, `$CLIENT.responses.create(...)`.
- Anthropic SDK — `$CLIENT.messages.create(...)`.
- AWS Bedrock direct — `$CLIENT.invoke_model(...)`, `$CLIENT.invoke_model_with_response_stream(...)`, `$CLIENT.converse(...)`, `$CLIENT.converse_stream(...)`.

**Sinks (dangerous executors):**

- `eval($X)`, `exec($X)`.
- `os.system($X)`.
- `subprocess.run($X, …, shell=True, …)` and the same for `subprocess.call`, `subprocess.check_call`, `subprocess.check_output`, `subprocess.Popen`. The list-form (no `shell=True`) is intentionally NOT a sink — argv is passed verbatim, no shell interpretation.

**Sanitizers:** `shlex.split(...)`, `shlex.quote(...)`, `ast.literal_eval(...)`.

### D004 (Java) — LLM output → code execution / SQL

Source: [agentshield/rules/detect/D004-llm-output-to-code-execution-java.yaml](./agentshield/rules/detect/D004-llm-output-to-code-execution-java.yaml). Mode: `taint`.

**What it flags.** Java port of D004 — Java LLM call output flows into `Runtime.exec` / `ProcessBuilder` / `ScriptEngine.eval` / unparameterized JDBC `Statement.execute*`.

**Sources:** identical Java LLM call shapes to D001 / DF001 / R001 (Java) — SMARTSDK, langchain4j, Spring AI, AWS Bedrock Runtime, Azure OpenAI, Google ADK Java.

**Sinks:**

- Process spawn — `Runtime.getRuntime().exec($X)`, `new ProcessBuilder($X)`.
- Script eval — `$ENGINE.eval($X)`.
- Unparameterized JDBC — `$STMT.execute($X)`, `$STMT.executeQuery($X)`, `$STMT.executeUpdate($X)`, `$STMT.executeLargeUpdate($X)`.

**Sanitizers:**

- OWASP Java Encoder — `Encode.forJava(...)`.
- Apache Commons Text — `StringEscapeUtils.escapeJava(...)`.
- JDBC parameter binding — `$PS.setString(...)`, `$PS.setInt(...)`, `$PS.setLong(...)`.
- Lakera Guard — `$G.detect(...)`, `$G.scan(...)`, `$G.guard(...)`, `$G.isSafe(...)`.

### D005 (Python) — hardcoded LLM credentials

Source: [agentshield/rules/detect/D005-hardcoded-llm-credentials.yaml](./agentshield/rules/detect/D005-hardcoded-llm-credentials.yaml).

**What it flags.** Hardcoded credential string passed to an LLM client constructor — CWE-798 (Use of Hard-coded Credentials). Secrets in source end up in git history, container images, and CI logs. OWASP LLM02 Sensitive Information Disclosure / LLM03 Supply Chain.

**Constructors recognised:**

- OpenAI — `openai.OpenAI(api_key="…")`, `openai.AsyncOpenAI(api_key="…")`, `OpenAI(api_key="…")`, `AsyncOpenAI(api_key="…")`.
- Anthropic — `anthropic.Anthropic(api_key="…")`, `anthropic.AsyncAnthropic(api_key="…")`, plus unqualified.
- Cohere — `cohere.Client("…")` (positional first arg), `cohere.ClientV2(api_key="…")`, `cohere.AsyncClient(...)`.
- Mistral — `MistralClient(api_key="…")`, `Mistral(api_key="…")`.
- Together — `Together(api_key="…")`, `together.Together(api_key="…")`.
- Groq — `Groq(api_key="…")`, `groq.Groq(api_key="…")`, `AsyncGroq(api_key="…")`.
- HuggingFace — `InferenceClient(token="…")`, `AsyncInferenceClient(token="…")`, `huggingface_hub.login(token="…")`.
- Google generative AI — `genai.configure(api_key="…")`, `google.generativeai.configure(api_key="…")`.
- AWS Bedrock direct — `boto3.client("bedrock-runtime", aws_access_key_id="…")`, `aws_secret_access_key="…"`, `boto3.Session(...)` with the same.
- Azure OpenAI — `AzureOpenAI(api_key="…")`, `AsyncAzureOpenAI(api_key="…")`.
- LangChain wrappers — `ChatOpenAI(openai_api_key="…")`, `ChatOpenAI(api_key="…")`, `ChatAnthropic(anthropic_api_key="…")`, `ChatAnthropic(api_key="…")`, `ChatCohere(cohere_api_key="…")`, `ChatCohere(api_key="…")`.

**The rule fires only on string literals.** Env-var lookups (`os.environ["…"]`), helper-function returns, secrets-manager calls, and Spring `@Value` bindings are not matched.

### D005 (Java) — hardcoded LLM credentials

Source: [agentshield/rules/detect/D005-hardcoded-llm-credentials-java.yaml](./agentshield/rules/detect/D005-hardcoded-llm-credentials-java.yaml).

**What it flags.** Java port of D005 — hardcoded credential strings in Java LLM SDK constructors / builders.

**Constructors / builders recognised:**

- Builder API (langchain4j, Spring AI, SMARTSDK Java) — `$X.apiKey("…")`, `$X.token("…")`, `$X.secretKey("…")` matched as sub-expressions inside any fluent chain.
- Azure OpenAI — `new AzureKeyCredential("…")`, `new com.azure.core.credential.AzureKeyCredential("…")`.
- AWS Bedrock Runtime (Java SDK v2) — `AwsBasicCredentials.create("…", "…")`, `AwsSessionCredentials.create("…", "…", "…")`, fully-qualified or short-form.
- AWS SDK v1 — `new BasicAWSCredentials("…", "…")` (still in some legacy codebases).
- Spring AI direct constructors — `new OpenAiApi("…")`, `new AnthropicApi("…")`, `new MistralAiApi("…")`.

### D006 (Python) — broad tool permissions

Source: [agentshield/rules/detect/D006-broad-tool-permissions.yaml](./agentshield/rules/detect/D006-broad-tool-permissions.yaml).

**What it flags.** Agent has access to a broad-permission tool — file mutation (read/write/delete/copy/move) or unrestricted HTTP. The agent can mutate the host filesystem or send arbitrary HTTP traffic with no per-call human approval. OWASP LLM06 Excessive Agency, OWASP Agentic T3 Privilege Compromise.

**Tool shapes recognised:**

- LangChain `FileManagementToolkit(...)` instantiated without a `selected_tools=` filter — exposes the entire toolset to the LLM.
- File-mutation tool classes — `WriteFileTool(...)`, `DeleteFileTool(...)`, `MoveFileTool(...)`, `CopyFileTool(...)`.
- HTTP request tools with `allow_dangerous_requests=True` — `RequestsGetTool`, `RequestsPostTool`, `RequestsPutTool`, `RequestsDeleteTool`, `RequestsPatchTool`.

**Suppressors:**

- `FileManagementToolkit(..., selected_tools=$T, ...)` with an explicit allowlist (e.g. `selected_tools=["read_file", "list_directory"]`) — only the listed tools enter the registry.
- HTTP request tools without `allow_dangerous_requests=True` (the SDK default is `False` — state-changing requests are blocked at the wrapper level).

### D006 (Java) — broad tool permissions

Source: [agentshield/rules/detect/D006-broad-tool-permissions-java.yaml](./agentshield/rules/detect/D006-broad-tool-permissions-java.yaml).

**What it flags.** Java port of D006 — `@Tool` annotated method wraps a broad-permission primitive: filesystem mutation or destructive HTTP.

**Tool shapes recognised:**

- `@Tool` annotated method whose body calls `Files.delete(...)`, `Files.deleteIfExists(...)`, `Files.write(...)`, or `Files.move(...)` (`java.nio.file.Files`).
- `@Tool` annotated method whose body calls `$REST.delete(...)` or `$REST.put(...)` constrained via `metavariable-type: RestTemplate` (the type filter was added in Phase B to prevent `Map.put(...)` collisions; details in git history).
- Both `@Tool` and `@Tool("description")` forms are matched.

### D007 (Python) — untrusted model loading

Source: [agentshield/rules/detect/D007-untrusted-model-loading.yaml](./agentshield/rules/detect/D007-untrusted-model-loading.yaml).

**What it flags.** A model is loaded from HuggingFace Hub (or a compatible API) without a pinned `revision=` argument. The default `main` branch can be force-pushed by anyone with write access to the repo — including a compromised account or a malicious maintainer. Without a revision pin, your next download silently switches to whatever's on `main` at fetch time. OWASP LLM03 Supply Chain + LLM04 Data and Model Poisoning, OWASP Agentic T3.

**Loader shapes recognised (each paired with a `pattern-not` requiring `revision=`):**

- `$X.from_pretrained($MODEL, ...)` — covers transformers `AutoModel.from_pretrained(...)`, `AutoTokenizer.from_pretrained(...)`, diffusers, sentence-transformers, etc.
- `hf_hub_download(...)` and the fully-qualified `huggingface_hub.hf_hub_download(...)`.
- `snapshot_download(...)` and the fully-qualified `huggingface_hub.snapshot_download(...)`.

**Suppressor:** any `revision=$REV` keyword argument in the call.

**Real-code testbed signal:** scanning llama-index produces 77 findings across 31 files (framework wrappers that pass model names through without enforcing a revision pin); langchain produces 5. All sampled findings were true positives — framework code presents the same supply-chain risk as user code, but is harder to remediate without API changes. End-user app scans see only their own `from_pretrained(...)` calls.

### D008 (Python) — untrusted system prompt

Source: [agentshield/rules/detect/D008-untrusted-system-prompt.yaml](./agentshield/rules/detect/D008-untrusted-system-prompt.yaml). Mode: `taint`.

**What it flags.** Content from a network read flows into an LLM system prompt. System prompts dictate the agent's role, tools, and constraints — an attacker who controls the system-prompt source can inject hidden instructions that override the developer's intent. OWASP LLM07 System Prompt Leakage / injection.

**Sources (untrusted reads):**

- requests / httpx — `requests.get(...).text`, `requests.get(...).json()`, `requests.post(...).text`, `requests.post(...).json()`, `requests.request(...).text`, `httpx.get(...).text`, `httpx.get(...).json()`, `httpx.post(...).text`.
- urllib raw reads — `urllib.request.urlopen(...).read()`, `urllib.request.urlopen(...).read().decode(...)`.
- AWS S3 — `$S3.get_object(...)["Body"].read()`, `$S3.get_object(...)["Body"].read().decode(...)`.
- AWS Systems Manager — `$SSM.get_parameter(...)["Parameter"]["Value"]`.

**Sinks (system-prompt-shaped):**

- Anthropic — `$CLIENT.messages.create(..., system=$X, ...)`.
- OpenAI Responses API — `$CLIENT.responses.create(..., instructions=$X, ...)`.
- LangChain — `SystemMessage($X)`, `SystemMessage(content=$X)`, `langchain_core.messages.SystemMessage(...)`, `ChatPromptTemplate.from_messages([..., ("system", $X), ...])`.
- AWS Bedrock Converse — `$CLIENT.converse(..., system=[{"text": $X}], ...)`.

**Sanitizers:**

- Guardrail libraries — NeMo Guardrails `LLMRails(...).generate(...)`, generic `$G.guard(...)` / `$G.scan(...)` / `$G.is_safe(...)`.
- Cryptographic verification — `$V.verify(...)`, `hmac.compare_digest(...)`.

### D008 (Java) — untrusted system prompt

Source: [agentshield/rules/detect/D008-untrusted-system-prompt-java.yaml](./agentshield/rules/detect/D008-untrusted-system-prompt-java.yaml). Mode: `taint`.

**What it flags.** Java port of D008 — content from a network read flows into a Spring AI / langchain4j / Bedrock system message.

**Sources:** Spring `RestTemplate` (`getForObject`, `getForEntity().getBody()`, `exchange().getBody()`), Spring `WebClient` (`.bodyToMono(...).block()`, `.toEntity(...).block().getBody()`), OkHttp (`newCall().execute().body().string()`), AWS Java SDK v2 S3 (`getObject(...).asUtf8String()`, `getObjectAsBytes(...).asUtf8String()`), AWS SSM (`getParameter(...).parameter().value()`), Apache `EntityUtils.toString(...)`.

**Sinks:** langchain4j `SystemMessage.from(...)` / `new SystemMessage(...)`, Spring AI `new SystemMessage(...)` / `$TPL.createMessage(...)`, Bedrock `SystemContentBlock.builder().text(...).build()`.

**Sanitizers:** OWASP Encoder (`Encode.forJava(...)`), Lakera Guard (`$G.detect/scan/guard/isSafe(...)`), Java MAC verification (`MessageDigest.isEqual(...)`, `$MAC.doFinal(...)`).

**Known limitation:** semgrep's intra-procedural taint analysis can't recognize an `if (MessageDigest.isEqual(...))` conditional gate as protecting the use site. To express verified-system-prompt safely in user code, extract HMAC verification into a wrapper function or apply Lakera Guard on the result before constructing the `SystemMessage`.

## 4. Defend rules

### DF001 (Python) — LLM call with no guardrails import

Source: [agentshield/rules/defend/DF001-no-guardrails-import-in-llm-module.yaml](./agentshield/rules/defend/DF001-no-guardrails-import-in-llm-module.yaml).

**What it flags.** A module invokes an LLM/agent/chain but does not import any known guardrails library — meaning there's no input or output filter layered around the call. Absence detection; calibrate severity per repo.

**LLM call shapes recognised:**

- **Generic LLM/agent verbs** (cover LangChain, LlamaIndex, OpenAI, Anthropic, Bedrock, Cohere, etc.): `$X.invoke(...)`, `$X.ainvoke(...)`, `$X.run(...)`, `$X.run_stream(...)`, `$X.run_async(...)`, `$X.predict(...)`, `$X.generate(...)`, `$X.query(...)`, `$X.chat(...)`.
- **Awaited variants** (FastAPI / asyncio / SMARTSDK awaited): `await $X.invoke(...)`, `await $X.ainvoke(...)`, `await $X.run(...)`, `await $X.run_stream(...)`, `await $X.run_async(...)`, `await $X.predict(...)`, `await $X.generate(...)`, `await $X.query(...)`, `await $X.chat(...)`. Kept as separate patterns because semgrep treats `await expr` as a distinct AST node.
- **SMARTSDK / Google ADK** — covered by the generic `$X.run`, `$X.run_stream`, `$X.run_async` shapes. (The earlier SMARTSDK-specific `$RUNNER.run($AGENT, ...)` patterns were removed because they overlapped with the generics and caused duplicate findings.)
- **SMARTSDK / RADSDK embeddings** — `$MODEL.embed(...)`, `$MODEL.aembed(...)`.

**Suppressors (a guardrails import in the same file silences the rule):**

- NeMo Guardrails — `import nemoguardrails`, `from nemoguardrails import …`.
- Lakera Chainguard — `import lakera_chainguard`, `from lakera_chainguard import …`.
- Rebuff — `import rebuff`, `from rebuff import …`.
- Guardrails-AI — `import guardrails`, `from guardrails import …`.
- Presidio — `import presidio_analyzer`, `from presidio_analyzer import …`.
- Llama Guard — `from llama_guard import …`.

**False-positive filters (always suppressed):** `asyncio.run(...)`, `threading.Thread(...).run(...)`, `subprocess.run(...)`, `re.compile(...).run(...)`. **Phase E.2 added** `$X.invoke(FunctionName=$FN, ...)` and `boto3.client("lambda").invoke(...)` — boto3 Lambda self-invocation is not an LLM call and was the largest single FP source on a real SMART SDK Lambda codebase.

### DF001 (Java) — LLM call with no guardrails import

Source: [agentshield/rules/defend/DF001-no-guardrails-import-in-llm-module-java.yaml](./agentshield/rules/defend/DF001-no-guardrails-import-in-llm-module-java.yaml).

**LLM call shapes recognised:**

- **SMARTSDK Java** — `runner.run(agent, ...)`, `runner.runStream(...)`, `runner.runAsync(...)`.
- **langchain4j** — `model.generate(...)`, `model.chat(...)`, `chain.execute(...)`, `assistant.chat(...)`.
- **Spring AI** — `client.prompt().user(x).call(...)`, `model.call(new Prompt(...))`, `model.stream(new Prompt(...))`.
- **AWS Bedrock Runtime** — `client.invokeModel(...)`, `client.invokeModelWithResponseStream(...)`, `client.converse(...)`, `client.converseStream(...)`.
- **Azure OpenAI Java SDK** — `client.getChatCompletions(...)`, `client.getCompletions(...)`.
- **Google ADK Java (direct)** — `agent.invoke(...)`, `agent.run(...)`.
- **Embeddings** — `model.embed(...)`, `embedding.embedAll(...)`, `client.getEmbeddings(...)`.

**Suppressors:**

- Lakera Java SDK — `import com.lakera.…`.
- OWASP Java Encoder — `import org.owasp.encoder.…`.
- Apache Commons Text — `import org.apache.commons.text.StringEscapeUtils`.
- Spring AI built-in advisors / moderation — `import org.springframework.ai.chat.client.advisor.…`, `import org.springframework.ai.moderation.…`.

### DF002 (Python) — tool without args schema

Source: [agentshield/rules/defend/DF002-tool-without-args-schema.yaml](./agentshield/rules/defend/DF002-tool-without-args-schema.yaml).

**What it flags.** Tool registered without an explicit `args_schema=` Pydantic model. Without a schema the LLM can pass arbitrary, unvalidated arguments — classic excessive-agency / tool-misuse vector. OWASP LLM06, OWASP Agentic T2.

**Tool registration shapes recognised:**

- LangChain `Tool(name=$N, func=$F, description=$D)` and `StructuredTool(name=$N, func=$F, description=$D)` (and the keyword-order variant) without a `args_schema=` kwarg.
- `@tool` decorated function without `@tool(args_schema=$S)` or `@tool($N, args_schema=$S)`.

### DF002 (Java) — tool without args schema

Source: [agentshield/rules/defend/DF002-tool-without-args-schema-java.yaml](./agentshield/rules/defend/DF002-tool-without-args-schema-java.yaml).

**What it flags.** Java port of DF002 — `@Tool` annotated method takes a bare `String` parameter without an `@P` (langchain4j) or `@ToolParam` (Spring AI) annotation. Without parameter annotations, the LLM has no description / no value constraints for what to pass.

**Patterns recognised:**

- `@Tool` or `@Tool($DESC)` on a method with `String $X` or `String $X, String $Y` parameters that lack annotations.

**Suppressors:**

- `@P(...)` on the parameter (langchain4j parameter description).
- `@ToolParam(...)` on the parameter (Spring AI 1.0+ parameter description).

**Known limitation:** the rule covers `String` parameters explicitly (the most common LLM-injectable type) and pairs of `String` parameters; methods with three or more bare String params, or with non-`String` types, are a gap and would need additional pattern variants.

### DF003 (Python) — no timeout / max_tokens cap

Source: [agentshield/rules/defend/DF003-no-timeout-or-token-cap-on-llm.yaml](./agentshield/rules/defend/DF003-no-timeout-or-token-cap-on-llm.yaml).

**What it flags.** LLM client / call constructed with an explicitly disabled bound — `timeout=None` or `max_tokens=None` (or `max_output_tokens=None`). Without bounds, a single request can hang a worker indefinitely or generate runaway output. OWASP LLM10 Unbounded Consumption, OWASP Agentic T4 Resource Overload.

**Client shapes recognised (explicit `timeout=None`):**

- Direct SDKs — `openai.OpenAI`, `openai.AsyncOpenAI`, `OpenAI`, `AsyncOpenAI`, `anthropic.Anthropic`, `anthropic.AsyncAnthropic`, `Anthropic`, `AsyncAnthropic`, `AzureOpenAI`, `AsyncAzureOpenAI`, `cohere.Client`, `cohere.ClientV2`, `MistralClient`, `Mistral`, `Groq`, `AsyncGroq`, `Together`.
- LangChain wrappers — `ChatOpenAI`, `ChatAnthropic`, `ChatCohere`, `ChatBedrock`, `ChatVertexAI`, `ChatGoogleGenerativeAI`.
- Indirect — `httpx.Client(timeout=None)`, `httpx.AsyncClient(timeout=None)` (commonly passed as the SDK transport).

**Call shapes recognised (explicit `max_tokens=None` / `max_output_tokens=None`):**

- Same LangChain wrappers above with `max_tokens=None` in the constructor.
- Direct SDK calls — `$CLIENT.chat.completions.create(..., max_tokens=None, ...)`, `$CLIENT.completions.create(...)`, `$CLIENT.responses.create(..., max_output_tokens=None, ...)`, `$CLIENT.messages.create(..., max_tokens=None, ...)`.

**The rule fires only on EXPLICIT `None`.** Defaults (no `timeout=` / `max_tokens=` kwarg at all) are out of scope — most SDKs default to a finite value.

### DF003 (Java) — no timeout / max_tokens cap

Source: [agentshield/rules/defend/DF003-no-timeout-or-token-cap-on-llm-java.yaml](./agentshield/rules/defend/DF003-no-timeout-or-token-cap-on-llm-java.yaml).

**What it flags.** Java port of DF003 — Java LLM client builder explicitly disables a bound: `null` timeout, `Duration.ZERO`, or 0-second OkHttp timeout.

**Patterns recognised (matched as sub-expressions inside any builder chain):**

- `$X.timeout(null)`, `$X.maxTokens(null)`, `$X.maxOutputTokens(null)`, `$X.maxRetries(null)` — explicit-null builder steps.
- `$X.timeout(Duration.ZERO)`, `$X.responseTimeout(Duration.ZERO)`, fully-qualified or short-form.
- OkHttp 0-second timeouts — `$X.connectTimeout(0, $UNIT)`, `$X.readTimeout(0, $UNIT)`, `$X.writeTimeout(0, $UNIT)`, `$X.callTimeout(0, $UNIT)` (OkHttp's convention is that `0` means "no timeout").
- AWS Bedrock — `$X.apiCallTimeout(Duration.ZERO)`, `$X.apiCallAttemptTimeout(Duration.ZERO)`.

### DF004 (Python) — destructive tool without human approval

Source: [agentshield/rules/defend/DF004-destructive-tool-without-human-approval.yaml](./agentshield/rules/defend/DF004-destructive-tool-without-human-approval.yaml).

**What it flags.** A `@tool` decorated function is named with a destructive verb but the file contains no human-approval mechanism — the agent can invoke the tool autonomously to perform an irreversible action. OWASP LLM06 Excessive Agency, OWASP Agentic T10 Overwhelming HITL.

**Trigger:** function name regex `^(delete|remove|destroy|drop|send|transfer|charge|email|notify|publish|deploy|shutdown|kill|terminate|wipe|purge|forget|revoke|cancel|refund)(_.*)?$` matched on a `@tool` or `@tool(...)` decorated function.

**Suppressors (any one silences the rule):**

- An explicit `input(...)` confirmation prompt inside the tool body.
- File imports `HumanApprovalCallbackHandler` from `langchain.callbacks.human`, `langchain_community.callbacks.human`, or `langchain_core.callbacks` — framework-level approval gating.
- File uses LangGraph `interrupt_before=$X` or `interrupt_after=$X` — graph-level approval breakpoints before the destructive node.

**Known limitation:** the rule is name-based — a destructive tool named `update_user_status` (semantically destructive but no destructive verb prefix) won't match. This is intentional — name-based matching keeps the false-positive rate low.

### DF004 (Java) — destructive tool without human approval

Source: [agentshield/rules/defend/DF004-destructive-tool-without-human-approval-java.yaml](./agentshield/rules/defend/DF004-destructive-tool-without-human-approval-java.yaml).

**What it flags.** Java port of DF004 — `@Tool` annotated method named with a destructive verb has no `confirm()` / `requireApproval()` call inside the body.

**Trigger:** method name regex `^(delete|remove|destroy|drop|send|transfer|charge|email|notify|publish|deploy|shutdown|kill|terminate|wipe|purge|forget|revoke|cancel|refund)([A-Z].*)?$` (camelCase match) matched on a `@Tool` annotated method.

**Suppressors:**

- `$X.confirm(...)` invoked inside the tool body — typical pattern for an injected approval service.
- `$X.requireApproval(...)` invoked inside the tool body — same pattern with a different method name.

## 5. Respond rules

### R001 (Python) — LLM call without audit logging

Source: [agentshield/rules/respond/R001-llm-call-without-audit-logging.yaml](./agentshield/rules/respond/R001-llm-call-without-audit-logging.yaml).

**What it flags.** An LLM call with no surrounding structured logger / callback / tracer — meaning there's no audit trail of what the agent saw, decided, or did.

**LLM call shapes recognised:** identical to DF001 (Python). Same generic + awaited patterns; same SMARTSDK / RADSDK embedding patterns.

**Suppressors (any of these in the file silences the rule):**

- structlog — `import structlog`.
- LangChain callbacks — `from langchain.callbacks import …`, `from langchain_core.callbacks import …`.
- LangSmith — `from langsmith import …`.
- OpenTelemetry — `from opentelemetry import …`.
- A `callbacks=` keyword on any call in scope — `callbacks=$CB`.
- **stdlib logger setup (Phase E.2)** — `$LOGGER = logging.getLogger(...)` or `$LOGGER = getLogger(...)`. The standard Python idiom for an instance-level audit logger; counts as audit-logging intent.
- **boto3 Lambda invocation excluded (Phase E.2)** — `$X.invoke(FunctionName=...)` and `boto3.client("lambda").invoke(...)` are not LLM calls and don't trigger this rule.

**Important:** plain `import logging` and `from logging import …` still deliberately do **not** suppress this rule on their own. The bar is *instance-level setup* (`logger = logging.getLogger(__name__)`) — the bare module import alone is too weak a signal because it's used everywhere for error handling.

### R001 (Java) — LLM call without audit logging

Source: [agentshield/rules/respond/R001-llm-call-without-audit-logging-java.yaml](./agentshield/rules/respond/R001-llm-call-without-audit-logging-java.yaml).

**LLM call shapes recognised:** identical to DF001 (Java).

**Suppressors:**

- SLF4J — `import org.slf4j.Logger`, `import org.slf4j.LoggerFactory`.
- `java.util.logging` — `import java.util.logging.Logger`.
- Log4j — `import org.apache.logging.log4j.…`.
- OpenTelemetry Java — `import io.opentelemetry.…`.

> **R002 removed in Phase E (2026-05-04).** The taint-mode rule for "LLM I/O logged without redaction" was retired after a real Spring AI codebase scan produced a 62% FP rate driven largely by R002 firing on non-LLM logging surfaces (session UUIDs, SAML auth params). The replacement guidance lives in [REMEDIATION_PATTERNS.md §R001](./REMEDIATION_PATTERNS.md#r001--llm-call-without-audit-logging) — when implementing R001's audit logging recommendation, use a redactor / hash / length-projection rather than logging raw I/O. Strategic shift: fewer high-precision rules over many noisy ones.

## 6. Retired-rule → Tier 2 cross-reference

Phase F.2 retired 8 rule families into the Tier 2 LLM-as-scanner checklist. Each entry below maps the retired rule to the Tier 2 check ID(s) that now cover its anti-pattern. The full Tier 2 check definitions live in [`agentshield/skills/tier2_checklist.md.tmpl`](./agentshield/skills/tier2_checklist.md.tmpl).

| Retired rule | Tier 2 successor | Why retired (one-line) |
|---|---|---|
| **D001-fb** (Python + Java fallback) | TIER2-LLM01-01 | Designed for triage by Tier 3; with Tier 3 retired, fallback rules have no consumer |
| **D002** (untrusted document loader) | TIER2-LLM01-02 | Narrow but 0 TPs across 5 phases of OSS testbed |
| **D006** (broad tool permissions) | TIER2-LLM06-02 | Heuristic on tool-permission breadth; FP-prone on framework-internal tools |
| **D007** (unpinned model loading) | TIER2-LLM03-01 | Version-string check; can't tell app's model from vendored test fixture |
| **DF001** (no guardrails import) | TIER2-LLM10-03 | Absence-detection; Phase E needed 5 rounds of fixes and still missed cross-method advisor wiring |
| **DF002** (`@Tool` args schema) | TIER2-LLM06-03 | Heuristic on `@Tool` + bare `String` parameters; FPs on framework tools |
| **DF004** (destructive verb naming) | TIER2-LLM06-01 | Pure name-based heuristic; no taint, high FP |
| **R001** (no audit logging) | TIER2-LLM10-02 | Absence-detection; Phase E.2 had to relax twice (Lombok @Slf4j, stdlib `logger = logging.getLogger(...)`); judge runs showed ~50% FP |
| **R002** (PII-in-logs, retired earlier in Phase E) | TIER2-LLM02-03 + TIER2-GAP-01 + TIER2-GAP-03 | 62%/100%/22% FP rates across three real codebases |

Tier 2 successor IDs are stable; if you want to pin a CI gate to "what Tier 1 used to catch," gate on those Tier 2 rule IDs after `agentshield merge`.

## 7. OWASP Agentic AI Top 10 coverage

| OWASP Agentic | Threat | Rules covering it (Python + Java) | Status |
|---|---|---|---|
| **T1** | Memory Poisoning | D002 | ✅ covered (RAG poisoning via untrusted URL document loaders) |
| **T2** | Tool Misuse | D003, D004, D006, DF002 | ✅ covered (code-exec tools, LLM output → exec sinks, broad-permission tools, missing arg schemas) |
| **T3** | Privilege Compromise | D005, D006 | ✅ covered (hardcoded credentials, broad filesystem / HTTP permissions) |
| **T4** | Resource Overload | DF003 | ✅ covered (`timeout=None` / `max_tokens=None` and the OkHttp / Bedrock equivalents) |
| **T5** | Cascading Hallucinations | — | out of SAST scope (runtime alignment behaviour, not source-code shape) |
| **T6** | Intent Breaking & Goal Manipulation | D001-fw, D001-fb, D002, DF001 | ✅ covered (taint to LLM, indirect prompt injection via RAG, missing guardrails) |
| **T7** | Misaligned & Deceptive Behaviours | — | out of SAST scope (runtime alignment, not source code) |
| **T8** | Repudiation & Untraceability | R001 | ✅ covered (LLM call without structured audit logging) |
| **T9** | Identity Spoofing & Impersonation | — | out of SAST scope (auth / identity infra outside the LLM call surface) |
| **T10** | Overwhelming HITL | DF004 | ✅ covered for destructive-verb tools (delete / send / charge / deploy / etc.) without explicit approval gates |
| **T11** | Unexpected RCE / Code Attacks | D003, D004 | ✅ covered (code-exec tool registration; LLM output to `eval` / `exec` / `os.system` / `subprocess shell=True` / `Runtime.exec` / `ProcessBuilder` / `ScriptEngine.eval` / unparameterized JDBC) |

Each row covers both Python and Java where the rule has a Java port (every rule listed above does). T5 / T7 / T9 are runtime-alignment / identity-infrastructure concerns that AgentShield's static-analysis scope does not reach — they need DAST / red-teaming / IAM review respectively.

## 8. Library cross-reference

Rules that recognise each LLM SDK or framework. The "via" column notes whether coverage is direct (the SDK has dedicated patterns) or indirect (caught by generic verb shapes / fallback verb regex).

### Python

| Library / SDK | Rules | Via |
|---|---|---|
| LangChain (sync + async) | D001-fw, D001-fb, D004, D005, DF001, R001 | direct (verbs `invoke`/`ainvoke`/`run`/`predict`/`generate`/`stream`/`batch`/etc.) + LangChain wrapper credentials in D005 |
| LangChain document loaders | D002 | direct (WebBaseLoader, RecursiveUrlLoader, SitemapLoader, etc.) |
| LangChain agent tools | D003, D006, DF002, DF004 | direct (PythonREPLTool / ShellTool / `@tool` decorator + FileManagementToolkit + Requests*Tool + destructive-verb naming) |
| LlamaIndex | D001-fw, D001-fb, DF001, R001 | direct (`query`/`aquery`/`chat`/`achat`) + fallback import gate |
| OpenAI Python SDK | D001-fw, D001-fb, D004, D005, DF001, DF003, R001 | direct via generic verbs + chat.completions.create / responses.create + hardcoded-key + timeout/max_tokens=None |
| Anthropic Python SDK | D001-fw, D001-fb, D004, D005, DF001, DF003, R001 | direct via generic verbs + messages.create + hardcoded-key + timeout/max_tokens=None |
| AWS Bedrock (boto3) | D001-fw, D001-fb, D004, D005, DF001, R001 | direct via generic verbs (`invoke_model`, `converse`) + hardcoded `aws_access_key_id` / `aws_secret_access_key` + fallback import gate |
| Google Generative AI / Vertex AI | D001-fb, D005, DF001, R001 | indirect via generic verbs + `genai.configure(api_key="…")` + fallback import gate |
| Cohere / Mistral / Together / Groq / Replicate / HuggingFace Hub | D001-fb, D005, DF003 | fallback import gate + verb regex + hardcoded-key + timeout=None |
| Azure OpenAI Python | D001-fb, D005, DF003 | fallback import gate + hardcoded-key + timeout=None |
| SMARTSDK / Google ADK (sync) | D001-fw, D004, DF001, R001 | direct (`runner.run/run_stream/run_async`) |
| SMARTSDK (awaited) | D001-fw, D004, DF001, R001 | direct (`await $X.run`, `await $X.run_stream`, `await $X.run_async`) |
| SMARTSDK (Content/Part-wrapped) | D001-fw | direct (`runner.run(agent, Content(parts=[Part(text=$X)]))`) |
| Generic embeddings (`$MODEL.embed`/`aembed`) | D001-fw, DF001, R001 | direct |
| httpx (HTTP transport for LLM SDKs) | DF003 | direct (`httpx.Client(timeout=None)` / `httpx.AsyncClient(timeout=None)`) |

### Java

| Library / SDK | Rules | Via |
|---|---|---|
| SMARTSDK Java (wraps Google ADK) | D001-fw, D001-fb, D004, DF001, R001 | direct (`runner.run/runStream/runAsync`) |
| langchain4j | D001-fw, D001-fb, D004, D005, DF001, DF003, R001 | direct LLM verbs + URL document loader (D002) + builder `.apiKey("…")` + `.timeout(null)` / `Duration.ZERO` |
| langchain4j document loaders | D002 | direct (`UrlDocumentLoader.load(...)`) |
| langchain4j tools | D003, D006, DF002, DF004 | direct (`@Tool` annotated methods wrapping Runtime.exec / ProcessBuilder / ScriptEngine.eval / Files.delete-write-move / RestTemplate.delete-put; `@Tool` with bare String parameters; destructive-verb method naming) |
| Spring AI | D001-fw, D001-fb, D004, D005, DF001, DF003, R001 | direct (`ChatClient.prompt(...).user(...).call(...)`, Tika/Jsoup readers in D002, `OpenAiApi("…")` constructor in D005) |
| Spring AI tools | D003, D006, DF002, DF004 | direct (`@Tool` annotated methods wrapping shell/script eval / Files mutation / destructive RestTemplate; `@Tool` with bare String parameters; destructive-verb naming) |
| AWS Bedrock Runtime (Java SDK v2) | D001-fw, D001-fb, D004, D005, DF001, DF003, R001 | direct (`client.invokeModel`, `converse`, `converseStream`) + `AwsBasicCredentials.create("…", "…")` + `apiCallTimeout(Duration.ZERO)` |
| AWS SDK v1 (`com.amazonaws.auth`) | D005 | direct (`new BasicAWSCredentials("…", "…")`) |
| Azure OpenAI Java SDK | D001-fw, D001-fb, D004, D005, DF001, R001 | direct (`client.getChatCompletions`, `getCompletions`) + `new AzureKeyCredential("…")` |
| Google ADK Java (direct) | D001-fw, D001-fb, D004, DF001, R001 | direct (`agent.invoke/run`) |
| OpenAI Java SDK (`com.openai`) | D001-fb | fallback import gate + verb regex |
| Anthropic Java SDK (`com.anthropic`) | D001-fb | fallback import gate + verb regex |
| Vertex AI Java (`com.google.cloud.vertexai`) | D001-fb | fallback import gate |
| Apache Tika | D002 | direct (`new Tika().parseToString(new URL(...))`) |
| OkHttp (HTTP transport for Java LLM SDKs) | DF003 | direct (0-second `connectTimeout` / `readTimeout` / `writeTimeout` / `callTimeout`) |
| `java.nio.file.Files` (used inside agent tools) | D006 | direct (`Files.delete` / `Files.deleteIfExists` / `Files.write` / `Files.move` inside `@Tool` methods) |
| Spring `RestTemplate` (used inside agent tools) | D006 | direct (`RestTemplate.delete` / `RestTemplate.put` inside `@Tool` methods) |

`fw` = framework rule (high confidence). `fb` = fallback rule (low confidence) — both v1 concepts. The v1 LLM-judge tier was retired in Phase F.6; v2 has only framework rules at Tier 1.

## 9. Known gaps

- **Python — no async embedding source patterns yet.** Embeddings are matched as sinks for D001 but `await $MODEL.embed(...)` is not separately covered by DF001 / R001 (would need `await $X.embed(...)` / `await $X.aembed(...)` patterns).
- **Python fallback rule — no `await $X.$VERB(...)` form.** The fallback sink pattern is `$X.$VERB($Y, ...)` only; awaited LLM-shaped calls in fallback-only code paths can be missed.
- **Java — Quarkus / Micronaut request annotations not covered.** D001 (Java) recognises Spring (`@RequestParam`/`@RequestBody`/etc.) and JAX-RS (`@QueryParam`/`@FormParam`/etc.) but not Quarkus or Micronaut equivalents.
- **Java — no `CompletableFuture`-chained sinks.** Calls that compose via `.thenApply(model::generate)` style won't match the direct sink patterns.
- **Java — DF002 covers `String` parameters only.** `@Tool` methods with non-`String` params or with three-or-more bare `String` params are not currently flagged; would need additional pattern variants.
- **Java — DF003 doesn't catch ToolSpecification builder without `.parameters(...)`.** semgrep's Java pattern engine doesn't allow `...` between method-chain links, so we can't easily express "no `.parameters()` call anywhere in this builder chain"; only the `@Tool` annotation case is covered.
- **DF004 is name-based.** A destructive tool named `update_user_status` (semantically destructive but no destructive verb prefix) won't match. Also, semantically-safe tools that happen to start with a destructive verb (`delete_old_cache_entries` for a local-only LRU cleanup) will produce false positives — calibrate per repo.
- **D006 doesn't cover MCP servers.** `MultiServerMCPClient(...)` instantiated without an `allowed_tools=` filter exposes whatever the connected MCP server advertises — currently a gap; would need a follow-up rule once MCP usage stabilises.
- ~~**System-prompt-leakage rule (LLM07) not yet implemented.**~~ **Closed.** D008 (Python + Java) added in Phase C — fires on network reads (requests / httpx / urlopen / S3 / SSM) flowing into Anthropic `system=`, OpenAI Responses `instructions=`, LangChain `SystemMessage`, Bedrock Converse system blocks. Java port covers Spring AI / langchain4j / Bedrock equivalents.
- ~~**Data-and-model-poisoning rule (LLM04) not yet implemented.**~~ **Closed.** D007 (Python) added in Phase C — fires on HuggingFace `from_pretrained(...)` / `hf_hub_download(...)` / `snapshot_download(...)` calls without `revision=` pin. Java equivalent intentionally skipped — HuggingFace-style hub-loading isn't a common Java pattern; Java apps mostly use cloud LLM APIs (Bedrock / Azure / OpenAI Java SDK) where model versioning is the cloud provider's concern.
- **Hardcoded credentials — D005 only fires on string literals.** F-strings containing a literal prefix (`api_key=f"sk-{tail}"`) and concatenation (`api_key="sk-" + os.environ[...]`) are not matched; rare in practice but a known false-negative.
- **No retry / no rate-limit detection.** DF003 catches `timeout=None` and `max_tokens=None` but doesn't flag missing `max_retries` or per-tenant rate-limiting.
- **Agentic Top 10 T5 / T7 / T9 are out of SAST scope.** Cascading hallucinations, misaligned behaviours, and identity spoofing are runtime / IAM concerns — handle via DAST, red-teaming, and IAM review respectively.
- **Both languages — only `.py` and `.java` files are scanned.** TypeScript / JavaScript / Go / Rust / C# repos are not covered today; see [agentshield/cli.py](./agentshield/cli.py) `_enumerate_candidate_files()`.
