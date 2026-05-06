# Remediation Patterns

Status: 2026-05-06 (Phase F architecture v2 shipped)
Companion to: [RULES_COVERAGE.md](./RULES_COVERAGE.md), [ROADMAP.md](./ROADMAP.md), [ARCHITECTURE_V2.md](./ARCHITECTURE_V2.md), [TIER2_USAGE.md](./TIER2_USAGE.md), [README.md](./README.md)

> ## ⚠ v2 architecture note
>
> Phase F (2026-05-06) pruned the Tier 1 rule pack to **6 high-precision families**. The patterns from the 8 retired families now live in the **Tier 2 LLM-as-scanner checklist** ([`agentshield/skills/tier2_checklist.md.tmpl`](./agentshield/skills/tier2_checklist.md.tmpl)).
>
> **The remediation guidance below is still correct for retired-rule patterns** — the anti-pattern hasn't changed, just the detection mechanism. If Tier 2 surfaces a `TIER2-LLM06-01` finding (destructive tool without approval), the GOOD pattern in the DF004 section here is still the fix.
>
> Each section below is tagged: 🟢 **[ACTIVE]** if a Tier 1 rule still fires on the BAD pattern, 🔴 **[RETIRED, Tier 2 covers it]** otherwise.

Worked code examples for fixing each AgentShield finding. For every rule (active or retired), this doc shows:

- **BAD** — the pattern AgentShield flags.
- **GOOD** — one or more concrete fixes that suppress the finding (and address the underlying security concern).
- Brief context on *why* the GOOD pattern is the fix.

The BAD / GOOD snippets are extracted from the project's own test fixtures plus the synthetic regression apps — every active-rule pattern shown here is one AgentShield's test suite continuously verifies.

## Contents

- [How to use this document](#how-to-use-this-document)
- [Detect rules](#detect-rules)
  - 🟢 [D001 — unsanitized user input → LLM](#d001--unsanitized-user-input--llm)
  - 🔴 [D002 — untrusted document loader → RAG](#d002--untrusted-document-loader--rag) (Tier 2: TIER2-LLM01-02)
  - 🟢 [D003 — code-execution tool registered](#d003--code-execution-tool-registered)
  - 🟢 [D004 — LLM output → code execution](#d004--llm-output--code-execution)
  - 🟢 [D005 — hardcoded LLM credentials](#d005--hardcoded-llm-credentials)
  - 🔴 [D006 — broad tool permissions](#d006--broad-tool-permissions) (Tier 2: TIER2-LLM06-02)
  - 🔴 [D007 — untrusted model loading](#d007--untrusted-model-loading-python-only) (Tier 2: TIER2-LLM03-01)
  - 🟢 [D008 — untrusted system prompt](#d008--untrusted-system-prompt)
- [Defend rules](#defend-rules)
  - 🔴 [DF001 — LLM call without guardrails](#df001--llm-call-without-guardrails) (Tier 2: TIER2-LLM10-03)
  - 🔴 [DF002 — tool without args schema](#df002--tool-without-args-schema) (Tier 2: TIER2-LLM06-03)
  - 🟢 [DF003 — no timeout / max_tokens cap](#df003--no-timeout--max_tokens-cap)
  - 🔴 [DF004 — destructive tool without human approval](#df004--destructive-tool-without-human-approval) (Tier 2: TIER2-LLM06-01)
- [Respond rules](#respond-rules)
  - 🔴 [R001 — LLM call without audit logging](#r001--llm-call-without-audit-logging) (Tier 2: TIER2-LLM10-02)
- [How to verify the fix](#how-to-verify-the-fix)

## How to use this document

1. Run AgentShield: `agentshield scan <your-code> --output-markdown report.md`.
2. For each rule ID in the report, find the corresponding section here.
3. Compare your code against the BAD pattern and apply the matching GOOD pattern.
4. Re-run AgentShield and confirm the finding is gone (see [How to verify](#how-to-verify-the-fix)).

When in doubt, `tests/fixtures/{python,java}/<rule_id>_*.py` shows the canonical positive (BAD) and negative (GOOD) shapes the rule was tuned against.

---

## Detect rules

### D001 — unsanitized user input → LLM

**Threat:** prompt-injection (OWASP LLM01). User input (HTTP request body, Lambda event, CLI arg) flows directly into an LLM call with no sanitiser between source and sink.

#### Python — BAD

```python
from flask import Flask, request
from langchain_openai import ChatOpenAI

app = Flask(__name__)
chain = ChatOpenAI(model="gpt-4o-mini")

@app.route("/chat", methods=["POST"])
def chat():
    user_question = request.json["q"]
    return chain.invoke(user_question)              # D001 fires here
```

#### Python — GOOD

```python
from flask import Flask, request
from langchain_openai import ChatOpenAI
from rebuff import Rebuff                           # input-injection detector

app = Flask(__name__)
chain = ChatOpenAI(model="gpt-4o-mini")
rb = Rebuff(api_token=os.environ["REBUFF_TOKEN"])

@app.route("/chat", methods=["POST"])
def chat():
    user_question = request.json["q"]
    if rb.detect_injection(user_question).injection_detected:
        return {"error": "Prompt injection detected"}, 400
    return chain.invoke(user_question)
```

Alternative sanitisers AgentShield recognises: `nemoguardrails.LLMRails(...).generate(...)`, `lakera_guard.detect(...)`, `presidio_analyzer.AnalyzerEngine().analyze(...)`, `bleach.clean(...)`, `html.escape(...)`. Any of these between source and sink suppress the finding.

#### Java — BAD

```java
@RestController
public class ChatController {
    private final ChatClient chatClient;

    @GetMapping("/chat")
    public String chat(@RequestParam String q) {
        return chatClient.prompt().user(q).call().content();   // D001-Java fires
    }
}
```

#### Java — GOOD

```java
@RestController
public class ChatController {
    private final ChatClient chatClient;
    private final LakeraGuard guard;

    @GetMapping("/chat")
    public String chat(@RequestParam String q) {
        if (!guard.isSafe(q)) {                                // D001-Java suppressed
            throw new SecurityException("Lakera flagged the prompt");
        }
        return chatClient.prompt().user(q).call().content();
    }
}
```

Alternative Java sanitisers: `Encode.forJava(...)` / `Encode.forHtml(...)` (OWASP Encoder), `StringEscapeUtils.escapeHtml4(...)` / `escapeJava(...)` (Apache Commons Text). Spring AI's built-in `SafeGuardAdvisor` registered on the `ChatClient` is the most idiomatic option.

---

### D002 — untrusted document loader → RAG

**Threat:** indirect prompt injection / RAG poisoning (OWASP LLM01 indirect, LLM08). Loading content from URLs without an allowlist lets an attacker plant instructions in your RAG index.

#### Python — BAD

```python
from langchain_community.document_loaders import WebBaseLoader

def ingest(url: str):
    loader = WebBaseLoader(url)
    return loader.load()                                   # D002 fires
```

#### Python — GOOD

```python
from urllib.parse import urlparse
from langchain_community.document_loaders import WebBaseLoader

ALLOWED_HOSTS = {"docs.example.com", "internal-wiki.corp"}

def ingest(url: str):
    host = urlparse(url).netloc
    if host not in ALLOWED_HOSTS:                         # allowlist guard
        raise ValueError(f"URL host '{host}' not in allowlist")
    loader = WebBaseLoader(url)
    return loader.load()
```

AgentShield's D002 suppressors: `if $URL in $ALLOWLIST: ...`, `if $URL.startswith($PREFIX): ...`, `assert $URL in $ALLOWLIST`. Any of these wrapping the loader call suppress the finding.

#### Java — BAD

```java
@GetMapping("/ingest")
public Document ingest(@RequestParam String url) throws Exception {
    return UrlDocumentLoader.load(url, null);            // D002-Java fires
}
```

#### Java — GOOD

```java
private static final Set<String> ALLOWED_HOSTS =
    Set.of("docs.example.com", "internal-wiki.corp");

@GetMapping("/ingest")
public Document ingest(@RequestParam String url) throws Exception {
    URI uri = URI.create(url);
    if (!ALLOWED_HOSTS.contains(uri.getHost())) {
        throw new SecurityException("URL host not in allowlist: " + uri.getHost());
    }
    return UrlDocumentLoader.load(url, null);
}
```

For Spring AI, prefer wrapping the `TikaDocumentReader` / `JsoupDocumentReader` construction behind an allowlist-checking factory rather than calling them directly with user-supplied URLs.

---

### D003 — code-execution tool registered

**Threat:** arbitrary code execution (OWASP LLM05/LLM06, Agentic T2/T11). The agent has access to `eval` / `exec` / shell as a tool — anything the LLM emits can run.

#### Python — BAD

```python
from langchain.agents import initialize_agent, Tool
from langchain_experimental.tools import PythonREPLTool
from langchain_community.tools import ShellTool
from langchain_openai import ChatOpenAI

llm = ChatOpenAI()
tools = [PythonREPLTool(), ShellTool()]                  # D003 fires
agent = initialize_agent(tools, llm)
```

#### Python — GOOD (sandboxed code execution)

```python
from langchain_azure_ai.tools import SessionsPythonREPLTool
from langchain.agents import initialize_agent
from langchain_openai import ChatOpenAI

# Azure-hosted sandboxed REPL — runs in an isolated session,
# no access to the host filesystem or network.
sandbox_tool = SessionsPythonREPLTool(pool_management_endpoint="...")

llm = ChatOpenAI()
agent = initialize_agent([sandbox_tool], llm)            # D003 still fires (any *REPLTool is flagged)
```

**The honest answer:** D003 is intentionally unsuppressible — exposing code-execution tools to an LLM is a fundamental risk decision that no static rule can absolve. The remediation is one of:

1. **Don't expose code-execution tools.** Replace with narrower domain-specific tools (e.g. instead of `PythonREPLTool`, expose a `calculate(expression: str)` tool that uses `ast.literal_eval` or a pinned formula evaluator).
2. **Run in a hardened sandbox** (Docker / Firecracker / gVisor / Azure Sessions REPL / SessionsPythonREPLTool) AND require human approval for every invocation.
3. **Document the risk acceptance** explicitly — the finding stands as the audit-trail entry for that decision.

#### Java — BAD

```java
@Tool("execute a shell command")
public String shell(String cmd) throws Exception {
    Process p = Runtime.getRuntime().exec(cmd);          // D003-Java fires
    return new String(p.getInputStream().readAllBytes());
}
```

#### Java — GOOD (replace with a narrow tool)

```java
@Tool("calculate an arithmetic expression — supports +, -, *, /, parentheses only")
public double calculate(@P("expression like '2 + 3 * (4 - 1)'") String expr) {
    return new ExpressionEvaluator().evaluate(expr);     // narrow, deterministic
}
// No Runtime.exec / ProcessBuilder / ScriptEngine.eval anywhere.
```

Same risk-acceptance framing as Python — if you genuinely need shell access, sandbox it (`SecurityManager`-restricted classloader, Docker, Firecracker), require human approval per call, and accept that D003-Java will continue to fire as the audit record.

---

### D004 — LLM output → code execution

**Threat:** LLM output (attacker-controllable via prompt injection) flows into an executor (OWASP LLM05).

#### Python — BAD

```python
import os
from langchain_openai import ChatOpenAI

llm = ChatOpenAI()
response = llm.invoke("write me a shell command")
os.system(response.content)                              # D004 fires
```

#### Python — GOOD

```python
import shlex
import subprocess
from langchain_openai import ChatOpenAI

llm = ChatOpenAI()
response = llm.invoke("write me a shell command")
# shlex.split tokenises into argv — no shell interpretation.
# Combined with subprocess(shell=False) (the default), no command injection.
subprocess.run(shlex.split(response.content), check=True)
```

D004's Python sanitisers: `shlex.split(...)`, `shlex.quote(...)`, `ast.literal_eval(...)` (when the LLM is meant to return a literal). For SQL specifically, use parameterised queries — never f-string the LLM output into a SQL body.

#### Java — BAD

```java
public void analyzeAndRun(@RequestParam String userPrompt) throws Exception {
    String suggestedCommand = chatClient.prompt().user(userPrompt).call().content();
    Runtime.getRuntime().exec(suggestedCommand);         // D004-Java fires
}
```

#### Java — GOOD

```java
import org.owasp.encoder.Encode;

public void analyzeAndRun(@RequestParam String userPrompt) throws Exception {
    String suggested = chatClient.prompt().user(userPrompt).call().content();
    String safe = Encode.forJava(suggested);             // sanitiser — D004-Java suppressed
    log.info("LLM suggested (encoded): {}", safe);       // log it; do NOT exec it
    // If exec is genuinely required, validate `safe` against an allowlist of
    // permitted commands first.
}

// For SQL — use PreparedStatement, never Statement.execute*:
public void analyzeAndQuery(@RequestParam String prompt) throws Exception {
    String reason = chatClient.prompt().user(prompt).call().content();
    // BAD: stmt.executeQuery("SELECT * FROM audit WHERE reason = '" + reason + "'");
    PreparedStatement ps = conn.prepareStatement(
        "INSERT INTO audit (user_id, reason) VALUES (?, ?)");
    ps.setLong(1, userId);
    ps.setString(2, reason);                             // bound — no injection
    ps.executeUpdate();
}
```

D004-Java sanitisers: `Encode.forJava(...)`, `StringEscapeUtils.escapeJava(...)`, JDBC parameter binding (`$PS.setString/setInt/setLong(...)`), Lakera Guard (`$G.detect/scan/guard/isSafe(...)`).

---

### D005 — hardcoded LLM credentials

**Threat:** CWE-798. Secrets in source code end up in git history, container images, CI logs.

#### Python — BAD

```python
client = openai.OpenAI(api_key="sk-proj-AAAAAAAAAAAAAAAAAAAA")   # D005 fires
```

#### Python — GOOD

```python
import os

# (1) Default credential resolver — omit api_key entirely; SDK reads env var
client = openai.OpenAI()                          # uses OPENAI_API_KEY env var

# (2) Explicit env var lookup
client = openai.OpenAI(api_key=os.environ["OPENAI_API_KEY"])

# (3) AWS Secrets Manager
import boto3
secrets = boto3.client("secretsmanager")
api_key = secrets.get_secret_value(SecretId="prod/openai-key")["SecretString"]
client = openai.OpenAI(api_key=api_key)
```

For AWS Bedrock specifically, use the default credential chain (IAM role / instance profile) — `boto3.client("bedrock-runtime", region_name="us-east-1")` with NO `aws_access_key_id` / `aws_secret_access_key` kwargs.

**If a credential was committed**, treat it as compromised — rotate it immediately. Removing it from HEAD doesn't remove it from git history; anyone who cloned has it forever.

#### Java — BAD

```java
return OpenAiChatModel.builder()
    .apiKey("sk-proj-AAAAAAAAAAAAAAAAAAAA")        // D005-Java fires
    .build();
```

#### Java — GOOD

```java
// (1) Spring @Value from environment / config server
@Value("${OPENAI_API_KEY}")
private String openAiKey;

return OpenAiChatModel.builder().apiKey(openAiKey).build();

// (2) Direct env-var lookup
return OpenAiChatModel.builder()
    .apiKey(System.getenv("OPENAI_API_KEY"))
    .build();

// (3) AWS Bedrock default credential chain
return BedrockRuntimeClient.builder()
    .credentialsProvider(DefaultCredentialsProvider.create())   // IAM role / instance profile
    .build();
```

---

### D006 — broad tool permissions

**Threat:** filesystem mutation or unrestricted HTTP exposed to the LLM (OWASP LLM06, Agentic T2/T3).

#### Python — BAD

```python
from langchain_community.agent_toolkits import FileManagementToolkit
from langchain_community.tools.requests.tool import RequestsPostTool

toolkit = FileManagementToolkit(root_dir="/tmp")           # D006 fires (no selected_tools=)
post = RequestsPostTool(
    requests_wrapper=wrapper,
    allow_dangerous_requests=True,                         # D006 fires
)
```

#### Python — GOOD

```python
# (1) Narrow the file toolkit to read-only operations
toolkit = FileManagementToolkit(
    root_dir="/tmp",
    selected_tools=["read_file", "list_directory"],        # D006 suppressed
)

# (2) For HTTP, omit allow_dangerous_requests=True (default is False)
get_tool = RequestsGetTool(requests_wrapper=wrapper)       # safe by default
# If you genuinely need state-changing HTTP, build a custom tool with
# a host allowlist and per-call human approval.
```

#### Java — BAD

```java
@Tool("delete a file from the workspace")
public void deleteFile(@P("file path") String path) throws Exception {
    Files.delete(Path.of(path));                           // D006-Java fires
}
```

#### Java — GOOD

```java
// Replace destructive file tools with read-only equivalents
@Tool("read a file from the workspace")
public String readFile(@P("file path") String path) throws Exception {
    Path p = Path.of(path).normalize();
    if (!p.startsWith(Path.of("/tmp/sandbox"))) {          // sandbox check
        throw new SecurityException("Path outside allowed sandbox");
    }
    return Files.readString(p);                            // D006-Java suppressed
}
```

For destructive HTTP via RestTemplate, the rule's `metavariable-type: RestTemplate` constraint means using a different HTTP client (WebClient, OkHttp, Apache HttpClient) bypasses the rule — but the underlying risk is the same. Use a custom tool with a host allowlist regardless of which HTTP client.

---

### D007 — untrusted model loading (Python only)

**Threat:** HuggingFace `from_pretrained` / `hf_hub_download` / `snapshot_download` without `revision=` pin. The default `main` branch can be force-pushed; your next download silently switches to whatever's there. OWASP LLM03 + LLM04.

#### Python — BAD

```python
from transformers import AutoModel, AutoTokenizer

model = AutoModel.from_pretrained("bert-base-uncased")             # D007 fires
tokenizer = AutoTokenizer.from_pretrained("bert-base-uncased")     # D007 fires
```

#### Python — GOOD

```python
from transformers import AutoModel, AutoTokenizer

# Pin to a specific commit SHA. Find it on
# https://huggingface.co/<org>/<model>/commits/main
PINNED_REVISION = "86b5e0934494bd15c9632b12f734a8a67f723594"

model = AutoModel.from_pretrained("bert-base-uncased", revision=PINNED_REVISION)
tokenizer = AutoTokenizer.from_pretrained("bert-base-uncased", revision=PINNED_REVISION)
```

Use the full commit SHA, not a tag name — tags can be re-pointed to a different commit. For air-gapped deployments, mirror the model to a private artifact store and load from there.

D007 has no Java port — the HuggingFace-style hub-loading pattern is rare in Java. Java apps typically use cloud LLM APIs (Bedrock / Azure / Vertex) where model versioning is the cloud provider's concern.

---

### D008 — untrusted system prompt

**Threat:** system prompt loaded from a network source. An attacker who controls the source can inject instructions that override developer intent (OWASP LLM07).

#### Python — BAD

```python
import requests
import anthropic

client = anthropic.Anthropic()
remote_prompt = requests.get("https://prompts.example/system.txt").text
client.messages.create(
    model="claude-sonnet-4-5",
    max_tokens=512,
    system=remote_prompt,                                  # D008 fires
    messages=[{"role": "user", "content": "hi"}],
)
```

#### Python — GOOD

```python
# (1) Bake into source — a constant string
SYSTEM_PROMPT = "You are a helpful assistant. Refuse off-topic queries."
client.messages.create(model="...", system=SYSTEM_PROMPT, ...)

# (2) Load from a packaged file (no network read at runtime)
import importlib.resources
with importlib.resources.files("myapp").joinpath("system_prompt.txt").open() as f:
    SYSTEM_PROMPT = f.read()

# (3) HMAC-verified network read (D008 sanitiser pattern)
import hmac, hashlib
SIGNING_KEY = os.environ["PROMPT_SIGNING_KEY"].encode()
EXPECTED_SIG = os.environ["PROMPT_SIG"]

response = requests.get("https://prompts.example/system.txt")
candidate = response.text
computed_sig = hmac.new(SIGNING_KEY, candidate.encode(), hashlib.sha256).hexdigest()
if hmac.compare_digest(computed_sig, EXPECTED_SIG):
    SYSTEM_PROMPT = candidate
else:
    raise SecurityError("Prompt signature verification failed")
```

#### Java — BAD

```java
String prompt = rest.getForObject(url, String.class);
return SystemMessage.from(prompt);                         // D008-Java fires
```

#### Java — GOOD

```java
// (1) Constant
return SystemMessage.from("You are a helpful assistant. Refuse off-topic queries.");

// (2) JAR resource
try (InputStream in = getClass().getResourceAsStream("/system_prompt.txt")) {
    String prompt = new String(in.readAllBytes(), StandardCharsets.UTF_8);
    return SystemMessage.from(prompt);
}

// (3) MAC-verified — extract the verification into a wrapper function
//     since semgrep's intra-procedural taint can't follow inline HMAC checks
private String fetchVerifiedPrompt(String url) throws Exception {
    String candidate = rest.getForObject(url, String.class);
    Mac mac = Mac.getInstance("HmacSHA256");
    mac.init(new SecretKeySpec(signingKey, "HmacSHA256"));
    byte[] computed = mac.doFinal(candidate.getBytes(StandardCharsets.UTF_8));
    if (MessageDigest.isEqual(computed, expectedMac)) {
        return candidate;
    }
    throw new SecurityException("Prompt MAC verification failed");
}
```

---

## Defend rules

### DF001 — LLM call without guardrails

**Threat:** LLM invocation without any input/output filter library imported. Absence detection — calibrate severity per repo. OWASP LLM01 + LLM05.

#### Python — BAD

```python
from langchain_openai import ChatOpenAI

chain = ChatOpenAI()
result = chain.invoke(user_prompt)                         # DF001 fires (no guardrails import)
```

#### Python — GOOD (any of these imports suppresses DF001)

```python
import nemoguardrails                                      # DF001 suppressed
# or:
from nemoguardrails import LLMRails
# or:
import lakera_chainguard
# or:
import rebuff
# or:
import guardrails                                          # Guardrails-AI
# or:
import presidio_analyzer
# or:
from llama_guard import LlamaGuardClient
```

**Practical recommendation for a SMARTSDK / Python LLM app:**

```python
# Combined input + PII protection
import nemoguardrails           # input/output rails (jailbreak, off-topic, etc.)
import presidio_analyzer        # PII redaction specifically

from nemoguardrails import LLMRails, RailsConfig
from presidio_analyzer import AnalyzerEngine
from presidio_anonymizer import AnonymizerEngine

config = RailsConfig.from_path("./rails-config")           # YAML + Colang
rails = LLMRails(config)
analyzer = AnalyzerEngine()
anonymizer = AnonymizerEngine()

def safe_invoke(user_prompt: str) -> str:
    # Redact PII before the prompt enters the LLM
    pii_results = analyzer.analyze(text=user_prompt, language="en")
    clean_prompt = anonymizer.anonymize(text=user_prompt, analyzer_results=pii_results).text
    # Run through NeMo's input + output rails
    response = rails.generate(messages=[{"role": "user", "content": clean_prompt}])
    return response["content"]
```

#### Java — BAD

```java
return chatClient.prompt().user(userPrompt).call().content();   // DF001-Java fires
```

#### Java — GOOD (any of these imports suppresses DF001-Java)

```java
import com.lakera.guard.LakeraGuard;                       // DF001-Java suppressed
// or:
import org.owasp.encoder.Encode;
// or:
import org.apache.commons.text.StringEscapeUtils;
// or — Spring AI built-in advisors are the easiest path
import org.springframework.ai.chat.client.advisor.SafeGuardAdvisor;
import org.springframework.ai.moderation.ModerationModel;
```

**Practical Spring AI recommendation:**

```java
import org.springframework.ai.chat.client.advisor.SafeGuardAdvisor;
import org.springframework.ai.chat.client.advisor.PromptChatMemoryAdvisor;

@RestController
public class ChatController {
    private final ChatClient chatClient;

    public ChatController(ChatClient.Builder builder) {
        this.chatClient = builder
            .defaultAdvisors(
                new SafeGuardAdvisor(List.of("prompt-injection", "off-topic")),
                new PromptChatMemoryAdvisor(chatMemory)    // also useful for audit-trail (R001)
            )
            .build();
    }
}
```

---

### DF002 — tool without args schema

**Threat:** LLM tool with no parameter schema gives the LLM no description/constraints — classic excessive-agency vector (OWASP LLM06, Agentic T2).

#### Python — BAD

```python
from langchain.tools import tool, Tool

@tool
def lookup_user(user_id: str) -> str:                      # DF002 fires (no args_schema)
    return f"user record for {user_id}"

unschema_tool = Tool(
    name="lookup",
    func=lookup_user_fn,
    description="lookup a user",                            # DF002 fires
)
```

#### Python — GOOD

```python
from langchain.tools import tool, Tool
from pydantic import BaseModel, Field

class LookupSchema(BaseModel):
    user_id: str = Field(description="The user's UUID, format: 8-4-4-4-12 hex")

@tool(args_schema=LookupSchema)                            # DF002 suppressed
def lookup_user(user_id: str) -> str:
    return f"user record for {user_id}"

# Or for the Tool() / StructuredTool form:
schemed_tool = Tool(
    name="lookup",
    func=lookup_user_fn,
    description="lookup a user",
    args_schema=LookupSchema,                              # DF002 suppressed
)
```

#### Java — BAD

```java
@Tool("look up a user by name")
public String lookupUser(String name) {                    // DF002-Java fires (no @P)
    return "user record for " + name;
}
```

#### Java — GOOD

```java
import dev.langchain4j.agent.tool.P;
import dev.langchain4j.agent.tool.Tool;

@Tool("look up a user by name")
public String lookupUser(@P("the user's full name, ASCII only") String name) {
    return "user record for " + name;                      // DF002-Java suppressed
}
```

For Spring AI, use `@ToolParam` instead of `@P`. The annotation gives the LLM a description of the parameter and a place to constrain values (regex, allowed enum, range).

---

### DF003 — no timeout / max_tokens cap

**Threat:** explicit `timeout=None` / `max_tokens=None` lets a single request hang a worker indefinitely or generate runaway output. OWASP LLM10 (Unbounded Consumption), Agentic T4. CWE-400.

#### Python — BAD

```python
client = openai.OpenAI(api_key=..., timeout=None)          # DF003 fires
chat = ChatOpenAI(model="gpt-4o-mini", max_tokens=None)    # DF003 fires
response = client.chat.completions.create(
    model="gpt-4o-mini",
    messages=[...],
    max_tokens=None,                                        # DF003 fires
)
```

#### Python — GOOD

```python
client = openai.OpenAI(api_key=..., timeout=30.0)          # finite seconds
chat = ChatOpenAI(model="gpt-4o-mini", max_tokens=512)     # cap output
response = client.chat.completions.create(
    model="gpt-4o-mini",
    messages=[...],
    max_tokens=256,
    timeout=15.0,
)

# Combine with retry budget + per-tenant rate limiting upstream
client = openai.OpenAI(api_key=..., timeout=30.0, max_retries=2)
```

DF003 only fires on EXPLICIT `None`. Omitting the kwarg entirely (using SDK defaults) is fine — most SDKs default to a finite 600s timeout.

#### Java — BAD

```java
OpenAiChatModel.builder()
    .apiKey(...)
    .timeout(null)                                          // DF003-Java fires
    .build();

OpenAiChatModel.builder()
    .apiKey(...)
    .timeout(Duration.ZERO)                                 // DF003-Java fires
    .build();

new OkHttpClient.Builder()
    .connectTimeout(0, TimeUnit.SECONDS)                   // DF003-Java fires (0 = no timeout in OkHttp)
    .build();
```

#### Java — GOOD

```java
OpenAiChatModel.builder()
    .apiKey(...)
    .timeout(Duration.ofSeconds(30))                       // finite Duration
    .maxTokens(512)                                         // cap output
    .build();

new OkHttpClient.Builder()
    .connectTimeout(10, TimeUnit.SECONDS)
    .readTimeout(30, TimeUnit.SECONDS)
    .build();
```

For AWS Bedrock direct, configure `ClientOverrideConfiguration.builder().apiCallTimeout(Duration.ofSeconds(30))` and a finite `RetryPolicy`.

---

### DF004 — destructive tool without human approval

**Threat:** `@tool` / `@Tool` named with destructive verb (delete / send / charge / deploy / etc.) without a HITL gate. The LLM can invoke autonomously. OWASP LLM06, Agentic T10.

#### Python — BAD

```python
from langchain.tools import tool

@tool
def delete_user(user_id: str) -> str:                      # DF004 fires
    return user_service.delete(user_id)

@tool
def send_email(recipient: str, body: str) -> str:          # DF004 fires
    return email_service.send(recipient, body)
```

#### Python — GOOD (any of these suppresses DF004)

```python
from langchain.tools import tool
from langchain.callbacks.human import HumanApprovalCallbackHandler   # DF004 suppressed

# (1) Inline confirmation prompt
@tool
def delete_user(user_id: str) -> str:
    if input(f"Confirm delete {user_id}? [y/N] ").strip().lower() != "y":
        return "aborted"
    return user_service.delete(user_id)

# (2) HumanApprovalCallbackHandler imported (framework-level approval gating)
agent.invoke({"input": "..."}, callbacks=[HumanApprovalCallbackHandler()])

# (3) LangGraph interrupt_before for graph-level breakpoints
graph.compile(interrupt_before=["delete_user_node"])
```

#### Java — BAD

```java
@Tool("delete a user account")
public String deleteUser(@P("user id") String userId) {    // DF004-Java fires
    return userService.delete(userId);
}
```

#### Java — GOOD

```java
@Tool("delete a user account")
public String deleteUser(@P("user id") String userId) {
    approvalService.confirm("delete user " + userId);      // DF004-Java suppressed
    return userService.delete(userId);
}

// Or:
@Tool("delete a user account")
public String deleteUser(@P("user id") String userId) {
    approvalService.requireApproval("delete user " + userId);
    return userService.delete(userId);
}
```

For high-risk actions (payments, mass deletes, deploys), require multi-party approval through your existing change-management system.

---

## Respond rules

### R001 — LLM call without audit logging

**Threat:** no structured logger / callback / tracer around the LLM call. Without an audit trail you can't reconstruct what the agent saw, decided, or did. OWASP LLM10 (audit side), Agentic T8.

#### Python — BAD

```python
import logging                                              # plain logging — DOES NOT suppress
log = logging.getLogger(__name__)

def chat(prompt):
    return chain.invoke(prompt)                            # R001 fires
```

#### Python — GOOD

```python
import structlog                                            # R001 suppressed

log = structlog.get_logger()

def chat(prompt):
    response = chain.invoke(prompt)
    log.info("llm_call", prompt_len=len(prompt), response_len=len(response.content))
    return response
```

R001 suppressors: `import structlog`, `from langchain.callbacks import …`, `from langchain_core.callbacks import …`, `from langsmith import …`, `from opentelemetry import …`, or a `callbacks=$CB` keyword on any call. **Plain `import logging` deliberately does NOT suppress** — most apps have stdlib logging for errors but no structured LLM audit trail.

**Companion concern (no longer rule-enforced — judgment-only):** once you're logging LLM I/O, redact it. Use one-way hashes, a redactor like Presidio, or length-only projections. Plain `log.info(prompt)` puts raw user-supplied content into the log stream — a sensitive-information-disclosure surface even if the audit gap itself is closed. (Earlier versions of AgentShield enforced this via the R002 rule. R002 was retired in Phase E because it produced too many FPs on non-LLM logging surfaces; the principle stands but is now reviewer-judgment, not SAST.)

```python
# Redaction patterns (review-per-deployment, no rule enforces these):
import hashlib
prompt_hash = hashlib.sha256(prompt.encode()).hexdigest()
log.info(f"User asked (hash={prompt_hash})")              # (1) hash

from presidio_analyzer import AnalyzerEngine
from presidio_anonymizer import AnonymizerEngine
analyzer, anonymizer = AnalyzerEngine(), AnonymizerEngine()
results = analyzer.analyze(text=prompt, language="en")
safe = anonymizer.anonymize(text=prompt, analyzer_results=results).text
log.info(f"User asked: {safe}")                           # (2) redact

log.info(f"prompt_len={len(prompt)} response_len={len(response.content)}")  # (3) length-only
```

#### Java — BAD

```java
public String chat(String prompt) {
    return chatClient.prompt().user(prompt).call().content();   // R001-Java fires
}
```

#### Java — GOOD

```java
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;                            // R001-Java suppressed

private static final Logger log = LoggerFactory.getLogger(MyClass.class);

public String chat(String prompt) {
    String response = chatClient.prompt().user(prompt).call().content();
    log.info("llm_call promptLen={} responseLen={}", prompt.length(), response.length());
    return response;
}
```

Or using Lombok (Phase E recognises this as a logger import):

```java
import lombok.extern.slf4j.Slf4j;

@Slf4j                                                     // R001-Java suppressed
public class ChatService {
    public String chat(String prompt) {
        String response = chatClient.prompt().user(prompt).call().content();
        log.info("llm_call promptLen={} responseLen={}", prompt.length(), response.length());
        return response;
    }
}
```

R001-Java suppressors: SLF4J, java.util.logging, Log4j, OpenTelemetry Java imports, Lombok `@Slf4j`.

**Companion redaction patterns (judgment-only, not rule-enforced):**

```java
// (1) Hash
byte[] hash = MessageDigest.getInstance("SHA-256")
    .digest(prompt.getBytes(StandardCharsets.UTF_8));
log.info("User asked (hash={})", Base64.getEncoder().encodeToString(hash));

// (2) Redactor (in-house ScrubbingCallAdvisor, OWASP Encoder, etc.)
log.info("User asked: {}", redactor.redact(prompt));

// (3) Length only
log.info("prompt len={} response len={}", prompt.length(), response.length());
```

---

## How to verify the fix

After applying any of the patterns above, run AgentShield against the same code and confirm the finding is gone:

```bash
# Before the fix
agentshield scan /path/to/your/code --no-judge --output-markdown before.md

# Apply the GOOD pattern from this doc

# After the fix
agentshield scan /path/to/your/code --no-judge --output-markdown after.md

# The targeted finding should be gone (or reduced)
diff before.md after.md
```

If the finding persists after applying the GOOD pattern, three common reasons:

1. **The sanitiser/import is in a different file** than the LLM call. Most rules use `pattern-not-inside` at file scope — the suppressor must be in the same source file as the call. Bringing the import to the call site fixes this.
2. **The sanitiser is *named* what AgentShield expects but doesn't actually do anything**. The rules trust method names (`$X.redact(...)`, `$X.guard(...)`) as a heuristic. If your `redact()` is a no-op stub, the rule is correctly suppressed but the underlying risk remains. The audit trail is on you.
3. **You have multiple rules firing on the same line** — fixing one (e.g. importing `structlog` to suppress R001) may not fix others. Address each rule independently.

When in doubt, `tests/fixtures/{python,java}/<rule_id>_*.py` shows the canonical positive (BAD) and negative (GOOD) shapes — diff your code against the negative fixture for the rule you're trying to suppress.
