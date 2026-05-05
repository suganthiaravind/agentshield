# synthetic-vuln-java-app

> **Synthetic, intentionally vulnerable Spring AI / langchain4j application.**
> Java parity to `moip-cost-anomaly-probe-lambda` (synthetic SMARTSDK Lambda).
> Exists ONLY as a known-answer regression target for AgentShield's Java
> anti-pattern rules. Do not deploy. Do not borrow patterns from this code.

## Purpose

Phase A of testbed validation revealed that the Java rules detecting
*anti-patterns* (D003 / D004 / D005 / D006 / DF003 / DF004 / DF002 Java)
fired zero times across our real-app testbed (langchain4j, spring-ai-examples,
langchain4j-examples, aws-bedrock-java-examples). That's a **positive signal
about rule precision** — best-practice demos intentionally avoid these
patterns — but it leaves the rules without real-world validation that they
fire correctly when the patterns ARE present.

This app intentionally contains every anti-pattern the Java rules detect,
in shapes that mirror real Spring AI / langchain4j applications. Each file
is a known-answer regression check.

## Expected AgentShield findings

| Rule | File | Why |
|---|---|---|
| D001 Java | `controller/ChatController.java` | `@RequestParam` user input flows into `ChatClient.prompt(...).user(...)` with no sanitizer |
| D002 Java | `controller/RagController.java` | `TikaDocumentReader(new UrlResource(...))` reads from a URL with no allowlist |
| D003 Java | `tools/DangerousTools.java` | `@Tool` methods wrap `Runtime.exec` / `ProcessBuilder` / `ScriptEngine.eval` |
| D004 Java | `controller/AnalysisController.java` | LLM output flows directly into `Runtime.exec` and `Statement.executeQuery` |
| D005 Java | `config/HardcodedKeys.java` | `OpenAiChatModel.builder().apiKey("sk-…")`, `new AzureKeyCredential("…")`, `AwsBasicCredentials.create("…", "…")` literals |
| D006 Java | `tools/BroadFileTools.java` | `@Tool` methods wrap `Files.delete` / `Files.write` / `RestTemplate.put` |
| DF001 Java | every controller / tool above | none of the files import a guardrail (Lakera / OWASP Encoder / Apache Commons Text / Spring AI advisors) |
| DF002 Java | `tools/BareParamTools.java` | `@Tool` methods take `String` params with no `@P` / `@ToolParam` annotation |
| DF003 Java | `client/UnboundedClient.java` | `OpenAiChatModel.builder()` with `.timeout(null)`, `.maxTokens(null)`, OkHttp `0`-second timeouts |
| DF004 Java | `tools/DestructiveActionTools.java` | `@Tool` methods named `deleteX` / `sendX` / `chargeX` / `deployX` with no `confirm()` / `requireApproval()` call |
| R001 Java | every controller / tool above | none import SLF4J / OpenTelemetry / java.util.logging / Log4j |

Total: **11 distinct files**, each focused on one (or one-and-DF001/R001) finding family.

## Layout

```
src/main/java/com/example/agent/
    controller/
        ChatController.java          # D001 Java + DF001 + R001
        RagController.java           # D002 Java + DF001 + R001
        AnalysisController.java      # D004 Java + DF001 + R001
    tools/
        DangerousTools.java          # D003 Java + DF001 + R001
        BroadFileTools.java          # D006 Java + DF001 + R001
        BareParamTools.java          # DF002 Java + DF001 + R001
        DestructiveActionTools.java  # DF004 Java + DF001 + R001
    config/
        HardcodedKeys.java           # D005 Java
    client/
        UnboundedClient.java         # DF003 Java + DF001 + R001
```
