// Fixture: should trigger DF003-java (no timeout / token cap).
// langchain4j builders pass null for timeout / maxTokens; OkHttp transport
// uses 0-second timeouts (= disabled). OWASP LLM10.
package com.example.vuln;

import dev.langchain4j.model.openai.OpenAiChatModel;
import okhttp3.OkHttpClient;

import java.time.Duration;
import java.util.concurrent.TimeUnit;

public class UnboundedLlm {

    public OpenAiChatModel nullTimeout() {
        return OpenAiChatModel.builder()
                .apiKey(System.getenv("OPENAI_API_KEY"))
                .timeout(null)  // DF003-java
                .build();
    }

    public OpenAiChatModel nullMaxTokens() {
        return OpenAiChatModel.builder()
                .apiKey(System.getenv("OPENAI_API_KEY"))
                .maxTokens(null)  // DF003-java
                .build();
    }

    public OpenAiChatModel zeroDuration() {
        return OpenAiChatModel.builder()
                .apiKey(System.getenv("OPENAI_API_KEY"))
                .timeout(Duration.ZERO)  // DF003-java
                .build();
    }

    public OkHttpClient unboundedHttp() {
        return new OkHttpClient.Builder()
                .connectTimeout(0, TimeUnit.SECONDS)  // DF003-java
                .readTimeout(0, TimeUnit.SECONDS)  // DF003-java
                .build();
    }
}
