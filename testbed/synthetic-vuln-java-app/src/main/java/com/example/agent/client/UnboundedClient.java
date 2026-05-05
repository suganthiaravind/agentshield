// Anti-pattern: DF003 Java (no timeout / max_tokens cap on LLM client + OkHttp).
// Also fires DF001 + R001.
package com.example.agent.client;

import dev.langchain4j.model.openai.OpenAiChatModel;
import okhttp3.OkHttpClient;

import java.time.Duration;
import java.util.concurrent.TimeUnit;

public class UnboundedClient {

    public OpenAiChatModel nullTimeout() {
        return OpenAiChatModel.builder()
                .apiKey(System.getenv("OPENAI_API_KEY"))
                .timeout(null)
                .build();
    }

    public OpenAiChatModel nullMaxTokens() {
        return OpenAiChatModel.builder()
                .apiKey(System.getenv("OPENAI_API_KEY"))
                .maxTokens(null)
                .build();
    }

    public OpenAiChatModel zeroDuration() {
        return OpenAiChatModel.builder()
                .apiKey(System.getenv("OPENAI_API_KEY"))
                .timeout(Duration.ZERO)
                .build();
    }

    public OkHttpClient unboundedHttp() {
        return new OkHttpClient.Builder()
                .connectTimeout(0, TimeUnit.SECONDS)
                .readTimeout(0, TimeUnit.SECONDS)
                .build();
    }
}
