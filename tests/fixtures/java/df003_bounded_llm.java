// Fixture: should NOT trigger DF003-java.
// All builders set finite timeouts / max tokens. OkHttp transports use
// non-zero timeouts. DF003 only fires on explicit null / Duration.ZERO /
// 0-second OkHttp timeouts — finite values are the safe path.
package com.example.safe;

import dev.langchain4j.model.openai.OpenAiChatModel;
import okhttp3.OkHttpClient;

import java.time.Duration;
import java.util.concurrent.TimeUnit;

public class BoundedLlm {

    public OpenAiChatModel finite() {
        return OpenAiChatModel.builder()
                .apiKey(System.getenv("OPENAI_API_KEY"))
                .timeout(Duration.ofSeconds(30))
                .maxTokens(512)
                .build();
    }

    public OkHttpClient boundedHttp() {
        return new OkHttpClient.Builder()
                .connectTimeout(10, TimeUnit.SECONDS)
                .readTimeout(30, TimeUnit.SECONDS)
                .build();
    }

    public OpenAiChatModel defaults() {
        // No timeout / maxTokens specified: SDK defaults apply. DF003 only
        // fires on EXPLICIT bound-disabling — defaults are out of scope.
        return OpenAiChatModel.builder()
                .apiKey(System.getenv("OPENAI_API_KEY"))
                .build();
    }
}
