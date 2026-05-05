// Fixture: should NOT trigger R002-java.
// Each log call passes through a redactor / hasher / length projection
// before reaching the log sink.
package com.example.safe;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.ai.chat.client.ChatClient;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

@RestController
public class LogRedacted {

    private static final Logger log = LoggerFactory.getLogger(LogRedacted.class);

    private final ChatClient chatClient;
    private final Redactor redactor;

    public LogRedacted(ChatClient chatClient, Redactor redactor) {
        this.chatClient = chatClient;
        this.redactor = redactor;
    }

    @PostMapping("/chat-hash")
    public String chatHash(@RequestParam String prompt) throws Exception {
        // Hash the prompt — log the hash, not the value.
        byte[] hashBytes = MessageDigest.getInstance("SHA-256")
                .digest(prompt.getBytes(StandardCharsets.UTF_8));
        String promptHash = Base64.getEncoder().encodeToString(hashBytes);
        log.info("User asked (hash={})", promptHash);

        String response = chatClient.prompt().user(prompt).call().content();
        byte[] respBytes = MessageDigest.getInstance("SHA-256")
                .digest(response.getBytes(StandardCharsets.UTF_8));
        log.info("Model returned (hash={})", Base64.getEncoder().encodeToString(respBytes));
        return response;
    }

    @PostMapping("/chat-redact")
    public String chatRedact(@RequestParam String prompt) {
        log.info("User asked: {}", redactor.redact(prompt));

        String response = chatClient.prompt().user(prompt).call().content();
        log.info("Model returned: {}", redactor.redact(response));
        return response;
    }

    @PostMapping("/chat-len")
    public String chatLen(@RequestParam String prompt) {
        log.info("prompt len={}", prompt.length());

        String response = chatClient.prompt().user(prompt).call().content();
        log.info("response len={}", response.length());
        return response;
    }

    public interface Redactor {
        String redact(String s);
    }
}
