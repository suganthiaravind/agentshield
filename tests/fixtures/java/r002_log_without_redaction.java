// Fixture: should trigger R002-java (LLM I/O logged without redaction).
// Spring controller user input + Spring AI ChatClient response logged
// directly via SLF4J / java.util.logging / System.out, no redactor.
package com.example.vuln;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.ai.chat.client.ChatClient;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class LogLeaker {

    private static final Logger log = LoggerFactory.getLogger(LogLeaker.class);

    private final ChatClient chatClient;

    public LogLeaker(ChatClient chatClient) {
        this.chatClient = chatClient;
    }

    @PostMapping("/chat")
    public String chat(@RequestParam String prompt) {
        log.info("User asked: {}", prompt);  // R002-java

        String response = chatClient.prompt().user(prompt).call().content();
        log.info("Model returned: {}", response);  // R002-java

        log.debug("debug detail prompt={} response={}", prompt, response);  // R002-java

        System.out.println("console: prompt=" + prompt);  // R002-java

        log.warn("Audit: user submitted {}", prompt);  // R002-java

        return response;
    }
}
