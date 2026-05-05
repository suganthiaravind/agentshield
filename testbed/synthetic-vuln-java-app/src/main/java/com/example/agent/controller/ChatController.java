// Anti-pattern: D001 Java (taint to LLM via Spring @RequestParam).
// Also fires DF001 (no guardrails import) + R001 (no audit logger).
package com.example.agent.controller;

import org.springframework.ai.chat.client.ChatClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ChatController {

    private final ChatClient chatClient;

    public ChatController(ChatClient chatClient) {
        this.chatClient = chatClient;
    }

    @GetMapping("/chat")
    public String chat(@RequestParam String q) {
        // Tainted: q -> ChatClient.user() -> .call() -> string out.
        return chatClient.prompt().user(q).call().content();
    }

    @PostMapping("/chat-body")
    public String chatBody(@RequestBody String prompt) {
        return chatClient.prompt().user(prompt).call().content();
    }
}
