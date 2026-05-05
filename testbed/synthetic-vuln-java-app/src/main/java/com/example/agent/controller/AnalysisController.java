// Anti-pattern: D004 Java (LLM output flows into Runtime.exec / SQL).
// Also fires DF001 + R001.
package com.example.agent.controller;

import org.springframework.ai.chat.client.ChatClient;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.sql.Connection;
import java.sql.Statement;

@RestController
public class AnalysisController {

    private final ChatClient chatClient;
    private final Connection conn;

    public AnalysisController(ChatClient chatClient, Connection conn) {
        this.chatClient = chatClient;
        this.conn = conn;
    }

    @PostMapping("/analyze-and-run")
    public String analyzeAndRun(@RequestParam String userPrompt) throws Exception {
        // LLM output (the chat completion) is piped into Runtime.exec — RCE if
        // the prompt asks the model to emit a destructive shell command.
        String suggestedCommand = chatClient.prompt().user(userPrompt).call().content();
        Process p = Runtime.getRuntime().exec(suggestedCommand);
        return new String(p.getInputStream().readAllBytes());
    }

    @PostMapping("/analyze-and-query")
    public String analyzeAndQuery(@RequestParam String userPrompt) throws Exception {
        // LLM output piped into unparameterized SQL — SQL injection if the
        // model emits SQL with user-controlled segments.
        String generatedSql = chatClient.prompt().user(userPrompt).call().content();
        Statement stmt = conn.createStatement();
        stmt.executeQuery(generatedSql);
        return "executed";
    }
}
