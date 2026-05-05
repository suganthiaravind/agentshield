// Fixture: should trigger D004-java (LLM output -> code execution).
// Spring AI ChatClient output is fed directly into Runtime.exec
// and JDBC Statement.execute. Classic LLM05 Improper Output Handling.
//
// Imports SLF4J + Lakera Guard import (suppressors for R001-java +
// DF001-java) so the golden cleanly shows D004-java alone.
package com.example.vuln;

import com.lakera.guard.LakeraGuard;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.ai.chat.client.ChatClient;

import java.sql.Connection;
import java.sql.Statement;

public class CodeExecVuln {
    private static final Logger log = LoggerFactory.getLogger(CodeExecVuln.class);
    private final ChatClient chatClient;
    private final Connection conn;

    public CodeExecVuln(ChatClient chatClient, Connection conn) {
        this.chatClient = chatClient;
        this.conn = conn;
    }

    public void runShell(String userPrompt) throws Exception {
        String cmd = chatClient.prompt().user(userPrompt).call().content();
        Runtime.getRuntime().exec(cmd);  // D004-java should fire here
    }

    public void spawnProcess(String userPrompt) throws Exception {
        String arg = chatClient.prompt().user(userPrompt).call().content();
        new ProcessBuilder(arg).start();  // D004-java should fire here
    }

    public void runQuery(String userPrompt) throws Exception {
        String sql = chatClient.prompt().user(userPrompt).call().content();
        Statement stmt = conn.createStatement();
        stmt.executeQuery(sql);  // D004-java should fire here
    }
}
