// Fixture: should NOT trigger D004-java.
// LLM output is either sanitized (Encode.forJava / Lakera guard) or fed to
// a safer sink (PreparedStatement with bound params, ProcessBuilder with
// argv array post-validation). Tests that sanitizers correctly cut the
// taint path.
package com.example.vuln;

import com.lakera.guard.LakeraGuard;
import org.owasp.encoder.Encode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.ai.chat.client.ChatClient;

import java.sql.Connection;
import java.sql.PreparedStatement;

public class CodeExecSafe {
    private static final Logger log = LoggerFactory.getLogger(CodeExecSafe.class);
    private final ChatClient chatClient;
    private final Connection conn;
    private final LakeraGuard guard;

    public CodeExecSafe(ChatClient chatClient, Connection conn, LakeraGuard guard) {
        this.chatClient = chatClient;
        this.conn = conn;
        this.guard = guard;
    }

    public void runQueryParameterized(String userPrompt, int userId) throws Exception {
        // PreparedStatement with bound parameter — query body is a constant,
        // LLM output never reaches the SQL string.
        String reason = chatClient.prompt().user(userPrompt).call().content();
        PreparedStatement ps = conn.prepareStatement("UPDATE audit SET reason = ? WHERE id = ?");
        ps.setString(1, reason);
        ps.setInt(2, userId);
        ps.executeUpdate();
    }

    public void runShellSanitized(String userPrompt) throws Exception {
        String raw = chatClient.prompt().user(userPrompt).call().content();
        String safe = Encode.forJava(raw);
        log.info("encoded shell arg: {}", safe);  // no exec sink reached
    }

    public void runShellGuarded(String userPrompt) throws Exception {
        String raw = chatClient.prompt().user(userPrompt).call().content();
        if (guard.isSafe(raw)) {
            log.info("guard cleared: {}", raw);  // sink not reached either
        }
    }
}
