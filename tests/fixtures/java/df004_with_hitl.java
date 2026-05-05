// Fixture: should NOT trigger DF004-java.
// Two cases:
//   - destructive verbs (deleteUser / sendEmail) but each tool body calls
//     an injected approval / confirmation service before performing the action.
//   - read-only verbs (readUser / listFiles) outside the destructive regex.
package com.example.safe;

import dev.langchain4j.agent.tool.P;
import dev.langchain4j.agent.tool.Tool;

public class HitlTools {

    private final ApprovalService approval;

    public HitlTools(ApprovalService approval) {
        this.approval = approval;
    }

    @Tool("delete a user account")
    public String deleteUser(@P("user id") String userId) {
        approval.confirm("delete user " + userId);  // suppressor
        return "deleted user " + userId;
    }

    @Tool("send an email")
    public String sendEmail(@P("recipient") String to, @P("body") String body) {
        approval.requireApproval("send email to " + to);  // suppressor
        return "sent email to " + to;
    }

    @Tool("read a user record")
    public String readUser(@P("user id") String userId) {
        // Non-destructive verb — outside DF004's regex, won't match.
        return "user record for " + userId;
    }

    @Tool("list files in a directory")
    public String listFiles(@P("path") String path) {
        return "files at " + path;
    }
}

interface ApprovalService {
    void confirm(String description);
    void requireApproval(String description);
}
