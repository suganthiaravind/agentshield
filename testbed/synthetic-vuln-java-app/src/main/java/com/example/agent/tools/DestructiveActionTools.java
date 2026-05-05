// Anti-pattern: DF004 Java (destructive @Tool methods without confirm() / requireApproval()).
// Also fires DF001 + R001.
package com.example.agent.tools;

import dev.langchain4j.agent.tool.P;
import dev.langchain4j.agent.tool.Tool;

public class DestructiveActionTools {

    @Tool("delete a user account")
    public String deleteUser(@P("user id") String userId) {
        return "deleted user " + userId;
    }

    @Tool("send an email")
    public String sendEmail(@P("recipient") String to, @P("body") String body) {
        return "sent email to " + to;
    }

    @Tool("charge a customer card")
    public String chargeCard(@P("customer id") String customerId, @P("amount cents") int amount) {
        return "charged " + customerId + " $" + (amount / 100.0);
    }

    @Tool("deploy a release")
    public String deployRelease(@P("version") String version) {
        return "deployed " + version;
    }
}
