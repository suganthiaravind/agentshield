// Fixture: should trigger DF004-java (destructive @Tool without human approval).
// Each method is named with a destructive verb (delete / send / charge /
// deploy) and the body has no confirm() / requireApproval() call.
package com.example.vuln;

import dev.langchain4j.agent.tool.P;
import dev.langchain4j.agent.tool.Tool;

public class NoHitlTools {

    @Tool("delete a user account")
    public String deleteUser(@P("user id") String userId) {  // DF004-java
        return "deleted user " + userId;
    }

    @Tool("send an email")
    public String sendEmail(@P("recipient") String to, @P("body") String body) {  // DF004-java
        return "sent email to " + to;
    }

    @Tool("charge a customer card")
    public String chargeCard(@P("customer id") String customerId, @P("amount in cents") int amount) {  // DF004-java
        return "charged " + customerId + " $" + (amount / 100.0);
    }

    @Tool("deploy a release")
    public String deployRelease(@P("version") String version) {  // DF004-java
        return "deployed " + version;
    }
}
