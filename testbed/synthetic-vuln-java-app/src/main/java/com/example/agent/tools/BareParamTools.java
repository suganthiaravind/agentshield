// Anti-pattern: DF002 Java (@Tool methods with bare String params — no @P / @ToolParam).
// Also fires DF001 + R001.
package com.example.agent.tools;

import dev.langchain4j.agent.tool.Tool;

public class BareParamTools {

    @Tool("look up a user by name")
    public String lookupUser(String name) {
        return "user record for " + name;
    }

    @Tool("send a chat message to a user")
    public void chat(String to, String body) {
        System.out.println("to=" + to + " body=" + body);
    }
}
