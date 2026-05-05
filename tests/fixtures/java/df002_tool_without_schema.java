// Fixture: should trigger DF002-java (tool without args schema).
// langchain4j @Tool annotated methods take String parameters with no @P
// annotation — the LLM has no description / no constraints on what to pass.
package com.example.vuln;

import dev.langchain4j.agent.tool.Tool;

public class UnschemaTools {

    @Tool("look up a user by name")
    public String lookupUser(String name) {  // DF002-java: no @P on `name`
        return "user record for " + name;
    }

    @Tool("send a message")
    public void sendMessage(String to, String body) {  // DF002-java: no @P
        System.out.println("to=" + to + " body=" + body);
    }
}
