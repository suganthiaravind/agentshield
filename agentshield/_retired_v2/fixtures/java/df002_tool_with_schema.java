// Fixture: should NOT trigger DF002-java.
// Each @Tool parameter has a langchain4j @P annotation describing what
// the LLM should pass. DF002 only fires on bare String params.
package com.example.safe;

import dev.langchain4j.agent.tool.P;
import dev.langchain4j.agent.tool.Tool;

public class SchematicTools {

    @Tool("look up a user by name")
    public String lookupUser(@P("the user's full name, ASCII only") String name) {
        return "user record for " + name;
    }

    @Tool("send a message")
    public void sendMessage(
            @P("the recipient email address") String to,
            @P("the message body, plain text") String body) {
        System.out.println("to=" + to + " body=" + body);
    }
}
