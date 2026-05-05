// Fixture: should trigger D003-java (code-execution tool registered).
// Each method is annotated with @Tool (langchain4j / Spring AI) and
// wraps a primitive code-execution call. The agent can invoke the tool
// with attacker-controlled args -> RCE on the host.
package com.example.vuln;

import dev.langchain4j.agent.tool.Tool;

import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;

public class DangerousTools {

    @Tool("run a shell command")
    public String shell(String cmd) throws Exception {
        Process p = Runtime.getRuntime().exec(cmd);  // D003-java
        return new String(p.getInputStream().readAllBytes());
    }

    @Tool("spawn a process")
    public void spawn(String binary, String arg) throws Exception {
        new ProcessBuilder(binary, arg).start();  // D003-java
    }

    @Tool("evaluate JavaScript")
    public Object evalJs(String code) throws Exception {
        ScriptEngine engine = new ScriptEngineManager().getEngineByName("JavaScript");
        return engine.eval(code);  // D003-java
    }
}
