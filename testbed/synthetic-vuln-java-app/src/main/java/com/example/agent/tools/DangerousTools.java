// Anti-pattern: D003 Java (code-execution tools registered).
// Also fires DF001 + R001.
package com.example.agent.tools;

import dev.langchain4j.agent.tool.Tool;

import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;

public class DangerousTools {

    @Tool("execute a shell command")
    public String shell(String cmd) throws Exception {
        Process p = Runtime.getRuntime().exec(cmd);
        return new String(p.getInputStream().readAllBytes());
    }

    @Tool("spawn a process")
    public void spawn(String binary, String arg) throws Exception {
        new ProcessBuilder(binary, arg).start();
    }

    @Tool("evaluate JavaScript expression")
    public Object evalJs(String code) throws Exception {
        ScriptEngine engine = new ScriptEngineManager().getEngineByName("JavaScript");
        return engine.eval(code);
    }
}
