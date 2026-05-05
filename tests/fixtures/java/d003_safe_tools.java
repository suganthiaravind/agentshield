// Fixture: should NOT trigger D003-java.
// Methods are annotated with @Tool but perform safe, narrowly-scoped
// operations (arithmetic, deterministic lookup). No Runtime.exec /
// ProcessBuilder / ScriptEngine.eval anywhere.
package com.example.safe;

import dev.langchain4j.agent.tool.Tool;

import java.time.LocalDate;

public class SafeTools {

    @Tool("today's date")
    public String today() {
        return LocalDate.now().toString();
    }

    @Tool("add two integers")
    public int add(int a, int b) {
        return a + b;
    }
}
