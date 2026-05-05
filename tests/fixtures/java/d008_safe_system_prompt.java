// Fixture: should NOT trigger D008-java.
// Two negative shapes:
//   1. System prompt is a constant string baked into the source.
//   2. System prompt is loaded from a JAR resource (no network read).
//
// NOT covered (intentional limitation): conditional HMAC-verified
// network reads. semgrep's intra-procedural taint mode can't prove
// that an `if (MessageDigest.isEqual(...))` branch guarantees the
// payload is safe to use as a system prompt — the conditional gate
// isn't propagated. To express verified-system-prompt safely, extract
// the verification into a wrapper function and apply Lakera Guard or
// equivalent on the result before passing to SystemMessage.
package com.example.safe;

import dev.langchain4j.data.message.SystemMessage;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;

public class SafeSystemPrompt {

    public SystemMessage fromConstant() {
        // Baked into source — not a network read.
        return SystemMessage.from("You are a helpful assistant. Refuse off-topic queries.");
    }

    public SystemMessage fromResource() throws Exception {
        // Packaged resource — read from JAR, not network.
        try (InputStream in = getClass().getResourceAsStream("/system_prompt.txt")) {
            String prompt = new String(in.readAllBytes(), StandardCharsets.UTF_8);
            return SystemMessage.from(prompt);
        }
    }
}
