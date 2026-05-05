// Anti-pattern: D005 Java (hardcoded LLM credentials — CWE-798).
package com.example.agent.config;

import com.azure.core.credential.AzureKeyCredential;
import dev.langchain4j.model.anthropic.AnthropicChatModel;
import dev.langchain4j.model.openai.OpenAiChatModel;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;

public class HardcodedKeys {

    public OpenAiChatModel openai() {
        return OpenAiChatModel.builder()
                .apiKey("sk-proj-AAAAAAAAAAAAAAAAAAAAAAAAAAAA")
                .modelName("gpt-4o-mini")
                .build();
    }

    public AnthropicChatModel anthropic() {
        return AnthropicChatModel.builder()
                .apiKey("sk-ant-api03-XXXXXXXXXXXXXXXXX")
                .modelName("claude-sonnet-4-5")
                .build();
    }

    public AzureKeyCredential azure() {
        return new AzureKeyCredential("az-key-LITERAL-EXAMPLE-AAAA");
    }

    public AwsBasicCredentials awsBasic() {
        return AwsBasicCredentials.create(
                "AKIAIOSFODNN7EXAMPLE",
                "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        );
    }
}
