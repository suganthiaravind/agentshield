// Fixture: should trigger D005-java (hardcoded credentials).
// Each constructor / builder below passes a literal credential string
// — CWE-798. Java port of D005.
package com.example.vuln;

import com.azure.core.credential.AzureKeyCredential;
import dev.langchain4j.model.openai.OpenAiChatModel;
import dev.langchain4j.model.anthropic.AnthropicChatModel;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;

public class HardcodedKeys {

    public OpenAiChatModel openai() {
        return OpenAiChatModel.builder()
                .apiKey("sk-proj-AAAAAAAAAAAAAAAAAAAAAAAAAAAA")  // D005-java
                .modelName("gpt-4o-mini")
                .build();
    }

    public AnthropicChatModel anthropic() {
        return AnthropicChatModel.builder()
                .apiKey("sk-ant-api03-XXXXXXXXXXXXXXXXX")  // D005-java
                .modelName("claude-sonnet-4-5")
                .build();
    }

    public AzureKeyCredential azure() {
        return new AzureKeyCredential("az-key-LITERAL-EXAMPLE-AAAA");  // D005-java
    }

    public AwsBasicCredentials awsBasic() {
        return AwsBasicCredentials.create(  // D005-java
                "AKIAIOSFODNN7EXAMPLE",
                "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        );
    }

    public StaticCredentialsProvider awsProvider() {
        return StaticCredentialsProvider.create(
                AwsBasicCredentials.create(  // D005-java (inner factory)
                        "AKIAIOSFODNN7EXAMPLE",
                        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
                )
        );
    }
}
