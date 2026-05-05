// Fixture: should NOT trigger D005-java.
// Every credential is sourced from env / Spring config / default credential
// resolver. Validates the rule only fires on string literals.
package com.example.safe;

import com.azure.core.credential.AzureKeyCredential;
import dev.langchain4j.model.openai.OpenAiChatModel;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import org.springframework.beans.factory.annotation.Value;

public class SafeKeys {

    @Value("${OPENAI_API_KEY}")
    private String openAiKey;

    @Value("${AZURE_OPENAI_KEY}")
    private String azureKey;

    public OpenAiChatModel openai() {
        // Env-sourced via Spring @Value — not a literal.
        return OpenAiChatModel.builder()
                .apiKey(openAiKey)
                .modelName("gpt-4o-mini")
                .build();
    }

    public OpenAiChatModel openaiFromEnv() {
        // Direct env lookup — not a literal.
        return OpenAiChatModel.builder()
                .apiKey(System.getenv("OPENAI_API_KEY"))
                .modelName("gpt-4o-mini")
                .build();
    }

    public AzureKeyCredential azure() {
        return new AzureKeyCredential(azureKey);  // variable, not literal
    }

    public DefaultCredentialsProvider awsDefault() {
        // Default chain: IAM role / instance profile / env / ~/.aws/credentials.
        return DefaultCredentialsProvider.create();
    }
}
