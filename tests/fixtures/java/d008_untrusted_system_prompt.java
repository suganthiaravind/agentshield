// Fixture: should trigger D008-java (untrusted source -> system message).
// Spring AI SystemMessage / langchain4j SystemMessage / Bedrock SystemContentBlock
// each constructed from a remote read with no signature verification.
package com.example.vuln;

import dev.langchain4j.data.message.SystemMessage;
import org.springframework.web.client.RestTemplate;
import software.amazon.awssdk.services.bedrockruntime.model.SystemContentBlock;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.ssm.SsmClient;
import software.amazon.awssdk.services.ssm.model.GetParameterRequest;

public class UntrustedSystemPrompt {

    private final RestTemplate rest = new RestTemplate();
    private final S3Client s3;
    private final SsmClient ssm;

    public UntrustedSystemPrompt(S3Client s3, SsmClient ssm) {
        this.s3 = s3;
        this.ssm = ssm;
    }

    public SystemMessage fromHttp(String url) {
        String prompt = rest.getForObject(url, String.class);
        return SystemMessage.from(prompt);  // D008-java
    }

    public SystemMessage fromS3(String bucket, String key) {
        String prompt = s3.getObject(GetObjectRequest.builder().bucket(bucket).key(key).build())
                .asUtf8String();
        return new SystemMessage(prompt);  // D008-java
    }

    public SystemMessage fromSsm(String paramName) {
        String prompt = ssm.getParameter(GetParameterRequest.builder().name(paramName).build())
                .parameter().value();
        return SystemMessage.from(prompt);  // D008-java
    }

    public SystemContentBlock fromHttpToBedrock(String url) {
        String prompt = rest.getForObject(url, String.class);
        return SystemContentBlock.builder().text(prompt).build();  // D008-java
    }
}
