// Fixture: should trigger D006-java (broad tool permissions).
// @Tool methods wrap Files.delete / Files.write / Files.move and destructive
// RestTemplate verbs with no allowlist or human-approval gate.
package com.example.vuln;

import dev.langchain4j.agent.tool.P;
import dev.langchain4j.agent.tool.Tool;
import org.springframework.web.client.RestTemplate;

import java.nio.file.Files;
import java.nio.file.Path;

public class BroadTools {

    private final RestTemplate rest = new RestTemplate();

    @Tool("delete a file from the workspace")
    public void deleteFile(@P("file path") String path) throws Exception {
        Files.delete(Path.of(path));  // D006-java
    }

    @Tool("write content to a file")
    public void writeFile(@P("file path") String path, @P("body") String body) throws Exception {
        Files.write(Path.of(path), body.getBytes());  // D006-java
    }

    @Tool("move a file")
    public void moveFile(@P("source") String src, @P("destination") String dst) throws Exception {
        Files.move(Path.of(src), Path.of(dst));  // D006-java
    }

    @Tool("delete a remote resource")
    public void deleteRemote(@P("URL") String url) {
        rest.delete(url);  // D006-java
    }

    @Tool("put a remote resource")
    public void putRemote(@P("URL") String url, @P("body") String body) {
        rest.put(url, body);  // D006-java
    }
}
