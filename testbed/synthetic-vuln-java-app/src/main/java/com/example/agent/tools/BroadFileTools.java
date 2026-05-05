// Anti-pattern: D006 Java (broad tool permissions — file mutation + destructive HTTP).
// Also fires DF001 + R001.
package com.example.agent.tools;

import dev.langchain4j.agent.tool.P;
import dev.langchain4j.agent.tool.Tool;
import org.springframework.web.client.RestTemplate;

import java.nio.file.Files;
import java.nio.file.Path;

public class BroadFileTools {

    private final RestTemplate rest = new RestTemplate();

    @Tool("delete a file")
    public void deleteFile(@P("file path") String path) throws Exception {
        Files.delete(Path.of(path));
    }

    @Tool("write content to a file")
    public void writeFile(@P("file path") String path, @P("body") String body) throws Exception {
        Files.write(Path.of(path), body.getBytes());
    }

    @Tool("move a file")
    public void moveFile(@P("source") String src, @P("destination") String dst) throws Exception {
        Files.move(Path.of(src), Path.of(dst));
    }

    @Tool("delete a remote resource")
    public void deleteRemote(@P("URL") String url) {
        rest.delete(url);
    }

    @Tool("put a remote resource")
    public void putRemote(@P("URL") String url, @P("body") String body) {
        rest.put(url, body);
    }
}
