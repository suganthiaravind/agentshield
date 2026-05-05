// Fixture: should NOT trigger D006-java.
// @Tool methods are read-only or use safe RestTemplate verbs (GET).
// Validates that D006-java fires only on filesystem-mutation / destructive-
// HTTP wrappers, not on read-only tools.
package com.example.safe;

import dev.langchain4j.agent.tool.P;
import dev.langchain4j.agent.tool.Tool;
import org.springframework.web.client.RestTemplate;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

public class NarrowTools {

    private final RestTemplate rest = new RestTemplate();

    @Tool("read a file from the workspace")
    public String readFile(@P("file path") String path) throws Exception {
        return Files.readString(Path.of(path));
    }

    @Tool("list a directory")
    public List<String> listDir(@P("directory path") String path) throws Exception {
        return Files.list(Path.of(path)).map(Path::toString).toList();
    }

    @Tool("fetch a remote resource")
    public String fetch(@P("URL") String url) {
        return rest.getForObject(url, String.class);  // GET, not destructive
    }
}
