// Anti-pattern: D002 Java (untrusted document loader -> RAG without URL allowlist).
// Also fires DF001 + R001.
package com.example.agent.controller;

import dev.langchain4j.data.document.Document;
import dev.langchain4j.data.document.loader.UrlDocumentLoader;
import org.apache.tika.Tika;
import org.springframework.ai.reader.tika.TikaDocumentReader;
import org.springframework.core.io.UrlResource;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.net.URL;

@RestController
public class RagController {

    @GetMapping("/ingest")
    public String ingest(@RequestParam String url) throws Exception {
        // No URL allowlist before fetching arbitrary remote content.
        Document doc = UrlDocumentLoader.load(url, null);
        return doc.text();
    }

    @GetMapping("/ingest-tika")
    public TikaDocumentReader ingestTika(@RequestParam String url) throws Exception {
        return new TikaDocumentReader(new UrlResource(url));
    }

    @GetMapping("/ingest-direct")
    public String ingestDirect(@RequestParam String url) throws Exception {
        return new Tika().parseToString(new URL(url));
    }
}
