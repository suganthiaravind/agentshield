// Fixture: should trigger D002-java (untrusted document loader -> RAG).
// Each loader below pulls content from a URL with no allowlist. langchain4j
// UrlDocumentLoader, Spring AI TikaDocumentReader against UrlResource, and
// Apache Tika direct URL fetch.
package com.example.vuln;

import dev.langchain4j.data.document.Document;
import dev.langchain4j.data.document.loader.UrlDocumentLoader;
import org.apache.tika.Tika;
import org.springframework.ai.reader.tika.TikaDocumentReader;
import org.springframework.core.io.UrlResource;

import java.net.URL;

public class UntrustedRagLoader {

    public Document langchain4jLoad(String url) throws Exception {
        return UrlDocumentLoader.load(url, null);  // D002-java
    }

    public TikaDocumentReader springTika(String url) throws Exception {
        return new TikaDocumentReader(new UrlResource(url));  // D002-java
    }

    public String tikaDirect(String url) throws Exception {
        return new Tika().parseToString(new URL(url));  // D002-java
    }
}
