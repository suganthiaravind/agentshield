// Fixture: should NOT trigger D002-java.
// All document loaders read from a local FileSystemResource / Path —
// no URL fetch, no RAG poisoning surface. Validates the rule only fires
// on URL-backed loaders, not local file readers.
package com.example.safe;

import dev.langchain4j.data.document.Document;
import dev.langchain4j.data.document.loader.FileSystemDocumentLoader;
import org.springframework.ai.reader.tika.TikaDocumentReader;
import org.springframework.core.io.FileSystemResource;

import java.nio.file.Path;

public class LocalRagLoader {

    public Document loadLocal(String path) {
        return FileSystemDocumentLoader.loadDocument(Path.of(path));
    }

    public TikaDocumentReader localTika(String path) {
        return new TikaDocumentReader(new FileSystemResource(path));
    }
}
