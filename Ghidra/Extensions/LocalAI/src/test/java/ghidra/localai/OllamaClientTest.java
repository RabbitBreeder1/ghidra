package ghidra.localai;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

public class OllamaClientTest {

    @Test
    public void extractsEscapedContent() {
        String json =
            "{\"message\":{\"role\":\"assistant\",\"content\":\"line 1\\nline 2 \\\"quoted\\\"\"}}";

        assertEquals(
            "line 1\nline 2 \"quoted\"",
            OllamaClient.extractJsonStringField(json, "content")
        );
    }

    @Test
    public void decodesUnicodeEscape() {
        String json = "{\"content\":\"name=\\u0066oo\"}";

        assertEquals("name=foo", OllamaClient.extractJsonStringField(json, "content"));
    }
}
