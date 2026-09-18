package ghidra.localai;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;

public class OllamaClient {
    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(120);

    private static final String SYSTEM_PROMPT = """
You are a local reverse-engineering assistant embedded in Ghidra.
Use the supplied CURRENT GHIDRA CONTEXT as the authoritative view of the current program and function.
Be concise, technical, and explicit when evidence is uncertain.

You may request Ghidra edits, but ONLY when the user explicitly asks you to rename, comment, modify,
or apply a change. Never emit an edit action merely because you think it would be helpful.
When the user explicitly asks for a supported edit and the requested value is clear, emit the
corresponding action tag so the extension can actually perform it.

Supported edit actions target only the supplied current function/cursor:
<GHIDRA_RENAME_FUNCTION>valid_symbol_name</GHIDRA_RENAME_FUNCTION>
<GHIDRA_SET_FUNCTION_COMMENT>comment text</GHIDRA_SET_FUNCTION_COMMENT>
<GHIDRA_SET_EOL_COMMENT>comment text</GHIDRA_SET_EOL_COMMENT>

Put any action tags after the human-readable answer. Do not put Markdown inside an action tag.
Do not claim an action succeeded; the Ghidra extension will report whether it was actually applied.
""";

    private final HttpClient client;

    public OllamaClient() {
        client = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(3))
            .build();
    }

    public String chat(String baseUrl, String model, List<ChatMessage> history,
            ContextSnapshot context) throws IOException, InterruptedException {

        URI uri = localUri(baseUrl, "/api/chat");
        String payload = buildChatPayload(model, history, context);

        HttpRequest request = HttpRequest.newBuilder(uri)
            .timeout(REQUEST_TIMEOUT)
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(payload))
            .build();

        HttpResponse<String> response =
            client.send(request, HttpResponse.BodyHandlers.ofString());

        if (response.statusCode() < 200 || response.statusCode() >= 300) {
            throw new IOException("Ollama returned HTTP " + response.statusCode() + ": " +
                abbreviate(response.body(), 800));
        }

        String content = extractJsonStringField(response.body(), "content");
        if (content == null) {
            String error = extractJsonStringField(response.body(), "error");
            if (error != null) {
                throw new IOException("Ollama error: " + error);
            }
            throw new IOException("Ollama response did not contain message.content");
        }
        return content;
    }

    public String complete(String baseUrl, String model, String systemPrompt, String userPrompt)
            throws IOException, InterruptedException {

        URI uri = localUri(baseUrl, "/api/chat");

        StringBuilder json = new StringBuilder();
        json.append("{\"model\":").append(jsonString(model));
        json.append(",\"stream\":false");
        json.append(",\"options\":{\"temperature\":0.15}");
        json.append(",\"messages\":[");
        appendMessage(json, "system", systemPrompt == null ? "" : systemPrompt);
        json.append(',');
        appendMessage(json, "user", userPrompt == null ? "" : userPrompt);
        json.append("]}");

        HttpRequest request = HttpRequest.newBuilder(uri)
            .timeout(REQUEST_TIMEOUT)
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(json.toString()))
            .build();

        HttpResponse<String> response =
            client.send(request, HttpResponse.BodyHandlers.ofString());

        if (response.statusCode() < 200 || response.statusCode() >= 300) {
            throw new IOException("Ollama returned HTTP " + response.statusCode() + ": " +
                abbreviate(response.body(), 800));
        }

        String content = extractJsonStringField(response.body(), "content");
        if (content == null) {
            String error = extractJsonStringField(response.body(), "error");
            if (error != null) {
                throw new IOException("Ollama error: " + error);
            }
            throw new IOException("Ollama response did not contain message.content");
        }
        return content;
    }

    public String check(String baseUrl) throws IOException, InterruptedException {
        URI uri = localUri(baseUrl, "/api/tags");
        HttpRequest request = HttpRequest.newBuilder(uri)
            .timeout(Duration.ofSeconds(5))
            .GET()
            .build();

        HttpResponse<String> response =
            client.send(request, HttpResponse.BodyHandlers.ofString());

        if (response.statusCode() < 200 || response.statusCode() >= 300) {
            throw new IOException("Ollama returned HTTP " + response.statusCode());
        }
        return "Ollama reachable";
    }

    private String buildChatPayload(String model, List<ChatMessage> history,
            ContextSnapshot context) {

        StringBuilder json = new StringBuilder();
        json.append("{\"model\":").append(jsonString(model));
        json.append(",\"stream\":false");
        json.append(",\"options\":{\"temperature\":0.2}");
        json.append(",\"messages\":[");

        appendMessage(json, "system", SYSTEM_PROMPT);
        int start = Math.max(0, history.size() - 12);

        ChatMessage latestUser = null;
        for (int i = start; i < history.size(); i++) {
            ChatMessage message = history.get(i);
            if (i == history.size() - 1 && "user".equals(message.role())) {
                latestUser = message;
                continue;
            }
            json.append(',');
            appendMessage(json, message.role(), message.content());
        }

        String userText = latestUser == null ? "" : latestUser.content();
        String contextualPrompt =
            "CURRENT GHIDRA CONTEXT\n======================\n" +
            context.toPromptContext() +
            "\n\nUSER REQUEST\n============\n" + userText;

        json.append(',');
        appendMessage(json, "user", contextualPrompt);
        json.append("]}");
        return json.toString();
    }

    private static void appendMessage(StringBuilder json, String role, String content) {
        json.append("{\"role\":").append(jsonString(role))
            .append(",\"content\":").append(jsonString(content)).append('}');
    }

    private static String jsonString(String value) {
        if (value == null) {
            return "\"\"";
        }

        StringBuilder out = new StringBuilder(value.length() + 16);
        out.append('"');
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"' -> out.append("\\\"");
                case '\\' -> out.append("\\\\");
                case '\b' -> out.append("\\b");
                case '\f' -> out.append("\\f");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                default -> {
                    if (c < 0x20) {
                        out.append(String.format("\\u%04x", (int)c));
                    }
                    else {
                        out.append(c);
                    }
                }
            }
        }
        out.append('"');
        return out.toString();
    }

    private static URI localUri(String baseUrl, String path) {
        String base = baseUrl == null || baseUrl.isBlank()
            ? "http://127.0.0.1:11434"
            : baseUrl.trim();

        if (base.endsWith("/")) {
            base = base.substring(0, base.length() - 1);
        }

        URI baseUri = URI.create(base);
        String scheme = baseUri.getScheme();
        if (!"http".equalsIgnoreCase(scheme) && !"https".equalsIgnoreCase(scheme)) {
            throw new IllegalArgumentException("Ollama URL must use http or https");
        }

        String host = baseUri.getHost();
        boolean local = host != null &&
            ("127.0.0.1".equals(host) || "localhost".equalsIgnoreCase(host) ||
                "::1".equals(host) || "[::1]".equals(host));

        if (!local) {
            throw new IllegalArgumentException(
                "LocalAI only allows loopback Ollama hosts (127.0.0.1, localhost, ::1)");
        }

        return URI.create(base + path);
    }

    static String extractJsonStringField(String json, String field) {
        if (json == null) {
            return null;
        }

        String needle = "\"" + field + "\"";
        int fieldPos = json.indexOf(needle);
        if (fieldPos < 0) {
            return null;
        }

        int colon = json.indexOf(':', fieldPos + needle.length());
        if (colon < 0) {
            return null;
        }

        int quote = json.indexOf('"', colon + 1);
        if (quote < 0) {
            return null;
        }

        StringBuilder value = new StringBuilder();
        for (int i = quote + 1; i < json.length(); i++) {
            char c = json.charAt(i);
            if (c == '"') {
                return value.toString();
            }
            if (c != '\\') {
                value.append(c);
                continue;
            }

            if (++i >= json.length()) {
                return null;
            }

            char escaped = json.charAt(i);
            switch (escaped) {
                case '"' -> value.append('"');
                case '\\' -> value.append('\\');
                case '/' -> value.append('/');
                case 'b' -> value.append('\b');
                case 'f' -> value.append('\f');
                case 'n' -> value.append('\n');
                case 'r' -> value.append('\r');
                case 't' -> value.append('\t');
                case 'u' -> {
                    if (i + 4 >= json.length()) {
                        return null;
                    }
                    String hex = json.substring(i + 1, i + 5);
                    try {
                        value.append((char)Integer.parseInt(hex, 16));
                    }
                    catch (NumberFormatException e) {
                        return null;
                    }
                    i += 4;
                }
                default -> value.append(escaped);
            }
        }
        return null;
    }

    private static String abbreviate(String value, int max) {
        if (value == null || value.length() <= max) {
            return value;
        }
        return value.substring(0, max) + "...";
    }
}
