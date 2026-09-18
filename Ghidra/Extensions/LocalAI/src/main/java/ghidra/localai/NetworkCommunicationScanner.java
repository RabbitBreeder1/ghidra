package ghidra.localai;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.symbol.ExternalLocationIterator;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;

public class NetworkCommunicationScanner {
    private static final int MAX_DEFINED_STRINGS = 150_000;
    private static final int MAX_REFERENCING_FUNCTIONS = 10;
    private static final int MAX_FINDINGS = 250;

    private static final Pattern URL_PATTERN = Pattern.compile(
        "(?i)\\b(?:https?|wss?|ftp)://[^\\s\\\"'<>]{4,240}"
    );

    private static final Pattern IPV4_PATTERN = Pattern.compile(
        "(?<![0-9])(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})" +
        "(?:\\.(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})){3}(?![0-9])"
    );

    private static final Pattern DOMAIN_PATTERN = Pattern.compile(
        "(?i)(?<![A-Za-z0-9_-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\\.)+" +
        "[A-Za-z]{2,24}(?![A-Za-z0-9_-])"
    );

    private final Map<String, FindingBuilder> findings = new LinkedHashMap<>();

    public NetworkReport scan(Program program) {
        findings.clear();

        if (program == null || program.isClosed()) {
            return NetworkReport.noProgram();
        }

        int externalSymbols = scanExternalNetworking(program);
        ScanCount strings = scanStrings(program);

        List<NetworkFinding> output = new ArrayList<>();
        for (FindingBuilder builder : findings.values()) {
            output.add(builder.build());
            if (output.size() >= MAX_FINDINGS) {
                break;
            }
        }

        String note =
            "Static preservation-oriented scan. Referenced functions are likely places to inspect " +
            "for client/server behavior. Runtime DNS, encrypted configuration, dynamically loaded APIs, " +
            "custom protocols, and endpoints assembled at runtime may require dynamic tracing.";

        return new NetworkReport(
            List.copyOf(output),
            strings.scanned(),
            externalSymbols,
            strings.truncated(),
            note
        );
    }

    private int scanExternalNetworking(Program program) {
        int scanned = 0;

        for (String library : program.getExternalManager().getExternalLibraryNames()) {
            if (library == null) {
                continue;
            }

            ExternalLocationIterator iterator =
                program.getExternalManager().getExternalLocations(library);

            while (iterator.hasNext()) {
                ExternalLocation location = iterator.next();
                scanned++;

                String label = location.getLabel();
                String classification = classifyNetworkApi(library, label);
                if (classification == null) {
                    continue;
                }

                Address externalAddress = location.getExternalSpaceAddress();
                List<String> refs = findReferencingFunctions(program, externalAddress);

                String value = library + "!" + (label == null ? "<unnamed>" : label);
                add(
                    "Network API - " + classification,
                    value,
                    "Imported external symbol",
                    refs
                );
            }
        }

        return scanned;
    }

    static String classifyNetworkApi(String library, String label) {
        String lib = library == null ? "" : library.toLowerCase(Locale.ROOT);
        String name = label == null ? "" : label.toLowerCase(Locale.ROOT);
        String combined = lib + "!" + name;

        if (lib.contains("ws2_32") || lib.contains("wsock32") ||
            matchesAny(name, "socket", "connect", "wsaconnect", "send", "recv",
                "sendto", "recvfrom", "getaddrinfo", "gethostbyname",
                "getnameinfo", "inet_addr", "inet_pton", "inet_ntop",
                "wsastartup", "wsasend", "wsarecv")) {
            return "Winsock / raw sockets";
        }

        if (lib.contains("winhttp") ||
            name.startsWith("winhttp")) {
            return "WinHTTP / HTTP(S)";
        }

        if (lib.contains("wininet") ||
            matchesAny(name, "internetopen", "internetconnect", "httpopenrequest",
                "httpsendrequest", "internetreadfile", "internetwritefile",
                "ftpopenfile", "ftpgetfile", "ftpputfile")) {
            return "WinINet / HTTP(S)/FTP";
        }

        if (combined.contains("curl") || name.startsWith("curl_")) {
            return "libcurl / HTTP(S)";
        }

        if (matchesAny(name, "ssl_connect", "ssl_read", "ssl_write", "ssl_new",
                "ssl_ctx_new", "tls_client_method", "bio_new_connect") ||
            lib.contains("libssl")) {
            return "OpenSSL / TLS";
        }

        if (lib.contains("secur32") &&
            matchesAny(name, "initializeSecurityContextA", "initializeSecurityContextW",
                "acquireCredentialsHandleA", "acquireCredentialsHandleW")) {
            return "Windows SSPI / TLS/authentication";
        }

        if (combined.contains("websocket") ||
            name.startsWith("winhttpwebsocket")) {
            return "WebSocket";
        }

        if (combined.contains("steamnetworking") ||
            combined.contains("isteamnetworking")) {
            return "Steam Networking";
        }

        if (combined.contains("eos_") &&
            (combined.contains("connect") || combined.contains("p2p") ||
             combined.contains("lobby") || combined.contains("sessions"))) {
            return "Epic Online Services";
        }

        if (combined.contains("raknet") || combined.contains("rakpeer")) {
            return "RakNet";
        }

        if (combined.contains("enet_")) {
            return "ENet";
        }

        return null;
    }

    private ScanCount scanStrings(Program program) {
        DataIterator iterator = program.getListing().getDefinedData(true);
        int scanned = 0;
        boolean truncated = false;

        while (iterator.hasNext()) {
            Data data = iterator.next();
            if (!data.hasStringValue()) {
                continue;
            }

            if (scanned >= MAX_DEFINED_STRINGS) {
                truncated = true;
                break;
            }

            scanned++;
            Object raw = data.getValue();
            if (!(raw instanceof String text) || text.isBlank()) {
                continue;
            }

            List<String> refs = findReferencingFunctions(program, data.getAddress());

            addMatches("Endpoint URL", text, data.getAddress(), refs, URL_PATTERN);
            addMatches("IPv4 address", text, data.getAddress(), refs, IPV4_PATTERN);

            Matcher domainMatcher = DOMAIN_PATTERN.matcher(text);
            while (domainMatcher.find()) {
                String domain = trimPunctuation(domainMatcher.group());
                if (isUsefulDomain(domain)) {
                    add(
                        "Domain / hostname",
                        domain,
                        "Defined string @" + data.getAddress() + ": " + abbreviate(text, 140),
                        refs
                    );
                }
            }

            String lower = text.toLowerCase(Locale.ROOT);
            if (containsProtocolMarker(lower)) {
                add(
                    "Protocol / request marker",
                    abbreviate(text, 180),
                    "Defined string @" + data.getAddress(),
                    refs
                );
            }

            if (findings.size() >= MAX_FINDINGS) {
                break;
            }
        }

        return new ScanCount(scanned, truncated);
    }

    private void addMatches(
            String kind,
            String sourceText,
            Address address,
            List<String> refs,
            Pattern pattern) {

        Matcher matcher = pattern.matcher(sourceText);
        while (matcher.find()) {
            String value = trimPunctuation(matcher.group());

            if ("Endpoint URL".equals(kind) && !isUsefulUrl(value, sourceText)) {
                continue;
            }

            add(
                kind,
                value,
                "Defined string @" + address + ": " + abbreviate(sourceText, 140),
                refs
            );
        }
    }

    private List<String> findReferencingFunctions(Program program, Address target) {
        if (target == null) {
            return List.of();
        }

        ReferenceManager references = program.getReferenceManager();
        ReferenceIterator iterator = references.getReferencesTo(target);
        Set<String> functions = new LinkedHashSet<>();

        while (iterator.hasNext() && functions.size() < MAX_REFERENCING_FUNCTIONS) {
            Reference reference = iterator.next();
            Function function =
                program.getFunctionManager().getFunctionContaining(reference.getFromAddress());

            if (function != null) {
                functions.add(function.getName() + "@" + function.getEntryPoint());
            }
        }

        return List.copyOf(functions);
    }

    private void add(
            String kind,
            String value,
            String evidence,
            List<String> referencingFunctions) {

        if (value == null || value.isBlank() || findings.size() >= MAX_FINDINGS) {
            return;
        }

        String key = kind + "|" + value.toLowerCase(Locale.ROOT);
        FindingBuilder existing = findings.get(key);

        if (existing == null) {
            findings.put(
                key,
                new FindingBuilder(kind, value, evidence, referencingFunctions)
            );
        }
        else {
            existing.addEvidence(evidence);
            existing.addReferencingFunctions(referencingFunctions);
        }
    }

    private static boolean matchesAny(String name, String... candidates) {
        for (String candidate : candidates) {
            if (name.equals(candidate.toLowerCase(Locale.ROOT))) {
                return true;
            }
        }
        return false;
    }

    private static boolean containsProtocolMarker(String value) {
        return value.contains("authorization:") ||
            value.contains("user-agent:") ||
            value.contains("content-type:") ||
            value.contains("application/json") ||
            value.contains("application/protobuf") ||
            value.contains("grpc") ||
            value.contains("socket.io") ||
            value.contains("/api/") ||
            value.startsWith("get /") ||
            value.startsWith("post /") ||
            value.startsWith("put /") ||
            value.startsWith("delete /");
    }

    static boolean isUsefulDomain(String domain) {
        if (domain == null || domain.length() < 4 || domain.length() > 253) {
            return false;
        }

        String lower = domain.toLowerCase(Locale.ROOT);

        if (isKnownSchemaHost(lower)) {
            return false;
        }

        return !(lower.endsWith(".dll") ||
            lower.endsWith(".exe") ||
            lower.endsWith(".pdb") ||
            lower.endsWith(".obj") ||
            lower.endsWith(".lib") ||
            lower.endsWith(".c") ||
            lower.endsWith(".cpp") ||
            lower.endsWith(".h") ||
            lower.endsWith(".json") ||
            lower.endsWith(".xml") ||
            lower.endsWith(".ini") ||
            lower.endsWith(".cfg") ||
            lower.endsWith(".png") ||
            lower.endsWith(".jpg") ||
            lower.endsWith(".dds"));
    }

    static boolean isUsefulUrl(String url, String sourceText) {
        if (url == null || url.isBlank()) {
            return false;
        }

        String lower = url.toLowerCase(Locale.ROOT);
        String source = sourceText == null ? "" : sourceText.toLowerCase(Locale.ROOT);

        if (lower.startsWith("http://schemas.microsoft.com/") ||
            lower.startsWith("https://schemas.microsoft.com/") ||
            lower.startsWith("http://www.w3.org/") ||
            lower.startsWith("https://www.w3.org/") ||
            lower.startsWith("http://schemas.xmlsoap.org/") ||
            lower.startsWith("https://schemas.xmlsoap.org/") ||
            lower.startsWith("http://schemas.openxmlformats.org/") ||
            lower.startsWith("https://schemas.openxmlformats.org/")) {
            return false;
        }

        if ((source.contains("<?xml") || source.contains("xmlns=") || source.contains("urn:")) &&
            (lower.contains("/schema") || lower.contains("/schemas/") ||
             lower.contains("windowssettings"))) {
            return false;
        }

        return true;
    }

    private static boolean isKnownSchemaHost(String host) {
        return host.equals("schemas.microsoft.com") ||
            host.equals("www.w3.org") ||
            host.equals("schemas.xmlsoap.org") ||
            host.equals("schemas.openxmlformats.org") ||
            host.equals("purl.org") ||
            host.equals("www.oasis-open.org") ||
            host.equals("www.ecma-international.org");
    }

    private static String trimPunctuation(String value) {
        if (value == null) {
            return "";
        }

        String result = value.trim();
        while (!result.isEmpty() &&
            ".,;:)]}".indexOf(result.charAt(result.length() - 1)) >= 0) {
            result = result.substring(0, result.length() - 1);
        }
        return result;
    }

    private static String abbreviate(String value, int max) {
        String singleLine = value.replace('\r', ' ').replace('\n', ' ').trim();
        if (singleLine.length() <= max) {
            return singleLine;
        }
        return singleLine.substring(0, max) + "...";
    }

    private record ScanCount(int scanned, boolean truncated) {
    }

    private static class FindingBuilder {
        private final String kind;
        private final String value;
        private final List<String> evidence = new ArrayList<>();
        private final Set<String> referencingFunctions = new LinkedHashSet<>();

        FindingBuilder(
                String kind,
                String value,
                String firstEvidence,
                List<String> functions) {
            this.kind = kind;
            this.value = value;
            addEvidence(firstEvidence);
            addReferencingFunctions(functions);
        }

        void addEvidence(String value) {
            if (value == null || value.isBlank() || evidence.contains(value)) {
                return;
            }
            if (evidence.size() < 3) {
                evidence.add(value);
            }
        }

        void addReferencingFunctions(List<String> functions) {
            if (functions == null) {
                return;
            }

            for (String function : functions) {
                if (referencingFunctions.size() >= MAX_REFERENCING_FUNCTIONS) {
                    break;
                }
                referencingFunctions.add(function);
            }
        }

        NetworkFinding build() {
            return new NetworkFinding(
                kind,
                value,
                String.join("; ", evidence),
                List.copyOf(referencingFunctions)
            );
        }
    }
}
