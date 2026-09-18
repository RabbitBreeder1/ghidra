package ghidra.localai;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.function.Consumer;
import java.util.stream.Stream;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryBlockSourceInfo;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;

public class GameFolderScanner {
    private static final int MAX_FILES = 300;
    private static final int MAX_DEPTH = 3;
    private static final long MAX_TOTAL_BYTES = 2L * 1024 * 1024 * 1024;
    private static final long MAX_BYTES_PER_FILE = 96L * 1024 * 1024;
    private static final int BUFFER_SIZE = 256 * 1024;
    private static final int MAX_EVIDENCE = 12;

    private static final Marker[] MARKERS = {
        new Marker("ws2_32.dll", 16, "Winsock library"),
        new Marker("wsock32.dll", 16, "Winsock library"),
        new Marker("winhttp.dll", 15, "WinHTTP library"),
        new Marker("wininet.dll", 15, "WinINet library"),
        new Marker("libcurl", 14, "libcurl"),
        new Marker("curl_easy_perform", 16, "libcurl request API"),
        new Marker("libssl", 12, "OpenSSL/TLS"),
        new Marker("ssl_connect", 15, "TLS connection API"),
        new Marker("steamnetworking", 18, "Steam Networking"),
        new Marker("isteamnetworking", 18, "Steam Networking interface"),
        new Marker("eos_connect", 18, "Epic Online Services Connect"),
        new Marker("eos_p2p", 18, "Epic Online Services P2P"),
        new Marker("raknet", 16, "RakNet"),
        new Marker("rakpeer", 16, "RakNet peer"),
        new Marker("enet_host", 15, "ENet"),
        new Marker("gamespy", 18, "GameSpy"),
        new Marker("natneg", 17, "GameSpy NAT negotiation"),
        new Marker("gpinitialize", 17, "GameSpy Presence"),
        new Marker("serverbrowsing", 14, "Server browser"),
        new Marker("getaddrinfo", 12, "DNS/address resolution"),
        new Marker("gethostbyname", 12, "DNS/address resolution"),
        new Marker("wsaconnect", 14, "Winsock connection API"),
        new Marker("internetconnect", 13, "WinINet connection API"),
        new Marker("winhttpconnect", 14, "WinHTTP connection API"),
        new Marker("winhttpsendrequest", 14, "WinHTTP request API"),
        new Marker("wss://", 12, "WebSocket URL"),
        new Marker("authorization:", 6, "Authorization-like header marker"),
        new Marker("application/json", 2, "JSON content-type/payload marker"),
        new Marker("/api/", 3, "API-like path marker"),
        new Marker("/login", 4, "Login-like path/string marker"),
        new Marker("/auth", 4, "Authentication-like path/string marker"),
        new Marker("/match", 3, "Match-like path/string marker"),
        new Marker("/lobby", 3, "Lobby-like path/string marker")
    };

    private static final FilenameMarker[] FILE_NAME_MARKERS = {
        new FilenameMarker("online", 10, "filename suggests online subsystem"),
        new FilenameMarker("network", 10, "filename suggests networking subsystem"),
        new FilenameMarker("netcode", 10, "filename suggests networking subsystem"),
        new FilenameMarker("match", 8, "filename suggests matchmaking"),
        new FilenameMarker("lobby", 8, "filename suggests lobby subsystem"),
        new FilenameMarker("auth", 8, "filename suggests authentication"),
        new FilenameMarker("server", 7, "filename suggests server communication"),
        new FilenameMarker("master", 6, "filename suggests master/server discovery"),
        new FilenameMarker("gamespy", 14, "filename suggests GameSpy SDK"),
        new FilenameMarker("steam", 10, "filename suggests Steam integration"),
        new FilenameMarker("eos", 10, "filename suggests Epic Online Services"),
        new FilenameMarker("uplay", 10, "filename suggests Ubisoft/Uplay integration"),
        new FilenameMarker("ubisoft", 10, "filename suggests Ubisoft integration")
    };

    private static final RoleHint[] ROLE_HINTS = {
        new RoleHint("blizzarderror", -35, "likely crash/error reporting helper"),
        new RoleHint("crashreport", -35, "likely crash reporting helper"),
        new RoleHint("crashhandler", -35, "likely crash reporting helper"),
        new RoleHint("crashpad", -35, "likely crash reporting helper"),
        new RoleHint("browser", -15, "likely embedded browser/web UI helper"),
        new RoleHint("cef", -15, "likely embedded Chromium/web UI helper"),
        new RoleHint("vivox", -22, "likely voice/chat SDK"),
        new RoleHint("steam_api", -12, "platform SDK/helper"),
        new RoleHint("nvngx", -45, "graphics/DLSS module"),
        new RoleHint("dlss", -45, "graphics/DLSS module"),
        new RoleHint("d3d", -35, "graphics module"),
        new RoleHint("dxgi", -35, "graphics module"),
        new RoleHint("fmod", -30, "audio middleware"),
        new RoleHint("wwise", -30, "audio middleware"),
        new RoleHint("xaudio", -30, "audio module")
    };

    public GameFolderReport scan(Program program, Consumer<String> progress) {
        if (program == null || program.isClosed()) {
            return GameFolderReport.unavailable("No active program is available.");
        }

        String executablePath = program.getExecutablePath();
        if (executablePath == null || executablePath.isBlank()) {
            return GameFolderReport.unavailable(
                "The loaded program does not expose an executable filesystem path."
            );
        }

        File executable = new File(executablePath);
        File root = executable.getParentFile();
        if (root == null || !root.isDirectory()) {
            return GameFolderReport.unavailable(
                "Could not resolve the game folder from: " + executablePath
            );
        }

        List<Path> files = new ArrayList<>();
        try (Stream<Path> stream = Files.walk(root.toPath(), MAX_DEPTH)) {
            stream.filter(Files::isRegularFile)
                .filter(GameFolderScanner::isExecutableModule)
                .limit(MAX_FILES)
                .forEach(files::add);
        }
        catch (IOException e) {
            return GameFolderReport.unavailable(
                "Failed to enumerate game folder: " + e.getMessage()
            );
        }

        List<GameModuleFinding> findings = new ArrayList<>();
        long totalBytesScanned = 0;
        boolean truncated = false;
        int index = 0;

        for (Path path : files) {
            if (totalBytesScanned >= MAX_TOTAL_BYTES) {
                truncated = true;
                break;
            }

            index++;
            update(progress, "Game folder module " + index + "/" + files.size() +
                ": " + path.getFileName());

            long remaining = MAX_TOTAL_BYTES - totalBytesScanned;
            ModuleScan scan = scanFile(path.toFile(), Math.min(MAX_BYTES_PER_FILE, remaining));
            totalBytesScanned += scan.bytesScanned();

            if (scan.truncated()) {
                truncated = true;
            }

            if (scan.score() <= 0) {
                continue;
            }

            String relative;
            try {
                relative = root.toPath().relativize(path).toString();
            }
            catch (Exception e) {
                relative = path.toString();
            }

            List<GameEvidenceHit> mappedHits =
                mapHitsForCurrentProgram(program, executable.toPath(), path, scan.hits());

            findings.add(new GameModuleFinding(
                path.getFileName().toString(),
                relative,
                safeSize(path),
                scan.score(),
                List.copyOf(scan.evidence()),
                mappedHits
            ));
        }

        findings.sort(
            Comparator.comparingInt(GameModuleFinding::score).reversed()
                .thenComparing(GameModuleFinding::fileName, String.CASE_INSENSITIVE_ORDER)
        );

        String note =
            "Raw folder scan only: files are not executed. It searches executable/DLL bytes and " +
            "filenames for networking/online-service indicators, then applies light filename-based " +
            "role hints so obvious crash, browser, graphics, voice, and platform helpers do not " +
            "automatically outrank likely game/loader modules. Scores prioritize what to inspect; " +
            "they do not prove a module's role. High-ranked modules should be imported into Ghidra " +
            "for deeper xref/decompiler analysis.";

        return new GameFolderReport(
            root.getAbsolutePath(),
            List.copyOf(findings),
            files.size(),
            totalBytesScanned,
            truncated,
            note
        );
    }

    private ModuleScan scanFile(File file, long maxBytes) {
        Set<String> evidence = new LinkedHashSet<>();
        Set<String> matchedMarkers = new LinkedHashSet<>();
        List<GameEvidenceHit> hits = new ArrayList<>();
        int score = 0;

        String lowerName = file.getName().toLowerCase(Locale.ROOT);
        for (FilenameMarker marker : FILE_NAME_MARKERS) {
            if (lowerName.contains(marker.value())) {
                score += marker.weight();
                addEvidence(evidence, marker.description());
            }
        }

        for (RoleHint hint : ROLE_HINTS) {
            if (lowerName.contains(hint.value())) {
                score += hint.scoreAdjustment();
                addEvidence(evidence, hint.description());
            }
        }

        long bytesScanned = 0;
        boolean truncated = false;
        int maxMarkerLength = maxMarkerLength();
        byte[] carry = new byte[Math.max(0, maxMarkerLength - 1)];
        int carryLength = 0;

        try (BufferedInputStream in =
                new BufferedInputStream(new FileInputStream(file), BUFFER_SIZE)) {

            byte[] buffer = new byte[BUFFER_SIZE];

            while (bytesScanned < maxBytes) {
                int request = (int)Math.min(buffer.length, maxBytes - bytesScanned);
                int read = in.read(buffer, 0, request);
                if (read < 0) {
                    break;
                }

                byte[] combined = new byte[carryLength + read];
                if (carryLength > 0) {
                    System.arraycopy(carry, 0, combined, 0, carryLength);
                }
                System.arraycopy(buffer, 0, combined, carryLength, read);

                String ascii = new String(combined, StandardCharsets.ISO_8859_1)
                    .toLowerCase(Locale.ROOT);

                for (Marker marker : MARKERS) {
                    int asciiIndex = ascii.indexOf(marker.value());
                    if (asciiIndex >= 0 && matchedMarkers.add(marker.value())) {
                        score += marker.weight();
                        long fileOffset = (bytesScanned - carryLength) + asciiIndex;
                        GameEvidenceHit hit = new GameEvidenceHit(
                            marker.description(),
                            marker.value(),
                            fileOffset,
                            "ASCII",
                            "",
                            ""
                        );
                        hits.add(hit);
                        addEvidence(evidence, hit.toDisplayText());
                    }
                }

                for (Marker marker : MARKERS) {
                    int utf16Index = indexOfUtf16LeAsciiIgnoreCase(combined, marker.value());
                    if (utf16Index >= 0 && matchedMarkers.add(marker.value())) {
                        score += marker.weight();
                        long fileOffset = (bytesScanned - carryLength) + utf16Index;
                        GameEvidenceHit hit = new GameEvidenceHit(
                            marker.description(),
                            marker.value(),
                            fileOffset,
                            "UTF-16LE",
                            "",
                            ""
                        );
                        hits.add(hit);
                        addEvidence(evidence, hit.toDisplayText());
                    }
                }

                bytesScanned += read;

                carryLength = Math.min(carry.length, combined.length);
                if (carryLength > 0) {
                    System.arraycopy(
                        combined,
                        combined.length - carryLength,
                        carry,
                        0,
                        carryLength
                    );
                }

                if (evidence.size() >= MAX_EVIDENCE) {
                    // Keep scanning only enough to respect the byte budget; evidence is already rich.
                }
            }

            if (file.length() > bytesScanned) {
                truncated = true;
            }
        }
        catch (IOException e) {
            addEvidence(evidence, "read error: " + e.getMessage());
        }

        return new ModuleScan(
            Math.max(0, score),
            List.copyOf(evidence),
            List.copyOf(hits),
            bytesScanned,
            truncated
        );
    }

    private static boolean isExecutableModule(Path path) {
        String name = path.getFileName().toString().toLowerCase(Locale.ROOT);
        return name.endsWith(".exe") || name.endsWith(".dll");
    }

    private static long safeSize(Path path) {
        try {
            return Files.size(path);
        }
        catch (IOException e) {
            return -1;
        }
    }

    private static int indexOfUtf16LeAsciiIgnoreCase(byte[] bytes, String marker) {
        if (marker == null || marker.isEmpty()) {
            return -1;
        }

        for (int start = 0; start + (marker.length() * 2) <= bytes.length; start++) {
            boolean match = true;
            for (int i = 0; i < marker.length(); i++) {
                int low = bytes[start + (i * 2)] & 0xff;
                int high = bytes[start + (i * 2) + 1] & 0xff;
                char expected = Character.toLowerCase(marker.charAt(i));

                if (high != 0 || Character.toLowerCase((char)low) != expected) {
                    match = false;
                    break;
                }
            }

            if (match) {
                return start;
            }
        }

        return -1;
    }

    private static List<GameEvidenceHit> mapHitsForCurrentProgram(
            Program program,
            Path executablePath,
            Path scannedPath,
            List<GameEvidenceHit> hits) {

        if (program == null || executablePath == null || scannedPath == null ||
            hits == null || hits.isEmpty()) {
            return hits == null ? List.of() : List.copyOf(hits);
        }

        try {
            if (!Files.isSameFile(executablePath, scannedPath)) {
                return List.copyOf(hits);
            }
        }
        catch (IOException e) {
            if (!executablePath.toAbsolutePath().normalize()
                    .equals(scannedPath.toAbsolutePath().normalize())) {
                return List.copyOf(hits);
            }
        }

        List<GameEvidenceHit> mapped = new ArrayList<>();
        for (GameEvidenceHit hit : hits) {
            Address address = locateAddressForFileOffset(program, hit.fileOffset());
            String mappedAddress = address == null ? "" : address.toString();
            String referencingFunctions =
                address == null ? "" : findReferencingFunctions(program, address);

            mapped.add(new GameEvidenceHit(
                hit.description(),
                hit.marker(),
                hit.fileOffset(),
                hit.encoding(),
                mappedAddress,
                referencingFunctions
            ));
        }

        return List.copyOf(mapped);
    }

    private static Address locateAddressForFileOffset(Program program, long fileOffset) {
        if (fileOffset < 0) {
            return null;
        }

        for (MemoryBlock block : program.getMemory().getBlocks()) {
            for (MemoryBlockSourceInfo sourceInfo : block.getSourceInfos()) {
                Address address = sourceInfo.locateAddressForFileOffset(fileOffset);
                if (address != null) {
                    return address;
                }
            }
        }

        return null;
    }

    private static String findReferencingFunctions(Program program, Address address) {
        ReferenceIterator refs = program.getReferenceManager().getReferencesTo(address);
        LinkedHashSet<String> functions = new LinkedHashSet<>();

        while (refs.hasNext() && functions.size() < 8) {
            Reference ref = refs.next();
            Function function =
                program.getFunctionManager().getFunctionContaining(ref.getFromAddress());
            if (function != null) {
                functions.add(function.getName() + "@" + function.getEntryPoint());
            }
        }

        return String.join(", ", functions);
    }

    private static int maxMarkerLength() {
        int max = 1;
        for (Marker marker : MARKERS) {
            max = Math.max(max, marker.value().length());
        }
        return max;
    }

    private static void addEvidence(Set<String> evidence, String value) {
        if (value != null && !value.isBlank() && evidence.size() < MAX_EVIDENCE) {
            evidence.add(value);
        }
    }

    private static void update(Consumer<String> progress, String message) {
        if (progress != null) {
            progress.accept(message);
        }
    }

    private record Marker(String value, int weight, String description) {
    }

    private record FilenameMarker(String value, int weight, String description) {
    }

    private record RoleHint(String value, int scoreAdjustment, String description) {
    }

    private record ModuleScan(
            int score,
            List<String> evidence,
            List<GameEvidenceHit> hits,
            long bytesScanned,
            boolean truncated) {
    }
}
