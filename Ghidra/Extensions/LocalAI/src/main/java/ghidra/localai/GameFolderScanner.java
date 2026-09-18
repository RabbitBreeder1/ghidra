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

import ghidra.program.model.listing.Program;

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
        new Marker("http://", 8, "HTTP URL"),
        new Marker("https://", 10, "HTTPS URL"),
        new Marker("wss://", 12, "WebSocket URL"),
        new Marker("/login", 8, "Login endpoint/path"),
        new Marker("/auth", 8, "Authentication endpoint/path"),
        new Marker("/match", 7, "Matchmaking endpoint/path"),
        new Marker("/lobby", 7, "Lobby endpoint/path")
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

            findings.add(new GameModuleFinding(
                path.getFileName().toString(),
                relative,
                safeSize(path),
                scan.score(),
                List.copyOf(scan.evidence())
            ));
        }

        findings.sort(
            Comparator.comparingInt(GameModuleFinding::score).reversed()
                .thenComparing(GameModuleFinding::fileName, String.CASE_INSENSITIVE_ORDER)
        );

        String note =
            "Raw folder scan only: files are not executed. It searches executable/DLL bytes and " +
            "filenames for networking/online-service indicators. High-ranked modules should be " +
            "imported into Ghidra for deeper xref/decompiler analysis.";

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
        int score = 0;

        String lowerName = file.getName().toLowerCase(Locale.ROOT);
        for (FilenameMarker marker : FILE_NAME_MARKERS) {
            if (lowerName.contains(marker.value())) {
                score += marker.weight();
                addEvidence(evidence, marker.description());
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
                    if (ascii.contains(marker.value())) {
                        score += marker.weight();
                        addEvidence(evidence, marker.description() + ": " + marker.value());
                    }
                }

                String utf16Collapsed = collapseUtf16LeAscii(combined).toLowerCase(Locale.ROOT);
                for (Marker marker : MARKERS) {
                    if (utf16Collapsed.contains(marker.value())) {
                        score += marker.weight();
                        addEvidence(evidence,
                            marker.description() + " (UTF-16LE): " + marker.value());
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

        return new ModuleScan(score, List.copyOf(evidence), bytesScanned, truncated);
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

    private static String collapseUtf16LeAscii(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length / 2);

        for (int i = 0; i + 1 < bytes.length; i += 2) {
            int low = bytes[i] & 0xff;
            int high = bytes[i + 1] & 0xff;

            if (high == 0 && low >= 0x20 && low <= 0x7e) {
                sb.append((char)low);
            }
            else {
                sb.append(' ');
            }
        }

        return sb.toString();
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

    private record ModuleScan(
            int score,
            List<String> evidence,
            long bytesScanned,
            boolean truncated) {
    }
}
