package ghidra.localai;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.stream.Stream;

import ghidra.program.model.listing.Program;

public class OfflineTraceFirewall {
    private static final int MAX_EXECUTABLES = 200;

    public OfflineTraceFirewallReport enable(Program program) {
        return changeGameFolder(program, true);
    }

    public OfflineTraceFirewallReport disable(Program program) {
        return changeGameFolder(program, false);
    }

    private OfflineTraceFirewallReport changeGameFolder(Program program, boolean enable) {
        if (program == null || program.isClosed()) {
            return failure(enable, null, null, null, "No active program is available.");
        }

        if (!isWindows()) {
            return failure(
                enable,
                program.getExecutablePath(),
                null,
                null,
                "Offline trace firewall automation is currently implemented only for Windows."
            );
        }

        String executablePath = program.getExecutablePath();
        if (executablePath == null || executablePath.isBlank()) {
            return failure(enable, null, null, null,
                "The loaded program does not expose an executable filesystem path.");
        }

        Path executable = Path.of(executablePath).toAbsolutePath().normalize();
        if (!Files.isRegularFile(executable)) {
            return failure(enable, executablePath, null, null,
                "Executable path does not exist on disk.");
        }

        Path root = executable.getParent();
        if (root == null || !Files.isDirectory(root)) {
            return failure(enable, executablePath, null, null,
                "Could not resolve the game folder.");
        }

        String folderId = Integer.toUnsignedString(
            root.toString().toLowerCase(Locale.ROOT).hashCode(),
            16
        );
        String prefix = "Ghidra LocalAI SafeTrace " + folderId;
        String outbound = prefix + " OUT *";
        String inbound = prefix + " IN *";

        try {
            List<Path> executables = enable ? enumerateExecutables(root) : List.of();
            if (enable && executables.isEmpty()) {
                return failure(
                    true,
                    executablePath,
                    outbound,
                    inbound,
                    "No executable files were found in the game folder."
                );
            }

            Path script = writeElevationScript(root, prefix, executables, enable);

            int exitCode = runElevatedPowerShell(script);
            try {
                Files.deleteIfExists(script);
            }
            catch (IOException ignored) {
                // Temporary file cleanup failure is non-fatal.
            }

            if (exitCode != 0) {
                return failure(
                    enable,
                    executablePath,
                    outbound,
                    inbound,
                    "Elevated firewall script returned exit code " + exitCode +
                        ". The UAC prompt may have been cancelled or rule verification failed."
                );
            }

            String message = enable
                ? "Verified inbound/outbound Windows Firewall block rules for " +
                    executables.size() + " EXE(s) under " + root +
                    ". This safety gate does not execute the game. DLLs loaded inside those " +
                    "blocked processes inherit the process network block. Launchers or helper " +
                    "processes located outside this game folder are NOT covered."
                : "Removed the LocalAI SafeTrace firewall rules for game folder " + root + ".";

            return new OfflineTraceFirewallReport(
                true,
                enable,
                root.toString(),
                outbound,
                inbound,
                message
            );
        }
        catch (Exception e) {
            return failure(
                enable,
                root.toString(),
                outbound,
                inbound,
                e.getMessage()
            );
        }
    }

    private static List<Path> enumerateExecutables(Path root) throws IOException {
        List<Path> executables = new ArrayList<>();

        try (Stream<Path> stream = Files.walk(root)) {
            stream.filter(Files::isRegularFile)
                .filter(path -> path.getFileName().toString()
                    .toLowerCase(Locale.ROOT).endsWith(".exe"))
                .limit(MAX_EXECUTABLES + 1L)
                .forEach(path -> executables.add(path.toAbsolutePath().normalize()));
        }

        if (executables.size() > MAX_EXECUTABLES) {
            throw new IOException(
                "More than " + MAX_EXECUTABLES +
                " executable files were found under the game folder. " +
                "LocalAI refuses to create an incomplete safety block."
            );
        }

        return List.copyOf(executables);
    }

    private static Path writeElevationScript(
            Path root,
            String prefix,
            List<Path> executables,
            boolean enable) throws IOException {

        StringBuilder body = new StringBuilder();
        body.append("$ErrorActionPreference = 'Stop'\r\n");
        body.append("$prefix = '").append(psSingleQuoted(prefix)).append("'\r\n");
        body.append("Get-NetFirewallRule -DisplayName ($prefix + '*') ")
            .append("-ErrorAction SilentlyContinue | Remove-NetFirewallRule\r\n");

        if (enable) {
            body.append("$programs = @(\r\n");
            for (Path executable : executables) {
                body.append("  '")
                    .append(psSingleQuoted(executable.toString()))
                    .append("'\r\n");
            }
            body.append(")\r\n");
            body.append("$i = 0\r\n");
            body.append("foreach ($program in $programs) {\r\n");
            body.append("  New-NetFirewallRule -DisplayName ($prefix + ' OUT ' + $i) ")
                .append("-Direction Outbound -Program $program -Action Block -Enabled True ")
                .append("-Profile Any | Out-Null\r\n");
            body.append("  New-NetFirewallRule -DisplayName ($prefix + ' IN ' + $i) ")
                .append("-Direction Inbound -Program $program -Action Block -Enabled True ")
                .append("-Profile Any | Out-Null\r\n");
            body.append("  $i++\r\n");
            body.append("}\r\n");
            body.append("$expected = $programs.Count * 2\r\n");
            body.append("$actual = @(Get-NetFirewallRule -DisplayName ($prefix + '*') ")
                .append("-ErrorAction SilentlyContinue).Count\r\n");
            body.append("if ($actual -lt $expected) { exit 31 }\r\n");
        }
        else {
            body.append("$remaining = @(Get-NetFirewallRule -DisplayName ($prefix + '*') ")
                .append("-ErrorAction SilentlyContinue).Count\r\n");
            body.append("if ($remaining -ne 0) { exit 32 }\r\n");
        }

        body.append("exit 0\r\n");

        Path script = Files.createTempFile("ghidra-localai-safetrace-", ".ps1");
        Files.writeString(script, body.toString(), StandardCharsets.UTF_8);
        return script;
    }

    private static int runElevatedPowerShell(Path script)
            throws IOException, InterruptedException {

        String scriptPath = script.toAbsolutePath().toString();
        String argumentLine =
            "-NoProfile -ExecutionPolicy Bypass -File \"" + scriptPath + "\"";

        String command =
            "$p = Start-Process -FilePath 'powershell.exe' -Verb RunAs -Wait -PassThru " +
            "-ArgumentList '" + argumentLine.replace("'", "''") +
            "'; exit $p.ExitCode";

        Process process = new ProcessBuilder(
            "powershell.exe",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            command
        ).inheritIO().start();

        return process.waitFor();
    }

    private static boolean isWindows() {
        return System.getProperty("os.name", "")
            .toLowerCase(Locale.ROOT)
            .contains("windows");
    }

    private static String psSingleQuoted(String value) {
        return value == null ? "" : value.replace("'", "''");
    }

    private static OfflineTraceFirewallReport failure(
            boolean enable,
            String executablePath,
            String outbound,
            String inbound,
            String message) {

        return new OfflineTraceFirewallReport(
            false,
            !enable,
            executablePath,
            outbound,
            inbound,
            message == null ? "Unknown error" : message
        );
    }
}
