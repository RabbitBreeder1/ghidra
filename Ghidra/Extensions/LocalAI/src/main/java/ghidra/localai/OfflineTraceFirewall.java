package ghidra.localai;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Locale;

import ghidra.program.model.listing.Program;

public class OfflineTraceFirewall {

    public OfflineTraceFirewallReport enable(Program program) {
        return change(program, true);
    }

    public OfflineTraceFirewallReport disable(Program program) {
        return change(program, false);
    }

    private OfflineTraceFirewallReport change(Program program, boolean enable) {
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

        Path executable = Path.of(executablePath);
        if (!Files.isRegularFile(executable)) {
            return failure(enable, executablePath, null, null,
                "Executable path does not exist on disk.");
        }

        String id = Integer.toUnsignedString(
            executablePath.toLowerCase(Locale.ROOT).hashCode(),
            16
        );
        String outbound = "Ghidra LocalAI Offline Trace OUT " + id;
        String inbound = "Ghidra LocalAI Offline Trace IN " + id;

        try {
            Path script = writeElevationScript(
                executablePath,
                outbound,
                inbound,
                enable
            );

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
                    "Elevated PowerShell returned exit code " + exitCode +
                        ". The UAC prompt may have been cancelled."
                );
            }

            return new OfflineTraceFirewallReport(
                true,
                enable,
                executablePath,
                outbound,
                inbound,
                enable
                    ? "Inbound and outbound Windows Firewall block rules were created for this executable. " +
                        "This does not automatically block separate launcher/helper processes."
                    : "LocalAI offline-trace firewall rules were removed for this executable."
            );
        }
        catch (Exception e) {
            return failure(
                enable,
                executablePath,
                outbound,
                inbound,
                e.getMessage()
            );
        }
    }

    private static Path writeElevationScript(
            String executablePath,
            String outbound,
            String inbound,
            boolean enable) throws IOException {

        String exe = psSingleQuoted(executablePath);
        String out = psSingleQuoted(outbound);
        String in = psSingleQuoted(inbound);

        String body;
        if (enable) {
            body =
                "$ErrorActionPreference = 'Stop'\r\n" +
                "Get-NetFirewallRule -DisplayName '" + out +
                    "' -ErrorAction SilentlyContinue | Remove-NetFirewallRule\r\n" +
                "Get-NetFirewallRule -DisplayName '" + in +
                    "' -ErrorAction SilentlyContinue | Remove-NetFirewallRule\r\n" +
                "New-NetFirewallRule -DisplayName '" + out +
                    "' -Direction Outbound -Program '" + exe +
                    "' -Action Block -Enabled True -Profile Any | Out-Null\r\n" +
                "New-NetFirewallRule -DisplayName '" + in +
                    "' -Direction Inbound -Program '" + exe +
                    "' -Action Block -Enabled True -Profile Any | Out-Null\r\n";
        }
        else {
            body =
                "$ErrorActionPreference = 'Stop'\r\n" +
                "Get-NetFirewallRule -DisplayName '" + out +
                    "' -ErrorAction SilentlyContinue | Remove-NetFirewallRule\r\n" +
                "Get-NetFirewallRule -DisplayName '" + in +
                    "' -ErrorAction SilentlyContinue | Remove-NetFirewallRule\r\n";
        }

        Path script = Files.createTempFile("ghidra-localai-firewall-", ".ps1");
        Files.writeString(script, body, StandardCharsets.UTF_8);
        return script;
    }

    private static int runElevatedPowerShell(Path script)
            throws IOException, InterruptedException {

        String scriptPath = psSingleQuoted(script.toAbsolutePath().toString());

        String command =
            "Start-Process -FilePath 'powershell.exe' -Verb RunAs -Wait " +
            "-ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File','" +
            scriptPath + "')";

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
