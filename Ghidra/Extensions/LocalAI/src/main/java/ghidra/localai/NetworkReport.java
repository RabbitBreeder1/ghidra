package ghidra.localai;

import java.util.List;

public record NetworkReport(
        List<NetworkFinding> findings,
        int definedStringsScanned,
        int externalSymbolsScanned,
        boolean stringScanTruncated,
        String note) {

    public static NetworkReport notScanned() {
        return new NetworkReport(
            List.of(), 0, 0, false,
            "Network/server communication scan has not been run for the current program."
        );
    }

    public static NetworkReport noProgram() {
        return new NetworkReport(
            List.of(), 0, 0, false,
            "No active program is available for network/server scanning."
        );
    }

    public boolean hasFindings() {
        return findings != null && !findings.isEmpty();
    }

    public String toDisplayText() {
        StringBuilder sb = new StringBuilder();
        sb.append("Network / Server Communication Scan\n");

        if (!hasFindings()) {
            sb.append("No recognized static network indicators were found.\n");
        }
        else {
            for (NetworkFinding finding : findings) {
                sb.append("- ")
                    .append(finding.kind())
                    .append(": ")
                    .append(finding.value())
                    .append("\n  Evidence: ")
                    .append(finding.evidence())
                    .append('\n');

                if (finding.referencingFunctions() != null &&
                    !finding.referencingFunctions().isEmpty()) {
                    sb.append("  Referenced by: ")
                        .append(String.join(", ", finding.referencingFunctions()))
                        .append('\n');
                }
            }
        }

        sb.append("Defined strings scanned: ").append(definedStringsScanned);
        if (stringScanTruncated) {
            sb.append(" (scan limit reached)");
        }
        sb.append('\n');
        sb.append("External symbols scanned: ").append(externalSymbolsScanned).append('\n');

        if (note != null && !note.isBlank()) {
            sb.append("Note: ").append(note);
        }

        return sb.toString();
    }

    public String toPromptText() {
        if (note != null && note.startsWith("Network/server communication scan has not")) {
            return "<not scanned>";
        }

        if (!hasFindings()) {
            return "No recognized static network indicators found. " +
                "This does not rule out runtime-resolved, encrypted, embedded, or custom networking.";
        }

        StringBuilder sb = new StringBuilder();
        for (NetworkFinding finding : findings) {
            sb.append(finding.kind())
                .append(" | ")
                .append(finding.value())
                .append(" | ")
                .append(finding.evidence());

            if (finding.referencingFunctions() != null &&
                !finding.referencingFunctions().isEmpty()) {
                sb.append(" | local functions: ")
                    .append(String.join(", ", finding.referencingFunctions()));
            }
            sb.append('\n');
        }
        return sb.toString().trim();
    }
}
