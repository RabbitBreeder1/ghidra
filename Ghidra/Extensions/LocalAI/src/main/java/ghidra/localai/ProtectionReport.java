package ghidra.localai;

import java.util.List;

public record ProtectionReport(
        List<ProtectionFinding> findings,
        int stringsScanned,
        boolean stringScanTruncated,
        String note) {

    public static ProtectionReport notScanned() {
        return new ProtectionReport(
            List.of(),
            0,
            false,
            "DRM/protector scan has not been run for the current program."
        );
    }

    public static ProtectionReport noProgram() {
        return new ProtectionReport(
            List.of(),
            0,
            false,
            "No active program is available for DRM/protector scanning."
        );
    }

    public boolean hasFindings() {
        return findings != null && !findings.isEmpty();
    }

    public String toDisplayText() {
        StringBuilder sb = new StringBuilder();
        sb.append("DRM / Protector Scan\n");

        if (!hasFindings()) {
            sb.append("No recognized DRM/protector indicators were found.\n");
        }
        else {
            for (ProtectionFinding finding : findings) {
                sb.append("- ")
                    .append(finding.technology())
                    .append(" [")
                    .append(finding.confidence())
                    .append("] ")
                    .append(finding.category())
                    .append("\n  Evidence: ")
                    .append(finding.evidence())
                    .append('\n');
            }
        }

        sb.append("Defined strings scanned: ").append(stringsScanned);
        if (stringScanTruncated) {
            sb.append(" (scan limit reached)");
        }
        sb.append('\n');

        if (note != null && !note.isBlank()) {
            sb.append("Note: ").append(note);
        }

        return sb.toString();
    }

    public String toPromptText() {
        if (note != null && note.startsWith("DRM/protector scan has not")) {
            return "<not scanned>";
        }

        if (!hasFindings()) {
            return "No recognized DRM/protector indicators found. This is heuristic and does not prove absence.";
        }

        StringBuilder sb = new StringBuilder();
        for (ProtectionFinding finding : findings) {
            sb.append(finding.technology())
                .append(" | ")
                .append(finding.confidence())
                .append(" | ")
                .append(finding.category())
                .append(" | ")
                .append(finding.evidence())
                .append('\n');
        }
        return sb.toString().trim();
    }
}
