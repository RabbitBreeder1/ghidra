package ghidra.localai;

public record SafePreservationWorkflowResult(
        AnalysisReadinessReport readiness,
        PreservationAnalysisReport preservation) {

    public String toDisplayText() {
        StringBuilder sb = new StringBuilder();
        sb.append(readiness == null ? "ANALYSIS READINESS\n<unavailable>" :
            readiness.toDisplayText());
        if (preservation != null) {
            sb.append("\n\n");
            sb.append(preservation.protectionReport() == null
                ? "DRM / PROTECTOR SCAN\n<unavailable>"
                : preservation.protectionReport().toDisplayText());

            sb.append("\n\n");
            sb.append(preservation.networkReport() == null
                ? "NETWORK / SERVER COMMUNICATION SCAN\n<unavailable>"
                : preservation.networkReport().toDisplayText());

            sb.append("\n\n");
            sb.append(preservation.gameFolderReport() == null
                ? "GAME FOLDER ANALYSIS\n<unavailable>"
                : preservation.gameFolderReport().toDisplayText());

            sb.append("\n\n");
            sb.append(preservation.toDisplayText());
        }
        else {
            sb.append("\n\nPRESERVATION ANALYSIS\n<unavailable>");
        }

        return sb.toString();
    }
}
