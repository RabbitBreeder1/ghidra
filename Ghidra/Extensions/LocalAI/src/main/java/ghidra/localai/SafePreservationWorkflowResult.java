package ghidra.localai;

public record SafePreservationWorkflowResult(
        AnalysisReadinessReport readiness,
        PreservationAnalysisReport preservation) {

    public String toDisplayText() {
        StringBuilder sb = new StringBuilder();
        sb.append(readiness == null ? "ANALYSIS READINESS\n<unavailable>" :
            readiness.toDisplayText());
        sb.append("\n\n");
        sb.append(preservation == null ? "PRESERVATION ANALYSIS\n<unavailable>" :
            preservation.toDisplayText());
        return sb.toString();
    }
}
