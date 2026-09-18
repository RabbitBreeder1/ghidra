package ghidra.localai;

import java.util.List;

public record PreservationAnalysisReport(
        ProtectionReport protectionReport,
        NetworkReport networkReport,
        List<PreservationFunctionAssessment> functions,
        String synthesis,
        String note) {

    public static PreservationAnalysisReport notRun() {
        return new PreservationAnalysisReport(
            ProtectionReport.notScanned(),
            NetworkReport.notScanned(),
            List.of(),
            "",
            "One-button preservation analysis has not been run for the current program."
        );
    }

    public String toDisplayText() {
        StringBuilder sb = new StringBuilder();
        sb.append("PRESERVATION ANALYSIS\n\n");

        if (synthesis != null && !synthesis.isBlank()) {
            sb.append(synthesis.trim()).append("\n\n");
        }

        if (functions != null && !functions.isEmpty()) {
            sb.append("Prioritized functions reviewed: ").append(functions.size()).append('\n');
            for (PreservationFunctionAssessment assessment : functions) {
                sb.append("- ")
                    .append(assessment.functionName())
                    .append('@')
                    .append(assessment.entryPoint())
                    .append(" [score ")
                    .append(assessment.priorityScore())
                    .append("]\n");

                if (assessment.evidence() != null && !assessment.evidence().isEmpty()) {
                    sb.append("  Evidence: ")
                        .append(String.join("; ", assessment.evidence()))
                        .append('\n');
                }

                if (assessment.aiSummary() != null && !assessment.aiSummary().isBlank()) {
                    sb.append("  AI: ")
                        .append(assessment.aiSummary().replace('\n', ' ').trim())
                        .append('\n');
                }
            }
        }

        if (note != null && !note.isBlank()) {
            sb.append("\nNote: ").append(note);
        }

        return sb.toString();
    }

    public String toPromptText() {
        if (note != null && note.startsWith("One-button preservation analysis has not")) {
            return "<not run>";
        }

        StringBuilder sb = new StringBuilder();
        if (synthesis != null && !synthesis.isBlank()) {
            sb.append(synthesis.trim()).append("\n\n");
        }

        int count = 0;
        if (functions != null) {
            for (PreservationFunctionAssessment assessment : functions) {
                if (count++ >= 12) {
                    sb.append("... additional analyzed functions omitted from prompt context ...\n");
                    break;
                }
                sb.append(assessment.functionName())
                    .append('@')
                    .append(assessment.entryPoint())
                    .append(" score=")
                    .append(assessment.priorityScore())
                    .append(" | ")
                    .append(assessment.aiSummary() == null ? "" :
                        assessment.aiSummary().replace('\n', ' ').trim())
                    .append('\n');
            }
        }
        return sb.toString().trim();
    }
}
