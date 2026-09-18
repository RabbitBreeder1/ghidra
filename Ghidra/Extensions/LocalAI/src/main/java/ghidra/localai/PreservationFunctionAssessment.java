package ghidra.localai;

import java.util.List;

public record PreservationFunctionAssessment(
        String functionName,
        String entryPoint,
        int priorityScore,
        List<String> evidence,
        String aiSummary) {
}
