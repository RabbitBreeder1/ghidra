package ghidra.localai;

import java.util.List;

public record NetworkFinding(
        String kind,
        String value,
        String evidence,
        List<String> referencingFunctions) {
}
