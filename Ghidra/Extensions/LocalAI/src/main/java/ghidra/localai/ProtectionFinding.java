package ghidra.localai;

public record ProtectionFinding(
        String technology,
        String category,
        String confidence,
        String evidence) {
}
