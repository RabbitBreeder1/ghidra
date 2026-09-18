package ghidra.localai;

public record GameEvidenceHit(
        String description,
        String marker,
        long fileOffset,
        String encoding,
        String mappedAddress,
        String referencingFunctions) {

    public String evidenceTier() {
        if (referencingFunctions != null && !referencingFunctions.isBlank()) {
            return "GHIDRA_XREF_FUNCTION";
        }
        if (mappedAddress != null && !mappedAddress.isBlank()) {
            return "GHIDRA_MAPPED_NO_XREF";
        }
        return "RAW_FILE";
    }

    public String toDisplayText() {
        StringBuilder sb = new StringBuilder();
        sb.append('[').append(evidenceTier()).append("] ")
            .append(description)
            .append(": ")
            .append(marker);

        if (fileOffset >= 0) {
            sb.append(" @ file+0x")
                .append(Long.toHexString(fileOffset).toUpperCase());
        }

        if (encoding != null && !encoding.isBlank()) {
            sb.append(" [").append(encoding).append(']');
        }

        if (mappedAddress != null && !mappedAddress.isBlank()) {
            sb.append(" -> ").append(mappedAddress);
        }

        if (referencingFunctions != null && !referencingFunctions.isBlank()) {
            sb.append(" refs: ").append(referencingFunctions);
        }

        return sb.toString();
    }
}
