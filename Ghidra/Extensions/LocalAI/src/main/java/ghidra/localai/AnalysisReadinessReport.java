package ghidra.localai;

public record AnalysisReadinessReport(
        boolean programOpen,
        boolean executablePathResolved,
        int functionCount,
        int definedStringCount,
        int externalSymbolCount,
        int externalLibraryCount,
        String assessment,
        String note) {

    public boolean basicStaticReady() {
        return programOpen && executablePathResolved && functionCount > 0;
    }

    public String toDisplayText() {
        StringBuilder sb = new StringBuilder();
        sb.append("ANALYSIS READINESS\n");
        sb.append("Program open: ").append(programOpen).append('\n');
        sb.append("Executable path resolved: ").append(executablePathResolved).append('\n');
        sb.append("Functions discovered: ").append(functionCount).append('\n');
        sb.append("Defined strings: ").append(definedStringCount).append('\n');
        sb.append("External symbols: ").append(externalSymbolCount).append('\n');
        sb.append("External libraries: ").append(externalLibraryCount).append('\n');
        sb.append("Assessment: ").append(assessment == null ? "UNKNOWN" : assessment).append('\n');
        if (note != null && !note.isBlank()) {
            sb.append("Note: ").append(note);
        }
        return sb.toString();
    }
}
