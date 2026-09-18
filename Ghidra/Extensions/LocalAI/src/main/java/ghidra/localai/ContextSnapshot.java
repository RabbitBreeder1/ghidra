package ghidra.localai;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;

public record ContextSnapshot(
        Program program,
        Address functionEntry,
        Address cursorAddress,
        String programName,
        String executableFormat,
        String language,
        String functionName,
        String prototype,
        String functionComment,
        String cursorComment,
        String decompiledCode,
        String protectionReport,
        String networkReport) {

    public boolean hasFunction() {
        return functionEntry != null;
    }

    public String toPromptContext() {
        StringBuilder sb = new StringBuilder();
        sb.append("Program: ").append(nullToEmpty(programName)).append('\n');
        sb.append("Executable format: ").append(nullToEmpty(executableFormat)).append('\n');
        sb.append("Language: ").append(nullToEmpty(language)).append('\n');
        sb.append("Cursor address: ").append(cursorAddress == null ? "<none>" : cursorAddress).append('\n');
        sb.append("Current function: ").append(nullToEmpty(functionName)).append('\n');
        sb.append("Function entry: ").append(functionEntry == null ? "<none>" : functionEntry).append('\n');
        sb.append("Prototype: ").append(nullToEmpty(prototype)).append('\n');
        sb.append("Function comment: ").append(nullToEmpty(functionComment)).append('\n');
        sb.append("Cursor EOL comment: ").append(nullToEmpty(cursorComment)).append('\n');

        sb.append("\nDRM / PROTECTION CHECK\n");
        sb.append(nullToEmpty(protectionReport)).append('\n');

        sb.append("\nNETWORK / SERVER COMMUNICATION CHECK\n");
        sb.append(nullToEmpty(networkReport)).append('\n');

        sb.append("\nDECOMPILED CODE\n");
        sb.append(decompiledCode == null || decompiledCode.isBlank()
                ? "<no decompiled function available>"
                : decompiledCode);
        return sb.toString();
    }

    private static String nullToEmpty(String value) {
        return value == null || value.isBlank() ? "<none>" : value;
    }
}
