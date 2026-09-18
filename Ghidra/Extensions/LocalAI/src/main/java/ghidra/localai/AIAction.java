package ghidra.localai;

public record AIAction(Type type, String value) {
    public enum Type {
        RENAME_FUNCTION,
        SET_FUNCTION_COMMENT,
        SET_EOL_COMMENT
    }
}
