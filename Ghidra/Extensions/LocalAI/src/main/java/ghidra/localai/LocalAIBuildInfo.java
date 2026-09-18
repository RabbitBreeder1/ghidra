package ghidra.localai;

public final class LocalAIBuildInfo {
    public static final String BUILD_ID = "2026-09-18-preservation-r5";

    public static String loadedFrom() {
        try {
            var source = LocalAIBuildInfo.class
                .getProtectionDomain()
                .getCodeSource();

            if (source == null || source.getLocation() == null) {
                return "<unknown>";
            }

            return source.getLocation().toString();
        }
        catch (Exception e) {
            return "<unknown>";
        }
    }

    private LocalAIBuildInfo() {
    }
}
