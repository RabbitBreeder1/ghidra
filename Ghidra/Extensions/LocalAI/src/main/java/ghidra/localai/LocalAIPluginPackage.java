package ghidra.localai;

import ghidra.framework.plugintool.util.PluginPackage;

public class LocalAIPluginPackage extends PluginPackage {
    public static final String NAME = "Local AI";

    public LocalAIPluginPackage() {
        super(
            NAME,
            null,
            "Local model assistance for decompiler-driven reverse engineering.",
            FEATURE_PRIORITY
        );
    }
}
