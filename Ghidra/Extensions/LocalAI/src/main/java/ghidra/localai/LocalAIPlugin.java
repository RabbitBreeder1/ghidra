package ghidra.localai;

import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;

@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = "Local AI",
    category = "Analysis",
    shortDescription = "Local Ollama AI assistant",
    description = "Dockable local AI chat using current Ghidra decompiler context with undoable AI edits."
)
public class LocalAIPlugin extends ProgramPlugin {
    private final ContextCollector contextCollector;
    private final LocalAIProvider provider;

    public LocalAIPlugin(PluginTool tool) {
        super(tool);
        contextCollector = new ContextCollector(tool);
        provider = new LocalAIProvider(tool, getName(), this);
    }

    public ContextSnapshot collectCurrentContext() {
        Program program = currentProgram;
        ProgramLocation location = currentLocation;
        return contextCollector.collect(program, location);
    }

    @Override
    protected void programActivated(Program program) {
        provider.updateContextSummary(program, currentLocation);
    }

    @Override
    protected void programDeactivated(Program program) {
        provider.updateContextSummary(currentProgram, null);
    }

    @Override
    protected void locationChanged(ProgramLocation location) {
        provider.updateContextSummary(currentProgram, location);
    }

    @Override
    public void dispose() {
        provider.setVisible(false);
        super.dispose();
    }
}
