package ghidra.localai;

import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;

@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = LocalAIPluginPackage.NAME,
    category = "Analysis",
    shortDescription = "Local Ollama AI assistant",
    description = "Dockable local AI chat using current Ghidra decompiler context with undoable AI edits."
)
public class LocalAIPlugin extends ProgramPlugin {
    private final ContextCollector contextCollector;
    private final ProtectionDetector protectionDetector;
    private final NetworkCommunicationScanner networkScanner;
    private final PreservationAnalyzer preservationAnalyzer;
    private final LocalAIProvider provider;

    private volatile ProtectionReport protectionReport = ProtectionReport.notScanned();
    private volatile NetworkReport networkReport = NetworkReport.notScanned();
    private volatile PreservationAnalysisReport preservationReport =
        PreservationAnalysisReport.notRun();

    public LocalAIPlugin(PluginTool tool) {
        super(tool);
        contextCollector = new ContextCollector(tool);
        protectionDetector = new ProtectionDetector();
        networkScanner = new NetworkCommunicationScanner();
        preservationAnalyzer = new PreservationAnalyzer(tool);
        provider = new LocalAIProvider(tool, getName(), this);
    }

    public ContextSnapshot collectCurrentContext() {
        Program program = currentProgram;
        ProgramLocation location = currentLocation;
        return contextCollector.collect(
            program,
            location,
            protectionReport,
            networkReport,
            preservationReport
        );
    }

    public ProtectionReport scanProtection() {
        ProtectionReport report = protectionDetector.scan(currentProgram);
        protectionReport = report;
        return report;
    }

    public NetworkReport scanNetworkCommunication() {
        NetworkReport report = networkScanner.scan(currentProgram);
        networkReport = report;
        return report;
    }

    public PreservationAnalysisReport runPreservationAnalysis(
            OllamaClient ollama,
            String baseUrl,
            String model,
            java.util.function.Consumer<String> progress) throws Exception {

        PreservationAnalysisReport report = preservationAnalyzer.analyze(
            currentProgram,
            ollama,
            baseUrl,
            model,
            progress
        );

        preservationReport = report;
        protectionReport = report.protectionReport();
        networkReport = report.networkReport();
        return report;
    }

    @Override
    protected void programActivated(Program program) {
        resetProgramScans();
        if (provider != null) {
            provider.updateContextSummary(program, currentLocation);
        }
    }

    @Override
    protected void programDeactivated(Program program) {
        resetProgramScans();
        if (provider != null) {
            provider.updateContextSummary(currentProgram, null);
        }
    }

    private void resetProgramScans() {
        protectionReport = ProtectionReport.notScanned();
        networkReport = NetworkReport.notScanned();
        preservationReport = PreservationAnalysisReport.notRun();
    }

    @Override
    protected void locationChanged(ProgramLocation location) {
        if (provider != null) {
            provider.updateContextSummary(currentProgram, location);
        }
    }

    @Override
    public void dispose() {
        if (provider != null) {
            provider.setVisible(false);
        }
        super.dispose();
    }
}
