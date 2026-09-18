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
    private final GameFolderScanner gameFolderScanner;
    private final AnalysisReadinessChecker readinessChecker;
    private final OfflineTraceFirewall offlineTraceFirewall;
    private final PreservationAnalyzer preservationAnalyzer;
    private final LocalAIProvider provider;

    private volatile ProtectionReport protectionReport = ProtectionReport.notScanned();
    private volatile NetworkReport networkReport = NetworkReport.notScanned();
    private volatile GameFolderReport gameFolderReport = GameFolderReport.notScanned();
    private volatile PreservationAnalysisReport preservationReport =
        PreservationAnalysisReport.notRun();

    public LocalAIPlugin(PluginTool tool) {
        super(tool);
        contextCollector = new ContextCollector(tool);
        protectionDetector = new ProtectionDetector();
        networkScanner = new NetworkCommunicationScanner();
        gameFolderScanner = new GameFolderScanner();
        readinessChecker = new AnalysisReadinessChecker();
        offlineTraceFirewall = new OfflineTraceFirewall();
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
            gameFolderReport,
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

    public GameFolderReport scanGameFolder(java.util.function.Consumer<String> progress) {
        GameFolderReport report = gameFolderScanner.scan(currentProgram, progress);
        gameFolderReport = report;
        return report;
    }

    public AnalysisReadinessReport checkReadiness() {
        return readinessChecker.check(currentProgram);
    }

    public OfflineTraceFirewallReport enableOfflineTraceFirewall() {
        return offlineTraceFirewall.enable(currentProgram);
    }

    public OfflineTraceFirewallReport disableOfflineTraceFirewall() {
        return offlineTraceFirewall.disable(currentProgram);
    }

    public SafePreservationWorkflowResult runSafePreservationWorkflow(
            OllamaClient ollama,
            String baseUrl,
            String model,
            java.util.function.Consumer<String> progress) throws Exception {

        AnalysisReadinessReport readiness = readinessChecker.check(currentProgram);
        if (!readiness.programOpen()) {
            return new SafePreservationWorkflowResult(
                readiness,
                PreservationAnalysisReport.notRun()
            );
        }

        if (progress != null) {
            progress.accept("Checking local Ollama...");
        }
        ollama.check(baseUrl);

        PreservationAnalysisReport preservation = runPreservationAnalysis(
            ollama,
            baseUrl,
            model,
            progress
        );

        return new SafePreservationWorkflowResult(readiness, preservation);
    }

    public PreservationAnalysisReport runPreservationAnalysis(
            OllamaClient ollama,
            String baseUrl,
            String model,
            java.util.function.Consumer<String> progress) throws Exception {

        GameFolderReport folder = gameFolderScanner.scan(currentProgram, progress);
        gameFolderReport = folder;

        PreservationAnalysisReport report = preservationAnalyzer.analyze(
            currentProgram,
            ollama,
            baseUrl,
            model,
            folder,
            progress
        );

        preservationReport = report;
        protectionReport = report.protectionReport();
        networkReport = report.networkReport();
        gameFolderReport = report.gameFolderReport();
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
        gameFolderReport = GameFolderReport.notScanned();
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
