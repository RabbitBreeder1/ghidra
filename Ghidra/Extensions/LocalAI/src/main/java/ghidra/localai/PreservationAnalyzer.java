package ghidra.localai;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompiledFunction;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.symbol.ExternalLocationIterator;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.util.task.TaskMonitor;

public class PreservationAnalyzer {
    private static final int MAX_AI_FUNCTIONS = 18;
    private static final int MAX_DECOMPILED_CHARS = 14_000;
    private static final int DECOMPILE_TIMEOUT_SECONDS = 20;
    private static final int MAX_DYNAMIC_STRINGS = 100_000;

    private static final Set<String> DYNAMIC_LOADER_APIS = Set.of(
        "loadlibrarya", "loadlibraryw", "loadlibraryexa", "loadlibraryexw",
        "getprocaddress", "ldrloaddll", "ldrgetprocedureaddress"
    );

    private static final String[] NETWORK_DYNAMIC_MARKERS = {
        "ws2_32.dll", "wsock32.dll", "winhttp.dll", "wininet.dll",
        "libcurl", "libssl", "libcrypto", "steamnetworking",
        "getaddrinfo", "gethostbyname", "wsaconnect", "sendto", "recvfrom",
        "winhttpconnect", "winhttpsendrequest", "internetconnect",
        "curl_easy_perform", "ssl_connect"
    };

    private static final String FUNCTION_SYSTEM_PROMPT = """
You are assisting with preservation-oriented reverse engineering of an old game client.
The goal is to understand how the client communicates with services that may no longer exist:
login/authentication, account/profile, version checks, matchmaking, lobbies, sessions,
telemetry, content/config downloads, and game-state networking.

Analyze only the evidence supplied by Ghidra. Do not invent server behavior.
Absence of evidence is UNKNOWN, not evidence for a "likely" architecture.
Do not infer TCP, UDP, HTTP, HTTPS, authentication, telemetry, matchmaking, or any other service
unless the supplied function/code/API/string/call evidence directly supports that inference.

Return a concise response with:
ROLE: evidence-supported role, or UNKNOWN
RELEVANCE: HIGH, MEDIUM, LOW, UNRELATED, or UNKNOWN
EVIDENCE: concrete code/API/string/call evidence only; write NONE if there is none
NEXT: one or two specific Ghidra investigation steps
""";

    private static final String FINAL_SYSTEM_PROMPT = """
You are producing a preservation research report for an old online game client.
Using only the supplied static-analysis evidence and function assessments, build a concise
preservation report.

STRICT EVIDENCE RULES:
- Never fill a missing category with what an online game would "probably" or "likely" use.
- If the evidence does not establish a protocol, API, endpoint, service, or function role, write UNKNOWN.
- Do not infer Winsock, TCP, UDP, HTTP, HTTPS, TLS, authentication, matchmaking, telemetry,
  version checking, or session management merely because the program is a game.
- A generic LoadLibrary/GetProcAddress call is NOT networking evidence by itself.
- Game-folder evidence uses explicit tiers:
  RAW_FILE = marker exists in file bytes only.
  GHIDRA_MAPPED_NO_XREF = file offset maps into Ghidra, but no function reference is established.
  GHIDRA_XREF_FUNCTION = Ghidra has an actual xref from a function to that mapped marker.
- Only GHIDRA_XREF_FUNCTION or structured Ghidra import/reference evidence may support a function-role claim.
- RAW_FILE and GHIDRA_MAPPED_NO_XREF may prioritize investigation but must never be described as proof
  that a function calls an API, uses a protocol, or implements a service.
- Separate CONFIRMED EVIDENCE from EVIDENCE-BACKED HYPOTHESES.
- A hypothesis is allowed only when you cite the exact supplied clue that supports it.
- If there are no network findings and no preservation-relevant function assessments, explicitly
  state that static analysis has not yet identified the networking implementation.

Report:
1. CONFIRMED EVIDENCE
2. EVIDENCE-BACKED HYPOTHESES
3. UNKNOWN / NOT YET ESTABLISHED
4. FUNCTIONS TO INVESTIGATE NEXT
5. NEXT PRESERVATION STEPS

The objective is interoperability research and preservation, not speculation.
""";

    private final PluginTool tool;
    private final ProtectionDetector protectionDetector = new ProtectionDetector();
    private final NetworkCommunicationScanner networkScanner = new NetworkCommunicationScanner();

    public PreservationAnalyzer(PluginTool tool) {
        this.tool = tool;
    }

    public PreservationAnalysisReport analyze(
            Program program,
            OllamaClient ollama,
            String baseUrl,
            String model,
            GameFolderReport gameFolder,
            Consumer<String> progress) throws Exception {

        if (program == null || program.isClosed()) {
            return new PreservationAnalysisReport(
                ProtectionReport.noProgram(),
                NetworkReport.noProgram(),
                GameFolderReport.unavailable("No active program is available."),
                List.of(),
                "",
                "No active program is available."
            );
        }

        update(progress, "Protection scan...");
        ProtectionReport protection = protectionDetector.scan(program);

        update(progress, "Network/server scan...");
        NetworkReport network = networkScanner.scan(program);

        Map<Address, Candidate> candidates = new LinkedHashMap<>();
        addNetworkCandidates(program, network, candidates);
        addMappedFolderCandidates(program, gameFolder, candidates);

        update(progress, "Finding dynamically resolved networking...");
        addDynamicResolutionCandidates(program, candidates);

        expandOneHop(candidates);

        List<Candidate> ranked = candidates.values().stream()
            .filter(candidate -> candidate.function() != null &&
                !candidate.function().isExternal() &&
                candidate.score() >= 5)
            .sorted(Comparator.comparingInt(Candidate::score).reversed())
            .limit(MAX_AI_FUNCTIONS)
            .toList();

        List<PreservationFunctionAssessment> assessments = new ArrayList<>();

        int index = 0;
        for (Candidate candidate : ranked) {
            index++;
            Function function = candidate.function();
            update(progress,
                "AI reviewing function " + index + "/" + ranked.size() + ": " + function.getName());

            String code = decompile(program, function);
            String prompt = buildFunctionPrompt(program, function, candidate, code);
            String summary = ollama.complete(baseUrl, model, FUNCTION_SYSTEM_PROMPT, prompt);

            assessments.add(new PreservationFunctionAssessment(
                function.getName(),
                function.getEntryPoint().toString(),
                candidate.score(),
                List.copyOf(candidate.evidence()),
                summary
            ));
        }

        update(progress, "Building preservation map...");
        String synthesis;

        boolean hasStructuredNetworkEvidence = network != null && network.hasFindings();
        boolean hasFunctionEvidence = !assessments.isEmpty();
        boolean hasFolderRawEvidence = gameFolder != null && gameFolder.hasCandidates();

        if (!hasStructuredNetworkEvidence && !hasFunctionEvidence) {
            synthesis = hasFolderRawEvidence
                ? buildRawFolderOnlySynthesis(program, protection, network, gameFolder)
                : buildNoEvidenceSynthesis(program, protection, network, gameFolder);
        }
        else {
            String finalPrompt =
                buildFinalPrompt(program, protection, network, gameFolder, assessments);
            synthesis = ollama.complete(baseUrl, model, FINAL_SYSTEM_PROMPT, finalPrompt);
        }

        String note =
            "One-button analysis is intentionally bounded to the top " + MAX_AI_FUNCTIONS +
            " statically relevant functions. Static analysis can miss runtime-decrypted endpoints, " +
            "custom protocols, dynamically generated hostnames, and behavior located in other DLLs.";

        update(progress, "Preservation analysis complete");
        return new PreservationAnalysisReport(
            protection,
            network,
            gameFolder == null ? GameFolderReport.notScanned() : gameFolder,
            List.copyOf(assessments),
            synthesis,
            note
        );
    }

    private void addNetworkCandidates(
            Program program,
            NetworkReport network,
            Map<Address, Candidate> candidates) {

        if (network == null || network.findings() == null) {
            return;
        }

        for (NetworkFinding finding : network.findings()) {
            if (finding.referencingFunctions() == null) {
                continue;
            }

            for (String ref : finding.referencingFunctions()) {
                Function function = functionFromDisplayRef(program, ref);
                if (function == null) {
                    continue;
                }

                Candidate candidate = candidates.computeIfAbsent(
                    function.getEntryPoint(),
                    ignored -> new Candidate(function)
                );

                candidate.addScore(12);
                candidate.addEvidence(finding.kind() + ": " + finding.value());
            }
        }
    }

    private void addMappedFolderCandidates(
            Program program,
            GameFolderReport gameFolder,
            Map<Address, Candidate> candidates) {

        if (gameFolder == null || gameFolder.modules() == null) {
            return;
        }

        for (GameModuleFinding module : gameFolder.modules()) {
            if (module.evidenceHits() == null) {
                continue;
            }

            for (GameEvidenceHit hit : module.evidenceHits()) {
                if (hit.mappedAddress() == null || hit.mappedAddress().isBlank()) {
                    continue;
                }

                Address[] addresses = program.parseAddress(hit.mappedAddress());
                if (addresses.length == 0) {
                    continue;
                }

                Address address = addresses[0];
                LinkedHashSet<Function> referencedFunctions = new LinkedHashSet<>();

                ReferenceIterator refs =
                    program.getReferenceManager().getReferencesTo(address);

                while (refs.hasNext()) {
                    Reference ref = refs.next();
                    Function function =
                        program.getFunctionManager().getFunctionContaining(ref.getFromAddress());
                    if (function != null && !function.isExternal()) {
                        referencedFunctions.add(function);
                    }
                }

                int score = scoreRawHit(hit);
                for (Function function : referencedFunctions) {
                    Candidate candidate = candidates.computeIfAbsent(
                        function.getEntryPoint(),
                        ignored -> new Candidate(function)
                    );

                    candidate.addScore(score);
                    candidate.addEvidence(
                        "Raw mapped marker " + hit.marker() +
                        " @ file+0x" + Long.toHexString(hit.fileOffset()).toUpperCase(Locale.ROOT) +
                        " -> " + hit.mappedAddress()
                    );
                }
            }
        }
    }

    private int scoreRawHit(GameEvidenceHit hit) {
        if (hit == null || hit.marker() == null) {
            return 0;
        }

        String marker = hit.marker().toLowerCase(Locale.ROOT);

        if (marker.contains("ws2_32") ||
            marker.contains("winhttp") ||
            marker.contains("wininet") ||
            marker.contains("curl_easy_perform") ||
            marker.contains("ssl_connect") ||
            marker.contains("getaddrinfo") ||
            marker.contains("gethostbyname") ||
            marker.contains("steamnetworking") ||
            marker.contains("eos_") ||
            marker.contains("raknet") ||
            marker.contains("enet_") ||
            marker.contains("gamespy")) {
            return 14;
        }

        if (marker.equals("libcurl") ||
            marker.equals("libssl") ||
            marker.equals("authorization:") ||
            marker.equals("wss://")) {
            return 9;
        }

        if (marker.contains("/login") ||
            marker.contains("/auth") ||
            marker.contains("/api/") ||
            marker.contains("/match") ||
            marker.contains("/lobby")) {
            return 6;
        }

        return 4;
    }

    private void addDynamicResolutionCandidates(
            Program program,
            Map<Address, Candidate> candidates) {

        for (String library : program.getExternalManager().getExternalLibraryNames()) {
            if (library == null) {
                continue;
            }

            ExternalLocationIterator iterator =
                program.getExternalManager().getExternalLocations(library);

            while (iterator.hasNext()) {
                ExternalLocation location = iterator.next();
                String label = location.getLabel();
                if (label == null ||
                    !DYNAMIC_LOADER_APIS.contains(label.toLowerCase(Locale.ROOT))) {
                    continue;
                }

                ReferenceIterator refs =
                    program.getReferenceManager().getReferencesTo(location.getExternalSpaceAddress());

                while (refs.hasNext()) {
                    Reference ref = refs.next();
                    Function function =
                        program.getFunctionManager().getFunctionContaining(ref.getFromAddress());

                    if (function == null) {
                        continue;
                    }

                    Candidate candidate = candidates.computeIfAbsent(
                        function.getEntryPoint(),
                        ignored -> new Candidate(function)
                    );

                    candidate.addScore(1);
                    candidate.addEvidence(
                        "Generic dynamic API resolver (not networking evidence by itself): " +
                        library + "!" + label
                    );
                }
            }
        }

        DataIterator dataIterator = program.getListing().getDefinedData(true);
        int strings = 0;

        while (dataIterator.hasNext() && strings < MAX_DYNAMIC_STRINGS) {
            Data data = dataIterator.next();
            if (!data.hasStringValue()) {
                continue;
            }

            strings++;
            Object raw = data.getValue();
            if (!(raw instanceof String text) || text.isBlank()) {
                continue;
            }

            String lower = text.toLowerCase(Locale.ROOT);
            String matchedMarker = null;
            for (String marker : NETWORK_DYNAMIC_MARKERS) {
                if (lower.contains(marker)) {
                    matchedMarker = marker;
                    break;
                }
            }

            if (matchedMarker == null) {
                continue;
            }

            ReferenceIterator refs =
                program.getReferenceManager().getReferencesTo(data.getAddress());

            while (refs.hasNext()) {
                Reference ref = refs.next();
                Function function =
                    program.getFunctionManager().getFunctionContaining(ref.getFromAddress());

                if (function == null) {
                    continue;
                }

                Candidate candidate = candidates.computeIfAbsent(
                    function.getEntryPoint(),
                    ignored -> new Candidate(function)
                );

                candidate.addScore(7);
                candidate.addEvidence(
                    "Network/dynamic-resolution string: " + abbreviate(text, 100)
                );
            }
        }
    }

    private void expandOneHop(Map<Address, Candidate> candidates) {
        List<Candidate> seeds = new ArrayList<>(candidates.values());

        for (Candidate seed : seeds) {
            Function function = seed.function();
            if (function == null) {
                continue;
            }

            for (Function caller : function.getCallingFunctions(TaskMonitor.DUMMY)) {
                if (caller == null || caller.isExternal()) {
                    continue;
                }

                Candidate adjacent = candidates.computeIfAbsent(
                    caller.getEntryPoint(),
                    ignored -> new Candidate(caller)
                );
                adjacent.addScore(3);
                adjacent.addEvidence("Calls preservation-relevant function " + function.getName());
            }

            for (Function callee : function.getCalledFunctions(TaskMonitor.DUMMY)) {
                if (callee == null || callee.isExternal()) {
                    continue;
                }

                Candidate adjacent = candidates.computeIfAbsent(
                    callee.getEntryPoint(),
                    ignored -> new Candidate(callee)
                );
                adjacent.addScore(2);
                adjacent.addEvidence("Called by preservation-relevant function " + function.getName());
            }
        }
    }

    private Function functionFromDisplayRef(Program program, String value) {
        if (value == null) {
            return null;
        }

        int at = value.lastIndexOf('@');
        if (at < 0 || at == value.length() - 1) {
            return null;
        }

        String addressText = value.substring(at + 1);
        Address[] addresses = program.parseAddress(addressText);
        if (addresses.length == 0) {
            return null;
        }

        return program.getFunctionManager().getFunctionAt(addresses[0]);
    }

    private String decompile(Program program, Function function) {
        DecompInterface decompiler = new DecompInterface();

        try {
            DecompileOptions options = DecompilerUtils.getDecompileOptions(tool, program);
            decompiler.setOptions(options);
            decompiler.toggleCCode(true);
            decompiler.toggleSyntaxTree(true);
            decompiler.setSimplificationStyle("decompile");

            if (!decompiler.openProgram(program)) {
                return "<decompiler failed to open program: " + decompiler.getLastMessage() + ">";
            }

            DecompileResults results = decompiler.decompileFunction(
                function,
                DECOMPILE_TIMEOUT_SECONDS,
                TaskMonitor.DUMMY
            );

            if (!results.decompileCompleted()) {
                return "<decompilation failed: " + results.getErrorMessage() + ">";
            }

            DecompiledFunction output = results.getDecompiledFunction();
            if (output == null || output.getC() == null) {
                return "<no decompiled C available>";
            }

            String code = output.getC();
            if (code.length() > MAX_DECOMPILED_CHARS) {
                return code.substring(0, MAX_DECOMPILED_CHARS) +
                    "\n/* ... truncated for preservation analysis ... */";
            }
            return code;
        }
        catch (Exception e) {
            return "<decompilation error: " + e.getMessage() + ">";
        }
        finally {
            decompiler.dispose();
        }
    }

    private String buildFunctionPrompt(
            Program program,
            Function function,
            Candidate candidate,
            String code) {

        StringBuilder sb = new StringBuilder();
        sb.append("Program: ").append(program.getName()).append('\n');
        sb.append("Function: ").append(function.getName())
            .append('@').append(function.getEntryPoint()).append('\n');
        sb.append("Prototype: ")
            .append(function.getPrototypeString(false, true)).append('\n');
        sb.append("Priority score: ").append(candidate.score()).append('\n');
        sb.append("Why selected:\n");
        for (String evidence : candidate.evidence()) {
            sb.append("- ").append(evidence).append('\n');
        }

        sb.append("Callers:\n");
        appendFunctionSet(sb, function.getCallingFunctions(TaskMonitor.DUMMY));

        sb.append("Callees:\n");
        appendFunctionSet(sb, function.getCalledFunctions(TaskMonitor.DUMMY));

        sb.append("\nDECOMPILED C\n============\n");
        sb.append(code);
        return sb.toString();
    }

    private void appendFunctionSet(StringBuilder sb, Set<Function> functions) {
        int count = 0;
        for (Function function : functions) {
            if (function == null) {
                continue;
            }
            if (count++ >= 20) {
                sb.append("- ... more omitted ...\n");
                break;
            }
            sb.append("- ")
                .append(function.getName())
                .append('@')
                .append(function.getEntryPoint())
                .append(function.isExternal() ? " [external]" : "")
                .append('\n');
        }
    }

    private String buildRawFolderOnlySynthesis(
            Program program,
            ProtectionReport protection,
            NetworkReport network,
            GameFolderReport gameFolder) {

        StringBuilder sb = new StringBuilder();
        sb.append("CONFIRMED EVIDENCE\n");
        sb.append("- Raw byte scanning found networking/online-service markers in one or more ")
            .append("game-folder modules. These are confirmed byte/string markers only.\n");

        if (protection != null && protection.hasFindings()) {
            sb.append("- Protection/packing indicators were detected; see the protection scan.\n");
        }

        int moduleCount = 0;
        if (gameFolder != null && gameFolder.modules() != null) {
            for (GameModuleFinding module : gameFolder.modules()) {
                if (moduleCount++ >= 8) {
                    sb.append("- ... additional module candidates omitted ...\n");
                    break;
                }

                sb.append("- ")
                    .append(module.fileName())
                    .append(" score=")
                    .append(module.score())
                    .append("\n");

                if (module.evidenceHits() != null) {
                    int hitCount = 0;
                    for (GameEvidenceHit hit : module.evidenceHits()) {
                        if (hitCount++ >= 6) {
                            break;
                        }
                        sb.append("  - ").append(hit.toDisplayText()).append("\n");
                    }
                }
            }
        }

        sb.append("\nEVIDENCE-BACKED HYPOTHESES\n");
        sb.append("- NONE promoted to protocol/service/function conclusions yet. ")
            .append("Raw markers are not sufficient by themselves.\n");

        sb.append("\nUNKNOWN / NOT YET ESTABLISHED\n");
        sb.append("- Which functions consume the raw markers: UNKNOWN unless a GHIDRA_XREF_FUNCTION ")
            .append("hit is shown.\n");
        sb.append("- Network protocol and transport: UNKNOWN\n");
        sb.append("- Authentication mechanism: UNKNOWN\n");
        sb.append("- Matchmaking/session implementation: UNKNOWN\n");
        sb.append("- Actual server endpoints: UNKNOWN unless a concrete endpoint string is found.\n");

        sb.append("\nFUNCTIONS TO INVESTIGATE NEXT\n");
        sb.append("- No function is promoted solely because a raw marker maps inside its address range.\n");
        sb.append("- Prioritize markers with real Ghidra xrefs, then import the highest-ranked adjacent ")
            .append("DLLs for their own xref/decompiler analysis.\n");

        sb.append("\nNEXT PRESERVATION STEPS\n");
        sb.append("- Use mapped raw file offsets as navigation targets in the current EXE.\n");
        sb.append("- Improve targeted xref recovery around mapped markers if Ghidra has not created ")
            .append("references automatically.\n");
        sb.append("- If static xrefs remain absent, use the verified offline runtime-trace path.\n");

        return sb.toString().trim();
    }

    private String buildNoEvidenceSynthesis(
            Program program,
            ProtectionReport protection,
            NetworkReport network,
            GameFolderReport gameFolder) {

        StringBuilder sb = new StringBuilder();
        sb.append("CONFIRMED EVIDENCE\n");
        sb.append("- Static analysis did not identify a recognized network API, server endpoint, ")
            .append("hostname/IP, or preservation-relevant network function in this program.\n");

        if (protection != null && protection.hasFindings()) {
            sb.append("- Protection/packing indicators were detected; see the protection scan.\n");
        }

        sb.append("\nEVIDENCE-BACKED HYPOTHESES\n");
        sb.append("- NONE. There is not enough static evidence to infer the networking stack.\n");

        sb.append("\nUNKNOWN / NOT YET ESTABLISHED\n");
        sb.append("- Network protocol: UNKNOWN\n");
        sb.append("- Server discovery method: UNKNOWN\n");
        sb.append("- Authentication/login implementation: UNKNOWN\n");
        sb.append("- Matchmaking/lobby/session implementation: UNKNOWN\n");
        sb.append("- Real-time game networking implementation: UNKNOWN\n");
        sb.append("- Telemetry/update services: UNKNOWN\n");

        sb.append("\nFUNCTIONS TO INVESTIGATE NEXT\n");
        sb.append("- No function has yet been tied to networking by static evidence.\n");

        sb.append("\nNEXT PRESERVATION STEPS\n");
        if (gameFolder == null || !gameFolder.hasCandidates()) {
            sb.append("- No adjacent EXE/DLL module was strongly tied to networking by the raw folder scan.\n");
        }
        sb.append("- Import the strongest adjacent module candidates into Ghidra if the folder scan identifies any.\n");
        sb.append("- Look for dynamically resolved networking API names and loader paths.\n");
        sb.append("- If static evidence remains absent, use an offline-safe dynamic trace to observe ")
            .append("DNS/API/socket activity without allowing live service access.\n");

        if (network != null) {
            sb.append("- Current network scan inspected ")
                .append(network.externalSymbolsScanned())
                .append(" external symbols and ")
                .append(network.definedStringsScanned())
                .append(" defined strings.\n");
        }

        return sb.toString().trim();
    }

    private String buildFinalPrompt(
            Program program,
            ProtectionReport protection,
            NetworkReport network,
            GameFolderReport gameFolder,
            List<PreservationFunctionAssessment> assessments) {

        StringBuilder sb = new StringBuilder();
        sb.append("PROGRAM\n")
            .append(program.getName()).append('\n')
            .append(program.getExecutableFormat()).append('\n')
            .append(program.getLanguageID()).append("\n\n");

        sb.append("PROTECTION FINDINGS\n")
            .append(protection == null ? "<none>" : protection.toPromptText())
            .append("\n\n");

        sb.append("NETWORK FINDINGS\n")
            .append(network == null ? "<none>" : network.toPromptText())
            .append("\n\n");

        sb.append("GAME FOLDER MODULE FINDINGS\n")
            .append(gameFolder == null ? "<not scanned>" : gameFolder.toPromptText())
            .append("\n\n");

        sb.append("FUNCTION ASSESSMENTS\n");
        for (PreservationFunctionAssessment assessment : assessments) {
            sb.append("\n--- ")
                .append(assessment.functionName())
                .append('@')
                .append(assessment.entryPoint())
                .append(" score=")
                .append(assessment.priorityScore())
                .append(" ---\n")
                .append(assessment.aiSummary())
                .append('\n');
        }

        return sb.toString();
    }

    private static void update(Consumer<String> progress, String message) {
        if (progress != null) {
            progress.accept(message);
        }
    }

    private static String abbreviate(String value, int max) {
        String singleLine = value.replace('\r', ' ').replace('\n', ' ').trim();
        if (singleLine.length() <= max) {
            return singleLine;
        }
        return singleLine.substring(0, max) + "...";
    }

    private static class Candidate {
        private final Function function;
        private int score;
        private final LinkedHashSet<String> evidence = new LinkedHashSet<>();

        Candidate(Function function) {
            this.function = function;
        }

        Function function() {
            return function;
        }

        int score() {
            return score;
        }

        Set<String> evidence() {
            return evidence;
        }

        void addScore(int points) {
            score += Math.max(0, points);
        }

        void addEvidence(String value) {
            if (value != null && !value.isBlank() && evidence.size() < 12) {
                evidence.add(value);
            }
        }
    }
}
