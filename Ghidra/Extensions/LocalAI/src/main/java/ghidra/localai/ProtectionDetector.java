package ghidra.localai;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;

public class ProtectionDetector {
    private static final int MAX_DEFINED_STRINGS = 100_000;

    private final Map<String, FindingBuilder> findings = new LinkedHashMap<>();

    public ProtectionReport scan(Program program) {
        findings.clear();

        if (program == null || program.isClosed()) {
            return ProtectionReport.noProgram();
        }

        scanLibraries(program);
        scanMemoryBlocks(program);
        ScanCount count = scanDefinedStrings(program);

        List<ProtectionFinding> output = new ArrayList<>();
        for (FindingBuilder builder : findings.values()) {
            output.add(builder.build());
        }

        String note =
            "Heuristic static detection only. A hit can indicate platform SDK/protection integration " +
            "without proving DRM is actively enforced, and no hit does not prove the executable is unprotected.";

        return new ProtectionReport(
            List.copyOf(output),
            count.scanned(),
            count.truncated(),
            note
        );
    }

    private void scanLibraries(Program program) {
        for (String library : program.getExternalManager().getExternalLibraryNames()) {
            if (library == null) {
                continue;
            }

            String value = library.toLowerCase(Locale.ROOT);

            if (value.contains("steam_api64") || value.contains("steam_api.dll")) {
                add("Steamworks / possible Steam DRM", "Platform/DRM indicator", "MEDIUM",
                    "Imported library: " + library);
            }
            if (value.contains("denuvo")) {
                add("Denuvo", "Anti-tamper / DRM", "HIGH",
                    "Imported library: " + library);
            }
            if (value.contains("vmprotect")) {
                add("VMProtect", "Software protector", "HIGH",
                    "Imported library: " + library);
            }
            if (value.contains("themida") || value.contains("winlicense")) {
                add("Themida / WinLicense", "Software protector / licensing", "HIGH",
                    "Imported library: " + library);
            }
            if (value.contains("arxan")) {
                add("Arxan", "Anti-tamper protection", "HIGH",
                    "Imported library: " + library);
            }
            if (value.contains("uplay_r1_loader") || value.contains("upc_r2_loader")) {
                add("Ubisoft Connect / Uplay", "Platform/DRM indicator", "MEDIUM",
                    "Imported library: " + library);
            }
            if (value.contains("secdrv")) {
                add("SafeDisc", "Legacy DRM", "HIGH",
                    "Imported library: " + library);
            }
        }
    }

    private void scanMemoryBlocks(Program program) {
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            String name = block.getName();
            if (name == null) {
                continue;
            }

            String value = name.toLowerCase(Locale.ROOT);

            if (value.equals(".vmp0") || value.equals(".vmp1") ||
                value.startsWith(".vmp")) {
                add("VMProtect", "Software protector", "HIGH",
                    "Memory section: " + name);
            }
            if (value.contains("themida") || value.contains("winlicense")) {
                add("Themida / WinLicense", "Software protector / licensing", "HIGH",
                    "Memory section: " + name);
            }
            if (value.startsWith("upx")) {
                add("UPX", "Executable packer (not DRM by itself)", "HIGH",
                    "Memory section: " + name);
            }
        }
    }

    private ScanCount scanDefinedStrings(Program program) {
        DataIterator iterator = program.getListing().getDefinedData(true);
        int scanned = 0;
        boolean truncated = false;

        while (iterator.hasNext()) {
            Data data = iterator.next();
            if (!data.hasStringValue()) {
                continue;
            }

            if (scanned >= MAX_DEFINED_STRINGS) {
                truncated = true;
                break;
            }

            scanned++;
            Object raw = data.getValue();
            if (!(raw instanceof String text) || text.isBlank()) {
                continue;
            }

            scanString(text, data.getAddress().toString());
        }

        return new ScanCount(scanned, truncated);
    }

    private void scanString(String text, String address) {
        String value = text.toLowerCase(Locale.ROOT);
        String evidence = "String @" + address + ": " + abbreviate(text, 120);

        if (value.contains("denuvo anti-tamper") || value.contains("denuvo")) {
            add("Denuvo", "Anti-tamper / DRM", "HIGH", evidence);
        }

        if (value.contains("steamstub")) {
            add("SteamStub", "Steam DRM wrapper", "HIGH", evidence);
        }
        else if (value.contains("steamapi_init") ||
                 value.contains("steamapi_restartappifnecessary") ||
                 value.contains("steam_api64.dll") ||
                 value.contains("steam_api.dll")) {
            add("Steamworks / possible Steam DRM", "Platform/DRM indicator", "MEDIUM", evidence);
        }

        if (value.contains("vmprotect")) {
            add("VMProtect", "Software protector", "HIGH", evidence);
        }

        if (value.contains("themida") ||
            value.contains("winlicense") ||
            value.contains("secureengine")) {
            add("Themida / WinLicense", "Software protector / licensing", "HIGH", evidence);
        }

        if (value.contains("arxan") || value.contains("arxanguard")) {
            add("Arxan", "Anti-tamper protection", "HIGH", evidence);
        }

        if (value.contains("securom")) {
            add("SecuROM", "Legacy DRM", "HIGH", evidence);
        }

        if (value.contains("safedisc") || value.contains("secdrv.sys")) {
            add("SafeDisc", "Legacy DRM", "HIGH", evidence);
        }

        if (value.contains("starforce")) {
            add("StarForce", "Legacy DRM / copy protection", "HIGH", evidence);
        }

        if (value.contains("uplay_r1_loader") ||
            value.contains("upc_r2_loader") ||
            value.contains("ubisoft connect")) {
            add("Ubisoft Connect / Uplay", "Platform/DRM indicator", "MEDIUM", evidence);
        }
    }

    private void add(String technology, String category, String confidence, String evidence) {
        FindingBuilder existing = findings.get(technology);
        if (existing == null) {
            findings.put(
                technology,
                new FindingBuilder(technology, category, confidence, evidence)
            );
            return;
        }

        existing.addEvidence(evidence);
        existing.raiseConfidence(confidence);
    }

    private static int confidenceRank(String confidence) {
        return switch (confidence) {
            case "HIGH" -> 3;
            case "MEDIUM" -> 2;
            default -> 1;
        };
    }

    private static String abbreviate(String value, int max) {
        String singleLine = value.replace('\r', ' ').replace('\n', ' ').trim();
        if (singleLine.length() <= max) {
            return singleLine;
        }
        return singleLine.substring(0, max) + "...";
    }

    private record ScanCount(int scanned, boolean truncated) {
    }

    private static class FindingBuilder {
        private final String technology;
        private final String category;
        private String confidence;
        private final List<String> evidence = new ArrayList<>();

        FindingBuilder(String technology, String category, String confidence, String firstEvidence) {
            this.technology = technology;
            this.category = category;
            this.confidence = confidence;
            addEvidence(firstEvidence);
        }

        void addEvidence(String value) {
            if (value == null || value.isBlank() || evidence.contains(value)) {
                return;
            }
            if (evidence.size() < 4) {
                evidence.add(value);
            }
        }

        void raiseConfidence(String candidate) {
            if (confidenceRank(candidate) > confidenceRank(confidence)) {
                confidence = candidate;
            }
        }

        ProtectionFinding build() {
            return new ProtectionFinding(
                technology,
                category,
                confidence,
                String.join("; ", evidence)
            );
        }
    }
}
