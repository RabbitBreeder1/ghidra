package ghidra.localai;

import java.util.List;

public record GameFolderReport(
        String rootPath,
        List<GameModuleFinding> modules,
        int filesConsidered,
        long bytesScanned,
        boolean truncated,
        String note) {

    public static GameFolderReport notScanned() {
        return new GameFolderReport(
            "",
            List.of(),
            0,
            0,
            false,
            "Game folder scan has not been run for the current program."
        );
    }

    public static GameFolderReport unavailable(String note) {
        return new GameFolderReport("", List.of(), 0, 0, false, note);
    }

    public boolean hasCandidates() {
        return modules != null && !modules.isEmpty();
    }

    public String toDisplayText() {
        StringBuilder sb = new StringBuilder();
        sb.append("GAME FOLDER ANALYSIS\n");
        sb.append("Root: ").append(rootPath == null || rootPath.isBlank() ? "<unknown>" : rootPath)
            .append('\n');
        sb.append("Executable/DLL files considered: ").append(filesConsidered).append('\n');
        sb.append("Bytes scanned: ").append(bytesScanned);
        if (truncated) {
            sb.append(" (one or more large modules were sampled rather than fully scanned)");
        }
        sb.append("\n\n");

        if (!hasCandidates()) {
            sb.append("No neighboring module was strongly tied to networking/online services by the ")
                .append("raw static scan.\n");
        }
        else {
            sb.append("Ranked module candidates:\n");
            int count = 0;
            for (GameModuleFinding module : modules) {
                if (count++ >= 30) {
                    sb.append("- ... additional candidates omitted ...\n");
                    break;
                }
                sb.append("- ")
                    .append(module.fileName())
                    .append(" [score ")
                    .append(module.score())
                    .append("] ")
                    .append(module.relativePath())
                    .append('\n');

                if (module.evidenceHits() != null && !module.evidenceHits().isEmpty()) {
                    for (GameEvidenceHit hit : module.evidenceHits()) {
                        sb.append("  - ").append(hit.toDisplayText()).append('\n');
                    }
                }
                else {
                    sb.append("  Evidence: ")
                        .append(String.join("; ", module.evidence()))
                        .append('\n');
                }
            }
        }

        if (note != null && !note.isBlank()) {
            sb.append("\nNote: ").append(note);
        }

        return sb.toString();
    }

    public String toPromptText() {
        if (note != null && note.startsWith("Game folder scan has not")) {
            return "<not scanned>";
        }

        if (!hasCandidates()) {
            return "No adjacent EXE/DLL module was strongly associated with networking by the raw folder scan.";
        }

        StringBuilder sb = new StringBuilder();
        int count = 0;
        for (GameModuleFinding module : modules) {
            if (count++ >= 20) {
                sb.append("... additional modules omitted ...\n");
                break;
            }

            sb.append(module.fileName())
                .append(" | score=")
                .append(module.score())
                .append(" | ");

            if (module.evidenceHits() != null && !module.evidenceHits().isEmpty()) {
                int hitCount = 0;
                for (GameEvidenceHit hit : module.evidenceHits()) {
                    if (hitCount++ >= 8) {
                        sb.append("... more hits omitted ...");
                        break;
                    }
                    if (hitCount > 1) {
                        sb.append("; ");
                    }
                    sb.append(hit.toDisplayText());
                }
            }
            else {
                sb.append(String.join("; ", module.evidence()));
            }

            sb.append('\n');
        }
        return sb.toString().trim();
    }
}
