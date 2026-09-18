package ghidra.localai;

import java.util.List;

public record GameModuleFinding(
        String fileName,
        String relativePath,
        long fileSize,
        int score,
        List<String> evidence,
        List<GameEvidenceHit> evidenceHits) {
}
