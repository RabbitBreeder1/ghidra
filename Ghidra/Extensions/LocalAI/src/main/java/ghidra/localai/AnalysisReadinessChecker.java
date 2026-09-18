package ghidra.localai;

import java.io.File;

import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.ExternalLocationIterator;

public class AnalysisReadinessChecker {

    public AnalysisReadinessReport check(Program program) {
        if (program == null || program.isClosed()) {
            return new AnalysisReadinessReport(
                false, false, 0, 0, 0, 0,
                "NOT READY",
                "Open an imported executable or DLL first."
            );
        }

        String executablePath = program.getExecutablePath();
        boolean pathResolved =
            executablePath != null && !executablePath.isBlank() &&
            new File(executablePath).isFile();

        int functionCount = program.getFunctionManager().getFunctionCount();
        int stringCount = countDefinedStrings(program);
        int libraryCount = 0;
        int externalSymbols = 0;

        for (String library : program.getExternalManager().getExternalLibraryNames()) {
            if (library == null) {
                continue;
            }
            libraryCount++;

            ExternalLocationIterator iterator =
                program.getExternalManager().getExternalLocations(library);
            while (iterator.hasNext()) {
                iterator.next();
                externalSymbols++;
            }
        }

        String assessment;
        String note;

        if (!pathResolved) {
            assessment = "PARTIAL";
            note = "Static Ghidra analysis is usable, but game-folder scanning and offline firewall " +
                "actions require a real executable path on disk.";
        }
        else if (functionCount == 0) {
            assessment = "TOO EARLY";
            note = "No functions have been discovered yet. Let entry-point/function analysis run " +
                "before expecting useful xref/function mapping.";
        }
        else if (functionCount < 20 && stringCount < 20 && externalSymbols < 10) {
            assessment = "PARTIAL";
            note = "Very little program structure is currently available. Static scans can run, " +
                "but function/xref results may be incomplete.";
        }
        else {
            assessment = "READY FOR PRESERVATION SCAN";
            note = "Enough structure exists for the bounded preservation workflow. Full Ghidra " +
                "auto-analysis is not required before running it.";
        }

        return new AnalysisReadinessReport(
            true,
            pathResolved,
            functionCount,
            stringCount,
            externalSymbols,
            libraryCount,
            assessment,
            note
        );
    }

    private int countDefinedStrings(Program program) {
        int count = 0;
        DataIterator iterator = program.getListing().getDefinedData(true);
        while (iterator.hasNext()) {
            Data data = iterator.next();
            if (data.hasStringValue()) {
                count++;
            }
        }
        return count;
    }
}
