package ghidra.localai;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompiledFunction;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.util.task.TaskMonitor;

public class ContextCollector {
    private static final int DECOMPILE_TIMEOUT_SECONDS = 20;
    private static final int MAX_DECOMPILED_CHARS = 24000;

    private final PluginTool tool;

    public ContextCollector(PluginTool tool) {
        this.tool = tool;
    }

    public ContextSnapshot collect(
            Program program,
            ProgramLocation location,
            ProtectionReport protectionReport,
            NetworkReport networkReport,
            PreservationAnalysisReport preservationReport) {

        String protectionText = protectionReport == null
            ? "<not scanned>"
            : protectionReport.toPromptText();

        String networkText = networkReport == null
            ? "<not scanned>"
            : networkReport.toPromptText();

        String preservationText = preservationReport == null
            ? "<not run>"
            : preservationReport.toPromptText();

        if (program == null || program.isClosed()) {
            return new ContextSnapshot(
                null, null, null, "<no active program>", "", "", "", "", "", "", "",
                protectionText, networkText, preservationText
            );
        }

        Address cursor = location == null ? null : location.getAddress();
        Function function = cursor == null ? null :
            program.getFunctionManager().getFunctionContaining(cursor);

        String functionName = "";
        String prototype = "";
        String functionComment = "";
        Address functionEntry = null;
        String decompiled = "";

        if (function != null) {
            functionEntry = function.getEntryPoint();
            functionName = function.getName();
            prototype = function.getPrototypeString(false, true);
            functionComment = function.getComment();
            decompiled = decompile(program, function);
        }

        String cursorComment = "";
        if (cursor != null) {
            cursorComment = program.getListing().getComment(CommentType.EOL, cursor);
        }

        return new ContextSnapshot(
            program,
            functionEntry,
            cursor,
            program.getName(),
            program.getExecutableFormat(),
            program.getLanguageID().getIdAsString(),
            functionName,
            prototype,
            functionComment,
            cursorComment,
            decompiled,
            protectionText,
            networkText,
            preservationText
        );
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
                return "<decompiler returned no C output>";
            }

            String code = output.getC();
            if (code.length() > MAX_DECOMPILED_CHARS) {
                return code.substring(0, MAX_DECOMPILED_CHARS) +
                    "\n/* ... LocalAI context truncated ... */";
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
}
