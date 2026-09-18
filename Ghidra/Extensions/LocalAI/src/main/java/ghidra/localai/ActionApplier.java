package ghidra.localai;

import java.util.ArrayList;
import java.util.List;

import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;

public class ActionApplier {

    public List<String> apply(ContextSnapshot snapshot, List<AIAction> actions) {
        if (actions == null || actions.isEmpty()) {
            return List.of();
        }

        Program program = snapshot.program();
        if (program == null || program.isClosed()) {
            return List.of("AI edits skipped: the program is no longer open.");
        }
        if (!program.isChangeable()) {
            return List.of("AI edits skipped: the program is read-only.");
        }

        int tx;
        try {
            tx = program.startTransaction("LocalAI edits");
        }
        catch (Exception e) {
            return List.of("AI edits could not start a Ghidra transaction: " + e.getMessage());
        }

        boolean commit = false;
        List<String> applied = new ArrayList<>();

        try {
            for (AIAction action : actions) {
                switch (action.type()) {
                    case RENAME_FUNCTION -> {
                        Function function = requireFunction(program, snapshot);
                        String oldName = function.getName();
                        function.setName(action.value().trim(), SourceType.AI);
                        applied.add("Renamed function " + oldName + " -> " + function.getName());
                    }
                    case SET_FUNCTION_COMMENT -> {
                        Function function = requireFunction(program, snapshot);
                        function.setComment(action.value());
                        applied.add("Updated function comment at " + function.getEntryPoint());
                    }
                    case SET_EOL_COMMENT -> {
                        if (snapshot.cursorAddress() == null) {
                            throw new IllegalStateException(
                                "No cursor address was available for the EOL comment");
                        }
                        program.getListing().setComment(
                            snapshot.cursorAddress(),
                            CommentType.EOL,
                            action.value()
                        );
                        applied.add("Updated EOL comment at " + snapshot.cursorAddress());
                    }
                }
            }
            commit = true;
            return List.copyOf(applied);
        }
        catch (Exception e) {
            return List.of("AI edit failed; all requested edits were rolled back: " + e.getMessage());
        }
        finally {
            program.endTransaction(tx, commit);
        }
    }

    private static Function requireFunction(Program program, ContextSnapshot snapshot) {
        if (snapshot.functionEntry() == null) {
            throw new IllegalStateException("No current function was captured for this request");
        }

        Function function =
            program.getFunctionManager().getFunctionAt(snapshot.functionEntry());

        if (function == null) {
            throw new IllegalStateException(
                "The original current function no longer exists at " + snapshot.functionEntry());
        }
        return function;
    }
}
