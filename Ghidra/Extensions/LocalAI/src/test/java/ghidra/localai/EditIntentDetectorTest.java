package ghidra.localai;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

public class EditIntentDetectorTest {

    private final EditIntentDetector detector = new EditIntentDetector();

    @Test
    public void renameRequiresExplicitRenameIntent() {
        AIAction action = new AIAction(AIAction.Type.RENAME_FUNCTION, "login_handler");

        assertTrue(detector.authorizes(
            "Rename the current function to login_handler.",
            action
        ));

        assertFalse(detector.authorizes(
            "What does the current function do?",
            action
        ));
    }

    @Test
    public void functionCommentRequiresFunctionCommentIntent() {
        AIAction action = new AIAction(
            AIAction.Type.SET_FUNCTION_COMMENT,
            "Handles login requests."
        );

        assertTrue(detector.authorizes(
            "Add a comment to this function explaining what it does.",
            action
        ));

        assertFalse(detector.authorizes(
            "Explain this function without changing anything.",
            action
        ));
    }

    @Test
    public void eolCommentRequiresCursorOrInstructionIntent() {
        AIAction action = new AIAction(
            AIAction.Type.SET_EOL_COMMENT,
            "Possible network call"
        );

        assertTrue(detector.authorizes(
            "Add an EOL comment at the current cursor saying possible network call.",
            action
        ));

        assertFalse(detector.authorizes(
            "Tell me whether this instruction looks network related.",
            action
        ));
    }
}
