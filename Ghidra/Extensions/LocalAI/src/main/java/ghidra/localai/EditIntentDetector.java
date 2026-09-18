package ghidra.localai;

import java.util.Locale;

public class EditIntentDetector {

    public boolean authorizes(String userPrompt, AIAction action) {
        if (userPrompt == null || userPrompt.isBlank() || action == null) {
            return false;
        }

        String prompt = normalize(userPrompt);

        return switch (action.type()) {
            case RENAME_FUNCTION -> authorizesRename(prompt);
            case SET_FUNCTION_COMMENT -> authorizesFunctionComment(prompt);
            case SET_EOL_COMMENT -> authorizesEolComment(prompt);
        };
    }

    private boolean authorizesRename(String prompt) {
        boolean renameVerb =
            containsAny(prompt, "rename", "re-name", "name this", "call this", "name the function");
        boolean functionTarget =
            containsAny(prompt, "function", "current function", "this function");

        return renameVerb && functionTarget;
    }

    private boolean authorizesFunctionComment(String prompt) {
        boolean commentVerb =
            containsAny(prompt, "comment", "document", "add a note", "write a note");
        boolean functionTarget =
            containsAny(prompt, "function", "current function", "this function", "function comment");

        return commentVerb && functionTarget;
    }

    private boolean authorizesEolComment(String prompt) {
        boolean commentVerb =
            containsAny(prompt, "comment", "add a note", "write a note");
        boolean locationTarget =
            containsAny(
                prompt,
                "eol",
                "end of line",
                "current line",
                "current cursor",
                "cursor",
                "this instruction",
                "current instruction"
            );

        return commentVerb && locationTarget;
    }

    private static boolean containsAny(String text, String... values) {
        for (String value : values) {
            if (text.contains(value)) {
                return true;
            }
        }
        return false;
    }

    private static String normalize(String value) {
        return value.toLowerCase(Locale.ROOT)
            .replaceAll("\\s+", " ")
            .trim();
    }
}
