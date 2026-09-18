package ghidra.localai;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class AIActionParser {
    private static final Pattern ACTION_PATTERN = Pattern.compile(
        "<GHIDRA_(RENAME_FUNCTION|SET_FUNCTION_COMMENT|SET_EOL_COMMENT)>(.*?)</GHIDRA_\\1>",
        Pattern.DOTALL
    );

    public ActionParseResult parse(String response) {
        if (response == null) {
            return new ActionParseResult("", List.of());
        }

        List<AIAction> actions = new ArrayList<>();
        Matcher matcher = ACTION_PATTERN.matcher(response);
        StringBuffer cleaned = new StringBuffer();

        while (matcher.find()) {
            String typeName = matcher.group(1);
            String value = matcher.group(2) == null ? "" : matcher.group(2).trim();

            if (!value.isEmpty()) {
                AIAction.Type type = switch (typeName) {
                    case "RENAME_FUNCTION" -> AIAction.Type.RENAME_FUNCTION;
                    case "SET_FUNCTION_COMMENT" -> AIAction.Type.SET_FUNCTION_COMMENT;
                    case "SET_EOL_COMMENT" -> AIAction.Type.SET_EOL_COMMENT;
                    default -> null;
                };
                if (type != null) {
                    actions.add(new AIAction(type, value));
                }
            }
            matcher.appendReplacement(cleaned, "");
        }

        matcher.appendTail(cleaned);
        return new ActionParseResult(cleaned.toString().trim(), List.copyOf(actions));
    }
}
