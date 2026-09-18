package ghidra.localai;

import java.util.List;

public record ActionParseResult(String displayText, List<AIAction> actions) {
}
