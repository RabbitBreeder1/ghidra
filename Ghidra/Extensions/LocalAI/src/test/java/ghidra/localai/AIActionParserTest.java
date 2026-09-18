package ghidra.localai;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

public class AIActionParserTest {

    @Test
    public void parsesAndStripsMultipleActions() {
        String response = """
This looks like a checksum helper.

<GHIDRA_RENAME_FUNCTION>calculate_checksum</GHIDRA_RENAME_FUNCTION>
<GHIDRA_SET_FUNCTION_COMMENT>Calculates a small integer checksum.</GHIDRA_SET_FUNCTION_COMMENT>
""";

        ActionParseResult result = new AIActionParser().parse(response);

        assertEquals("This looks like a checksum helper.", result.displayText());
        assertEquals(2, result.actions().size());
        assertEquals(AIAction.Type.RENAME_FUNCTION, result.actions().get(0).type());
        assertEquals("calculate_checksum", result.actions().get(0).value());
        assertEquals(AIAction.Type.SET_FUNCTION_COMMENT, result.actions().get(1).type());
    }

    @Test
    public void leavesNormalChatUntouched() {
        ActionParseResult result = new AIActionParser().parse("No edit requested.");

        assertEquals("No edit requested.", result.displayText());
        assertEquals(0, result.actions().size());
    }
}
