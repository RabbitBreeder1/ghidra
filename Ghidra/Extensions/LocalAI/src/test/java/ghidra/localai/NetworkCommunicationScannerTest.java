package ghidra.localai;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import org.junit.Test;

public class NetworkCommunicationScannerTest {

    @Test
    public void classifiesWinsock() {
        assertEquals(
            "Winsock / raw sockets",
            NetworkCommunicationScanner.classifyNetworkApi("WS2_32.dll", "connect")
        );
    }

    @Test
    public void classifiesWinHttp() {
        assertEquals(
            "WinHTTP / HTTP(S)",
            NetworkCommunicationScanner.classifyNetworkApi("WINHTTP.dll", "WinHttpSendRequest")
        );
    }

    @Test
    public void classifiesCurl() {
        assertEquals(
            "libcurl / HTTP(S)",
            NetworkCommunicationScanner.classifyNetworkApi("libcurl.dll", "curl_easy_perform")
        );
    }

    @Test
    public void ignoresUnrelatedSymbol() {
        assertNull(
            NetworkCommunicationScanner.classifyNetworkApi("KERNEL32.dll", "CreateFileW")
        );
    }
}
