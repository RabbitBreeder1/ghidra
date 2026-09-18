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

    @Test
    public void rejectsMicrosoftSchemaNamespaceUrl() {
        String xml = "<?xml version=\"1.0\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\">" +
            "<windowsSettings xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">";

        org.junit.Assert.assertFalse(
            NetworkCommunicationScanner.isUsefulUrl(
                "http://schemas.microsoft.com/SMI/2005/WindowsSettings",
                xml
            )
        );
    }

    @Test
    public void rejectsSchemaDomain() {
        org.junit.Assert.assertFalse(
            NetworkCommunicationScanner.isUsefulDomain("schemas.microsoft.com")
        );
    }

    @Test
    public void keepsNormalGameEndpoint() {
        org.junit.Assert.assertTrue(
            NetworkCommunicationScanner.isUsefulUrl(
                "https://auth.examplegame.com/v2/login",
                "https://auth.examplegame.com/v2/login"
            )
        );
    }
}
