package ghidra.localai;

public record OfflineTraceFirewallReport(
        boolean success,
        boolean enabled,
        String executablePath,
        String outboundRuleName,
        String inboundRuleName,
        String message) {

    public String toDisplayText() {
        StringBuilder sb = new StringBuilder();
        sb.append("OFFLINE TRACE FIREWALL\n");
        sb.append("Status: ").append(success ? "SUCCESS" : "FAILED").append('\n');
        sb.append("Rules enabled: ").append(enabled).append('\n');
        sb.append("Executable: ").append(executablePath == null ? "<unknown>" : executablePath)
            .append('\n');
        sb.append("Outbound rule: ").append(outboundRuleName == null ? "<none>" : outboundRuleName)
            .append('\n');
        sb.append("Inbound rule: ").append(inboundRuleName == null ? "<none>" : inboundRuleName)
            .append('\n');
        if (message != null && !message.isBlank()) {
            sb.append("Message: ").append(message);
        }
        return sb.toString();
    }
}
