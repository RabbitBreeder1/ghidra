package ghidra.localai;

import java.awt.BorderLayout;
import java.awt.GridLayout;
import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;

import javax.swing.AbstractAction;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.KeyStroke;
import javax.swing.SwingUtilities;

import docking.WindowPosition;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;

public class LocalAIProvider extends ComponentProviderAdapter {
    private static final String DEFAULT_URL = "http://127.0.0.1:11434";
    private static final String DEFAULT_MODEL = "qwen3-coder:30b";

    private final LocalAIPlugin plugin;
    private final OllamaClient ollamaClient = new OllamaClient();
    private final AIActionParser actionParser = new AIActionParser();
    private final EditIntentDetector editIntentDetector = new EditIntentDetector();
    private final ActionApplier actionApplier = new ActionApplier();
    private final List<ChatMessage> history = new ArrayList<>();

    private JPanel mainPanel;
    private JTextArea transcript;
    private JTextArea input;
    private JTextField urlField;
    private JTextField modelField;
    private JCheckBox allowEdits;
    private JLabel buildLabel;
    private JLabel statusLabel;
    private JLabel contextLabel;
    private JButton sendButton;
    private JButton checkButton;
    private JButton protectionScanButton;
    private JButton networkScanButton;
    private JButton gameFolderScanButton;
    private JButton offlineBlockEnableButton;
    private JButton offlineBlockRemoveButton;
    private JButton preservationAnalysisButton;
    private JButton clearButton;
    private volatile boolean busy;

    public LocalAIProvider(PluginTool tool, String owner, LocalAIPlugin plugin) {
        super(tool, "Local AI", owner);
        this.plugin = plugin;

        buildUi();
        setTitle("Local AI");
        setDefaultWindowPosition(WindowPosition.WINDOW);
        setVisible(true);
    }

    @Override
    public JComponent getComponent() {
        return mainPanel;
    }

    public void updateContextSummary(Program program, ProgramLocation location) {
        SwingUtilities.invokeLater(() -> {
            if (program == null || program.isClosed()) {
                contextLabel.setText("Context: no active program");
                return;
            }

            Address address = location == null ? null : location.getAddress();
            Function function = address == null ? null :
                program.getFunctionManager().getFunctionContaining(address);

            String functionText = function == null ? "<no function>" : function.getName();
            contextLabel.setText(
                "Context: " + program.getName() + " | " +
                (address == null ? "<no address>" : address.toString()) + " | " +
                functionText
            );
        });
    }

    private void buildUi() {
        mainPanel = new JPanel(new BorderLayout(6, 6));
        mainPanel.setBorder(BorderFactory.createEmptyBorder(6, 6, 6, 6));

        JPanel settings = new JPanel(new GridLayout(11, 2, 5, 4));
        buildLabel = new JLabel(LocalAIBuildInfo.BUILD_ID);
        urlField = new JTextField(DEFAULT_URL);
        modelField = new JTextField(DEFAULT_MODEL);
        allowEdits = new JCheckBox("Allow AI edits (undoable)", true);
        checkButton = new JButton("Check Ollama");
        protectionScanButton = new JButton("DRM / Protector Scan");
        networkScanButton = new JButton("Network / Server Scan");
        gameFolderScanButton = new JButton("Analyze Game Folder");
        offlineBlockEnableButton = new JButton("Enable Safe Offline Block (Folder)");
        offlineBlockRemoveButton = new JButton("Remove Safe Offline Block");
        preservationAnalysisButton = new JButton("Safe Preservation Workflow");

        settings.add(new JLabel("LocalAI build"));
        settings.add(buildLabel);
        settings.add(new JLabel("Ollama URL (loopback only)"));
        settings.add(urlField);
        settings.add(new JLabel("Model"));
        settings.add(modelField);
        settings.add(allowEdits);
        settings.add(checkButton);
        settings.add(new JLabel("Static protection check"));
        settings.add(protectionScanButton);
        settings.add(new JLabel("Game preservation"));
        settings.add(networkScanButton);
        settings.add(new JLabel("Adjacent modules"));
        settings.add(gameFolderScanButton);
        settings.add(new JLabel("Dynamic-trace safety"));
        settings.add(offlineBlockEnableButton);
        settings.add(new JLabel("Dynamic-trace cleanup"));
        settings.add(offlineBlockRemoveButton);
        settings.add(new JLabel("One-button workflow"));
        settings.add(preservationAnalysisButton);

        statusLabel = new JLabel("Status: not checked");
        contextLabel = new JLabel("Context: no active program");
        settings.add(statusLabel);
        settings.add(contextLabel);

        transcript = new JTextArea();
        transcript.setEditable(false);
        transcript.setLineWrap(true);
        transcript.setWrapStyleWord(true);

        input = new JTextArea(5, 40);
        input.setLineWrap(true);
        input.setWrapStyleWord(true);

        JScrollPane transcriptScroll = new JScrollPane(transcript);
        JScrollPane inputScroll = new JScrollPane(input);

        JSplitPane split = new JSplitPane(
            JSplitPane.VERTICAL_SPLIT,
            transcriptScroll,
            inputScroll
        );
        split.setResizeWeight(0.8);

        JPanel buttons = new JPanel(new GridLayout(1, 2, 5, 0));
        sendButton = new JButton("Send (Ctrl+Enter)");
        clearButton = new JButton("Clear Chat");
        buttons.add(sendButton);
        buttons.add(clearButton);

        mainPanel.add(settings, BorderLayout.NORTH);
        mainPanel.add(split, BorderLayout.CENTER);
        mainPanel.add(buttons, BorderLayout.SOUTH);

        sendButton.addActionListener(e -> send());
        clearButton.addActionListener(e -> clearChat());
        checkButton.addActionListener(e -> checkOllama());
        protectionScanButton.addActionListener(e -> scanProtection());
        networkScanButton.addActionListener(e -> scanNetworkCommunication());
        gameFolderScanButton.addActionListener(e -> scanGameFolder());
        offlineBlockEnableButton.addActionListener(e -> enableOfflineTraceBlock());
        offlineBlockRemoveButton.addActionListener(e -> removeOfflineTraceBlock());
        preservationAnalysisButton.addActionListener(e -> runPreservationAnalysis());

        input.getInputMap().put(
            KeyStroke.getKeyStroke(KeyEvent.VK_ENTER, InputEvent.CTRL_DOWN_MASK),
            "localai-send"
        );
        input.getActionMap().put("localai-send", new AbstractAction() {
            @Override
            public void actionPerformed(java.awt.event.ActionEvent e) {
                send();
            }
        });

        appendSystem(
            "LocalAI " + LocalAIBuildInfo.BUILD_ID + " ready. Static preservation actions never " +
            "execute the target. Open a program and use Safe Preservation Workflow for the guided path.\n" +
            "Loaded from: " + LocalAIBuildInfo.loadedFrom()
        );
    }

    private void checkOllama() {
        if (busy) {
            return;
        }

        setBusy(true);
        statusLabel.setText("Status: checking...");
        String url = urlField.getText();

        String model = modelField.getText().trim();

        CompletableFuture.supplyAsync(() -> {
            try {
                String server = ollamaClient.check(url);
                String modelResult = ollamaClient.checkModel(url, model);
                return server + " at " + url + "\n" + modelResult;
            }
            catch (Exception e) {
                throw new RuntimeException(e);
            }
        }).whenComplete((result, error) -> SwingUtilities.invokeLater(() -> {
            setBusy(false);
            if (error != null) {
                statusLabel.setText("Status: failed");
                appendSystem("Ollama/model check failed: " + rootMessage(error));
            }
            else {
                statusLabel.setText("Status: connected");
                appendSystem(result);
            }
        }));
    }

    private void scanProtection() {
        if (busy) {
            return;
        }

        setBusy(true);
        statusLabel.setText("Status: scanning DRM/protectors...");

        CompletableFuture.supplyAsync(plugin::scanProtection)
            .whenComplete((report, error) -> SwingUtilities.invokeLater(() -> {
                setBusy(false);

                if (error != null) {
                    statusLabel.setText("Status: DRM scan failed");
                    appendSystem("DRM/protector scan failed: " + rootMessage(error));
                    return;
                }

                statusLabel.setText("Status: DRM scan complete");
                appendSystem(report.toDisplayText());
            }));
    }

    private void scanNetworkCommunication() {
        if (busy) {
            return;
        }

        setBusy(true);
        statusLabel.setText("Status: scanning network/server communication...");

        CompletableFuture.supplyAsync(plugin::scanNetworkCommunication)
            .whenComplete((report, error) -> SwingUtilities.invokeLater(() -> {
                setBusy(false);

                if (error != null) {
                    statusLabel.setText("Status: network scan failed");
                    appendSystem("Network/server scan failed: " + rootMessage(error));
                    return;
                }

                statusLabel.setText("Status: network scan complete");
                appendSystem(report.toDisplayText());
            }));
    }

    private void scanGameFolder() {
        if (busy) {
            return;
        }

        setBusy(true);
        statusLabel.setText("Status: scanning game folder...");

        CompletableFuture.supplyAsync(() ->
            plugin.scanGameFolder(
                message -> SwingUtilities.invokeLater(
                    () -> statusLabel.setText("Status: " + message)
                )
            )
        ).whenComplete((report, error) -> SwingUtilities.invokeLater(() -> {
            setBusy(false);

            if (error != null) {
                statusLabel.setText("Status: game folder scan failed");
                appendSystem("Game folder scan failed: " + rootMessage(error));
                return;
            }

            statusLabel.setText("Status: game folder scan complete");
            appendSystem(report.toDisplayText());
        }));
    }

    private void enableOfflineTraceBlock() {
        if (busy) {
            return;
        }

        int choice = JOptionPane.showConfirmDialog(
            mainPanel,
            "This will request administrator permission and create verified inbound/outbound Windows " +
            "Firewall BLOCK rules for every EXE found under the loaded game's folder (bounded " +
            "recursive scan).\n\nIt does NOT launch the game. Continue?",
            "Enable Safe Offline Game-Folder Block",
            JOptionPane.YES_NO_OPTION,
            JOptionPane.WARNING_MESSAGE
        );

        if (choice != JOptionPane.YES_OPTION) {
            return;
        }

        changeOfflineTraceBlock(true);
    }

    private void removeOfflineTraceBlock() {
        if (busy) {
            return;
        }
        changeOfflineTraceBlock(false);
    }

    private void changeOfflineTraceBlock(boolean enable) {
        setBusy(true);
        statusLabel.setText(
            enable
                ? "Status: enabling offline trace firewall block..."
                : "Status: removing offline trace firewall block..."
        );

        CompletableFuture.supplyAsync(() ->
            enable
                ? plugin.enableOfflineTraceFirewall()
                : plugin.disableOfflineTraceFirewall()
        ).whenComplete((report, error) -> SwingUtilities.invokeLater(() -> {
            setBusy(false);

            if (error != null) {
                statusLabel.setText("Status: offline trace firewall action failed");
                appendSystem("Offline trace firewall action failed: " + rootMessage(error));
                return;
            }

            statusLabel.setText(
                report.success()
                    ? (enable
                        ? "Status: offline trace network block enabled"
                        : "Status: offline trace network block removed")
                    : "Status: offline trace firewall action failed"
            );
            appendSystem(report.toDisplayText());
        }));
    }

    private void runPreservationAnalysis() {
        if (busy) {
            return;
        }

        String url = urlField.getText().trim();
        String model = modelField.getText().trim();
        if (model.isEmpty()) {
            appendSystem("Enter an Ollama model name first.");
            return;
        }

        setBusy(true);
        statusLabel.setText("Status: starting safe preservation workflow...");
        appendSystem(
            "Starting Safe Preservation Workflow. This static workflow does NOT execute the target. " +
            "It will check analysis readiness, verify local Ollama, scan adjacent modules, run " +
            "protection/network discovery, map raw hits into Ghidra where possible, and review only " +
            "the strongest preservation-relevant functions."
        );

        CompletableFuture.supplyAsync(() -> {
            try {
                return plugin.runSafePreservationWorkflow(
                    ollamaClient,
                    url,
                    model,
                    message -> SwingUtilities.invokeLater(
                        () -> statusLabel.setText("Status: " + message)
                    )
                );
            }
            catch (Exception e) {
                throw new RuntimeException(e);
            }
        }).whenComplete((result, error) -> SwingUtilities.invokeLater(() -> {
            setBusy(false);

            if (error != null) {
                statusLabel.setText("Status: safe preservation workflow failed");
                appendSystem("Safe preservation workflow failed: " + rootMessage(error));
                return;
            }

            statusLabel.setText("Status: safe preservation workflow complete");
            appendSystem(result.toDisplayText());

            PreservationAnalysisReport report = result.preservation();
            if (report != null) {
                String summary = report.synthesis();
                if (summary != null && !summary.isBlank()) {
                    history.add(new ChatMessage(
                        "assistant",
                        "Preservation analysis result:\n" + summary.trim()
                    ));
                }
            }
        }));
    }

    private void send() {
        String prompt = input.getText().trim();
        if (prompt.isEmpty() || busy) {
            return;
        }

        String url = urlField.getText().trim();
        String model = modelField.getText().trim();
        if (model.isEmpty()) {
            appendSystem("Enter an Ollama model name first.");
            return;
        }

        input.setText("");
        appendUser(prompt);
        history.add(new ChatMessage("user", prompt));
        List<ChatMessage> requestHistory = List.copyOf(history);

        setBusy(true);
        statusLabel.setText("Status: thinking...");

        CompletableFuture.supplyAsync(() -> {
            try {
                ContextSnapshot snapshot = plugin.collectCurrentContext();
                String response =
                    ollamaClient.chat(url, model, requestHistory, snapshot);
                return new PendingResponse(snapshot, response);
            }
            catch (Exception e) {
                throw new RuntimeException(e);
            }
        }).whenComplete((pending, error) -> SwingUtilities.invokeLater(() -> {
            setBusy(false);

            if (error != null) {
                statusLabel.setText("Status: error");
                appendSystem("AI request failed: " + rootMessage(error));
                return;
            }

            statusLabel.setText("Status: connected");
            ActionParseResult parsed = actionParser.parse(pending.response());
            String visible = parsed.displayText().isBlank()
                ? "(AI requested one or more Ghidra edits.)"
                : parsed.displayText();

            appendAssistant(visible);
            history.add(new ChatMessage("assistant", visible));

            if (!parsed.actions().isEmpty()) {
                if (!allowEdits.isSelected()) {
                    appendSystem(
                        "AI requested " + parsed.actions().size() +
                        " edit(s), but 'Allow AI edits' is disabled."
                    );
                    return;
                }

                List<AIAction> authorized = new ArrayList<>();
                for (AIAction action : parsed.actions()) {
                    if (editIntentDetector.authorizes(prompt, action)) {
                        authorized.add(action);
                    }
                    else {
                        appendSystem(
                            "Ignored unauthorized AI edit request: " + action.type() +
                            ". Your prompt did not explicitly authorize that edit type."
                        );
                    }
                }

                if (!authorized.isEmpty()) {
                    List<String> results =
                        actionApplier.apply(pending.snapshot(), authorized);
                    for (String result : results) {
                        appendSystem(result);
                    }
                }
            }
        }));
    }

    private void clearChat() {
        history.clear();
        transcript.setText("");
        appendSystem("Chat history cleared. Ghidra program edits were not reverted.");
    }

    private void setBusy(boolean value) {
        busy = value;
        sendButton.setEnabled(!value);
        checkButton.setEnabled(!value);
        protectionScanButton.setEnabled(!value);
        networkScanButton.setEnabled(!value);
        gameFolderScanButton.setEnabled(!value);
        offlineBlockEnableButton.setEnabled(!value);
        offlineBlockRemoveButton.setEnabled(!value);
        preservationAnalysisButton.setEnabled(!value);
    }

    private void appendUser(String text) {
        append("You", text);
    }

    private void appendAssistant(String text) {
        append("AI", text);
    }

    private void appendSystem(String text) {
        append("LocalAI", text);
    }

    private void append(String speaker, String text) {
        transcript.append(speaker + ":\n" + text + "\n\n");
        transcript.setCaretPosition(transcript.getDocument().getLength());
    }

    private static String rootMessage(Throwable error) {
        Throwable current = error;
        while (current.getCause() != null) {
            current = current.getCause();
        }
        String message = current.getMessage();
        return message == null || message.isBlank()
            ? current.getClass().getSimpleName()
            : message;
    }

    private record PendingResponse(ContextSnapshot snapshot, String response) {
    }
}
