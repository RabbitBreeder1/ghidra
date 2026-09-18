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
    private static final String DEFAULT_MODEL = "qwen2.5-coder:7b";

    private final LocalAIPlugin plugin;
    private final OllamaClient ollamaClient = new OllamaClient();
    private final AIActionParser actionParser = new AIActionParser();
    private final ActionApplier actionApplier = new ActionApplier();
    private final List<ChatMessage> history = new ArrayList<>();

    private JPanel mainPanel;
    private JTextArea transcript;
    private JTextArea input;
    private JTextField urlField;
    private JTextField modelField;
    private JCheckBox allowEdits;
    private JLabel statusLabel;
    private JLabel contextLabel;
    private JButton sendButton;
    private JButton checkButton;
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

        JPanel settings = new JPanel(new GridLayout(4, 2, 5, 4));
        urlField = new JTextField(DEFAULT_URL);
        modelField = new JTextField(DEFAULT_MODEL);
        allowEdits = new JCheckBox("Allow AI edits (undoable)", true);
        checkButton = new JButton("Check Ollama");

        settings.add(new JLabel("Ollama URL (loopback only)"));
        settings.add(urlField);
        settings.add(new JLabel("Model"));
        settings.add(modelField);
        settings.add(allowEdits);
        settings.add(checkButton);

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
            "LocalAI ready. Open a program, place the cursor inside a function, and ask about it. " +
            "The current decompiled function is attached to every request."
        );
    }

    private void checkOllama() {
        if (busy) {
            return;
        }

        setBusy(true);
        statusLabel.setText("Status: checking...");
        String url = urlField.getText();

        CompletableFuture.supplyAsync(() -> {
            try {
                return ollamaClient.check(url);
            }
            catch (Exception e) {
                throw new RuntimeException(e);
            }
        }).whenComplete((result, error) -> SwingUtilities.invokeLater(() -> {
            setBusy(false);
            if (error != null) {
                statusLabel.setText("Status: failed");
                appendSystem("Ollama check failed: " + rootMessage(error));
            }
            else {
                statusLabel.setText("Status: connected");
                appendSystem(result + " at " + url);
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

                List<String> results =
                    actionApplier.apply(pending.snapshot(), parsed.actions());
                for (String result : results) {
                    appendSystem(result);
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
