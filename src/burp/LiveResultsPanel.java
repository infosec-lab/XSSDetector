package burp;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
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

    public LiveResultsPanel(FindingStore store, IBurpExtenderCallbacks callbacks) {
        super(new BorderLayout(8, 8));
        this.store = store;
        this.callbacks = callbacks;
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
        table.getSelectionModel().setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
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
        menu.add(toRepeater);
        menu.add(copyUrl);
        menu.add(copyPoc);

        table.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override public void mousePressed(java.awt.event.MouseEvent e) { maybeShow(e); }
            @Override public void mouseReleased(java.awt.event.MouseEvent e) { maybeShow(e); }
            private void maybeShow(java.awt.event.MouseEvent e) {
                if (e.isPopupTrigger()) {
                    int row = table.rowAtPoint(e.getPoint());
                    if (row >= 0) {
                        table.setRowSelectionInterval(row, row);
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

    // ---- table model ----

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
