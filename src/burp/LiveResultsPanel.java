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

    private final JTextArea requestView = new JTextArea();
    private final JTextArea responseView = new JTextArea();
    private final JLabel pocBar = new JLabel(" ");

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
        table.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
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

        requestView.setEditable(false);
        responseView.setEditable(false);
        Font mono = new Font(Font.MONOSPACED, Font.PLAIN, 12);
        requestView.setFont(mono);
        responseView.setFont(mono);
        requestView.setLineWrap(true);
        responseView.setLineWrap(true);

        JTabbedPane viewer = new JTabbedPane();
        viewer.addTab("Request", new JScrollPane(requestView));
        viewer.addTab("Response", new JScrollPane(responseView));

        // PoC / location bar: the exploit payload and where it landed.
        pocBar.setBorder(BorderFactory.createEmptyBorder(2, 4, 4, 4));
        pocBar.setFont(pocBar.getFont().deriveFont(Font.PLAIN));

        JPanel viewerPanel = new JPanel(new BorderLayout());
        viewerPanel.setBorder(BorderFactory.createTitledBorder("Selected finding - PoC highlighted in Request & Response"));
        viewerPanel.add(pocBar, BorderLayout.NORTH);
        viewerPanel.add(viewer, BorderLayout.CENTER);

        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableScroll, viewerPanel);
        split.setResizeWeight(0.55);
        split.setDividerLocation(300);
        split.setBorder(null);
        return split;
    }

    private static final javax.swing.text.Highlighter.HighlightPainter HL_RESP =
            new javax.swing.text.DefaultHighlighter.DefaultHighlightPainter(new Color(0xFF, 0xF1, 0x76));
    private static final javax.swing.text.Highlighter.HighlightPainter HL_REQ =
            new javax.swing.text.DefaultHighlighter.DefaultHighlightPainter(new Color(0xA6, 0xE2, 0x2E));

    /** Highlight a term in a text area and scroll so the first match is visible. */
    private void highlight(JTextArea area, String term, javax.swing.text.Highlighter.HighlightPainter painter) {
        area.getHighlighter().removeAllHighlights();
        if (term == null || term.isEmpty()) {
            return;
        }
        String text = area.getText();
        int idx = text.indexOf(term);
        if (idx < 0) {
            // fall back to a shorter, distinctive slice (payloads can be re-encoded)
            String probe = term.length() > 12 ? term.substring(0, 12) : term;
            idx = text.indexOf(probe);
            if (idx >= 0) {
                term = probe;
            }
        }
        if (idx < 0) {
            area.setCaretPosition(0);
            return;
        }
        try {
            area.getHighlighter().addHighlight(idx, idx + term.length(), painter);
            area.setCaretPosition(Math.min(text.length(), idx + term.length()));
            area.moveCaretPosition(idx); // selection view scrolls the match into view
        } catch (Exception ignored) {
            area.setCaretPosition(0);
        }
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
        int[] w = {70, 70, 80, 180, 120, 360, 80};
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
                String hay = (f.url + " " + f.parameter + " " + f.poc + " " + f.context).toLowerCase();
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
            requestView.setText("");
            responseView.setText("");
            requestView.getHighlighter().removeAllHighlights();
            responseView.getHighlighter().removeAllHighlights();
            pocBar.setText(" ");
            return;
        }
        requestView.setText(f.request != null ? new String(f.request, StandardCharsets.ISO_8859_1)
                : "(request not captured)");
        responseView.setText(f.response != null ? new String(f.response, StandardCharsets.ISO_8859_1)
                : "(response not captured)");

        // Highlight the injected value in the request and the reflected payload
        // in the response, scrolling each to the exact location of the finding.
        highlight(requestView, f.reqHighlight, HL_REQ);
        highlight(responseView, f.respHighlight, HL_RESP);

        boolean confirmed = XssFinding.STATUS_CONFIRMED.equals(f.status);
        String label = confirmed
                ? "<b>CONFIRMED</b> " + esc(f.severity) + " XSS"
                : "<b>Reflected</b> (unconfirmed - run an active scan)";
        String poc = confirmed ? "&nbsp; Payload: <code>" + esc(f.poc) + "</code>" : "";
        pocBar.setText("<html>" + label + " &nbsp;|&nbsp; Parameter: <b>" + esc(f.parameter)
                + "</b> &nbsp;|&nbsp; Context: " + esc(f.context) + poc + "</html>");
    }

    private static String esc(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }

    private void exportCsv() {
        try {
            JFileChooser fc = new JFileChooser();
            fc.setSelectedFile(new java.io.File("xssdetector-findings.csv"));
            if (fc.showSaveDialog(this) != JFileChooser.APPROVE_OPTION) {
                return;
            }
            try (FileWriter w = new FileWriter(fc.getSelectedFile())) {
                w.write("Time,Severity,Status,Context,Parameter,Method,Host,URL,Source,PoC\n");
                for (XssFinding f : model.rows) {
                    w.write(csv(timeFmt.format(new Date(f.time))) + "," + csv(f.severity) + "," + csv(f.status)
                            + "," + csv(f.context) + "," + csv(f.parameter) + "," + csv(f.method)
                            + "," + csv(f.host) + "," + csv(f.url) + "," + csv(f.source) + "," + csv(f.poc) + "\n");
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

    // ---- table model ----

    private class ResultsTableModel extends AbstractTableModel {
        private final String[] cols = {"Time", "Severity", "Status", "Context", "Parameter", "URL", "Source"};
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
                case 3: return f.context;
                case 4: return f.parameter;
                case 5: return f.url;
                case 6: return f.source;
                default: return "";
            }
        }
    }

    /** Colours the whole row by severity so high-risk findings stand out. */
    private class SeverityRowRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable t, Object v, boolean sel,
                                                       boolean focus, int row, int col) {
            Component comp = super.getTableCellRendererComponent(t, v, sel, focus, row, col);
            if (!sel) {
                XssFinding f = model.getRow(row);
                Color bg = Color.WHITE;
                if (f != null) {
                    if ("High".equals(f.severity)) {
                        bg = new Color(0xFD, 0xE7, 0xE9);
                    } else if ("Medium".equals(f.severity)) {
                        bg = new Color(0xFF, 0xF4, 0xDE);
                    } else {
                        bg = new Color(0xF0, 0xF4, 0xF8);
                    }
                    if (XssFinding.STATUS_CONFIRMED.equals(f.status) && col == 2) {
                        comp.setForeground(new Color(0xB0, 0x00, 0x20));
                    } else {
                        comp.setForeground(Color.BLACK);
                    }
                }
                comp.setBackground(bg);
            }
            return comp;
        }
    }
}
