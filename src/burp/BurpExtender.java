package burp;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.event.*;
import java.util.*;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.nio.charset.StandardCharsets;

import static burp.Constants.*;

/**
 * XSSDetector - Professional XSS Vulnerability Scanner for Burp Suite
 * Clean, production-ready implementation with essential XSS detection capabilities
 */
public class BurpExtender implements IBurpExtender, IScannerCheck, ITab, IHttpListener, IExtensionStateListener, IContextMenuFactory {
    
    // Plugin Information
    public static final String PLUGIN_NAME = "XSSDetector";
    public static final String VERSION = "2.0.0";
    
    // Core Burp Suite Components
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private Settings settings;
    
    // Essential UI Components
    private JPanel panel;
    private JButton addButton;
    private JButton deleteButton;
    private JTextField contentTypeTextField;
    private JTable table;
    private DefaultTableModel model;
    
    // Core Detection Settings
    private JCheckBox scopeOnly;
    private JCheckBox aggressiveMode;
    private JCheckBox autoConfirm;
    private JCheckBox checkContext;
    private JCheckBox modernDetection;
    private JCheckBox domXssDetection;
    private JCheckBox cspAnalysis;
    
    // Advanced XSS Detection
    private JCheckBox enableWAFBypass;
    private JCheckBox enableFrameworkSpecific;
    private JCheckBox enableEncodingBypass;
    private JCheckBox enableCSPBypass;
    private JCheckBox enablePolyglotPayloads;
    private JCheckBox enableBrowserSpecific;
    private JCheckBox enableJSFucker;
    private JCheckBox enablePrototypePollution;
    private JCheckBox enablePostMessageXSS;
    private JCheckBox enableWebComponents;
    private JCheckBox enableShadowDOM;
    private JCheckBox enableWebAssembly;
    private JCheckBox enableModernBrowserAPI;
    
    // Analysis and Reporting
    private JCheckBox detailedReporting;
    private JCheckBox exploitGeneration;
    private JCheckBox verboseLogging;
    
    // Core Detection Engines
    private ModernArchitectureDetector architectureDetector;
    private AdvancedJSONAnalyzer jsonAnalyzer;
    private EnhancedIssueReporter issueReporter;
    private AIContextAnalyzer aiAnalyzer;
    private PerformanceMonitor performanceMonitor;
    private ErrorRecoverySystem errorRecoverySystem;

    // Enhanced Detection Engines
    private ContextualReflectionEngine contextualEngine;
    private LiveResultsPanel liveResults;
    private ModernXSSAnalyzer modernXssAnalyzer;
    
    // Scan Control
    private volatile boolean scanInProgress = false;
    private volatile boolean scanPaused = false;
    private ExecutorService scanningExecutor;
    private static final int DEFAULT_MAX_THREADS = 5;
    private static final long MIN_SCAN_INTERVAL = 5000; // 5 seconds minimum between scans
    
    // Vulnerability Tracking
    private final Set<String> confirmedVulnerabilities = ConcurrentHashMap.newKeySet();
    private final Map<String, Long> parameterTestHistory = new ConcurrentHashMap<>();
    private static final long PARAMETER_COOLDOWN_MS = 300000; // 5 minutes between tests

    // IMPROVED: Global reported issues tracker to prevent duplicates
    private final Set<String> reportedIssueKeys = ConcurrentHashMap.newKeySet();
    private static final int MAX_REPORTED_ISSUES_CACHE = 5000;
    
    // Scan Status Management
    private enum ScanStatus {
        READY("Ready", new Color(0, 128, 0)),
        SCANNING("Scanning", new Color(0, 128, 255)),
        PAUSED("Paused", new Color(255, 165, 0)),
        COMPLETED("Completed", new Color(0, 128, 0)),
        ERROR("Error", new Color(255, 0, 0));
        
        private final String displayText;
        private final Color color;
        
        ScanStatus(String displayText, Color color) {
            this.displayText = displayText;
            this.color = color;
        }
        
        public String getDisplayText() { return displayText; }
        public Color getColor() { return color; }
    }
    
    private ScanStatus currentScanStatus = ScanStatus.READY;
    
    // Issue Naming
    private static final String XSS_POSSIBLE = "Cross-site scripting (reflected)";
    private static final String XSS_VULNERABLE = "Cross-site scripting (reflected)";
    private String issueName = XSS_POSSIBLE;
    
    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        
        // Set extension name
        callbacks.setExtensionName(PLUGIN_NAME + " v" + VERSION);
        
        // Initialize settings
        this.settings = new Settings(callbacks);
        
        // Initialize detection engines
        initializeDetectionEngines();
        
        // Initialize UI
        initializeUI();
        
        // Register scanner check
        callbacks.registerScannerCheck(this);

        // Add custom tab
        callbacks.addSuiteTab(this);

        // Register HTTP listener for REAL-TIME monitoring of all Burp tools
        callbacks.registerHttpListener(this);

        // Register extension state listener for cleanup on unload
        callbacks.registerExtensionStateListener(this);

        // Register right-click "Active XSS scan" menu (works in any Burp edition)
        callbacks.registerContextMenuFactory(this);

        // Initialize thread management
        initializeThreadManagement();

        // Log initialization
        callbacks.printOutput("[" + PLUGIN_NAME + "] Initialized successfully");
        callbacks.printOutput("[" + PLUGIN_NAME + "] Version: " + VERSION);
        callbacks.printOutput("[" + PLUGIN_NAME + "] Real-time HTTP monitoring: ENABLED");
    }
    
    /**
     * Initialize all detection engines with comprehensive error handling
     */
    private void initializeDetectionEngines() {
        int enginesInitialized = 0;
        int enginesFailed = 0;
        
        try {
            // CRITICAL: Initialize PerformanceMonitor and ErrorRecoverySystem FIRST
            // These are needed by the detection engines
            // Performance monitoring
            try {
                this.performanceMonitor = new PerformanceMonitor(callbacks);
                enginesInitialized++;
            } catch (Exception e) {
                callbacks.printError("[" + PLUGIN_NAME + "] Failed to initialize PerformanceMonitor: " + e.getMessage());
                enginesFailed++;
            }
            
            // Error recovery
            try {
                this.errorRecoverySystem = new ErrorRecoverySystem(callbacks, performanceMonitor);
                enginesInitialized++;
            } catch (Exception e) {
                callbacks.printError("[" + PLUGIN_NAME + "] Failed to initialize ErrorRecoverySystem: " + e.getMessage());
                enginesFailed++;
            }
            
            // Issue reporting (critical - must succeed, initialize early)
            try {
                this.issueReporter = new EnhancedIssueReporter(helpers, callbacks, settings);
                enginesInitialized++;
            } catch (Exception e) {
                callbacks.printError("[" + PLUGIN_NAME + "] CRITICAL: Failed to initialize EnhancedIssueReporter: " + e.getMessage());
                enginesFailed++;
            }
            
            // Modern architecture detection
            try {
                this.architectureDetector = new ModernArchitectureDetector(helpers, callbacks, settings);
                enginesInitialized++;
            } catch (Exception e) {
                callbacks.printError("[" + PLUGIN_NAME + "] Failed to initialize ModernArchitectureDetector: " + e.getMessage());
                enginesFailed++;
            }
            
            // JSON analysis
            try {
                this.jsonAnalyzer = new AdvancedJSONAnalyzer(helpers, callbacks, settings);
                enginesInitialized++;
            } catch (Exception e) {
                callbacks.printError("[" + PLUGIN_NAME + "] Failed to initialize AdvancedJSONAnalyzer: " + e.getMessage());
                enginesFailed++;
            }
            
            // AI context analysis
            try {
                this.aiAnalyzer = new AIContextAnalyzer(helpers, callbacks, settings);
                enginesInitialized++;
            } catch (Exception e) {
                callbacks.printError("[" + PLUGIN_NAME + "] Failed to initialize AIContextAnalyzer: " + e.getMessage());
                enginesFailed++;
            }
            
            // Contextual reflection engine (context-aware probe-and-confirm,
            // including JSON/JSONP) -- the primary context-aware detector.
            try {
                this.contextualEngine = new ContextualReflectionEngine(helpers, callbacks, settings);
                enginesInitialized++;
            } catch (Exception e) {
                callbacks.printError("[" + PLUGIN_NAME + "] Failed to initialize ContextualReflectionEngine: " + e.getMessage());
                enginesFailed++;
            }

            // Modern XSS analyzer for advanced attack vectors
            try {
                this.modernXssAnalyzer = new ModernXSSAnalyzer(helpers, callbacks, settings);
                enginesInitialized++;
            } catch (Exception e) {
                callbacks.printError("[" + PLUGIN_NAME + "] Failed to initialize ModernXSSAnalyzer: " + e.getMessage());
                enginesFailed++;
            }

            callbacks.printOutput("[" + PLUGIN_NAME + "] Detection engines initialized: " + enginesInitialized + " successful, " + enginesFailed + " failed");
            
            if (enginesFailed > 0) {
                callbacks.printError("[" + PLUGIN_NAME + "] WARNING: Some detection engines failed to initialize. Functionality may be limited.");
            }
            
        } catch (Exception e) {
            callbacks.printError("[" + PLUGIN_NAME + "] Critical error initializing detection engines: " + e.getMessage());
            if (settings != null && settings.getVerboseLogging()) {
                callbacks.printError("[" + PLUGIN_NAME + "] Stack trace: " + java.util.Arrays.toString(e.getStackTrace()));
            }
        }
    }
    
    /**
     * Initialize clean, professional UI
     */
    private void initializeUI() {
        try {
            // Root panel for the Burp tab, organised into navigable tabs.
            panel = new JPanel(new BorderLayout());
            JTabbedPane tabs = new JTabbedPane();

            // --- Tab 1: Live Results (real-time findings + smart filters) ---
            liveResults = new LiveResultsPanel(FindingStore.get(), callbacks);
            tabs.addTab("Live Results", liveResults);

            // --- Tab 2: Settings (left-aligned, scrollable sections) ---
            // Content-type management lives here too, as its own section.
            JPanel column = new JPanel();
            column.setLayout(new BoxLayout(column, BoxLayout.Y_AXIS));
            column.setBorder(BorderFactory.createEmptyBorder(12, 14, 12, 14));
            column.add(createHeader());
            column.add(Box.createVerticalStrut(10));
            column.add(createSettingsPanel());
            column.add(Box.createVerticalStrut(10));

            JPanel contentTypePanel = createContentTypePanel();
            contentTypePanel.setAlignmentX(Component.LEFT_ALIGNMENT);
            contentTypePanel.setMaximumSize(new Dimension(Integer.MAX_VALUE, 260));
            column.add(contentTypePanel);

            JPanel settingsHolder = new JPanel(new BorderLayout());
            settingsHolder.add(column, BorderLayout.NORTH);
            JScrollPane settingsScroll = new JScrollPane(settingsHolder,
                    JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED,
                    JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
            settingsScroll.setBorder(null);
            settingsScroll.getVerticalScrollBar().setUnitIncrement(16);
            tabs.addTab("Settings", settingsScroll);

            panel.add(tabs, BorderLayout.CENTER);

            // Initialize listeners
            initListeners();

            callbacks.printOutput("[" + PLUGIN_NAME + "] UI initialized successfully");

        } catch (Exception e) {
            callbacks.printError("[" + PLUGIN_NAME + "] Error initializing UI: " + e.getMessage());
        }
    }

    /** Title + one-line description shown at the top of the tab. */
    private JComponent createHeader() {
        JPanel p = new JPanel();
        p.setLayout(new BoxLayout(p, BoxLayout.Y_AXIS));
        p.setAlignmentX(Component.LEFT_ALIGNMENT);

        JLabel title = new JLabel("XSSDetector");
        title.setFont(title.getFont().deriveFont(Font.BOLD, 17f));
        title.setAlignmentX(Component.LEFT_ALIGNMENT);

        JLabel sub = new JLabel("<html><body style='width:560px'>Fully contextual reflected-XSS scanner "
                + "(HTML, attributes, JavaScript, CSS, JSON/JSONP) with live two-stage confirmation.</body></html>");
        sub.setForeground(new Color(120, 120, 120));
        sub.setAlignmentX(Component.LEFT_ALIGNMENT);

        p.add(title);
        p.add(Box.createVerticalStrut(4));
        p.add(sub);
        p.setMaximumSize(new Dimension(Integer.MAX_VALUE, p.getPreferredSize().height));
        return p;
    }

    /** Titled section whose body is left-aligned and never stretches vertically. */
    private JPanel section(String title, JComponent body) {
        JPanel s = new JPanel(new BorderLayout());
        s.setBorder(BorderFactory.createTitledBorder(title));
        body.setAlignmentX(Component.LEFT_ALIGNMENT);
        s.add(body, BorderLayout.CENTER);
        s.setAlignmentX(Component.LEFT_ALIGNMENT);
        s.setMaximumSize(new Dimension(Integer.MAX_VALUE, s.getPreferredSize().height));
        return s;
    }

    /** A left-aligned grid of controls with a fixed number of columns. */
    private JPanel grid(int cols, Component... items) {
        JPanel p = new JPanel(new GridLayout(0, cols, 18, 4));
        for (Component c : items) {
            p.add(c);
        }
        p.setAlignmentX(Component.LEFT_ALIGNMENT);
        return p;
    }

    /**
     * Create clean settings panel
     */
    private JPanel createSettingsPanel() {
        // --- Create controls (field names unchanged -> listeners stay wired) ---
        scopeOnly = new JCheckBox("Scan in-scope targets only", settings.getScopeOnly());
        aggressiveMode = new JCheckBox("Aggressive mode (extra bypass probes)", settings.getAggressiveMode());
        autoConfirm = new JCheckBox("Live confirm while browsing (sends probes, on by default)", settings.getAutoConfirm());
        autoConfirm.setToolTipText("On by default. Reflected parameters seen in proxied traffic are automatically "
                + "probe-and-confirmed, so reflected XSS is reported as Confirmed in realtime just by browsing - no "
                + "manual scan and no Burp scope setup required. Enable 'Scan in-scope targets only' above to restrict "
                + "this auto-confirmation to targets in Burp's scope. (Right-click -> Active XSS scan always works too.)");
        checkContext = new JCheckBox("Contextual reflection engine  (context-aware, incl. JSON/JSONP)", settings.getCheckContext());

        modernDetection = new JCheckBox("Modern framework detection", settings.getModernDetection());
        domXssDetection = new JCheckBox("DOM XSS (source-to-sink)", settings.getDomXssDetection());
        cspAnalysis = new JCheckBox("CSP analysis", settings.getCspAnalysis());

        enableWAFBypass = new JCheckBox("WAF bypass", settings.getEnableWAFBypass());
        enableFrameworkSpecific = new JCheckBox("Framework-specific", settings.getEnableFrameworkSpecific());
        enableEncodingBypass = new JCheckBox("Encoding bypass", settings.getEnableEncodingBypass());
        enableCSPBypass = new JCheckBox("CSP bypass", settings.getEnableCSPBypass());
        enablePolyglotPayloads = new JCheckBox("Polyglot", settings.getEnablePolyglotPayloads());
        enableBrowserSpecific = new JCheckBox("Browser-specific", settings.getEnableBrowserSpecific());
        enableJSFucker = new JCheckBox("JSFuck", settings.getEnableJSFucker());
        enablePrototypePollution = new JCheckBox("Prototype pollution", settings.getEnablePrototypePollution());
        enablePostMessageXSS = new JCheckBox("postMessage", settings.getEnablePostMessageXSS());
        enableWebComponents = new JCheckBox("Web components", settings.getEnableWebComponents());
        enableShadowDOM = new JCheckBox("Shadow DOM", settings.getEnableShadowDOM());
        enableWebAssembly = new JCheckBox("WebAssembly", settings.getEnableWebAssembly());
        enableModernBrowserAPI = new JCheckBox("Modern browser API", settings.getEnableModernBrowserAPI());

        detailedReporting = new JCheckBox("Detailed reporting", settings.getDetailedReporting());
        exploitGeneration = new JCheckBox("Exploit generation", settings.getExploitGeneration());
        verboseLogging = new JCheckBox("Verbose logging", settings.getVerboseLogging());

        // Helpful tooltips
        checkContext.setToolTipText("Primary engine: probes each parameter with a canary + break-out characters, "
                + "classifies the reflection context, and confirms with a live proof-of-concept before reporting.");
        aggressiveMode.setToolTipText("Also fire additional encoding/WAF-bypass payloads.");
        scopeOnly.setToolTipText("Restrict all scanning to items inside Burp's target scope.");

        // --- Assemble the column of titled sections ---
        JPanel col = new JPanel();
        col.setLayout(new BoxLayout(col, BoxLayout.Y_AXIS));
        col.setAlignmentX(Component.LEFT_ALIGNMENT);

        col.add(section("Scanning", grid(2, scopeOnly, aggressiveMode, autoConfirm)));
        col.add(Box.createVerticalStrut(8));

        // Detection engines, with the primary engine highlighted and described.
        JPanel engines = new JPanel();
        engines.setLayout(new BoxLayout(engines, BoxLayout.Y_AXIS));
        checkContext.setFont(checkContext.getFont().deriveFont(Font.BOLD));
        checkContext.setAlignmentX(Component.LEFT_ALIGNMENT);
        engines.add(checkContext);
        JLabel engineNote = new JLabel("<html><body style='width:540px;color:gray'>"
                + "Injects a canary + break-out probe, classifies the exact context "
                + "(HTML / attribute / JS / CSS / JSON), and verifies a live PoC before reporting "
                + "&mdash; near-zero false positives.</body></html>");
        engineNote.setAlignmentX(Component.LEFT_ALIGNMENT);
        engineNote.setBorder(BorderFactory.createEmptyBorder(2, 22, 6, 0));
        engines.add(engineNote);
        JPanel otherEngines = grid(3, modernDetection, domXssDetection, cspAnalysis);
        otherEngines.setAlignmentX(Component.LEFT_ALIGNMENT);
        engines.add(otherEngines);
        col.add(section("Detection engines", engines));
        col.add(Box.createVerticalStrut(8));

        col.add(section("Payload packs (WAF / filter bypass)", grid(3,
                enableWAFBypass, enableFrameworkSpecific, enableEncodingBypass,
                enableCSPBypass, enablePolyglotPayloads, enableBrowserSpecific,
                enableJSFucker, enablePrototypePollution, enablePostMessageXSS,
                enableWebComponents, enableShadowDOM, enableWebAssembly,
                enableModernBrowserAPI)));
        col.add(Box.createVerticalStrut(8));

        col.add(section("Reporting", grid(3, detailedReporting, exploitGeneration, verboseLogging)));

        return col;
    }

    /**
     * Create content type management panel - FULLY WIRED TO SETTINGS
     */
    private JPanel createContentTypePanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createTitledBorder("Content Type Management - Client-Side Injection Detection"));
        
        // CRITICAL: Use Settings to get content types (fully wired)
        ArrayList<Object[]> contentTypesList = settings.getContentTypes();
        
        // Create table with proper column names
        String[] columnNames = {"Enabled", "Content Type"};
        Object[][] data = new Object[contentTypesList.size()][2];
        for (int i = 0; i < contentTypesList.size(); i++) {
            Object[] row = contentTypesList.get(i);
            if (row != null && row.length >= 2) {
                data[i][0] = row[1]; // Enabled status
                data[i][1] = row[0]; // Content type
            } else {
                // Handle invalid row data
                data[i][0] = true;
                data[i][1] = "";
            }
        }
        
        // Create table model that saves to Settings
        model = new DefaultTableModel(data, columnNames) {
            @Override
            public Class<?> getColumnClass(int columnIndex) {
                if (columnIndex == 0) return Boolean.class; // Enabled checkbox
                return String.class; // Content type
            }
            
            @Override
            public boolean isCellEditable(int row, int column) {
                return true; // Both columns editable
            }
            
            @Override
            public void setValueAt(Object value, int row, int column) {
                super.setValueAt(value, row, column);
                // CRITICAL: Save to Settings immediately when changed
                saveContentTypesToSettings();
            }
        };
        
        table = new JTable(model);
        table.getColumnModel().getColumn(0).setPreferredWidth(60);
        table.getColumnModel().getColumn(1).setPreferredWidth(400);
        
        // Create buttons
        addButton = new JButton("Add");
        deleteButton = new JButton("Delete");
        JButton resetButton = new JButton("Reset to Defaults");
        contentTypeTextField = new JTextField(30);
        
        // Create button panel
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        buttonPanel.add(new JLabel("Content Type:"));
        buttonPanel.add(contentTypeTextField);
        buttonPanel.add(addButton);
        buttonPanel.add(deleteButton);
        buttonPanel.add(resetButton);
        
        // Add reset button listener
        resetButton.addActionListener(e -> resetContentTypesToDefaults());
        
        panel.add(new JScrollPane(table), BorderLayout.CENTER);
        panel.add(buttonPanel, BorderLayout.SOUTH);
        
        return panel;
    }
    
    /**
     * Save content types from table to Settings - FULLY WIRED WITH NULL CHECKS
     */
    private void saveContentTypesToSettings() {
        try {
            if (model == null || settings == null) {
                callbacks.printError("[" + PLUGIN_NAME + "] Cannot save content types: model or settings is null");
                return;
            }
            
            ArrayList<Object[]> contentTypesList = new ArrayList<>();
            for (int i = 0; i < model.getRowCount(); i++) {
                try {
                    Boolean enabled = (Boolean) model.getValueAt(i, 0);
                    String contentType = (String) model.getValueAt(i, 1);
                    if (contentType != null && !contentType.trim().isEmpty()) {
                        contentTypesList.add(new Object[]{contentType.trim(), enabled != null ? enabled : true});
                    }
                } catch (Exception e) {
                    // Skip invalid rows
                    callbacks.printError("[" + PLUGIN_NAME + "] Error processing row " + i + ": " + e.getMessage());
                }
            }
            
            settings.setContentTypes(contentTypesList);
            settings.saveContentTypes();
            callbacks.printOutput("[" + PLUGIN_NAME + "] Content types saved: " + contentTypesList.size() + " entries");
            
        } catch (Exception e) {
            callbacks.printError("[" + PLUGIN_NAME + "] Error saving content types: " + e.getMessage());
            if (settings != null && settings.getVerboseLogging()) {
                callbacks.printError("[" + PLUGIN_NAME + "] Stack trace: " + java.util.Arrays.toString(e.getStackTrace()));
            }
        }
    }
    
    /**
     * Reset content types to defaults
     */
    private void resetContentTypesToDefaults() {
        try {
            model.setRowCount(0); // Clear table
            ArrayList<Object[]> defaults = new ArrayList<>();
            for (String contentType : Constants.MODERN_DEFAULT_CONTENT_TYPES) {
                // Only enable text/html and application/json by default
                boolean enabled = "text/html".equals(contentType) || "application/json".equals(contentType);
                defaults.add(new Object[]{contentType, enabled});
                model.addRow(new Object[]{enabled, contentType});
            }
            settings.setContentTypes(defaults);
            settings.saveContentTypes();
            callbacks.printOutput("[" + PLUGIN_NAME + "] Reset content types to defaults (only text/html and application/json enabled)");
        } catch (Exception e) {
            callbacks.printError("Error resetting content types: " + e.getMessage());
        }
    }
    
    /**
     * Initialize event listeners - FULLY WIRED WITH NULL CHECKS
     */
    private void initListeners() {
        try {
            // CRITICAL: Verify all UI components are initialized before attaching listeners
            if (scopeOnly == null || aggressiveMode == null || autoConfirm == null || checkContext == null ||
                modernDetection == null || domXssDetection == null || cspAnalysis == null ||
                enableWAFBypass == null || enableFrameworkSpecific == null || enableEncodingBypass == null ||
                enableCSPBypass == null || enablePolyglotPayloads == null || enableBrowserSpecific == null ||
                enableJSFucker == null || enablePrototypePollution == null || enablePostMessageXSS == null ||
                enableWebComponents == null || enableShadowDOM == null || enableWebAssembly == null ||
                enableModernBrowserAPI == null || detailedReporting == null || exploitGeneration == null ||
                verboseLogging == null || addButton == null || deleteButton == null || table == null ||
                contentTypeTextField == null || settings == null) {
                callbacks.printError("[" + PLUGIN_NAME + "] CRITICAL: UI components not initialized before attaching listeners");
                return;
            }
            
            // Settings change listeners - All properly wired to Settings with immediate persistence
            scopeOnly.addActionListener(e -> {
                if (settings != null) settings.setScopeOnly(scopeOnly.isSelected());
            });
            aggressiveMode.addActionListener(e -> {
                if (settings != null) settings.setAggressiveMode(aggressiveMode.isSelected());
            });
            autoConfirm.addActionListener(e -> {
                if (settings != null) settings.setAutoConfirm(autoConfirm.isSelected());
            });
            checkContext.addActionListener(e -> {
                if (settings != null) settings.setCheckContext(checkContext.isSelected());
            });
            modernDetection.addActionListener(e -> {
                if (settings != null) settings.setModernDetection(modernDetection.isSelected());
            });
            domXssDetection.addActionListener(e -> {
                if (settings != null) settings.setDomXssDetection(domXssDetection.isSelected());
            });
            cspAnalysis.addActionListener(e -> {
                if (settings != null) settings.setCspAnalysis(cspAnalysis.isSelected());
            });
            enableWAFBypass.addActionListener(e -> {
                if (settings != null) settings.setEnableWAFBypass(enableWAFBypass.isSelected());
            });
            enableFrameworkSpecific.addActionListener(e -> {
                if (settings != null) settings.setEnableFrameworkSpecific(enableFrameworkSpecific.isSelected());
            });
            enableEncodingBypass.addActionListener(e -> {
                if (settings != null) settings.setEnableEncodingBypass(enableEncodingBypass.isSelected());
            });
            enableCSPBypass.addActionListener(e -> {
                if (settings != null) settings.setEnableCSPBypass(enableCSPBypass.isSelected());
            });
            enablePolyglotPayloads.addActionListener(e -> {
                if (settings != null) settings.setEnablePolyglotPayloads(enablePolyglotPayloads.isSelected());
            });
            enableBrowserSpecific.addActionListener(e -> {
                if (settings != null) settings.setEnableBrowserSpecific(enableBrowserSpecific.isSelected());
            });
            enableJSFucker.addActionListener(e -> {
                if (settings != null) settings.setEnableJSFucker(enableJSFucker.isSelected());
            });
            enablePrototypePollution.addActionListener(e -> {
                if (settings != null) settings.setEnablePrototypePollution(enablePrototypePollution.isSelected());
            });
            enablePostMessageXSS.addActionListener(e -> {
                if (settings != null) settings.setEnablePostMessageXSS(enablePostMessageXSS.isSelected());
            });
            enableWebComponents.addActionListener(e -> {
                if (settings != null) settings.setEnableWebComponents(enableWebComponents.isSelected());
            });
            enableShadowDOM.addActionListener(e -> {
                if (settings != null) settings.setEnableShadowDOM(enableShadowDOM.isSelected());
            });
            enableWebAssembly.addActionListener(e -> {
                if (settings != null) settings.setEnableWebAssembly(enableWebAssembly.isSelected());
            });
            enableModernBrowserAPI.addActionListener(e -> {
                if (settings != null) settings.setEnableModernBrowserAPI(enableModernBrowserAPI.isSelected());
            });
            detailedReporting.addActionListener(e -> {
                if (settings != null) settings.setDetailedReporting(detailedReporting.isSelected());
            });
            exploitGeneration.addActionListener(e -> {
                if (settings != null) settings.setExploitGeneration(exploitGeneration.isSelected());
            });
            verboseLogging.addActionListener(e -> {
                if (settings != null) settings.setVerboseLogging(verboseLogging.isSelected());
            });
            
            // Content type management listeners - Fully wired to Settings
            addButton.addActionListener(e -> {
                if (model != null && contentTypeTextField != null && settings != null) {
                    addContentType();
                }
            });
            deleteButton.addActionListener(e -> {
                if (table != null && model != null && settings != null) {
                    deleteContentType();
                }
            });
            
            // Table selection listener - Updates text field when row is selected
            if (table != null && contentTypeTextField != null) {
                table.getSelectionModel().addListSelectionListener(e -> {
                    if (!e.getValueIsAdjusting() && table != null && contentTypeTextField != null) {
                        try {
                            int selectedRow = table.getSelectedRow();
                            if (selectedRow >= 0 && model != null) {
                                // Column 1 contains the content-type string; column 0 is the enabled checkbox
                                Object ct = model.getValueAt(selectedRow, 1);
                                contentTypeTextField.setText(ct != null ? ct.toString() : "");
                            }
                        } catch (Exception ex) {
                            // Silently handle selection errors
                        }
                    }
                });
            }
            
            callbacks.printOutput("[" + PLUGIN_NAME + "] All UI listeners initialized and fully wired to Settings");
            
        } catch (Exception e) {
            callbacks.printError("[" + PLUGIN_NAME + "] Error initializing listeners: " + e.getMessage());
            if (settings != null && settings.getVerboseLogging()) {
                callbacks.printError("[" + PLUGIN_NAME + "] Stack trace: " + java.util.Arrays.toString(e.getStackTrace()));
            }
        }
    }
    
    /**
     * Add content type to allowed list - FULLY WIRED TO SETTINGS WITH VALIDATION
     */
    private void addContentType() {
        try {
            if (contentTypeTextField == null || model == null || settings == null) {
                callbacks.printError("[" + PLUGIN_NAME + "] Cannot add content type: UI components not initialized");
                return;
            }
            
            String contentType = contentTypeTextField.getText().trim();
            if (contentType.isEmpty()) {
                callbacks.printOutput("[" + PLUGIN_NAME + "] Content type cannot be empty");
                return;
            }
            
            // Validate content type format (basic validation)
            if (!contentType.contains("/") && !contentType.equals("*")) {
                callbacks.printOutput("[" + PLUGIN_NAME + "] Invalid content type format (should be like 'text/html' or '*'): " + contentType);
                return;
            }
            
            // Check if already exists
            boolean exists = false;
            for (int i = 0; i < model.getRowCount(); i++) {
                try {
                    String existing = (String) model.getValueAt(i, 1);
                    if (contentType.equalsIgnoreCase(existing)) {
                        exists = true;
                        break;
                    }
                } catch (Exception e) {
                    // Skip invalid rows
                }
            }
            
            if (!exists) {
                model.addRow(new Object[]{true, contentType});
                saveContentTypesToSettings();
                contentTypeTextField.setText("");
                callbacks.printOutput("[" + PLUGIN_NAME + "] Added content type: " + contentType);
            } else {
                callbacks.printOutput("[" + PLUGIN_NAME + "] Content type already exists: " + contentType);
            }
            
        } catch (Exception e) {
            callbacks.printError("[" + PLUGIN_NAME + "] Error adding content type: " + e.getMessage());
            if (settings != null && settings.getVerboseLogging()) {
                callbacks.printError("[" + PLUGIN_NAME + "] Stack trace: " + java.util.Arrays.toString(e.getStackTrace()));
            }
        }
    }
    
    /**
     * Delete selected content type - FULLY WIRED TO SETTINGS WITH VALIDATION
     */
    private void deleteContentType() {
        try {
            if (table == null || model == null || settings == null) {
                callbacks.printError("[" + PLUGIN_NAME + "] Cannot delete content type: UI components not initialized");
                return;
            }
            
            int selectedRow = table.getSelectedRow();
            if (selectedRow < 0) {
                callbacks.printOutput("[" + PLUGIN_NAME + "] Please select a content type to delete");
                return;
            }
            
            if (selectedRow >= model.getRowCount()) {
                callbacks.printError("[" + PLUGIN_NAME + "] Invalid row selected: " + selectedRow);
                return;
            }
            
            String contentType = (String) model.getValueAt(selectedRow, 1);
            model.removeRow(selectedRow);
            saveContentTypesToSettings();
            callbacks.printOutput("[" + PLUGIN_NAME + "] Removed content type: " + (contentType != null ? contentType : "unknown"));
            
        } catch (Exception e) {
            callbacks.printError("[" + PLUGIN_NAME + "] Error deleting content type: " + e.getMessage());
            if (settings != null && settings.getVerboseLogging()) {
                callbacks.printError("[" + PLUGIN_NAME + "] Stack trace: " + java.util.Arrays.toString(e.getStackTrace()));
            }
        }
    }
    
    /**
     * Get response content type from HTTP response
     */
    private String getResponseContentType(IHttpRequestResponse requestResponse) {
        try {
            byte[] response = requestResponse.getResponse();
            IResponseInfo responseInfo = helpers.analyzeResponse(response);
            for (String header : responseInfo.getHeaders()) {
                if (header.toLowerCase().startsWith("content-type:")) {
                    String contentType = header.substring(13).trim().split(";")[0].trim();
                    return contentType;
                }
            }
        } catch (Exception e) {
            // Ignore errors
        }
        return null;
    }
    
    /**
     * Initialize thread management
     */
    private void initializeThreadManagement() {
        try {
            scanningExecutor = Executors.newFixedThreadPool(DEFAULT_MAX_THREADS);
            callbacks.printOutput("[" + PLUGIN_NAME + "] Thread management initialized with " + DEFAULT_MAX_THREADS + " threads");
        } catch (Exception e) {
            callbacks.printError("[" + PLUGIN_NAME + "] Error initializing thread management: " + e.getMessage());
        }
    }

    @Override
    public String getTabCaption() {
        return PLUGIN_NAME;
    }

    @Override
    public Component getUiComponent() {
        return panel;
    }

    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
        List<IScanIssue> issues = new ArrayList<>();
        
        try {
            // Skip if scan is paused
            if (scanPaused) {
                return issues;
            }
            
            // Check if in scope
            if (settings.getScopeOnly() && !callbacks.isInScope(helpers.analyzeRequest(baseRequestResponse).getUrl())) {
                return issues;
            }

            // Skip excessively large responses (>10MB) to prevent memory/performance issues
            if (baseRequestResponse.getResponse() != null && baseRequestResponse.getResponse().length > 10 * 1024 * 1024) {
                return issues;
            }

            // XSS is reported ONLY by the ContextualReflectionEngine, which injects
            // a probe and confirms a live break-out before reporting -- zero
            // thresholds, zero heuristic guesses, zero false positives. The old
            // heuristic DOM / client-side / CSP detectors (which scored risk against
            // thresholds and produced false positives) are no longer invoked.

        } catch (Exception e) {
            callbacks.printError("[" + PLUGIN_NAME + "] Error in passive scan: " + e.getMessage());
            if (settings != null && settings.getVerboseLogging()) {
                callbacks.printError("[" + PLUGIN_NAME + "] Stack trace: " + java.util.Arrays.toString(e.getStackTrace()));
            }
        }
        
        // CRITICAL: Ensure all issues are reported to Burp with deduplication
        if (!issues.isEmpty()) {
            callbacks.printOutput("[" + PLUGIN_NAME + "] Total issues found in passive scan: " + issues.size());
            int reported = 0;
            for (IScanIssue issue : issues) {
                if (reportIssueWithDedup(issue)) {
                    reported++;
                }
            }
            if (reported < issues.size()) {
                callbacks.printOutput("[" + PLUGIN_NAME + "] Duplicates filtered: " + (issues.size() - reported));
            }
        }

        return issues;
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        List<JMenuItem> items = new ArrayList<>();
        try {
            final IHttpRequestResponse[] selected = invocation != null ? invocation.getSelectedMessages() : null;
            if (selected == null || selected.length == 0) {
                return items;
            }
            JMenuItem scan = new JMenuItem("Active XSS scan (XSSDetector)");
            scan.addActionListener(e -> scanningExecutor.submit(() -> runMenuScan(selected)));
            items.add(scan);

            // Sweep the whole Target site map (filtered by Content Type Management
            // and the scope setting). This is Burp's purpose; the user triggers it.
            JMenuItem sweep = new JMenuItem("Scan entire Target site map (XSSDetector)");
            sweep.addActionListener(e -> scanningExecutor.submit(this::runSiteMapScan));
            items.add(sweep);
        } catch (Exception ex) {
            callbacks.printError("[" + PLUGIN_NAME + "] context menu error: " + ex.getMessage());
        }
        return items;
    }

    /** Run the contextual engine over the selected requests and report findings.
     *  Works without Burp Pro's scanner (it sends its own probe/confirm requests). */
    private void runMenuScan(IHttpRequestResponse[] selected) {
        int confirmed = 0;
        int scanned = 0;
        int paramsTested = 0;
        int reflectedParams = 0;
        List<String> allNotes = new ArrayList<>();
        try {
            if (contextualEngine == null) {
                return;
            }
            for (IHttpRequestResponse rr : selected) {
                if (rr == null || rr.getRequest() == null) {
                    continue;
                }
                scanned++;
                ContextualReflectionEngine.ScanStats stats = new ContextualReflectionEngine.ScanStats();
                List<IScanIssue> issues = contextualEngine.scanRequest(rr, "Menu scan", stats);
                if (issues != null) {
                    for (IScanIssue issue : issues) {
                        if (reportIssueWithDedup(issue)) {
                            confirmed++;
                        }
                    }
                }
                paramsTested += stats.params;
                reflectedParams += stats.reflected;
                allNotes.addAll(stats.notes);
            }
            final int c = confirmed;
            final int s = scanned;
            final int pt = paramsTested;
            final int rp = reflectedParams;
            callbacks.printOutput("[" + PLUGIN_NAME + "] Active XSS scan: " + s + " request(s), "
                    + pt + " parameter(s) tested, " + rp + " reflected, " + c + " confirmed.");
            for (String note : allNotes) {
                callbacks.printOutput("[" + PLUGIN_NAME + "]   - " + note);
            }
            final StringBuilder detail = new StringBuilder();
            detail.append("Active XSS scan complete.\n\n")
                  .append("Requests scanned: ").append(s).append('\n')
                  .append("Parameters tested: ").append(pt).append('\n')
                  .append("Reflected: ").append(rp).append('\n')
                  .append("Confirmed XSS: ").append(c).append("\n\n");
            if (c > 0) {
                detail.append("See the Issues tab and the Live Results tab.");
            } else if (rp > 0) {
                detail.append("Parameters reflected but no break-out confirmed (filtered/encoded).\n")
                      .append("Reflected candidates are listed in the Live Results tab.");
            } else if (pt > 0) {
                detail.append("No reflection detected in the tested parameter(s).");
            } else {
                detail.append("This request has no parameters to inject into\n")
                      .append("(no query string, body, cookie or URL path segment).\n\n")
                      .append("Pick a request that carries input - e.g. a URL with ?name=value\n")
                      .append("such as /search.jsp?query=test or /index.jsp?content=... -\n")
                      .append("or select a site-map folder/host to scan all its requests at once.\n")
                      .append("Tip: just browse the target through the proxy; reflected inputs\n")
                      .append("are auto-confirmed and appear in Live Results.");
            }
            if (!allNotes.isEmpty()) {
                detail.append("\n\nPer-parameter:");
                int shown = 0;
                for (String note : allNotes) {
                    if (shown++ >= 12) { detail.append("\n  ... (see extension output)"); break; }
                    detail.append("\n  - ").append(note);
                }
            }
            SwingUtilities.invokeLater(() -> JOptionPane.showMessageDialog(panel,
                    detail.toString(), "XSSDetector", JOptionPane.INFORMATION_MESSAGE));
        } catch (Exception e) {
            callbacks.printError("[" + PLUGIN_NAME + "] Menu scan error: " + e.getMessage());
        }
    }

    private static final int SITEMAP_MAX_ENDPOINTS = 400;

    /**
     * Sweep Burp's entire Target site map and run the contextual XSS test on every
     * unique endpoint whose response content-type matches Content Type Management.
     * Honors the "Scan in-scope targets only" setting: OFF tests all domains in the
     * site map, ON restricts to Burp's Target scope. User-triggered (menu).
     */
    private void runSiteMapScan() {
        if (contextualEngine == null) {
            return;
        }
        int endpoints = 0;
        int paramsTested = 0;
        int reflected = 0;
        int confirmed = 0;
        int skippedType = 0;
        int skippedScope = 0;
        try {
            IHttpRequestResponse[] siteMap = callbacks.getSiteMap(null);
            if (siteMap == null || siteMap.length == 0) {
                SwingUtilities.invokeLater(() -> JOptionPane.showMessageDialog(panel,
                        "The Target site map is empty. Browse or crawl the target first, "
                        + "then run this again.", "XSSDetector", JOptionPane.INFORMATION_MESSAGE));
                return;
            }
            boolean scopeOnly = settings != null && settings.getScopeOnly();
            java.util.List<String> enabledTypes = settings != null ? settings.getEnabledContentTypes() : null;

            java.util.Set<String> seen = new java.util.HashSet<>();
            callbacks.printOutput("[" + PLUGIN_NAME + "] Site map sweep started: " + siteMap.length
                    + " entries (scope-only=" + scopeOnly + ").");

            for (IHttpRequestResponse rr : siteMap) {
                if (endpoints >= SITEMAP_MAX_ENDPOINTS) {
                    break;
                }
                if (rr == null || rr.getRequest() == null) {
                    continue;
                }
                IRequestInfo ri;
                try {
                    ri = helpers.analyzeRequest(rr);
                } catch (Exception ex) {
                    continue;
                }
                java.net.URL url = ri.getUrl();
                if (url == null) {
                    continue;
                }
                // Scope policy.
                if (scopeOnly) {
                    try {
                        if (!callbacks.isInScope(url)) {
                            skippedScope++;
                            continue;
                        }
                    } catch (Exception ex) {
                        skippedScope++;
                        continue;
                    }
                }
                // Content-type gate (must have a recorded response of an enabled type).
                String ct = getResponseContentType(rr);
                if (!contentTypeEnabledForSweep(ct, enabledTypes)) {
                    skippedType++;
                    continue;
                }
                // One scan per unique endpoint (method + host + path + param-name set).
                String key = dedupEndpointKey(ri, url);
                if (!seen.add(key)) {
                    continue;
                }
                endpoints++;

                ContextualReflectionEngine.ScanStats stats = new ContextualReflectionEngine.ScanStats();
                List<IScanIssue> issues = contextualEngine.scanRequest(rr, "Site map sweep", stats);
                paramsTested += stats.params;
                reflected += stats.reflected;
                if (issues != null) {
                    for (IScanIssue issue : issues) {
                        if (reportIssueWithDedup(issue)) {
                            confirmed++;
                        }
                    }
                }
                if (endpoints % 10 == 0) {
                    callbacks.printOutput("[" + PLUGIN_NAME + "] Sweep progress: " + endpoints
                            + " endpoints, " + reflected + " reflected, " + confirmed + " confirmed.");
                }
            }

            final int fe = endpoints, fp = paramsTested, fr = reflected, fc = confirmed,
                    fst = skippedType, fss = skippedScope;
            callbacks.printOutput("[" + PLUGIN_NAME + "] Site map sweep complete: " + fe + " endpoints, "
                    + fp + " parameters, " + fr + " reflected, " + fc + " confirmed "
                    + "(skipped " + fst + " by content-type, " + fss + " out of scope).");
            SwingUtilities.invokeLater(() -> JOptionPane.showMessageDialog(panel,
                    "Site map sweep complete.\n\n"
                    + "Endpoints scanned: " + fe + (fe >= SITEMAP_MAX_ENDPOINTS ? " (capped)" : "") + "\n"
                    + "Parameters tested: " + fp + "\n"
                    + "Reflected: " + fr + "\n"
                    + "Confirmed XSS: " + fc + "\n\n"
                    + "Skipped: " + fst + " (content-type not enabled), "
                    + fss + " (out of scope).\n\n"
                    + (fc > 0 ? "See the Issues tab and Live Results."
                             : "No XSS confirmed; reflected candidates (if any) are in Live Results."),
                    "XSSDetector", JOptionPane.INFORMATION_MESSAGE));
        } catch (Exception e) {
            callbacks.printError("[" + PLUGIN_NAME + "] Site map sweep error: " + e.getMessage());
        }
    }

    /** Content-type filter for the site-map sweep, matching Content Type Management. */
    private boolean contentTypeEnabledForSweep(String ct, java.util.List<String> enabledTypes) {
        if (ct == null || ct.isEmpty()) {
            return false; // no response/type recorded -> nothing to analyse
        }
        String c = ct.toLowerCase();
        if (enabledTypes != null && !enabledTypes.isEmpty()) {
            for (String e : enabledTypes) {
                if (e == null || e.isEmpty()) {
                    continue;
                }
                String le = e.toLowerCase();
                if (c.contains(le) || le.contains(c)) {
                    return true;
                }
            }
            return false;
        }
        return c.contains("html") || c.contains("json") || c.contains("javascript")
                || c.contains("xml") || c.contains("text");
    }

    /** Unique endpoint key so the sweep tests each endpoint once. */
    private String dedupEndpointKey(IRequestInfo ri, java.net.URL url) {
        StringBuilder names = new StringBuilder();
        try {
            java.util.TreeSet<String> ps = new java.util.TreeSet<>();
            for (IParameter p : ri.getParameters()) {
                byte t = p.getType();
                if (t == IParameter.PARAM_URL || t == IParameter.PARAM_BODY
                        || t == IParameter.PARAM_JSON || t == IParameter.PARAM_XML
                        || t == IParameter.PARAM_MULTIPART_ATTR) {
                    ps.add(t + ":" + p.getName());
                }
            }
            names.append(ps);
        } catch (Exception ignored) {
            // key without params
        }
        String path = url.getPath() == null ? "" : url.getPath();
        return ri.getMethod() + " " + url.getHost() + path + " " + names;
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        List<IScanIssue> issues = new ArrayList<>();
        
        try {
            // Skip if scan is paused
            if (scanPaused) {
        return issues;
    }

            // Check if in scope
            if (settings.getScopeOnly() && !callbacks.isInScope(helpers.analyzeRequest(baseRequestResponse).getUrl())) {
        return issues;
    }

            // Perform active XSS detection
            List<IScanIssue> activeIssues = performActiveXSSDetection(baseRequestResponse, insertionPoint);
            if (activeIssues != null && !activeIssues.isEmpty()) {
                issues.addAll(activeIssues);
                callbacks.printOutput("[" + PLUGIN_NAME + "] Active scan found " + activeIssues.size() + " issues");
                // Report with deduplication
                for (IScanIssue issue : activeIssues) {
                    reportIssueWithDedup(issue);
                }
            }

        } catch (Exception e) {
            callbacks.printError("[" + PLUGIN_NAME + "] Error in active scan: " + e.getMessage());
        }

        return issues;
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        // Return -1 to keep existing, 0 to keep both, 1 to keep new only.
        try {
            // Same canonical identity (URL path + XSS class + parameter) => duplicate,
            // regardless of which engine reported it, its wording, or the payload used.
            String existingKey = generateIssueKey(existingIssue);
            String newKey = generateIssueKey(newIssue);

            if (existingKey.equals(newKey)) {
                int existingScore = getSeverityScore(existingIssue.getSeverity());
                int newScore = getSeverityScore(newIssue.getSeverity());
                if (newScore > existingScore) {
                    callbacks.printOutput("[" + PLUGIN_NAME + "] Duplicate (higher severity kept): " + newKey);
                    return 1; // keep the higher-severity report
                }
                callbacks.printOutput("[" + PLUGIN_NAME + "] Duplicate filtered: " + existingKey);
                return -1;
            }
            return 0; // genuinely different issues
        } catch (Exception e) {
            return -1; // on error, keep existing
        }
    }

    /**
     * IMPROVED: Report an issue with built-in deduplication
     * Returns true if issue was reported, false if it was a duplicate
     */
    private boolean reportIssueWithDedup(IScanIssue issue) {
        if (issue == null) return false;

        try {
            // Generate unique key for this issue
            String issueKey = generateIssueKey(issue);

            // THREAD-SAFE: Use add() atomically - returns false if key already exists.
            // This eliminates the race condition where two threads both pass contains()
            // and both report the same issue.
            if (!reportedIssueKeys.add(issueKey)) {
                // Key already existed = duplicate
                if (settings != null && settings.getVerboseLogging()) {
                    callbacks.printOutput("[" + PLUGIN_NAME + "] Duplicate issue skipped: " + issue.getIssueName());
                }
                return false;
            }

            // Clean up old entries if cache is full (after add, so we don't lose the one we just added)
            if (reportedIssueKeys.size() >= MAX_REPORTED_ISSUES_CACHE) {
                // Clear half the cache (simple cleanup strategy)
                int toRemove = MAX_REPORTED_ISSUES_CACHE / 2;
                Iterator<String> iter = reportedIssueKeys.iterator();
                while (iter.hasNext() && toRemove > 0) {
                    String key = iter.next();
                    // Don't remove the key we just added
                    if (!key.equals(issueKey)) {
                        iter.remove();
                        toRemove--;
                    }
                }
            }

            // Report to Burp
            callbacks.addScanIssue(issue);

            // Also surface every reported XSS type in the Live Results view, so the
            // full range of detections (reflected, DOM, postMessage, client-side,
            // stored, template injection, ...) is visible in one place.
            pushIssueToLiveResults(issue);

            callbacks.printOutput("[" + PLUGIN_NAME + "] Issue reported: " + issue.getIssueName());
            return true;
        } catch (Exception e) {
            // Log but don't fail
            if (settings != null && settings.getVerboseLogging()) {
                callbacks.printError("[" + PLUGIN_NAME + "] Error reporting issue: " + e.getMessage());
            }
            return false;
        }
    }

    /**
     * Mirror any reported issue into the Live Results view. The contextual
     * reflected-XSS engine already publishes its own richer finding (with
     * request/response highlights), so those are skipped here to avoid
     * duplicates; every other XSS type is added.
     */
    private void pushIssueToLiveResults(IScanIssue issue) {
        try {
            if (issue == null) {
                return;
            }
            String name = issue.getIssueName() != null ? issue.getIssueName() : "Cross-Site Scripting";
            if (name.equals("Cross-Site Scripting (Reflected)")) {
                return; // already published by ContextualReflectionEngine with full evidence
            }
            String url = issue.getUrl() != null ? issue.getUrl().toString() : "";
            String host = issue.getUrl() != null ? issue.getUrl().getHost() : "";

            byte[] req = null;
            byte[] resp = null;
            String method = "";
            IHttpRequestResponse[] msgs = issue.getHttpMessages();
            if (msgs != null && msgs.length > 0 && msgs[0] != null) {
                req = msgs[0].getRequest();
                resp = msgs[0].getResponse();
                try {
                    method = helpers.analyzeRequest(msgs[0]).getMethod();
                } catch (Exception ignored) {
                    // method is best-effort
                }
            }

            String param = extractParameterFromIssueName(name);
            if (param == null || param.isEmpty()) {
                param = extractParameterFromDetail(issue.getIssueDetail());
            }
            if (param == null) {
                param = "";
            }

            XssFinding f = new XssFinding(
                    normalizeSeverity(issue.getSeverity()), XssFinding.STATUS_CONFIRMED,
                    name, param, method, host, url, "Scanner", "", req, resp);
            FindingStore.get().add(f);
        } catch (Exception ignored) {
            // Live Results mirroring must never affect reporting
        }
    }

    private String normalizeSeverity(String s) {
        if (s == null) {
            return "Medium";
        }
        String v = s.trim().toLowerCase();
        if (v.startsWith("high")) return "High";
        if (v.startsWith("med")) return "Medium";
        if (v.startsWith("low")) return "Low";
        if (v.startsWith("info")) return "Info";
        return "Medium";
    }

    /**
     * Canonical identity of an XSS finding, used for de-duplication across ALL
     * detection engines: (scheme+host[:port]+path) | vulnerability-class | parameter.
     *
     * The issue NAME and the PAYLOAD are deliberately NOT part of the key: one
     * vulnerable (URL, class, parameter) is a single instance no matter how many
     * payload variants confirm it, and no matter which engine or wording reported
     * it. Distinct classes (reflected vs DOM vs postMessage ...) and distinct
     * parameters still produce distinct keys, so genuine separate issues remain
     * separate.
     */
    private String generateIssueKey(IScanIssue issue) {
        StringBuilder key = new StringBuilder();
        if (issue.getUrl() != null) {
            key.append(issue.getUrl().getProtocol()).append("://");
            key.append(issue.getUrl().getHost());
            if (issue.getUrl().getPort() != -1 && issue.getUrl().getPort() != issue.getUrl().getDefaultPort()) {
                key.append(":").append(issue.getUrl().getPort());
            }
            key.append(issue.getUrl().getPath());
        }
        key.append("|").append(canonicalXssClass(issue.getIssueName()));

        // Prefer the parameter from the issue detail (reliable), then the name.
        // Ignore matches that are just the XSS class word (e.g. a trailing
        // "(Reflected)"), which would otherwise split the key.
        String param = extractParameterFromDetail(issue.getIssueDetail());
        if (param == null || param.isEmpty()) {
            param = extractParameterFromIssueName(issue.getIssueName());
        }
        if (param != null) {
            String pl = param.trim().toLowerCase();
            if (!pl.isEmpty() && !isClassWord(pl)) {
                key.append("|").append(pl);
            }
        }
        return key.toString();
    }

    private boolean isClassWord(String s) {
        switch (s) {
            case "reflected":
            case "dom":
            case "stored":
            case "postmessage":
            case "template":
            case "websocket":
            case "client-side":
            case "csp":
            case "xss":
                return true;
            default:
                return false;
        }
    }

    /**
     * Collapse an issue name to a coarse XSS class so that the same vulnerability
     * reported by different engines (with different names/payloads) de-duplicates,
     * while genuinely different vulnerability classes stay distinct.
     */
    private String canonicalXssClass(String issueName) {
        String n = issueName == null ? "" : issueName.toLowerCase();
        if (n.contains("dom")) return "dom";
        if (n.contains("stored")) return "stored";
        if (n.contains("postmessage") || n.contains("post message")) return "postmessage";
        if (n.contains("template")) return "template";
        if (n.contains("websocket")) return "websocket";
        if (n.contains("clobber") || n.contains("prototype pollution") || n.contains("mxss")
                || n.contains("client-side") || n.contains("client side")) return "client-side";
        if (n.contains("csp")) return "csp";
        if (n.contains("reflect")) return "reflected";
        return "xss";
    }

    /**
     * Extract parameter name from issue name
     * Example: "Cross-Site Scripting (XSS) - Reflected - query" -> "query"
     */
    private String extractParameterFromIssueName(String issueName) {
        if (issueName == null) return null;

        // First try: extract parameter from trailing parenthesized group
        // Matches formats like "... (paramName)" at end of string
        int lastOpen = issueName.lastIndexOf('(');
        int lastClose = issueName.lastIndexOf(')');
        if (lastOpen > 0 && lastClose > lastOpen && lastClose == issueName.length() - 1) {
            return issueName.substring(lastOpen + 1, lastClose).trim();
        }

        // Fallback: split by " - " and get last part
        String[] parts = issueName.split(" - ");
        if (parts.length >= 3) {
            return parts[parts.length - 1].trim();
        }
        return null;
    }

    /**
     * Get numeric score for severity comparison
     */
    private int getSeverityScore(String severity) {
        if (severity == null) return 0;
        switch (severity.toLowerCase()) {
            case "critical": return 4;
            case "high": return 3;
            case "medium": return 2;
            case "low": return 1;
            case "information": return 0;
            default: return 0;
        }
    }

    /**
     * Extract the parameter name from issue detail HTML, supporting both the
     * "<b>Parameter:</b> value" and "<b>Parameter</b></td><td>value</td>" formats.
     * Used as a fallback for the dedup key when the issue name omits the parameter.
     */
    private String extractParameterFromDetail(String detail) {
        if (detail == null) return null;
        try {
            java.util.regex.Matcher m = java.util.regex.Pattern.compile(
                "Parameter(?:/Locations)?\\s*:?\\s*</b>\\s*(?:</td>\\s*<td>)?\\s*([^<]{1,80})",
                java.util.regex.Pattern.CASE_INSENSITIVE).matcher(detail);
            if (m.find()) {
                String v = m.group(1).trim();
                if (!v.isEmpty() && !v.equalsIgnoreCase("N/A")) {
                    return v;
                }
            }
        } catch (Exception ignored) {}
        return null;
    }

    /**
     * Extract payload from issue detail HTML
     */
    private String extractPayloadFromDetail(String detail) {
        if (detail == null) return null;

        // Look for payload in <code> tags or after "Payload:" text
        int codeStart = detail.indexOf("<code>");
        int codeEnd = detail.indexOf("</code>");
        if (codeStart >= 0 && codeEnd > codeStart) {
            return detail.substring(codeStart + 6, codeEnd).trim();
        }

        // Look for "Payload:" or "payload:"
        int payloadIdx = detail.toLowerCase().indexOf("payload:");
        if (payloadIdx >= 0) {
            int start = payloadIdx + 8;
            int end = detail.indexOf("<", start);
            if (end < 0) end = Math.min(start + 100, detail.length());
            return detail.substring(start, end).trim();
        }

        return null;
    }

    // ============== REAL-TIME HTTP MONITORING ==============

    /**
     * IHttpListener implementation - Process HTTP messages in REAL-TIME
     * This method is called for ALL HTTP traffic through Burp (Proxy, Repeater, Intruder, etc.)
     */
    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        // Only process responses (not requests)
        if (messageIsRequest) {
            return;
        }

        // Skip if scan is paused
        if (scanPaused) {
            return;
        }

        // Skip if response is null
        if (messageInfo == null || messageInfo.getResponse() == null) {
            return;
        }

        // CRITICAL: Skip excessively large responses (>10MB) to prevent memory issues
        if (messageInfo.getResponse().length > 10 * 1024 * 1024) {
            return;
        }

        // Check scope if enabled
        try {
            if (settings != null && settings.getScopeOnly()) {
                if (!callbacks.isInScope(helpers.analyzeRequest(messageInfo).getUrl())) {
                    return;
                }
            }
        } catch (Exception e) {
            // Continue processing if scope check fails
        }

        // Performance: XSS can only live in textual responses, so skip the whole
        // passive pipeline for images, fonts, CSS, binaries and the like. This
        // sharply cuts background work (threads/memory) while browsing.
        try {
            IResponseInfo ri = helpers.analyzeResponse(messageInfo.getResponse());
            String inferred = ri.getInferredMimeType() != null ? ri.getInferredMimeType().toLowerCase() : "";
            String stated = ri.getStatedMimeType() != null ? ri.getStatedMimeType().toLowerCase() : "";
            String mt = inferred + " " + stated;
            boolean textual = mt.contains("html") || mt.contains("json") || mt.contains("script")
                    || mt.contains("xml") || mt.contains("text") || mt.contains("css");
            if (!textual) {
                return;
            }
        } catch (Exception e) {
            // if we cannot classify, fall through and let the scan decide
        }

        // Get tool name for logging
        String toolName = getToolNameFromFlag(toolFlag);

        // Process based on tool type - run async to avoid blocking
        scanningExecutor.submit(() -> {
            try {
                // Heuristic DOM / client-side realtime detection is DISABLED: it
                // scored risk against thresholds and produced false positives. XSS
                // is reported only by the confirm-based ContextualReflectionEngine
                // (passive reflection feed + live auto-confirmation) below.

                // Real-time behavioural feed: record where input is reflected in
                // this browsed/proxied response (no injection) so the Live Results
                // view fills as you browse. Active scanning upgrades these to
                // Confirmed when verified.
                if (settings != null && settings.getCheckContext() && contextualEngine != null) {
                    // Scope policy follows the "Scan in-scope only" setting:
                    //   - OFF (default): test every parameter you browse, so reflected
                    //     XSS is confirmed just by visiting the page (no Burp scope setup).
                    //   - ON: restricted to in-scope targets only (no probe traffic to
                    //     out-of-scope sites).
                    boolean scopeOk = true;
                    if (settings.getScopeOnly()) {
                        try {
                            scopeOk = callbacks.isInScope(helpers.analyzeRequest(messageInfo).getUrl());
                        } catch (Exception ignored) {
                            scopeOk = false;
                        }
                    }
                    // ALWAYS record where input is reflected (no injection) so the Live
                    // Results view fills with Info/Reflected rows as you browse -- this
                    // is the baseline feed and must never be gated off.
                    contextualEngine.passiveReflections(messageInfo, toolName);

                    // ADDITIONALLY, when auto-confirm is on, actively probe-and-confirm
                    // each reflected parameter. liveConfirm upgrades a row to CONFIRMED
                    // when a payload breaks out, or attaches the full test log (Original +
                    // probe + every Edited payload tried) to the reflected row when it
                    // does not -- so the viewer shows what was tested. This runs on top of
                    // the passive feed, never instead of it.
                    boolean autoTest = settings.getAutoConfirm() && scopeOk
                            && toolFlag != IBurpExtenderCallbacks.TOOL_SCANNER;
                    if (autoTest) {
                        List<IScanIssue> liveIssues = contextualEngine.liveConfirm(messageInfo, toolName);
                        if (liveIssues != null) {
                            for (IScanIssue li : liveIssues) {
                                reportIssueWithDedup(li); // central de-dup, not a direct addScanIssue
                            }
                        }
                    }
                }
            } catch (Exception e) {
                if (settings != null && settings.getVerboseLogging()) {
                    callbacks.printError("[" + PLUGIN_NAME + "] Error in real-time scan: " + e.getMessage());
                }
            }
        });
    }


    /**
     * Check if content type is relevant for XSS scanning
     */
    private boolean isRelevantContentType(String contentType) {
        if (contentType == null) return false;
        String lower = contentType.toLowerCase();
        return lower.contains("html") || lower.contains("javascript") ||
               lower.contains("xml") || lower.contains("text/plain");
    }

    /**
     * Get tool name from tool flag for logging
     */
    private String getToolNameFromFlag(int toolFlag) {
        switch (toolFlag) {
            case IBurpExtenderCallbacks.TOOL_PROXY: return "Proxy";
            case IBurpExtenderCallbacks.TOOL_REPEATER: return "Repeater";
            case IBurpExtenderCallbacks.TOOL_INTRUDER: return "Intruder";
            case IBurpExtenderCallbacks.TOOL_SCANNER: return "Scanner";
            case IBurpExtenderCallbacks.TOOL_SPIDER: return "Spider";
            case IBurpExtenderCallbacks.TOOL_TARGET: return "Target";
            case IBurpExtenderCallbacks.TOOL_EXTENDER: return "Extender";
            default: return "Unknown(" + toolFlag + ")";
        }
    }

    /**
     * Create a DOM XSS issue from detection result
     */
    private IScanIssue createDOMXSSIssue(IHttpRequestResponse messageInfo, EnhancedDOMXSSDetector.DOMXSSResult result) {
        if (issueReporter != null) {
            Map<String, Object> vulnData = new HashMap<>();
            vulnData.put("vulnerabilityType", "DOM XSS");
            vulnData.put("confidence", result.getConfidenceLevel());
            vulnData.put("riskLevel", result.getRiskLevel());
            vulnData.put("sourceSinkAnalysis", result.getSourceSinkAnalysis());
            return issueReporter.createEnhancedXSSIssue(messageInfo, vulnData);
        }
        return null;
    }

    /**
     * Create client-side issue from detection result
     */
    private IScanIssue createClientSideIssue(IHttpRequestResponse messageInfo,
            EnhancedClientSideAttackDetector.ClientSideAttackResult result) {
        if (issueReporter != null) {
            Map<String, Object> vulnData = new HashMap<>();
            vulnData.put("vulnerabilityType", "Client-Side Attack");
            vulnData.put("confidence", result.getConfidenceLevel());
            vulnData.put("riskScore", result.getRiskScore());
            vulnData.put("exploitPOC", result.getExploitPOC());
            return issueReporter.createEnhancedXSSIssue(messageInfo, vulnData);
        }
        return null;
    }

    /**
     * Create issue from Modern XSS Analyzer vulnerability result
     * Handles: DOM Clobbering, mXSS, Prototype Pollution, PostMessage XSS,
     * Service Worker, Import Maps, Trusted Types, GraphQL XSS, WebSocket XSS
     */
    private IScanIssue createModernXSSIssue(IHttpRequestResponse messageInfo,
            ModernXSSAnalyzer.VulnerabilityInfo vuln) {
        try {
            IRequestInfo reqInfo = helpers.analyzeRequest(messageInfo);
            java.net.URL url = reqInfo.getUrl();

            // Map severity to Burp severity levels
            String burpSeverity;
            switch (vuln.severity.toLowerCase()) {
                case "critical": burpSeverity = "High"; break;
                case "high": burpSeverity = "High"; break;
                case "medium": burpSeverity = "Medium"; break;
                case "low": burpSeverity = "Low"; break;
                default: burpSeverity = "Information"; break;
            }

            // Map confidence to Burp confidence levels
            String burpConfidence;
            if (vuln.confidence >= 80) {
                burpConfidence = "Certain";
            } else if (vuln.confidence >= 60) {
                burpConfidence = "Firm";
            } else {
                burpConfidence = "Tentative";
            }

            // Build professional issue detail
            StringBuilder detail = new StringBuilder();
            detail.append("<h3>").append(escapeHtml(vuln.type)).append("</h3>\n");
            detail.append("<table border='1' cellpadding='5'>\n");
            detail.append("<tr><td><b>Severity</b></td><td>").append(vuln.severity).append("</td></tr>\n");
            detail.append("<tr><td><b>Confidence</b></td><td>").append(String.format("%.0f%%", vuln.confidence)).append("</td></tr>\n");
            detail.append("<tr><td><b>HTTP Method</b></td><td>").append(vuln.httpMethod != null ? vuln.httpMethod : reqInfo.getMethod()).append("</td></tr>\n");
            detail.append("<tr><td><b>Parameter</b></td><td>").append(escapeHtml(vuln.parameter)).append("</td></tr>\n");
            if (vuln.paramType != null && !vuln.paramType.isEmpty()) {
                detail.append("<tr><td><b>Parameter Location</b></td><td>").append(escapeHtml(vuln.paramType)).append("</td></tr>\n");
            }
            if (vuln.sinkType != null && !vuln.sinkType.isEmpty()) {
                detail.append("<tr><td><b>Sink</b></td><td><code>").append(escapeHtml(vuln.sinkType)).append("</code></td></tr>\n");
            }
            if (vuln.targetUrl != null && !vuln.targetUrl.isEmpty()) {
                detail.append("<tr><td><b>Target URL</b></td><td>").append(escapeHtml(vuln.targetUrl)).append("</td></tr>\n");
            }
            if (vuln.messageKeys != null && !vuln.messageKeys.isEmpty()) {
                detail.append("<tr><td><b>Message Keys</b></td><td><code>").append(escapeHtml(vuln.messageKeys)).append("</code></td></tr>\n");
            }
            detail.append("</table>\n\n");

            detail.append("<h4>Description</h4>\n");
            detail.append("<p>").append(escapeHtml(vuln.description)).append("</p>\n\n");

            if (vuln.evidence != null && !vuln.evidence.isEmpty()) {
                detail.append("<h4>Evidence (Code Snippet)</h4>\n");
                detail.append("<pre>").append(escapeHtml(vuln.evidence)).append("</pre>\n\n");
            }

            if (vuln.handlerCode != null && !vuln.handlerCode.isEmpty()) {
                detail.append("<h4>Handler Code</h4>\n");
                detail.append("<pre>").append(escapeHtml(vuln.handlerCode)).append("</pre>\n\n");
            }

            // Gate exploit PoC and reproduction steps behind exploitGeneration setting
            boolean showExploits = settings == null || Boolean.TRUE.equals(settings.getExploitGeneration());
            if (showExploits) {
                detail.append("<h4>Proof of Concept Payload</h4>\n");
                detail.append("<pre>").append(escapeHtml(vuln.payload)).append("</pre>\n\n");

                // Steps to Reproduce section - ACTIONABLE, not template text
                detail.append("<h4>Steps to Reproduce</h4>\n");
                detail.append("<ol>\n");
                String method = vuln.httpMethod != null ? vuln.httpMethod : reqInfo.getMethod();
                String targetDisplay = vuln.targetUrl != null ? vuln.targetUrl : url.toString();

                if (vuln.paramType != null && vuln.paramType.startsWith("Client-side")) {
                    // Client-side vulnerability (PostMessage, WebSocket, etc.)
                    detail.append("<li>Open the target page in a browser: <code>").append(escapeHtml(targetDisplay)).append("</code></li>\n");
                    detail.append("<li>This is a <b>client-side</b> vulnerability (").append(escapeHtml(vuln.paramType)).append("). ");
                    detail.append("Create an attacker-controlled HTML page with the PoC payload above.</li>\n");
                    if (vuln.sinkType != null && !vuln.sinkType.isEmpty()) {
                        detail.append("<li>The message data flows to the <code>").append(escapeHtml(vuln.sinkType)).append("</code> sink in the handler.</li>\n");
                    }
                    detail.append("<li>Open the attacker page in the same browser session to trigger the exploit.</li>\n");
                    detail.append("<li>Verify JavaScript execution in the target page context (check browser console).</li>\n");
                } else if (vuln.parameter != null && !vuln.parameter.trim().isEmpty()
                        && !"Multiple".equalsIgnoreCase(vuln.parameter.trim())
                        && !vuln.parameter.toUpperCase().contains("N/A")) {
                    // Server-side reflected vulnerability with a specific parameter
                    detail.append("<li>Send a <b>").append(method).append("</b> request to: <code>").append(escapeHtml(targetDisplay)).append("</code></li>\n");
                    detail.append("<li>Set the <b>").append(escapeHtml(vuln.parameter)).append("</b> parameter");
                    if (vuln.paramType != null && !vuln.paramType.isEmpty()) {
                        detail.append(" (in <b>").append(escapeHtml(vuln.paramType)).append("</b>)");
                    }
                    detail.append(" to the PoC payload above.</li>\n");
                    if (vuln.sinkType != null && !vuln.sinkType.isEmpty()) {
                        detail.append("<li>The reflected value reaches the <code>").append(escapeHtml(vuln.sinkType)).append("</code> sink in JavaScript.</li>\n");
                    }
                    detail.append("<li>Observe the response - verify the payload executes in the browser.</li>\n");
                } else {
                    // Generic fallback
                    detail.append("<li>Navigate to: <code>").append(escapeHtml(targetDisplay)).append("</code></li>\n");
                    detail.append("<li>Review the evidence above to identify the vulnerable code pattern.</li>\n");
                    detail.append("<li>Test with the PoC payload to confirm exploitability.</li>\n");
                }
                detail.append("</ol>\n\n");
            }

            // No static remediation/background text: issues carry only live,
            // dynamic evidence (description, code snippet, PoC, steps).

            return new IScanIssue() {
                @Override
                public java.net.URL getUrl() { return url; }

                @Override
                public String getIssueName() {
                    // Clean, professional name: "Cross-Site Scripting (<vector>)"
                    // optionally with sink/parameter, but never the ugly "(N/A ...)" suffix.
                    String issueName = "Cross-Site Scripting (" + vuln.type + ")";
                    if (vuln.sinkType != null && !vuln.sinkType.isEmpty()) {
                        issueName += " via " + vuln.sinkType;
                    }
                    if (vuln.parameter != null && !vuln.parameter.trim().isEmpty()
                            && !vuln.parameter.toUpperCase().contains("N/A")
                            && !"Multiple".equalsIgnoreCase(vuln.parameter.trim())) {
                        issueName += " - parameter '" + vuln.parameter + "'";
                    }
                    return issueName;
                }

                @Override
                public int getIssueType() { return 0x00500100; } // Custom XSS type

                @Override
                public String getSeverity() { return burpSeverity; }

                @Override
                public String getConfidence() { return burpConfidence; }

                @Override
                public String getIssueBackground() { return ""; }

                @Override
                public String getRemediationBackground() { return ""; }

                @Override
                public String getIssueDetail() { return detail.toString(); }

                @Override
                public String getRemediationDetail() { return ""; }

                @Override
                public IHttpRequestResponse[] getHttpMessages() {
                    return new IHttpRequestResponse[] { messageInfo };
                }

                @Override
                public IHttpService getHttpService() { return messageInfo.getHttpService(); }
            };
        } catch (Exception e) {
            callbacks.printError("[" + PLUGIN_NAME + "] Error creating Modern XSS issue: " + e.getMessage());
            return null;
        }
    }

    /**
     * Get background information for modern XSS vulnerability types
     */
    private String getModernXSSBackground(String vulnType) {
        String lowerType = vulnType.toLowerCase();

        if (lowerType.contains("dom clobbering")) {
            return "<p><b>DOM Clobbering</b> is an attack where HTML elements with specific <code>id</code> or " +
                   "<code>name</code> attributes can override JavaScript variables and DOM properties. " +
                   "When JavaScript code accesses window or document properties without proper validation, " +
                   "attackers can inject HTML elements to control these values and potentially achieve XSS.</p>" +
                   "<p>Example: <code>&lt;form name=\"config\"&gt;&lt;input name=\"url\" value=\"javascript:alert(1)\"&gt;&lt;/form&gt;</code></p>";
        } else if (lowerType.contains("mxss") || lowerType.contains("mutation")) {
            return "<p><b>Mutation XSS (mXSS)</b> exploits differences between HTML parsing and serialization. " +
                   "When content is parsed, modified, and then re-serialized (e.g., via innerHTML), the output " +
                   "can differ from the input in ways that bypass sanitizers. Context-switching elements like " +
                   "&lt;noscript&gt;, &lt;style&gt;, and SVG/MathML are common mXSS vectors.</p>" +
                   "<p>Modern sanitizers like DOMPurify have specific mXSS protections that should be enabled.</p>";
        } else if (lowerType.contains("prototype pollution")) {
            return "<p><b>Prototype Pollution XSS</b> occurs when attackers can modify JavaScript object prototypes " +
                   "through vulnerable object merge/extend operations. If polluted properties reach DOM sinks like " +
                   "innerHTML, they can achieve XSS. This is common with libraries like lodash.merge() or jQuery.extend().</p>" +
                   "<p>Test payloads typically use <code>__proto__</code> or <code>constructor.prototype</code>.</p>";
        } else if (lowerType.contains("postmessage")) {
            return "<p><b>PostMessage XSS</b> occurs when web applications process postMessage events without " +
                   "properly validating the message origin. Attackers can send malicious messages from their own " +
                   "pages to trigger XSS in vulnerable message handlers.</p>" +
                   "<p>Always validate <code>event.origin</code> against a strict allowlist, not using " +
                   "contains/startsWith/endsWith which can be bypassed.</p>";
        } else if (lowerType.contains("service worker")) {
            return "<p><b>Service Worker Vulnerabilities</b> can lead to persistent XSS through cache poisoning " +
                   "or complete site takeover if the Service Worker script URL is injectable. Service Workers " +
                   "can intercept all network requests, making them high-value targets.</p>";
        } else if (lowerType.contains("import map")) {
            return "<p><b>Import Maps Injection</b> allows attackers to redirect JavaScript module imports to " +
                   "malicious URLs. If import map content is controllable by user input, attackers can make " +
                   "the application load arbitrary JavaScript.</p>";
        } else if (lowerType.contains("trusted types")) {
            return "<p><b>Trusted Types Bypass</b> vulnerabilities occur when the Trusted Types policy is too " +
                   "permissive (e.g., returns input unchanged) or when some sinks are not covered by the policy. " +
                   "Trusted Types is a browser security feature designed to prevent DOM XSS.</p>";
        } else if (lowerType.contains("graphql")) {
            return "<p><b>GraphQL XSS</b> can occur when GraphQL query results are rendered in HTML without " +
                   "proper encoding. The flexible query nature of GraphQL may allow attackers to inject " +
                   "malicious content through mutation inputs or query parameters.</p>";
        } else if (lowerType.contains("websocket")) {
            return "<p><b>WebSocket XSS</b> occurs when WebSocket message content is used in DOM sinks like " +
                   "innerHTML without sanitization. If attackers can inject messages (e.g., through CSWSH) " +
                   "or control the WebSocket URL, they can achieve XSS.</p>";
        }

        return "<p>This is a modern XSS attack vector that exploits advanced browser features or JavaScript APIs. " +
               "Traditional XSS filters may not protect against these attacks.</p>";
    }

    /**
     * Escape HTML special characters for safe display
     */
    private String escapeHtml(String input) {
        if (input == null) return "";
        return input.replace("&", "&amp;")
                   .replace("<", "&lt;")
                   .replace(">", "&gt;")
                   .replace("\"", "&quot;")
                   .replace("'", "&#39;");
    }

    // ============== EXTENSION LIFECYCLE ==============

    /**
     * IExtensionStateListener implementation - Called when extension is unloaded
     */
    @Override
    public void extensionUnloaded() {
        callbacks.printOutput("[" + PLUGIN_NAME + "] Extension unloading - cleaning up...");

        // Stop accepting new tasks
        scanPaused = true;

        // Shutdown executor service gracefully
        if (scanningExecutor != null) {
            try {
                scanningExecutor.shutdown();
                if (!scanningExecutor.awaitTermination(5, TimeUnit.SECONDS)) {
                    scanningExecutor.shutdownNow();
                    callbacks.printOutput("[" + PLUGIN_NAME + "] Forced shutdown of scanning threads");
                }
            } catch (InterruptedException e) {
                scanningExecutor.shutdownNow();
                Thread.currentThread().interrupt();
            }
        }

        // Clear caches and tracking data
        confirmedVulnerabilities.clear();
        parameterTestHistory.clear();

        callbacks.printOutput("[" + PLUGIN_NAME + "] Extension unloaded successfully");
    }

    
    /**
     * Perform active XSS detection with all engines fully integrated
     */
    private List<IScanIssue> performActiveXSSDetection(IHttpRequestResponse requestResponse, IScannerInsertionPoint insertionPoint) {
        List<IScanIssue> issues = new ArrayList<>();
        // Contextual-engine findings are already double-confirmed by a live probe,
        // so they bypass the heuristic post-filter (Step 4) and are appended last.
        List<IScanIssue> contextualConfirmed = new ArrayList<>();

        try {
            // Step 0: Contextual reflection engine -- per-character break-out
            // analysis with full context classification (HTML, attribute,
            // JS string/template, event handler, URL, CSS) and JSON/JSONP support.
            if (settings.getCheckContext() && contextualEngine != null) {
                try {
                    List<IScanIssue> contextualIssues = contextualEngine.scan(requestResponse, insertionPoint);
                    if (contextualIssues != null) {
                        contextualConfirmed.addAll(contextualIssues);
                    }
                } catch (Exception e) {
                    callbacks.printError("[" + PLUGIN_NAME + "] Error in contextual reflection engine: " + e.getMessage());
                }
            }

            // The ContextualReflectionEngine above is the single reflected-XSS
            // authority -- it confirms a real break-out before reporting.

            // Step 3: AI Context Analyzer (if enabled)
            if (settings.getCheckContext() && aiAnalyzer != null) {
                try {
                    // Perform AI analysis using insertion point context
                    // Parameters: requestResponse, parameter name, payload (base value), matches
                    String baseValue = insertionPoint.getBaseValue();
                    AIContextAnalyzer.AIAnalysisResult aiResult = aiAnalyzer.analyzeWithAI(
                        requestResponse,
                        insertionPoint.getInsertionPointName(),
                        baseValue != null ? baseValue : "",
                        null  // No specific matches at this point
                    );
                    if (aiResult != null && aiResult.getConfidence() > 70.0) {
                        // High confidence AI analysis - log insights
                        if (settings.getVerboseLogging()) {
                            callbacks.printOutput("[" + PLUGIN_NAME + "] AI Analysis: " +
                                "Confidence=" + aiResult.getConfidence() + "%" +
                                ", Type=" + aiResult.getVulnerabilityType() +
                                ", Difficulty=" + aiResult.getExploitationDifficulty());
                        }
                    }
                } catch (Exception e) {
                    callbacks.printError("[" + PLUGIN_NAME + "] Error in AI context analysis: " + e.getMessage());
                }
            }

        } catch (Exception e) {
            callbacks.printError("[" + PLUGIN_NAME + "] Error in active XSS detection: " + e.getMessage());
        }

        // Append live-confirmed contextual findings (not subject to the heuristic
        // post-filter) so genuine, verified reflections are never dropped.
        if (!contextualConfirmed.isEmpty()) {
            issues.addAll(contextualConfirmed);
        }

        return issues;
    }

    /**
     * Create comprehensive vulnerability data from detection results
     */
    private Map<String, Object> createVulnerabilityData(Object result) {
        Map<String, Object> data = new HashMap<>();
        
        try {
            if (result instanceof EnhancedDOMXSSDetector.DOMXSSResult) {
                EnhancedDOMXSSDetector.DOMXSSResult domResult = (EnhancedDOMXSSDetector.DOMXSSResult) result;
                data.put("vulnerabilityType", "DOM XSS");
                data.put("confidence", domResult.getConfidenceLevel());
                data.put("riskLevel", domResult.getRiskLevel());
                // CRITICAL FIX: Use uppercase keys to match isVulnerabilityTrulyExploitable validation
                String testPayload = domResult.getTestPayload();
                String testRequestStr = domResult.getTestRequest();
                String testResponseStr = domResult.getTestResponse();
                byte[] testRequest = testRequestStr != null ? testRequestStr.getBytes(StandardCharsets.UTF_8) : null;
                byte[] testResponse = testResponseStr != null ? testResponseStr.getBytes(StandardCharsets.UTF_8) : null;
                
                data.put("payload", testPayload != null ? testPayload : "");
                if (testRequest != null) {
                    data.put("TEST_REQUEST", testRequest);
                }
                if (testResponse != null) {
                    data.put("TEST_RESPONSE", testResponse);
                }
                // Also keep lowercase for backward compatibility
                data.put("testPayload", testPayload);
                data.put("testRequest", testRequest);
                data.put("testResponse", testResponse);
                
                // CRITICAL: For DOM XSS, confirmation is based on source-sink analysis, not payload injection
                // If we have valid source-sink flow with high confidence, mark as confirmed
                boolean hasSourceSink = domResult.getSourceSinkAnalysis() != null && 
                                       !domResult.getSourceSinkAnalysis().trim().isEmpty();
                boolean hasDataFlows = domResult.getDataFlows() != null && !domResult.getDataFlows().isEmpty();
                boolean hasSources = domResult.getDetectedSources() != null && !domResult.getDetectedSources().isEmpty();
                boolean hasSinks = domResult.getDetectedSinks() != null && !domResult.getDetectedSinks().isEmpty();
                boolean highConfidence = "Certain".equals(domResult.getConfidenceLevel()) || "Firm".equals(domResult.getConfidenceLevel());
                
                // Confirm if we have source-sink evidence AND high confidence
                boolean isConfirmed = (hasSourceSink || hasDataFlows || (hasSources && hasSinks)) && highConfidence;
                data.put("CONFIRMED_XSS", isConfirmed);
                // CRITICAL: Confidence score based on actual evidence, not simulated
                // Calculate from vulnerability score and confidence level
                int vulnScore = domResult.getVulnerabilityScore();
                String confLevel = domResult.getConfidenceLevel();
                double confidenceScore = 0.0;
                if ("Certain".equals(confLevel) && vulnScore >= 80) {
                    confidenceScore = 95.0;
                } else if ("Firm".equals(confLevel) && vulnScore >= 60) {
                    confidenceScore = 80.0;
                } else if (vulnScore >= 70) {
                    confidenceScore = 70.0; // High vulnerability score = firm confidence
                } else if (vulnScore >= 50) {
                    confidenceScore = 60.0; // Medium vulnerability score = tentative confidence
                } else {
                    confidenceScore = 0.0; // Low score = no confidence
                }
                data.put("CONFIDENCE_SCORE", confidenceScore);
                data.put("XSS_SCORE", domResult.getVulnerabilityScore());
                data.put("ENHANCED_CONTEXT", "DOM-based XSS - Client-side vulnerability");
                data.put("SCAN_TYPE", "DOM"); // Mark as DOM scan type for proper validation

                // Dynamic reproduction material (used by Burp-safe reporting)
                if (domResult.getExploitPOC() != null && !domResult.getExploitPOC().trim().isEmpty()) {
                    data.put("EXPLOIT_POC", domResult.getExploitPOC());
                }
                if (domResult.getReproductionSteps() != null && !domResult.getReproductionSteps().trim().isEmpty()) {
                    data.put("REPRODUCTION_STEPS", domResult.getReproductionSteps());
                }
                if (domResult.getSourceSinkAnalysis() != null && !domResult.getSourceSinkAnalysis().trim().isEmpty()) {
                    data.put("SOURCE_SINK_ANALYSIS", domResult.getSourceSinkAnalysis());
                }
                if (domResult.getBrowserExploitCode() != null && !domResult.getBrowserExploitCode().trim().isEmpty()) {
                    data.put("BROWSER_EXPLOIT_CODE", domResult.getBrowserExploitCode());
                }

                // Make paramName meaningful for client-side findings (required for reporting)
                String domParamName = "DOM XSS";
                try {
                    if (domResult.getDataFlows() != null && !domResult.getDataFlows().isEmpty()) {
                        EnhancedDOMXSSDetector.DataFlow flow = domResult.getDataFlows().get(0);
                        if (flow != null && flow.getSource() != null && flow.getSink() != null) {
                            String s = flow.getSource().getName();
                            String k = flow.getSink().getName();
                            if (s != null && k != null) domParamName = "DOM XSS: " + s + " -> " + k;
                        }
                    } else if (domResult.getDetectedSinks() != null && !domResult.getDetectedSinks().isEmpty()) {
                        String k = domResult.getDetectedSinks().get(0).getName();
                        if (k != null && !k.trim().isEmpty()) domParamName = "DOM XSS sink: " + k;
                    } else if (domResult.getDetectedSources() != null && !domResult.getDetectedSources().isEmpty()) {
                        String s = domResult.getDetectedSources().get(0).getName();
                        if (s != null && !s.trim().isEmpty()) domParamName = "DOM XSS source: " + s;
                    }
                } catch (Exception ignored) {}
                data.put("paramName", domParamName);

                // Terms to highlight in response when payload is not present in the request/response
                List<String> highlightTerms = new ArrayList<>();
                try {
                    if (domResult.getDetectedSinks() != null) {
                        for (EnhancedDOMXSSDetector.DOMSink s : domResult.getDetectedSinks()) {
                            if (s != null && s.getName() != null && !s.getName().trim().isEmpty()) {
                                highlightTerms.add(s.getName());
                                if (highlightTerms.size() >= 5) break;
                            }
                        }
                    }
                    if (domResult.getDetectedSources() != null && highlightTerms.size() < 5) {
                        for (EnhancedDOMXSSDetector.DOMSource s : domResult.getDetectedSources()) {
                            if (s != null && s.getName() != null && !s.getName().trim().isEmpty()) {
                                highlightTerms.add(s.getName());
                                if (highlightTerms.size() >= 5) break;
                            }
                        }
                    }
                } catch (Exception ignored) {}
                if (!highlightTerms.isEmpty()) {
                    data.put("HIGHLIGHT_TERMS", highlightTerms);
                }
                
                // Add DOM-specific data
                if (domResult.getDetectedSources() != null && !domResult.getDetectedSources().isEmpty()) {
                    data.put("DOM_SOURCES", domResult.getDetectedSources().size());
                }
                if (domResult.getDetectedSinks() != null && !domResult.getDetectedSinks().isEmpty()) {
                    data.put("DOM_SINKS", domResult.getDetectedSinks().size());
                }
                if (domResult.getDataFlows() != null && !domResult.getDataFlows().isEmpty()) {
                    data.put("DATA_FLOWS", domResult.getDataFlows().size());
                }
                
            } else if (result instanceof EnhancedClientSideAttackDetector.ClientSideAttackResult) {
                EnhancedClientSideAttackDetector.ClientSideAttackResult clientResult = (EnhancedClientSideAttackDetector.ClientSideAttackResult) result;
                data.put("vulnerabilityType", "Client-Side XSS");
                data.put("confidence", clientResult.getConfidenceLevel());
                data.put("riskLevel", clientResult.getRiskLevel());
                // CRITICAL FIX: Use uppercase keys to match isVulnerabilityTrulyExploitable validation
                String testPayload = clientResult.getTestPayload();
                String testRequestStr = clientResult.getTestRequest();
                String testResponseStr = clientResult.getTestResponse();
                byte[] testRequest = testRequestStr != null ? testRequestStr.getBytes(StandardCharsets.UTF_8) : null;
                byte[] testResponse = testResponseStr != null ? testResponseStr.getBytes(StandardCharsets.UTF_8) : null;
                
                data.put("payload", testPayload != null ? testPayload : "");
                if (testRequest != null) {
                    data.put("TEST_REQUEST", testRequest);
                }
                if (testResponse != null) {
                    data.put("TEST_RESPONSE", testResponse);
                }
                // Also keep lowercase for backward compatibility
                data.put("testPayload", testPayload);
                data.put("testRequest", testRequest);
                data.put("testResponse", testResponse);
                
                // CRITICAL: For client-side attacks, confirmation is based on source-sink correlation, not payload injection
                // Check for source-sink correlation evidence (TAINT_FLOW patterns in ModernAPIAnalysis)
                boolean hasSourceSinkCorrelation = false;
                String sourceSinkAnalysis = "";
                try {
                    if (clientResult.getModernAPIAnalysis() != null && clientResult.getModernAPIAnalysis().getDetectedPatterns() != null) {
                        List<String> patterns = clientResult.getModernAPIAnalysis().getDetectedPatterns();
                        for (String pattern : patterns) {
                            if (pattern != null && pattern.startsWith("TAINT_FLOW:")) {
                                hasSourceSinkCorrelation = true;
                                if (sourceSinkAnalysis.isEmpty()) {
                                    sourceSinkAnalysis = "Source-Sink Correlation Detected:\n";
                                }
                                sourceSinkAnalysis += "- " + pattern + "\n";
                            }
                        }
                    }
                } catch (Exception ignored) {}
                
                // Also check if vulnerable flag is set (which requires correlationScore >= 30 or high-risk vectors)
                boolean isVulnerable = clientResult.isVulnerable();
                boolean hasHighRiskScore = clientResult.getRiskScore() >= 70;
                String confidenceLevel = clientResult.getConfidenceLevel();
                boolean highConfidence = "High".equals(confidenceLevel) || "Certain".equals(confidenceLevel) || "Firm".equals(confidenceLevel);
                
                // CRITICAL FIX: Don't mark as CONFIRMED based solely on pattern matching
                // Pattern matching (proximity of sources/sinks) is NOT proof of actual data flow
                // Require STRONG evidence: either actual payload injection OR very high correlation score with multiple taint flows
                // Just having sources and sinks nearby doesn't mean they're connected
                // CRITICAL: CSP misconfiguration alone is NEVER exploitable XSS
                
                // CRITICAL: Check if this is ONLY CSP misconfiguration (not exploitable XSS)
                boolean isOnlyCSPMisconfig = clientResult.getCspAnalysis() != null && 
                                            clientResult.getCspAnalysis().getRiskScore() > 0 &&
                                            clientResult.getPostMessageAnalysis().getRiskScore() < 25 &&
                                            clientResult.getWebSocketAnalysis().getRiskScore() < 25 &&
                                            clientResult.getTemplateInjectionAnalysis().getRiskScore() < 25 &&
                                            clientResult.getPrototypePollutionAnalysis().getRiskScore() < 25;
                
                boolean isConfirmed = false;
                try {
                    // CRITICAL: Never confirm CSP misconfiguration alone
                    if (isOnlyCSPMisconfig) {
                        data.put("CONFIRMED_XSS", false);
                        isConfirmed = false;
                        callbacks.printOutput("[XSSDetector] CSP misconfiguration detected - NOT marking as CONFIRMED_XSS (informational only)");
                    } else {
                        // Count actual taint flows (not just pattern matches)
                        if (clientResult.getModernAPIAnalysis() != null && clientResult.getModernAPIAnalysis().getDetectedPatterns() != null) {
                            // CRITICAL FIX: Count UNIQUE taint flows (deduplicate)
                            Set<String> uniqueTaintFlows = new HashSet<>();
                            for (String pattern : clientResult.getModernAPIAnalysis().getDetectedPatterns()) {
                                if (pattern != null && pattern.startsWith("TAINT_FLOW:")) {
                                    uniqueTaintFlows.add(pattern); // Set automatically deduplicates
                                }
                            }
                            int taintFlowCount = uniqueTaintFlows.size();
                            
                            // Require multiple taint flows OR very high risk score to reduce false positives
                            // Single taint flow in proximity is not enough proof
                            boolean hasMultipleTaintFlows = taintFlowCount >= 3;
                            boolean hasVeryHighRisk = clientResult.getRiskScore() >= 85;
                            
                            // CRITICAL: Also require that the issue is actually vulnerable (not just CSP misconfig)
                            // AND the vulnerable flag is set (which means correlationScore >= 30 or high-risk vectors)
                            isConfirmed = !isOnlyCSPMisconfig && 
                                        hasSourceSinkCorrelation && 
                                        (hasMultipleTaintFlows || hasVeryHighRisk) && 
                                        isVulnerable && 
                                        (highConfidence || hasHighRiskScore);
                            data.put("CONFIRMED_XSS", isConfirmed);
                            
                            if (!isConfirmed && hasSourceSinkCorrelation) {
                                callbacks.printOutput("[XSSDetector] Client-side pattern detected but NOT confirmed - insufficient evidence (unique taint flows: " + taintFlowCount + ", risk: " + clientResult.getRiskScore() + ", vulnerable: " + isVulnerable + ")");
                            }
                        } else {
                            // No taint flows detected - definitely not confirmed
                            data.put("CONFIRMED_XSS", false);
                        }
                    }
                } catch (Exception e) {
                    // On error, don't confirm
                    data.put("CONFIRMED_XSS", false);
                    isConfirmed = false;
                }
                
                // CRITICAL: Calculate confidence score based on REAL evidence, not simulated
                // Base confidence from actual risk score
                int riskScore = clientResult.getRiskScore();
                double confidenceScore = 0.0;
                
                // Only set confidence if we have actual evidence
                if (riskScore >= 70) {
                    confidenceScore = 90.0; // High risk = high confidence
                } else if (riskScore >= 50) {
                    confidenceScore = 70.0; // Medium risk = medium confidence
                } else if (riskScore >= 30) {
                    confidenceScore = 50.0; // Low risk = low confidence
                } else {
                    confidenceScore = 0.0; // Very low risk = no confidence
                }
                
                // Boost for source-sink correlation (real evidence)
                if (hasSourceSinkCorrelation && riskScore >= 50) {
                    confidenceScore = Math.min(100.0, confidenceScore + 10.0);
                }
                
                // Boost for confirmed XSS (requires actual test request/response)
                if (isConfirmed && riskScore >= 70) {
                    confidenceScore = Math.min(100.0, confidenceScore + 5.0);
                }
                
                data.put("CONFIDENCE_SCORE", confidenceScore);
                data.put("XSS_SCORE", (double) clientResult.getRiskScore());
                data.put("ENHANCED_CONTEXT", "Client-side injection attack - Multiple vectors detected");
                data.put("SCAN_TYPE", "Client-Side Attack"); // Mark as Client-Side scan type for proper validation

                // Dynamic reproduction material (used by Burp-safe reporting)
                if (clientResult.getExploitPOC() != null && !clientResult.getExploitPOC().trim().isEmpty()) {
                    data.put("EXPLOIT_POC", clientResult.getExploitPOC());
                }
                if (clientResult.getReproductionSteps() != null && !clientResult.getReproductionSteps().trim().isEmpty()) {
                    data.put("REPRODUCTION_STEPS", clientResult.getReproductionSteps());
                }
                
                // CRITICAL: Store source-sink analysis for reporting
                if (!sourceSinkAnalysis.isEmpty()) {
                    data.put("SOURCE_SINK_ANALYSIS", sourceSinkAnalysis);
                } else {
                    // Fallback: Generate source-sink analysis from detected patterns
                    try {
                        if (clientResult.getModernAPIAnalysis() != null && clientResult.getModernAPIAnalysis().getDetectedPatterns() != null) {
                            List<String> analysisLines = new ArrayList<>();
                            analysisLines.add("Client-side risk score: " + clientResult.getRiskScore());
                            analysisLines.add("Vulnerable: " + isVulnerable);
                            if (hasSourceSinkCorrelation) {
                                analysisLines.add("Source-sink correlation: DETECTED");
                            }
                            List<String> patterns = clientResult.getModernAPIAnalysis().getDetectedPatterns();
                            for (String pattern : patterns) {
                                if (pattern != null && !pattern.trim().isEmpty()) {
                                    analysisLines.add("Pattern: " + pattern);
                                }
                            }
                            if (!analysisLines.isEmpty()) {
                                data.put("SOURCE_SINK_ANALYSIS", String.join("\n", analysisLines));
                            }
                        }
                    } catch (Exception ignored) {}
                }

                // Make paramName meaningful for client-side findings (required for reporting)
                String clientParamName = "Client-side issue";
                try {
                    if (clientResult.getCspAnalysis() != null && clientResult.getCspAnalysis().getRiskScore() > 0) {
                        // isOnlyCSPMisconfig already calculated above
                        if (isOnlyCSPMisconfig) {
                            // CSP misconfiguration alone - mark as informational, not exploitable
                            clientParamName = "CSP misconfiguration (informational)";
                            // CRITICAL: Never mark CSP misconfiguration as CONFIRMED_XSS
                            data.put("CONFIRMED_XSS", false);
                            data.put("CONFIDENCE_SCORE", 30.0); // Low confidence - informational only
                            callbacks.printOutput("[XSSDetector] CSP misconfiguration detected - marking as informational (not exploitable XSS)");
                        } else {
                            clientParamName = "CSP misconfiguration + client-side vectors";
                        }
                    } else if (clientResult.getPostMessageAnalysis() != null && clientResult.getPostMessageAnalysis().getRiskScore() > 0) {
                        clientParamName = "postMessage handler";
                    } else if (clientResult.getWebSocketAnalysis() != null && clientResult.getWebSocketAnalysis().getRiskScore() > 0) {
                        clientParamName = "WebSocket usage";
                    } else if (clientResult.getTemplateInjectionAnalysis() != null && clientResult.getTemplateInjectionAnalysis().getRiskScore() > 0) {
                        clientParamName = "Client-side template injection";
                    } else if (clientResult.getPrototypePollutionAnalysis() != null && clientResult.getPrototypePollutionAnalysis().getRiskScore() > 0) {
                        clientParamName = "Prototype pollution";
                    } else if (clientResult.getModernAPIAnalysis() != null && clientResult.getModernAPIAnalysis().getRiskScore() > 0) {
                        clientParamName = "Modern browser APIs";
                    } else if (clientResult.getWebComponentsAnalysis() != null && clientResult.getWebComponentsAnalysis().getRiskScore() > 0) {
                        clientParamName = "Web Components";
                    }
                } catch (Exception ignored) {}
                data.put("paramName", clientParamName);

                // Terms to highlight in response when payload is not present in the request/response
                List<String> highlightTerms = new ArrayList<>();
                try {
                    if (clientResult.getCspAnalysis() != null && clientResult.getCspAnalysis().getRiskScore() > 0) {
                        highlightTerms.add("Content-Security-Policy");
                        highlightTerms.add("content-security-policy");
                        highlightTerms.add("unsafe-inline");
                        highlightTerms.add("unsafe-eval");
                    }
                    if (clientResult.getPostMessageAnalysis() != null && clientResult.getPostMessageAnalysis().getRiskScore() > 0) {
                        highlightTerms.add("postMessage");
                        highlightTerms.add("addEventListener('message'");
                        highlightTerms.add("addEventListener(\"message\"");
                        highlightTerms.add("onmessage");
                        highlightTerms.add("event.data");
                        highlightTerms.add("message.data");
                    }
                    if (clientResult.getWebSocketAnalysis() != null && clientResult.getWebSocketAnalysis().getRiskScore() > 0) {
                        highlightTerms.add("WebSocket");
                        highlightTerms.add("ws://");
                        highlightTerms.add("wss://");
                        highlightTerms.add("onmessage");
                        highlightTerms.add("e.data");
                    }
                    if (clientResult.getTemplateInjectionAnalysis() != null && clientResult.getTemplateInjectionAnalysis().getRiskScore() > 0) {
                        highlightTerms.add("{{");
                        highlightTerms.add("${");
                        highlightTerms.add("<%=");
                    }
                    if (clientResult.getPrototypePollutionAnalysis() != null && clientResult.getPrototypePollutionAnalysis().getRiskScore() > 0) {
                        highlightTerms.add("__proto__");
                        highlightTerms.add("prototype");
                        highlightTerms.add("constructor");
                    }
                    // Generic high-impact sinks to highlight for correlated client-side issues
                    highlightTerms.add("innerHTML");
                    highlightTerms.add("outerHTML");
                    highlightTerms.add("insertAdjacentHTML");
                    highlightTerms.add("document.write");
                    highlightTerms.add("eval(");
                    highlightTerms.add("Function(");
                } catch (Exception ignored) {}
                if (!highlightTerms.isEmpty()) {
                    data.put("HIGHLIGHT_TERMS", highlightTerms);
                }

                // Human-readable client-side evidence for reporting (researcher-friendly)
                try {
                    List<String> lines = new ArrayList<>();
                    lines.add("Client-side risk score: " + clientResult.getRiskScore());

                    if (clientResult.getCspAnalysis() != null && clientResult.getCspAnalysis().getRiskScore() > 0) {
                        lines.add("CSP risk score: " + clientResult.getCspAnalysis().getRiskScore());
                        if (clientResult.getCspAnalysis().getUnsafeDirectives() != null && !clientResult.getCspAnalysis().getUnsafeDirectives().isEmpty()) {
                            lines.add("CSP unsafe directives: " + String.join(", ", clientResult.getCspAnalysis().getUnsafeDirectives()));
                        }
                        if (clientResult.getCspAnalysis().getMissingDirectives() != null && !clientResult.getCspAnalysis().getMissingDirectives().isEmpty()) {
                            lines.add("CSP missing directives: " + String.join(", ", clientResult.getCspAnalysis().getMissingDirectives()));
                        }
                    }

                    if (clientResult.getPostMessageAnalysis() != null && clientResult.getPostMessageAnalysis().getRiskScore() > 0) {
                        lines.add("PostMessage risk score: " + clientResult.getPostMessageAnalysis().getRiskScore());
                        if (clientResult.getPostMessageAnalysis().getDetectedPatterns() != null) {
                            for (String p : clientResult.getPostMessageAnalysis().getDetectedPatterns()) {
                                if (p != null && !p.trim().isEmpty()) lines.add("POSTMESSAGE: " + p);
                            }
                        }
                    }
                    if (clientResult.getWebSocketAnalysis() != null && clientResult.getWebSocketAnalysis().getRiskScore() > 0) {
                        lines.add("WebSocket risk score: " + clientResult.getWebSocketAnalysis().getRiskScore());
                        if (clientResult.getWebSocketAnalysis().getDetectedPatterns() != null) {
                            for (String p : clientResult.getWebSocketAnalysis().getDetectedPatterns()) {
                                if (p != null && !p.trim().isEmpty()) lines.add("WEBSOCKET: " + p);
                            }
                        }
                    }
                    if (clientResult.getTemplateInjectionAnalysis() != null && clientResult.getTemplateInjectionAnalysis().getRiskScore() > 0) {
                        lines.add("Template injection risk score: " + clientResult.getTemplateInjectionAnalysis().getRiskScore());
                        if (clientResult.getTemplateInjectionAnalysis().getDetectedPatterns() != null) {
                            for (String p : clientResult.getTemplateInjectionAnalysis().getDetectedPatterns()) {
                                if (p != null && !p.trim().isEmpty()) lines.add("TEMPLATE: " + p);
                            }
                        }
                    }
                    if (clientResult.getPrototypePollutionAnalysis() != null && clientResult.getPrototypePollutionAnalysis().getRiskScore() > 0) {
                        lines.add("Prototype pollution risk score: " + clientResult.getPrototypePollutionAnalysis().getRiskScore());
                        if (clientResult.getPrototypePollutionAnalysis().getDetectedPatterns() != null) {
                            for (String p : clientResult.getPrototypePollutionAnalysis().getDetectedPatterns()) {
                                if (p != null && !p.trim().isEmpty()) lines.add("PROTOTYPE: " + p);
                            }
                        }
                    }
                    if (clientResult.getModernAPIAnalysis() != null && clientResult.getModernAPIAnalysis().getRiskScore() > 0) {
                        lines.add("Modern API risk score: " + clientResult.getModernAPIAnalysis().getRiskScore());
                        if (clientResult.getModernAPIAnalysis().getDetectedPatterns() != null) {
                            for (String p : clientResult.getModernAPIAnalysis().getDetectedPatterns()) {
                                if (p != null && !p.trim().isEmpty()) lines.add("MODERN_API: " + p);
                            }
                        }
                    }
                    if (clientResult.getWebComponentsAnalysis() != null && clientResult.getWebComponentsAnalysis().getRiskScore() > 0) {
                        lines.add("Web Components risk score: " + clientResult.getWebComponentsAnalysis().getRiskScore());
                        if (clientResult.getWebComponentsAnalysis().getDetectedPatterns() != null) {
                            for (String p : clientResult.getWebComponentsAnalysis().getDetectedPatterns()) {
                                if (p != null && !p.trim().isEmpty()) lines.add("WEB_COMPONENTS: " + p);
                            }
                        }
                    }

                    // Cap output size to keep advisories readable
                    if (lines.size() > 80) {
                        lines = new ArrayList<>(lines.subList(0, 80));
                        lines.add("... (truncated)");
                    }

                    if (!lines.isEmpty()) {
                        data.put("SOURCE_SINK_ANALYSIS", String.join("\n", lines));
                    }
                } catch (Exception ignored) {}
                
                // Add client-side specific data
                if (clientResult.getCspAnalysis() != null && clientResult.getCspAnalysis().getRiskScore() > 0) {
                    data.put("CSP_BYPASS", true);
                }
                if (clientResult.getPostMessageAnalysis() != null && clientResult.getPostMessageAnalysis().getRiskScore() > 0) {
                    data.put("POSTMESSAGE_VULN", true);
                }
                if (clientResult.getWebSocketAnalysis() != null && clientResult.getWebSocketAnalysis().getRiskScore() > 0) {
                    data.put("WEBSOCKET_VULN", true);
                }
            }
            
            // Ensure paramName is set (fallback)
            if (!data.containsKey("paramName") || data.get("paramName") == null || String.valueOf(data.get("paramName")).trim().isEmpty()) {
                data.put("paramName", "detected_parameter");
            }
            
        } catch (Exception e) {
            callbacks.printError("[" + PLUGIN_NAME + "] Error creating vulnerability data: " + e.getMessage());
            // Return minimal data structure
            data.put("vulnerabilityType", "XSS");
            data.put("CONFIRMED_XSS", false);
            data.put("CONFIDENCE_SCORE", 50.0);
        }
        
        return data;
    }
    
    /**
     * Cleanup resources
     */
    public void cleanup() {
        try {
            if (scanningExecutor != null && !scanningExecutor.isShutdown()) {
                scanningExecutor.shutdown();
                    if (!scanningExecutor.awaitTermination(5, TimeUnit.SECONDS)) {
                        scanningExecutor.shutdownNow();
                    }
                }
            callbacks.printOutput("[" + PLUGIN_NAME + "] Cleanup completed");
        } catch (Exception e) {
            callbacks.printError("[" + PLUGIN_NAME + "] Error during cleanup: " + e.getMessage());
        }
    }
}