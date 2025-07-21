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

import static burp.Constants.*;

/**
 * XSSDetector - Professional XSS Vulnerability Scanner for Burp Suite
 * Clean, production-ready implementation with essential XSS detection capabilities
 */
public class BurpExtender implements IBurpExtender, IScannerCheck, ITab {
    
    // Plugin Information
    public static final String PLUGIN_NAME = "XSSDetector";
    public static final String AUTHOR = "Vikas Kumar";
    public static final String VERSION = "2.0.0 - Production Ready";
    
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
    private JCheckBox checkContext;
    private JCheckBox modernDetection;
    private JCheckBox domXssDetection;
    private JCheckBox cspAnalysis;
    
    // Advanced XSS Detection
    private JCheckBox enableWAFBypass;
    private JCheckBox enableFrameworkSpecific;
    private JCheckBox enableEncodingBypass;
    private JCheckBox enableCSPBypass;
    
    // Analysis and Reporting
    private JCheckBox detailedReporting;
    private JCheckBox exploitGeneration;
    private JCheckBox verboseLogging;
    
    // Core Detection Engines
    private CheckReflection checkReflection;
    private ModernArchitectureDetector architectureDetector;
    private AdvancedJSONAnalyzer jsonAnalyzer; 
    private EnhancedIssueReporter issueReporter;
    private AIContextAnalyzer aiAnalyzer;
    private EngineIntegrationManager engineIntegrationManager;
    private PerformanceMonitor performanceMonitor;
    private ErrorRecoverySystem errorRecoverySystem;

    // Enhanced Detection Engines
    private EnhancedDOMXSSDetector domXssDetector;
    private EnhancedClientSideAttackDetector clientSideDetector;
    private EnhancedAggressive aggressiveDetector;
    private AdvancedFilteringEngine filteringEngine;
    
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
        
        // Initialize thread management
        initializeThreadManagement();
        
        // Log initialization
        callbacks.printOutput("[" + PLUGIN_NAME + "] Initialized successfully - Production Ready");
        callbacks.printOutput("[" + PLUGIN_NAME + "] Author: " + AUTHOR);
        callbacks.printOutput("[" + PLUGIN_NAME + "] Version: " + VERSION);
    }
    
    /**
     * Initialize all detection engines
     */
    private void initializeDetectionEngines() {
        try {
            // Core reflection detection
            this.checkReflection = new CheckReflection(helpers, callbacks, settings);
            
            // Modern architecture detection
            this.architectureDetector = new ModernArchitectureDetector(helpers, callbacks, settings);
            
            // JSON analysis
            this.jsonAnalyzer = new AdvancedJSONAnalyzer(helpers, callbacks, settings);
            
            // Issue reporting
            this.issueReporter = new EnhancedIssueReporter(helpers, callbacks, settings);
            
            // AI context analysis
            this.aiAnalyzer = new AIContextAnalyzer(helpers, callbacks, settings);
            
            // Engine integration
            this.engineIntegrationManager = new EngineIntegrationManager(helpers, callbacks, settings);
            
            // Performance monitoring
            this.performanceMonitor = new PerformanceMonitor(callbacks);
            
            // Error recovery
            this.errorRecoverySystem = new ErrorRecoverySystem(callbacks, performanceMonitor);
            
            // Enhanced detection engines
            this.domXssDetector = new EnhancedDOMXSSDetector(helpers, callbacks, settings);
            this.clientSideDetector = new EnhancedClientSideAttackDetector(helpers, callbacks, settings);
            this.aggressiveDetector = new EnhancedAggressive(helpers, callbacks, settings);
            this.filteringEngine = new AdvancedFilteringEngine(helpers, callbacks, settings);
            
            callbacks.printOutput("[" + PLUGIN_NAME + "] All detection engines initialized successfully");
            
                        } catch (Exception e) {
            callbacks.printError("[" + PLUGIN_NAME + "] Error initializing detection engines: " + e.getMessage());
        }
    }
    
    /**
     * Initialize clean, professional UI
     */
    private void initializeUI() {
        try {
            // Create main panel
            panel = new JPanel(new BorderLayout());
            
            // Create settings panel
            JPanel settingsPanel = createSettingsPanel();
            panel.add(settingsPanel, BorderLayout.NORTH);
            
            // Create content type management panel
            JPanel contentTypePanel = createContentTypePanel();
            panel.add(contentTypePanel, BorderLayout.CENTER);
            
            // Initialize listeners
            initListeners();
            
            callbacks.printOutput("[" + PLUGIN_NAME + "] UI initialized successfully");
            
        } catch (Exception e) {
            callbacks.printError("[" + PLUGIN_NAME + "] Error initializing UI: " + e.getMessage());
        }
    }

    /**
     * Create clean settings panel
     */
    private JPanel createSettingsPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBorder(BorderFactory.createTitledBorder("XSS Detection Settings"));
        
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.anchor = GridBagConstraints.WEST;
        
        // Core detection settings
        scopeOnly = new JCheckBox("Scope Only", settings.getScopeOnly());
        aggressiveMode = new JCheckBox("Aggressive Mode", settings.getAggressiveMode());
        checkContext = new JCheckBox("Context Analysis", settings.getCheckContext());
        
        // Modern detection settings
        modernDetection = new JCheckBox("Modern Detection", settings.getModernDetection());
        domXssDetection = new JCheckBox("DOM XSS Detection", settings.getDomXssDetection());
        cspAnalysis = new JCheckBox("CSP Analysis", settings.getCspAnalysis());
        
        // Advanced settings
        enableWAFBypass = new JCheckBox("WAF Bypass", settings.getEnableWAFBypass());
        enableFrameworkSpecific = new JCheckBox("Framework Specific", settings.getEnableFrameworkSpecific());
        enableEncodingBypass = new JCheckBox("Encoding Bypass", settings.getEnableEncodingBypass());
        enableCSPBypass = new JCheckBox("CSP Bypass", settings.getEnableCSPBypass());
        
        // Reporting settings
        detailedReporting = new JCheckBox("Detailed Reporting", settings.getDetailedReporting());
        exploitGeneration = new JCheckBox("Exploit Generation", settings.getExploitGeneration());
        verboseLogging = new JCheckBox("Verbose Logging", settings.getVerboseLogging());
        
        // Add components to panel
        gbc.gridx = 0; gbc.gridy = 0; gbc.gridwidth = 2;
        panel.add(new JLabel("Core Detection:"), gbc);
        
        gbc.gridx = 0; gbc.gridy = 1; gbc.gridwidth = 1;
        panel.add(scopeOnly, gbc);
        
        gbc.gridx = 1; gbc.gridy = 1;
        panel.add(aggressiveMode, gbc);
        
        gbc.gridx = 0; gbc.gridy = 2;
        panel.add(checkContext, gbc);
        
        gbc.gridx = 1; gbc.gridy = 2;
        panel.add(modernDetection, gbc);
        
        gbc.gridx = 0; gbc.gridy = 3;
        panel.add(domXssDetection, gbc);
        
        gbc.gridx = 1; gbc.gridy = 3;
        panel.add(cspAnalysis, gbc);
        
        gbc.gridx = 0; gbc.gridy = 4; gbc.gridwidth = 2;
        panel.add(new JLabel("Advanced Detection:"), gbc);
        
        gbc.gridx = 0; gbc.gridy = 5; gbc.gridwidth = 1;
        panel.add(enableWAFBypass, gbc);
        
        gbc.gridx = 1; gbc.gridy = 5;
        panel.add(enableFrameworkSpecific, gbc);
        
        gbc.gridx = 0; gbc.gridy = 6;
        panel.add(enableEncodingBypass, gbc);
        
        gbc.gridx = 1; gbc.gridy = 6;
        panel.add(enableCSPBypass, gbc);
        
        gbc.gridx = 0; gbc.gridy = 7; gbc.gridwidth = 2;
        panel.add(new JLabel("Reporting:"), gbc);
        
        gbc.gridx = 0; gbc.gridy = 8; gbc.gridwidth = 1;
        panel.add(detailedReporting, gbc);
        
        gbc.gridx = 1; gbc.gridy = 8;
        panel.add(exploitGeneration, gbc);
        
        gbc.gridx = 0; gbc.gridy = 9;
        panel.add(verboseLogging, gbc);
        
        return panel;
    }
    
    /**
     * Create content type management panel
     */
    private JPanel createContentTypePanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createTitledBorder("Content Type Management"));
        
        // Create table
        String[] columnNames = {"Content Type", "Status"};
        Object[][] data = {};
        model = new DefaultTableModel(data, columnNames);
        table = new JTable(model);
        
        // Create buttons
        addButton = new JButton("Add");
        deleteButton = new JButton("Delete");
        contentTypeTextField = new JTextField(20);
        
        // Create button panel
        JPanel buttonPanel = new JPanel();
        buttonPanel.add(new JLabel("Content Type:"));
        buttonPanel.add(contentTypeTextField);
        buttonPanel.add(addButton);
        buttonPanel.add(deleteButton);
        
        panel.add(new JScrollPane(table), BorderLayout.CENTER);
        panel.add(buttonPanel, BorderLayout.SOUTH);
        
        return panel;
    }
    
    /**
     * Initialize event listeners
     */
    private void initListeners() {
        // Settings change listeners
        scopeOnly.addActionListener(e -> settings.setScopeOnly(scopeOnly.isSelected()));
        aggressiveMode.addActionListener(e -> settings.setAggressiveMode(aggressiveMode.isSelected()));
        checkContext.addActionListener(e -> settings.setCheckContext(checkContext.isSelected()));
        modernDetection.addActionListener(e -> settings.setModernDetection(modernDetection.isSelected()));
        domXssDetection.addActionListener(e -> settings.setDomXssDetection(domXssDetection.isSelected()));
        cspAnalysis.addActionListener(e -> settings.setCspAnalysis(cspAnalysis.isSelected()));
        enableWAFBypass.addActionListener(e -> settings.setEnableWAFBypass(enableWAFBypass.isSelected()));
        enableFrameworkSpecific.addActionListener(e -> settings.setEnableFrameworkSpecific(enableFrameworkSpecific.isSelected()));
        enableEncodingBypass.addActionListener(e -> settings.setEnableEncodingBypass(enableEncodingBypass.isSelected()));
        enableCSPBypass.addActionListener(e -> settings.setEnableCSPBypass(enableCSPBypass.isSelected()));
        detailedReporting.addActionListener(e -> settings.setDetailedReporting(detailedReporting.isSelected()));
        exploitGeneration.addActionListener(e -> settings.setExploitGeneration(exploitGeneration.isSelected()));
        verboseLogging.addActionListener(e -> settings.setVerboseLogging(verboseLogging.isSelected()));
        
        // Content type management listeners
        addButton.addActionListener(e -> addContentType());
        deleteButton.addActionListener(e -> deleteContentType());
        
        // Table selection listener
        table.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int selectedRow = table.getSelectedRow();
                if (selectedRow >= 0) {
                    contentTypeTextField.setText((String) table.getValueAt(selectedRow, 0));
                }
            }
        });
    }
    
    /**
     * Add content type to allowed list
     */
    private void addContentType() {
        String contentType = contentTypeTextField.getText().trim();
        if (!contentType.isEmpty()) {
            model.addRow(new Object[]{contentType, "Allowed"});
            contentTypeTextField.setText("");
            callbacks.printOutput("[" + PLUGIN_NAME + "] Added content type: " + contentType);
        }
    }
    
    /**
     * Delete selected content type
     */
    private void deleteContentType() {
        int selectedRow = table.getSelectedRow();
        if (selectedRow >= 0) {
            String contentType = (String) table.getValueAt(selectedRow, 0);
            model.removeRow(selectedRow);
            callbacks.printOutput("[" + PLUGIN_NAME + "] Removed content type: " + contentType);
        }
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
            if (scopeOnly.isSelected() && !callbacks.isInScope(helpers.analyzeRequest(baseRequestResponse).getUrl())) {
                return issues;
            }
            
            // Perform comprehensive XSS detection
            issues.addAll(performComprehensiveXSSDetection(baseRequestResponse));
            
                    } catch (Exception e) {
            callbacks.printError("[" + PLUGIN_NAME + "] Error in passive scan: " + e.getMessage());
        }
        
        return issues;
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
            if (scopeOnly.isSelected() && !callbacks.isInScope(helpers.analyzeRequest(baseRequestResponse).getUrl())) {
        return issues;
    }

            // Perform active XSS detection
            issues.addAll(performActiveXSSDetection(baseRequestResponse, insertionPoint));
            
        } catch (Exception e) {
            callbacks.printError("[" + PLUGIN_NAME + "] Error in active scan: " + e.getMessage());
        }
        
        return issues;
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        // Return -1 to keep existing issue, 0 to keep new issue, 1 to merge
        return -1; // Keep existing issue by default
    }
    
    /**
     * Perform comprehensive XSS detection
     */
    private List<IScanIssue> performComprehensiveXSSDetection(IHttpRequestResponse requestResponse) {
        List<IScanIssue> issues = new ArrayList<>();
        
        try {
            // Basic reflection detection
            if (checkReflection != null) {
                List<IScanIssue> reflectionIssues = checkReflection.doPassiveScan(requestResponse);
                issues.addAll(reflectionIssues);
            }
            
            // DOM XSS detection
            if (domXssDetection.isSelected() && domXssDetector != null) {
                EnhancedDOMXSSDetector.DOMXSSResult domResult = domXssDetector.analyzeDOMXSS(requestResponse);
            if (domResult.isVulnerable()) {
                    // Create DOM XSS issue
                    Map<String, Object> vulnerabilityData = createVulnerabilityData(domResult);
                    IScanIssue domIssue = issueReporter.createEnhancedXSSIssue(requestResponse, vulnerabilityData);
                if (domIssue != null) {
                    issues.add(domIssue);
                    }
                }
            }
            
            // Client-side attack detection
            if (modernDetection.isSelected() && clientSideDetector != null) {
                EnhancedClientSideAttackDetector.ClientSideAttackResult clientResult = clientSideDetector.analyzeClientSideAttacks(requestResponse);
                if (clientResult.isVulnerable()) {
                    // Create client-side issue
                    Map<String, Object> vulnerabilityData = createVulnerabilityData(clientResult);
                    IScanIssue clientIssue = issueReporter.createEnhancedXSSIssue(requestResponse, vulnerabilityData);
                    if (clientIssue != null) {
                        issues.add(clientIssue);
                    }
                }
            }
            
        } catch (Exception e) {
            callbacks.printError("[" + PLUGIN_NAME + "] Error in comprehensive XSS detection: " + e.getMessage());
        }
        
                return issues;
    }
    
    /**
     * Perform active XSS detection
     */
    private List<IScanIssue> performActiveXSSDetection(IHttpRequestResponse requestResponse, IScannerInsertionPoint insertionPoint) {
        List<IScanIssue> issues = new ArrayList<>();
        
        try {
            // Aggressive detection
            if (aggressiveMode.isSelected() && aggressiveDetector != null) {
                List<IScanIssue> aggressiveIssues = aggressiveDetector.doActiveScan(requestResponse, insertionPoint);
                issues.addAll(aggressiveIssues);
            }
            
            // Engine integration manager
            if (engineIntegrationManager != null) {
                List<IScanIssue> engineIssues = engineIntegrationManager.performActiveScan(requestResponse, insertionPoint);
                issues.addAll(engineIssues);
            }
            
        } catch (Exception e) {
            callbacks.printError("[" + PLUGIN_NAME + "] Error in active XSS detection: " + e.getMessage());
        }
        
        return issues;
    }
    
    /**
     * Create vulnerability data from detection results
     */
    private Map<String, Object> createVulnerabilityData(Object result) {
        Map<String, Object> data = new HashMap<>();
        
        if (result instanceof EnhancedDOMXSSDetector.DOMXSSResult) {
            EnhancedDOMXSSDetector.DOMXSSResult domResult = (EnhancedDOMXSSDetector.DOMXSSResult) result;
            data.put("vulnerabilityType", "DOM XSS");
            data.put("confidence", domResult.getConfidenceLevel());
            data.put("riskLevel", domResult.getRiskLevel());
            data.put("testPayload", domResult.getTestPayload());
            data.put("testRequest", domResult.getTestRequest());
            data.put("testResponse", domResult.getTestResponse());
        } else if (result instanceof EnhancedClientSideAttackDetector.ClientSideAttackResult) {
            EnhancedClientSideAttackDetector.ClientSideAttackResult clientResult = (EnhancedClientSideAttackDetector.ClientSideAttackResult) result;
            data.put("vulnerabilityType", "Client-Side XSS");
            data.put("confidence", clientResult.getConfidenceLevel());
            data.put("riskLevel", clientResult.getRiskLevel());
            data.put("testPayload", clientResult.getTestPayload());
            data.put("testRequest", clientResult.getTestRequest());
            data.put("testResponse", clientResult.getTestResponse());
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