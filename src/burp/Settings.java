package burp;

import java.util.ArrayList;
import java.util.regex.Pattern;

import static burp.Constants.*;

/**
 * Clean, professional settings management for XSSDetector
 * Removes excessive junk code and focuses on essential configuration
 */
class Settings {
    
    // Core settings
    private String scopeOnly;
    private String aggressiveMode;
    private String autoConfirm;
    private String checkContext;
    private IBurpExtenderCallbacks callbacks;
    private ArrayList<Object[]> contentTypes;
    private ArrayList<String> enabledContentTypes;
    
    // Essential detection settings
    private String modernDetection;
    private String domXssDetection;
    private String cspAnalysis;
    private String advancedFiltering;
    private String confidenceScoring;
    
    // Session handling
    private String sessionHandling;
    private String autoSessionHandling;
    private String csrfTokenHandling;
    
    // Core XSS technique settings
    private String enableWAFBypass;
    private String enableFrameworkSpecific;
    private String enableEncodingBypass;
    private String enableCSPBypass;
    private String enablePolyglotPayloads;
    private String enableBrowserSpecific;

    // Advanced payload packs (previously incorrectly mapped to other flags)
    private String enableJSFucker;
    private String enablePrototypePollution;
    private String enablePostMessageXSS;
    private String enableWebComponents;
    private String enableShadowDOM;
    private String enableWebAssembly;
    private String enableModernBrowserAPI;
    
    // Analysis and reporting
    private String detailedReporting;
    private String exploitGeneration;
    private String remediationSuggestions;
    private String verboseLogging;
    
    // Scanner mode
    private String scannerMode;
    
    // Bypass options
    private String bypassCookieChecks;
    private String bypassHeaderChecks;
    private String skipImageFiles;
    private String enableTruePositiveOnly;
    private String enableAdvancedValidation;
    private String enableContextAwareAnalysis;

    // Performance settings
    private String requestRateLimit;
    private String connectionTimeout;
    private String retryAttempts;
    private String readTimeout;
    
    // Constants
    final private String FALSE_CONST = "false";
    final private String TRUE_CONST = "true";
    final private String DIVIDER_OBJECT = ":divider:";
    final private String DIVIDER_ARRAY = "|divider|";
    final private String CONTENT_TYPES = "content types";

    public Settings(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.contentTypes = new ArrayList<>();
        this.enabledContentTypes = new ArrayList<>();
        
        // Initialize with default values
        initializeDefaultSettings();
        
        // Load saved settings
        loadSettings();
        
        // Load content types
        loadContentTypes();
    }
    
    private void initializeDefaultSettings() {
        // Core settings
        scopeOnly = FALSE_CONST;
        aggressiveMode = FALSE_CONST;
        autoConfirm = TRUE_CONST;
        checkContext = TRUE_CONST;
        
        // Essential detection
        modernDetection = TRUE_CONST;
        domXssDetection = TRUE_CONST;
        cspAnalysis = TRUE_CONST;
        advancedFiltering = TRUE_CONST;
        confidenceScoring = TRUE_CONST;
        
        // Session handling
        sessionHandling = TRUE_CONST;
        autoSessionHandling = TRUE_CONST;
        csrfTokenHandling = TRUE_CONST;
        
        // Core XSS techniques
        enableWAFBypass = TRUE_CONST;
        enableFrameworkSpecific = TRUE_CONST;
        enableEncodingBypass = TRUE_CONST;
        enableCSPBypass = TRUE_CONST;
        enablePolyglotPayloads = TRUE_CONST;
        enableBrowserSpecific = TRUE_CONST;

        // Advanced payload packs (default ON to maximize coverage; can be disabled in UI)
        enableJSFucker = FALSE_CONST; // very noisy payload family, keep off by default
        enablePrototypePollution = TRUE_CONST;
        enablePostMessageXSS = TRUE_CONST;
        enableWebComponents = TRUE_CONST;
        enableShadowDOM = TRUE_CONST;
        enableWebAssembly = TRUE_CONST;
        enableModernBrowserAPI = TRUE_CONST;
        
        // Analysis and reporting
        detailedReporting = TRUE_CONST;
        exploitGeneration = TRUE_CONST;
        remediationSuggestions = TRUE_CONST;
        verboseLogging = FALSE_CONST;
        
        // Scanner mode
        scannerMode = SCANNER_MODE_ADVANCED;
        
        // Bypass options
        bypassCookieChecks = FALSE_CONST;
        bypassHeaderChecks = FALSE_CONST;
        skipImageFiles = TRUE_CONST;
        enableTruePositiveOnly = FALSE_CONST;
        enableAdvancedValidation = TRUE_CONST;
        enableContextAwareAnalysis = TRUE_CONST;
        
        // Performance
        requestRateLimit = "10";
        connectionTimeout = "30000";
        retryAttempts = "3";
        readTimeout = "30000";
    }
    
    private void loadSettings() {
        try {
            // Load core settings
            scopeOnly = callbacks.loadExtensionSetting("scopeOnly");
            if (scopeOnly == null) scopeOnly = FALSE_CONST;
            
            aggressiveMode = callbacks.loadExtensionSetting("aggressiveMode");
            if (aggressiveMode == null) aggressiveMode = FALSE_CONST;

            autoConfirm = callbacks.loadExtensionSetting("autoConfirm");
            if (autoConfirm == null) autoConfirm = TRUE_CONST;
            
            checkContext = callbacks.loadExtensionSetting("checkContext");
            if (checkContext == null) checkContext = TRUE_CONST;
            
            // Load detection settings
            modernDetection = callbacks.loadExtensionSetting("modernDetection");
            if (modernDetection == null) modernDetection = TRUE_CONST;
            
            domXssDetection = callbacks.loadExtensionSetting("domXssDetection");
            if (domXssDetection == null) domXssDetection = TRUE_CONST;
            
            cspAnalysis = callbacks.loadExtensionSetting("cspAnalysis");
            if (cspAnalysis == null) cspAnalysis = TRUE_CONST;
            
            advancedFiltering = callbacks.loadExtensionSetting("advancedFiltering");
            if (advancedFiltering == null) advancedFiltering = TRUE_CONST;
            
            confidenceScoring = callbacks.loadExtensionSetting("confidenceScoring");
            if (confidenceScoring == null) confidenceScoring = TRUE_CONST;
            
            // Load session settings
            sessionHandling = callbacks.loadExtensionSetting("sessionHandling");
            if (sessionHandling == null) sessionHandling = TRUE_CONST;
            
            autoSessionHandling = callbacks.loadExtensionSetting("autoSessionHandling");
            if (autoSessionHandling == null) autoSessionHandling = TRUE_CONST;
            
            csrfTokenHandling = callbacks.loadExtensionSetting("csrfTokenHandling");
            if (csrfTokenHandling == null) csrfTokenHandling = TRUE_CONST;
            
            // Load XSS technique settings
            enableWAFBypass = callbacks.loadExtensionSetting("enableWAFBypass");
            if (enableWAFBypass == null) enableWAFBypass = TRUE_CONST;
            
            enableFrameworkSpecific = callbacks.loadExtensionSetting("enableFrameworkSpecific");
            if (enableFrameworkSpecific == null) enableFrameworkSpecific = TRUE_CONST;
            
            enableEncodingBypass = callbacks.loadExtensionSetting("enableEncodingBypass");
            if (enableEncodingBypass == null) enableEncodingBypass = TRUE_CONST;
            
            enableCSPBypass = callbacks.loadExtensionSetting("enableCSPBypass");
            if (enableCSPBypass == null) enableCSPBypass = TRUE_CONST;
            
            enablePolyglotPayloads = callbacks.loadExtensionSetting("enablePolyglotPayloads");
            if (enablePolyglotPayloads == null) enablePolyglotPayloads = TRUE_CONST;
            
            enableBrowserSpecific = callbacks.loadExtensionSetting("enableBrowserSpecific");
            if (enableBrowserSpecific == null) enableBrowserSpecific = TRUE_CONST;

            // Advanced payload packs (backwards compatible defaults)
            enableJSFucker = callbacks.loadExtensionSetting("enableJSFucker");
            if (enableJSFucker == null) enableJSFucker = FALSE_CONST;

            enablePrototypePollution = callbacks.loadExtensionSetting("enablePrototypePollution");
            if (enablePrototypePollution == null) enablePrototypePollution = enableFrameworkSpecific; // legacy behavior

            enablePostMessageXSS = callbacks.loadExtensionSetting("enablePostMessageXSS");
            if (enablePostMessageXSS == null) enablePostMessageXSS = enableFrameworkSpecific; // legacy behavior

            enableWebComponents = callbacks.loadExtensionSetting("enableWebComponents");
            if (enableWebComponents == null) enableWebComponents = enableFrameworkSpecific; // legacy behavior

            enableShadowDOM = callbacks.loadExtensionSetting("enableShadowDOM");
            if (enableShadowDOM == null) enableShadowDOM = enableFrameworkSpecific; // legacy behavior

            enableWebAssembly = callbacks.loadExtensionSetting("enableWebAssembly");
            if (enableWebAssembly == null) enableWebAssembly = enableFrameworkSpecific; // legacy behavior

            enableModernBrowserAPI = callbacks.loadExtensionSetting("enableModernBrowserAPI");
            if (enableModernBrowserAPI == null) enableModernBrowserAPI = enableFrameworkSpecific; // legacy behavior
            
            // Load analysis settings
            detailedReporting = callbacks.loadExtensionSetting("detailedReporting");
            if (detailedReporting == null) detailedReporting = TRUE_CONST;
            
            exploitGeneration = callbacks.loadExtensionSetting("exploitGeneration");
            if (exploitGeneration == null) exploitGeneration = TRUE_CONST;
            
            remediationSuggestions = callbacks.loadExtensionSetting("remediationSuggestions");
            if (remediationSuggestions == null) remediationSuggestions = TRUE_CONST;
            
            verboseLogging = callbacks.loadExtensionSetting("verboseLogging");
            if (verboseLogging == null) verboseLogging = FALSE_CONST;
            
            // Load scanner mode
            scannerMode = callbacks.loadExtensionSetting("scannerMode");
            if (scannerMode == null) scannerMode = SCANNER_MODE_ADVANCED;
            
            // Load bypass settings
            bypassCookieChecks = callbacks.loadExtensionSetting("bypassCookieChecks");
            if (bypassCookieChecks == null) bypassCookieChecks = FALSE_CONST;
            
            bypassHeaderChecks = callbacks.loadExtensionSetting("bypassHeaderChecks");
            if (bypassHeaderChecks == null) bypassHeaderChecks = FALSE_CONST;
            
            skipImageFiles = callbacks.loadExtensionSetting("skipImageFiles");
            if (skipImageFiles == null) skipImageFiles = TRUE_CONST;
            
            enableTruePositiveOnly = callbacks.loadExtensionSetting("enableTruePositiveOnly");
            if (enableTruePositiveOnly == null) enableTruePositiveOnly = FALSE_CONST;
            
            enableAdvancedValidation = callbacks.loadExtensionSetting("enableAdvancedValidation");
            if (enableAdvancedValidation == null) enableAdvancedValidation = TRUE_CONST;
            
            enableContextAwareAnalysis = callbacks.loadExtensionSetting("enableContextAwareAnalysis");
            if (enableContextAwareAnalysis == null) enableContextAwareAnalysis = TRUE_CONST;
            
            // Load performance settings
            requestRateLimit = callbacks.loadExtensionSetting("requestRateLimit");
            if (requestRateLimit == null) requestRateLimit = "10";
            
            connectionTimeout = callbacks.loadExtensionSetting("connectionTimeout");
            if (connectionTimeout == null) connectionTimeout = "30000";
            
            retryAttempts = callbacks.loadExtensionSetting("retryAttempts");
            if (retryAttempts == null) retryAttempts = "3";
            
            readTimeout = callbacks.loadExtensionSetting("readTimeout");
            if (readTimeout == null) readTimeout = "30000";
            
        } catch (Exception e) {
            callbacks.printError("Error loading settings: " + e.getMessage());
        }
    }
    
    private void loadContentTypes() {
        try {
            String savedContentTypes = callbacks.loadExtensionSetting(CONTENT_TYPES);
            if (savedContentTypes != null && !savedContentTypes.isEmpty()) {
                contentTypes = extractArray(savedContentTypes);
                enabledContentTypes = extractEnabledContentTypes();
            } else {
                // Initialize with default content types
                // Only text/html and application/json enabled by default
                contentTypes = new ArrayList<>();
                for (String contentType : MODERN_DEFAULT_CONTENT_TYPES) {
                    // Only enable text/html and application/json by default
                    boolean enabled = "text/html".equals(contentType) || "application/json".equals(contentType);
                    contentTypes.add(new Object[]{contentType, enabled});
                }
                enabledContentTypes = extractEnabledContentTypes();
            }
        } catch (Exception e) {
            callbacks.printError("Error loading content types: " + e.getMessage());
            // Fallback to defaults
            // Only text/html and application/json enabled by default
            contentTypes = new ArrayList<>();
            for (String contentType : MODERN_DEFAULT_CONTENT_TYPES) {
                // Only enable text/html and application/json by default
                boolean enabled = "text/html".equals(contentType) || "application/json".equals(contentType);
                contentTypes.add(new Object[]{contentType, enabled});
            }
            enabledContentTypes = extractEnabledContentTypes();
        }
    }
    
    // Core getters
    public Boolean getScopeOnly() { return Boolean.valueOf(scopeOnly); }
    public Boolean getAggressiveMode() { return Boolean.valueOf(aggressiveMode); }
    public Boolean getAutoConfirm() { return Boolean.valueOf(autoConfirm); }
    public Boolean getCheckContext() { return Boolean.valueOf(checkContext); }
    
    // Detection getters
    public Boolean getModernDetection() { return Boolean.valueOf(modernDetection); }
    public Boolean getDomXssDetection() { return Boolean.valueOf(domXssDetection); }
    public Boolean getCspAnalysis() { return Boolean.valueOf(cspAnalysis); }
    public Boolean getAdvancedFiltering() { return Boolean.valueOf(advancedFiltering); }
    public Boolean getConfidenceScoring() { return Boolean.valueOf(confidenceScoring); } // TODO: Feature not yet implemented
    
    // Session getters
    public Boolean getSessionHandling() { return Boolean.valueOf(sessionHandling); }
    public Boolean getAutoSessionHandling() { return Boolean.valueOf(autoSessionHandling); } // TODO: Feature not yet implemented
    public Boolean getCsrfTokenHandling() { return Boolean.valueOf(csrfTokenHandling); } // TODO: Feature not yet implemented
    
    // XSS technique getters
    public Boolean getEnableWAFBypass() { return Boolean.valueOf(enableWAFBypass); }
    public Boolean getEnableFrameworkSpecific() { return Boolean.valueOf(enableFrameworkSpecific); }
    public Boolean getEnableEncodingBypass() { return Boolean.valueOf(enableEncodingBypass); }
    public Boolean getEnableCSPBypass() { return Boolean.valueOf(enableCSPBypass); }
    public Boolean getEnablePolyglotPayloads() { return Boolean.valueOf(enablePolyglotPayloads); }
    public Boolean getEnableBrowserSpecific() { return Boolean.valueOf(enableBrowserSpecific); }
    
    // Analysis getters
    public Boolean getDetailedReporting() { return Boolean.valueOf(detailedReporting); }
    public Boolean getExploitGeneration() { return Boolean.valueOf(exploitGeneration); }
    public Boolean getRemediationSuggestions() { return Boolean.valueOf(remediationSuggestions); } // TODO: Feature not yet implemented
    public Boolean getVerboseLogging() { return Boolean.valueOf(verboseLogging); }
    
    // Scanner mode getter
    public String getScannerMode() { return scannerMode; }
    
    // Bypass getters
    public Boolean getBypassCookieChecks() { return Boolean.valueOf(bypassCookieChecks); }
    public Boolean getBypassHeaderChecks() { return Boolean.valueOf(bypassHeaderChecks); }
    public Boolean getSkipImageFiles() { return Boolean.valueOf(skipImageFiles); }
    public Boolean getEnableTruePositiveOnly() { return Boolean.valueOf(enableTruePositiveOnly); }
    public Boolean getEnableAdvancedValidation() { return Boolean.valueOf(enableAdvancedValidation); }
    public Boolean getEnableContextAwareAnalysis() { return Boolean.valueOf(enableContextAwareAnalysis); }
    
    // Performance getters
    public Integer getRequestRateLimit() { return Integer.valueOf(requestRateLimit); }
    public Integer getConnectionTimeout() { return Integer.valueOf(connectionTimeout); }
    public Integer getRetryAttempts() { return Integer.valueOf(retryAttempts); }
    public Integer getReadTimeout() { return Integer.valueOf(readTimeout); }
    
    // Advanced payload-pack getters (fully wired)
    public Boolean getEnableJSFucker() { return Boolean.valueOf(enableJSFucker); }
    public Boolean getEnablePrototypePollution() { return Boolean.valueOf(enablePrototypePollution); }
    public Boolean getEnablePostMessageXSS() { return Boolean.valueOf(enablePostMessageXSS); }
    public Boolean getEnableWebComponents() { return Boolean.valueOf(enableWebComponents); }
    public Boolean getEnableShadowDOM() { return Boolean.valueOf(enableShadowDOM); }
    public Boolean getEnableWebAssembly() { return Boolean.valueOf(enableWebAssembly); }
    public Boolean getEnableModernBrowserAPI() { return Boolean.valueOf(enableModernBrowserAPI); }
    
    // Core setters
    public void setScopeOnly(boolean scopeOnly) {
        this.scopeOnly = String.valueOf(scopeOnly);
        callbacks.saveExtensionSetting("scopeOnly", this.scopeOnly);
    }

    public void setAggressiveMode(boolean aggressiveMode) {
        this.aggressiveMode = String.valueOf(aggressiveMode);
        callbacks.saveExtensionSetting("aggressiveMode", this.aggressiveMode);
    }

    public void setAutoConfirm(boolean autoConfirm) {
        this.autoConfirm = String.valueOf(autoConfirm);
        callbacks.saveExtensionSetting("autoConfirm", this.autoConfirm);
    }

    public void setCheckContext(boolean checkContext) {
        this.checkContext = String.valueOf(checkContext);
        callbacks.saveExtensionSetting("checkContext", this.checkContext);
    }
    
    // Detection setters
    public void setModernDetection(boolean enabled) {
        this.modernDetection = String.valueOf(enabled);
        callbacks.saveExtensionSetting("modernDetection", this.modernDetection);
    }
    
    public void setDomXssDetection(boolean enabled) {
        this.domXssDetection = String.valueOf(enabled);
        callbacks.saveExtensionSetting("domXssDetection", this.domXssDetection);
    }
    
    public void setCspAnalysis(boolean enabled) {
        this.cspAnalysis = String.valueOf(enabled);
        callbacks.saveExtensionSetting("cspAnalysis", this.cspAnalysis);
    }
    
    public void setAdvancedFiltering(boolean enabled) {
        this.advancedFiltering = String.valueOf(enabled);
        callbacks.saveExtensionSetting("advancedFiltering", this.advancedFiltering);
    }
    
    public void setConfidenceScoring(boolean enabled) {
        this.confidenceScoring = String.valueOf(enabled);
        callbacks.saveExtensionSetting("confidenceScoring", this.confidenceScoring);
    }
    
    // Session setters
    public void setSessionHandling(boolean enabled) {
        this.sessionHandling = String.valueOf(enabled);
        callbacks.saveExtensionSetting("sessionHandling", this.sessionHandling);
    }
    
    public void setAutoSessionHandling(boolean enabled) {
        this.autoSessionHandling = String.valueOf(enabled);
        callbacks.saveExtensionSetting("autoSessionHandling", this.autoSessionHandling);
    }
    
    public void setCsrfTokenHandling(boolean enabled) {
        this.csrfTokenHandling = String.valueOf(enabled);
        callbacks.saveExtensionSetting("csrfTokenHandling", this.csrfTokenHandling);
    }
    
    // XSS technique setters
    public void setEnableWAFBypass(boolean enabled) {
        this.enableWAFBypass = String.valueOf(enabled);
        callbacks.saveExtensionSetting("enableWAFBypass", this.enableWAFBypass);
    }
    
    public void setEnableFrameworkSpecific(boolean enabled) {
        this.enableFrameworkSpecific = String.valueOf(enabled);
        callbacks.saveExtensionSetting("enableFrameworkSpecific", this.enableFrameworkSpecific);
    }
    
    public void setEnableEncodingBypass(boolean enabled) {
        this.enableEncodingBypass = String.valueOf(enabled);
        callbacks.saveExtensionSetting("enableEncodingBypass", this.enableEncodingBypass);
    }
    
    public void setEnableCSPBypass(boolean enabled) {
        this.enableCSPBypass = String.valueOf(enabled);
        callbacks.saveExtensionSetting("enableCSPBypass", this.enableCSPBypass);
    }
    
    public void setEnablePolyglotPayloads(boolean enabled) {
        this.enablePolyglotPayloads = String.valueOf(enabled);
        callbacks.saveExtensionSetting("enablePolyglotPayloads", this.enablePolyglotPayloads);
    }
    
    public void setEnableBrowserSpecific(boolean enabled) {
        this.enableBrowserSpecific = String.valueOf(enabled);
        callbacks.saveExtensionSetting("enableBrowserSpecific", this.enableBrowserSpecific);
    }

    // Advanced payload-pack setters (fully wired)
    public void setEnableJSFucker(boolean enabled) {
        this.enableJSFucker = String.valueOf(enabled);
        callbacks.saveExtensionSetting("enableJSFucker", this.enableJSFucker);
    }

    public void setEnablePrototypePollution(boolean enabled) {
        this.enablePrototypePollution = String.valueOf(enabled);
        callbacks.saveExtensionSetting("enablePrototypePollution", this.enablePrototypePollution);
    }

    public void setEnablePostMessageXSS(boolean enabled) {
        this.enablePostMessageXSS = String.valueOf(enabled);
        callbacks.saveExtensionSetting("enablePostMessageXSS", this.enablePostMessageXSS);
    }

    public void setEnableWebComponents(boolean enabled) {
        this.enableWebComponents = String.valueOf(enabled);
        callbacks.saveExtensionSetting("enableWebComponents", this.enableWebComponents);
    }

    public void setEnableShadowDOM(boolean enabled) {
        this.enableShadowDOM = String.valueOf(enabled);
        callbacks.saveExtensionSetting("enableShadowDOM", this.enableShadowDOM);
    }

    public void setEnableWebAssembly(boolean enabled) {
        this.enableWebAssembly = String.valueOf(enabled);
        callbacks.saveExtensionSetting("enableWebAssembly", this.enableWebAssembly);
    }

    public void setEnableModernBrowserAPI(boolean enabled) {
        this.enableModernBrowserAPI = String.valueOf(enabled);
        callbacks.saveExtensionSetting("enableModernBrowserAPI", this.enableModernBrowserAPI);
    }
    
    // Analysis setters
    public void setDetailedReporting(boolean enabled) {
        this.detailedReporting = String.valueOf(enabled);
        callbacks.saveExtensionSetting("detailedReporting", this.detailedReporting);
    }
    
    public void setExploitGeneration(boolean enabled) {
        this.exploitGeneration = String.valueOf(enabled);
        callbacks.saveExtensionSetting("exploitGeneration", this.exploitGeneration);
    }
    
    public void setRemediationSuggestions(boolean enabled) {
        this.remediationSuggestions = String.valueOf(enabled);
        callbacks.saveExtensionSetting("remediationSuggestions", this.remediationSuggestions);
    }
    
    public void setVerboseLogging(boolean enabled) {
        this.verboseLogging = String.valueOf(enabled);
        callbacks.saveExtensionSetting("verboseLogging", this.verboseLogging);
    }

    // Scanner mode setter
    public void setScannerMode(String mode) {
        this.scannerMode = mode;
        callbacks.saveExtensionSetting("scannerMode", this.scannerMode);
    }
    
    // Bypass setters
    public void setBypassCookieChecks(boolean enabled) {
        this.bypassCookieChecks = String.valueOf(enabled);
        callbacks.saveExtensionSetting("bypassCookieChecks", this.bypassCookieChecks);
    }
    
    public void setBypassHeaderChecks(boolean enabled) {
        this.bypassHeaderChecks = String.valueOf(enabled);
        callbacks.saveExtensionSetting("bypassHeaderChecks", this.bypassHeaderChecks);
    }
    
    public void setSkipImageFiles(boolean enabled) {
        this.skipImageFiles = String.valueOf(enabled);
        callbacks.saveExtensionSetting("skipImageFiles", this.skipImageFiles);
    }
    
    public void setEnableTruePositiveOnly(boolean enabled) {
        this.enableTruePositiveOnly = String.valueOf(enabled);
        callbacks.saveExtensionSetting("enableTruePositiveOnly", this.enableTruePositiveOnly);
    }
    
    public void setEnableAdvancedValidation(boolean enabled) {
        this.enableAdvancedValidation = String.valueOf(enabled);
        callbacks.saveExtensionSetting("enableAdvancedValidation", this.enableAdvancedValidation);
    }
    
    public void setEnableContextAwareAnalysis(boolean enabled) {
        this.enableContextAwareAnalysis = String.valueOf(enabled);
        callbacks.saveExtensionSetting("enableContextAwareAnalysis", this.enableContextAwareAnalysis);
    }
    
    // Performance setters - with input validation to prevent crashes
    public void setRequestRateLimit(int limit) {
        if (limit < 0) limit = 0;
        if (limit > 60000) limit = 60000;
        this.requestRateLimit = String.valueOf(limit);
        callbacks.saveExtensionSetting("requestRateLimit", this.requestRateLimit);
    }

    public void setConnectionTimeout(int timeout) {
        if (timeout < 1000) timeout = 1000;
        if (timeout > 120000) timeout = 120000;
        this.connectionTimeout = String.valueOf(timeout);
        callbacks.saveExtensionSetting("connectionTimeout", this.connectionTimeout);
    }

    public void setRetryAttempts(int attempts) {
        if (attempts < 0) attempts = 0;
        if (attempts > 10) attempts = 10;
        this.retryAttempts = String.valueOf(attempts);
        callbacks.saveExtensionSetting("retryAttempts", this.retryAttempts);
    }

    public void setReadTimeout(int timeout) {
        if (timeout < 1000) timeout = 1000;
        if (timeout > 120000) timeout = 120000;
        this.readTimeout = String.valueOf(timeout);
        callbacks.saveExtensionSetting("readTimeout", this.readTimeout);
    }
    
    // Content type management
    public void saveContentTypes() {
        String arrayPrepared = prepareArray();
        callbacks.saveExtensionSetting(CONTENT_TYPES, arrayPrepared);
    }
    
    private String prepareArray() {
        StringBuilder sb = new StringBuilder();
        for (Object[] contentType : contentTypes) {
            if (sb.length() > 0) {
                sb.append(DIVIDER_ARRAY);
            }
            sb.append(contentType[0]).append(DIVIDER_OBJECT).append(contentType[1]);
        }
        return sb.toString();
    }
    
    private ArrayList<Object[]> extractArray(String arrayPrepared) {
        ArrayList<Object[]> result = new ArrayList<>();
        if (arrayPrepared != null && !arrayPrepared.isEmpty()) {
            String[] parts = arrayPrepared.split(Pattern.quote(DIVIDER_ARRAY));
            for (String part : parts) {
                String[] subParts = part.split(Pattern.quote(DIVIDER_OBJECT));
                if (subParts.length == 2) {
                    result.add(new Object[]{subParts[0], Boolean.valueOf(subParts[1])});
                }
            }
        }
        return result;
    }
    
    public ArrayList<String> getEnabledContentTypes() {
        return enabledContentTypes;
    }
    
    private ArrayList<String> extractEnabledContentTypes() {
        ArrayList<String> enabled = new ArrayList<>();
        for (Object[] contentType : contentTypes) {
            if ((Boolean) contentType[1]) {
                enabled.add((String) contentType[0]);
            }
        }
        return enabled;
    }
    
    public ArrayList<Object[]> getContentTypes() {
        return contentTypes;
    }
    
    public void setContentTypes(ArrayList<Object[]> contentTypes) {
        this.contentTypes = contentTypes;
        this.enabledContentTypes = extractEnabledContentTypes();
    }
    
    private boolean isHighRiskContentType(String contentType) {
        if (contentType == null) return false;
        String lowerContentType = contentType.toLowerCase();
        return lowerContentType.contains("text/html") ||
               lowerContentType.contains("application/json") ||
               lowerContentType.contains("text/xml") ||
               lowerContentType.contains("application/xml") ||
               lowerContentType.contains("text/javascript") ||
               lowerContentType.contains("application/javascript");
    }
}