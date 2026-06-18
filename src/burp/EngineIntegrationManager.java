package burp;

import java.util.*;
import java.util.regex.Pattern;
import java.util.regex.Matcher;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * Engine Integration Manager - Professional XSS Detection Orchestration
 * Streamlines all XSS detection engines for optimal performance and accuracy
 */
public class EngineIntegrationManager {
    
    private final IExtensionHelpers helpers;
    private final IBurpExtenderCallbacks callbacks;
    private final Settings settings;
    
    // Core detection engines
    private EnhancedAggressive aggressiveEngine;
    private EnhancedDOMXSSDetector domXssDetector;
    private ModernArchitectureDetector architectureDetector;
    private EnhancedClientSideAttackDetector clientSideDetector;
    private AdvancedFilteringEngine filteringEngine;
    private PayloadManager payloadManager;
    
    // Performance monitoring
    private long scanStartTime;
    private int totalParametersTested;
    private int vulnerabilitiesConfirmed;
    private Map<String, Integer> engineResults;
    
    // Evidence collection
    private Map<String, Object> evidenceCollection;
    
    /**
     * Constructor with basic parameters - creates own engine instances (legacy)
     */
    public EngineIntegrationManager(IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks, Settings settings) {
        this(helpers, callbacks, settings, null, null, null, null, null);
    }

    /**
     * Constructor with engine injection - uses provided instances to avoid duplication
     * This is the preferred constructor to avoid creating duplicate engine instances.
     */
    public EngineIntegrationManager(IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks, Settings settings,
            EnhancedDOMXSSDetector domXssDetector,
            EnhancedClientSideAttackDetector clientSideDetector,
            ModernArchitectureDetector architectureDetector,
            AdvancedFilteringEngine filteringEngine,
            EnhancedAggressive aggressiveEngine) {
        this.helpers = helpers;
        this.callbacks = callbacks;
        this.settings = settings;
        this.engineResults = new HashMap<>();
        this.evidenceCollection = new HashMap<>();

        // Use injected instances if provided, otherwise create new ones
        this.domXssDetector = domXssDetector;
        this.clientSideDetector = clientSideDetector;
        this.architectureDetector = architectureDetector;
        this.filteringEngine = filteringEngine;
        this.aggressiveEngine = aggressiveEngine;

        initializeEngines();
    }

    /**
     * Initialize detection engines - only creates instances for engines not already injected
     */
    private void initializeEngines() {
        try {
            // PayloadManager is always created here as it's internal to this class
            this.payloadManager = new PayloadManager(settings, callbacks);

            // Only create engines that weren't injected
            if (this.filteringEngine == null) {
                this.filteringEngine = new AdvancedFilteringEngine(helpers, callbacks, settings);
            }
            if (this.architectureDetector == null) {
                this.architectureDetector = new ModernArchitectureDetector(helpers, callbacks, settings);
            }
            if (this.domXssDetector == null) {
                this.domXssDetector = new EnhancedDOMXSSDetector(helpers, callbacks, settings);
            }
            if (this.clientSideDetector == null) {
                this.clientSideDetector = new EnhancedClientSideAttackDetector(helpers, callbacks, settings);
            }
        } catch (Exception e) {
            callbacks.printError("Error initializing engines: " + e.getMessage());
        }
    }
    
    /**
     * Perform active scan for XSS vulnerabilities with confirmed detection
     */
    public List<IScanIssue> performActiveScan(IHttpRequestResponse requestResponse, IScannerInsertionPoint insertionPoint) {
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
            List<String> payloads;
            try {
                Map<String, Object> param = new HashMap<>();
                param.put(Constants.NAME, insertionPointName);
                param.put(Constants.TYPE, insertionPoint.getInsertionPointType());
                param.put("CONTENT_TYPE", contentType);
                
                // CRITICAL: Perform architecture analysis and pass to payload generation
                try {
                    if (architectureDetector != null) {
                        ModernArchitectureDetector.ArchitectureAnalysis archAnalysis = architectureDetector.analyzeArchitecture(requestResponse);
                        if (archAnalysis != null) {
                            param.put("ARCH_ANALYSIS", archAnalysis);
                        }
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
                    if (settings.getModernDetection() && domXssDetector != null) {
                        EnhancedDOMXSSDetector.DOMXSSResult domResult = domXssDetector.analyzeDOMXSS(requestResponse);
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
                    if (settings.getModernDetection() && clientSideDetector != null) {
                        EnhancedClientSideAttackDetector.ClientSideAttackResult clientResult = clientSideDetector.analyzeClientSideAttacks(requestResponse);
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
                
                payloads = payloadManager != null
                    ? payloadManager.getContextAwarePayloads(param, requestResponse, helpers)
                    : Arrays.asList(Constants.CORE_XSS_PAYLOADS);
            } catch (Exception e) {
                payloads = Arrays.asList(Constants.CORE_XSS_PAYLOADS);
            }

            // Payload cap per parameter - balance between thoroughness and speed.
            // 18 was too low and missed bypasses that required context-specific payloads.
            int maxPayloads = 35; // Default: covers simple + core payloads effectively
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
                        maxPayloads = 150; // Full coverage in aggressive/expert mode
                    } else if (hasAdvancedFeatures) {
                        maxPayloads = 75; // Extended testing with advanced features
                    }
                }
            } catch (Exception ignored) {}
            
            // CRITICAL: Get base response body to analyze context BEFORE encoding
            // Uses charset detection from Content-Type header (not hardcoded UTF-8)
            String baseResponseBody = null;
            String detectedContext = "UNKNOWN";
            String applicationType = null;
            try {
                baseResponseBody = extractResponseBody(requestResponse);
                // Get application type from param if available
                Map<String, Object> param = new HashMap<>();
                param.put(Constants.NAME, insertionPoint.getInsertionPointName());
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
                // Ignore - will use defaults
            }
            
            // Initialize aggressiveEngine early for context-aware encoding
            if (aggressiveEngine == null && requestResponse != null) {
                try {
                    aggressiveEngine = new EnhancedAggressive(settings, helpers, requestResponse, callbacks, new ArrayList<>());
                } catch (Exception e) {
                    callbacks.printError("Error initializing aggressiveEngine for encoding: " + e.getMessage());
                }
            }
            
            int tested = 0;
            for (String payload : payloads) {
                try {
                    if (tested++ >= maxPayloads) break;
                    
                    // CRITICAL: Get parameter type for context-aware encoding
                    byte insertionPointType = insertionPoint.getInsertionPointType();
                    int paramType = insertionPointType;
                    boolean isURLParameter = (insertionPointType == IParameter.PARAM_URL);
                    
                    // CRITICAL: Use context-aware encoding via aggressiveEngine if available
                    String encodedPayload = payload;
                    if (aggressiveEngine != null) {
                        try {
                            String context = detectedContext;
                            // Analyze context from base response if available
                            if (baseResponseBody != null) {
                                // Try to get context from base response structure
                                if (baseResponseBody.contains("<script") || baseResponseBody.contains("</script>")) {
                                    context = "HTML Body Context";
                                } else if (baseResponseBody.trim().startsWith("{") || baseResponseBody.trim().startsWith("[")) {
                                    context = "JSON";
                                } else if (baseResponseBody.contains("<?xml") || baseResponseBody.contains("<xml")) {
                                    context = "XML";
                                }
                            }
                            
                            // Use context-aware encoding
                            encodedPayload = aggressiveEngine.encodePayloadForContext(
                                payload, context, contentType, paramType, applicationType
                            );
                        } catch (Exception e) {
                            // Fall back to basic encoding
                            if (settings != null && settings.getVerboseLogging()) {
                                callbacks.printOutput("Could not use context-aware encoding: " + e.getMessage());
                            }
                        }
                    }
                    
                    // Fallback: Basic URL encoding if context-aware encoding failed or not available
                    if (encodedPayload.equals(payload) && isURLParameter) {
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
                    }
                    
                    // Create test request with ENCODED payload
                    // CRITICAL: For URL parameters, buildRequest might not URL-encode automatically
                    // We need to verify and manually fix if needed
                    byte[] testRequest = insertionPoint.buildRequest(encodedPayload.getBytes());
                    
                    // CRITICAL FIX: Verify and enforce URL encoding for URL parameters
                    // buildRequest might decode or not preserve URL encoding - we must fix it
                    if (isURLParameter) {
                        try {
                            String requestStr = new String(testRequest, StandardCharsets.UTF_8);
                            String ipName = insertionPoint.getInsertionPointName();
                            String encodedParamName = helpers.urlEncode(ipName);
                            
                            // Check if raw (unencoded) payload appears in the request
                            String pattern1 = "?" + ipName + "=" + payload;
                            String pattern2 = "&" + ipName + "=" + payload;
                            String pattern3 = "?" + encodedParamName + "=" + payload;
                            String pattern4 = "&" + encodedParamName + "=" + payload;
                            
                            boolean needsFix = requestStr.contains(pattern1) || requestStr.contains(pattern2) ||
                                             requestStr.contains(pattern3) || requestStr.contains(pattern4);
                            
                            // Additional check: verify encoded payload is present
                            if (!needsFix) {
                                String encodedPattern1 = "?" + ipName + "=" + encodedPayload;
                                String encodedPattern2 = "&" + ipName + "=" + encodedPayload;
                                String encodedPattern3 = "?" + encodedParamName + "=" + encodedPayload;
                                String encodedPattern4 = "&" + encodedParamName + "=" + encodedPayload;
                                
                                boolean hasEncoded = requestStr.contains(encodedPattern1) || requestStr.contains(encodedPattern2) ||
                                                   requestStr.contains(encodedPattern3) || requestStr.contains(encodedPattern4);
                                
                                if (!hasEncoded) {
                                    // Check query string more carefully
                                    int queryStart = requestStr.indexOf("?");
                                    if (queryStart >= 0) {
                                        int queryEnd = requestStr.indexOf(" ", queryStart);
                                        if (queryEnd < 0) queryEnd = requestStr.indexOf("\r\n", queryStart);
                                        if (queryEnd < 0) queryEnd = requestStr.length();
                                        
                                        String queryString = requestStr.substring(queryStart, queryEnd);
                                        if (queryString.contains(ipName + "=" + payload) || 
                                            queryString.contains(encodedParamName + "=" + payload)) {
                                            needsFix = true;
                                        }
                                    }
                                }
                            }
                            
                            if (needsFix) {
                                // buildRequest didn't encode it or decoded it - manually fix
                                String replacement = ipName + "=" + encodedPayload;
                                String replacementEncoded = encodedParamName + "=" + encodedPayload;
                                
                                requestStr = requestStr.replace(pattern1, "?" + replacement);
                                requestStr = requestStr.replace(pattern2, "&" + replacement);
                                requestStr = requestStr.replace(pattern3, "?" + replacementEncoded);
                                requestStr = requestStr.replace(pattern4, "&" + replacementEncoded);
                                
                                // Also handle cases where parameter appears in middle of query string
                                requestStr = requestStr.replace(ipName + "=" + payload, replacement);
                                requestStr = requestStr.replace(encodedParamName + "=" + payload, replacementEncoded);
                                
                                testRequest = requestStr.getBytes(StandardCharsets.UTF_8);
                                callbacks.printOutput("[XSSDetector] MANUALLY FIXED: URL-encoded parameter '" + ipName + "' in GET request");
                                
                                // Final verification
                                String finalCheck = new String(testRequest, StandardCharsets.UTF_8);
                                if (finalCheck.contains(ipName + "=" + payload) && !payload.equals(encodedPayload)) {
                                    callbacks.printError("WARNING: Raw payload still present after fix attempt");
                                }
                            }
                        } catch (Exception e) {
                            callbacks.printError("Could not manually fix URL encoding: " + e.getMessage());
                        }
                    }
                    
                    // ACTUALLY SEND THE REQUEST AND GET REAL RESPONSE - Critical for confirmed detection
                    IHttpRequestResponse testResponse = sendEngineRealHttpRequest(httpService, testRequest);
                    if (testResponse == null || testResponse.getResponse() == null || testResponse.getResponse().length == 0) {
                        continue; // Skip if request failed
                    }
                    
                    // Get actual response body
                    byte[] responseBytes = testResponse.getResponse();
                    int bodyOffset = helpers.analyzeResponse(responseBytes).getBodyOffset();
                    String responseBody = new String(Arrays.copyOfRange(responseBytes, bodyOffset, responseBytes.length), StandardCharsets.UTF_8);
                    
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
                    if (validateXSSExploitation(responseBody, encodedPayload, responseContentType)) {
                        isVulnerable = true;
                    }
                    // Check 2: Original payload reflection (if app doesn't URL-encode)
                    else if (validateXSSExploitation(responseBody, payload, responseContentType)) {
                        isVulnerable = true;
                    }
                    // Check 3: Decoded reflection (if we injected URL-encoded, app might decode it)
                    else if (!encodedPayload.equals(payload)) {
                        try {
                            String decodedPayload = helpers.urlDecode(encodedPayload);
                            if (decodedPayload != null && !decodedPayload.equals(encodedPayload)) {
                                if (validateXSSExploitation(responseBody, decodedPayload, responseContentType)) {
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
                    // Initialize aggressiveEngine if needed for bypass detection
                    if (aggressiveEngine == null && requestResponse != null) {
                        try {
                            aggressiveEngine = new EnhancedAggressive(settings, helpers, requestResponse, callbacks, new ArrayList<>());
                        } catch (Exception e) {
                            callbacks.printError("Error initializing aggressiveEngine for bypass detection: " + e.getMessage());
                        }
                    }
                    
                    Map<String, Object> escapingInfo = null;
                    if (aggressiveEngine != null) {
                        escapingInfo = aggressiveEngine.detectEscapingPatterns(responseBody, encodedPayload);
                    }
                    boolean escapingDetected = escapingInfo != null && (Boolean) escapingInfo.get("ESCAPING_DETECTED");
                    
                    if (escapingDetected && !isVulnerable && escapingInfo != null && aggressiveEngine != null) {
                        // Escaping detected but payload not exploitable - try bypasses
                        String escapingType = (String) escapingInfo.get("ESCAPING_TYPE");
                        callbacks.printOutput("[XSSDetector] ESCAPING DETECTED in EngineIntegrationManager - Auto-injecting bypass payloads: " + escapingType);
                        
                        // Generate and test bypass payloads with context awareness
                        String bypassReflectionContext = (String) escapingInfo.get("REFLECTION_CONTEXT");
                        if (bypassReflectionContext == null) {
                            bypassReflectionContext = detectedContext;
                        }
                        List<String> bypassPayloads = null;
                        try {
                            bypassPayloads = aggressiveEngine.generateBypassPayloads(payload, escapingType, bypassReflectionContext);
                        } catch (Exception e) {
                            if (settings != null && settings.getVerboseLogging()) {
                                callbacks.printError("Error generating bypass payloads: " + e.getMessage());
                            }
                        }
                        
                        if (bypassPayloads == null || bypassPayloads.isEmpty()) {
                            continue; // Skip if no bypass payloads generated
                        }
                        int bypassTested = 0;
                        int maxBypassTests = 15; // Limit for engine integration flow
                        
                        for (String bypassPayload : bypassPayloads) {
                            if (bypassTested++ >= maxBypassTests) break;
                            
                            try {
                                // CRITICAL: Use context-aware encoding for bypass payloads
                                String encodedBypass = aggressiveEngine.encodePayloadForContext(
                                    bypassPayload, bypassReflectionContext, contentType, paramType, applicationType
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
                                
                                // Fix URL encoding if needed
                                if (isURLParameter) {
                                    String bypassRequestStr = new String(bypassRequest, StandardCharsets.UTF_8);
                                    String ipName = insertionPoint.getInsertionPointName();
                                    if (bypassRequestStr.contains(ipName + "=" + bypassPayload) && 
                                        !bypassPayload.equals(encodedBypass)) {
                                        bypassRequestStr = bypassRequestStr.replace(
                                            ipName + "=" + bypassPayload,
                                            ipName + "=" + encodedBypass
                                        );
                                        bypassRequest = bypassRequestStr.getBytes(StandardCharsets.UTF_8);
                                    }
                                }
                                
                                // Send bypass request
                                IHttpRequestResponse bypassRR = sendEngineRealHttpRequest(httpService, bypassRequest);
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
                                if (validateXSSExploitation(bypassResponseBody, encodedBypass, bypassContentType)) {
                                    // BYPASS SUCCESSFUL!
                                    callbacks.printOutput("[XSSDetector] BYPASS SUCCESSFUL in EngineIntegrationManager! Payload: " + 
                                        bypassPayload.substring(0, Math.min(50, bypassPayload.length())));
                                    
                                    // Mark as vulnerable and continue with normal flow
                                    isVulnerable = true;
                                    encodedPayload = encodedBypass;
                                    payload = bypassPayload;
                                    responseBody = bypassResponseBody;
                                    responseContentType = bypassContentType;
                                    testResponse = bypassRR;
                                    responseBytes = bypassResponseBytes;
                                    break; // Found successful bypass, exit loop
                                }
                                
                            } catch (Exception e) {
                                // Continue with next bypass
                                if (settings != null && settings.getVerboseLogging()) {
                                    callbacks.printError("Error testing bypass in EngineIntegrationManager: " + e.getMessage());
                                }
                            }
                        }
                    }
                    
                    if (isVulnerable) {
                        // CRITICAL: First verify payload is actually reflected in response
                        // validateXSSExploitation() checks reflection, but we need explicit verification
                        boolean payloadReflectedExplicit = responseBody.contains(encodedPayload) || 
                                                          responseBody.contains(payload);
                        
                        // Check for decoded reflection
                        if (!payloadReflectedExplicit && encodedPayload != null && !encodedPayload.equals(payload)) {
                            try {
                                String decodedPayload = helpers.urlDecode(encodedPayload);
                                if (decodedPayload != null && !decodedPayload.equals(encodedPayload) && responseBody.contains(decodedPayload)) {
                                    payloadReflectedExplicit = true;
                                }
                            } catch (Exception e) {
                                // Ignore
                            }
                        }
                        
                        // CRITICAL FIX: Do NOT use partial reflection - this causes false positives
                        // Partial matches are NOT sufficient proof of vulnerability
                        // Only accept ACTUAL payload reflection (direct, decoded, or URL-encoded)
                        // Check for partial reflection as fallback - REMOVED (too lenient)
                        // if (!payloadReflectedExplicit) {
                        //     String[] payloadParts = payload.split("[<>\"'()\\[\\]{}]");
                        //     int foundParts = 0;
                        //     for (String part : payloadParts) {
                        //         if (part.length() > 3 && responseBody.contains(part)) {
                        //             foundParts++;
                        //         }
                        //     }
                        //     if (foundParts >= Math.max(1, payloadParts.length / 2)) {
                        //         payloadReflectedExplicit = true; // NO - too lenient
                        //     }
                        // }
                        
                        // CRITICAL: If payload is not reflected, skip (false positive)
                        if (!payloadReflectedExplicit) {
                            callbacks.printOutput("[XSSDetector] FALSE POSITIVE FILTERED in EngineIntegrationManager: Payload NOT reflected in response for parameter: " + insertionPointName);
                            continue; // Skip this payload - false positive
                        }
                        
                        // CRITICAL: Perform comprehensive advanced analysis to check for false positives
                        // Initialize aggressiveEngine if needed for advanced analysis
                        if (aggressiveEngine == null && requestResponse != null) {
                            try {
                                aggressiveEngine = new EnhancedAggressive(settings, helpers, requestResponse, callbacks, new ArrayList<>());
                            } catch (Exception e) {
                                callbacks.printError("Error initializing aggressiveEngine for advanced analysis: " + e.getMessage());
                            }
                        }
                        
                        // Build parameter map for analysis
                        Map<String, Object> analysisParam = new HashMap<>();
                        analysisParam.put(Constants.NAME, insertionPointName);
                        analysisParam.put("ORIGINAL_PAYLOAD", payload);
                        analysisParam.put("ENCODED_PAYLOAD", encodedPayload);
                        analysisParam.put("CONTENT_TYPE", responseContentType);
                        
                        // Perform advanced analysis if aggressiveEngine is available
                        boolean contextExploitable = true;
                        String validationFailureReason = null;
                        // CRITICAL: Start with 0 confidence - only increase based on real evidence
                        double confidenceScore = 0.0;
                        String reflectionContext = null;
                        
                        if (aggressiveEngine != null) {
                            try {
                                // Use Object type since AdvancedResponseAnalysis is a nested class
                                Object advancedAnalysisObj = 
                                    aggressiveEngine.analyzeResponseAdvanced(responseBody, payload, analysisParam);
                                
                                // Access methods via reflection
                                if (advancedAnalysisObj != null) {
                                    try {
                                        java.lang.reflect.Method getConfidence = advancedAnalysisObj.getClass().getMethod("getConfidence");
                                        java.lang.reflect.Method getReflectionContext = advancedAnalysisObj.getClass().getMethod("getReflectionContext");
                                        java.lang.reflect.Method isJavaScriptExecution = advancedAnalysisObj.getClass().getMethod("isJavaScriptExecution");
                                        
                                        Object confidenceObj = getConfidence.invoke(advancedAnalysisObj);
                                        Object reflectionContextObj = getReflectionContext.invoke(advancedAnalysisObj);
                                        Object jsExecObj = isJavaScriptExecution.invoke(advancedAnalysisObj);
                                        
                                        // CRITICAL: Only use confidence from analysis if it's based on real evidence
                                        if (confidenceObj instanceof Number) {
                                            double analysisConfidence = ((Number) confidenceObj).doubleValue();
                                            // Only use if > 0 (real evidence found)
                                            if (analysisConfidence > 0.0) {
                                                confidenceScore = analysisConfidence;
                                            }
                                        }
                                        if (reflectionContextObj instanceof String) {
                                            reflectionContext = (String) reflectionContextObj;
                                        }
                                        boolean isJSExec = Boolean.TRUE.equals(jsExecObj);
                                        
                                        // FINAL VALIDATION LAYER: Comprehensive context-aware validation
                                        // Check JavaScript string context
                                        if (reflectionContext != null && 
                                            (reflectionContext.contains("Script str") || reflectionContext.contains("JAVASCRIPT_STRING"))) {
                                            boolean jsExploitable = aggressiveEngine.isJavaScriptStringExploitable(responseBody, encodedPayload);
                                            if (!jsExploitable) {
                                                contextExploitable = false;
                                                validationFailureReason = "JavaScript string safely escaped";
                                                callbacks.printOutput("[XSSDetector] FINAL VALIDATION FAILED in EngineIntegrationManager: " + validationFailureReason);
                                            }
                                        }
                                        
                                        // Check JSON string context
                                        boolean isJSONContext = responseContentType != null && responseContentType.contains("application/json");
                                        if (contextExploitable && isJSONContext) {
                                            boolean jsonStrExploitable = aggressiveEngine.isJSONStringExploitable(responseBody, encodedPayload);
                                            if (!jsonStrExploitable) {
                                                contextExploitable = false;
                                                validationFailureReason = "JSON string safely escaped";
                                                callbacks.printOutput("[XSSDetector] FINAL VALIDATION FAILED in EngineIntegrationManager: " + validationFailureReason);
                                            } else {
                                                // Also check if JSON is exploitable (JSONP/unsafe consumption)
                                                boolean jsonExpl = aggressiveEngine.isJSONExploitable(responseBody, encodedPayload);
                                                if (!jsonExpl) {
                                                    contextExploitable = false;
                                                    validationFailureReason = "JSON not exploitable (no JSONP/unsafe consumption)";
                                                    callbacks.printOutput("[XSSDetector] FINAL VALIDATION FAILED in EngineIntegrationManager: " + validationFailureReason);
                                                }
                                            }
                                        }
                                        
                                        // Check HTML encoding
                                        if (contextExploitable && !isJSExec) {
                                            boolean htmlEncoded = aggressiveEngine.isPayloadHTMLEncoded(responseBody, encodedPayload);
                                            if (htmlEncoded) {
                                                contextExploitable = false;
                                                validationFailureReason = "Payload HTML-encoded and not in JavaScript execution context";
                                                callbacks.printOutput("[XSSDetector] FINAL VALIDATION FAILED in EngineIntegrationManager: " + validationFailureReason);
                                            }
                                        }
                                        
                                        // Check confidence
                                        if (contextExploitable && confidenceScore <= 0.0) {
                                            contextExploitable = false;
                                            validationFailureReason = "Confidence score is 0 (false positive)";
                                            callbacks.printOutput("[XSSDetector] FINAL VALIDATION FAILED in EngineIntegrationManager: " + validationFailureReason);
                                        }
                                    } catch (Exception e) {
                                        if (settings != null && settings.getVerboseLogging()) {
                                            callbacks.printError("Error accessing advanced analysis in EngineIntegrationManager: " + e.getMessage());
                                        }
                                    }
                                }
                            } catch (Exception e) {
                                if (settings != null && settings.getVerboseLogging()) {
                                    callbacks.printError("Error performing advanced analysis in EngineIntegrationManager: " + e.getMessage());
                                }
                            }
                        }
                        
                        // CRITICAL: Filter false positives
                        if (!contextExploitable) {
                            callbacks.printOutput("[XSSDetector] FALSE POSITIVE FILTERED in EngineIntegrationManager: " + 
                                (validationFailureReason != null ? validationFailureReason : "Validation failed") + 
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
                            callbacks.printOutput("[XSSDetector] FALSE POSITIVE FILTERED in EngineIntegrationManager: Payload not in request (" + payloadInRequest + ") or response (" + payloadInResponse + ")");
                            callbacks.printOutput("[XSSDetector] Request check: " + (payloadInRequest ? "PASS" : "FAIL"));
                            callbacks.printOutput("[XSSDetector] Response check: " + (payloadInResponse ? "PASS" : "FAIL"));
                            continue; // Skip - no proof
                        }
                        
                        // FINAL VALIDATION PASSED - Proceed with issue creation
                        callbacks.printOutput("[XSSDetector] FINAL VALIDATION PASSED in EngineIntegrationManager: Payload confirmed in request AND response - creating issue");
                        
                        // Create confirmed vulnerability data with actual request/response
                        Map<String, Object> vulnerabilityData = new HashMap<>();
                        vulnerabilityData.put("paramName", insertionPointName);
                        // Store the encoded payload that was actually injected
                        vulnerabilityData.put("payload", encodedPayload);
                        vulnerabilityData.put("ORIGINAL_PAYLOAD", payload);
                        vulnerabilityData.put("ENCODED_PAYLOAD", encodedPayload);
                        vulnerabilityData.put("SCAN_TYPE", "Engine Integration");
                        // CRITICAL: Only set CONFIRMED_XSS = true AFTER we've verified payload in request AND response
                        vulnerabilityData.put("CONFIRMED_XSS", true);
                        vulnerabilityData.put("CONFIDENCE_SCORE", confidenceScore);
                        vulnerabilityData.put("XSS_SCORE", confidenceScore);
                        vulnerabilityData.put("REFLECTION_CONTEXT", reflectionContext);
                        vulnerabilityData.put("ENHANCED_CONTEXT", "Engine integration confirmed XSS - Content-Type: " + responseContentType);
                        // CRITICAL FIX: Store TEST_REQUEST and TEST_RESPONSE as byte[] for proper validation
                        vulnerabilityData.put("TEST_REQUEST", testRequest);
                        vulnerabilityData.put("TEST_RESPONSE", responseBytes);
                        vulnerabilityData.put("payload", payload); // CRITICAL: Ensure payload key is set
                        vulnerabilityData.put("ORIGINAL_PARAM_VALUE", payload); // Store original value (payload is the test value)
                        vulnerabilityData.put("CONTENT_TYPE", responseContentType);
                        
                        // Mark if this was a bypass
                        if (escapingDetected) {
                            vulnerabilityData.put("BYPASS_PAYLOAD", true);
                            vulnerabilityData.put("ESCAPING_TYPE", escapingInfo.get("ESCAPING_TYPE"));
                            vulnerabilityData.put("BYPASSED_ESCAPING", true);
                        }
                        
                        // Create scan issue with confirmed detection
                        EnhancedIssueReporter issueReporter = new EnhancedIssueReporter(helpers, callbacks, settings);
                        IScanIssue issue = issueReporter.createEnhancedXSSIssue(testResponse, vulnerabilityData);
                        if (issue != null) {
                            issues.add(issue);
                        }
                        
                        // Found confirmed vulnerability, no need to test more payloads
                        break;
                    }
                    
                } catch (Exception e) {
                    callbacks.printError("Error testing payload: " + e.getMessage());
                }
            }
            
        } catch (Exception e) {
            callbacks.printError("Error in engine integration scan: " + e.getMessage());
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
     * Professional XSS scanning orchestration
     */
    public List<Map<String, Object>> performComprehensiveXSSScan(IHttpRequestResponse requestResponse, List<Map> reflectedParameters) {
        scanStartTime = System.currentTimeMillis();
        totalParametersTested = 0;
        vulnerabilitiesConfirmed = 0;
        engineResults.clear();
        evidenceCollection.clear();
        
        List<Map<String, Object>> allVulnerabilities = new ArrayList<>();
        
        try {
            // Step 1: Architecture Analysis
            ModernArchitectureDetector.ArchitectureAnalysis archAnalysis = performArchitectureAnalysis(requestResponse);
            
            // Step 2: Parameter Prioritization
            List<Map> prioritizedParameters = prioritizeParameters(reflectedParameters, archAnalysis);
            
            // Step 3: Professional Testing Pipeline
            for (Map parameter : prioritizedParameters) {
                try {
                    String paramName = (String) parameter.get("NAME");
                    
                    // Test parameter comprehensively with all detection types
                    Map<String, Object> vulnerability = testParameterComprehensively(parameter, requestResponse, archAnalysis);
                    
                    if (vulnerability != null) {
                        // CRITICAL: Validate vulnerability before marking as confirmed
                        // Only mark as CONFIRMED if we have actual payload reflection proof
                        Object testRequestObj = vulnerability.get("TEST_REQUEST");
                        Object testResponseObj = vulnerability.get("TEST_RESPONSE");
                        String payload = (String) vulnerability.get("payload");
                        
                        boolean hasValidProof = false;
                        if (testRequestObj != null && testResponseObj != null && payload != null && !payload.trim().isEmpty()) {
                            try {
                                byte[] testRequest = testRequestObj instanceof byte[] ? (byte[]) testRequestObj : 
                                                    testRequestObj instanceof String ? ((String) testRequestObj).getBytes(StandardCharsets.UTF_8) : null;
                                byte[] testResponse = testResponseObj instanceof byte[] ? (byte[]) testResponseObj : 
                                                     testResponseObj instanceof String ? ((String) testResponseObj).getBytes(StandardCharsets.UTF_8) : null;
                                
                                if (testRequest != null && testResponse != null) {
                                    String requestStr = new String(testRequest, StandardCharsets.UTF_8);
                                    String responseStr = new String(testResponse, StandardCharsets.UTF_8);
                                    
                                    // CRITICAL: Require payload in BOTH request AND response
                                    boolean payloadInRequest = requestStr.contains(payload);
                                    boolean payloadInResponse = responseStr.contains(payload);
                                    
                                    // Check for encoded versions
                                    if (!payloadInRequest) {
                                        String urlEncoded = helpers.urlEncode(payload);
                                        payloadInRequest = requestStr.contains(urlEncoded);
                                    }
                                    if (!payloadInResponse) {
                                        String urlEncoded = helpers.urlEncode(payload);
                                        payloadInResponse = responseStr.contains(urlEncoded);
                                    }
                                    
                                    hasValidProof = payloadInRequest && payloadInResponse;
                                }
                            } catch (Exception e) {
                                // Validation failed - don't confirm
                                hasValidProof = false;
                            }
                        }
                        
                        // Only mark as confirmed if we have valid proof
                        if (hasValidProof) {
                            vulnerability.put("CONFIRMED_XSS", true);
                            vulnerability.put("EXECUTION_CONFIRMED", true);
                            vulnerability.put("VULNERABILITY_CONFIRMED", true);
                            allVulnerabilities.add(vulnerability);
                            vulnerabilitiesConfirmed++;
                        } else {
                            callbacks.printOutput("[EngineIntegrationManager] FALSE POSITIVE FILTERED: No valid payload reflection proof for vulnerability");
                        }
                    }
                    
                    totalParametersTested++;
                    
                } catch (Exception e) {
                    callbacks.printError("Error testing parameter: " + e.getMessage());
                    totalParametersTested++;
                }
            }
            
            // Step 4: Advanced Detection (if no vulnerabilities found)
            if (allVulnerabilities.isEmpty()) {
                List<Map<String, Object>> advancedVulns = performAdvancedDetection(requestResponse, archAnalysis);
                allVulnerabilities.addAll(advancedVulns);
                vulnerabilitiesConfirmed += advancedVulns.size();
            }
            
            // Step 5: Generate comprehensive report
            generateScanReport(allVulnerabilities, archAnalysis);
            
        } catch (Exception e) {
            callbacks.printError("Error in comprehensive scan: " + e.getMessage());
        }
        
        return allVulnerabilities;
    }
    
    /**
     * Perform comprehensive architecture analysis
     */
    private ModernArchitectureDetector.ArchitectureAnalysis performArchitectureAnalysis(IHttpRequestResponse requestResponse) {
        try {
            ModernArchitectureDetector.ArchitectureAnalysis analysis = architectureDetector.analyzeArchitecture(requestResponse);
            evidenceCollection.put("architecture_analysis", analysis);
            return analysis;
        } catch (Exception e) {
            callbacks.printError("Error in architecture analysis: " + e.getMessage());
            return null;
        }
    }
    
    /**
     * Professional parameter prioritization
     */
    private List<Map> prioritizeParameters(List<Map> parameters, ModernArchitectureDetector.ArchitectureAnalysis archAnalysis) {
        List<Map> prioritized = new ArrayList<>(parameters);
        
        // Sort by risk level
        prioritized.sort((p1, p2) -> {
            int risk1 = calculateParameterRisk(p1, archAnalysis);
            int risk2 = calculateParameterRisk(p2, archAnalysis);
            return Integer.compare(risk2, risk1); // Higher risk first
        });
        
        return prioritized;
    }
    
    /**
     * Calculate parameter risk score
     */
    private int calculateParameterRisk(Map parameter, ModernArchitectureDetector.ArchitectureAnalysis archAnalysis) {
        int risk = 50; // Base risk
        
        try {
            String paramName = (String) parameter.get("NAME");
            String paramValue = (String) parameter.get("VALUE");
            
            // Parameter name risk factors
            if (paramName != null) {
                String lowerName = paramName.toLowerCase();
                if (lowerName.contains("search") || lowerName.contains("query")) risk += 20;
                if (lowerName.contains("input") || lowerName.contains("text")) risk += 15;
                if (lowerName.contains("url") || lowerName.contains("redirect")) risk += 25;
                if (lowerName.contains("comment") || lowerName.contains("message")) risk += 20;
                if (lowerName.contains("content") || lowerName.contains("body")) risk += 15;
            }
            
            // Parameter value risk factors
            if (paramValue != null) {
                if (paramValue.length() > 100) risk += 10;
                if (paramValue.contains("<") || paramValue.contains(">")) risk += 30;
                if (paramValue.contains("javascript:") || paramValue.contains("data:")) risk += 40;
            }
            
            // Architecture risk factors
            if (archAnalysis != null) {
                if (archAnalysis.getRiskLevel().equals("HIGH")) risk += 20;
                if (archAnalysis.getPrimaryArchitecture().contains("SPA")) risk += 15;
                if (archAnalysis.getPrimaryArchitecture().contains("API")) risk += 10;
            }
            
        } catch (Exception e) {
            // Ignore calculation errors
        }
        
        return Math.min(100, risk);
    }
    
    /**
     * Test parameter comprehensively with all detection types
     */
    private Map<String, Object> testParameterComprehensively(Map parameter, IHttpRequestResponse requestResponse, 
                                                           ModernArchitectureDetector.ArchitectureAnalysis archAnalysis) {
        Map<String, Object> vulnerability = null;
        
        // Test with different detection methods in order of priority
        String[] scanTypes = {"Basic", "Advanced", "DOM", "ClientSide"};
        
        for (String scanType : scanTypes) {
            try {
                switch (scanType) {
                    case "Basic":
                        vulnerability = performBasicXSSTesting(parameter, requestResponse);
                        break;
                    case "Advanced":
                        vulnerability = performAdvancedXSSTesting(parameter, requestResponse);
                        break;
                    case "DOM":
                        vulnerability = performDOMXSSTesting(parameter, requestResponse);
                        break;
                    case "ClientSide":
                        vulnerability = performClientSideAttackTesting(parameter, requestResponse);
                        break;
                }
                
                if (vulnerability != null) {
                    vulnerability.put("scanType", scanType);
                    vulnerability.put("archAnalysis", archAnalysis);
                    break;
                }
                
            } catch (Exception e) {
                callbacks.printError("Error in " + scanType + " testing: " + e.getMessage());
            }
        }
        
        return vulnerability;
    }
    
    private int getScanTypePriority(String scanType) {
        switch (scanType.toLowerCase()) {
            case "basic": return 1;
            case "advanced": return 2;
            case "dom": return 3;
            case "clientside": return 4;
            default: return 0;
        }
    }
    
    private Map<String, Object> performBasicXSSTesting(Map parameter, IHttpRequestResponse requestResponse) {
        try {
            this.aggressiveEngine = new EnhancedAggressive(settings, helpers, requestResponse, callbacks, Arrays.asList(parameter));
            List<Map> results = aggressiveEngine.scanReflectedParameters();
            
            if (results != null && !results.isEmpty()) {
                return convertToVulnerabilityData(results.get(0), "Basic");
            }
        } catch (Exception e) {
            callbacks.printError("Error in basic XSS testing: " + e.getMessage());
        }
        return null;
    }
    
    private Map<String, Object> performAdvancedXSSTesting(Map parameter, IHttpRequestResponse requestResponse) {
        try {
            // Advanced testing with enhanced payloads
            String paramName = (String) parameter.get("NAME");
            List<String> advancedPayloads = payloadManager.getAdvancedPayloads(parameter);
            
            for (String payload : advancedPayloads) {
                    Map<String, Object> result = testPayloadWithRealRequest(parameter, payload, requestResponse);
                    if (result != null) {
                    return convertToVulnerabilityData(result, "Advanced");
                }
            }
        } catch (Exception e) {
            callbacks.printError("Error in advanced XSS testing: " + e.getMessage());
        }
        return null;
    }
    
    private Map<String, Object> performDOMXSSTesting(Map parameter, IHttpRequestResponse requestResponse) {
        try {
            EnhancedDOMXSSDetector.DOMXSSResult domResult = domXssDetector.analyzeDOMXSS(requestResponse);
            
            if (domResult != null && domResult.isVulnerable()) {
                Map<String, Object> result = new HashMap<>();
                result.put("vulnerabilityType", "DOM XSS");
                result.put("payload", domResult.getSpecificPayloads().get(0)); // Use a specific payload
                result.put("paramName", parameter.get("NAME"));
                result.put("severity", domResult.getRiskLevel());
                result.put("confidence", domResult.getConfidenceLevel());
                result.put("TEST_REQUEST", domResult.getTestRequest());
                result.put("TEST_RESPONSE", domResult.getTestResponse());
                
                return convertToVulnerabilityData(result, "DOM");
            }
        } catch (Exception e) {
            callbacks.printError("Error in DOM XSS testing: " + e.getMessage());
        }
        return null;
    }
    
    private Map<String, Object> performClientSideAttackTesting(Map parameter, IHttpRequestResponse requestResponse) {
        try {
            EnhancedClientSideAttackDetector.ClientSideAttackResult clientResult = clientSideDetector.analyzeClientSideAttacks(requestResponse);
            
            if (clientResult != null && clientResult.isVulnerable()) {
                Map<String, Object> result = new HashMap<>();
                result.put("vulnerabilityType", "Client-Side Attack");
                result.put("payload", clientResult.getExploitPOC()); // Use exploitPOC for payload
                result.put("paramName", parameter.get("NAME"));
                result.put("severity", clientResult.getRiskScore());
                result.put("confidence", "Certain"); // Client-side attacks are often certain
                result.put("TEST_REQUEST", clientResult.getTestRequest());
                result.put("TEST_RESPONSE", clientResult.getTestResponse());
                
                return convertToVulnerabilityData(result, "ClientSide");
            }
        } catch (Exception e) {
            callbacks.printError("Error in client-side attack testing: " + e.getMessage());
        }
        return null;
    }
    
    private Map<String, Object> testPayloadWithRealRequest(Map parameter, String payload, IHttpRequestResponse requestResponse) {
        try {
            // CRITICAL: Create actual test request with payload using helpers.updateParameter()
            // This properly injects the payload into the request (not synthetic/fake)
            IRequestInfo requestInfo = helpers.analyzeRequest(requestResponse);
            List<IParameter> parameters = requestInfo.getParameters();
            
            String paramName = (String) parameter.get("NAME");
            byte[] testRequest = requestResponse.getRequest();
            
            // Find and update the parameter with payload
            for (IParameter param : parameters) {
                if (param.getName().equals(paramName)) {
                    IParameter newParam = helpers.buildParameter(paramName, payload, param.getType());
                    testRequest = helpers.updateParameter(testRequest, newParam);
                    break;
                }
            }
            
            // CRITICAL: Send ACTUAL HTTP request and get REAL response (not synthetic)
            IHttpRequestResponse testResponse = sendEngineRealHttpRequest(requestResponse.getHttpService(), testRequest);
            
            // CRITICAL: Initialize aggressiveEngine BEFORE validateXSSExploitation (needed for JSON exploitability check)
            if (aggressiveEngine == null && requestResponse != null) {
                try {
                    aggressiveEngine = new EnhancedAggressive(settings, helpers, requestResponse, callbacks, new ArrayList<>());
                } catch (Exception e) {
                    callbacks.printError("Error initializing aggressiveEngine: " + e.getMessage());
                }
            }
            
            if (testResponse != null && testResponse.getResponse() != null && testResponse.getResponse().length > 0) {
                // Get actual response body from real HTTP response
                byte[] responseBytes = testResponse.getResponse();
                int bodyOffset = helpers.analyzeResponse(responseBytes).getBodyOffset();
                String responseBody = new String(Arrays.copyOfRange(responseBytes, bodyOffset, responseBytes.length), StandardCharsets.UTF_8);
                
                // Get content type for validation
                String contentType = null;
                try {
                    IResponseInfo responseInfo = helpers.analyzeResponse(responseBytes);
                    List<String> headers = responseInfo.getHeaders();
                    for (String header : headers) {
                        if (header.toLowerCase().startsWith("content-type:")) {
                            contentType = header.substring(13).trim().split(";")[0].trim();
                            break;
                        }
                    }
                } catch (Exception e) {
                    // Ignore
                }
                
                boolean isVulnerable = validateXSSExploitation(responseBody, payload, contentType);
                
                if (!isVulnerable && aggressiveEngine != null) {
                    Map<String, Object> escapingInfo = null;
                    try {
                        escapingInfo = aggressiveEngine.detectEscapingPatterns(responseBody, payload);
                    } catch (Exception e) {
                        if (settings != null && settings.getVerboseLogging()) {
                            callbacks.printError("Error detecting escaping patterns in testPayloadWithRealRequest: " + e.getMessage());
                        }
                    }
                    
                    boolean escapingDetected = escapingInfo != null && (Boolean) escapingInfo.get("ESCAPING_DETECTED");
                    
                    if (escapingDetected && escapingInfo != null && aggressiveEngine != null) {
                        String escapingType = (String) escapingInfo.get("ESCAPING_TYPE");
                        callbacks.printOutput("[XSSDetector] ESCAPING DETECTED in testPayloadWithRealRequest - Auto-injecting bypass payloads: " + escapingType);
                        
                        // Generate and test bypass payloads
                        List<String> bypassPayloads = null;
                        try {
                            bypassPayloads = aggressiveEngine.generateBypassPayloads(payload, escapingType, null);
                        } catch (Exception e) {
                            if (settings != null && settings.getVerboseLogging()) {
                                callbacks.printError("Error generating bypass payloads in testPayloadWithRealRequest: " + e.getMessage());
                            }
                        }
                        
                        if (bypassPayloads == null || bypassPayloads.isEmpty()) {
                            return null; // Skip if no bypass payloads generated
                        }
                        
                        int bypassTested = 0;
                        int maxBypassTests = 10; // Limit for this method
                        
                        for (String bypassPayload : bypassPayloads) {
                            if (bypassTested++ >= maxBypassTests) break;
                            
                            try {
                                // Create test request with bypass payload
                                byte[] bypassRequest = requestResponse.getRequest();
                                for (IParameter param : parameters) {
                                    if (param.getName().equals(paramName)) {
                                        IParameter newParam = helpers.buildParameter(paramName, bypassPayload, param.getType());
                                        bypassRequest = helpers.updateParameter(bypassRequest, newParam);
                                        break;
                                    }
                                }
                                
                                // Send bypass request
                                IHttpRequestResponse bypassRR = sendEngineRealHttpRequest(requestResponse.getHttpService(), bypassRequest);
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
                                
                                if (validateXSSExploitation(bypassResponseBody, bypassPayload)) {
                                    // BYPASS SUCCESSFUL!
                                    callbacks.printOutput("[XSSDetector] BYPASS SUCCESSFUL in testPayloadWithRealRequest! Payload: " + 
                                        bypassPayload.substring(0, Math.min(50, bypassPayload.length())));
                                    
                                    // Return successful bypass result
                                    Map<String, Object> result = new HashMap<>();
                                    result.put("vulnerabilityType", "Reflected XSS - Escaping Bypass");
                                    result.put("payload", bypassPayload);
                                    result.put("paramName", paramName);
                                    result.put("severity", "High");
                                    result.put("confidence", "Certain");
                                    result.put("CONFIRMED_XSS", true);
                                    result.put("BYPASS_PAYLOAD", true);
                                    result.put("ESCAPING_TYPE", escapingType);
                                    result.put("BYPASSED_ESCAPING", true);
                                    result.put("TEST_REQUEST", bypassRequest);
                                    result.put("TEST_RESPONSE", bypassResponseBytes);
                                    
                                    return result;
                                }
                                
                            } catch (Exception e) {
                                // Continue with next bypass
                                if (settings != null && settings.getVerboseLogging()) {
                                    callbacks.printError("Error testing bypass in testPayloadWithRealRequest: " + e.getMessage());
                                }
                            }
                        }
                    }
                }
                
                if (isVulnerable) {
                    Map<String, Object> result = new HashMap<>();
                    result.put("vulnerabilityType", "Reflected XSS");
                    result.put("payload", payload);
                    result.put("paramName", paramName);
                    result.put("severity", "High");
                    result.put("confidence", "Certain");
                    result.put("CONFIRMED_XSS", true);
                    // Store actual HTTP request/response (not synthetic)
                    result.put("TEST_REQUEST", testRequest);
                    result.put("TEST_RESPONSE", responseBytes);
                    
                    return result;
                }
            }
        } catch (Exception e) {
            callbacks.printError("Error testing payload with real request: " + e.getMessage());
        }
        return null;
    }
    
    private List<Map<String, Object>> performAdvancedDetection(IHttpRequestResponse requestResponse, 
                                                              ModernArchitectureDetector.ArchitectureAnalysis archAnalysis) {
        List<Map<String, Object>> advancedVulns = new ArrayList<>();
        
        try {
            // GraphQL XSS detection
                List<Map<String, Object>> graphqlVulns = detectGraphQLXSS(requestResponse);
                advancedVulns.addAll(graphqlVulns);
            
            // WebSocket XSS detection
                List<Map<String, Object>> websocketVulns = detectWebSocketXSS(requestResponse);
                advancedVulns.addAll(websocketVulns);
            
            // SPA XSS detection
                List<Map<String, Object>> spaVulns = detectSPAXSS(requestResponse);
                advancedVulns.addAll(spaVulns);
            
        } catch (Exception e) {
            callbacks.printError("Error in advanced detection: " + e.getMessage());
        }
        
        return advancedVulns;
    }
    
    private List<Map<String, Object>> detectGraphQLXSS(IHttpRequestResponse requestResponse) {
        List<Map<String, Object>> vulnerabilities = new ArrayList<>();
        
        try {
            // Check if this is actually a GraphQL endpoint
            if (architectureDetector == null) {
                architectureDetector = new ModernArchitectureDetector(helpers, callbacks, settings);
            }
            ModernArchitectureDetector.ArchitectureAnalysis archAnalysis = architectureDetector.analyzeArchitecture(requestResponse);
            
            if (archAnalysis == null || !archAnalysis.hasGraphQL()) {
                return vulnerabilities; // Not a GraphQL endpoint
            }
            
            // Extract GraphQL parameters using existing infrastructure
            ModernParameterExtractor paramExtractor = new ModernParameterExtractor(helpers, callbacks);
            List<ModernParameter> graphqlParams = paramExtractor.extractGraphQLParameters(requestResponse);
            
            if (graphqlParams == null || graphqlParams.isEmpty()) {
                return vulnerabilities; // No GraphQL parameters found
            }
            
            // Test each GraphQL parameter for XSS using aggressive engine
            if (aggressiveEngine == null) {
                aggressiveEngine = new EnhancedAggressive(settings, helpers, requestResponse, callbacks, new ArrayList<>());
            }
            
            for (ModernParameter gqlParam : graphqlParams) {
                if (gqlParam == null || gqlParam.getName() == null || gqlParam.getValue() == null) {
                    continue;
                }
                
                // Create parameter map for testing
                Map<String, Object> param = new HashMap<>();
                param.put(Constants.NAME, gqlParam.getName());
                param.put(Constants.VALUE, gqlParam.getValue());
                param.put(Constants.TYPE, IParameter.PARAM_BODY);
                param.put("APPLICATION_TYPE", "GRAPHQL");
                param.put("ARCH_ANALYSIS", archAnalysis);
                
                // Use payload manager to get GraphQL-specific payloads
                if (payloadManager == null) {
                    payloadManager = new PayloadManager(settings, callbacks);
                }
                List<String> graphqlPayloads = payloadManager.getContextAwarePayloads(param, requestResponse);
                
                if (graphqlPayloads == null || graphqlPayloads.isEmpty()) {
                    continue;
                }
                
                // Test each payload with real request
                for (String payload : graphqlPayloads) {
                    if (payload == null || payload.trim().isEmpty()) {
                        continue;
                    }
                    
                    // Test payload with real request
                    Map<String, Object> result = testPayloadWithRealRequest(param, payload, requestResponse);
                    if (result != null && Boolean.TRUE.equals(result.get("CONFIRMED_XSS"))) {
                        result.put("vulnerabilityType", "GraphQL XSS");
                        result.put("SCAN_TYPE", "GraphQL");
                        vulnerabilities.add(result);
                        break; // Found vulnerability, no need to test more payloads
                    }
                }
            }
            
        } catch (Exception e) {
            callbacks.printError("Error in GraphQL XSS detection: " + e.getMessage());
        }
        
        return vulnerabilities;
    }
    
    private List<Map<String, Object>> detectWebSocketXSS(IHttpRequestResponse requestResponse) {
        List<Map<String, Object>> vulnerabilities = new ArrayList<>();
        
        try {
            // Check if WebSocket is detected
            if (architectureDetector == null) {
                architectureDetector = new ModernArchitectureDetector(helpers, callbacks, settings);
            }
            ModernArchitectureDetector.ArchitectureAnalysis archAnalysis = architectureDetector.analyzeArchitecture(requestResponse);
            
            if (archAnalysis == null || !archAnalysis.hasWebSocket()) {
                return vulnerabilities; // No WebSocket detected
            }
            
            // Use client-side attack detector for WebSocket XSS
            if (clientSideDetector == null) {
                clientSideDetector = new EnhancedClientSideAttackDetector(helpers, callbacks, settings);
            }
            
            EnhancedClientSideAttackDetector.ClientSideAttackResult clientResult = clientSideDetector.analyzeClientSideAttacks(requestResponse);
            
            if (clientResult != null && clientResult.isVulnerable()) {
                // Check if WebSocket is part of the vulnerability
                EnhancedClientSideAttackDetector.RealTimeDynamicAnalysisResult realTimeAnalysis = clientResult.getRealTimeDynamicAnalysis();
                if (realTimeAnalysis != null && realTimeAnalysis.isHasRealTimeCommunication()) {
                    // CRITICAL: Require high risk score (>= 85) for client-side issues without active scanning proof
                    // Pattern matching alone is NOT sufficient - require strong evidence
                    int riskScore = clientResult.getRiskScore();
                    if (riskScore >= 85) {
                        // Create vulnerability data from client result
                        Map<String, Object> vulnerabilityData = new HashMap<>();
                        vulnerabilityData.put("vulnerabilityType", "WebSocket XSS");
                        vulnerabilityData.put("SCAN_TYPE", "WebSocket");
                        vulnerabilityData.put("paramName", "WebSocket Communication");
                        vulnerabilityData.put("payload", clientResult.getTestPayload() != null ? clientResult.getTestPayload() : "");
                        vulnerabilityData.put("CONFIRMED_XSS", true);
                        vulnerabilityData.put("CONFIDENCE_SCORE", clientResult.getConfidenceLevel() != null ? 
                            (clientResult.getConfidenceLevel().equals("Certain") ? 95.0 : 80.0) : 70.0);
                        if (clientResult.getTestRequest() != null) {
                            vulnerabilityData.put("TEST_REQUEST", clientResult.getTestRequest().getBytes(StandardCharsets.UTF_8));
                        }
                        if (clientResult.getTestResponse() != null) {
                            vulnerabilityData.put("TEST_RESPONSE", clientResult.getTestResponse().getBytes(StandardCharsets.UTF_8));
                        }
                        vulnerabilities.add(vulnerabilityData);
                    } else {
                        callbacks.printOutput("[EngineIntegrationManager] FALSE POSITIVE FILTERED: WebSocket XSS risk score too low (" + riskScore + ") - requiring >= 85");
                    }
                }
            }
            
            // Also check DOM XSS detector for WebSocket-related flows
            if (domXssDetector == null) {
                domXssDetector = new EnhancedDOMXSSDetector(helpers, callbacks, settings);
            }
            
            EnhancedDOMXSSDetector.DOMXSSResult domResult = domXssDetector.analyzeDOMXSS(requestResponse);
            if (domResult != null && domResult.isVulnerable()) {
                EnhancedDOMXSSDetector.RealTimeDynamicAnalysis realTimeAnalysis = domResult.getRealTimeAnalysis();
                if (realTimeAnalysis != null && realTimeAnalysis.isHasWebSocket()) {
                    // CRITICAL: Require high vulnerability score (>= 85) for DOM XSS without payload reflection
                    // Source-sink correlation alone is NOT sufficient - require strong evidence
                    int vulnerabilityScore = domResult.getVulnerabilityScore();
                    boolean hasSourceSinkCorrelation = domResult.getDataFlows() != null && !domResult.getDataFlows().isEmpty();
                    
                    if (vulnerabilityScore >= 85 || (hasSourceSinkCorrelation && vulnerabilityScore >= 70)) {
                        // Create vulnerability data from DOM result
                        Map<String, Object> vulnerabilityData = new HashMap<>();
                        vulnerabilityData.put("vulnerabilityType", "WebSocket DOM XSS");
                        vulnerabilityData.put("SCAN_TYPE", "WebSocket");
                        vulnerabilityData.put("paramName", "WebSocket DOM XSS");
                        vulnerabilityData.put("payload", domResult.getTestPayload() != null ? domResult.getTestPayload() : "");
                        vulnerabilityData.put("CONFIRMED_XSS", true);
                        vulnerabilityData.put("CONFIDENCE_SCORE", domResult.getConfidenceLevel() != null ? 
                            (domResult.getConfidenceLevel().equals("Certain") ? 95.0 : 80.0) : 70.0);
                        if (domResult.getTestRequest() != null) {
                            vulnerabilityData.put("TEST_REQUEST", domResult.getTestRequest().getBytes(StandardCharsets.UTF_8));
                        }
                        if (domResult.getTestResponse() != null) {
                            vulnerabilityData.put("TEST_RESPONSE", domResult.getTestResponse().getBytes(StandardCharsets.UTF_8));
                        }
                        vulnerabilities.add(vulnerabilityData);
                    } else {
                        callbacks.printOutput("[EngineIntegrationManager] FALSE POSITIVE FILTERED: WebSocket DOM XSS score too low (" + vulnerabilityScore + ") - requiring >= 85 or (source-sink correlation AND >= 70)");
                    }
                }
            }
            
        } catch (Exception e) {
            callbacks.printError("Error in WebSocket XSS detection: " + e.getMessage());
        }
        
        return vulnerabilities;
    }
    
    private List<Map<String, Object>> detectSPAXSS(IHttpRequestResponse requestResponse) {
        List<Map<String, Object>> vulnerabilities = new ArrayList<>();
        
        try {
            // Check if this is a SPA
            if (architectureDetector == null) {
                architectureDetector = new ModernArchitectureDetector(helpers, callbacks, settings);
            }
            ModernArchitectureDetector.ArchitectureAnalysis archAnalysis = architectureDetector.analyzeArchitecture(requestResponse);
            
            if (archAnalysis == null || !archAnalysis.isSPA()) {
                return vulnerabilities; // Not a SPA
            }
            
            // SPA XSS is primarily DOM-based, so use DOM XSS detector
            if (domXssDetector == null) {
                domXssDetector = new EnhancedDOMXSSDetector(helpers, callbacks, settings);
            }
            
            EnhancedDOMXSSDetector.DOMXSSResult domResult = domXssDetector.analyzeDOMXSS(requestResponse);
            if (domResult != null && domResult.isVulnerable()) {
                // Check if we have strong evidence (source-sink correlation or high score)
                boolean hasSourceSinkCorrelation = domResult.getDataFlows() != null && !domResult.getDataFlows().isEmpty();
                EnhancedDOMXSSDetector.RealTimeDynamicAnalysis realTimeAnalysis = domResult.getRealTimeAnalysis();
                boolean hasHighConfidenceRealTime = realTimeAnalysis != null && realTimeAnalysis.hasRealTimeVectors();
                int vulnerabilityScore = domResult.getVulnerabilityScore();
                boolean hasHighScore = vulnerabilityScore >= 70;
                
                // CRITICAL: Require VERY HIGH score (>= 85) for DOM XSS without payload reflection
                // Pattern matching alone is NOT sufficient - require strong evidence
                if (hasSourceSinkCorrelation && vulnerabilityScore >= 85) {
                    // Create vulnerability data from DOM result
                    Map<String, Object> vulnerabilityData = new HashMap<>();
                    vulnerabilityData.put("vulnerabilityType", "SPA DOM XSS");
                    vulnerabilityData.put("SCAN_TYPE", "SPA");
                    vulnerabilityData.put("paramName", "SPA DOM XSS");
                    vulnerabilityData.put("payload", domResult.getTestPayload() != null ? domResult.getTestPayload() : "");
                    vulnerabilityData.put("CONFIRMED_XSS", true);
                    vulnerabilityData.put("CONFIDENCE_SCORE", domResult.getConfidenceLevel() != null ? 
                        (domResult.getConfidenceLevel().equals("Certain") ? 95.0 : 80.0) : 70.0);
                    if (domResult.getTestRequest() != null) {
                        vulnerabilityData.put("TEST_REQUEST", domResult.getTestRequest().getBytes(StandardCharsets.UTF_8));
                    }
                    if (domResult.getTestResponse() != null) {
                        vulnerabilityData.put("TEST_RESPONSE", domResult.getTestResponse().getBytes(StandardCharsets.UTF_8));
                    }
                    vulnerabilities.add(vulnerabilityData);
                } else {
                    callbacks.printOutput("[EngineIntegrationManager] FALSE POSITIVE FILTERED: SPA DOM XSS - requires source-sink correlation AND score >= 85 (current: " + vulnerabilityScore + ")");
                }
            }
            
            // Also check client-side attack detector for SPA-specific issues
            if (clientSideDetector == null) {
                clientSideDetector = new EnhancedClientSideAttackDetector(helpers, callbacks, settings);
            }
            
            EnhancedClientSideAttackDetector.ClientSideAttackResult clientResult = clientSideDetector.analyzeClientSideAttacks(requestResponse);
            if (clientResult != null && clientResult.isVulnerable()) {
                // Check if it's SPA-related (has real-time vectors or high risk)
                EnhancedClientSideAttackDetector.RealTimeDynamicAnalysisResult realTimeAnalysis = clientResult.getRealTimeDynamicAnalysis();
                int riskScore = clientResult.getRiskScore();
                // CRITICAL: Require VERY HIGH risk score (>= 85) for client-side issues without active scanning proof
                // Pattern matching alone is NOT sufficient - require strong evidence
                if (realTimeAnalysis != null && riskScore >= 85) {
                    // Create vulnerability data from client result
                    Map<String, Object> vulnerabilityData = new HashMap<>();
                    vulnerabilityData.put("vulnerabilityType", "SPA Client-Side XSS");
                    vulnerabilityData.put("SCAN_TYPE", "SPA");
                    vulnerabilityData.put("paramName", "SPA Client-Side XSS");
                    vulnerabilityData.put("payload", clientResult.getTestPayload() != null ? clientResult.getTestPayload() : "");
                    vulnerabilityData.put("CONFIRMED_XSS", true);
                    vulnerabilityData.put("CONFIDENCE_SCORE", clientResult.getConfidenceLevel() != null ? 
                        (clientResult.getConfidenceLevel().equals("Certain") ? 95.0 : 80.0) : 70.0);
                    if (clientResult.getTestRequest() != null) {
                        vulnerabilityData.put("TEST_REQUEST", clientResult.getTestRequest().getBytes(StandardCharsets.UTF_8));
                    }
                    if (clientResult.getTestResponse() != null) {
                        vulnerabilityData.put("TEST_RESPONSE", clientResult.getTestResponse().getBytes(StandardCharsets.UTF_8));
                    }
                    vulnerabilities.add(vulnerabilityData);
                } else {
                    callbacks.printOutput("[EngineIntegrationManager] FALSE POSITIVE FILTERED: SPA Client-Side XSS risk score too low (" + riskScore + ") - requiring >= 85");
                }
            }
            
            // Test SPA-specific parameters (hash, history state, etc.) using existing parameter extraction
            ModernParameterExtractor paramExtractor = new ModernParameterExtractor(helpers, callbacks);
            List<ModernParameter> modernParams = paramExtractor.extractParameters(requestResponse);
            
            if (modernParams != null && !modernParams.isEmpty()) {
                for (ModernParameter modernParam : modernParams) {
                    if (modernParam == null || modernParam.getName() == null) {
                        continue;
                    }
                    
                    // Focus on SPA-specific parameters
                    String paramName = modernParam.getName().toLowerCase();
                    if (paramName.contains("hash") || paramName.contains("state") || 
                        paramName.contains("route") || paramName.contains("path")) {
                        
                        // Create parameter map for testing
                        Map<String, Object> param = new HashMap<>();
                        param.put(Constants.NAME, modernParam.getName());
                        param.put(Constants.VALUE, modernParam.getValue());
                        param.put(Constants.TYPE, modernParam.getType());
                        param.put("APPLICATION_TYPE", "SPA");
                        param.put("ARCH_ANALYSIS", archAnalysis);
                        
                        // Use payload manager to get SPA-specific payloads
                        if (payloadManager == null) {
                            payloadManager = new PayloadManager(settings, callbacks);
                        }
                        List<String> spaPayloads = payloadManager.getContextAwarePayloads(param, requestResponse);
                        
                        if (spaPayloads != null && !spaPayloads.isEmpty()) {
                            for (String payload : spaPayloads) {
                                if (payload == null || payload.trim().isEmpty()) {
                                    continue;
                                }
                                
                                Map<String, Object> result = testPayloadWithRealRequest(param, payload, requestResponse);
                                if (result != null && Boolean.TRUE.equals(result.get("CONFIRMED_XSS"))) {
                                    result.put("vulnerabilityType", "SPA Parameter XSS");
                                    result.put("SCAN_TYPE", "SPA");
                                    vulnerabilities.add(result);
                                    break; // Found vulnerability
                                }
                            }
                        }
                    }
                }
            }
            
        } catch (Exception e) {
            callbacks.printError("Error in SPA XSS detection: " + e.getMessage());
        }
        
        return vulnerabilities;
    }
    
    private void generateScanReport(List<Map<String, Object>> vulnerabilities, 
                                  ModernArchitectureDetector.ArchitectureAnalysis archAnalysis) {
        long scanDuration = System.currentTimeMillis() - scanStartTime;
        
        callbacks.printOutput("=== XSS SCAN REPORT ===");
        callbacks.printOutput("Total Parameters Tested: " + totalParametersTested);
        callbacks.printOutput("Vulnerabilities Confirmed: " + vulnerabilitiesConfirmed);
        callbacks.printOutput("Scan Duration: " + scanDuration + "ms");
        
        if (archAnalysis != null) {
            callbacks.printOutput("Architecture: " + archAnalysis.getPrimaryArchitecture());
            callbacks.printOutput("Risk Level: " + archAnalysis.getRiskLevel());
        }
    }
    
    private Map<String, Object> convertToVulnerabilityData(Map result, String scanType) {
        Map<String, Object> vulnerabilityData = new HashMap<>();
        
        vulnerabilityData.put("vulnerabilityType", result.get("vulnerabilityType"));
        vulnerabilityData.put("payload", result.get("payload"));
        vulnerabilityData.put("paramName", result.get("paramName"));
        vulnerabilityData.put("severity", result.get("severity"));
        vulnerabilityData.put("confidence", result.get("confidence"));
        vulnerabilityData.put("scanType", scanType);
        vulnerabilityData.put("TEST_REQUEST", result.get("TEST_REQUEST"));
        vulnerabilityData.put("TEST_RESPONSE", result.get("TEST_RESPONSE"));
        
        return vulnerabilityData;
    }
    
    // REMOVED: createEngineTestRequestWithPayload() - This was a staging stub that returned original request unchanged
    // Replaced with proper implementation using helpers.updateParameter() and sendEngineRealHttpRequest()
    
    private IHttpRequestResponse sendEngineRealHttpRequest(IHttpService httpService, byte[] request) {
        try {
            // Prefer Burp's request engine (handles cookies, upstream proxy, HTTPS, etc.)
            IHttpRequestResponse rr = callbacks.makeHttpRequest(httpService, request);
            if (rr != null && rr.getResponse() != null) {
                return rr;
            }
            // If Burp returns nothing, return an empty response wrapper (do NOT bypass Burp with raw sockets).
            return new CustomHttpRequestResponse(request, new byte[0], httpService);
        } catch (Exception e) {
            callbacks.printError("Error sending HTTP request: " + e.getMessage());
            return null;
        }
    }
    
    private static class CustomHttpRequestResponse implements IHttpRequestResponse {
        private final byte[] request;
        private final byte[] response;
        private final IHttpService httpService;
        
        public CustomHttpRequestResponse(byte[] request, byte[] response, IHttpService httpService) {
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
        public String getComment() { return "REAL XSS Exploited Request"; }
        
        @Override
        public void setComment(String comment) { /* Read-only */ }
        
        @Override
        public String getHighlight() { return "red"; }
        
        @Override
        public void setHighlight(String color) { /* Read-only */ }
        
        @Override
        public IHttpService getHttpService() { return httpService; }
        
        @Override
        public void setHttpService(IHttpService httpService) { /* Read-only */ }
    }
    
    private boolean validateXSSExploitation(String response, String payload) {
        return validateXSSExploitation(response, payload, null);
    }
    
    private boolean validateXSSExploitation(String response, String payload, String contentType) {
        if (response == null || payload == null) {
            return false;
        }
        
        String lowerContentType = contentType != null ? contentType.toLowerCase() : "";
        boolean isJSON = lowerContentType.contains("application/json");
        boolean isHTML = lowerContentType.contains("text/html") || lowerContentType.contains("application/xhtml+xml");
        
        // Check for direct payload reflection (most reliable indicator)
        if (response.contains(payload)) {
            return true;
        }
        
        // For JSON responses, check for JSON-encoded payload
        // CRITICAL: JSON is NOT directly exploitable - only JSONP or unsafe consumption makes it exploitable
        if (isJSON) {
            // Check for JSON string encoding (escaped quotes)
            String jsonEncoded = payload.replace("\"", "\\\"").replace("\\", "\\\\");
            if (response.contains(jsonEncoded)) {
                // CRITICAL: Verify JSON is actually exploitable (JSONP or unsafe consumption)
                // Use aggressiveEngine's isJSONExploitable method if available
                if (aggressiveEngine != null) {
                    return aggressiveEngine.isJSONExploitable(response, payload);
                }
                // If aggressiveEngine not available, be conservative - require direct payload reflection
                // JSON-encoded payload alone is NOT sufficient proof
                return false;
            }
            
            // Check for unicode encoding in JSON
            String unicodeEncoded = payload.replace("<", "\\u003c").replace(">", "\\u003e");
            if (response.contains(unicodeEncoded)) {
                // CRITICAL: Verify JSON is actually exploitable
                if (aggressiveEngine != null) {
                    return aggressiveEngine.isJSONExploitable(response, payload);
                }
                return false;
            }
            
            // Check if payload appears in JSON string values (between quotes)
            Pattern jsonStringPattern = Pattern.compile("\"([^\"]*" + Pattern.quote(payload) + "[^\"]*)\"");
            if (jsonStringPattern.matcher(response).find()) {
                // CRITICAL: Verify JSON is actually exploitable
                if (aggressiveEngine != null) {
                    return aggressiveEngine.isJSONExploitable(response, payload);
                }
                // Without exploitability check, JSON reflection alone is NOT sufficient proof
                return false;
            }
        }
        
        // For HTML responses, check encoding-related reflections
        if (isHTML) {
            // CRITICAL FIX: HTML-entity-encoded payload (&lt;script&gt;) is SAFE.
            // The browser renders it as text, NOT as HTML tags. This is proper output encoding.
            // DO NOT return true for HTML-encoded reflections - that's a FALSE POSITIVE.
            String htmlEncoded = payload.replace("<", "&lt;").replace(">", "&gt;")
                                       .replace("\"", "&quot;").replace("'", "&#39;");
            if (response.contains(htmlEncoded)) {
                // Payload is properly HTML-encoded = SAFE, NOT exploitable
                return false;
            }

            // URL-encoded payload in HTML response body is also generally safe
            // (browser doesn't auto-decode URL encoding in HTML body context)
            // Only relevant if the payload is in a URL context (href, src, etc.)
            String urlEncoded = helpers.urlEncode(payload);
            if (response.contains(urlEncoded) && !response.contains(payload)) {
                // Only URL-encoded version exists - check if it's in a URL context
                int urlEncPos = response.indexOf(urlEncoded);
                if (urlEncPos >= 0) {
                    int ctxStart = Math.max(0, urlEncPos - 100);
                    String before = response.substring(ctxStart, urlEncPos).toLowerCase();
                    // Only exploitable if in href=, src=, action=, or javascript: context
                    if (before.contains("href=") || before.contains("src=") ||
                        before.contains("action=") || before.contains("javascript:")) {
                        return true;
                    }
                }
                return false; // URL-encoded in non-URL context = not exploitable
            }
        }
        
        // CRITICAL FIX: Do NOT use partial reflection - this causes false positives
        // Partial matches are NOT sufficient proof of vulnerability
        // Only accept ACTUAL payload reflection (direct, decoded, or URL-encoded)
        // Check for partial payload reflection - REMOVED (too lenient)
        // String[] payloadParts = payload.split("[<>\"'()\\[\\]{}]");
        // int foundParts = 0;
        // for (String part : payloadParts) {
        //     if (part.length() > 3 && response.contains(part)) {
        //         foundParts++;
        //     }
        // }
        // 
        // return foundParts >= Math.max(1, payloadParts.length / 2); // NO - too lenient
        
        return false; // Payload not reflected - not exploitable
    }

    /**
     * Detect charset from response headers. Falls back to UTF-8 if not found.
     * This prevents garbled responses when servers use ISO-8859-1, Windows-1252, etc.
     */
    private java.nio.charset.Charset detectResponseCharset(IHttpRequestResponse requestResponse) {
        try {
            IResponseInfo respInfo = helpers.analyzeResponse(requestResponse.getResponse());
            for (String header : respInfo.getHeaders()) {
                if (header.toLowerCase().startsWith("content-type:")) {
                    String ct = header.toLowerCase();
                    int charsetIdx = ct.indexOf("charset=");
                    if (charsetIdx >= 0) {
                        String charsetName = ct.substring(charsetIdx + 8).trim();
                        // Remove trailing semicolons or spaces
                        int end = charsetName.indexOf(';');
                        if (end >= 0) charsetName = charsetName.substring(0, end).trim();
                        end = charsetName.indexOf(' ');
                        if (end >= 0) charsetName = charsetName.substring(0, end).trim();
                        // Remove quotes if present
                        charsetName = charsetName.replace("\"", "").replace("'", "");
                        try {
                            return java.nio.charset.Charset.forName(charsetName);
                        } catch (Exception e) {
                            // Unknown charset, fall through to UTF-8
                        }
                    }
                    break;
                }
            }
        } catch (Exception e) {
            // Fall through to default
        }
        return StandardCharsets.UTF_8;
    }

    /**
     * Extract response body as string using the correct charset from Content-Type header.
     */
    private String extractResponseBody(IHttpRequestResponse requestResponse) {
        try {
            byte[] response = requestResponse.getResponse();
            if (response == null || response.length == 0) return "";
            int bodyOffset = helpers.analyzeResponse(response).getBodyOffset();
            if (bodyOffset >= response.length) return "";
            java.nio.charset.Charset charset = detectResponseCharset(requestResponse);
            return new String(Arrays.copyOfRange(response, bodyOffset, response.length), charset);
        } catch (Exception e) {
            return "";
        }
    }

    private boolean isJavaScriptResponse(String response) {
        if (response == null) return false;
        
        String lowerResponse = response.toLowerCase();
        return lowerResponse.contains("<script") || 
               lowerResponse.contains("javascript:") ||
               lowerResponse.contains("onload") ||
               lowerResponse.contains("onerror") ||
               lowerResponse.contains("onclick");
    }
    
    private boolean isJSONResponse(String response) {
        if (response == null) return false;
        
        String trimmed = response.trim();
        return trimmed.startsWith("{") && trimmed.endsWith("}") ||
               trimmed.startsWith("[") && trimmed.endsWith("]");
    }
    
    private boolean isXMLResponse(String response) {
        if (response == null) return false;
        
        String trimmed = response.trim();
        return trimmed.startsWith("<?xml") || 
               trimmed.startsWith("<") && trimmed.endsWith(">");
    }
    
    private boolean isInExecutableContext(String response, String payload) {
        if (response == null || payload == null) {
            return false;
        }
        
        // Check if payload is in JavaScript context
        if (response.contains("<script") && response.contains(payload)) {
            return true;
        }
        
        // Check if payload is in event handler context
        if (response.contains("onload") || response.contains("onerror") || 
            response.contains("onclick") || response.contains("onmouseover")) {
                    return true;
                }
        
        // Check if payload is in URL context
        if (response.contains("href=") && response.contains(payload)) {
            return true;
            }
            
            return false;
    }
} 