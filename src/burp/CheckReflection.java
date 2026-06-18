package burp;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.Arrays;
import java.nio.charset.StandardCharsets;

import static burp.Constants.*;

/**
 * Clean, professional reflection detection for XSSDetector
 * Removes excessive junk code and focuses on essential reflection analysis
 */
public class CheckReflection {

    private static final int MIN_PAYLOAD_LENGTH = 3;
    private int bodyOffset;  // Made non-final to allow instance reuse

    private IExtensionHelpers helpers;
    private IHttpRequestResponse iHttpRequestResponse;
    private Settings settings;
    private IBurpExtenderCallbacks callbacks;
    private PerformanceMonitor performanceMonitor;
    private ErrorRecoverySystem errorRecoverySystem;
    
    // Core components
    private AdvancedFilteringEngine filteringEngine;
    private SessionHandlingManager sessionManager;
    private ModernParameterExtractor modernParameterExtractor;
    private PayloadManager payloadManager;

    public CheckReflection(Settings settings, IExtensionHelpers helpers, IHttpRequestResponse iHttpRequestResponse, IBurpExtenderCallbacks callbacks, PerformanceMonitor performanceMonitor, ErrorRecoverySystem errorRecoverySystem) {
        this.settings = settings;
        this.helpers = helpers;
        this.callbacks = callbacks;
        this.iHttpRequestResponse = iHttpRequestResponse;
        this.bodyOffset = helpers.analyzeResponse(iHttpRequestResponse.getResponse()).getBodyOffset();
        
        this.performanceMonitor = performanceMonitor;
        this.errorRecoverySystem = errorRecoverySystem;
        
        // Initialize core components
        if (settings.getAdvancedFiltering()) {
            this.filteringEngine = new AdvancedFilteringEngine(helpers, callbacks, settings);
        }
        
        if (settings.getSessionHandling()) {
            this.sessionManager = new SessionHandlingManager(helpers, callbacks, settings);
        }
        
        this.modernParameterExtractor = new ModernParameterExtractor(helpers, callbacks);
        this.payloadManager = new PayloadManager(settings, callbacks);
    }
    
    /**
     * Constructor for BurpExtender integration
     */
    public CheckReflection(IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks, Settings settings) {
        this(helpers, callbacks, settings, null, null);
    }
    
    /**
     * Constructor for BurpExtender integration with PerformanceMonitor and ErrorRecoverySystem
     */
    public CheckReflection(IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks, Settings settings,
                          PerformanceMonitor performanceMonitor, ErrorRecoverySystem errorRecoverySystem) {
        this.settings = settings;
        this.helpers = helpers;
        this.callbacks = callbacks;
        this.iHttpRequestResponse = null;
        this.bodyOffset = 0;
        this.performanceMonitor = performanceMonitor;
        this.errorRecoverySystem = errorRecoverySystem;

        // Initialize core components
        if (settings.getAdvancedFiltering()) {
            this.filteringEngine = new AdvancedFilteringEngine(helpers, callbacks, settings);
        }

        if (settings.getSessionHandling()) {
            this.sessionManager = new SessionHandlingManager(helpers, callbacks, settings);
        }

        this.modernParameterExtractor = new ModernParameterExtractor(helpers, callbacks);
        this.payloadManager = new PayloadManager(settings, callbacks);
    }

    /**
     * Set the current request/response for analysis.
     * This allows reusing the same CheckReflection instance across multiple requests.
     * @return The body offset for the response, or -1 if response is null
     */
    public synchronized int setRequestResponse(IHttpRequestResponse requestResponse) {
        this.iHttpRequestResponse = requestResponse;
        if (requestResponse != null && requestResponse.getResponse() != null) {
            try {
                IResponseInfo responseInfo = helpers.analyzeResponse(requestResponse.getResponse());
                this.bodyOffset = responseInfo.getBodyOffset();
                return this.bodyOffset;
            } catch (Exception e) {
                callbacks.printError("CheckReflection: Error analyzing response: " + e.getMessage());
                this.bodyOffset = 0;
                return -1;
            }
        }
        this.bodyOffset = 0;
        return -1;
    }

    /**
     * Check response with the given request/response pair.
     * This is the preferred method - reuses instance and sets request/response inline.
     */
    public synchronized List<Map> checkResponseFor(IHttpRequestResponse requestResponse) {
        setRequestResponse(requestResponse);
        return checkResponse();
    }
    
    /**
     * Perform passive scan for XSS vulnerabilities with comprehensive error handling
     */
    public synchronized List<IScanIssue> doPassiveScan(IHttpRequestResponse requestResponse) {
        List<IScanIssue> issues = new ArrayList<>();

        try {
            if (requestResponse == null) {
                callbacks.printError("CheckReflection: Request/response is null");
                return issues;
            }

            if (requestResponse.getResponse() == null) {
                callbacks.printError("CheckReflection: Response is null");
                return issues;
            }

            // Reuse this instance - set the request/response and check
            // This avoids creating a new instance per request (performance improvement)
            List<Map> reflectedParameters = checkResponseFor(requestResponse);
            
            // CRITICAL: First, extract all issues that were created by EnhancedAggressive
            // These are stored in the parameter maps, but we need to collect them separately
            // to ensure none are lost
            Set<IScanIssue> enhancedIssues = new HashSet<>();
            if (reflectedParameters != null && !reflectedParameters.isEmpty()) {
                for (Map parameter : reflectedParameters) {
                    if (parameter != null) {
                        Object issueCreatedByEnhanced = parameter.get("ISSUE_CREATED_BY_ENHANCED");
                        Object enhancedIssue = parameter.get("ENHANCED_ISSUE");
                        if (Boolean.TRUE.equals(issueCreatedByEnhanced) && enhancedIssue instanceof IScanIssue) {
                            enhancedIssues.add((IScanIssue) enhancedIssue);
                            callbacks.printOutput("[CheckReflection] Found issue created by EnhancedAggressive");
                        }
                        // Also check if the parameter Map itself contains an ISSUE
                        Object issueObj = parameter.get("ISSUE");
                        if (issueObj instanceof IScanIssue) {
                            enhancedIssues.add((IScanIssue) issueObj);
                            callbacks.printOutput("[CheckReflection] Found issue in parameter Map");
                        }
                    }
                }
            }
            
            // CRITICAL: Also check if EnhancedAggressive has a createdIssues list we can access
            // This is a fallback in case issues weren't properly stored in parameter Maps
            try {
                // Try to get issues from the enhanced scan results directly
                if (reflectedParameters != null && !reflectedParameters.isEmpty() && 
                    (settings.getEnableTruePositiveOnly() || settings.getAggressiveMode())) {
                    // Re-run EnhancedAggressive to get issues (if not already done in checkResponse)
                    // Actually, checkResponse already calls EnhancedAggressive, so issues should be in parameter Maps
                    // But let's also check the enhancedResults from checkResponse
                }
            } catch (Exception e) {
                // Ignore - fallback mechanism
            }
            
            // Add all enhanced issues to the issues list
            issues.addAll(enhancedIssues);
            // Only log when something was actually collected, and only in verbose mode -
            // this runs on every passive scan and was pure noise ("Added 0 issues ...").
            if (!enhancedIssues.isEmpty() && settings != null && settings.getVerboseLogging()) {
                callbacks.printOutput("[CheckReflection] Added " + enhancedIssues.size() + " issues from EnhancedAggressive");
            }
            
            if (reflectedParameters == null || reflectedParameters.isEmpty()) {
                return issues; // Return any enhanced issues even if no reflected parameters
            }
            
            // Convert reflected parameters to scan issues (only if not already created by EnhancedAggressive)
            for (Map parameter : reflectedParameters) {
                try {
                    if (parameter == null) {
                        continue; // Skip null parameters
                    }
                    
                    // Validate required fields
                    Object paramNameObj = parameter.get(NAME);
                    Object paramValueObj = parameter.get(VALUE);
                    Object paramTypeObj = parameter.get(TYPE);
                    
                    if (paramNameObj == null || paramValueObj == null) {
                        continue; // Skip invalid parameters
                    }
                    
                    String paramName = paramNameObj.toString();
                    String paramValue = paramValueObj.toString();
                    
                    if (paramName.trim().isEmpty() || paramValue.trim().isEmpty()) {
                        continue; // Skip empty parameters
                    }
                    
                    // Determine parameter type and check if it's a URL parameter
                    int paramTypeInt = IParameter.PARAM_BODY; // Default
                    boolean isURLParameter = false;
                    if (paramTypeObj != null) {
                        if (paramTypeObj instanceof Integer) {
                            paramTypeInt = ((Integer) paramTypeObj).intValue();
                        } else if (paramTypeObj instanceof Byte) {
                            paramTypeInt = ((Byte) paramTypeObj).byteValue();
                        }
                        // CRITICAL: Check if this is a URL parameter
                        isURLParameter = (paramTypeInt == IParameter.PARAM_URL);
                    }
                    
                    // CRITICAL FIX: Also check request method and URL structure to detect URL parameters
                    if (!isURLParameter) {
                        try {
                            IRequestInfo reqInfo = helpers.analyzeRequest(requestResponse);
                            String method = reqInfo.getMethod();
                            java.net.URL url = reqInfo.getUrl();
                            String urlStr = url.toString();
                            
                            // GET requests with query parameters are URL parameters
                            if ("GET".equals(method) && urlStr.contains("?")) {
                                // Check if parameter name appears in query string
                                if (urlStr.contains(paramName + "=") || urlStr.contains(helpers.urlEncode(paramName) + "=")) {
                                    isURLParameter = true;
                                    paramTypeInt = IParameter.PARAM_URL;
                                    callbacks.printOutput("[CheckReflection] Detected URL parameter: " + paramName + " (via GET method and query string)");
                                }
                            }
                        } catch (Exception e) {
                            // Ignore
                        }
                    }
                    
                    // Create comprehensive vulnerability data
                    Map<String, Object> vulnerabilityData = new HashMap<>();
                    vulnerabilityData.put("paramName", paramName);
                    vulnerabilityData.put("payload", paramValue);
                    vulnerabilityData.put("ORIGINAL_PARAM_VALUE", paramValue); // CRITICAL: Store original value for validation
                    vulnerabilityData.put("SCAN_TYPE", "Basic");
                    
                    // Add parameter type for detailed reporting
                    if (paramTypeObj != null) {
                        vulnerabilityData.put("TYPE", paramTypeObj);
                    }
                    
                    // Get confirmed XSS status
                    Object confirmedXSS = parameter.get("CONFIRMED_XSS");
                    vulnerabilityData.put("CONFIRMED_XSS", confirmedXSS != null ? confirmedXSS : false);
                    
                    // Get confidence score
                    Object confidenceScore = parameter.get("CONFIDENCE_SCORE");
                    if (confidenceScore instanceof Double) {
                        vulnerabilityData.put("CONFIDENCE_SCORE", confidenceScore);
                    } else if (confidenceScore instanceof Number) {
                        vulnerabilityData.put("CONFIDENCE_SCORE", ((Number) confidenceScore).doubleValue());
                    } else {
                        vulnerabilityData.put("CONFIDENCE_SCORE", 70.0); // Default confidence
                    }
                    
                    // Get XSS score
                    Object xssScore = parameter.get("XSS_SCORE");
                    if (xssScore instanceof Double) {
                        vulnerabilityData.put("XSS_SCORE", xssScore);
                    } else if (xssScore instanceof Number) {
                        vulnerabilityData.put("XSS_SCORE", ((Number) xssScore).doubleValue());
                    } else {
                        vulnerabilityData.put("XSS_SCORE", 70.0); // Default score
                    }
                    
                    // Get enhanced context
                    Object enhancedContext = parameter.get("ENHANCED_CONTEXT");
                    vulnerabilityData.put("ENHANCED_CONTEXT", enhancedContext != null ? enhancedContext.toString() : "Standard context");
                    
                    // Get matches
                    vulnerabilityData.put("MATCHES", parameter.get(MATCHES));
                    vulnerabilityData.put("REFLECTED_IN", parameter.get(REFLECTED_IN));
                    
                    // TWO-STAGE DETECTION: Use context-aware encoded payloads
                    String testPayload = paramValue;
                    boolean isParamValueXSS = isActualXSSPayload(paramValue);
                    
                    // Get reflection context for context-aware encoding
                    String reflectionContext = (String) parameter.get("REFLECTION_CONTEXT");
                    String contentType = (String) parameter.get("CONTENT_TYPE");
                    if (reflectionContext == null) {
                        reflectionContext = "UNKNOWN";
                    }
                    
                    // If parameter value is not an XSS payload, use a standard XSS payload for testing
                    if (!isParamValueXSS) {
                        // CRITICAL FIX: Use simpler, more effective payloads first
                        // For HTML body context (most common), use simple payloads that break context
                        if ("HTML_BODY".equals(reflectionContext) || "HTML_TAG".equals(reflectionContext) || 
                            "HTML_VOID_ELEMENT".equals(reflectionContext) || "UNKNOWN".equals(reflectionContext)) {
                            // Simple HTML body payloads - most effective
                            testPayload = "><script>alert(1)</script>";
                        } else if ("HTML_ATTRIBUTE".equals(reflectionContext)) {
                            // For regular HTML attributes, break out with quote and inject event handler
                            testPayload = "'><img src=x onerror=alert(1)>";
                        } else if ("ATTRIBUTE_URL_EXECUTION".equals(reflectionContext)) {
                            // For URL attributes (href, src, action), inject javascript: protocol
                            // Don't use script tags - use javascript: protocol instead
                            testPayload = "javascript:alert(1)";
                        } else if ("JAVASCRIPT".equals(reflectionContext) || "JAVASCRIPT_STRING".equals(reflectionContext)) {
                            // JavaScript context - break string and execute
                            testPayload = "';alert(1);//";
                        } else if ("JSON".equals(reflectionContext) || (contentType != null && contentType.contains("application/json"))) {
                            // JSON context - break JSON string
                            testPayload = "\";alert(1);//";
                        } else if ("URL_JAVASCRIPT_EXECUTION".equals(reflectionContext) || "URL_EXECUTION".equals(reflectionContext)) {
                            // URL context - use javascript: protocol
                            testPayload = "javascript:alert(1)";
                        } else {
                            // Default: simple HTML body payload
                            testPayload = "><script>alert(1)</script>";
                        }
                        
                        // Capture original payload before encoding
                        String originalPayload = testPayload;

                        // CRITICAL FIX: Encode payload based on reflection context (but don't break it!)
                        testPayload = encodePayloadForContext(testPayload, reflectionContext, contentType);
                        
                        // CRITICAL FIX: For URL parameters, ALWAYS URL-encode the payload
                        // This is MANDATORY - browsers send URL parameters URL-encoded
                        if (isURLParameter) {
                            try {
                                // Check if payload is already URL-encoded (contains %)
                                if (!testPayload.contains("%") || !isValidURLEncoded(testPayload)) {
                                    // Not URL-encoded or invalid encoding - encode it
                                    String urlEncodedPayload = helpers.urlEncode(testPayload);
                                    if (settings != null && settings.getVerboseLogging())
                                        callbacks.printOutput("[CheckReflection] URL-encoding payload for URL parameter '" + paramName + "': " +
                                            testPayload.substring(0, Math.min(30, testPayload.length())) + " -> " +
                                            urlEncodedPayload.substring(0, Math.min(30, urlEncodedPayload.length())));
                                    testPayload = urlEncodedPayload;
                                }
                            } catch (Exception e) {
                                callbacks.printError("[CheckReflection] Error URL-encoding payload: " + e.getMessage());
                            }
                        }
                        
                        vulnerabilityData.put("payload", testPayload); // encoded version actually used
                        vulnerabilityData.put("ORIGINAL_PAYLOAD", originalPayload); // pre-encoding version
                        vulnerabilityData.put("ENCODED_PAYLOAD", testPayload); // actual encoded string (not boolean!)
                        vulnerabilityData.put("IS_ENCODED", !testPayload.equals(originalPayload));
                        vulnerabilityData.put("ENCODING_CONTEXT", reflectionContext);
                        vulnerabilityData.put("IS_URL_PARAMETER", isURLParameter);
                        // ADVANCED: Store browser execution context information
                        vulnerabilityData.put("BROWSER_EXECUTION_CONTEXT", reflectionContext);
                        vulnerabilityData.put("IS_EXECUTABLE_CONTEXT", isExecutableContext(reflectionContext));
                    } else {
                        // Parameter value is already an XSS payload - encode it for context
                        testPayload = encodePayloadForContext(paramValue, reflectionContext, contentType);
                        
                        // CRITICAL FIX: For URL parameters, ALWAYS URL-encode the payload
                        if (isURLParameter) {
                            try {
                                if (!testPayload.contains("%") || !isValidURLEncoded(testPayload)) {
                                    String urlEncodedPayload = helpers.urlEncode(testPayload);
                                    callbacks.printOutput("[CheckReflection] URL-encoding existing payload for URL parameter '" + paramName + "'");
                                    testPayload = urlEncodedPayload;
                                }
                            } catch (Exception e) {
                                callbacks.printError("[CheckReflection] Error URL-encoding existing payload: " + e.getMessage());
                            }
                        }
                        
                        vulnerabilityData.put("payload", testPayload); // encoded version actually used
                        vulnerabilityData.put("ORIGINAL_PAYLOAD", paramValue); // pre-encoding original
                        vulnerabilityData.put("ENCODED_PAYLOAD", testPayload); // actual encoded string (not boolean!)
                        vulnerabilityData.put("IS_ENCODED", !testPayload.equals(paramValue));
                        vulnerabilityData.put("ENCODING_CONTEXT", reflectionContext);
                        vulnerabilityData.put("IS_URL_PARAMETER", isURLParameter);
                        // ADVANCED: Store browser execution context information
                        vulnerabilityData.put("BROWSER_EXECUTION_CONTEXT", reflectionContext);
                        vulnerabilityData.put("IS_EXECUTABLE_CONTEXT", isExecutableContext(reflectionContext));
                    }
                    
                    // CRITICAL FIX: Actually send HTTP request to confirm vulnerability (even in passive scan)
                    // This is the KEY to finding real vulnerabilities - we MUST test with actual payloads
                    try {
                        // Create test request with context-aware encoded XSS payload
                        byte[] testRequest = createTestRequest(requestResponse, paramName, testPayload);

                        // Log the payload being tested (verbose only)
                        boolean verbose = settings != null && settings.getVerboseLogging();
                        if (verbose) {
                            callbacks.printOutput("[CheckReflection] Testing parameter: " + paramName +
                                " | Payload: " + testPayload.substring(0, Math.min(50, testPayload.length())) +
                                " | Is URL param: " + isURLParameter);
                        }

                        if (testRequest != null && testRequest.length > 0) {
                            // Log request being sent (verbose only)
                            String reqPreview = new String(testRequest, StandardCharsets.UTF_8);
                            int queryIdx = reqPreview.indexOf("?");
                            if (verbose && queryIdx > 0) {
                                int endIdx = reqPreview.indexOf(" ", queryIdx);
                                if (endIdx < 0) endIdx = Math.min(queryIdx + 100, reqPreview.length());
                                callbacks.printOutput("[CheckReflection] Request URL: " + reqPreview.substring(queryIdx, Math.min(endIdx, reqPreview.length())));
                            }

                            // CRITICAL: Actually send the HTTP request to get REAL response with payload
                            // This is what makes the extension actually find vulnerabilities!
                            byte[] actualResponse = sendRealHttpRequest(requestResponse.getHttpService(), testRequest);
                            
                            if (actualResponse != null && actualResponse.length > 0) {
                                // Store actual request/response for proof
                                vulnerabilityData.put("TEST_REQUEST", testRequest);
                                vulnerabilityData.put("TEST_RESPONSE", actualResponse);
                                
                                // Verify payload reflection in ACTUAL response
                                boolean payloadReflected = verifyPayloadReflection(
                                    actualResponse, testPayload, reflectionContext, contentType);
                                
                                // Get response body for detailed analysis
                                int bodyOffset = helpers.analyzeResponse(actualResponse).getBodyOffset();
                                String responseBody = new String(
                                    Arrays.copyOfRange(actualResponse, bodyOffset, actualResponse.length), 
                                    StandardCharsets.UTF_8);
                                
                                // CRITICAL FIX: Check for WAF blocks and error responses
                                IResponseInfo responseInfo = helpers.analyzeResponse(actualResponse);
                                int statusCode = responseInfo.getStatusCode();
                                boolean isWAFBlock = (statusCode == 403) || (statusCode == 406) || (statusCode == 429);
                                boolean isErrorResponse = (statusCode >= 400 && statusCode < 500) || (statusCode >= 500);
                                
                                // Check response headers for WAF indicators
                                List<String> responseHeaders = responseInfo.getHeaders();
                                boolean hasWAFIndicators = false;
                                for (String header : responseHeaders) {
                                    String lowerHeader = header.toLowerCase();
                                    if (lowerHeader.contains("incapsula") || lowerHeader.contains("imperva") || 
                                        lowerHeader.contains("cloudflare") || lowerHeader.contains("akamai") ||
                                        lowerHeader.contains("x-waf") || lowerHeader.contains("x-blocked")) {
                                        hasWAFIndicators = true;
                                        break;
                                    }
                                }
                                
                                // CRITICAL: Check if payload is actually reflected (not just original value)
                                // Only check for testPayload (the injected XSS payload), not the original payload variable
                                // This ensures we only report when the XSS payload is actually reflected
                                boolean payloadFound = responseBody.contains(testPayload) || payloadReflected;

                                // CRITICAL FIX: If testPayload is URL-encoded, also check for decoded version
                                // Server decodes URL parameters before reflecting them in response
                                if (!payloadFound && testPayload.contains("%")) {
                                    try {
                                        String decodedPayload = helpers.urlDecode(testPayload);
                                        if (decodedPayload != null && !decodedPayload.equals(testPayload)) {
                                            if (responseBody.contains(decodedPayload)) {
                                                payloadFound = true;
                                                if (settings != null && settings.getVerboseLogging()) {
                                                    callbacks.printOutput("[CheckReflection] Decoded payload reflected: '" +
                                                        decodedPayload.substring(0, Math.min(40, decodedPayload.length())) + "'");
                                                }
                                            } else {
                                                if (settings != null && settings.getVerboseLogging())
                                                    callbacks.printOutput("[CheckReflection] Looking for decoded payload: '" +
                                                    decodedPayload.substring(0, Math.min(40, decodedPayload.length())) + "' - NOT FOUND");
                                            }
                                        }
                                    } catch (Exception e) {
                                        // Ignore decode errors
                                    }
                                }

                                // Log reflection status (verbose only)
                                if (!payloadFound && !payloadReflected && settings != null && settings.getVerboseLogging()) {
                                    callbacks.printOutput("[CheckReflection] No reflection found for param: " + paramName);
                                    callbacks.printOutput("[CheckReflection] Response sample (first 200 chars): " +
                                        responseBody.substring(0, Math.min(200, responseBody.length())).replace("\n", " "));
                                }
                                
                                // CRITICAL FIX: For WAF blocks (403) or error responses, require STRICT payload reflection
                                // If WAF blocked the request, payload is NOT reflected - filter it out
                                if ((isWAFBlock || hasWAFIndicators) && !payloadFound) {
                                    callbacks.printOutput("[CheckReflection] FALSE POSITIVE FILTERED: WAF block detected (status " + statusCode + ") and payload NOT reflected for parameter: " + paramName);
                                    vulnerabilityData.put("CONFIRMED_XSS", false);
                                    vulnerabilityData.put("CONFIDENCE_SCORE", 0.0);
                                    vulnerabilityData.put("XSS_SCORE", 0.0);
                                    // Don't create issue - skip to next parameter
                                    // Note: We're in a try-catch, so we'll skip issue creation below
                                }
                                
                                // CRITICAL FIX: For error responses (4xx/5xx), require payload reflection
                                // Error responses that don't reflect payload are likely false positives
                                else if (isErrorResponse && !payloadFound) {
                                    callbacks.printOutput("[CheckReflection] FALSE POSITIVE FILTERED: Error response (status " + statusCode + ") and payload NOT reflected for parameter: " + paramName);
                                    vulnerabilityData.put("CONFIRMED_XSS", false);
                                    vulnerabilityData.put("CONFIDENCE_SCORE", 0.0);
                                    vulnerabilityData.put("XSS_SCORE", 0.0);
                                    // Don't create issue - skip to next parameter
                                }
                                
                                // If WAF block or error without reflection, skip the rest of processing
                                boolean shouldSkipProcessing = ((isWAFBlock || hasWAFIndicators) || isErrorResponse) && !payloadFound;
                                
                                if (!shouldSkipProcessing) {
                                    // Continue with normal processing - check for encoded versions
                                    
                                    // Also check for encoded versions of testPayload
                                    if (!payloadFound) {
                                        String htmlEncoded = testPayload.replace("<", "&lt;").replace(">", "&gt;");
                                        if (responseBody.contains(htmlEncoded)) {
                                        // CRITICAL FIX: HTML-encoded payload means the app is PROPERLY escaping
                                        // This is NOT a vulnerability - it's the correct defense against XSS!
                                        // Only try bypasses in aggressive mode, and only if user explicitly enabled it

                                        // Check if raw payload is ALSO in response (mixed encoding = vulnerable)
                                        if (responseBody.contains(testPayload)) {
                                            // Raw payload also present - this IS vulnerable
                                            payloadFound = true;
                                            callbacks.printOutput("[CheckReflection] Mixed encoding detected - raw payload present alongside encoded version");
                                        } else if (settings != null && settings.getAggressiveMode()) {
                                            // Only in aggressive mode: try bypass payloads
                                            // But still be careful - HTML encoding is usually safe
                                            callbacks.printOutput("[CheckReflection] HTML encoding detected - trying bypasses (aggressive mode)");

                                            try {
                                                EnhancedAggressive tempAggressive = new EnhancedAggressive(settings, helpers, requestResponse, callbacks, new ArrayList<>());
                                                Map<String, Object> escapingInfo = null;
                                                try {
                                                    escapingInfo = tempAggressive.detectEscapingPatterns(responseBody, testPayload);
                                                } catch (Exception e) {
                                                    if (settings != null && settings.getVerboseLogging()) {
                                                        callbacks.printError("Error detecting escaping patterns: " + e.getMessage());
                                                    }
                                                }

                                                boolean escapingDetected = escapingInfo != null && Boolean.TRUE.equals(escapingInfo.get("ESCAPING_DETECTED"));

                                                if (escapingDetected && escapingInfo != null) {
                                                    String escapingType = (String) escapingInfo.get("ESCAPING_TYPE");
                                                    callbacks.printOutput("[XSSDetector] Escaping detected: " + escapingType + " - testing limited bypasses");

                                                    List<String> bypassPayloads = null;
                                                    try {
                                                        bypassPayloads = tempAggressive.generateBypassPayloads(testPayload, escapingType, reflectionContext);
                                                    } catch (Exception e) {
                                                        // Ignore
                                                    }

                                                    if (bypassPayloads != null && !bypassPayloads.isEmpty()) {
                                                        int bypassTested = 0;
                                                        int maxBypassTests = 5; // Reduced limit - be less aggressive

                                                        for (String bypassPayload : bypassPayloads) {
                                                            if (bypassTested++ >= maxBypassTests) break;

                                                            try {
                                                                byte[] bypassRequest = createTestRequest(requestResponse, paramName, bypassPayload);
                                                                if (bypassRequest == null || bypassRequest.length == 0) continue;

                                                                byte[] bypassResponse = sendRealHttpRequest(requestResponse.getHttpService(), bypassRequest);
                                                                if (bypassResponse == null || bypassResponse.length == 0) continue;

                                                                int bypassBodyOffset = helpers.analyzeResponse(bypassResponse).getBodyOffset();
                                                                String bypassResponseBody = new String(
                                                                    Arrays.copyOfRange(bypassResponse, bypassBodyOffset, bypassResponse.length),
                                                                    StandardCharsets.UTF_8
                                                                );

                                                                // CRITICAL: Check if bypass payload is reflected RAW (not encoded)
                                                                boolean bypassReflected = bypassResponseBody.contains(bypassPayload);

                                                                // FIX: Reject reflections in error messages (WAF blocks, 403s, etc.)
                                                                if (bypassReflected) {
                                                                    int bpPos = bypassResponseBody.indexOf(bypassPayload);
                                                                    int ctxS = Math.max(0, bpPos - 200);
                                                                    int ctxE = Math.min(bypassResponseBody.length(), bpPos + bypassPayload.length() + 200);
                                                                    String errCtx = bypassResponseBody.substring(ctxS, ctxE).toLowerCase();
                                                                    if (errCtx.contains("error") || errCtx.contains("not allowed") ||
                                                                        errCtx.contains("blocked") || errCtx.contains("forbidden") ||
                                                                        errCtx.contains("invalid") || errCtx.contains("rejected") ||
                                                                        errCtx.contains("denied") || errCtx.contains("security")) {
                                                                        bypassReflected = false; // Error page reflection, not real XSS
                                                                    }
                                                                    // Also check HTTP status code
                                                                    IResponseInfo bri = helpers.analyzeResponse(bypassResponse);
                                                                    short bsc = bri.getStatusCode();
                                                                    if (bsc == 403 || bsc == 406 || bsc == 429 || bsc == 503) {
                                                                        bypassReflected = false; // WAF/rate-limit block
                                                                    }
                                                                }

                                                                // Also verify it's not in a safe context
                                                                if (bypassReflected && !isReflectionInSafeContext(bypassResponseBody, bypassPayload, -1)) {
                                                                    callbacks.printOutput("[XSSDetector] BYPASS SUCCESSFUL: " +
                                                                        bypassPayload.substring(0, Math.min(50, bypassPayload.length())));

                                                                    testPayload = bypassPayload;
                                                                    payloadFound = true;
                                                                    responseBody = bypassResponseBody;
                                                                    actualResponse = bypassResponse;
                                                                    testRequest = bypassRequest;
                                                                    vulnerabilityData.put("BYPASS_PAYLOAD", true);
                                                                    vulnerabilityData.put("ESCAPING_TYPE", escapingType);
                                                                    vulnerabilityData.put("BYPASSED_ESCAPING", true);
                                                                    break;
                                                                }
                                                            } catch (Exception e) {
                                                                // Continue with next bypass
                                                            }
                                                        }
                                                    }
                                                }
                                            } catch (Exception e) {
                                                if (settings != null && settings.getVerboseLogging()) {
                                                    callbacks.printError("Error in bypass detection: " + e.getMessage());
                                                }
                                            }

                                            // If no bypass found, this is NOT vulnerable
                                            if (!payloadFound) {
                                                callbacks.printOutput("[CheckReflection] FALSE POSITIVE FILTERED: Payload is HTML-encoded (proper defense) - no bypass found");
                                            }
                                        } else {
                                            // Not aggressive mode - HTML encoding = safe
                                            callbacks.printOutput("[CheckReflection] FALSE POSITIVE FILTERED: Payload is HTML-encoded - this is SAFE (proper XSS defense)");
                                            // payloadFound stays false - this is correct!
                                        }
                                    }
                                }
                                } // End of !shouldSkipProcessing block
                                
                                // CRITICAL FINAL VALIDATION: Verify payload is ACTUALLY in request AND reflected in response
                                // Only proceed if we didn't skip due to WAF/error
                                if (!shouldSkipProcessing) {
                                    // This is the ABSOLUTE FINAL check before marking as CONFIRMED
                                    String requestStr = new String(testRequest, StandardCharsets.UTF_8);
                                    boolean payloadInRequest = requestStr.contains(testPayload);
                                
                                // Check for URL-encoded payload in request (common in query parameters)
                                if (!payloadInRequest) {
                                    try {
                                        String urlEncoded = helpers.urlEncode(testPayload);
                                        if (requestStr.contains(urlEncoded)) {
                                            payloadInRequest = true;
                                        }
                                    } catch (Exception ignored) {}
                                }
                                
                                // Also check for double-encoded payload
                                if (!payloadInRequest) {
                                    try {
                                        String doubleEncoded = helpers.urlEncode(helpers.urlEncode(testPayload));
                                        if (requestStr.contains(doubleEncoded)) {
                                            payloadInRequest = true;
                                        }
                                    } catch (Exception ignored) {}
                                }
                                
                                // Also check if parameter name is in request (payload might be in parameter value)
                                if (!payloadInRequest) {
                                    try {
                                        IRequestInfo reqInfo = helpers.analyzeRequest(testRequest);
                                        List<IParameter> params = reqInfo.getParameters();
                                        for (IParameter p : params) {
                                            if (p.getName().equals(paramName)) {
                                                String pVal = p.getValue();
                                                if (pVal != null && (pVal.contains(testPayload) || 
                                                    pVal.contains(helpers.urlEncode(testPayload)))) {
                                                    payloadInRequest = true;
                                                    break;
                                                }
                                            }
                                        }
                                    } catch (Exception ignored) {}
                                }
                                
                                // Verify payload is reflected in response
                                boolean payloadInResponse = payloadFound;
                                
                                // CRITICAL: Only mark as CONFIRMED if we have PROOF in both request AND response
                                // CRITICAL FIX: For cookie parameters, require STRICT payload reflection (cookies rarely reflect)
                                Object paramTypeObjCookie = parameter.get(TYPE);
                                boolean isCookieParam = (paramTypeObjCookie != null &&
                                    ((paramTypeObjCookie instanceof Integer && ((Integer) paramTypeObjCookie).intValue() == IParameter.PARAM_COOKIE) ||
                                    (paramTypeObjCookie instanceof Byte && ((Byte) paramTypeObjCookie).byteValue() == IParameter.PARAM_COOKIE)));
                                
                                // For cookie parameters, be EXTRA strict - require actual payload reflection
                                if (isCookieParam && !payloadInResponse) {
                                    callbacks.printOutput("[CheckReflection] FALSE POSITIVE FILTERED: Cookie parameter '" + paramName + "' - payload NOT reflected in response (cookies rarely reflect)");
                                    vulnerabilityData.put("CONFIRMED_XSS", false);
                                    vulnerabilityData.put("CONFIDENCE_SCORE", 0.0);
                                    vulnerabilityData.put("XSS_SCORE", 0.0);
                                } else if (!payloadInRequest || !payloadInResponse) {
                                    // For non-cookie parameters, check for symbols reflection (but require multiple dangerous symbols)
                                    Object symbolsReflected = parameter.get("SYMBOLS_REFLECTED");
                                    Object reflectedSymbolsObj = parameter.get("REFLECTED_SYMBOLS");
                                    
                                    // CRITICAL FIX: Require MULTIPLE dangerous symbols, not just one
                                    // A single '/' character is NOT sufficient proof of XSS
                                    boolean hasMultipleDangerousSymbols = false;
                                    if (reflectedSymbolsObj instanceof List) {
                                        @SuppressWarnings("unchecked")
                                        List<String> reflectedSymbols = (List<String>) reflectedSymbolsObj;
                                        if (reflectedSymbols != null) {
                                            // Count dangerous symbols (not just any symbol)
                                            int dangerousCount = 0;
                                            for (String symbol : reflectedSymbols) {
                                                if (symbol != null && (symbol.contains("<") || symbol.contains(">") || 
                                                    symbol.contains("\"") || symbol.contains("'") || symbol.contains("(") || 
                                                    symbol.contains(")") || symbol.contains("javascript") || symbol.contains(":"))) {
                                                    dangerousCount++;
                                                }
                                            }
                                            // Require at least 2 dangerous symbols for confirmation
                                            hasMultipleDangerousSymbols = dangerousCount >= 2;
                                        }
                                    }
                                    
                                    // CRITICAL FIX: NEVER mark as CONFIRMED based on symbols-only reflection
                                    // Symbols reflection is NOT sufficient proof - require actual payload reflection
                                    // Even multiple dangerous symbols can be false positives
                                    callbacks.printOutput("[CheckReflection] FALSE POSITIVE FILTERED: Symbols reflected but payload NOT in request (" + payloadInRequest + ") or response (" + payloadInResponse + ") for parameter: " + paramName + " - symbols-only reflection is not sufficient proof");
                                    vulnerabilityData.put("CONFIRMED_XSS", false);
                                    vulnerabilityData.put("CONFIDENCE_SCORE", 0.0);
                                    vulnerabilityData.put("XSS_SCORE", 0.0);
                                } else if (payloadFound) {
                                    // Both checks passed - mark as confirmed
                                    vulnerabilityData.put("CONFIRMED_XSS", true);
                                    
                                    // Calculate confidence based on context and reflection quality
                                    double baseScore = 85.0;
                                    if (isParamValueXSS) {
                                        baseScore = 95.0; // Higher if original was XSS
                                    }
                                    if (!"UNKNOWN".equals(reflectionContext)) {
                                        baseScore += 5.0; // Bonus for context detection
                                    }
                                    if (isExecutableContext(reflectionContext)) {
                                        baseScore = 100.0; // Maximum for executable context
                                    }
                                    
                                    vulnerabilityData.put("CONFIDENCE_SCORE", Math.min(100.0, baseScore));
                                    vulnerabilityData.put("XSS_SCORE", Math.min(100.0, baseScore));
                                    
                                    callbacks.printOutput("[CheckReflection] CONFIRMED XSS in parameter: " + paramName + 
                                                        " with payload: " + testPayload.substring(0, Math.min(30, testPayload.length())));
                                } else {
                                    // Payload not reflected - check for symbols reflection (but require multiple dangerous symbols)
                                    Object symbolsReflectedObj = parameter.get("SYMBOLS_REFLECTED");
                                    Object reflectedSymbolsObj = parameter.get("REFLECTED_SYMBOLS");
                                    
                                    // CRITICAL FIX: Require MULTIPLE dangerous symbols, not just one
                                    boolean hasMultipleDangerousSymbols = false;
                                    if (reflectedSymbolsObj instanceof List) {
                                        @SuppressWarnings("unchecked")
                                        List<String> reflectedSymbols = (List<String>) reflectedSymbolsObj;
                                        if (reflectedSymbols != null) {
                                            int dangerousCount = 0;
                                            for (String symbol : reflectedSymbols) {
                                                if (symbol != null && (symbol.contains("<") || symbol.contains(">") || 
                                                    symbol.contains("\"") || symbol.contains("'") || symbol.contains("(") || 
                                                    symbol.contains(")") || symbol.contains("javascript") || symbol.contains(":"))) {
                                                    dangerousCount++;
                                                }
                                            }
                                            hasMultipleDangerousSymbols = dangerousCount >= 2;
                                        }
                                    }
                                    
                                    // CRITICAL FIX: NEVER mark as CONFIRMED based on symbols-only reflection
                                    // Even with test request/response, symbols reflection alone is NOT sufficient proof
                                    // We MUST have actual payload reflection, not just symbols
                                    callbacks.printOutput("[CheckReflection] FALSE POSITIVE FILTERED: Symbols reflected but payload NOT reflected for parameter: " + paramName + " - symbols-only reflection is not sufficient proof");
                                    vulnerabilityData.put("CONFIRMED_XSS", false);
                                    vulnerabilityData.put("CONFIDENCE_SCORE", 0.0);
                                    vulnerabilityData.put("XSS_SCORE", 0.0);
                                }
                                } // End of !shouldSkipProcessing else block for final validation
                            } else {
                                // Request failed - keep tentative scores but mark as unconfirmed
                                callbacks.printOutput("[CheckReflection] Test request failed for parameter: " + paramName + " - keeping tentative finding");
                                vulnerabilityData.put("CONFIRMED_XSS", false);
                                // Keep scores at reasonable level for tentative findings
                                if (vulnerabilityData.get("CONFIDENCE_SCORE") == null ||
                                    ((Number) vulnerabilityData.get("CONFIDENCE_SCORE")).doubleValue() < 40.0) {
                                    vulnerabilityData.put("CONFIDENCE_SCORE", 40.0);
                                }
                                if (vulnerabilityData.get("XSS_SCORE") == null ||
                                    ((Number) vulnerabilityData.get("XSS_SCORE")).doubleValue() < 40.0) {
                                    vulnerabilityData.put("XSS_SCORE", 40.0);
                                }
                            }
                        }
                    } catch (Exception e) {
                        callbacks.printError("CheckReflection: Error sending test request: " + e.getMessage());
                        if (settings != null && settings.getVerboseLogging()) {
                            callbacks.printError("CheckReflection: Stack trace: " + java.util.Arrays.toString(e.getStackTrace()));
                        }
                        // Keep tentative finding even if test request fails
                        callbacks.printOutput("[CheckReflection] Test request failed for parameter: " + paramName + " - keeping tentative finding");
                        vulnerabilityData.put("CONFIRMED_XSS", false);
                        // Keep reasonable scores for tentative findings
                        if (vulnerabilityData.get("CONFIDENCE_SCORE") == null ||
                            ((Number) vulnerabilityData.get("CONFIDENCE_SCORE")).doubleValue() < 40.0) {
                            vulnerabilityData.put("CONFIDENCE_SCORE", 40.0);
                        }
                        if (vulnerabilityData.get("XSS_SCORE") == null ||
                            ((Number) vulnerabilityData.get("XSS_SCORE")).doubleValue() < 40.0) {
                            vulnerabilityData.put("XSS_SCORE", 40.0);
                        }
                    }
                    
                    // CRITICAL: Add REFLECTED_SYMBOLS and SYMBOLS_REFLECTED to vulnerabilityData
                    Object reflectedSymbols = parameter.get("REFLECTED_SYMBOLS");
                    Object symbolsReflected = parameter.get("SYMBOLS_REFLECTED");
                    if (reflectedSymbols != null) {
                        vulnerabilityData.put("REFLECTED_SYMBOLS", reflectedSymbols);
                    }
                    if (symbolsReflected != null) {
                        vulnerabilityData.put("SYMBOLS_REFLECTED", symbolsReflected);
                    }
                    
                    // CRITICAL: Check if issue was already created by EnhancedAggressive
                    Object issueCreatedByEnhanced = parameter.get("ISSUE_CREATED_BY_ENHANCED");
                    Object enhancedIssue = parameter.get("ENHANCED_ISSUE");
                    
                    if (Boolean.TRUE.equals(issueCreatedByEnhanced) && enhancedIssue instanceof IScanIssue) {
                        // Issue was already created by EnhancedAggressive - skip creating duplicate
                        callbacks.printOutput("[CheckReflection] Skipping duplicate issue creation for parameter: " + paramName + " (already created by EnhancedAggressive)");
                    } else {
                        // Create scan issue - use simplified method first, fall back to enhanced
                        EnhancedIssueReporter issueReporter = new EnhancedIssueReporter(helpers, callbacks, settings);
                        IScanIssue issue = null;

                        // Get reflection data
                        String reflCtx = (String) vulnerabilityData.get("REFLECTION_CONTEXT");
                        Object confScoreObj = vulnerabilityData.get("CONFIDENCE_SCORE");
                        double confScore = confScoreObj instanceof Number ? ((Number) confScoreObj).doubleValue() : 0.0;
                        boolean payloadWasReflected = Boolean.TRUE.equals(vulnerabilityData.get("CONFIRMED_XSS"));
                        String testPayloadUsed = (String) vulnerabilityData.get("payload");

                        // Only create issues when we have actual confirmed XSS
                        if (!payloadWasReflected && confScore <= 0.0) {
                            callbacks.printOutput("[CheckReflection] Skipping issue creation: not confirmed and confidence=0 for: " + paramName);
                            continue;
                        }

                        // Try enhanced method first (proper validation + markers)
                        issue = issueReporter.createEnhancedXSSIssue(requestResponse, vulnerabilityData);

                        // Fallback to simplified method only for confirmed findings
                        if (issue == null && payloadWasReflected) {
                            issue = issueReporter.createXSSIssue(requestResponse, vulnerabilityData);
                        }

                        if (issue != null) {
                            // Add to the returned list ONLY. Central reporting + deduplication
                            // happens in BurpExtender.reportIssueWithDedup; reporting directly
                            // here bypasses dedup and double-reports the same finding.
                            issues.add(issue);
                            if (settings != null && settings.getVerboseLogging()) {
                                callbacks.printOutput("[CheckReflection] Issue queued for parameter: " + paramName +
                                    " (confidence: " + confScore + "%, reflected: " + payloadWasReflected + ")");
                            }
                        } else {
                            // Log why issue creation failed
                            callbacks.printOutput("[CheckReflection] Issue creation skipped for parameter: " + paramName +
                                " - confidence: " + confScore + "%, reflected: " + payloadWasReflected);
                        }
                    }
                    
                } catch (Exception e) {
                    callbacks.printError("CheckReflection: Error creating scan issue: " + e.getMessage());
                    if (settings != null && settings.getVerboseLogging()) {
                        callbacks.printError("CheckReflection: Stack trace: " + java.util.Arrays.toString(e.getStackTrace()));
                    }
                }
            }
            
        } catch (Exception e) {
            callbacks.printError("CheckReflection: Error in passive scan: " + e.getMessage());
            if (settings != null && settings.getVerboseLogging()) {
                callbacks.printError("CheckReflection: Stack trace: " + java.util.Arrays.toString(e.getStackTrace()));
            }
        }
        
        return issues;
    }
    
    /**
     * Create test request with payload
     * CRITICAL: For GET URL parameters, ALWAYS URL-encode the payload
     */
    private byte[] createTestRequest(IHttpRequestResponse originalRequest, String paramName, String payload) {
        try {
            IRequestInfo requestInfo = helpers.analyzeRequest(originalRequest);
            List<IParameter> parameters = requestInfo.getParameters();
            String method = requestInfo.getMethod();
            java.net.URL url = requestInfo.getUrl();
            
            byte[] modifiedRequest = originalRequest.getRequest();
            boolean isURLParameter = false;
            byte paramType = IParameter.PARAM_BODY;
            
            // Find the parameter and determine its type
            for (IParameter param : parameters) {
                if (param.getName().equals(paramName)) {
                    paramType = param.getType();
                    isURLParameter = (paramType == IParameter.PARAM_URL);
                    
                    // CRITICAL FIX: Also check if it's a GET request with query parameters
                    if (!isURLParameter && "GET".equals(method)) {
                        String urlStr = url.toString();
                        if (urlStr.contains("?") && (urlStr.contains(paramName + "=") || urlStr.contains(helpers.urlEncode(paramName) + "="))) {
                            isURLParameter = true;
                            paramType = IParameter.PARAM_URL;
                            callbacks.printOutput("[CheckReflection] Detected URL parameter in GET request: " + paramName);
                        }
                    }
                    break;
                }
            }
            
            // CRITICAL FIX: For URL parameters, ALWAYS URL-encode the payload
            // Browsers send URL parameters URL-encoded, so we must too
            if (isURLParameter) {
                try {
                    // Check if payload is already URL-encoded (contains %XX patterns)
                    String urlEncodedPayload = payload;
                    boolean verboseUrl = settings != null && settings.getVerboseLogging();
                    if (!isValidURLEncoded(payload)) {
                        // Payload is NOT URL-encoded - encode it
                        urlEncodedPayload = helpers.urlEncode(payload);
                        if (verboseUrl)
                            callbacks.printOutput("[CheckReflection] URL-encoding payload for URL parameter '" + paramName + "': " +
                                payload.substring(0, Math.min(30, payload.length())) + " -> " +
                                urlEncodedPayload.substring(0, Math.min(50, urlEncodedPayload.length())));
                    } else if (verboseUrl) {
                        callbacks.printOutput("[CheckReflection] Payload already URL-encoded for parameter: " + paramName);
                    }
                    
                    // Build parameter with URL-encoded payload
                    try {
                        IParameter newParam = helpers.buildParameter(paramName, urlEncodedPayload, paramType);
                        modifiedRequest = helpers.updateParameter(modifiedRequest, newParam);
                    } catch (UnsupportedOperationException e) {
                        // CRITICAL FIX: Some parameter types cannot be updated
                        callbacks.printOutput("[CheckReflection] Parameter type not supported for update: " + paramName + " (type: " + paramType + ") - skipping test request creation");
                        return originalRequest.getRequest();
                    }
                    
                    // CRITICAL: Verify the payload is actually URL-encoded in the final request
                    // buildParameter/updateParameter might decode it - we need to manually fix if needed
                    String requestStrCheck = new String(modifiedRequest, StandardCharsets.UTF_8);
                    String encodedParamName = helpers.urlEncode(paramName);
                    
                    // Check if raw (unencoded) payload appears in query string
                    boolean needsManualFix = false;
                    if (requestStrCheck.contains("?" + paramName + "=" + payload) || 
                        requestStrCheck.contains("&" + paramName + "=" + payload) ||
                        requestStrCheck.contains("?" + encodedParamName + "=" + payload) ||
                        requestStrCheck.contains("&" + encodedParamName + "=" + payload)) {
                        needsManualFix = true;
                    }
                    
                    if (needsManualFix) {
                        // buildParameter decoded it - manually fix the URL in the request string
                        if (settings != null && settings.getVerboseLogging())
                            callbacks.printOutput("[CheckReflection] Re-applying URL encoding for parameter '" + paramName + "' in GET request");
                        
                        // Extract URL parts from request string
                        String requestStr = new String(modifiedRequest, StandardCharsets.UTF_8);
                        int urlStart = requestStr.indexOf(" ");
                        int urlEnd = requestStr.indexOf(" ", urlStart + 1);
                        if (urlStart >= 0 && urlEnd > urlStart) {
                            String methodLine = requestStr.substring(0, urlStart + 1);
                            String urlPath = requestStr.substring(urlStart + 1, urlEnd);
                            String restOfRequest = requestStr.substring(urlEnd);
                            
                            // Parse URL path and query
                            int queryStart = urlPath.indexOf("?");
                            if (queryStart >= 0) {
                                String path = urlPath.substring(0, queryStart);
                                String queryString = urlPath.substring(queryStart + 1);
                                
                                // Replace parameter value in query string
                                String[] queryParams = queryString.split("&");
                                StringBuilder newQuery = new StringBuilder();
                                boolean paramFound = false;
                                
                                for (String qp : queryParams) {
                                    if (qp.startsWith(paramName + "=") || qp.startsWith(encodedParamName + "=")) {
                                        // Replace with URL-encoded value
                                        if (!paramFound) {
                                            newQuery.append(paramName).append("=").append(urlEncodedPayload);
                                            paramFound = true;
                                        }
                                    } else if (!qp.isEmpty()) {
                                        if (newQuery.length() > 0) newQuery.append("&");
                                        newQuery.append(qp);
                                    }
                                }
                                
                                if (!paramFound) {
                                    // Parameter not in query string - add it
                                    if (newQuery.length() > 0) newQuery.append("&");
                                    newQuery.append(paramName).append("=").append(urlEncodedPayload);
                                }
                                
                                // Reconstruct request with fixed URL
                                String fixedUrlPath = path + "?" + newQuery.toString();
                                String fixedRequest = methodLine + fixedUrlPath + restOfRequest;
                                modifiedRequest = fixedRequest.getBytes(StandardCharsets.UTF_8);
                                
                                if (settings != null && settings.getVerboseLogging())
                                    callbacks.printOutput("[CheckReflection] Fixed URL in request: " + fixedUrlPath.substring(0, Math.min(100, fixedUrlPath.length())));
                            }
                        }
                    }
                } catch (Exception e) {
                    callbacks.printError("[CheckReflection] Error URL-encoding payload for parameter '" + paramName + "': " + e.getMessage());
                    // Fallback: try with URL-encoded payload
                    try {
                        String urlEncodedPayload = helpers.urlEncode(payload);
                        IParameter newParam = helpers.buildParameter(paramName, urlEncodedPayload, paramType);
                        modifiedRequest = helpers.updateParameter(modifiedRequest, newParam);
                    } catch (Exception e2) {
                        // Last resort: use payload as-is
                        IParameter newParam = helpers.buildParameter(paramName, payload, paramType);
                        modifiedRequest = helpers.updateParameter(modifiedRequest, newParam);
                    }
                }
            } else {
                // Non-URL parameter - use payload as-is
                for (IParameter param : parameters) {
                    if (param.getName().equals(paramName)) {
                        try {
                            IParameter newParam = helpers.buildParameter(paramName, payload, param.getType());
                            modifiedRequest = helpers.updateParameter(modifiedRequest, newParam);
                        } catch (UnsupportedOperationException e) {
                            // CRITICAL FIX: Some parameter types (JSON, XML, etc.) cannot be updated
                            // Skip this parameter - it's not a standard parameter type we can modify
                            callbacks.printOutput("[CheckReflection] Parameter type not supported for update: " + paramName + " (type: " + param.getType() + ") - skipping test request creation");
                            return originalRequest.getRequest();
                        }
                        break;
                    }
                }
            }
            
            return modifiedRequest;
        } catch (UnsupportedOperationException e) {
            // CRITICAL FIX: Handle unsupported parameter types gracefully
            callbacks.printOutput("[CheckReflection] Parameter type not supported for update: " + paramName + " - " + e.getMessage());
            return originalRequest.getRequest();
        } catch (Exception e) {
            callbacks.printError("[CheckReflection] Error creating test request: " + e.getMessage());
            return originalRequest.getRequest();
        }
    }
    
    /**
     * Check if string is valid URL-encoded (contains %XX patterns)
     */
    private boolean isValidURLEncoded(String str) {
        if (str == null || !str.contains("%")) {
            return false;
        }
        // Simple check: look for % followed by 2 hex digits
        return str.matches(".*%[0-9A-Fa-f]{2}.*");
    }
    
    /**
     * REMOVED: createTestResponse() - This was creating synthetic/fake responses
     * 
     * For passive scanning, we MUST use the actual response from the server.
     * We cannot create synthetic responses - that defeats the purpose of real vulnerability detection.
     * 
     * The actual response is already available in requestResponse.getResponse()
     * and should be used directly without modification.
     */

                public List<Map> checkResponse() {
            List<Map> reflectedParameters = new ArrayList<>();
        
        // Extract response content type
        String responseContentType = extractResponseContentType();
        if (responseContentType == null) {
            responseContentType = "unknown";
        }
        
        // Skip image files if enabled
        if (settings.getSkipImageFiles() && responseContentType.startsWith("image/")) {
            return reflectedParameters;
        }
        
        // Check if content type is vulnerable
        boolean isVulnerableContentType = isVulnerableContentType(responseContentType);
        boolean isJSONResponse = responseContentType != null && responseContentType.toLowerCase().contains("application/json");
        boolean isModernAppResponse = isJSONResponse || (responseContentType != null && responseContentType.toLowerCase().contains("application/graphql"));
        
        // CRITICAL: For JSON responses, we need to check if they're actually exploitable
        // JSON is NOT directly executable - only JSONP or unsafe consumption makes it exploitable
        if (isJSONResponse) {
            // Check if it's JSONP (directly executable)
            String responseBody = new String(iHttpRequestResponse.getResponse());
            boolean isJSONP = isJSONPResponse(responseBody);
            
            // Check if JSON contains indicators of unsafe consumption
            boolean hasUnsafeIndicators = hasUnsafeJSONConsumptionIndicators(responseBody);
            
            // Only process JSON if it's JSONP or has unsafe consumption indicators
            if (!isJSONP && !hasUnsafeIndicators) {
                // Safe JSON — cannot have reflected XSS (data, not code)
                if (settings != null && settings.getVerboseLogging()) {
                    callbacks.printOutput("[CheckReflection] Safe JSON API response (no JSONP/unsafe indicators) - skipping XSS testing");
                }
                return reflectedParameters;
            }
        }
        
        if (!isVulnerableContentType && !isModernAppResponse) {
            return reflectedParameters;
        }
        
        // Session handling pre-processing
        SessionContext sessionContext = null;
        if (sessionManager != null) {
            sessionContext = sessionManager.processRequest(iHttpRequestResponse);
        }
        
        // Process standard parameters
        List<IParameter> parameters = helpers.analyzeRequest(iHttpRequestResponse).getParameters();
        for (IParameter parameter : parameters) {
            // Skip session-related parameters if session handling is enabled
            if (sessionManager != null && sessionContext != null) {
                String host = helpers.analyzeRequest(iHttpRequestResponse).getUrl().getHost();
                if (sessionManager.shouldExcludeParameter(parameter.getName(), host)) {
                    continue;
                }
            }
            
            // Apply bypass options
            if (settings.getBypassCookieChecks() && parameter.getType() == IParameter.PARAM_COOKIE) {
                continue;
            }
            
            if (settings.getBypassHeaderChecks() && isHeaderRelatedParameter(parameter)) {
                continue;
            }
            
            // Skip common non-vulnerable parameters in modern apps
            String paramNameLower = parameter.getName().toLowerCase();
            String paramValue = parameter.getValue();
            
            if (isModernAppResponse && (
                paramNameLower.contains("csrf") || 
                paramNameLower.contains("token") || 
                paramNameLower.contains("nonce") ||
                paramNameLower.contains("signature") ||
                paramNameLower.contains("timestamp") ||
                paramValue == null || paramValue.trim().isEmpty()
            )) {
                continue;
            }
            
            String decodedParamValue = helpers.urlDecode(parameter.getValue());
            byte[] bytesOfParamValue = decodedParamValue.getBytes();
            
            if (bytesOfParamValue.length > 2) {
                // TWO-STAGE DETECTION APPROACH:
                // Stage 1: Test with malicious symbols/characters first
                // Stage 2: If symbols are reflected, inject context-aware encoded XSS payloads
                
                // CRITICAL FIX: First check if original parameter value is reflected
                // Only proceed if the parameter value is actually reflected in the response
                Map<String, Object> symbolTestResult = performSymbolReflectionTest(parameter);
                if (symbolTestResult == null || !(Boolean) symbolTestResult.getOrDefault("SYMBOLS_REFLECTED", false)) {
                    // Original parameter value not reflected - skip this parameter
                    // This prevents testing parameters that don't reflect user input
                    continue;
                }
                
                // Symbols are reflected - proceed with enhanced detection
                List<int[]> listOfMatches = getEnhancedMatches(iHttpRequestResponse.getResponse(), parameter);
                
                if (!listOfMatches.isEmpty()) {
                    Map parameterDescription = new HashMap();
                    parameterDescription.put(NAME, parameter.getName());
                    parameterDescription.put(VALUE, parameter.getValue());
                    parameterDescription.put(TYPE, parameter.getType());
                    parameterDescription.put(VALUE_START, parameter.getValueStart());
                    parameterDescription.put(VALUE_END, parameter.getValueEnd());
                    parameterDescription.put(MATCHES, listOfMatches);
                    parameterDescription.put(REFLECTED_IN, checkWhereReflectionPlaced(listOfMatches));
                    parameterDescription.put("CONTENT_TYPE", responseContentType);
                    parameterDescription.put("IS_JSON_RESPONSE", isJSONResponse);
                    
                    // Store symbol test results
                    String reflectionContext = (String) symbolTestResult.get("REFLECTION_CONTEXT");
                    if (reflectionContext != null) {
                        parameterDescription.put("REFLECTION_CONTEXT", reflectionContext);
                    }
                    parameterDescription.put("SYMBOLS_REFLECTED", symbolTestResult.get("SYMBOLS_REFLECTED"));
                    parameterDescription.put("REFLECTED_SYMBOLS", symbolTestResult.get("REFLECTED_SYMBOLS"));
                    
                    // STREAMLINED: Add architecture analysis for application-type specific payloads
                    try {
                        ModernArchitectureDetector archDetector = new ModernArchitectureDetector(helpers, callbacks, settings);
                        ModernArchitectureDetector.ArchitectureAnalysis archAnalysis = archDetector.analyzeArchitecture(iHttpRequestResponse);
                        if (archAnalysis != null) {
                            parameterDescription.put("ARCH_ANALYSIS", archAnalysis);
                        }
                    } catch (Exception e) {
                        // Ignore architecture analysis errors
                    }
                    
                    // Enhanced context analysis
                    try {
                            String enhancedContext = performEnhancedContextAnalysis(parameter, listOfMatches);
                            if (reflectionContext != null && !reflectionContext.equals("UNKNOWN")) {
                                enhancedContext = reflectionContext + " - " + (enhancedContext != null ? enhancedContext : "Standard context");
                            }
                            parameterDescription.put("ENHANCED_CONTEXT", enhancedContext != null ? enhancedContext : "Standard context");
                    } catch (Exception e) {
                        parameterDescription.put("ENHANCED_CONTEXT", reflectionContext != null ? reflectionContext : "Analysis failed");
                    }
                    
                    // XSS vulnerability scoring
                    double xssScore = calculateXSSVulnerabilityScore(parameter, listOfMatches, responseContentType);
                    // Increase score if symbols are reflected
                    if ((Boolean) symbolTestResult.get("SYMBOLS_REFLECTED")) {
                        xssScore = Math.min(100.0, xssScore + 15.0);
                    }
                    parameterDescription.put("XSS_SCORE", xssScore);
                    
                    // Apply filtering
                    if (filteringEngine != null) {
                        FilterResult filterResult = filteringEngine.analyzeReflection(parameterDescription, iHttpRequestResponse);
                        
                        if (filterResult.isFiltered() && filterResult.getConfidenceScore() < 50.0) {
                            continue;
                        }
                        
                        // CRITICAL: Only set CONFIRMED_XSS if we have actual payload reflection evidence
                        // Check if parameter value is actually reflected in response
                        boolean hasReflectionEvidence = false;
                        if (iHttpRequestResponse != null && iHttpRequestResponse.getResponse() != null) {
                            try {
                                byte[] responseBytes = iHttpRequestResponse.getResponse();
                                int bodyOffset = helpers.analyzeResponse(responseBytes).getBodyOffset();
                                String responseBody = new String(
                                    Arrays.copyOfRange(responseBytes, bodyOffset, responseBytes.length),
                                    StandardCharsets.UTF_8
                                );
                                
                                String paramValueStr = parameter.getValue();
                                if (paramValueStr != null && !paramValueStr.isEmpty()) {
                                    // Check for direct reflection
                                    if (responseBody.contains(paramValueStr)) {
                                        hasReflectionEvidence = true;
                                    } else {
                                        // Check for encoded reflection
                                        String urlEncoded = helpers.urlEncode(paramValueStr);
                                        if (responseBody.contains(urlEncoded)) {
                                            hasReflectionEvidence = true;
                                        }
                                    }
                                }
                            } catch (Exception e) {
                                // Ignore errors
                            }
                        }
                        
                        // CRITICAL: Only confirm if we have ACTUAL PAYLOAD REFLECTION evidence AND high confidence
                        // Reflection evidence must be the actual payload, not just parameter value
                        // Check if actual XSS payload (not just original parameter value) is reflected
                        boolean hasActualPayloadReflection = false;
                        if (hasReflectionEvidence && iHttpRequestResponse != null && iHttpRequestResponse.getResponse() != null) {
                            try {
                                byte[] responseBytes = iHttpRequestResponse.getResponse();
                                int bodyOffset = helpers.analyzeResponse(responseBytes).getBodyOffset();
                                String responseBody = new String(
                                    Arrays.copyOfRange(responseBytes, bodyOffset, responseBytes.length),
                                    StandardCharsets.UTF_8
                                );
                                
                                // Check if response contains XSS indicators (actual payload, not just parameter value)
                                // This is a passive scan, so we check for dangerous symbols that indicate XSS payload reflection
                                String[] xssIndicators = {"<script", "</script>", "javascript:", "onerror", "onload", 
                                                          "onclick", "eval(", "alert(", "<img", "<svg", "<iframe"};
                                for (String indicator : xssIndicators) {
                                    if (responseBody.toLowerCase().contains(indicator.toLowerCase())) {
                                        hasActualPayloadReflection = true;
                                        break;
                                    }
                                }
                            } catch (Exception e) {
                                // Ignore errors
                            }
                        }
                        
                        // CRITICAL: Require BOTH reflection evidence AND actual payload indicators for confirmation
                        // High confidence alone is not enough - need actual payload reflection
                        if (filterResult.getConfidenceScore() >= 85.0 && hasReflectionEvidence && hasActualPayloadReflection) {
                            parameterDescription.put("CONFIRMED_XSS", true);
                        } else {
                            parameterDescription.put("CONFIRMED_XSS", false);
                            if (!hasActualPayloadReflection) {
                                callbacks.printOutput("[CheckReflection] FALSE POSITIVE FILTERED: No actual XSS payload indicators in response for parameter: " + parameter.getName());
                            }
                        }
                        
                        parameterDescription.put("CONFIDENCE_SCORE", filterResult.getConfidenceScore());
                        parameterDescription.put("CALCULATED_SEVERITY", filterResult.getSeverity());
                    } else {
                        // Default confidence for JSON responses - but require reflection evidence
                        if (isJSONResponse) {
                            parameterDescription.put("IS_JSON_RESPONSE", true);
                            parameterDescription.put("CONTENT_TYPE", responseContentType);
                            // CRITICAL: Check for actual reflection before confirming
                            boolean hasReflectionEvidenceJSON = false;
                            boolean isJSONExploitable = false;
                            if (iHttpRequestResponse != null && iHttpRequestResponse.getResponse() != null) {
                                try {
                                    byte[] responseBytes = iHttpRequestResponse.getResponse();
                                    int bodyOffset = helpers.analyzeResponse(responseBytes).getBodyOffset();
                                    String responseBody = new String(
                                        Arrays.copyOfRange(responseBytes, bodyOffset, responseBytes.length),
                                        StandardCharsets.UTF_8
                                    );

                                    String paramValueStrJSON = parameter.getValue();
                                    if (paramValueStrJSON != null && !paramValueStrJSON.isEmpty()) {
                                        if (responseBody.contains(paramValueStrJSON) || responseBody.contains(helpers.urlEncode(paramValueStrJSON))) {
                                            hasReflectionEvidenceJSON = true;
                                        }
                                    }

                                    // Check if JSON is actually exploitable (JSONP or unsafe consumption)
                                    boolean isJSONP = isJSONPResponse(responseBody);
                                    boolean hasUnsafe = hasUnsafeJSONConsumptionIndicators(responseBody);
                                    isJSONExploitable = isJSONP || hasUnsafe;
                                } catch (Exception e) {
                                    // Ignore errors
                                }
                            }

                            if (hasReflectionEvidenceJSON && isJSONExploitable) {
                                // Exploitable JSON (JSONP or unsafe consumption) -- confirm
                                parameterDescription.put("CONFIDENCE_SCORE", 85.0);
                                parameterDescription.put("CALCULATED_SEVERITY", "High");
                                parameterDescription.put("CONFIRMED_XSS", true);
                            } else if (hasReflectionEvidenceJSON) {
                                // Reflection in safe JSON.parse() context -- NOT exploitable
                                parameterDescription.put("CONFIDENCE_SCORE", 25.0);
                                parameterDescription.put("CALCULATED_SEVERITY", "Information");
                                parameterDescription.put("CONFIRMED_XSS", false);
                            } else {
                                parameterDescription.put("CONFIDENCE_SCORE", 25.0);
                                parameterDescription.put("CALCULATED_SEVERITY", "Low");
                                parameterDescription.put("CONFIRMED_XSS", false);
                            }
                        }
                    }
                    
                    reflectedParameters.add(parameterDescription);
                }
            }
        }
        
        // Process modern parameters
        if (settings.getModernDetection() || isJSONResponse) {
            List<Map> modernReflections = checkModernParameters(sessionContext);
            if (isJSONResponse) {
                for (Map modernParam : modernReflections) {
                    modernParam.put("IS_JSON_RESPONSE", true);
                    double existingConfidence = -1.0;
                    Object confObj = modernParam.get("CONFIDENCE_SCORE");
                    if (confObj instanceof Number) {
                        existingConfidence = ((Number) confObj).doubleValue();
                    } else if (confObj instanceof String) {
                        try { existingConfidence = Double.parseDouble(((String) confObj).trim()); } catch (Exception ignored) { /* ignore */ }
                    }

                    if (existingConfidence >= 0.0) {
                        modernParam.put("CONFIDENCE_SCORE", Math.min(95.0, existingConfidence + 25.0));
                    } else {
                        modernParam.put("CONFIDENCE_SCORE", 90.0);
                    }
                    modernParam.put("CALCULATED_SEVERITY", "High");
                }
            }
            reflectedParameters.addAll(modernReflections);
        }
        
        // Perform payload validation if enabled
        // CRITICAL: EnhancedAggressive now creates issues directly in testPayloadAdvanced
        // The issues are stored in createdIssues list and will be returned via doPassiveScan
        // We don't add enhancedResults to reflectedParameters to avoid duplicate issue creation
        // CRITICAL: EnhancedAggressive creates issues directly, so we don't need to process reflectedParameters again
        // The issues will be created by EnhancedAggressive and returned via its scanReflectedParameters() method
        if (!reflectedParameters.isEmpty() && (settings.getEnableTruePositiveOnly() || settings.getAggressiveMode())) {
            EnhancedAggressive enhancedScan = new EnhancedAggressive(settings, helpers, iHttpRequestResponse, callbacks, reflectedParameters);
            List<Map> enhancedResults = enhancedScan.scanReflectedParameters();
            
            // CRITICAL: Extract issues from enhancedResults and mark parameters as processed
            // enhancedResults contains Maps with "ISSUE" key if issue was created
            if (enhancedResults != null && !enhancedResults.isEmpty()) {
                for (Map result : enhancedResults) {
                    if (result != null) {
                        Object issueObj = result.get("ISSUE");
                        if (issueObj instanceof IScanIssue) {
                            // CRITICAL: Issue was created by EnhancedAggressive
                            // Mark the parameter as having an issue created to avoid duplicate creation in doPassiveScan
                            Object vulnDataObj = result.get("VULNERABILITY_DATA");
                            if (vulnDataObj instanceof Map) {
                                Map vulnData = (Map) vulnDataObj;
                                String paramName = (String) vulnData.get("paramName");
                                if (paramName != null) {
                                    // Mark this parameter as having an issue created
                                    for (Map param : reflectedParameters) {
                                        if (paramName.equals(param.get(NAME))) {
                                            param.put("ISSUE_CREATED_BY_ENHANCED", true);
                                            param.put("ENHANCED_ISSUE", issueObj);
                                            break;
                                        }
                                    }
                                }
                            }
                            callbacks.printOutput("[CheckReflection] Issue created by EnhancedAggressive - will be returned in doPassiveScan");
                        }
                    }
                }
            }
        }
        
        return reflectedParameters;
    }

    private List<Map> checkModernParameters(SessionContext sessionContext) {
        List<Map> reflectedParams = new ArrayList<>();
        
            try {
            List<ModernParameter> modernParameters = modernParameterExtractor.extractParameters(iHttpRequestResponse);
            
            for (ModernParameter modernParam : modernParameters) {
                Map paramMap = new HashMap();
                paramMap.put(NAME, modernParam.getName());
                paramMap.put(VALUE, modernParam.getValue());
                paramMap.put(TYPE, getModernParameterTypeCode(modernParam.getType()));
                paramMap.put("MODERN_TYPE", modernParam.getType());
                
                List<int[]> matches = getEnhancedMatches(iHttpRequestResponse.getResponse(), modernParam);
                
                if (!matches.isEmpty()) {
                    paramMap.put(MATCHES, matches);
                    paramMap.put(REFLECTED_IN, checkWhereReflectionPlaced(matches));
                    paramMap.put("IS_MODERN_PARAM", true);
                    
                    String enhancedContext = performEnhancedContextAnalysisModern(modernParam, matches);
                    paramMap.put("ENHANCED_CONTEXT", enhancedContext);
                    
                    double modernXssScore = calculateModernXSSScore(modernParam, matches);
                    paramMap.put("XSS_SCORE", modernXssScore);
                    
                    reflectedParams.add(paramMap);
                }
            }
            } catch (Exception e) {
                callbacks.printError("Modern parameter processing error: " + e.getMessage());
        }
        
        return reflectedParams;
    }
    
    private List<int[]> getEnhancedMatches(byte[] response, ModernParameter modernParam) {
        List<int[]> matches = new ArrayList<>();
        String paramValue = modernParam.getValue();
        
        if (paramValue != null && paramValue.length() >= MIN_PAYLOAD_LENGTH) {
            byte[] paramBytes = paramValue.getBytes();
            matches = getMatches(response, paramBytes);
        }
        
        return matches;
    }
    
    private int getModernParameterTypeCode(String modernType) {
        switch (modernType.toUpperCase()) {
            case "GRAPHQL": return 100;
            case "JWT": return 101;
            case "WEBSOCKET": return 102;
            case "API_KEY": return 103;
            case "MULTIPART": return 104;
            default: return IParameter.PARAM_BODY;
        }
    }
    
    private String performEnhancedContextAnalysisModern(ModernParameter modernParam, List<int[]> matches) {
        if (matches.isEmpty()) return "No context available";
        
        try {
            String responseBody = new String(iHttpRequestResponse.getResponse());
            int[] firstMatch = matches.get(0);
            int position = firstMatch[0];
            
            String context = getContextAround(responseBody, position, 100);
            
            if (context.contains("<script")) {
                return "JavaScript context - High risk";
            } else if (context.contains("onload") || context.contains("onerror")) {
                return "Event handler context - High risk";
            } else if (context.contains("href=") || context.contains("src=")) {
                return "Attribute context - Medium risk";
            } else if (context.contains("{{") || context.contains("${")) {
                return "Template context - High risk";
            } else {
                return "HTML body context - Medium risk";
            }
        } catch (Exception e) {
            return "Context analysis failed";
        }
    }
    
    private double calculateModernXSSScore(ModernParameter modernParam, List<int[]> matches) {
        double baseScore = 70.0;
        
        // Boost score for modern parameters
        baseScore += 15.0;
        
        // Boost for JSON responses
        String contentType = extractResponseContentType();
        if (contentType != null && contentType.toLowerCase().contains("application/json")) {
            baseScore += 10.0;
        }
        
        // Boost for GraphQL
        if ("GRAPHQL".equalsIgnoreCase(modernParam.getType())) {
            baseScore += 5.0;
        }
        
        return Math.min(100.0, baseScore);
    }
    
    private String checkWhereReflectionPlaced(List<int[]> listOfMatches) {
        if (listOfMatches.isEmpty()) return "Unknown";
        
        try {
            String responseBody = new String(iHttpRequestResponse.getResponse());
            int[] firstMatch = listOfMatches.get(0);
            int position = firstMatch[0];
            
            String context = getContextAround(responseBody, position, 50);
            
            if (context.contains("<script")) {
                return "JavaScript context";
            } else if (context.contains("onload") || context.contains("onerror")) {
                return "Event handler context";
            } else if (context.contains("href=") || context.contains("src=")) {
                return "Attribute context";
            } else {
                return "HTML body context";
            }
        } catch (Exception e) {
            return "Unknown context";
        }
    }
    
    private List<int[]> getMatches(byte[] response, byte[] match) {
        List<int[]> matches = new ArrayList<>();
        int responseLength = response.length;
        int matchLength = match.length;
        
        for (int i = 0; i <= responseLength - matchLength; i++) {
            boolean found = true;
            for (int j = 0; j < matchLength; j++) {
                if (response[i + j] != match[j]) {
                    found = false;
                    break;
                }
            }
            if (found) {
                matches.add(new int[]{i, i + matchLength});
            }
        }

        return matches;
    }
    
    private String extractResponseContentType() {
        try {
            IResponseInfo responseInfo = helpers.analyzeResponse(iHttpRequestResponse.getResponse());
            List<String> headers = responseInfo.getHeaders();
            
            for (String header : headers) {
                if (header.toLowerCase().startsWith("content-type:")) {
                    return header.substring(13).trim().split(";")[0];
                }
            }
        } catch (Exception e) {
            // Ignore
        }
        return null;
    }
    
    /**
     * CRITICAL: Check if content type is enabled in Settings
     * Only scan content types that are explicitly enabled by user
     */
    private boolean isVulnerableContentType(String contentType) {
        if (contentType == null || settings == null) return false;
        
        // Get enabled content types from Settings
        ArrayList<String> enabledContentTypes = settings.getEnabledContentTypes();
        
        // If no content types are enabled, default to HTML/XHTML only (JSON is data, not code)
        if (enabledContentTypes == null || enabledContentTypes.isEmpty()) {
            String lowerContentType = contentType.toLowerCase();
            return lowerContentType.contains("text/html") || lowerContentType.contains("application/xhtml");
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
     * Check if JSON response is JSONP (directly executable)
     */
    private boolean isJSONPResponse(String responseBody) {
        if (responseBody == null || responseBody.trim().isEmpty()) {
            return false;
        }
        
        // JSONP pattern: known callback names only (not any function call like console.log)
        Pattern jsonpPattern = Pattern.compile(
            "^\\s*(?:callback|jsonp|jsonpcallback|cb|jsoncallback|jQuery\\w+|__jp\\w*|angular\\.callbacks\\._\\w+)[\\w$]*\\s*\\(\\s*[\\{\\[].*[\\}\\]]\\s*\\)\\s*;?\\s*$",
            Pattern.DOTALL | Pattern.CASE_INSENSITIVE);
        return jsonpPattern.matcher(responseBody.trim()).find();
    }
    
    /**
     * Check if JSON has indicators suggesting unsafe consumption
     * JSON is safe unless consumed with eval(), innerHTML, etc.
     */
    private boolean hasUnsafeJSONConsumptionIndicators(String responseBody) {
        if (responseBody == null || responseBody.trim().isEmpty()) {
            return false;
        }
        
        // Check 1: Dangerous field names suggesting unsafe DOM manipulation
        String[] dangerousFields = {"innerHTML", "outerHTML", "html", "content", "script", "eval"};
        for (String field : dangerousFields) {
            Pattern fieldPattern = Pattern.compile("\"" + Pattern.quote(field) + "\"\\s*:", Pattern.CASE_INSENSITIVE);
            if (fieldPattern.matcher(responseBody).find()) {
                return true;
            }
        }
        
        // Check 2: HTML/script content in JSON values (suggests innerHTML usage)
        if (responseBody.contains("<script") || responseBody.contains("</script>") || 
            responseBody.contains("<img") || responseBody.contains("<svg")) {
            return true;
        }
        
        // Check 3: Event handlers in JSON (suggests unsafe usage)
        String[] eventHandlers = {"onclick", "onload", "onerror", "onmouseover"};
        for (String handler : eventHandlers) {
            if (responseBody.toLowerCase().contains("\"" + handler + "\"")) {
                return true;
            }
        }
        
        // Check 4: JavaScript code patterns in JSON
        if (responseBody.contains("javascript:") || responseBody.contains("eval(") || 
            responseBody.contains("Function(")) {
            return true;
        }
        
        // Check 5: Removed — {{ and ${ are too generic (match template literals, destructuring, etc.)
        // Template injection detection is handled separately by EnhancedClientSideAttackDetector

        return false;
    }
    
    private List<int[]> getEnhancedMatches(byte[] response, IParameter parameter) {
        List<int[]> matches = new ArrayList<>();
        String paramValue = parameter.getValue();
        
        if (paramValue != null && paramValue.length() >= MIN_PAYLOAD_LENGTH) {
            // Check original value
            byte[] paramBytes = paramValue.getBytes();
            matches.addAll(getMatches(response, paramBytes));
            
            // Check URL decoded value
            String decodedValue = helpers.urlDecode(paramValue);
            if (!decodedValue.equals(paramValue)) {
                byte[] decodedBytes = decodedValue.getBytes();
                matches.addAll(getMatches(response, decodedBytes));
            }
            
            // Check HTML entity decoded value
        String htmlDecoded = decodeHtmlEntities(paramValue);
        if (!htmlDecoded.equals(paramValue)) {
                byte[] htmlDecodedBytes = htmlDecoded.getBytes();
                matches.addAll(getMatches(response, htmlDecodedBytes));
            }
        }
        
        return removeDuplicateMatches(matches);
    }
    
    private String performEnhancedContextAnalysis(IParameter parameter, List<int[]> matches) {
        if (matches.isEmpty()) return "No context available";
        
        try {
            String responseBody = new String(iHttpRequestResponse.getResponse());
            int[] firstMatch = matches.get(0);
            int position = firstMatch[0];
            
            String context = getContextAround(responseBody, position, 100);
            
            if (context.contains("<script")) {
                return "JavaScript context - High risk";
            } else if (context.contains("onload") || context.contains("onerror")) {
                return "Event handler context - High risk";
            } else if (context.contains("href=") || context.contains("src=")) {
                return "Attribute context - Medium risk";
            } else if (context.contains("{{") || context.contains("${")) {
                return "Template context - High risk";
            } else {
                return "HTML body context - Medium risk";
            }
        } catch (Exception e) {
            return "Context analysis failed";
        }
    }
    
    private double calculateXSSVulnerabilityScore(IParameter parameter, List<int[]> matches, String contentType) {
        double score = 50.0;
        
        // Base score based on parameter type
        switch (parameter.getType()) {
            case IParameter.PARAM_URL:
                score += 10.0;
                break;
            case IParameter.PARAM_BODY:
                score += 15.0;
                break;
            case IParameter.PARAM_JSON:
                score += 20.0;
                break;
        }
        
        // Content type bonus - CRITICAL: JSON is only high risk if exploitable
        if (contentType != null) {
            String lowerContentType = contentType.toLowerCase();
            if (lowerContentType.contains("application/json")) {
                // Check if JSON is actually exploitable
                String responseBody = new String(iHttpRequestResponse.getResponse());
                boolean isJSONP = isJSONPResponse(responseBody);
                boolean hasUnsafeIndicators = hasUnsafeJSONConsumptionIndicators(responseBody);
                
                if (isJSONP) {
                    // JSONP is directly executable - HIGH RISK
                    score += 30.0;
                } else if (hasUnsafeIndicators) {
                    // JSON with unsafe consumption indicators - MEDIUM RISK
                    score += 15.0;
                } else {
                    // Safe JSON (standard JSON.parse) - LOW RISK
                    score += 5.0;
                }
            } else if (lowerContentType.contains("text/html")) {
                // HTML is directly executable - HIGH RISK
                score += 20.0;
            }
        }
        
        // Context bonus
        String context = performEnhancedContextAnalysis(parameter, matches);
        if (context.contains("JavaScript") || context.contains("Template")) {
                    score += 20.0;
        } else if (context.contains("Event handler")) {
                    score += 15.0;
                }
                
        return Math.min(100.0, score);
    }
    
    private boolean isHeaderRelatedParameter(IParameter parameter) {
        String paramName = parameter.getName().toLowerCase();
        return paramName.contains("user-agent") || 
               paramName.contains("referer") || 
               paramName.contains("origin") ||
               paramName.contains("accept") ||
               paramName.contains("content-type");
    }
    
    private String decodeHtmlEntities(String input) {
        if (input == null) return "";
        
        return input.replace("&lt;", "<")
                   .replace("&gt;", ">")
                   .replace("&amp;", "&")
                   .replace("&quot;", "\"")
                   .replace("&#39;", "'");
    }
    
    /**
     * Check if payload is actually an XSS payload (not just a parameter value)
     * CRITICAL: Prevents false positives from regular parameter values
     */
    private boolean isActualXSSPayload(String payload) {
        if (payload == null || payload.trim().isEmpty()) {
            return false;
        }
        
        String lowerPayload = payload.toLowerCase();
        
        // Check for XSS indicators
        String[] xssIndicators = {
            "<script", "</script>", "javascript:", "onerror", "onload", "onclick", 
            "onmouseover", "onfocus", "onblur", "onchange", "onsubmit", "oninput",
            "eval(", "Function(", "setTimeout", "setInterval", "document.write",
            "innerHTML", "outerHTML", "document.cookie", "alert(", "confirm(",
            "prompt(", "atob(", "String.fromCharCode", "\\u003c", "\\x3c",
            "data:text/html", "vbscript:", "expression(", "<img", "<svg", "<iframe",
            "<object", "<embed", "<form", "<input", "<textarea", "<select",
            "<style", "<link", "<meta", "<body", "<html", "<noscript"
        };
        
        for (String indicator : xssIndicators) {
            if (lowerPayload.contains(indicator.toLowerCase())) {
                return true;
            }
        }
        
        // Check for HTML tags
        if (payload.contains("<") && payload.contains(">")) {
            return true;
        }
        
        // Check for encoded XSS patterns
        if (payload.contains("\\u") || payload.contains("\\x") || payload.contains("%3c") || payload.contains("%3e")) {
            if (lowerPayload.contains("script") || lowerPayload.contains("alert") || lowerPayload.contains("eval")) {
                return true;
            }
        }
        
        // Check for template injection patterns
        if (payload.contains("{{") || payload.contains("${") || payload.contains("<%=")) {
            return true;
        }
        
        // Check for event handler patterns
        if (java.util.regex.Pattern.compile("on\\w+\\s*=", java.util.regex.Pattern.CASE_INSENSITIVE).matcher(payload).find()) {
            return true;
        }
        
        // If payload is just alphanumeric or common words, it's likely not an XSS payload
        if (payload.matches("^[a-zA-Z0-9_-]+$") && payload.length() < 20) {
            // Common non-XSS values
            String[] commonValues = {"true", "false", "yes", "no", "null", "undefined", 
                                     "get", "post", "put", "delete", "patch", "head", "options",
                                     "id", "name", "value", "type", "class", "style", "href", "src",
                                     "eoprebootweb", "accountsignup", "redirect", "entry", "flow",
                                     "context", "stepup", "return", "uri", "country", "locale"};
            for (String common : commonValues) {
                if (payload.equalsIgnoreCase(common)) {
                    return false;
                }
            }
            
            // If it's a short alphanumeric string without XSS indicators, it's likely not XSS
            return false;
        }
        
        return false;
    }
    
    private List<int[]> removeDuplicateMatches(List<int[]> matches) {
        List<int[]> uniqueMatches = new ArrayList<>();
        
        for (int[] match : matches) {
            boolean isDuplicate = false;
            for (int[] existing : uniqueMatches) {
                if (Math.abs(match[0] - existing[0]) < 5) {
                    isDuplicate = true;
                    break;
                }
            }
            if (!isDuplicate) {
                uniqueMatches.add(match);
            }
        }
        
        return uniqueMatches;
    }
    
    /**
     * STAGE 1: Test with malicious symbols/characters first
     * This identifies vulnerable parameters before injecting full XSS payloads
     */
    private Map<String, Object> performSymbolReflectionTest(IParameter parameter) {
        Map<String, Object> result = new HashMap<>();
        result.put("SYMBOLS_REFLECTED", false);
        result.put("REFLECTED_SYMBOLS", new ArrayList<String>());
        result.put("REFLECTION_CONTEXT", null);
        
        try {
            byte[] response = iHttpRequestResponse.getResponse();
            if (response == null || response.length == 0) {
                return result;
            }
            
            int bodyOffset = helpers.analyzeResponse(response).getBodyOffset();
            String responseBody = new String(Arrays.copyOfRange(response, bodyOffset, response.length), StandardCharsets.UTF_8);
            
            String paramValue = parameter.getValue();
            if (paramValue == null || paramValue.trim().isEmpty()) {
                return result;
            }
            
            // CRITICAL FIX: First check if the ORIGINAL parameter value is reflected in response
            // This is the foundation - if original value isn't reflected, don't test with symbols!
            int paramValueIndex = responseBody.indexOf(paramValue);
            String actualParamValue = paramValue;
            if (paramValueIndex < 0) {
                // Try URL decoded version
                String decodedParamValue = helpers.urlDecode(paramValue);
                paramValueIndex = responseBody.indexOf(decodedParamValue);
                if (paramValueIndex < 0) {
                    // Parameter value not reflected at all - skip this parameter
                    return result;
                }
                // Use decoded version for further checks
                actualParamValue = decodedParamValue;
            }
            
            // Parameter value IS reflected - now check for critical symbols
            String[] criticalSymbols = {"<", ">", "\"", "'", "`", "&", ";", "=", "(", ")", "[", "]", "{", "}", "/", "\\"};
            List<String> reflectedSymbols = new ArrayList<>();
            
            // Check if any critical symbols from parameter value are reflected
            for (String symbol : criticalSymbols) {
                if (actualParamValue.contains(symbol)) {
                    // Check if symbol appears in same context as paramValue (not just anywhere)
                    String reflectedValue = responseBody.substring(
                        Math.max(0, paramValueIndex - 10),
                        Math.min(responseBody.length(), paramValueIndex + actualParamValue.length() + 10)
                    );
                    if (reflectedValue.contains(symbol)) {
                        reflectedSymbols.add(symbol);
                    }
                }
            }
            
            // Only mark as symbol-reflected if actual dangerous symbols were found
            // Without symbols, there's no XSS vector to exploit
            if (!reflectedSymbols.isEmpty()) {
                result.put("SYMBOLS_REFLECTED", true);
            } else {
                result.put("SYMBOLS_REFLECTED", false);
                result.put("VALUE_REFLECTED", true); // Track that value was seen, but no dangerous symbols
            }
            result.put("REFLECTED_SYMBOLS", reflectedSymbols);
            
            // Determine reflection context based on WHERE the parameter is actually reflected
            String context = determineReflectionContext(responseBody, actualParamValue);
            result.put("REFLECTION_CONTEXT", context);
            
        } catch (Exception e) {
            if (settings != null && settings.getVerboseLogging()) {
                callbacks.printError("CheckReflection: Error in symbol reflection test: " + e.getMessage());
            }
        }
        
        return result;
    }
    
    /**
     * ADVANCED: Determine the context where parameter is reflected with full browser execution awareness
     * This analyzes how the browser will parse and execute the response content
     */
    private String determineReflectionContext(String responseBody, String paramValue) {
        try {
            // CRITICAL FIX: Try multiple search strategies before returning UNKNOWN
            int paramIndex = responseBody.indexOf(paramValue);
            
            // If not found, try case-insensitive search
            if (paramIndex < 0) {
                String lowerResponse = responseBody.toLowerCase();
                String lowerParam = paramValue.toLowerCase();
                paramIndex = lowerResponse.indexOf(lowerParam);
            }
            
            // If still not found, try URL decoded version
            if (paramIndex < 0) {
                try {
                    String urlDecoded = helpers.urlDecode(paramValue);
                    if (urlDecoded != null && !urlDecoded.equals(paramValue)) {
                        paramIndex = responseBody.indexOf(urlDecoded);
                    }
                } catch (Exception e) {
                    // Ignore
                }
            }
            
            // If still not found, try HTML entity decoded version
            if (paramIndex < 0) {
                try {
                    String htmlDecoded = paramValue.replace("&lt;", "<").replace("&gt;", ">")
                                                   .replace("&quot;", "\"").replace("&#39;", "'")
                                                   .replace("&amp;", "&");
                    if (!htmlDecoded.equals(paramValue)) {
                        paramIndex = responseBody.indexOf(htmlDecoded);
                    }
                } catch (Exception e) {
                    // Ignore
                }
            }
            
            // If still not found, try partial match (at least 70% of paramValue)
            if (paramIndex < 0 && paramValue.length() > 5) {
                int minMatchLength = (int)(paramValue.length() * 0.7);
                for (int i = 0; i <= paramValue.length() - minMatchLength; i++) {
                    String partial = paramValue.substring(i, Math.min(i + minMatchLength, paramValue.length()));
                    paramIndex = responseBody.indexOf(partial);
                    if (paramIndex >= 0) {
                        break;
                    }
                }
            }
            
            if (paramIndex < 0) {
                return "UNKNOWN";
            }
            
            // Extract extended context around reflection for deep analysis
            int contextStart = Math.max(0, paramIndex - 500);
            int contextEnd = Math.min(responseBody.length(), paramIndex + paramValue.length() + 500);
            String context = responseBody.substring(contextStart, contextEnd);
            int relativeParamIndex = paramIndex - contextStart;
            
            // ADVANCED: Check for JavaScript execution context (browser will execute this)
            if (context.contains("<script")) {
                // Find all script tags in context
                int scriptStart = context.lastIndexOf("<script", relativeParamIndex);
                if (scriptStart >= 0) {
                    int scriptTagEnd = context.indexOf(">", scriptStart);
                    if (scriptTagEnd > scriptStart) {
                        int scriptEnd = context.indexOf("</script>", scriptTagEnd);
                        if (scriptEnd > scriptTagEnd && relativeParamIndex > scriptTagEnd && relativeParamIndex < scriptEnd) {
                            // Payload is inside script tag - browser will execute as JavaScript
                            String scriptContent = context.substring(scriptTagEnd + 1, scriptEnd);
                            
                            // Check if in JavaScript string (quoted context)
                            String beforePayload = scriptContent.substring(0, relativeParamIndex - scriptTagEnd - 1);
                            int singleQuotes = countUnescapedQuotes(beforePayload, '\'');
                            int doubleQuotes = countUnescapedQuotes(beforePayload, '"');
                            int backticks = countUnescapedQuotes(beforePayload, '`');
                            
                            // Check for template literals
                            if (backticks % 2 == 1) {
                                return "JAVASCRIPT_TEMPLATE_LITERAL"; // Inside template literal - can execute
                            }
                            
                            // Check for string context
                            if (singleQuotes % 2 == 1) {
                                return "JAVASCRIPT_STRING_SINGLE"; // Inside single-quoted string
                            }
                            if (doubleQuotes % 2 == 1) {
                                return "JAVASCRIPT_STRING_DOUBLE"; // Inside double-quoted string
                            }
                            
                            // Check for comment context
                            if (beforePayload.contains("//") || beforePayload.contains("/*")) {
                                int lastComment = Math.max(beforePayload.lastIndexOf("//"), beforePayload.lastIndexOf("/*"));
                                if (lastComment > beforePayload.lastIndexOf("\n") && lastComment > beforePayload.lastIndexOf("*/")) {
                                    return "JAVASCRIPT_COMMENT"; // In comment - not executable
                                }
                            }
                            
                            // Direct JavaScript execution context - HIGHEST RISK
                            return "JAVASCRIPT_EXECUTION"; // Browser will execute this directly
                        }
                    }
                }
            }
            
            // ADVANCED: Check for event handler context (browser will execute on event)
            String[] eventHandlers = {"onload", "onerror", "onclick", "onmouseover", "onfocus", "onblur", 
                                     "onchange", "onsubmit", "oninput", "onkeydown", "onkeyup", "onkeypress",
                                     "onmousedown", "onmouseup", "onmousemove", "onmouseout", "onmouseenter",
                                     "onmouseleave", "ondblclick", "oncontextmenu", "onwheel", "onscroll"};
            for (String handler : eventHandlers) {
                int handlerIndex = context.toLowerCase().indexOf(handler + "=", Math.max(0, relativeParamIndex - 200));
                if (handlerIndex >= 0 && handlerIndex < relativeParamIndex) {
                    // Check if payload is in event handler value
                    int valueStart = context.indexOf("=", handlerIndex) + 1;
                    // Skip whitespace and quotes
                    while (valueStart < context.length() && (context.charAt(valueStart) == ' ' || 
                           context.charAt(valueStart) == '"' || context.charAt(valueStart) == '\'')) {
                        valueStart++;
                    }
                    int valueEnd = findAttributeValueEnd(context, valueStart);
                    if (relativeParamIndex >= valueStart && relativeParamIndex < valueEnd) {
                        // Browser will execute this as JavaScript when event fires
                        return "EVENT_HANDLER_EXECUTION"; // High risk - browser executes on event
                    }
                }
            }
            
            // ADVANCED: Check for HTML attribute context with execution potential
            // CRITICAL FIX: Only detect attribute context if paramValue is ACTUALLY inside an attribute value
            // First, find where paramValue appears in the context
            int paramValueStart = context.indexOf(paramValue, Math.max(0, relativeParamIndex - 200));
            if (paramValueStart >= 0) {
                // Look backwards from paramValue to find the nearest attribute
                String beforeParam = context.substring(Math.max(0, paramValueStart - 200), paramValueStart);
                Pattern attrPattern = Pattern.compile(
                    "(href|src|action|formaction|on\\w+)\\s*=\\s*([\"']?)\\s*[^\"'>]*$", 
                    Pattern.CASE_INSENSITIVE
                );
                java.util.regex.Matcher attrMatcher = attrPattern.matcher(beforeParam);
                if (attrMatcher.find()) {
                    // Found an attribute before paramValue - check if paramValue is in its value
                    String attrName = attrMatcher.group(1).toLowerCase();
                    String quote = attrMatcher.group(2);
                    
                    // Check if paramValue is actually inside this attribute's value
                    // (not just appearing after it)
                    int attrValueStart = attrMatcher.end();
                    int attrValueEnd = findAttributeValueEnd(context, attrValueStart);
                    if (paramValueStart >= attrValueStart && paramValueStart < attrValueEnd) {
                        // paramValue is inside attribute value
                        String attrValue = context.substring(attrValueStart, Math.min(attrValueEnd, context.length()));
                        
                        // Check if attribute can execute JavaScript
                        if (attrName.equals("href") || attrName.equals("src") || attrName.equals("action") || 
                            attrName.equals("formaction") || attrName.startsWith("on")) {
                            // Browser may execute JavaScript from these attributes
                            if (attrValue.contains("javascript:") || attrValue.contains("data:text/html") || 
                                attrValue.contains("data:text/javascript")) {
                                return "URL_JAVASCRIPT_EXECUTION"; // javascript: protocol - browser executes
                            }
                            // Only return ATTRIBUTE_URL_EXECUTION if it's actually a URL-like attribute
                            if (attrName.equals("href") || attrName.equals("src") || attrName.equals("action") || 
                                attrName.equals("formaction")) {
                                // CRITICAL: Only if paramValue looks like it could be a URL/path
                                // Don't detect file paths as URL attributes unless they're actually in href/src
                                if (paramValue.contains("/") || paramValue.contains(".") || 
                                    paramValue.contains("http") || paramValue.contains(":")) {
                                    return "ATTRIBUTE_URL_EXECUTION"; // URL attribute - may execute
                                }
                            }
                            // Event handlers are different
                            if (attrName.startsWith("on")) {
                                return "EVENT_HANDLER_EXECUTION"; // Event handler - browser executes
                            }
                        }
                        return "HTML_ATTRIBUTE"; // Regular attribute
                    }
                }
            }
            
            // ADVANCED: Check for JSON context with unsafe consumption
            if (context.contains("{") && context.contains("}")) {
                // Check if it's JSONP (executable)
                if (context.contains("callback") || context.contains("jsonp") || context.contains("jsoncallback")) {
                    return "JSONP_EXECUTION"; // JSONP - browser executes as JavaScript
                }
                // Check for unsafe JSON consumption patterns
                String beforeJson = responseBody.substring(Math.max(0, paramIndex - 1000), paramIndex);
                if (beforeJson.contains("eval(") || beforeJson.contains("Function(") || 
                    beforeJson.contains("innerHTML") || beforeJson.contains("document.write")) {
                    return "JSON_UNSAFE_CONSUMPTION"; // JSON consumed unsafely - may execute
                }
                if (context.contains("\"" + paramValue + "\"") || context.contains("'" + paramValue + "'")) {
                    return "JSON"; // Safe JSON
                }
            }
            
            // ADVANCED: Check for CSS context (may execute in some browsers)
            if (context.contains("<style") || context.contains("style=")) {
                int styleStart = context.lastIndexOf("<style", relativeParamIndex);
                if (styleStart >= 0) {
                    int styleEnd = context.indexOf("</style>", styleStart);
                    if (styleEnd > styleStart && relativeParamIndex > styleStart && relativeParamIndex < styleEnd) {
                        // Check for expression() or javascript: in CSS
                        String styleContent = context.substring(styleStart, styleEnd);
                        if (styleContent.contains("expression(") || styleContent.contains("javascript:") ||
                            styleContent.contains("url(javascript:")) {
                            return "CSS_EXECUTION"; // CSS with execution - browser may execute
                        }
                        return "CSS"; // Regular CSS
                    }
                }
            }
            
            // ADVANCED: Check for HTML tag context (browser will parse as HTML)
            if (context.matches(".*<[^>]*" + Pattern.quote(paramValue) + "[^>]*>.*")) {
                // Check if it's a self-closing tag or void element
                String[] voidElements = {"img", "input", "br", "hr", "meta", "link", "area", "base", 
                                        "col", "embed", "source", "track", "wbr"};
                for (String element : voidElements) {
                    if (context.matches(".*<" + element + "[^>]*" + Pattern.quote(paramValue) + ".*")) {
                        return "HTML_VOID_ELEMENT"; // Void element - browser parses immediately
                    }
                }
                return "HTML_TAG"; // Regular HTML tag
            }
            
            // ADVANCED: Check for URL context with execution potential
            if (context.contains("http://") || context.contains("https://") || context.contains("javascript:") ||
                context.contains("data:") || context.contains("vbscript:")) {
                if (context.contains("javascript:") || context.contains("data:text/html") || 
                    context.contains("data:text/javascript") || context.contains("vbscript:")) {
                    return "URL_EXECUTION"; // URL protocol that executes - browser executes
                }
                return "URL"; // Regular URL
            }
            
            // Default to HTML body (browser will parse as HTML)
            return "HTML_BODY";
            
        } catch (Exception e) {
            if (settings != null && settings.getVerboseLogging()) {
                callbacks.printError("CheckReflection: Error in determineReflectionContext: " + e.getMessage());
            }
            return "UNKNOWN";
        }
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
            // Quoted value
            for (int i = start + 1; i < context.length(); i++) {
                if (context.charAt(i) == quote && context.charAt(i - 1) != '\\') {
                    return i + 1;
                }
            }
            return context.length();
        } else {
            // Unquoted value - ends at space, >, or /
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
     * STAGE 2: Encode payload based on reflection context
     * This ensures payloads are properly encoded for the specific context where they're reflected
     */
    private String encodePayloadForContext(String payload, String context, String contentType) {
        if (payload == null || payload.isEmpty()) {
            return payload;
        }
        
        try {
            // JSON context encoding
            if ("JSON".equals(context) || (contentType != null && contentType.contains("application/json"))) {
                // JSON string encoding: escape quotes, backslashes, newlines
                return payload.replace("\\", "\\\\")
                             .replace("\"", "\\\"")
                             .replace("\n", "\\n")
                             .replace("\r", "\\r")
                             .replace("\t", "\\t");
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
            
            // CRITICAL FIX: ATTRIBUTE_URL_EXECUTION should NOT URL encode the entire payload!
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
                if (payload.contains("alert") || payload.contains("eval") || payload.contains("Function")) {
                    // JavaScript code for URL - don't URL encode!
                    return payload;
                }
                // Only URL encode if it's a plain string value
                return helpers.urlEncode(payload);
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
            
            // URL context encoding (only for URL parameter values, not JavaScript code)
            if ("URL".equals(context)) {
                // Only URL encode if it's not JavaScript code
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
     * Verify payload reflection in response with context awareness
     */
    /**
     * ADVANCED: Verify payload reflection with full browser execution context awareness
     * This understands how browsers will parse and execute the reflected payload
     */
    private boolean verifyPayloadReflection(byte[] response, String payload, String context, String contentType) {
        try {
            int bodyOffset = helpers.analyzeResponse(response).getBodyOffset();
            String responseBody = new String(Arrays.copyOfRange(response, bodyOffset, response.length), StandardCharsets.UTF_8);
            
            // ADVANCED: Re-determine context from actual response for accuracy
            String actualContext = determineReflectionContext(responseBody, payload);
            if (!"UNKNOWN".equals(actualContext) && !actualContext.equals(context)) {
                // Context changed - use actual context for verification
                context = actualContext;
            }
            
            // Check for direct reflection
            if (responseBody.contains(payload)) {
                // CRITICAL FIX: Check if payload is in a SAFE context (not exploitable)
                int payloadPos = responseBody.indexOf(payload);
                if (isReflectionInSafeContext(responseBody, payload, payloadPos)) {
                    callbacks.printOutput("[verifyPayloadReflection] Payload found but in SAFE context - NOT exploitable");
                    return false; // Safe context - not exploitable
                }
                // ADVANCED: Verify it's in an executable context
                if (isExecutableContext(actualContext)) {
                    return true; // Payload in executable context - exploitable
                }
                // Reflection confirmed and not in safe context
                return true;
            }
            
            // ADVANCED: Check for context-appropriate encoded reflection
            if ("JSON".equals(context) || "JSONP_EXECUTION".equals(context) || 
                "JSON_UNSAFE_CONSUMPTION".equals(context) || 
                (contentType != null && contentType.contains("application/json"))) {
                // Check for JSON-escaped version
                String jsonEscaped = payload.replace("\\", "\\\\").replace("\"", "\\\"")
                                           .replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t");
                if (responseBody.contains(jsonEscaped)) {
                    // JSONP or unsafe consumption means executable
                    if (context.contains("EXECUTION") || context.contains("UNSAFE")) {
                        return true; // Executable JSON context
                    }
                    return true; // JSON reflection confirmed
                }
            }
            
            // ADVANCED: Check for JavaScript string context reflection
            if (context.startsWith("JAVASCRIPT") || context.contains("EXECUTION")) {
                // Check for JavaScript-escaped version
                String jsEscaped = payload;
                if (context.contains("SINGLE")) {
                    jsEscaped = payload.replace("\\", "\\\\").replace("'", "\\'");
                } else if (context.contains("DOUBLE")) {
                    jsEscaped = payload.replace("\\", "\\\\").replace("\"", "\\\"");
                }
                if (responseBody.contains(jsEscaped) || responseBody.contains(payload)) {
                    return true; // JavaScript context - executable
                }
            }
            
            // ADVANCED: Check for event handler context reflection
            if (context.contains("EVENT_HANDLER") || context.contains("EXECUTION")) {
                // Event handlers execute JavaScript - check for reflection
                if (responseBody.contains(payload) || responseBody.contains(helpers.urlEncode(payload))) {
                    return true; // Event handler context - executable
                }
            }
            
            // CRITICAL FIX: Check for URL-encoded version (if we injected URL-encoded)
            String urlEncoded = helpers.urlEncode(payload);
            if (responseBody.contains(urlEncoded)) {
                // ADVANCED: Check if URL is in executable context
                if (context.contains("URL") && (context.contains("EXECUTION") || 
                    responseBody.contains("javascript:") || responseBody.contains("data:text/html"))) {
                    return true; // Executable URL context
                }
                return true; // URL reflection confirmed
            }
            
            // CRITICAL FIX: Check for URL-DECODED version (if we injected URL-encoded, server might decode it)
            // This is the KEY fix: we inject %3Cscript%3E but server reflects <script>
            try {
                // If payload is URL-encoded, check for decoded version
                if (payload.contains("%")) {
                    String urlDecoded = helpers.urlDecode(payload);
                    if (urlDecoded != null && !urlDecoded.equals(payload) && responseBody.contains(urlDecoded)) {
                        callbacks.printOutput("[CheckReflection] URL-decoded payload reflection detected: injected '" + 
                            payload.substring(0, Math.min(30, payload.length())) + "' but reflected '" + 
                            urlDecoded.substring(0, Math.min(30, urlDecoded.length())) + "'");
                        return true; // Decoded reflection confirmed
                    }
                }
                // Also check if original payload (which might be decoded) is in response
                // This handles cases where we inject <script> and it's reflected as-is
                if (!payload.contains("%") && responseBody.contains(payload)) {
                    return true; // Direct reflection
                }
            } catch (Exception e) {
                // Ignore decode errors
            }

            // Check for double URL-decoding (server decodes twice)
            if (payload.contains("%25")) {
                try {
                    String singleDecoded = helpers.urlDecode(payload);
                    if (singleDecoded != null && !singleDecoded.equals(payload) && responseBody.contains(singleDecoded)) {
                        callbacks.printOutput("[CheckReflection] Double-decode detected: server decoded once");
                        return true;
                    }
                    String doubleDecoded = helpers.urlDecode(singleDecoded);
                    if (doubleDecoded != null && !doubleDecoded.equals(singleDecoded) && responseBody.contains(doubleDecoded)) {
                        callbacks.printOutput("[CheckReflection] Double-decode detected: server decoded twice");
                        return true;
                    }
                } catch (Exception ignored) {}
            }

            // ADVANCED: Check for HTML entity encoded version (NOT exploitable)
            String htmlEncoded = payload.replace("<", "&lt;").replace(">", "&gt;")
                                       .replace("\"", "&quot;").replace("'", "&#39;");
            if (responseBody.contains(htmlEncoded) && !responseBody.contains(payload)) {
                // HTML encoded is safe - not exploitable
                return false;
            }

            // Check for numeric HTML entity encoded version (NOT exploitable)
            String numericEncoded = payload.replace("<", "&#60;").replace(">", "&#62;")
                                           .replace("\"", "&#34;").replace("'", "&#39;");
            if (!numericEncoded.equals(payload) && responseBody.contains(numericEncoded) && !responseBody.contains(payload)) {
                return false; // Numeric entity encoded = safe
            }

            // Check for JSON/Unicode encoded version (NOT exploitable in HTML context)
            String unicodeEncoded = payload.replace("<", "\\u003c").replace(">", "\\u003e");
            if (!unicodeEncoded.equals(payload) && responseBody.contains(unicodeEncoded) && !responseBody.contains(payload)) {
                return false; // Unicode escaped = safe
            }
            
            // CRITICAL FIX: Do NOT use partial reflection - this causes false positives
            // Partial matches are NOT sufficient proof of vulnerability
            // Only accept ACTUAL payload reflection (direct, decoded, or URL-encoded)
            // ADVANCED: Check for partial reflection in executable context - REMOVED (too lenient)
            // String[] payloadParts = payload.split("[<>\"'()\\[\\]{}]");
            // int foundParts = 0;
            // for (String part : payloadParts) {
            //     if (part.length() > 3 && responseBody.contains(part)) {
            //         foundParts++;
            //     }
            // }
            // 
            // // If in executable context, partial reflection may still be exploitable
            // if (isExecutableContext(actualContext) && foundParts >= Math.max(1, (int)(payloadParts.length * 0.5))) {
            //     return true; // NO - too lenient, causes false positives
            // }
            // 
            // // Standard partial reflection check (at least 70% of payload parts)
            // return foundParts >= Math.max(1, (int)(payloadParts.length * 0.7)); // NO - too lenient
            
            return false; // Payload not reflected - not exploitable
            
        } catch (Exception e) {
            if (settings != null && settings.getVerboseLogging()) {
                callbacks.printError("CheckReflection: Error in verifyPayloadReflection: " + e.getMessage());
            }
            return false;
        }
    }
    
    /**
     * CRITICAL FIX: Check if reflection is in a safe (non-executable) context
     * This prevents false positives from reflections in comments, CDATA, etc.
     * @param responseBody The full response body
     * @param payload The payload to check
     * @param position The position where payload was found (-1 to auto-detect)
     * @return true if payload is in a safe context (NOT exploitable)
     */
    private boolean isReflectionInSafeContext(String responseBody, String payload, int position) {
        if (responseBody == null || payload == null) return false;

        // Find payload position if not provided
        if (position < 0) {
            position = responseBody.indexOf(payload);
            if (position < 0) return false; // Payload not found
        }

        // Get context window around payload (500 chars before and after)
        int windowStart = Math.max(0, position - 500);
        int windowEnd = Math.min(responseBody.length(), position + payload.length() + 500);
        String contextBefore = responseBody.substring(windowStart, position);
        String contextAfter = responseBody.substring(position + payload.length(), windowEnd);

        // === CHECK 1: HTML COMMENT CONTEXT ===
        // Pattern: <!-- ... payload ... -->
        int lastCommentStart = contextBefore.lastIndexOf("<!--");
        int lastCommentEnd = contextBefore.lastIndexOf("-->");
        if (lastCommentStart > lastCommentEnd) {
            // We're inside an HTML comment - check if it closes after payload
            int nextCommentEnd = contextAfter.indexOf("-->");
            if (nextCommentEnd >= 0) {
                callbacks.printOutput("[SafeContext] FALSE POSITIVE: Payload in HTML comment - NOT exploitable");
                return true; // Safe - in HTML comment
            }
        }

        // === CHECK 2: CDATA SECTION ===
        // Pattern: <![CDATA[ ... payload ... ]]>
        int lastCDATAStart = contextBefore.lastIndexOf("<![CDATA[");
        int lastCDATAEnd = contextBefore.lastIndexOf("]]>");
        if (lastCDATAStart > lastCDATAEnd) {
            int nextCDATAEnd = contextAfter.indexOf("]]>");
            if (nextCDATAEnd >= 0) {
                callbacks.printOutput("[SafeContext] FALSE POSITIVE: Payload in CDATA section - NOT exploitable");
                return true; // Safe - in CDATA
            }
        }

        // === CHECK 3: JAVASCRIPT SINGLE-LINE COMMENT ===
        // Pattern: // ... payload ... \n
        // Check if there's a // before payload on the same line
        int lastNewlineBefore = contextBefore.lastIndexOf("\n");
        if (lastNewlineBefore < 0) lastNewlineBefore = 0;
        String sameLine = contextBefore.substring(lastNewlineBefore);
        if (sameLine.contains("//") && !sameLine.contains("http://") && !sameLine.contains("https://")) {
            // There's a // comment on this line before the payload
            int commentPos = sameLine.lastIndexOf("//");
            // Make sure it's not inside a string
            String beforeComment = sameLine.substring(0, commentPos);
            int singleQuotes = countOccurrences(beforeComment, '\'') - countOccurrences(beforeComment, "\\'");
            int doubleQuotes = countOccurrences(beforeComment, '"') - countOccurrences(beforeComment, "\\\"");
            if (singleQuotes % 2 == 0 && doubleQuotes % 2 == 0) {
                callbacks.printOutput("[SafeContext] FALSE POSITIVE: Payload in JS single-line comment - NOT exploitable");
                return true; // Safe - in JS comment
            }
        }

        // === CHECK 4: JAVASCRIPT MULTI-LINE COMMENT ===
        // Pattern: /* ... payload ... */
        int lastBlockCommentStart = contextBefore.lastIndexOf("/*");
        int lastBlockCommentEnd = contextBefore.lastIndexOf("*/");
        if (lastBlockCommentStart > lastBlockCommentEnd) {
            int nextBlockCommentEnd = contextAfter.indexOf("*/");
            if (nextBlockCommentEnd >= 0) {
                callbacks.printOutput("[SafeContext] FALSE POSITIVE: Payload in JS block comment - NOT exploitable");
                return true; // Safe - in JS block comment
            }
        }

        // === CHECK 5: PROPERLY ESCAPED JSON STRING ===
        // If payload contains < or > and they're escaped as \u003c or \u003e, it's safe
        String lowerContext = responseBody.substring(windowStart, windowEnd).toLowerCase();
        if (lowerContext.contains("\\u003c") || lowerContext.contains("\\u003e")) {
            // Check if our payload's dangerous chars are escaped
            String payloadLower = payload.toLowerCase();
            if (payloadLower.contains("<") || payloadLower.contains(">")) {
                // The response has unicode escapes - check if payload is escaped
                String escapedPayload = payload.replace("<", "\\u003c").replace(">", "\\u003e");
                if (responseBody.contains(escapedPayload) && !responseBody.contains(payload)) {
                    callbacks.printOutput("[SafeContext] FALSE POSITIVE: Payload Unicode-escaped in JSON - NOT exploitable");
                    return true; // Safe - unicode escaped
                }
            }
        }

        // === CHECK 6: HTML ENTITY ENCODED ===
        // If < and > are encoded as &lt; and &gt;, it's safe
        String htmlEncoded = payload.replace("<", "&lt;").replace(">", "&gt;")
                                   .replace("\"", "&quot;").replace("'", "&#39;");
        if (responseBody.contains(htmlEncoded) && !responseBody.contains(payload)) {
            callbacks.printOutput("[SafeContext] FALSE POSITIVE: Payload HTML-entity encoded - NOT exploitable");
            return true; // Safe - HTML encoded
        }

        // Also check for mixed encoding (some chars encoded, some not)
        if (payload.contains("<") && payload.contains(">")) {
            String partialEncoded1 = payload.replace("<", "&lt;");
            String partialEncoded2 = payload.replace(">", "&gt;");
            if ((responseBody.contains(partialEncoded1) || responseBody.contains(partialEncoded2))
                && !responseBody.contains(payload)) {
                callbacks.printOutput("[SafeContext] FALSE POSITIVE: Payload partially HTML-encoded - NOT exploitable");
                return true; // Safe - partially encoded
            }
        }

        // === CHECK 7: TEXTAREA OR XMP CONTEXT ===
        // Content in <textarea> or <xmp> is treated as text, not HTML
        String[] textContextTags = {"textarea", "xmp", "plaintext", "listing"};
        for (String tag : textContextTags) {
            int lastTagOpen = contextBefore.toLowerCase().lastIndexOf("<" + tag);
            int lastTagClose = contextBefore.toLowerCase().lastIndexOf("</" + tag);
            if (lastTagOpen > lastTagClose) {
                callbacks.printOutput("[SafeContext] FALSE POSITIVE: Payload in <" + tag + "> - NOT exploitable");
                return true; // Safe - in text context
            }
        }

        // === CHECK 8: NOSCRIPT CONTEXT ===
        int lastNoscriptOpen = contextBefore.toLowerCase().lastIndexOf("<noscript");
        int lastNoscriptClose = contextBefore.toLowerCase().lastIndexOf("</noscript");
        if (lastNoscriptOpen > lastNoscriptClose) {
            callbacks.printOutput("[SafeContext] FALSE POSITIVE: Payload in <noscript> - NOT exploitable (with JS enabled)");
            return true; // Safe when JS is enabled
        }

        // === CHECK 9: SVG/MATH FOREIGN CONTENT (but still check for script) ===
        // SVG and MathML can have script, so only safe if no execution vectors

        // === CHECK 10: TEMPLATE ELEMENT ===
        int lastTemplateOpen = contextBefore.toLowerCase().lastIndexOf("<template");
        int lastTemplateClose = contextBefore.toLowerCase().lastIndexOf("</template");
        if (lastTemplateOpen > lastTemplateClose) {
            // Template content is inert until cloned
            callbacks.printOutput("[SafeContext] FALSE POSITIVE: Payload in <template> - NOT immediately exploitable");
            return true; // Safe - template is inert
        }

        // === CHECK 11: ATTRIBUTE VALUE WITH PROPER QUOTING ===
        // Check if payload is inside a properly quoted attribute value
        // Pattern: attribute="...payload..." or attribute='...payload...'
        if (isInProperlyQuotedAttribute(contextBefore, contextAfter, payload)) {
            // Additional check: is the attribute an event handler or dangerous?
            String attrName = extractAttributeName(contextBefore);
            if (attrName != null) {
                String lowerAttr = attrName.toLowerCase();
                // Safe attributes (not event handlers, not href/src with javascript:)
                if (!lowerAttr.startsWith("on") && !lowerAttr.equals("href") &&
                    !lowerAttr.equals("src") && !lowerAttr.equals("action") &&
                    !lowerAttr.equals("formaction") && !lowerAttr.equals("data") &&
                    !lowerAttr.equals("srcdoc")) {
                    callbacks.printOutput("[SafeContext] Payload in safe attribute '" + attrName + "' with proper quoting");
                    // Note: Not returning true here as attribute values can still be dangerous
                    // depending on context. Let other checks handle this.
                }
            }
        }

        // === CHECK 12: CSS STYLE CONTEXT ===
        // Payload inside <style> block is not directly exploitable in modern browsers
        // (expression() only worked in IE <= 7, no longer relevant)
        int lastStyleOpen = contextBefore.toLowerCase().lastIndexOf("<style");
        int lastStyleClose = contextBefore.toLowerCase().lastIndexOf("</style");
        if (lastStyleOpen > lastStyleClose) {
            int nextStyleClose = contextAfter.toLowerCase().indexOf("</style");
            if (nextStyleClose >= 0) {
                // Verify it's NOT a closing tag breakout (payload contains </style>)
                if (!payload.toLowerCase().contains("</style")) {
                    callbacks.printOutput("[SafeContext] FALSE POSITIVE: Payload in CSS <style> block - NOT exploitable");
                    return true;
                }
            }
        }

        // === CHECK 13: NON-EXECUTABLE SCRIPT TYPES ===
        // <script type="application/ld+json">, <script type="text/template">, etc.
        // These script blocks are NOT executed by the browser
        int lastScriptOpen = contextBefore.toLowerCase().lastIndexOf("<script");
        if (lastScriptOpen >= 0) {
            String scriptTag = contextBefore.substring(lastScriptOpen);
            String lowerScriptTag = scriptTag.toLowerCase();
            boolean isNonExec = lowerScriptTag.contains("type=\"application/ld+json") ||
                lowerScriptTag.contains("type='application/ld+json") ||
                lowerScriptTag.contains("type=\"application/json") ||
                lowerScriptTag.contains("type='application/json") ||
                lowerScriptTag.contains("type=\"text/template") ||
                lowerScriptTag.contains("type='text/template") ||
                lowerScriptTag.contains("type=\"text/x-template") ||
                lowerScriptTag.contains("type='text/x-template") ||
                lowerScriptTag.contains("type=\"text/x-handlebars") ||
                lowerScriptTag.contains("type='text/x-handlebars") ||
                lowerScriptTag.contains("type=\"text/html") ||
                lowerScriptTag.contains("type='text/html") ||
                lowerScriptTag.contains("type=\"text/plain") ||
                lowerScriptTag.contains("type='text/plain");
            if (isNonExec) {
                int nextScriptClose = contextAfter.toLowerCase().indexOf("</script");
                if (nextScriptClose >= 0) {
                    // Verify the payload doesn't break out of the script tag
                    if (!payload.toLowerCase().contains("</script")) {
                        callbacks.printOutput("[SafeContext] FALSE POSITIVE: Payload in non-executable script type - NOT exploitable");
                        return true;
                    }
                }
            }
        }

        // === CHECK 14: SVG ATTRIBUTE VALUE (non-event, non-URL) ===
        // SVG attributes like d="...", viewBox="...", transform="..." are safe
        // even with reflected content (they're geometry, not code)
        String lowerBefore = contextBefore.toLowerCase();
        if (lowerBefore.contains("<svg") || lowerBefore.contains("<path") ||
            lowerBefore.contains("<rect") || lowerBefore.contains("<circle")) {
            // Check if we're inside a safe SVG attribute
            String svgAttrName = extractAttributeName(contextBefore);
            if (svgAttrName != null) {
                String lowerSvgAttr = svgAttrName.toLowerCase();
                // Safe SVG geometry attributes
                if (lowerSvgAttr.equals("d") || lowerSvgAttr.equals("viewbox") ||
                    lowerSvgAttr.equals("transform") || lowerSvgAttr.equals("points") ||
                    lowerSvgAttr.equals("x") || lowerSvgAttr.equals("y") ||
                    lowerSvgAttr.equals("width") || lowerSvgAttr.equals("height") ||
                    lowerSvgAttr.equals("fill") || lowerSvgAttr.equals("stroke") ||
                    lowerSvgAttr.equals("class") || lowerSvgAttr.equals("style") ||
                    lowerSvgAttr.equals("cx") || lowerSvgAttr.equals("cy") ||
                    lowerSvgAttr.equals("r") || lowerSvgAttr.equals("rx") ||
                    lowerSvgAttr.equals("ry") || lowerSvgAttr.equals("aria-hidden") ||
                    lowerSvgAttr.equals("focusable") || lowerSvgAttr.equals("xmlns")) {
                    callbacks.printOutput("[SafeContext] FALSE POSITIVE: Payload in safe SVG attribute '" + svgAttrName + "'");
                    return true;
                }
            }
        }

        return false; // Not in a known safe context
    }

    /**
     * Helper: Count occurrences of a character in a string
     */
    private int countOccurrences(String str, char ch) {
        int count = 0;
        for (int i = 0; i < str.length(); i++) {
            if (str.charAt(i) == ch) count++;
        }
        return count;
    }

    /**
     * Helper: Count occurrences of a substring in a string
     */
    private int countOccurrences(String str, String sub) {
        int count = 0;
        int idx = 0;
        while ((idx = str.indexOf(sub, idx)) != -1) {
            count++;
            idx += sub.length();
        }
        return count;
    }

    /**
     * Helper: Check if payload is inside a properly quoted attribute
     */
    private boolean isInProperlyQuotedAttribute(String before, String after, String payload) {
        // Check for double-quoted attribute
        int lastDoubleQuote = before.lastIndexOf('"');
        int lastEquals = before.lastIndexOf('=');
        if (lastDoubleQuote > lastEquals && lastEquals > 0) {
            // There's a quote after = before the payload
            // Check if there's a closing quote after payload
            int nextDoubleQuote = after.indexOf('"');
            if (nextDoubleQuote >= 0) {
                // Check the quote isn't escaped
                if (nextDoubleQuote == 0 || after.charAt(nextDoubleQuote - 1) != '\\') {
                    return true;
                }
            }
        }

        // Check for single-quoted attribute
        int lastSingleQuote = before.lastIndexOf('\'');
        if (lastSingleQuote > lastEquals && lastEquals > 0) {
            int nextSingleQuote = after.indexOf('\'');
            if (nextSingleQuote >= 0) {
                if (nextSingleQuote == 0 || after.charAt(nextSingleQuote - 1) != '\\') {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Helper: Extract attribute name from context before payload
     */
    private String extractAttributeName(String before) {
        // Find the last attribute pattern: name="
        int lastEquals = before.lastIndexOf('=');
        if (lastEquals < 0) return null;

        // Work backwards to find attribute name
        int nameEnd = lastEquals;
        int nameStart = nameEnd - 1;
        while (nameStart >= 0 && (Character.isLetterOrDigit(before.charAt(nameStart)) ||
               before.charAt(nameStart) == '-' || before.charAt(nameStart) == '_')) {
            nameStart--;
        }
        nameStart++; // Move past the non-name character

        if (nameStart < nameEnd) {
            return before.substring(nameStart, nameEnd);
        }
        return null;
    }

    /**
     * Check if context is executable by browser
     */
    private boolean isExecutableContext(String context) {
        if (context == null) return false;

        return context.contains("EXECUTION") ||
               context.contains("JAVASCRIPT") && !context.contains("COMMENT") ||
               context.contains("EVENT_HANDLER") ||
               context.contains("JSONP") ||
               context.contains("URL_EXECUTION") ||
               context.contains("CSS_EXECUTION") ||
               context.equals("JAVASCRIPT_EXECUTION") ||
               context.equals("EVENT_HANDLER_EXECUTION") ||
               context.equals("URL_JAVASCRIPT_EXECUTION");
    }
    
    /**
     * Send real HTTP request to confirm vulnerability
     * CRITICAL: This is what makes the extension actually find real vulnerabilities
     */
    private byte[] sendRealHttpRequest(IHttpService httpService, byte[] request) {
        try {
            IHttpRequestResponse rr = callbacks.makeHttpRequest(httpService, request);
            if (rr == null) return null;
            return rr.getResponse();
            
        } catch (Exception e) {
            if (settings != null && settings.getVerboseLogging()) {
                callbacks.printError("CheckReflection: Error sending HTTP request: " + e.getMessage());
            }
            return null;
        }
    }
    
    private String getContextAround(String text, int position, int windowSize) {
        int start = Math.max(0, position - windowSize);
        int end = Math.min(text.length(), position + windowSize);
        return text.substring(start, end);
    }
}
