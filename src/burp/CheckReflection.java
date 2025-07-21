package burp;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import static burp.Constants.*;

/**
 * Clean, professional reflection detection for XSSDetector
 * Removes excessive junk code and focuses on essential reflection analysis
 */
public class CheckReflection {

    private static final int MIN_PAYLOAD_LENGTH = 3;
    private final int bodyOffset;

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
        this.settings = settings;
        this.helpers = helpers;
        this.callbacks = callbacks;
        this.iHttpRequestResponse = null;
        this.bodyOffset = 0;
        
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
     * Perform passive scan for XSS vulnerabilities
     */
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse requestResponse) {
        List<IScanIssue> issues = new ArrayList<>();
        
        try {
            // Create temporary CheckReflection instance for this request
            CheckReflection tempReflection = new CheckReflection(settings, helpers, requestResponse, callbacks, performanceMonitor, errorRecoverySystem);
            List<Map> reflectedParameters = tempReflection.checkResponse();
            
            // Convert reflected parameters to scan issues
            for (Map parameter : reflectedParameters) {
                try {
                    // Create vulnerability data
                    Map<String, Object> vulnerabilityData = new HashMap<>();
                    vulnerabilityData.put("paramName", parameter.get(NAME));
                    vulnerabilityData.put("payload", parameter.get(VALUE));
                    vulnerabilityData.put("SCAN_TYPE", "Basic");
                    vulnerabilityData.put("CONFIRMED_XSS", parameter.get("CONFIRMED_XSS"));
                    vulnerabilityData.put("CONFIDENCE_SCORE", parameter.get("CONFIDENCE_SCORE"));
                    vulnerabilityData.put("XSS_SCORE", parameter.get("XSS_SCORE"));
                    vulnerabilityData.put("ENHANCED_CONTEXT", parameter.get("ENHANCED_CONTEXT"));
                    vulnerabilityData.put("MATCHES", parameter.get(MATCHES));
                    
                    // Create test request/response
                    String payload = (String) parameter.get(VALUE);
                    String paramName = (String) parameter.get(NAME);
                    byte[] testRequest = createTestRequest(requestResponse, paramName, payload);
                    byte[] testResponse = createTestResponse(requestResponse, payload);
                    
                    vulnerabilityData.put("TEST_REQUEST", new String(testRequest));
                    vulnerabilityData.put("TEST_RESPONSE", new String(testResponse));
                    
                    // Create scan issue
                    EnhancedIssueReporter issueReporter = new EnhancedIssueReporter(helpers, callbacks, settings);
                    IScanIssue issue = issueReporter.createEnhancedXSSIssue(requestResponse, vulnerabilityData);
                    if (issue != null) {
                        issues.add(issue);
                    }
                    
                } catch (Exception e) {
                    callbacks.printError("Error creating scan issue: " + e.getMessage());
                }
            }
            
        } catch (Exception e) {
            callbacks.printError("Error in passive scan: " + e.getMessage());
        }
        
        return issues;
    }
    
    /**
     * Create test request with payload
     */
    private byte[] createTestRequest(IHttpRequestResponse originalRequest, String paramName, String payload) {
        try {
            IRequestInfo requestInfo = helpers.analyzeRequest(originalRequest);
            List<IParameter> parameters = requestInfo.getParameters();
            
            byte[] modifiedRequest = originalRequest.getRequest();
            for (IParameter param : parameters) {
                if (param.getName().equals(paramName)) {
                    IParameter newParam = helpers.buildParameter(paramName, payload, param.getType());
                    modifiedRequest = helpers.updateParameter(modifiedRequest, newParam);
                    break;
                }
            }
            
            return modifiedRequest;
        } catch (Exception e) {
            return originalRequest.getRequest();
        }
    }
    
    /**
     * Create test response with highlighted payload
     */
    private byte[] createTestResponse(IHttpRequestResponse originalRequest, String payload) {
        try {
            byte[] originalResponse = originalRequest.getResponse();
            String responseBody = new String(originalResponse);
            
            // Highlight payload in response
            String highlightedResponse = responseBody.replace(payload, 
                "<mark style='background-color: yellow;'>" + payload + "</mark>");
            
            return highlightedResponse.getBytes();
        } catch (Exception e) {
            return originalRequest.getResponse();
        }
    }

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
        boolean isJSONResponse = responseContentType.toLowerCase().contains("application/json");
        boolean isModernAppResponse = isJSONResponse || responseContentType.toLowerCase().contains("application/graphql");
        
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
                // Enhanced reflection detection
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
                    
                    // Enhanced context analysis
                    try {
                            String enhancedContext = performEnhancedContextAnalysis(parameter, listOfMatches);
                            parameterDescription.put("ENHANCED_CONTEXT", enhancedContext != null ? enhancedContext : "Standard context");
                    } catch (Exception e) {
                        parameterDescription.put("ENHANCED_CONTEXT", "Analysis failed");
                    }
                    
                    // XSS vulnerability scoring
                    double xssScore = calculateXSSVulnerabilityScore(parameter, listOfMatches, responseContentType);
                    parameterDescription.put("XSS_SCORE", xssScore);
                    
                    // Apply filtering
                    if (filteringEngine != null) {
                        FilterResult filterResult = filteringEngine.analyzeReflection(parameterDescription, iHttpRequestResponse);
                        
                        if (filterResult.isFiltered() && filterResult.getConfidenceScore() < 50.0) {
                            continue;
                        }
                        
                        if (filterResult.getConfidenceScore() >= 85.0) {
                            parameterDescription.put("CONFIRMED_XSS", true);
                        }
                        
                        parameterDescription.put("CONFIDENCE_SCORE", filterResult.getConfidenceScore());
                        parameterDescription.put("CALCULATED_SEVERITY", filterResult.getSeverity());
                    } else {
                        // Default confidence for JSON responses
                        if (isJSONResponse) {
                            parameterDescription.put("CONFIDENCE_SCORE", 85.0);
                            parameterDescription.put("CALCULATED_SEVERITY", "High");
                            parameterDescription.put("CONFIRMED_XSS", true);
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
                    Double existingConfidence = (Double) modernParam.get("CONFIDENCE_SCORE");
                    if (existingConfidence != null) {
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
        if (!reflectedParameters.isEmpty() && (settings.getEnableTruePositiveOnly() || settings.getAggressiveMode())) {
                EnhancedAggressive enhancedScan = new EnhancedAggressive(settings, helpers, iHttpRequestResponse, callbacks, reflectedParameters);
                List<Map> enhancedResults = enhancedScan.scanReflectedParameters();
                
                if (enhancedResults != null && !enhancedResults.isEmpty()) {
                    reflectedParameters.addAll(enhancedResults);
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
    
    private boolean isVulnerableContentType(String contentType) {
        if (contentType == null) return false;
        
        String lowerContentType = contentType.toLowerCase();
        return lowerContentType.contains("text/html") ||
               lowerContentType.contains("application/xhtml+xml") ||
               lowerContentType.contains("text/xml") ||
               lowerContentType.contains("application/xml") ||
               lowerContentType.contains("image/svg+xml") ||
               lowerContentType.contains("text/javascript") ||
               lowerContentType.contains("application/javascript") ||
               lowerContentType.contains("application/json");
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
        
        // Content type bonus
        if (contentType != null) {
            if (contentType.toLowerCase().contains("application/json")) {
            score += 15.0;
            } else if (contentType.toLowerCase().contains("text/html")) {
                score += 10.0;
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
    
    private String getContextAround(String text, int position, int windowSize) {
        int start = Math.max(0, position - windowSize);
        int end = Math.min(text.length(), position + windowSize);
        return text.substring(start, end);
    }
}
