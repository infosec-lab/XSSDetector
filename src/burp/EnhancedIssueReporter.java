package burp;

import java.util.*;
import java.util.regex.Pattern;
import java.util.regex.Matcher;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.ArrayList;

/**
 * Professional Issue Reporter for XSSDetector
 * Provides Burp Suite integration with professional issue display
 */
public class EnhancedIssueReporter {
    
    private final IExtensionHelpers helpers;
    private final IBurpExtenderCallbacks callbacks;
    private final Settings settings;
    
    // Issue severity levels
    public enum SeverityLevel {
        CRITICAL("Critical", "High", "#dc2626"),
        HIGH("High", "High", "#ea580c"),
        MEDIUM("Medium", "Medium", "#d97706"),
        LOW("Low", "Low", "#65a30d"),
        INFO("Information", "Information", "#2563eb");
        
        private final String displayName;
        private final String burpSeverity;
        private final String colorCode;
        
        SeverityLevel(String displayName, String burpSeverity, String colorCode) {
            this.displayName = displayName;
            this.burpSeverity = burpSeverity;
            this.colorCode = colorCode;
        }
        
        public String getDisplayName() { return displayName; }
        public String getBurpSeverity() { return burpSeverity; }
        public String getColorCode() { return colorCode; }
    }
    
    // Issue confidence levels
    public enum ConfidenceLevel {
        CERTAIN("Certain", 100),
        FIRM("Firm", 80),
        TENTATIVE("Tentative", 60);
        
        private final String displayName;
        private final int score;
        
        ConfidenceLevel(String displayName, int score) {
            this.displayName = displayName;
            this.score = score;
        }
        
        public String getDisplayName() { return displayName; }
        public int getScore() { return score; }
    }
    
    public EnhancedIssueReporter(IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks, Settings settings) {
        this.helpers = helpers;
        this.callbacks = callbacks;
        this.settings = settings;
    }

    /**
     * SIMPLIFIED ISSUE CREATION - Fallback for confirmed XSS when enhanced method fails.
     * Accepts vulnerabilityData map for access to TEST_REQUEST/TEST_RESPONSE and markers.
     */
    public IScanIssue createXSSIssue(IHttpRequestResponse requestResponse,
                                     Map<String, Object> vulnerabilityData) {
        // DISABLED: this legacy reflected-XSS reporter produced false positives
        // with weak payloads (e.g. "value"+"alert(1)") and the old verbose
        // "Unfiltered Characters / Verification Summary" format. Reflected XSS is
        // now reported exclusively by ContextualReflectionEngine, which confirms a
        // real break-out with a working alert()/confirm()/prompt() payload.
        return null;
    }

    private IScanIssue createXSSIssueDisabled(IHttpRequestResponse requestResponse,
                                     Map<String, Object> vulnerabilityData) {
        try {
            if (requestResponse == null || vulnerabilityData == null) {
                return null;
            }

            // Extract fields from vulnerabilityData
            String paramName = (String) vulnerabilityData.get("paramName");
            if (paramName == null || paramName.isEmpty()) {
                paramName = "Unknown Parameter";
            }
            String payload = extractRealPayload(vulnerabilityData);
            if (payload == null || payload.isEmpty()) {
                callbacks.printOutput("[IssueReporter] Skipping: No payload provided");
                return null;
            }
            String reflectionContext = (String) vulnerabilityData.get("REFLECTION_CONTEXT");
            double confidenceScore = getDouble(vulnerabilityData, "CONFIDENCE_SCORE", 0.0);
            boolean confirmedXSS = Boolean.TRUE.equals(vulnerabilityData.get("CONFIRMED_XSS"));

            // Validate: require CONFIRMED_XSS=true OR confidence >= 50
            if (!confirmedXSS && confidenceScore < 50.0) {
                callbacks.printOutput("[IssueReporter] Skipping: Not confirmed and confidence too low (" + confidenceScore + "%)");
                return null;
            }

            // JSON responses are not directly exploitable -- require explicit confirmation
            Boolean isJsonResponse = (Boolean) vulnerabilityData.get("IS_JSON_RESPONSE");
            if (Boolean.TRUE.equals(isJsonResponse) && !confirmedXSS) {
                callbacks.printOutput("[IssueReporter] Skipping: JSON response without confirmed exploitation");
                return null;
            }

            // Validate: require payload to look like actual XSS
            if (!isActualXSSPayload(payload)) {
                callbacks.printOutput("[IssueReporter] Skipping: Payload is not an actual XSS payload");
                return null;
            }

            // Determine severity based on reflection and context
            SeverityLevel severity = SeverityLevel.MEDIUM;
            ConfidenceLevel confidence = ConfidenceLevel.TENTATIVE;

            if (confirmedXSS) {
                if (reflectionContext != null &&
                    (reflectionContext.contains("HTML") || reflectionContext.contains("Script") ||
                     reflectionContext.contains("Attribute") || reflectionContext.contains("Dangerous"))) {
                    severity = SeverityLevel.HIGH;
                    confidence = ConfidenceLevel.FIRM;
                }
                if (confidenceScore >= 80.0) {
                    confidence = ConfidenceLevel.CERTAIN;
                } else if (confidenceScore >= 60.0) {
                    confidence = ConfidenceLevel.FIRM;
                }
            }

            // Build issue name (include parameter so distinct params are distinct
            // issues and the dedup key can tell instances apart)
            String issueName = "Cross-site Scripting (Reflected)";
            if (reflectionContext != null && !reflectionContext.isEmpty()) {
                issueName += " - " + reflectionContext;
            }
            if (paramName != null && !paramName.trim().isEmpty()) {
                issueName += " - " + paramName;
            }

            // Build issue detail
            StringBuilder detail = new StringBuilder();
            detail.append("<p><b>XSS Vulnerability Detected</b></p>");
            detail.append("<p><b>Parameter:</b> ").append(escapeHtml(paramName)).append("</p>");
            detail.append("<p><b>Payload:</b> <code>").append(escapeHtml(truncatePayload(payload, 200))).append("</code></p>");
            if (reflectionContext != null) {
                detail.append("<p><b>Context:</b> ").append(escapeHtml(reflectionContext)).append("</p>");
            }
            detail.append("<p><b>Status:</b> ").append(confirmedXSS ? "CONFIRMED" : "Detected pattern").append("</p>");
            detail.append("<p><b>Confidence Score:</b> ").append(String.format("%.1f", confidenceScore)).append("%</p>");

            // Steps to Reproduce - ensure every report is actionable for pentesters
            detail.append("<h4>Steps to Reproduce</h4>");
            detail.append("<ol>");
            detail.append("<li>Send a request to the affected endpoint with the parameter <code>")
                  .append(escapeHtml(paramName)).append("</code>.</li>");
            detail.append("<li>Set the parameter value to the payload: <code>")
                  .append(escapeHtml(truncatePayload(payload, 200))).append("</code></li>");
            detail.append("<li>Inspect the response and confirm the payload is reflected unencoded")
                  .append(reflectionContext != null ? " in the " + escapeHtml(reflectionContext) + " context" : "")
                  .append(".</li>");
            detail.append("<li>Load the request in a browser and confirm the JavaScript executes ")
                  .append("(e.g. an <code>alert()</code> dialog appears or a network callback fires).</li>");
            detail.append("</ol>");

            // Build remediation
            String remediation = "<p>Implement proper output encoding based on context:</p>" +
                "<ul><li>HTML context: Use HTML entity encoding</li>" +
                "<li>JavaScript context: Use JavaScript encoding</li>" +
                "<li>URL context: Use URL encoding</li>" +
                "<li>CSS context: Use CSS encoding</li></ul>" +
                "<p>Consider implementing Content Security Policy (CSP) headers.</p>";

            // Build background
            String background = "<p>Cross-site scripting (XSS) vulnerabilities occur when user input is " +
                "included in web pages without proper encoding, allowing attackers to inject malicious scripts.</p>";

            // Get URL
            URL url = helpers.analyzeRequest(requestResponse).getUrl();

            // CRITICAL: Use createBurpHighlightedMessages() for proper marker creation
            IHttpRequestResponse[] httpMessages = createBurpHighlightedMessages(requestResponse, vulnerabilityData);

            callbacks.printOutput("[IssueReporter] Creating XSS issue for parameter: " + paramName +
                " (confidence: " + confidence.getDisplayName() + ", severity: " + severity.getDisplayName() + ")");

            return new EnhancedScanIssue(
                requestResponse.getHttpService(),
                url,
                httpMessages,
                issueName,
                detail.toString(),
                severity,
                confidence,
                remediation,
                background
            );

        } catch (Exception e) {
            callbacks.printError("[IssueReporter] Error creating XSS issue: " + e.getMessage());
            return null;
        }
    }

    /**
     * Validate if vulnerability is truly exploitable
     * CRITICAL: Only report if we have 100% proof with actual exploited request/response
     */
    private boolean isVulnerabilityTrulyExploitable(Map<String, Object> vulnerabilityData) {
        try {
            String payload = extractRealPayload(vulnerabilityData);
            if (payload == null || payload.trim().isEmpty()) {
                return false;
            }

            // Client-side / DOM issues often have no server-side injected payload present in the raw request.
            // For these, we validate using risk/evidence instead of "payload in request" proof.
            String scanType = (String) vulnerabilityData.get("SCAN_TYPE");
            String vulnType = (String) vulnerabilityData.get("vulnerabilityType");
            boolean clientSideIssue =
                (scanType != null && (scanType.toLowerCase().contains("dom") || scanType.toLowerCase().contains("client-side"))) ||
                (vulnType != null && (vulnType.toLowerCase().contains("dom") || vulnType.toLowerCase().contains("client-side")));

            if (!clientSideIssue) {
                // CRITICAL: For reflected/server-side XSS, payload must look like real XSS
                if (!isActualXSSPayload(payload)) {
                return false;
                }
            }
            
            // CRITICAL: Prefer test request/response for 100% proof, but allow reflection evidence
            Object testRequestObj = vulnerabilityData.get("TEST_REQUEST");
            Object testResponseObj = vulnerabilityData.get("TEST_RESPONSE");
            Object confirmedXSS = vulnerabilityData.get("CONFIRMED_XSS");
            Object symbolsReflected = vulnerabilityData.get("SYMBOLS_REFLECTED");
            
            // CRITICAL FIX: NEVER trust CONFIRMED_XSS flag without verifying payload reflection first
            // We MUST check if payload is actually reflected before trusting any flags
            // These early "trust" paths were causing false positives - REMOVED
            
            // CRITICAL FIX: For client-side issues, require STRONG evidence even if marked as "CONFIRMED"
            // Pattern matching (proximity of sources/sinks) is NOT sufficient proof
            // CRITICAL: CSP misconfiguration alone is NEVER exploitable XSS
            if (clientSideIssue) {
                // Check if this is ONLY CSP misconfiguration (not exploitable XSS)
                String paramName = (String) vulnerabilityData.get("paramName");
                boolean isOnlyCSPMisconfig = paramName != null && 
                                            (paramName.contains("CSP misconfiguration") || paramName.contains("CSP")) &&
                                            !paramName.contains("+ client-side vectors");
                
                // CRITICAL: Never report CSP misconfiguration alone as exploitable XSS
                if (isOnlyCSPMisconfig) {
                    callbacks.printOutput("[IssueReporter] FALSE POSITIVE FILTERED: CSP misconfiguration alone is NOT exploitable XSS - informational only");
                    return false;
                }
                
                if (Boolean.TRUE.equals(confirmedXSS)) {
                    // Check if we have actual test request/response with payload (from active scanning)
                    if (testRequestObj == null || testResponseObj == null) {
                        // No active scanning evidence - require very high risk score
                        // Single pattern match is not enough proof
                        Object xssScore = vulnerabilityData.get("XSS_SCORE");
                        double riskScore = xssScore instanceof Number ? ((Number) xssScore).doubleValue() : 0.0;
                        
                        // CRITICAL: Require VERY HIGH risk score (>= 85) for client-side without active scanning proof
                        // Pattern matching alone is NOT sufficient - require strong evidence
                        if (riskScore < 85.0) {
                            callbacks.printOutput("[IssueReporter] FALSE POSITIVE FILTERED: Client-side issue marked as CONFIRMED but risk score too low (" + riskScore + ") - requiring >= 85 for pattern-only detection");
                            return false;
                        }
                    }
                }
            }
            
            // If we have test request/response, validate them (only if CONFIRMED_XSS is not set or we don't have test data)
            if (testRequestObj != null && testResponseObj != null) {
                byte[] testRequest = null;
                byte[] testResponse = null;
                
                if (testRequestObj instanceof byte[]) {
                    testRequest = (byte[]) testRequestObj;
                } else if (testRequestObj instanceof String) {
                    testRequest = ((String) testRequestObj).getBytes(StandardCharsets.UTF_8);
                }
                
                if (testResponseObj instanceof byte[]) {
                    testResponse = (byte[]) testResponseObj;
                } else if (testResponseObj instanceof String) {
                    testResponse = ((String) testResponseObj).getBytes(StandardCharsets.UTF_8);
                }
                
                if (testRequest != null && testRequest.length > 0 && 
                    testResponse != null && testResponse.length > 0) {
                    if (!clientSideIssue) {
                        // Server-side XSS proof requires payload actually present in request
                        // CRITICAL: Check for both original and encoded payloads
                        String requestStr = new String(testRequest, StandardCharsets.UTF_8);
                        boolean payloadInRequest = requestStr.contains(payload);
                        
                        // If original payload not found, check for encoded versions
                        if (!payloadInRequest) {
                            // Check for URL-encoded payload
                            String urlEncoded = helpers.urlEncode(payload);
                            if (requestStr.contains(urlEncoded)) {
                                payloadInRequest = true;
                            } else {
                                // Check for HTML entity encoded
                                String htmlEncoded = payload.replace("<", "&lt;").replace(">", "&gt;")
                                                           .replace("\"", "&quot;").replace("'", "&#39;");
                                if (requestStr.contains(htmlEncoded)) {
                                    payloadInRequest = true;
                                } else {
                                    // Check for JSON-escaped
                                    String jsonEscaped = payload.replace("\\", "\\\\").replace("\"", "\\\"");
                                    if (requestStr.contains(jsonEscaped)) {
                                        payloadInRequest = true;
                                    }
                                }
                            }
                        }
                        
                        // Also check ENCODED_PAYLOAD from vulnerability data
                        if (!payloadInRequest) {
                            String encodedPayload = extractInjectedPayload(vulnerabilityData);
                            if (encodedPayload != null && !encodedPayload.equals(payload) && requestStr.contains(encodedPayload)) {
                                payloadInRequest = true;
                            }
                        }
                        
                        // Also check for double-encoded versions
                        if (!payloadInRequest) {
                            try {
                                String doubleEncoded = helpers.urlEncode(helpers.urlEncode(payload));
                                if (requestStr.contains(doubleEncoded)) {
                                    payloadInRequest = true;
                                }
                            } catch (Exception ignored) {}
                        }
                        
                        // CRITICAL FIX: ALWAYS require payload in request - no exceptions
                        // Even if CONFIRMED_XSS is set, we must verify payload is actually in the request
                        if (!payloadInRequest) {
                            callbacks.printOutput("[IssueReporter] FALSE POSITIVE FILTERED: Payload not found in request (checked original, URL-encoded, HTML-encoded, JSON-escaped, and double-encoded versions)");
                            return false;
                        }
                    } else {
                        // Client-side issues: accept real request/response as evidence even if payload isn't injected.
                        // We validate using risk signals / evidence terms in the response.
                        double score = 0.0;
                        Object s1 = vulnerabilityData.get("XSS_SCORE");
                        if (s1 instanceof Number) score = Math.max(score, ((Number) s1).doubleValue());
                        Object s2 = vulnerabilityData.get("CONFIDENCE_SCORE");
                        if (s2 instanceof Number) score = Math.max(score, ((Number) s2).doubleValue());

                        boolean hasEvidence = false;
                        Object ht = vulnerabilityData.get("HIGHLIGHT_TERMS");
                        if (ht instanceof List) {
                            try {
                                @SuppressWarnings("unchecked")
                                List<String> terms = (List<String>) ht;
                                if (terms != null && !terms.isEmpty()) {
                                    String responseStr = new String(testResponse, StandardCharsets.UTF_8);
                                    String lower = responseStr.toLowerCase();
                                    for (String t : terms) {
                                        if (t == null || t.isEmpty()) continue;
                                        if (lower.contains(t.toLowerCase())) {
                                            hasEvidence = true;
                                            break;
                                        }
                                    }
                                }
                            } catch (Exception ignored) {}
                        }

                        // CRITICAL: Require HIGH score (>= 70) for client-side issues - evidence terms alone are not enough
                        // Evidence terms can be false positives - require actual high risk score
                        if (score >= 70.0 && (Boolean.TRUE.equals(vulnerabilityData.get("CONFIRMED_XSS")) || hasEvidence)) {
                            return true;
                        }
                        // Score too low or no evidence - reject
                        callbacks.printOutput("[IssueReporter] FALSE POSITIVE FILTERED: Client-side issue score too low (" + score + ") - requiring >= 70");
                return false;
            }
            
                    // Validate payload is reflected in response (be more flexible)
                    String responseStr = new String(testResponse, StandardCharsets.UTF_8);
                    
                    // CRITICAL FIX: Check for WAF blocks and error responses
                    IResponseInfo responseInfo = helpers.analyzeResponse(testResponse);
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
                    
                    // CRITICAL FIX: Check BOTH original payload AND encoded payload
                    // payload = original (e.g., <script>)
                    // encodedPayload = what was actually injected (e.g., %3Cscript%3E)
                    String encodedPayload = extractInjectedPayload(vulnerabilityData);
                    
                    // Check 1: Original payload reflection
                    boolean payloadReflected = validatePayloadReflection(payload, responseStr);
                    
                    // CRITICAL FIX: For WAF blocks, require STRICT payload reflection
                    if ((isWAFBlock || hasWAFIndicators) && !payloadReflected) {
                        callbacks.printOutput("[IssueReporter] FALSE POSITIVE FILTERED: WAF block detected (status " + statusCode + ") and payload NOT reflected");
                        return false;
                    }
                    
                    // CRITICAL FIX: For error responses, require payload reflection
                    if (isErrorResponse && !payloadReflected) {
                        callbacks.printOutput("[IssueReporter] FALSE POSITIVE FILTERED: Error response (status " + statusCode + ") and payload NOT reflected");
                        return false;
                    }
                    
                    // Check 2: Encoded payload reflection (if different from original)
                    if (!payloadReflected && encodedPayload != null && !encodedPayload.equals(payload)) {
                        // We injected an encoded version - check if it's reflected as-is
                        if (responseStr.contains(encodedPayload)) {
                            payloadReflected = true;
                            callbacks.printOutput("[IssueReporter] Encoded payload reflection detected: " + 
                                                 encodedPayload.substring(0, Math.min(30, encodedPayload.length())));
                        } else {
                            // Check if decoded version is reflected (app decoded it)
                            try {
                                String decoded = helpers.urlDecode(encodedPayload);
                                if (decoded != null && !decoded.equals(encodedPayload) && responseStr.contains(decoded)) {
                                    payloadReflected = true;
                                    callbacks.printOutput("[IssueReporter] Decoded payload reflection detected: injected " + 
                                                         encodedPayload.substring(0, Math.min(30, encodedPayload.length())) + 
                                                         ", found " + decoded.substring(0, Math.min(30, decoded.length())));
                                }
                            } catch (Exception ignored) {}
                        }
                    }
                    
                    // Check 3: Also use validatePayloadReflection on encoded payload if available
                    if (!payloadReflected && encodedPayload != null && !encodedPayload.equals(payload)) {
                        payloadReflected = validatePayloadReflection(encodedPayload, responseStr);
                    }
                    
                    // CRITICAL FIX: Require actual payload reflection - don't trust CONFIRMED_XSS if payload is clearly not reflected
                    // This prevents false positives where payload is in request but not in response
                    if (!payloadReflected) {
                        // CRITICAL: For cookie parameters, ALWAYS require payload reflection (cookies rarely reflect)
                        String paramName = (String) vulnerabilityData.get("paramName");
                        boolean isCookieParam = paramName != null && paramName.toLowerCase().contains("cookie");
                        
                        // Also check if it's a cookie parameter from the scan type or context
                        // Note: scanType already declared at method start
                        Object paramType = vulnerabilityData.get("TYPE");
                        if (paramType != null) {
                            try {
                                int typeInt = paramType instanceof Integer ? ((Integer) paramType).intValue() : 
                                             paramType instanceof Byte ? ((Byte) paramType).byteValue() : -1;
                                if (typeInt == IParameter.PARAM_COOKIE) {
                                    isCookieParam = true;
                                }
                            } catch (Exception ignored) {}
                        }
                        
                        if (isCookieParam) {
                            // Cookie parameters MUST have payload reflection - no exceptions
                            callbacks.printOutput("[IssueReporter] FALSE POSITIVE FILTERED: Cookie parameter '" + paramName + "' - payload NOT reflected in response");
                            return false;
                        }
                        
                        if (!Boolean.TRUE.equals(confirmedXSS)) {
                            // CONFIRMED_XSS not set - require actual proof
                            callbacks.printOutput("[IssueReporter] Payload not reflected in response (checked original, encoded, and decoded versions)");
                            return false;
                        } else {
                            // CONFIRMED_XSS is set but payload not reflected - verify it's not a false positive
                            // CRITICAL FIX: For WAF blocks or error responses, NEVER trust CONFIRMED_XSS if payload not reflected
                            if (isWAFBlock || hasWAFIndicators || isErrorResponse) {
                                callbacks.printOutput("[IssueReporter] FALSE POSITIVE FILTERED: WAF block/error response and payload NOT reflected - ignoring CONFIRMED_XSS flag");
                                return false;
                            }
                            
                            // CRITICAL FIX: For cookie parameters, NEVER allow symbol-based evidence
                            // Cookies almost never reflect, so symbol reflection is not sufficient proof
                            if (isCookieParam) {
                                callbacks.printOutput("[IssueReporter] FALSE POSITIVE FILTERED: Cookie parameter '" + paramName + "' - payload not reflected (symbols reflection not sufficient for cookies)");
                                return false;
                            }
                            
                            // CRITICAL FIX: NEVER accept symbols-only reflection as proof - require actual payload reflection
                            // Symbols reflection alone is NOT sufficient proof of XSS vulnerability
                            // Even multiple dangerous symbols can be false positives (e.g., user input in safe contexts)
                            callbacks.printOutput("[IssueReporter] FALSE POSITIVE FILTERED: CONFIRMED_XSS flag set but payload NOT reflected in response - symbols reflection is not sufficient proof");
                            return false;
                        }
                    }
                    
                    if (payloadReflected) {
                        // We have valid test request/response with payload reflection - this is proof
            return true;
                    }
                }
            }
            
            // CRITICAL: For passive scans or when test request/response not available
            // If we reach here, it means we don't have test request/response with verified reflection
            // CRITICAL FIX: NEVER report without verified payload reflection in test response
            // All fallback paths that allowed reporting without verified reflection have been removed
            
            String paramNameCheck = (String) vulnerabilityData.get("paramName");
            callbacks.printOutput("[IssueReporter] FALSE POSITIVE FILTERED: No test request/response with verified payload reflection for parameter: " + paramNameCheck);
            callbacks.printOutput("[IssueReporter] CRITICAL: Cannot confirm XSS without actual payload reflection in test response");
            return false;
            
        } catch (Exception e) {
            callbacks.printError("Error validating vulnerability: " + e.getMessage());
            if (settings != null && settings.getVerboseLogging()) {
                callbacks.printError("Stack trace: " + java.util.Arrays.toString(e.getStackTrace()));
            }
            return false;
        }
    }
    
    /**
     * Check if payload is actually an XSS payload (not just a parameter value)
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
                                     "id", "name", "value", "type", "class", "style", "href", "src"};
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
    
    /**
     * Validate payload reflection - IMPROVED with safe context checking
     */
    private boolean validatePayloadReflection(String payload, String response) {
        if (payload == null || response == null || payload.isEmpty()) {
            return false;
        }

        // Check 1: Direct payload reflection (best case)
        if (response.contains(payload)) {
            // CRITICAL FIX: Check if payload is in a SAFE context (not exploitable)
            int payloadPos = response.indexOf(payload);
            if (isPayloadInSafeContext(response, payload, payloadPos)) {
                callbacks.printOutput("[validatePayloadReflection] Payload found but in SAFE context - NOT exploitable");
                return false; // Safe context - not exploitable
            }
            return true;
        }
        
        // Check 2: URL-encoded payload reflection (if we injected URL-encoded)
        String urlEncoded = helpers.urlEncode(payload);
        if (response.contains(urlEncoded)) {
            return true;
        }
        
        // Check 3: URL-decoded reflection (if we injected encoded, server decoded it)
        try {
            String urlDecoded = helpers.urlDecode(urlEncoded);
            if (urlDecoded != null && !urlDecoded.equals(urlEncoded) && response.contains(urlDecoded)) {
                return true;
            }
        } catch (Exception ignored) {}
        
        // Check 4: Double URL-encoded (some apps double-encode)
        try {
            String doubleUrlEncoded = helpers.urlEncode(urlEncoded);
            if (response.contains(doubleUrlEncoded)) {
                return true;
            }
        } catch (Exception ignored) {}
        
        // Check 5: Context-aware HTML-encoded reflection
        // HTML-encoded CAN be exploitable in JavaScript execution contexts
        // Check if payload is in a JavaScript context (script tag, event handler, etc.)
        String htmlEncoded = payload.replace("<", "&lt;").replace(">", "&gt;")
                                   .replace("\"", "&quot;").replace("'", "&#39;");
        if (response.contains(htmlEncoded)) {
            // Check if it's in a JavaScript execution context where HTML entities are decoded
            String lowerResponse = response.toLowerCase();
            int htmlEncodedPos = response.indexOf(htmlEncoded);
            if (htmlEncodedPos >= 0) {
                // Check context around the reflection
                int contextStart = Math.max(0, htmlEncodedPos - 200);
                int contextEnd = Math.min(response.length(), htmlEncodedPos + htmlEncoded.length() + 200);
                String context = response.substring(contextStart, contextEnd).toLowerCase();
                
                // If in JavaScript context, HTML entities might be decoded by browser
                if (context.contains("<script") || context.contains("javascript:") || 
                    context.contains("onerror") || context.contains("onload") ||
                    context.contains("onclick") || context.contains("eval(") ||
                    context.contains("function(") || context.contains("settimeout") ||
                    context.contains("setinterval")) {
                    return true; // HTML-encoded in JS context can be exploitable
                }
            }
        }
        
        // Check 6: JSON-escaped reflection (for JSON contexts)
        String jsonEscaped = payload.replace("\\", "\\\\").replace("\"", "\\\"");
        if (response.contains(jsonEscaped)) {
            return true;
        }
        
        // Check 7: Unicode-escaped reflection
        String unicodeEscaped = payload.replace("<", "\\u003c").replace(">", "\\u003e");
        if (response.contains(unicodeEscaped)) {
            return true;
        }
        
        // CRITICAL: Do NOT use partial reflection - this causes false positives
        // Partial matches are NOT sufficient proof of vulnerability

        return false; // Payload not reflected - not exploitable
    }

    /**
     * Check if payload is in a safe (non-executable) context
     * CRITICAL: Prevents false positives from comments, CDATA, encoded contexts
     */
    private boolean isPayloadInSafeContext(String response, String payload, int position) {
        if (response == null || payload == null || position < 0) return false;

        // Get context window around payload
        int windowStart = Math.max(0, position - 300);
        int windowEnd = Math.min(response.length(), position + payload.length() + 300);
        String contextBefore = response.substring(windowStart, position);
        String contextAfter = response.substring(position + payload.length(), windowEnd);

        // === CHECK 1: HTML COMMENT ===
        int lastCommentStart = contextBefore.lastIndexOf("<!--");
        int lastCommentEnd = contextBefore.lastIndexOf("-->");
        if (lastCommentStart > lastCommentEnd && contextAfter.contains("-->")) {
            return true; // In HTML comment - SAFE
        }

        // === CHECK 2: CDATA SECTION ===
        int lastCDATA = contextBefore.lastIndexOf("<![CDATA[");
        int lastCDATAEnd = contextBefore.lastIndexOf("]]>");
        if (lastCDATA > lastCDATAEnd && contextAfter.contains("]]>")) {
            return true; // In CDATA - SAFE
        }

        // === CHECK 3: JavaScript single-line comment ===
        int lastNewline = contextBefore.lastIndexOf("\n");
        String sameLine = (lastNewline >= 0) ? contextBefore.substring(lastNewline) : contextBefore;
        if (sameLine.contains("//") && !sameLine.contains("://")) {
            // Check if // is not inside a string
            int slashPos = sameLine.lastIndexOf("//");
            String beforeSlash = sameLine.substring(0, slashPos);
            int singleQuotes = countChar(beforeSlash, '\'');
            int doubleQuotes = countChar(beforeSlash, '"');
            if (singleQuotes % 2 == 0 && doubleQuotes % 2 == 0) {
                return true; // In JS comment - SAFE
            }
        }

        // === CHECK 4: JavaScript block comment ===
        int lastBlockStart = contextBefore.lastIndexOf("/*");
        int lastBlockEnd = contextBefore.lastIndexOf("*/");
        if (lastBlockStart > lastBlockEnd && contextAfter.contains("*/")) {
            return true; // In JS block comment - SAFE
        }

        // === CHECK 5: Text context elements ===
        String[] textTags = {"textarea", "xmp", "plaintext", "listing"};
        for (String tag : textTags) {
            int tagOpen = contextBefore.toLowerCase().lastIndexOf("<" + tag);
            int tagClose = contextBefore.toLowerCase().lastIndexOf("</" + tag);
            if (tagOpen > tagClose) {
                return true; // In text context - SAFE
            }
        }

        // === CHECK 6: HTML-encoded (check if raw payload exists elsewhere) ===
        // If only encoded version exists and no raw, it's safe
        String htmlEncoded = payload.replace("<", "&lt;").replace(">", "&gt;");
        if (!response.contains(payload) && response.contains(htmlEncoded)) {
            return true; // Only encoded version exists - SAFE
        }

        return false; // Not in safe context
    }

    /**
     * Helper: Count character occurrences
     */
    private int countChar(String str, char ch) {
        int count = 0;
        for (int i = 0; i < str.length(); i++) {
            if (str.charAt(i) == ch) count++;
        }
        return count;
    }

    /**
     * Create enhanced XSS issue with professional reporting
     * FINAL VALIDATION LAYER: Comprehensive checks before issue creation
     */
    public IScanIssue createEnhancedXSSIssue(IHttpRequestResponse requestResponse, 
                                            Map<String, Object> vulnerabilityData) {
        try {
            // FINAL VALIDATION STEP 1: Check if vulnerability is truly exploitable
            if (!isVulnerabilityTrulyExploitable(vulnerabilityData)) {
                callbacks.printOutput("[IssueReporter] FINAL VALIDATION FAILED: Vulnerability not truly exploitable");
                return null;
            }
            
            String payload = extractRealPayload(vulnerabilityData);
            if (payload == null || payload.trim().isEmpty()) {
                callbacks.printOutput("[IssueReporter] FINAL VALIDATION FAILED: Payload is null or empty");
                return null;
            }
            
            // FINAL VALIDATION STEP 2: Check confidence score
            Object confidenceObj = vulnerabilityData.get("CONFIDENCE_SCORE");
            if (confidenceObj instanceof Number) {
                double confidence = ((Number) confidenceObj).doubleValue();
                if (confidence <= 0.0) {
                    callbacks.printOutput("[IssueReporter] FINAL VALIDATION FAILED: Confidence score is 0 (false positive)");
                    return null;
                }
            }
            
            // FINAL VALIDATION STEP 3: Check for false positive indicators in vulnerability type
            Object vulnTypeObj = vulnerabilityData.get("vulnerabilityType");
            if (vulnTypeObj instanceof String) {
                String vulnType = (String) vulnTypeObj;
                if (vulnType != null && (vulnType.contains("False Positive") || 
                    vulnType.contains("Safely Escaped") || vulnType.contains("Not Exploitable"))) {
                    callbacks.printOutput("[IssueReporter] FINAL VALIDATION FAILED: Vulnerability type indicates false positive: " + vulnType);
                    return null;
                }
            }
            
            // FINAL VALIDATION STEP 4: Context-aware validation
            Object reflectionContextObj = vulnerabilityData.get("REFLECTION_CONTEXT");
            Object contentTypeObj = vulnerabilityData.get("CONTENT_TYPE");
            String reflectionContext = reflectionContextObj != null ? reflectionContextObj.toString() : null;
            String contentType = contentTypeObj != null ? contentTypeObj.toString() : null;
            
            // Check if payload is in a non-exploitable context
            if (reflectionContext != null) {
                if (reflectionContext.contains("Comment") || reflectionContext.contains("COMMENT")) {
                    callbacks.printOutput("[IssueReporter] FINAL VALIDATION FAILED: Payload in HTML comment (not exploitable)");
                    return null;
                }
                if (reflectionContext.contains("Safely Escaped") || reflectionContext.contains("False Positive")) {
                    callbacks.printOutput("[IssueReporter] FINAL VALIDATION FAILED: Reflection context indicates false positive");
                    return null;
                }
            }
            
            // FINAL VALIDATION STEP 5: Verify payload is actual XSS payload (for non-client-side issues)
            String scanType = (String) vulnerabilityData.get("SCAN_TYPE");
            boolean clientSideIssue = scanType != null && 
                (scanType.toLowerCase().contains("dom") || scanType.toLowerCase().contains("client-side"));
            
            if (!clientSideIssue && !isActualXSSPayload(payload)) {
                callbacks.printOutput("[IssueReporter] FINAL VALIDATION FAILED: Payload is not an actual XSS payload");
                return null;
            }
            
            // FINAL VALIDATION STEP 6: CRITICAL - Check if payload is actually reflected (for client-side issues too)
            // Even client-side issues need SOME evidence of actual vulnerability, not just pattern matching
            Object testRequestObj = vulnerabilityData.get("TEST_REQUEST");
            Object testResponseObj = vulnerabilityData.get("TEST_RESPONSE");
            
            // CRITICAL FIX: For client-side issues, if we have test request/response, check reflection
            // But if we don't have test data, allow high scores (>= 90) to pass validation
            if (clientSideIssue) {
                if (testRequestObj != null && testResponseObj != null) {
                    // We have test data - check reflection
                    byte[] testRequest = testRequestObj instanceof byte[] ? (byte[]) testRequestObj : 
                                        testRequestObj instanceof String ? ((String) testRequestObj).getBytes(StandardCharsets.UTF_8) : null;
                    byte[] testResponse = testResponseObj instanceof byte[] ? (byte[]) testResponseObj : 
                                         testResponseObj instanceof String ? ((String) testResponseObj).getBytes(StandardCharsets.UTF_8) : null;
                    
                    if (testRequest != null && testResponse != null) {
                        String responseStr = new String(testResponse, StandardCharsets.UTF_8);
                        boolean payloadReflected = validatePayloadReflection(payload, responseStr);
                        
                        // CRITICAL: For client-side issues, if we have test request/response, payload MUST be reflected
                        // Pattern matching alone is NOT sufficient - require actual reflection
                        if (!payloadReflected) {
                            // Check if we have high-risk vectors that justify reporting without reflection
                            double riskScore = getDouble(vulnerabilityData, "XSS_SCORE", 0.0);
                            double confidenceScore = getDouble(vulnerabilityData, "CONFIDENCE_SCORE", 0.0);
                            Boolean confirmed = (Boolean) vulnerabilityData.get("CONFIRMED_XSS");

                            // For confirmed findings with test data, use lower threshold (>= 80)
                            // Otherwise require >= 90 for pattern-only detection
                            double threshold = (Boolean.TRUE.equals(confirmed) && testRequestObj != null && testResponseObj != null) ? 80.0 : 90.0;
                            if (riskScore < threshold || confidenceScore < threshold) {
                                callbacks.printOutput("[IssueReporter] FINAL VALIDATION FAILED: Client-side issue - payload NOT reflected and risk/confidence scores too low (risk: " + riskScore + ", confidence: " + confidenceScore + ") - requiring >= " + threshold + " for detection");
                                return null;
                            }
                        }
                    }
                } else {
                    // No test data for client-side issue - require very high scores (>= 90) to pass
                    double riskScore = getDouble(vulnerabilityData, "XSS_SCORE", 0.0);
                    double confidenceScore = getDouble(vulnerabilityData, "CONFIDENCE_SCORE", 0.0);
                    Boolean confirmed = (Boolean) vulnerabilityData.get("CONFIRMED_XSS");
                    
                    // CRITICAL: Without test data, require VERY HIGH scores AND CONFIRMED_XSS flag
                    if (!Boolean.TRUE.equals(confirmed) || riskScore < 90.0 || confidenceScore < 90.0) {
                        callbacks.printOutput("[IssueReporter] FINAL VALIDATION FAILED: Client-side issue - no test data and insufficient scores (risk: " + riskScore + ", confidence: " + confidenceScore + ", confirmed: " + confirmed + ")");
                        return null;
                    }
                }
            }
            
            // FINAL VALIDATION STEP 7: CRITICAL - Check for "CSP misconfiguration + client-side vectors" false positives
            // Even if it says "+ client-side vectors", if there's no actual exploitable evidence, reject it
            String paramName = (String) vulnerabilityData.get("paramName");
            if (paramName != null && paramName.contains("CSP misconfiguration")) {
                // Check if we have actual exploitable vectors (not just CSP + some patterns)
                Object testReq = vulnerabilityData.get("TEST_REQUEST");
                Object testResp = vulnerabilityData.get("TEST_RESPONSE");
                double riskScore = getDouble(vulnerabilityData, "XSS_SCORE", 0.0);
                double confScore = getDouble(vulnerabilityData, "CONFIDENCE_SCORE", 0.0);
                
                // CRITICAL: "CSP misconfiguration + client-side vectors" requires:
                // 1. Actual test request/response with payload reflection, OR
                // 2. Very high risk score (>= 90) with multiple taint flows
                boolean hasTestData = testReq != null && testResp != null;
                boolean hasVeryHighScore = riskScore >= 90.0 && confScore >= 90.0;
                
                if (!hasTestData && !hasVeryHighScore) {
                    callbacks.printOutput("[IssueReporter] FINAL VALIDATION FAILED: CSP misconfiguration + client-side vectors - no actual exploitable evidence (risk: " + riskScore + ", confidence: " + confScore + ")");
                    return null;
                }
            }
            
            // FINAL VALIDATION PASSED - Proceed with issue creation
            callbacks.printOutput("[IssueReporter] FINAL VALIDATION PASSED: All checks confirmed - creating issue");
            
            // Get analysis results
            ModernArchitectureDetector.ArchitectureAnalysis archAnalysis = 
                (ModernArchitectureDetector.ArchitectureAnalysis) vulnerabilityData.get("archAnalysis");
            AdvancedJSONAnalyzer.JSONAnalysisResult jsonAnalysis = 
                (AdvancedJSONAnalyzer.JSONAnalysisResult) vulnerabilityData.get("jsonAnalysis");
            
            // Calculate severity and confidence
            SeverityLevel severity = calculateSeverity(vulnerabilityData, archAnalysis, jsonAnalysis);
            ConfidenceLevel confidence = calculateConfidence(vulnerabilityData, null);
            
            // Generate issue details
            String issueName = generateIssueName(vulnerabilityData, archAnalysis, jsonAnalysis, requestResponse);
            String advisoryDetail = generateBurpSafeIssueDetail(requestResponse, vulnerabilityData,
                                                           archAnalysis, jsonAnalysis, severity, confidence);
            
            // CRITICAL: If advisoryDetail is null, it means validation failed - don't create issue
            if (advisoryDetail == null) {
                callbacks.printOutput("[IssueReporter] Issue detail generation blocked - false positive detected");
                return null;
            }
            
            // Create HTTP messages with exploited request/response
            IHttpRequestResponse[] httpMessages = createBurpHighlightedMessages(requestResponse, vulnerabilityData);
            
            // Generate issue background with vulnerable parameter details
            String issueBackground = generateBurpSafeIssueBackground(vulnerabilityData, archAnalysis, jsonAnalysis, requestResponse);
            
            // Generate remediation detail (cleaner, less verbose)
            String remediationDetail = generateBurpSafeRemediationDetail(archAnalysis, jsonAnalysis);
            
            // Create the issue
            return new EnhancedScanIssue(
                requestResponse.getHttpService(),
                helpers.analyzeRequest(requestResponse).getUrl(),
                httpMessages,
                issueName,
                advisoryDetail,
                severity,
                confidence,
                remediationDetail,
                issueBackground
            );
            
        } catch (Exception e) {
            callbacks.printError("Error creating enhanced XSS issue: " + e.getMessage());
                return null;
        }
    }
    
    private SeverityLevel calculateSeverity(Map<String, Object> vulnerabilityData, 
                                          ModernArchitectureDetector.ArchitectureAnalysis archAnalysis,
                                          AdvancedJSONAnalyzer.JSONAnalysisResult jsonAnalysis) {
        double severityScore = 50.0;
        
        // Base score from vulnerability data
        severityScore = getDouble(vulnerabilityData, "XSS_SCORE", severityScore);
        
        // Boost for confirmed XSS
        Boolean confirmed = (Boolean) vulnerabilityData.get("CONFIRMED_XSS");
        if (confirmed != null && confirmed) {
            severityScore += 20.0;
        }
        
        // Boost for JSON responses
        Boolean isJsonResponse = (Boolean) vulnerabilityData.get("IS_JSON_RESPONSE");
        if (isJsonResponse != null && isJsonResponse) {
            severityScore += 10.0;
        }
        
        // Architecture analysis boost
        if (archAnalysis != null && archAnalysis.getRiskLevel().equals("HIGH")) {
            severityScore += 15.0;
        }
        
        // JSON analysis boost
        if (jsonAnalysis != null && jsonAnalysis.getJsonType() == AdvancedJSONAnalyzer.JSONType.JSONP) {
            severityScore += 10.0;
        }
        
        if (severityScore >= 85) return SeverityLevel.CRITICAL;
        if (severityScore >= 70) return SeverityLevel.HIGH;
        if (severityScore >= 50) return SeverityLevel.MEDIUM;
        return SeverityLevel.LOW;
    }
    
    private ConfidenceLevel calculateConfidence(Map<String, Object> vulnerabilityData, List<int[]> matches) {
        double confidenceScore = 60.0;
        
        // Base confidence from vulnerability data
        confidenceScore = getDouble(vulnerabilityData, "CONFIDENCE_SCORE", confidenceScore);
        
        // Boost for confirmed XSS
        Boolean confirmed = (Boolean) vulnerabilityData.get("CONFIRMED_XSS");
        if (confirmed != null && confirmed) {
            confidenceScore = 100.0;
        }
        
        // CRITICAL: Boost for source-sink correlation (client-side/DOM XSS evidence)
        Object sourceSinkAnalysis = vulnerabilityData.get("SOURCE_SINK_ANALYSIS");
        if (sourceSinkAnalysis != null && sourceSinkAnalysis.toString().trim().length() > 0) {
            // Source-sink correlation is strong evidence for client-side XSS
            confidenceScore = Math.min(100.0, confidenceScore + 15.0);
        }
        
        // Boost for JSON responses
        Boolean isJsonResponse = (Boolean) vulnerabilityData.get("IS_JSON_RESPONSE");
        if (isJsonResponse != null && isJsonResponse) {
            confidenceScore = Math.min(100.0, confidenceScore + 15.0);
        }
        
        if (confidenceScore >= 90) return ConfidenceLevel.CERTAIN;
        if (confidenceScore >= 70) return ConfidenceLevel.FIRM;
        return ConfidenceLevel.TENTATIVE;
    }
    
    /**
     * CRITICAL FIX: Extract payload from vulnerability data - check all possible keys
     */
    private String extractRealPayload(Map<String, Object> vulnerabilityData) {
        String injected = extractInjectedPayload(vulnerabilityData);
        if (injected != null) return injected;
        return extractOriginalPayload(vulnerabilityData);
    }

    private double getDouble(Map<String, Object> data, String key, double defaultValue) {
        if (data == null || key == null) return defaultValue;
        Object v = data.get(key);
        if (v == null) return defaultValue;
        if (v instanceof Number) return ((Number) v).doubleValue();
        if (v instanceof String) {
            try { return Double.parseDouble(((String) v).trim()); } catch (Exception ignored) { return defaultValue; }
        }
        return defaultValue;
    }

    /**
     * Payload that was actually injected into the request (encoded/context-aware if available).
     */
    private String extractInjectedPayload(Map<String, Object> vulnerabilityData) {
        if (vulnerabilityData == null) return null;
        String[] keys = new String[] { "ENCODED_PAYLOAD", "INJECTED_PAYLOAD", "payload", "PAYLOAD" };
        for (String k : keys) {
            Object v = vulnerabilityData.get(k);
            if (v instanceof String) {
                String s = ((String) v).trim();
                if (!s.isEmpty()) return s;
            }
        }
        return null;
    }

    /**
     * Original (pre-encoding) payload if present.
     */
    private String extractOriginalPayload(Map<String, Object> vulnerabilityData) {
        if (vulnerabilityData == null) return null;
        String[] keys = new String[] { "ORIGINAL_PAYLOAD", "ORIGINAL", "RAW_PAYLOAD" };
        for (String k : keys) {
            Object v = vulnerabilityData.get(k);
            if (v instanceof String) {
                String s = ((String) v).trim();
                if (!s.isEmpty()) return s;
            }
        }
        return null;
    }
    
    private String generateIssueName(Map<String, Object> vulnerabilityData,
                                   ModernArchitectureDetector.ArchitectureAnalysis archAnalysis,
                                   AdvancedJSONAnalyzer.JSONAnalysisResult jsonAnalysis,
                                   IHttpRequestResponse requestResponse) {
        // Extract clean parameter name (remove descriptive text for DOM/client-side issues)
        String paramName = (String) vulnerabilityData.get("paramName");
        String cleanParamName = extractCleanParameterName(paramName);
        
        // Determine vulnerability type
        String scanType = (String) vulnerabilityData.get("SCAN_TYPE");
        String vulnType = (String) vulnerabilityData.get("vulnerabilityType");
        
        // Unified, contextual naming: "Cross-Site Scripting (<Class>)".
        // The class alone goes in the name; the parameter/context live in the
        // detail (consistent with the contextual engine and the de-dup key).
        String type = (vulnType != null ? vulnType : "") + " " + (scanType != null ? scanType : "");
        String cls;
        if (type.toLowerCase().contains("dom")) {
            cls = "DOM-based";
        } else if (type.toLowerCase().contains("client-side")) {
            cls = "Client-side";
        } else if (type.toLowerCase().contains("stored")) {
            cls = "Stored";
        } else {
            cls = "Reflected";
        }
        // cleanParamName is intentionally not appended to the name.
        return "Cross-Site Scripting (" + cls + ")";
    }
    
    /**
     * Extract clean parameter name from potentially descriptive paramName
     * Examples:
     *   "DOM XSS: setTimeout -> Function" -> "setTimeout"
     *   "DOM XSS sink: innerHTML" -> "innerHTML"
     *   "query" -> "query"
     */
    private String extractCleanParameterName(String paramName) {
        if (paramName == null || paramName.trim().isEmpty()) {
            return "parameter";
        }
        
        // If it's a simple parameter name (no colons, arrows, or "DOM XSS" prefix), return as-is
        if (!paramName.contains(":") && !paramName.contains("->") && !paramName.toLowerCase().contains("dom xss") && 
            !paramName.toLowerCase().contains("client-side") && !paramName.toLowerCase().contains("sink") &&
            !paramName.toLowerCase().contains("source")) {
            return paramName.trim();
        }
        
        // Extract from "DOM XSS: source -> sink" format
        if (paramName.contains("->")) {
            String[] parts = paramName.split("->");
            if (parts.length > 0) {
                String source = parts[0].trim();
                // Remove "DOM XSS:" prefix if present
                if (source.contains(":")) {
                    source = source.substring(source.indexOf(":") + 1).trim();
                }
                if (!source.isEmpty()) {
                    return source;
                }
            }
        }
        
        // Extract from "DOM XSS sink: name" format
        if (paramName.toLowerCase().contains("sink:")) {
            String[] parts = paramName.split(":", 2);
            if (parts.length > 1) {
                return parts[1].trim();
            }
        }
        
        // Extract from "DOM XSS source: name" format
        if (paramName.toLowerCase().contains("source:")) {
            String[] parts = paramName.split(":", 2);
            if (parts.length > 1) {
                return parts[1].trim();
            }
        }
        
        // If all else fails, return cleaned version
        return paramName.replace("DOM XSS", "").replace("Client-side", "").replace("sink:", "").replace("source:", "")
                       .replace("->", "").replace(":", "").trim();
    }
    
    private String generateEnhancedIssueDetail(IHttpRequestResponse requestResponse,
                                             Map<String, Object> vulnerabilityData,
                                             ModernArchitectureDetector.ArchitectureAnalysis archAnalysis,
                                             AdvancedJSONAnalyzer.JSONAnalysisResult jsonAnalysis,
                                             SeverityLevel severity,
                                             ConfidenceLevel confidence) {
        StringBuilder detail = new StringBuilder();
        
        // Professional HTML structure with proper styling
        detail.append("<html><head><style>");
        detail.append("body { font-family: 'Segoe UI', Arial, sans-serif; line-height: 1.6; color: #333; margin: 20px; }");
        detail.append("h2 { color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; margin-top: 30px; }");
        detail.append("h3 { color: #34495e; border-bottom: 2px solid #ecf0f1; padding-bottom: 8px; margin-top: 25px; }");
        detail.append("h4 { color: #7f8c8d; margin-top: 20px; }");
        detail.append("code { background-color: #f4f4f4; padding: 2px 6px; border-radius: 3px; font-family: 'Courier New', monospace; }");
        detail.append("pre { background-color: #f8f9fa; padding: 15px; border-left: 4px solid #3498db; overflow-x: auto; }");
        detail.append("table { border-collapse: collapse; width: 100%; margin: 20px 0; }");
        detail.append("th { background-color: #3498db; color: white; padding: 12px; text-align: left; }");
        detail.append("td { padding: 10px; border: 1px solid #ddd; }");
        detail.append("tr:nth-child(even) { background-color: #f8f9fa; }");
        detail.append(".alert { padding: 15px; margin: 15px 0; border-left: 4px solid; border-radius: 4px; }");
        detail.append(".alert-danger { background-color: #f8d7da; border-color: #dc3545; color: #721c24; }");
        detail.append(".alert-warning { background-color: #fff3cd; border-color: #ffc107; color: #856404; }");
        detail.append(".alert-info { background-color: #d1ecf1; border-color: #17a2b8; color: #0c5460; }");
        detail.append("</style></head><body>");
        
        detail.append("<h2>XSS Vulnerability Advisory</h2>");
        detail.append("<div style='background-color: #e8f4f8; padding: 15px; border-radius: 5px; margin-bottom: 20px;'>");
        detail.append("<p style='margin: 5px 0;'><strong>Severity:</strong> <span style='color: ").append(severity.getColorCode()).append("; font-weight: bold;'>").append(severity.getDisplayName()).append("</span></p>");
        detail.append("<p style='margin: 5px 0;'><strong>Confidence:</strong> <span style='font-weight: bold;'>").append(confidence.getDisplayName()).append("</span></p>");
        detail.append("</div>");
        
        String payload = extractRealPayload(vulnerabilityData);
        String paramName = (String) vulnerabilityData.get("paramName");
        
        // CRITICAL: Add explicit "Actual Identified Payload" section at the top
        detail.append("<h3>Actual Identified Payload</h3>");
        detail.append("<div style='background-color: #fff3cd; padding: 15px; border-left: 4px solid #ffc107; margin-bottom: 20px;'>");
        detail.append("<p style='margin: 5px 0; font-size: 110%;'><strong>Payload:</strong> <code style='background-color: #fff; padding: 5px 10px; border-radius: 3px; font-size: 110%; color: #dc3545; font-weight: bold;'>").append(escapeHtml(payload)).append("</code></p>");
        detail.append("<p style='margin: 5px 0;'><strong>Payload Length:</strong> ").append(payload.length()).append(" characters</p>");
        Boolean confirmedXSS = (Boolean) vulnerabilityData.get("CONFIRMED_XSS");
        if (confirmedXSS != null && confirmedXSS) {
            detail.append("<p style='margin: 5px 0;'><strong>Status:</strong> <span style='color: #dc3545; font-weight: bold;'>✅ CONFIRMED EXPLOITABLE</span></p>");
        }
        detail.append("</div>");
        
        // CRITICAL: Add explicit "Vulnerable Parameter/Locations" section
        detail.append("<h3>Vulnerable Parameter/Locations</h3>");
        detail.append("<div style='background-color: #f8f9fa; padding: 15px; border-left: 4px solid #dc3545; margin-bottom: 20px;'>");
        detail.append("<table border='1' cellpadding='8' cellspacing='0' style='border-collapse: collapse; width: 100%;'>");
        detail.append("<tr style='background-color: #dc3545; color: white;'><th style='padding: 10px; text-align: left;'>Property</th><th style='padding: 10px; text-align: left;'>Value</th></tr>");
        detail.append("<tr><td style='padding: 8px;'><strong>Parameter Name</strong></td><td style='padding: 8px;'><code>").append(escapeHtml(paramName)).append("</code></td></tr>");
        
        // Parameter type
        Object paramTypeObj = vulnerabilityData.get("TYPE");
        if (paramTypeObj != null) {
            String paramType = "Unknown";
            if (paramTypeObj instanceof Byte) {
                byte pt = (Byte) paramTypeObj;
                switch (pt) {
                    case 0: paramType = "URL Parameter"; break;
                    case 1: paramType = "Body Parameter"; break;
                    case 2: paramType = "Cookie Parameter"; break;
                    case 3: paramType = "JSON Parameter"; break;
                    case 4: paramType = "XML Parameter"; break;
                    case 5: paramType = "XML Attribute"; break;
                    case 6: paramType = "Multipart Attribute"; break;
                }
            } else if (paramTypeObj instanceof Integer) {
                int pt = (Integer) paramTypeObj;
                switch (pt) {
                    case 0: paramType = "URL Parameter"; break;
                    case 1: paramType = "Body Parameter"; break;
                    case 2: paramType = "Cookie Parameter"; break;
                    case 3: paramType = "JSON Parameter"; break;
                    case 4: paramType = "XML Parameter"; break;
                    case 5: paramType = "XML Attribute"; break;
                    case 6: paramType = "Multipart Attribute"; break;
                }
            }
            detail.append("<tr><td style='padding: 8px;'><strong>Parameter Type</strong></td><td style='padding: 8px;'>").append(escapeHtml(paramType)).append("</td></tr>");
        }
        
        // Vulnerable URL
        try {
            IRequestInfo requestInfo = helpers.analyzeRequest(requestResponse);
            URL url = requestInfo.getUrl();
            detail.append("<tr><td style='padding: 8px;'><strong>Vulnerable URL</strong></td><td style='padding: 8px;'><code>").append(escapeHtml(url.toString())).append("</code></td></tr>");
            detail.append("<tr><td style='padding: 8px;'><strong>HTTP Method</strong></td><td style='padding: 8px;'>").append(escapeHtml(requestInfo.getMethod())).append("</td></tr>");
        } catch (Exception e) {
            // Ignore
        }
        
        detail.append("</table>");
        detail.append("</div>");
        
        // CRITICAL: Add explicit "Reflection Places/Position and Context" section
        detail.append("<h3>Reflection Places/Position and Context</h3>");
        detail.append("<div style='background-color: #d1ecf1; padding: 15px; border-left: 4px solid #17a2b8; margin-bottom: 20px;'>");
        
        String reflectionContext = (String) vulnerabilityData.get("REFLECTION_CONTEXT");
        String reflectedIn = (String) vulnerabilityData.get("REFLECTED_IN");
        @SuppressWarnings("unchecked")
        List<int[]> matches = (List<int[]>) vulnerabilityData.get("MATCHES");
        
        if (reflectionContext != null && !reflectionContext.equals("UNKNOWN")) {
            detail.append("<p><strong>Reflection Context:</strong> <code style='background-color: #fff; padding: 3px 8px; border-radius: 3px;'>").append(escapeHtml(reflectionContext)).append("</code></p>");
            
            // Explain context meaning
            if (reflectionContext.contains("EXECUTION") || reflectionContext.contains("JAVASCRIPT") || 
                reflectionContext.contains("EVENT_HANDLER")) {
                detail.append("<p style='color: #dc3545; font-weight: bold;'>⚠️ CRITICAL: Payload is in executable context - browser will execute JavaScript</p>");
            } else if (reflectionContext.contains("HTML") || reflectionContext.contains("ATTRIBUTE")) {
                detail.append("<p style='color: #856404; font-weight: bold;'>⚠️ MEDIUM RISK: Payload is in HTML context - enables tag injection</p>");
            } else if (reflectionContext.contains("JSON")) {
                detail.append("<p style='color: #0c5460;'>ℹ️ INFO: Payload is in JSON context - may be exploitable if consumed unsafely</p>");
            }
        } else {
            detail.append("<p><strong>Reflection Context:</strong> <span style='color: #6c757d;'>Not detected</span></p>");
        }
        
        if (reflectedIn != null && !reflectedIn.trim().isEmpty()) {
            detail.append("<p><strong>Reflection Location:</strong> ").append(escapeHtml(reflectedIn)).append("</p>");
        }
        
        if (matches != null && !matches.isEmpty()) {
            detail.append("<p><strong>Reflection Positions:</strong> ").append(matches.size()).append(" location(s) detected in response</p>");
            detail.append("<ul>");
            for (int i = 0; i < Math.min(matches.size(), 5); i++) {
                int[] match = matches.get(i);
                if (match != null && match.length >= 2) {
                    detail.append("<li>Position ").append(i + 1).append(": Offset ").append(match[0]).append(" (length: ").append(match[1] - match[0]).append(" bytes)</li>");
                }
            }
            if (matches.size() > 5) {
                detail.append("<li>... and ").append(matches.size() - 5).append(" more location(s)</li>");
            }
            detail.append("</ul>");
        }
        
        String encodingContext = (String) vulnerabilityData.get("ENCODING_CONTEXT");
        if (encodingContext != null && !encodingContext.equals("UNKNOWN")) {
            detail.append("<p><strong>Encoding Context:</strong> <code>").append(escapeHtml(encodingContext)).append("</code></p>");
        }
        
        detail.append("</div>");
        
        detail.append("<h3>Vulnerability Summary</h3>");
        detail.append("<p>A Cross-Site Scripting (XSS) vulnerability has been detected in the parameter <code>").append(paramName).append("</code>.</p>");
        
        // Enhanced detection method information
        String scanType = (String) vulnerabilityData.get("SCAN_TYPE");
        String detectionMethod = scanType != null ? scanType + " XSS Detection Engine" : "Advanced XSS Detection Engine";
        detail.append("<p><strong>Detection Method:</strong> ").append(detectionMethod).append("</p>");
        
        // Add confidence score and XSS score (robust to Integer/Double/String)
        double confidenceScore = getDouble(vulnerabilityData, "CONFIDENCE_SCORE", -1.0);
        double xssScore = getDouble(vulnerabilityData, "XSS_SCORE", -1.0);
        if (confidenceScore >= 0.0) {
            detail.append("<p><strong>Confidence Score:</strong> ").append(String.format("%.1f", confidenceScore)).append("%</p>");
        }
        if (xssScore >= 0.0) {
            detail.append("<p><strong>XSS Vulnerability Score:</strong> ").append(String.format("%.1f", xssScore)).append("%</p>");
        }
        
        // Add confirmed XSS status (reuse confirmedXSS from "Actual Identified Payload" section above)
        if (confirmedXSS != null && confirmedXSS) {
            detail.append("<p><strong>Status:</strong> <span style='color: red; font-weight: bold;'>CONFIRMED EXPLOITABLE</span></p>");
        }
        
        // Add vulnerability type
        String vulnerabilityType = (String) vulnerabilityData.get("vulnerabilityType");
        if (vulnerabilityType != null) {
            detail.append("<p><strong>Vulnerability Type:</strong> ").append(escapeHtml(vulnerabilityType)).append("</p>");
        }
        
        // Add exploit code
        detail.append("<h3>Exploit Code</h3>");
        detail.append("<h4>JavaScript</h4>");
        detail.append("<pre><code>");
        detail.append("// Replace 'PARAMETER_NAME' with the actual parameter name\n");
        detail.append("fetch('").append(escapeHtml(extractPathFromRequest(requestResponse))).append("', {\n");
        detail.append("  method: 'POST',\n");
        detail.append("  headers: {\n");
        detail.append("    'Content-Type': 'application/x-www-form-urlencoded',\n");
        detail.append("  },\n");
        detail.append("  body: '").append(paramName).append("=").append(escapeHtml(payload)).append("'\n");
        detail.append("});\n");
        detail.append("</code></pre>");
        
        detail.append("<h4>cURL</h4>");
        detail.append("<pre><code>");
        detail.append("curl -X POST '").append(escapeHtml(extractPathFromRequest(requestResponse))).append("' \\\n");
        detail.append("  -H 'Content-Type: application/x-www-form-urlencoded' \\\n");
        detail.append("  -d '").append(paramName).append("=").append(escapeHtml(payload)).append("'\n");
        detail.append("</code></pre>");
        
        detail.append("<h4>HTML</h4>");
        detail.append("<pre><code>");
        detail.append("&lt;form method=\"POST\" action=\"").append(escapeHtml(extractPathFromRequest(requestResponse))).append("\"&gt;\n");
        detail.append("  &lt;input type=\"hidden\" name=\"").append(paramName).append("\" value=\"").append(escapeHtml(payload)).append("\"&gt;\n");
        detail.append("  &lt;input type=\"submit\" value=\"Exploit\"&gt;\n");
        detail.append("&lt;/form&gt;\n");
        detail.append("</code></pre>");
        
        // ADVANCED: Add browser execution context analysis
        detail.append("<h3>Browser Execution Context Analysis</h3>");
        String browserContext = (String) vulnerabilityData.get("ACTUAL_BROWSER_CONTEXT");
        if (browserContext == null) {
            browserContext = (String) vulnerabilityData.get("BROWSER_EXECUTION_CONTEXT");
        }
        if (browserContext == null) {
            browserContext = (String) vulnerabilityData.get("REFLECTION_CONTEXT");
        }
        
        Boolean isExecutable = (Boolean) vulnerabilityData.get("IS_EXECUTABLE_CONTEXT");
        // encodingContext already declared above in "Reflection Places/Position and Context" section
        
        if (browserContext != null && !browserContext.equals("UNKNOWN")) {
            detail.append("<p><strong>Detected Browser Context:</strong> <code>").append(escapeHtml(browserContext)).append("</code></p>");
            
            // Explain what this context means for browser execution
            if (browserContext.contains("EXECUTION") || browserContext.contains("JAVASCRIPT") || 
                browserContext.contains("EVENT_HANDLER") || browserContext.contains("JSONP")) {
                detail.append("<p><span style='color: red; font-weight: bold;'>⚠️ CRITICAL:</span> ");
                if (browserContext.contains("JAVASCRIPT_EXECUTION")) {
                    detail.append("Payload is in JavaScript execution context - browser will execute payload directly as JavaScript code when page loads.</p>");
                } else if (browserContext.contains("EVENT_HANDLER")) {
                    detail.append("Payload is in event handler context - browser will execute payload as JavaScript when event fires (e.g., onload, onclick).</p>");
                } else if (browserContext.contains("JSONP")) {
                    detail.append("Payload is in JSONP context - browser will execute payload as JavaScript callback.</p>");
                } else if (browserContext.contains("URL_EXECUTION")) {
                    detail.append("Payload uses executable URL protocol (javascript:, data:) - browser will execute on navigation.</p>");
                } else {
                    detail.append("Payload is in executable context - browser will execute payload.</p>");
                }
            } else if (browserContext.contains("HTML") || browserContext.contains("ATTRIBUTE")) {
                detail.append("<p><span style='color: orange; font-weight: bold;'>⚠️ MEDIUM RISK:</span> ");
                detail.append("Payload is in HTML context - browser will parse as HTML, enabling tag injection.</p>");
            } else if (browserContext.contains("JSON")) {
                detail.append("<p><span style='color: blue;'>ℹ️ INFO:</span> ");
                detail.append("Payload is in JSON context - may be exploitable if consumed unsafely by JavaScript.</p>");
            }
            
            if (isExecutable != null && isExecutable) {
                detail.append("<p><strong>Execution Status:</strong> <span style='color: red; font-weight: bold;'>EXECUTABLE - Browser will execute payload</span></p>");
            } else {
                detail.append("<p><strong>Execution Status:</strong> <span style='color: orange;'>May be exploitable with context break</span></p>");
            }
        }
        
        if (encodingContext != null && !encodingContext.equals("UNKNOWN")) {
            detail.append("<p><strong>Payload Encoding Context:</strong> <code>").append(escapeHtml(encodingContext)).append("</code></p>");
            detail.append("<p>Payload was encoded based on detected reflection context to ensure proper injection.</p>");
        }
        
        // Add enhanced context analysis
        String enhancedContext = (String) vulnerabilityData.get("ENHANCED_CONTEXT");
        if (enhancedContext != null && !enhancedContext.trim().isEmpty()) {
            detail.append("<h3>Enhanced Context Analysis</h3>");
            detail.append("<p>").append(escapeHtml(enhancedContext)).append("</p>");
        }
        
        // Add comprehensive parameter details as Burp Suite displays
        detail.append("<h3>Parameter Details</h3>");
        detail.append("<table border='1' cellpadding='5' cellspacing='0' style='border-collapse: collapse; width: 100%;'>");
        detail.append("<tr><th style='background-color: #f0f0f0; text-align: left;'>Property</th><th style='background-color: #f0f0f0; text-align: left;'>Value</th></tr>");
        detail.append("<tr><td><strong>Parameter Name</strong></td><td><code>").append(escapeHtml(paramName)).append("</code></td></tr>");
        detail.append("<tr><td><strong>Parameter Type</strong></td><td>");
        
        // Get parameter type (reuse paramTypeObj from "Vulnerable Parameter/Locations" section above)
        if (paramTypeObj != null) {
            if (paramTypeObj instanceof Byte) {
                byte paramType = (Byte) paramTypeObj;
                switch (paramType) {
                    case 0: detail.append("URL Parameter"); break;
                    case 1: detail.append("Body Parameter"); break;
                    case 2: detail.append("Cookie Parameter"); break;
                    case 3: detail.append("JSON Parameter"); break;
                    case 4: detail.append("XML Parameter"); break;
                    case 5: detail.append("XML Attribute"); break;
                    case 6: detail.append("Multipart Attribute"); break;
                    default: detail.append("Unknown (").append(paramType).append(")"); break;
                }
            } else if (paramTypeObj instanceof Integer) {
                int paramType = (Integer) paramTypeObj;
                switch (paramType) {
                    case 0: detail.append("URL Parameter"); break;
                    case 1: detail.append("Body Parameter"); break;
                    case 2: detail.append("Cookie Parameter"); break;
                    case 3: detail.append("JSON Parameter"); break;
                    case 4: detail.append("XML Parameter"); break;
                    case 5: detail.append("XML Attribute"); break;
                    case 6: detail.append("Multipart Attribute"); break;
                    default: detail.append("Unknown (").append(paramType).append(")"); break;
                }
            } else {
                detail.append(escapeHtml(paramTypeObj.toString()));
            }
        } else {
            detail.append("Not specified");
        }
        detail.append("</td></tr>");
        
        detail.append("<tr><td><strong>Payload</strong></td><td><code>").append(escapeHtml(payload)).append("</code></td></tr>");
        detail.append("<tr><td><strong>Payload Length</strong></td><td>").append(payload.length()).append(" characters</td></tr>");
        
        // Reflection location (reuse reflectedIn from "Reflection Places/Position and Context" section above)
        if (reflectedIn != null) {
            detail.append("<tr><td><strong>Reflection Location</strong></td><td>").append(escapeHtml(reflectedIn)).append("</td></tr>");
        }
        
        // Reflection matches (reuse matches from "Reflection Places/Position and Context" section above)
        if (matches != null && !matches.isEmpty()) {
            detail.append("<tr><td><strong>Reflection Points</strong></td><td>").append(matches.size()).append(" location(s) detected</td></tr>");
        }
        
        // URL information
        try {
            IRequestInfo requestInfo = helpers.analyzeRequest(requestResponse);
            URL url = requestInfo.getUrl();
            detail.append("<tr><td><strong>Vulnerable URL</strong></td><td><code>").append(escapeHtml(url.toString())).append("</code></td></tr>");
            detail.append("<tr><td><strong>HTTP Method</strong></td><td>").append(escapeHtml(requestInfo.getMethod())).append("</td></tr>");
        } catch (Exception e) {
            // Ignore URL extraction errors
        }
        
        detail.append("</table>");
        
        // Add comprehensive validation evidence for pentesters
        detail.append("<h3>Validation Evidence - 100% Confirmed Exploitation</h3>");
        detail.append("<p>The following evidence confirms this vulnerability with actual proof:</p>");
        detail.append("<ul>");
        
        // CRITICAL: Only show evidence if we have actual proof
        Object testRequestObj = vulnerabilityData.get("TEST_REQUEST");
        Object testResponseObj = vulnerabilityData.get("TEST_RESPONSE");
        
        boolean hasProof = false;
        String testRequestStr = null;
        String testResponseStr = null;
        
        if (testRequestObj instanceof byte[]) {
            testRequestStr = new String((byte[]) testRequestObj, StandardCharsets.UTF_8);
            hasProof = true;
        } else if (testRequestObj instanceof String) {
            testRequestStr = (String) testRequestObj;
            hasProof = true;
        }
        
        if (testResponseObj instanceof byte[]) {
            testResponseStr = new String((byte[]) testResponseObj, StandardCharsets.UTF_8);
            hasProof = hasProof && true;
        } else if (testResponseObj instanceof String) {
            testResponseStr = (String) testResponseObj;
            hasProof = hasProof && true;
        }
        
        if (hasProof && testRequestStr != null && testResponseStr != null) {
            detail.append("<li><strong>✅ Actual Exploited Request:</strong> Yes - Real HTTP request with payload injected in parameter <code>").append(escapeHtml(paramName)).append("</code></li>");
            
            try {
                IRequestInfo reqInfo = helpers.analyzeRequest(requestResponse);
                detail.append("<li><strong>Request Method:</strong> ").append(escapeHtml(reqInfo.getMethod())).append("</li>");
            } catch (Exception e) {
                detail.append("<li><strong>Request Method:</strong> Unknown</li>");
            }
            
            // CRITICAL: For DOM/Client-side XSS, payload may not be in request (it's client-side)
            // Reuse scanType if already defined in method scope, otherwise get it
            String scanTypeLocal = (String) vulnerabilityData.get("SCAN_TYPE");
            String vulnType = (String) vulnerabilityData.get("vulnerabilityType");
            boolean isDOMOrClientSide = (scanTypeLocal != null && (scanTypeLocal.toLowerCase().contains("dom") || scanTypeLocal.toLowerCase().contains("client-side"))) ||
                                       (vulnType != null && (vulnType.toLowerCase().contains("dom") || vulnType.toLowerCase().contains("client-side")));
            
            // Validate payload in request
            if (testRequestStr.contains(payload)) {
                detail.append("<li><strong>✅ Payload in Request:</strong> Confirmed - Payload <code>").append(escapeHtml(payload)).append("</code> found in request parameter</li>");
            } else {
                if (isDOMOrClientSide) {
                    detail.append("<li><strong>ℹ️ Payload in Request:</strong> Not applicable - DOM/Client-side XSS detected via source-sink analysis (no server-side payload injection required)</li>");
                } else {
                    detail.append("<li><strong>❌ Payload in Request:</strong> NOT FOUND - Invalid proof</li>");
                }
            }
            
            // Validate payload reflection with context awareness
            // reflectionContext already declared above in "Reflection Places/Position and Context" section
            String encodingContextValue = (String) vulnerabilityData.get("ENCODING_CONTEXT");
            // Check for encoding flag (IS_ENCODED) or presence of ENCODED_PAYLOAD that differs from payload
            boolean isEncoded = false;
            if (vulnerabilityData.containsKey("IS_ENCODED")) {
                Object isEncodedObj = vulnerabilityData.get("IS_ENCODED");
                if (isEncodedObj instanceof Boolean) {
                    isEncoded = (Boolean) isEncodedObj;
                }
            } else {
                // Fallback: check if ENCODED_PAYLOAD exists and differs from payload
                String encodedPayload = extractInjectedPayload(vulnerabilityData);
                String originalPayload = extractOriginalPayload(vulnerabilityData);
                if (encodedPayload != null && originalPayload != null && !encodedPayload.equals(originalPayload)) {
                    isEncoded = true;
                }
            }
            
            if (testResponseStr.contains(payload)) {
                detail.append("<li><strong>✅ Payload Reflection:</strong> Confirmed - Payload found <span style='color: red; font-weight: bold;'>UNENCODED</span> in response - <span style='color: red; font-weight: bold;'>100% EXPLOITABLE</span></li>");
                if (reflectionContext != null && !reflectionContext.equals("UNKNOWN")) {
                    detail.append("<li><strong>Reflection Context:</strong> ").append(escapeHtml(reflectionContext)).append("</li>");
                }
            } else {
                // For DOM/Client-side XSS, check for source-sink evidence instead
                if (isDOMOrClientSide) {
                    Object sourceSinkAnalysis = vulnerabilityData.get("SOURCE_SINK_ANALYSIS");
                    if (sourceSinkAnalysis != null) {
                        detail.append("<li><strong>✅ DOM XSS Evidence:</strong> Source-sink flow detected - Vulnerability confirmed via static analysis of client-side code</li>");
                        detail.append("<li><strong>Detection Method:</strong> Static analysis of JavaScript sources and sinks (no server-side reflection required)</li>");
                    } else {
                        detail.append("<li><strong>ℹ️ Payload Reflection:</strong> Not applicable - DOM/Client-side XSS detected via source-sink analysis</li>");
                    }
                } else {
                    // CRITICAL FIX: HTML-encoded reflection means server properly escaped it - NOT exploitable
                    String htmlEncoded = payload.replace("<", "&lt;").replace(">", "&gt;");
                    if (testResponseStr.contains(htmlEncoded)) {
                        detail.append("<li><strong>❌ Payload Reflection:</strong> Found HTML-encoded in response - Server properly escaped it - <span style='color: orange; font-weight: bold;'>NOT EXPLOITABLE</span></li>");
                    } else {
                        // Check for context-aware encoded version (URL-encoded, etc.)
                        if (isEncoded && encodingContext != null) {
                            // URL-encoded might still be exploitable if decoded by browser
                            detail.append("<li><strong>✅ Payload Reflection:</strong> Found context-encoded payload in response (Context: ").append(escapeHtml(encodingContext)).append(")</li>");
                        } else {
                            detail.append("<li><strong>❌ Payload Reflection:</strong> NOT FOUND - Invalid proof</li>");
                        }
                    }
                }
            }
            
            // Show encoding information if available
            if (isEncoded && encodingContext != null) {
                detail.append("<li><strong>Encoding Applied:</strong> Context-aware encoding for ").append(escapeHtml(encodingContext)).append(" context</li>");
            }
            
            // Confirmed XSS status
            if (confirmedXSS != null && confirmedXSS) {
                detail.append("<li><strong>✅ Exploitation Status:</strong> <span style='color: red; font-weight: bold; font-size: 120%;'>CONFIRMED EXPLOITABLE - 100% PROOF</span></li>");
                if (isDOMOrClientSide) {
                    detail.append("<li><strong>✅ Proof of Concept:</strong> See <strong>Source → Sink Analysis</strong> section for detected data flow</li>");
                    detail.append("<li><strong>📋 Exploit Method:</strong> Client-side exploitation via detected source-sink flow (see Reproduction Steps for exploit code)</li>");
                } else {
                    detail.append("<li><strong>✅ Proof of Concept:</strong> See <strong>Injected Request</strong> and <strong>Injected Response</strong> tabs for actual exploited HTTP messages</li>");
                    detail.append("<li><strong>📋 Request Tab:</strong> Shows injected XSS payload highlighted in vulnerable parameter <code>").append(escapeHtml(paramName)).append("</code></li>");
                    detail.append("<li><strong>📋 Response Tab:</strong> Shows payload reflection highlighted in response body with response code</li>");
                }
            } else {
                // For DOM/Client-side, check if we have source-sink evidence
                if (isDOMOrClientSide) {
                    Object sourceSinkAnalysis = vulnerabilityData.get("SOURCE_SINK_ANALYSIS");
                    if (sourceSinkAnalysis != null) {
                        detail.append("<li><strong>✅ Exploitation Status:</strong> <span style='color: orange; font-weight: bold;'>CONFIRMED VIA SOURCE-SINK ANALYSIS</span> - DOM XSS vulnerability detected</li>");
                        detail.append("<li><strong>✅ Proof of Concept:</strong> See <strong>Source → Sink Analysis</strong> section for detected data flow</li>");
                    } else {
                        detail.append("<li><strong>⚠️ Exploitation Status:</strong> POTENTIAL - Source-sink flow detected but requires manual verification</li>");
                    }
                } else {
                    detail.append("<li><strong>❌ Exploitation Status:</strong> NOT CONFIRMED - Missing confirmation</li>");
                }
            }
        } else {
            detail.append("<li><strong>❌ Proof Missing:</strong> No actual exploited request/response available - This issue should not have been reported</li>");
        }
        
        detail.append("</ul>");
        
        // Add payload analysis for researchers
        String payloadCategory = (String) vulnerabilityData.get("PAYLOAD_CATEGORY");
        if (payloadCategory != null) {
            detail.append("<h3>Payload Analysis</h3>");
            detail.append("<p><strong>Payload Category:</strong> ").append(escapeHtml(payloadCategory)).append("</p>");
            
            // Add payload parts analysis if available
            String payloadAnalysis = (String) vulnerabilityData.get("PAYLOAD_PARTS_ANALYSIS");
            if (payloadAnalysis != null) {
                detail.append("<pre><code>").append(escapeHtml(payloadAnalysis)).append("</code></pre>");
            }
        }
        
        // Add response snippet if available
        String responseSnippet = (String) vulnerabilityData.get("RESPONSE_SNIPPET");
        if (responseSnippet != null) {
            detail.append("<h3>Response Snippet</h3>");
            detail.append("<p>The following snippet shows the payload reflection in the response:</p>");
            detail.append("<pre><code>").append(escapeHtml(responseSnippet)).append("</code></pre>");
        }
        
        // Add comprehensive exploitation steps for pentesters
        detail.append("<h3>Exploitation Steps for Pentesters</h3>");
        detail.append("<ol>");
        detail.append("<li><strong>Identify the vulnerable parameter:</strong> The parameter <code>").append(escapeHtml(paramName)).append("</code> is vulnerable to XSS injection.</li>");
        detail.append("<li><strong>Inject the payload:</strong> Replace the parameter value with the XSS payload: <code>").append(escapeHtml(payload)).append("</code></li>");
        detail.append("<li><strong>Verify reflection:</strong> Check the response to confirm the payload is reflected unencoded.</li>");
        detail.append("<li><strong>Test in browser:</strong> Open the URL with the injected payload in a browser to confirm execution.</li>");
        detail.append("<li><strong>Verify exploitation:</strong> Confirm that JavaScript executes (e.g., alert box appears or network request is made).</li>");
        detail.append("</ol>");
        
        // Add impact assessment
        detail.append("<h3>Impact Assessment</h3>");
        detail.append("<ul>");
        detail.append("<li><strong>Attack Vector:</strong> Reflected XSS via parameter injection</li>");
        detail.append("<li><strong>Attack Complexity:</strong> Low - Requires user interaction (clicking malicious link)</li>");
        detail.append("<li><strong>Privileges Required:</strong> None</li>");
        detail.append("<li><strong>User Interaction:</strong> Required - Victim must click malicious link</li>");
        detail.append("<li><strong>Scope:</strong> Unchanged - Attack affects same origin</li>");
        detail.append("<li><strong>Confidentiality Impact:</strong> High - Attackers can steal session cookies, credentials, and sensitive data</li>");
        detail.append("<li><strong>Integrity Impact:</strong> High - Attackers can modify page content and perform actions on behalf of users</li>");
        detail.append("<li><strong>Availability Impact:</strong> Low - Typically does not affect availability</li>");
        detail.append("</ul>");
        
        // Add minimal remediation guidance (no verbose details)
        // Removed verbose remediation - keep it simple
        
        // Add references for pentesters
        detail.append("<h3>References</h3>");
        detail.append("<ul>");
        detail.append("<li><a href='https://owasp.org/www-community/attacks/xss/'>OWASP XSS Prevention Cheat Sheet</a></li>");
        detail.append("<li><a href='https://portswigger.net/web-security/cross-site-scripting'>PortSwigger Web Security Academy - XSS</a></li>");
        detail.append("<li><a href='https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html'>OWASP XSS Prevention Cheat Sheet</a></li>");
        detail.append("<li><a href='https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP'>MDN - Content Security Policy</a></li>");
        detail.append("</ul>");
        
        return detail.toString();
    }
    
    // ---------------------------------------------------------------------
    // Burp-safe reporting (limited HTML subset) + marker-based highlighting
    // ---------------------------------------------------------------------

    private String generateBurpSafeIssueDetail(IHttpRequestResponse requestResponse,
                                                Map<String, Object> vulnerabilityData,
                                                ModernArchitectureDetector.ArchitectureAnalysis archAnalysis,
                                                AdvancedJSONAnalyzer.JSONAnalysisResult jsonAnalysis,
                                                SeverityLevel severity,
                                                ConfidenceLevel confidence) {
        // CRITICAL: Don't generate misleading reports for false positives
        // Check if this is actually exploitable before generating detail
        Object testRequestObj = vulnerabilityData.get("TEST_REQUEST");
        Object testResponseObj = vulnerabilityData.get("TEST_RESPONSE");
        String payloadCheck = extractRealPayload(vulnerabilityData);
        Boolean confirmedCheck = (Boolean) vulnerabilityData.get("CONFIRMED_XSS");
        
        // CRITICAL: If CONFIRMED_XSS is set but payload is not reflected, this is a false positive
        // Don't generate misleading report
        if (Boolean.TRUE.equals(confirmedCheck) && testRequestObj != null && testResponseObj != null && payloadCheck != null) {
            byte[] testResponse = testResponseObj instanceof byte[] ? (byte[]) testResponseObj : 
                                 testResponseObj instanceof String ? ((String) testResponseObj).getBytes(StandardCharsets.UTF_8) : null;
            if (testResponse != null) {
                String responseStr = new String(testResponse, StandardCharsets.UTF_8);
                if (!validatePayloadReflection(payloadCheck, responseStr)) {
                    // Payload not reflected - this is a false positive, don't generate misleading report
                    callbacks.printOutput("[IssueReporter] BLOCKING report generation: CONFIRMED_XSS set but payload NOT reflected - false positive");
                    return null; // This will cause createEnhancedXSSIssue to return null
                }
            }
        }
        // IMPORTANT: Use only Burp-supported tags; do NOT use <html>/<head>/<style>/<body>/<div>/<span> or inline CSS.
        StringBuilder out = new StringBuilder();

        String paramName = (String) vulnerabilityData.get("paramName");
        String injectedPayload = extractInjectedPayload(vulnerabilityData);
        String originalPayload = extractOriginalPayload(vulnerabilityData);
        String payload = injectedPayload != null ? injectedPayload : originalPayload;

        Boolean confirmed = (Boolean) vulnerabilityData.get("CONFIRMED_XSS");
        Object paramTypeObj = vulnerabilityData.get("TYPE");

        IRequestInfo baseInfo = null;
        try { baseInfo = helpers.analyzeRequest(requestResponse); } catch (Exception ignored) {}

        // Exploited pair if present (used for offsets + “Reproduction”)
        byte[] exploitedRequest = toBytes(vulnerabilityData.get("TEST_REQUEST"));
        byte[] exploitedResponse = toBytes(vulnerabilityData.get("TEST_RESPONSE"));
        boolean haveProofPair = exploitedRequest != null && exploitedRequest.length > 0
                             && exploitedResponse != null && exploitedResponse.length > 0;

        // Compute offsets (prefer real response search over stale MATCHES)
        List<int[]> responseOffsets = haveProofPair && payload != null
            ? findBestMarkers(exploitedResponse, payload, originalPayload, true)
            : Collections.emptyList();

        // Professional formatting using Burp-supported tags
        out.append("<b>Cross-Site Scripting (XSS) Vulnerability</b><br><br>");

        // Summary table
        out.append("<table>");
        out.append("<tr><td><b>Severity:</b></td><td>").append(escapeHtml(severity.getDisplayName())).append("</td></tr>");
        out.append("<tr><td><b>Confidence:</b></td><td>").append(escapeHtml(confidence.getDisplayName())).append("</td></tr>");
        // CRITICAL: For DOM/Client-side XSS, check if we have source-sink evidence even if not "confirmed" via payload injection
        String scanTypeForStatus = (String) vulnerabilityData.get("SCAN_TYPE");
        String vulnTypeForStatus = (String) vulnerabilityData.get("vulnerabilityType");
        boolean isDOMOrClientSide = (scanTypeForStatus != null && (scanTypeForStatus.toLowerCase().contains("dom") || scanTypeForStatus.toLowerCase().contains("client-side"))) ||
                                   (vulnTypeForStatus != null && (vulnTypeForStatus.toLowerCase().contains("dom") || vulnTypeForStatus.toLowerCase().contains("client-side")));
        
        String statusDisplay;
        if (Boolean.TRUE.equals(confirmed)) {
            statusDisplay = "CONFIRMED";
        } else if (isDOMOrClientSide) {
            // For DOM/Client-side, check if we have source-sink evidence
            Object sourceSinkAnalysis = vulnerabilityData.get("SOURCE_SINK_ANALYSIS");
            String confidenceLevel = (String) vulnerabilityData.get("confidence");
            if (sourceSinkAnalysis != null || "Certain".equals(confidenceLevel) || "Firm".equals(confidenceLevel)) {
                statusDisplay = "CONFIRMED (Source-Sink Analysis)";
            } else {
                statusDisplay = "NOT CONFIRMED";
            }
        } else {
            statusDisplay = "NOT CONFIRMED";
        }
        out.append("<tr><td><b>Status:</b></td><td>").append(statusDisplay).append("</td></tr>");
        out.append("</table><br>");

        // Vulnerable Parameter Section
        out.append("<b>Vulnerable Parameter</b><br>");
        out.append("<table>");
        if (paramName != null) {
            out.append("<tr><td><b>Parameter:</b></td><td><code>").append(escapeHtml(paramName)).append("</code></td></tr>");
        }
        if (paramTypeObj != null) {
            out.append("<tr><td><b>Type:</b></td><td>").append(escapeHtml(normalizeParamType(paramTypeObj))).append("</td></tr>");
        }
        if (baseInfo != null) {
            out.append("<tr><td><b>Method:</b></td><td>").append(escapeHtml(baseInfo.getMethod())).append("</td></tr>");
            out.append("<tr><td><b>Endpoint:</b></td><td>").append(escapeHtml(baseInfo.getUrl().getPath())).append("</td></tr>");
        }
        out.append("</table><br>");

        // Payload Section
        out.append("<b>Payload Details</b><br>");
        if (payload != null) {
            boolean payloadInRequest = haveProofPair && (bytesContain(exploitedRequest, payload) || (originalPayload != null && bytesContain(exploitedRequest, originalPayload)));
            out.append("<table>");
            out.append("<tr><td><b>").append(payloadInRequest ? "Injected" : "Test").append(" Payload:</b></td><td><code>")
               .append(escapeHtml(truncatePayload(payload, 200))).append("</code></td></tr>");
            if (originalPayload != null && injectedPayload != null && !originalPayload.equals(injectedPayload)) {
                out.append("<tr><td><b>Original:</b></td><td><code>").append(escapeHtml(truncatePayload(originalPayload, 200))).append("</code></td></tr>");
                Object decodedReflectionObj = vulnerabilityData.get("DECODED_REFLECTION_DETECTED");
                if (decodedReflectionObj instanceof Boolean && (Boolean) decodedReflectionObj) {
                    out.append("<tr><td><b>Reflection:</b></td><td>Decoded (server decoded the payload)</td></tr>");
                }
            }
            out.append("<tr><td><b>Length:</b></td><td>").append(payload.length()).append(" characters</td></tr>");
            out.append("</table>");
        } else {
            out.append("Payload details not available.<br>");
        }

        // Reflection Evidence Section (detailed mode only)
        boolean detailedMode = settings == null || Boolean.TRUE.equals(settings.getDetailedReporting());
        if (detailedMode) {
            out.append("<br><b>Reflection Evidence</b><br>");
            String reflectionContext = bestContext(vulnerabilityData);
            String reflectedIn = (String) vulnerabilityData.get("REFLECTED_IN");
            out.append("<table>");
            out.append("<tr><td><b>Context:</b></td><td>").append(escapeHtml(formatContext(reflectionContext))).append("</td></tr>");
            if (reflectedIn != null) {
                out.append("<tr><td><b>Location:</b></td><td>").append(escapeHtml(reflectedIn)).append("</td></tr>");
            }
            out.append("<tr><td><b>Matches:</b></td><td>").append(responseOffsets.isEmpty() ? "None detected" : (responseOffsets.size() + " location(s)")).append("</td></tr>");
            out.append("</table>");

            // Show reflection positions if available
            if (!responseOffsets.isEmpty()) {
                out.append("<br><i>Reflection positions in response:</i><br>");
                for (int i = 0; i < Math.min(responseOffsets.size(), 5); i++) {
                    int[] m = responseOffsets.get(i);
                    if (m != null && m.length >= 2) {
                        out.append("&nbsp;&nbsp;Position ").append(i + 1).append(": bytes ").append(m[0]).append("-").append(m[1]).append("<br>");
                    }
                }
                if (responseOffsets.size() > 5) {
                    out.append("&nbsp;&nbsp;<i>...and ").append(responseOffsets.size() - 5).append(" more</i><br>");
                }
            }

            // Dangerous Characters Section (only if available and meaningful)
            Object symbolsReflected = vulnerabilityData.get("SYMBOLS_REFLECTED");
            @SuppressWarnings("unchecked")
            List<String> reflectedSymbols = (List<String>) vulnerabilityData.get("REFLECTED_SYMBOLS");
            if (Boolean.TRUE.equals(symbolsReflected) && reflectedSymbols != null && !reflectedSymbols.isEmpty()) {
                out.append("<br><b>Unfiltered Characters</b><br>");
                out.append("The following characters were reflected without encoding: <code>");
                for (int i = 0; i < Math.min(reflectedSymbols.size(), 10); i++) {
                    if (i > 0) out.append(" ");
                    out.append(escapeHtml(reflectedSymbols.get(i)));
                }
                out.append("</code><br>");
            }
        }

        // Validation Summary Section
        out.append("<br><b>Verification Summary</b><br>");
        out.append("<table>");
        boolean payloadReflectedInResponse = false;
        if (haveProofPair && payload != null) {
            boolean inReq = bytesContain(exploitedRequest, payload) || (originalPayload != null && bytesContain(exploitedRequest, originalPayload));
            boolean inResp = !responseOffsets.isEmpty() || bytesContain(exploitedResponse, payload) || (originalPayload != null && bytesContain(exploitedResponse, originalPayload));
            payloadReflectedInResponse = inResp;
            out.append("<tr><td><b>Test Request Sent:</b></td><td>Yes</td></tr>");
            out.append("<tr><td><b>Payload in Request:</b></td><td>").append(inReq ? "Confirmed" : "Not found").append("</td></tr>");
            out.append("<tr><td><b>Payload Reflected:</b></td><td>").append(inResp ? "Confirmed" : "Not found").append("</td></tr>");
        } else {
            payloadReflectedInResponse = false;
            out.append("<tr><td><b>Test Request Sent:</b></td><td>No</td></tr>");
            out.append("<tr><td><b>Payload in Request:</b></td><td>Not verified</td></tr>");
            out.append("<tr><td><b>Payload Reflected:</b></td><td>Not verified</td></tr>");
        }

        // Exploitation status
        boolean exploitationConfirmed = payloadReflectedInResponse && Boolean.TRUE.equals(confirmed);
        String exploitStatus = exploitationConfirmed ? "Verified Exploitable" : (payloadReflectedInResponse ? "Likely Exploitable" : "Requires Manual Verification");
        out.append("<tr><td><b>Exploitation Status:</b></td><td>").append(exploitStatus).append("</td></tr>");
        out.append("</table>");

        // Block false positives
        if (!payloadReflectedInResponse && Boolean.TRUE.equals(confirmed)) {
            callbacks.printOutput("[IssueReporter] CRITICAL: CONFIRMED_XSS flag set but payload NOT reflected - BLOCKING issue creation");
            return null;
        }

        // CRITICAL FIX: Only show exploit POC if we have actual proof of vulnerability
        // Don't show misleading exploit code for false positives
        boolean hasActualProof = payloadReflectedInResponse || (testRequestObj != null && testResponseObj != null);
        
        // Optional dynamic POC / steps from DOM/client-side engines (preferred over generic guidance)
        // CRITICAL: Only show if we have actual proof, not just pattern matching
        // Also gated by exploitGeneration setting
        boolean showExploits = settings == null || Boolean.TRUE.equals(settings.getExploitGeneration());
        String exploitPoc = null;
        String reproSteps = null;
        if (hasActualProof && showExploits) {
            exploitPoc = (String) vulnerabilityData.get("EXPLOIT_POC");
            reproSteps = (String) vulnerabilityData.get("REPRODUCTION_STEPS");
            if (exploitPoc != null && !exploitPoc.trim().isEmpty()) {
                out.append("<br><b>Exploit POC</b><br>");
                out.append(formatPlainTextForHtml(exploitPoc, 6000)).append("<br>");
            }
            if (reproSteps != null && !reproSteps.trim().isEmpty()) {
                out.append("<br><b>Reproduction steps</b><br>");
                out.append(formatPlainTextForHtml(reproSteps, 6000)).append("<br>");
            }
        } else if (!hasActualProof) {
            // No actual proof - don't show misleading exploit POC
            out.append("<br><b>Note:</b> Exploit POC not available - no verified payload reflection detected.<br>");
        }
        
        // Ensure reproSteps is initialized even if hasActualProof is false
        if (reproSteps == null) {
            reproSteps = (String) vulnerabilityData.get("REPRODUCTION_STEPS");
        }

        // Client-side indicators and source-sink analysis (detailed mode only)
        if (detailedMode) {
            Object htObj = vulnerabilityData.get("HIGHLIGHT_TERMS");
            if (htObj instanceof List) {
                try {
                    @SuppressWarnings("unchecked")
                    List<String> terms = (List<String>) htObj;
                    if (terms != null && !terms.isEmpty()) {
                        out.append("<br><b>Client-side indicators</b><br><ul>");
                        int cap = Math.min(terms.size(), 12);
                        for (int i = 0; i < cap; i++) {
                            String t = terms.get(i);
                            if (t == null || t.trim().isEmpty()) continue;
                            out.append("<li>").append(escapeHtml(t)).append("</li>");
                        }
                        if (terms.size() > cap) out.append("<li>... and ").append(terms.size() - cap).append(" more</li>");
                        out.append("</ul>");
                    }
                } catch (Exception ignored) {}
            }

            String sourceSink = (String) vulnerabilityData.get("SOURCE_SINK_ANALYSIS");
            if (sourceSink != null && !sourceSink.trim().isEmpty()) {
                out.append("<br><b>Source → Sink analysis</b><br>");
                out.append(formatPlainTextForHtml(sourceSink, 6000)).append("<br>");
            }
        }

        // Avoid duplicating engine-provided reproduction steps: only show generic traffic guidance
        out.append("<br><b>").append((reproSteps != null && !reproSteps.trim().isEmpty()) ? "Traffic" : "Reproduction").append("</b><br>");
        if (haveProofPair) {
            try {
                IRequestInfo exploitedInfo = helpers.analyzeRequest(exploitedRequest);
                out.append("<b>Method:</b> ").append(escapeHtml(exploitedInfo.getMethod())).append("<br>");
                out.append("<b>URL:</b> ").append(escapeHtml(exploitedInfo.getUrl().toString())).append("<br>");
            } catch (Exception ignored) {
                out.append("See exploited request/response for exact traffic.<br>");
            }
        } else {
            out.append("See base request/response for endpoint and parameters.<br>");
        }
        if (haveProofPair && payload != null && bytesContain(exploitedRequest, payload)) {
            out.append("<b>Note:</b> The evidence message includes marker-based highlighting of the injected payload.<br>");
        } else {
            out.append("<b>Note:</b> The evidence message includes marker-based highlighting of detected client-side sinks/sources or risky patterns.<br>");
        }

        return out.toString();
    }

    private String generateBurpSafeIssueBackground(Map<String, Object> vulnerabilityData,
                                                  ModernArchitectureDetector.ArchitectureAnalysis archAnalysis,
                                                  AdvancedJSONAnalyzer.JSONAnalysisResult jsonAnalysis,
                                                  IHttpRequestResponse requestResponse) {
        boolean detailedMode = settings == null || Boolean.TRUE.equals(settings.getDetailedReporting());

        if (!detailedMode) {
            // Compact mode: one-sentence background
            return "Cross-site scripting (XSS) allows attackers to inject malicious scripts into web pages, " +
                   "potentially stealing session tokens, performing actions as the victim, or redirecting to malicious sites.";
        }

        StringBuilder out = new StringBuilder();

        String reflectionContext = bestContext(vulnerabilityData);

        out.append("<b>Vulnerability Overview</b><br><br>");
        out.append("Cross-site scripting (XSS) is a security vulnerability that allows attackers to inject ");
        out.append("malicious scripts into web pages viewed by other users. When user-supplied input is ");
        out.append("included in the response without proper encoding, browsers may execute it as code.<br><br>");

        // Context-specific explanation
        out.append("<b>Context Analysis</b><br>");
        if (reflectionContext == null || reflectionContext.trim().isEmpty()) {
            out.append("The reflection context could not be determined automatically. Manual analysis is ");
            out.append("recommended to identify the specific exploitation vector.<br><br>");
        } else {
            String rc = reflectionContext.toUpperCase(Locale.ROOT);
            if (rc.contains("JAVASCRIPT") || rc.contains("EVENT_HANDLER")) {
                out.append("The input is reflected within a <b>JavaScript context</b>. Attackers can potentially ");
                out.append("break out of string literals or inject code directly into script execution flow.<br><br>");
            } else if (rc.contains("HTML_ATTRIBUTE")) {
                out.append("The input is reflected within an <b>HTML attribute</b>. Depending on the attribute type ");
                out.append("and quoting, attackers may inject event handlers or break out of the attribute context.<br><br>");
            } else if (rc.contains("HTML")) {
                out.append("The input is reflected in the <b>HTML body</b>. Attackers can inject HTML elements ");
                out.append("including script tags or elements with event handlers.<br><br>");
            } else if (rc.contains("JSON")) {
                out.append("The input is reflected in a <b>JSON response</b>. If the JSON is consumed by client-side ");
                out.append("code using unsafe methods (innerHTML, eval), XSS may be exploitable.<br><br>");
            } else if (rc.contains("URL")) {
                out.append("The input is reflected in a <b>URL context</b>. javascript: URLs or manipulation of ");
                out.append("navigation targets may lead to code execution.<br><br>");
            } else {
                out.append("Review the specific context to determine the appropriate exploitation technique.<br><br>");
            }
        }

        out.append("<b>Potential Impact</b><br>");
        out.append("<ul>");
        out.append("<li><b>Session Hijacking:</b> Steal authentication cookies or tokens</li>");
        out.append("<li><b>Account Takeover:</b> Perform actions as the victim user</li>");
        out.append("<li><b>Data Theft:</b> Access sensitive information displayed to the user</li>");
        out.append("<li><b>Malware Distribution:</b> Redirect users to malicious sites</li>");
        out.append("<li><b>Defacement:</b> Modify page content to mislead users</li>");
        out.append("</ul><br>");

        out.append("<b>References</b><br>");
        out.append("<ul>");
        out.append("<li><a href='https://owasp.org/www-community/attacks/xss/'>OWASP - Cross-Site Scripting</a></li>");
        out.append("<li><a href='https://portswigger.net/web-security/cross-site-scripting'>PortSwigger - XSS</a></li>");
        out.append("<li><a href='https://cwe.mitre.org/data/definitions/79.html'>CWE-79: Improper Neutralization</a></li>");
        out.append("</ul>");

        return out.toString();
    }

    private String generateBurpSafeRemediationDetail(ModernArchitectureDetector.ArchitectureAnalysis archAnalysis,
                                                    AdvancedJSONAnalyzer.JSONAnalysisResult jsonAnalysis) {
        boolean detailedMode = settings == null || Boolean.TRUE.equals(settings.getDetailedReporting());

        if (!detailedMode) {
            // Compact mode: brief 2-line remediation
            return "<b>Remediation:</b> Apply context-appropriate output encoding for all user input. " +
                   "Implement a strict Content Security Policy (CSP) to mitigate impact.";
        }

        StringBuilder out = new StringBuilder();

        out.append("<b>Recommended Remediation</b><br><br>");

        out.append("<b>1. Output Encoding (Primary Defense)</b><br>");
        out.append("Apply context-appropriate encoding when including user input in responses:<br>");
        out.append("<ul>");
        out.append("<li><b>HTML Context:</b> Encode &lt; &gt; &amp; \" ' as HTML entities</li>");
        out.append("<li><b>JavaScript Context:</b> Use JavaScript-specific encoding or JSON.stringify()</li>");
        out.append("<li><b>URL Context:</b> Apply URL encoding for parameter values</li>");
        out.append("<li><b>CSS Context:</b> Use CSS-specific encoding</li>");
        out.append("</ul><br>");

        out.append("<b>2. Input Validation</b><br>");
        out.append("Validate and sanitize all user input on the server side. Implement allowlists for ");
        out.append("expected input formats where possible.<br><br>");

        out.append("<b>3. Content Security Policy</b><br>");
        out.append("Implement a strict Content Security Policy (CSP) header to mitigate the impact of XSS ");
        out.append("by restricting script sources and disabling inline scripts.<br><br>");

        out.append("<b>4. Security Libraries</b><br>");
        out.append("Use established security libraries and frameworks that provide automatic encoding ");
        out.append("(e.g., OWASP Java Encoder, DOMPurify for JavaScript).<br>");

        return out.toString();
    }

    private IHttpRequestResponse[] createBurpHighlightedMessages(IHttpRequestResponse requestResponse,
                                                           Map<String, Object> vulnerabilityData) {
        try {
                String paramName = (String) vulnerabilityData.get("paramName");
            String injectedPayload = extractInjectedPayload(vulnerabilityData);
            String originalPayload = extractOriginalPayload(vulnerabilityData);
            String payload = injectedPayload != null ? injectedPayload : originalPayload;

            Object testRequestObj = vulnerabilityData.get("TEST_REQUEST");
            Object testResponseObj = vulnerabilityData.get("TEST_RESPONSE");

            if (payload == null || paramName == null || testRequestObj == null || testResponseObj == null) {
                return new IHttpRequestResponse[] { requestResponse };
            }

            byte[] exploitedRequest = toBytes(testRequestObj);
            byte[] exploitedResponse = toBytes(testResponseObj);
            if (exploitedRequest == null || exploitedResponse == null || exploitedRequest.length == 0 || exploitedResponse.length == 0) {
                return new IHttpRequestResponse[] { requestResponse };
            }
            
            IHttpService httpService = requestResponse.getHttpService();
            
            // Markers (Burp will highlight these ranges and typically scroll to the first match)
            List<int[]> requestMarkers = findBestMarkers(exploitedRequest, payload, originalPayload, false);
            List<int[]> responseMarkers = findBestMarkers(exploitedResponse, payload, originalPayload, true);

            // If payload isn't present (typical for DOM/client-side issues), highlight evidence terms instead.
            if ((requestMarkers == null || requestMarkers.isEmpty()) && (responseMarkers == null || responseMarkers.isEmpty())) {
                Object ht = vulnerabilityData.get("HIGHLIGHT_TERMS");
                if (ht instanceof List) {
                    try {
                        @SuppressWarnings("unchecked")
                        List<String> terms = (List<String>) ht;
                        if (terms != null && !terms.isEmpty()) {
                            List<int[]> evMarkers = new ArrayList<>();
                            for (String t : terms) {
                                if (t == null || t.trim().isEmpty()) continue;
                                evMarkers.addAll(findAllMarkers(exploitedResponse, t.getBytes(StandardCharsets.UTF_8), 10));
                                if (evMarkers.size() >= 50) break;
                            }
                            if (!evMarkers.isEmpty()) {
                                responseMarkers = evMarkers;
                            }
                        }
                    } catch (Exception ignored) {}
                }
            }

            IHttpRequestResponse base = new SimpleHttpRequestResponseWrapper(
                requestResponse.getRequest(),
                requestResponse.getResponse(),
                httpService,
                "Base Request/Response - " + paramName,
                "blue"
            );

            IHttpRequestResponse exploited = new MarkedHttpRequestResponse(
                exploitedRequest,
                exploitedResponse,
                httpService,
                "Evidence / Exploited Request/Response - " + paramName,
                "red",
                requestMarkers,
                responseMarkers
            );

            return new IHttpRequestResponse[] { base, exploited };
            
        } catch (Exception e) {
            callbacks.printError("Error creating Burp highlighted messages: " + e.getMessage());
            return new IHttpRequestResponse[] { requestResponse };
        }
    }

    private byte[] toBytes(Object obj) {
        if (obj instanceof byte[]) return (byte[]) obj;
        if (obj instanceof String) return ((String) obj).getBytes(StandardCharsets.UTF_8);
        return null;
    }

    private String formatPlainTextForHtml(String text, int maxChars) {
        if (text == null) return "";
        String t = text;
        if (maxChars > 0 && t.length() > maxChars) {
            t = t.substring(0, maxChars) + "\n... (truncated)";
        }
        return escapeHtml(t).replace("\r\n", "\n").replace("\n", "<br>");
    }

    private boolean bytesContain(byte[] data, String needle) {
        if (data == null || needle == null || needle.isEmpty()) return false;
        return helpers.indexOf(data, needle.getBytes(StandardCharsets.UTF_8), true, 0, data.length) >= 0;
    }

    private String normalizeParamType(Object paramTypeObj) {
        try {
            int pt;
            if (paramTypeObj instanceof Byte) pt = ((Byte) paramTypeObj).intValue();
            else if (paramTypeObj instanceof Integer) pt = (Integer) paramTypeObj;
            else return String.valueOf(paramTypeObj);
            switch (pt) {
                case 0: return "URL parameter";
                case 1: return "Body parameter";
                case 2: return "Cookie parameter";
                case 3: return "JSON parameter";
                case 4: return "XML parameter";
                case 5: return "XML attribute";
                case 6: return "Multipart attribute";
                default: return "Unknown";
            }
        } catch (Exception e) {
            return String.valueOf(paramTypeObj);
        }
    }

    private String bestContext(Map<String, Object> vulnerabilityData) {
        String ctx = (String) vulnerabilityData.get("REFLECTION_CONTEXT");
        if (ctx == null || ctx.trim().isEmpty() || "UNKNOWN".equalsIgnoreCase(ctx)) {
            ctx = (String) vulnerabilityData.get("BROWSER_EXECUTION_CONTEXT");
        }
        if (ctx == null || ctx.trim().isEmpty() || "UNKNOWN".equalsIgnoreCase(ctx)) {
            ctx = (String) vulnerabilityData.get("ENCODING_CONTEXT");
        }
        return ctx;
    }

    /**
     * Truncate payload for display purposes
     */
    private String truncatePayload(String payload, int maxLength) {
        if (payload == null) return "";
        if (payload.length() <= maxLength) return payload;
        return payload.substring(0, maxLength) + "...";
    }

    /**
     * Format context string for professional display
     */
    private String formatContext(String context) {
        if (context == null || context.trim().isEmpty()) {
            return "Not determined";
        }

        // Convert technical context names to readable format
        String ctx = context.toUpperCase();
        if (ctx.contains("HTML_BODY")) return "HTML Body";
        if (ctx.contains("HTML_ATTRIBUTE")) return "HTML Attribute";
        if (ctx.contains("HTML_TAG")) return "HTML Tag";
        if (ctx.contains("JAVASCRIPT_STRING")) return "JavaScript String";
        if (ctx.contains("JAVASCRIPT") || ctx.contains("JS")) return "JavaScript Context";
        if (ctx.contains("EVENT_HANDLER")) return "Event Handler";
        if (ctx.contains("URL_EXECUTION") || ctx.contains("HREF") || ctx.contains("SRC")) return "URL Context";
        if (ctx.contains("JSON")) return "JSON Context";
        if (ctx.contains("CSS")) return "CSS Context";
        if (ctx.contains("COMMENT")) return "Comment (Safe)";
        if (ctx.contains("CDATA")) return "CDATA Section";

        // Return as-is with proper capitalization
        return context.substring(0, 1).toUpperCase() + context.substring(1).toLowerCase().replace("_", " ");
    }

    private List<int[]> findBestMarkers(byte[] message, String payload, String originalPayload, boolean includeHtmlEncoded) {
        if (message == null) return Collections.emptyList();
        List<String> candidates = new ArrayList<>();
        if (payload != null) {
            candidates.add(payload);
            try { candidates.add(helpers.urlEncode(payload)); } catch (Exception ignored) {}
            if (includeHtmlEncoded) candidates.add(payload.replace("<", "&lt;").replace(">", "&gt;"));
        }
        if (originalPayload != null && (payload == null || !originalPayload.equals(payload))) {
            candidates.add(originalPayload);
            try { candidates.add(helpers.urlEncode(originalPayload)); } catch (Exception ignored) {}
            if (includeHtmlEncoded) candidates.add(originalPayload.replace("<", "&lt;").replace(">", "&gt;"));
        }

        List<int[]> best = Collections.emptyList();
        for (String c : candidates) {
            if (c == null || c.isEmpty()) continue;
            List<int[]> markers = findAllMarkers(message, c.getBytes(StandardCharsets.UTF_8), 50);
            if (markers.size() > best.size()) best = markers;
        }
        return best;
    }

    private List<int[]> findAllMarkers(byte[] data, byte[] pattern, int maxMatches) {
        if (data == null || pattern == null || pattern.length == 0) return Collections.emptyList();
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
     * IHttpRequestResponse wrapper that exposes marker ranges for Burp's raw viewers.
     */
    private static class MarkedHttpRequestResponse implements IHttpRequestResponseWithMarkers {
        private final byte[] request;
        private final byte[] response;
        private final IHttpService httpService;
        private final String comment;
        private final String highlight;
        private final List<int[]> requestMarkers;
        private final List<int[]> responseMarkers;

        MarkedHttpRequestResponse(byte[] request, byte[] response, IHttpService httpService,
                                  String comment, String highlight,
                                  List<int[]> requestMarkers, List<int[]> responseMarkers) {
            this.request = request;
            this.response = response;
            this.httpService = httpService;
            this.comment = comment;
            this.highlight = highlight;
            this.requestMarkers = requestMarkers != null ? requestMarkers : Collections.emptyList();
            this.responseMarkers = responseMarkers != null ? responseMarkers : Collections.emptyList();
        }

        @Override public byte[] getRequest() { return request; }
        @Override public void setRequest(byte[] message) { /* read-only */ }
        @Override public byte[] getResponse() { return response; }
        @Override public void setResponse(byte[] message) { /* read-only */ }
        @Override public String getComment() { return comment; }
        @Override public void setComment(String comment) { /* read-only */ }
        @Override public String getHighlight() { return highlight; }
        @Override public void setHighlight(String color) { /* read-only */ }
        @Override public IHttpService getHttpService() { return httpService; }
        @Override public void setHttpService(IHttpService httpService) { /* read-only */ }

        @Override public List<int[]> getRequestMarkers() { return requestMarkers; }
        @Override public List<int[]> getResponseMarkers() { return responseMarkers; }
    }
    
    /**
     * Create 3 HTTP messages for Burp Suite tabs with actual exploited payloads
     * CRITICAL: Only creates messages if we have actual proof (TEST_REQUEST and TEST_RESPONSE)
     */
    private IHttpRequestResponse[] createHighlightedMessages(IHttpRequestResponse requestResponse,
                                                           Map<String, Object> vulnerabilityData) {
        try {
            String payload = extractRealPayload(vulnerabilityData);
            String paramName = (String) vulnerabilityData.get("paramName");
            
            if (payload == null || paramName == null) {
            return new IHttpRequestResponse[]{requestResponse};
        }
            
            // CRITICAL: MUST have actual test request/response for proof
            Object testRequestObj = vulnerabilityData.get("TEST_REQUEST");
            Object testResponseObj = vulnerabilityData.get("TEST_RESPONSE");
            
            if (testRequestObj == null || testResponseObj == null) {
                // No proof - return original only
                return new IHttpRequestResponse[]{requestResponse};
            }
            
            byte[] exploitedRequest = null;
            byte[] exploitedResponse = null;
            
            // Convert to byte arrays
            if (testRequestObj instanceof byte[]) {
                exploitedRequest = (byte[]) testRequestObj;
            } else if (testRequestObj instanceof String) {
                exploitedRequest = ((String) testRequestObj).getBytes(StandardCharsets.UTF_8);
            }
            
            if (testResponseObj instanceof byte[]) {
                exploitedResponse = (byte[]) testResponseObj;
            } else if (testResponseObj instanceof String) {
                exploitedResponse = ((String) testResponseObj).getBytes(StandardCharsets.UTF_8);
            }
            
            // CRITICAL: Validate we have actual exploited request/response
            if (exploitedRequest == null || exploitedResponse == null || 
                exploitedRequest.length == 0 || exploitedResponse.length == 0) {
                return new IHttpRequestResponse[]{requestResponse};
            }
            
            // CRITICAL: Validate payload is in request and response
            String requestStr = new String(exploitedRequest, StandardCharsets.UTF_8);
            String responseStr = new String(exploitedResponse, StandardCharsets.UTF_8);
            
            if (!requestStr.contains(payload) || !validatePayloadReflection(payload, responseStr)) {
                // Payload not properly injected/reflected - invalid
                return new IHttpRequestResponse[]{requestResponse};
            }
            
            IHttpService httpService = requestResponse.getHttpService();
            
            // Create 3 messages for Burp Suite tabs:
            // [0] Original Request/Response
            // [1] Injected Request (with actual exploited payload in parameter)
            // [2] Injected Response (with actual payload reflection)
            
            IHttpRequestResponse originalMessage = new SimpleHttpRequestResponseWrapper(
                requestResponse.getRequest(), 
                requestResponse.getResponse(), 
                httpService, 
                "Original Request/Response - Parameter: " + paramName,
                "blue"
            );
            
            // [1] Injected Request: Shows the request with payload injected in vulnerable parameter
            // CRITICAL: Use HighlightedHttpRequestResponse to enable payload highlighting in Burp Suite
            IHttpRequestResponse injectedRequestMessage = new HighlightedHttpRequestResponse(
                exploitedRequest,  // ACTUAL exploited request with payload injected in parameter
                new byte[0],  // Empty response for request-only view
                httpService,
                "Injected Request - Parameter: " + paramName + " | Payload: " + 
                (payload.length() > 50 ? payload.substring(0, 50) + "..." : payload),
                "red",
                payload,  // Payload to highlight
                paramName  // Parameter name for context
            );
            
            // [2] Injected Response: Shows the response with payload reflection
            // This tab highlights the payload reflection in the response body
            IHttpRequestResponse injectedResponseMessage = new SimpleHttpRequestResponseWrapper(
                exploitedRequest,  // The request that caused this response (for context)
                exploitedResponse,  // ACTUAL response showing payload reflection with highlighted response code
                httpService,
                "Injected Response - Payload reflected in: " + paramName + " | Payload: " + 
                (payload.length() > 50 ? payload.substring(0, 50) + "..." : payload),
                "red"
            );
            
            return new IHttpRequestResponse[]{
                originalMessage,
                injectedRequestMessage,
                injectedResponseMessage
            };
            
        } catch (Exception e) {
            callbacks.printError("Error creating highlighted messages: " + e.getMessage());
            return new IHttpRequestResponse[]{requestResponse};
        }
    }
    
    // REMOVED: Verbose remediation method - using minimal version instead
    
    private byte[] createRealExploitedRequest(IHttpRequestResponse originalRequest, String paramName, String payload) {
        try {
            IRequestInfo requestInfo = helpers.analyzeRequest(originalRequest);
            List<IParameter> parameters = requestInfo.getParameters();
            
            // Find and replace the target parameter
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
    
    private byte[] createRealExploitedResponse(IHttpRequestResponse originalRequest, String payload, List<int[]> matches) {
        try {
            byte[] originalResponse = originalRequest.getResponse();
            if (originalResponse == null || originalResponse.length == 0) {
                return originalResponse;
            }
            
            // Return original response as-is - Burp Suite will highlight based on matches
            // We don't modify the response body as Burp handles highlighting internally
            return originalResponse;
        } catch (Exception e) {
            return originalRequest.getResponse();
        }
    }
    
    private String extractPathFromRequest(IHttpRequestResponse requestResponse) {
        try {
            if (requestResponse != null && requestResponse.getHttpService() != null) {
                IRequestInfo requestInfo = helpers.analyzeRequest(requestResponse);
                return requestInfo.getUrl().toString();
            }
        } catch (Exception ex) {
            // Ignore
        }
        return "Unknown URL";
    }
    
    private String escapeHtml(String text) {
        if (text == null) return "";

        return text.replace("&", "&amp;")
                  .replace("<", "&lt;")
                  .replace(">", "&gt;")
                  .replace("\"", "&quot;")
                  .replace("'", "&#39;")
                  .replace("`", "&#96;")
                  .replace("/", "&#47;");
    }
    
    private String generateIssueBackground(Map<String, Object> vulnerabilityData,
                                         ModernArchitectureDetector.ArchitectureAnalysis archAnalysis,
                                         AdvancedJSONAnalyzer.JSONAnalysisResult jsonAnalysis,
                                         IHttpRequestResponse requestResponse) {
        StringBuilder background = new StringBuilder();
        
        // Professional HTML structure
        background.append("<html><body style='font-family: Arial, sans-serif; line-height: 1.6; color: #333;'>");
        
        // Issue Background Section
        background.append("<div style='margin-bottom: 30px;'>");
        background.append("<h2 style='color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px;'>Issue Background</h2>");
        background.append("<p>Cross-Site Scripting (XSS) is a web security vulnerability that allows attackers to inject malicious scripts into web pages viewed by other users.</p>");
        background.append("<p>This vulnerability occurs when user input is not properly validated or sanitized before being included in the page output.</p>");
        background.append("</div>");
        
        // CRITICAL: Accepted Malicious Characters on Vulnerable Parameter
        background.append("<div style='margin-bottom: 30px; background-color: #fff3cd; padding: 20px; border-left: 4px solid #ffc107;'>");
        background.append("<h3 style='color: #856404; margin-top: 0;'>Accepted Malicious Characters on Vulnerable Parameter</h3>");
        
        @SuppressWarnings("unchecked")
        List<String> reflectedSymbols = (List<String>) vulnerabilityData.get("REFLECTED_SYMBOLS");
        Object symbolsReflected = vulnerabilityData.get("SYMBOLS_REFLECTED");
        
        if (Boolean.TRUE.equals(symbolsReflected)) {
            if (reflectedSymbols != null && !reflectedSymbols.isEmpty()) {
                background.append("<p><strong>Malicious Characters Accepted and Reflected:</strong></p>");
                background.append("<p style='font-family: monospace; background-color: #fff; padding: 10px; border-radius: 3px;'>");
                for (int i = 0; i < reflectedSymbols.size(); i++) {
                    if (i > 0) background.append(" ");
                    String symbol = reflectedSymbols.get(i);
                    // Escape HTML but show the symbol
                    if (symbol.equals("<")) background.append("&lt;");
                    else if (symbol.equals(">")) background.append("&gt;");
                    else if (symbol.equals("\"")) background.append("&quot;");
                    else if (symbol.equals("'")) background.append("&#39;");
                    else if (symbol.equals("&")) background.append("&amp;");
                    else background.append(escapeHtml(symbol));
                }
                background.append("</p>");
                background.append("<p><strong>Impact:</strong> The application accepts and reflects dangerous characters that can be used to break out of HTML/JavaScript contexts and execute malicious code.</p>");
            } else {
                background.append("<p><strong>Status:</strong> Parameter accepts user input and reflects it in the response without proper encoding.</p>");
                background.append("<p><strong>Tested Characters:</strong> <code>&lt;</code> <code>&gt;</code> <code>&quot;</code> <code>&#39;</code> <code>&amp;</code> <code>;</code> <code>=</code> <code>(</code> <code>)</code> <code>[</code> <code>]</code> <code>{</code> <code>}</code> <code>/</code> <code>\\</code></p>");
            }
        } else {
            background.append("<p><strong>Status:</strong> Parameter value is reflected in the response, enabling XSS exploitation.</p>");
        }
        background.append("</div>");

        // Gather commonly used fields once for the remainder of the background
        String paramName = (String) vulnerabilityData.get("paramName");
        String payload = extractRealPayload(vulnerabilityData);
        String reflectionContext = (String) vulnerabilityData.get("REFLECTION_CONTEXT");
        
        // CRITICAL: Confirmed Exploitation Payload Based on Reflection Context
        background.append("<div style='margin-bottom: 30px; background-color: #f8d7da; padding: 20px; border-left: 4px solid #dc3545;'>");
        background.append("<h3 style='color: #721c24; margin-top: 0;'>Confirmed Exploitation Payload</h3>");
        
        if (payload != null) {
            background.append("<p><strong>Payload:</strong> <code style='background-color: #fff; padding: 5px 10px; border-radius: 3px; color: #dc3545; font-weight: bold; font-size: 110%;'>").append(escapeHtml(payload)).append("</code></p>");
        }
        
        if (reflectionContext != null && !reflectionContext.equals("UNKNOWN")) {
            background.append("<p><strong>Reflection Context:</strong> <code style='background-color: #fff; padding: 3px 8px; border-radius: 3px;'>").append(escapeHtml(reflectionContext)).append("</code></p>");
            
            // Explain how payload was selected based on context
            background.append("<p><strong>Payload Selection Rationale:</strong></p>");
            background.append("<ul>");
            if (reflectionContext.contains("JAVASCRIPT_EXECUTION") || reflectionContext.contains("JAVASCRIPT")) {
                background.append("<li>Context detected: <strong>JavaScript Execution</strong> - Payload designed to break out of JavaScript string and execute code</li>");
                background.append("<li>Payload strategy: Break string context with <code>';</code> or <code>\";</code> and inject executable JavaScript</li>");
            } else if (reflectionContext.contains("EVENT_HANDLER")) {
                background.append("<li>Context detected: <strong>Event Handler</strong> - Payload designed to execute in event handler attribute</li>");
                background.append("<li>Payload strategy: Break attribute context and inject event handler code</li>");
            } else if (reflectionContext.contains("HTML_BODY") || reflectionContext.contains("HTML_TAG")) {
                background.append("<li>Context detected: <strong>HTML Body/Tag</strong> - Payload designed to inject HTML tags</li>");
                background.append("<li>Payload strategy: Break HTML context with <code>&gt;</code> and inject script tags or event handlers</li>");
            } else if (reflectionContext.contains("HTML_ATTRIBUTE")) {
                background.append("<li>Context detected: <strong>HTML Attribute</strong> - Payload designed to break attribute context</li>");
                background.append("<li>Payload strategy: Break attribute with quote and inject event handler or JavaScript</li>");
            } else if (reflectionContext.contains("ATTRIBUTE_URL_EXECUTION") || reflectionContext.contains("URL_EXECUTION")) {
                background.append("<li>Context detected: <strong>URL Execution Context</strong> - Payload designed for URL-based execution</li>");
                background.append("<li>Payload strategy: Use <code>javascript:</code> protocol or data URI for execution</li>");
            } else if (reflectionContext.contains("JSON")) {
                background.append("<li>Context detected: <strong>JSON Context</strong> - Payload designed to break JSON structure</li>");
                background.append("<li>Payload strategy: Break JSON string and inject executable code</li>");
            } else {
                background.append("<li>Context: <strong>").append(escapeHtml(reflectionContext)).append("</strong></li>");
            }
            background.append("</ul>");
        }
        
        Boolean confirmedXSS = (Boolean) vulnerabilityData.get("CONFIRMED_XSS");
        if (confirmedXSS != null && confirmedXSS) {
            background.append("<p style='color: #dc3545; font-weight: bold; font-size: 110%;'>✅ <strong>EXPLOITATION CONFIRMED:</strong> Payload successfully reflected and exploitable in detected context</p>");
        }
        background.append("</div>");
        
        // CRITICAL: Actual Browser Execution Steps
        background.append("<div style='margin-bottom: 30px; background-color: #d1ecf1; padding: 20px; border-left: 4px solid #17a2b8;'>");
        background.append("<h3 style='color: #0c5460; margin-top: 0;'>Actual Browser Execution Steps</h3>");
        background.append("<p>The following steps describe how the browser will process and execute the malicious payload:</p>");
        background.append("<ol style='padding-left: 30px;'>");
        
        if (reflectionContext != null && !reflectionContext.equals("UNKNOWN")) {
            if (reflectionContext.contains("JAVASCRIPT_EXECUTION") || reflectionContext.contains("JAVASCRIPT")) {
                background.append("<li><strong>Request Processing:</strong> User submits request with payload in parameter <code>").append(escapeHtml(paramName)).append("</code></li>");
                background.append("<li><strong>Server Response:</strong> Server reflects payload unencoded in JavaScript execution context</li>");
                background.append("<li><strong>Browser Parsing:</strong> Browser parses HTML and encounters JavaScript code containing the payload</li>");
                background.append("<li><strong>JavaScript Execution:</strong> Browser executes JavaScript, breaking out of string context and executing injected code</li>");
                background.append("<li><strong>Code Execution:</strong> Malicious JavaScript code executes immediately when page loads</li>");
            } else if (reflectionContext.contains("EVENT_HANDLER")) {
                background.append("<li><strong>Request Processing:</strong> User submits request with payload in parameter <code>").append(escapeHtml(paramName)).append("</code></li>");
                background.append("<li><strong>Server Response:</strong> Server reflects payload in HTML event handler attribute (e.g., onload, onclick)</li>");
                background.append("<li><strong>Browser Parsing:</strong> Browser parses HTML and encounters event handler attribute with payload</li>");
                background.append("<li><strong>Event Trigger:</strong> When the event fires (e.g., page load, user click), browser executes the payload as JavaScript</li>");
                background.append("<li><strong>Code Execution:</strong> Malicious JavaScript code executes in response to the event</li>");
            } else if (reflectionContext.contains("HTML_BODY") || reflectionContext.contains("HTML_TAG")) {
                background.append("<li><strong>Request Processing:</strong> User submits request with payload in parameter <code>").append(escapeHtml(paramName)).append("</code></li>");
                background.append("<li><strong>Server Response:</strong> Server reflects payload unencoded in HTML body/tag context</li>");
                background.append("<li><strong>Browser Parsing:</strong> Browser parses HTML and encounters payload as HTML content</li>");
                background.append("<li><strong>HTML Injection:</strong> Browser interprets payload as HTML tags (e.g., &lt;script&gt; tags)</li>");
                background.append("<li><strong>Script Execution:</strong> Browser executes injected script tags or event handlers</li>");
            } else if (reflectionContext.contains("HTML_ATTRIBUTE")) {
                background.append("<li><strong>Request Processing:</strong> User submits request with payload in parameter <code>").append(escapeHtml(paramName)).append("</code></li>");
                background.append("<li><strong>Server Response:</strong> Server reflects payload in HTML attribute value</li>");
                background.append("<li><strong>Browser Parsing:</strong> Browser parses HTML and encounters attribute with payload</li>");
                background.append("<li><strong>Context Break:</strong> Payload breaks out of attribute context using quote characters</li>");
                background.append("<li><strong>Code Execution:</strong> Browser executes injected event handler or JavaScript code</li>");
            } else if (reflectionContext.contains("ATTRIBUTE_URL_EXECUTION") || reflectionContext.contains("URL_EXECUTION")) {
                background.append("<li><strong>Request Processing:</strong> User submits request with payload in parameter <code>").append(escapeHtml(paramName)).append("</code></li>");
                background.append("<li><strong>Server Response:</strong> Server reflects payload in URL attribute (href, src, action)</li>");
                background.append("<li><strong>Browser Parsing:</strong> Browser parses HTML and encounters URL attribute with payload</li>");
                background.append("<li><strong>URL Navigation:</strong> When user interacts with element (click, form submit), browser navigates to payload URL</li>");
                background.append("<li><strong>Protocol Execution:</strong> Browser executes <code>javascript:</code> protocol or data URI, executing malicious code</li>");
            } else {
                background.append("<li><strong>Request Processing:</strong> User submits request with payload in parameter <code>").append(escapeHtml(paramName)).append("</code></li>");
                background.append("<li><strong>Server Response:</strong> Server reflects payload in response</li>");
                background.append("<li><strong>Browser Parsing:</strong> Browser parses response and encounters payload</li>");
                background.append("<li><strong>Context Execution:</strong> Browser executes payload based on reflection context: <code>").append(escapeHtml(reflectionContext)).append("</code></li>");
            }
        } else {
            background.append("<li><strong>Request Processing:</strong> User submits request with payload in parameter <code>").append(escapeHtml(paramName)).append("</code></li>");
            background.append("<li><strong>Server Response:</strong> Server reflects payload unencoded in response</li>");
            background.append("<li><strong>Browser Parsing:</strong> Browser parses HTML response</li>");
            background.append("<li><strong>Code Execution:</strong> Browser executes injected malicious code</li>");
        }
        
        background.append("</ol>");
        background.append("</div>");
        
        // Vulnerable Parameter/Location Details
        String reflectedIn = (String) vulnerabilityData.get("REFLECTED_IN");
        @SuppressWarnings("unchecked")
        List<int[]> matches = (List<int[]>) vulnerabilityData.get("MATCHES");
        
        background.append("<div style='margin-bottom: 30px; background-color: #f8f9fa; padding: 20px; border-left: 4px solid #dc3545;'>");
        background.append("<h3 style='color: #dc3545; margin-top: 0;'>Vulnerable Parameter Details</h3>");
        
        if (paramName != null) {
            background.append("<p><strong>Vulnerable Parameter Name:</strong> <code style='background-color: #fff; padding: 2px 6px; border-radius: 3px;'>").append(escapeHtml(paramName)).append("</code></p>");
        }
        
        try {
            IRequestInfo requestInfo = helpers.analyzeRequest(requestResponse);
            URL url = requestInfo.getUrl();
            background.append("<p><strong>Vulnerable URL:</strong> <code style='background-color: #fff; padding: 2px 6px; border-radius: 3px;'>").append(escapeHtml(url.toString())).append("</code></p>");
            background.append("<p><strong>HTTP Method:</strong> <code style='background-color: #fff; padding: 2px 6px; border-radius: 3px;'>").append(escapeHtml(requestInfo.getMethod())).append("</code></p>");
            
            // Parameter type
            Object paramTypeObj = vulnerabilityData.get("TYPE");
            if (paramTypeObj != null) {
                String paramType = "Unknown";
                if (paramTypeObj instanceof Byte) {
                    byte pt = (Byte) paramTypeObj;
                    switch (pt) {
                        case 0: paramType = "URL Parameter"; break;
                        case 1: paramType = "Body Parameter"; break;
                        case 2: paramType = "Cookie Parameter"; break;
                        case 3: paramType = "JSON Parameter"; break;
                        case 4: paramType = "XML Parameter"; break;
                        case 5: paramType = "XML Attribute"; break;
                        case 6: paramType = "Multipart Attribute"; break;
                    }
                } else if (paramTypeObj instanceof Integer) {
                    int pt = (Integer) paramTypeObj;
                    switch (pt) {
                        case 0: paramType = "URL Parameter"; break;
                        case 1: paramType = "Body Parameter"; break;
                        case 2: paramType = "Cookie Parameter"; break;
                        case 3: paramType = "JSON Parameter"; break;
                        case 4: paramType = "XML Parameter"; break;
                        case 5: paramType = "XML Attribute"; break;
                        case 6: paramType = "Multipart Attribute"; break;
                    }
                }
                background.append("<p><strong>Parameter Type:</strong> ").append(escapeHtml(paramType)).append("</p>");
            }
        } catch (Exception e) {
            // Ignore
        }
        
        background.append("</div>");
        
        // Reflection Details
        background.append("<div style='margin-bottom: 30px; background-color: #fff3cd; padding: 20px; border-left: 4px solid #ffc107;'>");
        background.append("<h3 style='color: #856404; margin-top: 0;'>Payload Reflection Details</h3>");
        
        if (payload != null) {
            background.append("<p><strong>Identified Payload:</strong> <code style='background-color: #fff; padding: 2px 6px; border-radius: 3px; color: #dc3545; font-weight: bold;'>").append(escapeHtml(payload)).append("</code></p>");
        }
        
        if (reflectionContext != null && !reflectionContext.equals("UNKNOWN")) {
            background.append("<p><strong>Reflection Context:</strong> <code style='background-color: #fff; padding: 2px 6px; border-radius: 3px;'>").append(escapeHtml(reflectionContext)).append("</code></p>");
            
            // Explain context
            if (reflectionContext.contains("JAVASCRIPT_EXECUTION")) {
                background.append("<p style='color: #dc3545; font-weight: bold;'>⚠️ CRITICAL: Payload is in JavaScript execution context - browser will execute directly.</p>");
            } else if (reflectionContext.contains("EVENT_HANDLER")) {
                background.append("<p style='color: #dc3545; font-weight: bold;'>⚠️ CRITICAL: Payload is in event handler context - browser will execute on event.</p>");
            } else if (reflectionContext.contains("HTML_BODY") || reflectionContext.contains("HTML_TAG")) {
                background.append("<p style='color: #ffc107; font-weight: bold;'>⚠️ MEDIUM RISK: Payload is in HTML context - browser will parse as HTML.</p>");
            }
        }
        
        if (reflectedIn != null) {
            background.append("<p><strong>Reflection Location:</strong> ").append(escapeHtml(reflectedIn)).append("</p>");
        }
        
        if (matches != null && !matches.isEmpty()) {
            background.append("<p><strong>Reflection Positions:</strong> Payload reflected at ").append(matches.size()).append(" location(s) in the response</p>");
            background.append("<ul>");
            for (int i = 0; i < Math.min(matches.size(), 5); i++) {
                int[] match = matches.get(i);
                if (match.length >= 2) {
                    background.append("<li>Position ").append(i + 1).append(": Offset ").append(match[0]).append(" to ").append(match[1]).append("</li>");
                }
            }
            if (matches.size() > 5) {
                background.append("<li>... and ").append(matches.size() - 5).append(" more location(s)</li>");
            }
            background.append("</ul>");
        }
        
        // Detection details
        String scanType = (String) vulnerabilityData.get("SCAN_TYPE");
        if (scanType != null) {
            background.append("<p><strong>Detection Method:</strong> ").append(escapeHtml(scanType)).append(" XSS Detection Engine</p>");
        }
        
        double confidenceScore = getDouble(vulnerabilityData, "CONFIDENCE_SCORE", -1.0);
        if (confidenceScore >= 0.0) {
            background.append("<p><strong>Confidence Score:</strong> ").append(String.format("%.1f", confidenceScore)).append("%</p>");
        }
        
        background.append("</div>");
        
        // Impact Assessment
        background.append("<div style='margin-bottom: 30px;'>");
        background.append("<h3 style='color: #2c3e50; border-bottom: 2px solid #e74c3c; padding-bottom: 10px;'>Impact Assessment</h3>");
        background.append("<p><strong>Potential Impact:</strong></p>");
        background.append("<ul>");
        background.append("<li><strong>Session Hijacking:</strong> Steal user session cookies and authentication tokens</li>");
        background.append("<li><strong>Account Takeover:</strong> Perform actions on behalf of authenticated users</li>");
        background.append("<li><strong>Data Theft:</strong> Extract sensitive information from the page (credentials, personal data)</li>");
        background.append("<li><strong>Phishing:</strong> Create convincing phishing pages within the vulnerable application</li>");
        background.append("<li><strong>Defacement:</strong> Modify page content to display malicious messages</li>");
        background.append("<li><strong>Malware Distribution:</strong> Redirect users to malicious sites or download malware</li>");
        background.append("</ul>");
        background.append("</div>");
        
        // OWASP Classification
        background.append("<div style='margin-bottom: 30px;'>");
        background.append("<h3 style='color: #2c3e50; border-bottom: 2px solid #9b59b6; padding-bottom: 10px;'>OWASP Classification</h3>");
        background.append("<p>This vulnerability is classified under <strong>OWASP Top 10 2021 - A03:2021 Injection</strong> and specifically falls under:</p>");
        background.append("<ul>");
        background.append("<li><strong>Reflected XSS:</strong> Malicious script is reflected off the web server in response to a request</li>");
        background.append("<li><strong>Stored XSS:</strong> Malicious script is stored on the server and executed when accessed</li>");
        background.append("<li><strong>DOM-based XSS:</strong> Vulnerability exists in client-side code rather than server-side code</li>");
        background.append("</ul>");
        background.append("</div>");
        
        // CVSS Scoring
        background.append("<div style='margin-bottom: 30px;'>");
        background.append("<h3 style='color: #2c3e50; border-bottom: 2px solid #27ae60; padding-bottom: 10px;'>CVSS Scoring</h3>");
        background.append("<p><strong>Base Score:</strong> 6.1 (Medium) - CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N</p>");
        background.append("<p><strong>Explanation:</strong></p>");
        background.append("<ul>");
        background.append("<li><strong>Attack Vector (AV):</strong> Network - exploitable over network</li>");
        background.append("<li><strong>Attack Complexity (AC):</strong> Low - no special conditions required</li>");
        background.append("<li><strong>Privileges Required (PR):</strong> None - no authentication needed</li>");
        background.append("<li><strong>User Interaction (UI):</strong> Required - user must interact with malicious link</li>");
        background.append("<li><strong>Scope (S):</strong> Changed - can affect other components</li>");
        background.append("<li><strong>Confidentiality (C):</strong> Low - limited information disclosure</li>");
        background.append("<li><strong>Integrity (I):</strong> Low - limited data modification</li>");
        background.append("<li><strong>Availability (A):</strong> None - no availability impact</li>");
        background.append("</ul>");
        background.append("</div>");
        
        background.append("</body></html>");
        
        return background.toString();
    }
    
    private class EnhancedScanIssue implements IScanIssue {
        private final IHttpService httpService;
        private final URL url;
        private final IHttpRequestResponse[] httpMessages;
        private final String name;
        private final String detail;
        private final SeverityLevel severity;
        private final ConfidenceLevel confidence;
        private final String remediationDetail;
        private final String issueBackground;
        
        public EnhancedScanIssue(IHttpService httpService, URL url, IHttpRequestResponse[] httpMessages,
                               String name, String detail, SeverityLevel severity, ConfidenceLevel confidence,
                               String remediationDetail, String issueBackground) {
            this.httpService = httpService;
            this.url = url;
            this.httpMessages = httpMessages;
            this.name = name;
            this.detail = detail;
            this.severity = severity;
            this.confidence = confidence;
            this.remediationDetail = remediationDetail;
            this.issueBackground = issueBackground;
        }
        
        @Override
        public URL getUrl() { return url; }
        
        @Override
        public String getIssueName() { return name; }
        
        @Override
        public int getIssueType() {
            return 0x00400000; // Reflected XSS
        }
        
        @Override
        public String getSeverity() { return severity.getBurpSeverity(); }
        
        @Override
        public String getConfidence() { return confidence.getDisplayName(); }
        
        @Override
        // Static background/remediation intentionally suppressed: issues carry
        // only live, dynamic evidence to stay consistent across all detectors.
        public String getIssueBackground() { return ""; }

        @Override
        public String getRemediationBackground() { return ""; }

        @Override
        public String getIssueDetail() {
            return detail;
        }

        @Override
        public String getRemediationDetail() { return ""; }
        
        @Override
        public IHttpRequestResponse[] getHttpMessages() { return httpMessages; }
        
        @Override
        public IHttpService getHttpService() { return httpService; }
    }
    
    /**
     * Wrapper class for creating IHttpRequestResponse from actual request/response data
     * Used for displaying real exploited evidence in Burp Suite tabs
     */
    private static class SimpleHttpRequestResponseWrapper implements IHttpRequestResponse {
        private final byte[] request;
        private final byte[] response;
        private final IHttpService httpService;
        private final String comment;
        private final String highlight;
        
        public SimpleHttpRequestResponseWrapper(byte[] request, byte[] response, 
                                          IHttpService httpService, String comment, String highlight) {
            this.request = request;
            this.response = response;
            this.httpService = httpService;
            this.comment = comment;
            this.highlight = highlight;
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
        public String getComment() { return comment; }
        
        @Override
        public void setComment(String comment) { /* Read-only */ }
        
        @Override
        public String getHighlight() { return highlight; }
        
        @Override
        public void setHighlight(String color) { /* Read-only */ }
        
        @Override
        public IHttpService getHttpService() { return httpService; }
        
        @Override
        public void setHttpService(IHttpService httpService) { /* Read-only */ }
    }
    
    /**
     * CRITICAL: Custom IHttpRequestResponse implementation with payload highlighting support
     * This enables Burp Suite to automatically highlight the payload in the raw request view
     */
    private static class HighlightedHttpRequestResponse implements IHttpRequestResponse {
        private final byte[] request;
        private final byte[] response;
        private final IHttpService httpService;
        private final String comment;
        private final String highlight;
        private final String payload;
        private final String paramName;
        
        public HighlightedHttpRequestResponse(byte[] request, byte[] response, 
                                            IHttpService httpService, String comment, String highlight,
                                            String payload, String paramName) {
            this.request = request;
            this.response = response;
            this.httpService = httpService;
            this.comment = comment;
            this.highlight = highlight;
            this.payload = payload;
            this.paramName = paramName;
        }
        
        @Override
        public byte[] getRequest() { 
            // Burp Suite will automatically highlight matching content
            // The payload is already in the request, so Burp will find and highlight it
            return request; 
        }
        
        @Override
        public void setRequest(byte[] message) { /* Read-only */ }
        
        @Override
        public byte[] getResponse() { return response; }
        
        @Override
        public void setResponse(byte[] message) { /* Read-only */ }
        
        @Override
        public String getComment() { 
            // Include payload info in comment for better visibility
            return comment + " [Payload in parameter: " + paramName + "]";
        }
        
        @Override
        public void setComment(String comment) { /* Read-only */ }
        
        @Override
        public String getHighlight() { return highlight; }
        
        @Override
        public void setHighlight(String color) { /* Read-only */ }
        
        @Override
        public IHttpService getHttpService() { return httpService; }
        
        @Override
        public void setHttpService(IHttpService httpService) { /* Read-only */ }
    }
} 