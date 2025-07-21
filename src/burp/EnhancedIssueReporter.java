package burp;

import java.util.*;
import java.util.regex.Pattern;
import java.util.regex.Matcher;
import java.net.URL;
import java.nio.charset.StandardCharsets;
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
     * Validate if vulnerability is truly exploitable
     */
    private boolean isVulnerabilityTrulyExploitable(Map<String, Object> vulnerabilityData) {
        try {
            String realRequest = (String) vulnerabilityData.get("TEST_REQUEST");
            String realResponse = (String) vulnerabilityData.get("TEST_RESPONSE");
            String payload = (String) vulnerabilityData.get("payload");
            
            if (realRequest == null || realResponse == null || payload == null) {
                return false;
            }
            
            if (!realResponse.contains(payload)) {
                return false;
            }
            
            String paramName = (String) vulnerabilityData.get("paramName");
            if (paramName == null || paramName.trim().isEmpty()) {
                return false;
            }
            
            return true;
            
        } catch (Exception e) {
            callbacks.printError("Error validating vulnerability: " + e.getMessage());
            return false;
        }
    }
    
    /**
     * Validate payload reflection
     */
    private boolean validatePayloadReflection(String payload, String response) {
        if (response.contains(payload)) {
            return true;
        }
        
        String htmlEncoded = payload.replace("<", "&lt;").replace(">", "&gt;")
                                   .replace("\"", "&quot;").replace("'", "&#39;");
        if (response.contains(htmlEncoded)) {
            return true;
        }
        
        String urlEncoded = helpers.urlEncode(payload);
        if (response.contains(urlEncoded)) {
            return true;
        }
        
        String[] payloadParts = payload.split("[<>\"'()]");
        int foundParts = 0;
        for (String part : payloadParts) {
            if (part.length() > 3 && response.contains(part)) {
                foundParts++;
            }
        }
        
        return foundParts >= payloadParts.length / 2;
    }
    
    /**
     * Create enhanced XSS issue with professional reporting
     */
    public IScanIssue createEnhancedXSSIssue(IHttpRequestResponse requestResponse, 
                                            Map<String, Object> vulnerabilityData) {
        try {
            if (!isVulnerabilityTrulyExploitable(vulnerabilityData)) {
                return null;
            }
            
            String payload = extractRealPayload(vulnerabilityData);
            if (payload == null || payload.trim().isEmpty()) {
                return null;
            }
            
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
            String advisoryDetail = generateEnhancedIssueDetail(requestResponse, vulnerabilityData, 
                                                           archAnalysis, jsonAnalysis, severity, confidence);
            
            // Create HTTP messages with exploited request/response
            IHttpRequestResponse[] httpMessages = createHighlightedMessages(requestResponse, vulnerabilityData);
            
            // Create the issue
            return new EnhancedScanIssue(
                requestResponse.getHttpService(),
                helpers.analyzeRequest(requestResponse).getUrl(),
                httpMessages,
                issueName,
                advisoryDetail,
                severity,
                confidence,
                generateRemediationDetail(archAnalysis, jsonAnalysis),
                generateIssueBackground(archAnalysis, jsonAnalysis)
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
        Double xssScore = (Double) vulnerabilityData.get("XSS_SCORE");
        if (xssScore != null) {
            severityScore = xssScore;
        }
        
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
        Double existingConfidence = (Double) vulnerabilityData.get("CONFIDENCE_SCORE");
        if (existingConfidence != null) {
            confidenceScore = existingConfidence;
        }
        
        // Boost for confirmed XSS
        Boolean confirmed = (Boolean) vulnerabilityData.get("CONFIRMED_XSS");
        if (confirmed != null && confirmed) {
            confidenceScore = 100.0;
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
    
    private String extractRealPayload(Map<String, Object> vulnerabilityData) {
        String payload = (String) vulnerabilityData.get("payload");
        if (payload != null && !payload.trim().isEmpty()) {
            return payload;
        }
        
        payload = (String) vulnerabilityData.get("PAYLOAD");
        if (payload != null && !payload.trim().isEmpty()) {
                    return payload;
        }
        
        String scanType = (String) vulnerabilityData.get("SCAN_TYPE");
        if ("Basic".equals(scanType)) {
            return "<script>alert('XSS')</script>";
        } else if ("Advanced".equals(scanType)) {
            return "<script>alert('Advanced_XSS')</script>";
        }
        
            return "<script>alert('XSS')</script>";
    }
    
    private String generateIssueName(Map<String, Object> vulnerabilityData,
                                   ModernArchitectureDetector.ArchitectureAnalysis archAnalysis,
                                   AdvancedJSONAnalyzer.JSONAnalysisResult jsonAnalysis,
                                   IHttpRequestResponse requestResponse) {
        String paramName = (String) vulnerabilityData.get("paramName");
        if (paramName == null || paramName.trim().isEmpty()) {
            paramName = "parameter";
        }
        
        String scanType = (String) vulnerabilityData.get("SCAN_TYPE");
        if (scanType == null) {
            scanType = "XSS";
        }
        
        Boolean confirmed = (Boolean) vulnerabilityData.get("CONFIRMED_XSS");
        if (confirmed != null && confirmed) {
            return "CONFIRMED XSS - " + paramName;
        }
        
        if ("Basic".equals(scanType)) {
            return "Basic XSS - " + paramName;
            } else if ("Advanced".equals(scanType)) {
                return "Advanced XSS - " + paramName;
        }
        
        return "XSS Vulnerability - " + paramName;
    }
    
    private String generateEnhancedIssueDetail(IHttpRequestResponse requestResponse,
                                             Map<String, Object> vulnerabilityData,
                                             ModernArchitectureDetector.ArchitectureAnalysis archAnalysis,
                                             AdvancedJSONAnalyzer.JSONAnalysisResult jsonAnalysis,
                                             SeverityLevel severity,
                                             ConfidenceLevel confidence) {
        StringBuilder detail = new StringBuilder();
        
        detail.append("<h2>XSS Vulnerability Advisory</h2>");
        detail.append("<p><strong>Severity:</strong> ").append(severity.getDisplayName()).append("</p>");
        detail.append("<p><strong>Confidence:</strong> ").append(confidence.getDisplayName()).append("</p>");
        
        String payload = extractRealPayload(vulnerabilityData);
        String paramName = (String) vulnerabilityData.get("paramName");
        
        detail.append("<h3>Vulnerability Summary</h3>");
        detail.append("<p>A Cross-Site Scripting (XSS) vulnerability has been detected in the parameter <code>").append(paramName).append("</code>.</p>");
        detail.append("<p><strong>Confirmed Payload:</strong> <code>").append(escapeHtml(payload)).append("</code></p>");
        
        String detectionMethod = "Advanced XSS Detection Engine";
        detail.append("<p><strong>Detection Method:</strong> ").append(detectionMethod).append("</p>");
        
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
        
        // Add context analysis
        String enhancedContext = (String) vulnerabilityData.get("ENHANCED_CONTEXT");
        if (enhancedContext != null && !enhancedContext.trim().isEmpty()) {
            detail.append("<h3>Context Analysis</h3>");
            detail.append("<p>").append(escapeHtml(enhancedContext)).append("</p>");
        }
        
        return detail.toString();
    }
    
    private IHttpRequestResponse[] createHighlightedMessages(IHttpRequestResponse requestResponse,
                                                           Map<String, Object> vulnerabilityData) {
        try {
            String payload = extractRealPayload(vulnerabilityData);
                String paramName = (String) vulnerabilityData.get("paramName");
            
            // Create exploited request/response
            byte[] exploitedRequest = createRealExploitedRequest(requestResponse, paramName, payload);
            @SuppressWarnings("unchecked")
            List<int[]> matches = (List<int[]>) vulnerabilityData.get("MATCHES");
            byte[] exploitedResponse = createRealExploitedResponse(requestResponse, payload, matches);
            
            IHttpService httpService = requestResponse.getHttpService();
            
            IHttpRequestResponse exploitedMessage = new SimpleTestHttpRequestResponse(
                exploitedRequest, exploitedResponse, httpService, 
                "Exploited XSS Request/Response", "red"
            );
            
            return new IHttpRequestResponse[]{exploitedMessage};
            
        } catch (Exception e) {
            callbacks.printError("Error creating highlighted messages: " + e.getMessage());
            return new IHttpRequestResponse[]{requestResponse};
        }
    }
    
    private String generateRemediationDetail(ModernArchitectureDetector.ArchitectureAnalysis archAnalysis,
                                           AdvancedJSONAnalyzer.JSONAnalysisResult jsonAnalysis) {
        StringBuilder remediation = new StringBuilder();
        
        remediation.append("<h3>Remediation</h3>");
        remediation.append("<p><strong>Immediate Actions:</strong></p>");
        remediation.append("<ul>");
        remediation.append("<li>Implement proper input validation and sanitization</li>");
        remediation.append("<li>Use output encoding for all user-controlled data</li>");
        remediation.append("<li>Implement Content Security Policy (CSP)</li>");
        remediation.append("<li>Use modern frameworks with built-in XSS protection</li>");
        remediation.append("</ul>");
        
        remediation.append("<p><strong>Long-term Solutions:</strong></p>");
        remediation.append("<ul>");
        remediation.append("<li>Regular security testing and code reviews</li>");
        remediation.append("<li>Security training for development teams</li>");
        remediation.append("<li>Implement automated security scanning in CI/CD</li>");
        remediation.append("</ul>");
        
        return remediation.toString();
    }
    
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
            String responseBody = new String(originalResponse);
            
            // Highlight payload in response
            String highlightedResponse = highlightPayloadsInResponse(responseBody, payload);
            
            return highlightedResponse.getBytes(StandardCharsets.UTF_8);
        } catch (Exception e) {
            return originalRequest.getResponse();
        }
    }
    
    private String highlightPayloadsInResponse(String response, String payload) {
        if (payload == null || payload.isEmpty()) {
            return response;
        }
        
        return response.replace(payload, "<mark style='background-color: yellow;'>" + payload + "</mark>");
    }
    
    private String extractPathFromRequest(IHttpRequestResponse requestResponse) {
        try {
            IRequestInfo requestInfo = helpers.analyzeRequest(requestResponse);
            return requestInfo.getUrl().toString();
            } catch (Exception e) {
            return "http://example.com";
        }
    }
    
    private String escapeHtml(String text) {
        if (text == null) return "";
        
        return text.replace("&", "&amp;")
                  .replace("<", "&lt;")
                  .replace(">", "&gt;")
                  .replace("\"", "&quot;")
                   .replace("'", "&#39;");
    }
    
    private String generateIssueBackground(ModernArchitectureDetector.ArchitectureAnalysis archAnalysis,
                                         AdvancedJSONAnalyzer.JSONAnalysisResult jsonAnalysis) {
        StringBuilder background = new StringBuilder();
        
        background.append("<h3>Issue Background</h3>");
        background.append("<p>Cross-Site Scripting (XSS) is a web security vulnerability that allows attackers to inject malicious scripts into web pages viewed by other users.</p>");
        background.append("<p>This vulnerability occurs when user input is not properly validated or sanitized before being included in the page output.</p>");
        
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
        public String getIssueBackground() { return issueBackground; }
        
        @Override
        public String getRemediationBackground() {
            return remediationDetail;
        }
        
        @Override
        public String getIssueDetail() { 
            return detail;
        }
        
        @Override
        public String getRemediationDetail() { return remediationDetail; }
        
        @Override
        public IHttpRequestResponse[] getHttpMessages() { return httpMessages; }
        
        @Override
        public IHttpService getHttpService() { return httpService; }
    }
    
    private static class SimpleTestHttpRequestResponse implements IHttpRequestResponse {
        private final byte[] request;
        private final byte[] response;
        private final IHttpService httpService;
        private final String comment;
        private final String highlight;
        
        public SimpleTestHttpRequestResponse(byte[] request, byte[] response, 
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
} 