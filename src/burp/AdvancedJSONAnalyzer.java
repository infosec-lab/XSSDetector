package burp;

import java.util.*;
import java.util.regex.Pattern;
import java.util.regex.Matcher;
import java.io.*;
import java.nio.charset.StandardCharsets;

/**
 * Advanced JSON/API Response Analyzer for XSSDetector
 * Handles modern API responses including nested JSON, GraphQL, and streaming APIs
 */
public class AdvancedJSONAnalyzer {
    
    private final IExtensionHelpers helpers;
    private final IBurpExtenderCallbacks callbacks;
    private final Settings settings;
    
    // JSON patterns for detection
    private static final Pattern JSON_PATTERN = Pattern.compile("^\\s*[\\{\\[].*[\\}\\]]\\s*$", Pattern.DOTALL);
    private static final Pattern JSONP_PATTERN = Pattern.compile("^\\s*[\\w$]+\\s*\\(\\s*[\\{\\[].*[\\}\\]]\\s*\\)\\s*;?\\s*$", Pattern.DOTALL);
    private static final Pattern GRAPHQL_PATTERN = Pattern.compile("\"data\"\\s*:\\s*\\{.*\\}", Pattern.DOTALL);
    
    // Modern API content types
    private static final String[] JSON_CONTENT_TYPES = {
        "application/json", "application/hal+json", "application/vnd.api+json",
        "application/ld+json", "application/json-patch+json", "application/merge-patch+json",
        "application/vnd.github+json", "application/vnd.api+json", "text/json"
    };
    
    private static final String[] API_CONTENT_TYPES = {
        "application/graphql", "application/x-ndjson", "application/json-seq",
        "application/stream+json", "text/event-stream", "application/vnd.api+json"
    };
    
    // XSS dangerous JSON contexts
    private static final String[] DANGEROUS_JSON_FIELDS = {
        "html", "content", "message", "description", "innerHTML", "outerHTML",
        "script", "code", "eval", "javascript", "url", "href", "src", "action",
        "onclick", "onload", "onerror", "onmouseover", "onfocus", "onblur"
    };
    
    public AdvancedJSONAnalyzer(IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks, Settings settings) {
        this.helpers = helpers;
        this.callbacks = callbacks;
        this.settings = settings;
    }
    
    /**
     * Comprehensive JSON/API response analysis
     */
    public JSONAnalysisResult analyzeJSONResponse(IHttpRequestResponse requestResponse) {
        JSONAnalysisResult result = new JSONAnalysisResult();
        
        try {
            // Extract response body
            byte[] response = requestResponse.getResponse();
            int bodyOffset = helpers.analyzeResponse(response).getBodyOffset();
            String responseBody = new String(Arrays.copyOfRange(response, bodyOffset, response.length), StandardCharsets.UTF_8);
            
            // Analyze content type
            String contentType = getContentType(requestResponse);
            result.setContentType(contentType);
            
            // Determine JSON type
            JSONType jsonType = determineJSONType(responseBody, contentType);
            result.setJsonType(jsonType);
            
            if (jsonType != JSONType.NOT_JSON) {
                // Parse JSON structure
                result.setJsonStructure(parseJSONStructure(responseBody, jsonType));
                
                // Analyze XSS risks
                result.setXssRisks(analyzeXSSRisks(responseBody, jsonType));
                
                // Check for dangerous patterns
                result.setDangerousPatterns(findDangerousPatterns(responseBody));
                
                // Generate security recommendations
                result.setSecurityRecommendations(generateSecurityRecommendations(result));
                
                // Calculate risk score
                result.setRiskScore(calculateRiskScore(result));
            }
            
        } catch (Exception e) {
            callbacks.printError("JSON analysis error: " + e.getMessage());
        }
        
        return result;
    }
    
    /**
     * Determine JSON type from response
     */
    private JSONType determineJSONType(String responseBody, String contentType) {
        if (contentType.contains("application/graphql") || 
            GRAPHQL_PATTERN.matcher(responseBody).find()) {
            return JSONType.GRAPHQL;
        }
        
        if (JSONP_PATTERN.matcher(responseBody).find()) {
            return JSONType.JSONP;
        }
        
        if (contentType.contains("text/event-stream") || 
            responseBody.contains("data: {")) {
            return JSONType.STREAMING;
        }
        
        if (contentType.contains("application/x-ndjson") || 
            responseBody.contains("}\n{")) {
            return JSONType.NDJSON;
        }
        
        if (JSON_PATTERN.matcher(responseBody).find()) {
            return responseBody.trim().startsWith("[") ? JSONType.JSON_ARRAY : JSONType.JSON_OBJECT;
        }
        
        return JSONType.NOT_JSON;
    }
    
    /**
     * Parse JSON structure for analysis
     */
    private JSONStructure parseJSONStructure(String responseBody, JSONType jsonType) {
        JSONStructure structure = new JSONStructure();
        
        try {
            switch (jsonType) {
                case GRAPHQL:
                    structure = parseGraphQLStructure(responseBody);
                    break;
                case JSONP:
                    structure = parseJSONPStructure(responseBody);
                    break;
                case STREAMING:
                    structure = parseStreamingStructure(responseBody);
                    break;
                case NDJSON:
                    structure = parseNDJSONStructure(responseBody);
                    break;
                case JSON_OBJECT:
                case JSON_ARRAY:
                    structure = parseStandardJSONStructure(responseBody);
                    break;
            }
        } catch (Exception e) {
            callbacks.printError("JSON parsing error: " + e.getMessage());
        }
        
        return structure;
    }
    
    /**
     * Parse GraphQL response structure
     */
    private JSONStructure parseGraphQLStructure(String responseBody) {
        JSONStructure structure = new JSONStructure();
        structure.setType("GraphQL");
        
        // Extract GraphQL-specific fields
        if (responseBody.contains("\"data\"")) {
            structure.addField("data", "object");
        }
        if (responseBody.contains("\"errors\"")) {
            structure.addField("errors", "array");
        }
        if (responseBody.contains("\"extensions\"")) {
            structure.addField("extensions", "object");
        }
        
        // Find nested user data
        extractNestedFields(responseBody, structure, 0);
        
        return structure;
    }
    
    /**
     * Parse JSONP response structure
     */
    private JSONStructure parseJSONPStructure(String responseBody) {
        JSONStructure structure = new JSONStructure();
        structure.setType("JSONP");
        
        // Extract callback function name
        Matcher matcher = Pattern.compile("^\\s*([\\w$]+)\\s*\\(").matcher(responseBody);
        if (matcher.find()) {
            structure.setCallbackFunction(matcher.group(1));
        }
        
        // Parse JSON content inside callback
        int start = responseBody.indexOf("(") + 1;
        int end = responseBody.lastIndexOf(")");
        if (start > 0 && end > start) {
            String jsonContent = responseBody.substring(start, end);
            extractNestedFields(jsonContent, structure, 0);
        }
        
        return structure;
    }
    
    /**
     * Parse streaming JSON structure
     */
    private JSONStructure parseStreamingStructure(String responseBody) {
        JSONStructure structure = new JSONStructure();
        structure.setType("Streaming");
        
        // Split by lines for Server-Sent Events
        String[] lines = responseBody.split("\n");
        for (String line : lines) {
            if (line.startsWith("data: ")) {
                String data = line.substring(6);
                if (data.startsWith("{")) {
                    extractNestedFields(data, structure, 0);
                }
            }
        }
        
        return structure;
    }
    
    /**
     * Parse newline-delimited JSON structure
     */
    private JSONStructure parseNDJSONStructure(String responseBody) {
        JSONStructure structure = new JSONStructure();
        structure.setType("NDJSON");
        
        // Split by lines
        String[] lines = responseBody.split("\n");
        for (String line : lines) {
            if (line.trim().startsWith("{")) {
                extractNestedFields(line, structure, 0);
            }
        }
        
        return structure;
    }
    
    /**
     * Parse standard JSON structure
     */
    private JSONStructure parseStandardJSONStructure(String responseBody) {
        JSONStructure structure = new JSONStructure();
        structure.setType("Standard JSON");
        
        extractNestedFields(responseBody, structure, 0);
        
        return structure;
    }
    
    /**
     * Extract nested fields from JSON content
     */
    private void extractNestedFields(String jsonContent, JSONStructure structure, int depth) {
        if (depth > 10) return; // Prevent infinite recursion
        
        // Simple field extraction using regex
        Pattern fieldPattern = Pattern.compile("\"([^\"]+)\"\\s*:\\s*([^,}\\]]+)");
        Matcher matcher = fieldPattern.matcher(jsonContent);
        
        while (matcher.find()) {
            String fieldName = matcher.group(1);
            String fieldValue = matcher.group(2).trim();
            
            // Determine field type
            String fieldType = "string";
            if (fieldValue.startsWith("{")) {
                fieldType = "object";
            } else if (fieldValue.startsWith("[")) {
                fieldType = "array";
            } else if (fieldValue.matches("\\d+")) {
                fieldType = "number";
            } else if (fieldValue.equals("true") || fieldValue.equals("false")) {
                fieldType = "boolean";
            }
            
            structure.addField(fieldName, fieldType);
            
            // Check for dangerous field names
            for (String dangerous : DANGEROUS_JSON_FIELDS) {
                if (fieldName.toLowerCase().contains(dangerous.toLowerCase())) {
                    structure.addDangerousField(fieldName, fieldValue);
                    break;
                }
            }
        }
    }
    
    /**
     * Analyze XSS risks in JSON response
     */
    private List<String> analyzeXSSRisks(String responseBody, JSONType jsonType) {
        List<String> risks = new ArrayList<>();
        
        // Check for script injection risks
        if (responseBody.contains("<script") || responseBody.contains("javascript:")) {
            risks.add("Script injection detected in JSON response");
        }
        
        // Check for HTML injection risks
        if (responseBody.contains("<") && responseBody.contains(">")) {
            risks.add("HTML content detected in JSON response");
        }
        
        // Check for event handler risks
        String[] eventHandlers = {"onclick", "onload", "onerror", "onmouseover", "onfocus"};
        for (String handler : eventHandlers) {
            if (responseBody.toLowerCase().contains(handler)) {
                risks.add("Event handler '" + handler + "' detected in JSON response");
            }
        }
        
        // Check for URL injection risks
        if (responseBody.contains("javascript:") || responseBody.contains("data:text/html")) {
            risks.add("Dangerous URL scheme detected in JSON response");
        }
        
        // Check for template injection risks
        if (responseBody.contains("{{") || responseBody.contains("${")) {
            risks.add("Template injection patterns detected in JSON response");
        }
        
        // JSONP-specific risks
        if (jsonType == JSONType.JSONP) {
            risks.add("JSONP callback function may be vulnerable to injection");
        }
        
        // GraphQL-specific risks
        if (jsonType == JSONType.GRAPHQL) {
            if (responseBody.contains("\"errors\"")) {
                risks.add("GraphQL errors may contain sensitive information");
            }
        }
        
        return risks;
    }
    
    /**
     * Find dangerous patterns in JSON response
     */
    private List<String> findDangerousPatterns(String responseBody) {
        List<String> patterns = new ArrayList<>();
        
        // XSS patterns
        String[] xssPatterns = {
            "<script[^>]*>.*?</script>",
            "javascript:\\s*[^\\s]",
            "on\\w+\\s*=\\s*[\"'][^\"']*[\"']",
            "data:text/html[^\\s]*",
            "eval\\s*\\(",
            "Function\\s*\\(",
            "setTimeout\\s*\\(",
            "setInterval\\s*\\("
        };
        
        for (String pattern : xssPatterns) {
            if (Pattern.compile(pattern, Pattern.CASE_INSENSITIVE).matcher(responseBody).find()) {
                patterns.add("XSS pattern: " + pattern);
            }
        }
        
        // SQL injection patterns (sometimes in JSON APIs)
        String[] sqlPatterns = {
            "union\\s+select",
            "drop\\s+table",
            "insert\\s+into",
            "delete\\s+from",
            "update\\s+set"
        };
        
        for (String pattern : sqlPatterns) {
            if (Pattern.compile(pattern, Pattern.CASE_INSENSITIVE).matcher(responseBody).find()) {
                patterns.add("SQL injection pattern: " + pattern);
            }
        }
        
        return patterns;
    }
    
    /**
     * Generate security recommendations
     */
    private List<String> generateSecurityRecommendations(JSONAnalysisResult result) {
        List<String> recommendations = new ArrayList<>();
        
        // General JSON security
        recommendations.add("Implement proper JSON schema validation");
        recommendations.add("Use Content-Security-Policy headers");
        recommendations.add("Sanitize all user-controlled data in JSON responses");
        
        // Type-specific recommendations
        switch (result.getJsonType()) {
            case GRAPHQL:
                recommendations.add("Implement GraphQL query depth limiting");
                recommendations.add("Disable introspection in production");
                recommendations.add("Use GraphQL query whitelisting");
                break;
            case JSONP:
                recommendations.add("Validate JSONP callback function names");
                recommendations.add("Consider migrating to CORS instead of JSONP");
                recommendations.add("Implement strict callback validation");
                break;
            case STREAMING:
                recommendations.add("Implement rate limiting for streaming endpoints");
                recommendations.add("Validate streaming data before transmission");
                break;
        }
        
        // Risk-based recommendations
        if (result.getRiskScore() > 70) {
            recommendations.add("HIGH RISK: Immediate security review required");
            recommendations.add("Consider implementing Web Application Firewall");
        }
        
        return recommendations;
    }
    
    /**
     * Calculate overall risk score
     */
    private int calculateRiskScore(JSONAnalysisResult result) {
        int score = 0;
        
        // Base score for JSON type
        switch (result.getJsonType()) {
            case GRAPHQL:
                score += 20;
                break;
            case JSONP:
                score += 30;
                break;
            case STREAMING:
                score += 15;
                break;
            case NDJSON:
                score += 10;
                break;
            default:
                score += 5;
        }
        
        // Add score for XSS risks
        score += result.getXssRisks().size() * 15;
        
        // Add score for dangerous patterns
        score += result.getDangerousPatterns().size() * 10;
        
        // Add score for dangerous fields
        score += result.getJsonStructure().getDangerousFields().size() * 20;
        
        return Math.min(100, score);
    }
    
    /**
     * Get content type from response
     */
    private String getContentType(IHttpRequestResponse requestResponse) {
        List<String> headers = helpers.analyzeResponse(requestResponse.getResponse()).getHeaders();
        for (String header : headers) {
            if (header.toLowerCase().startsWith("content-type:")) {
                return header.substring(13).trim();
            }
        }
        return "unknown";
    }
    
    /**
     * JSON Type Enum
     */
    public enum JSONType {
        NOT_JSON, JSON_OBJECT, JSON_ARRAY, JSONP, GRAPHQL, STREAMING, NDJSON
    }
    
    /**
     * JSON Structure Class
     */
    public static class JSONStructure {
        private String type;
        private String callbackFunction;
        private Map<String, String> fields = new HashMap<>();
        private Map<String, String> dangerousFields = new HashMap<>();
        
        public void setType(String type) { this.type = type; }
        public void setCallbackFunction(String callbackFunction) { this.callbackFunction = callbackFunction; }
        public void addField(String name, String type) { fields.put(name, type); }
        public void addDangerousField(String name, String value) { dangerousFields.put(name, value); }
        
        public String getType() { return type; }
        public String getCallbackFunction() { return callbackFunction; }
        public Map<String, String> getFields() { return fields; }
        public Map<String, String> getDangerousFields() { return dangerousFields; }
    }
    
    /**
     * JSON Analysis Result Class
     */
    public static class JSONAnalysisResult {
        private String contentType;
        private JSONType jsonType;
        private JSONStructure jsonStructure;
        private List<String> xssRisks = new ArrayList<>();
        private List<String> dangerousPatterns = new ArrayList<>();
        private List<String> securityRecommendations = new ArrayList<>();
        private int riskScore;
        
        // Getters and setters
        public String getContentType() { return contentType; }
        public void setContentType(String contentType) { this.contentType = contentType; }
        
        public JSONType getJsonType() { return jsonType; }
        public void setJsonType(JSONType jsonType) { this.jsonType = jsonType; }
        
        public JSONStructure getJsonStructure() { return jsonStructure; }
        public void setJsonStructure(JSONStructure jsonStructure) { this.jsonStructure = jsonStructure; }
        
        public List<String> getXssRisks() { return xssRisks; }
        public void setXssRisks(List<String> xssRisks) { this.xssRisks = xssRisks; }
        
        public List<String> getDangerousPatterns() { return dangerousPatterns; }
        public void setDangerousPatterns(List<String> dangerousPatterns) { this.dangerousPatterns = dangerousPatterns; }
        
        public List<String> getSecurityRecommendations() { return securityRecommendations; }
        public void setSecurityRecommendations(List<String> securityRecommendations) { this.securityRecommendations = securityRecommendations; }
        
        public int getRiskScore() { return riskScore; }
        public void setRiskScore(int riskScore) { this.riskScore = riskScore; }
    }
} 