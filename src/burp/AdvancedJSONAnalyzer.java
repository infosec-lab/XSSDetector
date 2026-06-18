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
    private static final Pattern JSONRPC_PATTERN = Pattern.compile("\"jsonrpc\"\\s*:\\s*\"2\\.0\"", Pattern.CASE_INSENSITIVE);
    private static final Pattern JSONAPI_PATTERN = Pattern.compile("\"data\"\\s*:\\s*\\{\\s*\"type\"\\s*:", Pattern.CASE_INSENSITIVE);
    private static final Pattern JWT_PATTERN = Pattern.compile("^[A-Za-z0-9-_]+\\.[A-Za-z0-9-_]+\\.[A-Za-z0-9-_]*$");
    
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
        
        // JSON-RPC detection
        if (JSONRPC_PATTERN.matcher(responseBody).find() || 
            responseBody.contains("\"jsonrpc\"") && responseBody.contains("\"method\"")) {
            return JSONType.JSONRPC;
        }
        
        // JSON API (jsonapi.org) format detection
        if (JSONAPI_PATTERN.matcher(responseBody).find() || 
            (responseBody.contains("\"data\"") && responseBody.contains("\"type\"") && 
             responseBody.contains("\"attributes\""))) {
            return JSONType.JSONAPI;
        }
        
        // JWT detection (in response body or headers)
        if (JWT_PATTERN.matcher(responseBody.trim()).find() || 
            responseBody.contains("\"token\"") && JWT_PATTERN.matcher(responseBody).find()) {
            return JSONType.JWT;
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
     * Parse JSON-RPC structure
     */
    private JSONStructure parseJSONRPCStructure(String responseBody) {
        JSONStructure structure = new JSONStructure();
        structure.setType("JSON-RPC");
        
        // Extract JSON-RPC fields
        if (responseBody.contains("\"jsonrpc\"")) {
            structure.addField("jsonrpc", "string");
        }
        if (responseBody.contains("\"method\"")) {
            structure.addField("method", "string");
        }
        if (responseBody.contains("\"params\"")) {
            structure.addField("params", "object");
        }
        if (responseBody.contains("\"id\"")) {
            structure.addField("id", "string|number");
        }
        if (responseBody.contains("\"result\"")) {
            structure.addField("result", "object");
        }
        if (responseBody.contains("\"error\"")) {
            structure.addField("error", "object");
        }
        
        extractNestedFields(responseBody, structure, 0);
        return structure;
    }
    
    /**
     * Parse JSON API (jsonapi.org) structure
     */
    private JSONStructure parseJSONAPIStructure(String responseBody) {
        JSONStructure structure = new JSONStructure();
        structure.setType("JSON API");
        
        // Extract JSON API fields
        if (responseBody.contains("\"data\"")) {
            structure.addField("data", "array|object");
        }
        if (responseBody.contains("\"included\"")) {
            structure.addField("included", "array");
        }
        if (responseBody.contains("\"meta\"")) {
            structure.addField("meta", "object");
        }
        if (responseBody.contains("\"links\"")) {
            structure.addField("links", "object");
        }
        if (responseBody.contains("\"errors\"")) {
            structure.addField("errors", "array");
        }
        
        extractNestedFields(responseBody, structure, 0);
        return structure;
    }
    
    /**
     * Parse JWT structure
     */
    private JSONStructure parseJWTStructure(String responseBody) {
        JSONStructure structure = new JSONStructure();
        structure.setType("JWT");
        
        // Extract JWT claims
        if (responseBody.contains("\"sub\"")) {
            structure.addField("sub", "string");
        }
        if (responseBody.contains("\"iss\"")) {
            structure.addField("iss", "string");
        }
        if (responseBody.contains("\"aud\"")) {
            structure.addField("aud", "string");
        }
        if (responseBody.contains("\"exp\"")) {
            structure.addField("exp", "number");
        }
        if (responseBody.contains("\"iat\"")) {
            structure.addField("iat", "number");
        }
        if (responseBody.contains("\"email\"")) {
            structure.addField("email", "string");
        }
        if (responseBody.contains("\"name\"")) {
            structure.addField("name", "string");
        }
        if (responseBody.contains("\"username\"")) {
            structure.addField("username", "string");
        }
        
        extractNestedFields(responseBody, structure, 0);
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
     * CRITICAL: JSON responses are NOT always executable in browser - they need vulnerable consumption
     */
    private List<String> analyzeXSSRisks(String responseBody, JSONType jsonType) {
        List<String> risks = new ArrayList<>();
        
        // CRITICAL CHECK: JSON is only exploitable if consumed in vulnerable ways
        // Standard JSON.parse() is safe - we need to check for dangerous consumption patterns
        
        // Check 1: JSONP - Directly executable as JavaScript
        if (jsonType == JSONType.JSONP) {
            risks.add("CRITICAL: JSONP is directly executable in browser - callback function executes JSON as code");
            risks.add("JSONP callback may be vulnerable to injection attacks");
            
            // Check for callback injection
            Matcher jsonpMatcher = JSONP_PATTERN.matcher(responseBody);
            if (jsonpMatcher.find()) {
                String callbackName = extractCallbackName(responseBody);
                if (callbackName != null && !isSafeCallbackName(callbackName)) {
                    risks.add("Unsafe JSONP callback name detected: " + callbackName);
                }
            }
        }
        
        // Check 2: Script tag with JSON content-type (rare but dangerous)
        if (responseBody.contains("<script") && responseBody.contains("application/json")) {
            risks.add("CRITICAL: JSON served in script tag - may be executed as JavaScript");
        }
        
        // Check 3: Check if JSON contains executable code patterns
        // This indicates JSON might be used with eval() or similar
        if (containsExecutablePatterns(responseBody)) {
            risks.add("WARNING: JSON contains patterns that suggest unsafe consumption (eval, innerHTML, etc.)");
        }
        
        // Check 4: Check for dangerous field names that suggest unsafe usage
        if (hasDangerousFieldNames(responseBody)) {
            risks.add("WARNING: JSON contains field names suggesting unsafe DOM manipulation (innerHTML, outerHTML, etc.)");
        }
        
        // Check 5: Check for HTML/script content in JSON values
        // This suggests JSON might be used with innerHTML
        if (containsHTMLInValues(responseBody)) {
            risks.add("WARNING: JSON contains HTML/script content - may be used with innerHTML or similar");
        }
        
        // Check 6: Check for template injection patterns
        if (responseBody.contains("{{") || responseBody.contains("${")) {
            risks.add("WARNING: Template injection patterns detected - JSON may be processed by template engine");
        }
        
        // Check 7: GraphQL-specific risks
        if (jsonType == JSONType.GRAPHQL) {
            if (responseBody.contains("\"errors\"")) {
                risks.add("GraphQL errors may contain sensitive information");
            }
        }
        
        // Check 8: Check for unsafe JSON consumption indicators in response
        // Look for patterns that suggest the JSON will be used unsafely
        if (suggestsUnsafeConsumption(responseBody)) {
            risks.add("WARNING: Response suggests JSON may be consumed unsafely (check client-side code)");
        }
        
        return risks;
    }
    
    /**
     * Check if JSON contains patterns suggesting executable code
     */
    private boolean containsExecutablePatterns(String responseBody) {
        String[] executablePatterns = {
            "eval\\s*\\(",
            "Function\\s*\\(",
            "setTimeout\\s*\\(",
            "setInterval\\s*\\(",
            "document\\.write",
            "innerHTML\\s*=",
            "outerHTML\\s*=",
            "javascript:",
            "<script",
            "onerror\\s*=",
            "onload\\s*="
        };
        
        for (String pattern : executablePatterns) {
            if (Pattern.compile(pattern, Pattern.CASE_INSENSITIVE).matcher(responseBody).find()) {
                return true;
            }
        }
        return false;
    }
    
    /**
     * Check if JSON has dangerous field names suggesting unsafe usage
     */
    private boolean hasDangerousFieldNames(String responseBody) {
        for (String dangerous : DANGEROUS_JSON_FIELDS) {
            // Check if field name appears in JSON structure
            Pattern fieldPattern = Pattern.compile("\"" + Pattern.quote(dangerous) + "\"\\s*:", Pattern.CASE_INSENSITIVE);
            if (fieldPattern.matcher(responseBody).find()) {
                return true;
            }
        }
        return false;
    }
    
    /**
     * Check if JSON values contain HTML/script content
     */
    private boolean containsHTMLInValues(String responseBody) {
        // Look for HTML tags in JSON string values
        Pattern htmlInJson = Pattern.compile("\"[^\"]*<[^>]+>[^\"]*\"", Pattern.CASE_INSENSITIVE);
        if (htmlInJson.matcher(responseBody).find()) {
            return true;
        }
        
        // Look for script tags in JSON
        if (responseBody.contains("<script") || responseBody.contains("</script>")) {
            return true;
        }
        
        return false;
    }
    
    /**
     * Check if response suggests unsafe JSON consumption
     */
    private boolean suggestsUnsafeConsumption(String responseBody) {
        // Check for comments or patterns suggesting unsafe usage
        String[] unsafeIndicators = {
            "//.*eval",
            "//.*innerHTML",
            "//.*dangerouslySetInnerHTML",
            "JSON\\.parse.*eval",
            "JSON\\.parse.*innerHTML",
            "response\\.innerHTML",
            "data\\.innerHTML"
        };
        
        for (String indicator : unsafeIndicators) {
            if (Pattern.compile(indicator, Pattern.CASE_INSENSITIVE).matcher(responseBody).find()) {
                return true;
            }
        }
        return false;
    }
    
    /**
     * Extract callback function name from JSONP
     */
    private String extractCallbackName(String responseBody) {
        Matcher matcher = Pattern.compile("^\\s*([\\w$]+)\\s*\\(").matcher(responseBody);
        if (matcher.find()) {
            return matcher.group(1);
        }
        return null;
    }
    
    /**
     * Check if callback name is safe (alphanumeric only, no special chars)
     */
    private boolean isSafeCallbackName(String callbackName) {
        // Safe callback names should only contain alphanumeric and underscore/dollar
        return callbackName.matches("^[a-zA-Z_$][a-zA-Z0-9_$]*$") && 
               !callbackName.toLowerCase().contains("eval") &&
               !callbackName.toLowerCase().contains("function") &&
               !callbackName.toLowerCase().contains("constructor");
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
     * CRITICAL: Only high scores for actually exploitable JSON (JSONP, unsafe consumption)
     */
    private int calculateRiskScore(JSONAnalysisResult result) {
        int score = 0;
        
        // Base score for JSON type - JSONP is directly executable, others need unsafe consumption
        switch (result.getJsonType()) {
            case JSONP:
                // JSONP is directly executable - HIGH RISK
                score += 50;
                break;
            case GRAPHQL:
                // GraphQL can be risky if errors contain user input
                score += 15;
                break;
            case STREAMING:
                score += 10;
                break;
            case NDJSON:
                score += 5;
                break;
            case JSON_OBJECT:
            case JSON_ARRAY:
                // Standard JSON is safe unless consumed unsafely - LOW base score
                score += 5;
                break;
            default:
                score += 0;
        }
        
        // Add score for XSS risks - weight JSONP risks higher
        for (String risk : result.getXssRisks()) {
            if (risk.contains("CRITICAL") || risk.contains("JSONP")) {
                score += 25; // High weight for critical/JSONP risks
            } else if (risk.contains("WARNING")) {
                score += 10; // Medium weight for warnings
            } else {
                score += 5; // Low weight for other risks
            }
        }
        
        // Add score for dangerous patterns
        score += result.getDangerousPatterns().size() * 10;
        
        // Add score for dangerous fields
        score += result.getJsonStructure().getDangerousFields().size() * 15;
        
        // CRITICAL: If standard JSON with no unsafe consumption indicators, reduce score
        if (result.getJsonType() == JSONType.JSON_OBJECT || result.getJsonType() == JSONType.JSON_ARRAY) {
            if (result.getXssRisks().isEmpty() && result.getDangerousPatterns().isEmpty()) {
                // Safe JSON with no indicators of unsafe consumption - very low risk
                score = Math.min(score, 10);
            }
        }
        
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
        NOT_JSON, JSON_OBJECT, JSON_ARRAY, JSONP, GRAPHQL, STREAMING, NDJSON, JSONRPC, JSONAPI, JWT
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