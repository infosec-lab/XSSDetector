package burp;

import java.util.*;

public class ModernParameterExtractor {
    private final IExtensionHelpers helpers;
    private final IBurpExtenderCallbacks callbacks;
    
    public ModernParameterExtractor(IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks) {
        this.helpers = helpers;
        this.callbacks = callbacks;
    }
    
    /**
     * MAIN EXTRACTION METHOD - Extract all modern parameters (GraphQL, JWT, etc.)
     * This is the primary method that should be called by CheckReflection
     */
    public List<ModernParameter> extractParameters(IHttpRequestResponse requestResponse) {
        List<ModernParameter> allParams = new ArrayList<>();
        
        try {
            // Extract GraphQL parameters
            allParams.addAll(extractGraphQLParameters(requestResponse));
            
            // Extract JWT parameters
            allParams.addAll(extractJWTParameters(requestResponse));
            
            // Future: Add WebSocket, API key, and other modern parameter types here
            
        } catch (Exception e) {
            callbacks.printError("Modern parameter extraction error: " + e.getMessage());
        }
        
        return allParams;
    }
    
    /**
     * Extract GraphQL parameters from request body
     */
    public List<ModernParameter> extractGraphQLParameters(IHttpRequestResponse requestResponse) {
        List<ModernParameter> params = new ArrayList<>();
        
        if (!isGraphQLRequest(requestResponse)) return params;
        
        try {
            int bodyOffset = helpers.analyzeRequest(requestResponse).getBodyOffset();
            String body = new String(Arrays.copyOfRange(
                requestResponse.getRequest(), bodyOffset, requestResponse.getRequest().length));
            
            // Extract GraphQL query
            if (body.contains("\"query\"")) {
                String query = extractJSONValue(body, "query");
                if (query != null) {
                    params.add(new ModernParameter("gql_query", query, "GRAPHQL"));
                }
            }
            
            // Extract variables
            if (body.contains("\"variables\"")) {
                params.addAll(extractGraphQLVariables(body));
            }
            
        } catch (Exception e) {
            callbacks.printError("GraphQL extraction error: " + e.getMessage());
        }
        
        return params;
    }
    
    /**
     * Extract JWT token claims from headers and cookies
     */
    public List<ModernParameter> extractJWTParameters(IHttpRequestResponse requestResponse) {
        List<ModernParameter> params = new ArrayList<>();
        
        try {
            // Check Authorization header
            List<String> headers = helpers.analyzeRequest(requestResponse).getHeaders();
            for (String header : headers) {
                if (header.toLowerCase().startsWith("authorization:") && 
                    header.toLowerCase().contains("bearer")) {
                    String token = header.substring(header.indexOf("Bearer") + 6).trim();
                    params.addAll(parseJWTToken(token, "auth_jwt"));
                }
            }
            
            // Check cookies for JWT patterns
            List<IParameter> requestParams = helpers.analyzeRequest(requestResponse).getParameters();
            for (IParameter param : requestParams) {
                if (param.getType() == IParameter.PARAM_COOKIE && isJWTFormat(param.getValue())) {
                    params.addAll(parseJWTToken(param.getValue(), "cookie_jwt"));
                }
            }
            
        } catch (Exception e) {
            callbacks.printError("JWT extraction error: " + e.getMessage());
        }
        
        return params;
    }
    
    // Helper methods
    private boolean isGraphQLRequest(IHttpRequestResponse requestResponse) {
        List<String> headers = helpers.analyzeRequest(requestResponse).getHeaders();
        boolean isJSON = headers.stream().anyMatch(h -> 
            h.toLowerCase().contains("content-type") && 
            h.toLowerCase().contains("application/json"));
        
        if (!isJSON) return false;
        
        int bodyOffset = helpers.analyzeRequest(requestResponse).getBodyOffset();
        String body = new String(Arrays.copyOfRange(
            requestResponse.getRequest(), bodyOffset, requestResponse.getRequest().length));
        
        return body.contains("\"query\"") || body.contains("\"mutation\"") || body.contains("\"subscription\"");
    }
    
    private boolean isJWTFormat(String value) {
        return value != null && value.matches("^[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]*$");
    }
    
    private List<ModernParameter> parseJWTToken(String token, String prefix) {
        List<ModernParameter> params = new ArrayList<>();
        
        try {
            String[] parts = token.split("\\.");
            if (parts.length >= 2) {
                String payload = new String(Base64.getDecoder().decode(parts[1]));
                params.addAll(parseSimpleJSON(payload, prefix));
            }
        } catch (Exception e) {
            // Invalid JWT format
        }
        
        return params;
    }
    
    private List<ModernParameter> extractGraphQLVariables(String body) {
        List<ModernParameter> params = new ArrayList<>();
        
        // Simple variable extraction for GraphQL
        try {
            String variablesSection = extractJSONValue(body, "variables");
            if (variablesSection != null) {
                params.addAll(parseSimpleJSON(variablesSection, "gql_var"));
            }
        } catch (Exception e) {
            // Continue without breaking
        }
        
        return params;
    }
    
    private List<ModernParameter> parseSimpleJSON(String json, String prefix) {
        List<ModernParameter> params = new ArrayList<>();
        
        try {
            json = json.trim();
            if (json.startsWith("{") && json.endsWith("}")) {
                json = json.substring(1, json.length() - 1);
                String[] pairs = json.split(",");
                
                for (String pair : pairs) {
                    if (pair.contains(":")) {
                        String[] keyValue = pair.split(":", 2);
                        String key = keyValue[0].trim().replaceAll("[\"\']", "");
                        String value = keyValue[1].trim().replaceAll("[\"\']", "");
                        params.add(new ModernParameter(prefix + "." + key, value, "JSON"));
                    }
                }
            }
        } catch (Exception e) {
            // Continue without breaking
        }
        
        return params;
    }
    
    private String extractJSONValue(String json, String key) {
        try {
            String searchKey = "\"" + key + "\"";
            int keyIndex = json.indexOf(searchKey);
            if (keyIndex == -1) return null;
            
            int colonIndex = json.indexOf(":", keyIndex);
            int valueStart = colonIndex + 1;
            
            while (valueStart < json.length() && Character.isWhitespace(json.charAt(valueStart))) {
                valueStart++;
            }
            
            if (json.charAt(valueStart) == '"') {
                int valueEnd = json.indexOf('"', valueStart + 1);
                return json.substring(valueStart + 1, valueEnd);
            }
            
            return null;
        } catch (Exception e) {
            return null;
        }
    }
}

// Supporting class
class ModernParameter {
    private final String name;
    private final String value;
    private final String type;
    
    public ModernParameter(String name, String value, String type) {
        this.name = name;
        this.value = value;
        this.type = type;
    }
    
    public String getName() { return name; }
    public String getValue() { return value; }
    public String getType() { return type; }
}
