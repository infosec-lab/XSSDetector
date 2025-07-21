package burp;

import java.util.*;
import java.util.regex.Pattern;
import java.util.regex.Matcher;

/**
 * Advanced Modern Architecture Detector for XSSDetector
 * Detects modern web application architectures and adjusts XSS testing accordingly
 */
public class ModernArchitectureDetector {
    
    private final IExtensionHelpers helpers;
    private final IBurpExtenderCallbacks callbacks;
    private final Settings settings;
    
    // Modern architecture patterns
    private static final String[] SPA_INDICATORS = {
        "ng-app", "ng-controller", "ng-", "data-ng-", "v-app", "v-", "@", "data-v-",
        "react", "reactjs", "vue", "vuejs", "angular", "angularjs", "svelte", "next.js",
        "__webpack", "__NUXT__", "__NEXT_DATA__", "_app.js", "chunk.js", "vendor.js"
    };
    
    private static final String[] PWA_INDICATORS = {
        "manifest.json", "sw.js", "serviceworker", "service-worker", "pwa", 
        "workbox", "precache", "push-notification", "background-sync"
    };
    
    private static final String[] MICROSERVICES_INDICATORS = {
        "api/v1/", "api/v2/", "/graphql", "/graph", "X-Service-Name", "X-Microservice",
        "microservice", "service-mesh", "istio", "consul", "eureka", "kubernetes"
    };
    
    private static final String[] MODERN_API_INDICATORS = {
        "application/json", "application/graphql", "application/hal+json", "application/vnd.api+json",
        "grpc", "protobuf", "websocket", "socket.io", "rest", "restful", "openapi", "swagger"
    };
    
    private static final String[] JAMSTACK_INDICATORS = {
        "netlify", "vercel", "gatsby", "nuxt", "gridsome", "eleventy", "hugo", "jekyll",
        "static", "cdn", "edge", "lambda", "serverless", "functions"
    };
    
    private static final String[] MODERN_JS_FRAMEWORKS = {
        "react", "vue", "angular", "svelte", "alpine", "lit", "stencil", "preact",
        "solid", "qwik", "marko", "mithril", "ember", "backbone", "knockout"
    };
    
    public ModernArchitectureDetector(IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks, Settings settings) {
        this.helpers = helpers;
        this.callbacks = callbacks;
        this.settings = settings;
    }
    
    /**
     * Comprehensive modern architecture analysis
     */
    public ArchitectureAnalysis analyzeArchitecture(IHttpRequestResponse requestResponse) {
        ArchitectureAnalysis analysis = new ArchitectureAnalysis();
        
        try {
            // Analyze request headers
            List<String> requestHeaders = helpers.analyzeRequest(requestResponse).getHeaders();
            analysis.analyzeRequestHeaders(requestHeaders);
            
            // Analyze response headers
            List<String> responseHeaders = helpers.analyzeResponse(requestResponse.getResponse()).getHeaders();
            analysis.analyzeResponseHeaders(responseHeaders);
            
            // Analyze response body
            byte[] response = requestResponse.getResponse();
            int bodyOffset = helpers.analyzeResponse(response).getBodyOffset();
            String responseBody = new String(Arrays.copyOfRange(response, bodyOffset, response.length));
            analysis.analyzeResponseBody(responseBody);
            
            // Analyze URL patterns
            String url = helpers.analyzeRequest(requestResponse).getUrl().toString();
            analysis.analyzeUrlPatterns(url);
            
            // Generate XSS strategy recommendations
            analysis.generateXSSStrategy();
            
        } catch (Exception e) {
            callbacks.printError("Architecture analysis error: " + e.getMessage());
        }
        
        return analysis;
    }
    
    /**
     * Architecture Analysis Result Class
     */
    public class ArchitectureAnalysis {
        private boolean isSPA = false;
        private boolean isPWA = false;
        private boolean isMicroservices = false;
        private boolean isJAMStack = false;
        private boolean isModernAPI = false;
        private boolean hasCSP = false;
        private boolean hasWebSocket = false;
        private boolean hasGraphQL = false;
        private boolean hasServiceWorker = false;
        
        private List<String> detectedFrameworks = new ArrayList<>();
        private List<String> detectedTechnologies = new ArrayList<>();
        private List<String> securityHeaders = new ArrayList<>();
        private List<String> xssStrategies = new ArrayList<>();
        
        private String primaryArchitecture = "Traditional";
        private String riskLevel = "Medium";
        private int xssRiskScore = 50;
        
        public void analyzeRequestHeaders(List<String> headers) {
            for (String header : headers) {
                String lowerHeader = header.toLowerCase();
                
                // Check for SPA indicators
                if (lowerHeader.contains("x-requested-with: xmlhttprequest") ||
                    lowerHeader.contains("accept: application/json")) {
                    isSPA = true;
                }
                
                // Check for GraphQL
                if (lowerHeader.contains("content-type: application/graphql") ||
                    lowerHeader.contains("x-apollo-") || lowerHeader.contains("graphql")) {
                    hasGraphQL = true;
                    isModernAPI = true;
                }
                
                // Check for WebSocket upgrade
                if (lowerHeader.contains("upgrade: websocket") || 
                    lowerHeader.contains("connection: upgrade")) {
                    hasWebSocket = true;
                }
                
                // Check for modern API headers
                if (lowerHeader.contains("x-api-key") || lowerHeader.contains("authorization: bearer") ||
                    lowerHeader.contains("x-service-") || lowerHeader.contains("x-microservice")) {
                    isMicroservices = true;
                    isModernAPI = true;
                }
            }
        }
        
        public void analyzeResponseHeaders(List<String> headers) {
            for (String header : headers) {
                String lowerHeader = header.toLowerCase();
                
                // Security headers analysis
                if (lowerHeader.startsWith("content-security-policy")) {
                    hasCSP = true;
                    securityHeaders.add(header);
                    // Analyze CSP strength
                    if (lowerHeader.contains("'unsafe-inline'") || lowerHeader.contains("'unsafe-eval'")) {
                        xssRiskScore += 20; // Weak CSP increases risk
                    } else {
                        xssRiskScore -= 15; // Strong CSP reduces risk
                    }
                }
                
                if (lowerHeader.startsWith("x-frame-options") || 
                    lowerHeader.startsWith("x-content-type-options") ||
                    lowerHeader.startsWith("x-xss-protection")) {
                    securityHeaders.add(header);
                }
                
                // Check for PWA indicators
                if (lowerHeader.contains("x-pwa") || lowerHeader.contains("service-worker") ||
                    lowerHeader.contains("manifest")) {
                    isPWA = true;
                }
                
                // Check for modern deployment
                if (lowerHeader.contains("x-vercel") || lowerHeader.contains("x-netlify") ||
                    lowerHeader.contains("x-served-by") || lowerHeader.contains("x-cache")) {
                    isJAMStack = true;
                }
            }
        }
        
        public void analyzeResponseBody(String body) {
            String lowerBody = body.toLowerCase();
            
            // Framework detection
            for (String framework : MODERN_JS_FRAMEWORKS) {
                if (lowerBody.contains(framework)) {
                    detectedFrameworks.add(framework);
                    isSPA = true;
                    xssRiskScore += 10; // Client-side frameworks increase XSS risk
                }
            }
            
            // SPA detection
            for (String indicator : SPA_INDICATORS) {
                if (lowerBody.contains(indicator)) {
                    isSPA = true;
                    detectedTechnologies.add(indicator);
                }
            }
            
            // PWA detection
            for (String indicator : PWA_INDICATORS) {
                if (lowerBody.contains(indicator)) {
                    isPWA = true;
                    hasServiceWorker = true;
                    detectedTechnologies.add(indicator);
                }
            }
            
            // GraphQL detection
            if (lowerBody.contains("graphql") || lowerBody.contains("__schema") ||
                lowerBody.contains("query") && lowerBody.contains("mutation")) {
                hasGraphQL = true;
                isModernAPI = true;
                xssRiskScore += 15; // GraphQL increases complexity
            }
            
            // WebSocket detection
            if (lowerBody.contains("websocket") || lowerBody.contains("socket.io") ||
                lowerBody.contains("ws://") || lowerBody.contains("wss://")) {
                hasWebSocket = true;
                xssRiskScore += 10; // Real-time data increases risk
            }
            
            // Modern API patterns
            if (lowerBody.contains("api/v") || lowerBody.contains("microservice") ||
                lowerBody.contains("service-mesh")) {
                isMicroservices = true;
                isModernAPI = true;
            }
        }
        
        public void analyzeUrlPatterns(String url) {
            String lowerUrl = url.toLowerCase();
            
            // API endpoint detection
            if (lowerUrl.contains("/api/") || lowerUrl.contains("/graphql") ||
                lowerUrl.contains("/rest/") || lowerUrl.contains("/v1/") ||
                lowerUrl.contains("/v2/")) {
                isModernAPI = true;
            }
            
            // Microservices detection
            if (lowerUrl.contains("microservice") || lowerUrl.contains("service") ||
                lowerUrl.matches(".*://[^/]+/[^/]+/api/.*")) {
                isMicroservices = true;
            }
        }
        
        public void generateXSSStrategy() {
            // Determine primary architecture
            if (isSPA && isPWA) {
                primaryArchitecture = "Progressive Web App";
                riskLevel = "High";
                xssRiskScore += 20;
            } else if (isSPA) {
                primaryArchitecture = "Single Page Application";
                riskLevel = "High";
                xssRiskScore += 15;
            } else if (isMicroservices) {
                primaryArchitecture = "Microservices";
                riskLevel = "Medium";
                xssRiskScore += 10;
            } else if (isJAMStack) {
                primaryArchitecture = "JAMStack";
                riskLevel = "Medium";
                xssRiskScore += 5;
            }
            
            // Generate XSS strategies based on architecture
            if (isSPA) {
                xssStrategies.add("DOM-based XSS testing priority");
                xssStrategies.add("Client-side routing parameter injection");
                xssStrategies.add("Virtual DOM manipulation testing");
                xssStrategies.add("State management poisoning");
            }
            
            if (hasGraphQL) {
                xssStrategies.add("GraphQL query injection testing");
                xssStrategies.add("Batch query abuse detection");
                xssStrategies.add("Schema introspection XSS");
            }
            
            if (hasWebSocket) {
                xssStrategies.add("WebSocket message injection");
                xssStrategies.add("Real-time data poisoning");
                xssStrategies.add("Event-based XSS testing");
            }
            
            if (isPWA) {
                xssStrategies.add("Service Worker cache poisoning");
                xssStrategies.add("Push notification XSS");
                xssStrategies.add("Background sync manipulation");
            }
            
            if (isMicroservices) {
                xssStrategies.add("Inter-service communication XSS");
                xssStrategies.add("API gateway bypass testing");
                xssStrategies.add("Service mesh security validation");
            }
            
            // Adjust risk level based on security headers
            if (hasCSP && securityHeaders.size() > 2) {
                riskLevel = riskLevel.equals("High") ? "Medium" : "Low";
                xssRiskScore -= 10;
            }
            
            // Final risk score normalization
            xssRiskScore = Math.max(0, Math.min(100, xssRiskScore));
        }
        
        // Getters for all properties
        public boolean isSPA() { return isSPA; }
        public boolean isPWA() { return isPWA; }
        public boolean isMicroservices() { return isMicroservices; }
        public boolean isJAMStack() { return isJAMStack; }
        public boolean isModernAPI() { return isModernAPI; }
        public boolean hasCSP() { return hasCSP; }
        public boolean hasWebSocket() { return hasWebSocket; }
        public boolean hasGraphQL() { return hasGraphQL; }
        public boolean hasServiceWorker() { return hasServiceWorker; }
        public List<String> getDetectedFrameworks() { return detectedFrameworks; }
        public List<String> getDetectedTechnologies() { return detectedTechnologies; }
        public List<String> getSecurityHeaders() { return securityHeaders; }
        public List<String> getXSSStrategies() { return xssStrategies; }
        public String getPrimaryArchitecture() { return primaryArchitecture; }
        public String getRiskLevel() { return riskLevel; }
        public int getXSSRiskScore() { return xssRiskScore; }
    }
} 