package burp;

import java.util.*;
import java.util.regex.Pattern;
import java.util.regex.Matcher;

/**
 * AI-Powered Context Analyzer for XSSDetector
 * Uses advanced pattern recognition and machine learning-inspired techniques
 */
public class AIContextAnalyzer {
    
    private final IExtensionHelpers helpers;
    private final IBurpExtenderCallbacks callbacks;
    private final Settings settings;
    
    // AI-inspired confidence scoring weights
    private static final double WEIGHT_REFLECTION_QUALITY = 0.35;
    private static final double WEIGHT_CONTEXT_DANGER = 0.25;
    private static final double WEIGHT_PAYLOAD_SOPHISTICATION = 0.20;
    private static final double WEIGHT_ARCHITECTURE_RISK = 0.15;
    private static final double WEIGHT_HISTORICAL_PATTERNS = 0.05;
    
    // Advanced pattern recognition for modern applications
    private static final Pattern[] MODERN_XSS_PATTERNS = {
        // React/JSX patterns (including React 18+)
        Pattern.compile("dangerouslySetInnerHTML\\s*=\\s*\\{\\{\\s*__html\\s*:", Pattern.CASE_INSENSITIVE),
        Pattern.compile("React\\.createElement\\s*\\(\\s*[\"']script[\"']", Pattern.CASE_INSENSITIVE),
        Pattern.compile("createRoot\\s*\\([^)]*\\)\\s*\\.render", Pattern.CASE_INSENSITIVE),
        Pattern.compile("hydrateRoot\\s*\\([^)]*\\)", Pattern.CASE_INSENSITIVE),
        Pattern.compile("use server", Pattern.CASE_INSENSITIVE),
        Pattern.compile("use client", Pattern.CASE_INSENSITIVE),
        
        // Vue.js patterns (including Vue 3 Composition API)
        Pattern.compile("v-html\\s*=\\s*[\"'][^\"']*\\{\\{", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\$\\{[^}]*\\}", Pattern.CASE_INSENSITIVE),
        Pattern.compile("<script\\s+setup", Pattern.CASE_INSENSITIVE),
        Pattern.compile("defineProps\\s*\\([^)]*\\)", Pattern.CASE_INSENSITIVE),
        Pattern.compile("defineEmits\\s*\\([^)]*\\)", Pattern.CASE_INSENSITIVE),
        Pattern.compile("defineModel\\s*\\([^)]*\\)", Pattern.CASE_INSENSITIVE),
        
        // Angular patterns
        Pattern.compile("\\[innerHTML\\]\\s*=\\s*[\"'][^\"']*\\{\\{", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\*ngFor\\s*=\\s*[\"'][^\"']*\\{\\{", Pattern.CASE_INSENSITIVE),
        Pattern.compile("DomSanitizer\\.bypassSecurityTrust", Pattern.CASE_INSENSITIVE),
        
        // Svelte 5 runes patterns
        Pattern.compile("\\$state\\s*=", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\$derived\\s*=", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\$effect\\s*\\(", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\$props", Pattern.CASE_INSENSITIVE),
        Pattern.compile("@html\\s*=", Pattern.CASE_INSENSITIVE),
        
        // Next.js App Router patterns
        Pattern.compile("useSearchParams\\s*\\(\\s*\\)", Pattern.CASE_INSENSITIVE),
        Pattern.compile("usePathname\\s*\\(\\s*\\)", Pattern.CASE_INSENSITIVE),
        Pattern.compile("app/[^/]+/page", Pattern.CASE_INSENSITIVE),
        Pattern.compile("app/[^/]+/route", Pattern.CASE_INSENSITIVE),
        
        // Solid.js patterns
        Pattern.compile("createSignal\\s*\\([^)]*\\)", Pattern.CASE_INSENSITIVE),
        Pattern.compile("createEffect\\s*\\([^)]*\\)", Pattern.CASE_INSENSITIVE),
        
        // Qwik patterns
        Pattern.compile("component\\$\\s*\\([^)]*\\)", Pattern.CASE_INSENSITIVE),
        Pattern.compile("useSignal\\s*\\([^)]*\\)", Pattern.CASE_INSENSITIVE),
        
        // Remix patterns
        Pattern.compile("useLoaderData\\s*\\(\\s*\\)", Pattern.CASE_INSENSITIVE),
        Pattern.compile("useActionData\\s*\\(\\s*\\)", Pattern.CASE_INSENSITIVE),
        Pattern.compile("useFetcher\\s*\\(\\s*\\)", Pattern.CASE_INSENSITIVE),
        
        // Astro patterns
        Pattern.compile("Astro\\.props", Pattern.CASE_INSENSITIVE),
        Pattern.compile("Astro\\.params", Pattern.CASE_INSENSITIVE),
        Pattern.compile("set:html", Pattern.CASE_INSENSITIVE),
        
        // GraphQL patterns
        Pattern.compile("__typename\\s*:\\s*[\"'][^\"']*<", Pattern.CASE_INSENSITIVE),
        Pattern.compile("query\\s+[\\w_]+\\s*\\([^)]*\\)\\s*\\{[^}]*<script", Pattern.CASE_INSENSITIVE),
        
        // Modern JavaScript patterns
        Pattern.compile("document\\.querySelector\\s*\\([^)]*\\)\\s*\\.innerHTML", Pattern.CASE_INSENSITIVE),
        Pattern.compile("insertAdjacentHTML\\s*\\([^)]*,\\s*[^)]*<", Pattern.CASE_INSENSITIVE),
        
        // WebSocket patterns
        Pattern.compile("ws\\.send\\s*\\([^)]*<script", Pattern.CASE_INSENSITIVE),
        Pattern.compile("onmessage\\s*=\\s*[^;]*innerHTML", Pattern.CASE_INSENSITIVE),
        
        // Service Worker patterns
        Pattern.compile("self\\.addEventListener\\s*\\([^)]*,\\s*[^)]*<", Pattern.CASE_INSENSITIVE),
        Pattern.compile("caches\\.open\\s*\\([^)]*\\)\\s*\\.then[^}]*<script", Pattern.CASE_INSENSITIVE),
        
        // Modern state management patterns
        Pattern.compile("useStore\\s*\\([^)]*\\)", Pattern.CASE_INSENSITIVE),
        Pattern.compile("defineStore\\s*\\([^)]*\\)", Pattern.CASE_INSENSITIVE),
        Pattern.compile("useAtom\\s*\\([^)]*\\)", Pattern.CASE_INSENSITIVE),
        Pattern.compile("useQuery\\s*\\([^)]*\\)", Pattern.CASE_INSENSITIVE)
    };
    
    // Context danger levels (ML-inspired feature scoring)
    private static final Map<String, Double> CONTEXT_DANGER_SCORES = new HashMap<String, Double>() {{
        put("script", 1.0);
        put("javascript", 0.95);
        put("eval", 0.9);
        put("innerHTML", 0.85);
        put("outerHTML", 0.8);
        put("document.write", 0.75);
        put("setTimeout", 0.7);
        put("setInterval", 0.65);
        put("Function", 0.6);
        put("execScript", 0.95);
        put("insertAdjacentHTML", 0.8);
        put("dangerouslySetInnerHTML", 0.9);
        put("v-html", 0.85);
        put("ng-bind-html", 0.8);
    }};
    
    // Historical pattern database (simplified ML approach)
    private static final Map<String, Integer> HISTORICAL_PATTERNS = new HashMap<>();
    
    public AIContextAnalyzer(IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks, Settings settings) {
        this.helpers = helpers;
        this.callbacks = callbacks;
        this.settings = settings;
    }
    
    /**
     * AI-powered comprehensive context analysis
     */
    public AIAnalysisResult analyzeWithAI(IHttpRequestResponse requestResponse, 
                                        String parameter, String payload, List<int[]> matches) {
        
        AIAnalysisResult result = new AIAnalysisResult();
        
        try {
            // Extract response body
            byte[] response = requestResponse.getResponse();
            int bodyOffset = helpers.analyzeResponse(response).getBodyOffset();
            String responseBody = new String(Arrays.copyOfRange(response, bodyOffset, response.length));
            
            // Feature extraction (ML-inspired)
            double reflectionQuality = calculateReflectionQuality(responseBody, payload, matches);
            double contextDanger = calculateContextDanger(responseBody, payload, matches);
            double payloadSophistication = calculatePayloadSophistication(payload);
            double architectureRisk = calculateArchitectureRisk(requestResponse, responseBody);
            double historicalPatterns = calculateHistoricalPatterns(responseBody, payload);
            
            // AI-inspired confidence calculation
            double aiConfidence = (reflectionQuality * WEIGHT_REFLECTION_QUALITY) +
                                (contextDanger * WEIGHT_CONTEXT_DANGER) +
                                (payloadSophistication * WEIGHT_PAYLOAD_SOPHISTICATION) +
                                (architectureRisk * WEIGHT_ARCHITECTURE_RISK) +
                                (historicalPatterns * WEIGHT_HISTORICAL_PATTERNS);
            
            result.setConfidence(aiConfidence * 100);
            result.setReflectionQuality(reflectionQuality);
            result.setContextDanger(contextDanger);
            result.setPayloadSophistication(payloadSophistication);
            result.setArchitectureRisk(architectureRisk);
            
            // Advanced pattern recognition
            result.setModernPatterns(detectModernPatterns(responseBody));
            result.setVulnerabilityType(classifyVulnerabilityType(responseBody, payload));
            result.setExploitationDifficulty(calculateExploitationDifficulty(result));
            
            // Generate AI insights
            result.setAiInsights(generateAIInsights(result, responseBody, payload));
            
            // Update historical patterns (ML-inspired learning)
            updateHistoricalPatterns(responseBody, payload, result);
            
        } catch (Exception e) {
            callbacks.printError("AI analysis error: " + e.getMessage());
        }
        
        return result;
    }
    
    /**
     * Calculate reflection quality using advanced metrics
     */
    private double calculateReflectionQuality(String responseBody, String payload, List<int[]> matches) {
        if (matches == null || matches.isEmpty()) return 0.0;
        
        double quality = 0.0;
        
        // Number of reflections (more = higher quality)
        quality += Math.min(0.3, matches.size() * 0.1);
        
        // Payload integrity in reflections
        int intactReflections = 0;
        for (int[] match : matches) {
            try {
                String reflected = responseBody.substring(match[0], match[1]);
                if (reflected.equals(payload)) {
                    intactReflections++;
                }
            } catch (Exception e) {
                // Continue processing
            }
        }
        
        quality += (double) intactReflections / matches.size() * 0.4;
        
        // Context quality (not in comments or hidden elements)
        for (int[] match : matches) {
            try {
                int contextStart = Math.max(0, match[0] - 50);
                int contextEnd = Math.min(responseBody.length(), match[1] + 50);
                String context = responseBody.substring(contextStart, contextEnd);
                
                if (!context.contains("<!--") && !context.contains("display:none") && 
                    !context.contains("visibility:hidden")) {
                    quality += 0.1;
                }
            } catch (Exception e) {
                // Continue processing
            }
        }
        
        return Math.min(1.0, quality);
    }
    
    /**
     * Calculate context danger using ML-inspired scoring
     */
    private double calculateContextDanger(String responseBody, String payload, List<int[]> matches) {
        if (matches == null || matches.isEmpty()) return 0.0;
        
        double maxDanger = 0.0;
        
        for (int[] match : matches) {
            try {
                int contextStart = Math.max(0, match[0] - 100);
                int contextEnd = Math.min(responseBody.length(), match[1] + 100);
                String context = responseBody.substring(contextStart, contextEnd).toLowerCase();
                
                double contextDanger = 0.0;
                
                // Check for dangerous contexts
                for (Map.Entry<String, Double> entry : CONTEXT_DANGER_SCORES.entrySet()) {
                    if (context.contains(entry.getKey())) {
                        contextDanger = Math.max(contextDanger, entry.getValue());
                    }
                }
                
                // Additional context analysis
                if (context.contains("<script")) contextDanger = Math.max(contextDanger, 1.0);
                if (context.contains("javascript:")) contextDanger = Math.max(contextDanger, 0.95);
                if (context.contains("on" + "\\w+\\s*=")) contextDanger = Math.max(contextDanger, 0.8);
                if (context.contains("href") && context.contains("javascript:")) contextDanger = Math.max(contextDanger, 0.9);
                
                maxDanger = Math.max(maxDanger, contextDanger);
            } catch (Exception e) {
                // Continue processing
            }
        }
        
        return maxDanger;
    }
    
    /**
     * Calculate payload sophistication score
     */
    private double calculatePayloadSophistication(String payload) {
        if (payload == null || payload.isEmpty()) return 0.0;
        
        double sophistication = 0.0;
        String lowerPayload = payload.toLowerCase();
        
        // Basic XSS patterns
        if (lowerPayload.contains("<script")) sophistication += 0.2;
        if (lowerPayload.contains("javascript:")) sophistication += 0.15;
        if (lowerPayload.contains("onerror")) sophistication += 0.1;
        
        // Advanced XSS patterns
        if (lowerPayload.contains("eval(")) sophistication += 0.25;
        if (lowerPayload.contains("settimeout")) sophistication += 0.2;
        if (lowerPayload.contains("string.fromcharcode")) sophistication += 0.3;
        
        // Encoding sophistication
        if (payload.contains("&#x") || payload.contains("&#")) sophistication += 0.15;
        if (payload.contains("%3c") || payload.contains("%3e")) sophistication += 0.1;
        if (payload.contains("\\u00")) sophistication += 0.2;
        
        // Framework-specific patterns
        if (lowerPayload.contains("dangerouslysetinnerhtml")) sophistication += 0.35;
        if (lowerPayload.contains("v-html")) sophistication += 0.3;
        if (lowerPayload.contains("ng-bind-html")) sophistication += 0.25;
        
        // Advanced techniques
        if (lowerPayload.contains("constructor")) sophistication += 0.4;
        if (lowerPayload.contains("prototype")) sophistication += 0.35;
        if (lowerPayload.matches(".*[\\[\\]\\(\\)!\\+]{10,}.*")) sophistication += 0.5; // JSFucker
        
        return Math.min(1.0, sophistication);
    }
    
    /**
     * Calculate architecture-specific risk
     */
    private double calculateArchitectureRisk(IHttpRequestResponse requestResponse, String responseBody) {
        double risk = 0.0;
        String lowerResponse = responseBody.toLowerCase();
        
        // SPA indicators
        if (lowerResponse.contains("react") || lowerResponse.contains("vue") || 
            lowerResponse.contains("angular")) {
            risk += 0.3;
        }
        
        // API indicators
        String contentType = getContentType(requestResponse);
        if (contentType.contains("application/json")) risk += 0.2;
        if (contentType.contains("application/graphql")) risk += 0.3;
        
        // Modern web features
        if (lowerResponse.contains("websocket") || lowerResponse.contains("sse")) risk += 0.25;
        if (lowerResponse.contains("service-worker") || lowerResponse.contains("pwa")) risk += 0.2;
        
        // Security headers (reduce risk)
        if (lowerResponse.contains("content-security-policy")) risk -= 0.15;
        if (lowerResponse.contains("x-content-type-options")) risk -= 0.05;
        
        return Math.max(0.0, Math.min(1.0, risk));
    }
    
    /**
     * Calculate historical patterns score (ML-inspired)
     */
    private double calculateHistoricalPatterns(String responseBody, String payload) {
        double score = 0.0;
        
        // Simple pattern matching against historical data
        String combinedPattern = responseBody.toLowerCase() + "|" + payload.toLowerCase();
        
        for (Map.Entry<String, Integer> entry : HISTORICAL_PATTERNS.entrySet()) {
            if (combinedPattern.contains(entry.getKey())) {
                score += entry.getValue() * 0.001; // Normalize
            }
        }
        
        return Math.min(1.0, score);
    }
    
    /**
     * Detect modern XSS patterns
     */
    private List<String> detectModernPatterns(String responseBody) {
        List<String> patterns = new ArrayList<>();
        
        for (Pattern pattern : MODERN_XSS_PATTERNS) {
            Matcher matcher = pattern.matcher(responseBody);
            if (matcher.find()) {
                patterns.add("Modern pattern: " + pattern.pattern());
            }
        }
        
        return patterns;
    }
    
    /**
     * Classify vulnerability type using AI-inspired categorization
     */
    private String classifyVulnerabilityType(String responseBody, String payload) {
        String lowerResponse = responseBody.toLowerCase();
        String lowerPayload = payload.toLowerCase();
        
        // DOM-based XSS
        if (lowerResponse.contains("document.write") || lowerResponse.contains("innerhtml") ||
            lowerResponse.contains("location.href")) {
            return "DOM-based XSS";
        }
        
        // Stored XSS indicators
        if (lowerResponse.contains("database") || lowerResponse.contains("stored") ||
            lowerResponse.contains("persistent")) {
            return "Stored XSS";
        }
        
        // Framework-specific
        if (lowerResponse.contains("react") && lowerPayload.contains("dangerouslysetinnerhtml")) {
            return "React XSS";
        }
        if (lowerResponse.contains("vue") && lowerPayload.contains("v-html")) {
            return "Vue.js XSS";
        }
        if (lowerResponse.contains("angular") && lowerPayload.contains("ng-bind-html")) {
            return "Angular XSS";
        }
        
        // API-specific
        if (lowerResponse.contains("graphql")) {
            return "GraphQL XSS";
        }
        if (lowerResponse.contains("jsonp")) {
            return "JSONP XSS";
        }
        
        return "Reflected XSS";
    }
    
    /**
     * Calculate exploitation difficulty
     */
    private String calculateExploitationDifficulty(AIAnalysisResult result) {
        double difficulty = 0.0;
        
        // Higher quality = easier exploitation
        difficulty += (1.0 - result.getReflectionQuality()) * 0.4;
        
        // Higher context danger = easier exploitation
        difficulty += (1.0 - result.getContextDanger()) * 0.3;
        
        // Higher sophistication = harder exploitation
        difficulty += result.getPayloadSophistication() * 0.2;
        
        // Higher architecture risk = easier exploitation
        difficulty += (1.0 - result.getArchitectureRisk()) * 0.1;
        
        if (difficulty < 0.3) return "Low";
        if (difficulty < 0.6) return "Medium";
        return "High";
    }
    
    /**
     * Generate AI insights
     */
    private List<String> generateAIInsights(AIAnalysisResult result, String responseBody, String payload) {
        List<String> insights = new ArrayList<>();
        
        if (result.getConfidence() > 80) {
            insights.add("High confidence XSS vulnerability detected");
        }
        
        if (result.getContextDanger() > 0.8) {
            insights.add("Dangerous execution context identified");
        }
        
        if (result.getPayloadSophistication() > 0.7) {
            insights.add("Sophisticated payload suggests advanced attacker");
        }
        
        if (result.getArchitectureRisk() > 0.6) {
            insights.add("Modern architecture increases attack surface");
        }
        
        if (!result.getModernPatterns().isEmpty()) {
            insights.add("Modern framework patterns detected");
        }
        
        return insights;
    }
    
    /**
     * Update historical patterns (ML-inspired learning)
     */
    private void updateHistoricalPatterns(String responseBody, String payload, AIAnalysisResult result) {
        // Simple pattern learning
        String pattern = payload.toLowerCase().substring(0, Math.min(20, payload.length()));
        HISTORICAL_PATTERNS.put(pattern, HISTORICAL_PATTERNS.getOrDefault(pattern, 0) + 1);
        
        // Limit historical data size
        if (HISTORICAL_PATTERNS.size() > 1000) {
            HISTORICAL_PATTERNS.clear();
        }
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
     * AI Analysis Result Class
     */
    public static class AIAnalysisResult {
        private double confidence;
        private double reflectionQuality;
        private double contextDanger;
        private double payloadSophistication;
        private double architectureRisk;
        private List<String> modernPatterns = new ArrayList<>();
        private String vulnerabilityType;
        private String exploitationDifficulty;
        private List<String> aiInsights = new ArrayList<>();
        
        // Getters and setters
        public double getConfidence() { return confidence; }
        public void setConfidence(double confidence) { this.confidence = confidence; }
        
        public double getReflectionQuality() { return reflectionQuality; }
        public void setReflectionQuality(double reflectionQuality) { this.reflectionQuality = reflectionQuality; }
        
        public double getContextDanger() { return contextDanger; }
        public void setContextDanger(double contextDanger) { this.contextDanger = contextDanger; }
        
        public double getPayloadSophistication() { return payloadSophistication; }
        public void setPayloadSophistication(double payloadSophistication) { this.payloadSophistication = payloadSophistication; }
        
        public double getArchitectureRisk() { return architectureRisk; }
        public void setArchitectureRisk(double architectureRisk) { this.architectureRisk = architectureRisk; }
        
        public List<String> getModernPatterns() { return modernPatterns; }
        public void setModernPatterns(List<String> modernPatterns) { this.modernPatterns = modernPatterns; }
        
        public String getVulnerabilityType() { return vulnerabilityType; }
        public void setVulnerabilityType(String vulnerabilityType) { this.vulnerabilityType = vulnerabilityType; }
        
        public String getExploitationDifficulty() { return exploitationDifficulty; }
        public void setExploitationDifficulty(String exploitationDifficulty) { this.exploitationDifficulty = exploitationDifficulty; }
        
        public List<String> getAiInsights() { return aiInsights; }
        public void setAiInsights(List<String> aiInsights) { this.aiInsights = aiInsights; }
    }
} 