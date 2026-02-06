package burp;

import java.util.*;
import java.util.regex.Pattern;
import java.util.regex.Matcher;
import static burp.Constants.*;

/**
 * Advanced Filtering Engine for False Positive Reduction
 * Implements multiple layers of validation to ensure high-quality XSS detection
 */
public class AdvancedFilteringEngine {
    
    private final IExtensionHelpers helpers;
    private final IBurpExtenderCallbacks callbacks;
    private final Settings settings;
    
    // PRODUCTION: Static rate limiting for detection messages across all instances
    private static long lastJSONDetectionMessage = 0;
    private static long lastCuttingEdgeDetectionMessage = 0;
    
    // Confidence scoring weights
    private static final double WEIGHT_CONTEXT = 0.4;
    private static final double WEIGHT_PAYLOAD_QUALITY = 0.3;
    private static final double WEIGHT_RESPONSE_CONTEXT = 0.2;
    private static final double WEIGHT_PARAMETER_TYPE = 0.1;
    
    // Pattern for detecting encoded payloads
    private static final Pattern ENCODED_PAYLOAD_PATTERN = Pattern.compile("(%[0-9a-fA-F]{2}|&#x?[0-9a-fA-F]+;|&[a-zA-Z]+;)");
    
    // Common XSS payload patterns
    private static final String[] XSS_PATTERNS = {
        "<script", "javascript:", "on\\w+\\s*=", "expression\\s*\\(", "vbscript:",
        "data:text/html", "svg", "iframe", "object", "embed", "applet"
    };
    
    // False positive indicators
    private static final String[] FALSE_POSITIVE_INDICATORS = {
        "Content-Type.*image", "Content-Type.*audio", "Content-Type.*video",
        "Content-Type.*application/pdf", "Content-Type.*application/zip"
    };
    
    public AdvancedFilteringEngine(IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks, Settings settings) {
        this.helpers = helpers;
        this.callbacks = callbacks;
        this.settings = settings;
    }
    
    /**
     * ADVANCED XSS DETECTION ENGINE - FOCUSED ON CUTTING-EDGE TECHNIQUES
     * Revolutionary XSS Detection Engine (AI Removed for Better Detection)
     */
    public FilterResult analyzeReflection(Map reflectionData, IHttpRequestResponse requestResponse) {
        FilterResult result = new FilterResult();
        
        try {
            // SIMPLIFIED VALIDATION - No aggressive AI filtering
            String paramValue = (String) reflectionData.get(VALUE);
            
            // Only basic safety checks (prevent obvious false positives)
            if (paramValue == null || paramValue.trim().isEmpty()) {
                result.setFiltered(true);
                result.setReason("Empty parameter value");
                return result;
            }
            
            // Enhanced scoring for XSS techniques
            double contextScore = calculateAdvancedContextScore(reflectionData, requestResponse);
            double payloadScore = calculateAIPayloadScore(reflectionData);
            double responseScore = calculateDeepResponseScore(reflectionData, requestResponse);
            double parameterScore = calculateSmartParameterScore(reflectionData);
            double frameworkScore = calculateFrameworkScore(reflectionData, requestResponse);
            double encodingScore = calculateEncodingScore(reflectionData);
            
            // ENHANCED SCORING for advanced XSS techniques
            double finalScore = (contextScore * 0.30) +     // Context importance increased
                              (payloadScore * 0.25) +       // Payload quality increased
                              (responseScore * 0.20) +      // Response analysis increased
                              (parameterScore * 0.10) +     // Parameter type
                              (frameworkScore * 0.10) +     // Framework detection
                              (encodingScore * 0.05);       // Encoding analysis
            
            // CUTTING-EDGE TECHNIQUE BONUS SCORING
            finalScore = applyCuttingEdgeBonus(finalScore, reflectionData, requestResponse);
            
            result.setConfidenceScore(Math.min(95.0, finalScore)); // Cap at 95%
            result.setSeverity(calculateAISeverity(finalScore, reflectionData));
            
            // MINIMAL FILTERING - Focus on detection, not filtering
            boolean shouldFilter = shouldFilterMinimal(finalScore, reflectionData, requestResponse);
            result.setFiltered(shouldFilter);
            
            if (shouldFilter) {
                result.setReason("Filtered: " + getMinimalFilterReason(finalScore, reflectionData));
            } else {
                result.setReason("XSS DETECTED: " + String.format("%.1f", finalScore) + "% confidence - Advanced detection by XSSDetector");
            }
            
            return result;
            
        } catch (Exception e) {
            callbacks.printError("XSS detection engine error: " + e.getMessage());
            result.setConfidenceScore(70.0); // Default to higher confidence
            result.setSeverity("Medium");
            result.setFiltered(false); // Don't filter on errors
            return result;
        }
    }
    
    /**
     * Layer 1: Basic validation checks
     */
    private boolean passesBasicValidation(Map reflectionData, IHttpRequestResponse requestResponse) {
        String paramValue = (String) reflectionData.get(VALUE);
        
        // Check minimum payload length
        if (paramValue == null || paramValue.length() < MIN_PAYLOAD_LENGTH) {
            return false;
        }
        
        // Check maximum payload length (prevent DoS)
        if (paramValue.length() > MAX_PAYLOAD_LENGTH) {
            return false;
        }
        
        // Check if parameter value is just common words
        if (isCommonWord(paramValue)) {
            return false;
        }
        
        // Check if reflection has minimum occurrences
        @SuppressWarnings("unchecked")
        List<int[]> matches = (List<int[]>) reflectionData.get(MATCHES);
        if (matches == null || matches.isEmpty()) {
            return false;
        }
        
        return true;
    }
    
    /**
     * Layer 4: Context-aware scoring
     */
    private double calculateContextScore(Map reflectionData, IHttpRequestResponse requestResponse) {
        double score = 50.0; // Base score
        
        try {
            String reflectedIn = (String) reflectionData.get(REFLECTED_IN);
            
            // Higher score for body reflections (more dangerous)
            if (BODY.equals(reflectedIn)) {
                score += 20.0;
            } else if (HEADERS.equals(reflectedIn)) {
                score += 10.0; // Headers can still be dangerous
            } else if (BOTH.equals(reflectedIn)) {
                score += 25.0; // Highest risk
            }
            
            // Check for dangerous HTML context
            if (reflectionData.containsKey(VULNERABLE)) {
                String contextInfo = (String) reflectionData.get(VULNERABLE);
                
                // Context-specific scoring
                if (contextInfo.contains("Script")) {
                    score += 30.0; // JavaScript context is very dangerous
                } else if (contextInfo.contains("HTML")) {
                    score += 25.0; // HTML context is dangerous
                } else if (contextInfo.contains("Attribute")) {
                    score += 15.0; // Attribute context is moderately dangerous
                }
                
                // Check for context breaking characters
                if (contextInfo.contains("&lt;") || contextInfo.contains("<")) {
                    score += 20.0; // Can break out of context
                }
                
                if (contextInfo.contains("&#39;") || contextInfo.contains("'")) {
                    score += 15.0; // Can break quotes
                }
                
                if (contextInfo.contains("&quot;") || contextInfo.contains("\"")) {
                    score += 15.0; // Can break double quotes
                }
            }
            
            // Modern parameter type bonus
            if (reflectionData.containsKey("MODERN_TYPE")) {
                String modernType = (String) reflectionData.get("MODERN_TYPE");
                switch (modernType) {
                    case "GRAPHQL":
                        score += 10.0; // GraphQL often client-processed
                        break;
                    case "JWT":
                        score += 15.0; // JWT tokens often client-processed
                        break;
                    case "JSON":
                        score += 5.0; // JSON can be dangerous
                        break;
                }
            }
            
        } catch (Exception e) {
            callbacks.printError("Context scoring error: " + e.getMessage());
        }
        
        return Math.min(100.0, Math.max(0.0, score));
    }
    
    /**
     * Layer 5: Payload quality assessment
     */
    private double calculatePayloadQualityScore(Map reflectionData) {
        double score = 50.0; // Base score
        String paramValue = (String) reflectionData.get(VALUE);
        
        try {
            // Check for XSS-like patterns
            for (String xssPattern : XSS_PATTERNS) {
                if (Pattern.compile(xssPattern, Pattern.CASE_INSENSITIVE).matcher(paramValue).find()) {
                    score += 20.0;
                    break;
                }
            }
            
            // Check for special characters that are XSS-relevant
            if (paramValue.contains("<")) score += 15.0;
            if (paramValue.contains(">")) score += 10.0;
            if (paramValue.contains("'")) score += 10.0;
            if (paramValue.contains("\"")) score += 10.0;
            if (paramValue.contains("(")) score += 5.0;
            if (paramValue.contains(")")) score += 5.0;
            
            // Check for encoded content (might be obfuscated XSS)
            if (ENCODED_PAYLOAD_PATTERN.matcher(paramValue).find()) {
                score += 10.0;
            }
            
            // Penalize very short payloads
            if (paramValue.length() < 5) {
                score -= 20.0;
            }
            
            // Penalize very long payloads (might be data, not XSS)
            if (paramValue.length() > SUSPICIOUS_PAYLOAD_LENGTH) {
                score -= 10.0;
            }
            
            // Check for polyglot patterns
            if (isPolyglotPayload(paramValue)) {
                score += 25.0;
            }
            
        } catch (Exception e) {
            callbacks.printError("Payload quality scoring error: " + e.getMessage());
        }
        
        return Math.min(100.0, Math.max(0.0, score));
    }
    
    /**
     * Layer 6: Response context analysis
     */
    private double calculateResponseContextScore(Map reflectionData, IHttpRequestResponse requestResponse) {
        double score = 50.0; // Base score
        
        try {
            byte[] response = requestResponse.getResponse();
            int bodyOffset = helpers.analyzeResponse(response).getBodyOffset();
            String responseBody = new String(Arrays.copyOfRange(response, bodyOffset, response.length));
            
            // Check for JavaScript context indicators
            if (responseBody.contains("<script")) {
                score += 20.0;
            }
            
            // Check for event handlers
            if (Pattern.compile("on\\w+\\s*=", Pattern.CASE_INSENSITIVE).matcher(responseBody).find()) {
                score += 15.0;
            }
            
            // Check for dangerous functions
            String[] dangerousFunctions = {"eval", "setTimeout", "setInterval", "Function", "document.write"};
            for (String func : dangerousFunctions) {
                if (responseBody.contains(func)) {
                    score += 10.0;
                    break;
                }
            }
            
            // Check for SPA framework indicators
            for (String spaIndicator : SPA_INDICATORS) {
                if (responseBody.contains(spaIndicator)) {
                    score += 15.0; // SPA frameworks process data client-side
                    break;
                }
            }
            
            // Check for template engine indicators
            for (String templateIndicator : TEMPLATE_INDICATORS) {
                if (responseBody.contains(templateIndicator)) {
                    score += 10.0;
                    break;
                }
            }
            
            // Analyze reflection position context
            @SuppressWarnings("unchecked")
            List<int[]> matches = (List<int[]>) reflectionData.get(MATCHES);
            if (matches != null && !matches.isEmpty()) {
                for (int[] match : matches) {
                    String context = getReflectionContext(responseBody, match[0] - bodyOffset, 100);
                    
                    // Check context around reflection
                    if (context.contains("<script")) score += 20.0;
                    if (context.contains("javascript:")) score += 25.0;
                    if (context.contains("data:text/html")) score += 20.0;
                    if (Pattern.compile("on\\w+\\s*=", Pattern.CASE_INSENSITIVE).matcher(context).find()) {
                        score += 15.0;
                    }
                }
            }
            
        } catch (Exception e) {
            callbacks.printError("Response context scoring error: " + e.getMessage());
        }
        
        return Math.min(100.0, Math.max(0.0, score));
    }
    
    /**
     * Layer 7: Parameter type scoring
     */
    private double calculateParameterTypeScore(Map reflectionData) {
        double score = 50.0; // Base score
        
        try {
            Object paramType = reflectionData.get(TYPE);
            
            if (paramType instanceof Byte) {
                byte type = (Byte) paramType;
                switch (type) {
                    case IParameter.PARAM_URL:
                        score += 10.0; // URL parameters are commonly attacked
                        break;
                    case IParameter.PARAM_BODY:
                        score += 15.0; // POST body parameters are higher risk
                        break;
                    case IParameter.PARAM_COOKIE:
                        score += 5.0; // Cookies are sometimes XSS vectors
                        break;
                    case IParameter.PARAM_JSON:
                        score += 20.0; // JSON parameters often processed by JS
                        break;
                    case IParameter.PARAM_XML:
                        score += 15.0; // XML can be processed client-side
                        break;
                    case IParameter.PARAM_XML_ATTR:
                        score += 10.0; // XML attributes
                        break;
                    case IParameter.PARAM_MULTIPART_ATTR:
                        score += 5.0; // Multipart attributes
                        break;
                }
            }
            
            // Modern parameter type bonuses
            if (reflectionData.containsKey("MODERN_TYPE")) {
                String modernType = (String) reflectionData.get("MODERN_TYPE");
                switch (modernType) {
                    case "GRAPHQL":
                        score += 15.0;
                        break;
                    case "JWT":
                        score += 20.0;
                        break;
                    case "API_KEY":
                        score += 5.0;
                        break;
                    case "WEBSOCKET":
                        score += 25.0; // WebSocket data often processed live
                        break;
                }
            }
            
        } catch (Exception e) {
            callbacks.printError("Parameter type scoring error: " + e.getMessage());
        }
        
        return Math.min(100.0, Math.max(0.0, score));
    }
    
    /**
     * Calculate severity based on confidence score and context
     */
    private String calculateSeverity(double confidenceScore) {
        // Base severity on confidence score
        if (confidenceScore >= MIN_CONFIDENCE_HIGH) {
            return "High";
        } else if (confidenceScore >= MIN_CONFIDENCE_MEDIUM) {
            return "Medium";
        } else {
            return "Low";
        }
    }
    
    /**
     * Helper method to check if value is a common word
     */
    private boolean isCommonWord(String value) {
        if (value == null) return true;
        
        String lowerValue = value.toLowerCase();
        
        for (String commonWord : FALSE_POSITIVE_PATTERNS) {
            if (lowerValue.equals(commonWord)) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * Helper method to check if value is Base64 encoded
     */
    private boolean isBase64Encoded(String value) {
        if (value == null || value.length() < 4) return false;
        
        // Basic Base64 pattern check
        return Pattern.matches("^[A-Za-z0-9+/]*={0,2}$", value) && value.length() % 4 == 0;
    }
    
    /**
     * Helper method to check for polyglot payloads
     */
    private boolean isPolyglotPayload(String value) {
        if (value == null) return false;
        
        String lowerValue = value.toLowerCase();
        
        // Check for polyglot indicators
        return (lowerValue.contains("javascript:") && lowerValue.contains("<script")) ||
               (lowerValue.contains("&lt;") && lowerValue.contains("&gt;")) ||
               (lowerValue.contains("/*") && lowerValue.contains("*/") && lowerValue.contains("<"));
    }
    
    /**
     * Helper method to get reflection context
     */
    private String getReflectionContext(String responseBody, int position, int windowSize) {
        if (position < 0 || position >= responseBody.length()) {
            return "";
        }
        
        int start = Math.max(0, position - windowSize);
        int end = Math.min(responseBody.length(), position + windowSize);
        
        return responseBody.substring(start, end);
    }
    
    // =================== AI-POWERED ADVANCED METHODS ===================
    
    /**
     * AI Pattern Validation - World's most advanced pattern recognition
     */
    private boolean passesAIPatternValidation(Map reflectionData, IHttpRequestResponse requestResponse) {
        String paramValue = (String) reflectionData.get(VALUE);
        
        // Check for sophisticated XSS patterns
        if (containsAdvancedXSSPatterns(paramValue)) {
            return true;
        }
        
        // Check for polyglot payloads
        if (isAdvancedPolyglot(paramValue)) {
            return true;
        }
        
        // Check for framework-specific patterns
        if (containsFrameworkPatterns(paramValue)) {
            return true;
        }
        
        // Check for encoded XSS attempts
        if (containsEncodedXSS(paramValue)) {
            return true;
        }
        
        return true; // Pass by default for further analysis
    }
    
    /**
     * Advanced Context Scoring with AI analysis
     */
    private double calculateAdvancedContextScore(Map reflectionData, IHttpRequestResponse requestResponse) {
        double score = calculateContextScore(reflectionData, requestResponse);
        
        try {
            String responseStr = new String(requestResponse.getResponse());
            
            // Bonus for dangerous contexts
            if (responseStr.contains("Content-Type: text/html")) {
                score += 15.0;
            }
            
            // Framework detection bonus
            if (isModernFramework(responseStr)) {
                score += 20.0;
            }
            
            // CSP detection - penalize if strong CSP
            if (hasStrongCSP(responseStr)) {
                score -= 10.0;
            }
            
            // WAF detection - bonus if no WAF
            if (!hasWAFProtection(responseStr)) {
                score += 10.0;
            }
            
        } catch (Exception e) {
            // Continue with base score
        }
        
        return Math.min(100.0, Math.max(0.0, score));
    }
    
    /**
     * AI-Powered Payload Quality Assessment
     */
    private double calculateAIPayloadScore(Map reflectionData) {
        double score = calculatePayloadQualityScore(reflectionData);
        String paramValue = (String) reflectionData.get(VALUE);
        
        // Advanced payload analysis
        if (isWorldClassPayload(paramValue)) {
            score += 25.0;
        }
        
        // WAF bypass techniques
        if (containsWAFBypass(paramValue)) {
            score += 20.0;
        }
        
        // Browser-specific payloads
        if (isBrowserSpecific(paramValue)) {
            score += 15.0;
        }
        
        // Polyglot bonus
        if (isAdvancedPolyglot(paramValue)) {
            score += 30.0;
        }
        
        return Math.min(100.0, Math.max(0.0, score));
    }
    
    /**
     * Deep Response Analysis
     */
    private double calculateDeepResponseScore(Map reflectionData, IHttpRequestResponse requestResponse) {
        double score = calculateResponseContextScore(reflectionData, requestResponse);
        
        try {
            String responseStr = new String(requestResponse.getResponse());
            
            // DOM-based XSS indicators
            if (containsDOMSources(responseStr)) {
                score += 20.0;
            }
            
            // JavaScript framework indicators
            if (containsJSFrameworks(responseStr)) {
                score += 15.0;
            }
            
            // API response indicators
            if (isAPIResponse(responseStr)) {
                score += 10.0;
            }
            
        } catch (Exception e) {
            // Continue with base score
        }
        
        return Math.min(100.0, Math.max(0.0, score));
    }
    
    /**
     * Smart Parameter Type Scoring
     */
    private double calculateSmartParameterScore(Map reflectionData) {
        double score = calculateParameterTypeScore(reflectionData);
        
        // Modern parameter type bonus
        if (reflectionData.containsKey("MODERN_TYPE")) {
            String modernType = (String) reflectionData.get("MODERN_TYPE");
            switch (modernType) {
                case "GRAPHQL":
                    score += 25.0;
                    break;
                case "JWT":
                    score += 30.0;
                    break;
                case "API_KEY":
                    score += 20.0;
                    break;
                case "WEBSOCKET":
                    score += 35.0;
                    break;
            }
        }
        
        return Math.min(100.0, Math.max(0.0, score));
    }
    
    /**
     * Framework-Specific Scoring
     */
    private double calculateFrameworkScore(Map reflectionData, IHttpRequestResponse requestResponse) {
        double score = 50.0;
        
        try {
            String responseStr = new String(requestResponse.getResponse());
            String paramValue = (String) reflectionData.get(VALUE);
            
            // React detection
            if (responseStr.contains("react") || responseStr.contains("React")) {
                if (paramValue.contains("onClick") || paramValue.contains("dangerouslySetInnerHTML")) {
                    score += 30.0;
                }
            }
            
            // Angular detection
            if (responseStr.contains("angular") || responseStr.contains("ng-")) {
                if (paramValue.contains("{{") || paramValue.contains("ng-")) {
                    score += 25.0;
                }
            }
            
            // Vue detection
            if (responseStr.contains("vue") || responseStr.contains("v-")) {
                if (paramValue.contains("v-html") || paramValue.contains("@click")) {
                    score += 25.0;
                }
            }
            
            // GraphQL detection
            if (responseStr.contains("graphql") || responseStr.contains("__schema")) {
                score += 20.0;
            }
            
        } catch (Exception e) {
            // Continue with base score
        }
        
        return Math.min(100.0, Math.max(0.0, score));
    }
    
    /**
     * COMPREHENSIVE Advanced Encoding Analysis - World-Class Detection
     */
    private double calculateEncodingScore(Map reflectionData) {
        double score = 50.0;
        String paramValue = (String) reflectionData.get(VALUE);
        
        if (paramValue == null) return score;
        
        // === BASIC URL ENCODING ===
        if (paramValue.contains("%3C") || paramValue.contains("%3E") || 
            paramValue.contains("%3c") || paramValue.contains("%3e")) {
            score += 15.0;
        }
        
        // === DOUBLE/TRIPLE URL ENCODING ===
        if (paramValue.contains("%253C") || paramValue.contains("%253E") ||
            paramValue.contains("%25253C") || paramValue.contains("%25253E")) {
            score += 25.0; // Higher risk - advanced bypass
        }
        
        // === HTML ENTITY ENCODING ===
        if (paramValue.contains("&lt;") || paramValue.contains("&gt;") ||
            paramValue.contains("&#60;") || paramValue.contains("&#62;") ||
            paramValue.contains("&#x3C;") || paramValue.contains("&#x3E;")) {
            score += 12.0;
        }
        
        // === ADVANCED HTML ENTITIES ===
        if (paramValue.contains("&#x00003C;") || paramValue.contains("&#000000060;") ||
            paramValue.contains("&amp;lt;") || paramValue.contains("&amp;gt;")) {
            score += 20.0; // Advanced entity bypass
        }
        
        // === UNICODE ESCAPES ===
        if (paramValue.contains("\\u003c") || paramValue.contains("\\u003e") ||
            paramValue.contains("\\u003C") || paramValue.contains("\\u003E")) {
            score += 18.0;
        }
        
        // === ADVANCED UNICODE VARIATIONS ===
        if (paramValue.contains("\\u{3c}") || paramValue.contains("\\u{3e}") ||
            paramValue.contains("\\U0000003c") || paramValue.contains("\\U0000003e")) {
            score += 22.0; // Modern JavaScript/ES6 syntax
        }
        
        // === CSS ENCODING ===
        if (paramValue.contains("\\3c ") || paramValue.contains("\\3e ") ||
            paramValue.contains("\\00003c") || paramValue.contains("\\00003e") ||
            paramValue.contains("\\73\\63\\72\\69\\70\\74")) { // \\73 = 's', etc.
            score += 23.0; // CSS encoding is sophisticated
        }
        
        // === JAVASCRIPT STRING ESCAPES ===
        if (paramValue.contains("\\x3c") || paramValue.contains("\\x3e") ||
            paramValue.contains("\\\\x3c") || paramValue.contains("\\\\x3e")) {
            score += 19.0;
        }
        
        // === SQL ENCODING TECHNIQUES ===
        if (paramValue.contains("CHAR(60)") || paramValue.contains("CHAR(62)") ||
            paramValue.contains("0x3c73637269707") || // Hex SQL
            paramValue.toUpperCase().contains("CHAR(")) {
            score += 26.0; // SQL injection context is critical
        }
        
        // === UTF-7 ENCODING ===
        if (paramValue.contains("+ADw-") || paramValue.contains("+AD4-") ||
            paramValue.contains("+AHM-+AGM-+AHI-")) { // UTF-7 script
            score += 28.0; // UTF-7 is rare and dangerous
        }
        
        // === IIS DOUBLE ENCODING ===
        if (paramValue.contains("%u003c") || paramValue.contains("%u003e") ||
            paramValue.contains("%u0073%u0063%u0072")) { // %u encoded 'scr'
            score += 24.0; // IIS-specific bypass
        }
        
        // === OCTAL ENCODING ===
        if (paramValue.contains("\\074") || paramValue.contains("\\076") ||
            paramValue.contains("\\0074") || paramValue.contains("\\0076")) {
            score += 16.0;
        }
        
        // === JSON UNICODE ESCAPES ===
        if ((paramValue.contains("\\\"\\\\u003c") || paramValue.contains("\\\"\\\\\\\\u003c")) &&
            (paramValue.contains("script") || paramValue.contains("\\\\u0073"))) {
            score += 21.0; // JSON context encoding
        }
        
        // === BASE64 ENCODING VARIANTS ===
        if (isBase64XSS(paramValue) || 
            paramValue.startsWith("base64:") || 
            paramValue.startsWith("data:text/html;base64,") ||
            paramValue.matches("^[A-Za-z0-9+/]{20,}={0,2}$")) {
            score += 25.0;
        }
        
        // === PUNYCODE ENCODING ===
        if (paramValue.startsWith("xn--") && paramValue.contains(".")) {
            score += 30.0; // Punycode domain attacks are sophisticated
        }
        
        // === MIXED ENCODING COMBINATIONS ===
        int encodingTypes = 0;
        if (paramValue.contains("%") && (paramValue.contains("\\u") || paramValue.contains("&#"))) encodingTypes++;
        if (paramValue.contains("\\u") && paramValue.contains("&#")) encodingTypes++;
        if (paramValue.contains("\\x") && paramValue.contains("%")) encodingTypes++;
        if (encodingTypes > 0) {
            score += (encodingTypes * 15.0); // Multiple encoding types = advanced bypass
        }
        
        // === UNICODE NORMALIZATION BYPASSES ===
        if (containsHomographAttack(paramValue) || containsUnicodeNormalizationBypass(paramValue)) {
            score += 35.0; // Homograph attacks are very sophisticated
        }
        
        // === ZERO-WIDTH AND INVISIBLE CHARACTERS ===
        if (paramValue.contains("\\u200B") || paramValue.contains("\\uFEFF") ||
            paramValue.contains("\\u202E") || paramValue.contains("\\u202D")) {
            score += 27.0; // Zero-width character attacks
        }
        
        // === CONTROL CHARACTER BYPASSES ===
        if (paramValue.contains("\\u0000") || paramValue.contains("\\u0001") ||
            paramValue.contains("\\u007F") || paramValue.contains("\\u0009")) {
            score += 20.0; // Control character injection
        }
        
        // === ALTERNATIVE SPACE CHARACTERS ===
        if (paramValue.contains("\\u2000") || paramValue.contains("\\u2006") ||
            paramValue.contains("\\u205F") || paramValue.contains("\\u00A0")) {
            score += 18.0; // Alternative space bypasses
        }
        
        // === FULLWIDTH CHARACTER ENCODING ===
        if (paramValue.contains("\\uFF1C") || paramValue.contains("\\uFF1E")) {
            score += 29.0; // Fullwidth character bypass is rare
        }
        
        // === VARIATION SELECTORS AND COMBINING CHARACTERS ===
        if (paramValue.contains("\\uFE00") || paramValue.contains("\\uFE0F") ||
            paramValue.contains("\\u0300") || paramValue.contains("\\u0301")) {
            score += 31.0; // Very advanced Unicode manipulation
        }
        
        // === MATHEMATICAL ALPHANUMERIC SYMBOLS ===
        if (paramValue.contains("\\uD835\\uDCCE") || // Mathematical bold
            paramValue.contains("\\uD835")) {
            score += 33.0; // Mathematical Unicode symbols are extremely rare
        }
        
        // === ESCAPE SEQUENCE VARIATIONS ===
        if (paramValue.contains("\\\\\\\\u003c") || paramValue.contains("\\\\\\\\x3c")) {
            score += 24.0; // Multiple escape levels
        }
        
        return Math.min(100.0, Math.max(0.0, score));
    }
    
    /**
     * Detect homograph attacks using Unicode lookalikes
     */
    private boolean containsHomographAttack(String value) {
        // Check for Cyrillic characters that look like Latin
        return value.contains("\\u0430") || // Cyrillic 'a'
               value.contains("\\u043B") || // Cyrillic 'l' 
               value.contains("\\u0435") || // Cyrillic 'e'
               value.contains("\\u043E") || // Cyrillic 'o'
               value.contains("\\u0440") || // Cyrillic 'p'
               value.contains("\\u0443") || // Cyrillic 'u'
               value.contains("\\u0440") || // Cyrillic 'r'
               value.contains("\\u0442"); // Cyrillic 't'
    }
    
    /**
     * Detect Unicode normalization bypass attempts
     */
    private boolean containsUnicodeNormalizationBypass(String value) {
        // Check for accented characters and combining marks
        return value.contains("\\u1E9C") || // Unicode escape for XSS bypass
value.contains("\\u1EBF") || // Unicode escape for XSS bypass
               value.contains("\\u0300") || // Combining grave accent
               value.contains("\\u0301") || // Combining acute accent
               value.contains("\\u0302") || // Combining circumflex
               value.contains("\\u0303"); // Combining tilde
    }
    
    /**
     * Behavioral Pattern Analysis
     */
    private double calculateBehaviorScore(Map reflectionData, IHttpRequestResponse requestResponse) {
        double score = 50.0;
        
        try {
            String paramValue = (String) reflectionData.get(VALUE);
            @SuppressWarnings("unchecked")
            List<int[]> matches = (List<int[]>) reflectionData.get(MATCHES);
            
            // Multiple reflections bonus
            if (matches != null && matches.size() > 1) {
                score += 15.0;
            }
            
            // Length-based analysis
            if (paramValue.length() > 50 && paramValue.length() < 200) {
                score += 10.0; // Sweet spot for XSS payloads
            }
            
            // Character diversity analysis
            if (hasHighCharacterDiversity(paramValue)) {
                score += 15.0;
            }
            
        } catch (Exception e) {
            // Continue with base score
        }
        
        return Math.min(100.0, Math.max(0.0, score));
    }
    
    /**
     * AI Confidence Boost Algorithm
     */
    private double applyAIConfidenceBoost(double baseScore, Map reflectionData, IHttpRequestResponse requestResponse) {
        double boostedScore = baseScore;
        String paramValue = (String) reflectionData.get(VALUE);
        
        // World-class payload detection
        if (paramValue != null) {
            for (String payload : ADVANCED_XSS_PAYLOADS) {
                if (payload != null && paramValue.toLowerCase().contains(payload.toLowerCase().substring(0, Math.min(10, payload.length())))) {
                    boostedScore += 15.0;
                    break;
                }
            }
        }
        
        // Context-specific boost
        if (reflectionData.containsKey(VULNERABLE)) {
            String contextInfo = (String) reflectionData.get(VULNERABLE);
            if (contextInfo.contains("Script") && paramValue.contains("script")) {
                boostedScore += 20.0; // Perfect context match
            }
        }
        
        return Math.min(100.0, boostedScore);
    }
    
    /**
     * AI-based Severity Calculation
     */
    private String calculateAISeverity(double confidenceScore, Map reflectionData) {
        String paramValue = (String) reflectionData.get(VALUE);
        
        // Critical severity for polyglots and advanced payloads
        if (confidenceScore >= 90.0 || isWorldClassPayload(paramValue)) {
            return "Critical";
        } else if (confidenceScore >= 75.0) {
            return "High";
        } else if (confidenceScore >= 50.0) {
            return "Medium";
        } else {
            return "Low";
        }
    }
    
    /**
     * Advanced AI Filtering Decision
     */
    private boolean shouldFilterWithAI(double confidenceScore, Map reflectionData, IHttpRequestResponse requestResponse) {
        // Never filter high-confidence detections
        if (confidenceScore >= 80.0) {
            return false;
        }
        
        // Advanced pattern check
        String paramValue = (String) reflectionData.get(VALUE);
        if (isWorldClassPayload(paramValue)) {
            return false; // Never filter world-class payloads
        }
        
        // Context-based decision
        if (confidenceScore >= 60.0 && hasAdvancedContext(reflectionData)) {
            return false;
        }
        
        // Filter low confidence
        return confidenceScore < 45.0;
    }
    
    /**
     * AI Filter Reason Generator
     */
    private String getAIFilterReason(double confidenceScore, Map reflectionData) {
        String paramValue = (String) reflectionData.get(VALUE);
        
        if (confidenceScore < 30.0) {
            return "Very low confidence (" + String.format("%.1f", confidenceScore) + "%)";
        } else if (isCommonWord(paramValue)) {
            return "Common word pattern detected";
        } else if (paramValue.length() < MIN_PAYLOAD_LENGTH) {
            return "Payload too short for XSS";
        } else {
            return "Low confidence score (" + String.format("%.1f", confidenceScore) + "%)";
        }
    }
    
    // =================== HELPER METHODS ===================
    
    private boolean containsAdvancedXSSPatterns(String value) {
        String[] advancedPatterns = {
            "javascript:", "<script", "onerror=", "onload=", "eval\\(", 
            "String.fromCharCode", "atob\\(", "btoa\\(", "constructor.constructor"
        };
        
        for (String pattern : advancedPatterns) {
            if (Pattern.compile(pattern, Pattern.CASE_INSENSITIVE).matcher(value).find()) {
                return true;
            }
        }
        return false;
    }
    
    private boolean isAdvancedPolyglot(String value) {
        // Check for polyglot characteristics
        return value.contains("javascript:") && value.contains("<script") && value.contains("alert");
    }
    
    private boolean containsFrameworkPatterns(String value) {
        String[] frameworkPatterns = {"{{", "}}", "${", "v-html", "dangerouslySetInnerHTML", "ng-bind-html"};
        for (String pattern : frameworkPatterns) {
            if (value.contains(pattern)) return true;
        }
        return false;
    }
    
    private boolean containsEncodedXSS(String value) {
        return ENCODED_PAYLOAD_PATTERN.matcher(value).find() && 
               (value.toLowerCase().contains("script") || value.toLowerCase().contains("alert"));
    }
    
    private boolean isModernFramework(String response) {
        String[] frameworks = {"react", "angular", "vue", "svelte", "next.js"};
        String lowerResponse = response.toLowerCase();
        for (String framework : frameworks) {
            if (lowerResponse.contains(framework)) return true;
        }
        return false;
    }
    
    private boolean hasStrongCSP(String response) {
        return response.contains("Content-Security-Policy") && 
               response.contains("'unsafe-inline'") == false;
    }
    
    private boolean hasWAFProtection(String response) {
        String[] wafHeaders = {"X-WAF", "cloudflare", "akamai", "incapsula"};
        String lowerResponse = response.toLowerCase();
        for (String waf : wafHeaders) {
            if (lowerResponse.contains(waf)) return true;
        }
        return false;
    }
    
    private boolean isWorldClassPayload(String value) {
        // Check against our advanced payload database
        if (value != null) {
            for (String payload : ADVANCED_XSS_PAYLOADS) {
                if (payload != null && value.toLowerCase().contains(payload.toLowerCase().substring(0, Math.min(15, payload.length())))) {
                    return true;
                }
            }
        }
        return false;
    }
    
    private boolean containsWAFBypass(String value) {
        String[] bypassTechniques = {"\\u", "\\x", "String.fromCharCode", "eval", "atob"};
        for (String technique : bypassTechniques) {
            if (value.contains(technique)) return true;
        }
        return false;
    }
    
    private boolean isBrowserSpecific(String value) {
        String[] browserSpecific = {"moz-", "webkit-", "ms-", "o-"};
        for (String prefix : browserSpecific) {
            if (value.contains(prefix)) return true;
        }
        return false;
    }
    
    private boolean containsDOMSources(String response) {
        for (String source : DOM_SOURCES) {
            if (response.contains(source)) return true;
        }
        return false;
    }
    
    private boolean containsJSFrameworks(String response) {
        String[] jsFrameworks = {"jquery", "lodash", "underscore", "backbone"};
        String lowerResponse = response.toLowerCase();
        for (String framework : jsFrameworks) {
            if (lowerResponse.contains(framework)) return true;
        }
        return false;
    }
    
    private boolean isAPIResponse(String response) {
        return response.contains("Content-Type: application/json") ||
               response.contains("Content-Type: application/xml");
    }
    
    private boolean isBase64XSS(String value) {
        try {
            if (value.matches("^[A-Za-z0-9+/]*={0,2}$") && value.length() > 10) {
                String decoded = new String(java.util.Base64.getDecoder().decode(value));
                return decoded.contains("script") || decoded.contains("alert");
            }
        } catch (Exception e) {
            // Not valid base64
        }
        return false;
    }
    
    private boolean hasHighCharacterDiversity(String value) {
        java.util.Set<Character> uniqueChars = new java.util.HashSet<>();
        for (char c : value.toCharArray()) {
            uniqueChars.add(c);
        }
        return uniqueChars.size() > value.length() * 0.6;
    }
    
    private boolean hasAdvancedContext(Map reflectionData) {
        String reflectedIn = (String) reflectionData.get(REFLECTED_IN);
        return BODY.equals(reflectedIn) || BOTH.equals(reflectedIn);
    }
    
    /**
     * Apply cutting-edge technique bonus scoring
     * Boosts confidence for advanced XSS techniques
     */
    private double applyCuttingEdgeBonus(double baseScore, Map reflectionData, IHttpRequestResponse requestResponse) {
        double bonus = 0.0;
        String paramValue = (String) reflectionData.get(VALUE);
        
        if (paramValue != null) {
            String valueLower = paramValue.toLowerCase();
            
            // CUTTING-EDGE TECHNIQUE DETECTION BONUSES
            
            // PRODUCTION: Reduced logging for cutting-edge detections
            boolean foundCuttingEdge = false;
            String detectionType = "";
            
            // Prototype Pollution XSS
            if (valueLower.contains("prototype") || valueLower.contains("__proto__")) {
                bonus += 15.0;
                foundCuttingEdge = true;
                detectionType = "Prototype Pollution XSS";
            }
            
            // PostMessage XSS
            if (valueLower.contains("postmessage") || valueLower.contains("onmessage")) {
                bonus += 12.0;
                foundCuttingEdge = true;
                detectionType = "PostMessage XSS";
            }
            
            // Web Components XSS
            if (valueLower.contains("customelement") || valueLower.contains("define")) {
                bonus += 10.0;
                foundCuttingEdge = true;
                detectionType = "Web Components XSS";
            }
            
            // Shadow DOM XSS
            if (valueLower.contains("shadow") && (valueLower.contains("root") || valueLower.contains("dom"))) {
                bonus += 10.0;
                foundCuttingEdge = true;
                detectionType = "Shadow DOM XSS";
            }
            
            // Dynamic Import XSS
            if (valueLower.contains("import(")) {
                bonus += 12.0;
                foundCuttingEdge = true;
                detectionType = "Dynamic Import XSS";
            }
            
            // WebAssembly XSS
            if (valueLower.contains("webassembly") || valueLower.contains("wasmmodule")) {
                bonus += 15.0;
                foundCuttingEdge = true;
                detectionType = "WebAssembly XSS";
            }
            
            // Modern Browser API XSS
            if (valueLower.contains("navigator.") || valueLower.contains("clipboard") || 
                valueLower.contains("credentials") || valueLower.contains("locks")) {
                bonus += 8.0;
                foundCuttingEdge = true;
                detectionType = "Modern Browser API XSS";
            }
            
            // Rate-limited cutting-edge detection logging
            if (foundCuttingEdge) {
                long currentTime = System.currentTimeMillis();
                if (currentTime - lastCuttingEdgeDetectionMessage > 5000) { // Once every 5 seconds
                    callbacks.printOutput("[DETECTION] " + detectionType + " pattern detected");
                    lastCuttingEdgeDetectionMessage = currentTime;
                }
            }
            
            // Advanced JavaScript patterns
            if (valueLower.contains("constructor") || valueLower.contains("settimeout") ||
                valueLower.contains("setinterval") || valueLower.contains("requestanimationframe")) {
                bonus += 8.0;
            }
            
            // JSFucker or esoteric patterns
            if (valueLower.matches(".*[\\[\\]\\(\\)!\\+]{10,}.*")) {
                bonus += 20.0;
                // Rate-limited JSFucker detection
                long currentTime = System.currentTimeMillis();
                if (currentTime - lastCuttingEdgeDetectionMessage > 5000) {
                    callbacks.printOutput("[DETECTION] JSFucker/Esoteric XSS pattern detected");
                    lastCuttingEdgeDetectionMessage = currentTime;
                }
            }
            
            // Modern frameworks (React, Vue, Angular context)
            if (valueLower.contains("react") || valueLower.contains("vue") || 
                valueLower.contains("angular") || valueLower.contains("dangerouslysetinnerhtml")) {
                bonus += 5.0;
            }
        }
        
        // JSON response bonus - with throttling to prevent spam
        Boolean isJSON = (Boolean) reflectionData.get("IS_JSON_RESPONSE");
        if (Boolean.TRUE.equals(isJSON)) {
            bonus += 10.0;
            // Rate limit JSON detection messages to prevent spam
            long currentTime = System.currentTimeMillis();
            if (currentTime - lastJSONDetectionMessage > 2000) { // Only once every 2 seconds
                callbacks.printOutput("[DETECTION] JSON response XSS - Higher risk");
                lastJSONDetectionMessage = currentTime;
            }
        }
        
        // Modern parameter type bonus
        if (reflectionData.containsKey("MODERN_TYPE")) {
            String modernType = (String) reflectionData.get("MODERN_TYPE");
            switch (modernType) {
                case "GRAPHQL":
                    bonus += 12.0;
                    break;
                case "JWT":
                    bonus += 15.0;
                    break;
                case "JSON":
                    bonus += 8.0;
                    break;
            }
        }
        
        return baseScore + bonus;
    }
    
    /**
     * Advanced filtering approach - IMPROVED to reduce false positives
     * Filters reflections in safe contexts while preserving legitimate XSS detections
     */
    private boolean shouldFilterMinimal(double confidenceScore, Map reflectionData, IHttpRequestResponse requestResponse) {
        String paramValue = (String) reflectionData.get(VALUE);

        // === FILTER 1: Very low confidence without XSS indicators ===
        if (confidenceScore < 25.0) {
            if (paramValue != null && containsXSSIndicators(paramValue)) {
                return false; // Don't filter if it has XSS indicators
            }
            return true; // Filter low confidence without indicators
        }

        // === FILTER 2: Obvious non-XSS patterns ===
        if (paramValue != null) {
            // Pure numeric values
            if (paramValue.matches("^\\d+$")) {
                return true;
            }

            // Very short values without XSS chars
            if (paramValue.length() < 3 && !containsXSSIndicators(paramValue)) {
                return true;
            }

            // Common non-XSS values
            String[] commonValues = {"true", "false", "yes", "no", "null", "undefined", "0", "1", "en", "us"};
            for (String common : commonValues) {
                if (paramValue.equalsIgnoreCase(common)) {
                    return true;
                }
            }
        }

        // === FILTER 3: Check if reflection is in safe context ===
        if (requestResponse != null && paramValue != null) {
            // Check if payload is safely encoded (HTML entities)
            if (isPayloadSafelyEncoded(requestResponse, paramValue)) {
                callbacks.printOutput("[Filter] Payload is safely HTML-encoded - filtering as false positive");
                return true;
            }

            // Check if reflection is in a safe context (comments, CDATA, etc.)
            if (isReflectionInSafeContext(requestResponse, paramValue)) {
                callbacks.printOutput("[Filter] Reflection is in safe context - filtering as false positive");
                return true;
            }
        }

        // === FILTER 4: Confidence-based filtering ===
        // Medium confidence (25-50) - filter if no strong XSS indicators
        if (confidenceScore < 50.0 && paramValue != null && !containsStrongXSSIndicators(paramValue)) {
            return true;
        }

        return false; // Don't filter - potential true positive
    }

    /**
     * Check if reflection is in a safe (non-executable) context
     */
    private boolean isReflectionInSafeContext(IHttpRequestResponse requestResponse, String payload) {
        try {
            if (requestResponse == null || payload == null) return false;

            byte[] response = requestResponse.getResponse();
            if (response == null) return false;

            int bodyOffset = helpers.analyzeResponse(response).getBodyOffset();
            String responseBody = new String(Arrays.copyOfRange(response, bodyOffset, response.length));

            int payloadPos = responseBody.indexOf(payload);
            if (payloadPos < 0) return false;

            // Get context around payload
            int windowStart = Math.max(0, payloadPos - 200);
            int windowEnd = Math.min(responseBody.length(), payloadPos + payload.length() + 200);
            String contextBefore = responseBody.substring(windowStart, payloadPos);
            String contextAfter = responseBody.substring(payloadPos + payload.length(), windowEnd);

            // Check for HTML comment
            int lastCommentStart = contextBefore.lastIndexOf("<!--");
            int lastCommentEnd = contextBefore.lastIndexOf("-->");
            if (lastCommentStart > lastCommentEnd && contextAfter.contains("-->")) {
                return true; // In HTML comment
            }

            // Check for CDATA section
            int lastCDATA = contextBefore.lastIndexOf("<![CDATA[");
            int lastCDATAEnd = contextBefore.lastIndexOf("]]>");
            if (lastCDATA > lastCDATAEnd && contextAfter.contains("]]>")) {
                return true; // In CDATA
            }

            // Check for JavaScript comment (single-line)
            int lastNewline = contextBefore.lastIndexOf("\n");
            String sameLine = (lastNewline >= 0) ? contextBefore.substring(lastNewline) : contextBefore;
            if (sameLine.contains("//") && !sameLine.contains("://")) {
                return true; // In JS single-line comment
            }

            // Check for JavaScript block comment
            int lastBlockStart = contextBefore.lastIndexOf("/*");
            int lastBlockEnd = contextBefore.lastIndexOf("*/");
            if (lastBlockStart > lastBlockEnd && contextAfter.contains("*/")) {
                return true; // In JS block comment
            }

            // Check for textarea/xmp (text context)
            String[] textTags = {"textarea", "xmp", "plaintext"};
            for (String tag : textTags) {
                int tagOpen = contextBefore.toLowerCase().lastIndexOf("<" + tag);
                int tagClose = contextBefore.toLowerCase().lastIndexOf("</" + tag);
                if (tagOpen > tagClose) {
                    return true; // In text context element
                }
            }

        } catch (Exception e) {
            // Error - don't filter
        }
        return false;
    }

    /**
     * Check for STRONG XSS indicators (high confidence patterns)
     */
    private boolean containsStrongXSSIndicators(String value) {
        if (value == null) return false;
        String lower = value.toLowerCase();

        // Strong indicators that almost certainly indicate XSS attempt
        return lower.contains("<script") ||
               lower.contains("javascript:") ||
               lower.contains("onerror=") ||
               lower.contains("onload=") ||
               lower.contains("onclick=") ||
               lower.contains("onmouseover=") ||
               lower.contains("onfocus=") ||
               lower.contains("eval(") ||
               lower.contains("document.cookie") ||
               lower.contains("document.write") ||
               (lower.contains("<") && lower.contains(">") && lower.contains("="));
    }
    
    /**
     * Check if value contains XSS indicators
     */
    private boolean containsXSSIndicators(String value) {
        if (value == null) return false;
        
        String lowerValue = value.toLowerCase();
        
        // Check for XSS patterns
        for (String pattern : XSS_PATTERNS) {
            if (Pattern.compile(pattern, Pattern.CASE_INSENSITIVE).matcher(value).find()) {
                return true;
            }
        }
        
        // Check for HTML tags
        if (lowerValue.contains("<") && lowerValue.contains(">")) {
            return true;
        }
        
        // Check for JavaScript protocol
        if (lowerValue.contains("javascript:") || lowerValue.contains("data:")) {
            return true;
        }
        
        // Check for event handlers
        if (Pattern.compile("on\\w+\\s*=", Pattern.CASE_INSENSITIVE).matcher(value).find()) {
            return true;
        }
        
        // Check for encoded XSS attempts
        if (ENCODED_PAYLOAD_PATTERN.matcher(value).find() && 
            (lowerValue.contains("script") || lowerValue.contains("alert"))) {
            return true;
        }
        
        return false;
    }
    
    /**
     * Check if payload is safely encoded in response (not exploitable)
     * IMPROVED: More thorough encoding detection
     */
    private boolean isPayloadSafelyEncoded(IHttpRequestResponse requestResponse, String payload) {
        try {
            if (requestResponse == null || payload == null) {
                return false;
            }

            // Only check payloads that contain dangerous characters
            if (!payload.contains("<") && !payload.contains(">") &&
                !payload.contains("\"") && !payload.contains("'")) {
                return false; // No dangerous chars to encode
            }

            byte[] response = requestResponse.getResponse();
            if (response == null) return false;

            int bodyOffset = helpers.analyzeResponse(response).getBodyOffset();
            String responseBody = new String(Arrays.copyOfRange(response, bodyOffset, response.length));

            // Check if RAW payload is in response
            boolean hasRaw = responseBody.contains(payload);

            // If raw payload is present, check for context
            if (hasRaw) {
                // Raw payload present - might still be safe if in comment/CDATA
                // But generally not safe
                return false;
            }

            // Raw payload NOT present - check for encoded versions

            // Check 1: Full HTML entity encoding
            String htmlEncoded = payload.replace("<", "&lt;").replace(">", "&gt;")
                                       .replace("\"", "&quot;").replace("'", "&#39;");
            if (responseBody.contains(htmlEncoded)) {
                callbacks.printOutput("[SafeEncoding] Payload is HTML-entity encoded (full) - SAFE");
                return true;
            }

            // Check 2: Partial HTML entity encoding (just < and >)
            String partialEncoded = payload.replace("<", "&lt;").replace(">", "&gt;");
            if (responseBody.contains(partialEncoded)) {
                callbacks.printOutput("[SafeEncoding] Payload is HTML-entity encoded (< >) - SAFE");
                return true;
            }

            // Check 3: Numeric HTML entities
            String numericEncoded = payload.replace("<", "&#60;").replace(">", "&#62;")
                                          .replace("\"", "&#34;").replace("'", "&#39;");
            if (responseBody.contains(numericEncoded)) {
                callbacks.printOutput("[SafeEncoding] Payload is numeric HTML-entity encoded - SAFE");
                return true;
            }

            // Check 4: Hex HTML entities
            String hexEncoded = payload.replace("<", "&#x3c;").replace(">", "&#x3e;")
                                      .replace("\"", "&#x22;").replace("'", "&#x27;");
            if (responseBody.contains(hexEncoded) || responseBody.contains(hexEncoded.toUpperCase())) {
                callbacks.printOutput("[SafeEncoding] Payload is hex HTML-entity encoded - SAFE");
                return true;
            }

            // Check 5: JavaScript Unicode escapes
            String jsUnicodeEncoded = payload.replace("<", "\\u003c").replace(">", "\\u003e")
                                            .replace("\"", "\\u0022").replace("'", "\\u0027");
            if (responseBody.contains(jsUnicodeEncoded) || responseBody.contains(jsUnicodeEncoded.toUpperCase())) {
                callbacks.printOutput("[SafeEncoding] Payload is JS Unicode-escaped - SAFE");
                return true;
            }

            // Check 6: URL encoding (if not already URL-encoded payload)
            if (!payload.contains("%")) {
                String urlEncoded = helpers.urlEncode(payload);
                if (responseBody.contains(urlEncoded) && !responseBody.contains(payload)) {
                    callbacks.printOutput("[SafeEncoding] Payload is URL-encoded in response - SAFE");
                    return true;
                }
            }

            // Check 7: JSON string escaping
            String jsonEncoded = payload.replace("\\", "\\\\").replace("\"", "\\\"")
                                       .replace("<", "\\u003c").replace(">", "\\u003e");
            if (responseBody.contains(jsonEncoded)) {
                callbacks.printOutput("[SafeEncoding] Payload is JSON-escaped - SAFE");
                return true;
            }

            return false; // Not encoded
        } catch (Exception e) {
            return false; // On error, don't filter
        }
    }
    
    /**
     * Minimal filter reason - detailed explanations for researchers
     */
    private String getMinimalFilterReason(double confidenceScore, Map reflectionData) {
        if (confidenceScore < 20.0) {
            String paramValue = (String) reflectionData.get(VALUE);
            if (paramValue != null && !containsXSSIndicators(paramValue)) {
                return "Very low confidence score (" + String.format("%.1f", confidenceScore) + "%) - No XSS indicators detected";
            }
            return "Very low confidence score (" + String.format("%.1f", confidenceScore) + "%)";
        }
        
        String paramValue = (String) reflectionData.get(VALUE);
        if (paramValue != null) {
            if (paramValue.matches("^\\d+$") && !paramValue.contains("<") && !paramValue.contains(">")) {
                return "Numeric value only - No XSS characters present";
            }
            if (paramValue.length() < 3 && !containsXSSIndicators(paramValue)) {
                return "Value too short (< 3 chars) - No XSS indicators";
            }
            
            // Note: RequestResponse check would require it to be passed in reflectionData
            // For now, we rely on confidence score and XSS indicators
        }
        
        return "Common non-XSS value pattern";
    }
}

/**
 * Result class for filtering analysis
 */
class FilterResult {
    private boolean filtered;
    private double confidenceScore;
    private String severity;
    private String reason;
    
    public FilterResult() {
        this.filtered = false;
        this.confidenceScore = 0.0;
        this.severity = "Low";
        this.reason = "";
    }
    
    // Getters and setters
    public boolean isFiltered() { return filtered; }
    public void setFiltered(boolean filtered) { this.filtered = filtered; }
    
    public double getConfidenceScore() { return confidenceScore; }
    public void setConfidenceScore(double confidenceScore) { this.confidenceScore = confidenceScore; }
    
    public String getSeverity() { return severity; }
    public void setSeverity(String severity) { this.severity = severity; }
    
    public String getReason() { return reason; }
    public void setReason(String reason) { this.reason = reason; }
} 