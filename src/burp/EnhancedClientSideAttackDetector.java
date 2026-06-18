package burp;

import java.util.*;
import java.util.regex.Pattern;
import java.util.regex.Matcher;
import java.nio.charset.StandardCharsets;

/**
 * Enhanced Client-Side Attack Detector
 * Comprehensive detection for all types of client-side attacks
 */
public class EnhancedClientSideAttackDetector {
    
    private final IExtensionHelpers helpers;
    private final IBurpExtenderCallbacks callbacks;
    private final Settings settings;
    
    // CSP Bypass Detection Patterns
    private static final String[] CSP_BYPASS_PATTERNS = {
        "unsafe-inline", "unsafe-eval", "data:", "javascript:", "vbscript:",
        "nonce=", "unsafe-hashes", "strict-dynamic", "unsafe-allow-redirects"
    };
    
    // PostMessage Attack Patterns
    private static final String[] POSTMESSAGE_PATTERNS = {
        "addEventListener('message'", "onmessage", "window.postMessage",
        "postMessage(", "message", "origin", "source"
    };

    // High-signal sources for DOM/client-side injection (taint sources)
    private static final String[] TAINT_SOURCES = {
        "location.href", "location.search", "location.hash", "document.url", "document.documenturi",
        "document.referrer", "window.name", "localStorage", "sessionStorage",
        "event.data", "message.data", "e.data"
    };

    // High-impact sinks (execution / HTML injection)
    private static final String[] TAINT_SINKS = {
        "innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "document.writeln",
        "eval(", "Function(", "setTimeout(", "setInterval(", "location=", "location.href=",
        ".src=", ".href=", "setAttribute("
    };
    
    // WebSocket Attack Patterns
    private static final String[] WEBSOCKET_PATTERNS = {
        "WebSocket", "ws://", "wss://", "socket.io", "websocket",
        "onopen", "onmessage", "onclose", "onerror", "send("
    };
    
    // Client-Side Template Injection Patterns - CRITICAL: Only match patterns likely to be exploitable
    // Generic tokens like "{{" or "${" are too common in normal JS/HTML templates
    private static final String[] TEMPLATE_INJECTION_PATTERNS = {
        "{{7*7}}", "{{constructor.constructor", "{{config", "{{settings",
        "{{self.__init__", "{{request.", "{{''.__class__",
        "${alert(", "${document.", "${window.", "<%=alert(", "<%=eval("
    };

    // Prototype Pollution Patterns - CRITICAL: Only match actual pollution vectors
    // "constructor" and "prototype" alone appear in every JS file
    private static final String[] PROTOTYPE_POLLUTION_PATTERNS = {
        "__proto__", "Object.prototype.", "Array.prototype.",
        "constructor.prototype", "constructor[", "__proto__["
    };
    
    // Modern Browser API Attack Patterns
    private static final String[] MODERN_API_PATTERNS = {
        "SharedArrayBuffer", "BroadcastChannel", "Cache API", "Service Worker",
        "Web Workers", "Dynamic Import", "WebAssembly", "Trusted Types",
        // REAL-TIME DYNAMIC PATTERNS
        "MutationObserver", "ResizeObserver", "IntersectionObserver", "PerformanceObserver",
        "WebSocket", "EventSource", "Server-Sent Events", "requestAnimationFrame",
        "Promise", "async", "await", "Proxy", "Reflect", "Generator", "Iterator",
        "Symbol", "WeakMap", "WeakSet", "Map", "Set", "TypedArray", "DataView",
        "AbortController", "AbortSignal", "IntersectionObserver", "ResizeObserver",
        "PerformanceObserver", "ReportingObserver", "LayoutShift", "FirstInput",
        "LargestContentfulPaint", "CumulativeLayoutShift", "TimeToFirstByte"
    };
    
    // Web Components Attack Patterns
    private static final String[] WEB_COMPONENTS_PATTERNS = {
        "customElements.define", "Shadow DOM", "Web Components",
        "HTMLElement", "connectedCallback", "attributeChangedCallback",
        // REAL-TIME DYNAMIC WEB COMPONENTS
        "disconnectedCallback", "adoptedCallback", "observedAttributes",
        "attachShadow", "shadowRoot", "slot", "template", "HTMLTemplateElement",
        "DocumentFragment", "createDocumentFragment", "importNode", "adoptNode"
    };
    
    // REAL-TIME DYNAMIC ATTACK PATTERNS
    private static final String[] REALTIME_DYNAMIC_PATTERNS = {
        // Live DOM Monitoring
        "MutationObserver", "ResizeObserver", "IntersectionObserver", "PerformanceObserver",
        "ReportingObserver", "LayoutShift", "FirstInput", "LargestContentfulPaint",
        
        // Real-time Communication
        "WebSocket", "EventSource", "Server-Sent Events", "BroadcastChannel",
        "postMessage", "MessageChannel", "SharedWorker", "ServiceWorker",
        
        // Dynamic Code Execution
        "Dynamic Import", "import()", "import.meta", "import.meta.url",
        "WebAssembly", "WASM", "WebAssembly.instantiate", "WebAssembly.compile",
        
        // Advanced JavaScript Features
        "Proxy", "Reflect", "Symbol", "WeakMap", "WeakSet", "Map", "Set",
        "TypedArray", "DataView", "SharedArrayBuffer", "Atomics",
        
        // Asynchronous Patterns
        "Promise", "async", "await", "Generator", "Iterator", "Symbol.iterator",
        "requestAnimationFrame", "requestIdleCallback", "setImmediate",
        
        // Modern DOM APIs
        "IntersectionObserver", "ResizeObserver", "PerformanceObserver",
        "ReportingObserver", "LayoutShift", "FirstInput", "LargestContentfulPaint",
        "CumulativeLayoutShift", "TimeToFirstByte", "Navigation Timing",
        
        // Web APIs
        "Fetch API", "Streams API", "ReadableStream", "WritableStream",
        "TransformStream", "CompressionStream", "DecompressionStream",
        
        // Storage APIs
        "IndexedDB", "WebSQL", "localStorage", "sessionStorage",
        "Cache API", "Service Worker Cache", "Background Sync",
        
        // Security APIs
        "Trusted Types", "Sanitizer API", "Credential Management",
        "Web Authentication", "Payment Request API", "Web Crypto API"
    };
    
    public EnhancedClientSideAttackDetector(IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks, Settings settings) {
        this.helpers = helpers;
        this.callbacks = callbacks;
        this.settings = settings;
    }
    
    /**
     * Comprehensive Client-Side Attack Analysis with Enhanced Detection
     */
    public ClientSideAttackResult analyzeClientSideAttacks(IHttpRequestResponse requestResponse) {
        ClientSideAttackResult result = new ClientSideAttackResult();
        
        try {
            if (requestResponse == null || requestResponse.getResponse() == null) {
                callbacks.printError("Invalid request/response for client-side analysis");
                return result;
            }
            
            byte[] response = requestResponse.getResponse();
            int bodyOffset = helpers.analyzeResponse(response).getBodyOffset();
            String responseBody = new String(Arrays.copyOfRange(response, bodyOffset, response.length), StandardCharsets.UTF_8);
            
            // Analyze headers for CSP
            String headers = new String(Arrays.copyOfRange(response, 0, bodyOffset), StandardCharsets.UTF_8);
            
            // Perform comprehensive analysis with all detection types (gated by Settings where available)
            boolean enablePostMessage = settings == null || Boolean.TRUE.equals(settings.getEnablePostMessageXSS());
            boolean enablePrototype = settings == null || Boolean.TRUE.equals(settings.getEnablePrototypePollution());
            boolean enableWebComponents = settings == null || Boolean.TRUE.equals(settings.getEnableWebComponents());
            boolean enableModernApi = settings == null || Boolean.TRUE.equals(settings.getEnableModernBrowserAPI()) || Boolean.TRUE.equals(settings.getEnableWebAssembly());
            boolean enableCSPAnalysis = settings == null || Boolean.TRUE.equals(settings.getCspAnalysis());
            boolean enableCSPBypass = settings == null || Boolean.TRUE.equals(settings.getEnableCSPBypass());

            result.setCspAnalysis(enableCSPAnalysis ? analyzeCSP(headers, responseBody) : new CSPAnalysisResult());
            result.setPostMessageAnalysis(enablePostMessage ? analyzePostMessage(responseBody) : new PostMessageAnalysisResult());
            result.setWebSocketAnalysis(analyzeWebSocket(responseBody));
            result.setTemplateInjectionAnalysis(analyzeTemplateInjection(responseBody));
            result.setPrototypePollutionAnalysis(enablePrototype ? analyzePrototypePollution(responseBody) : new PrototypePollutionAnalysisResult());
            result.setModernAPIAnalysis(enableModernApi ? analyzeModernAPIs(responseBody) : new ModernAPIAnalysisResult());
            result.setWebComponentsAnalysis(enableWebComponents ? analyzeWebComponents(responseBody) : new WebComponentsAnalysisResult());

            // NEW: Correlate sources -> sinks (reduces false positives and increases accuracy)
            int correlationScore = analyzeClientSideSourceSinkCorrelation(responseBody, result);
            
            // REAL-TIME DYNAMIC ANALYSIS - Enhanced
            result.setRealTimeDynamicAnalysis(analyzeRealTimeDynamicAttacks(responseBody));
            
            // Additional client-side injection vectors
            analyzeAdditionalClientSideVectors(result, responseBody, headers);
            
            // Calculate overall risk score with enhanced weighting
            int riskScore = calculateEnhancedRiskScore(result);
            // Correlation score is the strongest signal for actual client-side injection
            riskScore = Math.min(100, riskScore + correlationScore);
            result.setRiskScore(riskScore);

            // CRITICAL FIX: CSP misconfiguration alone is NOT exploitable XSS
            // CSP misconfiguration is informational, not a confirmed XSS vulnerability
            boolean isOnlyCSPMisconfig = result.getCspAnalysis().getRiskScore() > 0 && 
                                        result.getPostMessageAnalysis().getRiskScore() < 25 &&
                                        result.getWebSocketAnalysis().getRiskScore() < 25 &&
                                        result.getTemplateInjectionAnalysis().getRiskScore() < 25 &&
                                        result.getPrototypePollutionAnalysis().getRiskScore() < 25 &&
                                        correlationScore < 30;
            
            // A client-side issue is "vulnerable" only if we have a high-signal correlated flow,
            // or multiple high-risk vectors (postMessage/websocket) with unsafe sinks.
            // CRITICAL: CSP misconfiguration alone does NOT make it vulnerable
            boolean hasCorrelatedFlow = correlationScore >= 30;
            boolean hasUnsafeMessaging = (result.getPostMessageAnalysis().getRiskScore() >= 25) || (result.getWebSocketAnalysis().getRiskScore() >= 25);
            boolean hasTemplateInjection = result.getTemplateInjectionAnalysis().getRiskScore() >= 25;
            boolean hasPrototypePollution = result.getPrototypePollutionAnalysis().getRiskScore() >= 25;
            
            // CRITICAL: Require STRONG evidence for client-side issues
            // Pattern matching (proximity of sources/sinks) is NOT sufficient proof
            // Require either:
            // 1. High correlation score (>= 30) with multiple taint flows (>= 3), OR
            // 2. Very high risk score (>= 85) with actual exploitable vectors
            boolean hasMultipleTaintFlows = false;
            try {
                if (result.getModernAPIAnalysis() != null && result.getModernAPIAnalysis().getDetectedPatterns() != null) {
                    Set<String> uniqueTaintFlows = new HashSet<>();
                    for (String pattern : result.getModernAPIAnalysis().getDetectedPatterns()) {
                        if (pattern != null && pattern.startsWith("TAINT_FLOW:")) {
                            uniqueTaintFlows.add(pattern);
                        }
                    }
                    hasMultipleTaintFlows = uniqueTaintFlows.size() >= 3;
                }
            } catch (Exception ignored) {}
            
            boolean hasVeryHighRisk = riskScore >= 85;
            boolean hasStrongEvidence = hasCorrelatedFlow && hasMultipleTaintFlows;
            
            // Only mark as vulnerable if we have actual exploitable vectors with STRONG evidence, NOT just CSP misconfiguration
            result.setVulnerable(!isOnlyCSPMisconfig && 
                                (hasStrongEvidence || (hasVeryHighRisk && (hasUnsafeMessaging || hasTemplateInjection || hasPrototypePollution))));
            
            // Generate exploit POC if vulnerable
            if (result.isVulnerable()) {
                result.setExploitPOC(generateExploitPOC(result, requestResponse));
                result.setReproductionSteps(generateReproductionSteps(result, requestResponse));
                
                // Create real exploited evidence for professional advisory
                createRealExploitedEvidence(result, requestResponse);
            }
            
        } catch (Exception e) {
            callbacks.printError("Client-Side Attack Analysis Error: " + e.getMessage());
            if (settings != null && settings.getVerboseLogging()) {
                callbacks.printError("Stack trace: " + java.util.Arrays.toString(e.getStackTrace()));
            }
        }
        
        return result;
    }

    /**
     * NEW: High-signal correlation between user-controlled sources and dangerous sinks.
     * This is a major missing piece in naive "pattern-only" scanners.
     *
     * We boost score when we find evidence of (source -> sink) in the same local context window.
     * Findings are stored into ModernAPIAnalysisResult.detectedPatterns for reporting/triage.
     */
    private int analyzeClientSideSourceSinkCorrelation(String body, ClientSideAttackResult result) {
        try {
            if (body == null || body.isEmpty() || result == null) return 0;

            String lower = body.toLowerCase();
            int score = 0;

            // If the app uses Trusted Types / DOMPurify, reduce score slightly (defense-in-depth)
            boolean hasTrustedTypes = lower.contains("trustedtypes") || lower.contains("trusted types");
            boolean hasDomPurify = lower.contains("dompurify") && lower.contains("sanitize");

            // ENHANCED: Larger sliding window for SPA detection (increased from 800 to 2000 chars)
            // SPAs often have larger codebases with indirect flows
            final int window = 2000;
            
            // CRITICAL FIX: Use Set to prevent duplicate TAINT_FLOW entries
            Set<String> detectedFlows = new HashSet<>();
            
            for (String sink : TAINT_SINKS) {
                String sinkLower = sink.toLowerCase();
                int idx = 0;
                while (idx >= 0 && idx < lower.length()) {
                    idx = lower.indexOf(sinkLower, idx);
                    if (idx < 0) break;

                    int start = Math.max(0, idx - window);
                    int end = Math.min(lower.length(), idx + window);
                    String context = lower.substring(start, end);

                    String matchedSource = null;
                    for (String src : TAINT_SOURCES) {
                        if (context.contains(src.toLowerCase())) {
                            matchedSource = src;
                            break;
                        }
                    }

                    if (matchedSource != null) {
                        // CRITICAL FIX: Create unique flow identifier to prevent duplicates
                        String flowId = matchedSource + " -> " + sink;
                        
                        // Only process if we haven't seen this exact flow before
                        if (!detectedFlows.contains(flowId)) {
                            detectedFlows.add(flowId);
                            
                            // Execution sinks are more dangerous than pure HTML sinks.
                            int delta = 0;
                            if (sinkLower.startsWith("eval") || sinkLower.startsWith("function(") || sinkLower.startsWith("settimeout") || sinkLower.startsWith("setinterval")) {
                                delta = 35;
                            } else if (sinkLower.contains("innerhtml") || sinkLower.contains("outerhtml") || sinkLower.contains("insertadjacenthtml") || sinkLower.contains("document.write")) {
                                delta = 25;
                            } else {
                                delta = 15;
                            }

                            score += delta;
                            result.getModernAPIAnalysis().getDetectedPatterns().add("TAINT_FLOW: " + flowId);

                            // Boost associated sub-analyses so UI shows the right "attack type"
                            if (matchedSource.toLowerCase().contains("event.data") || matchedSource.toLowerCase().contains("message.data")) {
                                result.getPostMessageAnalysis().setRiskScore(Math.min(100, result.getPostMessageAnalysis().getRiskScore() + 20));
                                result.getPostMessageAnalysis().getDetectedPatterns().add("Unsafe message data used in sink: " + sink);
                            }
                        }

                    }

                    idx = idx + Math.max(1, sinkLower.length());
                }
            }

            if (hasTrustedTypes) score -= 5;
            if (hasDomPurify) score -= 10;
            return Math.max(0, Math.min(score, 60)); // cap correlation contribution

        } catch (Exception e) {
            callbacks.printError("Error correlating client-side sources/sinks: " + e.getMessage());
            return 0;
        }
    }
    
    /**
     * Analyze additional client-side injection vectors
     */
    private void analyzeAdditionalClientSideVectors(ClientSideAttackResult result, String responseBody, String headers) {
        try {
            String bodyLower = responseBody.toLowerCase();
            
            // Mutation XSS detection
            if (bodyLower.contains("mutation") && (bodyLower.contains("xss") || bodyLower.contains("innerhtml"))) {
                result.getModernAPIAnalysis().setRiskScore(result.getModernAPIAnalysis().getRiskScore() + 15);
                result.getModernAPIAnalysis().getDetectedPatterns().add("Mutation XSS");
            }
            
            // Universal XSS detection
            if (bodyLower.contains("universal") || bodyLower.contains("uxss")) {
                result.getModernAPIAnalysis().setRiskScore(result.getModernAPIAnalysis().getRiskScore() + 20);
                result.getModernAPIAnalysis().getDetectedPatterns().add("Universal XSS");
            }
            
            // mXSS (Mutation XSS) detection
            if (bodyLower.contains("mxss") || (bodyLower.contains("mutation") && bodyLower.contains("xss"))) {
                result.getModernAPIAnalysis().setRiskScore(result.getModernAPIAnalysis().getRiskScore() + 18);
                result.getModernAPIAnalysis().getDetectedPatterns().add("Mutation XSS (mXSS)");
            }
            
            // Self-XSS detection
            if (bodyLower.contains("self-xss") || bodyLower.contains("self xss")) {
                result.getModernAPIAnalysis().setRiskScore(result.getModernAPIAnalysis().getRiskScore() + 10);
                result.getModernAPIAnalysis().getDetectedPatterns().add("Self-XSS");
            }
            
            // Flash-based XSS
            if (bodyLower.contains("flash") || bodyLower.contains("swf") || bodyLower.contains("object") && bodyLower.contains("embed")) {
                result.getModernAPIAnalysis().setRiskScore(result.getModernAPIAnalysis().getRiskScore() + 12);
                result.getModernAPIAnalysis().getDetectedPatterns().add("Flash-based XSS");
            }
            
            // SVG-based XSS
            if (bodyLower.contains("<svg") || bodyLower.contains("image/svg+xml")) {
                result.getModernAPIAnalysis().setRiskScore(result.getModernAPIAnalysis().getRiskScore() + 15);
                result.getModernAPIAnalysis().getDetectedPatterns().add("SVG-based XSS");
            }
            
            // CSS Injection
            if (bodyLower.contains("style") && (bodyLower.contains("expression") || bodyLower.contains("javascript:") || bodyLower.contains("@import"))) {
                result.getModernAPIAnalysis().setRiskScore(result.getModernAPIAnalysis().getRiskScore() + 14);
                result.getModernAPIAnalysis().getDetectedPatterns().add("CSS Injection");
            }
            
            // Trusted Types bypass detection
            if (bodyLower.contains("trustedtypes") || bodyLower.contains("trusted types")) {
                if (bodyLower.contains("createpolicy") && bodyLower.contains("createhtml")) {
                    result.getModernAPIAnalysis().setRiskScore(result.getModernAPIAnalysis().getRiskScore() + 20);
                    result.getModernAPIAnalysis().getDetectedPatterns().add("Trusted Types Bypass");
                }
            }
            
            // Sanitizer API bypass detection
            if (bodyLower.contains("sanitizer") && bodyLower.contains("sethtml")) {
                result.getModernAPIAnalysis().setRiskScore(result.getModernAPIAnalysis().getRiskScore() + 18);
                result.getModernAPIAnalysis().getDetectedPatterns().add("Sanitizer API Bypass");
            }
            
            // DOMPurify bypass detection
            if (bodyLower.contains("dompurify") && (bodyLower.contains("sanitize") || bodyLower.contains("purify"))) {
                if (bodyLower.contains("foreignobject") || bodyLower.contains("mathml") || bodyLower.contains("details")) {
                    result.getModernAPIAnalysis().setRiskScore(result.getModernAPIAnalysis().getRiskScore() + 16);
                    result.getModernAPIAnalysis().getDetectedPatterns().add("DOMPurify Bypass");
                }
            }
            
            // SameSite cookie bypass detection
            if (bodyLower.contains("samesite") || bodyLower.contains("same-site")) {
                if (bodyLower.contains("none") || bodyLower.contains("lax") || bodyLower.contains("strict")) {
                    result.getModernAPIAnalysis().setRiskScore(result.getModernAPIAnalysis().getRiskScore() + 12);
                    result.getModernAPIAnalysis().getDetectedPatterns().add("SameSite Cookie Bypass");
                }
            }
            
            // Header injection detection
            if (bodyLower.contains("x-forwarded") || bodyLower.contains("x-real-ip") || bodyLower.contains("user-agent") || bodyLower.contains("referer")) {
                if (bodyLower.contains("<script") || bodyLower.contains("javascript:") || bodyLower.contains("onerror")) {
                    result.getModernAPIAnalysis().setRiskScore(result.getModernAPIAnalysis().getRiskScore() + 15);
                    result.getModernAPIAnalysis().getDetectedPatterns().add("Header Injection XSS");
                }
            }
            
            // Cookie injection detection
            if (bodyLower.contains("document.cookie") || bodyLower.contains("set-cookie")) {
                if (bodyLower.contains("<script") || bodyLower.contains("javascript:") || bodyLower.contains("onerror")) {
                    result.getModernAPIAnalysis().setRiskScore(result.getModernAPIAnalysis().getRiskScore() + 13);
                    result.getModernAPIAnalysis().getDetectedPatterns().add("Cookie Injection XSS");
                }
            }
            
            // Markdown XSS detection
            if (bodyLower.contains("markdown") || bodyLower.contains("md") || bodyLower.contains("```")) {
                if (bodyLower.contains("javascript:") || bodyLower.contains("<script") || bodyLower.contains("onerror")) {
                    result.getModernAPIAnalysis().setRiskScore(result.getModernAPIAnalysis().getRiskScore() + 11);
                    result.getModernAPIAnalysis().getDetectedPatterns().add("Markdown XSS");
                }
            }
            
            // MathML XSS detection
            if (bodyLower.contains("<math") || bodyLower.contains("mathml")) {
                if (bodyLower.contains("xlink:href") || bodyLower.contains("javascript:") || bodyLower.contains("<script")) {
                    result.getModernAPIAnalysis().setRiskScore(result.getModernAPIAnalysis().getRiskScore() + 10);
                    result.getModernAPIAnalysis().getDetectedPatterns().add("MathML XSS");
                }
            }
            
            // Blob/File API XSS detection
            if (bodyLower.contains("blob:") || bodyLower.contains("url.createobjecturl") || bodyLower.contains("file api")) {
                if (bodyLower.contains("<script") || bodyLower.contains("javascript:") || bodyLower.contains("eval")) {
                    result.getModernAPIAnalysis().setRiskScore(result.getModernAPIAnalysis().getRiskScore() + 17);
                    result.getModernAPIAnalysis().getDetectedPatterns().add("Blob/File API XSS");
                }
            }
            
            // Import Maps XSS detection
            if (bodyLower.contains("importmap") || bodyLower.contains("type=\"importmap\"")) {
                if (bodyLower.contains("javascript:") || bodyLower.contains("data:text") || bodyLower.contains("blob:")) {
                    result.getModernAPIAnalysis().setRiskScore(result.getModernAPIAnalysis().getRiskScore() + 19);
                    result.getModernAPIAnalysis().getDetectedPatterns().add("Import Maps XSS");
                }
            }
            
            // Module Workers XSS detection
            if (bodyLower.contains("new worker") || bodyLower.contains("sharedworker") || bodyLower.contains("type:'module'")) {
                if (bodyLower.contains("javascript:") || bodyLower.contains("data:text") || bodyLower.contains("blob:")) {
                    result.getModernAPIAnalysis().setRiskScore(result.getModernAPIAnalysis().getRiskScore() + 16);
                    result.getModernAPIAnalysis().getDetectedPatterns().add("Module Workers XSS");
                }
            }
            
            // HTML5-based XSS
            if (bodyLower.contains("html5") || (bodyLower.contains("data-") && bodyLower.contains("on"))) {
                result.getModernAPIAnalysis().setRiskScore(result.getModernAPIAnalysis().getRiskScore() + 10);
                result.getModernAPIAnalysis().getDetectedPatterns().add("HTML5-based XSS");
            }
            
        } catch (Exception e) {
            callbacks.printError("Error analyzing additional client-side vectors: " + e.getMessage());
        }
    }
    
    /**
     * Calculate enhanced risk score with better weighting
     * CRITICAL FIX: CSP misconfiguration alone should not inflate risk score
     */
    private int calculateEnhancedRiskScore(ClientSideAttackResult result) {
        int score = 0;
        
        // CRITICAL FIX: Reduce CSP weight - CSP misconfiguration is informational, not exploitable
        // Only count CSP if there are other exploitable vectors
        boolean hasExploitableVectors = result.getPostMessageAnalysis().getRiskScore() >= 25 ||
                                       result.getWebSocketAnalysis().getRiskScore() >= 25 ||
                                       result.getTemplateInjectionAnalysis().getRiskScore() >= 25 ||
                                       result.getPrototypePollutionAnalysis().getRiskScore() >= 25;
        
        if (hasExploitableVectors) {
            // CSP misconfiguration makes existing vectors worse, but alone it's not exploitable
            score += (int)(result.getCspAnalysis().getRiskScore() * 0.15); // Reduced from 0.25
        } else {
            // CSP misconfiguration alone - cap at 30 (informational)
            score += Math.min((int)(result.getCspAnalysis().getRiskScore() * 0.10), 30);
        }
        
        // Weighted scoring for different attack types (exploitable vectors)
        score += (int)(result.getPostMessageAnalysis().getRiskScore() * 0.25); // Increased from 0.20
        score += (int)(result.getWebSocketAnalysis().getRiskScore() * 0.20); // Increased from 0.15
        score += (int)(result.getTemplateInjectionAnalysis().getRiskScore() * 0.20); // Increased from 0.15
        score += (int)(result.getPrototypePollutionAnalysis().getRiskScore() * 0.15); // Increased from 0.10
        score += (int)(result.getModernAPIAnalysis().getRiskScore() * 0.15); // Increased from 0.10
        score += (int)(result.getWebComponentsAnalysis().getRiskScore() * 0.05);
        
        // Real-time dynamic analysis bonus
        if (result.getRealTimeDynamicAnalysis() != null) {
            score += (int)(result.getRealTimeDynamicAnalysis().getRealTimeRiskScore() * 0.10);
        }
        
        return Math.min(score, 100);
    }
    
    /**
     * CSP Bypass Analysis
     */
    private CSPAnalysisResult analyzeCSP(String headers, String body) {
        CSPAnalysisResult result = new CSPAnalysisResult();
        
        // Check for CSP headers
        if (headers.contains("Content-Security-Policy")) {
            result.setCspPresent(true);
            
            // Check for unsafe directives
            for (String pattern : CSP_BYPASS_PATTERNS) {
                if (headers.toLowerCase().contains(pattern.toLowerCase())) {
                    result.getUnsafeDirectives().add(pattern);
                    result.setRiskScore(result.getRiskScore() + 15);
                }
            }
            
            // Check for missing directives
            if (!headers.contains("default-src")) {
                result.getMissingDirectives().add("default-src");
                result.setRiskScore(result.getRiskScore() + 10);
            }
            
            if (!headers.contains("script-src")) {
                result.getMissingDirectives().add("script-src");
                result.setRiskScore(result.getRiskScore() + 10);
            }
        } else {
            result.setCspPresent(false);
            // No CSP is a defense-in-depth gap, not automatically an exploitable injection.
            // Keep as a moderate signal (can be reported separately if desired).
            result.setRiskScore(20);
        }
        
        return result;
    }
    
    /**
     * PostMessage Attack Analysis
     */
    private PostMessageAnalysisResult analyzePostMessage(String body) {
        PostMessageAnalysisResult result = new PostMessageAnalysisResult();
        
        for (String pattern : POSTMESSAGE_PATTERNS) {
            if (body.contains(pattern)) {
                result.getDetectedPatterns().add(pattern);
                result.setRiskScore(result.getRiskScore() + 10);
            }
        }
        
        // Improve precision: "unsafe origin validation" is only meaningful if a message handler exists.
        String lower = body.toLowerCase();
        boolean hasHandler = lower.contains("addeventlistener('message'") || lower.contains("addeventlistener(\"message\"") || lower.contains("onmessage");
        if (hasHandler) {
            boolean checksOrigin = lower.contains("origin") || lower.contains("event.origin") || lower.contains("message.origin");
            boolean usesSource = lower.contains("source") || lower.contains("event.source") || lower.contains("message.source");
            if (!checksOrigin && !usesSource) {
                result.setUnsafeOriginValidation(true);
                result.setRiskScore(result.getRiskScore() + 15);
            }
            // Extra signal: message data used at all
            if (lower.contains("event.data") || lower.contains("message.data")) {
                result.setRiskScore(result.getRiskScore() + 10);
            }
        }
        
        return result;
    }
    
    /**
     * WebSocket Attack Analysis
     */
    private WebSocketAnalysisResult analyzeWebSocket(String body) {
        WebSocketAnalysisResult result = new WebSocketAnalysisResult();
        
        for (String pattern : WEBSOCKET_PATTERNS) {
            if (body.contains(pattern)) {
                result.getDetectedPatterns().add(pattern);
                result.setRiskScore(result.getRiskScore() + 8);
            }
        }
        
        // Check for insecure WebSocket connections
        if (body.contains("ws://") && !body.contains("wss://")) {
            result.setInsecureConnection(true);
            result.setRiskScore(result.getRiskScore() + 15);
        }
        
        return result;
    }
    
    /**
     * Template Injection Analysis
     */
    private TemplateInjectionAnalysisResult analyzeTemplateInjection(String body) {
        TemplateInjectionAnalysisResult result = new TemplateInjectionAnalysisResult();
        
        for (String pattern : TEMPLATE_INJECTION_PATTERNS) {
            if (body.contains(pattern)) {
                // CRITICAL FIX: Verify pattern is NOT inside a JS comment or string definition
                int idx = body.indexOf(pattern);
                if (idx >= 0) {
                    int lineStart = body.lastIndexOf('\n', idx);
                    if (lineStart < 0) lineStart = 0;
                    String linePrefix = body.substring(lineStart, idx).trim();
                    // Skip if in a single-line comment
                    if (linePrefix.contains("//")) continue;
                    // Skip if clearly in a block comment
                    String before100 = body.substring(Math.max(0, idx - 100), idx);
                    if (before100.contains("/*") && !before100.contains("*/")) continue;
                }
                result.getDetectedPatterns().add(pattern);
                result.setRiskScore(result.getRiskScore() + 12);
            }
        }

        return result;
    }

    /**
     * Prototype Pollution Analysis
     */
    private PrototypePollutionAnalysisResult analyzePrototypePollution(String body) {
        PrototypePollutionAnalysisResult result = new PrototypePollutionAnalysisResult();

        for (String pattern : PROTOTYPE_POLLUTION_PATTERNS) {
            if (body.contains(pattern)) {
                // CRITICAL FIX: Skip if pattern is in a defensive context (Object.freeze, hasOwnProperty check)
                int idx = body.indexOf(pattern);
                if (idx >= 0) {
                    String context = body.substring(Math.max(0, idx - 200), Math.min(body.length(), idx + 200));
                    // Skip defensive patterns - these are SAFE, not vulnerabilities
                    if (context.contains("Object.freeze") || context.contains("Object.seal") ||
                        context.contains("hasOwnProperty") || context.contains("Object.create(null)")) {
                        continue;
                    }
                }
                result.getDetectedPatterns().add(pattern);
                result.setRiskScore(result.getRiskScore() + 15);
            }
        }

        return result;
    }
    
    /**
     * Modern API Analysis
     */
    private ModernAPIAnalysisResult analyzeModernAPIs(String body) {
        ModernAPIAnalysisResult result = new ModernAPIAnalysisResult();
        
        for (String pattern : MODERN_API_PATTERNS) {
            if (body.contains(pattern)) {
                result.getDetectedPatterns().add(pattern);
                result.setRiskScore(result.getRiskScore() + 10);
            }
        }
        
        return result;
    }
    
    /**
     * Web Components Analysis
     */
    private WebComponentsAnalysisResult analyzeWebComponents(String body) {
        WebComponentsAnalysisResult result = new WebComponentsAnalysisResult();
        
        for (String pattern : WEB_COMPONENTS_PATTERNS) {
            if (body.contains(pattern)) {
                result.getDetectedPatterns().add(pattern);
                result.setRiskScore(result.getRiskScore() + 8);
            }
        }
        
        return result;
    }
    
    /**
     * REAL-TIME DYNAMIC ATTACK ANALYSIS - ENHANCED WITH ADVANCED PATTERN MATCHING
     * Comprehensive analysis of live DOM changes, dynamic content updates, and real-time exploitation vectors
     * Uses context-aware regex patterns for accurate detection
     */
    private RealTimeDynamicAnalysisResult analyzeRealTimeDynamicAttacks(String body) {
        RealTimeDynamicAnalysisResult result = new RealTimeDynamicAnalysisResult();
        String bodyLower = body.toLowerCase();
        
        // Live DOM Monitoring Detection - Enhanced with regex patterns
        Pattern mutationObserverPattern = Pattern.compile(
            "(?:new\\s+)?MutationObserver\\s*\\(|MutationObserver\\.observe|mutationobserver",
            Pattern.CASE_INSENSITIVE | Pattern.MULTILINE
        );
        if (mutationObserverPattern.matcher(body).find()) {
            // Check for actual usage
            Pattern usagePattern = Pattern.compile(
                "MutationObserver\\s*\\([^)]*\\)|MutationObserver\\.observe\\s*\\(|new\\s+MutationObserver",
                Pattern.CASE_INSENSITIVE
            );
            if (usagePattern.matcher(body).find()) {
                result.setHasLiveDOMMonitoring(true);
                result.setLiveDOMMonitoringRisk("HIGH");
                result.getDetectedVectors().add("LiveDOMMonitoring");
                callbacks.printOutput("[REALTIME] Live DOM monitoring detected with usage - Real-time DOM changes active");
            }
        }
        
        // Real-time Communication Detection - Enhanced with regex patterns
        Pattern webSocketPattern = Pattern.compile(
            "(?:new\\s+)?WebSocket\\s*\\(|websocket|ws://|wss://|socket\\.io",
            Pattern.CASE_INSENSITIVE
        );
        if (webSocketPattern.matcher(body).find()) {
            // Check for actual WebSocket instantiation
            Pattern wsUsagePattern = Pattern.compile(
                "new\\s+WebSocket\\s*\\(|WebSocket\\s*\\(|socket\\.io\\(|io\\.connect",
                Pattern.CASE_INSENSITIVE
            );
            if (wsUsagePattern.matcher(body).find()) {
                result.setHasRealTimeCommunication(true);
                result.setRealTimeCommunicationRisk("HIGH");
                result.getDetectedVectors().add("RealTimeCommunication");
                callbacks.printOutput("[REALTIME] Real-time communication detected with usage - Live data streaming active");
            }
        }
        
        // Dynamic Code Execution Detection - Enhanced with regex patterns
        Pattern dynamicImportPattern = Pattern.compile(
            "import\\s*\\(|dynamic\\s+import|import\\.meta",
            Pattern.CASE_INSENSITIVE
        );
        if (dynamicImportPattern.matcher(body).find()) {
            // Check for actual dynamic import usage (not static import)
            Pattern diUsagePattern = Pattern.compile(
                "import\\s*\\([^)]+\\)|import\\.meta\\.url|import\\.meta\\.resolve",
                Pattern.CASE_INSENSITIVE
            );
            if (diUsagePattern.matcher(body).find()) {
                result.setHasDynamicCodeExecution(true);
                result.setDynamicCodeExecutionRisk("HIGH");
                result.getDetectedVectors().add("DynamicCodeExecution");
                callbacks.printOutput("[REALTIME] Dynamic code execution detected with usage - Runtime module loading active");
            }
        }
        
        // Advanced JavaScript Features Detection
        if (bodyLower.contains("proxy") || bodyLower.contains("reflect.") || bodyLower.contains("symbol")) {
            result.setHasAdvancedJSFeatures(true);
            result.setAdvancedJSFeaturesRisk("MEDIUM");
            result.getDetectedVectors().add("AdvancedJSFeatures");
            callbacks.printOutput("[REALTIME] Advanced JavaScript features detected - Meta-programming possible");
        }
        
        // Asynchronous Patterns Detection
        if (bodyLower.contains("async") || bodyLower.contains("await") || bodyLower.contains("generator")) {
            result.setHasAsyncPatterns(true);
            result.setAsyncPatternsRisk("MEDIUM");
            result.getDetectedVectors().add("AsyncPatterns");
            callbacks.printOutput("[REALTIME] Asynchronous patterns detected - Non-blocking execution possible");
        }
        
        // Modern DOM APIs Detection
        if (bodyLower.contains("intersectionobserver") || bodyLower.contains("resizeobserver") || bodyLower.contains("performanceobserver")) {
            result.setHasModernDOMAPIs(true);
            result.setModernDOMAPIsRisk("MEDIUM");
            result.getDetectedVectors().add("ModernDOMAPIs");
            callbacks.printOutput("[REALTIME] Modern DOM APIs detected - Advanced event monitoring possible");
        }
        
        // Web APIs Detection
        if (bodyLower.contains("fetch api") || bodyLower.contains("streams api") || bodyLower.contains("readablestream")) {
            result.setHasWebAPIs(true);
            result.setWebAPIsRisk("MEDIUM");
            result.getDetectedVectors().add("WebAPIs");
            callbacks.printOutput("[REALTIME] Web APIs detected - Advanced data handling possible");
        }
        
        // Storage APIs Detection
        if (bodyLower.contains("indexeddb") || bodyLower.contains("websql") || bodyLower.contains("cache api")) {
            result.setHasStorageAPIs(true);
            result.setStorageAPIsRisk("MEDIUM");
            result.getDetectedVectors().add("StorageAPIs");
            callbacks.printOutput("[REALTIME] Storage APIs detected - Persistent data storage possible");
        }
        
        // Security APIs Detection
        if (bodyLower.contains("trusted types") || bodyLower.contains("sanitizer api") || bodyLower.contains("web authentication")) {
            result.setHasSecurityAPIs(true);
            result.setSecurityAPIsRisk("LOW");
            result.getDetectedVectors().add("SecurityAPIs");
            callbacks.printOutput("[REALTIME] Security APIs detected - Enhanced security measures present");
        }
        
        // Calculate real-time risk score
        int realTimeRiskScore = calculateRealTimeRiskScore(result);
        result.setRealTimeRiskScore(realTimeRiskScore);
        
        return result;
    }
    
    /**
     * Calculate real-time risk score based on detected vectors
     */
    private int calculateRealTimeRiskScore(RealTimeDynamicAnalysisResult result) {
        int score = 0;
        
        if (result.isHasLiveDOMMonitoring()) score += 25;
        if (result.isHasRealTimeCommunication()) score += 30;
        if (result.isHasDynamicCodeExecution()) score += 35;
        if (result.isHasAdvancedJSFeatures()) score += 20;
        if (result.isHasAsyncPatterns()) score += 15;
        if (result.isHasModernDOMAPIs()) score += 15;
        if (result.isHasWebAPIs()) score += 10;
        if (result.isHasStorageAPIs()) score += 10;
        if (result.isHasSecurityAPIs()) score -= 5; // Security APIs reduce risk
        
        return Math.min(Math.max(score, 0), 100);
    }
    
    /**
     * Calculate Overall Risk Score
     */
    private int calculateRiskScore(ClientSideAttackResult result) {
        int score = 0;
        
        score += result.getCspAnalysis().getRiskScore();
        score += result.getPostMessageAnalysis().getRiskScore();
        score += result.getWebSocketAnalysis().getRiskScore();
        score += result.getTemplateInjectionAnalysis().getRiskScore();
        score += result.getPrototypePollutionAnalysis().getRiskScore();
        score += result.getModernAPIAnalysis().getRiskScore();
        score += result.getWebComponentsAnalysis().getRiskScore();
        
        return Math.min(score, 100);
    }
    
    /**
     * Generate Context-Specific Exploit POC
     */
    private String generateExploitPOC(ClientSideAttackResult result, IHttpRequestResponse requestResponse) {
        StringBuilder poc = new StringBuilder();
        
        String targetUrl = requestResponse.getHttpService().getProtocol() + "://" + 
                          requestResponse.getHttpService().getHost() + ":" + 
                          requestResponse.getHttpService().getPort() + 
                          helpers.analyzeRequest(requestResponse).getUrl().getPath();
        
        poc.append("Client-Side Attack Exploit POC\n");
        poc.append("Target URL: ").append(targetUrl).append("\n");
        poc.append("Risk Score: ").append(result.getRiskScore()).append("%\n");
        poc.append("Vulnerable: ").append(result.isVulnerable() ? "Yes" : "No").append("\n\n");
        
        // Context-Specific CSP Bypass Exploits
        if (result.getCspAnalysis().getRiskScore() > 0) {
            poc.append("CSP Bypass Exploits:\n");
            poc.append("// Context-Specific CSP Bypass for detected vulnerability\n");
            poc.append("var cspBypass = {\n");
            poc.append("    target: '").append(targetUrl).append("',\n");
            poc.append("    method: 'CSP Bypass',\n");
            poc.append("    execute: function() {\n");
            poc.append("        // Method 1: Nonce Bypass\n");
            poc.append("        var script = document.createElement('script');\n");
            poc.append("        script.nonce = 'random-nonce-value';\n");
            poc.append("        script.textContent = 'alert(\\\"CSP_BYPASS\\\")';\n");
            poc.append("        document.head.appendChild(script);\n");
            poc.append("        \n");
            poc.append("        // Method 2: Data URI Bypass\n");
            poc.append("        var dataScript = document.createElement('script');\n");
            poc.append("        dataScript.src = 'data:text/javascript,alert(1)';\n");
            poc.append("        document.head.appendChild(dataScript);\n");
            poc.append("        \n");
            poc.append("        // Method 3: Unsafe Inline Bypass\n");
            poc.append("        var img = document.createElement('img');\n");
            poc.append("        img.src = 'x';\n");
            poc.append("        img.onerror = new Function('alert(\\\"CSP_BYPASS\\\")');\n");
            poc.append("        document.body.appendChild(img);\n");
            poc.append("    }\n");
            poc.append("};\n\n");
        }
        
        // Context-Specific PostMessage Exploits
        if (result.getPostMessageAnalysis().getRiskScore() > 0) {
            poc.append("PostMessage Exploits:\n");
            poc.append("// Context-Specific PostMessage Attack for detected vulnerability\n");
            poc.append("var postMessageExploit = {\n");
            poc.append("    target: '").append(targetUrl).append("',\n");
            poc.append("    method: 'PostMessage Attack',\n");
            poc.append("    execute: function() {\n");
            poc.append("        // Method 1: Direct postMessage\n");
            poc.append("        window.postMessage('<script>alert(1)</script>', '*');\n");
            poc.append("        \n");
            poc.append("        // Method 2: Iframe communication\n");
            poc.append("        var iframe = document.createElement('iframe');\n");
            poc.append("        iframe.src = this.target;\n");
            poc.append("        document.body.appendChild(iframe);\n");
            poc.append("        iframe.onload = function() {\n");
            poc.append("            iframe.contentWindow.postMessage('<script>alert(1)</script>', '*');\n");
            poc.append("        };\n");
            poc.append("        \n");
            poc.append("        // Method 3: Cross-origin postMessage\n");
            poc.append("        var popup = window.open(this.target, '_blank');\n");
            poc.append("        setTimeout(function() {\n");
            poc.append("            popup.postMessage('javascript:alert(1)', '*');\n");
            poc.append("        }, 1000);\n");
            poc.append("    }\n");
            poc.append("};\n\n");
        }
        
        // Context-Specific WebSocket Exploits
        if (result.getWebSocketAnalysis().getRiskScore() > 0) {
            poc.append("WebSocket Exploits:\n");
            poc.append("// Context-Specific WebSocket Attack for detected vulnerability\n");
            poc.append("var websocketExploit = {\n");
            poc.append("    target: '").append(targetUrl).append("',\n");
            poc.append("    method: 'WebSocket Attack',\n");
            poc.append("    execute: function() {\n");
            poc.append("        // Method 1: Direct WebSocket\n");
            poc.append("        var ws = new WebSocket('ws://' + window.location.host + '/ws');\n");
            poc.append("        ws.onopen = function() {\n");
            poc.append("            ws.send(JSON.stringify({\n");
            poc.append("                type: 'message',\n");
            poc.append("                data: '<script>alert(1)</script>'\n");
            poc.append("            }));\n");
            poc.append("        };\n");
            poc.append("        \n");
            poc.append("        // Method 2: Secure WebSocket\n");
            poc.append("        var wss = new WebSocket('wss://' + window.location.host + '/ws');\n");
            poc.append("        wss.onopen = function() {\n");
            poc.append("            wss.send('<script>alert(1)</script>');\n");
            poc.append("        };\n");
            poc.append("        \n");
            poc.append("        // Method 3: Socket.io\n");
            poc.append("        if (typeof io !== 'undefined') {\n");
            poc.append("            var socket = io();\n");
            poc.append("            socket.emit('message', '<script>alert(1)</script>');\n");
            poc.append("        }\n");
            poc.append("    }\n");
            poc.append("};\n\n");
        }
        
        // Context-Specific Template Injection Exploits
        if (result.getTemplateInjectionAnalysis().getRiskScore() > 0) {
            poc.append("Template Injection Exploits:\n");
            poc.append("// Context-Specific Template Injection for detected vulnerability\n");
            poc.append("var templateExploit = {\n");
            poc.append("    target: '").append(targetUrl).append("',\n");
            poc.append("    method: 'Template Injection',\n");
            poc.append("    execute: function() {\n");
            poc.append("        // Method 1: Angular template injection\n");
            poc.append("        var angularPayload = '{{constructor.constructor(\\'alert(\\\\\\'ANGULAR\\\\\\')\\')()}}';\n");
            poc.append("        document.getElementById('angular-app').innerHTML = angularPayload;\n");
            poc.append("        \n");
            poc.append("        // Method 2: Handlebars template injection\n");
            poc.append("        var handlebarsPayload = '{{#with this}}{{constructor.constructor(\\'alert(\\\\\\'HANDLEBARS\\\\\\')\\')()}}{{/with}}';\n");
            poc.append("        document.getElementById('handlebars-app').innerHTML = handlebarsPayload;\n");
            poc.append("        \n");
            poc.append("        // Method 3: EJS template injection\n");
            poc.append("        var ejsPayload = '<%=constructor.constructor(\\'alert(\\\\\\'EJS\\\\\\')\\')()%>';\n");
            poc.append("        document.getElementById('ejs-app').innerHTML = ejsPayload;\n");
            poc.append("        \n");
            poc.append("        // Method 4: Basic template injection\n");
            poc.append("        var basicPayload = '{{7*7}}{{alert(1)}}';\n");
            poc.append("        document.getElementById('template-area').innerHTML = basicPayload;\n");
            poc.append("    }\n");
            poc.append("};\n\n");
        }
        
        // Context-Specific Modern API Exploits
        if (result.getModernAPIAnalysis().getRiskScore() > 0) {
            poc.append("Modern API Exploits:\n");
            poc.append("// Context-Specific Modern API Attack for detected vulnerability\n");
            poc.append("var modernAPIExploit = {\n");
            poc.append("    target: '").append(targetUrl).append("',\n");
            poc.append("    method: 'Modern API Attack',\n");
            poc.append("    execute: function() {\n");
            poc.append("        // Method 1: SharedArrayBuffer exploit\n");
            poc.append("        if (typeof SharedArrayBuffer !== 'undefined') {\n");
            poc.append("            var sab = new SharedArrayBuffer(1024);\n");
            poc.append("            var ta = new Uint8Array(sab);\n");
            poc.append("            ta[0] = 0x41; // 'A'\n");
            poc.append("        }\n");
            poc.append("        \n");
            poc.append("        // Method 2: BroadcastChannel exploit\n");
            poc.append("        if (typeof BroadcastChannel !== 'undefined') {\n");
            poc.append("            var bc = new BroadcastChannel('xss-channel');\n");
            poc.append("            bc.postMessage('<script>alert(1)</script>');\n");
            poc.append("        }\n");
            poc.append("        \n");
            poc.append("        // Method 3: Dynamic Import exploit\n");
            poc.append("        import('data:text/javascript,alert(1)').catch(console.error);\n");
            poc.append("        \n");
            poc.append("        // Method 4: WebAssembly exploit\n");
            poc.append("        if (typeof WebAssembly !== 'undefined') {\n");
            poc.append("            WebAssembly.instantiate(new Uint8Array([0x00, 0x61, 0x73, 0x6d]));\n");
            poc.append("        }\n");
            poc.append("    }\n");
            poc.append("};\n\n");
        }
        
        return poc.toString();
    }
    
    /**
     * CRITICAL FIX: Create real exploited evidence for client-side attacks
     */
    private void createRealExploitedEvidence(ClientSideAttackResult result, IHttpRequestResponse requestResponse) {
        try {
            // Generate taint-flow-aware payload recommendation (SPA/JSON friendly)
            String contentType = extractContentType(requestResponse);
            String payload = pickBestClientSidePayload(result, contentType);
            
            // CRITICAL: For client-side attack passive scanning, we analyze the actual response
            // We cannot send HTTP requests in passive scanning - that requires active scanning
            // Store the actual request/response as evidence
            try {
                // Use actual request/response from the server
                byte[] actualRequest = requestResponse.getRequest();
                byte[] actualResponse = requestResponse.getResponse();
                
                if (actualRequest != null && actualRequest.length > 0) {
                    result.setTestRequest(new String(actualRequest, StandardCharsets.UTF_8));
                }
                if (actualResponse != null && actualResponse.length > 0) {
                    result.setTestResponse(new String(actualResponse, StandardCharsets.UTF_8));
                }
                result.setTestPayload(payload);
                callbacks.printOutput("[CLIENT-SIDE] Using actual request/response for evidence");
            } catch (Exception e) {
                callbacks.printError("[CLIENT-SIDE] Error processing actual request/response: " + e.getMessage());
            }
            
        } catch (Exception e) {
            callbacks.printError("[CLIENT-SIDE] Error creating exploited evidence: " + e.getMessage());
        }
    }
    
    /**
     * Generate appropriate payload for client-side attacks
     */
    private String pickBestClientSidePayload(ClientSideAttackResult result, String responseContentType) {
        List<String> payloads = getRecommendedClientSidePayloads(result, responseContentType);
        if (payloads.isEmpty()) return "<svg/onload=alert(1)>";
        return payloads.get(0);
    }

    private List<String> getRecommendedClientSidePayloads(ClientSideAttackResult result, String responseContentType) {
        List<String> out = new ArrayList<>();
        if (result == null) return out;

        boolean isJson = responseContentType != null && responseContentType.toLowerCase().contains("application/json");

        String flowSink = extractPrimaryTaintSink(result);
        String sinkLower = flowSink != null ? flowSink.toLowerCase() : "";

        // Prefer sink-specific payloads (most likely to execute in SPAs)
        if (sinkLower.contains("eval") || sinkLower.contains("function(") || sinkLower.contains("settimeout") || sinkLower.contains("setinterval")) {
            out.add("alert(1)");
            out.add("confirm(1)");
        } else if (sinkLower.contains("innerhtml") || sinkLower.contains("outerhtml") || sinkLower.contains("insertadjacenthtml") || sinkLower.contains("document.write")) {
            out.add("<svg/onload=alert(1)>");
            out.add("%3Csvg%2Fonload%3Dalert(1)%3E"); // URL-encoded (SPA-friendly)
            if (isJson) out.add("\\u003csvg/onload=alert(1)\\u003e"); // JSON string friendly
        } else if (result.getTemplateInjectionAnalysis() != null && result.getTemplateInjectionAnalysis().getRiskScore() > 0) {
            out.add("{{7*7}}");
            out.add("{{constructor.constructor('alert(1)')()}}");
        } else if (result.getPostMessageAnalysis() != null && result.getPostMessageAnalysis().getRiskScore() > 0) {
            out.add("<svg/onload=alert(1)>");
            out.add("alert(1)");
        } else {
            // Safe, widely effective baseline for DOM sinks
            out.add("<svg/onload=alert(1)>");
            out.add("%3Csvg%2Fonload%3Dalert(1)%3E");
            if (isJson) out.add("\\u003csvg/onload=alert(1)\\u003e");
        }

        return out;
    }

    private String extractPrimaryTaintSink(ClientSideAttackResult result) {
        try {
            if (result == null || result.getModernAPIAnalysis() == null) return null;
            List<String> patterns = result.getModernAPIAnalysis().getDetectedPatterns();
            if (patterns == null) return null;
            for (String p : patterns) {
                if (p == null) continue;
                if (p.startsWith("TAINT_FLOW:")) {
                    int arrow = p.indexOf("->");
                    if (arrow > 0 && arrow + 2 < p.length()) {
                        return p.substring(arrow + 2).trim();
                    }
                }
            }
        } catch (Exception ignored) {}
        return null;
    }

    private String extractContentType(IHttpRequestResponse rr) {
        try {
            if (rr == null || rr.getResponse() == null) return null;
            int bodyOffset = helpers.analyzeResponse(rr.getResponse()).getBodyOffset();
            String headers = new String(Arrays.copyOfRange(rr.getResponse(), 0, bodyOffset), StandardCharsets.UTF_8);
            for (String line : headers.split("\r\n")) {
                if (line.toLowerCase().startsWith("content-type:")) {
                    return line.substring("content-type:".length()).trim().split(";")[0].trim();
                }
            }
        } catch (Exception ignored) {}
        return null;
    }
    
    // REMOVED: createClientSideTestRequest() and createClientSideTestResponse() - These were creating synthetic/fake data
    // For passive scanning, we MUST use actual request/response from the server
    // For active scanning, we use actual HTTP requests via sendRealHttpRequest()
    
    /**
     * Get attack type description for response
     */
    private String getAttackTypeDescription(ClientSideAttackResult result) {
        if (result.getCspAnalysis().getRiskScore() > 0) return "CSP Bypass";
        if (result.getPostMessageAnalysis().getRiskScore() > 0) return "PostMessage Attack";
        if (result.getWebSocketAnalysis().getRiskScore() > 0) return "WebSocket Attack";
        if (result.getTemplateInjectionAnalysis().getRiskScore() > 0) return "Template Injection";
        if (result.getPrototypePollutionAnalysis().getRiskScore() > 0) return "Prototype Pollution";
        if (result.getModernAPIAnalysis().getRiskScore() > 0) return "Modern API Attack";
        if (result.getWebComponentsAnalysis().getRiskScore() > 0) return "Web Components Attack";
        return "Client-Side Attack";
    }
    
    /**
     * Generate Reproduction Steps
     */
    private String generateReproductionSteps(ClientSideAttackResult result, IHttpRequestResponse requestResponse) {
        StringBuilder steps = new StringBuilder();
        
        steps.append("Context-Specific Client-Side Attack Reproduction Steps\n\n");
        
        String targetUrl = requestResponse.getHttpService().getProtocol() + "://" + 
                          requestResponse.getHttpService().getHost() + ":" + 
                          requestResponse.getHttpService().getPort() + 
                          helpers.analyzeRequest(requestResponse).getUrl().getPath();
        
        steps.append("URL: ").append(targetUrl).append("\n");
        steps.append("Method: Client-side analysis\n");
        steps.append("Risk Score: ").append(result.getRiskScore()).append("\n\n");
        
        String contentType = extractContentType(requestResponse);
        List<String> payloads = getRecommendedClientSidePayloads(result, contentType);

        String taintSource = extractPrimaryTaintSource(result);
        String taintSink = extractPrimaryTaintSink(result);

        steps.append("Primary taint flow: ").append(taintSource != null ? taintSource : "(unknown source)")
             .append(" -> ").append(taintSink != null ? taintSink : "(unknown sink)").append("\n\n");

        steps.append("Recommended payloads (try in order):\n");
        for (int i = 0; i < Math.min(payloads.size(), 5); i++) {
            steps.append("- ").append(payloads.get(i)).append("\n");
        }
        steps.append("\n");

        // SPA-friendly reproduction guidance (focus on client-side sources)
        if (taintSource != null) {
            String src = taintSource.toLowerCase();
            if (src.contains("location.hash")) {
                steps.append("SPA reproduction (hash source):\n");
                steps.append("- Open: ").append(targetUrl).append("#").append(payloads.isEmpty() ? "alert(1)" : payloads.get(0)).append("\n");
                steps.append("- If the app URL-decodes hash, also try: ").append(targetUrl).append("#").append(payloads.size() > 1 ? payloads.get(1) : "%3Csvg%2Fonload%3Dalert(1)%3E").append("\n\n");
            } else if (src.contains("location.search")) {
                steps.append("SPA reproduction (query-string source):\n");
                steps.append("- Open: ").append(targetUrl).append("?q=").append(payloads.isEmpty() ? "%3Csvg%2Fonload%3Dalert(1)%3E" : payloads.get(Math.min(1, payloads.size()-1))).append("\n");
                steps.append("- If the app uses a different param name, locate it in the JS bundle (URLSearchParams.get(...)).\n\n");
            } else if (src.contains("localstorage") || src.contains("sessionstorage")) {
                steps.append("SPA reproduction (storage source):\n");
                steps.append("- In DevTools console, set the key used by the app to a payload, then reload.\n");
                steps.append("- Execute: localStorage.setItem('KEY', '").append(payloads.isEmpty() ? "<svg/onload=alert(1)>" : payloads.get(0)).append("'); location.reload();\n\n");
            } else if (src.contains("document.referrer")) {
                steps.append("Reproduction (referrer source):\n");
                steps.append("- Host an attacker page that links to the target and sets the referrer to a payload-bearing URL.\n\n");
            } else if (src.contains("window.name")) {
                steps.append("Reproduction (window.name source):\n");
                steps.append("- Open the target via a popup where window.name is set to a payload, then navigate the popup to the target.\n\n");
            }
        }

        if (result.getPostMessageAnalysis() != null && result.getPostMessageAnalysis().getRiskScore() > 0) {
            steps.append("Reproduction (postMessage):\n");
            steps.append("- From an attacker origin, open the target in an iframe/popup and postMessage a payload.\n");
            steps.append("- Ensure the target does not validate event.origin and routes event.data into a sink.\n\n");
        }
        
        return steps.toString();
    }

    private String extractPrimaryTaintSource(ClientSideAttackResult result) {
        try {
            if (result == null || result.getModernAPIAnalysis() == null) return null;
            List<String> patterns = result.getModernAPIAnalysis().getDetectedPatterns();
            if (patterns == null) return null;
            for (String p : patterns) {
                if (p == null) continue;
                if (p.startsWith("TAINT_FLOW:")) {
                    int arrow = p.indexOf("->");
                    if (arrow > 0) {
                        String left = p.substring("TAINT_FLOW:".length(), arrow).trim();
                        return left;
                    }
                }
            }
        } catch (Exception ignored) {}
        return null;
    }
    
    // Data classes
    public static class ClientSideAttackResult {
        private CSPAnalysisResult cspAnalysis = new CSPAnalysisResult();
        private PostMessageAnalysisResult postMessageAnalysis = new PostMessageAnalysisResult();
        private WebSocketAnalysisResult webSocketAnalysis = new WebSocketAnalysisResult();
        private TemplateInjectionAnalysisResult templateInjectionAnalysis = new TemplateInjectionAnalysisResult();
        private PrototypePollutionAnalysisResult prototypePollutionAnalysis = new PrototypePollutionAnalysisResult();
        private ModernAPIAnalysisResult modernAPIAnalysis = new ModernAPIAnalysisResult();
        private WebComponentsAnalysisResult webComponentsAnalysis = new WebComponentsAnalysisResult();
        private int riskScore = 0;
        private boolean vulnerable = false;
        private String exploitPOC = "";
        private String reproductionSteps = "";
        private RealTimeDynamicAnalysisResult realTimeDynamicAnalysis = new RealTimeDynamicAnalysisResult();
        
        // CRITICAL FIX: Add TEST_REQUEST and TEST_RESPONSE for real exploited evidence
        private String testRequest = "";
        private String testResponse = "";
        private String testPayload = "";
        
        // Compatibility methods for BurpExtender integration
        // CRITICAL: Enhanced confidence calculation based on risk score and correlation
        public String getConfidenceLevel() { 
            if (riskScore >= 80) return "Certain";
            if (riskScore >= 60) return "Firm";
            if (riskScore >= 40) return "Tentative";
            return "Low";
        }
        public String getRiskLevel() { 
            if (riskScore >= 80) return "Critical";
            if (riskScore >= 60) return "High";
            if (riskScore >= 40) return "Medium";
            return "Low";
        }
        
        // Getters and setters
        public CSPAnalysisResult getCspAnalysis() { return cspAnalysis; }
        public void setCspAnalysis(CSPAnalysisResult cspAnalysis) { this.cspAnalysis = cspAnalysis; }
        
        public PostMessageAnalysisResult getPostMessageAnalysis() { return postMessageAnalysis; }
        public void setPostMessageAnalysis(PostMessageAnalysisResult postMessageAnalysis) { this.postMessageAnalysis = postMessageAnalysis; }
        
        public WebSocketAnalysisResult getWebSocketAnalysis() { return webSocketAnalysis; }
        public void setWebSocketAnalysis(WebSocketAnalysisResult webSocketAnalysis) { this.webSocketAnalysis = webSocketAnalysis; }
        
        public TemplateInjectionAnalysisResult getTemplateInjectionAnalysis() { return templateInjectionAnalysis; }
        public void setTemplateInjectionAnalysis(TemplateInjectionAnalysisResult templateInjectionAnalysis) { this.templateInjectionAnalysis = templateInjectionAnalysis; }
        
        public PrototypePollutionAnalysisResult getPrototypePollutionAnalysis() { return prototypePollutionAnalysis; }
        public void setPrototypePollutionAnalysis(PrototypePollutionAnalysisResult prototypePollutionAnalysis) { this.prototypePollutionAnalysis = prototypePollutionAnalysis; }
        
        public ModernAPIAnalysisResult getModernAPIAnalysis() { return modernAPIAnalysis; }
        public void setModernAPIAnalysis(ModernAPIAnalysisResult modernAPIAnalysis) { this.modernAPIAnalysis = modernAPIAnalysis; }
        
        public WebComponentsAnalysisResult getWebComponentsAnalysis() { return webComponentsAnalysis; }
        public void setWebComponentsAnalysis(WebComponentsAnalysisResult webComponentsAnalysis) { this.webComponentsAnalysis = webComponentsAnalysis; }
        
        public int getRiskScore() { return riskScore; }
        public void setRiskScore(int riskScore) { this.riskScore = riskScore; }
        
        public boolean isVulnerable() { return vulnerable; }
        public void setVulnerable(boolean vulnerable) { this.vulnerable = vulnerable; }
        
        public String getExploitPOC() { return exploitPOC; }
        public void setExploitPOC(String exploitPOC) { this.exploitPOC = exploitPOC; }
        
        public String getReproductionSteps() { return reproductionSteps; }
        public void setReproductionSteps(String reproductionSteps) { this.reproductionSteps = reproductionSteps; }
        
        public RealTimeDynamicAnalysisResult getRealTimeDynamicAnalysis() { return realTimeDynamicAnalysis; }
        public void setRealTimeDynamicAnalysis(RealTimeDynamicAnalysisResult realTimeDynamicAnalysis) { this.realTimeDynamicAnalysis = realTimeDynamicAnalysis; }
        
        // CRITICAL FIX: Getters and setters for real exploited evidence
        public String getTestRequest() { return testRequest; }
        public void setTestRequest(String testRequest) { this.testRequest = testRequest; }
        
        public String getTestResponse() { return testResponse; }
        public void setTestResponse(String testResponse) { this.testResponse = testResponse; }
        
        public String getTestPayload() { return testPayload; }
        public void setTestPayload(String testPayload) { this.testPayload = testPayload; }
    }
    
    public static class CSPAnalysisResult {
        private boolean cspPresent = false;
        private List<String> unsafeDirectives = new ArrayList<>();
        private List<String> missingDirectives = new ArrayList<>();
        private int riskScore = 0;
        
        // Getters and setters
        public boolean isCspPresent() { return cspPresent; }
        public void setCspPresent(boolean cspPresent) { this.cspPresent = cspPresent; }
        
        public List<String> getUnsafeDirectives() { return unsafeDirectives; }
        public void setUnsafeDirectives(List<String> unsafeDirectives) { this.unsafeDirectives = unsafeDirectives; }
        
        public List<String> getMissingDirectives() { return missingDirectives; }
        public void setMissingDirectives(List<String> missingDirectives) { this.missingDirectives = missingDirectives; }
        
        public int getRiskScore() { return riskScore; }
        public void setRiskScore(int riskScore) { this.riskScore = riskScore; }
    }
    
    public static class PostMessageAnalysisResult {
        private List<String> detectedPatterns = new ArrayList<>();
        private boolean unsafeOriginValidation = false;
        private int riskScore = 0;
        
        // Getters and setters
        public List<String> getDetectedPatterns() { return detectedPatterns; }
        public void setDetectedPatterns(List<String> detectedPatterns) { this.detectedPatterns = detectedPatterns; }
        
        public boolean isUnsafeOriginValidation() { return unsafeOriginValidation; }
        public void setUnsafeOriginValidation(boolean unsafeOriginValidation) { this.unsafeOriginValidation = unsafeOriginValidation; }
        
        public int getRiskScore() { return riskScore; }
        public void setRiskScore(int riskScore) { this.riskScore = riskScore; }
    }
    
    public static class WebSocketAnalysisResult {
        private List<String> detectedPatterns = new ArrayList<>();
        private boolean insecureConnection = false;
        private int riskScore = 0;
        
        // Getters and setters
        public List<String> getDetectedPatterns() { return detectedPatterns; }
        public void setDetectedPatterns(List<String> detectedPatterns) { this.detectedPatterns = detectedPatterns; }
        
        public boolean isInsecureConnection() { return insecureConnection; }
        public void setInsecureConnection(boolean insecureConnection) { this.insecureConnection = insecureConnection; }
        
        public int getRiskScore() { return riskScore; }
        public void setRiskScore(int riskScore) { this.riskScore = riskScore; }
    }
    
    public static class TemplateInjectionAnalysisResult {
        private List<String> detectedPatterns = new ArrayList<>();
        private int riskScore = 0;
        
        // Getters and setters
        public List<String> getDetectedPatterns() { return detectedPatterns; }
        public void setDetectedPatterns(List<String> detectedPatterns) { this.detectedPatterns = detectedPatterns; }
        
        public int getRiskScore() { return riskScore; }
        public void setRiskScore(int riskScore) { this.riskScore = riskScore; }
    }
    
    public static class PrototypePollutionAnalysisResult {
        private List<String> detectedPatterns = new ArrayList<>();
        private int riskScore = 0;
        
        // Getters and setters
        public List<String> getDetectedPatterns() { return detectedPatterns; }
        public void setDetectedPatterns(List<String> detectedPatterns) { this.detectedPatterns = detectedPatterns; }
        
        public int getRiskScore() { return riskScore; }
        public void setRiskScore(int riskScore) { this.riskScore = riskScore; }
    }
    
    public static class ModernAPIAnalysisResult {
        private List<String> detectedPatterns = new ArrayList<>();
        private int riskScore = 0;
        
        // Getters and setters
        public List<String> getDetectedPatterns() { return detectedPatterns; }
        public void setDetectedPatterns(List<String> detectedPatterns) { this.detectedPatterns = detectedPatterns; }
        
        public int getRiskScore() { return riskScore; }
        public void setRiskScore(int riskScore) { this.riskScore = riskScore; }
    }
    
    public static class WebComponentsAnalysisResult {
        private List<String> detectedPatterns = new ArrayList<>();
        private int riskScore = 0;
        
        // Getters and setters
        public List<String> getDetectedPatterns() { return detectedPatterns; }
        public void setDetectedPatterns(List<String> detectedPatterns) { this.detectedPatterns = detectedPatterns; }
        
        public int getRiskScore() { return riskScore; }
        public void setRiskScore(int riskScore) { this.riskScore = riskScore; }
    }

    public static class RealTimeDynamicAnalysisResult {
        private boolean hasLiveDOMMonitoring = false;
        private String liveDOMMonitoringRisk = "LOW";
        private boolean hasRealTimeCommunication = false;
        private String realTimeCommunicationRisk = "LOW";
        private boolean hasDynamicCodeExecution = false;
        private String dynamicCodeExecutionRisk = "LOW";
        private boolean hasAdvancedJSFeatures = false;
        private String advancedJSFeaturesRisk = "LOW";
        private boolean hasAsyncPatterns = false;
        private String asyncPatternsRisk = "LOW";
        private boolean hasModernDOMAPIs = false;
        private String modernDOMAPIsRisk = "LOW";
        private boolean hasWebAPIs = false;
        private String webAPIsRisk = "LOW";
        private boolean hasStorageAPIs = false;
        private String storageAPIsRisk = "LOW";
        private boolean hasSecurityAPIs = false;
        private String securityAPIsRisk = "LOW";
        private List<String> detectedVectors = new ArrayList<>();
        private int realTimeRiskScore = 0;

        // Getters and setters
        public boolean isHasLiveDOMMonitoring() { return hasLiveDOMMonitoring; }
        public void setHasLiveDOMMonitoring(boolean hasLiveDOMMonitoring) { this.hasLiveDOMMonitoring = hasLiveDOMMonitoring; }
        public String getLiveDOMMonitoringRisk() { return liveDOMMonitoringRisk; }
        public void setLiveDOMMonitoringRisk(String liveDOMMonitoringRisk) { this.liveDOMMonitoringRisk = liveDOMMonitoringRisk; }
        public boolean isHasRealTimeCommunication() { return hasRealTimeCommunication; }
        public void setHasRealTimeCommunication(boolean hasRealTimeCommunication) { this.hasRealTimeCommunication = hasRealTimeCommunication; }
        public String getRealTimeCommunicationRisk() { return realTimeCommunicationRisk; }
        public void setRealTimeCommunicationRisk(String realTimeCommunicationRisk) { this.realTimeCommunicationRisk = realTimeCommunicationRisk; }
        public boolean isHasDynamicCodeExecution() { return hasDynamicCodeExecution; }
        public void setHasDynamicCodeExecution(boolean hasDynamicCodeExecution) { this.hasDynamicCodeExecution = hasDynamicCodeExecution; }
        public String getDynamicCodeExecutionRisk() { return dynamicCodeExecutionRisk; }
        public void setDynamicCodeExecutionRisk(String dynamicCodeExecutionRisk) { this.dynamicCodeExecutionRisk = dynamicCodeExecutionRisk; }
        public boolean isHasAdvancedJSFeatures() { return hasAdvancedJSFeatures; }
        public void setHasAdvancedJSFeatures(boolean hasAdvancedJSFeatures) { this.hasAdvancedJSFeatures = hasAdvancedJSFeatures; }
        public String getAdvancedJSFeaturesRisk() { return advancedJSFeaturesRisk; }
        public void setAdvancedJSFeaturesRisk(String advancedJSFeaturesRisk) { this.advancedJSFeaturesRisk = advancedJSFeaturesRisk; }
        public boolean isHasAsyncPatterns() { return hasAsyncPatterns; }
        public void setHasAsyncPatterns(boolean hasAsyncPatterns) { this.hasAsyncPatterns = hasAsyncPatterns; }
        public String getAsyncPatternsRisk() { return asyncPatternsRisk; }
        public void setAsyncPatternsRisk(String asyncPatternsRisk) { this.asyncPatternsRisk = asyncPatternsRisk; }
        public boolean isHasModernDOMAPIs() { return hasModernDOMAPIs; }
        public void setHasModernDOMAPIs(boolean hasModernDOMAPIs) { this.hasModernDOMAPIs = hasModernDOMAPIs; }
        public String getModernDOMAPIsRisk() { return modernDOMAPIsRisk; }
        public void setModernDOMAPIsRisk(String modernDOMAPIsRisk) { this.modernDOMAPIsRisk = modernDOMAPIsRisk; }
        public boolean isHasWebAPIs() { return hasWebAPIs; }
        public void setHasWebAPIs(boolean hasWebAPIs) { this.hasWebAPIs = hasWebAPIs; }
        public String getWebAPIsRisk() { return webAPIsRisk; }
        public void setWebAPIsRisk(String webAPIsRisk) { this.webAPIsRisk = webAPIsRisk; }
        public boolean isHasStorageAPIs() { return hasStorageAPIs; }
        public void setHasStorageAPIs(boolean hasStorageAPIs) { this.hasStorageAPIs = hasStorageAPIs; }
        public String getStorageAPIsRisk() { return storageAPIsRisk; }
        public void setStorageAPIsRisk(String storageAPIsRisk) { this.storageAPIsRisk = storageAPIsRisk; }
        public boolean isHasSecurityAPIs() { return hasSecurityAPIs; }
        public void setHasSecurityAPIs(boolean hasSecurityAPIs) { this.hasSecurityAPIs = hasSecurityAPIs; }
        public String getSecurityAPIsRisk() { return securityAPIsRisk; }
        public void setSecurityAPIsRisk(String securityAPIsRisk) { this.securityAPIsRisk = securityAPIsRisk; }
        public List<String> getDetectedVectors() { return detectedVectors; }
        public void setDetectedVectors(List<String> detectedVectors) { this.detectedVectors = detectedVectors; }
        public int getRealTimeRiskScore() { return realTimeRiskScore; }
        public void setRealTimeRiskScore(int realTimeRiskScore) { this.realTimeRiskScore = realTimeRiskScore; }
        
        // CRITICAL: Add hasRealTimeVectors() method for compatibility with DOM XSS detector
        public boolean hasRealTimeVectors() {
            return detectedVectors != null && !detectedVectors.isEmpty();
        }
    }
} 