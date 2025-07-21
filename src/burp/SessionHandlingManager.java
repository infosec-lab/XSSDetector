package burp;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;
import java.util.regex.Matcher;
import static burp.Constants.*;

/**
 * Advanced Session Handling Manager
 * Handles session tokens, CSRF tokens, and authentication state
 */
public class SessionHandlingManager {
    
    private final IExtensionHelpers helpers;
    private final IBurpExtenderCallbacks callbacks;
    private final Settings settings;
    
    // Session tracking
    private final Map<String, SessionInfo> activeSessions = new ConcurrentHashMap<>();
    private final Map<String, String> csrfTokens = new ConcurrentHashMap<>();
    private final Set<String> sessionTokenNames = new HashSet<>();
    private final Set<String> csrfTokenNames = new HashSet<>();
    
    // Session patterns
    private static final Pattern SESSION_ID_PATTERN = Pattern.compile(
        "(session|sessid|sid|jsessionid|phpsessid|aspsessionid)[\\w_-]*", 
        Pattern.CASE_INSENSITIVE
    );
    
    private static final Pattern CSRF_TOKEN_PATTERN = Pattern.compile(
        "(csrf|xsrf|token|authenticity_token|csrfmiddlewaretoken|_token)[\\w_-]*", 
        Pattern.CASE_INSENSITIVE
    );
    
    public SessionHandlingManager(IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks, Settings settings) {
        this.helpers = helpers;
        this.callbacks = callbacks;
        this.settings = settings;
        initializeCommonTokenNames();
    }
    
    /**
     * Initialize common session and CSRF token names
     */
    private void initializeCommonTokenNames() {
        // Common session token names
        sessionTokenNames.addAll(Arrays.asList(
            "JSESSIONID", "PHPSESSID", "ASPSESSIONID", "session", "sessid", "sid",
            "session_id", "sessionid", "user_session", "auth_session", "login_session"
        ));
        
        // Common CSRF token names
        csrfTokenNames.addAll(Arrays.asList(
            "csrf_token", "authenticity_token", "csrfmiddlewaretoken", "_token",
            "xsrf_token", "anti_forgery_token", "form_token", "security_token"
        ));
    }
    
    /**
     * Process request and extract session information
     */
    public SessionContext processRequest(IHttpRequestResponse requestResponse) {
        SessionContext context = new SessionContext();
        
        try {
            // Extract session tokens from cookies
            List<SessionToken> sessionTokens = extractSessionTokens(requestResponse);
            context.setSessionTokens(sessionTokens);
            
            // Extract CSRF tokens from parameters and headers
            List<CSRFToken> csrfTokens = extractCSRFTokens(requestResponse);
            context.setCsrfTokens(csrfTokens);
            
            // Determine authentication state
            AuthenticationState authState = determineAuthState(requestResponse, sessionTokens);
            context.setAuthState(authState);
            
            // Check for session-related parameters that should be excluded from XSS testing
            Set<String> excludedParams = identifySessionParameters(requestResponse);
            context.setExcludedParameters(excludedParams);
            
            // Update session tracking
            updateSessionTracking(requestResponse, sessionTokens, csrfTokens);
            
        } catch (Exception e) {
            callbacks.printError("Session processing error: " + e.getMessage());
        }
        
        return context;
    }
    
    /**
     * Extract session tokens from cookies and headers
     */
    private List<SessionToken> extractSessionTokens(IHttpRequestResponse requestResponse) {
        List<SessionToken> tokens = new ArrayList<>();
        
        try {
            // Check cookies
            List<IParameter> cookies = helpers.analyzeRequest(requestResponse).getParameters();
            for (IParameter cookie : cookies) {
                if (cookie.getType() == IParameter.PARAM_COOKIE) {
                    if (isSessionToken(cookie.getName())) {
                        SessionToken token = new SessionToken(cookie.getName(), cookie.getValue(), "COOKIE");
                        token.setHttpOnly(isHttpOnlyCookie(requestResponse, cookie.getName()));
                        token.setSecure(isSecureCookie(requestResponse, cookie.getName()));
                        tokens.add(token);
                    }
                }
            }
            
            // Check headers for custom session tokens
            List<String> headers = helpers.analyzeRequest(requestResponse).getHeaders();
            for (String header : headers) {
                if (header.toLowerCase().startsWith("authorization:") ||
                    header.toLowerCase().startsWith("x-auth-token:") ||
                    header.toLowerCase().startsWith("x-session-token:")) {
                    
                    String[] parts = header.split(":", 2);
                    if (parts.length == 2) {
                        String tokenValue = parts[1].trim();
                        if (tokenValue.startsWith("Bearer ")) {
                            tokenValue = tokenValue.substring(7);
                        }
                        tokens.add(new SessionToken(parts[0], tokenValue, "HEADER"));
                    }
                }
            }
            
        } catch (Exception e) {
            callbacks.printError("Session token extraction error: " + e.getMessage());
        }
        
        return tokens;
    }
    
    /**
     * Extract CSRF tokens from parameters and headers
     */
    private List<CSRFToken> extractCSRFTokens(IHttpRequestResponse requestResponse) {
        List<CSRFToken> tokens = new ArrayList<>();
        
        try {
            // Check all parameters
            List<IParameter> parameters = helpers.analyzeRequest(requestResponse).getParameters();
            for (IParameter param : parameters) {
                if (isCSRFToken(param.getName())) {
                    CSRFToken token = new CSRFToken(param.getName(), param.getValue(), getParameterTypeString(param.getType()));
                    tokens.add(token);
                }
            }
            
            // Check headers for CSRF tokens
            List<String> headers = helpers.analyzeRequest(requestResponse).getHeaders();
            for (String header : headers) {
                if (header.toLowerCase().startsWith("x-csrf-token:") ||
                    header.toLowerCase().startsWith("x-xsrf-token:") ||
                    header.toLowerCase().startsWith("x-requested-with:")) {
                    
                    String[] parts = header.split(":", 2);
                    if (parts.length == 2) {
                        tokens.add(new CSRFToken(parts[0], parts[1].trim(), "HEADER"));
                    }
                }
            }
            
        } catch (Exception e) {
            callbacks.printError("CSRF token extraction error: " + e.getMessage());
        }
        
        return tokens;
    }
    
    /**
     * Determine authentication state based on session tokens and request characteristics
     */
    private AuthenticationState determineAuthState(IHttpRequestResponse requestResponse, List<SessionToken> sessionTokens) {
        AuthenticationState state = new AuthenticationState();
        
        try {
            // Check if session tokens are present
            state.setHasSessionTokens(!sessionTokens.isEmpty());
            
            // Check for authentication-related headers
            List<String> headers = helpers.analyzeRequest(requestResponse).getHeaders();
            for (String header : headers) {
                String lowerHeader = header.toLowerCase();
                if (lowerHeader.startsWith("authorization:")) {
                    state.setHasAuthHeader(true);
                    if (lowerHeader.contains("basic")) {
                        state.setAuthType("BASIC");
                    } else if (lowerHeader.contains("bearer")) {
                        state.setAuthType("BEARER");
                    } else if (lowerHeader.contains("digest")) {
                        state.setAuthType("DIGEST");
                    }
                    break;
                }
            }
            
            // Analyze request URL for authentication indicators
            String url = helpers.analyzeRequest(requestResponse).getUrl().toString().toLowerCase();
            if (url.contains("/login") || url.contains("/auth") || url.contains("/signin")) {
                state.setAuthenticationEndpoint(true);
            }
            
            if (url.contains("/logout") || url.contains("/signout")) {
                state.setLogoutEndpoint(true);
            }
            
            // Check for protected resource indicators
            if (url.contains("/admin") || url.contains("/dashboard") || url.contains("/profile")) {
                state.setProtectedResource(true);
            }
            
        } catch (Exception e) {
            callbacks.printError("Authentication state determination error: " + e.getMessage());
        }
        
        return state;
    }
    
    /**
     * Identify parameters that should be excluded from XSS testing due to session handling
     */
    private Set<String> identifySessionParameters(IHttpRequestResponse requestResponse) {
        Set<String> excludedParams = new HashSet<>();
        
        try {
            List<IParameter> parameters = helpers.analyzeRequest(requestResponse).getParameters();
            for (IParameter param : parameters) {
                String paramName = param.getName().toLowerCase();
                
                // Exclude session tokens
                if (isSessionToken(paramName)) {
                    excludedParams.add(param.getName());
                }
                
                // Exclude CSRF tokens
                if (isCSRFToken(paramName)) {
                    excludedParams.add(param.getName());
                }
                
                // Exclude other security-related parameters
                if (paramName.equals("password") || paramName.equals("pwd") || 
                    paramName.equals("pass") || paramName.contains("secret")) {
                    excludedParams.add(param.getName());
                }
                
                // Exclude API keys
                if (paramName.contains("api") && (paramName.contains("key") || paramName.contains("token"))) {
                    excludedParams.add(param.getName());
                }
            }
            
        } catch (Exception e) {
            callbacks.printError("Session parameter identification error: " + e.getMessage());
        }
        
        return excludedParams;
    }
    
    /**
     * Update session tracking information
     */
    private void updateSessionTracking(IHttpRequestResponse requestResponse, 
                                     List<SessionToken> sessionTokens, 
                                     List<CSRFToken> csrfTokens) {
        try {
            String host = helpers.analyzeRequest(requestResponse).getUrl().getHost();
            
            // Update session info for this host
            SessionInfo sessionInfo = activeSessions.computeIfAbsent(host, k -> new SessionInfo(host));
            sessionInfo.updateTokens(sessionTokens);
            sessionInfo.updateCSRFTokens(csrfTokens);
            sessionInfo.setLastActivity(System.currentTimeMillis());
            
            // Store CSRF tokens for potential reuse
            for (CSRFToken csrfToken : csrfTokens) {
                this.csrfTokens.put(host + ":" + csrfToken.getName(), csrfToken.getValue());
            }
            
        } catch (Exception e) {
            callbacks.printError("Session tracking update error: " + e.getMessage());
        }
    }
    
    /**
     * Check if parameter name indicates a session token
     */
    private boolean isSessionToken(String paramName) {
        String lowerParamName = paramName.toLowerCase();
        
        // Check exact matches
        for (String tokenName : sessionTokenNames) {
            if (lowerParamName.equals(tokenName.toLowerCase())) {
                return true;
            }
        }
        
        // Check pattern matches
        return SESSION_ID_PATTERN.matcher(lowerParamName).matches();
    }
    
    /**
     * Check if parameter name indicates a CSRF token
     */
    private boolean isCSRFToken(String paramName) {
        String lowerParamName = paramName.toLowerCase();
        
        // Check exact matches
        for (String tokenName : csrfTokenNames) {
            if (lowerParamName.equals(tokenName.toLowerCase())) {
                return true;
            }
        }
        
        // Check pattern matches
        return CSRF_TOKEN_PATTERN.matcher(lowerParamName).matches();
    }
    
    /**
     * Check if cookie is HttpOnly
     */
    private boolean isHttpOnlyCookie(IHttpRequestResponse requestResponse, String cookieName) {
        try {
            List<String> headers = helpers.analyzeResponse(requestResponse.getResponse()).getHeaders();
            for (String header : headers) {
                if (header.toLowerCase().startsWith("set-cookie:") && 
                    header.toLowerCase().contains(cookieName.toLowerCase()) &&
                    header.toLowerCase().contains("httponly")) {
                    return true;
                }
            }
        } catch (Exception e) {
            // Continue without breaking
        }
        return false;
    }
    
    /**
     * Check if cookie is Secure
     */
    private boolean isSecureCookie(IHttpRequestResponse requestResponse, String cookieName) {
        try {
            List<String> headers = helpers.analyzeResponse(requestResponse.getResponse()).getHeaders();
            for (String header : headers) {
                if (header.toLowerCase().startsWith("set-cookie:") && 
                    header.toLowerCase().contains(cookieName.toLowerCase()) &&
                    header.toLowerCase().contains("secure")) {
                    return true;
                }
            }
        } catch (Exception e) {
            // Continue without breaking
        }
        return false;
    }
    
    /**
     * Convert parameter type integer to string
     */
    private String getParameterTypeString(int type) {
        switch (type) {
            case IParameter.PARAM_URL: return "URL";
            case IParameter.PARAM_BODY: return "BODY";
            case IParameter.PARAM_COOKIE: return "COOKIE";
            case IParameter.PARAM_JSON: return "JSON";
            case IParameter.PARAM_XML: return "XML";
            case IParameter.PARAM_XML_ATTR: return "XML_ATTR";
            case IParameter.PARAM_MULTIPART_ATTR: return "MULTIPART";
            default: return "UNKNOWN";
        }
    }
    
    /**
     * Get current CSRF token for a host
     */
    public String getCurrentCSRFToken(String host, String tokenName) {
        return csrfTokens.get(host + ":" + tokenName);
    }
    
    /**
     * Check if parameter should be excluded from testing
     */
    public boolean shouldExcludeParameter(String paramName, String host) {
        if (!settings.getSessionHandling()) {
            return false;
        }
        
        return isSessionToken(paramName) || isCSRFToken(paramName);
    }
    
    /**
     * Get session information for a host
     */
    public SessionInfo getSessionInfo(String host) {
        return activeSessions.get(host);
    }
}

// Supporting classes

class SessionContext {
    private List<SessionToken> sessionTokens;
    private List<CSRFToken> csrfTokens;
    private AuthenticationState authState;
    private Set<String> excludedParameters;
    
    public SessionContext() {
        this.sessionTokens = new ArrayList<>();
        this.csrfTokens = new ArrayList<>();
        this.excludedParameters = new HashSet<>();
    }
    
    // Getters and setters
    public List<SessionToken> getSessionTokens() { return sessionTokens; }
    public void setSessionTokens(List<SessionToken> sessionTokens) { this.sessionTokens = sessionTokens; }
    
    public List<CSRFToken> getCsrfTokens() { return csrfTokens; }
    public void setCsrfTokens(List<CSRFToken> csrfTokens) { this.csrfTokens = csrfTokens; }
    
    public AuthenticationState getAuthState() { return authState; }
    public void setAuthState(AuthenticationState authState) { this.authState = authState; }
    
    public Set<String> getExcludedParameters() { return excludedParameters; }
    public void setExcludedParameters(Set<String> excludedParameters) { this.excludedParameters = excludedParameters; }
}

class SessionToken {
    private final String name;
    private final String value;
    private final String source;
    private boolean httpOnly;
    private boolean secure;
    
    public SessionToken(String name, String value, String source) {
        this.name = name;
        this.value = value;
        this.source = source;
    }
    
    // Getters and setters
    public String getName() { return name; }
    public String getValue() { return value; }
    public String getSource() { return source; }
    public boolean isHttpOnly() { return httpOnly; }
    public void setHttpOnly(boolean httpOnly) { this.httpOnly = httpOnly; }
    public boolean isSecure() { return secure; }
    public void setSecure(boolean secure) { this.secure = secure; }
}

class CSRFToken {
    private final String name;
    private final String value;
    private final String source;
    
    public CSRFToken(String name, String value, String source) {
        this.name = name;
        this.value = value;
        this.source = source;
    }
    
    // Getters
    public String getName() { return name; }
    public String getValue() { return value; }
    public String getSource() { return source; }
}

class AuthenticationState {
    private boolean hasSessionTokens;
    private boolean hasAuthHeader;
    private String authType;
    private boolean authenticationEndpoint;
    private boolean logoutEndpoint;
    private boolean protectedResource;
    
    public AuthenticationState() {
        this.authType = "NONE";
    }
    
    // Getters and setters
    public boolean hasSessionTokens() { return hasSessionTokens; }
    public void setHasSessionTokens(boolean hasSessionTokens) { this.hasSessionTokens = hasSessionTokens; }
    
    public boolean hasAuthHeader() { return hasAuthHeader; }
    public void setHasAuthHeader(boolean hasAuthHeader) { this.hasAuthHeader = hasAuthHeader; }
    
    public String getAuthType() { return authType; }
    public void setAuthType(String authType) { this.authType = authType; }
    
    public boolean isAuthenticationEndpoint() { return authenticationEndpoint; }
    public void setAuthenticationEndpoint(boolean authenticationEndpoint) { this.authenticationEndpoint = authenticationEndpoint; }
    
    public boolean isLogoutEndpoint() { return logoutEndpoint; }
    public void setLogoutEndpoint(boolean logoutEndpoint) { this.logoutEndpoint = logoutEndpoint; }
    
    public boolean isProtectedResource() { return protectedResource; }
    public void setProtectedResource(boolean protectedResource) { this.protectedResource = protectedResource; }
}

class SessionInfo {
    private final String host;
    private List<SessionToken> currentTokens;
    private List<CSRFToken> currentCSRFTokens;
    private long lastActivity;
    
    public SessionInfo(String host) {
        this.host = host;
        this.currentTokens = new ArrayList<>();
        this.currentCSRFTokens = new ArrayList<>();
        this.lastActivity = System.currentTimeMillis();
    }
    
    public void updateTokens(List<SessionToken> tokens) {
        this.currentTokens = new ArrayList<>(tokens);
    }
    
    public void updateCSRFTokens(List<CSRFToken> tokens) {
        this.currentCSRFTokens = new ArrayList<>(tokens);
    }
    
    // Getters and setters
    public String getHost() { return host; }
    public List<SessionToken> getCurrentTokens() { return currentTokens; }
    public List<CSRFToken> getCurrentCSRFTokens() { return currentCSRFTokens; }
    public long getLastActivity() { return lastActivity; }
    public void setLastActivity(long lastActivity) { this.lastActivity = lastActivity; }
} 