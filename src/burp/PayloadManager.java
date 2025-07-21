package burp;

import java.util.*;
import static burp.Constants.*;

/**
 * PayloadManager - Integrates UI Settings with Advanced Payloads
 * This class was MISSING and caused the disconnection between UI and backend
 */
public class PayloadManager {
    private final Settings settings;
    private final IBurpExtenderCallbacks callbacks;
    
    public PayloadManager(Settings settings, IBurpExtenderCallbacks callbacks) {
        this.settings = settings;
        this.callbacks = callbacks;
    }
    
    /**
     * Get advanced payloads based on enabled settings - CRITICAL INTEGRATION
     */
    public List<String> getAdvancedPayloads(Map parameter) {
        List<String> payloads = new ArrayList<>();
        
        // Basic payloads - always included
        payloads.addAll(Arrays.asList(ADVANCED_XSS_PAYLOADS));
        
        // Advanced payloads based on UI settings - NOW PROPERLY WIRED
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
        
        // CUTTING-EDGE PAYLOADS - PREVIOUSLY MISSING INTEGRATION
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
        
        if (settings.getEnableModernBrowserAPI()) {
            payloads.addAll(Arrays.asList(MODERN_BROWSER_API_XSS));
        }
        
        callbacks.printOutput("Selected " + payloads.size() + " payloads for parameter: " + parameter.get(NAME));
        return payloads;
    }
    
    /**
     * Get context-aware payloads (alias for getAdvancedPayloads for compatibility)
     */
    public List<String> getContextAwarePayloads(Map parameter, IHttpRequestResponse requestResponse) {
        return getAdvancedPayloads(parameter);
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