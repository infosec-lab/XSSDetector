package burp;

import java.awt.Component;
import java.io.OutputStream;
import java.net.URL;
import java.util.List;

/**
 * This interface is used by Burp Suite to pass to extensions a set of callback
 * methods that can be used by extensions to perform various actions within Burp.
 */
public interface IBurpExtenderCallbacks {

    // Tool flag constants for identifying Burp tools
    int TOOL_SUITE = 0x00000001;
    int TOOL_TARGET = 0x00000002;
    int TOOL_PROXY = 0x00000004;
    int TOOL_SPIDER = 0x00000008;
    int TOOL_SCANNER = 0x00000010;
    int TOOL_INTRUDER = 0x00000020;
    int TOOL_REPEATER = 0x00000040;
    int TOOL_SEQUENCER = 0x00000080;
    int TOOL_DECODER = 0x00000100;
    int TOOL_COMPARER = 0x00000200;
    int TOOL_EXTENDER = 0x00000400;

    /**
     * Set the display name for the current extension.
     * @param name The extension name.
     */
    void setExtensionName(String name);

    /**
     * Print a message to the standard output stream.
     * @param output The message to print.
     */
    void printOutput(String output);

    /**
     * Print a message to the standard error stream.
     * @param error The error message to print.
     */
    void printError(String error);

    /**
     * Register a new Scanner check.
     * @param check An object implementing IScannerCheck.
     */
    void registerScannerCheck(IScannerCheck check);

    /**
     * Add a custom tab to Burp Suite's UI.
     * @param tab An object implementing ITab.
     */
    void addSuiteTab(ITab tab);

    /**
     * Customize UI components in line with Burp's UI style.
     * @param component The UI component to customize.
     */
    void customizeUiComponent(Component component);

    /**
     * Obtain an IExtensionHelpers object for various helper methods.
     * @return An IExtensionHelpers object.
     */
    IExtensionHelpers getHelpers();

    /**
     * Load a setting that was persisted using saveExtensionSetting.
     * @param name The setting name.
     * @return The setting value, or null if not found.
     */
    String loadExtensionSetting(String name);

    /**
     * Save a setting so it persists across sessions.
     * @param name The setting name.
     * @param value The setting value.
     */
    void saveExtensionSetting(String name, String value);

    /**
     * Check if a URL is in the current target scope.
     * @param url The URL to check.
     * @return True if the URL is in scope.
     */
    boolean isInScope(URL url);

    /**
     * Send an HTTP request via Burp (preserves upstream proxy settings, cookies/session handling, etc).
     * This is the preferred way for extensions to issue requests during scanning.
     * @param httpService The HTTP service to send the request to.
     * @param request The request bytes.
     * @return The request/response pair.
     */
    IHttpRequestResponse makeHttpRequest(IHttpService httpService, byte[] request);

    // ============== NEW METHODS FOR REAL-TIME MONITORING ==============

    /**
     * Register a listener for HTTP messages processed by any Burp tool.
     * This enables real-time monitoring of proxy, repeater, intruder, etc.
     * @param listener An object implementing IHttpListener.
     */
    void registerHttpListener(IHttpListener listener);

    /**
     * Register a listener for extension state changes (e.g., unload).
     * @param listener An object implementing IExtensionStateListener.
     */
    void registerExtensionStateListener(IExtensionStateListener listener);

    /**
     * Register a listener for new scanner issues.
     * @param listener An object implementing IScannerListener.
     */
    void registerScannerListener(IScannerListener listener);

    /**
     * Programmatically add a scan issue to Burp's Scanner results.
     * @param issue The issue to add.
     */
    void addScanIssue(IScanIssue issue);

    /**
     * Send an HTTP request to Burp's Repeater tool.
     */
    void sendToRepeater(String host, int port, boolean useHttps, byte[] request, String tabCaption);

    /**
     * Register a factory for custom context-menu items.
     */
    void registerContextMenuFactory(IContextMenuFactory factory);

    /**
     * Get all scan issues for URLs matching the specified prefix.
     * @param urlPrefix The URL prefix to match (null for all issues).
     * @return Array of matching scan issues.
     */
    IScanIssue[] getScanIssues(String urlPrefix);

    /**
     * Generate a scan issue with request/response markers for highlighting.
     * @param httpService The HTTP service.
     * @param request The request bytes.
     * @param response The response bytes.
     * @param requestMarkers Markers for request highlighting.
     * @param responseMarkers Markers for response highlighting.
     * @return An IHttpRequestResponseWithMarkers object.
     */
    IHttpRequestResponseWithMarkers applyMarkers(
        IHttpRequestResponse baseRequestResponse,
        List<int[]> requestMarkers,
        List<int[]> responseMarkers
    );

    /**
     * Get the tool name for a given tool flag.
     * @param toolFlag The tool flag constant.
     * @return The tool name string.
     */
    String getToolName(int toolFlag);

    /**
     * Display an alert message to the user.
     * @param message The alert message.
     */
    void issueAlert(String message);

    /**
     * Get the standard output stream for the extension.
     * @return The output stream.
     */
    OutputStream getStdout();

    /**
     * Get the standard error stream for the extension.
     * @return The error stream.
     */
    OutputStream getStderr();

    /**
     * Include or exclude a URL from the target scope.
     * @param url The URL to modify.
     * @param inScope True to include, false to exclude.
     */
    void includeInScope(URL url);

    /**
     * Exclude a URL from the target scope.
     * @param url The URL to exclude.
     */
    void excludeFromScope(URL url);

    /**
     * Create a new HTTP service object.
     * @param host The hostname.
     * @param port The port number.
     * @param useHttps True for HTTPS, false for HTTP.
     * @return An IHttpService object.
     */
    IHttpService buildHttpService(String host, int port, boolean useHttps);
}
