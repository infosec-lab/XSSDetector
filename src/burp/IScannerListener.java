package burp;

/**
 * Extensions can implement this interface and register it via
 * IBurpExtenderCallbacks.registerScannerListener() to receive notifications
 * about new issues discovered by the Scanner tool.
 */
public interface IScannerListener {

    /**
     * This method is invoked when a new issue is added to Burp Scanner's results.
     *
     * @param issue An IScanIssue object containing details of the new issue.
     */
    void newScanIssue(IScanIssue issue);
}
