package burp;

/**
 * Extensions can implement this interface and register it via
 * IBurpExtenderCallbacks.registerHttpListener() to receive notifications
 * about HTTP messages processed by any Burp tool.
 */
public interface IHttpListener {

    /**
     * This method is invoked when an HTTP request is about to be issued,
     * and when an HTTP response has been received.
     *
     * @param toolFlag A flag indicating the Burp tool that issued the request.
     *                 Burp tool flags are defined in the IBurpExtenderCallbacks interface.
     * @param messageIsRequest True if the message is a request, false if it is a response.
     * @param messageInfo Details of the request/response to be processed.
     */
    void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo);
}
