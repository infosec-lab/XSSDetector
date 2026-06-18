package burp;

/**
 * Extensions can implement this interface and register it via
 * IBurpExtenderCallbacks.registerExtensionStateListener() to receive
 * notifications of changes in the extension's state.
 */
public interface IExtensionStateListener {

    /**
     * This method is called when the extension is unloaded.
     * Extensions should perform any necessary cleanup here.
     */
    void extensionUnloaded();
}
