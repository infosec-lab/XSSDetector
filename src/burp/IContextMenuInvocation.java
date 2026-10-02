package burp;

/**
 * Burp context-menu invocation (subset of the Burp Extender API). Only the
 * members the extension uses are declared.
 */
public interface IContextMenuInvocation {
    IHttpRequestResponse[] getSelectedMessages();
    byte getInvocationContext();
}
