package burp;

import java.util.List;

/**
 * Marker interface used by Burp Suite to highlight byte ranges in the raw
 * request/response viewers for a given issue.
 *
 * Ranges are expressed as int[] pairs: { startOffset, endOffset }.
 */
public interface IHttpRequestResponseWithMarkers extends IHttpRequestResponse {
    List<int[]> getRequestMarkers();
    List<int[]> getResponseMarkers();
}


