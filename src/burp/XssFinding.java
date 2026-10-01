package burp;

/**
 * One row of live scanner evidence shown in the Live Results view.
 *
 * A finding is either CONFIRMED (an active probe injected a context-specific
 * payload and observed it reflected unescaped) or REFLECTED (passive, seen
 * while browsing: the input is reflected but not yet actively verified).
 */
public final class XssFinding {

    public static final String STATUS_CONFIRMED = "Confirmed";
    public static final String STATUS_REFLECTED = "Reflected";

    public final long time;
    public final String severity;   // High / Medium / Low / Info
    public final String status;     // Confirmed / Reflected
    public final String context;    // reflection context label
    public final String parameter;
    public final String method;
    public final String host;
    public final String url;
    public final String source;     // Scanner / Proxy / Repeater ...
    public final String poc;
    public final byte[] request;
    public final byte[] response;

    // Optional viewer/navigation extras (set after construction).
    public String reqHighlight;   // substring to highlight+scroll-to in the request
    public String respHighlight;  // substring to highlight+scroll-to in the response
    public int port;
    public boolean https;

    public XssFinding(String severity, String status, String context, String parameter,
                      String method, String host, String url, String source, String poc,
                      byte[] request, byte[] response) {
        this.time = System.currentTimeMillis();
        this.severity = severity == null ? "Info" : severity;
        this.status = status == null ? STATUS_REFLECTED : status;
        this.context = context == null ? "" : context;
        this.parameter = parameter == null ? "" : parameter;
        this.method = method == null ? "" : method;
        this.host = host == null ? "" : host;
        this.url = url == null ? "" : url;
        this.source = source == null ? "" : source;
        this.poc = poc == null ? "" : poc;
        this.request = request;
        this.response = response;
    }

    /** Stable identity so the same reflection is not listed twice. */
    public String dedupKey() {
        return status + "|" + severity + "|" + context + "|" + parameter + "|" + stripQuery(url);
    }

    private static String stripQuery(String u) {
        int q = u.indexOf('?');
        return q >= 0 ? u.substring(0, q) : u;
    }

    public int severityRank() {
        switch (severity) {
            case "High": return 3;
            case "Medium": return 2;
            case "Low": return 1;
            default: return 0;
        }
    }
}
