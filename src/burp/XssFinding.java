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
    public String technique;      // the bypass technique that confirmed it (direct, double-URL-encoded, ...)

    /** Where the parameter lives: "URL parameter", "Body parameter", "Cookie",
     *  "JSON value", "XML value", "Multipart parameter", "URL path", ... Shown
     *  as its own column so a cookie/header-style parameter is never confused
     *  with a query-string one. */
    public String paramSource = "";

    /** True when THIS row came from an active probe-and-confirm pass (a real
     *  context-specific payload was injected and the live response checked) --
     *  as opposed to a purely passive text match while browsing, where the
     *  parameter's value simply happened to appear somewhere in the response.
     *  Surfaced as its own "Tested" column so the two are never conflated. */
    public boolean testedContextually;

    /** Real headless-browser execution proof (see BrowserExecutionVerifier):
     *  null = not attempted (non-GET, browser unavailable, or disabled in
     *  Settings); true = alert/confirm/prompt genuinely fired when replayed
     *  in a real browser; false = attempted but did not fire. This is a
     *  STRONGER signal than the text-based confirmation every other field
     *  here already represents -- it is on top of it, never a substitute. */
    public Boolean browserVerified;
    public String browserDetail;

    /** One request/response pair shown in the viewer (Original, Edited 1, ...). */
    public static final class Msg {
        public final String label;
        public final byte[] request;
        public final byte[] response;
        public final String reqHighlight;
        public final String respHighlight;

        public Msg(String label, byte[] request, byte[] response, String reqHighlight, String respHighlight) {
            this.label = label;
            this.request = request;
            this.response = response;
            this.reqHighlight = reqHighlight;
            this.respHighlight = respHighlight;
        }
    }

    /** Ordered message pairs for the viewer: Original first, then each Edited probe/PoC. */
    public final java.util.List<Msg> messages = new java.util.ArrayList<>();

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

    /** Stable identity so the same reflection is not listed twice. Deliberately
     *  independent of status, severity and payload, so a later CONFIRMED result
     *  UPGRADES the earlier REFLECTED row for the same spot instead of adding a
     *  second row. */
    public String dedupKey() {
        return context + "|" + parameter + "|" + stripQuery(url);
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
