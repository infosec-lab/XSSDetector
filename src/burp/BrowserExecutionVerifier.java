package burp;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.WebSocket;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Drives a real, local headless Chromium over the Chrome DevTools Protocol
 * (CDP) to answer the one question text-matching can never fully answer:
 * does the confirmed payload actually EXECUTE as JavaScript in a real
 * browser? Every other confirmation in this engine (and in most scanners)
 * is "the payload came back unescaped in the HTTP response" -- strong
 * evidence, but still an inference. This drives the exact bytes of the
 * confirmed request through a real browser's real HTML/JS parser, hooks
 * alert()/confirm()/prompt(), and reports whether they actually fired.
 *
 * Pure JDK: no bundled browser-automation library. CDP is just JSON over a
 * WebSocket (java.net.http.WebSocket, standard since Java 11) to a process
 * launched locally; discovery, the WS handshake, and the protocol messages
 * are all hand-rolled here deliberately, so this Burp extension stays a
 * single jar with no third-party runtime dependency to vet or ship.
 *
 * Fully optional and fail-soft: if no Chromium/Chrome binary can be found,
 * or the browser or protocol misbehaves, every call degrades to
 * {@link Verdict#unavailable(String)} and the engine's existing text-based
 * confirmation is unaffected -- this is an additional, stronger signal on
 * top of it, never a replacement or a gate.
 */
public final class BrowserExecutionVerifier {

    /** The hook installed on every new document, before any page script
     *  runs, via Page.addScriptToEvaluateOnNewDocument. It replaces the
     *  three classic XSS sink functions with recorders instead of letting
     *  them block the page on a modal (which would hang headless Chrome)
     *  and instead of leaving them as native functions a toString()-based
     *  detector could be fooled by. */
    private static final String HOOK_SCRIPT =
            "(function(){" +
            "  window.__xssdetector_fired = false;" +
            "  window.__xssdetector_calls = [];" +
            "  function hook(name){" +
            "    return function(){" +
            "      window.__xssdetector_fired = true;" +
            "      try { window.__xssdetector_calls.push(name + ':' + Array.prototype.join.call(arguments, ',')); } catch(e){}" +
            "      return true;" +
            "    };" +
            "  }" +
            "  window.alert = hook('alert');" +
            "  window.confirm = hook('confirm');" +
            "  window.prompt = hook('prompt');" +
            "})();";

    private static final Pattern WS_LISTEN_LINE =
            Pattern.compile("DevTools listening on (ws://127\\.0\\.0\\.1:\\d+/devtools/browser/[\\w-]+)");

    private static final String[] CANDIDATE_BINARIES = {
        "chromium", "chromium-browser", "google-chrome", "google-chrome-stable",
        "chrome", "microsoft-edge", "msedge"
    };

    private final HttpClient http = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5))
            .build();

    private volatile Process browserProcess;
    private volatile int devtoolsPort = -1;
    private final Object launchLock = new Object();
    private final java.util.concurrent.Semaphore concurrency = new java.util.concurrent.Semaphore(2);
    private volatile String unavailableReason; // sticky once discovery fails, so we don't retry every call

    /** The outcome of one browser-execution attempt. */
    public static final class Verdict {
        public final boolean attempted;
        public final boolean executed;
        public final String detail;
        public final List<String> sinkCalls;

        private Verdict(boolean attempted, boolean executed, String detail, List<String> sinkCalls) {
            this.attempted = attempted;
            this.executed = executed;
            this.detail = detail;
            this.sinkCalls = sinkCalls;
        }

        static Verdict unavailable(String why) {
            return new Verdict(false, false, why, java.util.Collections.emptyList());
        }

        static Verdict ran(boolean executed, String detail, List<String> sinkCalls) {
            return new Verdict(true, executed, detail, sinkCalls);
        }
    }

    /**
     * Replay a confirmed GET request in a real headless browser and report
     * whether alert()/confirm()/prompt() actually fired. {@code url} is the
     * exact URL of the confirmed evidence request (so the payload is in the
     * query string exactly as it was sent); {@code cookieHeader} and
     * {@code extraHeaders} let the replay carry whatever session state the
     * original request needed to reach the vulnerable page at all.
     */
    public Verdict verifyGet(String url, String cookieHeader, List<String[]> extraHeaders) {
        if (url == null || url.isEmpty()) {
            return Verdict.unavailable("no URL");
        }
        if (!concurrency.tryAcquire()) {
            return Verdict.unavailable("browser verifier busy (max concurrent replays reached)");
        }
        try {
            int port = ensureBrowser();
            if (port < 0) {
                return Verdict.unavailable(unavailableReason != null ? unavailableReason : "headless browser unavailable");
            }
            return navigateAndCheck(port, url, cookieHeader, extraHeaders);
        } catch (Exception e) {
            return Verdict.unavailable("browser verification error: " + e.getMessage());
        } finally {
            concurrency.release();
        }
    }

    /** Kill the headless browser process, if one is running. Call on extension unload. */
    public void shutdown() {
        Process p = browserProcess;
        if (p != null) {
            try {
                p.destroy();
                if (!p.waitFor(2, TimeUnit.SECONDS)) {
                    p.destroyForcibly();
                }
            } catch (Exception ignored) {
                // best-effort
            }
        }
    }

    // ------------------------------------------------------------------
    // Browser discovery + lazy launch
    // ------------------------------------------------------------------

    private int ensureBrowser() {
        Process p = browserProcess;
        if (p != null && p.isAlive() && devtoolsPort > 0) {
            return devtoolsPort;
        }
        synchronized (launchLock) {
            p = browserProcess;
            if (p != null && p.isAlive() && devtoolsPort > 0) {
                return devtoolsPort;
            }
            if (unavailableReason != null) {
                return -1; // discovery already failed this session; don't hammer the filesystem/process table
            }
            String binary = findBinary();
            if (binary == null) {
                unavailableReason = "no Chromium/Chrome binary found on PATH (tried "
                        + String.join(", ", CANDIDATE_BINARIES) + ")";
                return -1;
            }
            try {
                java.io.File profile = java.nio.file.Files.createTempDirectory("xssdetector-chrome").toFile();
                profile.deleteOnExit();
                ProcessBuilder pb = new ProcessBuilder(
                        binary,
                        "--headless=new",
                        "--disable-gpu",
                        "--no-sandbox",
                        "--disable-dev-shm-usage",
                        "--disable-extensions",
                        "--disable-popup-blocking", // alert() is hooked, not blocked, but keep nothing else modal
                        "--remote-debugging-port=0",
                        "--user-data-dir=" + profile.getAbsolutePath()
                );
                pb.redirectErrorStream(false);
                Process proc = pb.start();
                int port = readDevtoolsPort(proc);
                if (port < 0) {
                    proc.destroyForcibly();
                    unavailableReason = "headless browser started but never printed a DevTools listening port";
                    return -1;
                }
                browserProcess = proc;
                devtoolsPort = port;
                return port;
            } catch (Exception e) {
                unavailableReason = "could not launch headless browser: " + e.getMessage();
                return -1;
            }
        }
    }

    private String findBinary() {
        String override = System.getenv("XSSDETECTOR_CHROME_PATH");
        if (override != null && !override.isEmpty() && new java.io.File(override).canExecute()) {
            return override;
        }
        for (String name : CANDIDATE_BINARIES) {
            try {
                Process probe = new ProcessBuilder(name, "--version").start();
                boolean done = probe.waitFor(3, TimeUnit.SECONDS);
                if (done && probe.exitValue() == 0) {
                    return name;
                }
                probe.destroyForcibly();
            } catch (Exception ignored) {
                // not found / not executable -- try the next candidate
            }
        }
        return null;
    }

    private int readDevtoolsPort(Process proc) throws Exception {
        // Chrome prints "DevTools listening on ws://127.0.0.1:PORT/devtools/browser/<id>"
        // to stderr as soon as the debug port is up.
        BufferedReader err = new BufferedReader(new InputStreamReader(proc.getErrorStream(), StandardCharsets.UTF_8));
        long deadline = System.currentTimeMillis() + 10_000;
        String line;
        while (System.currentTimeMillis() < deadline && (line = err.readLine()) != null) {
            Matcher m = WS_LISTEN_LINE.matcher(line);
            if (m.find()) {
                String ws = m.group(1); // ws://127.0.0.1:PORT/devtools/browser/<id>
                Matcher pm = Pattern.compile(":(\\d+)/").matcher(ws);
                if (pm.find()) {
                    return Integer.parseInt(pm.group(1));
                }
            }
            if (!proc.isAlive()) {
                break;
            }
        }
        return -1;
    }

    // ------------------------------------------------------------------
    // One navigate-and-check pass, in a fresh tab
    // ------------------------------------------------------------------

    private Verdict navigateAndCheck(int port, String url, String cookieHeader, List<String[]> extraHeaders)
            throws Exception {
        String targetId = null;
        String wsUrl = null;
        try {
            HttpResponse<String> newTab = http.send(
                    HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + "/json/new?about:blank"))
                            .timeout(Duration.ofSeconds(5)).PUT(HttpRequest.BodyPublishers.noBody()).build(),
                    HttpResponse.BodyHandlers.ofString());
            String body = newTab.body();
            targetId = extractJsonString(body, "id");
            wsUrl = extractJsonString(body, "webSocketDebuggerUrl");
            if (wsUrl == null) {
                return Verdict.unavailable("could not open a new browser tab (DevTools /json/new failed)");
            }

            CdpSession session = new CdpSession(wsUrl);
            try {
                session.send("Page.enable", "{}");
                session.send("Runtime.enable", "{}");
                session.send("Network.enable", "{}");
                session.send("Page.addScriptToEvaluateOnNewDocument",
                        "{\"source\":" + jsonString(HOOK_SCRIPT) + "}");

                java.net.URI target = java.net.URI.create(url);
                String host = target.getHost();
                if (cookieHeader != null && !cookieHeader.isEmpty() && host != null) {
                    for (String pair : cookieHeader.split(";")) {
                        int eq = pair.indexOf('=');
                        if (eq <= 0) continue;
                        String name = pair.substring(0, eq).trim();
                        String value = pair.substring(eq + 1).trim();
                        if (name.isEmpty()) continue;
                        session.send("Network.setCookie", "{\"name\":" + jsonString(name)
                                + ",\"value\":" + jsonString(value) + ",\"url\":" + jsonString(url) + "}");
                    }
                }
                if (extraHeaders != null && !extraHeaders.isEmpty()) {
                    StringBuilder hdrs = new StringBuilder("{");
                    boolean first = true;
                    for (String[] h : extraHeaders) {
                        if (!first) hdrs.append(',');
                        hdrs.append(jsonString(h[0])).append(':').append(jsonString(h[1]));
                        first = false;
                    }
                    hdrs.append('}');
                    session.send("Network.setExtraHTTPHeaders", "{\"headers\":" + hdrs + "}");
                }

                session.send("Page.navigate", "{\"url\":" + jsonString(url) + "}");

                // Give the page, and anything it does on load (sync scripts,
                // onload handlers), a short window to run, then ask it directly
                // whether the hook fired. Polled rather than event-driven to
                // keep the CDP client small and dependency-free.
                boolean fired = false;
                List<String> calls = new ArrayList<>();
                long deadline = System.currentTimeMillis() + 3000;
                while (System.currentTimeMillis() < deadline) {
                    Thread.sleep(200);
                    // Deliberately a bare boolean, not JSON.stringify()'d: a
                    // stringified object nests escaped quotes inside the CDP
                    // response's own JSON, which a simple regex extractor
                    // cannot reliably unwrap. A primitive boolean has no such
                    // nesting problem.
                    if ("true".equals(session.evaluate("window.__xssdetector_fired===true"))) {
                        fired = true;
                        // Best-effort, separate round-trip for the human-readable
                        // detail; a rare separator avoids needing to parse
                        // embedded quotes/commas from arbitrary alert() arguments.
                        String joined = session.evaluate("(window.__xssdetector_calls||[]).join('\\u0001')");
                        if (joined != null && !joined.isEmpty()) {
                            calls.addAll(Arrays.asList(joined.split("\u0001")));
                        }
                        break;
                    }
                }
                return Verdict.ran(fired,
                        fired ? "alert/confirm/prompt actually executed in a real headless browser"
                              : "navigated successfully but no alert/confirm/prompt fired within 3s",
                        calls);
            } finally {
                session.close();
            }
        } finally {
            if (targetId != null) {
                try {
                    http.send(HttpRequest.newBuilder(
                            URI.create("http://127.0.0.1:" + port + "/json/close/" + targetId))
                            .timeout(Duration.ofSeconds(3)).PUT(HttpRequest.BodyPublishers.noBody()).build(),
                            HttpResponse.BodyHandlers.discarding());
                } catch (Exception ignored) {
                    // best-effort tab cleanup
                }
            }
        }
    }

    // ------------------------------------------------------------------
    // Minimal CDP-over-WebSocket session (JSON-RPC-ish, hand-rolled)
    // ------------------------------------------------------------------

    private static final class CdpSession {
        private final WebSocket ws;
        private final AtomicInteger nextId = new AtomicInteger(1);
        private final java.util.Map<Integer, CompletableFuture<String>> pending = new ConcurrentHashMap<>();
        private final StringBuilder frameBuffer = new StringBuilder();

        CdpSession(String wsUrl) throws Exception {
            CompletableFuture<Void> opened = new CompletableFuture<>();
            this.ws = HttpClient.newHttpClient().newWebSocketBuilder()
                    .connectTimeout(Duration.ofSeconds(5))
                    .buildAsync(URI.create(wsUrl), new WebSocket.Listener() {
                        @Override
                        public void onOpen(WebSocket webSocket) {
                            opened.complete(null);
                            WebSocket.Listener.super.onOpen(webSocket);
                        }

                        @Override
                        public CompletableFuture<?> onText(WebSocket webSocket, CharSequence data, boolean last) {
                            frameBuffer.append(data);
                            if (last) {
                                String msg = frameBuffer.toString();
                                frameBuffer.setLength(0);
                                handleMessage(msg);
                            }
                            webSocket.request(1);
                            return null;
                        }
                    })
                    .get(5, TimeUnit.SECONDS);
            opened.get(5, TimeUnit.SECONDS);
        }

        private void handleMessage(String msg) {
            Matcher idm = Pattern.compile("^\\{\"id\":(\\d+)").matcher(msg);
            if (idm.find()) {
                int id = Integer.parseInt(idm.group(1));
                CompletableFuture<String> f = pending.remove(id);
                if (f != null) {
                    f.complete(msg);
                }
            }
            // Events (no "id") are ignored -- this client polls Runtime.evaluate
            // instead of subscribing to Page.loadEventFired, deliberately, to
            // keep the protocol surface this small and dependency-free.
        }

        String send(String method, String paramsJson) throws Exception {
            int id = nextId.getAndIncrement();
            CompletableFuture<String> f = new CompletableFuture<>();
            pending.put(id, f);
            String payload = "{\"id\":" + id + ",\"method\":" + jsonString(method)
                    + ",\"params\":" + paramsJson + "}";
            ws.sendText(payload, true).get(5, TimeUnit.SECONDS);
            try {
                return f.get(5, TimeUnit.SECONDS);
            } catch (Exception e) {
                pending.remove(id);
                return null;
            }
        }

        /** Runtime.evaluate and return the JSON-encoded result value as a raw string. */
        String evaluate(String expression) throws Exception {
            String resp = send("Runtime.evaluate",
                    "{\"expression\":" + jsonString(expression) + ",\"returnByValue\":true}");
            if (resp == null) {
                return null;
            }
            // Escape-aware string alternative FIRST: "((?:\\.|[^"\\])*)" correctly
            // treats an escaped quote (\") as content, not a terminator -- a naive
            // ".*?" lazy match stops at the first literal '"' and silently
            // truncates any value containing one (which every JSON.stringify()'d
            // object does). Learned the hard way: this exact bug made every
            // execution look unconfirmed in early local testing.
            Matcher m = Pattern.compile(
                    "\"value\":(\"(?:\\\\.|[^\"\\\\])*\"|true|false|-?\\d+(?:\\.\\d+)?)").matcher(resp);
            if (m.find()) {
                String raw = m.group(1);
                if (raw.startsWith("\"")) {
                    return unescapeJson(raw.substring(1, raw.length() - 1));
                }
                return raw;
            }
            return null; // no "value" field (e.g. undefined result) -- not an error
        }

        void close() {
            try {
                ws.sendClose(WebSocket.NORMAL_CLOSURE, "").get(2, TimeUnit.SECONDS);
            } catch (Exception ignored) {
                // best-effort
            }
        }
    }

    // ------------------------------------------------------------------
    // Tiny, purpose-built JSON helpers (no library -- the surface used here
    // is narrow enough that hand-rolled escaping/extraction is safe and
    // keeps this file dependency-free).
    // ------------------------------------------------------------------

    private static String jsonString(String s) {
        StringBuilder b = new StringBuilder("\"");
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"': b.append("\\\""); break;
                case '\\': b.append("\\\\"); break;
                case '\n': b.append("\\n"); break;
                case '\r': b.append("\\r"); break;
                case '\t': b.append("\\t"); break;
                default:
                    if (c < 0x20) {
                        b.append(String.format("\\u%04x", (int) c));
                    } else {
                        b.append(c);
                    }
            }
        }
        return b.append('"').toString();
    }

    private static String unescapeJson(String s) {
        if (s == null) return "";
        String t = s.trim();
        if (t.startsWith("\"") && t.endsWith("\"") && t.length() >= 2) {
            t = t.substring(1, t.length() - 1);
        }
        StringBuilder b = new StringBuilder();
        for (int i = 0; i < t.length(); i++) {
            char c = t.charAt(i);
            if (c == '\\' && i + 1 < t.length()) {
                char n = t.charAt(++i);
                switch (n) {
                    case 'n': b.append('\n'); break;
                    case 'r': b.append('\r'); break;
                    case 't': b.append('\t'); break;
                    case '"': b.append('"'); break;
                    case '\\': b.append('\\'); break;
                    default: b.append(n);
                }
            } else {
                b.append(c);
            }
        }
        return b.toString();
    }

    /** Extract a top-level string field "key":"value" from a small flat JSON blob. */
    private static String extractJsonString(String json, String key) {
        if (json == null) return null;
        Matcher m = Pattern.compile("\"" + Pattern.quote(key) + "\"\\s*:\\s*\"((?:[^\"\\\\]|\\\\.)*)\"").matcher(json);
        if (m.find()) {
            return unescapeJson(m.group(1));
        }
        return null;
    }
}
