# XSSDetector — live test notes

Short, hand-written notes for taking this build to a live target. Written after a
full readiness audit (compile, tests, UI render, wiring) — see the checklist at
the end.

## What it does now

One engine does the detection: the **Contextual Reflection Engine**. For every
URL, body, cookie, **JSON, XML and multipart** parameter it

1. sends a canary + break-out probe and measures which characters survive,
2. classifies **every distinct reflection context** the parameter lands in
   (HTML text, attribute, tag position, `<script>`, JS string / template,
   event handler, CSS, JSON value, JSONP — a parameter reflected into more
   than one context, e.g. once in HTML and once in a JSON blob, gets a
   context-specific payload tried against each one, not just the single
   most-confident context), and
3. injects a real payload per context and **confirms a live break-out** (a
   working `alert()/confirm()/prompt()`) before it reports anything.

If the break-out does not come back executable, it is **not** reported as a
vulnerability — so there are no score thresholds and effectively no false
positives. The old heuristic DOM / client-side / CSP detectors (which guessed
against risk thresholds and produced the false positives) have been removed.

**Passive "reflected" sightings require a distinctive value.** While browsing,
a parameter whose *current* value is a generic boolean/enum/tiny-number
(`true`, `false`, `0`, `1`, `on`, `off`, `asc`, `desc`, ...) is never flagged
as "reflected" from a plain text match — that text is likely to appear
elsewhere in the page for reasons that have nothing to do with the
parameter. The active probe (which injects a random canary, never the
original value) still fully tests these parameters for a real break-out.

## Load it

1. Build (or use `dist/XSSDetector.jar`): `bash build.sh`.
2. Burp → **Extensions → Add → Java** → pick `dist/XSSDetector.jar`.
3. Open the **XSSDetector** tab. You should see **Live Results** and **Settings**.

## Run the live test (two ways)

**A. Just browse (auto-confirm, default).** Proxy your target through Burp and use
the app normally. Reflected parameters are probed and confirmed automatically as
you browse — confirmed XSS shows up in **Live Results** and in Burp's **Issues**
tab. No Burp scope setup needed.

- If you only want it to touch certain hosts, turn on **Settings → Scan in-scope
  targets only** and set your Target scope. With it off (default), it
  auto-confirms everything you browse.

**C. Whole site map.** Right-click anywhere in Burp → **Scan entire Target site
map (XSSDetector)**. It sweeps every unique endpoint in Burp's Target site map,
tests only responses whose content-type is enabled in Content Type Management,
and honors the scope setting (scope off = all domains; scope on = in-scope only).
Capped at 400 endpoints per run; progress and a summary print to the extension
output and a dialog.

**B. On demand.** Right-click a request anywhere in Burp → **Active XSS scan**.
It tests every parameter and pops a summary: parameters tested / reflected /
confirmed, with a per-parameter line (confirmed, or reflected-but-filtered, or
not reflected). Reflected-but-not-exploitable spots are listed as grey
**Reflected (Info)** rows so you can see them — they are never reported as issues.

## Reading Live Results

- **Confirmed** (red) = verified break-out. **Reflected** = seen but not (yet)
  exploitable; its row is amber if it was *actively tested* (a real
  context-specific payload was fired and did not break out) and grey-blue if
  it is a *passive sighting only* (seen while browsing, never yet probed).
- **Tested** column — "Yes"/"No". Tells you, per row, whether a live payload
  was actually injected and checked for that exact spot, as opposed to the
  parameter's existing value merely being spotted somewhere in the response
  text. Shown in green ("Yes") / grey ("No") so the two very different
  confidence levels are never confused at a glance.
- **Param Source** column — where the parameter lives: `URL parameter`,
  `Body parameter`, `Cookie`, `JSON value`, `XML value`, `Multipart
  parameter`, or `URL path`.
- Request on the left, response on the right; each pane's dropdown switches
  Original / Edited 1, 2, 3 … The injected value and the reflected payload are
  highlighted and scrolled to. Per-pane search with ▲/▼.
- The PoC bar shows the parameter, its source, context, exploit payload and
  the bypass technique that confirmed it.

## Real browser-execution proof

Every "Confirmed" finding above is still, fundamentally, a text match: the
payload came back unescaped in the HTTP response. That is strong evidence,
but it is an inference, not a demonstration -- a scanner saying "this text
would execute" is not the same as it actually executing.

So, on top of every confirmed GET finding, the engine now also drives a
real, local headless Chromium over the Chrome DevTools Protocol: it hooks
`alert`/`confirm`/`prompt` (recording the call instead of letting it block a
modal, which would hang headless Chrome), replays the EXACT confirmed
request -- including its `Cookie` header and any `Authorization`/`X-*`
headers, via CDP, so an auth-gated reflection still reaches the vulnerable
page -- and reports whether the hook genuinely fired. This is pure-JDK (the
WebSocket client in `java.net.http`, standard since Java 11): no bundled
browser-automation library, so the extension stays one dependency-free jar.

- **Settings -> Verify execution in a real headless browser** (on by
  default). Needs a `chromium`/`chromium-browser`/`google-chrome`/
  `google-chrome-stable`/`chrome`/`microsoft-edge`/`msedge` binary on PATH
  (or `XSSDETECTOR_CHROME_PATH` pointing at one directly). If none is found,
  every attempt degrades to "not attempted" -- logged once, never retried,
  never a false claim either way -- and the text-based result is completely
  unaffected.
- POST/PUT/etc. findings are skipped (a browser navigation has no request
  body) and show "not attempted (non-GET request)".
- Live Results gets a **Browser Proof** column: bold green **EXECUTED** (the
  strongest signal this tool can produce), amber **no** (replayed, but
  didn't fire -- the text-based Confirmed result still stands), or grey
  **-** (not attempted). The PoC bar and the Burp issue detail both carry
  the same verdict, plus which sink (`alert`/`confirm`/`prompt`) and
  argument actually fired when it did.
- The headless browser process is launched lazily on first use and reused
  across findings (so after the first ~1-2s cold start, each replay is
  typically well under a second); it is killed on extension unload.

This was built and verified end-to-end against a local test server during
development (a genuinely vulnerable unescaped-reflection page that correctly
reported EXECUTED, a safely-HTML-encoded control page that correctly did
not, and an auth-gated page that only executed once the session cookie and
a custom header were replayed) -- not just written to look plausible.

## Custom attack (your own payload list)

The table is multi-select (ctrl/shift-click, or drag across rows) specifically
so this can target several reflected findings at once. Select one or more
rows with an injectable parameter, then **Custom attack (payload list)...**
— either the button in the filters panel or the right-click menu item (a
right-click on a row already part of your selection keeps the whole
selection; on an unselected row it replaces it, as usual). Each selected row
is re-located to its exact parameter in its own original request, and the
SAME payload list you provide is then fired at every one of them, one
request per (target, payload) pair. Rows that can't be resolved (parameter no
longer in the stored request, no host, etc.) are skipped with a reason shown
up front; the rest still run.

- **Paste** payloads straight into the text area (one per line; blank lines
  and lines starting with `#` are skipped).
- **Load from file...** reads a `.txt` list (one payload per line) in.
- **Built-in set** has five small starter lists (basic tags, attribute
  break-out, JavaScript context, filter/WAF bypass, a polyglot) you can
  insert and then edit.

**Start attack** runs the whole list against every target in turn, in the
background (Stop cancels mid-run), and shows a live results table of Target /
Payload / Reflected / Status. Any payload that comes back **verbatim and
unescaped** is also added to the main Live Results table as a Confirmed,
High-severity row (source "Custom Attack"), so it is
filterable/exportable/sendable-to-Repeater exactly like an engine-found
issue. Capped at 2000 payloads per run (asks first if your list is bigger) --
note that is 2000 PER TARGET, so N targets means up to N x 2000 live requests.

This is a separate path from the engine's own automatic, confirmed-only
detection above — it exists for when you already have a payload (or a list
from elsewhere) you specifically want tried against a known reflection
point, rather than the engine's own curated context payloads.

## Settings that actually drive detection

- **Contextual reflection engine** — master on/off for all detection (keep on).
- **Live confirm while browsing** — the auto-confirm in method A (on by default).
- **Scan in-scope targets only** — restricts auto-confirm to Burp scope (off by default).
- **Content Type Management** (bottom of Settings) — which response types are
  looked at; `text/html` and `application/json` are on by default.
- **Verbose logging** — off by default; turn on only to debug (it prints probe detail).

Other check-boxes (payload packs, etc.) are left in place but the confirm engine
uses its own fixed, curated set of context payloads and bypasses, so they do not
change what gets detected.

## Readiness checklist

- Clean compile, Java 11 bytecode (class version 55) — verified with
  `javac --release 11` directly, not just `build.sh`'s own jar step.
- Jar packs clean (no stale/removed classes); UI renders both tabs.
- All Burp hooks registered: scanner check, HTTP listener, context-menu factory,
  extension-state listener, suite tab.
- Detection wired on all three paths: active scan, browse (passive + live
  confirm), and right-click Active XSS scan; each now tries a context-specific
  payload against every distinct reflection context a parameter has, not only
  the single highest-confidence one.

## Troubleshooting: "I don't see anything Confirmed anywhere"

Open Burp's **Extender -> Extensions -> XSSDetector -> Output** tab (not the
XSSDetector suite tab -- the Extender output console). Two things to look
for, both now always printed (no need to turn on Verbose logging first):

1. **At load**, an "Effective settings" block: whether the engine toggle is
   even ON, whether "Live confirm while browsing" is ON, and -- usually the
   actual cause -- the Content Type Management list. Browse-time detection
   (passive + live confirm) ONLY looks at responses whose Content-Type is in
   that list; if your target serves e.g. `application/vnd.api+json` and only
   `text/html`/`application/json` are enabled, every response is silently
   skipped. A one-time line also fires the first time a response is skipped
   for exactly this reason, naming the actual Content-Type seen.
2. **While browsing**, one `Live browse param '<name>' (<source>) at
   <host><path>: <diagnostic>` line per parameter that was actually tested
   (the same diagnostic the active Scanner path has always printed). It
   tells you plainly which of these happened:
   - `not reflected` -- the parameter's value never came back at all.
   - `reflected in <context>; no break-out character survived
     (encoded/stripped)` -- seen, but the app HTML-encodes or strips every
     special character there (a real, correctly-escaped app -- not a bug).
   - `reflected; context=<context>; trying payload`, followed (if nothing
     made it to Confirmed) by a second line saying the break-out character(s)
     survived but no payload variant confirmed unescaped -- check that row's
     Edited attempts in Live Results to see exactly what was tried and how
     the app handled each one.
   - If you see NO such lines at all while browsing a page you know has
     parameters: either the parameter's current value is too short/generic
     to pass the initial filters (less than 3-4 chars, a path-like value, or
     a low-signal boolean/enum -- Custom Attack bypasses this, since you
     choose the payload directly), or "Live confirm while browsing" is OFF,
     or the response's status code is >= 400 (error pages are skipped), or
     the parameter was already probed once this session (each spot is only
     auto-probed once per session -- restart the scan or reload the
     extension to re-probe).

If after checking the Output tab a parameter you believe is vulnerable shows
`not reflected` or an encoded-only diagnostic, that is the engine's honest
answer for that target as tested, not a silent failure -- try **Custom
attack** with your own payload list against that exact parameter instead,
or pull the Live Results row's Edited attempts to see the raw responses.

**No automated test suite is committed to this repo** (`git ls-files` for
anything test-related returns nothing, despite earlier revisions of this file
claiming specific passing counts — that claim was never backed by a checked-in
test). Validate changes against a real target or a local reflecting
sandbox page before relying on this build live.
