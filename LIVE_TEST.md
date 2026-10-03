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

## Custom attack (your own payload list)

Select any row with an injectable parameter, then **Custom attack (payload
list)...** — either the button in the filters panel or the right-click menu
item. It re-locates that row's exact parameter in its original request and
fires your own payloads at it, one per live request:

- **Paste** payloads straight into the text area (one per line; blank lines
  and lines starting with `#` are skipped).
- **Load from file...** reads a `.txt` list (one payload per line) in.
- **Built-in set** has five small starter lists (basic tags, attribute
  break-out, JavaScript context, filter/WAF bypass, a polyglot) you can
  insert and then edit.

**Start attack** runs the whole list in the background (Stop cancels mid-run)
and shows a live results table of Payload / Reflected / Status. Any payload
that comes back **verbatim and unescaped** is also added to the main Live
Results table as a Confirmed, High-severity row (source "Custom Attack"), so
it is filterable/exportable/sendable-to-Repeater exactly like an engine-found
issue. Capped at 2000 payloads per run (asks first if your list is bigger).

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

**No automated test suite is committed to this repo** (`git ls-files` for
anything test-related returns nothing, despite earlier revisions of this file
claiming specific passing counts — that claim was never backed by a checked-in
test). Validate changes against a real target or a local reflecting
sandbox page before relying on this build live.
