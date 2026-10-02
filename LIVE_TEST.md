# XSSDetector — live test notes

Short, hand-written notes for taking this build to a live target. Written after a
full readiness audit (compile, tests, UI render, wiring) — see the checklist at
the end.

## What it does now

One engine does the detection: the **Contextual Reflection Engine**. For every
URL, body, cookie, **JSON, XML and multipart** parameter it

1. sends a canary + break-out probe and measures which characters survive,
2. classifies the exact reflection context (HTML text, attribute, tag position,
   `<script>`, JS string / template, event handler, CSS, JSON value, JSONP), and
3. injects a real payload and **confirms a live break-out** (a working
   `alert()/confirm()/prompt()`) before it reports anything.

If the break-out does not come back executable, it is **not** reported as a
vulnerability — so there are no score thresholds and effectively no false
positives. The old heuristic DOM / client-side / CSP detectors (which guessed
against risk thresholds and produced the false positives) have been removed.

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

**B. On demand.** Right-click a request anywhere in Burp → **Active XSS scan**.
It tests every parameter and pops a summary: parameters tested / reflected /
confirmed, with a per-parameter line (confirmed, or reflected-but-filtered, or
not reflected). Reflected-but-not-exploitable spots are listed as grey
**Reflected (Info)** rows so you can see them — they are never reported as issues.

## Reading Live Results

- **Confirmed** (red) = verified break-out. **Reflected** (grey) = seen but not
  (yet) exploitable.
- Request on the left, response on the right; each pane's dropdown switches
  Original / Edited 1, 2, 3 … The injected value and the reflected payload are
  highlighted and scrolled to. Per-pane search with ▲/▼.
- The PoC bar shows the parameter, context, exploit payload and the bypass
  technique that confirmed it.

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

## Readiness checklist (all passing)

- Clean compile, Java 11 bytecode (class version 55).
- Test suites: Engine 17, JSON 5, context 7, dedup 6, variants 11, plus an
  in-process integration harness (8) that drives real reflected XSS — including a
  JSON POST body — through the engine and confirms it, while a safely
  HTML-encoded reflection is correctly **not** confirmed.
- Jar packs clean (no stale/removed classes); UI renders both tabs.
- All Burp hooks registered: scanner check, HTTP listener, context-menu factory,
  extension-state listener, suite tab.
- Detection wired on all three paths: active scan, browse (passive + live
  confirm), and right-click Active XSS scan.
