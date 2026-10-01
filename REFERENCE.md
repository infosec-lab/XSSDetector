# XSSDetector — quick reference

Short notes on using the extension and reading its UI. Load the JAR in
**Extensions → Add → Java**, then open the **XSSDetector** tab.

## Tabs

- **Live Results** — findings as they happen, plus filters and a request/response viewer.
- **Settings** — what to run (engines, payload packs, reporting).
- **Content Types** — which response types to look at (text/html and application/json on by default).

## Live Results

The table fills in real time from two sources:

- **Confirmed** (red) — an active scan injected a context payload and saw it
  reflected unescaped. Real, verified XSS.
- **Reflected** (grey) — seen while browsing: the input is reflected somewhere,
  not yet actively tested. Run an active scan on it; if it checks out it flips to
  Confirmed on its own.

Columns: Time · Severity · Status · Context · Parameter · URL · Source.

Pick a row to see its **Request** / **Response** below (the payload is highlighted
in the real Burp view too).

### Smart filters (right side)

- **Search** — matches URL, parameter, context or PoC as you type.
- **Severity** — High / Medium / Low·Info.
- **Status** — Confirmed and/or Reflected.
- **Context** — HTML, Attribute, JavaScript, JSON/JSONP, CSS, Other.
- **Clear results** empties the list; **Export CSV** saves what's currently shown.

The counter reads `shown / total`, so you always know what the filters are hiding.

## Running it

1. Add the target to Burp scope (turn on *Scan in-scope targets only* if you want).
2. Browse the app — reflections start showing up under Live Results.
3. Right-click a request → **Scan**, or run Burp's scanner, to confirm them.
4. Confirmed findings also appear in Burp's own **Issues** list, with the live
   break-out table and a ready PoC — no boilerplate.

## How a confirm works (one line)

For each parameter it sends a canary + every break-out character, reads back
exactly which survive and in what context, then fires the matching PoC and only
reports if that PoC comes back unescaped — so false positives are rare.
