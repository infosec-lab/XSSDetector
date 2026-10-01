# XSSDetector — Advanced XSS Vulnerability Scanner for Burp Suite

<div align="center">

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Java](https://img.shields.io/badge/Java-11%2B-blue.svg)](https://www.oracle.com/java/)
[![Burp Suite](https://img.shields.io/badge/Burp%20Suite-2023.1%2B-orange.svg)](https://portswigger.net/burp)
[![Version](https://img.shields.io/badge/Version-2.0.0-green.svg)](https://github.com/infosec-lab/XSSDetector/releases)

A Burp Suite extension that detects reflected, stored, DOM, and client-side XSS
using context-aware payloads, encoding/filter-bypass techniques, and
source-to-sink analysis — with validated, reproducible findings.

</div>

## Screenshot

![Results Dashboard](screenshot/4.Results.png)
*Findings with payload, reflection context, exploit PoC, and steps to reproduce.*

## Features

- **Contextual reflection engine** — a Reflector-style (elkokc/reflector) probe
  that injects a unique canary interleaved with every break-out character, then
  measures *exactly* which characters survive unencoded at each reflection point
  and classifies the context with a real HTML/JS tokenizer
- **Two-stage live confirmation (near-zero false positives)** — a candidate is
  only reported after its context-specific proof-of-concept is injected for real
  and observed reflected **verbatim and unescaped** in the response; anything the
  application encodes, escapes, or a keyword/tag WAF blocks is suppressed
- **Full context coverage** — HTML text, HTML comments, tag/attribute-name
  positions, single/double/unquoted attribute values, URL attributes
  (`javascript:` scheme), `on*` event handlers, inline `<script>` blocks,
  JavaScript single/double/template strings, `<style>`/CSS, and rawtext/RCDATA
  elements (`textarea`, `title`, `iframe`, `xmp`, …) where only the matching end
  tag can break out — so inert reflections are never misreported
- **JSON & JSONP aware** — handles modern API responses that Reflector does not:
  JSONP callback execution, JSON bodies rendered as HTML via wrong/sniffable
  `Content-Type`, while correctly treating strict `application/json` +
  `X-Content-Type-Options: nosniff` as non-exploitable
- **Dynamic, evidence-only reports** — each finding shows live data only: the
  reflection context, a per-character break-out table, the confirmed PoC, and the
  live reflected snippet (no boilerplate background or remediation text)
- **DOM XSS detection** — client-side source-to-sink data-flow analysis
- **Client-side checks** — postMessage, WebSocket, and template-injection patterns
- **Modern framework awareness** — React, Angular, Vue.js, GraphQL, WebSockets
- **WAF/filter bypass** — Unicode, Base64, and URL encoding plus mutation variants
- **Detailed HTML reports** — payload, context, exploit PoC, steps to reproduce, remediation
- **Confidence scoring** — configurable reporting threshold and duplicate filtering
- **Burp integration** — passive scanner, active scanner, and real-time proxy analysis

## Requirements

- Java 11 or higher (the JAR is compiled for Java 11 compatibility)
- Burp Suite Professional 2023.1 or higher

## Installation

A prebuilt `dist/XSSDetector.jar` is included. To build from source:

```bash
./build.sh    # Linux/macOS
build.bat     # Windows
```

Then in Burp: **Extender → Extensions → Add → Java**, select `dist/XSSDetector.jar`.
Confirm the **XSSDetector** tab appears and that there are no errors in
**Extender → Output**.

## Usage

1. Set your target in Burp's scope (optionally enable **Scope only**).
2. In the **XSSDetector** tab, enable the checks you need — Modern Detection,
   DOM XSS, active/aggressive scanning, and encoding options.
3. Browse the target or run Burp's scanner. Findings appear in the **Issues** tab,
   and in real time as you proxy traffic.

## Detection Scope

| Type | Method |
|------|--------|
| Reflected XSS | Contextual probe (canary + break-out characters) with per-context exploitability analysis |
| JSON / JSONP XSS | JSONP callback execution, JSON-rendered-as-HTML, and JSON string break-out (MIME/nosniff aware) |
| DOM XSS | Source-to-sink data-flow analysis |
| Stored XSS | Response pattern analysis on persisted input |
| Template Injection | Client-side template/expression pattern detection |
| WAF/Filter Bypass | Encoding and mutation technique variants |

### How the contextual engine works

Detection is a two-request, double-confirmed process per insertion point:

**Stage 1 — Measure.** The engine sends one probe of the form
`CANARY c0 CANARY c1 CANARY … CANARY`, where each `c` is a break-out character
(`< > " ' ` + `` ` `` + ` ( ) { } ; / \ = :` space `$`). Because the canary is pure
`[a-z]` it passes through every output encoder unchanged, so splitting the
reflected block on the canary reveals precisely how the application transformed
each character (verbatim, HTML-entity-encoded, backslash-escaped, URL-encoded,
or stripped). A forward HTML/JS tokenizer — which models rawtext/RCDATA elements,
quoted/unquoted attributes, URL attributes, event handlers and JS
string/template literals — fixes the exact reflection context. Exploitability is
decided from the context plus the surviving characters (e.g. a double-quoted
attribute only when `"` survives unescaped; an inline script string only when its
delimiter survives unescaped or `</script>` can terminate the element).

**Stage 2 — Confirm.** The context-specific proof-of-concept is injected for real
and the response is checked for it reflected **verbatim and unescaped**. Only then
is an issue raised. This catches keyword/tag WAFs that pass single characters but
block whole payloads, and drives the false-positive rate to near zero. Each
finding reports only this live evidence — context, per-character break-out table,
confirmed PoC, and the highlighted reflection — with no remediation boilerplate.

> Findings carry a confidence score and are gated behind a configurable threshold
> to reduce false positives. As with any heuristic scanner, validate findings
> before disclosure.

## Building from Source

Requires a Java 11+ JDK. Run `./build.sh` (or `build.bat`); the output is
`dist/XSSDetector.jar`. A GitHub Actions workflow also builds the JAR on
Ubuntu/Windows/macOS with Java 11 and 17.

## Contributing

Issues and pull requests are welcome. There is no automated test suite yet —
validate changes manually against deliberately vulnerable apps such as the
PortSwigger Web Security Academy labs, OWASP Juice Shop, or DVWA.

## Security

See [SECURITY.md](SECURITY.md) for how to report a vulnerability.

## License

MIT — see [LICENSE](LICENSE).

## Contact

- **Email**: [infoseclab005@gmail.com](mailto:infoseclab005@gmail.com)
- **GitHub**: [@infosec-lab](https://github.com/infosec-lab)
