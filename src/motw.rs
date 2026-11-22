// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 EON contributors
//
// Additional permission under GNU GPL version 3 section 7:
// see LICENSE-EXCEPTION.md (EON Module ABI Exception 1.0).

//! Windows' "this came from the internet" mark (the `Zone.Identifier` stream).
//!
//! A file downloaded by a browser carries it; Windows uses it to warn before a
//! program from the internet runs and to open Office files read-only. An
//! archiver that drops it on extraction removes that warning — 7-Zip's
//! CVE-2025-0411 did exactly that through nested archives. EON Zip copies the
//! mark from the archive to everything it writes, always.

use std::path::Path;

/// The mark of `archive`, if it has one (Windows only; elsewhere `None`).
pub fn read(archive: &Path) -> Option<Vec<u8>> {
    if !cfg!(windows) {
        return None;
    }
    let stream = format!("{}:Zone.Identifier", archive.display());
    std::fs::read(stream).ok().filter(|b| !b.is_empty())
}

/// Give `file` the same mark.
pub fn write(file: &Path, mark: &[u8]) {
    if cfg!(windows) {
        let stream = format!("{}:Zone.Identifier", file.display());
        let _ = std::fs::write(stream, mark);
    }
}
