// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 EON contributors
//
// Additional permission under GNU GPL version 3 section 7:
// see LICENSE-EXCEPTION.md (EON Module ABI Exception 1.0).

//! What an archive is, told by its first bytes before its name.

use serde::{Deserialize, Serialize};
use std::io::Read;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Format {
    Zip,
    SevenZ,
    Tar,
    TarGz,
    TarBz2,
    TarXz,
    TarZst,
    Gz,
    Bz2,
    Xz,
    Zst,
    /// Recognised; read through 7-Zip in a later version (parity.md).
    Rar,
    Iso,
    Cab,
}

impl Format {
    /// The extension a new archive of this format gets.
    pub fn extension(self) -> &'static str {
        match self {
            Format::Zip => "zip",
            Format::SevenZ => "7z",
            Format::Tar => "tar",
            Format::TarGz => "tar.gz",
            Format::TarBz2 => "tar.bz2",
            Format::TarXz => "tar.xz",
            Format::TarZst => "tar.zst",
            Format::Gz => "gz",
            Format::Bz2 => "bz2",
            Format::Xz => "xz",
            Format::Zst => "zst",
            Format::Rar => "rar",
            Format::Iso => "iso",
            Format::Cab => "cab",
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Format::Zip => "ZIP",
            Format::SevenZ => "7z",
            Format::Tar => "TAR",
            Format::TarGz => "TAR.GZ",
            Format::TarBz2 => "TAR.BZ2",
            Format::TarXz => "TAR.XZ",
            Format::TarZst => "TAR.ZST",
            Format::Gz => "GZIP",
            Format::Bz2 => "BZIP2",
            Format::Xz => "XZ",
            Format::Zst => "Zstandard",
            Format::Rar => "RAR",
            Format::Iso => "ISO",
            Format::Cab => "CAB",
        }
    }

    /// Formats EON Zip creates.
    pub fn creatable(self) -> bool {
        !matches!(self, Format::Rar | Format::Iso | Format::Cab)
    }

    /// A single compressed file rather than a set of entries.
    pub fn single(self) -> bool {
        matches!(self, Format::Gz | Format::Bz2 | Format::Xz | Format::Zst)
    }

    /// By extension, for choosing what to create.
    pub fn from_extension(name: &str) -> Option<Format> {
        let n = name.to_ascii_lowercase();
        let ends = |s: &str| n.ends_with(s);
        Some(if ends(".tar.gz") || ends(".tgz") {
            Format::TarGz
        } else if ends(".tar.bz2") || ends(".tbz2") || ends(".tbz") {
            Format::TarBz2
        } else if ends(".tar.xz") || ends(".txz") {
            Format::TarXz
        } else if ends(".tar.zst") || ends(".tzst") {
            Format::TarZst
        } else if ends(".zip") {
            Format::Zip
        } else if ends(".7z") {
            Format::SevenZ
        } else if ends(".tar") {
            Format::Tar
        } else if ends(".gz") {
            Format::Gz
        } else if ends(".bz2") {
            Format::Bz2
        } else if ends(".xz") {
            Format::Xz
        } else if ends(".zst") {
            Format::Zst
        } else if ends(".rar") {
            Format::Rar
        } else if ends(".iso") {
            Format::Iso
        } else if ends(".cab") {
            Format::Cab
        } else {
            return None;
        })
    }
}

/// The format of the bytes at `head` (the file's first 64 KiB is plenty), with
/// the name used only where the content cannot tell (a gzip holding a tar).
pub fn detect(head: &[u8], name: &str) -> Option<Format> {
    let starts = |sig: &[u8]| head.starts_with(sig);
    let by_name = Format::from_extension(name);
    let compressed_tar = |tar: Format, single: Format| {
        if matches!(by_name, Some(f) if f == tar) {
            tar
        } else {
            single
        }
    };
    if starts(b"PK\x03\x04") || starts(b"PK\x05\x06") || starts(b"PK\x07\x08") {
        Some(Format::Zip)
    } else if starts(&[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]) {
        Some(Format::SevenZ)
    } else if starts(b"Rar!\x1a\x07") {
        Some(Format::Rar)
    } else if starts(b"MSCF") {
        Some(Format::Cab)
    } else if starts(&[0x1F, 0x8B]) {
        Some(compressed_tar(Format::TarGz, Format::Gz))
    } else if starts(b"BZh") {
        Some(compressed_tar(Format::TarBz2, Format::Bz2))
    } else if starts(&[0xFD, b'7', b'z', b'X', b'Z', 0]) {
        Some(compressed_tar(Format::TarXz, Format::Xz))
    } else if starts(&[0x28, 0xB5, 0x2F, 0xFD]) {
        Some(compressed_tar(Format::TarZst, Format::Zst))
    } else if head.len() >= 262 && &head[257..262] == b"ustar" {
        Some(Format::Tar)
    } else if head.len() >= 0x8006 && &head[0x8001..0x8006] == b"CD001" {
        Some(Format::Iso)
    } else if matches!(by_name, Some(Format::Tar)) && head.len() >= 512 {
        // Old (v7) tar has no magic; trust the name when the header checksum agrees.
        tar_checksum_ok(&head[..512]).then_some(Format::Tar)
    } else {
        None
    }
}

fn tar_checksum_ok(h: &[u8]) -> bool {
    let stored = std::str::from_utf8(&h[148..156])
        .ok()
        .map(|s| s.trim_matches(|c: char| c == '\0' || c == ' '))
        .and_then(|s| u32::from_str_radix(s, 8).ok());
    let sum: u32 = h
        .iter()
        .enumerate()
        .map(|(i, b)| {
            if (148..156).contains(&i) {
                32
            } else {
                u32::from(*b)
            }
        })
        .sum();
    stored == Some(sum)
}

/// Read a file's first bytes.
pub fn head(path: &Path) -> std::io::Result<Vec<u8>> {
    let mut buf = vec![0u8; 64 * 1024];
    let mut f = std::fs::File::open(path)?;
    let mut n = 0;
    while n < buf.len() {
        let got = f.read(&mut buf[n..])?;
        if got == 0 {
            break;
        }
        n += got;
    }
    buf.truncate(n);
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_first_name_for_the_tar_inside() {
        assert_eq!(detect(b"PK\x03\x04....", "x.bin"), Some(Format::Zip));
        assert_eq!(
            detect(&[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C, 0, 4], "a.zip"),
            Some(Format::SevenZ)
        );
        assert_eq!(detect(&[0x1F, 0x8B, 8, 0], "a.tar.gz"), Some(Format::TarGz));
        assert_eq!(detect(&[0x1F, 0x8B, 8, 0], "a.tgz"), Some(Format::TarGz));
        assert_eq!(
            detect(&[0x1F, 0x8B, 8, 0], "notes.txt.gz"),
            Some(Format::Gz)
        );
        assert_eq!(detect(b"Rar!\x1a\x07\x01\x00", "x.rar"), Some(Format::Rar));
        assert_eq!(detect(b"hello", "x.zip"), None);
    }
}
