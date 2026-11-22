// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 EON contributors
//
// Additional permission under GNU GPL version 3 section 7:
// see LICENSE-EXCEPTION.md (EON Module ABI Exception 1.0).

//! Checksums of files, as 7-Zip's "CRC SHA" menu gives them, in one pass over
//! each file for every algorithm asked for.

use crate::{Cancel, OnProgress, Progress, Result};
use serde::{Deserialize, Serialize};
use sha1::Digest as _;
use std::io::Read;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Algorithm {
    Crc32,
    Md5,
    Sha1,
    Sha256,
    Sha512,
    Blake3,
    Xxh64,
}

impl Algorithm {
    pub const ALL: [Algorithm; 7] = [
        Algorithm::Crc32,
        Algorithm::Md5,
        Algorithm::Sha1,
        Algorithm::Sha256,
        Algorithm::Sha512,
        Algorithm::Blake3,
        Algorithm::Xxh64,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Algorithm::Crc32 => "CRC-32",
            Algorithm::Md5 => "MD5",
            Algorithm::Sha1 => "SHA-1",
            Algorithm::Sha256 => "SHA-256",
            Algorithm::Sha512 => "SHA-512",
            Algorithm::Blake3 => "BLAKE3",
            Algorithm::Xxh64 => "XXH64",
        }
    }
}

enum State {
    Crc32(crc32fast::Hasher),
    Md5(md5::Md5),
    Sha1(sha1::Sha1),
    Sha256(sha2::Sha256),
    Sha512(sha2::Sha512),
    Blake3(Box<blake3::Hasher>),
    Xxh64(xxhash_rust::xxh64::Xxh64),
}

impl State {
    fn new(a: Algorithm) -> Self {
        match a {
            Algorithm::Crc32 => State::Crc32(crc32fast::Hasher::new()),
            Algorithm::Md5 => State::Md5(md5::Md5::new()),
            Algorithm::Sha1 => State::Sha1(sha1::Sha1::new()),
            Algorithm::Sha256 => State::Sha256(sha2::Sha256::new()),
            Algorithm::Sha512 => State::Sha512(sha2::Sha512::new()),
            Algorithm::Blake3 => State::Blake3(Box::new(blake3::Hasher::new())),
            Algorithm::Xxh64 => State::Xxh64(xxhash_rust::xxh64::Xxh64::new(0)),
        }
    }

    fn update(&mut self, b: &[u8]) {
        match self {
            State::Crc32(h) => h.update(b),
            State::Md5(h) => h.update(b),
            State::Sha1(h) => h.update(b),
            State::Sha256(h) => h.update(b),
            State::Sha512(h) => h.update(b),
            State::Blake3(h) => {
                h.update(b);
            }
            State::Xxh64(h) => h.update(b),
        }
    }

    fn finish(self) -> String {
        match self {
            State::Crc32(h) => format!("{:08X}", h.finalize()),
            State::Md5(h) => hex(&h.finalize()),
            State::Sha1(h) => hex(&h.finalize()),
            State::Sha256(h) => hex(&h.finalize()),
            State::Sha512(h) => hex(&h.finalize()),
            State::Blake3(h) => h.finalize().to_hex().to_string(),
            State::Xxh64(h) => format!("{:016X}", h.digest()),
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// One file's checksums, in the order asked.
#[derive(Debug, Clone, Serialize)]
pub struct Line {
    pub path: PathBuf,
    pub size: u64,
    pub sums: Vec<(Algorithm, String)>,
}

/// Every file under `paths` (folders are walked, sorted), hashed.
pub fn files(
    paths: &[PathBuf],
    algorithms: &[Algorithm],
    progress: OnProgress<'_>,
    cancel: &Cancel,
) -> Result<Vec<Line>> {
    let mut list = Vec::new();
    for p in paths {
        walk(p, &mut list)?;
    }
    let total: u64 = list.iter().map(|(_, s)| s).sum();
    let mut done = 0u64;
    let mut out = Vec::new();
    let mut buf = vec![0u8; 1 << 20];
    for (path, size) in list {
        let mut states: Vec<State> = algorithms.iter().map(|a| State::new(*a)).collect();
        let mut f = std::fs::File::open(&path)?;
        loop {
            cancel.check()?;
            let n = f.read(&mut buf)?;
            if n == 0 {
                break;
            }
            for s in &mut states {
                s.update(&buf[..n]);
            }
            done += n as u64;
            progress(&Progress {
                done,
                total,
                name: path.to_string_lossy().into_owned(),
            });
        }
        let sums = algorithms
            .iter()
            .zip(states)
            .map(|(a, s)| (*a, s.finish()))
            .collect();
        out.push(Line { path, size, sums });
    }
    Ok(out)
}

fn walk(p: &Path, out: &mut Vec<(PathBuf, u64)>) -> Result<()> {
    let meta = std::fs::symlink_metadata(p)?;
    if meta.is_dir() {
        let mut children: Vec<PathBuf> =
            std::fs::read_dir(p)?.flatten().map(|e| e.path()).collect();
        children.sort();
        for c in children {
            walk(&c, out)?;
        }
    } else if meta.is_file() {
        out.push((p.to_path_buf(), meta.len()));
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn known_answers() {
        let dir = std::env::temp_dir().join(format!("eon-zip-hash-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("abc.txt");
        std::fs::write(&f, b"abc").unwrap();
        let lines = files(&[f], &Algorithm::ALL, &|_| {}, &Cancel::default()).unwrap();
        let sums: Vec<&str> = lines[0].sums.iter().map(|(_, s)| s.as_str()).collect();
        assert_eq!(sums[0], "352441C2");
        assert_eq!(sums[1], "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(sums[2], "a9993e364706816aba3e25717850c26c9cd0d89d");
        assert_eq!(
            sums[3],
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert!(sums[4].starts_with("ddaf35a193617aba"));
        assert_eq!(
            sums[5],
            "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85"
        );
        assert_eq!(sums[6], "44BC2CF5AD770999");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
