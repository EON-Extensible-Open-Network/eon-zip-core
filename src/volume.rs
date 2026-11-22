// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 EON contributors
//
// Additional permission under GNU GPL version 3 section 7:
// see LICENSE-EXCEPTION.md (EON Module ABI Exception 1.0).

//! Volumes: an archive cut into `name.7z.001`, `name.7z.002`... as 7-Zip and
//! WinRAR cut them, read back as one file without joining them on disk.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

/// All the parts of the archive `path` belongs to, in order. A file that is not
/// a numbered part is its own only part.
pub fn parts_of(path: &Path) -> Vec<PathBuf> {
    let Some(name) = path.file_name().map(|n| n.to_string_lossy().into_owned()) else {
        return vec![path.to_path_buf()];
    };
    let Some((stem, number)) = name.rsplit_once('.') else {
        return vec![path.to_path_buf()];
    };
    if number.len() < 3 || !number.bytes().all(|b| b.is_ascii_digit()) {
        return vec![path.to_path_buf()];
    }
    let width = number.len();
    let mut parts = Vec::new();
    for i in 1.. {
        let p = path.with_file_name(format!("{stem}.{i:0width$}"));
        if !p.is_file() {
            break;
        }
        parts.push(p);
    }
    if parts.is_empty() {
        vec![path.to_path_buf()]
    } else {
        parts
    }
}

/// The name an archive of parts has as one file (`x.7z.001` → `x.7z`).
pub fn joined_name(path: &Path) -> String {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    match name.rsplit_once('.') {
        Some((stem, n)) if n.len() >= 3 && n.bytes().all(|b| b.is_ascii_digit()) => stem.to_owned(),
        _ => name,
    }
}

/// Several files read as one.
pub struct MultiReader {
    files: Vec<(File, u64)>,
    total: u64,
    pos: u64,
}

impl MultiReader {
    pub fn open(parts: &[PathBuf]) -> io::Result<Self> {
        let mut files = Vec::with_capacity(parts.len());
        let mut total = 0;
        for p in parts {
            let f = File::open(p)?;
            let len = f.metadata()?.len();
            total += len;
            files.push((f, len));
        }
        Ok(MultiReader {
            files,
            total,
            pos: 0,
        })
    }

    pub fn len(&self) -> u64 {
        self.total
    }

    pub fn is_empty(&self) -> bool {
        self.total == 0
    }
}

impl Read for MultiReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut start = 0u64;
        for (f, len) in &mut self.files {
            if self.pos < start + *len {
                let within = self.pos - start;
                f.seek(SeekFrom::Start(within))?;
                let room = (*len - within).min(buf.len() as u64) as usize;
                let n = f.read(&mut buf[..room])?;
                self.pos += n as u64;
                return Ok(n);
            }
            start += *len;
        }
        Ok(0)
    }
}

impl Seek for MultiReader {
    fn seek(&mut self, to: SeekFrom) -> io::Result<u64> {
        let next = match to {
            SeekFrom::Start(n) => i128::from(n),
            SeekFrom::End(d) => i128::from(self.total) + i128::from(d),
            SeekFrom::Current(d) => i128::from(self.pos) + i128::from(d),
        };
        if next < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "seek before the start",
            ));
        }
        self.pos = u64::try_from(next).unwrap_or(u64::MAX);
        Ok(self.pos)
    }
}

/// Cut `path` into parts of `size` bytes named `path.001`, `path.002`...; the
/// original is removed once every part is written. Returns the parts.
pub fn split(path: &Path, size: u64) -> io::Result<Vec<PathBuf>> {
    let total = std::fs::metadata(path)?.len();
    if size == 0 || total <= size {
        return Ok(vec![path.to_path_buf()]);
    }
    let mut src = File::open(path)?;
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let mut parts = Vec::new();
    let mut i = 1;
    loop {
        let part = path.with_file_name(format!("{name}.{i:03}"));
        let mut out = File::create(&part)?;
        let n = io::copy(&mut (&mut src).take(size), &mut out)?;
        if n == 0 {
            drop(out);
            std::fs::remove_file(&part)?;
            break;
        }
        parts.push(part);
        i += 1;
    }
    drop(src);
    std::fs::remove_file(path)?;
    Ok(parts)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn parts_read_back_as_one() {
        let dir = std::env::temp_dir().join(format!("eon-zip-vol-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let whole = dir.join("x.7z");
        let data: Vec<u8> = (0..10_000u32).map(|i| (i % 251) as u8).collect();
        std::fs::write(&whole, &data).unwrap();
        let parts = split(&whole, 3000).unwrap();
        assert_eq!(parts.len(), 4);
        assert!(!whole.exists());
        assert_eq!(parts_of(&parts[2]), parts);
        assert_eq!(joined_name(&parts[0]), "x.7z");
        let mut r = MultiReader::open(&parts).unwrap();
        let mut back = Vec::new();
        r.read_to_end(&mut back).unwrap();
        assert_eq!(back, data);
        r.seek(SeekFrom::Start(2990)).unwrap();
        let mut b = [0u8; 20];
        r.read_exact(&mut b).unwrap();
        assert_eq!(&b[..], &data[2990..3010]);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
