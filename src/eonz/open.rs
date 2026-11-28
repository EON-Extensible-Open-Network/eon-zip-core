// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 EON contributors

//! Reading a `.eonz`. Nothing is decompressed until a file is read; each block's stored
//! bytes are checked against their BLAKE3 before use, each chunk and each whole file
//! against theirs after.

use std::cell::RefCell;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use super::{
    u64_at, unhex32, unseal, Header, Index, IndexEntry, Kind, Trailer, HEADER_LEN, INDEX_NUMBER,
    TRAILER_LEN,
};
use crate::{Error, Result};

/// One entry, as the rest of EON Zip sees it.
#[derive(Debug, Clone)]
pub struct EonzEntry {
    pub path: String,
    pub kind: Kind,
    pub size: u64,
    /// Nanoseconds since 1970.
    pub mtime: Option<u64>,
    pub mode: Option<u32>,
    pub target: Option<String>,
}

/// An opened `.eonz`.
pub struct Eonz {
    pub path: PathBuf,
    header: Header,
    index: Index,
    key: Option<[u8; 32]>,
    file: RefCell<File>,
    /// The last block read, by number.
    cache: RefCell<Option<(u32, std::rc::Rc<Vec<u8>>)>>,
}

const DAMAGED: &str = "the archive is damaged; if it carries recovery data, EON Zip can repair it";

fn read_at(f: &mut File, at: u64, len: usize) -> io::Result<Vec<u8>> {
    f.seek(SeekFrom::Start(at))?;
    let mut b = vec![0u8; len];
    f.read_exact(&mut b)?;
    Ok(b)
}

/// The header, or the offsets from the trailer when the header is damaged.
pub(crate) fn locate(f: &mut File) -> Result<Header> {
    let len = f.metadata().map_err(Error::from)?.len();
    if len < HEADER_LEN + TRAILER_LEN {
        return Err(Error::Format("too short to be a .eonz archive".into()));
    }
    let head = read_at(f, 0, HEADER_LEN as usize).map_err(Error::from)?;
    if let Some(h) = Header::decode(&head)? {
        return Ok(h);
    }
    let tail = read_at(f, len - TRAILER_LEN, TRAILER_LEN as usize).map_err(Error::from)?;
    match Trailer::decode(&tail) {
        // The header's other fields (encryption) are lost with it: reading needs a repair.
        Some(_) => Err(Error::Damaged(format!("its header is damaged; {DAMAGED}"))),
        None => Err(Error::Damaged(DAMAGED.into())),
    }
}

impl Eonz {
    pub fn open(path: &Path, password: Option<&str>) -> Result<Eonz> {
        let mut f = File::open(path).map_err(Error::from)?;
        let header = locate(&mut f)?;
        let len = f.metadata().map_err(Error::from)?.len();
        if header.index_len < 8 + 32 || header.index_at.saturating_add(header.index_len) > len {
            return Err(Error::Damaged(DAMAGED.into()));
        }
        let raw = read_at(
            &mut f,
            header.index_at,
            usize::try_from(header.index_len)
                .map_err(|_| Error::Format("index too large".into()))?,
        )
        .map_err(Error::from)?;
        let stored_len = u64_at(&raw, 0);
        if stored_len + 8 + 32 != header.index_len {
            return Err(Error::Damaged(DAMAGED.into()));
        }
        let stored = &raw[8..raw.len() - 32];
        if blake3::hash(stored).as_bytes()[..] != raw[raw.len() - 32..] {
            return Err(Error::Damaged(format!("its index is damaged; {DAMAGED}")));
        }
        let key = if header.encrypted() {
            let p = password
                .filter(|p| !p.is_empty())
                .ok_or(Error::PasswordNeeded)?;
            Some(super::derive_key(p, &header)?)
        } else {
            None
        };
        let json = unseal(stored, None, key.as_ref(), INDEX_NUMBER)?;
        let index: Index = serde_json::from_slice(&json)
            .map_err(|e| Error::Format(format!("its index cannot be read: {e}")))?;
        check(&index, header.index_at)?;
        Ok(Eonz {
            path: path.to_path_buf(),
            header,
            index,
            key,
            file: RefCell::new(f),
            cache: RefCell::new(None),
        })
    }

    pub fn encrypted(&self) -> bool {
        self.header.encrypted()
    }

    pub fn has_recovery(&self) -> bool {
        self.header.recovery_len > 0
    }

    pub fn comment(&self) -> Option<&str> {
        self.index.comment.as_deref()
    }

    pub fn entries(&self) -> Vec<EonzEntry> {
        self.index
            .entries
            .iter()
            .map(|e| EonzEntry {
                path: e.path.clone(),
                kind: e.kind.clone(),
                size: e.size,
                mtime: e.mtime,
                mode: e.mode,
                target: e.target.clone(),
            })
            .collect()
    }

    /// Plain bytes held in blocks, and what they took on disk: the compression ratio.
    pub fn packed(&self) -> (u64, u64) {
        self.index
            .blocks
            .iter()
            .fold((0, 0), |(p, s), b| (p + b.plain, s + b.stored))
    }

    /// One block's plain bytes, checked.
    fn block(&self, n: u32) -> Result<std::rc::Rc<Vec<u8>>> {
        if let Some((m, data)) = self.cache.borrow().as_ref() {
            if *m == n {
                return Ok(data.clone());
            }
        }
        let b = self
            .index
            .blocks
            .get(n as usize)
            .ok_or_else(|| Error::Damaged(DAMAGED.into()))?;
        let total = usize::try_from(b.stored + 8 + 32)
            .map_err(|_| Error::Damaged("a block is too large".into()))?;
        let raw = read_at(&mut self.file.borrow_mut(), b.offset, total)
            .map_err(|e| Error::Damaged(format!("{e}; {DAMAGED}")))?;
        let stored = &raw[8..raw.len() - 32];
        let want = unhex32(&b.hash).ok_or_else(|| Error::Damaged(DAMAGED.into()))?;
        if u64_at(&raw, 0) != b.stored
            || blake3::hash(stored).as_bytes() != &want
            || raw[raw.len() - 32..] != want
        {
            return Err(Error::Damaged(DAMAGED.into()));
        }
        let plain = std::rc::Rc::new(unseal(
            stored,
            Some(b.plain),
            self.key.as_ref(),
            u64::from(n),
        )?);
        *self.cache.borrow_mut() = Some((n, plain.clone()));
        Ok(plain)
    }

    /// A reader of entry `i`'s bytes: each chunk is checked as it is read, the whole
    /// file at the end.
    pub fn reader(&self, i: usize) -> Result<EntryReader<'_>> {
        let e = self
            .index
            .entries
            .get(i)
            .ok_or_else(|| Error::Format("no such entry".into()))?;
        Ok(EntryReader {
            archive: self,
            entry: e,
            next: 0,
            current: Vec::new(),
            at: 0,
            whole: blake3::Hasher::new(),
            checked: false,
        })
    }

    /// Check every block's stored bytes, without the password. `false` if any is damaged.
    pub fn blocks_intact(&self) -> Result<bool> {
        let mut f = self.file.borrow_mut();
        for b in &self.index.blocks {
            let total = usize::try_from(b.stored + 8 + 32).unwrap_or(usize::MAX);
            let Ok(raw) = read_at(&mut f, b.offset, total) else {
                return Ok(false);
            };
            let want = unhex32(&b.hash);
            if want.is_none_or(|w| blake3::hash(&raw[8..raw.len() - 32]).as_bytes() != &w) {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

/// Everything the index points at must be inside the file and consistent, before any of
/// it is trusted.
fn check(index: &Index, index_at: u64) -> Result<()> {
    let bad = |what: &str| {
        Err(Error::Damaged(format!(
            "its index is inconsistent ({what})"
        )))
    };
    for b in &index.blocks {
        if b.offset < HEADER_LEN
            || b.offset.saturating_add(b.stored + 8 + 32) > index_at
            || unhex32(&b.hash).is_none()
        {
            return bad("a block lies outside the data");
        }
    }
    for c in &index.chunks {
        let Some(b) = index.blocks.get(c.block as usize) else {
            return bad("a chunk names no block");
        };
        if c.at.saturating_add(c.len) > b.plain || unhex32(&c.hash).is_none() {
            return bad("a chunk lies outside its block");
        }
    }
    for e in &index.entries {
        let mut size = 0u64;
        for id in &e.chunks {
            let Some(c) = index.chunks.get(*id as usize) else {
                return bad("a file names no chunk");
            };
            size = size.saturating_add(c.len);
        }
        if e.kind == Kind::File && size != e.size {
            return bad("a file's chunks do not add up to its size");
        }
    }
    Ok(())
}

/// The bytes of one file, chunk by chunk.
pub struct EntryReader<'a> {
    archive: &'a Eonz,
    entry: &'a IndexEntry,
    next: usize,
    current: Vec<u8>,
    at: usize,
    whole: blake3::Hasher,
    checked: bool,
}

impl Read for EntryReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        while self.at >= self.current.len() {
            let Some(id) = self.entry.chunks.get(self.next) else {
                if !self.checked {
                    self.checked = true;
                    let want = self.entry.hash.as_deref().and_then(unhex32);
                    if want.is_some_and(|w| self.whole.finalize().as_bytes() != &w) {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "the file does not match its checksum",
                        ));
                    }
                }
                return Ok(0);
            };
            self.next += 1;
            let c = self
                .archive
                .index
                .chunks
                .get(*id as usize)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no such chunk"))?;
            let block = self
                .archive
                .block(c.block)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
            let (a, n) = (c.at as usize, c.len as usize);
            let data = &block[a..a + n];
            if unhex32(&c.hash).is_none_or(|w| blake3::hash(data).as_bytes() != &w) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "a chunk does not match its checksum",
                ));
            }
            self.whole.update(data);
            self.current.clear();
            self.current.extend_from_slice(data);
            self.at = 0;
        }
        let n = buf.len().min(self.current.len() - self.at);
        buf[..n].copy_from_slice(&self.current[self.at..self.at + n]);
        self.at += n;
        Ok(n)
    }
}
