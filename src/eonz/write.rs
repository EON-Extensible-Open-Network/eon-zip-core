// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 EON contributors

//! Writing a `.eonz`: files are cut into content-defined chunks, a chunk seen before is
//! referenced rather than stored again, new chunks fill solid blocks, and blocks are
//! compressed (and encrypted) on every core, then written in order.

use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::time::UNIX_EPOCH;

use super::{
    cdc, hex, seal, BlockRef, ChunkRef, Codec, Header, Index, IndexEntry, Kind, Trailer,
    ARGON2_LANES, ARGON2_MEMORY_KIB, ARGON2_PASSES, FLAG_ENCRYPTED, FLAG_RECOVERY, HEADER_LEN,
    INDEX_NUMBER,
};
use crate::create::{Settings, Source};
use crate::{Cancel, Counting, Error, Level, OnProgress, Result};

/// Codec, block size and how many blocks are compressed at once, by level. Bigger blocks
/// and windows find more repetition and need more memory (shown in the window).
fn plan(level: Level, threads: u32) -> (Codec, usize, usize) {
    let (zstd, block_mib, window, cap) = match level {
        Level::Store => (-5, 4, None, 64),
        Level::Fastest => (1, 4, None, 64),
        Level::Fast => (3, 8, None, 64),
        Level::Normal => (9, 16, Some(24), 16),
        Level::Maximum => (17, 32, Some(25), 4),
        Level::Ultra => (19, 64, Some(26), 2),
    };
    let workers = (threads as usize).clamp(1, cap);
    (
        Codec {
            level: zstd,
            window_log: window,
        },
        block_mib * 1024 * 1024,
        workers,
    )
}

struct Writer<'a> {
    file: File,
    pos: u64,
    codec: Codec,
    key: Option<[u8; 32]>,
    workers: usize,
    block_size: usize,
    index: Index,
    seen: HashMap<[u8; 32], u32>,
    /// Blocks filled but not yet compressed, and the one being filled.
    pending: Vec<Vec<u8>>,
    current: Vec<u8>,
    cancel: &'a Cancel,
}

impl Writer<'_> {
    fn put(&mut self, bytes: &[u8]) -> Result<()> {
        self.file.write_all(bytes).map_err(Error::from)?;
        self.pos += bytes.len() as u64;
        Ok(())
    }

    /// The number the next block will get.
    fn next_block(&self) -> u32 {
        (self.index.blocks.len() + self.pending.len()) as u32
    }

    /// One chunk of a file: its id, stored now if it is new.
    fn chunk(&mut self, data: &[u8]) -> Result<u32> {
        let hash = *blake3::hash(data).as_bytes();
        if let Some(id) = self.seen.get(&hash) {
            return Ok(*id);
        }
        let id = self.index.chunks.len() as u32;
        self.index.chunks.push(ChunkRef {
            block: self.next_block(),
            at: self.current.len() as u64,
            len: data.len() as u64,
            hash: hex(&hash),
        });
        self.seen.insert(hash, id);
        self.current.extend_from_slice(data);
        if self.current.len() >= self.block_size {
            self.pending.push(std::mem::take(&mut self.current));
            if self.pending.len() >= self.workers {
                self.flush()?;
            }
        }
        Ok(id)
    }

    /// Compress the pending blocks side by side, then write them in order.
    fn flush(&mut self) -> Result<()> {
        if self.pending.is_empty() {
            return Ok(());
        }
        self.cancel.check().map_err(Error::from)?;
        let first = self.index.blocks.len() as u64;
        let blocks = std::mem::take(&mut self.pending);
        let (codec, key) = (self.codec, self.key);
        let sealed: Vec<Result<Vec<u8>>> = std::thread::scope(|s| {
            let handles: Vec<_> = blocks
                .iter()
                .enumerate()
                .map(|(i, b)| s.spawn(move || seal(b, codec, key.as_ref(), first + i as u64)))
                .collect();
            handles
                .into_iter()
                .map(|h| {
                    h.join()
                        .unwrap_or_else(|_| Err(Error::Io("a compression thread stopped".into())))
                })
                .collect()
        });
        for (plain, stored) in blocks.iter().zip(sealed) {
            let stored = stored?;
            let offset = self.pos;
            let hash = *blake3::hash(&stored).as_bytes();
            self.put(&(stored.len() as u64).to_le_bytes())?;
            self.put(&stored)?;
            self.put(&hash)?;
            self.index.blocks.push(BlockRef {
                offset,
                stored: stored.len() as u64,
                plain: plain.len() as u64,
                hash: hex(&hash),
            });
        }
        Ok(())
    }
}

fn nanos(t: Option<std::time::SystemTime>) -> Option<u64> {
    t.and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .and_then(|d| u64::try_from(d.as_nanos()).ok())
}

#[cfg(unix)]
fn mode_of(m: &std::fs::Metadata) -> (Option<u32>, Option<u32>) {
    use std::os::unix::fs::PermissionsExt;
    (Some(m.permissions().mode() & 0o7777), None)
}

#[cfg(windows)]
fn mode_of(m: &std::fs::Metadata) -> (Option<u32>, Option<u32>) {
    use std::os::windows::fs::MetadataExt;
    (None, Some(m.file_attributes()))
}

#[cfg(not(any(unix, windows)))]
fn mode_of(_m: &std::fs::Metadata) -> (Option<u32>, Option<u32>) {
    (None, None)
}

fn random<const N: usize>() -> Result<[u8; N]> {
    let mut b = [0u8; N];
    getrandom::fill(&mut b)
        .map_err(|e| Error::Io(format!("no randomness from the system: {e}")))?;
    Ok(b)
}

/// Write `items` as a `.eonz` into `file`, which must be readable too (the recovery data
/// is computed from what was written).
#[allow(clippy::too_many_arguments)]
pub(crate) fn write(
    file: File,
    items: &[Source],
    s: &Settings,
    threads: u32,
    done: &std::cell::Cell<u64>,
    total: u64,
    progress: OnProgress<'_>,
    cancel: &Cancel,
) -> Result<()> {
    let (codec, block_size, workers) = plan(s.level, threads);
    let mut header = Header {
        id: random()?,
        ..Header::default()
    };
    let key = match s.password.as_deref().filter(|p| !p.is_empty()) {
        Some(p) => {
            header.flags |= FLAG_ENCRYPTED;
            header.salt = random()?;
            header.memory_kib = ARGON2_MEMORY_KIB;
            header.passes = ARGON2_PASSES;
            header.lanes = ARGON2_LANES;
            Some(super::derive_key(p, &header)?)
        }
        None => None,
    };
    let mut w = Writer {
        file,
        pos: 0,
        codec,
        key,
        workers,
        block_size,
        index: Index {
            comment: s.comment.clone().filter(|c| !c.is_empty()),
            ..Index::default()
        },
        seen: HashMap::new(),
        pending: Vec::new(),
        current: Vec::new(),
        cancel,
    };
    // Room for the header, written once the offsets are known.
    w.put(&[0u8; HEADER_LEN as usize])?;
    for item in items {
        cancel.check().map_err(Error::from)?;
        let entry = w.add(item, done, total, progress)?;
        w.index.entries.push(entry);
    }
    if !w.current.is_empty() {
        let last = std::mem::take(&mut w.current);
        w.pending.push(last);
    }
    w.flush()?;
    w.finish(header, s.recovery_percent.min(100))
}

impl Writer<'_> {
    /// One file or folder: its entry, with its content cut into chunks and stored.
    fn add(
        &mut self,
        item: &Source,
        done: &std::cell::Cell<u64>,
        total: u64,
        progress: OnProgress<'_>,
    ) -> Result<IndexEntry> {
        let meta = std::fs::symlink_metadata(&item.path)
            .map_err(|e| Error::Io(format!("{}: {e}", item.path.display())))?;
        let (mode, attributes) = mode_of(&meta);
        let mut entry = IndexEntry {
            path: item.name.clone(),
            kind: if item.is_dir { Kind::Dir } else { Kind::File },
            size: 0,
            chunks: Vec::new(),
            hash: None,
            mtime: nanos(meta.modified().ok()),
            mode,
            attributes,
            target: None,
        };
        if item.is_dir {
            return Ok(entry);
        }
        let mut r = Counting {
            inner: File::open(&item.path)
                .map_err(|e| Error::Io(format!("{}: {e}", item.path.display())))?,
            done,
            total,
            name: &item.name,
            progress,
            cancel: self.cancel,
            last: std::cell::Cell::new(done.get()),
        };
        let mut whole = blake3::Hasher::new();
        let mut buf: Vec<u8> = Vec::with_capacity(cdc::MAX * 2);
        let mut ended = false;
        loop {
            // Keep at least one largest chunk ahead, so every cut sees what it needs.
            while !ended && buf.len() < cdc::MAX {
                let at = buf.len();
                buf.resize(at + cdc::MAX, 0);
                let n = r.read(&mut buf[at..]).map_err(Error::from)?;
                buf.truncate(at + n);
                ended = n == 0;
            }
            if buf.is_empty() {
                break;
            }
            let n = cdc::cut(&buf);
            whole.update(&buf[..n]);
            entry.size += n as u64;
            entry.chunks.push(self.chunk(&buf[..n])?);
            buf.drain(..n);
        }
        entry.hash = Some(hex(whole.finalize().as_bytes()));
        Ok(entry)
    }

    /// The index, the header, the recovery data and the trailer.
    fn finish(mut self, mut header: Header, percent: u8) -> Result<()> {
        let json = serde_json::to_vec(&self.index).map_err(|e| Error::Io(e.to_string()))?;
        let index_codec = Codec {
            level: 19,
            window_log: None,
        };
        let stored = seal(&json, index_codec, self.key.as_ref(), INDEX_NUMBER)?;
        header.index_at = self.pos;
        let hash = *blake3::hash(&stored).as_bytes();
        self.put(&(stored.len() as u64).to_le_bytes())?;
        self.put(&stored)?;
        self.put(&hash)?;
        header.index_len = self.pos - header.index_at;
        // The recovery data protects the header too, so the header goes in first, with
        // the recovery data's place and size, which depend only on the region's size.
        if percent > 0 {
            header.flags |= FLAG_RECOVERY;
            header.recovery_at = self.pos;
            header.recovery_len = super::recovery::length(self.pos, percent);
        }
        self.file.seek(SeekFrom::Start(0)).map_err(Error::from)?;
        self.file.write_all(&header.encode()).map_err(Error::from)?;
        self.file
            .seek(SeekFrom::Start(self.pos))
            .map_err(Error::from)?;
        if percent > 0 {
            let written = super::recovery::build(&mut self.file, self.pos, percent, self.cancel)?;
            if written != header.recovery_len {
                return Err(Error::Io(
                    "the recovery data is not the size it should be".into(),
                ));
            }
            self.pos += written;
            self.file
                .seek(SeekFrom::Start(self.pos))
                .map_err(Error::from)?;
        }
        self.put(&Trailer::of(&header).encode())?;
        self.file.sync_all().map_err(Error::from)?;
        Ok(())
    }
}
