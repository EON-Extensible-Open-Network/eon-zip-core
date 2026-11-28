// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 EON contributors

//! `.eonz`, EON Zip's own format, version 0 (plan madde 49i; the specification is
//! eon-docs `zip/eonz.md`). Proven parts in a new container: Zstandard in solid blocks
//! compressed in parallel, content-defined chunks stored once, BLAKE3 everywhere,
//! AES-256-GCM with Argon2id, and Reed-Solomon recovery data inside the archive.

pub mod cdc;
mod open;
pub mod recovery;
mod write;

pub use open::{Eonz, EonzEntry};
pub use recovery::{repair, RepairReport};
pub(crate) use write::write;

use crate::{Error, Result};
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::Aes256Gcm;
use serde::{Deserialize, Serialize};

pub const MAGIC: [u8; 8] = *b"EONZ\r\n\x1a\n";
pub const TRAILER_MAGIC: [u8; 8] = *b"EONZEND\0";
pub const VERSION: u16 = 0;
pub const HEADER_LEN: u64 = 128;
pub const TRAILER_LEN: u64 = 64;
const FLAG_ENCRYPTED: u16 = 1;
const FLAG_RECOVERY: u16 = 2;
/// The nonce number of the index block (data blocks count up from 0).
const INDEX_NUMBER: u64 = u64::MAX;
/// The largest index read (an index this big holds tens of millions of files).
const INDEX_LIMIT: u64 = 1 << 30;

/// Argon2id defaults: 64 MiB, 3 passes, 1 lane (RFC 9106's second recommendation).
pub const ARGON2_MEMORY_KIB: u32 = 64 * 1024;
pub const ARGON2_PASSES: u32 = 3;
pub const ARGON2_LANES: u32 = 1;

/// The first 16 bytes of a BLAKE3 hash.
pub(crate) fn hash16(data: &[u8]) -> [u8; 16] {
    let mut out = [0u8; 16];
    out.copy_from_slice(&blake3::hash(data).as_bytes()[..16]);
    out
}

fn u16_at(b: &[u8], at: usize) -> u16 {
    let mut x = [0u8; 2];
    x.copy_from_slice(&b[at..at + 2]);
    u16::from_le_bytes(x)
}

fn u32_at(b: &[u8], at: usize) -> u32 {
    let mut x = [0u8; 4];
    x.copy_from_slice(&b[at..at + 4]);
    u32::from_le_bytes(x)
}

pub(crate) fn u64_at(b: &[u8], at: usize) -> u64 {
    let mut x = [0u8; 8];
    x.copy_from_slice(&b[at..at + 8]);
    u64::from_le_bytes(x)
}

/// Where things are, at the start of the file (and, the offsets only, at its end).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Header {
    pub flags: u16,
    pub id: [u8; 16],
    pub salt: [u8; 16],
    pub memory_kib: u32,
    pub passes: u32,
    pub lanes: u32,
    pub index_at: u64,
    pub index_len: u64,
    pub recovery_at: u64,
    pub recovery_len: u64,
}

impl Header {
    pub fn encrypted(&self) -> bool {
        self.flags & FLAG_ENCRYPTED != 0
    }

    pub fn encode(&self) -> [u8; 128] {
        let mut b = [0u8; 128];
        b[0..8].copy_from_slice(&MAGIC);
        b[8..10].copy_from_slice(&VERSION.to_le_bytes());
        b[10..12].copy_from_slice(&self.flags.to_le_bytes());
        b[12..28].copy_from_slice(&self.id);
        b[28..44].copy_from_slice(&self.salt);
        b[44..48].copy_from_slice(&self.memory_kib.to_le_bytes());
        b[48..52].copy_from_slice(&self.passes.to_le_bytes());
        b[52..56].copy_from_slice(&self.lanes.to_le_bytes());
        b[56..64].copy_from_slice(&self.index_at.to_le_bytes());
        b[64..72].copy_from_slice(&self.index_len.to_le_bytes());
        b[72..80].copy_from_slice(&self.recovery_at.to_le_bytes());
        b[80..88].copy_from_slice(&self.recovery_len.to_le_bytes());
        let check = hash16(&b[..112]);
        b[112..128].copy_from_slice(&check);
        b
    }

    /// `None` if these are not the bytes of a whole, undamaged header. A newer format
    /// version is an error of its own, so it is not mistaken for damage.
    pub fn decode(b: &[u8]) -> Result<Option<Header>> {
        if b.len() < 128 || b[0..8] != MAGIC {
            return Ok(None);
        }
        if hash16(&b[..112]) != b[112..128] {
            return Ok(None);
        }
        let version = u16_at(b, 8);
        if version != VERSION {
            return Err(Error::Unsupported(format!(
                "this .eonz file is format version {version}; this EON Zip reads version {VERSION}"
            )));
        }
        let flags = u16_at(b, 10);
        if flags & !(FLAG_ENCRYPTED | FLAG_RECOVERY) != 0 {
            return Err(Error::Unsupported(
                "this .eonz file uses features this EON Zip does not know".into(),
            ));
        }
        let mut id = [0u8; 16];
        id.copy_from_slice(&b[12..28]);
        let mut salt = [0u8; 16];
        salt.copy_from_slice(&b[28..44]);
        Ok(Some(Header {
            flags,
            id,
            salt,
            memory_kib: u32_at(b, 44),
            passes: u32_at(b, 48),
            lanes: u32_at(b, 52),
            index_at: u64_at(b, 56),
            index_len: u64_at(b, 64),
            recovery_at: u64_at(b, 72),
            recovery_len: u64_at(b, 80),
        }))
    }
}

/// The offsets again, at the end of the file.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Trailer {
    pub index_at: u64,
    pub index_len: u64,
    pub recovery_at: u64,
    pub recovery_len: u64,
    pub id: [u8; 16],
}

impl Trailer {
    pub fn of(h: &Header) -> Trailer {
        Trailer {
            index_at: h.index_at,
            index_len: h.index_len,
            recovery_at: h.recovery_at,
            recovery_len: h.recovery_len,
            id: h.id,
        }
    }

    pub fn encode(&self) -> [u8; 64] {
        let mut b = [0u8; 64];
        b[0..8].copy_from_slice(&self.index_at.to_le_bytes());
        b[8..16].copy_from_slice(&self.index_len.to_le_bytes());
        b[16..24].copy_from_slice(&self.recovery_at.to_le_bytes());
        b[24..32].copy_from_slice(&self.recovery_len.to_le_bytes());
        b[32..48].copy_from_slice(&self.id);
        b[48..56].copy_from_slice(&TRAILER_MAGIC);
        let check = hash16(&b[..56]);
        b[56..64].copy_from_slice(&check[..8]);
        b
    }

    pub fn decode(b: &[u8]) -> Option<Trailer> {
        if b.len() < 64 || b[48..56] != TRAILER_MAGIC || hash16(&b[..56])[..8] != b[56..64] {
            return None;
        }
        let mut id = [0u8; 16];
        id.copy_from_slice(&b[32..48]);
        Some(Trailer {
            index_at: u64_at(b, 0),
            index_len: u64_at(b, 8),
            recovery_at: u64_at(b, 16),
            recovery_len: u64_at(b, 24),
            id,
        })
    }
}

/// The key for `password` under the header's parameters.
pub(crate) fn derive_key(password: &str, h: &Header) -> Result<[u8; 32]> {
    use argon2::{Algorithm, Argon2, Params, Version};
    // A file asks for these numbers; refuse ones that would exhaust the machine.
    if h.memory_kib > 4 * 1024 * 1024
        || h.passes == 0
        || h.passes > 64
        || h.lanes == 0
        || h.lanes > 64
    {
        return Err(Error::Format(
            "the archive asks for unreasonable password-hashing settings".into(),
        ));
    }
    let params = Params::new(h.memory_kib, h.passes, h.lanes, Some(32))
        .map_err(|e| Error::Format(e.to_string()))?;
    let mut key = [0u8; 32];
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(password.as_bytes(), &h.salt, &mut key)
        .map_err(|e| Error::Format(e.to_string()))?;
    Ok(key)
}

fn nonce(number: u64) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[..8].copy_from_slice(&number.to_le_bytes());
    n
}

/// How a block is compressed.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Codec {
    pub level: i32,
    /// Zstandard's window as a power of two, with long-distance matching; `None` keeps
    /// the level's own.
    pub window_log: Option<u32>,
}

/// Compress, and encrypt with `key`, one block's plain bytes: what the file stores.
pub(crate) fn seal(
    plain: &[u8],
    codec: Codec,
    key: Option<&[u8; 32]>,
    number: u64,
) -> Result<Vec<u8>> {
    use zstd::stream::raw::CParameter;
    let mut c = zstd::bulk::Compressor::new(codec.level).map_err(|e| Error::Io(e.to_string()))?;
    if let Some(w) = codec.window_log {
        c.set_parameter(CParameter::EnableLongDistanceMatching(true))
            .and_then(|()| c.set_parameter(CParameter::WindowLog(w)))
            .map_err(|e| Error::Io(e.to_string()))?;
    }
    c.include_checksum(false)
        .map_err(|e| Error::Io(e.to_string()))?;
    let packed = c.compress(plain).map_err(|e| Error::Io(e.to_string()))?;
    match key {
        None => Ok(packed),
        Some(k) => {
            let cipher = Aes256Gcm::new_from_slice(k).map_err(|e| Error::Io(e.to_string()))?;
            let mut out = nonce(number).to_vec();
            let sealed = cipher
                .encrypt(&nonce(number).into(), packed.as_slice())
                .map_err(|_| Error::Io("encryption failed".into()))?;
            out.extend_from_slice(&sealed);
            Ok(out)
        }
    }
}

/// Decrypt (when `key` is given) and decompress stored bytes. `plain` is the size the
/// index promises; `None` (the index itself) reads up to [`INDEX_LIMIT`].
pub(crate) fn unseal(
    stored: &[u8],
    plain: Option<u64>,
    key: Option<&[u8; 32]>,
    number: u64,
) -> Result<Vec<u8>> {
    let packed: std::borrow::Cow<'_, [u8]> = match key {
        None => stored.into(),
        Some(k) => {
            if stored.len() < 12 + 16 || stored[..12] != nonce(number) {
                return Err(Error::Damaged("an encrypted block is cut short".into()));
            }
            let cipher = Aes256Gcm::new_from_slice(k).map_err(|e| Error::Io(e.to_string()))?;
            let opened = cipher
                .decrypt(&nonce(number).into(), &stored[12..])
                .map_err(|_| {
                    if number == INDEX_NUMBER {
                        Error::WrongPassword
                    } else {
                        Error::Damaged("a block does not match its key".into())
                    }
                })?;
            opened.into()
        }
    };
    if let Some(n) = plain {
        {
            let mut d = zstd::bulk::Decompressor::new().map_err(|e| Error::Io(e.to_string()))?;
            d.window_log_max(31).map_err(|e| Error::Io(e.to_string()))?;
            let out = d
                .decompress(&packed, usize::try_from(n).unwrap_or(usize::MAX))
                .map_err(|e| Error::Damaged(format!("a block does not decompress: {e}")))?;
            if out.len() as u64 != n {
                return Err(Error::Damaged(
                    "a block is not the size its index says".into(),
                ));
            }
            Ok(out)
        }
    } else {
        {
            use std::io::Read;
            let mut d = zstd::stream::read::Decoder::new(&packed[..])
                .map_err(|e| Error::Damaged(e.to_string()))?;
            d.window_log_max(31)
                .map_err(|e| Error::Damaged(e.to_string()))?;
            let mut out = Vec::new();
            (&mut d)
                .take(INDEX_LIMIT)
                .read_to_end(&mut out)
                .map_err(|e| Error::Damaged(format!("the index does not decompress: {e}")))?;
            Ok(out)
        }
    }
}

/// Bytes as lowercase hex, for the JSON index.
pub(crate) fn hex(b: &[u8]) -> String {
    use std::fmt::Write;
    b.iter()
        .fold(String::with_capacity(b.len() * 2), |mut s, x| {
            let _ = write!(s, "{x:02x}");
            s
        })
}

pub(crate) fn unhex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(s.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

/// The index, as stored (JSON).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(crate) struct Index {
    pub blocks: Vec<BlockRef>,
    pub chunks: Vec<ChunkRef>,
    pub entries: Vec<IndexEntry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct BlockRef {
    /// Where its length field starts.
    pub offset: u64,
    /// Bytes stored (without the length field and the hash).
    pub stored: u64,
    pub plain: u64,
    pub hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ChunkRef {
    pub block: u32,
    pub at: u64,
    pub len: u64,
    pub hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    File,
    Dir,
    Symlink,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct IndexEntry {
    pub path: String,
    pub kind: Kind,
    #[serde(default)]
    pub size: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub chunks: Vec<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtime: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attributes: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_and_trailer_round_trip_and_refuse_damage() {
        let h = Header {
            flags: FLAG_ENCRYPTED,
            id: [7; 16],
            salt: [9; 16],
            memory_kib: 1024,
            passes: 1,
            lanes: 1,
            index_at: 4096,
            index_len: 300,
            recovery_at: 4396,
            recovery_len: 1000,
        };
        let b = h.encode();
        assert_eq!(Header::decode(&b), Ok(Some(h.clone())));
        let mut bad = b;
        bad[60] ^= 1;
        assert_eq!(Header::decode(&bad), Ok(None));
        let t = Trailer::of(&h);
        assert_eq!(Trailer::decode(&t.encode()), Some(t));
        let mut newer = b;
        newer[8] = 1;
        let check = hash16(&newer[..112]);
        newer[112..128].copy_from_slice(&check);
        assert!(matches!(Header::decode(&newer), Err(Error::Unsupported(_))));
    }

    #[test]
    fn blocks_seal_and_unseal_with_and_without_a_key() {
        let plain = b"EON Zip ".repeat(1000);
        let codec = Codec {
            level: 3,
            window_log: Some(22),
        };
        let open = seal(&plain, codec, None, 0).unwrap_or_default();
        assert!(open.len() < plain.len());
        assert_eq!(
            unseal(&open, Some(plain.len() as u64), None, 0),
            Ok(plain.clone())
        );
        let key = [5u8; 32];
        let closed = seal(&plain, codec, Some(&key), 4).unwrap_or_default();
        assert_eq!(
            unseal(&closed, Some(plain.len() as u64), Some(&key), 4),
            Ok(plain.clone())
        );
        // Another key, or the block moved to another place, does not open.
        assert!(unseal(&closed, Some(plain.len() as u64), Some(&[6u8; 32]), 4).is_err());
        assert!(unseal(&closed, Some(plain.len() as u64), Some(&key), 5).is_err());
        let index = seal(b"{}", codec, Some(&key), INDEX_NUMBER).unwrap_or_default();
        assert_eq!(
            unseal(&index, None, Some(&[1u8; 32]), INDEX_NUMBER),
            Err(Error::WrongPassword)
        );
    }

    #[test]
    fn hex_round_trip() {
        let h = *blake3::hash(b"x").as_bytes();
        assert_eq!(unhex32(&hex(&h)), Some(h));
        assert_eq!(unhex32("zz"), None);
    }
}
