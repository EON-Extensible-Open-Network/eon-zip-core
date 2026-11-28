// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 EON contributors

//! Recovery data: Reed-Solomon parity (GF(2¹⁶), `reed-solomon-simd`) over everything from
//! the header to the end of the index, so a damaged `.eonz` repairs itself — WinRAR's
//! recovery record, which 7z has no equivalent of.
//!
//! The region is cut into equal shards. Shard `j` belongs to group `j mod G`, so a burst of
//! damage (a bad sector, a cut transfer) is spread thinly over every group instead of
//! sinking one. Each group of at most 256 shards gets its own parity shards, which keeps
//! memory at a small, fixed share of the archive. A BLAKE3-128 per shard says which shards
//! are damaged; the table is kept twice.
//!
//! ```text
//! fixed (48) | table | check (16) | parity shards | table | check | fixed (48)
//! fixed: "EONZREC0", shard size u64, data shards u64, groups u32, parity per group u32,
//!        region length u64, shards per group u32, reserved u32
//! ```

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use super::{hash16, u64_at, Header, Trailer, TRAILER_LEN};
use crate::{Cancel, Error, Result};

pub const MAGIC: [u8; 8] = *b"EONZREC0";
const FIXED: u64 = 48;
const MAX_SHARDS: u64 = 262_144;
const PER_GROUP: u64 = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Geometry {
    shard: u64,
    data: u64,
    groups: u64,
    per_group: u64,
    parity: u64,
    region: u64,
}

impl Geometry {
    fn new(region: u64, percent: u8) -> Geometry {
        let shard = (region.div_ceil(MAX_SHARDS).max(4096)).div_ceil(64) * 64;
        let data = region.div_ceil(shard).max(1);
        let groups = data.div_ceil(PER_GROUP);
        let per_group = data.div_ceil(groups);
        let parity = (per_group * u64::from(percent)).div_ceil(100).max(1);
        Geometry {
            shard,
            data,
            groups,
            per_group,
            parity,
            region,
        }
    }

    fn table(&self) -> u64 {
        (self.data + self.groups * self.parity) * 16
    }

    fn total(&self) -> u64 {
        2 * (FIXED + self.table() + 16) + self.groups * self.parity * self.shard
    }

    fn fixed(&self) -> [u8; 48] {
        let mut b = [0u8; 48];
        b[0..8].copy_from_slice(&MAGIC);
        b[8..16].copy_from_slice(&self.shard.to_le_bytes());
        b[16..24].copy_from_slice(&self.data.to_le_bytes());
        b[24..28].copy_from_slice(&(self.groups as u32).to_le_bytes());
        b[28..32].copy_from_slice(&(self.parity as u32).to_le_bytes());
        b[32..40].copy_from_slice(&self.region.to_le_bytes());
        b[40..44].copy_from_slice(&(self.per_group as u32).to_le_bytes());
        b
    }

    fn parse(b: &[u8]) -> Option<Geometry> {
        if b.len() < 48 || b[0..8] != MAGIC {
            return None;
        }
        let u32_at =
            |at: usize| u64::from(u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]]));
        let g = Geometry {
            shard: u64_at(b, 8),
            data: u64_at(b, 16),
            groups: u32_at(24),
            parity: u32_at(28),
            region: u64_at(b, 32),
            per_group: u32_at(40),
        };
        // Only geometries this code could have written.
        (g == Geometry::new(g.region, 0).with_parity(g.parity)).then_some(g)
    }

    fn with_parity(mut self, parity: u64) -> Geometry {
        self.parity = parity;
        self
    }

    /// The data shard at position `i` of group `g`, if there is one.
    fn member(&self, g: u64, i: u64) -> Option<u64> {
        let j = g + i * self.groups;
        (j < self.data).then_some(j)
    }

    /// Where the first copy's parity shards start, from the start of the recovery data.
    fn parity_at(&self) -> u64 {
        FIXED + self.table() + 16
    }
}

/// How many bytes the recovery data for a region of `region` bytes takes.
pub fn length(region: u64, percent: u8) -> u64 {
    Geometry::new(region, percent).total()
}

fn shard_of(f: &mut File, geo: &Geometry, j: u64) -> std::io::Result<Vec<u8>> {
    let mut b = vec![0u8; geo.shard as usize];
    let at = j * geo.shard;
    let n = geo.shard.min(geo.region.saturating_sub(at)) as usize;
    f.seek(SeekFrom::Start(at))?;
    f.read_exact(&mut b[..n])?;
    Ok(b)
}

fn rs_err(e: impl std::fmt::Display) -> Error {
    Error::Io(format!("recovery data: {e}"))
}

/// Compute the recovery data for the first `region` bytes of `f` and append it at the
/// current end. Returns the bytes written.
pub(crate) fn build(f: &mut File, region: u64, percent: u8, cancel: &Cancel) -> Result<u64> {
    let geo = Geometry::new(region, percent);
    let start = region;
    // Hashes of the data shards, in order.
    let mut table = Vec::with_capacity(geo.table() as usize);
    for j in 0..geo.data {
        let s = shard_of(f, &geo, j).map_err(Error::from)?;
        table.extend_from_slice(&hash16(&s));
    }
    // Parity, group by group.
    let mut parity_hashes = Vec::with_capacity((geo.groups * geo.parity * 16) as usize);
    let parity_start = start + geo.parity_at();
    for g in 0..geo.groups {
        cancel.check().map_err(Error::from)?;
        let mut shards = Vec::with_capacity(geo.per_group as usize);
        for i in 0..geo.per_group {
            shards.push(match geo.member(g, i) {
                Some(j) => shard_of(f, &geo, j).map_err(Error::from)?,
                None => vec![0u8; geo.shard as usize],
            });
        }
        let parity =
            reed_solomon_simd::encode(geo.per_group as usize, geo.parity as usize, &shards)
                .map_err(rs_err)?;
        f.seek(SeekFrom::Start(parity_start + g * geo.parity * geo.shard))
            .map_err(Error::from)?;
        for p in &parity {
            f.write_all(p).map_err(Error::from)?;
            parity_hashes.extend_from_slice(&hash16(p));
        }
    }
    table.extend_from_slice(&parity_hashes);
    let fixed = geo.fixed();
    let mut checked = fixed.to_vec();
    checked.extend_from_slice(&table);
    let check = hash16(&checked);
    // First copy: fixed, table, check.
    f.seek(SeekFrom::Start(start)).map_err(Error::from)?;
    f.write_all(&fixed).map_err(Error::from)?;
    f.write_all(&table).map_err(Error::from)?;
    f.write_all(&check).map_err(Error::from)?;
    // Second copy at the very end, fixed last so it can be found from the end.
    f.seek(SeekFrom::Start(
        parity_start + geo.groups * geo.parity * geo.shard,
    ))
    .map_err(Error::from)?;
    f.write_all(&table).map_err(Error::from)?;
    f.write_all(&check).map_err(Error::from)?;
    f.write_all(&fixed).map_err(Error::from)?;
    Ok(geo.total())
}

/// What a repair found and did.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct RepairReport {
    /// Shards of the archive that did not match their checksum.
    pub damaged: u64,
    /// Of those, rebuilt from the recovery data.
    pub repaired: u64,
    /// Shard size in bytes, to say how much was damaged.
    pub shard: u64,
    /// True when the repaired copy is whole.
    pub whole: bool,
}

/// Read the recovery data's description and hash table: the first copy, else the second.
fn description(f: &mut File, at: u64, len: u64) -> Result<(Geometry, Vec<u8>)> {
    let read = |f: &mut File, at: u64, n: u64| -> std::io::Result<Vec<u8>> {
        let mut b = vec![0u8; n as usize];
        f.seek(SeekFrom::Start(at))?;
        f.read_exact(&mut b)?;
        Ok(b)
    };
    let valid = |fixed: &[u8], table: &[u8], check: &[u8]| {
        let mut c = fixed.to_vec();
        c.extend_from_slice(table);
        hash16(&c) == check
    };
    if let Ok(fixed) = read(f, at, FIXED) {
        if let Some(geo) = Geometry::parse(&fixed) {
            if let Ok(rest) = read(f, at + FIXED, geo.table() + 16) {
                let (table, check) = rest.split_at(geo.table() as usize);
                if valid(&fixed, table, check) {
                    return Ok((geo, table.to_vec()));
                }
            }
        }
    }
    let end = at + len;
    if let Ok(fixed) = read(f, end.saturating_sub(FIXED), FIXED) {
        if let Some(geo) = Geometry::parse(&fixed) {
            let n = geo.table() + 16;
            if let Ok(rest) = read(f, end.saturating_sub(FIXED + n), n) {
                let (table, check) = rest.split_at(geo.table() as usize);
                if valid(&fixed, table, check) {
                    return Ok((geo, table.to_vec()));
                }
            }
        }
    }
    Err(Error::Damaged(
        "the recovery data is itself damaged beyond use".into(),
    ))
}

/// Where the recovery data is: from the header, else the trailer.
fn find(f: &mut File) -> Result<(u64, u64)> {
    let len = f.metadata().map_err(Error::from)?.len();
    let mut head = vec![0u8; 128];
    if f.seek(SeekFrom::Start(0))
        .and_then(|_| f.read_exact(&mut head))
        .is_ok()
    {
        if let Ok(Some(h)) = Header::decode(&head) {
            if h.recovery_len > 0 {
                return Ok((h.recovery_at, h.recovery_len));
            }
            return Err(Error::Unsupported(
                "this archive was made without recovery data".into(),
            ));
        }
    }
    let mut tail = vec![0u8; TRAILER_LEN as usize];
    if len >= TRAILER_LEN
        && f.seek(SeekFrom::Start(len - TRAILER_LEN))
            .and_then(|_| f.read_exact(&mut tail))
            .is_ok()
    {
        if let Some(t) = Trailer::decode(&tail) {
            if t.recovery_len > 0 {
                return Ok((t.recovery_at, t.recovery_len));
            }
        }
    }
    Err(Error::Damaged(
        "neither the header nor the trailer says where the recovery data is".into(),
    ))
}

/// Write a repaired copy of `path` to `out`, rebuilding damaged parts from its recovery
/// data. `out` is written only when something can be rebuilt; the original is never
/// touched.
pub fn repair(path: &Path, out: &Path, cancel: &Cancel) -> Result<RepairReport> {
    let mut src = File::open(path).map_err(Error::from)?;
    let (at, len) = find(&mut src)?;
    let (geo, table) = description(&mut src, at, len)?;
    let mut report = RepairReport {
        shard: geo.shard,
        ..RepairReport::default()
    };
    // Which data shards are damaged, by group.
    let mut bad: Vec<Vec<u64>> = vec![Vec::new(); geo.groups as usize];
    for j in 0..geo.data {
        cancel.check().map_err(Error::from)?;
        let s = shard_of(&mut src, &geo, j).ok();
        let want = &table[(j * 16) as usize..(j * 16 + 16) as usize];
        if s.is_none_or(|s| hash16(&s) != want) {
            bad[(j % geo.groups) as usize].push(j);
            report.damaged += 1;
        }
    }
    if report.damaged == 0 {
        report.whole = true;
        return Ok(report);
    }
    std::fs::copy(path, out).map_err(Error::from)?;
    let mut dst = OpenOptions::new()
        .read(true)
        .write(true)
        .open(out)
        .map_err(Error::from)?;
    let parity_start = at + geo.parity_at();
    for g in 0..geo.groups {
        let lost = &bad[g as usize];
        if lost.is_empty() {
            continue;
        }
        cancel.check().map_err(Error::from)?;
        let mut originals = Vec::new();
        for i in 0..geo.per_group {
            match geo.member(g, i) {
                Some(j) if lost.contains(&j) => {}
                Some(j) => {
                    originals.push((
                        i as usize,
                        shard_of(&mut src, &geo, j).map_err(Error::from)?,
                    ));
                }
                None => originals.push((i as usize, vec![0u8; geo.shard as usize])),
            }
        }
        let mut recovery = Vec::new();
        for p in 0..geo.parity {
            let slot = g * geo.parity + p;
            let mut s = vec![0u8; geo.shard as usize];
            let ok = src
                .seek(SeekFrom::Start(parity_start + slot * geo.shard))
                .and_then(|_| src.read_exact(&mut s))
                .is_ok();
            let h = ((geo.data + slot) * 16) as usize;
            if ok && hash16(&s) == table[h..h + 16] {
                recovery.push((p as usize, s));
            }
        }
        if recovery.len() < lost.len() {
            continue;
        }
        let restored = reed_solomon_simd::decode(
            geo.per_group as usize,
            geo.parity as usize,
            originals.iter().map(|(i, s)| (*i, s.as_slice())),
            recovery.iter().map(|(i, s)| (*i, s.as_slice())),
        )
        .map_err(rs_err)?;
        for j in lost {
            let i = (j / geo.groups) as usize;
            if let Some(data) = restored.get(&i) {
                let at = j * geo.shard;
                let n = geo.shard.min(geo.region - at) as usize;
                dst.seek(SeekFrom::Start(at)).map_err(Error::from)?;
                dst.write_all(&data[..n]).map_err(Error::from)?;
                report.repaired += 1;
            }
        }
    }
    // The trailer is outside the protected region: write it again from the header.
    let mut head = vec![0u8; 128];
    dst.seek(SeekFrom::Start(0))
        .and_then(|_| dst.read_exact(&mut head))
        .map_err(Error::from)?;
    if let Ok(Some(h)) = Header::decode(&head) {
        let end = dst.metadata().map_err(Error::from)?.len();
        if end >= TRAILER_LEN {
            dst.seek(SeekFrom::Start(end - TRAILER_LEN))
                .map_err(Error::from)?;
            dst.write_all(&Trailer::of(&h).encode())
                .map_err(Error::from)?;
        }
    }
    dst.sync_all().map_err(Error::from)?;
    report.whole = report.repaired == report.damaged;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn geometry_keeps_its_promises() {
        for (region, percent) in [
            (1u64, 5u8),
            (4096, 5),
            (10_000_000, 5),
            (1 << 34, 10),
            (123_456_789, 50),
        ] {
            let g = Geometry::new(region, percent);
            assert!(g.shard.is_multiple_of(64) && g.shard >= 4096);
            assert!(g.data * g.shard >= region && g.data <= MAX_SHARDS);
            assert!(g.per_group <= PER_GROUP && g.groups * g.per_group >= g.data);
            assert!(g.parity >= 1);
            assert_eq!(Geometry::parse(&g.fixed()), Some(g));
        }
    }
}
