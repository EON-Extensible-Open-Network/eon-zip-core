// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 EON contributors

//! Content-defined chunking (`FastCDC`'s normalised cut): a 64-bit gear hash rolls over the
//! bytes and a chunk ends where its masked bits are zero, so the same content is cut the
//! same way wherever it sits in a file — even after an insertion before it. Equal chunks
//! are then stored once (deduplication).

/// Smallest, average (aimed at) and largest chunk.
pub const MIN: usize = 16 * 1024;
pub const AVG: usize = 64 * 1024;
pub const MAX: usize = 256 * 1024;

/// A harder mask before the average (fewer early cuts) and an easier one after it
/// (`FastCDC`'s normalisation, level 2: log2 of the average ± 2 bits), which narrows the
/// spread of chunk sizes. Bits are spread over the hash's upper half, where the gear hash
/// carries the most recent bytes.
const MASK_HARD: u64 = spread(18);
const MASK_EASY: u64 = spread(14);

/// `n` bits set: bit 63, 61, 59 … downwards.
const fn spread(n: u32) -> u64 {
    let mut m = 0u64;
    let mut i = 0;
    while i < n {
        m |= 1 << (63 - 2 * i);
        i += 1;
    }
    m
}

/// 256 pseudo-random 64-bit values, fixed by the format: `SplitMix64` from seed 0x454f4e5a
/// ("EONZ"). Changing them changes every cut, so they are part of version 0.
pub const GEAR: [u64; 256] = gear();

const fn gear() -> [u64; 256] {
    let mut out = [0u64; 256];
    let mut state: u64 = 0x454f_4e5a;
    let mut i = 0;
    while i < 256 {
        state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        out[i] = z ^ (z >> 31);
        i += 1;
    }
    out
}

/// Where the first chunk of `data` ends. `data` is everything still to cut, or at least
/// [`MAX`] bytes of it; when fewer than [`MIN`] bytes remain, they are one chunk.
pub fn cut(data: &[u8]) -> usize {
    let n = data.len().min(MAX);
    if n <= MIN {
        return n;
    }
    let mut h: u64 = 0;
    let mut i = MIN;
    let middle = AVG.min(n);
    while i < middle {
        h = (h << 1).wrapping_add(GEAR[data[i] as usize]);
        if h & MASK_HARD == 0 {
            return i + 1;
        }
        i += 1;
    }
    while i < n {
        h = (h << 1).wrapping_add(GEAR[data[i] as usize]);
        if h & MASK_EASY == 0 {
            return i + 1;
        }
        i += 1;
    }
    n
}

#[cfg(test)]
mod tests {
    use super::*;

    fn noise(n: usize, seed: u64) -> Vec<u8> {
        let mut s = seed;
        (0..n)
            .map(|_| {
                s ^= s << 13;
                s ^= s >> 7;
                s ^= s << 17;
                (s >> 24) as u8
            })
            .collect()
    }

    fn chunks(data: &[u8]) -> Vec<&[u8]> {
        let mut out = Vec::new();
        let mut at = 0;
        while at < data.len() {
            let n = cut(&data[at..]);
            out.push(&data[at..at + n]);
            at += n;
        }
        out
    }

    #[test]
    fn sizes_stay_in_bounds_and_average_near_the_aim() {
        let data = noise(8 * 1024 * 1024, 1);
        let c = chunks(&data);
        assert!(c[..c.len() - 1]
            .iter()
            .all(|x| x.len() >= MIN && x.len() <= MAX));
        let avg = data.len() / c.len();
        assert!((AVG / 2..AVG * 2).contains(&avg), "average {avg}");
    }

    #[test]
    fn an_insertion_moves_only_the_chunks_around_it() {
        let data = noise(4 * 1024 * 1024, 2);
        let mut changed = data.clone();
        changed.splice(1000..1000, b"inserted".iter().copied());
        let a: std::collections::HashSet<&[u8]> = chunks(&data).into_iter().collect();
        let b = chunks(&changed);
        let shared = b.iter().filter(|x| a.contains(*x)).count();
        // Almost every chunk after the insertion is found again unchanged.
        assert!(shared + 2 >= b.len(), "{shared} of {}", b.len());
    }

    /// The table and the masks are part of the format: any change moves every cut, so
    /// version 0 archives would deduplicate differently. These values were recorded once.
    #[test]
    fn the_cut_rules_are_fixed() {
        let sum = GEAR.iter().fold(0u64, |a, x| a.wrapping_add(*x));
        assert_eq!(sum, 6_825_758_195_896_114_991);
        assert_eq!((MASK_HARD.count_ones(), MASK_EASY.count_ones()), (18, 14));
        assert_eq!(MASK_HARD & MASK_EASY, MASK_EASY);
    }
}
