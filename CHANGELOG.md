<!--
SPDX-License-Identifier: GPL-3.0-or-later
SPDX-FileCopyrightText: 2026 EON contributors
-->

# Changelog

## v0.0.1 — 28 November 2026

**`.eonz`, EON Zip's own format** (plan madde 49i, the owner's request; specification in
eon-docs `zip/eonz.md`). Created with `Format::Eonz`, opened like any other archive, and
repaired with `eonz::repair`:

- files are cut where their content says (a gear hash, `FastCDC`'s normalised cut, 64 KiB
  on average), and a chunk seen before is referenced, not stored again: three copies of a
  3 MiB file that does not compress, one shifted by three bytes, take under 3.6 MiB;
- chunks fill solid blocks (4–64 MiB by level) compressed with Zstandard, long-distance
  matching from Normal up, several blocks at once;
- BLAKE3 for every block (checked before use, without the password), chunk and file;
- with a password, AES-256-GCM for every block and for the index, so names are hidden,
  and a key from Argon2id (64 MiB, 3 passes); a wrong password is told apart from damage;
- Reed-Solomon recovery data (5 % by default), with shards interleaved over groups so a
  burst of damage is spread thin; the tests damage 20 KB in the middle, and the header
  itself, and get the original back byte for byte;
- a `.eonz` whose header is damaged is still recognised by its name, so the person hears
  "damaged, can be repaired" instead of "not an archive".

New dependencies, each with its reason in `Cargo.toml`: `serde_json`, `aes-gcm`, `argon2`,
`getrandom` (already in the tree), `reed-solomon-simd` (MIT and BSD-3-Clause).

The 7-Zip-backed formats (RAR, ISO, CAB…) planned for this version still wait for the
owner's approval to download and run 7-Zip here.

## v0.0.0 — 22 November 2026

The first version (plan madde 49): 7z, ZIP, the tar family and single compressed files,
made and read; volumes; tests; hashes; conversion; and the safety rules in `src/safe.rs`.

Found while testing: 7-Zip refuses a ZIP password with any letter outside ASCII (`ğ`, `é`).
`portable_zip_password` says so, so the window can suggest 7z or English letters.
