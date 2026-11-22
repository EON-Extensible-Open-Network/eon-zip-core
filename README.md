<!--
SPDX-License-Identifier: GPL-3.0-or-later
SPDX-FileCopyrightText: 2026 EON contributors
-->

# eon-zip-core

The core of **EON Zip** (plan madde 49): open, list, extract, test and create archives,
split and join volumes, hash files, convert between formats. A library with no window;
EON Zip's application uses it.

```rust
let archive = Archive::open(path, password, Some("tr"))?;   // any part of a set of volumes
let plan = archive.plan(dest, &Extract::default());          // where everything goes, decided first
archive.extract(&plan, &progress, &cancel)?;                  // nothing outside `dest`, ever
create(&sources, target, &Settings { format: Format::SevenZ, ..Default::default() }, &progress, &cancel)?;
```

## Formats

| Format | Create | Extract |
|---|---|---|
| 7z (LZMA2 multi-threaded, LZMA, PPMd, BZip2, Zstandard; AES-256; encrypted names; solid) | ✓ | ✓ |
| ZIP (Deflate, BZip2, Zstandard, XZ, PPMd; AES-256; comment) | ✓ | ✓ (also Deflate64, LZMA) |
| TAR, TAR.GZ, TAR.BZ2, TAR.XZ, TAR.ZST | ✓ | ✓ |
| GZIP, BZIP2, XZ, Zstandard (one file) | ✓ | ✓ |
| Volumes `.001`, `.002`… | ✓ | ✓ |
| RAR, ISO, CAB and the rest of what 7-Zip reads | — | later, through 7-Zip itself |

Pure Rust except Zstandard (the reference C library). Creating RAR is not possible for
anyone but RARLAB; see `eon-docs/zip/research.md`.

## What it does that 7-Zip and WinRAR do not

- **One place decides where an entry is written** (`src/safe.rs`), with no way to turn it
  off: absolute paths, drive letters, `..` in every disguise, and links are refused.
  Windows device names and characters it cannot hold are made safe.
- **Programs, scripts, double extensions** (`fatura.pdf.exe`) and names with hidden
  direction characters are named in the plan before anything is written.
- **Archive bombs** stop at a limit the person can raise, and an entry that writes more
  than it declared is cut off and removed.
- **The "from the internet" mark** of a downloaded archive is copied to every file.
- **Smart extraction:** one top folder is used as it is (renamed, not merged, if taken);
  loose files get a folder named after the archive.
- **Names in old ZIPs** are decoded in the code page they were written in (CP857 Turkish,
  CP866, Shift-JIS…), told from the names themselves.
- **Already-compressed files** (JPEG, MP4, ZIP…) are stored, not compressed again.

## Checks

```
cargo test        # the rules, every format both ways, passwords, volumes, attacks, damage,
                  # and the real 7-Zip reading ours and ours reading 7-Zip's when it is installed
```

Licence: `GPL-3.0-or-later` with the EON Module ABI Exception (`LICENSE-EXCEPTION.md`).
