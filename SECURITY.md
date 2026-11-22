<!--
SPDX-License-Identifier: GPL-3.0-or-later
SPDX-FileCopyrightText: 2026 EON contributors
-->

# Security

Report privately through GitHub's **Security → Report a vulnerability** on this
repository; the organisation-wide policy is
[`.github/SECURITY.md`](https://github.com/EON-Extensible-Open-Network/.github/blob/main/SECURITY.md).

An archiver opens files from strangers. Both 7-Zip and WinRAR have had archives write
outside the chosen folder and drop Windows' "from the internet" mark, and those flaws were
used against people. EON Zip's rules, each tested in `tests/roundtrip.rs`:

- **One function decides where an entry goes** (`safe::entry_path`); every format uses it
  and nothing can turn it off. Absolute paths, drive letters, UNC paths, `..` (also with
  the trailing dots and spaces Windows drops) are refused; device names and characters
  Windows cannot hold are made safe.
- **Links in archives are not created**, and a folder already on disk that leads outside
  the target is not written through.
- **An entry cannot write more than it declares**, and an extraction stops at a size limit
  unless the person agrees to more.
- **The "from the internet" mark** is copied from the archive to every file written.
- **Programs and disguised names** are listed before anything is written.
- **A result is written under a working name** and renamed when whole; a failed or
  stopped operation leaves nothing behind.

## Known

- Creating archives does not follow symbolic links, and does not store them yet.
- Builds are not signed (no keys yet; plan madde 30, 34).
