<!--
SPDX-License-Identifier: GPL-3.0-or-later
SPDX-FileCopyrightText: 2026 EON contributors
-->

# Changelog

## v0.0.0 — 22 November 2026

The first version (plan madde 49): 7z, ZIP, the tar family and single compressed files,
made and read; volumes; tests; hashes; conversion; and the safety rules in `src/safe.rs`.

Found while testing: 7-Zip refuses a ZIP password with any letter outside ASCII (`ğ`, `é`).
`portable_zip_password` says so, so the window can suggest 7z or English letters.
