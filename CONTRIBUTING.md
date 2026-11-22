<!--
SPDX-License-Identifier: GPL-3.0-or-later
SPDX-FileCopyrightText: 2026 EON contributors
-->

# Contributing to EON Zip core

The organisation-wide guide,
[`.github/CONTRIBUTING.md`](https://github.com/EON-Extensible-Open-Network/.github/blob/main/CONTRIBUTING.md),
applies: DCO sign-off (`git commit -s`), Conventional Commits (`feat(zip): ...`,
`fix(safe): ...`). By contributing you license your work under `GPL-3.0-or-later` with the
EON Module ABI Exception.

- **Every write goes through `safe::entry_path`** and `Archive::plan`. A new format adds a
  reader, never a second way to decide paths.
- **A new format comes with a round trip** in `tests/roundtrip.rs`, and with the real
  7-Zip reading it where 7-Zip can.
- **A security fix comes with the archive that broke it**, as a test.
- **`eon-docs/zip/parity.md` is updated in the same change** when a capability arrives.
- A library, never a window: no GUI dependency, no listening socket. No telemetry.
