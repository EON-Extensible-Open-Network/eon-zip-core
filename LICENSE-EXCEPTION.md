# EON Module ABI Exception

**Version 1.0 — 2026-09-25, as applied to EON Download Manager on 2026-11-20**
**Status: DRAFT.** This text has not yet been reviewed by a lawyer. See madde 13 and
madde 33 of the project plan (`eon-docs/plan/eon-plan.md`). Do not rely on it as legal
advice.

This is the same exception that `eon-stream-core`, `eon-stream-engine` and `eon-stream-app`
carry. It is an umbrella-level text (madde 42b); the only thing that differs per product
family is **which published interface is the boundary**, named in condition 1.

---

## Additional permission under GNU GPL version 3 section 7

The copyright holders of this Program grant you the following additional permission,
as provided by section 7 of the GNU General Public License version 3.

You have permission to combine this Program with **Independent Modules**, and to convey
the resulting combined work, distributing the Independent Modules under terms of your
own choosing — including terms that are not compatible with the GNU GPL — provided that
all of the following conditions are met:

1. **Defined boundary.** The Independent Module communicates with this Program
   *exclusively* through the **EON Download Manager hand-off and resume-state formats**, as
   published in the `eon-download-manager-spec` repository (`docs/handoff.md`,
   `docs/resume-state.md`, `schemas/*.v0.schema.json`) at a released version. Communication through
   any other interface — direct linking against this Program's internal symbols,
   inclusion of its source, use of its private data structures, or patching its build —
   is outside this permission.

2. **No derivation.** The Independent Module does not contain, copy, or derive from
   source code of this Program, other than the interface declarations published in
   `eon-download-manager-spec`, which are licensed separately under Apache-2.0.

3. **GPL still applies to this Program.** You continue to comply with the GNU GPL in
   full for this Program itself, including the obligation to convey its Corresponding
   Source when you convey the combined work.

4. **No implied grant over other components.** This permission covers only the
   combination described above. It grants no rights in this Program beyond that, and
   grants nothing at all in third-party components this Program depends on (see
   `NOTICE`).

If you modify this Program, you may extend this exception to your modified version,
but you are not obliged to. If you do not wish to extend it, delete this statement
from your version.

---

## Why this exception exists here

A browser extension or a script that hands downloads over through the published hand-off
is a separate program, and the GPL does not reach it whatever this file says. The exception
matters for the day something runs *inside* the program — a protocol handler, a
post-processing step — which madde 4's sandbox rules do not allow yet. It is granted now, at the first commit, because contributions are
accepted under the DCO and every contributor keeps their copyright: adding it later would
need every contributor's agreement.

## SPDX

There is no registered SPDX identifier for this exception. Source files use:

```
// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 EON contributors
//
// Additional permission under GNU GPL version 3 section 7:
// see LICENSE-EXCEPTION.md (EON Module ABI Exception 1.0).
```
