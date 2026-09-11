# kompli / komplid configuration (`/etc/kompli/kompli.conf`)

The single main configuration file for `komplid` (and any future `kompli` CLI
settings) is `/etc/kompli/kompli.conf`. This document is its **living contract**:
the format is fixed, the key set grows as milestones land. The filesystem
placement, ownership, and the security invariants around it are fixed by
[ADR-0004](../../docs/unified-definitions/adr/ADR-0004-komplid-filesystem-privilege-contract.md)
(feature-scoped) — this file only documents the *schema* of the file's contents.

> Path resolution note: the ADR link above resolves inside a feature workspace,
> where the `docs` repo is checked out alongside this one. It is not expected to
> resolve in a standalone `kompli` checkout.

## Location, ownership, permissions

- **Path:** `/etc/kompli/kompli.conf` (fixed; not overridable by flag or env).
- **Owner / mode:** `root:kompli`, `0640` — root-writable only, group-readable,
  never group-writable (the same posture as the rest of `/etc/kompli/`).

## Format

- **JSON**, parsed with the same `nlohmann/json` already used across
  `benchmarkio`/`Engine`. No new config-format parser is introduced in front of
  the root daemon (mirrors the wire-protocol decision to avoid an HTTP layer).
- **Versioned envelope** for forward compatibility:

  ```json
  {
    "apiVersion": "v1",
    "kind": "KompliConfig"
  }
  ```

- **Load semantics:**
  - **Absent file** → `komplid` starts with built-in defaults.
  - **Present but malformed** (invalid JSON, unknown `apiVersion`/`kind`, or a
    value failing validation) → `komplid` **refuses to start** with an explicit
    error. It never silently falls back to defaults on a malformed file.

## Security invariant — behavioral knobs only

`kompli.conf` carries **behavioral tuning only**. Trust-boundary paths — the
definitions directory (`/etc/kompli/definitions/`), the socket
(`/run/komplid.sock`), the state directory (`/var/lib/komplid/`), and the
database (`/var/lib/komplid/komplid.db`) — are compile-time constants and are
**not** configurable here. This bounds what a config-file compromise can achieve:
it can never redirect the root daemon at an attacker-controlled definitions tree
or database. Any proposed new key that would relocate or widen a trust boundary
must be rejected here and reconsidered as an ADR instead.

## Keys

### `v1` — current

The initial `v1` schema defines only the envelope (`apiVersion`, `kind`). No
behavioral keys are stabilized yet; `komplid`'s current synchronous core (M-5)
needs none. Keys are added below as their owning milestone lands.

### Planned (added when the owning milestone lands)

These are **reserved** — documented for direction, not yet implemented. Names,
shapes, and defaults are provisional until their milestone stabilizes them.

- **M-15 — background tasks.** The static list of slow rules/procedures that opt
  into backgrounding (everything else runs synchronously):

  ```jsonc
  {
    "backgroundTasks": {
      "rules": []          // provisional: rule ids or procedure names, TBD
    }
  }
  ```

- **M-16 — audit-result cache.** The audit-cache time-to-live and related knobs:

  ```jsonc
  {
    "auditCache": {
      "ttlSeconds": 0      // provisional: default value TBD in M-16
    }
  }
  ```

Each planned block is added to this document (with a stabilized default and
validation rules) by the milestone that implements it, and removed from
"Planned" once shipped under `v1`.
