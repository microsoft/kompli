# kompli / komplid configuration (`/etc/kompli/kompli.conf`)

The single main configuration file for `komplid` (and any future `kompli` CLI
settings) is `/etc/kompli/kompli.conf`. This document is its design contract:
the format is fixed, the key set grows over time. The filesystem
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

- **JSON**, parsed with `parson` (the same JSON library the wire protocol
  itself uses - see `Protocol.cpp` - and every other JSON-handling piece of
  `komplid`). No new config-format parser, or a second JSON library, is
  introduced in front of the root daemon.
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

### `v1`

| Key | Type | Default | Meaning |
|---|---|---|---|
| `auditCache.ttlSeconds` | integer, `>= 0` | `300` | How long a cached `audit` result is served without re-evaluating the rule (see "Result caching" in [src/komplid/README.md](../src/komplid/README.md#result-caching)). `0` disables caching. Global only — not yet per-rule/benchmark. A request-level override to force a fresh evaluation exists too, but as a wire-protocol field (`forceRefresh` on the request itself, not a config key — see the README link above). |
| `backgroundTasks.rules` | array of strings | `[]` | The static opt-in list of rule ids that run in the background instead of synchronously (see "Long-running rules: background tasks" in [src/komplid/README.md](../src/komplid/README.md#long-running-rules-background-tasks)). Empty by default — no rule backgrounds until an operator opts it in here. |

```jsonc
{
  "apiVersion": "v1",
  "kind": "KompliConfig",
  "auditCache": { "ttlSeconds": 300 },
  "backgroundTasks": { "rules": [] }
}
```
