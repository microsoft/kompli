# komplid

This directory holds `komplid`, the planned native kompli agent. It currently
ships only a **placeholder implementation** (see "Current implementation"
below) — real request handling is a separate, follow-up piece of work.

## Status

- Build target exists and produces a real (if placeholder) binary + systemd
  units. Built by default (`-DBUILD_KOMPLID=ON` is now the default; pass
  `-DBUILD_KOMPLID=OFF` to exclude it).
- Current implementation: reads JSONL from its socket-activated connection and
  echoes back a pretty-printed copy of each line. It does **not** interpret,
  validate, or act on the input in any way yet — no engine, no benchmark
  evaluation. This exists to validate the socket-activation wiring end to end
  before the real protocol lands.

## Planned shape (see [docs/architecture.md](../../docs/architecture.md))

- `komplid` will link `complianceenginelib`
  ([src/modules/complianceengine/src/lib](../modules/complianceengine/src/lib))
  and `benchmarkio`
  ([src/modules/complianceengine/src/benchmarkio](../modules/complianceengine/src/benchmarkio))
  — the same benchmark-definition parsing and root-safe input-file checks
  used by the `kompli` CLI
  ([src/modules/complianceengine/src/cli](../modules/complianceengine/src/cli)) —
  rather than duplicating that logic. (The current placeholder only links
  `parsonlib`; these links land with the real implementation.)
- It will read its configuration from `/etc/kompli/` (main config file plus a
  `definitions/` directory of installed benchmark-definition files).
- The `kompli` CLI will gain daemon-awareness (a CLI flag that checks for the
  socket) once this exists; today the CLI always runs the engine in-process.
  See [docs/CLI.md](../../docs/CLI.md) for the canonical CLI contract,
  including the planned per-rule `plan`/`run` model this wire protocol is
  designed to match.

Each of these is a separate, follow-up piece of work.

## Socket activation: started by systemd, `Accept=yes`

`komplid` is started by systemd via socket activation (`komplid.socket` /
`komplid@.service`, socket at `/run/komplid.sock`), never run directly.
**Decided: `Accept=yes`** — systemd accepts each connection itself and spawns
one fresh `komplid` process per connection, with the connection wired to that
process's stdin/stdout. Chosen first because it keeps the initial
implementation simple: no accept loop, no in-process concurrency, no shared
mutable state to reason about — each connection is handled exactly like one
invocation of the `kompli` CLI. This can be revisited for `Accept=no` later if
a persistent warm process becomes worth the added complexity (see the
concurrency-model discussion referenced from
[docs/architecture.md](../../docs/architecture.md) §3).

## Privilege model

`komplid` always runs as root (`User=root`, set explicitly in
`komplid@.service` rather than left to the implicit default) — it's the sole
process that needs root to execute audit/remediate/enforce actions against
the system. The point of the daemon existing is to let a client stop needing
root itself, in exchange for talking to something that already does:

- **System group `kompli`.** A new system user/group. `/etc/kompli/`
  (including `definitions/`) will be owned by it and **read-only for the
  group** (root-owned, root-writable only — the same "non-writable by
  group/others" posture `InputSecurity` already enforces elsewhere in this
  codebase, applied here specifically). This matters: `komplid` runs as root
  and executes payload content straight out of these files, so if a
  `kompli`-group member could *write* there too, that would be a
  privilege-escalation path back to root — group membership must only ever
  grant read access. Membership is what lets the `kompli` CLI read benchmark
  definitions (`list`/`plan`, see [docs/CLI.md](../../docs/CLI.md)) and
  connect to `komplid`'s socket without being root.
  **Packaging**: creating this user/group happens via `.deb`/`.rpm`
  packaging scriptlets - see the "Packaging" section below for what's
  implemented and what's still open.
- **Socket permissions**: `komplid.socket` sets `SocketMode=0660` +
  `SocketGroup=kompli` — connecting requires `kompli` group membership (or
  root), not world access.
- **Defense-in-depth beyond the socket file mode**: `komplid` should also
  verify the connecting peer's credentials via `SO_PEERCRED`
  (`getsockopt(SOL_SOCKET, SO_PEERCRED, ...)`) — kernel-verified uid/gid/pid
  of the actual connected process, independent of and unspoofable relative to
  the socket file's mode. Not yet implemented (the placeholder doesn't
  authorize anything), but decided as a requirement: protects against the
  socket file's permissions being loosened by mistake later, and is the
  natural hook for an audit trail of which user requested what.
- **No role separation.** A single `kompli` group gates all passthrough
  access, regardless of mode (`audit`/`remediate`/the reserved `enforce`).
  Deliberately not split into finer-grained groups (e.g. read-only vs.
  mutating): many audits already need root-level read access in their own
  right (e.g. iterating other users' files, checking root-owned resource
  permissions), so a read/write split at the group level wouldn't produce a
  clean security boundary anyway.
- **No fallback between modes, and no auto-detection.** Standalone mode (no
  daemon involved, the CLI drives the engine directly — today's only mode)
  is the default and always requires root, full stop; there is no
  lower-privilege path through it. Passthrough mode is only entered when the
  caller explicitly passes `--passthrough` (see
  [docs/CLI.md](../../docs/CLI.md) §7) — the CLI never silently prefers the
  daemon just because its socket happens to exist. Once `--passthrough` is
  requested, it requires `kompli` group membership (or root) to connect. If
  the mode actually in effect can't meet its own requirement — e.g.
  `--passthrough` was given but `komplid`'s socket is unreachable, or the
  caller has neither root nor group membership — that must be a clear,
  explicit failure. It must never silently
  degrade into attempting the other mode.

## Logging: stderr by default, descriptor-based rework (roadmap item)

`komplid`'s `StandardOutput=socket` means stdout **is** the wire protocol
stream — any diagnostic logging that ended up there would corrupt it.
`IsDaemon()` (`getppid() == 1`, in `src/common/logging/Logging.c`) already
auto-disables console logging today, and that likely covers real
systemd-spawned instances in practice — but it's an indirect heuristic built
for the old double-forking OSConfig platform daemon, not something
deliberately verified for `komplid`, and it does **not** protect an ad-hoc
invocation for local testing (`komplid < input.jsonl` from a shell, where
`getppid()` isn't 1). `komplid` should log to stderr unconditionally instead
of relying on that heuristic — standard daemon behavior, and something this
fork is now free to do that the upstream OSConfig project wasn't.

Separately, and tracked as its own **roadmap item**: the shared logging
library's `OpenLog()` is path-only (see the "Residual TOCTOU" note in
`src/modules/complianceengine/src/cli/THREAT_MODEL.md`), which is a real,
already-documented TOCTOU gap for `--log-file` — previously accepted as a
permanent limitation because fixing it meant touching a library shared with
every azure-osconfig binary upstream. Now that this is a fork, that
constraint no longer applies: reworking the logging library to a
descriptor-based interface (caller opens/verifies the fd, hands it to the
logger) is in scope and should happen, just not as part of this
design pass — tracked here so it isn't lost.

## Packaging

CPack is already configured for both formats in `src/CMakeLists.txt`
(package metadata, `CPACK_RPM_*`/`CPACK_DEBIAN_*` variables) and references
six scriptlet files plus an RPM changelog under `devops/rpm/` and
`devops/debian/` - until now, those files didn't exist, so building either
package would have failed outright.

- **Implemented**: `devops/rpm/{postinst,preun,postun,changelog}` and
  `devops/debian/{postinst,prerm,postrm}` now exist and cover what's already
  decided: create the `kompli` system group/user (idempotent, no login shell
  or home directory - nothing ever authenticates as this identity, it only
  exists to own files and gate socket access), create `/etc/kompli/definitions/`
  owned `root:kompli` with group-read-only permissions (§ "Privilege model"
  above), enable/start `komplid.socket` on install, stop/disable it only on
  an actual removal (not an upgrade, to avoid an availability blip), and
  deliberately *not* remove the user/group/directory on uninstall (standard
  practice for system service accounts - matches e.g. postgres/nginx-style
  packaging).
- **Not yet covered, deferred until the relevant design settles**:
  - The rest of `/etc/kompli/`'s layout (the main config file, the
    provisional `/var/lib/komplid/komplid.db` task/cache database's
    ownership) isn't finalized yet, so the scriptlets don't touch it.
  - **Cross-repo delivery of benchmark content, decided direction:** this
    repo's package ships `komplid`/`kompli` and an *empty*
    `/etc/kompli/definitions/` directory only - it deliberately does not
    ship any `*.benchmark.json` content, because that content (CIS/STIG
    benchmark text) is externally-sourced, third-party material and
    shouldn't be coupled to this repo's release cadence or licensing.
    Definitions are produced by a separate pipeline (the Compliance
    Augmentation Engine), which today only publishes them as NuGet packages
    (the GC/Azure Policy delivery path). **Planned**: that pipeline gains the
    ability to also build native `.deb`/`.rpm` packages straight from the
    same generated `*.benchmark.json` content - separate from, and installed
    on top of, this repo's `kompli`/`komplid` package - dropping files into
    `/etc/kompli/definitions/` with the ownership/permissions this repo's
    package already established. Preferably signed and upstreamed to PMC
    (Microsoft's `packages.microsoft.com` Linux package repository), the
    same trusted-distribution channel other Microsoft Linux tooling uses.
    This is augmentation-engine-side pipeline work, not implemented in this
    repo - tracked here as the resolution to what was an open question, not
    yet built.
  - Per-distro verification: `devops/docker/` already has build images for
    12 distributions (Debian/Ubuntu and RHEL-family/SUSE), but none of the
    scriptlets above have been exercised against any of them yet.

## State directory: intentionally not yet shared

`komplid` does not yet use a persistent state directory, and neither does the
`kompli` CLI (`CliContext` creates a fresh, ephemeral `/tmp/...` directory per
invocation, removed on exit). **This is expected for now, not an oversight.**
Once the contents and layout of `/etc/kompli/` and the daemon's persistent
state directory (under `/var/lib/`) are stabilized, both `kompli` and
`komplid` will point at a single shared location — deliberately deferred
because the location must be chosen to avoid clashing with GuestConfiguration
(the Azure Automanage Machine Configuration agent), which owns its own
`/var/lib/GuestConfig` (and similar) paths on the same system.

**Exception**: the task registry and audit-result cache (below) are
intrinsically shared, persistent state — they can't be per-invocation
ephemeral by definition, since a later connection/process needs to read what
an earlier one wrote. Until the broader shared-state-directory question is
settled, `komplid` will use a narrow, provisional path of its own
(`/var/lib/komplid/komplid.db`, a single SQLite database) rather than waiting
on that larger decision. This path is provisional and may move once the
broader `/var/lib/` layout is finalized; the `kompli` CLI has no need to read
or write it directly.

## Wire protocol

- **Framing: JSONL (newline-delimited JSON) over the Unix domain socket.**
  Decided. Each request/response is a single JSON value terminated by `\n`.
  This deliberately replaces the old OSConfig-era MPI design (a small
  HTTP/REST layer over UDS, see `src/common/mpiclient/`): parsing HTTP just to
  immediately unwrap a JSON body adds an extra, unnecessary parser (and attack
  surface) in front of a root-privileged daemon for no benefit on a local,
  single-purpose socket. `mpiclient` is not used by `komplid`.
- **Request/response granularity: per-rule.** Decided. A request identifies
  one rule (a `benchmark` + `payloadKey`) and one `mode`
  (`audit` | `remediate` | `enforce`, the last a reserved placeholder — no
  working mechanism yet, deferred, but kept in every contract/roadmap so it's
  never forgotten — see below); the response is that rule's canonical result
  (indicators, status, etc. — the same shape regardless of `mode`). This was
  chosen over sending a whole benchmark, or a map of rule-to-mode overrides,
  in one message:
  - `kompli` reads `/etc/kompli/definitions/` directly (same files `komplid`
    reads), so there's no risk of client/server copies of a benchmark drifting
    apart, and no need to ship a benchmark's worth of JSON over the socket —
    a request is just an identifier tuple.
  - Uniform per-rule granularity makes error reporting simpler (e.g. "rule not
    found") and keeps every response the same shape, instead of needing to
    decide how a mixed-mode batch response should look.
  - `kompli` is expected to gain its own "list benchmarks / rules in a
    benchmark" capability (reading the same directory) so it can enumerate
    what to request; the daemon revalidating a `payloadKey` server-side is
    defense-in-depth (e.g. a TOCTOU if the file changed underneath), not the
    primary error-reporting path.
  - **`payloadKey`, not `ruleId`.** `ruleId` is a checksum *of* the payload
    key, kept in the canonical result purely for external conformance (some
    consumers already key off it) — it carries no information `payloadKey`
    doesn't already have, so nothing internal (wire requests, the plan file,
    the task registry, the audit cache) needs to reference it. Only
    `payloadKey` is used internally. **Code note**: `BenchmarkIO::Resource`
    currently discards the raw `payloadKey` after parsing it into
    `benchmarkInfo` (see `Resource.hpp`) — it needs to retain it verbatim
    before any of this can be implemented.
- **Connection scope: one connection per session, many sequential
  requests.** Decided. `Accept=yes` spawns one process per *connection*, not
  per request — so a whole benchmark run is one connection carrying many
  sequential per-rule request/response pairs, not one connection per rule
  (which would mean hundreds of fork/execs for a large benchmark). The
  placeholder implementation already loops over multiple JSONL lines per
  connection, so this needs no structural change.
- **Response envelope: a starter draft.** Every response (not just
  successful rule results) needs a common shape so a client can tell them
  apart, including asynchronous task-completion pushes interleaved with
  ordinary responses on the same connection. Draft, not finalized — a real
  JSON schema comes later, once this settles (tracked as a TODO):

  ```jsonc
  // Request: requestId is client-assigned (e.g. an incrementing counter),
  // used to correlate a response (including a later, asynchronous task-done
  // push) back to the request that triggered it. parameters is optional -
  // omitted or empty means "use this rule's defaults" (see docs/CLI.md's
  // "Parametrization" section - kompli/komplid fold in the parameter
  // overrides GC/NRP already supports, via the plan file).
  { "requestId": "1", "benchmark": "cis_ubuntu24.04", "payloadKey": "...", "mode": "audit", "parameters": {} }

  // Responses all share {type, requestId}; shape beyond that depends on type:
  { "type": "result",     "requestId": "1", "result": { /* canonical per-rule result */ } }
  { "type": "task",       "requestId": "1", "taskId": "..." }              // ack: running in background
  { "type": "taskResult", "requestId": "1", "taskId": "...", "result": {} } // async push when done
  { "type": "taskStatus", "requestId": "1", "taskId": "...", "status": "pending"|"running"|"done" } // reply to a "check task" request
  { "type": "error",      "requestId": "1", "code": "...", "message": "..." }
  ```

  The `error` type is what a malformed request, an unknown `benchmark`, a
  `payloadKey` that fails server-side revalidation, or an internal failure
  produces — distinct from a rule that ran fine and reported `NonCompliant`,
  which is a normal `result`, not an error. Exact `code` taxonomy: **not yet
  decided**, tracked as a TODO alongside the rest of this envelope.
- **Message schema: still a draft, not finalized.** The placeholder
  implementation sidesteps this entirely by not interpreting the input at
  all. Treat everything above as provisional until a real JSON schema exists
  for it (deferred — planning should finish settling first).

## Long-running rules: background tasks

Some rules are slow (e.g. a cold package-manager query or filesystem scan).
Rather than block the connection for the duration, a slow rule's response can
be a task ID instead of an immediate result, with the actual work continuing
in the background:

- **Precedent, not a new mechanism.** `FilesystemScanner::BackgroundScan()`
  (`src/modules/complianceengine/src/lib/FilesystemScanner.cpp`) already
  forks a child to do slow work independently of the parent's lifetime,
  writing its result via lock + atomic rename. The task model generalizes
  this existing, proven pattern rather than inventing a new one.
- **Task registry: the SQLite database above** (`task_id`, rule, mode,
  status, result, timestamps). Required because the process that later polls
  or reconnects for a task's result is very likely a *different* forked
  `komplid` instance than the one that started it.
- **Which rules become tasks: leaning toward a static map, not a runtime
  watchdog.** Proposed direction (not fully settled): rather than a generic
  wall-clock timeout wrapping every rule, maintain a curated,
  compile-time/config-time list of rules or procedures already known to be
  slow (e.g. `PackageInstalled` on a cold cache, filesystem-scan-dependent
  procedures) that opt into backgrounding; everything else runs
  synchronously by default.
- **Duplicate concurrent requests: attach to the existing task.** Decided
  direction: if a request for the same `(benchmark, payloadKey, mode)` arrives
  while a task for it is already in flight, attach the new request to the
  existing task (return/correlate to its `taskId`) rather than starting a
  second one — avoids redundant work, and for `remediate` specifically avoids
  re-opening the "must not run concurrently" problem the remediation lock
  exists to close. **Open, deferred to a future planning session**: this is
  exactly where parametrization (see `docs/CLI.md`) bites — rules can be
  parametrized, so two requests for the same `(benchmark, payloadKey, mode)`
  could carry *different* `parameters`, in which case they are not actually
  the same request and naively attaching would be wrong. Dedup needs to
  compare `parameters` too, not just `(benchmark, payloadKey, mode)`. Needs
  its own design pass once the daemon-split work resumes — tracked as a
  TODO, not solved here.
- **Delivery: push while connected, pull if not.** The connection-owning
  process forks the background worker, then keeps servicing that same
  connection — reading further rule requests *and* watching for its own
  child's completion — via `select()` on the client socket together with a
  way to detect child completion (e.g. `SIGCHLD` / a self-pipe), rather than
  simple timed polling. When a background task finishes, it pushes an
  unsolicited `taskResult` line (see the envelope draft above) down the same
  connection, interleaved with ordinary responses. If the client disconnected
  before that happened, the detached child still finishes and persists its
  result to the registry; a later connection (the same client or a different
  one) retrieves it with a "check task `<id>`" request against the same
  registry.
- **Remediation locking still applies.** A backgrounded `remediate`/`enforce`
  task still has to take the cross-process remediation lock (the planned
  `FileLock` extraction — see the concurrency notes on remediation
  serialization) for its duration; backgrounding a task doesn't relax that
  requirement.
- **Not yet decided**: task expiry/cleanup policy, and how `enforce`'s
  fundamentally different lifecycle (start/keep-running/stop, not
  start/finish) maps onto this same task concept — plausible that it reuses
  the mechanism (a task that stays "running" until explicitly stopped instead
  of reaching a terminal state), but that needs its own design pass before
  committing to it.

## Result caching

- **Audit results only.** Decided. `remediate` and `enforce` always execute
  for real and are never served from a cache — the caller needs confirmation
  the action ran *this time*.
- **Storage: the same SQLite database**, keyed by rule **and its
  parameters** (`benchmark` + `payloadKey` + `parameters`) — not just
  `(benchmark, payloadKey)`. Two audits of the same rule with different
  parameter overrides (e.g. checking for a different package name) can
  legitimately produce different results, so they must not share a cache
  entry. Storing the last audit result and its timestamp.
- **Behavior**: an audit request checks the cached entry's age against a
  (configurable) TTL. Within the TTL, return the cached result immediately
  without re-evaluating. Once expired, drop the entry and re-evaluate system
  state as normal.
- **Invalidation on remediation.** A successful `remediate` for a rule must
  invalidate (or overwrite) that rule's cached audit entry — otherwise a
  subsequent audit could report stale `NonCompliant` for up to the TTL window
  *after* the rule was actually fixed, which is worse than not caching at all.
- **Not yet decided**: the default TTL value, the exact request-level knob to
  force a fresh evaluation (bypassing the cache), and whether the TTL is
  global or configurable per rule/benchmark.
