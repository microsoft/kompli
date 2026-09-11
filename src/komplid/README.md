# komplid

This directory holds `komplid`, the native kompli agent. It speaks a
synchronous JSONL audit/remediate protocol against the shared `Engine` (the
same one the `kompli` CLI uses) — see "Design overview" below for what it
covers, and the open design questions still ahead.

## Design overview

- Split into `komplid-lib` (peer auth, wire protocol, request dispatch) and
  the `komplid` executable, so `komplid-tests` links the same object code
  without duplicating it (mirrors the CLI's `kompli-cli-lib`/
  `kompli-cli-tests` split). Built via the `-DBUILD_KOMPLID` CMake option.
- Authenticates the connecting peer via `SO_PEERCRED` (see "Privilege model"
  below), then reads bounded (≤1 MiB) JSONL lines from its socket-activated
  connection and runs each one **synchronously** through the same `Engine`
  the `kompli` CLI uses, in `audit`/`remediate` mode, against benchmark
  definitions under `/etc/kompli/definitions`. Each response is one JSONL
  line: a `result` or `error` envelope (see "Wire protocol" below for the
  exact fields).
- `enforce` mode is a reserved value that parses but is rejected with
  `unsupported_mode` (see §3 of
  [docs/architecture.md](../../docs/architecture.md)) — no execution backend
  exists for it. Background tasks / the SQLite task registry, result
  caching, and `--passthrough` forwarding are separate design layers,
  described below.

## Linkage & configuration (see [docs/architecture.md](../../docs/architecture.md))

- `komplid` links `complianceenginelib`
  ([src/modules/complianceengine/src/lib](../modules/complianceengine/src/lib))
  and `benchmarkio`
  ([src/modules/complianceengine/src/benchmarkio](../modules/complianceengine/src/benchmarkio))
  — the same benchmark-definition parsing and root-safe input-file checks
  used by the `kompli` CLI
  ([src/modules/complianceengine/src/cli](../modules/complianceengine/src/cli)) —
  rather than duplicating that logic.
- Benchmark definitions are read from a fixed, non-configurable
  `/etc/kompli/definitions` (see `Main.cpp`) — deliberately not overridable
  via an environment variable or flag, since that would defeat the point of
  it being a root-owned, trusted directory. The separate `/etc/kompli/`
  main config file for behavioral knobs beyond the definitions path is
  `/etc/kompli/kompli.conf` (JSON; `root:kompli` `0640`) — its schema and load
  semantics are the contract in [docs/configuration.md](../../docs/configuration.md).
- The `kompli` CLI gains daemon-awareness via `--passthrough` (a CLI flag
  that checks for the socket); without it, the CLI runs the engine
  in-process. See [docs/cli.md](../../docs/cli.md) for the CLI contract,
  including the per-rule `plan`/`run` model this wire protocol is designed
  to match.

## Socket activation: started by systemd, `Accept=yes`

`komplid` is started by systemd via socket activation (`komplid.socket` /
`komplid@.service`, socket at `/run/komplid.sock`), never run directly with
**`Accept=yes`** — systemd accepts each connection itself and spawns
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
  definitions (`list`/`plan`, see [docs/cli.md](../../docs/cli.md)) and
  connect to `komplid`'s socket without being root.
  **Packaging**: creating this user/group happens via `.deb`/`.rpm`
  packaging scriptlets - see the "Packaging" section below for the scriptlet
  design.
- **Socket permissions**: `komplid.socket` sets `SocketMode=0660` +
  `SocketGroup=kompli` — connecting requires `kompli` group membership (or
  root), not world access.
- **Defense-in-depth beyond the socket file mode**: `komplid` also
  verifies the connecting peer's credentials via `SO_PEERCRED`
  (`getsockopt(SOL_SOCKET, SO_PEERCRED, ...)`) — kernel-verified uid/gid/pid
  of the actual connected process, independent of and unspoofable relative to
  the socket file's mode. This is a requirement, not just a nice-to-have:
  protects against the socket file's permissions being loosened by mistake
  later, and is the natural hook for an audit trail of which user requested
  what.
- **No role separation.** A single `kompli` group gates all passthrough
  access, regardless of mode (`audit`/`remediate`/the reserved `enforce`).
  Deliberately not split into finer-grained groups (e.g. read-only vs.
  mutating): many audits already need root-level read access in their own
  right (e.g. iterating other users' files, checking root-owned resource
  permissions), so a read/write split at the group level wouldn't produce a
  clean security boundary anyway.
- **No fallback between modes, and no auto-detection.** Standalone mode (no
  daemon involved, the CLI drives the engine directly) is the default and
  always requires root, full stop; there is no
  lower-privilege path through it. Passthrough mode is only entered when the
  caller explicitly passes `--passthrough` (see
  [docs/cli.md](../../docs/cli.md) §7) — the CLI never silently prefers the
  daemon just because its socket happens to exist. Once `--passthrough` is
  requested, it requires `kompli` group membership (or root) to connect. If
  the mode actually in effect can't meet its own requirement — e.g.
  `--passthrough` was given but `komplid`'s socket is unreachable, or the
  caller has neither root nor group membership — that must be a clear,
  explicit failure. It must never silently
  degrade into attempting the other mode.

## Logging: stderr by default

`komplid`'s `StandardOutput=socket` means stdout **is** the wire protocol
stream — any diagnostic logging that ended up there would corrupt it.
Console logging (stderr) is unconditional: the shared logging library has no
`IsDaemon()` (`getppid() == 1`) heuristic gating
`IsConsoleLoggingEnabled()` — such a heuristic would be built for the old
double-forking OSConfig platform daemon, not something verified for
`komplid`, and would also misfire for the standalone CLI in some
containerized CI environments (where kompli runs as a direct child of
PID 1). `komplid` (and every other kompli entry point) logs to stderr
unconditionally — standard daemon behavior.

The shared logging library's `OpenLog()`-based TOCTOU gap (see
the former "Residual TOCTOU" note in
`src/modules/complianceengine/src/cli/THREAT_MODEL.md`) is closed by
elimination rather than by a descriptor-based rework — the `kompli` CLI has
no `--log-file` flag (the only consumer of that path), and the NRP module
logs to `syslog(3)` instead of a fixed-path `OpenLog()`.
See [docs/logging.md](../../docs/logging.md) for the full design. The
descriptor-based `OpenLog` rework is therefore not needed: there is no
operator-supplied log path to harden.

## Packaging

CPack is configured for both formats in `src/CMakeLists.txt`
(package metadata, `CPACK_RPM_*`/`CPACK_DEBIAN_*` variables), referencing
scriptlets under `devops/rpm/` and `devops/debian/`.

- **Scriptlets** (`devops/rpm/{postinst,preun,postun,changelog}`,
  `devops/debian/{postinst,prerm,postrm}`) create the `kompli` system
  group/user (idempotent, no login shell or home directory - nothing ever
  authenticates as this identity, it only exists to own files and gate
  socket access), create `/etc/kompli/` (+ `definitions/`, `kompli.conf`)
  and `/var/lib/komplid/` with the ownership/modes in
  [docs/configuration.md](../../docs/configuration.md) and its
  feature-scoped filesystem/privilege contract
  (§ "Privilege model" above), enable/start `komplid.socket` on install,
  stop/disable it only on an actual removal (not an upgrade, to avoid an
  availability blip), and deliberately *not* remove the user/group/directory
  on uninstall (standard practice for system service accounts - matches
  e.g. postgres/nginx-style packaging).
- **Cross-repo delivery of benchmark content:** this repo's package ships
  `komplid`/`kompli` and an *empty* `/etc/kompli/definitions/` directory
  only - it deliberately does not ship any `*.benchmark.json` content,
  because that content (benchmark text for each supported framework) is
  externally-sourced, third-party material and shouldn't be coupled to this
  repo's release cadence or licensing. Definitions are produced by a
  separate pipeline (the definitions generator), which publishes them as
  NuGet packages (the GC/Azure Policy delivery path) and is meant to also
  build native `.deb`/`.rpm` packages straight from the same generated
  `*.benchmark.json` content - separate from, and installed on top of, this
  repo's `kompli`/`komplid` package - dropping files into
  `/etc/kompli/definitions/` with the ownership/permissions this repo's
  package establishes. Preferably signed and upstreamed to PMC (Microsoft's
  `packages.microsoft.com` Linux package repository), the same
  trusted-distribution channel other Microsoft Linux tooling uses. This is
  the definitions generator's own pipeline work, not this repo's.
- Per-distro verification: `devops/docker/` has build images for 12
  distributions (Debian/Ubuntu and RHEL-family/SUSE) to exercise the
  scriptlets against.

## State directory

`komplid` and the `kompli` CLI each use their own ephemeral per-invocation
temp directory (`CliContext` creates a fresh `/tmp/...` directory, removed
on exit) rather than a shared persistent state directory — the location
must be chosen to avoid clashing with GuestConfiguration (the Azure
Automanage Machine Configuration agent), which owns its own
`/var/lib/GuestConfig` (and similar) paths on the same system.

**Exception**: the task registry and audit-result cache (below) are
intrinsically shared, persistent state — they can't be per-invocation
ephemeral by definition, since a later connection/process needs to read what
an earlier one wrote. `komplid` uses its own root-only state path
(`/var/lib/komplid/komplid.db`, a single SQLite database, `root:root` `0600`)
— see [docs/configuration.md](../../docs/configuration.md) — chosen under
`/var/lib/komplid/` rather than `/var/lib/GuestConfig` to avoid clashing
with GuestConfiguration; the `kompli` CLI has no need to read or write it
directly.

## Wire protocol

- **Framing: JSONL (newline-delimited JSON) over the Unix domain socket.**
  Each request/response is a single JSON value terminated by `\n`.
  This replaces the old OSConfig-era MPI design (a small
  HTTP/REST layer over UDS, see `src/common/mpiclient/`): parsing HTTP just to
  immediately unwrap a JSON body adds an extra, unnecessary parser (and attack
  surface) in front of a root-privileged daemon for no benefit on a local,
  single-purpose socket. `mpiclient` is not used by `komplid`.
- **Request/response granularity: per-rule.** A request identifies
  one rule (a `benchmark` + `id`) and one `mode`
  (`audit` | `remediate` | `enforce`, the last a reserved placeholder — no
  execution backend, kept in every contract so it's never forgotten — see
  below); the response is that rule's canonical result
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
    what to request; the daemon revalidating an `id` server-side is
    defense-in-depth (e.g. a TOCTOU if the file changed underneath), not the
    primary error-reporting path.
  - **`id`, not `ruleId`.** `ruleId` is a checksum *of* the payload
    key, needed only by external consumers reconstructing the pre-unification
    MOF/Azure-Policy identity (some already key off it) — it carries no
    information `id` doesn't already have, so nothing internal (wire
    requests, the plan file, the task registry, the audit cache) needs to
    reference it. kompli's own JSON contracts (definition schema, canonical
    result schema, `Resource`) don't carry `ruleId` — see
    [docs/payload-key-format.md §12](../../docs/payload-key-format.md#12-id-not-ruleid-in-komplis-own-schema).
    Only `id` is used internally. `BenchmarkIO::Resource` retains `id`
    verbatim (see `Resource.hpp`), as the opaque remainder only (the
    hoisted file-level prefix lives on `BenchmarkDocument::benchmarkInfo`
    instead — see
    [docs/payload-key-format.md §3](../../docs/payload-key-format.md#3-unified-definition-file-hoisted-prefix-kompli-side-only--see-10)).
- **Connection scope: one connection per session, many sequential
  requests.** `Accept=yes` spawns one process per *connection*, not
  per request — so a whole benchmark run is one connection carrying many
  sequential per-rule request/response pairs, not one connection per rule
  (which would mean hundreds of fork/execs for a large benchmark).
- **Response envelope: a starter draft.** Every response (not just
  successful rule results) needs a common shape so a client can tell them
  apart, including asynchronous task-completion pushes interleaved with
  ordinary responses on the same connection. Draft, not finalized — a real
  JSON schema comes later, once this settles (tracked as a TODO):

  ```jsonc
  // Request: requestId is client-assigned (e.g. an incrementing counter),
  // used to correlate a response (including a later, asynchronous task-done
  // push) back to the request that triggered it. parameters is optional -
  // omitted or empty means "use this rule's defaults" (see docs/cli.md's
  // "Parametrization" section - kompli/komplid fold in the parameter
  // overrides GC/NRP already supports, via the plan file).
  { "requestId": "1", "benchmark": "frameworkA_ubuntu24.04", "id": "...", "mode": "audit", "parameters": {} }

  // Responses all share {type, requestId}; shape beyond that depends on type:
  { "type": "result",     "requestId": "1", "result": { /* canonical per-rule result */ } }
  { "type": "task",       "requestId": "1", "taskId": "..." }              // ack: running in background
  { "type": "taskResult", "requestId": "1", "taskId": "...", "result": {} } // async push when done
  { "type": "taskStatus", "requestId": "1", "taskId": "...", "status": "pending"|"running"|"done" } // reply to a "check task" request
  { "type": "error",      "requestId": "1", "code": "...", "message": "..." }
  ```

  The `error` type is what a malformed request, an unknown `benchmark`, an
  `id` that fails server-side revalidation, or an internal failure
  produces — distinct from a rule that ran fine and reported `NonCompliant`,
  which is a normal `result`, not an error. Exact `code` taxonomy: an open
  question, tracked alongside the rest of this envelope.
- **Message schema.** The request shape (`requestId`, `benchmark`, `id`,
  `mode`, optional `parameters`) and the `result`/`error` response envelopes
  above are specified in `Protocol.hpp`/`.cpp`. The
  `task`/`taskResult`/`taskStatus` envelope types remain a draft, pending
  the background-tasks design settling (see "Long-running rules" below).

## Long-running rules: background tasks

Some rules are slow (e.g. a cold package-manager query or filesystem scan).
Rather than block the connection for the duration, a slow rule's response can
be a task ID instead of an immediate result, with the actual work continuing
in the background:

- **Precedent, not a new mechanism.** `FilesystemScanner::BackgroundScan()`
  (`src/modules/complianceengine/src/lib/FilesystemScanner.cpp`) forks a
  child to do slow work independently of the parent's lifetime, writing its
  result via lock + atomic rename. The task model generalizes this existing
  pattern rather than inventing a new one.
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
- **Duplicate concurrent requests: attach to the existing task.** If a
  request for the same `(benchmark, id, mode)` arrives
  while a task for it is already in flight, attach the new request to the
  existing task (return/correlate to its `taskId`) rather than starting a
  second one — avoids redundant work, and for `remediate` specifically avoids
  re-opening the "must not run concurrently" problem the remediation lock
  exists to close. **Open question**: this is
  exactly where parametrization (see `docs/cli.md`) bites — rules can be
  parametrized, so two requests for the same `(benchmark, id, mode)`
  could carry *different* `parameters`, in which case they are not actually
  the same request and naively attaching would be wrong. Dedup needs to
  compare `parameters` too, not just `(benchmark, id, mode)` — needs
  its own design pass, not solved here.
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

- **Audit results only.** `remediate` and `enforce` always execute
  for real and are never served from a cache — the caller needs confirmation
  the action ran *this time*.
- **Storage: the same SQLite database**, keyed by rule **and its
  parameters** (`benchmark` + `id` + `parameters`) — not just
  `(benchmark, id)`. Two audits of the same rule with different
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
