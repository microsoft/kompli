# kompli — Logging

Design decision and reference for where kompli's diagnostic logging goes, and why.
Written before implementation; the code changes it describes land in a follow-up.

## Model

kompli runs in several scenarios. The log **sink** is chosen by one question: does
kompli own a process with a clean stderr of its own, or is it running under the
configuration agent? **No log file is opened by path in any of them.**

| Scenario | What it is | Sink |
|----------|-----------|------|
| **Standalone** | an operator runs the `kompli` CLI (`audit`/`remediate`/`render`) directly | **stderr** |
| **komplid** (daemon) | the systemd socket-activated service (`src/komplid/`) | **stderr** — its unit routes stderr to the journal |
| **Passthrough** | the configuration agent invokes the `kompli` binary on demand (a request “passed through” to a fresh invocation) | **system log** via `syslog(3)` |
| **NRP** (Machine Configuration) | the `.so` adapter (`OsConfigResource.c` / `ComplianceEngineModule.c`) loaded **in-process** by the GC worker | **system log** via `syslog(3)` |

**Governing rule:** log to **stderr** when kompli owns the process (standalone CLI,
komplid) and to **`syslog(3)`** when it runs under the agent (passthrough, and the
in-process NRP), where its own stderr is not an independent channel.

The canonical result JSON is the CLI's **stdout** payload; diagnostics must never
share that stream — hence stderr or syslog, never stdout.

## Background — why this changed

- The shared logging macro historically wrote console output with `printf`, i.e. to
  **stdout**. A `kompli audit` with no `--log-file` therefore interleaved `[INFO]…`
  lines into the result JSON.
- `--log-file` was originally added **only** to escape that stdout clobbering — a
  workaround, not a feature in its own right.
- **Fix (done):** the console macro now writes to **stderr**
  (`__LOG__` → `fprintf(stderr, …)` in `src/common/logging/Logging.h`). stdout is now
  clean, which removes the original reason `--log-file` existed.

## How the logs reach the system log (mechanics)

Two *different* mechanisms are in play, and journald can ingest both — this is why
different scenarios pick different sinks.

- **stderr** is just a file descriptor (fd 2). kompli writes bytes to it; *where they
  land* is decided by whoever launched the process — a terminal, a redirect
  (`kompli audit f.json 2> run.log`), or, for a **systemd service**, the journal
  (systemd sets `StandardError=journal` by default). kompli doesn't “connect” to
  anything; it emits and lets the environment route.
- **`syslog(3)`** is an explicit IPC call: `openlog()` + `syslog(priority, …)` sends a
  structured datagram to the `/dev/log` socket the system log daemon listens on. It
  reaches the system log the same way regardless of how the process was started —
  which is exactly why agent-driven / in-process code uses it.

On a systemd host the daemon is **systemd-journald**. It listens on both inputs and
stores everything in a **binary journal** (`/var/log/journal/` when persistent, else
`/run/log/journal/`) that it rotates and size-caps itself (`journald.conf`) — read
with `journalctl` (e.g. `journalctl -t kompli`). If `rsyslog`/`syslog-ng` is also
installed, journald forwards to it and the classic plaintext files
(`/var/log/syslog`, `/var/log/messages`) appear as well.

```mermaid
flowchart LR
  SE["kompli stderr (standalone / komplid)"] -->|run as a systemd unit| J[systemd-journald]
  SE -.->|interactive or redirected| TERM["terminal / redirect file"]
  SL["kompli syslog() (passthrough / NRP)"] -->|/dev/log| J
  J --> BJ[("binary journal — journalctl -t kompli")]
  J -. forwards .-> RS["rsyslog (optional) — /var/log/syslog"]
```

So **kompli opens and manages no plaintext logfile in any scenario**:

- standalone / komplid emit to **stderr** — the terminal, a redirect, or (running as
  a unit) the journal owns it;
- passthrough / NRP call **`syslog()`** — **journald** (systemd) owns the storage,
  rotation, and retention. There is no file we `tail`; you query the journal.

**Why not stderr everywhere?** The **NRP** adapter is a shared library loaded *inside
the agent's process*, so its stderr **is the agent's** — a channel kompli neither
owns nor can rely on (it may be discarded or interleaved with the agent's own
output). `syslog()` is self-contained: it always reaches the system log, tagged with
kompli's own ident, independent of the host process. The same reasoning applies to
passthrough, where kompli is launched by the agent rather than an interactive shell.

## Decisions

1. **Console logging → stderr.** *(Implemented.)* Diagnostics never touch stdout.
2. **Standalone default → stderr.** No file by default; operators redirect
   (`kompli audit f.json 2> run.log`) for persistence. `komplid` logs to stderr
   **unconditionally** rather than relying on the `IsDaemon()` (`getppid()==1`)
   heuristic, which doesn't cover ad-hoc local runs.
3. **Passthrough and NRP → `syslog(3)`.** Both run under the configuration agent, so
   they route to the system log via `syslog()` rather than opening a file — the
   in-process NRP module can't rely on its own stderr (see the mechanics section).
   This replaces the NRP module's current fixed `/var/log/osconfig_nrp.log` open.
   Open with `openlog("kompli", LOG_PID, LOG_DAEMON)` so records filter cleanly
   (`journalctl -t kompli`).
4. **`--log-file` deprecated, targeting removal.** Its sole purpose is now served by
   stderr redirection. Keeping it re-introduces an operator-supplied, root-opened
   path — the *only* attacker-influenceable log path in the system. Remove it; if a
   documented power-user need forces keeping it, treat it explicitly as trusted
   operator input.
5. **No app-managed log-file rotation for kompli.** Retention/rotation is owned by
   syslog/journald (passthrough/NRP) or the operator (standalone/komplid). This also
   disposes of the single-`.bak` overwrite risk (two size-cap saturations in quick
   succession could drop the older backup).

## Security outcome — the residual TOCTOU closes by *elimination*

The residual TOCTOU (documented in
`src/modules/complianceengine/src/cli/THREAT_MODEL.md`, tracked in
`src/komplid/README.md`): `OpenLog()` is path-only and `TrimLog()` re-opens the path
on every rotation, leaving a check-to-use window on the operator-supplied
`--log-file`. The mitigation to date (require a root-owned, non-writable parent) only
*narrows* it.

**Resolution: remove the operator-supplied path entirely.** With standalone/komplid
→ stderr and passthrough/NRP → syslog, kompli never opens an attacker-influenceable
log path, so there is no window to close. Removing the risky input is strictly
stronger than hardening it.

Consequently, the previously-scoped **descriptor-based `OpenLog` rework** (an
`OpenLogEx`/verified-fd open with `O_NOFOLLOW` + `fstat`, dir-fd `renameat` rotation)
and the CLI's `RefuseUnsafeLogFile` are **no longer needed** and are dropped from the
roadmap. The only remaining `OpenLog(path)` consumers are fixed, root-owned paths
(e.g. telemetry's own file), which are low-risk `Default`-mode opens.

## Level mapping (OsConfig → syslog)

| OsConfig level | syslog priority |
|----------------|-----------------|
| Emergency | `LOG_EMERG` |
| Alert | `LOG_ALERT` |
| Critical | `LOG_CRIT` |
| Error | `LOG_ERR` |
| Warning | `LOG_WARNING` |
| Notice | `LOG_NOTICE` |
| Informational | `LOG_INFO` |
| Debug | `LOG_DEBUG` |

## Implementation notes (for the follow-up change)

- **Syslog sink in the shared logging library** (`Logging.c`/`Logging.h`): a third
  mode alongside file/console. When active, `OsConfigLog(...)` routes to
  `syslog(priority, "%s", …)` instead of a `FILE*`, using the mapping above. The file
  mode stays for other consumers (telemetry).
- **NRP module init** (`src/modules/complianceengine/src/so/ComplianceEngineModule.c`
  and the MC adapter) switches from `OpenLog("/var/log/osconfig_nrp.log", …)` to the
  syslog sink.
- **`Main.cpp`**: remove `--log-file` (and the `RefuseUnsafeLogFile` call/validation);
  the stderr default is already in place via the console→stderr fix.
- **Retire** the `OpenLogEx`/hardened-open design and the `logrotate.d/kompli` idea —
  both obviated by this model.

## Caveats / migration

- **Rate-limiting.** journald/syslog rate-limits; a debug flood can drop lines.
  Acceptable for audit/remediation records; note it if complete debug traces are ever
  required.
- **Operator migration.** Anything tailing `/var/log/osconfig_nrp.log` moves to
  `journalctl -t kompli` (or the configured syslog target). Call this out in the
  package changelog.
- **Telemetry** keeps its own file log; it is out of scope for this change.

## Supersedes

- The "descriptor-based rework" **roadmap item** in `src/komplid/README.md` (§ Logging)
  — replaced by *eliminate the operator path*.
- The "Residual TOCTOU" note in
  `src/modules/complianceengine/src/cli/THREAT_MODEL.md` — resolved by removal; that
  note (and the `--log-file` mentions in `docs/CLI.md` / `docs/architecture.md`) are
  updated when the change lands.
