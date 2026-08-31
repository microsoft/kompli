# compliance-engine-assessor — Threat model

This document is the security reference for the `compliance-engine-assessor`
binary (`Main.cpp` and the benchmark-definition parser). Keep it in sync when the
input format, the input-hardening posture, or the trust boundary changes.

## Trust boundary

The tool runs **as root** on Linux endpoints to perform CIS benchmark audit and
remediation. The trust boundary is the invoking operator: the input
benchmark-definition file, the log-file path, and command-line arguments are
operator-supplied — trusted to be benign in *intent*, but not trusted to be free
of bugs or accidental hostile content. The hardening below defends the root
process against a malformed, tampered, or swapped input rather than against the
operator.

### Why input integrity is security-critical

Each rule's `payload` object is passed verbatim to the ComplianceEngine, which
parses and **executes it as root** (procedures may spawn scripts and run
commands). The parser does *not* sandbox or semantically validate the payload —
that is the engine's job. Therefore the file-integrity checks below are the
**sole barrier** between a tampered definition file and arbitrary root code
execution. Treat any regression in these checks as a security regression.

## Input parser

The parser (`BenchmarkDefinition`) is strict:

- It validates the resource envelope (`apiVersion` / `kind == "BenchmarkDefinition"`
  / `metadata` / `spec.rules`) and the per-rule field set the augmentation engine
  emits (`title`, `ruleId`, `ruleName`, `payloadKey`, `payload`).
- It bounds the total input size (`kMaxInputBytes`) and the rule count (`kMaxRules`).
- It **fails closed on an embedded NUL byte**: the underlying JSON parser is
  NUL-terminated (parses via `c_str()`), so a NUL would silently truncate the
  document and hide everything after it. Such input is rejected outright rather
  than parsed as a prefix.
- Nesting depth is bounded by the vendored parson (`MAX_NESTING == 2048`), so
  deeply nested input cannot overflow the stack.
- A fuzzer target (`fuzzer/target.cpp`) exercises `ParseString` and asserts the
  parser is crash-free and never throws; because `ParseString` is the single
  choke point, the NUL rejection and every other guard are attested by the
  fuzzer. Extend the corpus when changing the format.

## Input file integrity (positional filename)

Definition input **must** be a verified on-disk file, supplied as the positional
filename argument (`audit|remediate <file>`). The parser owns the file and
applies, in order:

1. **Parent directory (stat):** must be root-owned and not writable by group or
   others. A writable directory enables a rename-swap attack: an attacker could
   unlink the validated file and place a hostile one before the process reads it.

2. **`open(O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)`:** the kernel refuses
   a symlink in the final path component atomically (`ELOOP`), eliminating the
   lstat-then-open TOCTOU window. Symlinks are rejected rather than
   accepted-with-a-warning; callers that stage input via a symlink must resolve
   the link before passing the path. `O_NONBLOCK` prevents `open()` from blocking
   on a FIFO and is cleared once the regular-file check passes. Note: symlinks in
   *intermediate* path components are not checked; the operator is trusted to
   supply a straightforward path.

3. **`fstat` on the open fd:** ownership and mode are verified against the inode
   actually held, not a potentially-swapped path entry. The file must be a
   regular file (FIFOs, devices, sockets are refused so they cannot block the
   read or stream unbounded data), root-owned, and not group/world-writable.

4. **Bounded read into a buffered parse:** the verified fd is read in bounded
   chunks and accumulated into a single in-memory buffer, with the size cap
   (`kMaxInputBytes`) enforced *during* the read so an oversized input is
   rejected before it is fully buffered. JSON parsing is not streaming: the whole
   document is then parsed at once (buffer plus the parson DOM built on top), so
   peak memory is a multiple of the input size — bounded, but not constant. The
   held fd keeps the inode reachable across the read even if the directory entry
   is concurrently renamed or unlinked. Both the total input size and the rule
   count (`kMaxRules`) are bounded inside the parser.

### stdin is not supported for definitions

`audit` / `remediate` **require** a positional benchmark-definition file
argument; a missing path or `-` is a hard error. stdin is deliberately
unsupported so the integrity checks above can never be bypassed by piping data
into the root process. (The root-free `render` subcommand, which only reformats
a result JSON and performs none of these checks, still accepts stdin.)

## Other process hardening

- **umask** is tightened to at least `S_IRWXG | S_IRWXO` (preserving any stricter
  inherited mask). The `--log-file` case is the primary beneficiary.

- **`--log-file` path validation** (`RefuseUnsafeLogFile`): the shared logging
  code opens the log with a symlink-following append and `chmod`s it while we run
  as root, so a symlink, non-root-owned target, or writable parent directory is
  refused to prevent redirecting root's writes onto a sensitive file.

  *Residual TOCTOU (known limitation):* unlike the definition-file input, the log
  file is not verified via `fstat()` on a held fd. The shared `OpenLog()` API is path-only
  (no fd-accepting entry point) and `TrimLog()` re-opens the path with `fopen()`
  on every rotation, so a pinned, pre-verified fd cannot be handed to the logging
  layer. `RefuseUnsafeLogFile()` checks the path with `lstat()` shortly before
  `OpenLog()` resolves it again, leaving a small check-to-use window. That window
  is closed in practice by the parent-directory check: requiring the parent to be
  root-owned and not group/world-writable prevents an attacker from creating,
  renaming, or swapping the entry at all. Fully eliminating the window (an
  fd-based open with `O_NOFOLLOW` handed to the logger) would require changing the
  shared logging library, which affects every azure-osconfig binary and is out of
  scope here.

- **`PATH` / `IFS`** are inherited and used by the procedure scripts the engine
  spawns. Sanitizing the environment is the engine's responsibility, not the
  assessor's.

## Applicability / version matching

Before running a rule, the assessor checks the benchmark's
distribution/version against the detected system via
`CISBenchmarkInfo::Match`. This is the **same shared code**
(`lib/BenchmarkInfo.cpp`) used by the module interface's
`ComplianceEngineCheckApplicability`, so the assessor and the engine agree by
construction. Version matching uses `fnmatch(3)` against the system `VERSION_ID`;
`ValidateGlobbing` rejects `[ ] { }` character-class/brace metacharacters. The
`fnmatch` subject (`VERSION_ID`) is short and system-supplied, so the residual
catastrophic-backtracking surface from `*`/`?` patterns is minimal. Any future
hardening belongs in the shared `BenchmarkInfo` code so both consumers benefit.

## Known limitations / deferred work

See [SECURITY_REVIEW.md](./SECURITY_REVIEW.md) for the full findings list and the
tracked follow-ups.

- **Schema is not a runtime control.** `benchmark.schema.json` gates generation,
  not execution: the parser only requires `title` / `ruleId` / `ruleName` /
  `payloadKey` / `payload` and ignores schema-required `section` / `tags` /
  `metadata`. Do not rely on the schema to constrain what the assessor executes.
  (`tags` / `metadata` consumption is planned in a follow-up.)
- **`apiVersion` value is not validated** — only required to be present and
  non-empty. There is currently no version-skew detection; value pinning is
  planned as a follow-up.
