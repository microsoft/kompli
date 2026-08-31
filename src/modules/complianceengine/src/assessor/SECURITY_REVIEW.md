# compliance-engine-assessor — Security review findings

Security review of the benchmark-definition JSON parser that replaces the MOF
input path (`BenchmarkDefinition.{cpp,hpp}`, `Resource.hpp`, and the
`audit`/`remediate` wiring in `Main.cpp`). The parser runs **as root**; see
[THREAT_MODEL.md](./THREAT_MODEL.md) for the trust boundary and input-hardening
posture. This document tracks the findings from that review and, in particular,
the work deliberately deferred to follow-up PRs.

Reviewed at kompli commits `834acde1` ("Support the new definitions format") and
`3f070bb3` ("Fix the schema patterns").

## Status summary

| # | Finding | Severity | Status |
|---|---------|----------|--------|
| 1 | File integrity is the sole barrier to root code execution | High (by design) | Documented (threat model) |
| 2 | `stdin` bypassed all input-integrity checks | Medium | Fixed — stdin removed for definitions |
| 3 | Schema is not a runtime control; `tags`/`metadata` ignored by parser | Low | **Deferred** — follow-up PR |
| 4 | Embedded NUL byte silently truncated the parse | Low | Fixed — fail-closed on NUL |
| 5 | `apiVersion` value never validated | Low | **Deferred** — follow-up PR |
| 6 | `fnmatch` version-glob hardening | Low | **Deferred** — shared-lib change |
| 7 | Memory / recursion bounds | Low | Adjusted — input cap lowered to 8 MiB |
| 8 | TOCTOU: parent-dir stat vs. open | Low | Pre-existing, documented, mitigated |

## Fixed in this work

### 2. stdin is no longer accepted for definitions
`audit` / `remediate` now require an on-disk file as the positional filename
argument; a missing path or `-` is a hard error. This removes the ability to bypass the input-hardening
posture (root-owned, non-writable parent, `O_NOFOLLOW`, regular-file/ownership/
mode checks) by piping data into the root process. The root-free `render`
subcommand still accepts stdin because it performs none of those checks.

### 4. Embedded NUL bytes fail closed
`BenchmarkDefinition::ParseString` rejects any input containing a `\0`. The JSON
parser is NUL-terminated (parses via `c_str()`), so a NUL would otherwise
silently truncate the document and hide everything after it. Because
`ParseString` is the single choke point, this also protects `ParseFile`,
`ParseStream`, and the fuzzer. Covered by unit tests (`RejectsEmbeddedNulByte`,
`RejectsLeadingNulByte`) and attested crash-free by the libFuzzer target.

### 7. Input memory cap lowered
JSON parsing is not streaming: the whole document is buffered and parsed at once
(buffer plus the parson DOM built on top), so peak memory is a multiple of the
input size. The input cap (`kMaxInputBytes`) was lowered from 64 MiB to 8 MiB
(the largest committed definition is ~1 MiB) to bound that worst-case footprint
while keeping ample headroom. Rule count is separately capped (`kMaxRules`, with
`reserve` performed only after the cap check), and the vendored parson bounds
nesting at `MAX_NESTING == 2048`, so deeply nested input cannot overflow the
stack.

## Documented (no code change)

### 1. Input integrity is security-critical
Each rule's `payload` is passed verbatim to the ComplianceEngine, which parses
and **executes it as root**. The parser does not sandbox or semantically
validate the payload, so the file-integrity checks are the sole barrier between
a tampered definition file and arbitrary root code execution. Any regression in
those checks is a security regression. Captured in THREAT_MODEL.md.

### 8. Parent-directory TOCTOU
`RefuseWritableParentDir` stats by path while `OpenVerifiedInput` verifies via
`fstat` on the held fd; intermediate-component symlinks are unchecked. This is
mitigated by requiring a root-owned, non-writable parent and is already analyzed
in THREAT_MODEL.md.

## Deferred — follow-up PRs

> These are intentionally out of scope for the current change. Track them here so
> they are not lost.

### 3. Schema is not a runtime control; `tags` / `metadata` are ignored
`benchmark.schema.json` gates *generation*, not *execution*. The parser only
requires `title` / `ruleId` / `ruleName` / `payloadKey` / `payload` and ignores
the schema-required `section` / `tags` / `metadata`. Consequences:

- A file that would fail schema validation can still be executed by the assessor.
- The per-rule `section` field is unused (the section is derived from `payloadKey`).

**Planned:** `tags` and `metadata` consumption is intended in a follow-up PR.
When that lands, decide whether the parser should also enforce their presence
(closing the parser/schema divergence) or continue to treat the schema purely as
a generation-time gate.

### 5. `apiVersion` value is not validated
`ParseString` requires `apiVersion` to be present and non-empty but never checks
its value, so there is no version-skew detection: an incompatible future format
would be parsed on a best-effort basis.

**Planned:** pin / allowlist known `apiVersion` values in a follow-up so the
assessor rejects formats it does not understand instead of silently
best-effort-parsing them.

### 6. `fnmatch` version-glob hardening (shared library)
Applicability matching uses `fnmatch(version, VERSION_ID)` where `version` comes
from the definition file. `ValidateGlobbing` already rejects `[ ] { }`, but
`*` / `?` / `\` remain. The subject (`VERSION_ID`) is short and system-supplied,
so the residual catastrophic-backtracking surface is minimal.

Importantly, the assessor does **not** have its own copy of this logic: it calls
the shared `CISBenchmarkInfo::Match` in `lib/BenchmarkInfo.cpp`, the same code
used by the module interface's `ComplianceEngineCheckApplicability`. So there is
nothing assessor-specific to change — any hardening belongs in the shared library
so both consumers benefit.

**Idea (not yet implemented):**
1. Bound the pattern in `ValidateGlobbing`: cap `version` length and reject an
   excessive count of `*` / `?`, eliminating pathological patterns up front.
2. Consider `FNM_NOESCAPE` and dropping the `\`-unescape in `SanitizedVersion`,
   or keep escaping but document the version axis as a restricted glob rather
   than an arbitrary pattern.
3. This is defense-in-depth given the short, trusted subject — low urgency.

## Verification performed

- Built with the clang toolchain (`./build/clang`): assessor, tests, and fuzzer
  compiled clean.
- Unit tests: all `BenchmarkDefinitionParserTest` cases pass, including the new
  NUL-rejection cases.
- Fuzzer: the libFuzzer parser target ran clean (no crashes/leaks) under
  AddressSanitizer + UndefinedBehaviorSanitizer, exercising NUL-containing input.
