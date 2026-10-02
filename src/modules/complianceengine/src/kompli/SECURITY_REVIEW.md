# kompli — Security review findings

Security review of the benchmark-definition JSON parser that replaces the MOF
input path (`BenchmarkDefinition.{cpp,hpp}`, `Resource.hpp`, and the
`run` wiring in `Main.cpp`). The parser runs **as root**; see
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
| 3 | Schema constraints not fully enforced at runtime | Low | Required `tags`/`metadata` validated; remaining constraints deferred |
| 4 | Embedded NUL byte silently truncated the parse | Low | Fixed — fail-closed on NUL |
| 5 | `apiVersion` value never validated | Low | Fixed — allowlist gate |
| 6 | `fnmatch` version-glob hardening | Low | **Deferred** — shared-lib change |
| 7 | Memory / recursion bounds | Low | Adjusted — input cap lowered to 8 MiB |
| 8 | TOCTOU: parent-dir stat vs. open | Low | Pre-existing, documented, mitigated |

## Fixed in this work

### 2. stdin is no longer accepted for definitions
`run` reads on-disk definition files from its plan. A missing path or `-` is a hard error. This removes the ability to bypass the input-hardening
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

### 5. `apiVersion` value is now validated
`ParseString` now rejects any `apiVersion` outside a small allowlist
(`kSupportedApiVersions`, currently just `"v1"`) with an error naming the
supported set, closing the version-skew gap: an incompatible future format is
no longer parsed best-effort. The supplied value is not echoed into logs,
because it could contain control characters or be unreasonably long. Covered
by `RejectsUnsupportedApiVersion` and
`DoesNotEchoUnsupportedApiVersionInError`. Retention and removal criteria for
future formats are not yet decided; they must account for deployed versions
and customers still using older definitions when a format change is proposed.

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

### 3. Schema is not a complete runtime control
`benchmark.schema.json` gates *generation*, not *execution*. The parser
now requires and validates `ruleId`, `tags`, `metadata`, and either `id` or
complete legacy `section` + `payloadKey` identity, but does not implement
every schema constraint (including the content-version contract). `id` is the
opaque framework identifier; `ruleId` remains stable for external
correlation. Do not assume a file rejected by the schema is necessarily
rejected at runtime.

**Planned:** Decide whether to enforce the remaining schema constraints at
runtime or retain the schema purely as a generation-time gate.

### 6. `fnmatch` version-glob hardening (shared library)
Applicability matching uses `fnmatch(version, VERSION_ID)` where `version` comes
from the definition file. `ValidateGlobbing` already rejects `[ ] { }`, but
`*` / `?` / `\` remain. The subject (`VERSION_ID`) is short and system-supplied,
so the residual catastrophic-backtracking surface is minimal.

Importantly, kompli does **not** have its own copy of this logic: it calls
the shared `BenchmarkInfo::Match` in `lib/BenchmarkInfo.cpp`, the same code
used by the module interface's `ComplianceEngineCheckApplicability`. So there is
nothing kompli-specific to change — any hardening belongs in the shared library
so both consumers benefit.

**Idea (not yet implemented):**
1. Bound the pattern in `ValidateGlobbing`: cap `version` length and reject an
   excessive count of `*` / `?`, eliminating pathological patterns up front.
2. Consider `FNM_NOESCAPE` and dropping the `\`-unescape in `SanitizedVersion`,
   or keep escaping but document the version axis as a restricted glob rather
   than an arbitrary pattern.
3. This is defense-in-depth given the short, trusted subject — low urgency.

## Verification performed

- Built with the clang toolchain (`./build/clang`): kompli, tests, and fuzzer
  compiled clean.
- Unit tests: all `BenchmarkDefinitionParserTest` cases pass, including the new
  NUL-rejection cases.
- Fuzzer: the libFuzzer parser target ran clean (no crashes/leaks) under
  AddressSanitizer + UndefinedBehaviorSanitizer, exercising NUL-containing input.
