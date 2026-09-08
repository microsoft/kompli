# Payload key format

This document is the canonical spec for the `payloadKey` string every rule
carries — its structure, what's guaranteed vs. opaque, and how the unified
benchmark-definition file format and the MOF format diverge in how much of it
each one stores. Cross-referenced from
[CLI.md](CLI.md#2-plan--run-per-rule-granularity-implemented) (plan/run key
choice) and [architecture.md](architecture.md).

Status legend: **Decided** (agreed direction, not all pieces implemented yet),
**Implemented**, **Deferred** (agreed to leave for later, explicitly out of
scope for now).

## 1. Structure — Decided

```
/<framework>/<distribution>/<distributionVersion>/<benchmarkVersion>/<section>
```

| # | Segment | Example | Notes |
|---|---|---|---|
| 1 | `framework` | `cis`, `stig` | Closed set today (`BenchmarkInfo.cpp`'s `sBenchmarkTypeMap`); an unrecognised value is a hard parse error. Opening this to arbitrary framework strings (for user-authored/custom benchmarks) is **Deferred** — not needed while only CIS is GA and STIG is early-stage, but the format itself doesn't preclude it later. |
| 2 | `distribution` | `ubuntu`, `azurelinux` | Matched against the host's detected distribution. |
| 3 | `distributionVersion` | `22.04`, `3.*` | `fnmatch`-style glob, matched against the host's `VERSION_ID`. |
| 4 | `benchmarkVersion` | `v2.0.0` | **Decided:** always `v`-prefixed, for every framework. STIG's existing generator omits the `v` (`2.5.0`) — see §4, this is being fixed since STIG is still early-stage. Opaque beyond the prefix requirement: kompli never parses or validates the rest of this segment, it's stored as-is. |
| 5+ | `section` (the "remainder") | `1/1/1/1` (CIS), `SV-260469` (STIG) | Framework-defined shape, **opaque to kompli** — see §2. Only required to be unique within one file (see §5's duplicate-key enforcement). |

Verified empirically (not assumed): every rule in a real committed definition
file shares exactly one distinct 4-segment prefix — checked via `jq` across
both a CIS and a STIG file, `unique | length` = 1 in both. This is the
invariant §3's hoisting relies on.

## 2. The remainder is opaque — Decided, Implemented

Previously, `BenchmarkDefinition.cpp` derived a display `section` from the
remainder via an **unconditional** `/` → `.` replace, then cross-validated it
against the rule's explicit `section` field. This happened to produce
correct results for both CIS (multi-segment numeric, e.g. `1/1/1/1` →
`1.1.1.1`) and STIG (single opaque token, no slashes to replace, e.g.
`SV-260469` unchanged), but only because STIG's remainder never contains a
slash — it was not actually framework-aware, unlike the augmentation-engine
generator's own `__get_section()`, which *is* framework-conditional (a CIS
regex branch vs. a STIG regex branch). A hypothetical future remainder shape
that legitimately used `/` for a non-CIS-numbering reason, or a `section`
that already contained a literal `.`, would have silently misparsed under the
old blanket replace.

**Implemented fix**: kompli no longer derives `section` from the payload key
remainder. The remainder (stored as `payloadKey`, see §3) is a fully opaque
token — compared only for equality (map/lookup key via
`BenchmarkIO::Resource::payloadKey`), never decomposed. The already-present,
schema-required, explicit `section` field on each rule is now the sole
source for anything display-facing (CLI `-s/--section` filtering,
`--audit=<section>` toggle resolution, `kompli list` output) — retained
verbatim on `BenchmarkIO::Resource::section`. It is not required to be
algorithmically re-derivable from the payload key, and (see §5) uniqueness is
now enforced on `payloadKey`, not `section`.

## 3. Unified definition file: hoisted prefix — Decided, Implemented (kompli side only — see §10)

**Schema change** (`benchmark.schema.json`, allowed per explicit user
decision — this is not a MOF change, see §4): the file-level prefix
(framework / distribution / distributionVersion / benchmarkVersion) is stored
**once**, not repeated in every rule's `payloadKey`. Concretely:

- `metadata.labels.framework` / `.distribution` / `.distributionVersion` and
  `metadata.annotations.benchmarkVersion` are now **required** by the schema
  (previously free-form, optional string maps) and are the sole,
  canonical source of the file-level prefix — `CISBenchmarkInfo::FromMetadata`
  parses them directly, no path-string parsing involved. `benchmarkVersion`
  additionally requires the `^v.+` pattern (both in the JSON schema and in
  `FromMetadata`) — see §8.
- Each rule's `payloadKey` field is trimmed to store **only the remainder**
  (segment 5+), not the full path — retained verbatim on
  `BenchmarkIO::Resource::payloadKey`. `ruleId` derivation is unaffected (see
  below) — only the serialized field's contents shrink.

**Hard requirement, not optional**: `ruleId = UUID(sha256(payload_key))`
(`common/rule.py`'s `get_uuid()`) must keep hashing the **reconstructed full
logical key** (prefix + remainder), not the trimmed stored string. The
generator already computes the full key in memory before serialization
(`rule.get_key()`) — `get_uuid()` must keep calling that, independent of what
gets written into the `payloadKey` JSON field. Get this wrong and every
existing CIS `ruleId` changes, which is the one thing explicitly ruled out
for CIS (GA'ed, external consumers already key off `ruleId`). **This is a
Python-side (augmentation-engine) requirement, not yet implemented — see
§10.**

**Consequence for kompli's parser (implemented)**: distribution/version
extraction moved from *per rule* to *per file* — parsed once from
`metadata` (`BenchmarkDefinition::ParseString` calls `CISBenchmarkInfo::
FromMetadata` once per document, not once per rule). This isn't just a
simplification: once the prefix is hoisted, a rule's stored `payloadKey`
(now remainder-only) structurally no longer contains distro/version
information, so a per-rule distro/version check becomes *impossible* for
anything reading the JSON form, not merely unnecessary. See §6 for why this
doesn't apply to the MOF/NRP path.

**Operational note, not yet true**: this changes the serialized bytes of
every committed `data/definitions/*.benchmark.json` (28 files today) —
expect a large but purely mechanical drift-gate diff on regeneration, not a
semantic change to any rule's actual content. **None of the 28 files have
been regenerated yet — see §10, this is a real, currently-blocking gap, not
just a future formality.**

## 4. MOF format is unchanged — Decided, hard constraint

The hoisting in §3 applies **only** to the unified benchmark-definition JSON.
The MOF format is explicitly **not** changing: each MOF resource instance
keeps the **full, self-contained payload key**, exactly as today. The MOF
generator (`mof.py` / equivalent) reconstructs the full key
(prefix from the file's hoisted metadata + that rule's stored remainder) at
MOF-generation time — the trimming in §3 is purely a JSON-storage
optimization and must be fully transparent to every MOF consumer.

## 5. Applicability checking splits by scenario — Decided, Implemented

This split falls directly out of §3/§4: the JSON form loses per-rule
distro/version data (by construction, once hoisted), while the MOF form keeps
it (unchanged). The two consumers must therefore check applicability
differently, and this is not a stopgap — it's the correct, permanent shape
given each format's structure:

- **kompli CLI** (`audit`/`remediate`/`plan`/`run`, always operating over one
  whole definition file at a time): validates applicability **once per
  file**, against the file-level hoisted prefix, before evaluating any rule.
  This relies on and enforces the §1 invariant (one distro/version per file) —
  it is the *only* applicability check the CLI can perform once rules no
  longer carry their own distro/version, not merely a fast path.
- **NRP** (Guest Configuration / Machine Configuration, MOF-driven,
  `MmiSet`/`MmiGet` invoked per resource instance): has no "whole file"
  context — each call only sees one resource's fully self-contained payload
  key. Applicability **must** be validated per rule/per resource, failing
  just that resource if it doesn't apply. This is unaffected by §3 (the MOF
  never loses per-rule distro/version data) and must not be broken or
  assumed away by the CLI-side per-file shortcut above.

## 6. Plan/run key by payload key, not `section` — Decided, Implemented

Earlier design rounds (recorded in `docs/CLI.md`'s history) decided plan
files key rules by the human-typeable `section` field, with `payloadKey`
reserved for internal/wire use. **This is reversed**: plan/run key rules by
the verbatim `payloadKey` remainder — it's the field actually guaranteed
unique within a file (§1), it's not opaque like `ruleId` (a hash, useless as
a human/plan reference), and per §2 it no longer needs any lossy
transformation to be usable as a lookup key. `section` remains purely a
display/CLI-ergonomics field (§2).

**CLI ergonomics — Decided**: the CLI toggle flags (`--audit=<X>` etc.) keep
accepting the human-typeable `section` value; `plan` resolves it to the
matching rule's `payloadKey` internally (`GeneratePlan` builds a
`section`→`payloadKey` map from the parsed document) before writing the plan
file. The *stored* plan format is therefore keyed purely by `payloadKey`
(framework-agnostic, unique-by-construction) while the *typed* CLI surface
stays ergonomic (short dotted `section` values). **Known sharp edge, not
guarded against**: if two rules in a file share the same `section` (not
rejected — see §5, only `payloadKey` uniqueness is enforced), the
`section`→`payloadKey` resolution map silently retains whichever one was
parsed last; `--audit=<that section>` then resolves to that one arbitrarily.
Out of scope for now (tracked in `CLI.md` §6).

**Implementation prerequisite — done**: `BenchmarkIO::Resource` now retains
both `section` and `payloadKey` verbatim (`Resource.hpp`), so plan/run and
the future wire protocol can both key on `payloadKey` without re-parsing
anything.

**Also follows from this — done**: the duplicate-rule-reference rejection in
`BenchmarkDefinition::ParseString` now checks uniqueness of `payloadKey`
directly (not a derived `section`), since §2 removed the `section`↔payloadKey
cross-validation that used to make `section` uniqueness a reasonable proxy.

## 7. Plan format: mixing rules from multiple benchmark files — Decided, Implemented

Motivation: a corporate baseline combining, say, CIS rules and STIG rules for
the same host, without hand-copying rule content into a new file (which would
drift out of sync with upstream fixes) and without being forced into
`N` separate scans (`N` plans, `N` `run` invocations) just because the
rules originate from different unified-definition files.

**Format change** (supersedes the single-`benchmark` shape shipped as v1 and
already verified against a real host): the plan's single `benchmark` object
becomes a `benchmarks` **array**, each entry independently scoped:

```jsonc
{
  "benchmarks": [
    {
      "file": "cis_ubuntu_22.04.benchmark.json",
      "sha256": "<hash at plan-generation time>",
      "rules": {
        "1/1/1/1": { "mode": "audit", "parameters": {} }
      }
    },
    {
      "file": "disa_stig_ubuntu_22.04.benchmark.json",
      "sha256": "<hash at plan-generation time>",
      "rules": {
        "SV-260469": { "mode": "audit", "parameters": {} }
      }
    }
  ]
}
```

Each block keeps its own `sha256` drift-check (§ old CLI.md §2) and its own
`rules` map, keyed by that file's rule remainder (§6) — since the prefix is
scoped per block, rules don't need to repeat it. `run` validates each block
independently: re-hashes that block's file, re-validates that block's rule
references, and applies §5's per-file applicability check separately per
block (see below for what happens on a mismatch).

**Cross-distro mixing — Decided: hard fail.** The primary motivating scenario
is same-distro CIS+STIG (one host, two frameworks); the array shape doesn't
*prevent* referencing files targeting different distros in one plan, though.
**Decided**: a block whose file doesn't match the current host's
distro/version (§5's per-file check) hard-fails the **whole** `run`
immediately — it is not skipped while other blocks continue. Rationale (the
user's words): "let's not mix too much, otherwise we'd have to work with
partial reports." Implemented in `Main.cpp`'s `run` dispatch — the per-file
applicability check happens before that block's rules are evaluated, and
returns a hard error (no partial `BenchmarkFormatter` output) on mismatch.

**Breaking change — confirmed, and it happened.** This superseded the
already-shipped/verified single-`benchmark` v1 plan shape as a breaking
change, not an additive "version" field — the single-`benchmark` shape no
longer exists in the parser (`ParsePlanFile` requires a `benchmarks` array;
there is no fallback for the old shape). Any plan file generated by the
previous `kompli plan` build is now rejected by `ParsePlanFile` and must be
regenerated.

## 8. STIG `benchmarkVersion` migration — Decided

STIG's generator currently omits the `v` prefix (`2.5.0`) that CIS always has
(`v1.0.0`) — a pre-existing inconsistency, not something introduced by this
document. **Decided**: STIG will be updated to match CIS's `v`-prefixed
format. Unlike CIS, this is accepted to cause a one-time `ruleId` change for
STIG's already-generated definitions, since STIG is still early-stage /
not yet broadly deployed (per explicit user decision) — the same tolerance
does not extend to CIS, which is GA'ed.

## 9. Not addressed here (explicitly out of scope)

- Opening the `framework` segment (§1) beyond `cis`/`stig` to arbitrary
  framework strings for genuinely user-authored benchmarks — **Deferred**,
  not urgent while only CIS is GA and STIG is early-stage.
- ~~`std::to_string(CISBenchmarkInfo)` hardcodes `BenchmarkType::CIS`~~ —
  **Fixed** as part of implementing this document: `CISBenchmarkInfo` gained
  a `benchmarkType` field and `to_string` now round-trips it correctly for
  both frameworks (`BenchmarkInfoTest.cpp`'s `Valid_Stig` test asserts the
  `/stig/...` round-trip).

## 10. Augmentation-engine-side work not started — blocking gap

Everything above (§2, §3, §5, §6, §7) is **implemented on the kompli
(C++) side only**. The augmentation-engine Python generator
(`tools/compliancectl/`) has not been touched, and this is a real,
currently-blocking incompatibility, not a future formality:

- **Verified via `jq` against real committed files**: every
  `data/definitions/*.benchmark.json` file's `metadata.annotations.
  benchmarkVersion` is **not** `v`-prefixed today (e.g. `"1.0.0"`,
  `"2.5.0"`), for CIS files as well as STIG (checked
  `cis_aks_optimized_azure_linux_3_benchmark_v1.0.0.benchmark.json`,
  `cis_ubuntu_linux_24.04_lts_benchmark_v1.0.0.benchmark.json`,
  `disa_stig_ubuntu_22.04_lts_v2.5.0.benchmark.json`). This fails both the
  JSON schema's new `^v.+` pattern and `CISBenchmarkInfo::FromMetadata`'s
  `benchmarkVersion[0] == 'v'` check (§3, §8) — **all 28 committed
  definition files currently fail to parse** under the kompli build produced
  in this round. `metadata.labels.framework`/`.distribution`/
  `.distributionVersion` are already present with correct values in the
  files checked (the generator already derives them from the first rule's
  payload key), so only the `benchmarkVersion` annotation's missing prefix
  is the blocker on the labels/annotations side.
- **`payloadKey` is not yet trimmed**: committed files still store the full
  path (e.g. `"/cis/azurelinux/3.*/v1.0.0/1/1/1/1"`) rather than the
  remainder (`"1/1/1/1"`). This does **not** fail parsing (kompli's parser no
  longer validates `payloadKey`'s shape, only that it's present and unique —
  §2, §5), but it means a plan generated against an un-regenerated file would
  have to use the full path as its `rules` map key, defeating §6's ergonomics
  goal, and it leaves the file's bytes not actually reflecting the "hoisted,
  not repeated" design in §3.
- **`rule.py`'s STIG `__get_payload_key()` still omits the `v` prefix**
  (§8) — not yet fixed.
- **Not started**: any regeneration of the 28 committed files, any change to
  `rule.py`/`benchmark_def.py`/`mof.py`, any update to augmentation-engine's
  own generator unit tests.

**Practical consequence**: a real end-to-end `kompli plan`/`kompli run`
against any currently-committed definition file will fail at the
metadata-annotation-validation step until augmentation-engine's generator is
updated (STIG `v`-prefix fix, `payloadKey` trimming, `ruleId` computed from
the reconstructed full key — not the trimmed field) and the 28 files are
regenerated. The round 15.7 successful real-host run recorded in repo memory
predates this schema change and used the old (pre-hoisting) parser — it does
not demonstrate the new schema working end-to-end.
