# Payload key format

This document is the spec for the `id` string every rule carries — its
structure, what's guaranteed vs. opaque, and how the unified
benchmark-definition file format and the MOF format diverge in how much of it
each one stores. Cross-referenced from
[cli.md](cli.md#2-plan--run-per-rule-granularity) (plan/run key
choice) and [architecture.md](architecture.md).

**Terminology note**: "payload key" (this document's title term) refers to
the full MOF-style string (prefix + remainder, §1). kompli's own JSON
contracts (definition schema, result schema, `Resource`) store only the
remainder, under the field name `id`.

## 1. Structure

```
/<framework>/<distribution>/<distributionVersion>/<benchmarkVersion>/<remainder>
```

| # | Segment | Example | Notes |
|---|---|---|---|
| 1 | `framework` | `cis`, `stig` | Closed set (`BenchmarkInfo.cpp`'s `sBenchmarkTypeMap`); an unrecognised value is a hard parse error. Opening this to arbitrary framework strings (for user-authored/custom benchmarks) is out of scope for now (§9) — the format itself doesn't preclude it later. |
| 2 | `distribution` | `ubuntu`, `azurelinux` | Matched against the host's detected distribution. |
| 3 | `distributionVersion` | `22.04`, `3.*` | `fnmatch`-style glob, matched against the host's `VERSION_ID`. |
| 4 | `benchmarkVersion` | `v2.0.0` | Always `v`-prefixed, for every framework (§8). Opaque beyond the prefix requirement: kompli never parses or validates the rest of this segment, it's stored as-is. |
| 5+ | `id` (the "remainder") | `1.1.1.1` (CIS), `SV-260469` (STIG) | Framework-defined shape, **opaque to kompli** — see §2. The sole externally-quoted per-rule identifier (§11/§12). Only required to be unique within one file (§5). |

Every rule in one benchmark-definition file shares exactly one distinct
4-segment prefix — this is the invariant §3's hoisting relies on.

## 2. The remainder is opaque

The remainder (stored as `id`, see §3) is a fully opaque
token — compared only for equality (map/lookup key via
`BenchmarkIO::Resource::id`), never decomposed. Nothing derives a display
`section` from it via string manipulation (e.g. `/` → `.` replace) — that
would be fragile for any framework whose remainder shape doesn't happen to
avoid the replaced character, and framework-conditional string surgery isn't
something kompli's parser does.

## 3. Unified definition file: hoisted prefix (kompli side only — see §10)

**Schema**: the file-level prefix (framework / distribution /
distributionVersion / benchmarkVersion) is stored **once** per file, not
repeated in every rule's `id` (this is a kompli-side-only schema shape, not a
MOF change — see §4):

- `metadata.labels.framework` / `.distribution` / `.distributionVersion` and
  `metadata.annotations.benchmarkVersion` are **required** by the schema and
  are the sole, canonical source of the file-level prefix —
  `CISBenchmarkInfo::FromMetadata` parses them directly, no path-string
  parsing involved. `benchmarkVersion` additionally requires the `^v.+`
  pattern (both in the JSON schema and in `FromMetadata` — see §8).
- Each rule's `id` field stores **only the remainder** (segment 5+), not the
  full path.

**Hard requirement**: `ruleId = UUID(sha256(payload_key))`
(`common/rule.py`'s `get_uuid()`) must hash the **reconstructed full
logical key** (prefix + remainder), not the trimmed stored string — the
generator computes the full key in memory before serialization
(`rule.get_key()`), independent of what gets written into the `id` JSON
field. Getting this wrong would change every existing CIS `ruleId`, which is
the one thing explicitly ruled out for CIS (GA'ed, external consumers
already key off `ruleId`).

**Consequence for kompli's parser**: distribution/version extraction happens
*per file*, not per rule (`BenchmarkDefinition::ParseString` calls
`CISBenchmarkInfo::FromMetadata` once per document). Once the prefix is
hoisted, a rule's stored `id` (remainder-only) structurally no longer
contains distro/version information, so a per-rule distro/version check is
*impossible* for anything reading the JSON form. See §6 for why this doesn't
apply to the MOF/NRP path.

## 4. MOF format is unchanged — hard constraint

The hoisting in §3 applies **only** to the unified benchmark-definition JSON.
The MOF format is explicitly **not** changing: each MOF resource instance
keeps the **full, self-contained payload key**, exactly as before. The MOF
generator (`mof.py` / equivalent) reconstructs the full key
(prefix from the file's hoisted metadata + that rule's stored remainder) at
MOF-generation time — the trimming in §3 is purely a JSON-storage
optimization and must be fully transparent to every MOF consumer.

## 5. Applicability checking splits by scenario

This split falls directly out of §3/§4: the JSON form loses per-rule
distro/version data (by construction, once hoisted), while the MOF form keeps
it (unchanged). The two consumers must therefore check applicability
differently — this is the correct, permanent shape given each format's
structure, not a stopgap:

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

## 6. Plan/run key by `id`

Plan/run key rules by the verbatim `id` (§1) — the field guaranteed unique
within a file, not opaque like `ruleId` (a hash, useless as a human/plan
reference), and usable as a lookup key with no transformation (§2).

**CLI ergonomics**: the CLI toggle flags (`--audit=<X>` etc.) and
`-s/--section` keep those flag names for continuity, even though there is no
separate `section` field behind them (§11) — they match directly against a
rule's `id` (dot-form for CIS, e.g. `1.1.1.1`). The stored plan format is
keyed purely by `id` (framework-agnostic, unique-by-construction).

`BenchmarkIO::Resource` retains `id` verbatim (`Resource.hpp`), so plan/run
and the wire protocol (`komplid`) can both key on `id` without re-parsing
anything. The duplicate-rule-reference rejection in
`BenchmarkDefinition::ParseString` checks uniqueness of `id` directly (§5).

## 7. Plan format: mixing rules from multiple benchmark files

Motivation: a corporate baseline combining, say, CIS rules and STIG rules for
the same host, without hand-copying rule content into a new file (which would
drift out of sync with upstream fixes) and without being forced into
`N` separate scans (`N` plans, `N` `run` invocations) just because the
rules originate from different unified-definition files.

**Format**: the plan's top level is a `benchmarks` **array**, each entry
independently scoped:

```jsonc
{
  "benchmarks": [
    {
      "file": "cis_ubuntu_22.04.benchmark.json",
      "sha256": "<hash at plan-generation time>",
      "rules": {
        "1.1.1.1": { "mode": "audit", "parameters": {} }
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

Each block keeps its own `sha256` drift-check and its own `rules` map, keyed
by that file's rule remainder (§6) — since the prefix is scoped per block,
rules don't need to repeat it. `run` validates each block independently:
re-hashes that block's file, re-validates that block's rule references, and
applies §5's per-file applicability check separately per block.

**Cross-distro mixing: hard fail.** The primary motivating scenario is
same-distro CIS+STIG (one host, two frameworks); the array shape doesn't
*prevent* referencing files targeting different distros in one plan, though.
A block whose file doesn't match the current host's distro/version (§5's
per-file check) hard-fails the **whole** `run` immediately — it is not
skipped while other blocks continue. Rationale: partial results from a plan
that silently dropped a mismatched benchmark would be misleading ("let's not
mix too much, otherwise we'd have to work with partial reports").

## 8. STIG `benchmarkVersion`

STIG's generator omits the `v` prefix (`2.5.0`) that CIS always has
(`v1.0.0`) — a pre-existing inconsistency. STIG matches CIS's `v`-prefixed
format. Unlike CIS, this is accepted to cause a one-time `ruleId` change for
STIG's definitions, since STIG is still early-stage / not yet broadly
deployed — the same tolerance does not extend to CIS, which is GA'ed.

## 9. Not addressed here (explicitly out of scope)

- Opening the `framework` segment (§1) beyond `cis`/`stig` to arbitrary
  framework strings for genuinely user-authored benchmarks — not urgent
  while only CIS is GA and STIG is early-stage.

## 10. Augmentation-engine-side work

Everything in §2, §3, §5, §6, §7 needs a matching implementation on **both**
sides: kompli (C++) and augmentation-engine (Python,
`tools/compliancectl/`):

- `rule.py`'s STIG `__get_payload_key()` emits a `v`-prefixed
  `benchmarkVersion` segment, matching CIS (§8).
- `benchmark_def.py`'s `metadata.annotations.benchmarkVersion` is sourced
  from the payload key's own (already `v`-prefixed) 4th segment, not the raw
  unprefixed XCCDF version string.
- Each rule's `id` is trimmed to the remainder at generation time (§11 — the
  *sole* per-rule identifier, not a redundant pair with a separate `section`
  field).
- `common/definition_source.py`'s `DefinitionRule`/`DefinitionBenchmark`
  (the `compliancectl get mof` replay path) reconstruct the full MOF key
  from the file-level hoisted metadata + the stored remainder, preserving
  §4's MOF-format-unchanged constraint for that path too.

## 11. `id`: the sole per-rule identifier (no separate `section`)

The definition file has no separate `section` field — `id` (§1) is the sole
externally-quoted per-rule identifier, dot-form for CIS (e.g. `1.1.1.1`) and
unchanged for STIG (e.g. `SV-260469`).

- **Schema**: neither `benchmark.schema.json` nor `kompli-result.schema.json`
  has a `section` property on a rule; `id`'s description states it as the
  identifier, not just an opaque lookup key.
- **`BenchmarkIO::Resource`**: no `section` field; `id` serves every role
  (CLI `-s/--section` filtering, `--audit=<X>`/plan lookup, and the
  canonical result's per-rule identifier).
- **CLI surface, deliberately unchanged**: kompli's own flags
  (`-s/--section`, `--audit=<section>`/`--remediate=<section>`/
  `--enforce=<section>`) keep these names for continuity — renaming a
  public flag is a separate UX decision this format doesn't force — and
  match directly against `Resource::id`, with no translation step.
- **Augmentation-engine**: `rule.py`'s `get_id()` (the dot-form CIS
  remainder via `__get_section`'s `/`→`.` replace) is the sole source
  `benchmark_def.py` uses for the serialized `id` field.
- **MOF special-case handler**: the MOF format's `PayloadKey` stays
  byte-identical to the slash-separated full key (§4) — unaffected for the
  XCCDF-direct path (`XccdfRule.get_key()`/`__get_payload_key` build the
  full slash-form key for `ruleId` hashing and MOF generation). The
  definition-replay MOF path (`compliancectl get mof` sourcing from a
  committed definition instead of XCCDF, via `common/definition_source.py`)
  needs a handler: `DefinitionRule.get_key()` converts a CIS `id`'s dots
  back to slashes (`self._framework == "cis"` gate) before concatenating it
  onto the file-level hoisted prefix, reconstructing the original MOF key.
  STIG's `id` has no dots to convert either way.
- **Result schema**: `kompli-result.schema.json` has no per-rule `section`
  — `JUnitRenderer`/`TextRenderers` (and any external consumer, e.g.
  `tests/plan_run_test.sh` in augmentation-engine) read `id` from the
  canonical result instead.

## 12. `id`, not `ruleId`, in kompli's own schema

`id` is kompli's sole per-rule identifier. `ruleId` (a UUID hash) is not
consumed by any kompli-internal code path — it exists purely for external
consumers reconstructing the pre-unification MOF/Azure-Policy identity. The
original MOF-era payload key and `ruleId` remain **reconstructible** — not
carried by kompli itself:

- **Schema**: neither `benchmark.schema.json`'s nor
  `kompli-result.schema.json`'s rule `required`/`properties` includes
  `ruleId`.
- **`BenchmarkIO::Resource`**: no `ruleId` field. Every consumer
  (`BenchmarkFormatter`, `Main.cpp`'s `-s/--section` filter and plan lookup,
  `Plan.cpp`'s plan-file keying/parsing, `JUnitRenderer`, `TextRenderers`)
  uses `id`. The `TextStyle::Debug` renderer has no `(ruleId=...)` display
  segment, since the canonical result doesn't carry the field.
- **Augmentation-engine**: `Rule.get_id()` (abstract, and every concrete
  override — `XccdfRule`, `DefinitionRule`, test `MockRule`s) is the
  identifier accessor. `benchmark_def.py` emits no `"ruleId"` key in
  `rule_def`; its identifier key is `"id"`. `mof.py` and `policy.py`'s own
  `rule.get_uuid()`/`"RuleId"`/`"ruleId"` usages (the MOF's `RuleId` DSC
  property, the Azure Policy artifact's `ref["ruleId"]`) are separate from
  kompli's own contract — those are MOF/Azure-Policy concerns.
- **Reconstructibility, the hard requirement this section exists to
  satisfy**: `DefinitionRule.get_uuid()` computes
  `UUID(sha256(full_key))` (the same formula `Rule.get_uuid()` uses) from
  `self.get_key()` (which reconstructs the full slash-form key via §11's CIS
  dot→slash handler). This means `compliancectl get mof` sourcing from a
  committed definition still produces a byte-identical MOF
  `RuleId`/`PayloadKey`, even though neither is stored in the definition
  file — both are derived on demand from `id` plus the file-level hoisted
  prefix (§3).
