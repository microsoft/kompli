# kompli CLI contract

This document is the canonical contract for the `kompli` CLI — what
subcommands exist, what they mean, and the on-disk formats they read/write.
**Keep it in sync with the code**: when a flag, subcommand, or file format
changes, update this document in the same change. Cross-referenced from
[architecture.md](architecture.md) and [src/komplid/README.md](../src/komplid/README.md)
rather than duplicated there.

Status legend used throughout: **Implemented** (matches shipped code today),
**Planned** (designed, not yet implemented), **Deferred** (designed, planned,
but intentionally not scheduled yet).

## 1. Implemented today

| Command | Status | Description |
|---|---|---|
| `kompli audit <file>` | Implemented | Evaluate every rule in a benchmark-definition file, emit the canonical result JSON. |
| `kompli remediate <file>` | Implemented | Remediate every rule in a benchmark-definition file, emit the canonical result JSON. |
| `kompli render [file]` | Implemented | Render a canonical result JSON (from `audit`/`remediate`) into a presentation format. |
| `kompli plan <file>` | Implemented | Generate a plan file selecting a mode (audit/remediate/enforce) per rule. See §2. |
| `kompli run <plan-file>` | Implemented | Execute a plan file (one or more benchmark files), emit one combined canonical result JSON. See §2. |

Common flags: `-h/--help`, `-V/--version`, `-v/--verbose`, `-d/--debug`.
`audit`/`remediate`/`run`-only: `-e/--continue-on-error`, `-l/--log-file`
(`run` does re-check `--section` is *not* accepted - the plan already selects
rules). `audit`/`remediate`-only: `-s/--section` (prefix filter on a rule's
dotted section). `plan`-only: repeatable `--audit=<section>` /
`--remediate=<section>` / `--enforce=<section>` toggles, `-o/--output`.
`render`-only: `-f/--format {junit,nested-list,compact-list,debug}` (default
`junit`), `--suite-name`.

`audit`/`remediate`/`plan`/`run` all require a file as a positional argument
(the benchmark-definition file for the first three, the plan file for `run`);
a missing path or `-` is a hard error — stdin is deliberately
unsupported for definitions (see the input-hardening posture in
`src/modules/complianceengine/src/cli/THREAT_MODEL.md`). `render` is a
root-free, pure transformation and does accept stdin.

Every rule in the file runs in the *same* mode (whichever subcommand was
invoked) — there is no way to mix modes, or to run a subset by anything other
than `--section`'s prefix match. That's the gap this document's "Planned"
section addresses.

## 2. `plan` / `run`, per-rule granularity (implemented)

> **Payload key format, keying, and the hoisted-prefix definition-file schema
> change are specified in [payload-key-format.md](payload-key-format.md)** —
> this section covers the CLI-facing plan/run contract only; that document is
> the canonical source for anything about the `payloadKey` string itself.

### Why

The wire protocol `komplid` will speak is per-rule (`{benchmark, payloadKey,
mode}` → one canonical result), because different rules may need different
modes (`audit` vs `remediate` vs the reserved, not-yet-working `enforce` —
kept in this contract regardless, see below) in the same run. The CLI needs
an input model that can express that, without forcing a user to
hand-enumerate every rule for the common "audit/remediate everything" case.

### `kompli list <file>` — Planned

Enumerates rules in a benchmark-definition file: `section`, `payloadKey`,
`title`. Prerequisite for building a plan — a user or script needs to know
what to reference before they can toggle its mode. A detail view for one rule
(`kompli list <file> --rule=<section>`, exact flag not finalized) additionally
shows its parameters and their defaults — needed so a user knows what's
available to override in a plan (see "Parametrization" under `plan` below).
Rules are referenced by `section` in **CLI-facing arguments**
(`--audit=<section>`, `-s/--section`) — `section` is documented as the
"externally-quoted per-rule identifier" in `benchmark.schema.json` and is
meant to be human-typeable. **The plan file itself keys rules by the full
`payloadKey`, not `section`** (see
[payload-key-format.md §6](payload-key-format.md#6-planrun-key-by-payload-key-not-section--decided-implemented)
for the rationale): `payloadKey` is the field actually guaranteed unique
within a file, and unlike `ruleId` (a checksum, opaque) it needs no lossy
transformation to serve as a lookup key. `plan` resolves a `--audit=<section>`
argument to its rule's `payloadKey` at generation time (`BenchmarkIO::Resource`
retains both fields verbatim); `run` never sees `section` at all.

**Rule-identity caveat (enforced by the parser — see §5):** `payloadKey` is
only guaranteed unique *within one benchmark-definition file*, not globally.
Augmentation-engine-generated CIS/STIG definitions won't collide in
practice, but kompli intends to support user-authored custom rule sets too,
which can't be guaranteed unique against anything else on the system.
[payload-key-format.md §7](payload-key-format.md#7-plan-format-mixing-rules-from-multiple-benchmark-files--decided-implemented)
documents the implemented plan format that lets one plan reference *multiple*
files' rules — each block is still independently scoped to its own file;
there is no cross-file rule identity.

### `kompli plan <file>` — Implemented

Generates a plan: **every** rule in `<file>` is seeded at `mode: audit`
(never a mutating default). Toggle specific rules with repeatable
`--audit=<section>` / `--remediate=<section>` / `--enforce=<section>` flags
(`--enforce` is accepted and recorded like the others, consistent with
keeping `enforce` in every contract even though `run`/`komplid` can't
actually execute it yet — see §2's `enforce` note). **Output default,
decided:** standard output, same as `audit`/`remediate`/`render`; `-o/--output
<path>` writes to a file instead.

**Toggle semantics, decided**: applying `--audit=X` when `X` is already
`audit` in the plan is a no-op; it only modifies `X` if the plan currently
has it in a different mode. Same for `--remediate=`/`--enforce=`. Flags are
applied in argument order, so `--audit=X --remediate=X` in one invocation
resolves to `remediate` (the later flag is the one still in effect once both
have been applied) — not an error, just ordinary last-applied-wins toggling.
An unrecognised `--audit=`/`--remediate=`/`--enforce=` section is a hard
error (fail fast), matching the eager-validation principle in §4.

**Plan file format** (JSON — kept lean, no new parser dependency; the
codebase already leans on `parson` everywhere and this keeps it that way).
One plan can span **multiple** benchmark files (see
[payload-key-format.md §7](payload-key-format.md#7-plan-format-mixing-rules-from-multiple-benchmark-files--decided-implemented)) —
`kompli plan <file>` (single positional argument) always generates a
single-entry `benchmarks` array; combining plans from multiple files today is
a manual JSON edit (concatenating `benchmarks` arrays), not yet a dedicated
CLI feature (tracked in §6):

```jsonc
{
  "benchmarks": [
    {
      "file": "cis_ubuntu24.04.benchmark.json",
      "name": "cis_ubuntu24.04",     // from the definition's metadata.name
      "sha256": "<hash of the file at plan-generation time>",
      "rules": {
        "1/1/1/1": { "mode": "audit", "parameters": { "PKG_NAME": "cramfs" } },
        "1/1/2": { "mode": "remediate", "parameters": {} }
      }
    }
  ]
}
```

Each `rules` map is keyed by `payloadKey` — now just the opaque remainder
(segment 5+ of the full payload key, see
[payload-key-format.md §1](payload-key-format.md#1-structure--decided)),
not the full `/cis/.../...` path, since the file-level prefix
(framework/distribution/distributionVersion/benchmarkVersion) is hoisted into
each `benchmarks[]` entry's referenced file metadata rather than repeated per
rule.

Each rule's value is an object, not a bare mode string, so parameters travel
alongside mode (see "Parametrization" below) rather than needing a second,
key-synchronized map. **Current limitation:** every rule's `parameters` is
currently always an empty object — see "Parametrization" below (still
blocked on the same prerequisite).

- Each block's `sha256` lets `run` detect that its benchmark file changed
  since the plan was generated (same integrity-verification spirit as the
  existing `InputSecurity` file-hardening checks elsewhere in this codebase,
  applied to a different threat: drift between planning and execution, not
  tampering).
- Plans are meant to be hand-editable afterward. A rule manually **removed**
  from a block's `rules` map is not an error — it's how a user narrows a plan
  down. A whole `benchmarks[]` entry can be removed the same way.
- `plan` validates every `--audit=`/`--remediate=`/`--enforce=` rule
  reference against the benchmark file eagerly (fail fast) — see §4 for why
  `run` re-validates too.

### Parametrization

Procedures can be parametrized (e.g. a package name, a file mode/mask); the
unified definitions already carry default values for every parameter today
(only the GC/NRP scenario currently supports overriding them — this folds
that capability into `kompli`/`komplid` too, not just GC).

- **Plan generation pre-fills every rule's parameters with their defaults.**
  A rule's `parameterMetadata` (name → `{default, validationRegex, mandatory,
  displayName}`) is a plain, top-level sibling of `payload` in the
  benchmark-definition schema — not buried inside the opaque procedure
  payload — so `plan` reads it directly (no need to involve the engine at
  all for this). Since defaults are always present, initial plan generation
  never has a rule with missing/unknown parameter values.
- **Overriding a value**: primarily by hand-editing the generated plan
  (change a value under a rule's `parameters`) — the plan already has every
  parameter pre-filled, so most users only need to touch the handful they
  actually want to change. `plan` also gets a repeatable
  `--param=<section>.<name>=<value>` flag as a scripting convenience for the
  same edit, applied like the mode-toggle flags (only at `plan`
  generation/editing time, not at `run` — `run` executes the plan file's
  exact contents, it doesn't accept its own overrides).
- **Validation extends to parameters, same eager-plus-re-validate pattern as
  rule references (§4)**: a `--param=` name must exist in the rule's
  `parameterMetadata`, and its value must match `validationRegex` when the
  rule declares one — checked at `plan` time (fail fast) and again at `run`
  (TOCTOU safety net, same reasoning as §4).
- **Result reporting needs no schema change.** `kompli-result.schema.json`'s
  per-rule object already has a required `parameters` field — this only
  needs the actually-used values (defaults or overrides) threaded through
  into it, not a new field.
- **Code prerequisite, not yet implemented**: `BenchmarkIO::Resource` doesn't
  parse or retain `parameterMetadata` yet — see the `TODO` in `Resource.hpp`.
  **Status: not implemented.** `plan`/`run` only handle mode selection; every
  rule's `parameters` is emitted/read as an empty object regardless of the
  payload's actual parameters. Everything else in this subsection remains
  the design for when the `Resource` prerequisite lands.

### `kompli run <plan-file>` — Implemented

Executes a plan: for each `benchmarks[]` entry, re-resolves its `file` and
re-checks its `sha256` against the plan's recorded hash, re-validates
applicability **once for that file** against the current host (see
[payload-key-format.md §5](payload-key-format.md#5-applicability-checking-splits-by-scenario--decided-implemented)),
then for each rule present in that block's `rules`, runs it in the specified
mode. All blocks' results are combined into **one** canonical result
document covering the whole plan.

- **Severity, decided: hard error**, per block. A `sha256` mismatch aborts
  the run rather than warning and continuing — the plan's rule references
  were only validated against the file as it existed at generation time, so
  proceeding on a changed file would run against unvalidated content.
- **Cross-distro/version mismatch, decided: hard error, whole run aborts.**
  If any block's file doesn't match the current host's distribution/version,
  `run` fails immediately — it does **not** skip that block and continue with
  the rest. Rationale: partial results from a plan that silently dropped a
  mismatched benchmark would be misleading ("let's not mix too much,
  otherwise we'd have to work with partial reports" — the deciding
  rationale). This resolves
  [payload-key-format.md §7](payload-key-format.md#7-plan-format-mixing-rules-from-multiple-benchmark-files--decided-implemented)'s
  previously-open cross-distro-mixing question.
- Re-validates every rule reference against each (re-loaded) benchmark file
  — belt-and-suspenders with `plan`'s eager validation, since a file could
  have changed between the two commands (TOCTOU). This is drift *reduction*,
  not a hard guarantee — accepted tradeoff, not a gap to close later.
- A rule that exists in a benchmark file but is **absent** from that block's
  `rules` map is not evaluated. **Current simplification:** it is also
  omitted from the result entirely, rather than appearing with the designed
  `Skipped` status (see §3) — that needs the per-rule `action` field and
  `Skipped` status this section originally called for, which is deferred
  (tracked in §6) since it also touches `kompli-result.schema.json`,
  `JUnitRenderer`, and `TextRenderers`. Not implemented yet: distinguishing
  "skipped by the plan" from "just not present in the output" in the JSON.
- A rule set to `enforce` fails that rule with a logged error (honoring
  `--continue-on-error`) rather than producing a result for it — `enforce`
  has no execution backend yet (see §2's note on the reserved value).
- Executes in-process today; forwarding to `komplid` (daemon-awareness, §7)
  is unimplemented, so the orthogonality goal below still needs verifying
  against a real second backend.
- Should behave identically whether execution happens in-process (today) or
  is forwarded to `komplid` (once daemon-awareness, §7, lands) — the plan/run
  input model and the execution backend are meant to be orthogonal, so that
  landing daemon support doesn't force another CLI rework.

### `kompli audit <file>` / `kompli remediate <file>` — still their own execution path

The original design called for `audit`/`remediate` to become sugar over
`plan`+`run` (generate a full-coverage temporary plan, then run it). **Not
done yet**: `audit`/`remediate` remain a separate, direct code path in
`Main.cpp` that applies one mode to every rule without ever materializing a
plan file. `run`'s per-rule dispatch shares the same audit/remediate/enforce
switch logic internally (keyed on a per-rule mode rather than the invoked
subcommand), but `audit`/`remediate` do not go through `GeneratePlan`/
`ParsePlanFile` at all. Existing invocations/scripts are unaffected either
way. Revisit collapsing these into one path once the schema changes in §3
land and make it worth the refactor.

### `kompli plan --interactive` — Deferred

Interactively build or edit a plan (pick a rule, pick/toggle its mode,
repeat) rather than only via repeatable flags. Explicitly wanted, explicitly
not scheduled — keeping it here so the design accounts for it (e.g. the plan
format shouldn't need to change to support an interactive editor for it
later).

## 3. Result schema changes this implies

`kompli-result.schema.json`'s current shape has a **top-level** `action`
field (`Audit`/`Remediation`) applying to the whole result. Once one `run`
invocation can mix modes across rules, that has to move to per-rule (each
rule's own action), the same conclusion reached independently for `komplid`'s
wire protocol — the CLI's own output and the daemon's output should converge
on the same per-rule shape rather than diverging again. A new `Skipped`
status value (§2) is also needed. **Neither has been implemented yet** —
`run` instead derives a best-effort top-level `action` (`Remediation` if any
block remediates any rule, `Audit` otherwise) and silently omits plan-absent
rules from the result rather than marking them `Skipped` (see §2's `run`
section for both simplifications). Tracked in §6.

## 4. Validation timing

Both `plan` (at generation) and `run` (at execution) validate rule references
against the benchmark file. This is intentionally redundant — good UX
(fail fast) plus a TOCTOU safety net (the file could change between the two
commands) — not a substitute for a real locking/transaction guarantee, which
is out of scope here.

## 5. Rule-reference uniqueness — implemented

A rule reference (`payloadKey`, which plan/run key on) must be unambiguous
within one file for any of the above to safely rely on it.
`BenchmarkDefinition::ParseString`/`ParseFile`
(`src/modules/complianceengine/src/benchmarkio/BenchmarkDefinition.hpp`) now
**reject** a document with a duplicate `payloadKey` across its rules (checked
as each rule is parsed — see `BenchmarkDefinitionTest.cpp`'s
`RejectsDuplicatePayloadKey`). `section` uniqueness is **not** separately
enforced (see [payload-key-format.md §2](payload-key-format.md#2-the-remainder-is-opaque--decided-implemented) —
`section` and `payloadKey` are independent fields with no required
relationship since the remainder-derivation cross-check was removed); a plan
author referencing a rule by a non-unique `--audit=<section>` gets whichever
rule `GeneratePlan`'s internal `section`→`payloadKey` resolution map happens
to have retained last for that `section` — a known, accepted sharp edge, not
guarded against today.

`BenchmarkIO::Resource` retains both `section` and `payloadKey` verbatim
(implemented — the `Resource.hpp` TODO this used to block on is resolved),
so `komplid`'s wire protocol (which will identify a rule by `payloadKey`) has
what it needs once that work starts.

## 6. TODO items deferred to future planning sessions

Tracked here so they aren't lost, not solved in this document:

- **Per-rule `action` field + `Skipped` status** (§3) — `run` uses a
  best-effort top-level `action` and omits plan-absent rules from the result
  instead. Needs a `kompli-result.schema.json` change plus `JUnitRenderer`/
  `TextRenderers` updates.
- **`kompli list <file>`** (§2) — not implemented; `plan`/`run` assume the
  caller already knows a benchmark's sections (e.g. from the definition
  source or a schema-validated `data/definitions/*.benchmark.json`).
- **Parametrization** (§2) — not implemented; blocked on `BenchmarkIO::
  Resource` parsing/retaining `parameterMetadata` (see its `TODO`). Every
  plan rule's `parameters` is an empty object today.
- **`kompli audit`/`remediate` as literal `plan`+`run` shorthands** (§2) —
  not implemented; they remain a separate direct code path in `Main.cpp`
  today, sharing only the per-rule audit/remediate/enforce dispatch logic
  with `run`.
- **A dedicated `kompli plan --merge`-style flag** (§2) to combine multiple
  files' plans into one, instead of the current manual-JSON-edit workaround.
- **Plan file JSON schema.** Deferred until the plan format itself finishes
  settling — premature to write a schema for a format still in flux.
- **`section` non-uniqueness sharp edge** (§5) — a plan author referencing a
  non-unique `section` via `--audit=<section>` silently resolves to whichever
  rule the internal lookup map retained; not guarded against.
- **augmentation-engine side of the payload-key-format work has not started**
  (see [payload-key-format.md §10](payload-key-format.md#10-augmentation-engine-side-work-not-started--blocking-gap)) —
  every currently-committed `data/definitions/*.benchmark.json` file fails to
  parse under the schema/validation changes above until the generator is
  updated and the 28 files are regenerated. This blocks using real committed
  definitions with the current kompli build, not just a hypothetical future
  concern.
- **Response envelope's exact `error` code taxonomy** and its formal JSON
  schema (see the envelope draft in
  [src/komplid/README.md](../src/komplid/README.md#wire-protocol)) — a clean
  prose shape first, a JSON schema once that settles.
- **Duplicate-request/parametrized-rule interaction** for task
  deduplication — see the "attach to the existing task" note in
  [src/komplid/README.md](../src/komplid/README.md#long-running-rules-background-tasks).

## 7. Daemon-awareness (Phase 3, not yet designed in detail)

`run` will eventually gain the ability to forward its per-rule requests to
`komplid` instead of executing them in-process, behind an explicit
**`--passthrough` flag (decided name)**. Without it, `kompli` always runs
standalone (today's only mode) — there is no auto-detection of `komplid`'s
socket; the daemon is deliberately opt-in while it's still new, so standalone
stays solid as the default. See
[src/komplid/README.md](../src/komplid/README.md) for the wire protocol this
would speak. The design principle from §2 applies: this should be an
alternate backend for `run`, not a different input model.

### Privilege requirement, decided

- **Standalone mode** (the default — no daemon involved): always requires
  root, no lower-privilege path. Unchanged from the original assessor's
  posture.
- **Passthrough mode** (`--passthrough`, once implemented): requires
  membership in the `kompli` system group (or root) to connect to
  `komplid`'s socket and to read `/etc/kompli/`. See
  [src/komplid/README.md](../src/komplid/README.md#privilege-model)
  for the full policy (socket permissions, `SO_PEERCRED`, no role separation
  between `audit`/`remediate`/`enforce`, `/etc/kompli/definitions/` being
  read-only for the group, and the `.deb`/`.rpm` packaging this all depends
  on to create the `kompli` user/group).
- **No fallback between the two.** If `--passthrough` is given but `komplid`
  is unreachable, or the caller has neither root nor `kompli` group
  membership, that's a clear, explicit failure — never a silent attempt to
  run standalone instead (which would just fail confusingly if the caller
  isn't root anyway).
