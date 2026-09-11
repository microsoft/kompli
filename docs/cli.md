# kompli CLI contract

This document is the target design contract for the `kompli` CLI — what
subcommands are meant to exist, what they mean, and the on-disk formats
they read/write. It describes the shape `kompli`'s CLI is converging to, not
a snapshot of what's shipped at any given moment; implementation status and
remaining gaps are tracked separately, in each workstream's own roadmap.
Cross-referenced from [architecture.md](architecture.md) and
[src/komplid/README.md](../src/komplid/README.md) rather than duplicated
there.

## 1. Command overview

| Command | Description |
|---|---|
| `kompli render [file]` | Render a canonical result JSON (from `plan`+`run`) into a presentation format. |
| `kompli plan <file>...` | Generate a plan file selecting a mode (audit/remediate/enforce) per rule, from one or more definition files. See §2. |
| `kompli run <plan-file>` | Execute a plan file (one or more benchmark files), emit one combined canonical result JSON. See §2. |
| `kompli list <file>` | List every rule's `id`/`title`, one per line. See §2. |

Common flags: `-h/--help`, `-V/--version`, `-v/--verbose`, `-d/--debug`.
`run`-only: `-e/--continue-on-error`. kompli logs
to stderr unconditionally (no `--log-file`; see
[logging.md](logging.md) for the sink model and why the flag was removed).
`plan`-only: repeatable
`--audit=<section>` / `--remediate=<section>` / `--enforce=<section>`
toggles (flag names kept for continuity with the payload-key-format's
former `section` field, see §2), `-o/--output`.
`render`-only: `-f/--format {junit,nested-list,compact-list,debug}` (default
`junit`), `--suite-name`. `list` takes no flags beyond the common ones -
see §2.

`plan`/`run`/`list` all require a file as a positional
argument (the benchmark-definition file for `plan`/`list`, the plan file for
`run`); a missing path or `-` is a hard error — stdin is deliberately
unsupported for definitions (see the input-hardening posture in
`src/modules/complianceengine/src/cli/THREAT_MODEL.md`). `render` is a
root-free, pure transformation and does accept stdin.

There is no whole-file, single-mode command — `plan`+`run` (§2) is the only
way to scope and execute rules; a plan can still cover an entire file (every
rule seeded at one mode) when that's what's wanted.

## 2. `plan` / `run`: per-rule granularity

> **Payload key format, keying, and the hoisted-prefix definition-file schema
> change are specified in [payload-key-format.md](payload-key-format.md)** —
> this section covers the CLI-facing plan/run contract only; that document is
> the canonical source for anything about the payload key string itself
> (kompli's own JSON field for it is called `id` - see
> [payload-key-format.md §12](payload-key-format.md#12-id-not-ruleid-in-komplis-own-schema)).

### Why

The wire protocol `komplid` will speak is per-rule (`{benchmark, id,
mode}` → one canonical result), because different rules may need different
modes (`audit` vs `remediate` vs the reserved, not-yet-working `enforce` —
kept in this contract regardless, see below) in the same run. The CLI needs
an input model that can express that, without forcing a user to
hand-enumerate every rule for the common "run everything" case. There is no
separate `audit`/`remediate` command that applies one mode to a whole file —
`plan`+`run` is the only input model, whether a plan covers one rule or
every rule in a file.

### `kompli list <file>`

Enumerates rules in a benchmark-definition file: prints each rule's `id` and
`title`, tab-separated, one per line, in document order, to stdout. Root-free
(same posture as `plan`/`render` — it only reads and parses the file via the
shared `BenchmarkDefinition::ParseFile`, so it inherits the same input-hardening
posture as `plan`/`run`). No flags beyond the common ones
(`-h/-V/-v/-d`); `--continue-on-error`/toggles/`--output`/`--format`
are all rejected, matching `plan`'s scoping. Prerequisite for building a plan —
a user or script needs to know what to reference before they can toggle its
mode. A detail view for one rule
(`kompli list <file> --rule=<id>`, exact flag not finalized) additionally
showing its parameters and their defaults — needed so a user knows what's
available to override in a plan (see "Parametrization" under `plan` below).
`id` is
kompli's *sole* externally-quoted per-rule
identifier — a separate `section` field used to exist but was eliminated
(see [payload-key-format.md §11](payload-key-format.md#11-id-the-sole-per-rule-identifier-no-separate-section)),
and the field itself was later renamed from `payloadKey` to `id` (see
[payload-key-format.md §12](payload-key-format.md#12-id-not-ruleid-in-komplis-own-schema));
it's dot-form for Framework A (e.g. `1.1.1.1`) and unchanged for Framework B
(e.g. `RULE-4502`), and doubles as both the CLI-facing argument
(`--audit=<section>` — flag name kept for continuity with the former
`section` field) and the plan file's lookup key, with no translation step
between the two.

**Rule-identity caveat (enforced by the parser — see §5):** `id` is
only guaranteed unique *within one benchmark-definition file*, not globally.
Definitions-generator-produced files won't collide in
practice, but kompli intends to support user-authored custom rule sets too,
which can't be guaranteed unique against anything else on the system.
[payload-key-format.md §7](payload-key-format.md#7-plan-format-mixing-rules-from-multiple-benchmark-files)
documents the plan format that lets one plan reference *multiple*
files' rules — each block is still independently scoped to its own file;
there is no cross-file rule identity.

### `kompli plan <file>`

Generates a plan: **every** rule in `<file>` is seeded at `mode: audit`
(never a mutating default). Toggle specific rules with repeatable
`--audit=<section>` / `--remediate=<section>` / `--enforce=<section>` flags
(`--enforce` is accepted and recorded like the others, consistent with
keeping `enforce` in every contract even though `run`/`komplid` can't
actually execute it yet — see §2's `enforce` note). **Output default:**
standard output, same as `render`; `-o/--output
<path>` writes to a file instead.

**Toggle semantics**: applying `--audit=X` when `X` is already
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
[payload-key-format.md §7](payload-key-format.md#7-plan-format-mixing-rules-from-multiple-benchmark-files)) —
`kompli plan <file>...` is variadic (see "Multiple definition files in one
`plan`" below): one or more definition files on
the command line produce **one** plan with one `benchmarks[]` entry per file:

```jsonc
{
  "benchmarks": [
    {
      "file": "frameworkA_ubuntu24.04.benchmark.json",
      "name": "frameworkA_ubuntu24.04",     // from the definition's metadata.name
      "sha256": "<hash of the file at plan-generation time>",
      "rules": {
        "1.1.1.1": { "mode": "audit", "parameters": { "PKG_NAME": "cramfs" } },
        "1.1.2": { "mode": "remediate", "parameters": {} }
      }
    }
  ]
}
```

Each `rules` map is keyed by `id` — now just the opaque remainder
(segment 5+ of the full payload key, see
[payload-key-format.md §1](payload-key-format.md#1-structure)),
not the full `/frameworkA/.../...` path, since the file-level prefix
(framework/distribution/distributionVersion/benchmarkVersion) is hoisted into
each `benchmarks[]` entry's referenced file metadata rather than repeated per
rule.

Each rule's value is an object, not a bare mode string, so parameters travel
alongside mode (see "Parametrization" below) rather than needing a second,
key-synchronized map. Every rule's `parameters` is pre-filled from the
rule's `parameterMetadata` defaults at plan-generation time and can be
overridden by hand-editing the plan or via `--param=` (see "Parametrization"
below).

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

### Multiple definition files in one `plan`

The `plan` positional argument is variadic: `kompli plan <file>` covers a
single file; `kompli plan <file1> <file2> ...` produces one plan whose
`benchmarks` array has one entry per file, in argument order. This needs no
new keyword (no `plan generate`/`plan derive`) because `plan` already *is*
the "generate a plan from a definition" command — the runtime plan format
already supports multiple `benchmarks[]` entries (see above,
[payload-key-format.md §7](payload-key-format.md#7-plan-format-mixing-rules-from-multiple-benchmark-files)).

- **Duplicate files: hard error.** The same file path given twice
  (or two different paths that canonicalize to the same file) is rejected
  eagerly, matching the fail-fast principle in §4 — a plan with two entries
  for one file is never a sensible thing to generate.
- **Cross-file benchmark-identity uniqueness: hard error.** Two
  *different* file paths are still rejected if they resolve to the same
  `(framework, distribution, distributionVersion, benchmarkVersion)` tuple
  (each file's own hoisted metadata prefix, §1/§3 of
  [payload-key-format.md](payload-key-format.md)) — that tuple identifies
  *which benchmark* a file is, and §1's one-prefix-per-file invariant only
  guarantees uniqueness *inside* one file, not across several given to one
  `plan` invocation. Two files sharing a tuple are either the same benchmark
  staged twice under different names, or two genuinely different revisions
  disagreeing about which one is current — both are ambiguous inputs, not a
  case to silently pick one and continue. Checked before any rule references
  are resolved (fail fast, §4). This is **separate from, and in addition to**
  the per-file `id`-uniqueness check (§5) — one governs uniqueness of rules
  *inside* a file, the other governs uniqueness of *which files* may appear
  together.
- **The same check applies to `run` too.** `run`'s multi-`benchmarks[]`-block
  execution (§2,
  [payload-key-format.md §7](payload-key-format.md#7-plan-format-mixing-rules-from-multiple-benchmark-files))
  must reject a hand-edited plan with two blocks pointing at files that
  share a `(framework, distribution, distributionVersion, benchmarkVersion)`
  tuple — `Main.cpp`'s `run` dispatch calls `CheckUniqueBenchmarkIdentities`
  (`Plan.cpp`/`Plan.hpp`) over every block's already-resolved
  `CISBenchmarkInfo`, before evaluating any rule, whether the plan was
  hand-assembled or produced by the multi-file `plan`.
- **Toggle-flag ambiguity across files.** `id` is only guaranteed
  unique *within* one file (the rule-identity caveat under `kompli list`
  above) — with several files in one `plan` invocation, an unqualified
  `--audit=<id>` could match a rule in more than one of them. Resolution:
  when **more than one** file is given, every `--audit=`/`--remediate=`/
  `--enforce=`/`--param=` value must be **qualified** as `<file-basename>:<id>` (e.g.
  `--audit=frameworkA_ubuntu24.04.benchmark.json:1.1.1.1`); an unqualified value is a
  hard error in that case. With exactly **one** file, unqualified values keep
  working exactly as with a single-file `plan` (no forced migration for the
  common case). An unrecognised `<file-basename>` (doesn't match any of the
  given files) or an `id` not found in the file it's qualified against is a
  hard error, same as the unqualified-unrecognised-section error.
- **Output, unchanged.** Same `-o/--output` behavior; still one JSON document
  on stdout or to the given path.
- **Not in scope**: an interactive picker across files (that's
  `plan --interactive`, below) and a `--merge` flag that combines two
  *already-generated* plan files (regenerating from the source definitions
  is always equivalent and simpler, since plans are meant to be regenerated
  rather than hand-assembled from other plans).

### Parametrization

Procedures can be parametrized (e.g. a package name, a file mode/mask); the
The unified definitions carry default values for every parameter (only the
GC/NRP scenario supports overriding them elsewhere — this folds
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
  actually want to change. `plan` also has a repeatable
  `--param=<ref>.<name>=<value>` flag as a scripting convenience for the
  same edit, applied like the mode-toggle flags (only at `plan`
  generation/editing time, not at `run` — `run` executes the plan file's
  exact contents, it doesn't accept its own overrides). `<ref>` uses the
  same qualification form as a toggle's `<ref>` (see "Multiple definition
  files in one `plan`" above): an unqualified `<id>`
  with one input file, or `<file-basename>:<id>` with more than one.
- **Validation extends to parameters, same eager-plus-re-validate pattern as
  rule references (§4)**: a `--param=` name must exist in the rule's
  `parameterMetadata`, and its value must match `validationRegex` when the
  rule declares one — checked at `plan` time (fail fast). `run` threads a
  plan's resolved parameter values into the procedure it executes
  (`ApplyParameterOverrides`), overwriting the procedure's own baked-in
  defaults with the plan's.
- **Result reporting needs no schema change.** `kompli-result.schema.json`'s
  per-rule object already has a required `parameters` field — the actually-
  used values (defaults or overrides) are threaded through into it.

### `kompli run <plan-file>`

Executes a plan: for each `benchmarks[]` entry, re-resolves its `file` and
re-checks its `sha256` against the plan's recorded hash, re-validates
applicability **once for that file** against the current host (see
[payload-key-format.md §5](payload-key-format.md#5-applicability-checking-splits-by-scenario)),
then for each rule present in that block's `rules`, runs it in the specified
mode. All blocks' results are combined into **one** canonical result
document covering the whole plan.

- **Severity: hard error**, per block. A `sha256` mismatch aborts
  the run rather than warning and continuing — the plan's rule references
  were only validated against the file as it existed at generation time, so
  proceeding on a changed file would run against unvalidated content.
- **Cross-distro/version mismatch: hard error, whole run aborts.**
  If any block's file doesn't match the current host's distribution/version,
  `run` fails immediately — it does **not** skip that block and continue with
  the rest. Rationale: partial results from a plan that silently dropped a
  mismatched benchmark would be misleading ("let's not mix too much,
  otherwise we'd have to work with partial reports"). This resolves
  [payload-key-format.md §7](payload-key-format.md#7-plan-format-mixing-rules-from-multiple-benchmark-files)'s
  cross-distro-mixing question.
- **Duplicate benchmark identity across blocks: hard error.** Before
  evaluating any rule, `run` checks every block's already-resolved
  `CISBenchmarkInfo` and refuses the plan if two blocks
  share the same `(framework, distribution, distributionVersion,
  benchmarkVersion)` tuple (`CheckUniqueBenchmarkIdentities` in `Plan.cpp`) —
  such a plan is ambiguous (the same benchmark staged twice, or two
  revisions disagreeing about which is current), not a case to silently
  pick one and continue. The same check applies to the variadic `plan`
  (see "Multiple definition files in one `plan`" above) at generation time.
- Re-validates every rule reference against each (re-loaded) benchmark file
  — belt-and-suspenders with `plan`'s eager validation, since a file could
  have changed between the two commands (TOCTOU). This is drift *reduction*,
  not a hard guarantee — accepted tradeoff, not a gap to close later.
- A rule that exists in a benchmark file but is **absent** from that block's
  `rules` map is not evaluated, and appears in the result with a `Skipped`
  status (see §3) rather than being silently omitted — distinguishing
  "skipped by the plan" from "just not present in the output" in the JSON.
- A rule set to `enforce` fails that rule with a logged error (honoring
  `--continue-on-error`) rather than producing a result for it — `enforce`
  has no execution backend (see §2's note on the reserved value).
- Execution happens either in-process (the default) or forwarded to
  `komplid` via `--passthrough` (daemon-awareness, §7) — the plan/run input
  model and the execution backend are meant to be orthogonal, so switching
  backend doesn't require a CLI rework.

### `kompli plan --interactive`

Interactively build or edit a plan (pick a rule, pick/toggle its mode,
repeat) rather than only via repeatable flags — kept in the design so the
plan format doesn't need to change to support an interactive editor for it
later.

## 3. Result schema changes this implies

`kompli-result.schema.json`'s current shape has a **top-level** `action`
field (`Audit`/`Remediation`) applying to the whole result. Once one `run`
invocation can mix modes across rules, that has to move to per-rule (each
rule's own action), the same conclusion reached independently for `komplid`'s
wire protocol — the CLI's own output and the daemon's output should converge
on the same per-rule shape rather than diverging again. A new `Skipped`
status value (§2) is also needed for a rule present in a benchmark file but
absent from a plan's `rules` map.

## 4. Validation timing

Both `plan` (at generation) and `run` (at execution) validate rule references
against the benchmark file. This is intentionally redundant — good UX
(fail fast) plus a TOCTOU safety net (the file could change between the two
commands) — not a substitute for a real locking/transaction guarantee, which
is out of scope here.

## 5. Rule-reference uniqueness

A rule reference (`id`, which plan/run key on, and which is
kompli's *sole* per-rule identifier — see
[payload-key-format.md §12](payload-key-format.md#12-id-not-ruleid-in-komplis-own-schema))
must be unambiguous within one file for any of the above to safely rely on
it. `BenchmarkDefinition::ParseString`/`ParseFile`
(`src/modules/complianceengine/src/benchmarkio/BenchmarkDefinition.hpp`) must
**reject** a document with a duplicate `id` across its rules, checked as each
rule is parsed.

`BenchmarkIO::Resource` retains `id` verbatim, which `komplid`'s wire
protocol needs to identify a rule by `id`.

## 6. Open design questions

Not yet resolved by this contract:

- **Per-rule `action` field + `Skipped` status** (§2, §3) — needs a
  `kompli-result.schema.json` change plus `JUnitRenderer`/`TextRenderers`
  updates.
- **`kompli list <file> --rule=<id>` detail view** (§2) — exact flag/output
  not finalized.
- **Plan file JSON schema** — premature to write until the plan format
  itself finishes settling.
- **Response envelope's exact `error` code taxonomy** and its formal JSON
  schema (see the envelope draft in
  [src/komplid/README.md](../src/komplid/README.md#wire-protocol)) — a clean
  prose shape first, a JSON schema once that settles.
- **Duplicate-request/parametrized-rule interaction** for task
  deduplication — see the "attach to the existing task" note in
  [src/komplid/README.md](../src/komplid/README.md#long-running-rules-background-tasks).

## 7. Daemon-awareness

`run` forwards its per-rule requests to `komplid` instead of executing them
in-process when given an explicit **`--passthrough` flag**. Without it,
`kompli` runs standalone. There is no auto-detection of `komplid`'s socket —
passthrough is deliberately opt-in, so standalone remains the solid default.
See [src/komplid/README.md](../src/komplid/README.md) for the wire protocol
this would speak. The design principle from §2 applies: this is an alternate
backend for `run`, not a different input model.

### Privilege requirement

- **Standalone mode** (the default — no daemon involved): always requires
  root, no lower-privilege path. Unchanged from the original assessor's
  posture.
- **Passthrough mode** (`--passthrough`): requires
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

