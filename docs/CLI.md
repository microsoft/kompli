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

Common flags: `-h/--help`, `-V/--version`, `-v/--verbose`, `-d/--debug`.
`audit`/`remediate`-only: `-e/--continue-on-error`, `-l/--log-file`,
`-s/--section` (prefix filter on a rule's dotted section). `render`-only:
`-f/--format {junit,nested-list,compact-list,debug}` (default `junit`),
`--suite-name`.

`audit`/`remediate` require the benchmark-definition file as a positional
argument; a missing path or `-` is a hard error — stdin is deliberately
unsupported for definitions (see the input-hardening posture in
`src/modules/complianceengine/src/cli/THREAT_MODEL.md`). `render` is a
root-free, pure transformation and does accept stdin.

Every rule in the file runs in the *same* mode (whichever subcommand was
invoked) — there is no way to mix modes, or to run a subset by anything other
than `--section`'s prefix match. That's the gap this document's "Planned"
section addresses.

## 2. Planned: `plan` / `run`, per-rule granularity

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
Rules are referenced by
`section` everywhere in this CLI (the dotted CIS/STIG identifier) — `section`
is documented as the "externally-quoted per-rule identifier" in
`benchmark.schema.json` and is meant to be human-typeable. `run` resolves
each plan entry's `section` to a `payloadKey` via the benchmark file before
dispatching (locally or to `komplid`) — `payloadKey`, not `ruleId`, is what
actually identifies a rule internally (wire requests, the plan file's
resolved form, the task registry, the audit cache). `ruleId` is a checksum
*of* the payload key, retained in the canonical result purely for external
conformance (some consumers already key off it) — it carries no information
`payloadKey` doesn't already have, so nothing internal needs it.

**Rule-identity caveat (important, not yet enforced by the parser — see §5):**
`payloadKey`/`section` is only guaranteed unique *within one benchmark-definition
file*, not globally. Augmentation-engine-generated CIS/STIG definitions won't
collide in practice, but kompli intends to support user-authored custom rule
sets too, which can't be guaranteed unique against anything else on the
system. Every rule reference in a plan or a `komplid` request is therefore
implicitly scoped to one file — there is no cross-file rule identity.

### `kompli plan <file>` — Planned

Generates a plan: **every** rule in `<file>` is seeded at `mode: audit`
(never a mutating default). Toggle specific rules with repeatable
`--audit=<section>` / `--remediate=<section>` / `--enforce=<section>` flags
(`--enforce` is accepted and recorded like the others, consistent with
keeping `enforce` in every contract even though `run`/`komplid` can't
actually execute it yet — see §2's `enforce` note). Output goes to a file
(exact default path/flag: **not yet decided** — candidates: write next to the
input file, or require an explicit `-o/--output`).

**Toggle semantics, decided**: applying `--audit=X` when `X` is already
`audit` in the plan is a no-op; it only modifies `X` if the plan currently
has it in a different mode. Same for `--remediate=`/`--enforce=`. Flags are
applied in argument order, so `--audit=X --remediate=X` in one invocation
resolves to `remediate` (the later flag is the one still in effect once both
have been applied) — not an error, just ordinary last-applied-wins toggling.

**Plan file format** (JSON — kept lean, no new parser dependency; the
codebase already leans on `parson` everywhere and this keeps it that way):

```jsonc
{
  "benchmark": {
    "file": "cis_ubuntu24.04.benchmark.json",
    "name": "cis_ubuntu24.04",     // from the definition's metadata.name
    "sha256": "<hash of the file at plan-generation time>"
  },
  "rules": {
    "1.1.1.1": { "mode": "audit", "parameters": { "PKG_NAME": "cramfs" } },
    "1.1.2": { "mode": "remediate", "parameters": {} }
  }
}
```

Each rule's value is an object, not a bare mode string, so parameters travel
alongside mode (see "Parametrization" below) rather than needing a second,
key-synchronized map.

- `sha256` lets `run` detect that the benchmark file changed since the plan
  was generated (same integrity-verification spirit as the existing
  `InputSecurity` file-hardening checks elsewhere in this codebase, applied to
  a different threat: drift between planning and execution, not tampering).
- Plans are meant to be hand-editable afterward. A rule manually **removed**
  from the `rules` map is not an error — it's how a user narrows a plan down.
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

### `kompli run <plan-file>` — Planned

Executes a plan: for each rule present in `rules`, run it in the specified
mode against the referenced benchmark file; emit one canonical result
document covering the whole plan.

- Re-resolves `benchmark.file` and re-checks its `sha256` against the plan's
  recorded hash before running anything; a mismatch is at least a warning
  (exact severity — hard error vs. warn-and-continue — **not yet decided**).
- Re-validates every rule reference against the (re-loaded) benchmark file —
  belt-and-suspenders with `plan`'s eager validation, since the file could
  have changed between the two commands (TOCTOU). This is drift *reduction*,
  not a hard guarantee — accepted tradeoff, not a gap to close later.
- A rule that exists in the benchmark file but is **absent** from the plan's
  `rules` map is not silently omitted from the result: it appears with a new
  `Skipped` status (see §3) rather than being indistinguishable from
  `NotApplicable` (which already means something different — "doesn't apply
  to this OS/version"). `Skipped` rolls up like `NotApplicable` in the overall
  aggregate status (doesn't drag it to `NonCompliant`) but stays visible in
  the per-rule detail.
- Should behave identically whether execution happens in-process (today) or
  is forwarded to `komplid` (once daemon-awareness, §7, lands) — the plan/run
  input model and the execution backend are meant to be orthogonal, so that
  landing daemon support doesn't force another CLI rework.

### `kompli audit <file>` / `kompli remediate <file>` — become shorthands

Once `plan`/`run` exist, these two stop being their own execution path and
become sugar: generate a full-coverage temporary plan (every rule at the
invoked mode) in `CliContext`'s existing per-invocation ephemeral directory
(`/tmp/kompli-cli.XXXXXX`, already created and cleaned up today — no new
mechanism needed), then run it. Existing invocations/scripts keep working
unchanged; there is exactly one real execution path (`run`) underneath both.

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
status value (§2) is also needed. Neither has been implemented yet.

## 4. Validation timing

Both `plan` (at generation) and `run` (at execution) validate rule references
against the benchmark file. This is intentionally redundant — good UX
(fail fast) plus a TOCTOU safety net (the file could change between the two
commands) — not a substitute for a real locking/transaction guarantee, which
is out of scope here.

## 5. Prerequisite not yet implemented: payload-key uniqueness

None of the above can safely rely on "a rule reference is unambiguous within
one file" until the parser actually enforces it. Today,
`BenchmarkDefinition::ParseString`/`ParseFile`
(`src/modules/complianceengine/src/benchmarkio/BenchmarkDefinition.hpp`) do
**not** reject a document with a duplicate `payloadKey` across its rules —
see the `TODO` left in that header. This needs to land before `list`/`plan`/
`run` can trust rule-reference uniqueness.

Also not yet implemented: `BenchmarkIO::Resource` currently discards the raw
`payloadKey` string once it's parsed into `benchmarkInfo` (see the `TODO` in
`Resource.hpp`) — it needs to retain it verbatim, since `payloadKey` (not
`ruleId`) is the identifier the rest of this design uses internally.

## 6. TODO items deferred to future planning sessions

Tracked here so they aren't lost, not solved in this document:

- **Plan file JSON schema.** Deferred until the plan format itself finishes
  settling — premature to write a schema for a format still in flux.
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
