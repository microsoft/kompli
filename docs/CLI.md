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

The wire protocol `komplid` will speak is per-rule (`{benchmark, ruleId,
mode}` → one canonical result), because different rules may need different
modes (`audit` vs `remediate` vs the reserved future `enforce`) in the same
run. The CLI needs an input model that can express that, without forcing a
user to hand-enumerate every rule for the common "audit/remediate everything"
case.

### `kompli list <file>` — Planned

Enumerates rules in a benchmark-definition file: `section`, `ruleId`
(payload key), `title`. Prerequisite for building a plan — a user or script
needs to know what to reference before they can toggle its mode. Rules are
referenced by `section` everywhere in this CLI (the dotted CIS/STIG
identifier), not the internal `ruleId` UUID — `section` is documented as the
"externally-quoted per-rule identifier" in `benchmark.schema.json` and is
meant to be human-typeable.

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
`--audit=<section>` / `--remediate=<section>` flags. Output goes to a file
(exact default path/flag: **not yet decided** — candidates: write next to the
input file, or require an explicit `-o/--output`).

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
    "1.1.1.1": "audit",
    "1.1.2": "remediate"
  }
}
```

- `sha256` lets `run` detect that the benchmark file changed since the plan
  was generated (same integrity-verification spirit as the existing
  `InputSecurity` file-hardening checks elsewhere in this codebase, applied to
  a different threat: drift between planning and execution, not tampering).
- Plans are meant to be hand-editable afterward. A rule manually **removed**
  from the `rules` map is not an error — it's how a user narrows a plan down.
- `plan` validates every `--audit=`/`--remediate=` rule reference against the
  benchmark file eagerly (fail fast) — see §4 for why `run` re-validates too.

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
  is forwarded to `komplid` (once daemon-awareness, §6, lands) — the plan/run
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

## 6. Daemon-awareness (Phase 3, not yet designed in detail)

`run` will eventually gain the ability to forward its per-rule requests to
`komplid` instead of executing them in-process, behind some CLI flag (name
not yet decided — candidates discussed: `--with-daemon`, `--passthrough`).
See [src/komplid/README.md](../src/komplid/README.md) for the wire protocol
this would speak. The design principle from §2 applies: this should be an
alternate backend for `run`, not a different input model.
