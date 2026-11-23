# Glossary

These terms describe the engine, local CLI and Machine Configuration
interfaces in this repository. See the [architecture](architecture.md) for
their relationships and the [CLI contract](cli.md) for commands and formats.

## Project and execution

| Term | Meaning |
|---|---|
| <a id="kompli"></a>**kompli (project)** | The Linux security compliance engine, its local CLI and Machine Configuration integration. |
| <a id="engine"></a>**kompli core (engine)** | The C++ evaluator in `src/engine/`, shared by the CLI and MC integration. It evaluates built-in and Lua procedures; it is not the CLI or the resource-provider adapter. |
| <a id="kompli-cli"></a>**`kompli` CLI** | The executable providing `plan`, `run`, `list` and `render`. `run` executes selected rules locally; `plan` and `list` inspect definitions, and `render` formats results. |
| <a id="procedure"></a>**Procedure** | A rule's audit expression and optional remediation expression evaluated by the core, including built-in and Lua operations. |
| <a id="procedure-payload"></a>**Procedure payload** | Serialized procedure JSON. The core accepts plain or base64-encoded JSON; an MC MOF field's encoding is a separate interface requirement. |
| <a id="parameter"></a>**Parameter** | A named string value declared by a rule and resolved from defaults and caller overrides for execution. |

## Definitions, plans and results

| Term | Meaning |
|---|---|
| <a id="benchmark-definition"></a>**Benchmark definition** | Trusted JSON input with an `apiVersion`/`kind`/`metadata`/`spec` envelope and `spec.rules`; identifies a benchmark by framework, distribution, distribution version and benchmark version. |
| <a id="rule"></a>**Rule** | One `spec.rules` entry. Its `id` selects a rule within a definition; `ruleId` is the separate stable external-correlation value; `ruleName` names its core procedure. |
| <a id="plan"></a>**Plan** | CLI JSON selecting definition files and per-rule modes/parameters for a later `run`; it references definitions rather than embedding their procedures. |
| <a id="typed-result"></a>**Typed result** | In-process C++ `Result<T>`, carrying a value or error; an audit value is `AuditResult` with status and payload. This type is not a JSON result or a separate public execution protocol. |
| <a id="rule-result"></a>**Rule result** | Canonical per-rule JSON in a CLI result document's `rules` array. Its status, action, parameters and diagnostics describe one selected rule, not the whole run. |
| <a id="result-document"></a>**Result document** | Whole-run JSON from `BenchmarkFormatter`, with `timestamp`, `host`, `rules`, `durationMs` and overall `status`. CLI `render` consumes this document, not a bare rule result. |

## Machine Configuration interfaces

| Term | Meaning |
|---|---|
| <a id="mc"></a>**MC** | Azure Machine Configuration, the management integration that supplies resource configurations to the GC worker. |
| <a id="gc-worker"></a>**GC worker** | Guest Configuration host process that loads a native resource provider. It is separate from the local CLI process. |
| <a id="nrp"></a>**NRP** | Native Resource Provider: a shared library loaded by the GC worker for a resource class. |
| <a id="mc-adapter"></a>**MC adapter** | The `OsConfigResource` NRP in `src/adapters/mc/`; translates resource operations and MOF fields into calls to the engine and reports resource outcomes. |
| <a id="mof"></a>**MOF** | Managed Object Format resource description consumed by the GC worker. Its resource fields are not interchangeable with native benchmark JSON. |
| <a id="mmi"></a>**MMI** | Management Module Interface: the C interface and object-name dispatch used by the engine's callers in this source version. It is an interface boundary, not another name for the kompli core. |
| <a id="mpi"></a>**MPI** | Management Platform Interface: the retained client transport used by the MC adapter's fallback path. It is distinct from an in-process engine call. |
| <a id="mim"></a>**MIM** | Management Information Model describing the interface's components and objects. A model instance is distinct from the JSON Schema that describes its format. |

For exact data shapes, use the [benchmark schema](../src/engine/benchmark.schema.json),
[result schema](../src/kompli/kompli-result.schema.json) and
[MC adapter guide](../src/adapters/mc/README.md).
