kompli - North Star Architecture
========================================

# 1. Introduction

kompli combines a shared [kompli core](glossary.md#engine), a local
[CLI](glossary.md#kompli-cli) and a
[Machine Configuration adapter](glossary.md#mc-adapter) for Linux.

This document describes the North Star architecture of this project. Its prime target is to guide the people who develop kompli. The doc can be also useful to anyone who is interested to learn about this project.

kompli design principles are the following:

- Policy evaluator engine.
- Modular architecture.
- Portable and extensible to other management platforms.
- Simple and focused on what is truly needed.
- Not permanently tied to any management authority.

The main way to extend kompli is by developing new [procedures](../src/engine/procedures/).

# 2. Overall kompli Architecture

## 2.1. Repository Layout

```
src/
  adapters/
    mc/                 Native resource provider (OsConfigResource.c)
      complianceengine/ Compliance bridge (Baseline.c) and shell MOF
  common/
    commonutils/        Shared OS utility functions
    logging/            Circular file logging
    mpiclient/          MPI REST API client
    parson/             Vendored JSON parser
  engine/               Core engine, evaluator, procedures, Lua integration
    tests/              Unit tests
  benchmarkio/          Benchmark-definition parsing + input-file security
  kompli/               kompli CLI tool
  tools/
    lua-evaluator/      Lua evaluator tool
  telemetry/            Telemetry support
  tests/
    fuzzer/             Shared utility libFuzzer targets
```

## 2.2. Scenarios

kompli supports two integration scenarios that share the C++ core in
`src/engine/`:

- **Machine Configuration (NRP)** — a standalone adapter library loaded by the GC worker on demand. MOF resource instances supply each rule's audit and remediation inputs.
- **CLI (`kompli`)** — a standalone CLI tool (`src/kompli/`) that builds plans from one or more benchmark-definition JSON files and executes each plan's per-rule audit/remediation choices without platform or daemon involvement. Definition and plan inputs are required on-disk files; stdin is not supported for them.

Benchmark definitions bind the file-level identity tuple (`framework`,
`distribution`, `distributionVersion`, `benchmarkVersion`) in metadata. Each
rule carries a framework-defined `id` for selection/display and the existing
stable `ruleId` for external correlation. Framework is required and
participates in identity, but it does not select parsing or execution behavior;
all frameworks use the same definition shape. The Machine Configuration path
continues to carry the same tuple plus its rule section in each payload key.
The human-readable `title` is preserved verbatim (including any existing
`id` prefix) and need not be unique. `ruleName` dispatches the engine procedure
and is not a rule identity or uniqueness guarantee; distinct rules remain
distinguished by `id` within their benchmark.

### 2.2.1. Ephemeral CLI state

Short-lived CLI consumers create a private, per-invocation state directory
beneath a non-empty `TMPDIR`. If `TMPDIR` is unset or empty, they use `/tmp` as
the compatibility parent. A configured parent must be absolute, contain no
whitespace, `.`/`..` components, or symlinked components, have a trusted owner,
and not be group- or world-writable without the sticky bit. The parent descriptor remains
open through the context lifetime. A cryptographically random directory name
is created atomically beneath that descriptor with `mkdirat` (mode `0700`),
then the directory itself is held open for descriptor-relative, no-follow
cleanup. The root name is checked against the held directory before removal;
the parent ownership and sticky-bit rules prevent replacement by a different
unprivileged user. A caller with the same UID can still modify its own paths,
so this does not make every later pathname-based consumer operation race-free.
Failure to validate or create a directory beneath the selected parent is
fatal; the process does not retry under a different parent.

# 3. kompli Agent

kompli will be able to run as a standalone daemon that can evaluate policy given requests from external sources.

## 3.1. MMI

The kompli library implements MMI resource [OsConfigResource.c](../src/adapters/mc/OsConfigResource.c) using [Baseline.c](../src/adapters/mc/complianceengine/Baseline.c), which is used as entry point for MMI module in this case only [ComplianceEngineModule.c](../src/modules/complianceengine/src/so/ComplianceEngineModule.c)

The MMI transports the json object payloads of settings for the module.

In general, any process can load a module and communicate to it over the MMI.

The MMI is a simple C API and includes the calls described in this section.

The MMI header file is [src/modules/inc/Mmi.h](../src/modules/inc/Mmi.h)

## 3.2. MmiGetInfo

MmiGetInfo returns information about the module to help the client to correctly identify it. MmiGetInfo may be called at any time and is typically called immediately after the module is loaded by the client, before MmiOpen. MmiGetInfo must succeed called at any time while the module is loaded.

MmiGetInfo takes as input argument the name of the client (the module use that name to identify the caller, same as passed to MmiOpen) and returns via output arguments a JSON payload and size of payload in bytes plus MMI_OK if success, NULL and respectively 0 as payloadSizeBytes plus an error code if failure, same as MmiGet. The caller must free the memory for payload calling MmiFree.

```C
// Not null terminated, UTF-8, JSON formatted string
typedef char MMI_JSON_STRING;

int MmiGetInfo(
    const char clientName,
    MMI_JSON_STRING payload,
    int payloadSizeBytes);
```

The following values can be present in the JSON payload response. The values not marked (optional) are mandatory. Optional values that are implemented are required to follow the following guideline:

Field | Type | Description
-----|-----|-----
Name | String | Name of the module
Description | String | Short description of the module
Manufacturer | String | Name of the module manufacturer
VersionMajor | Integer | Major (first) version number of the module
VersionMinor | Integer |  Minor (second) version number of the module
VersionPatch | Integer | (optional) Patch (third) version number of the module
VersionTweak | Integer | (optional) Tweak (fourth) version number of the module
VersionInfo | String | Short description of the version of the module
Components | List of strings | The names of the components supported by the module, same as used for the componentName argument for MmiGet and MmiSet. Modules are required to support at least one component.
Lifetime | Enumeration of integers | One of the following values: 0 (Undefined), 1 (Long life/keep loaded): the module requires to be kept loaded by the client for as long as possible (for example when the module needs to monitor another component or Hardware), 2 (Short life): the module can be loaded and unloaded often, for example unloaded after a period of inactivity and re-loaded when a new request arrives
LicenseUri | String | (optional) URI path for license of the module
ProjectUri | String | (optional) URI path for the module project
UserAccount | Integer | (optional) The Linux UID of the user account the module needs to run as. One of the UIDs in the local /etc/passwd. 0 is root. Note that UIDs can change (be moved). Root (0) is default.

In addition to the values in the above table the module manufacturer can add their own values.

A JSON schema of the MmiGetInfo payload response is at [MmiGetInfo JSON schema](../src/modules/schema/mmi-get-info.schema.json)

## 3.3. MmiOpen

MmiOpen starts a new client session with the module. MmiOpen receives as an input argument the name of the client (the module use that name to identify the caller) and the maximum size in bytes for object payload values supported by the client (0 if unlimited). On success, MmiOpen returns a newly created handle to identify this session. The handle is a module-specific opaque handle (where the module can hide a C structure or C++ class that identifies the current session) to be used for subsequent calls. On failure, MmiOpen returns NULL.

```C
typedef void* MMI_HANDLE;

MMI_HANDLE MmiOpen(
    const char* clientName,
    const unsigned int maxPayloadSizeBytes);
```

## 3.4. MmiClose

MmiClose ends a client session with the module. MmiClose receives as an input argument the handle returned by a previous MmiOpen call. No further calls with that handle can be made after this call.

```C
void MmiClose(MMI_HANDLE clientSession);
```

## 3.5. MmiSet

MmiSet function is called with the value of of ProcedureObjectName as the objectName parameter and the value of ProcedureObjectValue as the payload parameter.

This call sets up dynamic procedures for audit and, optionally, remediation. It also determines the list of parameters applicable to the procedure with their default values.
ProcedureObjectName as the objectName parameter and the value of ProcedureObjectValue as the payload parameter.


```C
int MmiSet(
    MMI_HANDLE clientSession,
    const char* componentName,
    const char* objectName,
    const MMI_JSON_STRING payload,
    const int payloadSizeBytes);
```

On completion MmiSet returns MMI_OK (0) if success or an error code defined in errno.h.

```C
// Plus any error codes from errno.h
#define MMI_OK 0
```

The payload argument contains a JSON formatted, not null terminated UTF-8 string, that contains one or multiple values in the following format:

- Integer payload example: ```"123"```
- String payload example: ```"This is a test"```
- Boolean payload example: ```"true"```
- Complex payload example combining all the above as fields into same object payload: ```"{"valueOne":123,"valueTwo":"This is a test.","valueThree":true}"``` where "valueOne", "valueTwo" and "valueThree" are the respective field names.

kompli will not attempt to parse and validate the payload and payloadSizeBytes arguments. It is the responsability of the respective Module to do this and return errors if appropriate. Modules must also validate the clientSession, componentName and objectName arguments against invalid values.

The maximum size of payload will be limited to the size specified via MmiOpen if that's a non-zero value (0 meaning unlimited).

MmiSet may be called with the same payload several times. kompli must be able to handle these calls either by reapplying the desired payload or detect when the respective desired configuration was already applied and in that case return MMI_OK without reapplying the payload and without logging errors.

## 3.6. MmiGet

MmiGet takes as input arguments a handle returned by MmiOpen, the name of the Component, the name of the Object, and returns via output arguments the reported Object payload formatted as JSON (same format as for MmiSet), the size of value size and MMI_OK if success, NULL, 0 and an error code defined in errno.h if failure. On success, the caller requests the module to free the memory for the JSON payload with MmiFree.

The objectName and payload must must match a reported. There can only be one single MIM Object per MmiGet call.

```C
int MmiGet(
    MMI_HANDLE clientSession,
    const char* componentName,
    const char* objectName,
    MMI_JSON_STRING* payload,
    int* payloadSizeBytes);
```


## 3.7. MmiFree

Frees memory allocated by Module for the payload returned to MmiGetInfo and MmiGet:

```C
void MmiFree(MMI_JSON_STRING payload);
```


# 4. kompli Management Platform

## 4.1. Introduction

The kompli Management Platform runs in its own daemon process. The platform communicates with the management authority adapters the Universal NRP using MMI.

- MMI Client: makes MMI API calls to modules.

The platform also includes several utility libraries which are shared with all OSConfig components, including adapters and modules:

- Logging: file and console circular logging library.
- CommonUtils: various utility APIs useful for accesing and working with the Linux OS.
- MpiClient: client for the MPI REST API
- Asb: the implementation of the Azure Security Baseline, shared among the Universal NRP adapter and the SecurityBaseline module.

The platform is completely decoupled from the adapters and the modules. The platform can function without any particular adapter. New modules can be installed without changing or recompiling the platform.

## 4.2. Management Platform Interface (MPI)

The Management Platform Interface (MPI) provides a way for the OSConfig Management Platform to be invoked by management authority adapters.

The MPI has two different implementations:

- REST API over Unix Domain Sockets (UDS) for inter-process communication (IPC) with the adapters.
- C API for internal in-process communication between the MPI REST API server and the Modules Manager.

MPI REST API calls include GET (MpiGet, MpiGetReported) and POST (MpiSet, MpiSetDesired).

The MPI C API header file is [src/common/mpiclient/Mpi.h](../src/common/mpiclient/Mpi.h)

The MPI is almost identical to the MMI, except that:

- MMI has one extra method, MmiGetInfo, that each Management Module must implement but it is not needed for the MPI
- MPI has the MpiSetDesired and MpiGetReported that the MMI does not have.

For the MMI C API declarations, including MmiOpen, MmiClose, MmiFree, MmiSet
and MmiGet, see [Mmi.h](../src/modules/inc/Mmi.h).

For more about MpiGetReported and MpiSetDesired see the next section.

### 4.2.1. Functional parity between local and remote management

In addition to the common MpiGet and MpiSet an additional pair of MpiGetReported and MpiSetDesired MPI calls are provided so local management authorities such as OOBE can contact the OSConfig Management Platform directly exchanging full or partial desired and reported payload like it happens for the Digital Twins in the following JSON format, including one or many MIM components and MIM objects:

```
{"ComponentName":{"objectName":[{"stringSettingName":"some value","integerValueName":N,"booleanValueName":true|false,"integerEnumerationSettingName":N,"stringArraySettingName":["stringArrayItemA","stringArrayItemB","stringArrayItemC"],"integerArraySettingName":[A,B,C],"stringMapSettingName":{"mapKeyX":"X","mapKeyY":"Y","mapKeyZ":"Z"},"integerMapSettingName":{"mapKeyX":X,"mapKeyY":Y,"mapKeyZ":Z}},{...}]},{"objectNameZ":{...}}},{"ComponentNameY":{...}}
```

Example:

```json
{"CommandRunner":{"commandArguments":{"commandId":"726","arguments":"ls", "action":4}}, "Settings":{"deviceHealthTelemetryConfiguration":2, "deliveryOptimizationPolicies":{"percentageDownloadThrottle":90,"cacheHostSource":2, "cacheHost":"Test cache host","cacheHostFallback":2021}}}
```

The [RC/DC JSON Schema](../src/modules/schema/rcdc.schema.json) describes this
payload format.

## 4.3. Orchestrator


## 4.9. Logging

kompli provides a Logging library component that makes it easy for all kompli components to log in a standard fashion to date and time stamped self-rolled log files.


# 5. kompli core and CLI

## 5.1. kompli core

The kompli core (`src/engine/`) evaluates rules using recursive JSON payloads with logical combinators (`allOf`, `anyOf`, `not`), built-in C++ procedures, and Lua scripts. It is linked into a dynamically loaded shared object (`.so`) exposing a single MIM component: `Compliance`; the MC adapter (`src/adapters/mc/complianceengine/`) is a separate component.

The MIM definition is at
[src/modules/mim/complianceengine.json](../src/modules/mim/complianceengine.json)
and is validated by the
[MIM JSON Schema](../src/modules/schema/mim.schema.json).

### Procedure entries (`procedure{RuleName}`)

Desired objects (`MmiSet`). The value is a base64-encoded JSON object containing audit and optional remediation procedure snippets, plus a `parameters` map of supported parameters and their default values. The engine decodes the payload, stores the procedure definition, and records the default parameter values for the rule.

### Init entries (`init{RuleName}`)

Desired objects (`MmiSet`). The value is a human-readable, space-separated key-value string (e.g. `PKG_NAME=cron`). Used to supply user-defined parameter overrides that apply when the audit procedure runs. The engine associates the provided values with the parameters registered by the matching procedure entry.

### Remediate entries (`remediate{RuleName}`)

Desired objects (`MmiSet`). Same key-value format as init entries. Triggers execution of the remediation procedure for the rule with the supplied parameter values.

A rule without a `remediate` object is audit-only: the request evaluates its
`audit` tree in audit mode and reports the result without changing the system.
Inside a `remediate` tree, procedures without a remediation handler and anything
under `not` are audited. `SCE` has an explicit remediation stub that always
reports non-compliance without executing a script.

`SysctlValue` remediation accepts a literal value, optionally surrounded by
`^` and `$`. With `runtimeOnly: true` it updates only the selected `/proc/sys`
entry. Otherwise it also atomically maintains
`/etc/sysctl.d/99-zz-kompli-<sysctlName>.conf`; persistent names must use dotted
notation. The name sorts after stock late files such as `99-sysctl.conf` (the
`/etc/sysctl.conf` link) and `99-cloudimg-*.conf`, so the managed value wins
over them. The configuration directory must already exist. Other administrator
files and unrelated runtime keys are not changed. The handler verifies the
existing runtime-and-persistence audit and rolls back both changes if writing
or verification fails, including when a later-precedence file overrides the
managed setting. Missing runtime keys remain not applicable. Regex alternatives
are audit-only: the handler does not guess which acceptable value to select.

On older systemd versions without `systemd-sysctl --cat-config`, the persistence
audit reads the selected `.conf` files directly. It preserves directory priority,
basename masking, lexical filename ordering, and `/dev/null` masks. Legacy
`sysctl.conf` is read only when a selected sysctl.d symlink includes it. Other
command failures and unreadable configuration sources remain explicit errors.

`PasswordPolicyOption` accepts explicit allowlisted targets for existing
`/etc/security/{pwquality,faillock,pwhistory}.conf` files. Numeric settings are
range-checked; boolean flags use the value `"true"` and are written as bare
options. It atomically updates all occurrences of the selected option while
preserving other settings, comments, and file metadata, verifies its own audit,
and restores the original file if verification fails. No reload is needed.
The main pwquality configuration takes precedence over its drop-ins; this
writer does not change drop-ins. The original benchmark audit can still reject
conflicting drop-ins, which must be resolved separately.

Without `integratePam`, the handler requires an existing configuration file and
PAM module reference, including read-only authselect targets. It parses Linux-PAM
continuations and refuses conflicting inline values, custom configuration paths,
and unsafe configuration targets without changing authentication stacks.

The explicit string flag `"integratePam": "true"` enables vendor-managed
integration for installed modules. Authselect systems retain their selected
providers/features; unselected EL systems can adopt a custom profile copied from
their actual PAM and NSS configuration. When the selection is already a
`custom/kompli-preserved-*` profile, later options update its templates in place
(restored on rollback) instead of creating another copy. Debian/Ubuntu use `pam-auth-update`
profiles, including managed faillock preauth/failure/account-reset boundaries.
SUSE password history uses inspected `pam-config` state. Provider or NSS drift,
administrator overrides, unsupported control flow, and vendor command failures
refuse integration and trigger transaction rollback. Existing stronger policy
values are retained. Inline-only history modules receive effective PAM arguments
instead of an ignored configuration file.

Validated faillock integration establishes its configured tally directory using
scoped systemd-tmpfiles metadata, preserving existing administrator metadata.
Validated history integration initializes a missing default `opasswd` database
with root-only permissions and SELinux labeling where applicable; existing
history records remain untouched. Unverified custom databases, missing modules,
unsupported SUSE hooks, and unmanaged activation paths remain explicit refusals.
No existing passwords are changed. Successful configuration validation does not
replace real service authentication, lockout, and password-change testing.
Before enabling password-quality enforcement, provision and verify the vendor
CrackLib dictionary as well as the PAM module. Minimal Debian/Ubuntu images can
have `libpam-pwquality` installed without the recommended dictionary packages;
enforcement then rejects password changes with an error loading the dictionary.
Install `cracklib-runtime` and a vendor word list such as `wamerican`, and verify
real password changes rather than disabling dictionary checks.

`AuditdRules` reports malformed search, exclusion, and required-option regexes
as evaluation errors, not as noncompliance. Legacy distinct-option source
patterns must be lowered to supported regex syntax during payload generation.

`AuditdWatch` remediates only an explicit literal path and permission set.
The target and `/etc/audit/rules.d` must already exist, auditing must be enabled
with a running daemon, and changes require mutable kernel audit state. The
effective `auditd.service` must either have a single `ExecStartPost` command
invoking `/sbin/augenrules --load` or `/usr/sbin/augenrules --load`, or explicitly
require/want the vendor `augenrules.service` or `audit-rules.service`. A vendor
loader must be a loaded oneshot, ordered after auditd, with that same single
`augenrules --load` command. Ambiguous or other startup arrangements are refused,
not inferred. These checks do not execute the loader. An already-compliant
immutable system is left untouched.

The handler creates a mode-0600
`70-kompli-watch-<hex-path>-<permissions>.rules` source when no matching source
exists and adds only the selected runtime watch, using the reserved
`kompli_watch` key. It reuses matching administrator watches without changing
them. Different permissions, syscall-form equivalents, audit suppression,
scoped deletion, and disabled-audit directives require administrator review.
Unreadable or unsafe source files are errors. Permissions must be a nonempty
subset in `rwxa` order; paths are limited to 96 safe literal characters.

It does not create missing watch targets, compile or overwrite `audit.rules`,
restart auditd, invoke a global rule load/flush, or set immutable mode.
Verification checks runtime and persistent sources. Failure removes only a
newly added owned watch and a newly created unchanged managed file; rollback
failures and concurrent changes are reported explicitly. Existing rules and
other successfully remediated leaves are not part of a global transaction.

Generated payloads guard optional `/etc/pam.conf` and `/etc/gshadow` watches with
audit-only file-absence branches, in both audit and remediation. An absent
optional file skips only its watch without creating PAM configuration or a
group-password database; existing files still require their watches. The native writer itself retains
its existing-target requirement.

### Explicit SSH option remediation

`SshdOption` remains audit-only unless `remediationValue` supplies an explicit
literal target. The first slice supports `maxauthtries`, `logingracetime`,
`maxstartups` (`10:30:60`), `disableforwarding`, `permitrootlogin`,
`gssapiauthentication`, `clientaliveinterval`, and `clientalivecountmax`.
Boolean targets only harden the setting; numeric targets have bounded positive
ranges. The target must satisfy the original audit predicate, including customer
overrides, before any write. Values are never inferred from regular expressions.

Already-compliant rules and stricter compliant numeric values are not changed.
For a required change, the main
configuration must be a regular, non-hardlinked file. All includes are inspected
with bounded traversal; conditional `Match` blocks, quoted include paths,
continued lines, custom startup options, and nonstandard/inactive services are
refused for administrator review. Existing `Match` semantics are not rewritten.
The writer prepends an explicit global setting before includes when the
effective value needs changing. It replaces only selected global declarations
whose own value fails the audit predicate in the main file and included files,
preserving declarations the audit accepts (for example a customer-allowed
`prohibit-password`), unrelated content, comments, and metadata. This also
handles a compliant effective boolean whose ignored contradictory declarations
still fail the complete benchmark audit. Every changed source must be regular
and non-hardlinked.

The original configuration and then the candidate are checked with `sshd -t`;
the candidate's effective value is checked through the existing audit before
reloading the active standard `ssh.service` or `sshd.service`. Reload retains
existing sessions. Validation failures restore all modified sources without reload.
A failed reload restores all sources and reloads the original configuration. Rollback never
overwrites a concurrent content change; rollback/recovery failures are errors.
No user/group allowlists or cryptographic policy are generated.

### Audit entries (`audit{RuleName}`)

Reported objects (`MmiGet`). Triggers execution of the audit procedure. Returns a string that begins with `PASS` on success or contains a descriptive log on failure.

## 5.3. kompli CLI Mode

The kompli CLI (`src/kompli/`) is a standalone CLI
tool that reads a benchmark-definition JSON file and drives the engine directly
— no platform daemon, MPI, or RC/DC files are involved.

### Input

`audit` / `remediate` require the benchmark-definition JSON file as a required
positional filename argument; `ParseCommandLine` rejects a missing path or `-`
outright, so stdin is not supported for definitions. Input is capped at 8 MB
and 100 000 rules to guard against malformed or hostile input when running as
root.

### Per-entry execution

For each rule parsed from the benchmark-definition file, kompli:

1. **Registers the procedure** — calls `engine.MmiSet("procedure" + ruleName, procedurePayload)` to load the plain-JSON audit/remediation definition and its default parameter values.
2. **Audit path** — calls `engine.MmiSet("init" + ruleName, initPayload)` with an empty JSON object (rules carry no desired-object override in this format), then calls `engine.MmiGet("audit" + ruleName)` to execute the audit and collect the result.
3. **Remediate path** — calls `engine.MmiSet("remediate" + ruleName, desiredPayload)` to execute the remediation procedure.

`audit` / `remediate` always emit the canonical result JSON; `render` (below)
turns that JSON into one of the presentation formats.

### Output formats

`render` writes to stdout in the format selected by `--format` (default `junit`):

| Format | Description |
|---|---|
| `junit` (default) | JUnit XML, one `<testcase>` per rule |
| `nested-list` | Human-readable hierarchical text |
| `compact-list` | Single-line-per-rule text |
| `debug` | Verbose diagnostic output |

JUnit uses a rule's `id` as the testcase classname and its `title` as the
testcase name (`ruleName` for older results without `title`). Non-empty tags
are rendered as XML-escaped `<tag value="..."/>` entries. Attribute tabs,
newlines, and carriage returns use character references so XML parsers
preserve title, identity, tag, and suite-name values. A present malformed
`tags` field, a non-string `title`, a missing, non-string, empty, or NUL-containing
`id`, or invalid XML 1.0 characters in an attribute cause `render` to fail
rather than publish a misleading report. Legacy body text normalizes illegal
ASCII control characters to spaces; other invalid XML 1.0 characters and
invalid UTF-8 cause rendering to fail. Tags longer than 256 UTF-8 bytes and
JUnit documents over 16 MiB are rejected rather than allowing unbounded
expansion during XML escaping.

`run` always emits the canonical result JSON; `render` is what turns that JSON into one of the formats above.

### Security controls

- The process umask is tightened to at least `S_IRWXG | S_IRWXO` at startup (preserving any stricter inherited mask), restricting file-creation permissions.
- The positional benchmark-definition filename is checked for path traversal and a writable parent directory, then opened with `O_NOFOLLOW`, before it is read.
- The `--log-file` path is validated to refuse symlinks and attacker-writable locations before the log handle is opened.

### Log and telemetry paths

Telemetry-enabled MC shell packages include the executable `kompliTelemetry`
beside `libOsConfigResource.so`. The adapter invokes this helper on unload;
downstream benchmark packages must preserve it when present.

The MC adapter writes `/var/log/kompli/kompli.log`, and the telemetry helper
writes `/var/log/kompli/telemetry.log`. The `/var/log/kompli/` directory is
created if needed. Each log rotates to the same basename with a `.bak`
extension. The standalone module shared object does not write a log file.
The CLI continues to log to stderr unless `--log-file` is supplied.

Telemetry-enabled builds use `/var/lib/kompli/telemetry.events.json` for the
event file and `/var/lib/kompli/telemetry.cache.db` for the telemetry cache.
Existing logs and telemetry data under the old OSConfig paths are not migrated.

# 6. kompli Universal Native Resource Provider (NRP)

The kompli Universal Native Resource Provider (NRP) Adapter links kompli to the [Azure Automanage Machine Configuration (MC)](https://learn.microsoft.com/en-us/azure/governance/machine-configuration/).

Using MC and the kompli Universal NRP, we can create Azure Policies that automatically target for compliance audit or remediation all Linux devices in a particular Azure subscription and Azure resource group.

## 6.1. MC NRP adapter

The NRP scenario uses a standalone shared library (`src/adapters/mc/complianceengine/`) bundled in a policy package. The GC worker dynamically loads the library periodically and uses the `OsConfigResource` class as its interface.

The adapter implements `ComplianceMmiSet` and `ComplianceMmiGet` functions, which follow the same C interface as the existing `AsbMmiSet`/`AsbMmiGet` functions. `OsConfigResource.c` selects the appropriate function set at library-load time based on `ComponentName`, so both ASB and Compliance rules can coexist in the same package without changes to the GC worker.

Direct MMI calls are used (no MPI communication) to match the existing ASB implementation and avoid introducing additional IPC complexity for this critical path.

## 6.2. MOF File Structure

A MOF resource instance describes one compliance rule:

```
instance of OsConfigResource as $OsConfigResource0ref {
    ResourceID           = "Ensure X Y Z";          // human-readable rule title
    ComponentName        = "Compliance";
    ProcedureObjectName  = "procedure{RuleName}";   // optional
    ProcedureObjectValue = "{base64}";              // optional
    InitObjectName       = "init{RuleName}";
    ReportedObjectName   = "audit{RuleName}";
    ExpectedObjectValue  = "PASS";
    DesiredObjectName    = "remediate{RuleName}";
    DesiredObjectValue   = "{key-value string}";    // e.g. "PKG_NAME=cron"
    ModuleName           = "GuestConfiguration";
    ModuleVersion        = "1.0.0";
    ConfigurationName    = "Compliance";
};
```

`ProcedureObjectName` and `ProcedureObjectValue` are optional. When absent they are ignored, leaving existing ASB resource instances unaffected. The Compliance module validates whether these fields are present and whether the payload is correctly formatted.

## 6.3. NRP Control Flow

For each MOF resource instance the GC worker drives the following sequence:

1. **Procedure setup** — `ComplianceMmiSet(ProcedureObjectName, ProcedureObjectValue)` registers the audit/remediation procedures and their default parameter values.
2. **Init (audit parameters)** — `ComplianceMmiSet(InitObjectName, DesiredObjectValue)` applies user-provided parameter overrides that are used during the audit.
3. **Audit** — `ComplianceMmiGet(ReportedObjectName)` executes the audit procedure and returns the result (`PASS` or a descriptive failure log).
4. **Remediation** — `ComplianceMmiSet(DesiredObjectName, DesiredObjectValue)` executes the remediation procedure with the user-provided parameter values.
