# Remediation candidate assessment

This assessment combines ComplianceEngine handler availability with procedure
usage in 8,112 generated benchmark rules from the Compliance Augmentation
Engine. Usage is shown as `rules / positive leaves`; negated leaves are excluded
because remediation generation intentionally does not invert audit procedures.

## Recommendation

`KernelModuleUnavailable` is the best next remediation candidate.

- It is used by 270 rules and every payload supplies one exact module name.
- The desired state is one-way and deterministic.
- A conservative first implementation can persist a managed modprobe deny rule
  while refusing to unload a module that is already active.
- It avoids the immediate lockout risks of SSH, firewall, account, and live
  service-state changes.

The initial implementation should:

1. Validate the module name.
2. Return without mutation when the audit is already compliant.
3. Refuse to unload a loaded module.
4. Maintain a Kompli-owned file below `/etc/modprobe.d` containing both
   `blacklist <module>` and `install <module> /bin/false`.
5. Use atomic creation or replacement, validate with `modprobe --showconfig`,
   post-audit, and roll back on failure.
6. Avoid initramfs updates and runtime unloads.

## Highest-value alternatives

| Rank | Procedure | Usage | Assessment |
|---|---|---:|---|
| 1 | `KernelModuleUnavailable` | 270 / 270 | Best risk-adjusted candidate; exact target and safe persistent-only first phase |
| 2 | `SystemdUnitState` | 417 / 863 | Broad value, including 300 exact `enabled` and 306 exact `active` leaves, but changing service state is operationally disruptive |
| 3 | `AuditdRules` | 408 / 1,130 | High raw volume, but only 152 rules and 387 leaves are straightforward literal watch rules; loading rules changes the running audit subsystem |
| 4 | `PackageInstalled` | 447 / 652 | Deterministic installation target, but network, dependency, and maintainer-script impact; intentionally deferred |
| 5 | `SshdOption` | 412 / 687 | High coverage, but values are mainly regexes, lists, or thresholds and incorrect changes can cause remote lockout |
| 6 | `ShadowField` | 86 / 123 | Some numeric policies are deterministic, but broad username patterns can change many accounts and cause lockout |

## Complete procedure assessment

| Procedure | Usage | Assessment |
|---|---:|---|
| `FileRegexMatch` | 2,398 / 5,853 | The API describes acceptable text, not replacement text or the authoritative file. It needs a structured edit API. |
| `AuditFailure` | 450 / 462 | Control procedure intentionally representing failure; it has no remediation semantics. |
| `PackageInstalled` | 447 / 652 | Install-if-absent is feasible but high impact. Minimum versions also introduce upgrade and repository complexity. |
| `AuditSuccess` | 446 / 446 | Control procedure already representing success; remediation is meaningless. |
| `SystemdUnitState` | 417 / 863 | Active and persistent state should be separated before starting, stopping, enabling, disabling, or masking units. |
| `SshdOption` | 412 / 687 | Needs exact targets, managed early-precedence drop-ins, `sshd -t` and `sshd -T`, reload, and rollback protection. |
| `AuditdRules` | 408 / 1,130 | Literal watch rules are feasible. Regex and alternative syscall rules do not identify one canonical rule; `-e 2` must remain excluded. |
| `KernelModuleUnavailable` | 270 / 270 | Recommended. Exact module target and a conservative persistent-only implementation are possible. |
| `MountPointExists` | 169 / 169 | Knows only the mount point, not device, filesystem, options, or persistence policy. |
| `CommandOutputMatch` | 156 / 304 | Arbitrary command output has no general inverse. |
| `UfwStatus` | 109 / 124 | Uses a status regex rather than explicit enable/disable intent. Enabling a firewall can cause remote lockout. |
| `ShadowField` | 86 / 123 | Numeric fields can sometimes derive values, but many rules target all users and require exclusions and recovery policy. |
| `NoDuplicateEntries` | 84 / 84 | Detects duplicate names or IDs but cannot determine which record is authoritative. |
| `NoShellAccountsLocked` | 22 / 22 | Aggregate account mutation with lockout risk and no explicit account selection or exclusions. |
| `NoUnownedFiles` | 22 / 22 | Cannot infer the correct owner of each filesystem object. |
| `NoWorldWritableFiles` | 22 / 22 | Removing world-write is mechanically possible but is a broad recursive mutation across application and user data. |
| `MtaLocalOnly` | 21 / 21 | Aggregate check without a backend-specific target; needs separate Postfix, Exim, and Sendmail adapters. |
| `PasswordChangeDate` | 21 / 21 | Changing dates affects password expiry broadly and the target semantics are insufficient for safe mutation. |
| `SystemAccountShell` | 21 / 21 | Aggregate account-shell changes can break services and lack explicit account targets and exclusions. |
| `RootPathSecurity` | 20 / 20 | Can represent multiple unrelated path, ownership, and permission defects without identifying one mutation. |
| `WirelessDisabled` | 20 / 20 | Dynamically discovers device modules; denying them can remove network access and has no explicit deployment opt-in. |
| `FileSymlinkTarget` | 18 / 28 | Stores only a compiled target regex, so the desired literal symlink target cannot be recovered. |
| `ApparmorProfileState` | 14 / 14 | Aggregate counts do not identify which profiles to load or change. |
| `Ip6tablesOpenPorts` | 6 / 6 | Firewall mutation lacks rule ownership, persistence, and connection-preservation policy. |
| `IptablesOpenPorts` | 6 / 6 | Same concerns as IPv6 firewall rules. |
| `NoShadowPrimaryGroup` | 6 / 6 | Identity database mutation can break account ownership and cannot infer replacement groups safely. |
| `FirewalldZoneTargets` | 5 / 5 | Changing zone targets can immediately disrupt network access and needs transactional apply with timed rollback. |
| `UfwOpenPorts` | 4 / 4 | Cannot safely infer which application or rule should change; remote lockout risk. |
| `FileExists` | 0 / 0 | Used only under negation in current audits and lacks object type, content, owner, group, and mode. |
| `NetworkInterfaceFlag` | 0 / 0 | Used only under negation and expresses presence rather than explicit set/clear intent or persistence. |
| `UniqueGroupId` | 0 / 0 | Aggregate identity mutation cannot select the authoritative group or a safe new ID. |
| `UniqueUserId` | 0 / 0 | Same issue for users, plus filesystem ownership migration requirements. |
| `AksCommand` | 0 / 0 | Arbitrary command audit with no general inverse. |
| `AuditGetParamValues` | 0 / 0 | Internal utility, not a machine-state remediation target. |
| `AuditNotApplicable` | 0 / 0 | Control procedure; remediation is meaningless. |
