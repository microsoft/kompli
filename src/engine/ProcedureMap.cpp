// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// This file is auto-generated. Do not edit manually.
#include <ProcedureMap.h>
#include <Bindings.h>
#include <RevertMap.h>

namespace Kompli
{
// AideAttributes.h:18
const char* Bindings<AideAttributesParams>::names[] = {"configPath", "filename", "attributes"};

// AksCommand.h:37
const char* Bindings<AksCommandParams>::names[] = {"operation", "clusterName", "resourceGroup", "nodeName", "namespaceName", "serviceAccountName", "podName", "pattern", "matchMeansCompliant"};

// ApparmorProfileState.h:15
const char* Bindings<ApparmorProfileStateParams>::names[] = {"enforce"};

// AuditdRules.h:22
const char* Bindings<AuditdRulesParams>::names[] = {"searchItem", "excludeOption", "requiredOptions"};

// AuditdWatch.h:19
const char* Bindings<AuditdWatchParams>::names[] = {"path", "permissions"};

// CommandOutputMatch.h:43
const char* Bindings<CommandOutputMatchParams>::names[] = {"command", "awk", "pattern", "type"};

// DconfValue.h:31
const char* Bindings<DconfValueParams>::names[] = {"key", "value", "operation"};

// FileExists.h:15
const char* Bindings<FileExistsParams>::names[] = {"filename"};

// FilePermissions.h:39
const char* Bindings<FilePermissionsParams>::names[] = {"path", "owner", "group", "groupId", "permissions", "mask", "behavior"};

// FilePermissions.h:88
const char* Bindings<FilePermissionsCollectionParams>::names[] = {"directory", "recurse", "directoriesOnly", "allFileTypes", "excludeSymlinks", "excludeDirectories", "maximumUid", "maximumGid", "filePattern", "filePatternIsRegex", "owner", "group", "groupId", "permissions", "mask", "behavior"};

// FileRegexMatch.h:82
const char* Bindings<FileRegexMatchParams>::names[] = {"path", "filenamePattern", "filenameSearch", "matchOperation", "matchPattern", "stateOperation", "statePattern", "minimumValue", "maximumValue", "allMatches", "wholeFile", "noneMatches", "ignoreCase", "behavior"};

// FileSymlinkTarget.h:15
const char* Bindings<FileSymlinkTargetParams>::names[] = {"filename", "targetPattern"};

// FilesystemMountOption.h:28
const char* Bindings<FilesystemMountOptionParams>::names[] = {"mountpoint", "mountpointIsPattern", "requireMountpoint", "optionsSet", "optionsNotSet"};

// GsettingsValue.h:56
const char* Bindings<GsettingsValueParams>::names[] = {"schema", "key", "keyType", "operation", "value"};

// KernelModule.h:15
const char* Bindings<KernelModuleUnavailableParams>::names[] = {"moduleName"};

// LogFilePermissions.h:15
const char* Bindings<LogFilePermissionsParams>::names[] = {"path"};

// LoginDefsOption.h:24
const char* Bindings<LoginDefsOptionParams>::names[] = {"option", "value", "comparison"};

// MountPointExists.h:15
const char* Bindings<MountPointExistsParams>::names[] = {"mountPoint"};

// MtaLocalOnly.h:32
const char* Bindings<MtaLocalOnlyParams>::names[] = {"configurationVersion"};

// NameserverCount.h:16
const char* Bindings<NameserverCountParams>::names[] = {"path"};

// NetworkInterfaceFlag.h:73
const char* Bindings<NetworkInterfaceFlagParams>::names[] = {"flag", "interfaceName"};

// NoDuplicateEntries.h:24
const char* Bindings<NoDuplicateEntriesParams>::names[] = {"filename", "delimiter", "column", "context"};

// NoShellAccountsLocked.h:21
const char* Bindings<NoShellAccountsLockedParams>::names[] = {"excludeUsers", "skipBelowUidMin", "skipInvalidShells"};

// PackageInstalled.h:34
const char* Bindings<PackageInstalledParams>::names[] = {"packageName", "minPackageVersion", "packageManager"};

// PasswordPolicyOption.h:26
const char* Bindings<PasswordPolicyOptionParams>::names[] = {"policy", "option", "value", "integratePam"};

// SCE.h:18
const char* Bindings<SCEParams>::names[] = {"scriptName", "environment"};

// ShadowField.h:87
const char* Bindings<ShadowFieldParams>::names[] = {"username", "usernameOperation", "field", "value", "operation"};

// SshKeyPermissions.h:24
const char* Bindings<SshKeyPermissionsParams>::names[] = {"type"};

// SshdOption.h:67
const char* Bindings<SshdOptionParams>::names[] = {"option", "value", "op", "mode", "readExtraConfigs", "remediationValue"};

// SysctlValue.h:25
const char* Bindings<SysctlValueParams>::names[] = {"sysctlName", "value", "runtimeOnly"};

// SystemdConfig.h:55
const char* Bindings<SystemdConfigValueParams>::names[] = {"parameter", "valueRegex", "op", "value", "file", "block", "dir", "passOnNotFound"};

// SystemdUnitState.h:31
const char* Bindings<SystemdUnitStateParams>::names[] = {"unitName", "activeState", "subState", "loadState", "unitFileState", "unit"};

// TestingProcedures.h:15
const char* Bindings<TestingProcedureParams>::names[] = {"message"};

// TestingProcedures.h:29
const char* Bindings<TestingProcedureParametrizedParams>::names[] = {"result"};

// TestingProcedures.h:38
const char* Bindings<TestingProcedureGetParamValuesParams>::names[] = {"KEY1", "KEY2", "KEY3"};

// UfwStatus.h:16
const char* Bindings<UfwStatusParams>::names[] = {"statusRegex"};

// UniqueGroupId.h:19
const char* Bindings<UniqueGroupIdParams>::names[] = {"groupName", "gid"};

// UniqueUserId.h:23
const char* Bindings<UniqueUserIdParams>::names[] = {"username", "uid", "gid"};

const ProcedureMap Evaluator::mProcedureMap = {
    {"AideAttributes", {MakeHandler(AuditAideAttributes), MakeHandler(RemediateAideAttributes)}},
    {"AksCommand", {MakeHandler(AuditAksCommand), nullptr}},
    {"ApparmorProfileState", {MakeHandler(AuditApparmorProfileState), nullptr}},
    {"AuditFailure", {MakeHandler(AuditAuditFailure), nullptr}},
    {"AuditGetParamValues", {MakeHandler(AuditAuditGetParamValues), nullptr}},
    {"AuditNotApplicable", {MakeHandler(AuditAuditNotApplicable), nullptr}},
    {"AuditSuccess", {MakeHandler(AuditAuditSuccess), nullptr}},
    {"AuditdRules", {MakeHandler(AuditAuditdRules), nullptr}},
    {"AuditdWatch", {MakeHandler(AuditAuditdWatch), MakeHandler(RemediateAuditdWatch)}},
    {"CommandOutputMatch", {MakeHandler(AuditCommandOutputMatch), nullptr}},
    {"DconfValue", {MakeHandler(AuditDconfValue), MakeHandler(RemediateDconfValue)}},
    {"DefaultUmask", {MakeHandler(AuditDefaultUmask), MakeHandler(RemediateDefaultUmask)}},
    {"FileExists", {MakeHandler(AuditFileExists), nullptr}},
    {"FilePermissions", {MakeHandler(AuditFilePermissions), MakeHandler(RemediateFilePermissions)}},
    {"FilePermissionsCollection", {MakeHandler(AuditFilePermissionsCollection), MakeHandler(RemediateFilePermissionsCollection)}},
    {"FileRegexMatch", {MakeHandler(AuditFileRegexMatch), nullptr}},
    {"FileSymlinkTarget", {MakeHandler(AuditFileSymlinkTarget), nullptr}},
    {"FilesystemMountOption", {MakeHandler(AuditFilesystemMountOption), MakeHandler(RemediateFilesystemMountOption)}},
    {"FirewalldZoneTargets", {MakeHandler(AuditFirewalldZoneTargets), nullptr}},
    {"GsettingsValue", {MakeHandler(AuditGsettingsValue), MakeHandler(RemediateGsettingsValue)}},
    {"Ip6tablesOpenPorts", {MakeHandler(AuditIp6tablesOpenPorts), nullptr}},
    {"IptablesOpenPorts", {MakeHandler(AuditIptablesOpenPorts), nullptr}},
    {"KernelModuleUnavailable", {MakeHandler(AuditKernelModuleUnavailable), MakeHandler(RemediateKernelModuleUnavailable)}},
    {"LogFilePermissions", {MakeHandler(AuditLogFilePermissions), MakeHandler(RemediateLogFilePermissions)}},
    {"LoginDefsOption", {MakeHandler(AuditLoginDefsOption), MakeHandler(RemediateLoginDefsOption)}},
    {"MountPointExists", {MakeHandler(AuditMountPointExists), nullptr}},
    {"MtaLocalOnly", {MakeHandler(AuditMtaLocalOnly), nullptr}},
    {"NameserverCount", {MakeHandler(AuditNameserverCount), nullptr}},
    {"NetworkInterfaceFlag", {MakeHandler(AuditNetworkInterfaceFlag), nullptr}},
    {"NoDuplicateEntries", {MakeHandler(AuditNoDuplicateEntries), nullptr}},
    {"NoShadowPrimaryGroup", {MakeHandler(AuditNoShadowPrimaryGroup), nullptr}},
    {"NoShellAccountsLocked", {MakeHandler(AuditNoShellAccountsLocked), nullptr}},
    {"NoUnownedFiles", {MakeHandler(AuditNoUnownedFiles), nullptr}},
    {"NoWorldWritableFiles", {MakeHandler(AuditNoWorldWritableFiles), nullptr}},
    {"PackageInstalled", {MakeHandler(AuditPackageInstalled), nullptr}},
    {"PasswdGroupsExist", {MakeHandler(AuditPasswdGroupsExist), MakeHandler(RemediatePasswdGroupsExist)}},
    {"PasswordChangeDate", {MakeHandler(AuditPasswordChangeDate), nullptr}},
    {"PasswordPolicyOption", {MakeHandler(AuditPasswordPolicyOption), MakeHandler(RemediatePasswordPolicyOption)}},
    {"RemediationFailure", {nullptr, MakeHandler(RemediateRemediationFailure)}},
    {"RemediationNotApplicable", {nullptr, MakeHandler(RemediateRemediationNotApplicable)}},
    {"RemediationParametrized", {nullptr, MakeHandler(RemediateRemediationParametrized)}},
    {"RemediationSuccess", {nullptr, MakeHandler(RemediateRemediationSuccess)}},
    {"RootPathSecurity", {MakeHandler(AuditRootPathSecurity), nullptr}},
    {"SCE", {MakeHandler(AuditSCE), MakeHandler(RemediateSCE)}},
    {"SetBenchmarkSettings", {MakeHandler(AuditSetBenchmarkSettings), nullptr}},
    {"ShadowField", {MakeHandler(AuditShadowField), nullptr}},
    {"ShellTimeout", {MakeHandler(AuditShellTimeout), MakeHandler(RemediateShellTimeout)}},
    {"SshKeyPermissions", {MakeHandler(AuditSshKeyPermissions), MakeHandler(RemediateSshKeyPermissions)}},
    {"SshdOption", {MakeHandler(AuditSshdOption), MakeHandler(RemediateSshdOption)}},
    {"SysctlValue", {MakeHandler(AuditSysctlValue), MakeHandler(RemediateSysctlValue)}},
    {"SystemAccountShell", {MakeHandler(AuditSystemAccountShell), nullptr}},
    {"SystemdConfigValue", {MakeHandler(AuditSystemdConfigValue), MakeHandler(RemediateSystemdConfigValue)}},
    {"SystemdUnitState", {MakeHandler(AuditSystemdUnitState), nullptr}},
    {"UfwOpenPorts", {MakeHandler(AuditUfwOpenPorts), nullptr}},
    {"UfwStatus", {MakeHandler(AuditUfwStatus), nullptr}},
    {"UniqueGroupId", {MakeHandler(AuditUniqueGroupId), nullptr}},
    {"UniqueUserId", {MakeHandler(AuditUniqueUserId), nullptr}},
    {"UserDotFilePermissions", {MakeHandler(AuditUserDotFilePermissions), MakeHandler(RemediateUserDotFilePermissions)}},
    {"UserHomeDirectoryPermissions", {MakeHandler(AuditUserHomeDirectoryPermissions), MakeHandler(RemediateUserHomeDirectoryPermissions)}},
    {"WirelessDisabled", {MakeHandler(AuditWirelessDisabled), nullptr}},
    {"XdmcpDisabled", {MakeHandler(AuditXdmcpDisabled), MakeHandler(RemediateXdmcpDisabled)}},
};
} // namespace Kompli

namespace std
{
string to_string(const Kompli::AksCommandOperation value) noexcept(false)
{
    const auto& map = Kompli::MapEnum<Kompli::AksCommandOperation>();
    static const auto revmap = Kompli::RevertMap(map);
    const auto it = revmap.find(value);
    if (revmap.end() == it)
    {
        throw std::out_of_range("Invalid enum value");
    }
    return it->second;
}

string to_string(const Kompli::Behavior value) noexcept(false)
{
    const auto& map = Kompli::MapEnum<Kompli::Behavior>();
    static const auto revmap = Kompli::RevertMap(map);
    const auto it = revmap.find(value);
    if (revmap.end() == it)
    {
        throw std::out_of_range("Invalid enum value");
    }
    return it->second;
}

string to_string(const Kompli::RegexType value) noexcept(false)
{
    const auto& map = Kompli::MapEnum<Kompli::RegexType>();
    static const auto revmap = Kompli::RevertMap(map);
    const auto it = revmap.find(value);
    if (revmap.end() == it)
    {
        throw std::out_of_range("Invalid enum value");
    }
    return it->second;
}

string to_string(const Kompli::DconfOperation value) noexcept(false)
{
    const auto& map = Kompli::MapEnum<Kompli::DconfOperation>();
    static const auto revmap = Kompli::RevertMap(map);
    const auto it = revmap.find(value);
    if (revmap.end() == it)
    {
        throw std::out_of_range("Invalid enum value");
    }
    return it->second;
}

string to_string(const Kompli::Operation value) noexcept(false)
{
    const auto& map = Kompli::MapEnum<Kompli::Operation>();
    static const auto revmap = Kompli::RevertMap(map);
    const auto it = revmap.find(value);
    if (revmap.end() == it)
    {
        throw std::out_of_range("Invalid enum value");
    }
    return it->second;
}

string to_string(const Kompli::IgnoreCase value) noexcept(false)
{
    const auto& map = Kompli::MapEnum<Kompli::IgnoreCase>();
    static const auto revmap = Kompli::RevertMap(map);
    const auto it = revmap.find(value);
    if (revmap.end() == it)
    {
        throw std::out_of_range("Invalid enum value");
    }
    return it->second;
}

string to_string(const Kompli::GsettingsKeyType value) noexcept(false)
{
    const auto& map = Kompli::MapEnum<Kompli::GsettingsKeyType>();
    static const auto revmap = Kompli::RevertMap(map);
    const auto it = revmap.find(value);
    if (revmap.end() == it)
    {
        throw std::out_of_range("Invalid enum value");
    }
    return it->second;
}

string to_string(const Kompli::GsettingsOperationType value) noexcept(false)
{
    const auto& map = Kompli::MapEnum<Kompli::GsettingsOperationType>();
    static const auto revmap = Kompli::RevertMap(map);
    const auto it = revmap.find(value);
    if (revmap.end() == it)
    {
        throw std::out_of_range("Invalid enum value");
    }
    return it->second;
}

string to_string(const Kompli::MtaConfigurationVersion value) noexcept(false)
{
    const auto& map = Kompli::MapEnum<Kompli::MtaConfigurationVersion>();
    static const auto revmap = Kompli::RevertMap(map);
    const auto it = revmap.find(value);
    if (revmap.end() == it)
    {
        throw std::out_of_range("Invalid enum value");
    }
    return it->second;
}

string to_string(const Kompli::InterfaceFlag value) noexcept(false)
{
    const auto& map = Kompli::MapEnum<Kompli::InterfaceFlag>();
    static const auto revmap = Kompli::RevertMap(map);
    const auto it = revmap.find(value);
    if (revmap.end() == it)
    {
        throw std::out_of_range("Invalid enum value");
    }
    return it->second;
}

string to_string(const Kompli::PackageManagerType value) noexcept(false)
{
    const auto& map = Kompli::MapEnum<Kompli::PackageManagerType>();
    static const auto revmap = Kompli::RevertMap(map);
    const auto it = revmap.find(value);
    if (revmap.end() == it)
    {
        throw std::out_of_range("Invalid enum value");
    }
    return it->second;
}

string to_string(const Kompli::ComparisonOperation value) noexcept(false)
{
    const auto& map = Kompli::MapEnum<Kompli::ComparisonOperation>();
    static const auto revmap = Kompli::RevertMap(map);
    const auto it = revmap.find(value);
    if (revmap.end() == it)
    {
        throw std::out_of_range("Invalid enum value");
    }
    return it->second;
}

string to_string(const Kompli::Field value) noexcept(false)
{
    const auto& map = Kompli::MapEnum<Kompli::Field>();
    static const auto revmap = Kompli::RevertMap(map);
    const auto it = revmap.find(value);
    if (revmap.end() == it)
    {
        throw std::out_of_range("Invalid enum value");
    }
    return it->second;
}

string to_string(const Kompli::SshKeyType value) noexcept(false)
{
    const auto& map = Kompli::MapEnum<Kompli::SshKeyType>();
    static const auto revmap = Kompli::RevertMap(map);
    const auto it = revmap.find(value);
    if (revmap.end() == it)
    {
        throw std::out_of_range("Invalid enum value");
    }
    return it->second;
}

string to_string(const Kompli::SshdOptionOperation value) noexcept(false)
{
    const auto& map = Kompli::MapEnum<Kompli::SshdOptionOperation>();
    static const auto revmap = Kompli::RevertMap(map);
    const auto it = revmap.find(value);
    if (revmap.end() == it)
    {
        throw std::out_of_range("Invalid enum value");
    }
    return it->second;
}

string to_string(const Kompli::SshdOptionMode value) noexcept(false)
{
    const auto& map = Kompli::MapEnum<Kompli::SshdOptionMode>();
    static const auto revmap = Kompli::RevertMap(map);
    const auto it = revmap.find(value);
    if (revmap.end() == it)
    {
        throw std::out_of_range("Invalid enum value");
    }
    return it->second;
}

string to_string(const Kompli::SystemdConfigValueOperator value) noexcept(false)
{
    const auto& map = Kompli::MapEnum<Kompli::SystemdConfigValueOperator>();
    static const auto revmap = Kompli::RevertMap(map);
    const auto it = revmap.find(value);
    if (revmap.end() == it)
    {
        throw std::out_of_range("Invalid enum value");
    }
    return it->second;
}

} // namespace std
