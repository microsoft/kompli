// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <Regex.h>
#include <StringTools.h>
#include <SysctlValue.h>
#include <algorithm>
#include <fcntl.h>
#include <fstream>
#include <sstream>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

namespace ComplianceEngine
{
// Valid sysctl names contain only alphanumeric characters, dots, underscores, hyphens, and forward slashes.
// Forward slashes are valid in some sysctl naming conventions (e.g., fs.binfmt_misc.python3/10).
// Path traversal is still prevented by the ".." check below.
static bool IsValidSysctlName(const std::string& name)
{
    if (name.empty())
    {
        return false;
    }

    // Check for path traversal patterns
    if (name.find("..") != std::string::npos)
    {
        return false;
    }

    // Validate characters: only allow alphanumeric, dots, underscores, hyphens, and forward slashes
    static const regex validPattern("^[a-zA-Z0-9._/-]+$");
    return regex_match(name, validPattern);
}

// File paths must be absolute and not contain path traversal sequences
static bool IsValidFilePath(const std::string& path)
{
    if (path.empty())
    {
        return false;
    }

    // Must be absolute path
    if (path[0] != '/')
    {
        return false;
    }

    // Check for path traversal patterns
    if (path.find("..") != std::string::npos)
    {
        return false;
    }

    return true;
}

static Result<std::string> GetLiteralRemediationValue(const Pattern& value)
{
    std::string literal = value.GetPattern();
    if (literal.size() >= 2 && literal.front() == '^' && literal.back() == '$')
    {
        literal = literal.substr(1, literal.size() - 2);
    }
    if (literal.empty() || literal.find_first_of(R"(\.^$|()[]{}*+?)") != std::string::npos || literal.find('\0') != std::string::npos ||
        literal.find_first_of("\r\n") != std::string::npos)
    {
        return Error("Sysctl remediation requires an exact literal value", ENOTSUP);
    }
    return literal;
}

static Optional<Error> WriteRuntimeSysctl(const std::string& path, const std::string& value)
{
    const int fd = open(path.c_str(), O_WRONLY | O_TRUNC | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0)
    {
        const int status = errno;
        return Error("Failed to open runtime sysctl '" + path + "': " + strerror(status), status);
    }

    struct stat metadata;
    if (fstat(fd, &metadata) != 0)
    {
        const int status = errno;
        close(fd);
        return Error("Failed to inspect runtime sysctl '" + path + "': " + strerror(status), status);
    }
    if (!S_ISREG(metadata.st_mode))
    {
        close(fd);
        return Error("Runtime sysctl is not a regular file: " + path, EINVAL);
    }

    size_t written = 0;
    while (written < value.size())
    {
        const ssize_t count = write(fd, value.data() + written, value.size() - written);
        if (count < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            const int status = errno;
            close(fd);
            return Error("Failed to write runtime sysctl '" + path + "': " + strerror(status), status);
        }
        if (count == 0)
        {
            close(fd);
            return Error("Failed to write runtime sysctl '" + path + "'", EIO);
        }
        written += static_cast<size_t>(count);
    }
    if (close(fd) != 0)
    {
        const int status = errno;
        return Error("Failed to close runtime sysctl '" + path + "': " + strerror(status), status);
    }
    return {};
}

Result<Status> AuditSysctlValue(const SysctlValueParams& params, IndicatorsTree& indicators, ContextInterface& context)
{
    assert(params.runtimeOnly.HasValue());

    auto log = context.GetLogHandle();
    std::string procfsLocation = "/proc/sys";

    if (!IsValidSysctlName(params.sysctlName))
    {
        OsConfigLogError(log, "Invalid sysctl name (possible path traversal attempt): %s", params.sysctlName.c_str());
        return Error("Invalid sysctl name: " + params.sysctlName, EINVAL);
    }

    auto sysctlPath = params.sysctlName;
    std::replace(sysctlPath.begin(), sysctlPath.end(), '.', '/');
    std::string procSysPath = procfsLocation + std::string("/") + sysctlPath;

    auto output = context.GetFileContents(context.GetSpecialFilePath(procSysPath));
    if (!output.HasValue())
    {
        if (output.Error().code == ENOENT)
        {
            return indicators.NotApplicable("Sysctl '" + params.sysctlName + "' not found in runtime configuration");
        }

        return output.Error();
    }

    std::string sysctlOutput = output.Value();

    // remove trailing newline character, if any. The emptiness check is required because rbegin()
    // on an empty string is rend(); dereferencing it is undefined behaviour (out-of-bounds read).
    // GetFileContents can legitimately return an empty string here, e.g. for an empty sysctl leaf
    // under /proc/sys or when the resolved path is a /proc/sys sub-directory read as zero bytes.
    if (!sysctlOutput.empty() && *sysctlOutput.rbegin() == '\n')
    {
        sysctlOutput.erase(sysctlOutput.size() - 1);
    }

    sysctlOutput = TrimWhiteSpaces(sysctlOutput);

    if (regex_search(sysctlOutput, params.value.GetRegex()) == false)
    {
        return indicators.NonCompliant("Expected '" + params.sysctlName + "' value '" + std::to_string(params.value) + "' got '" + sysctlOutput +
                                       "' in runtime configuration");
    }
    else
    {
        indicators.Compliant("Correct value for '" + params.sysctlName + "' in runtime configuration");
    }

    // If runtimeOnly is set to true, skip config file check
    if (params.runtimeOnly.Value())
    {
        // The status has already been set to Compliant above, so we can return it here.
        OsConfigLogInfo(log, "Skipping sysctl configuration file check for '%s' as per parameters", params.sysctlName.c_str());
        return indicators.Compliant("Runtime-only check for '" + params.sysctlName + "' passed");
    }

    // systemd-sysctl can be in different places on different OSes, we need to do some heuristics.
    std::string systemdSysctl;
    std::vector<std::string> systemdSysctlLocations = {"/lib/systemd/systemd-sysctl", "/usr/lib/systemd/systemd-sysctl"};
    const std::string argVersion = " --version";
    const std::string argCatConfig = " --cat-config";
    for (auto& cmd : systemdSysctlLocations)
    {
        auto result = context.ExecuteCommand(cmd + argVersion);
        if (result.HasValue())
        {
            systemdSysctl = cmd + argCatConfig;
            break;
        }
    }
    if (systemdSysctl.empty())
    {
        return Error("Cannot find systemd-sysctl command", ENOENT);
    }
    // systemd-sysctl shows all configs used by system that have sysctl's
    auto execResult = context.ExecuteCommand(systemdSysctl);
    if (!execResult.HasValue())
    {
        OsConfigLogError(log, "Failed to execute systemd-sysctl command");
        return execResult.Error();
    }

    std::istringstream configurations(execResult.Value());
    std::string line;
    std::string runSysctlValue;
    std::vector<std::string> sysctlConfigLines;

    // Reverse order of output, to check sysctls from most important till less important
    while (std::getline(configurations, line))
    {
        sysctlConfigLines.push_back(line);
    }

    bool found = false;
    bool invalid = false;
    auto lines = sysctlConfigLines.rbegin();

    // TODO(kkanas) consider using regex_match when we have all platforms with up to date support
    static const auto nameValuePattern = regex("\\s*([a-zA-Z0-9_]+[\\.a-zA-Z0-9_-]+)\\s*=\\s*(.*)");

    // Iterate sysctlConfigLines backwards, when last value matches expected valueRegex
    // we are done.
    for (; !found && lines != sysctlConfigLines.rend(); ++lines)
    {
        line = *lines;
        size_t comment = line.find('#');
        if (comment != std::string::npos)
        {
            line = line.substr(0, comment);
        }
        if (line == "")
        {
            continue;
        }

        if (regex_search(line, nameValuePattern))
        {
            size_t eqPos = line.find('=');
            if (eqPos == std::string::npos)
            {
                continue;
            }

            std::string name = line.substr(0, eqPos);
            name = TrimWhiteSpaces(name);
            runSysctlValue = line.substr(eqPos + 1, line.size() - eqPos);
            runSysctlValue = TrimWhiteSpaces(runSysctlValue);

            if (name == params.sysctlName)
            {
                found = true;
                if (not regex_search(runSysctlValue, params.value.GetRegex()))
                {
                    invalid = true;
                }
            }
        }
    }
    // we found a match with correct value
    if (found && !invalid)
    {
        return indicators.Compliant("Correct value for '" + params.sysctlName + "' in stored configuration");
    }

    // TODO(kkanas) consider using regex_match when we have all platforms with up to date support
    static const auto fileNamePattern = regex("^\\s*#\\s*(\\/.*\\.conf)$");

    // lines are iterated backwards so filename is before last value marked by lines
    std::string fileName;
    for (; lines != sysctlConfigLines.rend(); ++lines)
    {
        line = *lines;
        if (regex_search(line, fileNamePattern))
        {
            size_t comment = line.find('#');
            if (comment == std::string::npos)
            {
                continue;
            }
            size_t slash = line.find_first_of('/', comment + 1);
            if (slash == std::string::npos)
            {
                continue;
            }
            fileName = line.substr(slash);
            break;
        }
    }

    if (found && invalid)
    {
        return indicators.NonCompliant("Expected '" + params.sysctlName + "' got '" + runSysctlValue + "' found in: '" + fileName + "'");
    }
    else
    {
        indicators.NonCompliant("Expected '" + params.sysctlName + "' not found in stored sysctl configuration");
    }

    auto ufwDefaults = context.GetFileContents("/etc/default/ufw");
    if (!ufwDefaults.HasValue())
    {
        return indicators.NonCompliant("Failed to read /etc/default/ufw: " + ufwDefaults.Error().message);
    }
    std::istringstream iss(ufwDefaults.Value());
    std::string sysctlFile;
    while (std::getline(iss, line))
    {
        if (line.find("IPT_SYSCTL=", 0) == 0)
        {
            sysctlFile = line.substr(std::string("IPT_SYSCTL=").size());
            break;
        }
    }
    if (sysctlFile.empty())
    {
        return indicators.NonCompliant("Failed to find IPT_SYSCTL in /etc/default/ufw");
    }

    std::string trimmedSysctlFile = TrimWhiteSpaces(sysctlFile);
    if (!IsValidFilePath(trimmedSysctlFile))
    {
        OsConfigLogError(log, "Invalid sysctl file path in /etc/default/ufw (possible path traversal): %s", trimmedSysctlFile.c_str());
        return indicators.NonCompliant("Invalid sysctl file path in /etc/default/ufw");
    }

    auto sysctlContents = context.GetFileContents(trimmedSysctlFile);
    if (!sysctlContents.HasValue())
    {
        return indicators.NonCompliant("Failed to read ufw sysctl config file: " + sysctlContents.Error().message);
    }
    std::istringstream sysctlStream(sysctlContents.Value());
    while (std::getline(sysctlStream, line))
    {
        if (line.find(sysctlPath + "=", 0) == 0)
        {
            auto value = line.substr(params.sysctlName.size() + 1);
            if (regex_search(value, params.value.GetRegex()))
            {
                return indicators.Compliant("Correct value for '" + params.sysctlName + "' in UFW configuration");
            }
            else
            {
                return indicators.NonCompliant("Expected '" + params.sysctlName + "', got '" + value + "' in UFW configuration");
            }
        }
    }

    return indicators.NonCompliant("Value not found in UFW configuration for '" + params.sysctlName + "'");
}

Result<Status> RemediateSysctlValue(const SysctlValueParams& params, IndicatorsTree& indicators, ContextInterface& context)
{
    if (!params.runtimeOnly.HasValue() || !params.runtimeOnly.Value())
    {
        return Error("Sysctl remediation currently supports runtime-only policies", ENOTSUP);
    }
    if (!IsValidSysctlName(params.sysctlName))
    {
        return Error("Invalid sysctl name: " + params.sysctlName, EINVAL);
    }
    auto desired = GetLiteralRemediationValue(params.value);
    if (!desired.HasValue())
    {
        return desired.Error();
    }

    auto audit = AuditSysctlValue(params, indicators, context);
    if (!audit.HasValue() || audit.Value() == Status::Compliant || audit.Value() == Status::NotApplicable)
    {
        return audit;
    }

    auto sysctlPath = params.sysctlName;
    std::replace(sysctlPath.begin(), sysctlPath.end(), '.', '/');
    const auto runtimePath = context.GetSpecialFilePath("/proc/sys/" + sysctlPath);
    auto original = context.GetFileContents(runtimePath);
    if (!original.HasValue())
    {
        return original.Error();
    }

    auto writeError = WriteRuntimeSysctl(runtimePath, desired.Value());
    if (writeError.HasValue())
    {
        return writeError.Value();
    }
    auto postAudit = AuditSysctlValue(params, indicators, context);
    if (postAudit.HasValue() && postAudit.Value() == Status::Compliant)
    {
        return postAudit;
    }

    auto rollbackError = WriteRuntimeSysctl(runtimePath, original.Value());
    if (rollbackError.HasValue())
    {
        const std::string reason = postAudit.HasValue() ? "Runtime sysctl remained noncompliant" : postAudit.Error().message;
        return Error(reason + "; rollback failed: " + rollbackError->message, rollbackError->code);
    }
    return postAudit;
}
} // namespace ComplianceEngine
