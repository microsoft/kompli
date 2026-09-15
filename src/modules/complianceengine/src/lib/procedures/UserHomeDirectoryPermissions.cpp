// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include <Evaluator.h>
#include <FilePermissions.h>
#include <ListValidShells.h>
#include <Result.h>
#include <Telemetry.h>
#include <UserHomeDirectoryPermissions.h>
#include <fcntl.h>
#include <fstream>
#include <grp.h>
#include <pwd.h>
#include <set>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

namespace ComplianceEngine
{
using std::ifstream;
using std::map;
using std::ostringstream;
using std::set;
using std::string;

Result<Status> AuditUserHomeDirectoryPermissions(IndicatorsTree& indicators, ContextInterface& context)
{
    const auto validShells = ListValidShells(context);
    if (!validShells.HasValue())
    {
        OsConfigLogError(context.GetLogHandle(), "Failed to get valid shells: %s", validShells.Error().message.c_str());
        OSConfigTelemetryStatusTrace("ListValidShells", validShells.Error().code);
        return validShells.Error();
    }

    auto result = Status::Compliant;
    auto users = context.GetAccountDatabase().GetUsers();
    if (!users.HasValue())
    {
        return users.Error();
    }

    for (const auto& user : *users.Value())
    {
        const auto it = validShells->find(user.shell);
        if (it == validShells->end())
        {
            OsConfigLogDebug(context.GetLogHandle(), "User '%s' has shell '%s' not listed in /etc/shells", user.name.c_str(), user.shell.c_str());
            continue;
        }

        struct stat st;
        if (0 != stat(user.homeDirectory.c_str(), &st))
        {
            int status = errno;
            if (status == ENOENT)
            {
                OsConfigLogDebug(context.GetLogHandle(), "User '%s' has home directory '%s' which does not exist", user.name.c_str(), user.homeDirectory.c_str());
                result = indicators.NonCompliant("User's '" + user.name + "' home directory '" + user.homeDirectory + "' does not exist");
                continue;
            }
            else
            {
                OsConfigLogError(context.GetLogHandle(), "Failed to stat home directory '%s' for user '%s': %s", user.homeDirectory.c_str(),
                    user.name.c_str(), strerror(status));
                OSConfigTelemetryStatusTrace("stat", status);
                return Error(string("Failed to stat home directory: ") + strerror(status), status);
            }
        }

        auto group = context.GetAccountDatabase().FindGroupById(user.gid);
        if (!group.HasValue())
        {
            return group.Error();
        }
        if (nullptr == group.Value())
        {
            return Error("Failed to get group for user '" + user.name + "'", ENOENT);
        }

        auto pwdPattern = Pattern::Make(user.name);
        if (!pwdPattern.HasValue())
        {
            return pwdPattern.Error();
        }

        auto groupPattern = Pattern::Make(group.Value()->name);
        if (!groupPattern.HasValue())
        {
            return groupPattern.Error();
        }

        FilePermissionsParams params;
        params.path = user.homeDirectory;
        params.mask = 027;
        params.owner = {{std::move(pwdPattern.Value())}};
        params.group = {{std::move(groupPattern.Value())}};
        indicators.Push("EnsureFilePermissions");
        auto subResult = AuditFilePermissions(params, indicators, context);
        if (!subResult.HasValue())
        {
            OsConfigLogError(context.GetLogHandle(), "Failed to check permissions for home directory '%s' for user '%s': %s",
                user.homeDirectory.c_str(), user.name.c_str(), subResult.Error().message.c_str());
            OSConfigTelemetryStatusTrace("AuditFilePermissions", subResult.Error().code);
            return subResult;
        }
        indicators.Back().status = subResult.Value();
        indicators.Pop();

        if (subResult.Value() == Status::NonCompliant)
        {
            OsConfigLogInfo(context.GetLogHandle(), "User '%s' has home directory '%s' with incorrect permissions", user.name.c_str(),
                user.homeDirectory.c_str());
            indicators.NonCompliant("User's '" + user.name + "' home directory '" + user.homeDirectory + "' has incorrect permissions");
            result = Status::NonCompliant;
        }
    }
    return result;
}

Result<Status> RemediateUserHomeDirectoryPermissions(IndicatorsTree& indicators, ContextInterface& context)
{
    const auto validShells = ListValidShells(context);
    if (!validShells.HasValue())
    {
        OsConfigLogError(context.GetLogHandle(), "Failed to get valid shells: %s", validShells.Error().message.c_str());
        OSConfigTelemetryStatusTrace("ListValidShells", validShells.Error().code);
        return validShells.Error();
    }

    auto result = Status::Compliant;
    auto users = context.GetAccountDatabase().GetUsers();
    if (!users.HasValue())
    {
        return users.Error();
    }

    for (const auto& user : *users.Value())
    {
        const auto it = validShells->find(user.shell);
        if (it == validShells->end())
        {
            OsConfigLogDebug(context.GetLogHandle(), "User '%s' has shell '%s' not in /etc/shells", user.name.c_str(), user.shell.c_str());
            continue;
        }

        struct stat st;
        if (stat(user.homeDirectory.c_str(), &st) != 0)
        {
            int status = errno;
            OsConfigLogDebug(context.GetLogHandle(), "stat failed for home directory '%s' for user '%s': %s", user.homeDirectory.c_str(),
                user.name.c_str(), strerror(status));
            if (status == ENOENT)
            {
                // Home directory does not exist, so we need to create it
                if (0 != mkdir(user.homeDirectory.c_str(), 0750))
                {
                    status = errno;
                    OsConfigLogError(context.GetLogHandle(), "Failed to create home directory '%s' for user '%s': %s", user.homeDirectory.c_str(),
                        user.name.c_str(), strerror(status));
                    OSConfigTelemetryStatusTrace("mkdir", status);
                    return Error(string("Failed to create home directory: ") + strerror(status), status);
                }
            }
            else
            {
                OsConfigLogError(context.GetLogHandle(), "Failed to stat home directory '%s' for user '%s': %s", user.homeDirectory.c_str(),
                    user.name.c_str(), strerror(status));
                OSConfigTelemetryStatusTrace("stat", status);
                return Error(string("Failed to stat home directory: ") + strerror(status), status);
            }
        }

        auto group = context.GetAccountDatabase().FindGroupById(user.gid);
        if (!group.HasValue())
        {
            return group.Error();
        }
        if (nullptr == group.Value())
        {
            return Error("Failed to get group for user '" + user.name + "'", ENOENT);
        }

        auto pwdPattern = Pattern::Make(user.name);
        if (!pwdPattern.HasValue())
        {
            return pwdPattern.Error();
        }

        auto groupPattern = Pattern::Make(group.Value()->name);
        if (!groupPattern.HasValue())
        {
            return groupPattern.Error();
        }

        FilePermissionsParams params;
        params.path = user.homeDirectory;
        params.mask = 027;
        params.owner = {{std::move(pwdPattern.Value())}};
        params.group = {{std::move(groupPattern.Value())}};
        indicators.Push("EnsureFilePermissions");
        auto subResult = RemediateFilePermissions(params, indicators, context);
        if (!subResult.HasValue())
        {
            OsConfigLogError(context.GetLogHandle(), "Failed to remediate permissions for home directory '%s' for user '%s': %s",
                user.homeDirectory.c_str(), user.name.c_str(), subResult.Error().message.c_str());
            OSConfigTelemetryStatusTrace("RemediateEnsureFilePermissionsHelper", subResult.Error().code);
            result = Status::NonCompliant;
        }
        indicators.Back().status = subResult.Value();
        indicators.Pop();
    }
    return result;
}

} // namespace ComplianceEngine
