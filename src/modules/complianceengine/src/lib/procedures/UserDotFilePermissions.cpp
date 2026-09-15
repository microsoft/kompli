// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include <Evaluator.h>
#include <FilePermissions.h>
#include <FileTreeWalk.h>
#include <ListValidShells.h>
#include <Result.h>
#include <Telemetry.h>
#include <UserDotFilePermissions.h>
#include <fcntl.h>
#include <fstream>
#include <grp.h>
#include <pwd.h>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

namespace ComplianceEngine
{
using std::map;
using std::string;

Result<Status> AuditUserDotFilePermissions(IndicatorsTree& indicators, ContextInterface& context)
{
    const auto validShells = ListValidShells(context);
    if (!validShells.HasValue())
    {
        OsConfigLogError(context.GetLogHandle(), "Failed to get valid shells: %s", validShells.Error().message.c_str());
        OSConfigTelemetryStatusTrace("ListValidShells", validShells.Error().code);
        return validShells.Error();
    }

    auto status = Status::Compliant;
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
            OsConfigLogDebug(context.GetLogHandle(), "User '%s' has shell '%s' not listed in valid shells", user.name.c_str(), user.shell.c_str());
            continue;
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

        auto ftwCallback = [&user, group, &indicators, &context](const string& directory, const std::string& filename, const struct stat& st) -> Result<Status> {
            if (!S_ISREG(st.st_mode))
            {
                OsConfigLogDebug(context.GetLogHandle(), "Skipping non-regular file '%s'", filename.c_str());
                return Status::Compliant;
            }

            if (filename.find(".") != 0)
            {
                OsConfigLogDebug(context.GetLogHandle(), "Skipping entry '%s' as its name doesn't start with '.'", filename.c_str());
                return Status::Compliant;
            }

            if (filename == ".forward" || filename == ".rhosts")
            {
                return indicators.NonCompliant("'" + filename + "' exists in home directory '" + user.homeDirectory + "'");
            }

            Result<Status> result = Status::Compliant;
            const auto path = directory + "/" + filename;

            // Performs a file permissions check and updates the result in case of error or non-compliance
            auto checkFile = [&user, group, &path, &indicators, &context, &result](const mode_t mask) {
                auto groupPattern = Pattern::Make(group.Value()->name);
                if (!groupPattern.HasValue())
                {
                    result = groupPattern.Error();
                    return;
                }

                auto pwdPattern = Pattern::Make(user.name);
                if (!pwdPattern.HasValue())
                {
                    result = pwdPattern.Error();
                    return;
                }

                FilePermissionsParams params;
                params.path = path;
                params.owner = {{std::move(pwdPattern.Value())}};
                params.group = {{std::move(groupPattern.Value())}};
                params.mask = mask;
                indicators.Push("AuditFilePermissions");
                auto subResult = AuditFilePermissions(params, indicators, context);
                if (!subResult.HasValue())
                {
                    OsConfigLogError(context.GetLogHandle(), "Failed to check permissions for file '%s': %s", path.c_str(), subResult.Error().message.c_str());
                    OSConfigTelemetryStatusTrace("AuditFilePermissions", subResult.Error().code);
                    result = subResult.Error();
                    return;
                }
                indicators.Back().status = subResult.Value();
                indicators.Pop();

                if (subResult.Value() == Status::NonCompliant)
                {
                    result = subResult.Value();
                }
            };

            if (result.HasValue() && filename == ".netrc")
            {
                checkFile(0177);
            }

            if (result.HasValue() && filename == ".bash_history")
            {
                checkFile(0177);
            }

            if (result.HasValue())
            {
                checkFile(0133);
            }

            return result;
        };

        auto result = FileTreeWalk(user.homeDirectory, ftwCallback, BreakOnNonCompliant::True, context);
        if (!result.HasValue() || result.Value() == Status::NonCompliant)
        {
            OsConfigLogDebug(context.GetLogHandle(), "Directory validation for user %s id %d returned NonCompliant, but continuing", user.name.c_str(), user.uid);
            status = Status::NonCompliant;
        }
    }

    return status;
}

Result<Status> RemediateUserDotFilePermissions(IndicatorsTree& indicators, ContextInterface& context)
{
    const auto validShells = ListValidShells(context);
    if (!validShells.HasValue())
    {
        OsConfigLogError(context.GetLogHandle(), "Failed to get valid shells: %s", validShells.Error().message.c_str());
        OSConfigTelemetryStatusTrace("ListValidShells", validShells.Error().code);
        return validShells.Error();
    }

    auto status = Status::Compliant;
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
            OsConfigLogDebug(context.GetLogHandle(), "User '%s' has shell '%s' not listed in valid shells", user.name.c_str(), user.shell.c_str());
            continue;
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

        auto ftwCallback = [&user, group, &indicators, &context](const string& directory, const std::string& filename, const struct stat& st) -> Result<Status> {
            if (!S_ISREG(st.st_mode))
            {
                OsConfigLogDebug(context.GetLogHandle(), "Skipping non-regular file '%s'", filename.c_str());
                return Status::Compliant;
            }

            if (filename.find(".") != 0)
            {
                OsConfigLogDebug(context.GetLogHandle(), "Skipping entry '%s' as its name doesn't start with '.'", filename.c_str());
                return Status::Compliant;
            }

            // Refuse to remediate a dot-file that has more than one hard link. This directory is
            // owned and writable by the (unprivileged) user, so a multiply-linked entry here may
            // share its inode with a sensitive root-owned file (e.g. a hard link to /etc/shadow).
            // Since a hard link is an ordinary regular file, it passes the S_ISREG check above and
            // is not caught by symlink protection; remediating it would change the linked file's
            // ownership and mode too, which is a privilege-escalation vector when this runs as root.
            if (st.st_nlink > 1)
            {
                OsConfigLogError(context.GetLogHandle(), "Refusing to remediate '%s/%s': file has %lu hard links", directory.c_str(), filename.c_str(),
                    static_cast<unsigned long>(st.st_nlink));
                OSConfigTelemetryStatusTrace("hardlink", EPERM);
                return indicators.NonCompliant("Refusing to remediate hard-linked file '" + filename + "' in home directory '" + user.homeDirectory +
                                               "'");
            }

            if (filename == ".forward" || filename == ".rhosts")
            {
                // We don't want to remove user files, the remediation will always fail here.
                return indicators.NonCompliant("'" + filename + "' exists in home directory '" + user.homeDirectory + "'");
            }

            Result<Status> result = Status::Compliant;
            const auto path = directory + "/" + filename;

            // Performs a file permissions check and updates the result in case of error or non-compliance
            auto remediateFile = [&user, group, &path, &indicators, &context, &result](const mode_t mask) {
                auto pwdPattern = Pattern::Make(user.name);
                if (!pwdPattern.HasValue())
                {
                    result = pwdPattern.Error();
                    return;
                }
                auto groupPattern = Pattern::Make(group.Value()->name);
                if (!groupPattern.HasValue())
                {
                    result = groupPattern.Error();
                    return;
                }
                FilePermissionsParams params;
                params.path = path;
                params.owner = {{pwdPattern.Value()}};
                params.group = {{groupPattern.Value()}};
                params.mask = mask;
                indicators.Push("RemediateFilePermissions");
                auto subResult = RemediateFilePermissions(params, indicators, context);
                if (!subResult.HasValue())
                {
                    OsConfigLogError(context.GetLogHandle(), "Failed to remediate permissions for file '%s': %s", path.c_str(),
                        subResult.Error().message.c_str());
                    OSConfigTelemetryStatusTrace("RemediateEnsureFilePermissionsHelper", subResult.Error().code);
                    result = subResult.Error();
                    return;
                }
                indicators.Back().status = subResult.Value();
                indicators.Pop();

                if (subResult.Value() == Status::NonCompliant)
                {
                    result = subResult.Value();
                }
            };

            if (result.HasValue() && (filename == ".netrc" || filename == ".bash_history"))
            {
                remediateFile(0177);
            }

            if (result.HasValue())
            {
                // Ths file starts with a dot, so we need to check the permissions
                remediateFile(0133);
            }

            return result;
        };

        auto result = FileTreeWalk(user.homeDirectory, ftwCallback, BreakOnNonCompliant::False, context);
        if (!result.HasValue() || result.Value() == Status::NonCompliant)
        {
            OsConfigLogError(context.GetLogHandle(), "Directory validation for user %s id %d returned NonCompliant, but continuing", user.name.c_str(), user.uid);
            OSConfigTelemetryStatusTrace("FileTreeWalk", result.HasValue() ? EPERM : result.Error().code);
            status = Status::NonCompliant;
        }
    }

    return status;
}

} // namespace ComplianceEngine
