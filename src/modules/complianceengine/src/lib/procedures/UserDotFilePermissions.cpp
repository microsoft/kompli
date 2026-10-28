// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include <Evaluator.h>
#include <FilePermissions.h>
#include <ListValidShells.h>
#include <Result.h>
#include <UserDotFilePermissions.h>
#include <UserPermissionsTestSeams.h>
#include <UsersIterator.h>
#include <fcntl.h>
#include <filesystem/FilesystemCollection.hpp>
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

namespace
{
using Filesystem::FilesystemCollectionEntry;
using Filesystem::FilesystemCollectionLimits;
using Filesystem::FilesystemCollectionRequest;
using Filesystem::FilesystemDepthAction;
using Filesystem::FilesystemDirection;
using Filesystem::FilesystemRootKind;
using Filesystem::FilesystemScope;
using Filesystem::FilesystemYieldType;
using Filesystem::SymlinkFollowing;

FilesystemCollectionRequest DotfilePolicy(const string& home)
{
    FilesystemCollectionRequest policy(home, FilesystemRootKind::Directory);
    policy.direction = FilesystemDirection::Down;
    policy.maxDepth = 32;
    policy.depthAction = FilesystemDepthAction::Error;
    policy.scope = FilesystemScope::All;
    policy.rootFileLinkAction = SymlinkFollowing::Follow;
    policy.rootDirectoryLinkAction = SymlinkFollowing::Follow;
    policy.childFileLinkAction = SymlinkFollowing::DoNotFollow;
    policy.childDirectoryLinkAction = SymlinkFollowing::DoNotFollow;
    policy.yieldType = FilesystemYieldType::RegularFiles;
    return policy;
}

Result<const struct group*> LookupUserGroup(gid_t id, const char* user, ContextInterface& context)
{
    errno = 0;
    const auto* group = context.GetGroupById(id);
    if (nullptr == group)
    {
        const int code = errno ? errno : ENOENT;
        OsConfigLogError(context.GetLogHandle(), "Failed to get group for user '%s': %s", user, strerror(code));
        return Error(string("Failed to get group for user: ") + strerror(code), code);
    }
    return group;
}

Result<Status> CloseAfterError(const Error& primary, Filesystem::FTW::FileRange& files, ContextInterface& context)
{
    const auto cleanup = files.Close();
    if (!cleanup.HasValue() && (cleanup.Error().code != primary.code || cleanup.Error().message != primary.message))
    {
        OsConfigLogError(context.GetLogHandle(), "Dotfile range cleanup failed after primary error: %s", cleanup.Error().message.c_str());
    }
    return primary;
}
} // namespace

Result<Status> AuditUserDotFilePermissions(IndicatorsTree& indicators, ContextInterface& context)
{
    return AuditUserDotFilePermissionsWithPasswdFile(indicators, context, "/etc/passwd");
}

Result<Status> AuditUserDotFilePermissionsWithPasswdFile(IndicatorsTree& indicators, ContextInterface& context, const string& passwdPath)
{
    const auto validShells = ListValidShells(context);
    if (!validShells.HasValue())
    {
        OsConfigLogError(context.GetLogHandle(), "Failed to get valid shells: %s", validShells.Error().message.c_str());
        return validShells.Error();
    }

    auto status = Status::Compliant;
    auto users = UsersRange::Make(passwdPath, context.GetLogHandle());
    if (!users.HasValue())
    {
        return users.Error();
    }

    for (const auto& pwd : users.Value())
    {
        const auto shell = string(pwd.pw_shell);
        const auto it = validShells->find(shell);
        if (it == validShells->end())
        {
            OsConfigLogDebug(context.GetLogHandle(), "User '%s' has shell '%s' not listed in valid shells", pwd.pw_name, pwd.pw_shell);
            continue;
        }

        const auto groupResult = LookupUserGroup(pwd.pw_gid, pwd.pw_name, context);
        if (!groupResult.HasValue())
        {
            return groupResult.Error();
        }
        const auto* group = groupResult.Value();

        auto processFile = [pwd, group, &indicators, &context](const FilesystemCollectionEntry& entry) -> Result<Status> {
            const auto& path = entry.path;
            const std::size_t separator = path.find_last_of('/');
            const string filename = path.substr(separator + 1);
            if (filename.find(".") != 0)
            {
                OsConfigLogDebug(context.GetLogHandle(), "Skipping entry '%s' as its name doesn't start with '.'", filename.c_str());
                return Status::Compliant;
            }

            if (filename == ".forward" || filename == ".rhosts")
            {
                return indicators.NonCompliant("'" + filename + "' exists in home directory '" + pwd.pw_dir + "'");
            }

            Result<Status> result = Status::Compliant;
            // Performs a file permissions check and updates the result in case of error or non-compliance
            auto checkFile = [pwd, group, &path, &entry, &indicators, &context, &result](const mode_t mask) {
                auto groupPattern = Pattern::Make(group->gr_name);
                if (!groupPattern.HasValue())
                {
                    result = groupPattern.Error();
                    return;
                }

                auto pwdPattern = Pattern::Make(pwd.pw_name);
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
                auto subResult = CheckPinnedFilePermissions(params, *entry.LiveHandle(), FilesystemCollectionLimits{}.fullPathBytes, indicators, context);
                if (!subResult.HasValue())
                {
                    OsConfigLogError(context.GetLogHandle(), "Failed to check permissions for file '%s': %s", path.c_str(), subResult.Error().message.c_str());
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

        const auto policy = DotfilePolicy(pwd.pw_dir);
        // The selected home is the accepted root; only live pins, not
        // diagnostic paths, authorize checks or remediation.
        auto opened = Filesystem::FTW::Files(policy, context);
        if (!opened.HasValue())
        {
            OsConfigLogError(context.GetLogHandle(), "Directory validation for user '%s' failed: %s", pwd.pw_name, opened.Error().message.c_str());
            return opened.Error();
        }
        auto& files = opened.Value();
        Status verdict = Status::Compliant;
        for (const auto& entry : files)
        {
            if (!entry.HasValue())
            {
                return CloseAfterError(entry.Error(), files, context);
            }
            const auto result = processFile(entry.Value());
            if (!result.HasValue())
            {
                return CloseAfterError(result.Error(), files, context);
            }
            if (result.Value() == Status::NonCompliant)
            {
                verdict = Status::NonCompliant;
                break;
            }
        }
        const auto closed = files.Close();
        if (!closed.HasValue())
        {
            return closed.Error();
        }
        if (verdict == Status::NonCompliant)
        {
            OsConfigLogDebug(context.GetLogHandle(), "Directory validation for user %s id %d returned NonCompliant, but continuing", pwd.pw_name, pwd.pw_uid);
            status = Status::NonCompliant;
        }
    }

    return status;
}

Result<Status> RemediateUserDotFilePermissions(IndicatorsTree& indicators, ContextInterface& context)
{
    return RemediateUserDotFilePermissionsWithPasswdFile(indicators, context, "/etc/passwd");
}

Result<Status> RemediateUserDotFilePermissionsWithPasswdFile(IndicatorsTree&, ContextInterface&, const string&)
{
    // A null remediation handler falls back to audit, potentially claiming
    // success without fixing the file. Keep this explicit disabled handler.
    return Error("UserDotFilePermissions remediation is disabled", ENOTSUP);
}

} // namespace ComplianceEngine
