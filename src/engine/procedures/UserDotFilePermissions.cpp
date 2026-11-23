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
using Filesystem::SymlinkPolicy;

FilesystemCollectionRequest DotfilePolicy(const string& home)
{
    FilesystemCollectionRequest policy(home, FilesystemRootKind::Directory);
    policy.direction = FilesystemDirection::Down;
    policy.maxDepth = 32;
    policy.depthAction = FilesystemDepthAction::Error;
    policy.scope = FilesystemScope::All;
    policy.rootFileLinkAction = SymlinkPolicy::Follow;
    policy.rootDirectoryLinkAction = SymlinkPolicy::Follow;
    policy.childFileLinkAction = SymlinkPolicy::DoNotFollow;
    policy.childDirectoryLinkAction = SymlinkPolicy::DoNotFollow;
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
        const string userName = pwd.pw_name;
        const string homeName = pwd.pw_dir;
        const string groupName = groupResult.Value()->gr_name;

        auto processFile = [userName, homeName, groupName, &indicators, &context](const FilesystemCollectionEntry& entry) -> Result<Status> {
            const string path = entry.path;
            auto pin = entry.LiveComponent();
            const std::size_t separator = path.find_last_of('/');
            const string filename = path.substr(separator + 1);
            if (filename.find(".") != 0)
            {
                OsConfigLogDebug(context.GetLogHandle(), "Skipping entry '%s' as its name doesn't start with '.'", filename.c_str());
                return Status::Compliant;
            }

            if (filename == ".forward" || filename == ".rhosts")
            {
                return indicators.NonCompliant("'" + filename + "' exists in home directory '" + homeName + "'");
            }

            Result<Status> result = Status::Compliant;
            // Performs a file permissions check and updates the result in case of error or non-compliance
            auto checkFile = [userName, groupName, path, pin, &indicators, &context, &result](const mode_t mask) {
                auto groupPattern = Pattern::Make(groupName);
                if (!groupPattern.HasValue())
                {
                    result = groupPattern.Error();
                    return;
                }

                auto pwdPattern = Pattern::Make(userName);
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
                if (!pin.HasValue())
                {
                    result = Error("Dotfile collection requires an acquired file", EBADF);
                    return;
                }
                indicators.Push("AuditFilePermissions");
                auto subResult = CheckPinnedFilePermissions(params, pin.Value(), indicators, context);
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
        auto resolved = Filesystem::ResolveFilesystemCollectionRequest(policy);
        if (!resolved.HasValue())
            return resolved.Error();
        auto root = Filesystem::Path::Make(context, resolved.Value().rootPath, Filesystem::CollectionRootPolicy(resolved.Value()),
            Filesystem::CollectionRootLimits(resolved.Value()));
        if (!root.HasValue())
            return root.Error();
        if (root.Value().Is<Filesystem::Path::RejectionReason>())
            continue; // missing/excluded home: no dotfiles to inspect
        // FTW freezes the selected starting leaf at its common entry point.
        if (As<Filesystem::Path>(root.Value()).Leaf().Metadata().FileType() != Filesystem::Type::Directory)
            return Error("Expected directory root at '" + policy.rootPath + "'", ENOTDIR);
        auto opened = Filesystem::FTW::Files(As<Filesystem::Path>(std::move(root).Value()), resolved.Value().rootPath,
            Filesystem::CollectionContinuation(resolved.Value()));
        if (!opened.HasValue())
        {
            OsConfigLogError(context.GetLogHandle(), "Directory validation for user '%s' failed: %s", pwd.pw_name, opened.Error().message.c_str());
            return opened.Error();
        }
        auto files = std::move(opened).Value();
        Status verdict = Status::Compliant;
        for (const auto& entry : files)
        {
            if (!entry.HasValue())
            {
                return entry.Error();
            }
            const auto result = processFile(entry.Value());
            if (!result.HasValue())
            {
                return result.Error();
            }
            if (result.Value() == Status::NonCompliant)
            {
                verdict = Status::NonCompliant;
                break;
            }
        }
        files.Stop();
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
