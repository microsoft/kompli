// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <CommonUtils.h>
#include <Evaluator.h>
#include <FilePermissions.h>
#include <SshKeyPermissions.h>
#include <filesystem/FilesystemCollection.hpp>
#include <sstream>

namespace ComplianceEngine
{
namespace
{
using Filesystem::FilesystemCollectionRequest;
using Filesystem::FilesystemDepthAction;
using Filesystem::FilesystemDirection;
using Filesystem::FilesystemRootKind;
using Filesystem::FilesystemScope;
using Filesystem::FilesystemYieldType;
using Filesystem::SymlinkPolicy;
// Helper routine shared by audit and remediation for SSH key permission checks.
// When isRemediation == true it will remediate permissions/ownership, otherwise only audit.
Result<Status> SshKeyPermsHelper(bool isPublic, bool isRemediation, IndicatorsTree& indicators, ContextInterface& context)
{
    const std::string baseDir = context.GetSpecialFilePath("/etc/ssh");

    // Prepare static args map passed to existing file permission helpers.
    // owner=root, group=root|ssh_keys
    // Public keys: permission mask 0133 (i.e. we remove group/world write/execute and others read?) -> apply as mask (bits to be cleared)
    // Private keys: permissions 0600 (mask 0137 to enforce?) - requirement given: permissions 0137 (interpretation: mask for private keys?)
    // From user instructions: public key uses mask 0133; private key uses permissions 0137.
    // For consistency with existing helpers which treat 'permissions' as bits that MUST be set (perms != (st_mode & perms) -> NonCompliant) and 'mask' as bits that MUST NOT be set (statbuf.st_mode & mask) -> NonCompliant, we:
    //  - pass mask for public keys (bits forbidden)
    //  - pass mask for private keys too if semantics is to forbid bits (private keys should typically be 0600). However user explicitly said 'permissions 0137'. That suggests we want to CLEAR these bits. In helper logic supplying 'permissions' would require those bits to be present which is opposite. Thus we pass it as 'mask'.
    // So: treat provided numbers as masks of forbidden bits.

    auto processFile = [&](const Filesystem::FilesystemCollectionEntry& entry) -> Result<Status> {
        const auto* pin = entry.LiveHandle();
        if (pin == nullptr || entry.missing)
        {
            return Error("SSH key collection requires a live regular-file pin", EBADF);
        }
        auto opened = pin->OpenReadOnly();
        if (!opened.HasValue())
        {
            return std::move(opened).Error();
        }
        auto readable = std::move(opened).Value();
        // The old classifier used only the first line but propagated errors
        // reading the entire file. Retain that behavior with a bounded read.
        constexpr std::size_t maxKeyBytes = 1024 * 1024;
        std::string content;
        auto closeAfterError = [&]() {
            auto closed = readable.Close();
            if (!closed.HasValue())
            {
                try
                {
                    OsConfigLogError(context.GetLogHandle(), "Secondary SSH key reader close failure: %d", closed.Error().code);
                }
                catch (...)
                {
                    OsConfigLogError(nullptr, "Secondary SSH key reader close or log failure: %d", closed.Error().code);
                }
            }
        };
        for (;;)
        {
            auto chunk = readable.Read(4096);
            if (!chunk.HasValue())
            {
                auto primary = std::move(chunk).Error();
                closeAfterError();
                return primary;
            }
            if (!chunk.Value().HasValue())
                break;
            const auto& bytes = chunk.Value().Value();
            if (bytes.size() > maxKeyBytes - content.size())
            {
                closeAfterError();
                return Error("SSH key content exceeds classification byte limit", E2BIG);
            }
            content += bytes;
        }
        auto closed = readable.Close();
        if (!closed.HasValue())
            return std::move(closed).Error();
        std::istringstream iss(content);
        std::string firstLine;
        if (!std::getline(iss, firstLine))
        {
            return Status::Compliant;
        }

        bool isKey = false;
        if (isPublic)
        {
            // Public key line starts with one of these prefixes
            static const char* prefixes[] = {"ssh-dss", "ssh-rsa", "ecdsa-sha2-", "ssh-ed25519"};
            for (auto p : prefixes)
            {
                if (firstLine.rfind(p, 0) == 0)
                {
                    isKey = true;
                    break;
                }
            }
        }
        else
        {
            static const char* privPrefixes[] = {
                "SSH PRIVATE KEY", "-----BEGIN OPENSSH PRIVATE KEY-----", "-----BEGIN PRIVATE KEY-----", "-----BEGIN ENCRYPTED PRIVATE KEY"};
            for (auto p : privPrefixes)
            {
                if (firstLine.rfind(p, 0) == 0)
                {
                    isKey = true;
                    break;
                }
            }
        }

        if (!isKey)
        {
            return Status::Compliant;
        }

        FilePermissionsParams params;
        params.path = entry.path;
        static const auto rootPattern = Pattern::Make("root");
        if (!rootPattern.HasValue())
        {
            return rootPattern.Error();
        }
        static const auto sshKeysPattern = Pattern::Make("ssh_keys");
        if (!sshKeysPattern.HasValue())
        {
            return sshKeysPattern.Error();
        }
        params.owner = {{rootPattern.Value()}};
        params.group = {{rootPattern.Value(), sshKeysPattern.Value()}};
        if (isPublic)
        {
            params.mask = 0133; // forbidden bits
        }
        else
        {
            params.mask = 0137; // private key stricter forbidden bits
        }

        Result<Status> result = isRemediation ? EnforcePinnedFilePermissions(params, *pin, false, indicators, context) :
                                                CheckPinnedFilePermissions(params, *pin, indicators, context);
        if (!result.HasValue())
        {
            return result.Error();
        }
        return result.Value();
    };

    FilesystemCollectionRequest policy(baseDir, FilesystemRootKind::Directory);
    policy.direction = FilesystemDirection::Down;
    policy.maxDepth = 32;
    policy.depthAction = FilesystemDepthAction::Error;
    policy.scope = FilesystemScope::All;
    policy.rootFileLinkAction = SymlinkPolicy::Follow;
    policy.rootDirectoryLinkAction = SymlinkPolicy::Follow;
    policy.childDirectoryLinkAction = SymlinkPolicy::DoNotFollow;
    policy.childFileLinkAction = SymlinkPolicy::DoNotFollow;
    policy.yieldType = FilesystemYieldType::RegularFiles;
    auto resolved = Filesystem::ResolveFilesystemCollectionRequest(policy);
    if (!resolved.HasValue())
        return resolved.Error();
    auto root = Filesystem::Path::Make(context, resolved.Value().rootPath, Filesystem::CollectionRootPolicy(resolved.Value()),
        Filesystem::CollectionRootLimits(resolved.Value()));
    if (!root.HasValue())
        return root.Error();
    if (root.Value().Is<Filesystem::Path::RejectionReason>())
        return Status::Compliant;
    auto frozen = As<Filesystem::Path>(root.Value()).FreezeRoot();
    if (!frozen.HasValue())
        return std::move(frozen).Error();
    if (As<Filesystem::Path>(root.Value()).Root().AcquiredType() != Filesystem::Handle::Type::Directory)
        return Error("Expected directory root at '" + baseDir + "'", ENOTDIR);
    auto opened = Filesystem::FTW::Files(As<Filesystem::Path>(std::move(root).Value()), resolved.Value().rootPath,
        Filesystem::CollectionContinuation(resolved.Value()));
    if (!opened.HasValue())
    {
        return opened.Error();
    }
    auto& files = opened.Value();
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
        if (Status::Compliant != result.Value())
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
    return verdict;
}
} // anonymous namespace

Result<Status> AuditSshKeyPermissions(const SshKeyPermissionsParams& params, IndicatorsTree& indicators, ContextInterface& context)
{
    bool isPublic = (params.type == SshKeyType::Public);
    return SshKeyPermsHelper(isPublic, false, indicators, context);
}

Result<Status> RemediateSshKeyPermissions(const SshKeyPermissionsParams& params, IndicatorsTree& indicators, ContextInterface& context)
{
    bool isPublic = (params.type == SshKeyType::Public);
    return SshKeyPermsHelper(isPublic, true, indicators, context);
}

} // namespace ComplianceEngine
