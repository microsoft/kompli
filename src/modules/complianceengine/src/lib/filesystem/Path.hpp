// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef COMPLIANCEENGINE_FILESYSTEM_PATH_HPP
#define COMPLIANCEENGINE_FILESYSTEM_PATH_HPP

#include "FilesystemPolicy.hpp"
#include "Handle.hpp"

#include <cstddef>
#include <cstdint>
#include <deque>
#include <memory>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>
#include <vector>

namespace ComplianceEngine
{
class ContextInterface;

namespace Filesystem
{
class Path;
namespace Detail
{
class ResolvedPath;
} // namespace Detail

// Explicit per-call ceilings; every member must be positive. No implicit
// foundation defaults or authorization are inferred from these limits.
struct PrefixLimits
{
    std::size_t targetBytes;
    std::size_t components;
    std::size_t work;
    std::size_t liveDescriptors;
    std::size_t retainedBytes;
    std::size_t fdinfoBytes;
};
enum class MountPolicy
{
    AllowCrossing,
    StayOnRootMount
};
struct ResolverLimits
{
    PrefixLimits shared;
    std::size_t linkTargetBytes;
    std::size_t linkExpansions;
    std::size_t depth;
};

namespace Detail
{
// Source-compatible spellings for limits and policy formerly declared here.
// New consumers use the Filesystem names above without an internal include.
using PrefixLimits = ::ComplianceEngine::Filesystem::PrefixLimits;
using ResolverLimits = ::ComplianceEngine::Filesystem::ResolverLimits;
using MountPolicy = ::ComplianceEngine::Filesystem::MountPolicy;
} // namespace Detail

enum class HardlinkPolicy
{
    Permit,
    RequireUnique // unsupported until inspection timing/semantics are agreed
};
enum class UnsupportedTypeAction
{
    Reject, // default; only the selected final unsupported inode is eligible
    Skip    // never converts lookup, link, mount, budget or cleanup errors
};
enum class NonFollowedLinkAction
{
    Reject, // ELOOP, including the reader's no-follow policy
    Skip    // intentional FTW omission, distinct from a rejected link
};
struct ExtensionPolicy
{
    ExtensionPolicy(SymlinkPolicy symlinks, MountPolicy mounts, HardlinkPolicy hardlinks, UnsupportedTypeAction unsupported = UnsupportedTypeAction::Reject)
        : symlinks(symlinks),
          mounts(mounts),
          hardlinks(hardlinks),
          unsupported(unsupported),
          fileLinks(symlinks),
          directoryLinks(fileLinks)
    {
    }
    SymlinkPolicy symlinks;
    MountPolicy mounts;
    HardlinkPolicy hardlinks;
    UnsupportedTypeAction unsupported;
    SymlinkPolicy fileLinks;
    SymlinkPolicy directoryLinks;
    NonFollowedLinkAction nonFollowedLinks = NonFollowedLinkAction::Reject;
    // Only a direct missing name is reported, never an ENOENT from trusted
    // procfs or symlink-target resolution. FTW additionally checks DT_REG.
    bool reportMissingRegularFile = false;
};

// The caller's explicit choice of a configured absolute directory is its
// authorization under the trusted service/mount-namespace assumption.
// Authorization is not inferred from path ownership or from successful opens.
// Context and all borrowed handles must outlive their users; end insertion
// preserves references to existing stack elements. No public fd escapes.
class Path
{
public:
    struct Policy
    {
        Policy(SymlinkPolicy symlinks, MountPolicy mounts)
            : symlinks(symlinks),
              mounts(mounts),
              fileLinks(symlinks),
              directoryLinks(fileLinks)
        {
        }
        SymlinkPolicy symlinks;
        MountPolicy mounts;
        SymlinkPolicy fileLinks;
        SymlinkPolicy directoryLinks;
        NonFollowedLinkAction nonFollowedLinks = NonFollowedLinkAction::Reject;
    };
    struct Result;
    struct Metadata
    {
        struct stat accepted = {};         // retained accepted directory/regular-file pin
        Optional<struct stat> initialLink; // first name's live link pin during acquisition
        std::uint64_t mountId = 0;         // original name's verified mount, before a link target
    };
    enum class PushOutcome
    {
        Pushed,
        SkippedUnsupported, // no stack mutation; checked release of every temp pin
        SkippedLink,        // only an explicit final-type DoNotFollow + Skip action
        Missing             // only explicit reporting of a direct missing name
    };
    // Pin each prefix through the trusted resolver, then rebase all subsequent
    // descendant resolution on the selected file or directory, never on "/".
    // Missing is reported only for a directly missing path component; helper
    // and confined-resolution ENOENT remain errors. Excluded means an
    // explicit final-link policy omission, never an unsupported root.
    static ComplianceEngine::Result<Path::Result> Make(const ContextInterface& context, std::string absolutePath, Policy policy, ResolverLimits limits);
    Path(Path&&) noexcept;
    Path& operator=(Path&&) noexcept;
    ~Path() noexcept;
    Path(const Path&) = delete;
    Path& operator=(const Path&) = delete;

    ComplianceEngine::Result<PushOutcome> Push(std::string component, ExtensionPolicy policy);
    // Transfers the last pin, including the root, without reacquiring its
    // name. The removed element's borrows expire; surviving borrows do not.
    // Popping any element leaves its hidden acquisition-stage pins owned by
    // this Path until Close/destruction, so those closes remain checked.
    // The transferred pin immediately stops counting toward Path's budgets;
    // the consumer must bound retained handles independently.
    // An empty (also moved-from) Path returns EINVAL.
    ComplianceEngine::Result<Handle> Pop();
    // Release every pin still owned by this Path, including retained root,
    // stage and hidden symlink-resolution lineage pins. Attempt all closes;
    // return the first error and log subsequent failures. No native close is
    // retried. The Path becomes empty, with the original result cached for
    // repeated calls. Popped handles and activated readable files are separate
    // owners and remain valid; close popped handles explicitly if required.
    // Destruction logs an unobserved first failure if Close was not called.
    ComplianceEngine::Result<bool> Close();
    // On an empty Path these reference-returning accessors throw logic_error.
    const Handle& Root() const;
    const Handle& Leaf() const;
    // Pinned metadata for the first symlink in the most recent root/child
    // acquisition, if the selected name itself was a link. This observation
    // is bound to the link pin used for confined resolution, not a name replay.
    Metadata LeafMetadata() const;
    std::size_t Size() const noexcept;
    // Count only resources still owned by this Path, including hidden and
    // retired acquisition-stage pins, not handles transferred by Pop().
    std::size_t RetainedDescriptors() const noexcept;
    std::size_t RetainedBytes() const noexcept;

private:
    class Resolver;
    static ComplianceEngine::Result<Detail::ResolvedPath> ResolveChild(const ContextInterface& context, const std::vector<const Handle*>& rootLineage,
        const std::vector<const Handle*>& parentLineage, std::string component, bool followSymlinks, MountPolicy mounts, const ResolverLimits& limits,
        bool permitUnsupported, bool allowMissing, bool excludeLinks, std::size_t* spent = nullptr);
    Path(const ContextInterface& context, ResolverLimits limits);
    ComplianceEngine::Result<Handle> RetainLeaf(Detail::ResolvedPath& stage, const std::string& component);
    ComplianceEngine::Result<bool> ReleaseStage(Detail::ResolvedPath& stage);
    std::size_t HeldDescriptors() const noexcept;
    bool ChargeWork() noexcept;
    ComplianceEngine::Result<std::uint64_t> RootMountId() const;

    const ContextInterface* mContext;
    ResolverLimits mLimits;
    std::size_t mWorkSpent = 0;
    std::size_t mStoredMemory = 0;
    std::uint64_t mRootMountId = 0;
    std::unique_ptr<Handle> mProcessRoot;
    std::deque<Detail::ResolvedPath> mRootStages;
    std::deque<Detail::ResolvedPath> mStages;
    std::deque<Detail::ResolvedPath> mRetiredStages;
    std::deque<Handle> mComponents;
    std::vector<const Handle*> mRootLineage;
    std::vector<const Handle*> mCurrentLineage;
    bool mCloseAttempted = false;
    int mCloseError = 0;
};

struct Path::Result
{
    enum class Status
    {
        Accepted,
        Missing,
        Excluded
    };
    // No default or externally mutable discriminant: an accepted result
    // always owns an accepted Path. Moving it leaves the source non-accepted.
    static Result Accepted(Path path)
    {
        return Result(std::move(path));
    }
    static Result Missing()
    {
        return Result(Status::Missing);
    }
    static Result Excluded()
    {
        return Result(Status::Excluded);
    }
    Result(Result&& other) noexcept
        : mStatus(other.mStatus),
          mPath(std::move(other.mPath))
    {
        other.mStatus = Status::Missing;
    }
    Result& operator=(Result&& other) noexcept
    {
        if (this != &other)
        {
            mPath = std::move(other.mPath);
            mStatus = other.mStatus;
            other.mStatus = Status::Missing;
        }
        return *this;
    }
    ~Result() = default;
    Result(const Result&) = delete;
    Result& operator=(const Result&) = delete;

    Status GetStatus() const noexcept
    {
        return mStatus;
    }
    Path& AcceptedPath() &
    {
        return mPath.Value();
    }
    const Path& AcceptedPath() const&
    {
        return mPath.Value();
    }
    Path TakePath() &&
    {
        Path accepted(std::move(mPath).Value());
        mPath.Reset();
        mStatus = Status::Missing;
        return accepted;
    }

private:
    explicit Result(Path&& accepted)
        : mStatus(Status::Accepted),
          mPath(std::move(accepted))
    {
    }
    explicit Result(Status status)
        : mStatus(status)
    {
    }
    Status mStatus;
    Optional<Path> mPath; // engaged if and only if mStatus == Accepted
};
} // namespace Filesystem
} // namespace ComplianceEngine

#endif // COMPLIANCEENGINE_FILESYSTEM_PATH_HPP
