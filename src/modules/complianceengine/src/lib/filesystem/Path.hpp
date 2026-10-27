// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef COMPLIANCEENGINE_FILESYSTEM_PATH_HPP
#define COMPLIANCEENGINE_FILESYSTEM_PATH_HPP

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
struct DetachedResources;
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

enum class SymlinkPolicy
{
    Reject,
    FollowWithinRoot
};
enum class HardlinkPolicy
{
    Permit,
    RequireUnique // unsupported until inspection timing/semantics are agreed
};
struct RootPolicy
{
    RootPolicy(SymlinkPolicy symlinks, MountPolicy mounts)
        : symlinks(symlinks),
          mounts(mounts)
    {
    }
    SymlinkPolicy symlinks;
    MountPolicy mounts;
};
struct ExtensionPolicy
{
    ExtensionPolicy(SymlinkPolicy symlinks, MountPolicy mounts, HardlinkPolicy hardlinks)
        : symlinks(symlinks),
          mounts(mounts),
          hardlinks(hardlinks)
    {
    }
    SymlinkPolicy symlinks;
    MountPolicy mounts;
    HardlinkPolicy hardlinks;
};

// The caller's explicit choice of a configured absolute directory is its
// authorization under the trusted service/mount-namespace assumption.
// Selection is not inferred from path ownership or from successful opens.
// Context and all borrowed handles must outlive their users; end insertion
// preserves references to existing stack elements. No public fd escapes.
class Path
{
public:
    static Result<Path> AcquireRoot(const ContextInterface& context, std::string absoluteRoot, RootPolicy policy, ResolverLimits limits, bool regularFileRoot = false);
    Path(Path&&) noexcept;
    Path& operator=(Path&&) noexcept;
    ~Path() noexcept;
    Path(const Path&) = delete;
    Path& operator=(const Path&) = delete;

    Result<bool> Push(std::string component, ExtensionPolicy policy);
    // Observe a single name relative to the live directory pin. This is
    // selection metadata only; it never grants authority to mutate that name.
    struct ChildObservation
    {
        struct stat metadata = {};
        std::uint64_t mountId = 0;
    };
    // Empty only when the child openat itself returned ENOENT. Procfs and
    // parent-inspection failures (even ENOENT) remain errors.
    Result<Optional<ChildObservation>> ObserveChild(const std::string& component, std::size_t fdinfoByteCap) const;
    // Transfers the last pin, including the root, without reacquiring its
    // name. The removed element's borrows expire; surviving borrows do not.
    // Popping any element leaves its hidden acquisition-stage pins owned by
    // this Path until Close/destruction, so those closes remain checked.
    // An empty (also moved-from) Path returns EINVAL.
    Result<Handle> Pop();
    // Release every pin still owned by this Path, including retained root,
    // stage and hidden symlink-resolution lineage pins. Attempt all closes;
    // return the first error and log subsequent failures. No native close is
    // retried. The Path becomes empty, with the original result cached for
    // repeated calls. Popped handles and activated readable files are separate
    // owners and remain valid; close popped handles explicitly if required.
    // Destruction logs an unobserved first failure if Close was not called.
    Result<bool> Close();
    // On an empty Path these reference-returning accessors throw logic_error.
    const Handle& Root() const;
    const Handle& Leaf() const;
    // Pinned metadata for the first symlink in the most recent root/child
    // acquisition, if the selected name itself was a link. This observation
    // is bound to the link pin used for confined resolution, not a name replay.
    Optional<struct stat> LeafLinkMetadata() const;
    std::size_t Size() const noexcept;
    std::size_t RetainedDescriptors() const noexcept;
    std::size_t RetainedBytes() const noexcept;

private:
    class Resolver;
    static Result<Detail::ResolvedPath> ResolveChild(const ContextInterface& context, const std::vector<const Handle*>& rootLineage,
        const std::vector<const Handle*>& parentLineage, std::string component, bool followSymlinks, MountPolicy mounts, const ResolverLimits& limits,
        std::size_t* spent = nullptr);
    Path(const ContextInterface& context, ResolverLimits limits);
    Result<Handle> RetainLeaf(Detail::ResolvedPath& stage, const std::string& component);
    std::size_t HeldDescriptors() const noexcept;
    bool ChargeWork() noexcept;
    Result<std::uint64_t> RootMountId() const;

    const ContextInterface* mContext;
    ResolverLimits mLimits;
    std::size_t mWorkSpent = 0;
    std::shared_ptr<Detail::DetachedResources> mDetachedResources;
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
} // namespace Filesystem
} // namespace ComplianceEngine

#endif // COMPLIANCEENGINE_FILESYSTEM_PATH_HPP
