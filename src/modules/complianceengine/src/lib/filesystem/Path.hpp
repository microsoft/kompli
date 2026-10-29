// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef COMPLIANCEENGINE_FILESYSTEM_PATH_HPP
#define COMPLIANCEENGINE_FILESYSTEM_PATH_HPP

#include "FilesystemPolicy.hpp"
#include "Handle.hpp"
#include "Variant.h"

#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
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

// Per-call ceilings with conservative defaults; every member must be positive.
// Defaults are budgets, not an authorization to access a path.
struct PrefixLimits
{
    std::size_t targetBytes = 4096;
    std::size_t components = 128;
    std::size_t work = 100000;
    std::size_t liveDescriptors = 256;
    std::size_t retainedBytes = std::size_t{1024} * 1024;
    std::size_t fdinfoBytes = 4096;
};
enum class MountPolicy
{
    AllowCrossing,
    StayOnRootMount
};
struct ResolverLimits
{
    PrefixLimits shared;
    std::size_t linkTargetBytes = 4096;
    std::size_t linkExpansions = 128;
    std::size_t depth = 128;
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
    SymlinkPolicy symlinks = SymlinkPolicy::DoNotFollow;
    MountPolicy mounts = MountPolicy::StayOnRootMount;
    HardlinkPolicy hardlinks = HardlinkPolicy::Permit;
    UnsupportedTypeAction unsupported = UnsupportedTypeAction::Reject;
    SymlinkPolicy fileLinks = SymlinkPolicy::DoNotFollow;
    SymlinkPolicy directoryLinks = SymlinkPolicy::DoNotFollow;
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
    enum class RejectionReason
    {
        Missing,
        Excluded,
        UnsupportedType
    };
    struct Policy
    {
        SymlinkPolicy symlinks = SymlinkPolicy::DoNotFollow;
        MountPolicy mounts = MountPolicy::StayOnRootMount;
        SymlinkPolicy fileLinks = SymlinkPolicy::DoNotFollow;
        SymlinkPolicy directoryLinks = SymlinkPolicy::DoNotFollow;
        NonFollowedLinkAction nonFollowedLinks = NonFollowedLinkAction::Reject;
    };
    struct Metadata
    {
        struct stat accepted = {}; // retained accepted directory/regular-file pin
        std::uint64_t mountId = 0; // original name's verified mount, before a link target
    };
    // Pin the initial absolute spelling through the trusted resolver, close
    // its scratch ancestors before acceptance, then resolve descendants only
    // through the selected root pin. Complete logical/effective root names
    // select this frozen binding, not a fresh process-root lookup.
    // The Path alternative is accepted. Missing is reported only for a
    // directly missing path component; helper and confined-resolution ENOENT
    // remain errors. Excluded means an explicit final-link policy omission,
    // never an unsupported root; UnsupportedType is only a Push skip.
    static ComplianceEngine::Result<Variant<Path, Path::RejectionReason>> Make(const ContextInterface& context, std::string absolutePath, Policy policy,
        ResolverLimits limits);
    Path(Path&&) noexcept;
    Path& operator=(Path&&) noexcept;
    ~Path() noexcept;
    Path(const Path&) = delete;
    Path& operator=(const Path&) = delete;

    // Success borrows this Path after committing the child. The borrow expires
    // on owner destruction/move and reflects subsequent owner mutations; it is
    // not an immutable snapshot. Rejections leave the stack unchanged.
    ComplianceEngine::Result<Variant<const Path&, RejectionReason>> Push(std::string component, ExtensionPolicy policy);
    // Transfers the last pin, including the root, without reacquiring its
    // name. The removed element's borrows expire; surviving borrows do not.
    // Popping releases hidden pins acquired for this logical step immediately.
    // If an auxiliary close fails, all step pins are still closed, the
    // detached leaf is closed rather than returned, and the preceding Path
    // remains valid; native closes cannot be rolled back.
    // The transferred pin immediately stops counting toward Path's budgets;
    // the consumer must bound retained handles independently.
    // An empty (also moved-from) Path returns EINVAL.
    ComplianceEngine::Result<Handle> Pop();
    // Release every pin still owned by this Path, including hidden
    // symlink-resolution pins. Attempt all closes;
    // return the first error and log subsequent failures. No native close is
    // retried. The Path becomes empty; subsequent calls succeed without native
    // closes. Popped handles and activated readable files are separate
    // owners and remain valid; close popped handles explicitly if required.
    // Destruction logs an unobserved first failure if Close was not called.
    ComplianceEngine::Result<bool> Close();
    // On an empty Path these reference-returning accessors throw logic_error.
    const Handle& Root() const;
    const Handle& Leaf() const;
    // Accepted pin metadata and the original component's verified mount ID.
    Metadata LeafMetadata() const;
    std::size_t Size() const noexcept;
    // Count only resources still owned by this Path, including hidden pins,
    // not handles transferred by Pop().
    std::size_t RetainedDescriptors() const noexcept;
    std::size_t RetainedBytes() const noexcept;
    // Acquired effective spelling; not a current global canonical pathname.
    std::string ToString() const;
    const ContextInterface& Context() const noexcept
    {
        return mContext.get();
    }
    const std::string& DiagnosticPath() const noexcept
    {
        return mDiagnosticPath;
    }
    const ResolverLimits& Limits() const noexcept
    {
        return mLimits;
    }

private:
    class Resolver;
    struct NameBinding
    {
        const Handle* pin;
        const std::string* lookup;
        const std::string* effective;
        std::uint64_t mount;
    };
    static ComplianceEngine::Result<Detail::ResolvedPath> ResolveChild(const ContextInterface& context, const std::vector<const Handle*>& rootLineage,
        const std::vector<const Handle*>& parentLineage, std::string component, bool followSymlinks, MountPolicy mounts, const ResolverLimits& limits,
        bool permitUnsupported, bool allowMissing, bool excludeLinks, const std::vector<NameBinding>& names, const std::string& logicalRoot,
        const std::string& effectiveRoot, std::size_t* spent = nullptr);
    std::vector<NameBinding> Bindings() const;
    Path(const ContextInterface& context, ResolverLimits limits);
    ComplianceEngine::Result<Handle> RetainLeaf(Detail::ResolvedPath& stage, const std::string& component);
    ComplianceEngine::Result<bool> ReleaseStage(Detail::ResolvedPath& stage);
    ComplianceEngine::Result<bool> Commit(Detail::ResolvedPath& stage, Handle leaf, bool root);
    std::vector<const Handle*> Lineage(std::size_t index) const;
    std::size_t HeldDescriptors() const noexcept;
    bool ChargeWork() noexcept;
    ComplianceEngine::Result<std::uint64_t> RootMountId() const;

    std::reference_wrapper<const ContextInterface> mContext;
    ResolverLimits mLimits;
    struct Usage
    {
        std::size_t workSpent = 0;
        std::size_t retainedBytes = 0;
    };
    Usage mUsage;
    std::uint64_t mRootMountId = 0;
    // One persistent owner deque. Effective names are captured at actual
    // acquisition and tied to the pins; logical leaves delimit Pop steps.
    struct Entry
    {
        Entry(Handle&& owned, std::string lookup, std::string effective, std::uint64_t mount, bool leaf)
            : pin(std::move(owned)),
              lookupName(std::move(lookup)),
              effectiveName(std::move(effective)),
              originalMount(mount),
              logicalLeaf(leaf)
        {
        }
        Handle pin;
        std::string lookupName;
        std::string effectiveName;
        std::uint64_t originalMount;
        bool logicalLeaf;
    };
    static constexpr std::size_t NoIndex = static_cast<std::size_t>(-1);
    std::deque<Entry> mEntries;
    std::size_t mLeafIndex = NoIndex;
    std::size_t mSize = 0;
    std::string mDiagnosticPath;
};

} // namespace Filesystem
} // namespace ComplianceEngine

#endif // COMPLIANCEENGINE_FILESYSTEM_PATH_HPP
