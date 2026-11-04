// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef COMPLIANCEENGINE_FILESYSTEM_PATH_HPP
#define COMPLIANCEENGINE_FILESYSTEM_PATH_HPP

#include "FilesystemPolicy.hpp"
#include "Handle.hpp"
#include "PathLinkAccess.hpp"
#include "Variant.hpp"

#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <iterator>
#include <memory>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>
#include <utility>
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

// Conservative budgets, not authorization to access a path. All must be positive.
struct PrefixLimits
{
    std::size_t targetBytes = 4096;                       // each absolute symlink target
    std::size_t components = 128;                         // resolution steps per confined child acquisition
    std::size_t work = 100000;                            // cumulative for Make and subsequent Push calls, including failed attempts
    std::size_t liveDescriptors = 256;                    // held Path pins plus current resolution and helper headroom
    std::size_t retainedBytes = std::size_t{1024} * 1024; // Path-owned state and current resolution's transient storage
    std::size_t fdinfoBytes = 4096;                       // each pinned fdinfo read
};
enum class MountPolicy
{
    AllowCrossing,
    StayOnRootMount
};
struct ResolverLimits
{
    PrefixLimits shared;
    std::size_t linkTargetBytes = 4096; // each pinned symlink read
    std::size_t linkExpansions = 128;   // total followed links per Make or Push, including held aliases
    std::size_t depth = 128;            // physical directory stack per confined child acquisition
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
    MountPolicy mounts = MountPolicy::StayOnRootMount;
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
// Context outlives all owners. Components retain their particular pins;
// no public fd escapes.
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
    // Immutable shared acquisition: a Component always owns one complete pin.
    class Component
    {
    public:
        Component() = delete;
        Component(const Component&) noexcept = default;
        Component& operator=(const Component&) & noexcept = default;
        Component(Component&& other) noexcept
            : mAcquisition(other.mAcquisition)
        {
        }
        Component& operator=(Component&& other) & noexcept
        {
            mAcquisition = other.mAcquisition;
            return *this;
        }
        ~Component() noexcept = default;

        AcquisitionFacts Acquired() const noexcept
        {
            return mAcquisition->Acquired();
        }
        std::string LookupName() const
        {
            return mAcquisition->LookupName();
        }
        std::string EffectiveName() const
        {
            return mAcquisition->EffectiveName();
        }
        Result<struct stat> Stat() const
        {
            return mAcquisition->Stat();
        }
        Result<bool> SetOwnership(UserId owner, GroupId group) const
        {
            return mAcquisition->SetOwnership(owner, group);
        }
        Result<bool> SetMode(mode_t mode) const
        {
            return mAcquisition->SetMode(mode);
        }
        Result<ReadableFile> OpenReadOnly() const
        {
            return mAcquisition->OpenReadOnly();
        }
        Result<ReadableFile> OpenReadOnly(ReadableFile::Policy policy) const
        {
            return mAcquisition->OpenReadOnly(policy);
        }
        Result<DirectoryCursor> OpenChildren() const
        {
            return mAcquisition->OpenChildren();
        }

    private:
        friend class Path;
        explicit Component(Detail::Handle owned)
            : mAcquisition(std::make_shared<const Detail::Handle>(std::move(owned)))
        {
        }
        bool SameAcquisition(Component other) const noexcept
        {
            return mAcquisition == other.mAcquisition;
        }
        std::shared_ptr<const Detail::Handle> mAcquisition;
    };

private:
    using Handle = Detail::Handle;
    struct Entry
    {
        Entry(Handle&& owned, bool leaf, std::string source, std::string target, std::size_t lookupBytes, std::size_t effectiveBytes)
            : component(std::move(owned)),
              logicalLeaf(leaf),
              lookupPart(std::move(source)),
              effectivePart(std::move(target)),
              lookupLength(lookupBytes),
              effectiveLength(effectiveBytes)
        {
        }
        Entry(Handle&& owned, bool leaf, std::string source = {}, std::string target = {})
            : Entry(std::move(owned), leaf, source, target, source.size(), target.size())
        {
        }
        Component component;
        bool logicalLeaf;
        std::size_t lookupParent = 0;
        std::size_t effectiveParent = 0;
        // Path route bindings are separate from immutable acquisition names.
        std::string lookupPart;
        std::string effectivePart;
        std::size_t lookupLength;
        std::size_t effectiveLength;
    };

public:
    // Pin the initial absolute spelling through the trusted resolver. Before
    // FreezeRoot, acquisition remains bounded by the held process-root pin;
    // selected-root access is unavailable. FreezeRoot narrows the boundary to
    // the selected pin; discarded ancestor pins are disposed diagnostically.
    // The Path alternative is accepted. Missing is reported only for a
    // directly missing path component; helper and confined-resolution ENOENT
    // remain errors. Excluded means an explicit final-link policy omission,
    // never an unsupported root; UnsupportedType is only a Push skip.
    static ComplianceEngine::Result<Variant<Path, Path::RejectionReason>> Make(const ContextInterface& context, std::string absolutePath, Policy policy,
        ResolverLimits limits);
    // A second freeze is an error. Failed preparation leaves the Path
    // unchanged; disposal failures cannot veto a completed freeze.
    ComplianceEngine::Result<bool> FreezeRoot();
    bool IsFrozen() const noexcept
    {
        return mFrozen && mSize != 0;
    }
    Path(Path&&) noexcept;
    Path& operator=(Path&&) & noexcept;
    ~Path() noexcept;
    Path(const Path&) = delete;
    Path& operator=(const Path&) = delete;

    // Success reports true after committing the child. Rejections leave the
    // stack unchanged.
    ComplianceEngine::Result<Variant<bool, RejectionReason>> Push(std::string component, ExtensionPolicy policy) &;
    // Acquire an absolute selection only from the pristine, unfrozen process
    // root sentinel (including a Path returned by Make("/")). Invalid input
    // leaves it unchanged. After a later component fails or is rejected,
    // already accepted prefix pins remain above "/" and may be frozen or
    // closed; this is not a whole-path rollback or permission to replace them.
    // Success reports true, as with child Push.
    ComplianceEngine::Result<Variant<bool, RejectionReason>> Push(std::string absolutePath, Policy policy) &;
    // Transfers the last pin, including the root, without reacquiring its
    // name. Hidden pins for this logical step are disposed diagnostically.
    // A disposal failure cannot replace the returned pin or an operational
    // error. The transferred pin stops counting toward Path's budgets;
    // the consumer must bound retained owners independently.
    // An empty (also moved-from) Path returns EINVAL.
    ComplianceEngine::Result<Component> Pop();
    // The consumer holds logical history; Path keeps the physical pins alive
    // until restoration. This token is valid only for this live Path owner.
    // The parent remains unchanged even when acquisition rejects or fails.
    ComplianceEngine::Result<Variant<Path, RejectionReason>> AcquireChild(std::string component, ExtensionPolicy policy) const&;
    Component Root() const;
    Component Leaf() const;
    std::vector<Component> Components() const;
    // Number of visible components in the frozen Path.
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
    ResolverLimits Limits() const noexcept
    {
        return mLimits;
    }

private:
    friend class ::ComplianceEngine::Tests::DescriptorTestAccess;
    // A held link pin is inspected only through Path or the focused test seam.
    static Result<Detail::LinkTarget> ReadPinnedLink(const Detail::Descriptor& linkPin, std::size_t targetByteCap, std::size_t fdinfoByteCap);
    static Result<Detail::LinkTarget> ReadVerifiedLinkText(const Detail::Descriptor& linkPin, const struct stat& before,
        const Detail::ProcfsDescriptorAccess& procfs, std::size_t targetByteCap, std::size_t fdinfoByteCap);
    class Resolver;
    enum class ExtensionMode
    {
        RootAcquisition,
        ChildPush
    };
    enum class DirectoryRequirement
    {
        DirectoryOnly,
        FileOrDirectory
    };
    struct NameBinding
    {
        Component component;
        std::string lookup;
        std::string effective;
        std::uint64_t mount;
    };
    struct ResolutionPolicy
    {
        bool followLinks;
        MountPolicy mounts;
        bool permitUnsupported;
        bool allowMissing;
        bool excludeLinks;
    };
    std::vector<NameBinding> Bindings() const;
    Path(const ContextInterface& context, ResolverLimits limits);
    // A duplicate not transferred to the candidate is disposed diagnostically;
    // recognition failure also disposes the candidate without replacing its error.
    static ComplianceEngine::Result<Handle> RetainDuplicatedLeaf(const ContextInterface& context, const ResolverLimits& limits,
        Detail::ResolvedPath& stage, const Handle& source, Detail::Descriptor& duplicate, int duplicateError);
    static ComplianceEngine::Result<Handle> RetainLeaf(const ContextInterface& context, const ResolverLimits& limits, std::size_t held,
        Detail::ResolvedPath& stage, const Handle& source);
    // Fallible bootstrap after input validation; constructor itself only
    // initializes local state. Charges the exact spelling and sentinel entry.
    ComplianceEngine::Result<bool> PinProcessRoot();
    ComplianceEngine::Result<Variant<bool, RejectionReason>> Extend(std::string component, ExtensionPolicy policy, ExtensionMode mode,
        DirectoryRequirement directoryRequirement, std::size_t& followed);
    ComplianceEngine::Result<bool> Commit(Detail::ResolvedPath& stage, Handle leaf);
    ComplianceEngine::Result<bool> CommitStage(Detail::ResolvedPath& stage, Handle leaf, bool logicalLeaf);
    std::size_t HeldDescriptors() const noexcept;
    // Charge work before checking optional retained headroom; failed
    // headroom checks do not refund an attempted operation.
    Optional<Error> ChargeWork(std::size_t retainedHeadroom = 0);
    ComplianceEngine::Result<std::uint64_t> RootMountId() const;

    void Clear() noexcept;
    std::reference_wrapper<const ContextInterface> mContext;
    ResolverLimits mLimits;
    struct Usage
    {
        std::size_t retainedBytes = 0;
    };
    Usage mUsage;
    // Until a traversal-owned cumulative allowance is selected, independent
    // child locations share the initial acquisition's checked work allowance.
    // This owner holds no pins or locations; rejected attempts still charge it.
    struct WorkAllowance
    {
        std::size_t spent = 0;
    };
    std::shared_ptr<WorkAllowance> mWorkAllowance;
    std::uint64_t mRootMountId = 0;
    std::uint64_t mLeafSourceMount = 0;
    bool mFrozen = false;
    std::string mAcquisitionName;
    std::size_t mAcquisitionBytes = 0;
    // One persistent owner deque. Effective names are captured at actual
    // acquisition and tied to the pins; logical leaves delimit Pop steps.
    static bool Footprint(std::size_t lookup, std::size_t effective, std::size_t& bytes) noexcept;
    static bool Footprint(const Entry& pin, std::size_t& bytes) noexcept;
    std::string Name(std::size_t index, bool lookup) const;
    // Own the deque allocation separately: moving a deque itself may allocate
    // an empty map even when its declared move constructor is noexcept.
    // A moved-from Path has no deque and remains a valid empty owner.
    std::unique_ptr<std::deque<Entry>> mEntries;
    // Indexes into the owning deque in physical ancestor order. Entries not
    // selected after a branch remain owned until Pop or Path destruction.
    std::vector<std::size_t> mPhysical;
    std::size_t mSize = 0;
};

} // namespace Filesystem
} // namespace ComplianceEngine

#endif // COMPLIANCEENGINE_FILESYSTEM_PATH_HPP
