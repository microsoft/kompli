// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef COMPLIANCEENGINE_FILESYSTEM_PATH_HPP
#define COMPLIANCEENGINE_FILESYSTEM_PATH_HPP

#include "FilesystemPolicy.hpp"
#include "Handle.hpp"
#include "Variant.hpp"

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
    std::size_t components = 128;                         // resolution steps per confined ResolveChild call
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
    std::size_t depth = 128;            // physical directory stack per confined ResolveChild call
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
    // Path owns each component's pin. A Component is not an independent
    // descriptor or a copyable snapshot of its acquisition.
    struct Component
    {
        Component(Handle&& owned, std::string source = {}, std::string target = {})
            : pin(std::move(owned)),
              lookupPart(std::move(source)),
              effectivePart(std::move(target))
        {
        }
        Handle pin;
        // Only the root retains complete frozen names. Other pins retain
        // component names; Path keeps their ancestry in private entries.
        std::string lookupPart;
        std::string effectivePart;
    };

private:
    struct Entry
    {
        Entry(Handle&& owned, bool leaf, std::string source = {}, std::string target = {})
            : component(std::move(owned), std::move(source), std::move(target)),
              logicalLeaf(leaf),
              lookupLength(component.lookupPart.size()),
              effectiveLength(component.effectivePart.size())
        {
        }
        Component component;
        bool logicalLeaf;
        std::size_t lookupParent = 0;
        std::size_t effectiveParent = 0;
        // Continue conservatively charging complete reconstructed spellings
        // until all temporary/scratch storage has replacement coverage.
        std::size_t lookupLength;
        std::size_t effectiveLength;
        std::size_t generation = 0;
    };

public:
    // Borrowed view of the active physical chain, not every owned component.
    // The range and its iterators are invalidated by Path mutation, move or
    // destruction. Neither iteration nor dereference duplicates a pin.
    class ComponentRange
    {
    public:
        class Iterator
        {
        public:
            using iterator_category = std::forward_iterator_tag;
            using value_type = Component;
            using difference_type = std::ptrdiff_t;
            using pointer = const Component*;
            using reference = const Component&;

            Iterator() = default;
            reference operator*() const
            {
                return (*mEntries)[(*mPhysical)[mPosition]].component;
            }
            pointer operator->() const
            {
                return &**this;
            }
            Iterator& operator++()
            {
                ++mPosition;
                return *this;
            }
            Iterator operator++(int)
            {
                auto previous = *this;
                ++*this;
                return previous;
            }
            bool operator==(const Iterator& other) const
            {
                return mEntries == other.mEntries && mPhysical == other.mPhysical && mPosition == other.mPosition;
            }
            bool operator!=(const Iterator& other) const
            {
                return !(*this == other);
            }

        private:
            friend class ComponentRange;
            Iterator(const std::deque<Entry>* entries, const std::vector<std::size_t>* physical, std::size_t position)
                : mEntries(entries),
                  mPhysical(physical),
                  mPosition(position)
            {
            }
            const std::deque<Entry>* mEntries = nullptr;
            const std::vector<std::size_t>* mPhysical = nullptr;
            std::size_t mPosition = 0;
        };

        Iterator begin() const // NOLINT(*-identifier-naming)
        {
            return Iterator(mEntries, mPhysical, 0);
        }
        Iterator end() const // NOLINT(*-identifier-naming)
        {
            return Iterator(mEntries, mPhysical, mPhysical ? mPhysical->size() : 0);
        }

    private:
        friend class Path;
        ComponentRange(const std::deque<Entry>* entries, const std::vector<std::size_t>* physical)
            : mEntries(entries),
              mPhysical(physical)
        {
        }
        const std::deque<Entry>* mEntries;
        const std::vector<std::size_t>* mPhysical;
    };
    // Pin the initial absolute spelling through the trusted resolver. Before
    // FreezeRoot, acquisition remains bounded by the held process-root pin;
    // selected-root access is unavailable. FreezeRoot narrows the boundary to
    // the selected pin and checked-closes acquisition ancestors.
    // The Path alternative is accepted. Missing is reported only for a
    // directly missing path component; helper and confined-resolution ENOENT
    // remain errors. Excluded means an explicit final-link policy omission,
    // never an unsupported root; UnsupportedType is only a Push skip.
    static ComplianceEngine::Result<Variant<Path, Path::RejectionReason>> Make(const ContextInterface& context, std::string absolutePath, Policy policy,
        ResolverLimits limits);
    // A second freeze is an error. On cleanup failure the Path is empty and
    // unusable; no uncertain boundary is published.
    ComplianceEngine::Result<bool> FreezeRoot();
    bool IsFrozen() const noexcept
    {
        return mFrozen && mSize != 0;
    }
    Path(Path&&) noexcept;
    Path& operator=(Path&&) noexcept;
    ~Path() noexcept;
    Path(const Path&) = delete;
    Path& operator=(const Path&) = delete;

    // Success borrows this Path after committing the child. The borrow expires
    // on owner destruction/move and reflects subsequent owner mutations; it is
    // not an immutable snapshot. Rejections leave the stack unchanged.
    ComplianceEngine::Result<Variant<const Path&, RejectionReason>> Push(std::string component, ExtensionPolicy policy);
    // Acquire an absolute selection only from the pristine, unfrozen process
    // root sentinel (including a Path returned by Make("/")). Invalid input
    // leaves it unchanged. After a later component fails or is rejected,
    // already accepted prefix pins remain above "/" and may be frozen or
    // closed; this is not a whole-path rollback or permission to replace them.
    // Success borrows this Path, as with child Push.
    ComplianceEngine::Result<Variant<const Path&, RejectionReason>> Push(std::string absolutePath, Policy policy);
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
    // The consumer holds logical history; Path keeps the physical pins alive
    // until restoration. This token is valid only for this live Path owner.
    struct Restoration
    {
        std::size_t StorageBytes() const noexcept
        {
            return physical.size() * sizeof(std::size_t) + generations.size() * sizeof(std::size_t);
        }

    private:
        friend class Path;
        std::vector<std::size_t> physical;
        const void* owner = nullptr;
        std::vector<std::size_t> generations;
    };
    // Before freezing, Capture returns an invalid token; Restore rejects it.
    Restoration Capture() const;
    ComplianceEngine::Result<bool> Restore(Restoration previous);
    // Retain a selected leaf independently while a walker restores its
    // physical ancestry. The duplicate shares the held object, not its name.
    ComplianceEngine::Result<Handle> DuplicateLeaf() const;
    // On an empty Path these reference-returning accessors throw logic_error.
    const Handle& Root() const;
    const Handle& Leaf() const;
    // Before FreezeRoot, throws logic_error like Root/Leaf. After the root
    // is popped or Close(), returns an empty range (never the process root).
    ComponentRange Components() const&;
    ComponentRange Components() const&& = delete;
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
    const ResolverLimits& Limits() const noexcept
    {
        return mLimits;
    }

private:
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
        const Handle* pin;
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
    static ComplianceEngine::Result<Variant<Detail::ResolvedPath, RejectionReason>> ResolveChild(const ContextInterface& context, const Handle& root,
        const std::vector<const Handle*>& parentLineage, std::string component, ResolutionPolicy policy, const ResolverLimits& limits,
        const std::vector<NameBinding>& names, const std::string& logicalRoot, const std::string& effectiveRoot, std::size_t& spent, std::size_t& followed);
    std::vector<NameBinding> Bindings() const;
    Path(const ContextInterface& context, ResolverLimits limits);
    // The caller checked-closes any duplicate not transferred to the
    // candidate; the candidate is checked-closed here on recognition failure.
    static ComplianceEngine::Result<Handle> RetainDuplicatedLeaf(const ContextInterface& context, const ResolverLimits& limits,
        Detail::ResolvedPath& stage, const Handle& source, Detail::Descriptor& duplicate, int duplicateError);
    static ComplianceEngine::Result<Handle> RetainLeaf(const ContextInterface& context, const ResolverLimits& limits, std::size_t held,
        Detail::ResolvedPath& stage, const Handle& source);
    // Fallible bootstrap after input validation; constructor itself only
    // initializes local state. Charges the exact spelling and sentinel entry.
    ComplianceEngine::Result<bool> PinProcessRoot();
    ComplianceEngine::Result<Variant<const Path&, RejectionReason>> Extend(std::string component, ExtensionPolicy policy, ExtensionMode mode,
        DirectoryRequirement directoryRequirement, std::size_t& followed);
    ComplianceEngine::Result<bool> Commit(Detail::ResolvedPath& stage, Handle leaf);
    ComplianceEngine::Result<bool> CommitStage(Detail::ResolvedPath& stage, Handle leaf, bool logicalLeaf);
    static ComplianceEngine::Result<std::vector<const Handle*>> PhysicalLineage(const Handle& root, const std::string& rootName, const Handle& target,
        const std::string& targetName, const std::vector<NameBinding>& names, const Detail::ResolvedPath* stage, std::size_t depth);
    ComplianceEngine::Result<std::vector<const Handle*>> Lineage(std::size_t index) const;
    std::size_t HeldDescriptors() const noexcept;
    // Charge work before checking optional retained headroom; failed
    // headroom checks do not refund an attempted operation.
    Optional<Error> ChargeWork(std::size_t retainedHeadroom = 0);
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
    // selected after a branch remain owned until checked Pop/Close cleanup.
    std::vector<std::size_t> mPhysical;
    std::size_t mSize = 0;
    std::size_t mNextGeneration = 1;
};

} // namespace Filesystem
} // namespace ComplianceEngine

#endif // COMPLIANCEENGINE_FILESYSTEM_PATH_HPP
