// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include "Path.hpp"

#include "ContextInterface.h"
#include "FilesystemHelpers.hpp"
#include "PathLinkAccess.hpp"

#include <cerrno>
#include <climits>
#include <cstdint>
#include <deque>
#include <fcntl.h>
#include <functional>
#include <limits>
#include <linux/magic.h>
#include <memory>
#include <stdexcept>
#include <sys/statfs.h>
#include <unistd.h>
#include <utility>
#include <vector>
namespace ComplianceEngine
{
namespace Filesystem
{
using Detail::Descriptor;
using Detail::LinkTarget;
using Detail::Pin;
using Detail::SavedError;
namespace
{
bool Fits(std::size_t used, std::size_t addition, std::size_t limit) noexcept
{
    return (used <= limit) && (addition <= limit - used);
}
std::size_t BoundedSum(std::initializer_list<std::size_t> terms) noexcept
{
    std::size_t total = 0;
    for (std::size_t term : terms)
    {
        if (term > std::numeric_limits<std::size_t>::max() - total)
            return std::numeric_limits<std::size_t>::max();
        total += term;
    }
    return total;
}
// Procfs bootstrap holds at most three verified directories; the published
// fd/fdinfo pair plus one fdinfo reader also holds three. A new child pin
// remains owned during either phase. Shared stack copies do not duplicate fds.
constexpr std::size_t kProcfsBootstrapPeak = 3;
constexpr std::size_t kProcfsRetained = 2;
constexpr std::size_t kProcfsReadPeak = kProcfsRetained + 1;
constexpr std::size_t kProcfsTemporaryPeak = kProcfsBootstrapPeak > kProcfsReadPeak ? kProcfsBootstrapPeak : kProcfsReadPeak;
constexpr std::size_t kNewChildPeak = 1 + kProcfsTemporaryPeak;
constexpr std::size_t kMinimumPathPeak = 1 + kProcfsTemporaryPeak; // root and procfs
std::string Join(const std::string& parent, const std::string& child)
{
    return parent == "/" ? parent + child : parent + "/" + child;
}
bool AtBoundary(const std::string& text, const std::string& prefix)
{
    return text.compare(0, prefix.size(), prefix) == 0 && (prefix == "/" || text.size() == prefix.size() || text[prefix.size()] == 47);
}
std::string CollapseSeparators(const std::string& name)
{
    std::string result;
    result.reserve(name.size());
    for (char c : name)
        if (c != 47 || result.empty() || result.back() != 47)
            result += c;
    if (result.size() > 1 && result.back() == 47)
        result.pop_back();
    return result;
}
Optional<Error> Validate(const Path::Policy& policy, const ResolverLimits& limits)
{
    if ((policy.prefixLinks != PrefixLinkPolicy::Reject && policy.prefixLinks != PrefixLinkPolicy::Follow) ||
        (policy.fileLinks != FileLinkPolicy::Reject && policy.fileLinks != FileLinkPolicy::Follow) ||
        (policy.directoryLinks != DirectoryLinkPolicy::Reject && policy.directoryLinks != DirectoryLinkPolicy::Follow) ||
        (policy.rejectedLinks != RejectedLinkDisposition::Error && policy.rejectedLinks != RejectedLinkDisposition::Skip) ||
        (policy.unsupportedTypes != UnsupportedTypeDisposition::Error && policy.unsupportedTypes != UnsupportedTypeDisposition::Skip) ||
        (policy.missingFiles != MissingFileDisposition::Error && policy.missingFiles != MissingFileDisposition::Report) ||
        (policy.mounts != MountPolicy::CrossMounts && policy.mounts != MountPolicy::StayOnRootMount))
        return Error("Invalid path policy", EINVAL);
    if (limits.shared.work == 0 || limits.shared.components == 0 || limits.shared.liveDescriptors < kMinimumPathPeak || limits.shared.fdinfoBytes == 0 ||
        limits.shared.targetBytes == 0 || limits.linkTargetBytes == 0 || limits.linkExpansions == 0 || limits.depth == 0 ||
        limits.linkTargetBytes >= std::vector<char>().max_size() - 1 || limits.linkTargetBytes >= static_cast<std::size_t>(std::numeric_limits<ssize_t>::max()) ||
        limits.shared.fdinfoBytes >= static_cast<std::size_t>(std::numeric_limits<ssize_t>::max()))
        return Error("Invalid path resolver limits", EINVAL);
    return {};
}
} // namespace

// The shared owner is immutable. Moving a Component copies its shared pin,
// leaving the source usable without a second metadata allocation.
bool Path::Component::SameAcquisition(const Component& first, const Component& second) noexcept
{
    return first.mAcquisition == second.mAcquisition;
}
std::size_t Path::Component::LookupNameBytes(const Component& owner) noexcept
{
    return owner.mAcquisition->mMetadata.mLookupName.mValue.size();
}
std::size_t Path::Component::EffectiveNameBytes(const Component& owner) noexcept
{
    return owner.mAcquisition->mMetadata.mEffectiveName.mValue.size();
}
std::string Path::Component::LookupName(const Component& owner)
{
    return owner.mAcquisition->mMetadata.mLookupName.mValue;
}
std::string Path::Component::EffectiveName(const Component& owner)
{
    return owner.mAcquisition->mMetadata.mEffectiveName.mValue;
}
Path::Component::Component(Detail::Pin owned)
    : mAcquisition(std::make_shared<const Detail::Pin>(std::move(owned)))
{
}
Path::Component::Component(const Component& other) noexcept
    : mAcquisition(other.mAcquisition)
{
}
Path::Component& Path::Component::operator=(const Component& other) & noexcept
{
    mAcquisition = other.mAcquisition;
    return *this;
}
Path::Component::Component(Component&& other) noexcept
    : mAcquisition(other.mAcquisition)
{
}
Path::Component& Path::Component::operator=(Component&& other) & noexcept
{
    mAcquisition = other.mAcquisition;
    return *this;
}
Path::Component::~Component() noexcept = default;
::ComplianceEngine::Filesystem::Metadata Path::Component::Metadata() const
{
    return mAcquisition->Metadata();
}
Result<struct stat> Path::Component::Stat() const
{
    return mAcquisition->Stat();
}
Result<bool> Path::Component::SetOwnership(UserId owner, GroupId group) const
{
    return mAcquisition->SetOwnership(owner, group);
}
Result<bool> Path::Component::SetMode(mode_t mode) const
{
    return mAcquisition->SetMode(mode);
}
Result<ReadableFile> Path::Component::OpenReadOnly(ReadableFile::Policy policy) const
{
    return mAcquisition->OpenReadOnly(policy);
}

namespace
{
// Resolver work units charged against limits.shared.work; shared by every
// snapshot of one Path so copying the stack can't reset the count.
struct WorkAllowance
{
    std::size_t spent = 0;
};
} // namespace

// The cumulative work allowance alone is shared and mutable across immutable stack snapshots.
struct Path::State
{
    State(const ContextInterface& owner, ResolverLimits caps, Component root)
        : context(owner),
          limits(caps),
          allowance(std::make_shared<WorkAllowance>()),
          pins{root},
          boundaryLookup(Component::LookupName(root)),
          boundaryEffective(Component::EffectiveName(root)),
          lookup(boundaryLookup),
          effective(boundaryEffective),
          baseline(root.Metadata().TargetMount().Value())
    {
    }
    // A temporary context would dangle past construction: State retains the
    // context reference for its own lifetime (see `context` below). State is
    // only ever constructed from the `context` Path::Make already received
    // (whose own deleted `const ContextInterface&&` overload rejects a
    // temporary at that boundary), so this is defense in depth, not a
    // currently reachable call.
    State(const ContextInterface&&, ResolverLimits, Component) = delete;
    std::reference_wrapper<const ContextInterface> context;
    ResolverLimits limits;
    std::shared_ptr<WorkAllowance> allowance;
    std::vector<Component> pins;
    std::size_t boundary = 0;
    std::string boundaryLookup;
    std::string boundaryEffective;
    std::string lookup;
    std::string effective;
    std::uint64_t baseline;
};
struct Path::Step::Data
{
    Data(std::size_t depth, Component anchor, Component barrier, std::size_t boundaryIndex, std::string bindingLookup, std::string bindingEffective, std::uint64_t mount)
        : sourceDepth(depth),
          attach(std::move(anchor)),
          boundaryPin(std::move(barrier)),
          boundary(boundaryIndex),
          boundaryLookup(std::move(bindingLookup)),
          boundaryEffective(std::move(bindingEffective)),
          baseline(mount)
    {
    }
    std::size_t sourceDepth;
    Component attach;
    std::vector<Component> popped;
    std::vector<Component> pushed;
    Component boundaryPin;
    std::size_t boundary;
    std::string boundaryLookup;
    std::string boundaryEffective;
    std::uint64_t baseline;
    std::string sourceLookup;
    std::string sourceEffective;
    std::string targetLookup;
    std::string targetEffective;
    // The requested source link can differ from a reused target pin.
    std::uint64_t lookupMount = 0;
    bool hasLookupMount = false;
};
void Path::Step::RequireLive() const
{
    if (!mData)
        throw std::logic_error("Path::Step: use after move");
}
::ComplianceEngine::Filesystem::Metadata Path::Step::Metadata() const
{
    RequireLive();
    auto acquired = Target().Metadata();
    if (!mData->hasLookupMount)
        return acquired;
    return ::ComplianceEngine::Filesystem::Metadata(acquired.mType, acquired.mStat, LookupMountId(mData->lookupMount), acquired.mTargetMount,
        acquired.mLookupName, acquired.mEffectiveName);
}
Path::Component Path::Step::Target() const
{
    RequireLive();
    return mData->pushed.empty() ? mData->attach : mData->pushed.back();
}
std::size_t Path::Step::RetainedDescriptors() const
{
    RequireLive();
    return 2 + mData->popped.size() + mData->pushed.size();
}
void Path::RequireLive() const
{
    if (!mState)
        throw std::logic_error("Path: use after move");
}
Path::Component Path::Root() const
{
    RequireLive();
    return mState->pins.front();
}
Path::Component Path::Leaf() const
{
    RequireLive();
    return mState->pins.back();
}
std::string Path::LookupName() const
{
    RequireLive();
    return mState->lookup;
}
std::string Path::ToString() const
{
    RequireLive();
    return mState->effective;
}
std::size_t Path::Size() const
{
    RequireLive();
    return mState->pins.size();
}
std::size_t Path::RetainedDescriptors() const
{
    RequireLive();
    return mState->pins.size();
}
ResolverLimits Path::Limits() const
{
    RequireLive();
    return mState->limits;
}
const ContextInterface& Path::Context() const
{
    RequireLive();
    return mState->context.get();
}
// Checked pinned-link readers and the root-component factory dispatch
// through ContextInterface's friend-gated native surface or Component's
// private constructor, so they stay direct private members of Path (the
// narrowest friend that already has both), not anonymous-namespace functions.
Path::Component Path::MakeRootComponent(Pin root)
{
    return Component(std::move(root));
}

// A live O_PATH pin cannot change mount (see Pin::OpenAndVerifyAlias
// above), and the resolver observes this pin's mount once at acquisition,
// before deciding to follow it as a link (Resolver::Run, the mount read
// immediately after the child pin's stat). So this reader does not re-read
// or compare the pin's fdinfo mount id around the readlink; it only
// re-checks identity (stat), which a link's target text/content must still
// satisfy independent of mount. It therefore needs no procfs session and no
// fdinfo byte cap.
Result<LinkTarget> Path::ReadVerifiedLinkText(const Descriptor& linkPin, const struct stat& before, std::size_t targetByteCap)
{
    const ContextInterface& context = linkPin.Context();
    // A single read into a buffer sized to the platform's maximum possible
    // link length: symlink(2) targets are at most PATH_MAX bytes, so a full
    // buffer means the read was truncated, not that more text remains.
    const std::size_t bufferBytes = (targetByteCap < static_cast<std::size_t>(PATH_MAX) ? targetByteCap : static_cast<std::size_t>(PATH_MAX)) + 1;
    std::vector<char> buffer(bufferBytes);
    const ssize_t count = context.ReadLink(linkPin, buffer.data(), buffer.size());
    if (count < 0)
        return Error("Cannot read pinned link", SavedError());
    if (count == 0 || static_cast<std::size_t>(count) > targetByteCap)
        return Error("Pinned link exceeds byte cap or is empty", E2BIG);
    if (static_cast<std::size_t>(count) == buffer.size())
        return Error("Pinned link target exceeds platform path length", ENAMETOOLONG);
    struct stat after = {};
    if (context.StatFile(linkPin, &after) != 0)
        return Error("Cannot recheck pinned link", SavedError());
    if (!Detail::SameIdentity(before, after))
        return Error("Pinned link identity changed", EAGAIN);
    LinkTarget target;
    target.text.assign(buffer.data(), static_cast<std::size_t>(count));
    if (target.text.find(char(0)) != std::string::npos)
        return Error("Pinned link contains NUL", EINVAL);
    return target;
}
Result<LinkTarget> Path::ReadPinnedLink(const Descriptor& linkPin, std::size_t targetByteCap)
{
    const ContextInterface& context = linkPin.Context();
    if (targetByteCap == 0 || targetByteCap >= std::vector<char>().max_size() - 1 ||
        targetByteCap >= static_cast<std::size_t>(std::numeric_limits<ssize_t>::max()))
        return Error("Invalid pinned link cap", EINVAL);
    const int flags = context.StatusFlags(linkPin);
    if (flags < 0)
        return Error("Cannot inspect pinned link flags", SavedError());
    const int descriptorFlags = context.DescriptorFlags(linkPin);
    if (descriptorFlags < 0)
        return Error("Cannot inspect pinned link flags", SavedError());
    if ((flags & O_PATH) == 0 || (descriptorFlags & FD_CLOEXEC) == 0)
        return Error("Pinned link must be close-on-exec O_PATH", EINVAL);
    struct stat before = {};
    struct statfs filesystem = {};
    if (context.StatFile(linkPin, &before) != 0 || context.StatFilesystem(linkPin, &filesystem) != 0)
        return Error("Cannot inspect pinned link", SavedError());
    if (!S_ISLNK(before.st_mode) || PROC_SUPER_MAGIC == filesystem.f_type)
        return Error("Not an ordinary filesystem symlink", ELOOP);
    return ReadVerifiedLinkText(linkPin, before, targetByteCap);
}

namespace
{
// A rejected (not failed) resolution outcome.
Result<Variant<Path::Step, Path::RejectionReason>> Rejected(Path::RejectionReason reason)
{
    return Variant<Path::Step, Path::RejectionReason>(InPlaceType<Path::RejectionReason>{}, reason);
}
} // namespace

class Path::Resolver
{
public:
    Resolver(const Path& path, Policy policy, InputRole role, std::size_t& followed)
        : mState(path.mState),
          mPolicy(policy),
          mRole(role),
          mFollowed(followed)
    {
    }

    Result<Variant<Step, RejectionReason>> Run(const std::string& name)
    {
        auto source = mState;
        if (source->pins.back().Metadata().FileType() != Type::Directory)
            return Error("Cannot resolve beneath a file", ENOTDIR);
        if (source->pins.size() > source->limits.shared.liveDescriptors - kProcfsTemporaryPeak)
            return Error("Path budget exhausted before resolution", E2BIG);
        // The logical lookup never grows past targetBytes, independent of
        // physical depth, so a lookup rejected here has not consumed any
        // snapshot work.
        if (BoundedSum({source->lookup.size(), std::size_t{1}, name.size()}) > source->limits.shared.targetBytes)
            return Error("Logical lookup exceeds target byte limit", ENAMETOOLONG);
        const std::size_t snapshotCost = source->pins.size();
        if (!Fits(source->allowance->spent, snapshotCost, source->limits.shared.work))
            return Error("Resolver snapshot work budget exhausted", E2BIG);
        source->allowance->spent += snapshotCost;
        mStack = source->pins;
        mSourceLookup = Join(source->lookup, name);
        std::deque<Pending> pending;
        pending.push_back(Pending{name, false});
        ++mQueuedComponents;
        std::size_t frameDepth = 1;
        bool direct = true;
        bool finalDirectory = mRole == InputRole::Prefix;
        bool directLink = false;
        while (!pending.empty())
        {
            Pending item = std::move(pending.front());
            pending.pop_front();
            if (item.endFrame)
            {
                --frameDepth;
                continue;
            }
            --mQueuedComponents;
            if (!Charge())
                return Error("Resolver work budget exhausted", E2BIG);
            if (item.name.empty() || item.name == ".")
                continue;
            if (item.name == "..")
            {
                if (mStack.size() <= source->boundary + 1)
                    return Error("Parent crosses traversal barrier", EXDEV);
                mStack.pop_back();
                continue;
            }
            if (!Detail::IsSingleChildComponent(item.name))
                return Error("Invalid resolved component", EINVAL);
            const bool intermediate = HasComponent(pending) || finalDirectory;
            if (mStack.back().Metadata().FileType() != Type::Directory)
                return Error("Intermediate component is not a directory", ENOTDIR);
            const std::string parent = Effective();
            const std::string lookup = Join(parent, item.name);
            auto held = FindHeld(lookup);
            if (!held.HasValue())
                return std::move(held).Error();
            if (held.Value().HasValue())
            {
                const HeldMatch match = held.Value().Value();
                if (match.alias)
                {
                    if (direct)
                    {
                        directLink = true;
                        mDirectLookup = lookup;
                        mDirectMount = match.pin.Metadata().LookupMount().Value();
                    }
                    if (!Following(intermediate))
                    {
                        if (direct && !HasComponent(pending) && mRole == InputRole::Leaf && mPolicy.rejectedLinks == RejectedLinkDisposition::Skip)
                            return Rejected(RejectionReason::Excluded);
                        return Error("Held symlink following is disabled", ELOOP);
                    }
                    if (mFollowed >= source->limits.linkExpansions)
                        return Error("Link expansion budget exhausted", ELOOP);
                    ++mFollowed;
                }
                const auto facts = match.pin.Metadata();
                if (mPolicy.mounts == MountPolicy::StayOnRootMount &&
                    (facts.LookupMount().Value() != source->baseline || facts.TargetMount().Value() != source->baseline))
                    return Error("Held component crosses root mount", EXDEV);
                if (match.index < source->boundary)
                    return Error("Held component crosses traversal barrier", EXDEV);
                // The selected held pin carries its original physical lineage.
                const std::size_t lineageWork = match.fromStack ? mStack.size() - match.index - 1 : match.index + 1;
                if (!Fits(source->allowance->spent, lineageWork, source->limits.shared.work))
                    return Error("Held lineage work budget exhausted", E2BIG);
                source->allowance->spent += lineageWork;
                if (match.fromStack)
                    mStack.erase(mStack.begin() + match.index + 1, mStack.end());
                else
                {
                    mStack.assign(source->pins.begin(), source->pins.begin() + match.index + 1);
                }
                direct = false;
                continue;
            }
            if (source->pins.size() > source->limits.shared.liveDescriptors - kNewChildPeak ||
                mNewPins > source->limits.shared.liveDescriptors - kNewChildPeak - source->pins.size())
                return Error("Resolver descriptor budget exhausted", EMFILE);
            auto opened = source->context.get().OpenAt(mStack.back().mAcquisition->mDescriptor, item.name.c_str(),
                intermediate ? ContextInterface::OpenProfile::PinChildDirectory : ContextInterface::OpenProfile::PinChild);
            if (!opened.HasValue() && opened.Error().code == ENOTDIR && intermediate)
                opened = source->context.get().OpenAt(mStack.back().mAcquisition->mDescriptor, item.name.c_str(), ContextInterface::OpenProfile::PinChild);
            if (!opened.HasValue())
            {
                // Make resolves each input component separately, including Prefix roles.
                // Only this direct child lookup can report absence; expanded link targets
                // and trusted helper failures retain their error provenance.
                if (direct && !HasComponent(pending) && opened.Error().code == ENOENT && mPolicy.missingFiles == MissingFileDisposition::Report)
                    return Rejected(RejectionReason::Missing);
                return Error("Cannot pin confined component", opened.Error().code);
            }
            // Stat and mount are observed together, through the shared
            // acquisition helper; its procfs session retires before it
            // returns, so only the new child pin remains owned afterward.
            auto acquired = Pin::AcquirePinnedObject(source->context.get(), std::move(opened).Value(), source->limits.shared.fdinfoBytes,
                "Cannot inspect confined component");
            if (!acquired.HasValue())
                return std::move(acquired).Error();
            Pin::AcquiredPin object = std::move(acquired).Value();
            Descriptor pin = std::move(object.pin);
            const struct stat snapshot = object.snapshot;
            const std::uint64_t mount = object.mount;
            if (mPolicy.mounts == MountPolicy::StayOnRootMount && mount != source->baseline)
                return Error("Component crosses root mount", EXDEV);
            if (S_ISLNK(snapshot.st_mode))
            {
                if (direct)
                {
                    directLink = true;
                    mDirectLookup = lookup;
                    mDirectMount = mount;
                }
                if (!Following(intermediate))
                {
                    if (direct && !HasComponent(pending) && mRole == InputRole::Leaf && mPolicy.rejectedLinks == RejectedLinkDisposition::Skip)
                        return Rejected(RejectionReason::Excluded);
                    return Error("Symlink following is disabled", ELOOP);
                }
                if (mFollowed >= source->limits.linkExpansions)
                    return Error("Link expansion budget exhausted", ELOOP);
                ++mFollowed;
                // The pin's mount is observed just above (and compared
                // against StayOnRootMount's baseline); a live O_PATH pin
                // cannot change mount, so ReadPinnedLink does not re-read or
                // re-compare it around the readlink.
                auto target = Path::ReadPinnedLink(pin, source->limits.linkTargetBytes);
                if (!target.HasValue())
                    return std::move(target).Error();
                std::string text = std::move(target).Value().text;
                if (text.size() > source->limits.shared.targetBytes)
                    return Error("Link target exceeds target byte limit", E2BIG);
                if (text.back() == 47 && !HasComponent(pending))
                    finalDirectory = true;
                if (text.front() == 47)
                {
                    const std::string absolute = CollapseSeparators(text);
                    bool matched = false;
                    std::string suffix;
                    for (const std::string& binding : {source->boundaryLookup, source->boundaryEffective})
                    {
                        if (!AtBoundary(absolute, binding))
                            continue;
                        const std::string candidate = absolute.substr(binding == "/" ? 1 : binding.size());
                        if (matched && suffix != candidate)
                            return Error("Ambiguous acquired boundary binding", EXDEV);
                        suffix = candidate;
                        matched = true;
                    }
                    if (!matched)
                        return Error("Absolute link outside traversal barrier", EXDEV);
                    text = std::move(suffix);
                    mStack.erase(mStack.begin() + source->boundary + 1, mStack.end());
                }
                if (frameDepth >= 64)
                    return Error("Symlink frame ceiling exhausted", ELOOP);
                // Count and validate components before allocating the
                // expansion queue: the queued-component cap below is
                // checked before the deque is built.
                std::size_t componentCount = 0;
                for (std::size_t scan = 0; scan < text.size();)
                {
                    const std::size_t slash = text.find(47, scan);
                    const std::size_t end = slash == std::string::npos ? text.size() : slash;
                    if (end != scan)
                    {
                        if (end - scan > NAME_MAX)
                            return Error("Link target component exceeds NAME_MAX", ENAMETOOLONG);
                        ++componentCount;
                    }
                    scan = end + 1;
                }
                std::size_t remainingComponents = 0;
                if (Fits(mSteps, mQueuedComponents, source->limits.shared.components))
                    remainingComponents = source->limits.shared.components - mSteps - mQueuedComponents;
                if (componentCount > remainingComponents)
                    return Error("Symlink expansion exceeds resolver component budget", E2BIG);
                std::deque<Pending> expansion;
                std::size_t start = 0;
                while (start < text.size())
                {
                    const std::size_t slash = text.find(47, start);
                    const std::size_t end = slash == std::string::npos ? text.size() : slash;
                    if (end != start)
                    {
                        expansion.push_back(Pending{text.substr(start, end - start), false});
                        ++mQueuedComponents;
                    }
                    start = end + 1;
                }
                expansion.push_back(Pending{std::string(), true});
                while (!pending.empty())
                {
                    expansion.push_back(std::move(pending.front()));
                    pending.pop_front();
                }
                pending.swap(expansion);
                ++frameDepth;
                direct = false;
                continue;
            }
            if (!S_ISDIR(snapshot.st_mode) && !S_ISREG(snapshot.st_mode))
            {
                if (!HasComponent(pending) && mRole == InputRole::Leaf && mPolicy.unsupportedTypes == UnsupportedTypeDisposition::Skip)
                    return Rejected(RejectionReason::UnsupportedType);
                return Error("Unsupported confined object", EOPNOTSUPP);
            }
            if (intermediate && !S_ISDIR(snapshot.st_mode))
                return Error("Intermediate component is not a directory", ENOTDIR);
            // Prefixes of a followed link retain their own acquisition names;
            // only its terminal pin carries the requested link provenance.
            const bool linkTerminal = !mDirectLookup.empty() && !HasComponent(pending);
            ::ComplianceEngine::Filesystem::Metadata metadata(S_ISDIR(snapshot.st_mode) ? Type::Directory : Type::RegularFile, snapshot,
                LookupMountId(linkTerminal ? mDirectMount : mount), TargetMountId(mount), Detail::LookupSpelling(linkTerminal ? mDirectLookup : lookup),
                Detail::EffectiveSpelling(lookup));
            Pin acquisition(std::move(pin), std::move(metadata));
            Component pushed(std::move(acquisition));
            mStack.push_back(std::move(pushed));
            ++mNewPins;
            if (mStack.size() - 1 > source->limits.depth)
                return Error("Physical resolution depth exhausted", E2BIG);
            direct = false;
        }
        if (finalDirectory && mStack.back().Metadata().FileType() != Type::Directory)
            return Error("Trailing slash requires directory", ENOTDIR);
        if (directLink && mRole == InputRole::Leaf && !FollowingFinal(mStack.back().Metadata().FileType()))
        {
            if (mPolicy.rejectedLinks == RejectedLinkDisposition::Skip)
                return Rejected(RejectionReason::Excluded);
            return Error("Terminal symlink policy rejects target", ELOOP);
        }
        return Prepare();
    }

private:
    struct Pending
    {
        std::string name;
        bool endFrame;
    };
    struct HeldMatch
    {
        HeldMatch(Component owner, std::size_t position, bool isAlias, bool stackOwner)
            : pin(std::move(owner)),
              index(position),
              alias(isAlias),
              fromStack(stackOwner)
        {
        }
        Component pin;
        std::size_t index;
        bool alias;
        bool fromStack;
    };
    static bool HasComponent(const std::deque<Pending>& pending)
    {
        for (const Pending& item : pending)
            if (!item.endFrame)
                return true;
        return false;
    }
    bool Charge()
    {
        const ResolverLimits limits = mState->limits;
        const std::size_t chunks = limits.shared.fdinfoBytes / 256 + ((limits.shared.fdinfoBytes % 256) != 0);
        if (chunks > (std::numeric_limits<std::size_t>::max() - 128) / 4 || mSteps >= limits.shared.components)
            return false;
        const std::size_t cost = 128 + 4 * chunks;
        auto allowance = mState->allowance;
        if (!Fits(allowance->spent, cost, limits.shared.work))
            return false;
        ++mSteps;
        allowance->spent += cost;
        return true;
    }
    bool Following(bool intermediate) const
    {
        if (intermediate)
            return mPolicy.prefixLinks == PrefixLinkPolicy::Follow;
        return (mPolicy.fileLinks == FileLinkPolicy::Follow || mPolicy.directoryLinks == DirectoryLinkPolicy::Follow);
    }
    bool FollowingFinal(Type type) const
    {
        return type == Type::Directory ? mPolicy.directoryLinks == DirectoryLinkPolicy::Follow : mPolicy.fileLinks == FileLinkPolicy::Follow;
    }
    std::string Effective() const
    {
        if (Component::SameAcquisition(mStack.back(), mState->pins.back()))
            return mState->effective;
        if (Component::SameAcquisition(mStack.back(), mState->pins[mState->boundary]))
            return mState->boundaryEffective;
        return Component::EffectiveName(mStack.back());
    }
    Result<Optional<HeldMatch>> FindHeld(const std::string& lookup)
    {
        Optional<HeldMatch> match;
        for (std::size_t scope = 0; scope < 2; ++scope)
        {
            const std::size_t count = scope == 0 ? mState->pins.size() : mStack.size();
            for (std::size_t index = mState->boundary; index < count; ++index)
            {
                // Copy only the owner being inspected; never retain an alias to
                // either published or mutable stack across subsequent work.
                Component pin = scope == 0 ? mState->pins[index] : mStack[index];
                if (pin.Metadata().FileType() != Type::Directory)
                    continue;
                const std::size_t names = BoundedSum({Component::LookupNameBytes(pin), Component::EffectiveNameBytes(pin)});
                const std::size_t cost = BoundedSum({std::size_t{1}, lookup.size(), names});
                if (!Fits(mState->allowance->spent, cost, mState->limits.shared.work))
                    return Error("Held search work budget exhausted", E2BIG);
                mState->allowance->spent += cost;
                const std::string acquiredLookup = Component::LookupName(pin);
                const std::string acquiredEffective = Component::EffectiveName(pin);
                if (acquiredLookup != lookup && acquiredEffective != lookup)
                    continue;
                if (match.HasValue() && !Component::SameAcquisition(match.Value().pin, pin))
                    return Error("Ambiguous held directory binding", EXDEV);
                if (!match.HasValue())
                    match = HeldMatch(pin, index, acquiredLookup == lookup && acquiredEffective != lookup, scope != 0);
            }
        }
        return match;
    }
    Result<Variant<Step, RejectionReason>> Prepare()
    {
        auto source = mState;
        std::size_t common = 0;
        while (common < source->pins.size() && common < mStack.size() && Component::SameAcquisition(source->pins[common], mStack[common]))
            ++common;
        if (common <= source->boundary || common == 0)
            return Error("Resolution displaced traversal barrier", EXDEV);
        const std::size_t finalSize = mStack.size();
        if (finalSize - 1 > source->limits.depth || finalSize > source->limits.shared.liveDescriptors - kProcfsTemporaryPeak)
            return Error("Resolved stack exceeds physical budget", E2BIG);
        const std::string targetEffective = Effective();
        auto data = std::make_shared<Step::Data>(source->pins.size(), source->pins[common - 1], source->pins[source->boundary], source->boundary,
            source->boundaryLookup, source->boundaryEffective, source->baseline);
        data->popped.assign(source->pins.begin() + common, source->pins.end());
        data->pushed.assign(mStack.begin() + common, mStack.end());
        data->sourceLookup = source->lookup;
        data->sourceEffective = source->effective;
        data->targetLookup = mSourceLookup;
        data->targetEffective = targetEffective;
        data->hasLookupMount = !mDirectLookup.empty();
        data->lookupMount = mDirectMount;
        return Variant<Step, RejectionReason>(InPlaceType<Step>{}, Step(std::move(data)));
    }
    std::shared_ptr<const State> mState;
    Policy mPolicy;
    InputRole mRole;
    std::size_t& mFollowed;
    std::vector<Component> mStack;
    std::string mSourceLookup;
    std::string mDirectLookup;
    std::uint64_t mDirectMount = 0;
    std::size_t mSteps = 0;
    std::size_t mNewPins = 0;
    std::size_t mQueuedComponents = 0;
};

Result<Variant<Path::Step, Path::RejectionReason>> Path::ResolveInput(const Path& path, std::string name, Policy policy, InputRole role, std::size_t& followed)
{
    // Both callers (Resolve, already checked; Make's factory loop, never
    // moved) already guarantee a live `path`, so this reads mState directly
    // rather than through the checked Limits() accessor, which throws
    // std::logic_error for a moved-from Path.
    auto validation = Validate(policy, path.mState->limits);
    if (validation.HasValue())
        return std::move(validation).Value();
    if (!Detail::IsSingleChildComponent(name) && role == InputRole::Leaf)
        return Error("Resolve requires a single child name", EINVAL);
    if (name.empty() || name.find(47) != std::string::npos || name.find(char(0)) != std::string::npos)
        return Error("Invalid path component", EINVAL);
    if (name.size() > NAME_MAX)
        return Error("Path component exceeds NAME_MAX", ENAMETOOLONG);
    Resolver resolver(path, policy, role, followed);
    return resolver.Run(name);
}
Result<Variant<Path::Step, Path::RejectionReason>> Path::Resolve(std::string name, Policy policy) const
{
    RequireLive();
    std::size_t followed = 0;
    return ResolveInput(*this, std::move(name), policy, InputRole::Leaf, followed);
}
Result<Path::Step> Path::Apply(Step&& step) &
{
    RequireLive();
    step.RequireLive();
    // Apply consumes its Step argument on every return path: take the
    // Step's payload here, before any other validation, so the caller's
    // Step is moved-from on every return path below -- success or
    // rejection alike.
    auto delta = std::move(step.mData);
    auto source = mState;
    if (source->pins.size() != delta->sourceDepth || delta->popped.size() >= delta->sourceDepth)
        return Error("Stale Path step depth", ESTALE);
    const std::size_t attachIndex = delta->sourceDepth - delta->popped.size() - 1;
    if (source->boundary >= source->pins.size())
        return Error("Step is detached from its acquisition context", ESTALE);
    // Check the physical suffix and source route before classifying a pop
    // across a newly frozen barrier. An unrelated same-depth path is stale.
    if (!Component::SameAcquisition(source->pins[attachIndex], delta->attach) || source->lookup != delta->sourceLookup || source->effective != delta->sourceEffective)
        return Error("Step is detached from its acquisition context", ESTALE);
    for (std::size_t index = 0; index < delta->popped.size(); ++index)
        if (!Component::SameAcquisition(source->pins[attachIndex + index + 1], delta->popped[index]))
            return Error("Step physical suffix changed", ESTALE);
    if (attachIndex < source->boundary)
        return Error("Step crosses traversal barrier", EXDEV);
    if (source->boundary != delta->boundary || !Component::SameAcquisition(source->pins[source->boundary], delta->boundaryPin) ||
        source->boundaryLookup != delta->boundaryLookup || source->boundaryEffective != delta->boundaryEffective || source->baseline != delta->baseline)
        return Error("Step is detached from its acquisition context", ESTALE);
    if (delta->pushed.size() > std::numeric_limits<std::size_t>::max() - attachIndex - 1)
        return Error("Step physical depth overflows", E2BIG);
    const std::size_t finalSize = attachIndex + 1 + delta->pushed.size();
    if (finalSize - 1 > source->limits.depth || finalSize > source->limits.shared.liveDescriptors - kProcfsTemporaryPeak)
        return Error("Step exceeds physical stack budget", E2BIG);
    if (finalSize > std::numeric_limits<std::size_t>::max() - source->pins.size())
        return Error("Snapshot work overflows", E2BIG);
    const std::size_t work = source->pins.size() + finalSize;
    if (!Fits(source->allowance->spent, work, source->limits.shared.work))
        return Error("Apply snapshot work budget exhausted", E2BIG);
    // Failed preparation is work too; consume before fallible allocations.
    source->allowance->spent += work;
    // All allocations, inverse construction, and bounded name copies precede
    // publication. No descriptor is duplicated, reopened or reclassified.
    auto inverse = std::make_shared<Step::Data>(finalSize, delta->attach, source->pins[source->boundary], source->boundary, source->boundaryLookup,
        source->boundaryEffective, source->baseline);
    inverse->popped = delta->pushed;
    inverse->pushed = delta->popped;
    inverse->sourceLookup = delta->targetLookup;
    inverse->sourceEffective = delta->targetEffective;
    inverse->targetLookup = delta->sourceLookup;
    inverse->targetEffective = delta->sourceEffective;
    // Build the exact final allocation; vector::erase would retain capacity
    // for popped pins and under-report a long-lived Path footprint.
    std::vector<Component> replacement;
    replacement.reserve(finalSize);
    for (std::size_t index = 0; index <= attachIndex; ++index)
        replacement.push_back(source->pins[index]);
    for (Component pin : delta->pushed)
        replacement.push_back(pin);
    auto candidate = std::make_shared<State>(*source);
    candidate->pins.swap(replacement);
    candidate->lookup = delta->targetLookup;
    candidate->effective = delta->targetEffective;
    std::shared_ptr<const State> published(std::move(candidate));
    std::shared_ptr<const Step::Data> undo(std::move(inverse));
    mState.swap(published);
    return Step(std::move(undo));
}
Result<bool> Path::Freeze() &
{
    RequireLive();
    auto source = mState;
    if (source->boundary == source->pins.size() - 1)
        return false;
    if (!Fits(source->allowance->spent, source->pins.size(), source->limits.shared.work))
        return Error("Freeze snapshot work budget exhausted", E2BIG);
    source->allowance->spent += source->pins.size();
    auto candidate = std::make_shared<State>(*source);
    candidate->boundary = source->pins.size() - 1;
    candidate->boundaryLookup = source->lookup;
    candidate->boundaryEffective = source->effective;
    candidate->baseline = source->pins.back().Metadata().TargetMount().Value();
    if (candidate->pins.size() > source->limits.shared.liveDescriptors - kProcfsTemporaryPeak)
        return Error("Freeze preparation exceeds retained resource budget", E2BIG);
    std::shared_ptr<const State> published(std::move(candidate));
    mState.swap(published);
    return true;
}
Result<Variant<Path, Path::RejectionReason>> Path::Make(const ContextInterface& context, std::string absolutePath, Policy policy, ResolverLimits limits)
{
    auto validation = Validate(policy, limits);
    if (validation.HasValue())
        return std::move(validation).Value();
    if (absolutePath.empty() || absolutePath.front() != 47 || absolutePath.find(char(0)) != std::string::npos)
        return Error("Make requires a bounded absolute path", EINVAL);
    if (absolutePath.size() > limits.shared.targetBytes)
        return Error("Make input exceeds target byte limit", ENAMETOOLONG);
    for (std::size_t prescan = absolutePath.find_first_not_of("/", 1); prescan != std::string::npos;)
    {
        const std::size_t slash = absolutePath.find(47, prescan);
        const std::size_t end = slash == std::string::npos ? absolutePath.size() : slash;
        if (end - prescan > NAME_MAX)
            return Error("Path component exceeds NAME_MAX", ENAMETOOLONG);
        prescan = absolutePath.find_first_not_of("/", end);
    }
    const std::size_t chunks = limits.shared.fdinfoBytes / 256 + ((limits.shared.fdinfoBytes % 256) != 0);
    if (chunks > (std::numeric_limits<std::size_t>::max() - 128) / 4 || !Fits(0, 128 + 4 * chunks, limits.shared.work))
        return Error("Path work budget exhausted", E2BIG);
    const std::size_t rootWork = 128 + 4 * chunks;
    auto root = Pin::PinProcessRoot(context, limits.shared);
    if (!root.HasValue())
        return std::move(root).Error();
    Component rootComponent = MakeRootComponent(std::move(root).Value());
    auto state = std::make_shared<State>(context, limits, std::move(rootComponent));
    Path result(std::move(state));
    result.mState->allowance->spent = rootWork;
    // Factory input absence is a typed selection regardless of the caller's
    // traversal disposition; public Resolve still uses the supplied policy.
    Policy factoryPolicy = policy;
    factoryPolicy.missingFiles = MissingFileDisposition::Report;
    std::size_t followed = 0;
    std::size_t start = absolutePath.find_first_not_of("/", 1);
    while (start != std::string::npos)
    {
        const std::size_t slash = absolutePath.find(47, start);
        const std::size_t end = slash == std::string::npos ? absolutePath.size() : slash;
        const std::size_t next = absolutePath.find_first_not_of("/", end);
        const bool prefix = next != std::string::npos || absolutePath.back() == 47;
        auto resolved = ResolveInput(result, absolutePath.substr(start, end - start), factoryPolicy, prefix ? InputRole::Prefix : InputRole::Leaf, followed);
        if (!resolved.HasValue())
            return std::move(resolved).Error();
        if (resolved.Value().Is<RejectionReason>())
            return Variant<Path, RejectionReason>(InPlaceType<RejectionReason>{}, resolved.Value().Get<RejectionReason>());
        auto applied = result.Apply(std::move(resolved.Value().Get<Step>()));
        if (!applied.HasValue())
            return std::move(applied).Error();
        start = next;
    }
    return Variant<Path, RejectionReason>(InPlaceType<Path>{}, std::move(result));
}

} // namespace Filesystem
} // namespace ComplianceEngine
