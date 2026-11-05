// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include "Path.hpp"

#include "ContextInterface.h"
#include "FilesystemHelpers.hpp"
#include "ProcfsDescriptorAccess.hpp"

#include <algorithm>
#include <cerrno>
#include <deque>
#include <fcntl.h>
#include <limits>
#include <linux/magic.h>
#include <sys/statfs.h>
#include <unistd.h>
#include <utility>
#include <vector>
namespace ComplianceEngine
{
namespace Filesystem
{
using Detail::Descriptor;
using Detail::Handle;
using Detail::LinkTarget;
using Detail::ProcfsDescriptorAccess;
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
std::size_t BoundedTwice(std::size_t value) noexcept
{
    const std::size_t limit = std::numeric_limits<std::size_t>::max();
    return value > limit / 2 ? limit : value * 2;
}
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
    if (limits.shared.work == 0 || limits.shared.components == 0 || limits.shared.liveDescriptors < kMinimumPathPeak || limits.shared.retainedBytes == 0 ||
        limits.shared.fdinfoBytes == 0 || limits.shared.targetBytes == 0 || limits.linkTargetBytes == 0 || limits.linkExpansions == 0 || limits.depth == 0 ||
        limits.linkTargetBytes >= std::vector<char>().max_size() - 1 || limits.linkTargetBytes >= static_cast<std::size_t>(std::numeric_limits<ssize_t>::max()) ||
        limits.shared.fdinfoBytes >= static_cast<std::size_t>(std::numeric_limits<ssize_t>::max()))
        return Error("Invalid path resolver limits", EINVAL);
    return {};
}
} // namespace
// The cumulative work allowance alone is shared and mutable across immutable stack snapshots.
struct Path::State
{
    State(const ContextInterface& owner, ResolverLimits caps, Component root)
        : context(&owner),
          limits(caps),
          allowance(std::make_shared<WorkAllowance>()),
          pins{root},
          boundaryLookup(root.LookupName()),
          boundaryEffective(root.EffectiveName()),
          lookup(boundaryLookup),
          effective(boundaryEffective),
          baseline(root.Acquired().targetMount.value),
          pinNames(root.LookupName().size() + root.EffectiveName().size())
    {
    }
    const ContextInterface* context;
    ResolverLimits limits;
    std::shared_ptr<WorkAllowance> allowance;
    std::vector<Component> pins;
    std::size_t boundary = 0;
    std::string boundaryLookup;
    std::string boundaryEffective;
    std::string lookup;
    std::string effective;
    std::uint64_t baseline;
    std::size_t pinNames;
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
    std::size_t bytes = 0;
};
namespace
{
std::size_t StateBytes(std::size_t pins, std::size_t lookup, std::size_t effective, std::size_t pinNames = 0) noexcept
{
    const std::size_t limit = std::numeric_limits<std::size_t>::max();
    if (pins > (limit - 512) / (sizeof(Path::Component) + 128))
        return limit;
    std::size_t bytes = 512 + pins * (sizeof(Path::Component) + 128);
    if (!Fits(bytes, lookup, limit) || !Fits(bytes + lookup, effective, limit) || !Fits(bytes + lookup + effective, pinNames, limit))
        return limit;
    return bytes + lookup + effective + pinNames;
}
} // namespace
AcquisitionFacts Path::Step::Acquired() const noexcept
{
    AcquisitionFacts facts = Target().Acquired();
    if (mData->hasLookupMount)
        facts.lookupMount.value = mData->lookupMount;
    return facts;
}
Path::Component Path::Step::Target() const noexcept
{
    return mData->pushed.empty() ? mData->attach : mData->pushed.back();
}
std::size_t Path::Step::RetainedDescriptors() const noexcept
{
    return 2 + mData->popped.size() + mData->pushed.size();
}
std::size_t Path::Step::RetainedBytes() const noexcept
{
    return mData->bytes;
}
Path::Component Path::Root() const noexcept
{
    return mState->pins.front();
}
Path::Component Path::Leaf() const noexcept
{
    return mState->pins.back();
}
std::string Path::LookupName() const
{
    return mState->lookup;
}
std::string Path::ToString() const
{
    return mState->effective;
}
std::size_t Path::Size() const noexcept
{
    return mState->pins.size();
}
std::size_t Path::RetainedDescriptors() const noexcept
{
    return mState->pins.size();
}
std::size_t Path::RetainedBytes() const noexcept
{
    return StateBytes(mState->pins.size(), BoundedSum({mState->lookup.size(), mState->boundaryLookup.size()}),
        BoundedSum({mState->effective.size(), mState->boundaryEffective.size()}), mState->pinNames);
}
ResolverLimits Path::Limits() const noexcept
{
    return mState->limits;
}
const ContextInterface& Path::Context() const noexcept
{
    return *mState->context;
}
Result<LinkTarget> Path::ReadVerifiedLinkText(const Descriptor& linkPin, const struct stat& before, const ProcfsDescriptorAccess& procfs,
    std::size_t targetByteCap, std::size_t fdinfoByteCap, std::size_t temporaryBudget)
{
    const ContextInterface& context = linkPin.Context();
    auto mount = procfs.ReadMountId(linkPin, fdinfoByteCap);
    if (!mount.HasValue())
        return std::move(mount).Error();
    // Buffer and the copied target coexist until this helper returns. Guard
    // the configured cap, not just the length of the eventual link text.
    if (targetByteCap >= temporaryBudget || !Fits(targetByteCap + 1, targetByteCap, temporaryBudget))
        return Error("Link target exceeds memory budget", E2BIG);
    std::vector<char> buffer(targetByteCap + 1);
    const ssize_t count = context.ReadLink(linkPin, buffer.data(), buffer.size());
    if (count < 0)
        return Error("Cannot read pinned link", SavedError());
    if (count == 0 || static_cast<std::size_t>(count) > targetByteCap)
        return Error("Pinned link exceeds byte cap or is empty", E2BIG);
    struct stat after = {};
    if (context.StatFile(linkPin, &after) != 0)
        return Error("Cannot recheck pinned link", SavedError());
    if (!Detail::SameIdentity(before, after))
        return Error("Pinned link identity changed", EAGAIN);
    auto retained = procfs.ReadMountId(linkPin, fdinfoByteCap);
    if (!retained.HasValue())
        return std::move(retained).Error();
    if (mount.Value() != retained.Value())
        return Error("Pinned link mount changed", EAGAIN);
    LinkTarget target;
    target.text.assign(buffer.data(), static_cast<std::size_t>(count));
    if (target.text.find(char(0)) != std::string::npos)
        return Error("Pinned link contains NUL", EINVAL);
    target.mountId = mount.Value();
    return target;
}
Result<LinkTarget> Path::ReadPinnedLink(const Descriptor& linkPin, std::size_t targetByteCap, std::size_t fdinfoByteCap, std::size_t temporaryBudget)
{
    const ContextInterface& context = linkPin.Context();
    if (targetByteCap == 0 || targetByteCap >= std::vector<char>().max_size() - 1 ||
        targetByteCap >= static_cast<std::size_t>(std::numeric_limits<ssize_t>::max()) || fdinfoByteCap == 0)
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
    auto procfs = ProcfsDescriptorAccess::Open(context);
    if (!procfs.HasValue())
        return std::move(procfs).Error();
    return ReadVerifiedLinkText(linkPin, before, procfs.Value(), targetByteCap, fdinfoByteCap, temporaryBudget);
}

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
        if (source->pins.back().Acquired().type != Type::Directory)
            return Error("Cannot resolve beneath a file", ENOTDIR);
        if (source->pins.size() > source->limits.shared.liveDescriptors - kProcfsTemporaryPeak ||
            StateBytes(source->pins.size(), BoundedSum({source->lookup.size(), source->boundaryLookup.size()}),
                BoundedSum({source->effective.size(), source->boundaryEffective.size()}), source->pinNames) >= source->limits.shared.retainedBytes)
            return Error("Path budget exhausted before resolution", E2BIG);
        const std::size_t snapshotCost = source->pins.size();
        if (!Fits(source->allowance->spent, snapshotCost, source->limits.shared.work))
            return Error("Resolver snapshot work budget exhausted", E2BIG);
        source->allowance->spent += snapshotCost;
        mTemporaryBytes = StateBytes(3 * source->pins.size(), BoundedSum({source->lookup.size(), name.size(), 1, source->boundaryLookup.size()}),
            BoundedSum({source->effective.size(), source->boundaryEffective.size()}), source->pinNames);
        if (mTemporaryBytes > source->limits.shared.retainedBytes)
            return Error("Resolver snapshot exceeds memory budget", E2BIG);
        mStack = source->pins;
        mSourceLookup = Join(source->lookup, name);
        std::deque<Pending> pending;
        pending.push_back(Pending{name, false});
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
            if (mStack.back().Acquired().type != Type::Directory)
                return Error("Intermediate component is not a directory", ENOTDIR);
            const std::string parent = Effective();
            const std::string lookup = Join(parent, item.name);
            auto held = FindHeld(lookup, parent.size());
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
                        mDirectMount = match.pin.Acquired().lookupMount.value;
                    }
                    if (!Following(intermediate))
                    {
                        if (direct && !HasComponent(pending) && mRole == InputRole::Leaf && mPolicy.rejectedLinks == RejectedLinkDisposition::Skip)
                            return Variant<Step, RejectionReason>(InPlaceType<RejectionReason>{}, RejectionReason::Excluded);
                        return Error("Held symlink following is disabled", ELOOP);
                    }
                    if (mFollowed >= source->limits.linkExpansions)
                        return Error("Link expansion budget exhausted", ELOOP);
                    ++mFollowed;
                }
                const AcquisitionFacts facts = match.pin.Acquired();
                if (mPolicy.mounts == MountPolicy::StayOnRootMount && (facts.lookupMount.value != source->baseline || facts.targetMount.value != source->baseline))
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
                    if (!Fits(mTemporaryBytes, StateBytes(match.index + 1, 0, 0), source->limits.shared.retainedBytes))
                        return Error("Held lineage exceeds memory budget", E2BIG);
                    mStack.assign(source->pins.begin(), source->pins.begin() + match.index + 1);
                }
                direct = false;
                continue;
            }
            if (source->pins.size() > source->limits.shared.liveDescriptors - kNewChildPeak ||
                mNewPins > source->limits.shared.liveDescriptors - kNewChildPeak - source->pins.size())
                return Error("Resolver descriptor budget exhausted", EMFILE);
            auto opened = source->context->OpenAt(mStack.back().mAcquisition->mDescriptor, item.name.c_str(),
                intermediate ? ContextInterface::OpenProfile::PinChildDirectory : ContextInterface::OpenProfile::PinChild);
            if (!opened.HasValue() && opened.Error().code == ENOTDIR && intermediate)
                opened = source->context->OpenAt(mStack.back().mAcquisition->mDescriptor, item.name.c_str(), ContextInterface::OpenProfile::PinChild);
            if (!opened.HasValue())
            {
                // Make resolves each input component separately, including Prefix roles.
                // Only this direct child lookup can report absence; expanded link targets
                // and trusted helper failures retain their error provenance.
                if (direct && !HasComponent(pending) && opened.Error().code == ENOENT && mPolicy.missingFiles == MissingFileDisposition::Report)
                    return Variant<Step, RejectionReason>(InPlaceType<RejectionReason>{}, RejectionReason::Missing);
                return Error("Cannot pin confined component", opened.Error().code);
            }
            Descriptor pin = std::move(opened).Value();
            struct stat snapshot = {};
            if (source->context->StatFile(pin, &snapshot) != 0)
                return Error("Cannot inspect confined component", SavedError());
            // Release both retained procfs roles before inspecting a possible link:
            // pinned readlink opens its own independently verified session.
            std::uint64_t mount = 0;
            {
                auto procfs = ProcfsDescriptorAccess::Open(*source->context);
                if (!procfs.HasValue())
                    return std::move(procfs).Error();
                auto observed = procfs.Value().ReadMountId(pin, source->limits.shared.fdinfoBytes);
                if (!observed.HasValue())
                    return std::move(observed).Error();
                mount = observed.Value();
            }
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
                        return Variant<Step, RejectionReason>(InPlaceType<RejectionReason>{}, RejectionReason::Excluded);
                    return Error("Symlink following is disabled", ELOOP);
                }
                if (mFollowed >= source->limits.linkExpansions)
                    return Error("Link expansion budget exhausted", ELOOP);
                ++mFollowed;
                const std::size_t activeNames = BoundedSum({parent.size(), lookup.size()});
                if (!Fits(mTemporaryBytes, activeNames, source->limits.shared.retainedBytes))
                    return Error("Link target exceeds memory budget", E2BIG);
                auto target = Path::ReadPinnedLink(pin, source->limits.linkTargetBytes, source->limits.shared.fdinfoBytes,
                    source->limits.shared.retainedBytes - mTemporaryBytes - activeNames);
                if (!target.HasValue())
                    return std::move(target).Error();
                if (mount != target.Value().mountId)
                    return Error("Pinned link changed mount", EAGAIN);
                std::string text = std::move(target).Value().text;
                if (text.size() > source->limits.shared.targetBytes || text.size() >= source->limits.shared.retainedBytes / sizeof(Pending) ||
                    !Fits(mTemporaryBytes, text.size() + sizeof(Pending) * (text.size() + 1), source->limits.shared.retainedBytes))
                    return Error("Link target exceeds memory budget", E2BIG);
                mTemporaryBytes += text.size() + sizeof(Pending) * (text.size() + 1);
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
                std::deque<Pending> expansion;
                std::size_t start = 0;
                while (start < text.size())
                {
                    const std::size_t slash = text.find(47, start);
                    const std::size_t end = slash == std::string::npos ? text.size() : slash;
                    if (end != start)
                        expansion.push_back(Pending{text.substr(start, end - start), false});
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
                    return Variant<Step, RejectionReason>(InPlaceType<RejectionReason>{}, RejectionReason::UnsupportedType);
                return Error("Unsupported confined object", EOPNOTSUPP);
            }
            if (intermediate && !S_ISDIR(snapshot.st_mode))
                return Error("Intermediate component is not a directory", ENOTDIR);
            if (!Fits(mTemporaryBytes, sizeof(Component) + 128 + lookup.size() * 2, source->limits.shared.retainedBytes))
                return Error("Resolver pin storage exceeds memory budget", E2BIG);
            mTemporaryBytes += sizeof(Component) + 128 + lookup.size() * 2;
            // Prefixes of a followed link retain their own acquisition names;
            // only its terminal pin carries the requested link provenance.
            const bool linkTerminal = !mDirectLookup.empty() && !HasComponent(pending);
            Handle handle(std::move(pin),
                AcquisitionFacts{S_ISDIR(snapshot.st_mode) ? Type::Directory : Type::RegularFile, snapshot,
                    LookupMountId(linkTerminal ? mDirectMount : mount), TargetMountId(mount)},
                Detail::LookupSpelling{linkTerminal ? mDirectLookup : lookup}, Detail::EffectiveSpelling{lookup}, source->limits.shared.fdinfoBytes);
            mStack.push_back(Component(std::move(handle)));
            ++mNewPins;
            if (mStack.size() - 1 > source->limits.depth)
                return Error("Physical resolution depth exhausted", E2BIG);
            direct = false;
        }
        if (finalDirectory && mStack.back().Acquired().type != Type::Directory)
            return Error("Trailing slash requires directory", ENOTDIR);
        if (directLink && mRole == InputRole::Leaf && !FollowingFinal(mStack.back().Acquired().type))
        {
            if (mPolicy.rejectedLinks == RejectedLinkDisposition::Skip)
                return Variant<Step, RejectionReason>(InPlaceType<RejectionReason>{}, RejectionReason::Excluded);
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
        if (mStack.back().SameAcquisition(mState->pins.back()))
            return mState->effective;
        if (mStack.back().SameAcquisition(mState->pins[mState->boundary]))
            return mState->boundaryEffective;
        return mStack.back().EffectiveName();
    }
    Result<Optional<HeldMatch>> FindHeld(const std::string& lookup, std::size_t activeParentBytes)
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
                if (pin.Acquired().type != Type::Directory)
                    continue;
                const std::size_t names = BoundedSum({pin.LookupNameBytes(), pin.EffectiveNameBytes()});
                const std::size_t cost = BoundedSum({std::size_t{1}, lookup.size(), names});
                if (!Fits(mState->allowance->spent, cost, mState->limits.shared.work))
                    return Error("Held search work budget exhausted", E2BIG);
                mState->allowance->spent += cost;
                if (!Fits(mTemporaryBytes, BoundedSum({activeParentBytes, lookup.size(), names}), mState->limits.shared.retainedBytes))
                    return Error("Held search names exceed memory budget", E2BIG);
                const std::string acquiredLookup = pin.LookupName();
                const std::string acquiredEffective = pin.EffectiveName();
                if (acquiredLookup != lookup && acquiredEffective != lookup)
                    continue;
                if (match.HasValue() && !match.Value().pin.SameAcquisition(pin))
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
        while (common < source->pins.size() && common < mStack.size() && source->pins[common].SameAcquisition(mStack[common]))
            ++common;
        if (common <= source->boundary || common == 0)
            return Error("Resolution displaced traversal barrier", EXDEV);
        const std::size_t finalSize = mStack.size();
        if (finalSize - 1 > source->limits.depth || finalSize > source->limits.shared.liveDescriptors - kProcfsTemporaryPeak)
            return Error("Resolved stack exceeds physical budget", E2BIG);
        const std::string targetEffective = Effective();
        std::size_t pinNames = 0;
        for (Component pin : mStack)
        {
            const std::size_t names = pin.LookupName().size() + pin.EffectiveName().size();
            if (!Fits(pinNames, names, source->limits.shared.retainedBytes))
                return Error("Acquired names exceed retained-memory budget", E2BIG);
            pinNames += names;
        }
        const std::size_t byteLimit = source->limits.shared.retainedBytes;
        const std::size_t newStateBytes = StateBytes(finalSize, BoundedSum({mSourceLookup.size(), source->boundaryLookup.size()}),
            BoundedSum({targetEffective.size(), source->boundaryEffective.size()}), pinNames);
        if (newStateBytes > byteLimit)
            return Error("Resolved stack exceeds memory budget", E2BIG);
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
        const std::size_t owners = 2 + data->popped.size() + data->pushed.size();
        if (owners > (byteLimit - newStateBytes) / (sizeof(Component) + 128))
            return Error("Step ownership exceeds memory budget", E2BIG);
        data->bytes = sizeof(Step::Data) + owners * (sizeof(Component) + 128);
        for (Component pin : {data->attach, data->boundaryPin})
        {
            const std::size_t names = pin.LookupName().size() + pin.EffectiveName().size();
            if (!Fits(newStateBytes + data->bytes, names, byteLimit))
                return Error("Step anchor names exceed memory budget", E2BIG);
            data->bytes += names;
        }
        for (Component pin : data->popped)
        {
            const std::size_t names = pin.LookupName().size() + pin.EffectiveName().size();
            if (!Fits(newStateBytes + data->bytes, names, byteLimit))
                return Error("Step pin names exceed memory budget", E2BIG);
            data->bytes += names;
        }
        for (Component pin : data->pushed)
        {
            const std::size_t names = pin.LookupName().size() + pin.EffectiveName().size();
            if (!Fits(newStateBytes + data->bytes, names, byteLimit))
                return Error("Step pin names exceed memory budget", E2BIG);
            data->bytes += names;
        }
        for (const std::string& name :
            {data->boundaryLookup, data->boundaryEffective, data->sourceLookup, data->sourceEffective, data->targetLookup, data->targetEffective})
        {
            if (!Fits(newStateBytes + data->bytes, name.size(), byteLimit))
                return Error("Step names exceed memory budget", E2BIG);
            data->bytes += name.size();
        }
        if (!Fits(newStateBytes + data->bytes, mTemporaryBytes, byteLimit))
            return Error("Resolver preparation peak exceeds memory budget", E2BIG);
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
    std::size_t mTemporaryBytes = 0;
};

Result<Variant<Path::Step, Path::RejectionReason>> Path::ResolveInput(std::string name, Policy policy, InputRole role, std::size_t& followed) const
{
    auto validation = Validate(policy, mState->limits);
    if (validation.HasValue())
        return std::move(validation).Value();
    if (!Detail::IsSingleChildComponent(name) && role == InputRole::Leaf)
        return Error("Resolve requires a single child name", EINVAL);
    if (name.empty() || name.size() > mState->limits.shared.retainedBytes || name.find(47) != std::string::npos || name.find(char(0)) != std::string::npos)
        return Error("Invalid path component", EINVAL);
    Resolver resolver(*this, policy, role, followed);
    return resolver.Run(name);
}
Result<Variant<Path::Step, Path::RejectionReason>> Path::Resolve(std::string name, Policy policy) const
{
    std::size_t followed = 0;
    return ResolveInput(std::move(name), policy, InputRole::Leaf, followed);
}
Result<Path::Step> Path::Apply(Step&& step) &
{
    auto delta = step.mData;
    auto source = mState;
    if (source->pins.size() != delta->sourceDepth || delta->popped.size() >= delta->sourceDepth)
        return Error("Stale Path step depth", ESTALE);
    const std::size_t attachIndex = delta->sourceDepth - delta->popped.size() - 1;
    if (source->boundary >= source->pins.size())
        return Error("Step is detached from its acquisition context", ESTALE);
    // Check the physical suffix and source route before classifying a pop
    // across a newly frozen barrier. An unrelated same-depth path is stale.
    if (!source->pins[attachIndex].SameAcquisition(delta->attach) || source->lookup != delta->sourceLookup || source->effective != delta->sourceEffective)
        return Error("Step is detached from its acquisition context", ESTALE);
    for (std::size_t index = 0; index < delta->popped.size(); ++index)
        if (!source->pins[attachIndex + index + 1].SameAcquisition(delta->popped[index]))
            return Error("Step physical suffix changed", ESTALE);
    if (attachIndex < source->boundary)
        return Error("Step crosses traversal barrier", EXDEV);
    if (source->boundary != delta->boundary || !source->pins[source->boundary].SameAcquisition(delta->boundaryPin) ||
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
    const std::size_t budget = source->limits.shared.retainedBytes;
    const std::size_t finalBytes = StateBytes(finalSize, BoundedSum({delta->targetLookup.size(), source->boundaryLookup.size()}),
        BoundedSum({delta->targetEffective.size(), source->boundaryEffective.size()}), source->pinNames);
    if (finalBytes > budget || !Fits(finalBytes, delta->bytes, budget))
        return Error("Step and inverse exceed retained-memory budget", E2BIG);
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
    inverse->bytes = delta->bytes;
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
    candidate->pinNames = 0;
    for (Component pin : candidate->pins)
    {
        const std::size_t names = pin.LookupName().size() + pin.EffectiveName().size();
        if (!Fits(candidate->pinNames, names, budget))
            return Error("Applied pin names exceed memory budget", E2BIG);
        candidate->pinNames += names;
    }
    if (StateBytes(finalSize, BoundedSum({candidate->lookup.size(), source->boundaryLookup.size()}),
            BoundedSum({candidate->effective.size(), source->boundaryEffective.size()}), candidate->pinNames) > budget)
        return Error("Applied stack exceeds memory budget", E2BIG);
    // During preparation the original Path, candidate copy and replacement
    // vector coexist; do not charge only the published final stack.
    const std::size_t preparation = StateBytes(BoundedSum({BoundedTwice(source->pins.size()), finalSize}),
        BoundedSum({source->lookup.size(), candidate->lookup.size(), BoundedTwice(source->boundaryLookup.size())}),
        BoundedSum({source->effective.size(), candidate->effective.size(), BoundedTwice(source->boundaryEffective.size())}),
        BoundedSum({BoundedTwice(source->pinNames), candidate->pinNames}));
    if (preparation > budget || !Fits(preparation, delta->bytes, budget) || !Fits(preparation + delta->bytes, inverse->bytes, budget))
        return Error("Step preparation peak exceeds memory budget", E2BIG);
    std::shared_ptr<const State> published(std::move(candidate));
    std::shared_ptr<const Step::Data> undo(std::move(inverse));
    mState.swap(published);
    return Step(std::move(undo));
}
Result<bool> Path::Freeze() &
{
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
    candidate->baseline = source->pins.back().Acquired().targetMount.value;
    const std::size_t bytes = StateBytes(candidate->pins.size(), BoundedSum({candidate->lookup.size(), candidate->boundaryLookup.size()}),
        BoundedSum({candidate->effective.size(), candidate->boundaryEffective.size()}), candidate->pinNames);
    const std::size_t oldBytes = StateBytes(source->pins.size(), BoundedSum({source->lookup.size(), source->boundaryLookup.size()}),
        BoundedSum({source->effective.size(), source->boundaryEffective.size()}), source->pinNames);
    if (!Fits(oldBytes, bytes, source->limits.shared.retainedBytes) || candidate->pins.size() > source->limits.shared.liveDescriptors - kProcfsTemporaryPeak)
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
    if (absolutePath.empty() || absolutePath.front() != 47 || absolutePath.find(char(0)) != std::string::npos || absolutePath.size() > limits.shared.retainedBytes)
        return Error("Make requires a bounded absolute path", EINVAL);
    const std::size_t chunks = limits.shared.fdinfoBytes / 256 + ((limits.shared.fdinfoBytes % 256) != 0);
    if (chunks > (std::numeric_limits<std::size_t>::max() - 128) / 4 || !Fits(0, 128 + 4 * chunks, limits.shared.work))
        return Error("Path work budget exhausted", E2BIG);
    const std::size_t rootWork = 128 + 4 * chunks;
    auto root = Handle::PinProcessRoot(context, limits.shared.fdinfoBytes);
    if (!root.HasValue())
        return std::move(root).Error();
    auto state = std::make_shared<State>(context, limits, Component(std::move(root).Value()));
    Path result(std::move(state));
    result.mState->allowance->spent = rootWork;
    if (result.RetainedBytes() > limits.shared.retainedBytes)
        return Error("Root exceeds retained-memory budget", E2BIG);
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
        auto resolved = result.ResolveInput(absolutePath.substr(start, end - start), factoryPolicy, prefix ? InputRole::Prefix : InputRole::Leaf, followed);
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
