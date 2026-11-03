// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "ContextInterface.h"
#include "FilesystemHelpers.hpp"
#include "PathLinkAccess.hpp"
#include "PathResolutionStage.hpp"
#include "ProcfsDescriptorAccess.hpp"

#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <fcntl.h>
#include <limits>
#include <linux/magic.h>
#include <ranges/PathComponents.hpp>
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
using Detail::ProcfsDescriptorAccess;
using Detail::SameIdentity;
using Detail::SavedError;

namespace
{
bool ValidFollowing(SymlinkPolicy action)
{
    return action == SymlinkPolicy::Follow || action == SymlinkPolicy::DoNotFollow;
}

bool ValidNonFollowedLink(NonFollowedLinkAction action)
{
    return action == NonFollowedLinkAction::Reject || action == NonFollowedLinkAction::Skip;
}

bool FollowForClassification(SymlinkPolicy file, SymlinkPolicy directory)
{
    return file != directory || file == SymlinkPolicy::Follow;
}

Optional<Error> ValidateLimits(ResolverLimits const& limits)
{
    if (limits.shared.work == 0)
    {
        return Error("Work budget must be positive", EINVAL);
    }

    if (limits.shared.components == 0)
    {
        return Error("Components budget must be positive", EINVAL);
    }

    if (limits.shared.liveDescriptors == 0)
    {
        return Error("Live descriptors budget must be positive", EINVAL);
    }

    if (limits.shared.retainedBytes == 0)
    {
        return Error("Retained bytes budget must be positive", EINVAL);
    }

    if (limits.shared.targetBytes == 0)
    {
        return Error("Target bytes budget must be positive", EINVAL);
    }

    if (limits.shared.fdinfoBytes == 0 || limits.shared.fdinfoBytes >= std::string().max_size() || limits.shared.fdinfoBytes > std::vector<char>().max_size() ||
        limits.shared.fdinfoBytes > static_cast<std::size_t>(std::numeric_limits<ssize_t>::max()))
    {
        return Error("FD info bytes budget is invalid", EINVAL);
    }

    if (limits.linkTargetBytes == 0)
    {
        return Error("Link target bytes budget must be positive", EINVAL);
    }

    if (limits.depth == 0)
    {
        return Error("Depth budget must be positive", EINVAL);
    }

    return Optional<Error>{};
}

// Shared fields of the absolute and child policies; reject int-cast enum values.
Optional<Error> ValidateLinkPolicy(MountPolicy mounts, SymlinkPolicy fileLinks, SymlinkPolicy directoryLinks, NonFollowedLinkAction nonFollowedLinks)
{
    if (!ValidFollowing(fileLinks))
    {
        return Error("Invalid file link policy", EINVAL);
    }

    if (!ValidFollowing(directoryLinks))
    {
        return Error("Invalid directory link policy", EINVAL);
    }

    if (!ValidNonFollowedLink(nonFollowedLinks))
    {
        return Error("Invalid non-followed link policy", EINVAL);
    }

    if (mounts != MountPolicy::AllowCrossing && mounts != MountPolicy::StayOnRootMount)
    {
        return Error("Invalid mount policy", EINVAL);
    }

    return {};
}

Optional<Error> ValidatePolicy(Path::Policy const& policy)
{
    if (!ValidFollowing(policy.symlinks))
        return Error("Invalid symlink policy", EINVAL);
    return ValidateLinkPolicy(policy.mounts, policy.fileLinks, policy.directoryLinks, policy.nonFollowedLinks);
}

Optional<Error> ValidatePolicy(ExtensionPolicy const& policy)
{
    auto validation = ValidateLinkPolicy(policy.mounts, policy.fileLinks, policy.directoryLinks, policy.nonFollowedLinks);
    if (validation.HasValue())
        return std::move(validation).Value();
    if (policy.unsupported != UnsupportedTypeAction::Reject && policy.unsupported != UnsupportedTypeAction::Skip)
        return Error("Invalid unsupported type action", EINVAL);
    return {};
}

Optional<Error> ValidateExtendInput(const std::string& component, ExtensionPolicy const& policy)
{
    if (!Detail::IsSingleChildComponent(component))
        return Error("Invalid child component", EINVAL);
    return ValidatePolicy(policy);
}

Optional<Error> ValidateAbsolutePath(const std::string& path, Path::Policy const& policy, ResolverLimits const& limits)
{
    if ((path.empty()) || (path.front() != '/'))
    {
        return Error("Path must be absolute", EINVAL);
    }

    if (path.find('\0') != std::string::npos)
    {
        return Error("Path contains NUL byte", EINVAL);
    }

    if ((path.size() > limits.shared.retainedBytes) || (limits.shared.liveDescriptors < 8) || !ValidFollowing(policy.symlinks) ||
        !ValidFollowing(policy.fileLinks) || !ValidFollowing(policy.directoryLinks) || !ValidNonFollowedLink(policy.nonFollowedLinks) ||
        ((policy.mounts != MountPolicy::AllowCrossing) && (policy.mounts != MountPolicy::StayOnRootMount)))
    {
        return Error("An absolute authorized directory, policy and positive budgets are required", EINVAL);
    }
    return Optional<Error>{};
}

Optional<Error> ValidateMakeInput(const std::string& absolutePath, Path::Policy const& policy, ResolverLimits const& limits)
{
    auto validationResult = ValidateLimits(limits);
    if (validationResult.HasValue())
        return std::move(validationResult).Value();

    validationResult = ValidatePolicy(policy);
    if (validationResult.HasValue())
        return std::move(validationResult).Value();

    validationResult = ValidateAbsolutePath(absolutePath, policy, limits);
    if (validationResult.HasValue())
        return std::move(validationResult).Value();

    return {};
}

std::string JoinName(const std::string& parent, const std::string& child)
{
    return parent == "/" ? parent + child : parent + "/" + child;
}

// Remove only redundant separators. Dot components must be handled during
// descriptor resolution in filesystem order, never by lexical simplification.
std::string CollapseSeparators(const std::string& name)
{
    std::string result;
    result.reserve(name.size());
    for (char c : name)
    {
        if (c != '/' || result.empty() || result.back() != '/')
            result += c;
    }
    if (result.size() > 1 && result.back() == '/')
        result.pop_back();
    return result;
}

bool AtBoundary(const std::string& target, const std::string& prefix)
{
    return target.compare(0, prefix.size(), prefix) == 0 && (prefix == "/" || target.size() == prefix.size() || target[prefix.size()] == '/');
}
} // namespace

namespace Detail
{
namespace
{
// The acquisition snapshot does not bracket the read: re-observe the pinned
// object and its mount on both sides of readlinkat, without following its text.
Result<LinkTarget> ReadVerifiedLinkText(const Descriptor& linkPin, const struct stat& before, const ProcfsDescriptorAccess& procfs,
    std::size_t targetByteCap, std::size_t fdinfoByteCap)
{
    const ContextInterface& context = linkPin.Context();
    auto mount = procfs.ReadMountId(linkPin, fdinfoByteCap);
    if (!mount.HasValue())
        return std::move(mount).Error();

    std::vector<char> buffer(targetByteCap + 1);
    const ssize_t count = context.ReadLink(linkPin, buffer.data(), buffer.size());
    if (count < 0)
        return Error("Cannot read pinned symlink target", SavedError());
    if ((count == 0) || (static_cast<std::size_t>(count) > targetByteCap))
        return Error("Pinned symlink target exceeds byte cap or is empty", E2BIG);

    struct stat after = {};
    if (context.StatFile(linkPin, &after) != 0)
        return Error("Cannot recheck pinned symlink", SavedError());
    if (!SameIdentity(before, after))
        return Error("Pinned symlink identity changed", EAGAIN);
    auto retainedMount = procfs.ReadMountId(linkPin, fdinfoByteCap);
    if (!retainedMount.HasValue())
        return std::move(retainedMount).Error();
    if (mount.Value() != retainedMount.Value())
        return Error("Pinned symlink mount changed", EAGAIN);

    LinkTarget target;
    target.text.assign(buffer.data(), static_cast<std::size_t>(count));
    if (target.text.find('\0') != std::string::npos)
        return Error("Pinned symlink contains NUL", EINVAL);
    target.mountId = mount.Value();
    return target;
}
} // namespace

Result<LinkTarget> ReadPinnedLink(const Descriptor& linkPin, std::size_t targetByteCap, std::size_t fdinfoByteCap)
{
    if (!linkPin.HasValue())
    {
        return Error("Pinned link is empty", EBADF);
    }
    const ContextInterface& context = linkPin.Context();
    if ((targetByteCap == 0) || (targetByteCap >= std::vector<char>().max_size() - 1) ||
        (targetByteCap >= static_cast<std::size_t>(std::numeric_limits<ssize_t>::max())) || (fdinfoByteCap == 0))
    {
        return Error("Invalid pinned link or byte cap", EINVAL);
    }
    const int flags = context.StatusFlags(linkPin);
    if (flags < 0)
    {
        return Error("Cannot inspect pinned link flags", SavedError());
    }
    const int descriptorFlags = context.DescriptorFlags(linkPin);
    if (descriptorFlags < 0)
    {
        return Error("Cannot inspect pinned link flags", SavedError());
    }

    if (((flags & O_PATH) == 0) || ((descriptorFlags & FD_CLOEXEC) == 0))
    {
        return Error("Pinned link must be a close-on-exec O_PATH descriptor", EINVAL);
    }
    struct stat before = {};
    struct statfs filesystem = {};
    if ((context.StatFile(linkPin, &before) != 0) || (context.StatFilesystem(linkPin, &filesystem) != 0))
    {
        return Error("Cannot inspect pinned link", SavedError());
    }

    if (!S_ISLNK(before.st_mode) || (PROC_SUPER_MAGIC == filesystem.f_type))
    {
        return Error("Not an ordinary filesystem symlink", ELOOP);
    }
    ProcfsDescriptorAccess procfs(context);
    auto verified = procfs.Open();
    if (!verified.HasValue())
    {
        return std::move(verified).Error();
    }
    auto inspected = ReadVerifiedLinkText(linkPin, before, procfs, targetByteCap, fdinfoByteCap);
    auto closed = procfs.Close();
    if (!closed.HasValue())
    {
        if (inspected.HasValue())
        {
            return std::move(closed).Error();
        }
        LogSecondaryClose(context, closed.Error().code);
    }
    return inspected;
}
} // namespace Detail

namespace Detail
{
const Handle& ResolvedPath::Leaf() const
{
    return mPins->at(mOwnedLeaf).handle;
}

Handle ResolvedPath::TakeOwnedLeaf()
{
    Handle owned(std::move(mPins->at(mOwnedLeaf).handle));
    mLeafTaken = true;
    return owned;
}

std::size_t ResolvedPath::OwnedDescriptors() const noexcept
{
    // Only the owned leaf can leave a stage; all other staged pins remain
    // live until the stage is destroyed.
    return mPins->size() - (mLeafTaken ? 1 : 0);
}

std::size_t ResolvedPath::AccountedBytes() const noexcept
{
    return mAccountedBytes;
}

Result<bool> ResolvedPath::Close(const ContextInterface& context)
{
    Optional<Error> first;
    for (auto pin = mPins->rbegin(); pin != mPins->rend(); ++pin)
    {
        auto closed = pin->handle.Close();
        if (!closed.HasValue())
        {
            if (!first.HasValue())
                first = std::move(closed).Error();
            else
                LogSecondaryClose(context, closed.Error().code);
        }
    }
    return first.HasValue() ? Result<bool>(std::move(first.Value())) : Result<bool>(true);
}

} // namespace Detail

class Path::Resolver
{
public:
    Resolver(const Path& location, ResolutionPolicy policy, std::size_t& followed)
        : mLocation(location),
          mContext(location.mContext.get()),
          mPolicy(policy),
          mLimits(location.mLimits),
          mLedger(location.mWorkAllowance->spent),
          mFollowed(followed)
    {
    }

    ComplianceEngine::Result<Variant<Detail::ResolvedPath, RejectionReason>> Run(std::string component)
    {
        if (!Detail::IsSingleChildComponent(component) || mLocation.mPhysical.empty() ||
            (mPolicy.mounts != MountPolicy::AllowCrossing && mPolicy.mounts != MountPolicy::StayOnRootMount) || (mLimits.linkTargetBytes == 0) ||
            (mLimits.linkExpansions == 0) || (mLimits.depth == 0) || (mLimits.shared.targetBytes == 0) || (mLimits.shared.components == 0) ||
            (mLimits.shared.work == 0) || (mLimits.shared.liveDescriptors == 0) || (mLimits.shared.retainedBytes == 0) ||
            (mLimits.shared.fdinfoBytes == 0) || !mLocation.mEntries || mLocation.mEntries->empty())
        {
            return Error("Invalid confined resolver input or mandatory limits", EINVAL);
        }

        const std::size_t held = mLocation.HeldDescriptors();
        if (held > mLimits.shared.liveDescriptors || mLimits.shared.liveDescriptors - held < 7 || mLocation.mUsage.retainedBytes >= mLimits.shared.retainedBytes)
            return Error("Location budget exhausted before resolution", E2BIG);
        mLimits.shared.retainedBytes -= mLocation.mUsage.retainedBytes;
        if (!mLocation.mFrozen && mPolicy.permitUnsupported)
        {
            const std::size_t extra = component.size() + 1;
            if (extra > mLimits.shared.retainedBytes)
                return Error("Acquisition name exceeds retained-memory budget", E2BIG);
            mLimits.shared.retainedBytes -= extra;
        }
        mNames = mLocation.Bindings();
        // The resolver keeps full reconstructed binding spellings and owning
        // Component snapshots. Count every copied binding, even inactive
        // branches, before allocating the rest of the walk schedule.
        for (const NameBinding& binding : mNames)
        {
            const std::size_t remaining = mLimits.shared.retainedBytes - mRetained;
            if (sizeof(NameBinding) > remaining || binding.lookup.size() > remaining - sizeof(NameBinding) ||
                binding.effective.size() > remaining - sizeof(NameBinding) - binding.lookup.size())
                return Error("Held bindings exceed resolution memory budget", E2BIG);
            mRetained += sizeof(NameBinding) + binding.lookup.size() + binding.effective.size();
        }
        const auto boundary = std::find(mLocation.mPhysical.begin(), mLocation.mPhysical.end(), 0);
        if (boundary == mLocation.mPhysical.end())
            return Error("Accepted root is absent from physical ancestry", EINVAL);
        mParentLineage.assign(boundary, mLocation.mPhysical.end());
        if (!AddInput(0))
            return Error("Invalid or over-budget root lineage", E2BIG);
        for (std::size_t index : mParentLineage)
        {
            if (!AddInput(index))
            {
                return Error("Invalid or over-budget parent lineage", E2BIG);
            }
        }
        mLimits.shared.liveDescriptors -= held - mInputPins;

        if ((mParentLineage.size() > mLimits.depth) || (mInputPins > mLimits.shared.liveDescriptors) || (mLimits.shared.liveDescriptors - mInputPins < 7))
        {
            return Error("Initial depth or descriptor budget exhausted", EMFILE);
        }

        if (!Charge())
        {
            return Error("Resolver work budget exhausted", E2BIG);
        }
        {
            ProcfsDescriptorAccess procfs(mContext);
            auto verified = procfs.Open();
            if (!verified.HasValue())
            {
                return std::move(verified).Error();
            }
            // The accepted root's live pin already retains its acquired mount.
            const std::uint64_t baseline = mNames.front().component.Pin().mTargetMount;
            auto closed = procfs.Close();
            if (!closed.HasValue())
                return std::move(closed).Error();
            mBaseline = baseline;
        }
        // No procfs helper stays open while another helper reads a link.
        return ResolveComponents(std::move(component));
    }

private:
    struct Pending
    {
        std::string name;
        bool endFrame = false;
        Pending(std::string text, bool end = false)
            : name(std::move(text)),
              endFrame(end)
        {
        }
    };
    using Schedule = std::deque<Pending>;
    static bool HasComponent(const Schedule& pending)
    {
        return std::any_of(pending.begin(), pending.end(), [](const Pending& item) { return !item.endFrame; });
    }

    bool AddInput(std::size_t index)
    {
        if (index >= mNames.size() || mNames[index].component.Pin().mType != Handle::Type::Directory || !mNames[index].component.Pin().mDescriptor.HasValue())
        {
            return false;
        }

        if (std::find(mSeen.begin(), mSeen.end(), index) != mSeen.end())
            return true;
        // Charge the held pin and conservative lineage/index storage.
        const std::size_t slot = sizeof(Handle) + 4 * sizeof(std::size_t);
        if (slot > mLimits.shared.retainedBytes - mRetained)
            return false;
        mSeen.push_back(index);
        ++mInputPins;
        mRetained += slot;
        return true;
    }

    bool Charge()
    {
        const std::size_t chunks = (mLimits.shared.fdinfoBytes / 256) + ((mLimits.shared.fdinfoBytes % 256) ? 1 : 0);
        if ((chunks > (std::numeric_limits<std::size_t>::max() - 128) / 4) || (mSteps >= mLimits.shared.components))
        {
            return false;
        }
        const std::size_t cost = 128 + 4 * chunks;
        if ((mLedger > mLimits.shared.work) || (cost > mLimits.shared.work - mLedger))
        {
            return false;
        }
        ++mSteps;
        mLedger += cost;
        return true;
    }

    bool CanRetain(std::size_t bytes) const
    {
        return (mRetained <= mLimits.shared.retainedBytes) && (bytes <= mLimits.shared.retainedBytes - mRetained);
    }

    ComplianceEngine::Result<std::uint64_t> ObservedMount(const Descriptor& descriptor)
    {
        ProcfsDescriptorAccess procfs(mContext);
        auto verified = procfs.Open();
        if (!verified.HasValue())
        {
            return std::move(verified).Error();
        }
        auto mount = procfs.ReadMountId(descriptor, mLimits.shared.fdinfoBytes);
        auto closed = procfs.Close();
        if (!closed.HasValue())
        {
            if (mount.HasValue())
            {
                return std::move(closed).Error();
            }
            Detail::LogSecondaryClose(mContext, closed.Error().code);
        }
        return mount;
    }

    const Handle& Pin(std::size_t index, const Detail::ResolvedPath& stage) const
    {
        return index < mNames.size() ? mNames[index].component.Pin() : stage.mPins->at(index - mNames.size()).handle;
    }

    const std::string& Effective(std::size_t index, const Detail::ResolvedPath& stage) const
    {
        return index < mNames.size() ? mNames[index].effective : stage.mPins->at(index - mNames.size()).effective;
    }

    struct HeldMatch
    {
        std::size_t index;
        std::uint64_t mount;
        bool alias;
    };

    ComplianceEngine::Result<Optional<HeldMatch>> FindHeld(const std::string& lookup, const Detail::ResolvedPath& stage) const
    {
        Optional<HeldMatch> match;
        for (std::size_t index = 0; index < mNames.size(); ++index)
        {
            const auto& binding = mNames[index];
            if (binding.lookup != lookup && binding.effective != lookup)
                continue;
            if (match.HasValue() && (!SameIdentity(Pin(match.Value().index, stage).AcquiredMetadata(), binding.component.AcquiredMetadata()) ||
                                        Effective(match.Value().index, stage) != binding.effective))
                return Error("Conflicting held name bindings", EXDEV);
            match = HeldMatch{index, binding.mount, binding.lookup == lookup && binding.effective != lookup};
        }
        for (std::size_t index = 0; index < stage.mPins->size(); ++index)
        {
            const auto& pin = (*stage.mPins)[index];
            if (pin.effective != lookup || pin.handle.AcquiredType() != Handle::Type::Directory)
                continue;
            if (match.HasValue() && (!SameIdentity(Pin(match.Value().index, stage).AcquiredMetadata(), pin.handle.AcquiredMetadata()) ||
                                        Effective(match.Value().index, stage) != lookup))
                return Error("Conflicting staged name bindings", EXDEV);
            match = HeldMatch{mNames.size() + index, 0, false};
        }
        return match;
    }

    struct Inspected
    {
        Inspected(Descriptor&& owned, const struct stat& metadata, std::uint64_t mountId) noexcept
            : pin(std::move(owned)),
              snapshot(metadata),
              mount(mountId)
        {
        }
        Descriptor pin;
        struct stat snapshot;
        std::uint64_t mount;
    };

    ComplianceEngine::Result<Variant<Inspected, RejectionReason>> AcquireComponent(const Handle& parent, const std::string& name, bool intermediate, bool directMissing)
    {
        // Intermediate opens require a directory; retry ENOTDIR only with
        // O_PATH|O_NOFOLLOW for link classification, never operational access.
        auto opened = mContext.OpenAt(parent.mDescriptor, name.c_str(),
            intermediate ? ContextInterface::OpenProfile::PinChildDirectory : ContextInterface::OpenProfile::PinChild);
        if (!opened.HasValue() && opened.Error().code == ENOTDIR && intermediate)
            opened = mContext.OpenAt(parent.mDescriptor, name.c_str(), ContextInterface::OpenProfile::PinChild);
        if (!opened.HasValue())
        {
            if (mPolicy.allowMissing && directMissing && opened.Error().code == ENOENT)
                return Variant<Inspected, RejectionReason>(InPlaceType<RejectionReason>{}, RejectionReason::Missing);
            return Error("Cannot pin confined component", opened.Error().code);
        }
        Descriptor acquired = std::move(opened).Value();
        struct stat snapshot = {};
        Optional<Error> primary;
        std::uint64_t mountId = 0;
        if (mContext.StatFile(acquired, &snapshot) != 0)
            primary = Error("Cannot inspect confined component", SavedError());
        if (!primary.HasValue())
        {
            auto mount = ObservedMount(acquired);
            if (!mount.HasValue())
                primary = std::move(mount).Error();
            else
                mountId = mount.Value();
        }
        if (primary.HasValue())
        {
            auto closed = acquired.Close();
            if (!closed.HasValue())
                Detail::LogSecondaryClose(mContext, closed.Error().code);
            return std::move(primary.Value());
        }
        return Variant<Inspected, RejectionReason>(InPlaceType<Inspected>{}, Inspected(std::move(acquired), snapshot, mountId));
    }

    // Both held and newly acquired pins have an observed mount before they
    // advance the cursor. Held aliases also retain their original mount.
    ComplianceEngine::Result<bool> VerifyTransitionMount(std::uint64_t observed, std::uint64_t original, bool held) const
    {
        if (mPolicy.mounts == MountPolicy::StayOnRootMount && (observed != mBaseline || (original != 0 && original != mBaseline)))
            return Error(held ? "Held component crosses accepted root mount" : "Component crosses accepted root mount", EXDEV);
        return true;
    }

    ComplianceEngine::Result<std::vector<std::size_t>> HeldLineage(std::size_t target, const Detail::ResolvedPath& stage) const
    {
        if (target >= mNames.size() || Pin(target, stage).AcquiredType() != Handle::Type::Directory ||
            !AtBoundary(mNames[target].effective, mNames.front().effective))
            return Error("Acquired directory outside physical root", EXDEV);
        std::vector<std::size_t> reverse;
        std::size_t current = target;
        while (true)
        {
            if (reverse.size() >= mLimits.depth)
                return Error("Held physical ancestor exceeds depth budget", E2BIG);
            reverse.push_back(current);
            const auto& binding = mNames[current];
            // A captured parent relationship, not a reconstruction from a
            // live pathname. Reject contradictory bindings of the same
            // acquired spelling, including pins staged by this walk.
            for (std::size_t index = 0; index < mNames.size(); ++index)
                if (mNames[index].effective == binding.effective && mNames[index].component.AcquiredType() == Handle::Type::Directory &&
                    !SameIdentity(binding.component.AcquiredMetadata(), mNames[index].component.AcquiredMetadata()))
                    return Error("Conflicting held physical ancestors", EXDEV);
            for (std::size_t index = 0; index < stage.mPins->size(); ++index)
                if ((*stage.mPins)[index].effective == binding.effective && (*stage.mPins)[index].handle.AcquiredType() == Handle::Type::Directory &&
                    !SameIdentity(binding.component.AcquiredMetadata(), (*stage.mPins)[index].handle.AcquiredMetadata()))
                    return Error("Conflicting staged physical ancestors", EXDEV);
            if (current == 0)
                break;
            const std::size_t parent = (*mLocation.mEntries)[current].effectiveParent;
            if (parent >= current || parent >= mNames.size() || JoinName(mNames[parent].effective, binding.component.effectiveName) != binding.effective)
                return Error("Missing acquired physical ancestor", EXDEV);
            current = parent;
        }
        std::reverse(reverse.begin(), reverse.end());
        return reverse;
    }

    ComplianceEngine::Result<bool> AdvanceDirectory(std::size_t directory, bool alias, std::vector<std::size_t>& directories, Detail::ResolvedPath& resolved)
    {
        if (alias)
        {
            // An alias transitions to the held physical lineage, never to
            // the lookup parent's potentially unrelated lexical lineage.
            auto lineage = HeldLineage(directory, resolved);
            if (!lineage.HasValue())
                return std::move(lineage).Error();
            if (mPolicy.mounts == MountPolicy::StayOnRootMount)
            {
                for (std::size_t ancestor : lineage.Value())
                {
                    if (ancestor == 0)
                        continue;
                    if (Pin(ancestor, resolved).mTargetMount != mBaseline)
                        return Error("Held physical ancestor crosses accepted root mount", EXDEV);
                }
            }
            directories = std::move(lineage).Value();
        }
        else
        {
            if (directories.size() >= mLimits.depth)
                return Error("Confined resolution depth exhausted", E2BIG);
            directories.push_back(directory);
        }
        return true;
    }

    ComplianceEngine::Result<bool> ExpandPinnedLink(const Descriptor& pin, Schedule& pending, std::vector<std::size_t>& directories,
        bool& finalDirectoryRequired, std::uint64_t observedMount)
    {
        // The resolver itself is iterative (one C++ call frame), with at most
        // 64 live target/suffix frames on the bounded heap work schedule.
        // This avoids relying on the caller's possibly small thread stack.
        if (mFrameDepth >= 64)
            return Error("Symlink resolution frame ceiling exhausted", ELOOP);
        auto target = Detail::ReadPinnedLink(pin, mLimits.linkTargetBytes, mLimits.shared.fdinfoBytes);
        if (!target.HasValue())
            return std::move(target).Error();
        if (target.Value().mountId != observedMount || !CanRetain(target.Value().text.size()))
            return Error("Symlink changed mount or exhausted retained-memory budget", E2BIG);
        mRetained += target.Value().text.size();
        std::string text = std::move(target).Value().text;
        if (text.back() == '/' && !HasComponent(pending))
            finalDirectoryRequired = true;
        if (text.front() == '/')
        {
            if (text.size() > mLimits.shared.targetBytes)
                return Error("Absolute link exceeds target byte budget", E2BIG);
            const std::string absolute = CollapseSeparators(text);
            bool matched = false;
            std::string tail;
            for (const std::string* binding : {&mNames.front().lookup, &mNames.front().effective})
            {
                if (!AtBoundary(absolute, *binding))
                    continue;
                const std::string candidate = absolute.substr(binding->size());
                if (matched && candidate != tail)
                    return Error("Ambiguous acquired root binding", EXDEV);
                matched = true;
                tail = candidate;
            }
            if (!matched)
                return Error("Absolute symlink target is outside acquired root bindings", EXDEV);
            text = std::move(tail);
            directories.assign(1, 0);
        }
        Schedule expanded;
        std::size_t start = 0;
        while (start < text.size())
        {
            const std::size_t slash = text.find('/', start);
            const std::size_t end = slash == std::string::npos ? text.size() : slash;
            if (end != start)
            {
                if (!CanRetain(sizeof(Pending) + end - start))
                    return Error("Symlink expansion exceeds retained-memory budget", E2BIG);
                mRetained += sizeof(Pending) + end - start;
                expanded.emplace_back(text.substr(start, end - start));
            }
            start = end + 1;
        }
        if (!CanRetain(sizeof(Pending)))
            return Error("Symlink frame storage exceeds retained-memory budget", E2BIG);
        mRetained += sizeof(Pending);
        expanded.emplace_back(std::string(), true);
        while (!pending.empty())
        {
            expanded.emplace_back(std::move(pending.front()));
            pending.pop_front();
        }
        pending.swap(expanded);
        ++mFrameDepth;
        return true;
    }

    ComplianceEngine::Result<bool> PrepareStep(Detail::ResolvedPath& step, const std::vector<std::size_t>& directories, std::size_t leaf)
    {
        step.mFrames = directories;

        step.mEffectiveLeaf = Effective(leaf, step);
        if (leaf >= mNames.size())
        {
            step.mOwnedLeaf = leaf - mNames.size();
            step.mAccountedBytes = mRetained;
            return true;
        }
        // A held ancestor may be the final leaf after physical "..". Pin a
        // verified independent owner before returning an accepted step.
        auto duplicated = RetainLeaf(mContext, mLimits, mInputPins, step, Pin(leaf, step));
        if (!duplicated.HasValue())
            return std::move(duplicated).Error();
        step.mOwnedLeaf = step.mPins->size();
        step.mPins->emplace_back(std::move(duplicated).Value());
        step.mAccountedBytes = mRetained;
        return true;
    }

    enum class ComponentProgress
    {
        ExpandedLink,
        RetainedObject
    };

    // The caller closes the acquisition pin exactly once after this operation,
    // whether it expanded a link, staged an owner, rejected or failed.
    ComplianceEngine::Result<Variant<ComponentProgress, RejectionReason>> ProcessAcquiredComponent(Inspected& component, const std::string& lookup,
        Schedule& pending, std::vector<std::size_t>& directories, Detail::ResolvedPath& resolved, std::size_t& last, bool& finalDirectoryRequired,
        bool& resolvingRequestedName)
    {
        auto mount = VerifyTransitionMount(component.mount, 0, false);
        if (!mount.HasValue())
            return std::move(mount).Error();
        if (resolvingRequestedName)
            resolved.mInitialMountId = component.mount;

        const struct stat& snapshot = component.snapshot;
        if (S_ISLNK(snapshot.st_mode))
        {
            if (!mPolicy.followLinks)
            {
                if (mPolicy.excludeLinks && resolvingRequestedName && !HasComponent(pending))
                    return Variant<ComponentProgress, RejectionReason>(InPlaceType<RejectionReason>{}, RejectionReason::Excluded);
                return Error("Descendant symlink following is disabled", ELOOP);
            }
            if (mFollowed >= mLimits.linkExpansions)
                return Error("Symlink expansion budget exhausted", ELOOP);
            ++mFollowed;
            if (resolvingRequestedName)
                resolved.mInitialFollowedLink = true;
            auto expanded = ExpandPinnedLink(component.pin, pending, directories, finalDirectoryRequired, component.mount);
            if (!expanded.HasValue())
                return std::move(expanded).Error();
            last = directories.back();
            resolvingRequestedName = false;
            return Variant<ComponentProgress, RejectionReason>(InPlaceType<ComponentProgress>{}, ComponentProgress::ExpandedLink);
        }
        resolvingRequestedName = false;
        if ((!S_ISDIR(snapshot.st_mode)) && (!S_ISREG(snapshot.st_mode)))
        {
            // Only a final unsupported object may be skipped. It never
            // becomes an accepted Handle, even when reached through a link.
            if (mPolicy.permitUnsupported && !HasComponent(pending))
                return Variant<ComponentProgress, RejectionReason>(InPlaceType<RejectionReason>{}, RejectionReason::UnsupportedType);
            return Error("Unsupported confined object type", EOPNOTSUPP);
        }
        if (HasComponent(pending) && !S_ISDIR(snapshot.st_mode))
            return Error("Intermediate component is not a directory", ENOTDIR);

        // Full effective spellings cost O(depth squared) across staged pins.
        const std::size_t ownerBytes = sizeof(Handle) + 2 * lookup.size() + (S_ISDIR(snapshot.st_mode) ? 4 * sizeof(std::size_t) : 0);
        if (!CanRetain(ownerBytes))
            return Error("Confined resolution retained-memory budget exhausted", E2BIG);
        mRetained += ownerBytes;
        Handle staged(std::move(component.pin), S_ISDIR(snapshot.st_mode) ? Handle::Type::Directory : Handle::Type::RegularFile, snapshot,
            mLimits.shared.fdinfoBytes, component.mount, component.mount);
        resolved.mPins->emplace_back(std::move(staged), lookup, lookup);
        last = mNames.size() + resolved.mPins->size() - 1;
        if (S_ISDIR(snapshot.st_mode))
        {
            auto advanced = AdvanceDirectory(last, false, directories, resolved);
            if (!advanced.HasValue())
                return std::move(advanced).Error();
        }
        return Variant<ComponentProgress, RejectionReason>(InPlaceType<ComponentProgress>{}, ComponentProgress::RetainedObject);
    }

    ComplianceEngine::Result<Variant<Detail::ResolvedPath, RejectionReason>> WalkComponents(std::string component, Detail::ResolvedPath& resolved)
    {
        if (!CanRetain(sizeof(Pending) + component.size()))
        {
            return Error("Initial resolution exceeds retained-memory budget", E2BIG);
        }
        mRetained += sizeof(Pending) + component.size();
        std::vector<std::size_t> directories(mParentLineage);
        Schedule pending;
        pending.emplace_back(std::move(component));
        std::size_t last = directories.back();
        resolved.mSourceLookup = JoinName(Effective(last, resolved), pending.front().name);
        bool finalDirectoryRequired = false;
        // This is the original requested name, not the first loop iteration:
        // link-expanded names do not qualify for direct-name Missing/Excluded.
        bool resolvingRequestedName = true;
        while (!pending.empty())
        {
            if (pending.front().endFrame)
            {
                pending.pop_front();
                --mFrameDepth;
                continue;
            }
            if (!Charge())
            {
                return Error("Confined resolution work budget exhausted", E2BIG);
            }
            std::string name = std::move(pending.front().name);
            pending.pop_front();
            if (name.empty() || ("." == name))
            {
                continue;
            }

            if (".." == name)
            {
                if (directories.size() == 1)
                {
                    return Error("Symlink target escapes the accepted root", EXDEV);
                }
                directories.pop_back();
                last = directories.back();
                continue;
            }

            if (!Detail::IsSingleChildComponent(name) || (mInputPins + resolved.mPins->size() > mLimits.shared.liveDescriptors - 7))
            {
                return Error("Invalid component or insufficient descriptor budget", E2BIG);
            }
            const std::string lookup = JoinName(Effective(directories.back(), resolved), name);
            auto held = FindHeld(lookup, resolved);
            if (!held.HasValue())
                return std::move(held).Error();
            if (held.Value().HasValue() && Pin(held.Value().Value().index, resolved).AcquiredType() == Handle::Type::Directory)
            {
                const HeldMatch& binding = held.Value().Value();
                const std::size_t cached = binding.index;
                const std::uint64_t cachedOriginalMount = binding.mount;
                const bool cachedAlias = binding.alias;
                if (cachedAlias && !mPolicy.followLinks)
                {
                    if (mPolicy.excludeLinks && resolvingRequestedName && !HasComponent(pending))
                        return Variant<Detail::ResolvedPath, RejectionReason>(InPlaceType<RejectionReason>{}, RejectionReason::Excluded);
                    return Error("Descendant symlink following is disabled", ELOOP);
                }
                if (cachedAlias)
                {
                    if (mFollowed >= mLimits.linkExpansions)
                        return Error("Symlink expansion budget exhausted", ELOOP);
                    ++mFollowed;
                }
                auto verified = VerifyTransitionMount(Pin(cached, resolved).mTargetMount, cachedOriginalMount, true);
                if (!verified.HasValue())
                    return std::move(verified).Error();
                if (resolvingRequestedName)
                    resolved.mInitialMountId = cachedOriginalMount != 0 ? cachedOriginalMount : Pin(cached, resolved).mTargetMount;
                if (resolvingRequestedName && cachedAlias)
                    resolved.mInitialFollowedLink = true;
                auto advanced = AdvanceDirectory(cached, cachedAlias, directories, resolved);
                if (!advanced.HasValue())
                    return std::move(advanced).Error();
                resolvingRequestedName = false;
                last = cached;
                continue;
            }
            auto inspected = AcquireComponent(Pin(directories.back(), resolved), name, HasComponent(pending), resolvingRequestedName && !HasComponent(pending));
            if (!inspected.HasValue())
                return std::move(inspected).Error();
            if (inspected.Value().Is<RejectionReason>())
            {
                return Variant<Detail::ResolvedPath, RejectionReason>(InPlaceType<RejectionReason>{}, inspected.Value().Get<RejectionReason>());
            }
            Inspected& component = inspected.Value().Get<Inspected>();
            Descriptor& acquired = component.pin;
            auto step = ProcessAcquiredComponent(component, lookup, pending, directories, resolved, last, finalDirectoryRequired, resolvingRequestedName);
            auto closed = acquired.Close();
            if (!closed.HasValue())
            {
                if (step.HasValue())
                {
                    step = std::move(closed).Error();
                }
                else
                {
                    Detail::LogSecondaryClose(mContext, closed.Error().code);
                }
            }
            if (!step.HasValue())
            {
                return std::move(step).Error();
            }
            if (step.Value().Is<RejectionReason>())
                return Variant<Detail::ResolvedPath, RejectionReason>(InPlaceType<RejectionReason>{}, step.Value().Get<RejectionReason>());
            if (step.Value().Get<ComponentProgress>() == ComponentProgress::ExpandedLink)
                continue;
            // A retained directory or leaf is now the physical cursor.
        }

        if (finalDirectoryRequired && (Pin(last, resolved).AcquiredType() != Handle::Type::Directory))
        {
            return Error("Trailing slash requires a directory", ENOTDIR);
        }
        auto prepared = PrepareStep(resolved, directories, last);
        if (!prepared.HasValue())
            return std::move(prepared).Error();
        return Variant<Detail::ResolvedPath, RejectionReason>(InPlaceType<Detail::ResolvedPath>{}, std::move(resolved));
    }

    ComplianceEngine::Result<Variant<Detail::ResolvedPath, RejectionReason>> ResolveComponents(std::string component)
    {
        Detail::ResolvedPath resolved;
        auto resolution = WalkComponents(std::move(component), resolved);
        if (!resolution.HasValue())
        {
            auto primary = std::move(resolution).Error();
            auto closed = resolved.Close(mContext);
            if (!closed.HasValue())
                Detail::LogSecondaryClose(mContext, closed.Error().code);
            return primary;
        }
        if (resolution.Value().Is<RejectionReason>())
        {
            auto closed = resolved.Close(mContext);
            if (!closed.HasValue())
                return std::move(closed).Error();
            return resolution;
        }
        return resolution;
    }

    const Path& mLocation;
    const ContextInterface& mContext;
    std::vector<std::size_t> mParentLineage;
    ResolutionPolicy mPolicy;
    ResolverLimits mLimits;
    std::vector<NameBinding> mNames;
    std::size_t& mLedger;
    std::size_t& mFollowed;
    std::vector<std::size_t> mSeen;
    std::size_t mInputPins = 0, mRetained = 0, mSteps = 0;
    std::size_t mFrameDepth = 1;
    std::uint64_t mBaseline = 0;
};

Path::Path(const ContextInterface& context, ResolverLimits limits)
    : mContext(context),
      mLimits(limits),
      mWorkAllowance(std::make_shared<WorkAllowance>()),
      mEntries(new std::deque<Entry>())
{
}

Path::Path(Path&& other) noexcept
    : mContext(other.mContext),
      mLimits(other.mLimits),
      mUsage(other.mUsage),
      mWorkAllowance(std::move(other.mWorkAllowance)),
      mRootMountId(other.mRootMountId),
      mLeafSourceMount(other.mLeafSourceMount),
      mFrozen(other.mFrozen),
      mAcquisitionName(std::move(other.mAcquisitionName)),
      mAcquisitionBytes(other.mAcquisitionBytes),
      mEntries(std::move(other.mEntries)),
      mPhysical(std::move(other.mPhysical)),
      mSize(other.mSize)
{
    other.mSize = 0;
    other.mFrozen = false;
    other.mAcquisitionBytes = 0;
    other.mUsage = Usage{};
}

Path& Path::operator=(Path&& other) noexcept
{
    if (this != &other)
    {
        // The replaced ownership retains its nonthrowing destructor fallback.
        Path incoming(std::move(other));
        using std::swap;
        swap(mContext, incoming.mContext);
        swap(mLimits, incoming.mLimits);
        swap(mUsage, incoming.mUsage);
        mWorkAllowance.swap(incoming.mWorkAllowance);
        swap(mRootMountId, incoming.mRootMountId);
        swap(mLeafSourceMount, incoming.mLeafSourceMount);
        swap(mFrozen, incoming.mFrozen);
        swap(mAcquisitionName, incoming.mAcquisitionName);
        swap(mAcquisitionBytes, incoming.mAcquisitionBytes);
        mEntries.swap(incoming.mEntries);
        mPhysical.swap(incoming.mPhysical);
        swap(mSize, incoming.mSize);
    }
    return *this;
}

Path::~Path() noexcept
{
    if (mEntries && !mEntries->empty())
    {
        try
        {
            auto closed = Close();
            if (!closed.HasValue())
            {
                OsConfigLogError(mContext.get().GetLogHandle(), "Failed to close acquired filesystem path: %d", closed.Error().code);
            }
        }
        catch (...)
        {
            OsConfigLogError(nullptr, "Acquired path destruction close or log failure: %d", EIO);
        }
    }
}

ComplianceEngine::Result<bool> Path::Close()
{
    // Relinquish the entire path before any native close or diagnostic can
    // throw. Remaining detached pins are released by their guarded owners.
    auto entries = std::move(mEntries);
    mPhysical.clear();
    mSize = 0;
    mFrozen = false;
    mAcquisitionName.clear();
    mAcquisitionBytes = 0;
    mUsage.retainedBytes = 0;
    if (!entries)
        return true;
    int firstError = 0;
    auto release = [this, &firstError](Component& component) {
        auto closed = component.Close();
        if (!closed.HasValue())
        {
            if (firstError == 0)
            {
                firstError = closed.Error().code;
            }
            else
            {
                OsConfigLogError(mContext.get().GetLogHandle(), "Secondary filesystem pin close failure: %d", closed.Error().code);
            }
        }
    };
    for (auto entry = entries->rbegin(); entry != entries->rend(); ++entry)
    {
        release(entry->component);
    }
    if (firstError != 0)
    {
        return Error("Cannot close acquired filesystem path", firstError);
    }
    return true;
}

Optional<Error> Path::ChargeWork(std::size_t retainedHeadroom)
{
    const std::size_t chunks = (mLimits.shared.fdinfoBytes / 256) + ((mLimits.shared.fdinfoBytes % 256) ? 1 : 0);
    if (chunks > (std::numeric_limits<std::size_t>::max() - 128) / 4)
    {
        return Error("Path work budget exhausted", E2BIG);
    }
    const std::size_t cost = 128 + 4 * chunks;
    if ((mWorkAllowance->spent > mLimits.shared.work) || (cost > mLimits.shared.work - mWorkAllowance->spent))
    {
        return Error("Path work budget exhausted", E2BIG);
    }
    mWorkAllowance->spent += cost;
    if ((retainedHeadroom != 0) && ((mUsage.retainedBytes > mLimits.shared.retainedBytes) || (retainedHeadroom > mLimits.shared.retainedBytes - mUsage.retainedBytes)))
    {
        return Error("Path retained-memory budget exhausted", E2BIG);
    }
    return {};
}

std::size_t Path::HeldDescriptors() const noexcept
{
    return mEntries ? mEntries->size() : 0;
}

ComplianceEngine::Result<std::uint64_t> Path::RootMountId() const
{
    ProcfsDescriptorAccess procfs(mContext.get());
    auto opened = procfs.Open();
    if (!opened.HasValue())
    {
        return std::move(opened).Error();
    }
    const std::uint64_t mount = mEntries->front().component.Pin().mTargetMount;
    auto closed = procfs.Close();
    if (!closed.HasValue())
        return std::move(closed).Error();
    return mount;
}

ComplianceEngine::Result<Handle> Path::RetainDuplicatedLeaf(const ContextInterface& context, const ResolverLimits& limits, Detail::ResolvedPath& stage,
    const Handle& source, Descriptor& duplicate, int duplicateError)
{
    if (!duplicate.HasValue())
    {
        return Error("Cannot retain pinned directory", duplicateError);
    }
    struct stat snapshot = {};
    if (context.StatFile(duplicate, &snapshot) != 0)
    {
        return Error("Cannot inspect retained directory pin", SavedError());
    }

    if (!SameIdentity(source.AcquiredMetadata(), snapshot) || !S_ISDIR(snapshot.st_mode))
    {
        return Error("Retained directory identity changed", EAGAIN);
    }
    // Duplicate shares the held source's kernel path; it is not a new
    // filename resolution or a distinct acquired target.
    Handle candidate(std::move(duplicate), Handle::Type::Directory, snapshot, source.mFdinfoBytes, stage.mInitialMountId, source.mTargetMount);
    auto matched = Handle::RecognizeAcceptedRoot(source, candidate, limits.shared.fdinfoBytes);
    if (!matched.HasValue())
    {
        auto primary = std::move(matched).Error();
        auto closed = candidate.Close();
        if (!closed.HasValue())
        {
            Detail::LogSecondaryClose(context, closed.Error().code);
        }
        return primary;
    }

    if (!matched.Value())
    {
        const Error primary("Retained directory mount differs from its source", EAGAIN);
        auto closed = candidate.Close();
        if (!closed.HasValue())
        {
            Detail::LogSecondaryClose(context, closed.Error().code);
        }
        return primary;
    }
    return std::move(candidate);
}

ComplianceEngine::Result<Handle> Path::RetainLeaf(const ContextInterface& context, const ResolverLimits& limits, std::size_t held,
    Detail::ResolvedPath& stage, const Handle& source)
{
    if (!source.mDescriptor.HasValue() || (&source.mDescriptor.Context() != &context) || (source.mType != Handle::Type::Directory) ||
        (held > limits.shared.liveDescriptors) || (stage.OwnedDescriptors() > limits.shared.liveDescriptors - held) ||
        (limits.shared.liveDescriptors - held - stage.OwnedDescriptors() < 7))
    {
        return Error("Cannot retain borrowed directory without descriptor budget", EMFILE);
    }
    auto duplicated = context.Duplicate(source.mDescriptor);
    const int duplicateError = duplicated.HasValue() ? 0 : duplicated.Error().code;
    Descriptor duplicate = duplicated.HasValue() ? std::move(duplicated).Value() : context.EmptyDescriptor();
    auto retained = RetainDuplicatedLeaf(context, limits, stage, source, duplicate, duplicateError);
    auto closed = duplicate.Close();
    if (!closed.HasValue())
    {
        if (retained.HasValue())
        {
            return std::move(closed).Error();
        }
        Detail::LogSecondaryClose(context, closed.Error().code);
    }
    return retained;
}

std::vector<Path::NameBinding> Path::Bindings() const
{
    std::vector<NameBinding> names;
    names.reserve(mEntries->size());
    for (std::size_t index = 0; index < mEntries->size(); ++index)
    {
        const Entry& entry = (*mEntries)[index];
        names.push_back({entry.component, Name(index, true), Name(index, false), entry.component.OriginalMount()});
    }
    return names;
}

std::string Path::Name(std::size_t index, bool lookup) const
{
    if (!mEntries || index >= mEntries->size())
        throw std::logic_error("Path name has no owned pin");
    if (index == 0)
        return lookup ? mEntries->front().component.lookupName : mEntries->front().component.effectiveName;
    const Entry& entry = (*mEntries)[index];
    std::vector<std::size_t> ancestry;
    std::size_t parent = lookup ? entry.lookupParent : entry.effectiveParent;
    while (parent != 0)
    {
        if (parent >= index)
            throw std::logic_error("Path name has no held parent");
        ancestry.push_back(parent);
        index = parent;
        parent = (*mEntries)[index].effectiveParent;
    }
    std::string result = mEntries->front().component.effectiveName;
    for (auto ancestor = ancestry.rbegin(); ancestor != ancestry.rend(); ++ancestor)
        result = JoinName(result, (*mEntries)[*ancestor].component.effectiveName);
    return JoinName(result, lookup ? entry.component.lookupName : entry.component.effectiveName);
}

bool Path::Footprint(std::size_t lookup, std::size_t effective, std::size_t& bytes) noexcept
{
    bytes = sizeof(Entry);
    for (std::size_t size : {lookup, effective})
    {
        if (size > std::numeric_limits<std::size_t>::max() - bytes)
            return false;
        bytes += size;
    }
    return true;
}

bool Path::Footprint(const Entry& pin, std::size_t& bytes) noexcept
{
    return Footprint(pin.lookupLength, pin.effectiveLength, bytes);
}

ComplianceEngine::Result<bool> Path::Commit(Detail::ResolvedPath& stage, Handle leaf)
{
    if (mSize == 0)
        return Error("Cannot extend an uncommitted path", EINVAL);
    auto committed = CommitStage(stage, std::move(leaf), true);
    if (committed.HasValue())
        mSize = mPhysical.size();
    return committed;
}

ComplianceEngine::Result<bool> Path::CommitStage(Detail::ResolvedPath& stage, Handle leaf, bool logicalLeaf)
{
    // Prepare the physical selection before changing the accepted Path.
    // Old branches remain owned until a checked Pop/Close can release them;
    // closing a predecessor while committing would make a failed close
    // impossible to roll back.
    auto abort = [this, &stage, &leaf](const Error& error) -> ComplianceEngine::Result<bool> {
        const auto closedLeaf = leaf.Close();
        if (!closedLeaf.HasValue())
            Detail::LogSecondaryClose(mContext.get(), closedLeaf.Error().code);
        const auto closedStage = stage.Close(mContext.get());
        if (!closedStage.HasValue())
            Detail::LogSecondaryClose(mContext.get(), closedStage.Error().code);
        return error;
    };
    std::vector<bool> keep(stage.mPins->size(), false);
    std::vector<std::size_t> next;
    std::vector<std::size_t> stagedIndex(stage.mPins->size(), std::numeric_limits<std::size_t>::max());
    const bool physical = mSize != 0;
    for (std::size_t frame : stage.mFrames)
    {
        if (frame < mEntries->size())
        {
            if ((*mEntries)[frame].component.AcquiredType() != Handle::Type::Directory)
                return abort(Error("Invalid held staged ancestor", EINVAL));
        }
        else
        {
            const std::size_t staged = frame - mEntries->size();
            if (staged >= stage.mPins->size() || (*stage.mPins)[staged].handle.AcquiredType() != Handle::Type::Directory)
                return abort(Error("Invalid staged directory index", EINVAL));
            keep[staged] = true;
        }
    }
    std::size_t append = mEntries->size();
    for (std::size_t i = 0; i < stage.mPins->size(); ++i)
        if (keep[i] && !(stage.mLeafTaken && i == stage.mOwnedLeaf))
            stagedIndex[i] = append++;
    const std::size_t leafIndex = append;
    bool appendLeaf = true;
    if (physical)
    {
        for (std::size_t frame : stage.mFrames)
        {
            if (frame < mEntries->size())
                next.push_back(frame);
            else
            {
                const std::size_t staged = frame - mEntries->size();
                next.push_back(stage.mLeafTaken && staged == stage.mOwnedLeaf ? leafIndex : stagedIndex[staged]);
            }
        }
        if (leaf.AcquiredType() == Handle::Type::Directory && !next.empty() && next.back() != leafIndex)
            appendLeaf = false; // a held ancestor is already the physical leaf
        else if (next.empty() || next.back() != leafIndex)
            next.push_back(leafIndex);
        if (next.empty() || next.front() != 0 || next.size() > mLimits.shared.components || next.size() > mLimits.depth)
            return abort(Error("Physical component stack budget exhausted", E2BIG));
    }
    std::size_t bytes = 0;
    if (appendLeaf && !Footprint(stage.mSourceLookup.size(), stage.mEffectiveLeaf.size(), bytes))
        return abort(Error("Path entry storage exceeds retained-memory budget", E2BIG));
    for (std::size_t i = 0; i < stage.mPins->size(); ++i)
    {
        if (stage.mLeafTaken && i == stage.mOwnedLeaf)
            continue;
        if (keep[i])
        {
            std::size_t record = 0;
            if (!Footprint((*stage.mPins)[i].lookup.size(), (*stage.mPins)[i].effective.size(), record) || record > std::numeric_limits<std::size_t>::max() - bytes)
                return abort(Error("Path entry storage exceeds retained-memory budget", E2BIG));
            bytes += record;
        }
    }
    if (mUsage.retainedBytes > mLimits.shared.retainedBytes || bytes > mLimits.shared.retainedBytes - mUsage.retainedBytes)
        return abort(Error("Path entry storage exceeds retained-memory budget", E2BIG));

    struct CompactName
    {
        std::string source;
        std::string target;
        std::size_t sourceParent = 0;
        std::size_t targetParent = 0;
    };
    // Prepare all parent relationships while the staged full spellings and
    // their pinned owners still exist. Nothing can fail after moving a pin.
    auto compact = [this, &stage, &keep, &stagedIndex](const std::string& source, const std::string& target) -> ComplianceEngine::Result<CompactName> {
        CompactName name;
        auto parent = [this, &stage, &keep, &stagedIndex](const std::string& full, std::string& part) -> ComplianceEngine::Result<std::size_t> {
            const std::size_t slash = full.find_last_of('/');
            if (slash == std::string::npos || slash + 1 == full.size())
                return Error("Invalid pinned physical component spelling", EINVAL);
            part = full.substr(slash + 1);
            const std::string prefix = slash == 0 ? "/" : full.substr(0, slash);
            for (std::size_t i = 0; i < mEntries->size(); ++i)
                if ((*mEntries)[i].component.AcquiredType() == Handle::Type::Directory && Name(i, false) == prefix)
                    return i;
            for (std::size_t i = 0; i < stage.mPins->size(); ++i)
                if (keep[i] && stagedIndex[i] != std::numeric_limits<std::size_t>::max() && (*stage.mPins)[i].effective == prefix &&
                    (*stage.mPins)[i].handle.AcquiredType() == Handle::Type::Directory)
                    return stagedIndex[i];
            return Error("Missing pinned physical component parent", EXDEV);
        };
        auto sourceIndex = parent(source, name.source);
        if (!sourceIndex.HasValue())
            return std::move(sourceIndex).Error();
        name.sourceParent = sourceIndex.Value();
        auto targetIndex = parent(target, name.target);
        if (!targetIndex.HasValue())
            return std::move(targetIndex).Error();
        name.targetParent = targetIndex.Value();
        return name;
    };
    std::vector<CompactName> stagedNames(stage.mPins->size());
    for (std::size_t i = 0; i < stage.mPins->size(); ++i)
        if (keep[i] && !(stage.mLeafTaken && i == stage.mOwnedLeaf))
        {
            auto name = compact((*stage.mPins)[i].lookup, (*stage.mPins)[i].effective);
            if (!name.HasValue())
                return abort(std::move(name).Error());
            stagedNames[i] = std::move(name).Value();
        }
    CompactName leafName;
    if (appendLeaf)
    {
        auto name = compact(stage.mSourceLookup, stage.mEffectiveLeaf);
        if (!name.HasValue())
            return abort(std::move(name).Error());
        leafName = std::move(name).Value();
    }

    // Reserve all owning slots before moving any staged pin. End insertion
    // preserves existing Handle references, and a failed allocation removes
    // only empty placeholders.
    const std::size_t oldSize = mEntries->size();
    try
    {
        for (std::size_t i = oldSize; i < leafIndex + (appendLeaf ? 1U : 0U); ++i)
        {
            struct stat empty = {};
            mEntries->emplace_back(Handle(mContext.get().EmptyDescriptor(), Handle::Type::Directory, empty, mLimits.shared.fdinfoBytes, 0, 0), false);
        }
    }
    catch (...)
    {
        while (mEntries->size() > oldSize)
            mEntries->pop_back();
        throw;
    }
    auto rollbackSlots = [this, oldSize]() {
        while (mEntries->size() > oldSize)
            mEntries->pop_back();
    };
    // Close abandoned temporary branches before changing any accepted pin.
    for (std::size_t i = 0; i < stage.mPins->size(); ++i)
    {
        if (!keep[i] && !(stage.mLeafTaken && i == stage.mOwnedLeaf))
        {
            auto closed = (*stage.mPins)[i].handle.Close();
            if (!closed.HasValue())
            {
                rollbackSlots();
                return abort(std::move(closed).Error());
            }
        }
    }
    if (!appendLeaf)
    {
        auto closed = leaf.Close();
        if (!closed.HasValue())
        {
            rollbackSlots();
            return abort(std::move(closed).Error());
        }
    }
    for (std::size_t i = 0; i < stage.mPins->size(); ++i)
    {
        if (!keep[i] || (stage.mLeafTaken && i == stage.mOwnedLeaf))
            continue;
        (*mEntries)[stagedIndex[i]].component.Pin() = std::move((*stage.mPins)[i].handle);
        (*mEntries)[stagedIndex[i]].component.RefreshAcquisition();
        (*mEntries)[stagedIndex[i]].lookupLength = (*stage.mPins)[i].lookup.size();
        (*mEntries)[stagedIndex[i]].effectiveLength = (*stage.mPins)[i].effective.size();
        (*mEntries)[stagedIndex[i]].component.lookupName = std::move(stagedNames[i].source);
        (*mEntries)[stagedIndex[i]].component.effectiveName = std::move(stagedNames[i].target);
        (*mEntries)[stagedIndex[i]].lookupParent = stagedNames[i].sourceParent;
        (*mEntries)[stagedIndex[i]].effectiveParent = stagedNames[i].targetParent;
    }
    if (appendLeaf)
    {
        leaf.mOriginalMount = stage.mInitialMountId;
        (*mEntries)[leafIndex].component.Pin() = std::move(leaf);
        (*mEntries)[leafIndex].component.RefreshAcquisition();
        (*mEntries)[leafIndex].lookupLength = stage.mSourceLookup.size();
        (*mEntries)[leafIndex].effectiveLength = stage.mEffectiveLeaf.size();
        (*mEntries)[leafIndex].component.lookupName = std::move(leafName.source);
        (*mEntries)[leafIndex].component.effectiveName = std::move(leafName.target);
        (*mEntries)[leafIndex].lookupParent = leafName.sourceParent;
        (*mEntries)[leafIndex].effectiveParent = leafName.targetParent;
        (*mEntries)[leafIndex].logicalLeaf = logicalLeaf;
    }
    if (physical)
    {
        mLeafSourceMount = stage.mInitialMountId;
        mPhysical.swap(next);
    }
    mUsage.retainedBytes += bytes;
    return true;
}

ComplianceEngine::Result<bool> Path::PinProcessRoot()
{
    // The pinned sentinel owns both "/" strings and its acquisition spelling.
    mAcquisitionName = "/";
    mAcquisitionBytes = 2;
    mUsage.retainedBytes = mAcquisitionBytes;
    auto charge = ChargeWork(sizeof(Entry) + 2);
    if (charge.HasValue())
        return std::move(charge).Value();
    auto process = Handle::PinProcessRoot(mContext.get(), mLimits.shared.fdinfoBytes);
    if (!process.HasValue())
        return std::move(process).Error();
    mEntries->emplace_back(std::move(process).Value(), false, "/", "/");
    mUsage.retainedBytes += sizeof(Entry) + 2;
    mPhysical.push_back(0);
    mSize = 1;
    mRootMountId = mEntries->front().component.Pin().mTargetMount;
    mLeafSourceMount = mRootMountId;
    return true;
}

ComplianceEngine::Result<Variant<Path, Path::RejectionReason>> Path::Make(const ContextInterface& context, std::string absolutePath, Policy policy, ResolverLimits limits)
{
    auto validationResult = ValidateMakeInput(absolutePath, policy, limits);
    if (validationResult.HasValue())
    {
        return std::move(validationResult).Value();
    }

    Path path(context, limits);
    auto bootstrapped = path.PinProcessRoot();
    if (!bootstrapped.HasValue())
    {
        auto closed = path.Close();
        if (!closed.HasValue())
            Detail::LogSecondaryClose(context, closed.Error().code);
        return std::move(bootstrapped).Error();
    }
    auto acquired = path.Push(absolutePath, policy);
    if (!acquired.HasValue())
    {
        auto primary = std::move(acquired).Error();
        auto closed = path.Close();
        if (!closed.HasValue())
            OsConfigLogError(context.GetLogHandle(), "Failed to close pinned descriptors for %s: %d", absolutePath.c_str(), closed.Error().code);
        return primary;
    }
    if (acquired.Value().Is<RejectionReason>())
    {
        const auto reason = acquired.Value().Get<RejectionReason>();
        auto closed = path.Close();
        if (!closed.HasValue())
            return std::move(closed).Error();
        return Variant<Path, RejectionReason>(InPlaceType<RejectionReason>{}, reason);
    }
    return Variant<Path, RejectionReason>(InPlaceType<Path>{}, std::move(path));
}

ComplianceEngine::Result<bool> Path::FreezeRoot()
{
    if (mFrozen || mSize == 0)
        return Error("Cannot freeze an empty or already frozen path", EINVAL);
    auto charge = ChargeWork();
    if (charge.HasValue())
        return std::move(charge).Value();
    ProcfsDescriptorAccess procfs(mContext.get());
    auto opened = procfs.Open();
    if (!opened.HasValue())
        return std::move(opened).Error();
    auto helperClosed = procfs.Close();
    if (!helperClosed.HasValue())
        return std::move(helperClosed).Error();
    const std::size_t selected = mPhysical.back();
    std::string lookup = mAcquisitionName;
    std::string effective = Name(selected, false);
    const auto& pin = (*mEntries)[selected].component.Pin();
    const std::uint64_t mount = pin.mTargetMount;
    std::size_t record = 0;
    if (!Footprint(lookup.size(), effective.size(), record) || record > mLimits.shared.retainedBytes - mAcquisitionBytes)
        return Error("Acquired root name exceeds retained-memory budget", E2BIG);
    // Allocate before moving the chosen pin. Afterwards every discarded pin
    // is checked-closed; a failed close invalidates and closes the candidate.
    std::vector<std::size_t> frozenPhysical{0};
    std::deque<Entry> chosen;
    chosen.emplace_back(std::move((*mEntries)[selected]));
    std::deque<Entry> scratch;
    scratch.swap(*mEntries);
    mEntries->swap(chosen);
    int first = 0;
    for (auto item = scratch.rbegin(); item != scratch.rend(); ++item)
    {
        auto closed = item->component.Close();
        if (!closed.HasValue())
        {
            if (first == 0)
                first = closed.Error().code;
            else
                Detail::LogSecondaryClose(mContext.get(), closed.Error().code);
        }
    }
    if (first != 0)
    {
        auto closed = Close();
        if (!closed.HasValue())
            Detail::LogSecondaryClose(mContext.get(), closed.Error().code);
        return Error("Cannot close initial root-prefix scratch pins", first);
    }
    Entry& root = mEntries->front();
    root.component.lookupName = std::move(lookup);
    root.component.effectiveName = std::move(effective);
    root.lookupLength = root.component.lookupName.size();
    root.effectiveLength = root.component.effectiveName.size();
    root.lookupParent = root.effectiveParent = 0;
    root.logicalLeaf = true;
    mPhysical.swap(frozenPhysical);
    mSize = 1;
    mRootMountId = mount;
    mLeafSourceMount = mount;
    mUsage.retainedBytes = record;
    mAcquisitionBytes = 0;
    std::string().swap(mAcquisitionName);
    mFrozen = true;
    return true;
}

Path::Metadata Path::LeafMetadata() const
{
    Metadata metadata;
    metadata.accepted = Leaf().AcquiredMetadata();
    metadata.mountId = mLeafSourceMount;
    return metadata;
}

ComplianceEngine::Result<Variant<const Path&, Path::RejectionReason>> Path::Push(std::string component, ExtensionPolicy policy)
{
    std::size_t followed = 0;
    return Extend(std::move(component), policy, ExtensionMode::ChildPush, DirectoryRequirement::FileOrDirectory, followed);
}

ComplianceEngine::Result<Variant<Path, Path::RejectionReason>> Path::AcquireChild(std::string component, ExtensionPolicy policy) const&
{
    if (!IsFrozen())
        return Error("Cannot acquire from an empty or unfrozen location", EINVAL);
    // Copy only metadata and strong references to actual acquired pins. A
    // copied entry is not another descriptor and cannot revoke its parent.
    Path child(mContext.get(), mLimits);
    *child.mEntries = *mEntries;
    child.mPhysical = mPhysical;
    child.mSize = mSize;
    child.mFrozen = mFrozen;
    child.mRootMountId = mRootMountId;
    child.mLeafSourceMount = mLeafSourceMount;
    child.mUsage = mUsage;
    child.mWorkAllowance = mWorkAllowance;
    std::size_t followed = 0;
    auto acquired = child.Extend(std::move(component), policy, ExtensionMode::ChildPush, DirectoryRequirement::FileOrDirectory, followed);
    if (!acquired.HasValue())
    {
        const auto error = std::move(acquired).Error();
        auto closed = child.Close();
        if (!closed.HasValue())
            Detail::LogSecondaryClose(mContext.get(), closed.Error().code);
        return error;
    }
    if (acquired.Value().Is<RejectionReason>())
    {
        const auto reason = acquired.Value().Get<RejectionReason>();
        auto closed = child.Close();
        if (!closed.HasValue())
            return std::move(closed).Error();
        return Variant<Path, RejectionReason>(InPlaceType<RejectionReason>{}, reason);
    }
    return Variant<Path, RejectionReason>(InPlaceType<Path>{}, std::move(child));
}

ComplianceEngine::Result<Variant<const Path&, Path::RejectionReason>> Path::Push(std::string absolutePath, Policy policy)
{
    if (mFrozen || mSize != 1 || !mEntries || mEntries->size() != 1 || mPhysical.size() != 1 || mPhysical.front() != 0 || mAcquisitionName != "/")
        return Error("Absolute acquisition requires a pristine process-root sentinel", EINVAL);
    auto validation = ValidateMakeInput(absolutePath, policy, mLimits);
    if (validation.HasValue())
        return std::move(validation).Value();
    // Validate every component before reserving bytes or touching a pin.
    for (const auto& component : Ranges::PathComponents(absolutePath))
    {
        if (!Detail::IsSingleChildComponent(component))
            return Error("Root contains an invalid component", EINVAL);
    }
    // Reserve the entire supplied spelling for the operation; successful
    // prefix commits then carry their own normalized spelling if it fails.
    const std::size_t extra = absolutePath.size() - 1;
    if (mUsage.retainedBytes > mLimits.shared.retainedBytes || extra > mLimits.shared.retainedBytes - mUsage.retainedBytes)
        return Error("Path retained-memory budget exhausted", E2BIG);
    mAcquisitionBytes += extra;
    mUsage.retainedBytes += extra;
    auto settle = [this]() {
        const std::size_t used = mAcquisitionName.size() + 1;
        const std::size_t unused = mAcquisitionBytes - used;
        mUsage.retainedBytes -= unused;
        mAcquisitionBytes = used;
    };
    std::size_t followed = 0; // one counter across all components and nested expansions
    const Ranges::PathComponents components(absolutePath);
    for (auto current = components.begin(); current != components.end();)
    {
        auto nextComponent = current;
        ++nextComponent;
        const bool finalComponent = nextComponent == components.end();
        std::string component = *current;
        std::string acceptedName = JoinName(mAcquisitionName, component);
        ExtensionPolicy extension;
        extension.mounts = policy.mounts;
        extension.fileLinks = finalComponent ? policy.fileLinks : policy.symlinks;
        extension.directoryLinks = finalComponent ? policy.directoryLinks : policy.symlinks;
        extension.nonFollowedLinks = finalComponent ? policy.nonFollowedLinks : NonFollowedLinkAction::Reject;
        extension.reportMissingRegularFile = true;
        auto next = Extend(std::move(component), extension, ExtensionMode::RootAcquisition,
            (!finalComponent || absolutePath.back() == '/') ? DirectoryRequirement::DirectoryOnly : DirectoryRequirement::FileOrDirectory, followed);
        if (!next.HasValue())
        {
            settle();
            return std::move(next).Error();
        }
        if (next.Value().Is<RejectionReason>())
        {
            const auto reason = next.Value().Get<RejectionReason>();
            settle();
            return Variant<const Path&, RejectionReason>(InPlaceType<RejectionReason>{}, reason);
        }
        mAcquisitionName.swap(acceptedName);
        current = nextComponent;
    }
    mAcquisitionName = CollapseSeparators(absolutePath);
    return Variant<const Path&, RejectionReason>(InPlaceType<const Path&>{}, static_cast<const Path&>(*this));
}

ComplianceEngine::Result<Variant<const Path&, Path::RejectionReason>> Path::Extend(std::string component, ExtensionPolicy policy, ExtensionMode mode,
    DirectoryRequirement directoryRequirement, std::size_t& followed)
{
    if (mSize == 0)
    {
        return Error("Path has no accepted root", EINVAL);
    }

    auto validation = ValidateExtendInput(component, policy);
    if (validation.HasValue())
        return std::move(validation).Value();

    if ((*mEntries)[mPhysical.back()].component.AcquiredType() != Handle::Type::Directory)
    {
        return Error("Cannot extend a regular-file leaf", ENOTDIR);
    }

    if (mode == ExtensionMode::ChildPush)
    {
        auto charge = ChargeWork();
        if (charge.HasValue())
            return std::move(charge).Value();
    }
    auto baseline = RootMountId();
    if (!baseline.HasValue())
    {
        return std::move(baseline).Error();
    }

    if (mRootMountId != baseline.Value())
    {
        return Error("Accepted root mount identity changed", EAGAIN);
    }
    const std::size_t held = HeldDescriptors();
    if ((held > mLimits.shared.liveDescriptors) || (mLimits.shared.liveDescriptors - held < 7))
    {
        return Error("Path descriptor budget exhausted", EMFILE);
    }

    if (mUsage.retainedBytes >= mLimits.shared.retainedBytes)
    {
        return Error("Path retained-memory budget exhausted", E2BIG);
    }
    std::string nextAcquisitionName;
    std::size_t extra = 0;
    if (!mFrozen && mode == ExtensionMode::ChildPush)
    {
        extra = component.size() + 1;
        if (extra > mLimits.shared.retainedBytes - mUsage.retainedBytes)
            return Error("Acquisition name exceeds retained-memory budget", E2BIG);
        nextAcquisitionName = JoinName(mAcquisitionName, component);
    }
    auto resolved = Resolver(*this,
        ResolutionPolicy{FollowForClassification(policy.fileLinks, policy.directoryLinks), policy.mounts, mode == ExtensionMode::ChildPush, policy.reportMissingRegularFile,
            policy.nonFollowedLinks == NonFollowedLinkAction::Skip && policy.fileLinks == SymlinkPolicy::DoNotFollow && policy.directoryLinks == SymlinkPolicy::DoNotFollow},
        followed)
                        .Run(std::move(component));
    if (!resolved.HasValue())
    {
        return std::move(resolved).Error();
    }
    if (resolved.Value().Is<RejectionReason>())
    {
        const auto reason = resolved.Value().Get<RejectionReason>();
        if (reason == RejectionReason::UnsupportedType && policy.unsupported == UnsupportedTypeAction::Reject)
            return Error("Unsupported confined object type", EOPNOTSUPP);
        return Variant<const Path&, RejectionReason>(InPlaceType<RejectionReason>{}, reason);
    }
    Detail::ResolvedPath& step = resolved.Value().Get<Detail::ResolvedPath>();
    if (step.mInitialFollowedLink)
    {
        const SymlinkPolicy action = step.Leaf().AcquiredType() == Handle::Type::Directory ? policy.directoryLinks : policy.fileLinks;
        if (action == SymlinkPolicy::DoNotFollow)
        {
            auto cleanup = step.Close(mContext.get());
            if (!cleanup.HasValue())
            {
                return std::move(cleanup).Error();
            }
            if (policy.nonFollowedLinks == NonFollowedLinkAction::Skip)
            {
                return Variant<const Path&, RejectionReason>(InPlaceType<RejectionReason>{}, RejectionReason::Excluded);
            }
            return Error("Confined child symlink is rejected", ELOOP);
        }
    }
    if (directoryRequirement == DirectoryRequirement::DirectoryOnly && step.Leaf().AcquiredType() != Handle::Type::Directory)
    {
        auto cleanup = step.Close(mContext.get());
        if (!cleanup.HasValue())
            Detail::LogSecondaryClose(mContext.get(), cleanup.Error().code);
        return Error("Configured root component is not a directory", ENOTDIR);
    }
    const std::size_t bytes = step.AccountedBytes();
    if (bytes > mLimits.shared.retainedBytes - mUsage.retainedBytes - extra)
    {
        auto closed = step.Close(mContext.get());
        if (!closed.HasValue())
            Detail::LogSecondaryClose(mContext.get(), closed.Error().code);
        return Error("Path retained-memory budget exhausted", E2BIG);
    }
    auto committed = Commit(step, step.TakeOwnedLeaf());
    if (!committed.HasValue())
        return std::move(committed).Error();
    if (!mFrozen && mode == ExtensionMode::ChildPush)
    {
        // The acquisition spelling is retained only until FreezeRoot.
        mAcquisitionName.swap(nextAcquisitionName);
        mAcquisitionBytes += extra;
        mUsage.retainedBytes += extra;
    }
    return Variant<const Path&, RejectionReason>(InPlaceType<const Path&>{}, static_cast<const Path&>(*this));
}

ComplianceEngine::Result<Path::Component> Path::Pop()
{
    if (!IsFrozen())
    {
        return Error("Cannot pop an empty path", EINVAL);
    }
    const std::size_t selected = mPhysical.back();
    const std::size_t checkpoint = mPhysical.size() == 1 ? 0 : mPhysical[mPhysical.size() - 2] + 1;
    if (selected < checkpoint || selected >= mEntries->size())
        return Error("Invalid physical leaf index", EINVAL);
    std::size_t releasedBytes = 0;
    for (std::size_t i = checkpoint; i < mEntries->size(); ++i)
    {
        const Entry& entry = (*mEntries)[i];
        std::size_t record = 0;
        if (!Footprint(entry, record) || record > std::numeric_limits<std::size_t>::max() - releasedBytes)
            return Error("Invalid acquired leaf footprint", E2BIG);
        releasedBytes += record;
    }
    // Reserve before moving any entries. Deque end removal preserves borrows
    // of surviving ancestors; detached entries own every removed pin during
    // fallible cleanup.
    std::vector<Entry> detached;
    detached.reserve(mEntries->size() - checkpoint);
    while (mEntries->size() > checkpoint)
    {
        detached.push_back(std::move(mEntries->back()));
        mEntries->pop_back();
    }
    Component removed(std::move(detached[mEntries->size() + detached.size() - 1 - selected].component));
    mUsage.retainedBytes = releasedBytes <= mUsage.retainedBytes ? mUsage.retainedBytes - releasedBytes : 0;
    mPhysical.pop_back();
    mSize = mPhysical.size();
    mLeafSourceMount = mSize == 0 ? 0 : (mSize == 1 ? mRootMountId : Leaf().OriginalMount());
    if (mSize == 0)
        mUsage.retainedBytes = 0;
    int firstError = 0;
    for (Entry& entry : detached)
    {
        auto closed = entry.component.Close();
        if (!closed.HasValue())
        {
            if (firstError == 0)
                firstError = closed.Error().code;
            else
                Detail::LogSecondaryClose(mContext.get(), closed.Error().code);
        }
    }
    if (firstError != 0)
    {
        auto closed = removed.Close();
        if (!closed.HasValue())
            Detail::LogSecondaryClose(mContext.get(), closed.Error().code);
        return Error("Cannot close auxiliary filesystem pins after pop", firstError);
    }
    return std::move(removed);
}

std::size_t Path::RetainedDescriptors() const noexcept
{
    return HeldDescriptors();
}

std::size_t Path::RetainedBytes() const noexcept
{
    return mUsage.retainedBytes;
}

std::string Path::ToString() const
{
    if (!IsFrozen())
        throw std::logic_error("Path has no acquired effective name");
    return Name(mPhysical.back(), false);
}

Path::Component Path::Root() const
{
    if (!IsFrozen())
    {
        throw std::logic_error("Path has no accepted root");
    }
    return mEntries->front().component;
}

Path::Component Path::Leaf() const
{
    if (!IsFrozen())
    {
        throw std::logic_error("Path has no leaf");
    }
    return (*mEntries)[mPhysical.back()].component;
}

std::vector<Path::Component> Path::Components() const
{
    if (!mFrozen && mSize != 0)
        throw std::logic_error("Path components are unavailable before FreezeRoot");
    if (!IsFrozen())
        return {};
    std::vector<Component> components;
    components.reserve(mPhysical.size());
    for (std::size_t index : mPhysical)
        components.push_back((*mEntries)[index].component);
    return components;
}

std::size_t Path::Size() const noexcept
{
    return IsFrozen() ? mSize : 0;
}
} // namespace Filesystem
} // namespace ComplianceEngine
