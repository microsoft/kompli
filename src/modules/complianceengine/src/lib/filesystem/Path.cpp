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

// Simple validation of enum class to rule out int-cast values
Optional<Error> ValidatePolicy(Path::Policy const& policy)
{
    if (!ValidFollowing(policy.symlinks))
    {
        return Error("Invalid symlink policy", EINVAL);
    }

    if (!ValidFollowing(policy.fileLinks))
    {
        return Error("Invalid file link policy", EINVAL);
    }

    if (!ValidFollowing(policy.directoryLinks))
    {
        return Error("Invalid directory link policy", EINVAL);
    }

    if (!ValidNonFollowedLink(policy.nonFollowedLinks))
    {
        return Error("Invalid non-followed link policy", EINVAL);
    }

    if (((policy.mounts != MountPolicy::AllowCrossing) && (policy.mounts != MountPolicy::StayOnRootMount)))
    {
        return Error("Invalid mount policy", EINVAL);
    }

    return Optional<Error>{};
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
    Resolver(const ContextInterface& context, const Handle& root, const std::vector<const Handle*>& parentLineage, ResolutionPolicy policy,
        const ResolverLimits& limits, const std::vector<NameBinding>& names, const std::string& logicalRoot, const std::string& effectiveRoot,
        std::size_t& ledger, std::size_t& followed)
        : mContext(context),
          mRoot(root),
          mParentLineage(parentLineage),
          mPolicy(policy),
          mLimits(limits),
          mNames(names),
          mLogicalRoot(logicalRoot),
          mEffectiveRoot(effectiveRoot),
          mLedger(ledger),
          mFollowed(followed)
    {
    }

    ComplianceEngine::Result<Variant<Detail::ResolvedPath, RejectionReason>> Run(std::string component)
    {
        if (!Detail::IsSingleChildComponent(component) || mParentLineage.empty() ||
            (mPolicy.mounts != MountPolicy::AllowCrossing && mPolicy.mounts != MountPolicy::StayOnRootMount) || (mLimits.linkTargetBytes == 0) ||
            (mLimits.linkExpansions == 0) || (mLimits.depth == 0) || (mLimits.shared.targetBytes == 0) || (mLimits.shared.components == 0) ||
            (mLimits.shared.work == 0) || (mLimits.shared.liveDescriptors == 0) || (mLimits.shared.retainedBytes == 0) ||
            (mLimits.shared.fdinfoBytes == 0) || (&mRoot != mParentLineage.front()))
        {
            return Error("Invalid confined resolver input or mandatory limits", EINVAL);
        }

        if (!AddInput(&mRoot))
            return Error("Invalid or over-budget root lineage", E2BIG);
        for (const Handle* pin : mParentLineage)
        {
            if (!AddInput(pin))
            {
                return Error("Invalid or over-budget parent lineage", E2BIG);
            }
        }

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
            const std::uint64_t baseline = mRoot.mTargetMount;
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

    bool AddInput(const Handle* pin)
    {
        if ((pin == nullptr) || (pin->mType != Handle::Type::Directory) || !pin->mDescriptor.HasValue())
        {
            return false;
        }

        for (const Handle* already : mSeen)
        {
            if (pin == already)
            {
                return true;
            }
        }
        // Charge the held pin and conservative storage for the seen/lineage
        // pointers, including vector growth, before allocating another slot.
        const auto binding = std::find_if(mNames.begin(), mNames.end(), [pin](const NameBinding& name) { return name.pin == pin; });
        if (binding == mNames.end())
            return false;
        const std::size_t slot = sizeof(Handle) + 4 * sizeof(const Handle*);
        if ((mRetained > mLimits.shared.retainedBytes) || (slot > mLimits.shared.retainedBytes - mRetained) ||
            (binding->lookup.size() > mLimits.shared.retainedBytes - mRetained - slot) ||
            (binding->effective.size() > mLimits.shared.retainedBytes - mRetained - slot - binding->lookup.size()))
        {
            return false;
        }
        mSeen.push_back(pin);
        ++mInputPins;
        mRetained += slot + binding->lookup.size() + binding->effective.size();
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

    const std::string& Effective(const Handle* pin, const Detail::ResolvedPath& stage) const
    {
        for (const auto& owned : *stage.mPins)
            if (&owned.handle == pin)
                return owned.effective;
        for (const auto& binding : mNames)
            if (binding.pin == pin)
                return binding.effective;
        throw std::logic_error("Unbound acquired directory");
    }

    struct HeldMatch
    {
        const Handle* pin;
        const std::string* effective;
        std::uint64_t mount;
        bool alias;
    };

    ComplianceEngine::Result<Optional<HeldMatch>> FindHeld(const std::string& lookup, const Detail::ResolvedPath& stage) const
    {
        Optional<HeldMatch> match;
        for (const auto& binding : mNames)
        {
            if (binding.lookup != lookup && binding.effective != lookup)
                continue;
            if (match.HasValue() &&
                (!SameIdentity(match.Value().pin->AcquiredMetadata(), binding.pin->AcquiredMetadata()) || *match.Value().effective != binding.effective))
                return Error("Conflicting held name bindings", EXDEV);
            match = HeldMatch{binding.pin, &binding.effective, binding.mount, binding.lookup == lookup && binding.effective != lookup};
        }
        for (const auto& pin : *stage.mPins)
        {
            if (pin.effective != lookup || pin.handle.AcquiredType() != Handle::Type::Directory)
                continue;
            if (match.HasValue() && (!SameIdentity(match.Value().pin->AcquiredMetadata(), pin.handle.AcquiredMetadata()) || *match.Value().effective != lookup))
                return Error("Conflicting staged name bindings", EXDEV);
            match = HeldMatch{&pin.handle, &pin.effective, 0, false};
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

    ComplianceEngine::Result<bool> AdvanceDirectory(const Handle* directory, const std::string& effective, bool alias,
        std::vector<const Handle*>& directories, Detail::ResolvedPath& resolved)
    {
        if (alias)
        {
            // An alias transitions to the held physical lineage, never to
            // the lookup parent's potentially unrelated lexical lineage.
            auto lineage = PhysicalLineage(mRoot, Effective(&mRoot, resolved), *directory, effective, mNames, &resolved, mLimits.depth);
            if (!lineage.HasValue())
                return std::move(lineage).Error();
            if (mPolicy.mounts == MountPolicy::StayOnRootMount)
            {
                for (const Handle* ancestor : lineage.Value())
                {
                    if (ancestor == &mRoot)
                        continue;
                    if (ancestor->mTargetMount != mBaseline)
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

    ComplianceEngine::Result<bool> ExpandPinnedLink(const Descriptor& pin, Schedule& pending, std::vector<const Handle*>& directories,
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
            for (const std::string* binding : {&mLogicalRoot, &mEffectiveRoot})
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
            directories.assign(1, &mRoot);
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

    ComplianceEngine::Result<bool> PrepareStep(Detail::ResolvedPath& step, const std::vector<const Handle*>& directories, const Handle* leaf)
    {
        for (const Handle* directory : directories)
        {
            bool staged = false;
            for (std::size_t index = 0; index < step.mPins->size(); ++index)
            {
                if (&(*step.mPins)[index].handle == directory)
                {
                    step.mFrames.emplace_back(InPlaceType<std::size_t>{}, std::size_t(index));
                    staged = true;
                    break;
                }
            }
            if (!staged)
                step.mFrames.emplace_back(InPlaceType<const Handle*>{}, directory);
        }

        step.mEffectiveLeaf = Effective(leaf, step);
        for (std::size_t index = 0; index < step.mPins->size(); ++index)
            if (&(*step.mPins)[index].handle == leaf)
            {
                step.mOwnedLeaf = index;
                step.mAccountedBytes = mRetained;
                return true;
            }
        // A held ancestor may be the final leaf after physical "..". Pin a
        // verified independent owner before returning an accepted step.
        auto duplicated = RetainLeaf(mContext, mLimits, mInputPins, step, *leaf);
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
        Schedule& pending, std::vector<const Handle*>& directories, Detail::ResolvedPath& resolved, const Handle*& last, bool& finalDirectoryRequired,
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
        const std::size_t ownerBytes = sizeof(Handle) + 2 * lookup.size() + (S_ISDIR(snapshot.st_mode) ? 4 * sizeof(const Handle*) : 0);
        if (!CanRetain(ownerBytes))
            return Error("Confined resolution retained-memory budget exhausted", E2BIG);
        mRetained += ownerBytes;
        Handle staged(std::move(component.pin), S_ISDIR(snapshot.st_mode) ? Handle::Type::Directory : Handle::Type::RegularFile, snapshot,
            mLimits.shared.fdinfoBytes, component.mount, component.mount);
        resolved.mPins->emplace_back(std::move(staged), lookup, lookup);
        last = &resolved.mPins->back().handle;
        if (S_ISDIR(snapshot.st_mode))
        {
            auto advanced = AdvanceDirectory(last, lookup, false, directories, resolved);
            if (!advanced.HasValue())
                return std::move(advanced).Error();
        }
        return Variant<ComponentProgress, RejectionReason>(InPlaceType<ComponentProgress>{}, ComponentProgress::RetainedObject);
    }

    ComplianceEngine::Result<Variant<Detail::ResolvedPath, RejectionReason>> WalkComponents(std::string component, Detail::ResolvedPath& resolved)
    {
        auto effective = [this, &resolved](const Handle* pin) -> const std::string& { return Effective(pin, resolved); };
        if (!CanRetain(sizeof(Pending) + component.size()))
        {
            return Error("Initial resolution exceeds retained-memory budget", E2BIG);
        }
        mRetained += sizeof(Pending) + component.size();
        std::vector<const Handle*> directories(mParentLineage);
        Schedule pending;
        pending.emplace_back(std::move(component));
        const Handle* last = directories.back();
        resolved.mSourceLookup = JoinName(effective(last), pending.front().name);
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
            const std::string lookup = JoinName(effective(directories.back()), name);
            auto held = FindHeld(lookup, resolved);
            if (!held.HasValue())
                return std::move(held).Error();
            if (held.Value().HasValue() && held.Value().Value().pin->AcquiredType() == Handle::Type::Directory)
            {
                const HeldMatch& binding = held.Value().Value();
                const Handle* cached = binding.pin;
                const std::string& cachedEffective = *binding.effective;
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
                auto verified = VerifyTransitionMount(cached->mTargetMount, cachedOriginalMount, true);
                if (!verified.HasValue())
                    return std::move(verified).Error();
                if (resolvingRequestedName)
                    resolved.mInitialMountId = cachedOriginalMount != 0 ? cachedOriginalMount : cached->mTargetMount;
                if (resolvingRequestedName && cachedAlias)
                    resolved.mInitialFollowedLink = true;
                auto advanced = AdvanceDirectory(cached, cachedEffective, cachedAlias, directories, resolved);
                if (!advanced.HasValue())
                    return std::move(advanced).Error();
                resolvingRequestedName = false;
                last = cached;
                continue;
            }
            auto inspected = AcquireComponent(*directories.back(), name, HasComponent(pending), resolvingRequestedName && !HasComponent(pending));
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

        if (finalDirectoryRequired && (last->AcquiredType() != Handle::Type::Directory))
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

    const ContextInterface& mContext;
    const Handle& mRoot;
    const std::vector<const Handle*>& mParentLineage;
    ResolutionPolicy mPolicy;
    const ResolverLimits& mLimits;
    const std::vector<NameBinding>& mNames;
    const std::string& mLogicalRoot;
    const std::string& mEffectiveRoot;
    std::size_t& mLedger;
    std::size_t& mFollowed;
    std::vector<const Handle*> mSeen;
    std::size_t mInputPins = 0, mRetained = 0, mSteps = 0;
    std::size_t mFrameDepth = 1;
    std::uint64_t mBaseline = 0;
};

ComplianceEngine::Result<Variant<Detail::ResolvedPath, Path::RejectionReason>> Path::ResolveChild(const ContextInterface& context, const Handle& root,
    const std::vector<const Handle*>& parentLineage, std::string component, ResolutionPolicy policy, const ResolverLimits& limits,
    const std::vector<NameBinding>& names, const std::string& logicalRoot, const std::string& effectiveRoot, std::size_t& ledger, std::size_t& followed)
{
    return Resolver(context, root, parentLineage, policy, limits, names, logicalRoot, effectiveRoot, ledger, followed).Run(std::move(component));
}

Path::Path(const ContextInterface& context, ResolverLimits limits)
    : mContext(context),
      mLimits(limits),
      mEntries(new std::deque<Entry>())
{
}

Path::Path(Path&& other) noexcept
    : mContext(other.mContext),
      mLimits(other.mLimits),
      mUsage(other.mUsage),
      mRootMountId(other.mRootMountId),
      mLeafSourceMount(other.mLeafSourceMount),
      mFrozen(other.mFrozen),
      mAcquisitionName(std::move(other.mAcquisitionName)),
      mAcquisitionBytes(other.mAcquisitionBytes),
      mEntries(std::move(other.mEntries)),
      mPhysical(std::move(other.mPhysical)),
      mSize(other.mSize),
      mNextGeneration(other.mNextGeneration)
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
        swap(mRootMountId, incoming.mRootMountId);
        swap(mLeafSourceMount, incoming.mLeafSourceMount);
        swap(mFrozen, incoming.mFrozen);
        swap(mAcquisitionName, incoming.mAcquisitionName);
        swap(mAcquisitionBytes, incoming.mAcquisitionBytes);
        mEntries.swap(incoming.mEntries);
        mPhysical.swap(incoming.mPhysical);
        swap(mSize, incoming.mSize);
        swap(mNextGeneration, incoming.mNextGeneration);
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
    auto release = [this, &firstError](Handle& pin) {
        auto closed = pin.Close();
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
        release(entry->pin);
    }
    if (firstError != 0)
    {
        return Error("Cannot close acquired filesystem path", firstError);
    }
    return true;
}

Path::Restoration Path::Capture() const
{
    Restoration point;
    if (!IsFrozen())
        return point;
    point.physical = mPhysical;
    point.owner = mEntries.get();
    point.generations.reserve(mPhysical.size());
    for (std::size_t index : mPhysical)
        point.generations.push_back((*mEntries)[index].generation);
    return point;
}

ComplianceEngine::Result<Handle> Path::DuplicateLeaf() const
{
    if (!IsFrozen())
        return Error("Cannot retain an empty physical leaf", EINVAL);
    const Handle& source = Leaf();
    auto duplicated = mContext.get().Duplicate(source.mDescriptor);
    if (!duplicated.HasValue())
        return std::move(duplicated).Error();
    Detail::Descriptor pin = std::move(duplicated).Value();
    struct stat snapshot = {};
    const int inspection = mContext.get().StatFile(pin, &snapshot);
    if (inspection != 0 || !SameIdentity(snapshot, source.mAcquiredMetadata))
    {
        const int error = inspection != 0 ? (errno ? errno : EIO) : EAGAIN;
        auto closed = pin.Close();
        if (!closed.HasValue())
            Detail::LogSecondaryClose(mContext.get(), closed.Error().code);
        return Error("Cannot verify retained physical leaf", error);
    }
    return Handle(std::move(pin), source.mType, snapshot, source.mFdinfoBytes, mLeafSourceMount, source.mTargetMount);
}

ComplianceEngine::Result<bool> Path::Restore(Restoration previous)
{
    if (!IsFrozen() || previous.physical.empty() || !mEntries || previous.owner != mEntries.get() || previous.physical.front() != 0 ||
        previous.generations.size() != previous.physical.size() || previous.physical.back() >= mEntries->size())
        return Error("Invalid held physical restoration point", EINVAL);
    for (std::size_t i = 0; i < previous.physical.size(); ++i)
        if ((i != 0 && previous.physical[i] <= previous.physical[i - 1]) || (*mEntries)[previous.physical[i]].generation != previous.generations[i] ||
            (*mEntries)[previous.physical[i]].pin.AcquiredType() != Handle::Type::Directory)
            return Error("Stale held physical restoration point", EINVAL);
    const std::size_t kept = previous.physical.back() + 1;
    mPhysical.swap(previous.physical);
    mSize = mPhysical.size();
    mLeafSourceMount = mSize == 1 ? mRootMountId : Leaf().OriginalMount();
    int first = 0;
    while (mEntries->size() > kept)
    {
        Entry& entry = mEntries->back();
        std::size_t bytes = 0;
        if (Footprint(entry, bytes) && bytes <= mUsage.retainedBytes)
            mUsage.retainedBytes -= bytes;
        auto closed = entry.pin.Close();
        if (!closed.HasValue())
        {
            if (first == 0)
                first = closed.Error().code;
            else
                Detail::LogSecondaryClose(mContext.get(), closed.Error().code);
        }
        mEntries->pop_back();
    }
    return first ? Result<bool>(Error("Cannot close retired physical pins", first)) : Result<bool>(true);
}

bool Path::ChargeWork() noexcept
{
    const std::size_t chunks = (mLimits.shared.fdinfoBytes / 256) + ((mLimits.shared.fdinfoBytes % 256) ? 1 : 0);
    if (chunks > (std::numeric_limits<std::size_t>::max() - 128) / 4)
    {
        return false;
    }
    const std::size_t cost = 128 + 4 * chunks;
    if ((mUsage.workSpent > mLimits.shared.work) || (cost > mLimits.shared.work - mUsage.workSpent))
    {
        return false;
    }
    mUsage.workSpent += cost;
    return true;
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
    const std::uint64_t mount = mEntries->front().pin.mTargetMount;
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
        names.push_back({&entry.pin, Name(index, true), Name(index, false), entry.pin.OriginalMount()});
    }
    return names;
}

std::string Path::Name(std::size_t index, bool lookup) const
{
    if (!mEntries || index >= mEntries->size())
        throw std::logic_error("Path name has no owned pin");
    if (index == 0)
        return lookup ? mEntries->front().lookupPart : mEntries->front().effectivePart;
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
    std::string result = mEntries->front().effectivePart;
    for (auto ancestor = ancestry.rbegin(); ancestor != ancestry.rend(); ++ancestor)
        result = JoinName(result, (*mEntries)[*ancestor].effectivePart);
    return JoinName(result, lookup ? entry.lookupPart : entry.effectivePart);
}

ComplianceEngine::Result<std::vector<const Handle*>> Path::PhysicalLineage(const Handle& root, const std::string& rootName, const Handle& target,
    const std::string& targetName, const std::vector<NameBinding>& names, const Detail::ResolvedPath* stage, std::size_t depth)
{
    if (root.AcquiredType() != Handle::Type::Directory || target.AcquiredType() != Handle::Type::Directory || !AtBoundary(targetName, rootName))
        return Error("Acquired directory outside physical root", EXDEV);
    std::vector<const Handle*> pins{&root};
    std::size_t start = rootName == "/" ? 1 : rootName.size() + 1;
    while (start < targetName.size())
    {
        const std::size_t slash = targetName.find('/', start);
        const std::string prefix = targetName.substr(0, slash);
        const Handle* selected = nullptr;
        auto consider = [&](const Handle& pin) -> bool {
            if (selected != nullptr && !SameIdentity(selected->AcquiredMetadata(), pin.AcquiredMetadata()))
                return false;
            selected = &pin;
            return true;
        };
        for (const NameBinding& binding : names)
        {
            if (binding.effective != prefix || binding.pin->AcquiredType() != Handle::Type::Directory)
                continue;
            if (!consider(*binding.pin))
                return Error("Conflicting held physical ancestors", EXDEV);
        }
        if (stage != nullptr)
            for (const auto& pin : *stage->mPins)
                if (pin.effective == prefix && pin.handle.AcquiredType() == Handle::Type::Directory && !consider(pin.handle))
                    return Error("Conflicting staged physical ancestors", EXDEV);
        if (prefix == targetName)
            selected = &target;
        if (selected == nullptr)
            return Error("Missing acquired physical ancestor", EXDEV);
        if (pins.size() >= depth)
            return Error("Held physical ancestor exceeds depth budget", E2BIG);
        pins.push_back(selected);
        if (slash == std::string::npos)
            break;
        start = slash + 1;
    }
    return pins;
}

ComplianceEngine::Result<std::vector<const Handle*>> Path::Lineage(std::size_t index) const
{
    if (mSize != 0)
    {
        std::vector<const Handle*> pins;
        pins.reserve(mPhysical.size());
        for (std::size_t entry : mPhysical)
            pins.push_back(&(*mEntries)[entry].pin);
        return pins;
    }
    if (!mEntries || index >= mEntries->size())
        return Error("Invalid acquired directory boundary", EINVAL);
    return PhysicalLineage(mEntries->front().pin, mEntries->front().effectivePart, (*mEntries)[index].pin, Name(index, false), Bindings(), nullptr,
        std::numeric_limits<std::size_t>::max());
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
    for (const auto& frame : stage.mFrames)
    {
        if (frame.Is<std::size_t>())
        {
            if (frame.Get<std::size_t>() >= stage.mPins->size())
                return abort(Error("Invalid staged directory index", EINVAL));
            keep[frame.Get<std::size_t>()] = true;
        }
        else if (frame.Get<const Handle*>() == nullptr ||
                 std::none_of(mEntries->begin(), mEntries->end(), [&frame](const Entry& entry) { return &entry.pin == frame.Get<const Handle*>(); }))
            return abort(Error("Invalid borrowed staged ancestor", EINVAL));
    }
    std::size_t append = mEntries->size();
    for (std::size_t i = 0; i < stage.mPins->size(); ++i)
        if (keep[i] && !(stage.mLeafTaken && i == stage.mOwnedLeaf))
            stagedIndex[i] = append++;
    const std::size_t leafIndex = append;
    bool appendLeaf = true;
    if (physical)
    {
        for (const auto& frame : stage.mFrames)
        {
            if (frame.Is<std::size_t>())
            {
                const std::size_t index = frame.Get<std::size_t>();
                next.push_back(stage.mLeafTaken && index == stage.mOwnedLeaf ? leafIndex : stagedIndex[index]);
            }
            else
            {
                const Handle* held = frame.Get<const Handle*>();
                auto found = std::find_if(mEntries->begin(), mEntries->end(), [held](const Entry& entry) { return &entry.pin == held; });
                next.push_back(static_cast<std::size_t>(found - mEntries->begin()));
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
                if ((*mEntries)[i].pin.AcquiredType() == Handle::Type::Directory && Name(i, false) == prefix)
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
            mEntries->back().generation = mNextGeneration++;
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
        (*mEntries)[stagedIndex[i]].pin = std::move((*stage.mPins)[i].handle);
        (*mEntries)[stagedIndex[i]].lookupLength = (*stage.mPins)[i].lookup.size();
        (*mEntries)[stagedIndex[i]].effectiveLength = (*stage.mPins)[i].effective.size();
        (*mEntries)[stagedIndex[i]].lookupPart = std::move(stagedNames[i].source);
        (*mEntries)[stagedIndex[i]].effectivePart = std::move(stagedNames[i].target);
        (*mEntries)[stagedIndex[i]].lookupParent = stagedNames[i].sourceParent;
        (*mEntries)[stagedIndex[i]].effectiveParent = stagedNames[i].targetParent;
    }
    if (appendLeaf)
    {
        leaf.mOriginalMount = stage.mInitialMountId;
        (*mEntries)[leafIndex].pin = std::move(leaf);
        (*mEntries)[leafIndex].lookupLength = stage.mSourceLookup.size();
        (*mEntries)[leafIndex].effectiveLength = stage.mEffectiveLeaf.size();
        (*mEntries)[leafIndex].lookupPart = std::move(leafName.source);
        (*mEntries)[leafIndex].effectivePart = std::move(leafName.target);
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

ComplianceEngine::Result<Optional<Path::RejectionReason>> Path::AcquireInitialRoot(Path& path, const std::string& rootName, const Policy& policy)
{
    const ContextInterface& context = path.mContext.get();
    const ResolverLimits& limits = path.mLimits;
    path.mUsage.retainedBytes = rootName.size() + 1;
    path.mAcquisitionBytes = rootName.size() + 1;
    if (!path.ChargeWork())
    {
        return Error("Root acquisition work budget exhausted", E2BIG);
    }
    if (path.mUsage.retainedBytes > limits.shared.retainedBytes || sizeof(Entry) + 1 > limits.shared.retainedBytes - path.mUsage.retainedBytes)
        return Error("Process root exceeds retained-memory budget", E2BIG);
    auto process = Handle::PinProcessRoot(context, limits.shared.fdinfoBytes);
    if (!process.HasValue())
    {
        return std::move(process).Error();
    }

    const bool hasComponent = rootName.find_first_not_of('/') != std::string::npos;
    path.mEntries->emplace_back(std::move(process).Value(), false, "/", "/");
    path.mEntries->back().generation = path.mNextGeneration++;
    path.mUsage.retainedBytes += sizeof(Entry) + 2;
    path.mPhysical.push_back(0);
    path.mSize = 1;
    path.mRootMountId = path.mEntries->front().pin.mTargetMount;
    path.mLeafSourceMount = path.mRootMountId;
    std::size_t followed = 0; // one counter for all Make components and nested expansions
    if (hasComponent)
    {
        for (std::size_t position = 1; position < rootName.size();)
        {
            const std::size_t slash = rootName.find('/', position);
            const std::size_t end = (slash == std::string::npos) ? rootName.size() : slash;
            const std::string component = rootName.substr(position, end - position);
            if (component.empty())
            {
                position = end + 1;
                continue;
            }
            if (!Detail::IsSingleChildComponent(component))
            {
                return Error("Root contains an invalid component", EINVAL);
            }

            const bool finalComponent = (rootName.find_first_not_of('/', end) == std::string::npos);
            ExtensionPolicy extension;
            extension.mounts = policy.mounts;
            extension.fileLinks = finalComponent ? policy.fileLinks : policy.symlinks;
            extension.directoryLinks = finalComponent ? policy.directoryLinks : policy.symlinks;
            extension.nonFollowedLinks = finalComponent ? policy.nonFollowedLinks : NonFollowedLinkAction::Reject;
            extension.reportMissingRegularFile = true;
            auto next = path.Extend(component, extension, true, !finalComponent || rootName.back() == '/', followed);
            if (!next.HasValue())
                return std::move(next).Error();
            if (next.Value().Is<RejectionReason>())
                return Optional<RejectionReason>(next.Value().Get<RejectionReason>());
            position = (slash == std::string::npos) ? rootName.size() : slash + 1;
        }
    }
    path.mAcquisitionName = CollapseSeparators(rootName);
    return Optional<RejectionReason>{};
}

ComplianceEngine::Result<Variant<Path, Path::RejectionReason>> Path::Make(const ContextInterface& context, std::string absolutePath, Policy policy, ResolverLimits limits)
{
    auto validationResult = ValidateMakeInput(absolutePath, policy, limits);
    if (validationResult.HasValue())
    {
        return std::move(validationResult).Value();
    }

    Path path(context, limits);
    const std::string& rootName = absolutePath;
    auto acquired = AcquireInitialRoot(path, rootName, policy);
    if (!acquired.HasValue() || acquired.Value().HasValue())
    {
        Optional<Error> primary;
        if (!acquired.HasValue())
        {
            primary = std::move(acquired).Error();
        }
        auto closed = path.Close();
        if (!closed.HasValue())
        {
            if (!primary.HasValue())
            {
                return std::move(closed).Error();
            }
            OsConfigLogError(context.GetLogHandle(), "Failed to close pinned descriptors for %s: %d", rootName.c_str(), closed.Error().code);
        }
        if (primary.HasValue())
        {
            return std::move(primary.Value());
        }
        return Variant<Path, RejectionReason>(InPlaceType<RejectionReason>{}, acquired.Value().Value());
    }
    return Variant<Path, RejectionReason>(InPlaceType<Path>{}, std::move(path));
}

ComplianceEngine::Result<bool> Path::FreezeRoot()
{
    if (mFrozen || mSize == 0)
        return Error("Cannot freeze an empty or already frozen path", EINVAL);
    if (!ChargeWork())
        return Error("Root mount-inspection work budget exhausted", E2BIG);
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
    const auto& pin = (*mEntries)[selected].pin;
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
        auto closed = item->pin.Close();
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
    root.lookupPart = std::move(lookup);
    root.effectivePart = std::move(effective);
    root.lookupLength = root.lookupPart.size();
    root.effectiveLength = root.effectivePart.size();
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
    return Extend(std::move(component), policy, false, false, followed);
}

ComplianceEngine::Result<Variant<const Path&, Path::RejectionReason>> Path::Extend(std::string component, ExtensionPolicy policy, bool acquisition,
    bool requireDirectory, std::size_t& followed)
{
    if (mSize == 0)
    {
        return Error("Path has no accepted root", EINVAL);
    }

    if (!Detail::IsSingleChildComponent(component) || (policy.mounts != MountPolicy::AllowCrossing && policy.mounts != MountPolicy::StayOnRootMount) ||
        !ValidFollowing(policy.fileLinks) || !ValidFollowing(policy.directoryLinks) || !ValidNonFollowedLink(policy.nonFollowedLinks))
    {
        return Error("Invalid child component or extension policy", EINVAL);
    }

    if ((policy.unsupported != UnsupportedTypeAction::Reject) && (policy.unsupported != UnsupportedTypeAction::Skip))
    {
        return Error("Invalid unsupported type action", EINVAL);
    }

    if ((*mEntries)[mPhysical.back()].pin.AcquiredType() != Handle::Type::Directory)
    {
        return Error("Cannot extend a regular-file leaf", ENOTDIR);
    }

    if (!acquisition && !ChargeWork())
    {
        return Error("Path work budget exhausted", E2BIG);
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
    ResolverLimits available = mLimits;
    auto lineage = Lineage(mPhysical.back());
    if (!lineage.HasValue())
        return std::move(lineage).Error();
    std::vector<const Handle*> parentLineage = std::move(lineage).Value();
    // The logical root can be reached through aliases: its physical parents
    // are not themselves a permitted ".." escape from the accepted boundary.
    const Handle& gate = mEntries->front().pin;
    auto boundary = std::find(parentLineage.begin(), parentLineage.end(), &gate);
    if (boundary == parentLineage.end())
        return Error("Accepted root is absent from physical ancestry", EINVAL);
    parentLineage.erase(parentLineage.begin(), boundary);
    std::vector<const Handle*> unique{&gate};
    for (const Handle* pin : parentLineage)
    {
        if (unique.end() == std::find(unique.begin(), unique.end(), pin))
        {
            unique.push_back(pin);
        }
    }
    available.shared.liveDescriptors -= held - unique.size();
    available.shared.retainedBytes -= mUsage.retainedBytes;
    auto names = Bindings();
    std::string nextAcquisitionName;
    std::size_t extra = 0;
    if (!mFrozen && !acquisition)
    {
        extra = component.size() + 1;
        if (extra > mLimits.shared.retainedBytes - mUsage.retainedBytes)
            return Error("Acquisition name exceeds retained-memory budget", E2BIG);
        nextAcquisitionName = JoinName(mAcquisitionName, component);
        available.shared.retainedBytes -= extra;
    }
    auto resolved = ResolveChild(mContext.get(), gate, parentLineage, component,
        ResolutionPolicy{FollowForClassification(policy.fileLinks, policy.directoryLinks), policy.mounts, !acquisition, policy.reportMissingRegularFile,
            policy.nonFollowedLinks == NonFollowedLinkAction::Skip && policy.fileLinks == SymlinkPolicy::DoNotFollow && policy.directoryLinks == SymlinkPolicy::DoNotFollow},
        available, names, mEntries->front().lookupPart, mEntries->front().effectivePart, mUsage.workSpent, followed);
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
    if (requireDirectory && step.Leaf().AcquiredType() != Handle::Type::Directory)
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
    if (!mFrozen && !acquisition)
    {
        // The acquisition spelling is retained only until FreezeRoot.
        mAcquisitionName.swap(nextAcquisitionName);
        mAcquisitionBytes += extra;
        mUsage.retainedBytes += extra;
    }
    return Variant<const Path&, RejectionReason>(InPlaceType<const Path&>{}, static_cast<const Path&>(*this));
}

ComplianceEngine::Result<Handle> Path::Pop()
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
    Handle removed(std::move(detached[mEntries->size() + detached.size() - 1 - selected].pin));
    mUsage.retainedBytes = releasedBytes <= mUsage.retainedBytes ? mUsage.retainedBytes - releasedBytes : 0;
    mPhysical.pop_back();
    mSize = mPhysical.size();
    mLeafSourceMount = mSize == 0 ? 0 : (mSize == 1 ? mRootMountId : Leaf().OriginalMount());
    if (mSize == 0)
        mUsage.retainedBytes = 0;
    int firstError = 0;
    for (Entry& entry : detached)
    {
        auto closed = entry.pin.Close();
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

const Handle& Path::Root() const
{
    if (!IsFrozen())
    {
        throw std::logic_error("Path has no accepted root");
    }
    return mEntries->front().pin;
}

const Handle& Path::Leaf() const
{
    if (!IsFrozen())
    {
        throw std::logic_error("Path has no leaf");
    }
    return (*mEntries)[mPhysical.back()].pin;
}

std::size_t Path::Size() const noexcept
{
    return IsFrozen() ? mSize : 0;
}
} // namespace Filesystem
} // namespace ComplianceEngine
