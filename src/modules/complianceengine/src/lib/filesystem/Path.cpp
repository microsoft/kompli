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
        const ResolverLimits& limits, const std::vector<NameBinding>& names, const std::string& logicalRoot, const std::string& effectiveRoot, std::size_t& ledger)
        : mContext(context),
          mRoot(root),
          mParentLineage(parentLineage),
          mPolicy(policy),
          mLimits(limits),
          mNames(names),
          mLogicalRoot(logicalRoot),
          mEffectiveRoot(effectiveRoot),
          mLedger(ledger)
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
        const std::size_t slot = sizeof(Handle) + 4 * sizeof(const Handle*);
        if ((mRetained > mLimits.shared.retainedBytes) || (slot > mLimits.shared.retainedBytes - mRetained) ||
            (pin->LookupName().size() > mLimits.shared.retainedBytes - mRetained - slot) ||
            (pin->EffectiveName().size() > mLimits.shared.retainedBytes - mRetained - slot - pin->LookupName().size()))
        {
            return false;
        }
        mSeen.push_back(pin);
        ++mInputPins;
        mRetained += slot + pin->LookupName().size() + pin->EffectiveName().size();
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
                return owned.handle.EffectiveName();
        for (const auto& binding : mNames)
            if (binding.pin == pin)
                return *binding.effective;
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
            if (*binding.lookup != lookup && *binding.effective != lookup)
                continue;
            if (match.HasValue() &&
                (!SameIdentity(match.Value().pin->AcquiredMetadata(), binding.pin->AcquiredMetadata()) || *match.Value().effective != *binding.effective))
                return Error("Conflicting held name bindings", EXDEV);
            match = HeldMatch{binding.pin, binding.effective, binding.mount, *binding.lookup == lookup && *binding.effective != lookup};
        }
        for (const auto& pin : *stage.mPins)
        {
            if (pin.handle.EffectiveName() != lookup || pin.handle.AcquiredType() != Handle::Type::Directory)
                continue;
            if (match.HasValue() && (!SameIdentity(match.Value().pin->AcquiredMetadata(), pin.handle.AcquiredMetadata()) || *match.Value().effective != lookup))
                return Error("Conflicting staged name bindings", EXDEV);
            match = HeldMatch{&pin.handle, &pin.handle.EffectiveName(), 0, false};
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

    ComplianceEngine::Result<bool> ExpandPinnedLink(const Descriptor& pin, std::deque<std::string>& pending, std::vector<const Handle*>& directories,
        bool& finalDirectoryRequired, std::uint64_t observedMount)
    {
        auto target = Detail::ReadPinnedLink(pin, mLimits.linkTargetBytes, mLimits.shared.fdinfoBytes);
        if (!target.HasValue())
            return std::move(target).Error();
        if (target.Value().mountId != observedMount || !CanRetain(target.Value().text.size()))
            return Error("Symlink changed mount or exhausted retained-memory budget", E2BIG);
        mRetained += target.Value().text.size();
        std::string text = std::move(target).Value().text;
        if (text.back() == '/' && pending.empty())
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
        std::deque<std::string> expanded;
        std::size_t start = 0;
        while (start < text.size())
        {
            const std::size_t slash = text.find('/', start);
            const std::size_t end = slash == std::string::npos ? text.size() : slash;
            if (end != start)
            {
                if (!CanRetain(sizeof(std::string) + end - start))
                    return Error("Symlink expansion exceeds retained-memory budget", E2BIG);
                mRetained += sizeof(std::string) + end - start;
                expanded.emplace_back(text.substr(start, end - start));
            }
            start = end + 1;
        }
        while (!pending.empty())
        {
            expanded.emplace_back(std::move(pending.front()));
            pending.pop_front();
        }
        pending.swap(expanded);
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
        std::deque<std::string>& pending, std::vector<const Handle*>& directories, Detail::ResolvedPath& resolved, const Handle*& last,
        std::size_t& expansions, bool& finalDirectoryRequired, bool& resolvingRequestedName)
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
                if (mPolicy.excludeLinks && resolvingRequestedName && pending.empty())
                    return Variant<ComponentProgress, RejectionReason>(InPlaceType<RejectionReason>{}, RejectionReason::Excluded);
                return Error("Descendant symlink following is disabled", ELOOP);
            }
            if (++expansions > mLimits.linkExpansions)
                return Error("Symlink expansion budget exhausted", ELOOP);
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
            if (mPolicy.permitUnsupported && pending.empty())
                return Variant<ComponentProgress, RejectionReason>(InPlaceType<RejectionReason>{}, RejectionReason::UnsupportedType);
            return Error("Unsupported confined object type", EOPNOTSUPP);
        }
        if ((!pending.empty()) && !S_ISDIR(snapshot.st_mode))
            return Error("Intermediate component is not a directory", ENOTDIR);

        // Full effective spellings cost O(depth squared) across staged pins.
        const std::size_t ownerBytes = sizeof(Handle) + 2 * lookup.size() + (S_ISDIR(snapshot.st_mode) ? 4 * sizeof(const Handle*) : 0);
        if (!CanRetain(ownerBytes))
            return Error("Confined resolution retained-memory budget exhausted", E2BIG);
        mRetained += ownerBytes;
        Handle staged(std::move(component.pin), S_ISDIR(snapshot.st_mode) ? Handle::Type::Directory : Handle::Type::RegularFile, snapshot,
            mLimits.shared.fdinfoBytes, lookup, lookup, component.mount, component.mount);
        resolved.mPins->emplace_back(std::move(staged));
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
        if (!CanRetain(sizeof(std::string) + component.size()))
        {
            return Error("Initial resolution exceeds retained-memory budget", E2BIG);
        }
        mRetained += sizeof(std::string) + component.size();
        std::vector<const Handle*> directories(mParentLineage);
        std::deque<std::string> pending;
        pending.emplace_back(std::move(component));
        const Handle* last = directories.back();
        resolved.mSourceLookup = JoinName(effective(last), pending.front());
        std::size_t expansions = 0;
        bool finalDirectoryRequired = false;
        // This is the original requested name, not the first loop iteration:
        // link-expanded names do not qualify for direct-name Missing/Excluded.
        bool resolvingRequestedName = true;
        while (!pending.empty())
        {
            if (!Charge())
            {
                return Error("Confined resolution work budget exhausted", E2BIG);
            }
            std::string name = std::move(pending.front());
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
                    if (mPolicy.excludeLinks && resolvingRequestedName && pending.empty())
                        return Variant<Detail::ResolvedPath, RejectionReason>(InPlaceType<RejectionReason>{}, RejectionReason::Excluded);
                    return Error("Descendant symlink following is disabled", ELOOP);
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
            auto inspected = AcquireComponent(*directories.back(), name, !pending.empty(), resolvingRequestedName && pending.empty());
            if (!inspected.HasValue())
                return std::move(inspected).Error();
            if (inspected.Value().Is<RejectionReason>())
            {
                return Variant<Detail::ResolvedPath, RejectionReason>(InPlaceType<RejectionReason>{}, inspected.Value().Get<RejectionReason>());
            }
            Inspected& component = inspected.Value().Get<Inspected>();
            Descriptor& acquired = component.pin;
            auto step = ProcessAcquiredComponent(component, lookup, pending, directories, resolved, last, expansions, finalDirectoryRequired, resolvingRequestedName);
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
    std::vector<const Handle*> mSeen;
    std::size_t mInputPins = 0, mRetained = 0, mSteps = 0;
    std::uint64_t mBaseline = 0;
};

ComplianceEngine::Result<Variant<Detail::ResolvedPath, Path::RejectionReason>> Path::ResolveChild(const ContextInterface& context, const Handle& root,
    const std::vector<const Handle*>& parentLineage, std::string component, ResolutionPolicy policy, const ResolverLimits& limits,
    const std::vector<NameBinding>& names, const std::string& logicalRoot, const std::string& effectiveRoot, std::size_t& ledger)
{
    return Resolver(context, root, parentLineage, policy, limits, names, logicalRoot, effectiveRoot, ledger).Run(std::move(component));
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
      mEntries(std::move(other.mEntries)),
      mSize(other.mSize)
{
    other.mSize = 0;
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
        mEntries.swap(incoming.mEntries);
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
    mSize = 0;
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
    const std::uint64_t mount = Root().mTargetMount;
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
    Handle candidate(std::move(duplicate), Handle::Type::Directory, snapshot, source.mFdinfoBytes, stage.mSourceLookup, stage.mEffectiveLeaf,
        stage.mInitialMountId, source.mTargetMount);
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
    for (const Entry& entry : *mEntries)
        names.push_back({&entry.pin, &entry.pin.LookupName(), &entry.pin.EffectiveName(), entry.pin.OriginalMount()});
    return names;
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
            if (*binding.effective != prefix || binding.pin->AcquiredType() != Handle::Type::Directory)
                continue;
            if (!consider(*binding.pin))
                return Error("Conflicting held physical ancestors", EXDEV);
        }
        if (stage != nullptr)
            for (const auto& pin : *stage->mPins)
                if (pin.handle.EffectiveName() == prefix && pin.handle.AcquiredType() == Handle::Type::Directory && !consider(pin.handle))
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
    if (!mEntries || index >= mEntries->size())
        return Error("Invalid acquired directory boundary", EINVAL);
    return PhysicalLineage(mEntries->front().pin, mEntries->front().pin.EffectiveName(), (*mEntries)[index].pin, (*mEntries)[index].pin.EffectiveName(),
        Bindings(), nullptr, std::numeric_limits<std::size_t>::max());
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

bool Path::Footprint(const Handle& pin, std::size_t& bytes) noexcept
{
    return Footprint(pin.LookupName().size(), pin.EffectiveName().size(), bytes);
}

ComplianceEngine::Result<bool> Path::Commit(Detail::ResolvedPath& stage, Handle leaf)
{
    if (mSize == 0)
        return Error("Cannot extend an uncommitted path", EINVAL);
    auto committed = CommitStage(stage, std::move(leaf), true);
    if (committed.HasValue())
        ++mSize;
    return committed;
}

ComplianceEngine::Result<bool> Path::CommitScratch(Detail::ResolvedPath& stage, Handle leaf)
{
    if (mSize != 0)
        return Error("Cannot append scratch to an accepted path", EINVAL);
    return CommitStage(stage, std::move(leaf), false);
}

ComplianceEngine::Result<bool> Path::CommitStage(Detail::ResolvedPath& stage, Handle leaf, bool logicalLeaf)
{
    // Keep only directories in the final physical ancestry. Previous logical
    // steps remain owned until their own Pop, even if a link branched away.
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
    std::size_t bytes = 0;
    if (!Footprint(stage.mSourceLookup.size(), stage.mEffectiveLeaf.size(), bytes))
        return abort(Error("Path entry storage exceeds retained-memory budget", E2BIG));
    for (std::size_t i = 0; i < stage.mPins->size(); ++i)
    {
        if (stage.mLeafTaken && i == stage.mOwnedLeaf)
            continue;
        if (keep[i])
        {
            std::size_t record = 0;
            if (!Footprint((*stage.mPins)[i].handle, record) || record > std::numeric_limits<std::size_t>::max() - bytes)
                return abort(Error("Path entry storage exceeds retained-memory budget", E2BIG));
            bytes += record;
        }
    }
    if (mUsage.retainedBytes > mLimits.shared.retainedBytes || bytes > mLimits.shared.retainedBytes - mUsage.retainedBytes)
        return abort(Error("Path entry storage exceeds retained-memory budget", E2BIG));

    // Close abandoned temporary branches before changing the accepted
    // Path. A failure leaves every existing borrow and index untouched.
    for (std::size_t i = 0; i < stage.mPins->size(); ++i)
    {
        if (!keep[i] && !(stage.mLeafTaken && i == stage.mOwnedLeaf))
        {
            auto closed = (*stage.mPins)[i].handle.Close();
            if (!closed.HasValue())
                return abort(std::move(closed).Error());
        }
    }
    for (std::size_t i = 0; i < stage.mPins->size(); ++i)
    {
        if (!keep[i] || (stage.mLeafTaken && i == stage.mOwnedLeaf))
            continue;
        mEntries->emplace_back(std::move((*stage.mPins)[i].handle), false);
    }
    // The logical leaf can be a duplicated ancestor or a link target. Bind
    // this particular owner to the requested lookup and resolved target.
    leaf.mLookupName = std::move(stage.mSourceLookup);
    leaf.mEffectiveName = std::move(stage.mEffectiveLeaf);
    leaf.mOriginalMount = stage.mInitialMountId;
    mEntries->emplace_back(std::move(leaf), logicalLeaf);
    mUsage.retainedBytes += bytes;
    return true;
}

ComplianceEngine::Result<Optional<Path::RejectionReason>> Path::AcquireInitialRoot(Path& path, const std::string& rootName, const Policy& policy)
{
    const ContextInterface& context = path.mContext.get();
    const ResolverLimits& limits = path.mLimits;
    path.mUsage.retainedBytes = rootName.size() + 1;
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
    path.mEntries->emplace_back(std::move(process).Value(), false);
    path.mUsage.retainedBytes += sizeof(Entry) + 2;
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

            if ((path.HeldDescriptors() > limits.shared.liveDescriptors - 7) || (path.mUsage.retainedBytes >= limits.shared.retainedBytes))
            {
                return Error("Root lineage exceeds resource budget", E2BIG);
            }
            ResolverLimits available = limits;
            available.shared.liveDescriptors -= path.HeldDescriptors() - 1;
            available.shared.retainedBytes -= path.mUsage.retainedBytes;
            const bool finalComponent = (rootName.find_first_not_of('/', end) == std::string::npos);
            const bool follow = finalComponent ? FollowForClassification(policy.fileLinks, policy.directoryLinks) : policy.symlinks == SymlinkPolicy::Follow;
            const bool exclude = finalComponent && policy.nonFollowedLinks == NonFollowedLinkAction::Skip &&
                                 policy.fileLinks == SymlinkPolicy::DoNotFollow && policy.directoryLinks == SymlinkPolicy::DoNotFollow;
            auto prefix = path.Lineage(path.mEntries->size() - 1);
            if (!prefix.HasValue())
                return std::move(prefix).Error();
            auto names = path.Bindings();
            auto next = ResolveChild(context, path.mEntries->front().pin, prefix.Value(), component,
                ResolutionPolicy{follow, policy.mounts, false, true, exclude}, available, names, "/", "/", path.mUsage.workSpent);
            if (!next.HasValue())
            {
                return std::move(next).Error();
            }
            if (next.Value().Is<RejectionReason>())
            {
                return Optional<RejectionReason>(next.Value().Get<RejectionReason>());
            }
            Detail::ResolvedPath& step = next.Value().Get<Detail::ResolvedPath>();
            if (finalComponent && step.mInitialFollowedLink)
            {
                const SymlinkPolicy action = step.Leaf().AcquiredType() == Handle::Type::Directory ? policy.directoryLinks : policy.fileLinks;
                if (action == SymlinkPolicy::DoNotFollow)
                {
                    auto cleanup = step.Close(context);
                    if (!cleanup.HasValue())
                    {
                        return std::move(cleanup).Error();
                    }
                    if (policy.nonFollowedLinks == NonFollowedLinkAction::Skip)
                    {
                        return Optional<RejectionReason>(RejectionReason::Excluded);
                    }
                    return Error("Selected root symlink is rejected", ELOOP);
                }
            }
            if ((step.Leaf().AcquiredType() != Handle::Type::Directory) &&
                !(finalComponent && (step.Leaf().AcquiredType() == Handle::Type::RegularFile) && (rootName.back() != '/')))
            {
                auto closed = step.Close(context);
                if (!closed.HasValue())
                    Detail::LogSecondaryClose(context, closed.Error().code);
                return Error("Configured root component is not a directory", ENOTDIR);
            }
            const std::size_t bytes = step.AccountedBytes();
            if (bytes > limits.shared.retainedBytes - path.mUsage.retainedBytes)
            {
                auto closed = step.Close(context);
                if (!closed.HasValue())
                    Detail::LogSecondaryClose(context, closed.Error().code);
                return Error("Root lineage exceeds retained-memory budget", E2BIG);
            }
            auto committed = path.CommitScratch(step, step.TakeOwnedLeaf());
            if (!committed.HasValue())
                return std::move(committed).Error();
            position = (slash == std::string::npos) ? rootName.size() : slash + 1;
        }
    }

    if (path.mEntries->size() != 1)
    {
        std::deque<Entry> scratch;
        scratch.swap(*path.mEntries);
        path.mEntries->emplace_back(std::move(scratch.back()));
        int first = 0;
        for (std::size_t i = scratch.size(); i > 0; --i)
        {
            auto closed = scratch[i - 1].pin.Close();
            if (!closed.HasValue())
            {
                if (first == 0)
                    first = closed.Error().code;
                else
                    Detail::LogSecondaryClose(context, closed.Error().code);
            }
        }
        if (first != 0)
            return Error("Cannot close initial root-prefix scratch pins", first);
        path.mEntries->front().pin.mLookupName = CollapseSeparators(rootName);
        std::size_t record = 0;
        if (!Footprint(path.mEntries->front().pin, record) || record > limits.shared.retainedBytes - (rootName.size() + 1))
            return Error("Acquired root name exceeds retained-memory budget", E2BIG);
        path.mUsage.retainedBytes = rootName.size() + 1 + record;
        if (path.mUsage.retainedBytes > limits.shared.retainedBytes)
            return Error("Acquired root name exceeds retained-memory budget", E2BIG);
    }
    if (!path.ChargeWork())
    {
        return Error("Root mount-inspection work budget exhausted", E2BIG);
    }
    ProcfsDescriptorAccess procfs(context);
    auto opened = procfs.Open();
    if (!opened.HasValue())
        return std::move(opened).Error();
    const std::uint64_t mount = path.mEntries->front().pin.mTargetMount;
    auto closed = procfs.Close();
    if (!closed.HasValue())
        return std::move(closed).Error();
    path.mRootMountId = mount;
    path.mEntries->front().logicalLeaf = true;
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
    Path accepted(context, limits);
    accepted.mEntries = std::move(path.mEntries);
    accepted.mSize = 1;
    accepted.mUsage = path.mUsage;
    // The factory's reporting spelling was temporary; accepted Paths retain
    // only acquisition provenance, not another copy of caller text.
    accepted.mUsage.retainedBytes -= rootName.size() + 1;
    accepted.mRootMountId = path.mRootMountId;
    return Variant<Path, RejectionReason>(InPlaceType<Path>{}, std::move(accepted));
}

Path::Metadata Path::LeafMetadata() const
{
    Metadata metadata;
    metadata.accepted = Leaf().AcquiredMetadata();
    metadata.mountId = mEntries->back().pin.OriginalMount();
    if (mSize == 1)
        metadata.mountId = mRootMountId;
    return metadata;
}

ComplianceEngine::Result<Variant<const Path&, Path::RejectionReason>> Path::Push(std::string component, ExtensionPolicy policy)
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

    if (Leaf().AcquiredType() != Handle::Type::Directory)
    {
        return Error("Cannot extend a regular-file leaf", ENOTDIR);
    }

    if (!ChargeWork())
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
    auto lineage = Lineage(mEntries->size() - 1);
    if (!lineage.HasValue())
        return std::move(lineage).Error();
    std::vector<const Handle*> parentLineage = std::move(lineage).Value();
    // The logical root can be reached through aliases: its physical parents
    // are not themselves a permitted ".." escape from the accepted boundary.
    auto boundary = std::find(parentLineage.begin(), parentLineage.end(), &Root());
    if (boundary == parentLineage.end())
        return Error("Accepted root is absent from physical ancestry", EINVAL);
    parentLineage.erase(parentLineage.begin(), boundary);
    std::vector<const Handle*> unique{&Root()};
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
    auto resolved = ResolveChild(mContext.get(), Root(), parentLineage, std::move(component),
        ResolutionPolicy{FollowForClassification(policy.fileLinks, policy.directoryLinks), policy.mounts, true, policy.reportMissingRegularFile,
            policy.nonFollowedLinks == NonFollowedLinkAction::Skip && policy.fileLinks == SymlinkPolicy::DoNotFollow && policy.directoryLinks == SymlinkPolicy::DoNotFollow},
        available, names, mEntries->front().pin.LookupName(), mEntries->front().pin.EffectiveName(), mUsage.workSpent);
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
    const std::size_t bytes = step.AccountedBytes();
    if (bytes > mLimits.shared.retainedBytes - mUsage.retainedBytes)
    {
        auto closed = step.Close(mContext.get());
        if (!closed.HasValue())
            Detail::LogSecondaryClose(mContext.get(), closed.Error().code);
        return Error("Path retained-memory budget exhausted", E2BIG);
    }
    auto committed = Commit(step, step.TakeOwnedLeaf());
    if (!committed.HasValue())
        return std::move(committed).Error();
    return Variant<const Path&, RejectionReason>(InPlaceType<const Path&>{}, static_cast<const Path&>(*this));
}

ComplianceEngine::Result<Handle> Path::Pop()
{
    if (mSize == 0)
    {
        return Error("Cannot pop an empty path", EINVAL);
    }
    const std::size_t checkpoint = mSize == 1 ? 0 : [&]() {
        std::size_t i = mEntries->size() - 1;
        while (i > 0 && !(*mEntries)[i - 1].logicalLeaf)
            --i;
        return i;
    }();
    std::size_t releasedBytes = 0;
    for (std::size_t i = checkpoint; i < mEntries->size(); ++i)
    {
        const Entry& entry = (*mEntries)[i];
        std::size_t record = 0;
        if (!Footprint(entry.pin, record) || record > std::numeric_limits<std::size_t>::max() - releasedBytes)
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
    Handle removed(std::move(detached.front().pin));
    mUsage.retainedBytes = releasedBytes <= mUsage.retainedBytes ? mUsage.retainedBytes - releasedBytes : 0;
    --mSize;
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
    if (mSize == 0)
        throw std::logic_error("Path has no acquired effective name");
    return mEntries->back().pin.EffectiveName();
}

const Handle& Path::Root() const
{
    if (mSize == 0)
    {
        throw std::logic_error("Path has no accepted root");
    }
    return mEntries->front().pin;
}

const Handle& Path::Leaf() const
{
    if (mSize == 0)
    {
        throw std::logic_error("Path has no leaf");
    }
    return mEntries->back().pin;
}

std::size_t Path::Size() const noexcept
{
    return mSize;
}
} // namespace Filesystem
} // namespace ComplianceEngine
