// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "ContextInterface.h"
#include "PathInternal.hpp"

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
using Detail::MountId;
using Detail::SameIdentity;
using Detail::SavedError;
using Detail::VerifiedProcfs;

constexpr std::size_t Path::NoIndex;

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
Result<LinkTarget> ReadPinnedLink(const ContextInterface& context, const Descriptor& linkPin, std::size_t targetByteCap, std::size_t fdinfoByteCap)
{
    if (!linkPin.HasValue())
    {
        return Error("Pinned link is empty", EBADF);
    }
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
    struct stat before = {}, after = {};
    struct statfs filesystem = {};
    if ((context.StatFile(linkPin, &before) != 0) || (context.StatFilesystem(linkPin, &filesystem) != 0))
    {
        return Error("Cannot inspect pinned link", SavedError());
    }

    if (!S_ISLNK(before.st_mode) || (PROC_SUPER_MAGIC == filesystem.f_type))
    {
        return Error("Not an ordinary filesystem symlink", ELOOP);
    }
    VerifiedProcfs procfs(context);
    auto verified = procfs.Open();
    if (!verified.HasValue())
    {
        return std::move(verified).Error();
    }
    auto inspected = [&]() -> Result<LinkTarget> {
        auto mount = MountId(context, procfs.fdinfo, linkPin, fdinfoByteCap);
        if (!mount.HasValue())
        {
            return std::move(mount).Error();
        }
        std::vector<char> buffer(targetByteCap + 1);
        const ssize_t count = context.ReadLink(linkPin, buffer.data(), buffer.size());
        if (count < 0)
        {
            return Error("Cannot read pinned symlink target", SavedError());
        }

        if ((count == 0) || (static_cast<std::size_t>(count) > targetByteCap))
        {
            return Error("Pinned symlink target exceeds byte cap or is empty", E2BIG);
        }

        if (context.StatFile(linkPin, &after) != 0)
        {
            return Error("Cannot recheck pinned symlink", SavedError());
        }

        if (!SameIdentity(before, after))
        {
            return Error("Pinned symlink identity changed", EAGAIN);
        }
        auto retainedMount = MountId(context, procfs.fdinfo, linkPin, fdinfoByteCap);
        if (!retainedMount.HasValue())
        {
            return std::move(retainedMount).Error();
        }

        if (mount.Value() != retainedMount.Value())
        {
            return Error("Pinned symlink mount changed", EAGAIN);
        }
        LinkTarget target;
        target.text.assign(buffer.data(), static_cast<std::size_t>(count));
        if (target.text.find('\0') != std::string::npos)
        {
            return Error("Pinned symlink contains NUL", EINVAL);
        }
        target.mountId = mount.Value();
        return target;
    }();
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

bool IsSingleChildComponent(const std::string& component) noexcept
{
    return !component.empty() && (component != ".") && (component != "..") && (component.find('/') == std::string::npos) &&
           (component.find('\0') == std::string::npos);
}
} // namespace Detail

namespace Detail
{
const Handle& ResolvedPath::Leaf() const
{
    return mOwnsLeaf ? mPins.at(mOwnedLeaf) : *mBorrowedLeaf;
}

Handle ResolvedPath::TakeOwnedLeaf()
{
    Handle owned(std::move(mPins.at(mOwnedLeaf)));
    mLeafTaken = true;
    return owned;
}

std::size_t ResolvedPath::OwnedDescriptors() const noexcept
{
    // Only the owned leaf can leave a stage; all other staged pins remain
    // live until the stage is destroyed.
    return mPins.size() - (mLeafTaken ? 1 : 0);
}

std::size_t ResolvedPath::AccountedBytes() const noexcept
{
    return mAccountedBytes;
}

} // namespace Detail

class Path::Resolver
{
public:
    Resolver(const ContextInterface& context, const std::vector<const Handle*>& rootLineage, const std::vector<const Handle*>& parentLineage,
        bool followLinks, MountPolicy mounts, const ResolverLimits& limits, bool permitUnsupported, bool allowMissing, bool excludeLinks,
        const std::vector<NameBinding>& names, const std::string& logicalRoot, const std::string& effectiveRoot, std::size_t* ledger)
        : mContext(context),
          mRootLineage(rootLineage),
          mParentLineage(parentLineage),
          mFollowLinks(followLinks),
          mMounts(mounts),
          mLimits(limits),
          mPermitUnsupported(permitUnsupported),
          mAllowMissing(allowMissing),
          mExcludeLinks(excludeLinks),
          mNames(names),
          mLogicalRoot(logicalRoot),
          mEffectiveRoot(effectiveRoot),
          mLedger(ledger)
    {
    }

    ComplianceEngine::Result<Detail::ResolvedPath> Run(std::string component)
    {
        if (!Detail::IsSingleChildComponent(component) || mRootLineage.empty() || mParentLineage.empty() ||
            (mMounts != MountPolicy::AllowCrossing && mMounts != MountPolicy::StayOnRootMount) || (mLimits.linkTargetBytes == 0) ||
            (mLimits.linkExpansions == 0) || (mLimits.depth == 0) || (mLimits.shared.targetBytes == 0) || (mLimits.shared.components == 0) ||
            (mLimits.shared.work == 0) || (mLimits.shared.liveDescriptors == 0) || (mLimits.shared.retainedBytes == 0) ||
            (mLimits.shared.fdinfoBytes == 0) || (mRootLineage.back() != mParentLineage.front()))
        {
            return Error("Invalid confined resolver input or mandatory limits", EINVAL);
        }

        for (const Handle* pin : mRootLineage)
        {
            if (!AddInput(pin))
            {
                return Error("Invalid or over-budget root lineage", E2BIG);
            }
        }
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
            VerifiedProcfs procfs(mContext);
            auto verified = procfs.Open();
            if (!verified.HasValue())
            {
                return std::move(verified).Error();
            }
            auto baseline = MountId(mContext, procfs.fdinfo, mRootLineage.back()->mDescriptor, mLimits.shared.fdinfoBytes);
            auto closed = procfs.Close();
            if (!closed.HasValue())
            {
                if (baseline.HasValue())
                {
                    baseline = std::move(closed).Error();
                }
                else
                {
                    Detail::LogSecondaryClose(mContext, closed.Error().code);
                }
            }
            if (!baseline.HasValue())
            {
                return std::move(baseline).Error();
            }
            mBaseline = baseline.Value();
        }
        // No procfs helper stays open while another helper reads a link.
        return ContinueAfterBaseline(std::move(component));
    }

private:
    bool AddInput(const Handle* pin)
    {
        if ((pin == nullptr) || (!pin->mPin) || (pin->mType != Handle::Type::Directory) || !pin->mDescriptor.HasValue())
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
            (pin->Component().size() > mLimits.shared.retainedBytes - mRetained - slot))
        {
            return false;
        }
        mSeen.push_back(pin);
        ++mInputPins;
        mRetained += slot + pin->Component().size();
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
        if ((mSpent > mLimits.shared.work) || (cost > mLimits.shared.work - mSpent) ||
            ((mLedger != nullptr) && ((*mLedger > mLimits.shared.work) || (cost > mLimits.shared.work - *mLedger))))
        {
            return false;
        }
        ++mSteps;
        mSpent += cost;
        if (mLedger != nullptr)
        {
            *mLedger += cost;
        }
        return true;
    }

    bool CanRetain(std::size_t bytes) const
    {
        return (mRetained <= mLimits.shared.retainedBytes) && (bytes <= mLimits.shared.retainedBytes - mRetained);
    }

    ComplianceEngine::Result<std::uint64_t> ObservedMount(const Descriptor& descriptor)
    {
        VerifiedProcfs procfs(mContext);
        auto verified = procfs.Open();
        if (!verified.HasValue())
        {
            return std::move(verified).Error();
        }
        auto mount = MountId(mContext, procfs.fdinfo, descriptor, mLimits.shared.fdinfoBytes);
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

    ComplianceEngine::Result<Detail::ResolvedPath> ContinueAfterBaseline(std::string component)
    {
        Detail::ResolvedPath resolved;
        auto resolution = [&]() -> ComplianceEngine::Result<bool> {
            auto effective = [this, &resolved](const Handle* pin) -> std::string {
                for (std::size_t i = 0; i < resolved.mPins.size(); ++i)
                    if (&resolved.mPins[i] == pin)
                        return resolved.mEffectivePins[i];
                for (const auto& name : mNames)
                    if (name.pin == pin)
                        return *name.effective;
                if (pin == mRootLineage.front() && mLogicalRoot == "/")
                    return "/";
                throw std::logic_error("Unbound acquired directory");
            };
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
            bool firstComponent = true;
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

                if (!Detail::IsSingleChildComponent(name) || (mInputPins + resolved.mPins.size() > mLimits.shared.liveDescriptors - 7))
                {
                    return Error("Invalid component or insufficient descriptor budget", E2BIG);
                }
                const std::string lookup = JoinName(effective(directories.back()), name);
                const Handle* cached = nullptr;
                std::string cachedEffective;
                std::uint64_t cachedOriginalMount = 0;
                for (const auto& binding : mNames)
                {
                    if (*binding.lookup != lookup && *binding.effective != lookup)
                        continue;
                    if (cached != nullptr && (!SameIdentity(cached->Stat(), binding.pin->Stat()) || cachedEffective != *binding.effective))
                        return Error("Conflicting held name bindings", EXDEV);
                    cached = binding.pin;
                    cachedEffective = *binding.effective;
                    cachedOriginalMount = binding.mount;
                }
                for (std::size_t i = 0; i < resolved.mPins.size(); ++i)
                {
                    if (resolved.mEffectivePins[i] != lookup || resolved.mPins[i].AcquiredType() != Handle::Type::Directory)
                        continue;
                    if (cached != nullptr && (!SameIdentity(cached->Stat(), resolved.mPins[i].Stat()) || cachedEffective != lookup))
                        return Error("Conflicting staged name bindings", EXDEV);
                    cached = &resolved.mPins[i];
                    cachedEffective = lookup;
                }
                if (cached != nullptr && cached->AcquiredType() == Handle::Type::Directory)
                {
                    auto mount = ObservedMount(cached->mDescriptor);
                    if (!mount.HasValue())
                        return std::move(mount).Error();
                    if (mMounts == MountPolicy::StayOnRootMount && (mount.Value() != mBaseline || (cachedOriginalMount != 0 && cachedOriginalMount != mBaseline)))
                        return Error("Held component crosses accepted root mount", EXDEV);
                    if (firstComponent)
                        resolved.mInitialMountId = cachedOriginalMount != 0 ? cachedOriginalMount : mount.Value();
                    firstComponent = false;
                    last = cached;
                    if (directories.size() >= mLimits.depth)
                        return Error("Confined resolution depth exhausted", E2BIG);
                    directories.push_back(last);
                    continue;
                }
                // Restrict normal intermediate directory opens; on ENOTDIR retry
                // only as O_PATH|O_NOFOLLOW to inspect a pinned symlink without
                // ever causing an operational open of a substituted special file.
                auto opened = mContext.OpenAt(directories.back()->mDescriptor, name.c_str(),
                    pending.empty() ? ContextInterface::OpenProfile::PinChild : ContextInterface::OpenProfile::PinChildDirectory);
                if (!opened.HasValue() && (opened.Error().code == ENOTDIR) && !pending.empty())
                {
                    opened = mContext.OpenAt(directories.back()->mDescriptor, name.c_str(), ContextInterface::OpenProfile::PinChild);
                }
                const int openError = opened.HasValue() ? 0 : opened.Error().code;
                Descriptor acquired = opened.HasValue() ? std::move(opened).Value() : mContext.EmptyDescriptor();
                auto step = [&]() -> ComplianceEngine::Result<bool> {
                    if (!acquired.HasValue())
                    {
                        if (mAllowMissing && firstComponent && pending.empty() && openError == ENOENT)
                        {
                            resolved.mMissingLeaf = true;
                            return true;
                        }
                        return Error("Cannot pin confined component", openError);
                    }
                    struct stat snapshot = {};
                    if (mContext.StatFile(acquired, &snapshot) != 0)
                    {
                        return Error("Cannot inspect confined component", SavedError());
                    }
                    auto mount = ObservedMount(acquired);
                    if (!mount.HasValue())
                    {
                        return std::move(mount).Error();
                    }

                    if ((mMounts == MountPolicy::StayOnRootMount) && (mount.Value() != mBaseline))
                    {
                        return Error("Component crosses accepted root mount", EXDEV);
                    }
                    if (firstComponent)
                    {
                        resolved.mInitialMountId = mount.Value();
                    }

                    if (S_ISLNK(snapshot.st_mode))
                    {
                        if (!mFollowLinks)
                        {
                            if (mExcludeLinks && firstComponent && pending.empty())
                            {
                                resolved.mExcludedLink = true;
                                return true;
                            }
                            return Error("Descendant symlink following is disabled", ELOOP);
                        }

                        if (++expansions > mLimits.linkExpansions)
                        {
                            return Error("Symlink expansion budget exhausted", ELOOP);
                        }
                        auto target = Detail::ReadPinnedLink(mContext, acquired, mLimits.linkTargetBytes, mLimits.shared.fdinfoBytes);
                        if (!target.HasValue())
                        {
                            return std::move(target).Error();
                        }

                        if (firstComponent)
                        {
                            resolved.mInitialFollowedLink = true;
                        }

                        if ((target.Value().mountId != mount.Value()) || !CanRetain(target.Value().text.size()))
                        {
                            return Error("Symlink changed mount or exhausted retained-memory budget", E2BIG);
                        }
                        mRetained += target.Value().text.size();
                        std::string text = std::move(target).Value().text;
                        if ((text.back() == '/') && pending.empty())
                        {
                            finalDirectoryRequired = true;
                        }

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
                            directories.assign(1, mRootLineage.back());
                            last = directories.back();
                        }
                        std::deque<std::string> expanded;
                        std::size_t start = 0;
                        while (start < text.size())
                        {
                            const std::size_t slash = text.find('/', start);
                            const std::size_t end = (slash == std::string::npos) ? text.size() : slash;
                            if (end != start)
                            {
                                if (!CanRetain(sizeof(std::string) + end - start))
                                {
                                    return Error("Symlink expansion exceeds retained-memory budget", E2BIG);
                                }
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
                        firstComponent = false;
                        return true;
                    }
                    firstComponent = false;
                    if ((!S_ISDIR(snapshot.st_mode)) && (!S_ISREG(snapshot.st_mode)))
                    {
                        // Only the final unsupported object may be skipped,
                        // whether directly pinned or reached by a followed
                        // link. It never becomes an accepted Handle.
                        if (mPermitUnsupported && pending.empty())
                        {
                            resolved.mUnsupportedLeaf = true;
                            return true;
                        }
                        return Error("Unsupported confined object type", EOPNOTSUPP);
                    }

                    if ((!pending.empty()) && !S_ISDIR(snapshot.st_mode))
                    {
                        return Error("Intermediate component is not a directory", ENOTDIR);
                    }
                    // The captured full effective spelling is stored with
                    // each staged pin and can cost O(depth squared) bytes.
                    const std::size_t ownerBytes =
                        sizeof(Handle) + name.size() + sizeof(std::string) + lookup.size() + (S_ISDIR(snapshot.st_mode) ? 4 * sizeof(const Handle*) : 0);
                    if (!CanRetain(ownerBytes))
                    {
                        return Error("Confined resolution retained-memory budget exhausted", E2BIG);
                    }
                    mRetained += ownerBytes;
                    Handle staged(std::move(acquired), S_ISDIR(snapshot.st_mode) ? Handle::Type::Directory : Handle::Type::RegularFile, std::move(name), snapshot);
                    resolved.mPins.emplace_back(std::move(staged));
                    resolved.mEffectivePins.emplace_back(lookup);
                    last = &resolved.mPins.back();
                    if (S_ISDIR(snapshot.st_mode))
                    {
                        if (directories.size() >= mLimits.depth)
                        {
                            return Error("Confined resolution depth exhausted", E2BIG);
                        }
                        directories.push_back(last);
                    }
                    return true;
                }();
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
            }

            if (resolved.mMissingLeaf || resolved.mExcludedLink)
            {
                resolved.mAccountedBytes = mRetained;
                return true;
            }
            if (finalDirectoryRequired && (last->AcquiredType() != Handle::Type::Directory))
            {
                return Error("Trailing slash requires a directory", ENOTDIR);
            }
            if (resolved.mUnsupportedLeaf)
            {
                resolved.mAccountedBytes = mRetained;
                return true;
            }

            for (const Handle* directory : directories)
            {
                Detail::ResolvedPath::Frame frame;
                for (std::size_t index = 0; index < resolved.mPins.size(); ++index)
                {
                    if (&resolved.mPins[index] == directory)
                    {
                        frame.owned = true;
                        frame.ownedIndex = index;
                        break;
                    }
                }

                if (!frame.owned)
                {
                    frame.borrowed = directory;
                }
                resolved.mFrames.emplace_back(frame);
            }

            for (std::size_t index = 0; index < resolved.mPins.size(); ++index)
            {
                if (&resolved.mPins[index] == last)
                {
                    resolved.mOwnedLeaf = index;
                    resolved.mOwnsLeaf = true;
                    break;
                }
            }

            if (!resolved.mOwnsLeaf)
            {
                resolved.mBorrowedLeaf = last;
            }
            resolved.mEffectiveLeaf = effective(last);
            resolved.mAccountedBytes = mRetained;
            return true;
        }();
        if (!resolution.HasValue())
        {
            auto primary = std::move(resolution).Error();
            for (auto pin = resolved.mPins.rbegin(); pin != resolved.mPins.rend(); ++pin)
            {
                auto closed = pin->Close();
                if (!closed.HasValue())
                {
                    Detail::LogSecondaryClose(mContext, closed.Error().code);
                }
            }
            return primary;
        }
        return std::move(resolved);
    }

    const ContextInterface& mContext;
    const std::vector<const Handle*>& mRootLineage;
    const std::vector<const Handle*>& mParentLineage;
    bool mFollowLinks;
    MountPolicy mMounts;
    const ResolverLimits& mLimits;
    bool mPermitUnsupported;
    bool mAllowMissing;
    bool mExcludeLinks;
    const std::vector<NameBinding>& mNames;
    const std::string& mLogicalRoot;
    const std::string& mEffectiveRoot;
    std::size_t* mLedger;
    std::vector<const Handle*> mSeen;
    std::size_t mInputPins = 0, mRetained = 0, mSteps = 0, mSpent = 0;
    std::uint64_t mBaseline = 0;
};

ComplianceEngine::Result<Detail::ResolvedPath> Path::ResolveChild(const ContextInterface& context, const std::vector<const Handle*>& rootLineage,
    const std::vector<const Handle*>& parentLineage, std::string component, bool followSymlinks, MountPolicy mounts, const ResolverLimits& limits,
    bool permitUnsupported, bool allowMissing, bool excludeLinks, const std::vector<NameBinding>& names, const std::string& logicalRoot,
    const std::string& effectiveRoot, std::size_t* ledger)
{
    return Resolver(context, rootLineage, parentLineage, followSymlinks, mounts, limits, permitUnsupported, allowMissing, excludeLinks, names,
        logicalRoot, effectiveRoot, ledger)
        .Run(std::move(component));
}

Path::Path(const ContextInterface& context, ResolverLimits limits)
    : mContext(context),
      mLimits(limits)
{
}

Path::Path(Path&& other) noexcept
    : mContext(other.mContext),
      mLimits(other.mLimits),
      mUsage(other.mUsage),
      mRootMountId(other.mRootMountId),
      mEntries(std::move(other.mEntries)),
      mLeafIndex(other.mLeafIndex),
      mSize(other.mSize),
      mDiagnosticPath(std::move(other.mDiagnosticPath))
{
    other.mEntries.clear();
    other.mLeafIndex = NoIndex;
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
        swap(mLeafIndex, incoming.mLeafIndex);
        swap(mSize, incoming.mSize);
        mDiagnosticPath.swap(incoming.mDiagnosticPath);
    }
    return *this;
}

Path::~Path() noexcept
{
    if (!mEntries.empty())
    {
        try
        {
            auto closed = Close();
            if (!closed.HasValue())
            {
                try
                {
                    OsConfigLogError(mContext.get().GetLogHandle(), "Failed to close acquired filesystem path: %d", closed.Error().code);
                }
                catch (...)
                {
                    OsConfigLogError(nullptr, "Acquired path close log failure: %d", closed.Error().code);
                }
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
    int firstError = 0;
    auto release = [this, &firstError](Handle& pin) {
        const int error = pin.CloseOnce();
        if (error != 0)
        {
            if (firstError == 0)
            {
                firstError = error;
            }
            else
            {
                try
                {
                    OsConfigLogError(mContext.get().GetLogHandle(), "Secondary filesystem pin close failure: %d", error);
                }
                catch (...)
                {
                    OsConfigLogError(nullptr, "Secondary filesystem pin close log failure: %d", error);
                }
            }
        }
    };
    for (auto entry = mEntries.rbegin(); entry != mEntries.rend(); ++entry)
    {
        release(entry->pin);
    }
    mEntries.clear();
    mLeafIndex = NoIndex;
    mSize = 0;
    mUsage.retainedBytes = 0;
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
    return mEntries.size();
}

ComplianceEngine::Result<std::uint64_t> Path::RootMountId() const
{
    VerifiedProcfs procfs(mContext.get());
    auto opened = procfs.Open();
    if (!opened.HasValue())
    {
        return std::move(opened).Error();
    }
    auto mount = MountId(mContext.get(), procfs.fdinfo, Root().mDescriptor, mLimits.shared.fdinfoBytes);
    auto closed = procfs.Close();
    if (!closed.HasValue())
    {
        if (mount.HasValue())
        {
            return std::move(closed).Error();
        }
        Detail::LogSecondaryClose(mContext.get(), closed.Error().code);
    }
    return mount;
}

ComplianceEngine::Result<Handle> Path::RetainLeaf(Detail::ResolvedPath& stage, const std::string& component)
{
    if (stage.mOwnsLeaf)
    {
        return stage.TakeOwnedLeaf();
    }
    const Handle& source = stage.Leaf();
    const std::size_t held = HeldDescriptors();
    if ((source.mContext == nullptr) || !source.mDescriptor.HasValue() || (source.mType != Handle::Type::Directory) || (held > mLimits.shared.liveDescriptors) ||
        (stage.OwnedDescriptors() > mLimits.shared.liveDescriptors - held) || (mLimits.shared.liveDescriptors - held - stage.OwnedDescriptors() < 7))
    {
        return Error("Cannot retain borrowed directory without descriptor budget", EMFILE);
    }
    auto duplicated = mContext.get().Duplicate(source.mDescriptor);
    const int duplicateError = duplicated.HasValue() ? 0 : duplicated.Error().code;
    Descriptor duplicate = duplicated.HasValue() ? std::move(duplicated).Value() : mContext.get().EmptyDescriptor();
    auto retained = [&]() -> ComplianceEngine::Result<Handle> {
        if (!duplicate.HasValue())
        {
            return Error("Cannot retain pinned directory", duplicateError);
        }
        struct stat snapshot = {};
        if (mContext.get().StatFile(duplicate, &snapshot) != 0)
        {
            return Error("Cannot inspect retained directory pin", SavedError());
        }

        if (!SameIdentity(source.mSnapshot, snapshot) || !S_ISDIR(snapshot.st_mode))
        {
            return Error("Retained directory identity changed", EAGAIN);
        }
        Handle candidate(std::move(duplicate), Handle::Type::Directory, component, snapshot);
        auto matched = Handle::RecognizeAcceptedRoot(source, candidate, mLimits.shared.fdinfoBytes);
        if (!matched.HasValue())
        {
            auto primary = std::move(matched).Error();
            auto closed = candidate.Close();
            if (!closed.HasValue())
            {
                Detail::LogSecondaryClose(mContext.get(), closed.Error().code);
            }
            return primary;
        }

        if (!matched.Value())
        {
            const Error primary("Retained directory mount differs from its source", EAGAIN);
            auto closed = candidate.Close();
            if (!closed.HasValue())
            {
                Detail::LogSecondaryClose(mContext.get(), closed.Error().code);
            }
            return primary;
        }
        return std::move(candidate);
    }();
    auto closed = duplicate.Close();
    if (!closed.HasValue())
    {
        if (retained.HasValue())
        {
            return std::move(closed).Error();
        }
        Detail::LogSecondaryClose(mContext.get(), closed.Error().code);
    }
    return retained;
}

ComplianceEngine::Result<bool> Path::ReleaseStage(Detail::ResolvedPath& stage)
{
    Optional<Error> first;
    for (auto pin = stage.mPins.rbegin(); pin != stage.mPins.rend(); ++pin)
    {
        auto closed = pin->Close();
        if (!closed.HasValue())
        {
            if (!first.HasValue())
            {
                first = std::move(closed).Error();
            }
            else
            {
                Detail::LogSecondaryClose(mContext.get(), closed.Error().code);
            }
        }
    }
    return first.HasValue() ? ComplianceEngine::Result<bool>(std::move(first.Value())) : ComplianceEngine::Result<bool>(true);
}

std::vector<Path::NameBinding> Path::Bindings() const
{
    std::vector<NameBinding> names;
    names.reserve(mEntries.size());
    for (const Entry& entry : mEntries)
        names.push_back({&entry.pin, &entry.lookupName, &entry.effectiveName, entry.originalMount});
    return names;
}

std::vector<const Handle*> Path::Lineage(std::size_t index) const
{
    if (index >= mEntries.size() || mEntries[index].pin.AcquiredType() != Handle::Type::Directory)
        throw std::logic_error("Invalid acquired directory boundary");
    const std::string& rootName = mEntries.front().effectiveName;
    const std::string& target = mEntries[index].effectiveName;
    if (!AtBoundary(target, rootName))
        throw std::logic_error("Acquired directory outside physical root");
    std::vector<const Handle*> pins{&mEntries.front().pin};
    std::size_t start = rootName == "/" ? 1 : rootName.size() + 1;
    while (start < target.size())
    {
        const std::size_t slash = target.find('/', start);
        const std::string prefix = target.substr(0, slash);
        const Entry* selected = nullptr;
        for (const Entry& entry : mEntries)
        {
            if (entry.effectiveName != prefix || entry.pin.AcquiredType() != Handle::Type::Directory)
                continue;
            if (selected != nullptr && !SameIdentity(selected->pin.Stat(), entry.pin.Stat()))
                throw std::logic_error("Conflicting held physical ancestor");
            selected = &entry;
        }
        if (selected == nullptr)
            throw std::logic_error("Missing acquired physical ancestor");
        pins.push_back(&selected->pin);
        if (slash == std::string::npos)
            break;
        start = slash + 1;
    }
    if (index != 0)
    {
        if (target != rootName)
            pins.back() = &mEntries[index].pin;
    }
    return pins;
}

ComplianceEngine::Result<bool> Path::Commit(Detail::ResolvedPath& stage, Handle leaf, bool root)
{
    const std::size_t start = mEntries.size();
    // Keep only directories in the final physical ancestry. Previous logical
    // steps remain owned until their own Pop, even if a link branched away.
    auto abort = [this, &stage, &leaf](const Error& error) -> ComplianceEngine::Result<bool> {
        const auto closedLeaf = leaf.Close();
        if (!closedLeaf.HasValue())
            Detail::LogSecondaryClose(mContext.get(), closedLeaf.Error().code);
        const auto closedStage = ReleaseStage(stage);
        if (!closedStage.HasValue())
            Detail::LogSecondaryClose(mContext.get(), closedStage.Error().code);
        return error;
    };
    try
    {
        std::vector<bool> keep(stage.mPins.size(), false);
        for (const auto& frame : stage.mFrames)
        {
            if (frame.owned)
            {
                if (frame.ownedIndex >= stage.mPins.size())
                    return abort(Error("Invalid staged directory index", EINVAL));
                keep[frame.ownedIndex] = true;
            }
            else if (frame.borrowed == nullptr ||
                     std::none_of(mEntries.begin(), mEntries.end(), [&frame](const Entry& entry) { return &entry.pin == frame.borrowed; }))
                return abort(Error("Invalid borrowed staged ancestor", EINVAL));
        }
        std::size_t bytes = sizeof(Entry) + leaf.Component().size() + stage.mSourceLookup.size() + stage.mEffectiveLeaf.size();
        for (std::size_t i = 0; i < stage.mPins.size(); ++i)
        {
            if (stage.mLeafTaken && i == stage.mOwnedLeaf)
                continue;
            if (keep[i])
                bytes += sizeof(Entry) + stage.mPins[i].Component().size() + 2 * stage.mEffectivePins[i].size();
        }
        if (mUsage.retainedBytes > mLimits.shared.retainedBytes || bytes > mLimits.shared.retainedBytes - mUsage.retainedBytes)
            return abort(Error("Path entry storage exceeds retained-memory budget", E2BIG));

        // Close abandoned temporary branches before changing the accepted
        // Path. A failure leaves every existing borrow and index untouched.
        for (std::size_t i = 0; i < stage.mPins.size(); ++i)
        {
            if (!keep[i] && !(stage.mLeafTaken && i == stage.mOwnedLeaf))
            {
                auto closed = stage.mPins[i].Close();
                if (!closed.HasValue())
                    return abort(std::move(closed).Error());
            }
        }
        for (std::size_t i = 0; i < stage.mPins.size(); ++i)
        {
            if (!keep[i] || (stage.mLeafTaken && i == stage.mOwnedLeaf))
                continue;
            mEntries.emplace_back(std::move(stage.mPins[i]), stage.mEffectivePins[i], stage.mEffectivePins[i], 0, false);
        }
        mEntries.emplace_back(std::move(leaf), stage.mSourceLookup, stage.mEffectiveLeaf, stage.mInitialMountId, root || mSize != 0);
        mUsage.retainedBytes += bytes;
        mLeafIndex = mEntries.size() - 1;
        if (root)
            mSize = 1;
        else if (mSize != 0)
            ++mSize;
        return true;
    }
    catch (...)
    {
        for (std::size_t i = mEntries.size(); i > start; --i)
        {
            const int error = mEntries[i - 1].pin.CloseOnce();
            if (error != 0)
                Detail::LogSecondaryClose(mContext.get(), error);
            mEntries.pop_back();
        }
        const auto closed = leaf.Close();
        if (!closed.HasValue())
            Detail::LogSecondaryClose(mContext.get(), closed.Error().code);
        const auto remaining = ReleaseStage(stage);
        if (!remaining.HasValue())
            Detail::LogSecondaryClose(mContext.get(), remaining.Error().code);
        throw;
    }
}

ComplianceEngine::Result<Variant<Path, Path::RejectionReason>> Path::Make(const ContextInterface& context, std::string absolutePath, Policy policy, ResolverLimits limits)
{
    if ((absolutePath.empty()) || (absolutePath.front() != '/') || (absolutePath.find('\0') != std::string::npos) || (limits.shared.work == 0) ||
        (limits.shared.components == 0) || (limits.shared.liveDescriptors == 0) || (limits.shared.retainedBytes == 0) || (limits.shared.targetBytes == 0) ||
        (limits.shared.fdinfoBytes == 0) || (limits.linkTargetBytes == 0) || (limits.linkExpansions == 0) || (limits.depth == 0) ||
        (absolutePath.size() > limits.shared.retainedBytes) || (limits.shared.liveDescriptors < 8) || !ValidFollowing(policy.symlinks) ||
        !ValidFollowing(policy.fileLinks) || !ValidFollowing(policy.directoryLinks) || !ValidNonFollowedLink(policy.nonFollowedLinks) ||
        ((policy.mounts != MountPolicy::AllowCrossing) && (policy.mounts != MountPolicy::StayOnRootMount)))
    {
        return Error("An absolute authorized directory, policy and positive budgets are required", EINVAL);
    }
    Path path(context, limits);
    path.mDiagnosticPath = std::move(absolutePath);
    const std::string& rootName = path.mDiagnosticPath;
    path.mUsage.retainedBytes = rootName.size() + 1;
    Optional<RejectionReason> selection;
    auto acquired = [&]() -> ComplianceEngine::Result<bool> {
        if (!path.ChargeWork())
        {
            return Error("Root acquisition work budget exhausted", E2BIG);
        }
        if (path.mUsage.retainedBytes > limits.shared.retainedBytes || sizeof(Entry) + 1 > limits.shared.retainedBytes - path.mUsage.retainedBytes)
            return Error("Process root exceeds retained-memory budget", E2BIG);
        auto process = Handle::PinProcessRoot(context);
        if (!process.HasValue())
        {
            return std::move(process).Error();
        }

        const bool hasComponent = rootName.find_first_not_of('/') != std::string::npos;
        if (!hasComponent)
        {
            path.mEntries.emplace_back(std::move(process).Value(), "/", "/", 0, true);
            path.mLeafIndex = 0;
            path.mSize = 1;
            path.mUsage.retainedBytes += sizeof(Entry) + 3;
        }
        else
        {
            path.mEntries.emplace_back(std::move(process).Value(), "/", "/", 0, false);
            path.mLeafIndex = 0;
            path.mUsage.retainedBytes += sizeof(Entry) + 3;
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
                std::vector<const Handle*> prefix;
                try
                {
                    prefix = path.Lineage(path.mLeafIndex);
                }
                catch (const std::logic_error&)
                {
                    return Error("Conflicting held root-prefix identities", EXDEV);
                }
                auto names = path.Bindings();
                auto next = ResolveChild(context, path.Lineage(0), prefix, component, follow, policy.mounts, available, false, true, exclude, names,
                    "/", "/", &path.mUsage.workSpent);
                if (!next.HasValue())
                {
                    return std::move(next).Error();
                }
                if (next.Value().mMissingLeaf || next.Value().mExcludedLink)
                {
                    selection = next.Value().mMissingLeaf ? RejectionReason::Missing : RejectionReason::Excluded;
                    return path.ReleaseStage(next.Value());
                }
                if (finalComponent && next.Value().mInitialFollowedLink)
                {
                    const SymlinkPolicy action = next.Value().Leaf().AcquiredType() == Handle::Type::Directory ? policy.directoryLinks : policy.fileLinks;
                    if (action == SymlinkPolicy::DoNotFollow)
                    {
                        auto cleanup = path.ReleaseStage(next.Value());
                        if (!cleanup.HasValue())
                        {
                            return std::move(cleanup).Error();
                        }
                        if (policy.nonFollowedLinks == NonFollowedLinkAction::Skip)
                        {
                            selection = RejectionReason::Excluded;
                            return true;
                        }
                        return Error("Selected root symlink is rejected", ELOOP);
                    }
                }
                if ((next.Value().Leaf().AcquiredType() != Handle::Type::Directory) &&
                    !(finalComponent && (next.Value().Leaf().AcquiredType() == Handle::Type::RegularFile) && (rootName.back() != '/')))
                {
                    auto closed = path.ReleaseStage(next.Value());
                    if (!closed.HasValue())
                        Detail::LogSecondaryClose(context, closed.Error().code);
                    return Error("Configured root component is not a directory", ENOTDIR);
                }
                const std::size_t bytes = next.Value().AccountedBytes();
                if (bytes > limits.shared.retainedBytes - path.mUsage.retainedBytes)
                {
                    auto closed = path.ReleaseStage(next.Value());
                    if (!closed.HasValue())
                        Detail::LogSecondaryClose(context, closed.Error().code);
                    return Error("Root lineage exceeds retained-memory budget", E2BIG);
                }
                const std::string leafName = next.Value().Leaf().Component();
                auto owned = path.RetainLeaf(next.Value(), leafName);
                if (!owned.HasValue())
                {
                    auto primary = std::move(owned).Error();
                    auto closed = path.ReleaseStage(next.Value());
                    if (!closed.HasValue())
                        Detail::LogSecondaryClose(context, closed.Error().code);
                    return primary;
                }
                auto committed = path.Commit(next.Value(), std::move(owned).Value(), finalComponent);
                if (!committed.HasValue())
                    return std::move(committed).Error();
                position = (slash == std::string::npos) ? rootName.size() : slash + 1;
            }
            if (path.mSize == 0)
            {
                return Error("Configured root needs a directory component", EINVAL);
            }
        }

        if (selection.HasValue())
        {
            return true;
        }
        if (path.mLeafIndex != 0)
        {
            std::deque<Entry> scratch;
            scratch.swap(path.mEntries);
            path.mEntries.emplace_back(std::move(scratch[path.mLeafIndex]));
            int first = 0;
            for (std::size_t i = scratch.size(); i > 0; --i)
            {
                const int error = scratch[i - 1].pin.CloseOnce();
                if (error != 0)
                {
                    if (first == 0)
                        first = error;
                    else
                        Detail::LogSecondaryClose(context, error);
                }
            }
            if (first != 0)
                return Error("Cannot close initial root-prefix scratch pins", first);
            path.mLeafIndex = 0;
            path.mEntries.front().lookupName = CollapseSeparators(rootName);
            path.mUsage.retainedBytes = rootName.size() + 1 + sizeof(Entry) + path.Root().Component().size() + path.mEntries.front().lookupName.size() +
                                        path.mEntries.front().effectiveName.size();
            if (path.mUsage.retainedBytes > limits.shared.retainedBytes)
                return Error("Acquired root name exceeds retained-memory budget", E2BIG);
        }
        if (!path.ChargeWork())
        {
            return Error("Root mount-inspection work budget exhausted", E2BIG);
        }
        auto mount = path.RootMountId();
        if (!mount.HasValue())
        {
            return std::move(mount).Error();
        }
        path.mRootMountId = mount.Value();
        return true;
    }();
    if (!acquired.HasValue() || selection.HasValue())
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
            try
            {
                OsConfigLogError(context.GetLogHandle(), "Failed to close pinned descriptors for %s: %d", rootName.c_str(), closed.Error().code);
            }
            catch (...)
            {
                OsConfigLogError(nullptr, "Root secondary pin close log failure for %s: %d", rootName.c_str(), closed.Error().code);
            }
        }
        if (primary.HasValue())
        {
            return std::move(primary.Value());
        }
        return Variant<Path, RejectionReason>(InPlaceType<RejectionReason>{}, selection.Value());
    }
    return Variant<Path, RejectionReason>(InPlaceType<Path>{}, std::move(path));
}

Path::Metadata Path::LeafMetadata() const
{
    Metadata metadata;
    metadata.accepted = Leaf().Stat();
    metadata.mountId = mEntries.at(mLeafIndex).originalMount;
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

    if (!Detail::IsSingleChildComponent(component) || !ValidFollowing(policy.symlinks) ||
        (policy.mounts != MountPolicy::AllowCrossing && policy.mounts != MountPolicy::StayOnRootMount) || !ValidFollowing(policy.fileLinks) ||
        !ValidFollowing(policy.directoryLinks) || !ValidNonFollowedLink(policy.nonFollowedLinks))
    {
        return Error("Invalid child component or extension policy", EINVAL);
    }

    if (policy.hardlinks == HardlinkPolicy::RequireUnique)
    {
        return Error("Hardlink inspection timing is not yet specified", ENOTSUP);
    }

    if (policy.hardlinks != HardlinkPolicy::Permit)
    {
        return Error("Invalid hardlink policy", EINVAL);
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
    std::vector<const Handle*> rootLineage, parentLineage;
    try
    {
        rootLineage = Lineage(0);
        parentLineage = Lineage(mLeafIndex);
    }
    catch (const std::logic_error&)
    {
        return Error("Conflicting held physical ancestor identities", EXDEV);
    }
    // The logical root can be reached through aliases: its physical parents
    // are not themselves a permitted ".." escape from the accepted boundary.
    auto boundary = std::find(parentLineage.begin(), parentLineage.end(), &Root());
    if (boundary == parentLineage.end())
        return Error("Accepted root is absent from physical ancestry", EINVAL);
    parentLineage.erase(parentLineage.begin(), boundary);
    std::vector<const Handle*> unique = rootLineage;
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
    auto resolved = ResolveChild(mContext.get(), rootLineage, parentLineage, std::move(component),
        FollowForClassification(policy.fileLinks, policy.directoryLinks), policy.mounts, available, true, policy.reportMissingRegularFile,
        policy.nonFollowedLinks == NonFollowedLinkAction::Skip && policy.fileLinks == SymlinkPolicy::DoNotFollow && policy.directoryLinks == SymlinkPolicy::DoNotFollow,
        names, mEntries.front().lookupName, mEntries.front().effectiveName, &mUsage.workSpent);
    if (!resolved.HasValue())
    {
        return std::move(resolved).Error();
    }
    if (resolved.Value().mMissingLeaf || resolved.Value().mExcludedLink)
    {
        const bool missing = resolved.Value().mMissingLeaf;
        auto closed = ReleaseStage(resolved.Value());
        if (!closed.HasValue())
        {
            return std::move(closed).Error();
        }
        return Variant<const Path&, RejectionReason>(InPlaceType<RejectionReason>{}, missing ? RejectionReason::Missing : RejectionReason::Excluded);
    }
    if (resolved.Value().mUnsupportedLeaf)
    {
        auto cleanup = ReleaseStage(resolved.Value());
        if (policy.unsupported == UnsupportedTypeAction::Reject)
        {
            if (!cleanup.HasValue())
            {
                Detail::LogSecondaryClose(mContext.get(), cleanup.Error().code);
            }
            return Error("Unsupported confined object type", EOPNOTSUPP);
        }
        if (!cleanup.HasValue())
        {
            return std::move(cleanup).Error();
        }
        return Variant<const Path&, RejectionReason>(InPlaceType<RejectionReason>{}, RejectionReason::UnsupportedType);
    }
    if (resolved.Value().mInitialFollowedLink)
    {
        const SymlinkPolicy action = resolved.Value().Leaf().AcquiredType() == Handle::Type::Directory ? policy.directoryLinks : policy.fileLinks;
        if (action == SymlinkPolicy::DoNotFollow)
        {
            auto cleanup = ReleaseStage(resolved.Value());
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
    const std::size_t bytes = resolved.Value().AccountedBytes();
    if (bytes > mLimits.shared.retainedBytes - mUsage.retainedBytes)
    {
        auto closed = ReleaseStage(resolved.Value());
        if (!closed.HasValue())
            Detail::LogSecondaryClose(mContext.get(), closed.Error().code);
        return Error("Path retained-memory budget exhausted", E2BIG);
    }
    const std::string name = resolved.Value().Leaf().Component();
    auto leaf = RetainLeaf(resolved.Value(), name);
    if (!leaf.HasValue())
    {
        auto primary = std::move(leaf).Error();
        auto closed = ReleaseStage(resolved.Value());
        if (!closed.HasValue())
            Detail::LogSecondaryClose(mContext.get(), closed.Error().code);
        return primary;
    }
    auto committed = Commit(resolved.Value(), std::move(leaf).Value(), false);
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
        std::size_t i = mEntries.size() - 1;
        while (i > 0 && !mEntries[i - 1].logicalLeaf)
            --i;
        return i;
    }();
    Handle removed(std::move(mEntries.back().pin));
    int firstError = 0;
    for (std::size_t i = mEntries.size(); i > checkpoint; --i)
    {
        const Entry& entry = mEntries[i - 1];
        const std::size_t bytes = sizeof(Entry) + (i == mEntries.size() ? removed.Component().size() : entry.pin.Component().size()) +
                                  entry.lookupName.size() + entry.effectiveName.size();
        mUsage.retainedBytes = bytes <= mUsage.retainedBytes ? mUsage.retainedBytes - bytes : 0;
        const int error = mEntries[i - 1].pin.CloseOnce();
        if (error != 0)
        {
            if (firstError == 0)
                firstError = error;
            else
                Detail::LogSecondaryClose(mContext.get(), error);
        }
        mEntries.pop_back();
    }
    --mSize;
    mLeafIndex = mSize == 0 ? NoIndex : mEntries.size() - 1;
    if (mSize == 0)
        mUsage.retainedBytes = 0;
    if (firstError != 0)
    {
        const int detachedError = removed.CloseOnce();
        if (detachedError != 0)
            Detail::LogSecondaryClose(mContext.get(), detachedError);
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
    return mEntries.at(mLeafIndex).effectiveName;
}

const Handle& Path::Root() const
{
    if (mSize == 0)
    {
        throw std::logic_error("Path has no accepted root");
    }
    return mEntries.front().pin;
}

const Handle& Path::Leaf() const
{
    if (mSize == 0)
    {
        throw std::logic_error("Path has no leaf");
    }
    return mEntries.at(mLeafIndex).pin;
}

std::size_t Path::Size() const noexcept
{
    return mSize;
}
} // namespace Filesystem
} // namespace ComplianceEngine
