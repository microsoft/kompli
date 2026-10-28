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

namespace Detail
{
Result<LinkTarget> ReadPinnedLink(const ContextInterface& context, int linkPin, std::size_t targetByteCap, std::size_t fdinfoByteCap)
{
    if ((linkPin < 0) || (targetByteCap == 0) || (targetByteCap >= std::vector<char>().max_size() - 1) ||
        (targetByteCap >= static_cast<std::size_t>(std::numeric_limits<ssize_t>::max())) || (fdinfoByteCap == 0))
    {
        return Error("Invalid pinned link or byte cap", EINVAL);
    }
    const int flags = ::fcntl(linkPin, F_GETFL);
    if (flags < 0)
    {
        return Error("Cannot inspect pinned link flags", SavedError());
    }
    const int descriptorFlags = ::fcntl(linkPin, F_GETFD);
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
    if ((context.StatFileDescriptor(linkPin, &before) != 0) || (::fstatfs(linkPin, &filesystem) != 0))
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
        auto mount = MountId(context, procfs.fdinfo.Get().Value(), linkPin, fdinfoByteCap);
        if (!mount.HasValue())
        {
            return std::move(mount).Error();
        }
        std::vector<char> buffer(targetByteCap + 1);
        const ssize_t count = ::readlinkat(linkPin, "", buffer.data(), buffer.size());
        if (count < 0)
        {
            return Error("Cannot read pinned symlink target", SavedError());
        }

        if ((count == 0) || (static_cast<std::size_t>(count) > targetByteCap))
        {
            return Error("Pinned symlink target exceeds byte cap or is empty", E2BIG);
        }

        if (context.StatFileDescriptor(linkPin, &after) != 0)
        {
            return Error("Cannot recheck pinned symlink", SavedError());
        }

        if (!SameIdentity(before, after))
        {
            return Error("Pinned symlink identity changed", EAGAIN);
        }
        auto retainedMount = MountId(context, procfs.fdinfo.Get().Value(), linkPin, fdinfoByteCap);
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
    return (mForwardedLeaf != nullptr) ? *mForwardedLeaf : (mOwnsLeaf ? mPins.at(mOwnedLeaf) : *mBorrowedLeaf);
}

Handle ResolvedPath::TakeOwnedLeaf()
{
    Handle owned(std::move(mPins.at(mOwnedLeaf)));
    mLeafTaken = true;
    return owned;
}

void ResolvedPath::ForwardLeaf(const Handle& external)
{
    mForwardedLeaf = &external;
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

std::vector<const Handle*> ResolvedPath::DirectoryLineage() const
{
    std::vector<const Handle*> lineage;
    lineage.reserve(mFrames.size());
    for (const auto& frame : mFrames)
    {
        lineage.push_back(frame.owned ? (((mForwardedLeaf != nullptr) && (frame.ownedIndex == mOwnedLeaf)) ? mForwardedLeaf : &mPins.at(frame.ownedIndex)) :
                                        frame.borrowed);
    }
    return lineage;
}
} // namespace Detail

class Path::Resolver
{
public:
    Resolver(const ContextInterface& context, const std::vector<const Handle*>& rootLineage, const std::vector<const Handle*>& parentLineage,
        bool followLinks, MountPolicy mounts, const ResolverLimits& limits, std::size_t* ledger)
        : mContext(context),
          mRootLineage(rootLineage),
          mParentLineage(parentLineage),
          mFollowLinks(followLinks),
          mMounts(mounts),
          mLimits(limits),
          mLedger(ledger)
    {
    }

    Result<Detail::ResolvedPath> Run(std::string component)
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
        mRootPins = mInputPins;
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
            auto baseline = MountId(mContext, procfs.fdinfo.Get().Value(), mRootLineage.back()->mDescriptor.Get().Value(), mLimits.shared.fdinfoBytes);
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

    Result<std::uint64_t> ObservedMount(int descriptor)
    {
        VerifiedProcfs procfs(mContext);
        auto verified = procfs.Open();
        if (!verified.HasValue())
        {
            return std::move(verified).Error();
        }
        auto mount = MountId(mContext, procfs.fdinfo.Get().Value(), descriptor, mLimits.shared.fdinfoBytes);
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

    Result<Detail::ResolvedPath> ContinueAfterBaseline(std::string component)
    {
        Detail::ResolvedPath resolved;
        auto resolution = [&]() -> Result<bool> {
            if (!CanRetain(sizeof(std::string) + component.size()))
            {
                return Error("Initial resolution exceeds retained-memory budget", E2BIG);
            }
            mRetained += sizeof(std::string) + component.size();
            std::vector<const Handle*> directories(mParentLineage);
            std::deque<std::string> pending;
            pending.emplace_back(std::move(component));
            const Handle* last = directories.back();
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
                // Restrict normal intermediate directory opens; on ENOTDIR retry
                // only as O_PATH|O_NOFOLLOW to inspect a pinned symlink without
                // ever causing an operational open of a substituted special file.
                const int baseFlags = O_PATH | O_NOFOLLOW | O_CLOEXEC;
                int descriptor =
                    mContext.OpenNativeAt(directories.back()->mDescriptor.Get().Value(), name.c_str(), baseFlags | (pending.empty() ? 0 : O_DIRECTORY));
                if ((descriptor < 0) && (errno == ENOTDIR) && !pending.empty())
                {
                    descriptor = mContext.OpenNativeAt(directories.back()->mDescriptor.Get().Value(), name.c_str(), baseFlags);
                }
                const int openError = SavedError();
                Descriptor acquired = Descriptor::Take(mContext, descriptor);
                auto step = [&]() -> Result<bool> {
                    if (!acquired.HasValue())
                    {
                        return Error("Cannot pin confined component", openError);
                    }
                    struct stat snapshot = {};
                    if (mContext.StatFileDescriptor(acquired.Get().Value(), &snapshot) != 0)
                    {
                        return Error("Cannot inspect confined component", SavedError());
                    }
                    auto mount = ObservedMount(acquired.Get().Value());
                    if (!mount.HasValue())
                    {
                        return std::move(mount).Error();
                    }

                    if ((mMounts == MountPolicy::StayOnRootMount) && (mount.Value() != mBaseline))
                    {
                        return Error("Component crosses accepted root mount", EXDEV);
                    }

                    if (S_ISLNK(snapshot.st_mode))
                    {
                        if (!mFollowLinks)
                        {
                            return Error("Descendant symlink following is disabled", ELOOP);
                        }

                        if (++expansions > mLimits.linkExpansions)
                        {
                            return Error("Symlink expansion budget exhausted", ELOOP);
                        }
                        auto target = Detail::ReadPinnedLink(mContext, acquired.Get().Value(), mLimits.linkTargetBytes, mLimits.shared.fdinfoBytes);
                        if (!target.HasValue())
                        {
                            return std::move(target).Error();
                        }

                        if (firstComponent)
                        {
                            resolved.mInitialLinkMetadata = snapshot;
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
                            const std::size_t remaining = mLimits.shared.work - ((mLedger != nullptr) ? *mLedger : mSpent);
                            PrefixLimits prefix = mLimits.shared;
                            prefix.work = remaining;
                            // The prefix walk also charges the committed work budget.
                            const std::size_t chunks = (prefix.fdinfoBytes / 256) + ((prefix.fdinfoBytes % 256) ? 1 : 0);
                            const std::size_t cost = 128 + 4 * chunks;
                            if ((mRootLineage.size() > remaining / cost) || (mSteps > prefix.components) || (mRootLineage.size() > prefix.components - mSteps))
                            {
                                return Error("Absolute candidate exceeds remaining work budget", E2BIG);
                            }
                            const std::size_t otherInputPins = mInputPins - mRootPins;
                            if (otherInputPins + resolved.mPins.size() + 1 > mLimits.shared.liveDescriptors)
                            {
                                return Error("Absolute candidate exceeds live-descriptor budget", EMFILE);
                            }
                            prefix.liveDescriptors = mLimits.shared.liveDescriptors - otherInputPins - resolved.mPins.size() - 1;
                            if (mRetained > mLimits.shared.retainedBytes)
                            {
                                return Error("Absolute candidate exceeds retained-memory budget", E2BIG);
                            }
                            prefix.retainedBytes = mLimits.shared.retainedBytes - mRetained;
                            auto suffix = Handle::ValidateAbsolutePrefix(mContext, mRootLineage, text, prefix);
                            mSpent += mRootLineage.size() * cost;
                            if (mLedger != nullptr)
                            {
                                *mLedger += mRootLineage.size() * cost;
                            }
                            mSteps += mRootLineage.size();
                            if (!suffix.HasValue())
                            {
                                return std::move(suffix).Error();
                            }
                            text = std::move(suffix).Value();
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
                        return Error("Unsupported confined object type", EOPNOTSUPP);
                    }

                    if ((!pending.empty()) && !S_ISDIR(snapshot.st_mode))
                    {
                        return Error("Intermediate component is not a directory", ENOTDIR);
                    }
                    const std::size_t ownerBytes = sizeof(Handle) + name.size() + (S_ISDIR(snapshot.st_mode) ? 4 * sizeof(const Handle*) : 0);
                    if (!CanRetain(ownerBytes))
                    {
                        return Error("Confined resolution retained-memory budget exhausted", E2BIG);
                    }
                    mRetained += ownerBytes;
                    Handle staged(std::move(acquired), S_ISDIR(snapshot.st_mode) ? Handle::Type::Directory : Handle::Type::RegularFile, std::move(name), snapshot);
                    resolved.mPins.emplace_back(std::move(staged));
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

            if (finalDirectoryRequired && (last->AcquiredType() != Handle::Type::Directory))
            {
                return Error("Trailing slash requires a directory", ENOTDIR);
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
    std::size_t* mLedger;
    std::vector<const Handle*> mSeen;
    std::size_t mInputPins = 0, mRootPins = 0, mRetained = 0, mSteps = 0, mSpent = 0;
    std::uint64_t mBaseline = 0;
};

Result<Detail::ResolvedPath> Path::ResolveChild(const ContextInterface& context, const std::vector<const Handle*>& rootLineage,
    const std::vector<const Handle*>& parentLineage, std::string component, bool followSymlinks, MountPolicy mounts, const ResolverLimits& limits,
    std::size_t* ledger)
{
    return Resolver(context, rootLineage, parentLineage, followSymlinks, mounts, limits, ledger).Run(std::move(component));
}

Path::Path(const ContextInterface& context, ResolverLimits limits)
    : mContext(&context),
      mLimits(limits),
      mDetachedResources(std::make_shared<Detail::DetachedResources>())
{
}

Path::Path(Path&& other) noexcept
    : mContext(other.mContext),
      mLimits(other.mLimits),
      mWorkSpent(other.mWorkSpent),
      mDetachedResources(std::move(other.mDetachedResources)),
      mStoredMemory(other.mStoredMemory),
      mRootMountId(other.mRootMountId),
      mProcessRoot(std::move(other.mProcessRoot)),
      mRootStages(std::move(other.mRootStages)),
      mStages(std::move(other.mStages)),
      mRetiredStages(std::move(other.mRetiredStages)),
      mComponents(std::move(other.mComponents)),
      mRootLineage(std::move(other.mRootLineage)),
      mCurrentLineage(std::move(other.mCurrentLineage)),
      mCloseAttempted(other.mCloseAttempted),
      mCloseError(other.mCloseError)
{
    other.mStoredMemory = 0;
    other.mCloseAttempted = false;
    other.mCloseError = 0;
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
        swap(mWorkSpent, incoming.mWorkSpent);
        mDetachedResources.swap(incoming.mDetachedResources);
        swap(mStoredMemory, incoming.mStoredMemory);
        swap(mRootMountId, incoming.mRootMountId);
        mProcessRoot.swap(incoming.mProcessRoot);
        mRootStages.swap(incoming.mRootStages);
        mStages.swap(incoming.mStages);
        mRetiredStages.swap(incoming.mRetiredStages);
        mComponents.swap(incoming.mComponents);
        mRootLineage.swap(incoming.mRootLineage);
        mCurrentLineage.swap(incoming.mCurrentLineage);
        swap(mCloseAttempted, incoming.mCloseAttempted);
        swap(mCloseError, incoming.mCloseError);
    }
    return *this;
}

Path::~Path() noexcept
{
    if (!mCloseAttempted && (mProcessRoot || !mComponents.empty() || !mRootStages.empty() || !mStages.empty() || !mRetiredStages.empty()))
    {
        try
        {
            (void)Close();
        }
        catch (...)
        {
            OsConfigLogError(nullptr, "Acquired path destruction close failure: %d", mCloseError != 0 ? mCloseError : EIO);
        }

        if (mCloseError != 0)
        {
            try
            {
                OsConfigLogError(mContext->GetLogHandle(), "Failed to close acquired filesystem path: %d", mCloseError);
            }
            catch (...)
            {
                OsConfigLogError(nullptr, "Acquired path close log failure: %d", mCloseError);
            }
        }
    }
}

Result<bool> Path::Close()
{
    if (mCloseAttempted)
    {
        if (mCloseError != 0)
        {
            return Error("Cannot close acquired filesystem path", mCloseError);
        }
        return true;
    }
    mCloseAttempted = true;
    // Drop borrowed pointers before any owner is destroyed; no later
    // operation may inspect a lineage after terminal release.
    mRootLineage.clear();
    mCurrentLineage.clear();
    auto release = [this](Handle& pin) {
        const int error = pin.CloseOnce();
        if (error != 0)
        {
            if (mCloseError == 0)
            {
                mCloseError = error;
            }
            else
            {
                try
                {
                    OsConfigLogError(mContext->GetLogHandle(), "Secondary filesystem pin close failure: %d", error);
                }
                catch (...)
                {
                    OsConfigLogError(nullptr, "Secondary filesystem pin close log failure: %d", error);
                }
            }
        }
    };
    for (auto stage = mStages.rbegin(); stage != mStages.rend(); ++stage)
    {
        for (auto pin = stage->mPins.rbegin(); pin != stage->mPins.rend(); ++pin)
        {
            release(*pin);
        }
    }

    for (auto stage = mRetiredStages.rbegin(); stage != mRetiredStages.rend(); ++stage)
    {
        for (auto pin = stage->mPins.rbegin(); pin != stage->mPins.rend(); ++pin)
        {
            release(*pin);
        }
    }

    for (auto stage = mRootStages.rbegin(); stage != mRootStages.rend(); ++stage)
    {
        for (auto pin = stage->mPins.rbegin(); pin != stage->mPins.rend(); ++pin)
        {
            release(*pin);
        }
    }

    for (auto pin = mComponents.rbegin(); pin != mComponents.rend(); ++pin)
    {
        release(*pin);
    }

    if (mProcessRoot)
    {
        release(*mProcessRoot);
    }
    mStages.clear();
    mRetiredStages.clear();
    mRootStages.clear();
    mComponents.clear();
    mProcessRoot.reset();
    mStoredMemory = 0;
    if (mCloseError != 0)
    {
        return Error("Cannot close acquired filesystem path", mCloseError);
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
    if ((mWorkSpent > mLimits.shared.work) || (cost > mLimits.shared.work - mWorkSpent))
    {
        return false;
    }
    mWorkSpent += cost;
    return true;
}

std::size_t Path::HeldDescriptors() const noexcept
{
    std::size_t count = mComponents.size() + ((mProcessRoot != nullptr) ? 1 : 0) + (mDetachedResources ? mDetachedResources->descriptors : 0);
    for (const auto& stage : mRootStages)
    {
        count += stage.OwnedDescriptors();
    }

    for (const auto& stage : mStages)
    {
        count += stage.OwnedDescriptors();
    }

    for (const auto& stage : mRetiredStages)
    {
        count += stage.OwnedDescriptors();
    }
    return count;
}

Result<std::uint64_t> Path::RootMountId() const
{
    VerifiedProcfs procfs(*mContext);
    auto opened = procfs.Open();
    if (!opened.HasValue())
    {
        return std::move(opened).Error();
    }
    auto mount = MountId(*mContext, procfs.fdinfo.Get().Value(), mComponents.front().mDescriptor.Get().Value(), mLimits.shared.fdinfoBytes);
    auto closed = procfs.Close();
    if (!closed.HasValue())
    {
        if (mount.HasValue())
        {
            return std::move(closed).Error();
        }
        Detail::LogSecondaryClose(*mContext, closed.Error().code);
    }
    return mount;
}

Result<Handle> Path::RetainLeaf(Detail::ResolvedPath& stage, const std::string& component)
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
    const int duplicateFd = ::fcntl(source.mDescriptor.Get().Value(), F_DUPFD_CLOEXEC, 0);
    const int duplicateError = SavedError();
    Descriptor duplicate = Descriptor::Take(*mContext, duplicateFd);
    auto retained = [&]() -> Result<Handle> {
        if (!duplicate.HasValue())
        {
            return Error("Cannot retain pinned directory", duplicateError);
        }
        struct stat snapshot = {};
        if (mContext->StatFileDescriptor(duplicate.Get().Value(), &snapshot) != 0)
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
                Detail::LogSecondaryClose(*mContext, closed.Error().code);
            }
            return primary;
        }

        if (!matched.Value())
        {
            const Error primary("Retained directory mount differs from its source", EAGAIN);
            auto closed = candidate.Close();
            if (!closed.HasValue())
            {
                Detail::LogSecondaryClose(*mContext, closed.Error().code);
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
        Detail::LogSecondaryClose(*mContext, closed.Error().code);
    }
    return retained;
}

Result<Path> Path::AcquireRoot(const ContextInterface& context, std::string absoluteRoot, RootPolicy policy, ResolverLimits limits, bool regularFileRoot)
{
    if ((absoluteRoot.empty()) || (absoluteRoot.front() != '/') || (absoluteRoot.find('\0') != std::string::npos) || (limits.shared.work == 0) ||
        (limits.shared.components == 0) || (limits.shared.liveDescriptors == 0) || (limits.shared.retainedBytes == 0) ||
        (limits.shared.targetBytes == 0) || (limits.shared.fdinfoBytes == 0) || (limits.linkTargetBytes == 0) || (limits.linkExpansions == 0) ||
        (limits.depth == 0) || (absoluteRoot.size() > limits.shared.retainedBytes) || (limits.shared.liveDescriptors < 8) ||
        ((policy.symlinks != SymlinkPolicy::Reject) && (policy.symlinks != SymlinkPolicy::FollowWithinRoot)) ||
        ((policy.mounts != MountPolicy::AllowCrossing) && (policy.mounts != MountPolicy::StayOnRootMount)))
    {
        return Error("An absolute authorized directory, policy and positive budgets are required", EINVAL);
    }
    Path path(context, limits);
    auto acquired = [&]() -> Result<bool> {
        if (!path.ChargeWork())
        {
            return Error("Root acquisition work budget exhausted", E2BIG);
        }
        auto process = Handle::PinProcessRoot(context);
        if (!process.HasValue())
        {
            return std::move(process).Error();
        }

        if (("/" == absoluteRoot) && regularFileRoot)
        {
            return Error("Expected a regular file root", EISDIR);
        }

        if ("/" == absoluteRoot)
        {
            path.mComponents.emplace_back(std::move(process).Value());
            path.mRootLineage.push_back(&path.mComponents.front());
            path.mCurrentLineage = path.mRootLineage;
            path.mStoredMemory = sizeof(Handle) + 1;
        }
        else
        {
            path.mProcessRoot.reset(new Handle(std::move(process).Value()));
            path.mRootLineage.push_back(path.mProcessRoot.get());
            std::vector<const Handle*> parent = path.mRootLineage;
            for (std::size_t position = 1; position < absoluteRoot.size();)
            {
                const std::size_t slash = absoluteRoot.find('/', position);
                const std::size_t end = (slash == std::string::npos) ? absoluteRoot.size() : slash;
                const std::string component = absoluteRoot.substr(position, end - position);
                if (!Detail::IsSingleChildComponent(component))
                {
                    return Error("Root contains an invalid component", EINVAL);
                }

                if ((path.HeldDescriptors() > limits.shared.liveDescriptors - 7) || (path.mStoredMemory >= limits.shared.retainedBytes))
                {
                    return Error("Root lineage exceeds resource budget", E2BIG);
                }
                ResolverLimits available = limits;
                available.shared.liveDescriptors -= path.HeldDescriptors() - 1;
                available.shared.retainedBytes -= path.mStoredMemory;
                auto next = ResolveChild(context, path.mRootLineage, parent, component, policy.symlinks == SymlinkPolicy::FollowWithinRoot,
                    policy.mounts, available, &path.mWorkSpent);
                if (!next.HasValue())
                {
                    return std::move(next).Error();
                }
                const bool finalComponent = (slash == std::string::npos);
                if ((next.Value().Leaf().AcquiredType() != Handle::Type::Directory) &&
                    !(regularFileRoot && finalComponent && (next.Value().Leaf().AcquiredType() == Handle::Type::RegularFile)))
                {
                    return Error("Configured root component is not a directory", ENOTDIR);
                }
                const std::size_t bytes = next.Value().AccountedBytes();
                if (bytes > limits.shared.retainedBytes - path.mStoredMemory)
                {
                    return Error("Root lineage exceeds retained-memory budget", E2BIG);
                }
                path.mStoredMemory += bytes;
                path.mRootStages.emplace_back(std::move(next).Value());
                parent = path.mRootStages.back().DirectoryLineage();
                position = (slash == std::string::npos) ? absoluteRoot.size() : slash + 1;
            }

            if (path.mRootStages.empty())
            {
                return Error("Configured root needs a directory component", EINVAL);
            }
            const std::string rootName = path.mRootStages.back().Leaf().Component();
            auto ownedRoot = path.RetainLeaf(path.mRootStages.back(), rootName);
            if (!ownedRoot.HasValue())
            {
                return std::move(ownedRoot).Error();
            }
            path.mComponents.emplace_back(std::move(ownedRoot).Value());
            path.mRootStages.back().ForwardLeaf(path.mComponents.front());
            path.mRootLineage = path.mRootStages.back().DirectoryLineage();
            path.mRootLineage.back() = &path.mComponents.front();
            path.mCurrentLineage.assign(1, &path.mComponents.front());
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
        if (regularFileRoot && (path.Root().AcquiredType() != Handle::Type::RegularFile))
        {
            return Error("Expected a regular file root", EISDIR);
        }

        if (!regularFileRoot && (path.Root().AcquiredType() != Handle::Type::Directory))
        {
            return Error("Expected a directory root", ENOTDIR);
        }
        return true;
    }();
    if (!acquired.HasValue())
    {
        auto primary = std::move(acquired).Error();
        auto closed = path.Close();
        if (!closed.HasValue())
        {
            Detail::LogSecondaryClose(context, closed.Error().code);
        }
        return primary;
    }
    return std::move(path);
}

Result<Optional<Path::ChildObservation>> Path::ObserveChild(const std::string& component, std::size_t fdinfoByteCap) const
{
    if (mComponents.empty() || (Leaf().AcquiredType() != Handle::Type::Directory) || !Detail::IsSingleChildComponent(component))
    {
        return Error("A live directory and one child name are required", EINVAL);
    }
    // Verify the parent through the same trusted-procfs route as all pinned
    // operations before observing its child. A failed procfs check is fatal.
    auto parent = Leaf().Stat(fdinfoByteCap);
    if (!parent.HasValue())
    {
        return std::move(parent).Error();
    }
    const int childFd = mContext->OpenNativeAt(Leaf().mDescriptor.Get().Value(), component.c_str(), O_PATH | O_NOFOLLOW | O_CLOEXEC);
    const int openError = SavedError();
    Descriptor child = Descriptor::Take(*mContext, childFd);
    auto observedResult = [&]() -> Result<Optional<ChildObservation>> {
        if (!child.HasValue())
        {
            if (openError == ENOENT)
            {
                return Optional<ChildObservation>();
            }
            return Error("Cannot observe pinned directory child", openError);
        }
        ChildObservation observed;
        if (mContext->StatFileDescriptor(child.Get().Value(), &observed.metadata) != 0)
        {
            return Error("Cannot inspect pinned directory child", SavedError());
        }
        VerifiedProcfs procfs(*mContext);
        auto verified = procfs.Open();
        if (!verified.HasValue())
        {
            return std::move(verified).Error();
        }
        auto mount = MountId(*mContext, procfs.fdinfo.Get().Value(), child.Get().Value(), fdinfoByteCap);
        auto closed = procfs.Close();
        if (!closed.HasValue())
        {
            if (mount.HasValue())
            {
                mount = std::move(closed).Error();
            }
            else
            {
                Detail::LogSecondaryClose(*mContext, closed.Error().code);
            }
        }
        if (!mount.HasValue())
        {
            return std::move(mount).Error();
        }
        observed.mountId = mount.Value();
        return Optional<ChildObservation>(std::move(observed));
    }();
    auto closed = child.Close();
    if (!closed.HasValue())
    {
        if (observedResult.HasValue())
        {
            return std::move(closed).Error();
        }
        Detail::LogSecondaryClose(*mContext, closed.Error().code);
    }
    return observedResult;
}

Optional<struct stat> Path::LeafLinkMetadata() const
{
    if (mComponents.size() > 1)
    {
        return mStages.back().mInitialLinkMetadata;
    }
    return mRootStages.empty() ? Optional<struct stat>() : mRootStages.back().mInitialLinkMetadata;
}

Result<bool> Path::Push(std::string component, ExtensionPolicy policy)
{
    if (mComponents.empty())
    {
        return Error("Path has no accepted root", EINVAL);
    }

    if (!Detail::IsSingleChildComponent(component) || (policy.symlinks != SymlinkPolicy::Reject && policy.symlinks != SymlinkPolicy::FollowWithinRoot) ||
        (policy.mounts != MountPolicy::AllowCrossing && policy.mounts != MountPolicy::StayOnRootMount))
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

    if (mComponents.back().AcquiredType() != Handle::Type::Directory)
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

    if ((mStoredMemory > mLimits.shared.retainedBytes) || (mDetachedResources->bytes >= mLimits.shared.retainedBytes - mStoredMemory))
    {
        return Error("Path retained-memory budget exhausted", E2BIG);
    }
    ResolverLimits available = mLimits;
    std::vector<const Handle*> unique = mRootLineage;
    for (const Handle* pin : mCurrentLineage)
    {
        if (unique.end() == std::find(unique.begin(), unique.end(), pin))
        {
            unique.push_back(pin);
        }
    }
    available.shared.liveDescriptors -= held - unique.size();
    available.shared.retainedBytes -= mStoredMemory + mDetachedResources->bytes;
    auto resolved = ResolveChild(*mContext, mRootLineage, mCurrentLineage, std::move(component), policy.symlinks == SymlinkPolicy::FollowWithinRoot,
        policy.mounts, available, &mWorkSpent);
    if (!resolved.HasValue())
    {
        return std::move(resolved).Error();
    }
    const std::size_t bytes = resolved.Value().AccountedBytes();
    if (bytes > mLimits.shared.retainedBytes - mStoredMemory - mDetachedResources->bytes)
    {
        return Error("Path retained-memory budget exhausted", E2BIG);
    }
    const std::string name = resolved.Value().Leaf().Component();
    auto leaf = RetainLeaf(resolved.Value(), name);
    if (!leaf.HasValue())
    {
        return std::move(leaf).Error();
    }
    mComponents.emplace_back(std::move(leaf).Value());
    bool stageAdded = false;
    try
    {
        resolved.Value().ForwardLeaf(mComponents.back());
        mStages.emplace_back(std::move(resolved).Value());
        stageAdded = true;
        auto physical = mStages.back().DirectoryLineage();
        mCurrentLineage.swap(physical);
    }
    catch (...)
    {
        if (stageAdded)
        {
            mStages.pop_back();
        }
        mComponents.pop_back();
        throw;
    }
    mStoredMemory += bytes;
    return true;
}

Result<Handle> Path::Pop()
{
    if (mComponents.empty())
    {
        return Error("Cannot pop an empty path", EINVAL);
    }
    // Prepare the surviving physical lineage before transferring ownership:
    // allocation failure must leave the stack and every borrow unchanged.
    std::vector<const Handle*> surviving;
    if (mComponents.size() > 2)
    {
        surviving = mStages[mStages.size() - 2].DirectoryLineage();
    }
    else if (mComponents.size() == 2)
    {
        surviving.push_back(&mComponents.front());
    }

    const bool retainStage = mComponents.size() > 1 && mStages.back().OwnedDescriptors() != 0;
    if (retainStage)
    {
        // Allocate before transferring the leaf; failure leaves the
        // existing path and all its borrows intact.
        mRetiredStages.emplace_back(std::move(mStages.back()));
        mStages.pop_back();
        auto& retired = mRetiredStages.back();
        retired.mFrames.clear();
        retired.mBorrowedLeaf = nullptr;
        retired.mForwardedLeaf = nullptr;
    }
    const std::size_t bytes = sizeof(Handle) + mComponents.back().mComponent.size();
    Handle removed(std::move(mComponents.back()));
    mComponents.pop_back();
    removed.mDetachedResources = mDetachedResources;
    removed.mDetachedBytes = bytes;
    ++mDetachedResources->descriptors;
    mDetachedResources->bytes += bytes;
    if (mComponents.empty())
    {
        // No implicit reset or new acquisition authority after root removal.
        // Keep the remaining acquisition pins for a checked Path::Close,
        // even when the caller has popped the root itself. The popped pin
        // belongs only to its new Handle owner.
        for (auto& stage : mRootStages)
        {
            stage.mFrames.clear();
            stage.mBorrowedLeaf = nullptr;
            stage.mForwardedLeaf = nullptr;
        }
        mRootLineage.clear();
        mCurrentLineage.clear();
        if (mRootStages.empty())
        {
            mStoredMemory = 0;
        }
        else if (mRootStages.back().mLeafTaken)
        {
            // The final root leaf was transferred out of its stage. Its
            // handle/name charge is now held by the detached ledger.
            mStoredMemory -= bytes;
        }
    }
    else
    {
        if (retainStage)
        {
            if (mRetiredStages.back().mLeafTaken)
            {
                // The owned leaf left the stage; its charge moved to the
                // detached-handle ledger. Hidden pins remain in the Path.
                mStoredMemory -= bytes;
            }
        }
        else
        {
            // Stages without live pins have no checked closes to defer.
            mStoredMemory -= mStages.back().AccountedBytes();
            mStages.pop_back();
        }
        mCurrentLineage.swap(surviving);
    }
    return std::move(removed);
}

std::size_t Path::RetainedDescriptors() const noexcept
{
    return HeldDescriptors();
}

std::size_t Path::RetainedBytes() const noexcept
{
    return mStoredMemory + (mDetachedResources ? mDetachedResources->bytes : 0);
}

const Handle& Path::Root() const
{
    if (mComponents.empty())
    {
        throw std::logic_error("Path has no accepted root");
    }
    return mComponents.front();
}

const Handle& Path::Leaf() const
{
    if (mComponents.empty())
    {
        throw std::logic_error("Path has no leaf");
    }
    return mComponents.back();
}

std::size_t Path::Size() const noexcept
{
    return mComponents.size();
}
} // namespace Filesystem
} // namespace ComplianceEngine
