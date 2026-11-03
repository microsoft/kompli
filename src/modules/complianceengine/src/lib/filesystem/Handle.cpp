// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "Handle.hpp"

#include "ContextInterface.h"
#include "FilesystemHelpers.hpp"
#include "Optional.h"
#include "ProcfsDescriptorAccess.hpp"
#include "ReadableFile.hpp"

#include <cerrno>
#include <cstdint>
#include <dirent.h>
#include <fcntl.h>
#include <utility>

namespace ComplianceEngine
{
namespace Filesystem
{
using Detail::Descriptor;
using Detail::LogSecondaryClose;
using Detail::ProcfsDescriptorAccess;
using Detail::SameIdentity;
using Detail::SavedError;

// The live O_PATH pin holds its kernel path (including mount). A verified
// current-task procfd alias of that pin opens the same path; inode/type checks
// still reject a wrong-object alias. Direct-test pins without an acquisition
// mount retain the independent fdinfo comparisons below.
Result<bool> Handle::OpenAndVerifyAlias(const ContextInterface& context, const ProcfsDescriptorAccess& procfs, const Descriptor& pin,
    Descriptor& aliasOwner, const struct stat& before, bool directory, std::size_t fdinfoByteCap, const std::uint64_t* heldMount)
{
    Result<std::uint64_t> pinnedMount = heldMount ? Result<std::uint64_t>(*heldMount) : procfs.ReadMountId(pin, fdinfoByteCap);
    if (!pinnedMount.HasValue())
    {
        return std::move(pinnedMount).Error();
    }
    // Only the decimal alias of the held pin is followed intentionally.
    auto aliasResult = context.OpenAlias(procfs, pin, directory, ContextInterface::CloseDiagnostic::DirectoryActivation);
    if (!aliasResult.HasValue())
    {
        return Error("Cannot open pinned descriptor alias for reading", aliasResult.Error().code);
    }
    aliasOwner = std::move(aliasResult).Value();
    // After acquisition, the caller owns this output even if later verification fails.
    if (!aliasOwner.HasValue())
    {
        return Error("Cannot open pinned descriptor alias for reading", EPROTO);
    }
    struct stat activated = {}, stillPinned = {};
    if ((context.StatFile(aliasOwner, &activated) != 0) || (context.StatFile(pin, &stillPinned) != 0))
    {
        return Error("Cannot inspect activated object and pin", SavedError());
    }

    if (!SameIdentity(before, activated) || !SameIdentity(before, stillPinned))
    {
        return Error("Activated object does not match live pin", EAGAIN);
    }
    if (!heldMount)
    {
        auto activatedMount = procfs.ReadMountId(aliasOwner, fdinfoByteCap);
        if (!activatedMount.HasValue())
            return std::move(activatedMount).Error();
        auto retainedMount = procfs.ReadMountId(pin, fdinfoByteCap);
        if (!retainedMount.HasValue())
            return std::move(retainedMount).Error();
        if ((pinnedMount.Value() != activatedMount.Value()) || (pinnedMount.Value() != retainedMount.Value()))
            return Error("Activated object mount does not match live pin", EAGAIN);
    }
    return true;
}

Result<Descriptor> Handle::ActivateReadOnlyImpl(const ContextInterface& context, const Descriptor& pin, const struct stat& snapshot, bool directory,
    std::size_t fdinfoByteCap, const std::uint64_t* heldMount)
{
    if (!pin.HasValue())
    {
        return Error("Read-only activation requires a live pin", EBADF);
    }

    if ((fdinfoByteCap == 0) || (fdinfoByteCap >= std::string().max_size()))
    {
        return Error("Invalid procfs descriptor information byte cap", EINVAL);
    }
    struct stat before = {};
    if (context.StatFile(pin, &before) != 0)
    {
        return Error("Cannot inspect pinned object", SavedError());
    }

    if (!SameIdentity(before, snapshot))
    {
        return Error("Pinned object identity changed", EAGAIN);
    }

    if ((directory && !S_ISDIR(before.st_mode)) || (!directory && !S_ISREG(before.st_mode)))
    {
        return Error("Pinned object has an unsupported type", EINVAL);
    }
    const int pinFlags = context.StatusFlags(pin);
    if (pinFlags < 0)
    {
        return Error("Cannot inspect pinned descriptor flags", SavedError());
    }
    const int pinDescriptorFlags = context.DescriptorFlags(pin);
    if (pinDescriptorFlags < 0)
    {
        return Error("Cannot inspect pinned descriptor flags", SavedError());
    }

    if (((pinFlags & O_PATH) == 0) || ((pinDescriptorFlags & FD_CLOEXEC) == 0))
    {
        return Error("Pinned object is not a close-on-exec O_PATH descriptor", EINVAL);
    }

    ProcfsDescriptorAccess procfs(context);
    auto verified = procfs.Open();
    if (!verified.HasValue())
    {
        return std::move(verified).Error();
    }
    Descriptor aliasOwner = context.EmptyDescriptor(ContextInterface::CloseDiagnostic::DirectoryActivation);
    auto inspected = OpenAndVerifyAlias(context, procfs, pin, aliasOwner, before, directory, fdinfoByteCap, heldMount);
    auto procfsClose = procfs.Close();
    if (!procfsClose.HasValue())
    {
        if (inspected.HasValue())
        {
            inspected = std::move(procfsClose).Error();
        }
        else
        {
            LogSecondaryClose(context, procfsClose.Error().code);
        }
    }
    if (!inspected.HasValue())
    {
        auto primary = std::move(inspected).Error();
        auto cleanup = aliasOwner.Close();
        if (!cleanup.HasValue())
        {
            LogSecondaryClose(context, cleanup.Error().code);
        }
        return primary;
    }
    // The alias must remain owned until all procfs checks and
    // helper closes have succeeded; output transfer occurs below.
    return std::move(aliasOwner);
}

Result<Descriptor> Handle::ActivateReadOnly(const ContextInterface& context, const Descriptor& pin, const struct stat& snapshot, bool directory, std::size_t fdinfoByteCap)
{
    return ActivateReadOnlyImpl(context, pin, snapshot, directory, fdinfoByteCap, nullptr);
}

Handle::Handle(Detail::Descriptor&& descriptor, Type type, const struct stat& snapshot, std::size_t fdinfoBytes, std::uint64_t originalMount, std::uint64_t targetMount)
    : mDescriptor(std::move(descriptor)),
      mType(type),
      mOriginalMount(originalMount),
      mTargetMount(targetMount),
      mAcquiredMetadata(snapshot),
      mFdinfoBytes(fdinfoBytes)
{
}

Handle::Handle(Handle&& other) noexcept
    : mDescriptor(std::move(other.mDescriptor)),
      mType(other.mType),
      mOriginalMount(other.mOriginalMount),
      mTargetMount(other.mTargetMount),
      mAcquiredMetadata(other.mAcquiredMetadata),
      mFdinfoBytes(other.mFdinfoBytes)
{
}

Handle& Handle::operator=(Handle&& other) noexcept
{
    if (this != &other)
    {
        Handle incoming(std::move(other));
        Swap(incoming);
    }
    return *this;
}

Handle::~Handle() noexcept = default;

Handle::Type Handle::AcquiredType() const noexcept
{
    return mType;
}

std::uint64_t Handle::OriginalMount() const noexcept
{
    return mOriginalMount;
}

struct stat Handle::AcquiredMetadata() const noexcept
{
    return mAcquiredMetadata;
}

Result<Handle::PinObservation> Handle::InspectWithProcfs(const ProcfsDescriptorAccess& procfs) const
{
    if (!mDescriptor.HasValue())
    {
        return Error("Metadata inspection requires a live pin", EBADF);
    }
    const auto& context = mDescriptor.Context();
    const int flags = context.StatusFlags(mDescriptor);
    if (flags < 0)
    {
        return Error("Cannot inspect pinned descriptor flags", SavedError());
    }
    const int descriptorFlags = context.DescriptorFlags(mDescriptor);
    if (descriptorFlags < 0)
    {
        return Error("Cannot inspect pinned descriptor flags", SavedError());
    }

    if (((flags & O_PATH) == 0) || ((descriptorFlags & FD_CLOEXEC) == 0))
    {
        return Error("Metadata operation requires a close-on-exec O_PATH pin", EINVAL);
    }
    struct stat before = {}, after = {};
    if (context.StatFile(mDescriptor, &before) != 0)
    {
        return Error("Cannot inspect pinned metadata", SavedError());
    }

    if (!SameIdentity(before, mAcquiredMetadata) || ((mType == Type::RegularFile) && !S_ISREG(before.st_mode)) ||
        ((mType == Type::Directory) && !S_ISDIR(before.st_mode)))
    {
        return Error("Pinned metadata has an unexpected identity or type", EAGAIN);
    }
    if (context.StatFile(mDescriptor, &after) != 0)
    {
        return Error("Cannot recheck pinned metadata", SavedError());
    }

    if (!SameIdentity(before, after))
    {
        return Error("Pinned metadata identity changed", EAGAIN);
    }
    // Stat remains fresh; mount identity is held by the live O_PATH owner.
    // The verified procfs session is still opened/closed by callers, so
    // caller/role failures and cleanup precedence are unchanged.
    (void)procfs;
    return PinObservation{after};
}

Result<struct stat> Handle::Stat() const
{
    if (!mDescriptor.HasValue())
    {
        return Error("Fresh inspection requires a live pin", EBADF);
    }
    const auto& context = mDescriptor.Context();
    ProcfsDescriptorAccess procfs(context);
    auto opened = procfs.Open();
    if (!opened.HasValue())
    {
        return std::move(opened).Error();
    }
    auto inspected = InspectWithProcfs(procfs);
    auto closed = procfs.Close();
    if (!closed.HasValue())
    {
        if (inspected.HasValue())
        {
            return std::move(closed).Error();
        }
        Detail::LogSecondaryClose(context, closed.Error().code);
    }
    if (!inspected.HasValue())
    {
        return std::move(inspected).Error();
    }
    return inspected.Value().metadata;
}

Result<std::uint64_t> Handle::MountIdentity() const
{
    if (!mDescriptor.HasValue())
    {
        return Error("Mount inspection requires a live pin", EBADF);
    }
    const auto& context = mDescriptor.Context();
    ProcfsDescriptorAccess procfs(context);
    auto opened = procfs.Open();
    if (!opened.HasValue())
    {
        return std::move(opened).Error();
    }
    auto inspected = InspectWithProcfs(procfs);
    auto closed = procfs.Close();
    if (!closed.HasValue())
    {
        if (inspected.HasValue())
        {
            return std::move(closed).Error();
        }
        Detail::LogSecondaryClose(context, closed.Error().code);
    }
    if (!inspected.HasValue())
    {
        return std::move(inspected).Error();
    }
    return mTargetMount;
}

Result<bool> Handle::SetOwnership(uid_t owner, gid_t group) const
{
    if (!mDescriptor.HasValue())
    {
        return Error("Ownership change requires a live pin", EBADF);
    }
    const auto& context = mDescriptor.Context();
    ProcfsDescriptorAccess procfs(context);
    auto opened = procfs.Open();
    if (!opened.HasValue())
    {
        return std::move(opened).Error();
    }
    auto changed = [&]() -> Result<bool> {
        auto beforeMutation = InspectWithProcfs(procfs);
        if (!beforeMutation.HasValue())
        {
            return std::move(beforeMutation).Error();
        }
        // AT_EMPTY_PATH acts on the O_PATH pin itself. No alias or target
        // pathname is needed, including for an unreadable regular file.
        if (context.ChownPinned(mDescriptor, owner, group) != 0)
        {
            return Error("Cannot change pinned ownership", SavedError());
        }
        auto after = InspectWithProcfs(procfs);
        if (!after.HasValue())
        {
            return std::move(after).Error(); // The ownership syscall may already have succeeded.
        }

        return true;
    }();
    auto closed = procfs.Close();
    if (!closed.HasValue())
    {
        if (changed.HasValue())
        {
            return std::move(closed).Error();
        }
        Detail::LogSecondaryClose(context, closed.Error().code);
    }
    return changed;
}

Result<bool> Handle::SetModeWithProcfs(const ProcfsDescriptorAccess& procfs, mode_t mode) const
{
    const auto& context = mDescriptor.Context();
    auto beforeMutation = InspectWithProcfs(procfs);
    if (!beforeMutation.HasValue())
    {
        return std::move(beforeMutation).Error();
    }
    // Only this verified procfs descriptor alias is followed. Opening it
    // with O_PATH validates the alias without requiring content-read
    // permission or triggering special-file open effects.
    auto aliasResult = context.OpenPinAlias(procfs, mDescriptor, mType == Type::Directory);
    if (!aliasResult.HasValue())
    {
        return Error("Cannot inspect pinned mode alias", aliasResult.Error().code);
    }
    Descriptor modeAlias = std::move(aliasResult).Value();
    auto changed = [&]() -> Result<bool> {
        if (!modeAlias.HasValue())
        {
            return Error("Cannot inspect pinned mode alias", EPROTO);
        }
        struct stat target = {};
        if (context.StatFile(modeAlias, &target) != 0)
        {
            return Error("Cannot inspect pinned mode target", SavedError());
        }

        if (!SameIdentity(beforeMutation.Value().metadata, target))
        {
            return Error("Pinned mode alias identity differs", EAGAIN);
        }
        // A genuine current-task procfd alias of this live owner has the
        // same mount; the stat comparison above rejects wrong-object mocks.
        auto retained = InspectWithProcfs(procfs);
        if (!retained.HasValue())
        {
            return std::move(retained).Error();
        }

        // Linux's baseline fchmodat follows the procfd magic link, rather
        // than attempting fchmod on O_PATH or requiring a readable fd.
        if (context.ChmodAlias(procfs, mDescriptor, mode) != 0)
        {
            return Error("Cannot change pinned mode", SavedError());
        }
        auto after = InspectWithProcfs(procfs);
        if (!after.HasValue())
        {
            return std::move(after).Error(); // The chmod syscall may already have succeeded.
        }

        return true;
    }();
    auto aliasClose = modeAlias.Close();
    if (!aliasClose.HasValue())
    {
        if (changed.HasValue())
        {
            return std::move(aliasClose).Error();
        }
        Detail::LogSecondaryClose(context, aliasClose.Error().code);
    }
    return changed;
}

Result<bool> Handle::SetMode(mode_t mode) const
{
    if (!mDescriptor.HasValue())
    {
        return Error("Mode change requires a live pin", EBADF);
    }
    const auto& context = mDescriptor.Context();
    ProcfsDescriptorAccess procfs(context);
    auto opened = procfs.Open();
    if (!opened.HasValue())
    {
        return std::move(opened).Error();
    }
    auto changed = SetModeWithProcfs(procfs, mode);
    auto procfsClose = procfs.Close();
    if (!procfsClose.HasValue())
    {
        if (changed.HasValue())
        {
            return std::move(procfsClose).Error();
        }
        Detail::LogSecondaryClose(context, procfsClose.Error().code);
    }
    return changed;
}

Result<ReadableFile> Handle::OpenReadOnly() const
{
    return OpenReadOnly(ReadableFile::Policy{});
}

Result<ReadableFile> Handle::OpenReadOnly(ReadableFile::Policy policy) const
{
    if (!mDescriptor.HasValue())
    {
        return Error("Read-only activation requires a live file pin", EBADF);
    }

    if (mType != Type::RegularFile)
    {
        return Error("Read-only activation requires a regular file", EINVAL);
    }
    auto activated = ActivateReadOnlyImpl(mDescriptor.Context(), mDescriptor, mAcquiredMetadata, false, mFdinfoBytes, &mTargetMount);
    if (!activated.HasValue())
    {
        return std::move(activated).Error();
    }
    return ReadableFile(std::move(activated).Value(), policy);
}

Result<DirectoryCursor> Handle::OpenChildren() const
{
    if (!mDescriptor.HasValue())
    {
        return Error("Directory enumeration requires a live directory pin", EBADF);
    }
    if (mType != Type::Directory)
    {
        return Error("Directory enumeration requires a directory pin", EINVAL);
    }
    const auto& context = mDescriptor.Context();
    auto activated = ActivateReadOnlyImpl(context, mDescriptor, mAcquiredMetadata, true, mFdinfoBytes, &mTargetMount);
    if (!activated.HasValue())
    {
        return std::move(activated).Error();
    }
    // fdopendir consumes the verified operational descriptor on success;
    // on failure its typed owner retains it and closes exactly once.
    Descriptor operational = std::move(activated).Value();
    auto cursor = context.OpenDirectoryCursor(std::move(operational));
    if (!cursor.HasValue())
    {
        auto primary = std::move(cursor).Error();
        auto closed = operational.Close();
        if (!closed.HasValue())
        {
            Detail::LogSecondaryClose(context, closed.Error().code);
        }
        return primary;
    }
    return cursor;
}

void Handle::Swap(Handle& other) noexcept
{
    using std::swap;
    swap(mDescriptor, other.mDescriptor);
    swap(mType, other.mType);
    swap(mOriginalMount, other.mOriginalMount);
    swap(mTargetMount, other.mTargetMount);
    swap(mAcquiredMetadata, other.mAcquiredMetadata);
    swap(mFdinfoBytes, other.mFdinfoBytes);
}

Result<bool> Handle::Close()
{
    auto closed = mDescriptor.Close();
    if (!closed.HasValue())
    {
        return Error("Cannot close pinned filesystem descriptor", closed.Error().code);
    }
    return true;
}

Result<Handle> Handle::PinProcessRoot(const ContextInterface& context, std::size_t fdinfoBytes)
{
    auto opened = context.OpenAbsolutePin("/");
    if (!opened.HasValue())
    {
        return Error("Cannot pin process root for absolute-prefix validation", opened.Error().code);
    }
    Descriptor acquired = std::move(opened).Value();
    auto pinned = [&]() -> Result<Handle> {
        if (!acquired.HasValue())
        {
            return Error("Cannot pin process root for absolute-prefix validation", EPROTO);
        }
        struct stat snapshot = {};
        if (context.StatFile(acquired, &snapshot) != 0)
        {
            return Error("Cannot inspect process root pin", SavedError());
        }

        if (!S_ISDIR(snapshot.st_mode))
        {
            return Error("Process root is not a directory", ENOTDIR);
        }
        ProcfsDescriptorAccess procfs(context);
        auto verified = procfs.Open();
        if (!verified.HasValue())
            return std::move(verified).Error();
        auto mount = procfs.ReadMountId(acquired, fdinfoBytes);
        auto closed = procfs.Close();
        if (!closed.HasValue())
        {
            if (mount.HasValue())
                mount = std::move(closed).Error();
            else
                Detail::LogSecondaryClose(context, closed.Error().code);
        }
        if (!mount.HasValue())
            return std::move(mount).Error();
        Handle root(std::move(acquired), Handle::Type::Directory, snapshot, fdinfoBytes, 0, mount.Value());
        return std::move(root);
    }();
    auto closed = acquired.Close();
    if (!closed.HasValue())
    {
        if (pinned.HasValue())
        {
            return std::move(closed).Error();
        }
        Detail::LogSecondaryClose(context, closed.Error().code);
    }
    return pinned;
}

Result<bool> Handle::RecognizeAcceptedRoot(const Handle& acceptedRoot, const Handle& candidate, std::size_t fdinfoByteCap)
{
    if ((acceptedRoot.mType != Handle::Type::Directory) || (candidate.mType != Handle::Type::Directory) || !acceptedRoot.mDescriptor.HasValue() ||
        !candidate.mDescriptor.HasValue() || (fdinfoByteCap == 0))
    {
        return Error("Two live directory pins and a positive fdinfo cap are required", EINVAL);
    }
    if (&acceptedRoot.mDescriptor.Context() != &candidate.mDescriptor.Context())
    {
        return Error("Directory pins belong to different contexts", EINVAL);
    }
    struct stat root = {}, observed = {};
    const auto& context = acceptedRoot.mDescriptor.Context();
    if ((context.StatFile(acceptedRoot.mDescriptor, &root) != 0) || (context.StatFile(candidate.mDescriptor, &observed) != 0))
    {
        return Error("Cannot inspect accepted root and candidate pins", SavedError());
    }

    if (!SameIdentity(root, acceptedRoot.mAcquiredMetadata) || !SameIdentity(observed, candidate.mAcquiredMetadata) || !S_ISDIR(root.st_mode) ||
        !S_ISDIR(observed.st_mode))
    {
        return Error("Root or candidate pin identity changed", EAGAIN);
    }

    if (!SameIdentity(root, observed))
    {
        return false;
    }
    ProcfsDescriptorAccess procfs(context);
    auto verified = procfs.Open();
    if (!verified.HasValue())
    {
        return std::move(verified).Error();
    }
    auto compared = [&]() -> Result<bool> {
        struct stat retainedRoot = {}, retainedCandidate = {};
        if ((context.StatFile(acceptedRoot.mDescriptor, &retainedRoot) != 0) || (context.StatFile(candidate.mDescriptor, &retainedCandidate) != 0))
        {
            return Error("Cannot recheck accepted root and candidate pins", SavedError());
        }

        if (!SameIdentity(root, retainedRoot) || !SameIdentity(observed, retainedCandidate))
        {
            return Error("Root or candidate pin changed during comparison", EAGAIN);
        }
        return acceptedRoot.mTargetMount == candidate.mTargetMount;
    }();
    auto closed = procfs.Close();
    if (!closed.HasValue())
    {
        if (compared.HasValue())
        {
            return std::move(closed).Error();
        }
        Detail::LogSecondaryClose(context, closed.Error().code);
    }
    return compared;
}

DirectoryCursor::DirectoryCursor(const ContextInterface& context, DIR* stream) noexcept
    : mContext(&context),
      mStream(stream)
{
}

DirectoryCursor::DirectoryCursor(DirectoryCursor&& other) noexcept
    : mContext(other.mContext),
      mStream(other.mStream)
{
    other.mContext = nullptr;
    other.mStream = nullptr;
}

DirectoryCursor& DirectoryCursor::operator=(DirectoryCursor&& other) noexcept
{
    if (this != &other)
    {
        DirectoryCursor replaced(std::move(*this));
        mContext = other.mContext;
        mStream = other.mStream;
        other.mContext = nullptr;
        other.mStream = nullptr;
    }
    return *this;
}

DirectoryCursor::~DirectoryCursor() noexcept
{
    if (mStream)
    {
        int error = 0;
        try
        {
            auto closed = Close();
            if (!closed.HasValue())
            {
                error = closed.Error().code;
            }
        }
        catch (...)
        {
            OsConfigLogError(nullptr, "Directory cursor destruction close or log failure: %d", error != 0 ? error : EIO);
        }
    }
}

Result<bool> DirectoryCursor::Close()
{
    if (!mStream)
    {
        return true;
    }
    DIR* stream = mStream;
    mStream = nullptr;
    const int error = mContext->CloseOwnedDirectoryCursor(stream) != 0 ? SavedError() : 0;

    if (error != 0)
    {
        OsConfigLogError(mContext->GetLogHandle(), "Cannot close pinned directory: %d", error);
        return Error("Cannot close pinned directory", error);
    }
    return true;
}

Result<Optional<std::string>> DirectoryCursor::Next()
{
    auto next = NextEntry();
    if (!next.HasValue())
    {
        return std::move(next).Error();
    }

    if (!next.Value().HasValue())
    {
        return Optional<std::string>();
    }
    return Optional<std::string>(std::move(next).Value().Value().name);
}

Result<Optional<DirectoryChild>> DirectoryCursor::NextEntry()
{
    if (!mStream)
    {
        return Error("Cannot read closed pinned directory", EBADF);
    }

    for (;;)
    {
        errno = 0;
        const struct dirent* entry = mContext->ReadDirectory(mStream);
        if (!entry)
        {
            if (errno != 0)
            {
                return Error("Cannot read pinned directory", SavedError());
            }
            return Optional<DirectoryChild>();
        }
        const std::string name(entry->d_name);
        if (("." == name) || (".." == name))
        {
            continue;
        }

        if (!Detail::IsSingleChildComponent(name))
        {
            return Error("Pinned directory returned an invalid child name", EINVAL);
        }
        DirectoryChild child;
        child.name = name;
        child.type = entry->d_type;
        return Optional<DirectoryChild>(std::move(child));
    }
}

} // namespace Filesystem
} // namespace ComplianceEngine
