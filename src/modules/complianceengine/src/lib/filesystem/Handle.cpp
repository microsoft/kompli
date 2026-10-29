// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "Handle.hpp"

#include "ContextInterface.h"
#include "Optional.h"
#include "PathInternal.hpp"
#include "ReadableFile.hpp"

#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <dirent.h>
#include <fcntl.h>
#include <limits>
#include <linux/magic.h>
#include <sys/statfs.h>
#include <unistd.h>
#include <utility>

namespace ComplianceEngine
{
namespace Filesystem
{
namespace Detail
{
int SavedError() noexcept
{
    return (errno != 0) ? errno : EIO;
}

void LogSecondaryClose(const ContextInterface& context, int error)
{
    OsConfigLogError(context.GetLogHandle(), "Secondary filesystem helper close failure: %d", error);
}

static bool IsProcfsDirectory(const ContextInterface& context, const Descriptor& descriptor)
{
    struct statfs filesystem = {};
    struct stat metadata = {};
    return (context.StatFilesystem(descriptor, &filesystem) == 0) && (filesystem.f_type == PROC_SUPER_MAGIC) &&
           (context.StatFile(descriptor, &metadata) == 0) && S_ISDIR(metadata.st_mode);
}

bool SameIdentity(const struct stat& first, const struct stat& second) noexcept
{
    return (first.st_dev == second.st_dev) && (first.st_ino == second.st_ino) && ((first.st_mode & S_IFMT) == (second.st_mode & S_IFMT));
}

// All procfs names are relative to previously held, verified directories.
// "self" is the one intentional link and must identify the current PID.
VerifiedProcfs::VerifiedProcfs(const ContextInterface& context)
    : proc(context.EmptyDescriptor()),
      self(context.EmptyDescriptor()),
      pid(context.EmptyDescriptor()),
      fd(context.EmptyDescriptor()),
      fdinfo(context.EmptyDescriptor())
{
}
Result<bool> VerifiedProcfs::Open()
{
    auto opened = [&]() -> Result<bool> {
        if (proc.HasValue())
        {
            return Error("Procfs directory verification was already attempted", EINVAL);
        }
        auto openedProc = proc.Context().OpenAbsolutePin("/proc");
        if (!openedProc.HasValue())
        {
            return Error("Trusted procfs directory is unavailable", openedProc.Error().code);
        }
        proc = std::move(openedProc).Value();
        if (!proc.HasValue() || !IsProcfsDirectory(proc.Context(), proc))
        {
            return Error("Trusted procfs directory is unavailable", EPROTO);
        }
        auto openedSelf = proc.Context().OpenAt(proc, "self", ContextInterface::OpenProfile::PinSelfDirectory);
        if (!openedSelf.HasValue())
        {
            return Error("Procfs self directory cannot be verified", openedSelf.Error().code);
        }
        self = std::move(openedSelf).Value();
        if (!self.HasValue())
        {
            return Error("Procfs self directory cannot be verified", EPROTO);
        }
        auto openedPid = proc.Context().OpenAt(proc, std::to_string(::getpid()).c_str(), ContextInterface::OpenProfile::PinDirectory);
        if (!openedPid.HasValue())
        {
            return Error("Procfs self directory cannot be verified", openedPid.Error().code);
        }
        pid = std::move(openedPid).Value();
        struct stat selfStat = {}, pidStat = {};
        if (!pid.HasValue() || !IsProcfsDirectory(proc.Context(), self) || !IsProcfsDirectory(proc.Context(), pid) ||
            (proc.Context().StatFile(self, &selfStat) != 0) || (proc.Context().StatFile(pid, &pidStat) != 0) || !SameIdentity(selfStat, pidStat))
        {
            return Error("Procfs self directory cannot be verified", EPROTO);
        }
        auto openedFd = proc.Context().OpenAt(self, "fd", ContextInterface::OpenProfile::PinDirectory);
        if (!openedFd.HasValue())
        {
            return Error("Procfs descriptor directories cannot be verified", openedFd.Error().code);
        }
        fd = std::move(openedFd).Value();
        if (!fd.HasValue())
        {
            return Error("Procfs descriptor directories cannot be verified", EPROTO);
        }
        auto openedFdinfo = proc.Context().OpenAt(self, "fdinfo", ContextInterface::OpenProfile::PinDirectory);
        if (!openedFdinfo.HasValue())
        {
            return Error("Procfs descriptor directories cannot be verified", openedFdinfo.Error().code);
        }
        fdinfo = std::move(openedFdinfo).Value();
        if (!fdinfo.HasValue() || !IsProcfsDirectory(proc.Context(), fd) || !IsProcfsDirectory(proc.Context(), fdinfo))
        {
            return Error("Procfs descriptor directories cannot be verified", EPROTO);
        }
        if ((proc.Context().StatFile(fd, &mFdIdentity) != 0) || (proc.Context().StatFile(fdinfo, &mFdinfoIdentity) != 0))
        {
            return Error("Procfs descriptor directory identity cannot be verified", SavedError());
        }
        mVerified = true;
        return true;
    }();
    if (!opened.HasValue())
    {
        auto closed = Close();
        if (!closed.HasValue())
        {
            LogSecondaryClose(proc.Context(), closed.Error().code);
        }
    }
    return opened;
}

Result<bool> VerifiedProcfs::Close()
{
    mVerified = false;
    Optional<Error> firstError;
    Descriptor* resources[] = {&fdinfo, &fd, &pid, &self, &proc};
    for (Descriptor* resource : resources)
    {
        auto closed = resource->Close();
        if (!closed.HasValue())
        {
            if (!firstError.HasValue())
            {
                firstError = std::move(closed).Error();
            }
            else
            {
                LogSecondaryClose(proc.Context(), closed.Error().code);
            }
        }
    }
    if (firstError.HasValue())
    {
        return std::move(firstError.Value());
    }
    return true;
}

bool VerifiedProcfs::VerifyRole(const ContextInterface& context, bool information) const
{
    if (!mVerified || &proc.Context() != &context)
        return false;
    const Descriptor& role = information ? fdinfo : fd;
    if (!role.HasValue() || &role.Context() != &context)
        return false;
    struct stat identity = {};
    return context.StatFile(role, &identity) == 0 && SameIdentity(identity, information ? mFdinfoIdentity : mFdIdentity) && S_ISDIR(identity.st_mode);
}

static Result<std::uint64_t> ParseMountIdImpl(const std::string& fdinfo)
{
    if (fdinfo.find('\0') != std::string::npos)
    {
        return Error("Malformed procfs descriptor information", EPROTO);
    }
    bool found = false;
    std::uint64_t mountId = 0;
    std::size_t lineStart = 0;
    while (lineStart < fdinfo.size())
    {
        const std::size_t end = fdinfo.find('\n', lineStart);
        if (end == std::string::npos)
        {
            return Error("Truncated procfs descriptor information", EPROTO);
        }

        if (fdinfo.compare(lineStart, 7, "mnt_id:") == 0)
        {
            if (found)
            {
                return Error("Duplicate procfs descriptor mount ID", EPROTO);
            }
            found = true;
            std::size_t position = lineStart + 7;
            while ((position < end) && ((fdinfo[position] == ' ') || (fdinfo[position] == '\t')))
            {
                ++position;
            }

            if (position == end)
            {
                return Error("Empty procfs descriptor mount ID", EPROTO);
            }

            for (; position < end; ++position)
            {
                const char digit = fdinfo[position];
                if ((digit < '0') || (digit > '9') || (mountId > (std::numeric_limits<std::uint64_t>::max() - static_cast<unsigned>(digit - '0')) / 10))
                {
                    return Error("Invalid procfs descriptor mount ID", EPROTO);
                }
                mountId = (mountId * 10) + static_cast<unsigned>(digit - '0');
            }

            if (mountId == 0)
            {
                return Error("Invalid procfs descriptor mount ID", EPROTO);
            }
        }
        lineStart = end + 1;
    }

    if (!found)
    {
        return Error("Missing procfs descriptor mount ID", EPROTO);
    }
    return mountId;
}

Result<std::uint64_t> MountId(const ContextInterface& context, const VerifiedProcfs& procfs, const Descriptor& descriptor, std::size_t byteCap)
{
    if ((byteCap == 0) || (byteCap >= std::string().max_size()))
    {
        return Error("Invalid procfs descriptor information byte cap", EINVAL);
    }
    auto opened = context.OpenFdinfo(procfs, descriptor);
    if (!opened.HasValue())
    {
        return Error("Cannot open procfs descriptor information", opened.Error().code);
    }
    Descriptor info = std::move(opened).Value();
    auto read = [&]() -> Result<std::uint64_t> {
        if (!info.HasValue())
        {
            return Error("Cannot open procfs descriptor information", EPROTO);
        }
        std::string bytes;
        char buffer[256] = {};
        for (;;)
        {
            const std::size_t request = std::min(sizeof(buffer), byteCap - bytes.size() + 1);
            const ssize_t count = context.ReadFile(info, buffer, request);
            if (count < 0)
            {
                return Error("Cannot read procfs descriptor information", SavedError());
            }

            if (count == 0)
            {
                break;
            }

            if (static_cast<std::size_t>(count) > request)
            {
                return Error("Procfs descriptor information returned more bytes than requested", EIO);
            }

            if (static_cast<std::size_t>(count) > byteCap - bytes.size())
            {
                return Error("Procfs descriptor information exceeds byte cap", E2BIG);
            }
            bytes.append(buffer, static_cast<std::size_t>(count));
        }
        return ParseMountIdImpl(bytes);
    }();
    auto closed = info.Close();
    if (!closed.HasValue())
    {
        if (read.HasValue())
        {
            return std::move(closed).Error();
        }
        LogSecondaryClose(context, closed.Error().code);
    }
    return read;
}
// An inode identity (device/inode/type) does not identify a bind mount:
// compare procfs mount IDs as well, including for the verified alias.
// Repeated pin observations bracket sensitive operations but do not freeze
// metadata or namespace state; checked helper closes gate published success.
static Result<bool> OpenAndVerifyAlias(const ContextInterface& context, const VerifiedProcfs& procfs, const Descriptor& pin, Descriptor& aliasOwner,
    const struct stat& before, bool directory, std::size_t fdinfoByteCap)
{
    auto pinnedMount = MountId(context, procfs, pin, fdinfoByteCap);
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
    auto activatedMount = MountId(context, procfs, aliasOwner, fdinfoByteCap);
    if (!activatedMount.HasValue())
    {
        return std::move(activatedMount).Error();
    }
    auto retainedMount = MountId(context, procfs, pin, fdinfoByteCap);
    if (!retainedMount.HasValue())
    {
        return std::move(retainedMount).Error();
    }

    if ((pinnedMount.Value() != activatedMount.Value()) || (pinnedMount.Value() != retainedMount.Value()))
    {
        return Error("Activated object mount does not match live pin", EAGAIN);
    }
    return true;
}

Result<Descriptor> ActivateReadOnly(const ContextInterface& context, const Descriptor& pin, const struct stat& snapshot, bool directory, std::size_t fdinfoByteCap)
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

    VerifiedProcfs procfs(context);
    auto verified = procfs.Open();
    if (!verified.HasValue())
    {
        return std::move(verified).Error();
    }
    Descriptor aliasOwner = context.EmptyDescriptor(ContextInterface::CloseDiagnostic::DirectoryActivation);
    auto inspected = OpenAndVerifyAlias(context, procfs, pin, aliasOwner, before, directory, fdinfoByteCap);
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

Result<std::uint64_t> ParseMountId(const std::string& fdinfo)
{
    return ParseMountIdImpl(fdinfo);
}

} // namespace Detail

using Detail::Descriptor;
using Detail::MountId;
using Detail::SameIdentity;
using Detail::SavedError;
using Detail::VerifiedProcfs;

Handle::Handle(Detail::Descriptor&& descriptor, Type type, std::string component, const struct stat& snapshot, std::size_t fdinfoBytes)
    : mDescriptor(std::move(descriptor)),
      mType(type),
      mComponent(std::move(component)),
      mAcquiredMetadata(snapshot),
      mFdinfoBytes(fdinfoBytes)
{
}

Handle::Handle(Handle&& other) noexcept
    : mDescriptor(std::move(other.mDescriptor)),
      mType(other.mType),
      mComponent(std::move(other.mComponent)),
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

const std::string& Handle::Component() const& noexcept
{
    return mComponent;
}

struct stat Handle::AcquiredMetadata() const noexcept
{
    return mAcquiredMetadata;
}

Result<Handle::PinObservation> Handle::InspectWithProcfs(const VerifiedProcfs& procfs) const
{
    if (!mDescriptor.HasValue())
    {
        return Error("Metadata inspection requires a live pin", EBADF);
    }
    const auto& context = mDescriptor.Context();
    const std::size_t fdinfoByteCap = mFdinfoBytes;
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
    auto observedMount = MountId(context, procfs, mDescriptor, fdinfoByteCap);
    if (!observedMount.HasValue())
    {
        return std::move(observedMount).Error();
    }

    if (context.StatFile(mDescriptor, &after) != 0)
    {
        return Error("Cannot recheck pinned metadata", SavedError());
    }

    if (!SameIdentity(before, after))
    {
        return Error("Pinned metadata identity changed", EAGAIN);
    }
    auto retainedMount = MountId(context, procfs, mDescriptor, fdinfoByteCap);
    if (!retainedMount.HasValue())
    {
        return std::move(retainedMount).Error();
    }

    if (observedMount.Value() != retainedMount.Value())
    {
        return Error("Pinned metadata mount changed", EAGAIN);
    }
    return PinObservation{after, observedMount.Value()};
}

Result<struct stat> Handle::Stat() const
{
    if (!mDescriptor.HasValue())
    {
        return Error("Fresh inspection requires a live pin", EBADF);
    }
    const auto& context = mDescriptor.Context();
    VerifiedProcfs procfs(context);
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
    VerifiedProcfs procfs(context);
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
    return inspected.Value().mountId;
}

Result<bool> Handle::SetOwnership(uid_t owner, gid_t group) const
{
    if (!mDescriptor.HasValue())
    {
        return Error("Ownership change requires a live pin", EBADF);
    }
    const auto& context = mDescriptor.Context();
    VerifiedProcfs procfs(context);
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

        if (beforeMutation.Value().mountId != after.Value().mountId)
        {
            return Error("Pinned mount changed after ownership mutation", EAGAIN);
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

Result<bool> Handle::SetModeWithProcfs(const VerifiedProcfs& procfs, mode_t mode) const
{
    const auto& context = mDescriptor.Context();
    const std::size_t fdinfoByteCap = mFdinfoBytes;
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
        auto targetMount = MountId(context, procfs, modeAlias, fdinfoByteCap);
        if (!targetMount.HasValue())
        {
            return std::move(targetMount).Error();
        }

        if (beforeMutation.Value().mountId != targetMount.Value())
        {
            return Error("Pinned mode alias mount differs", EAGAIN);
        }
        auto retained = InspectWithProcfs(procfs);
        if (!retained.HasValue())
        {
            return std::move(retained).Error();
        }

        if (beforeMutation.Value().mountId != retained.Value().mountId)
        {
            return Error("Pinned mount changed before mode mutation", EAGAIN);
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

        if (beforeMutation.Value().mountId != after.Value().mountId)
        {
            return Error("Pinned mount changed after mode mutation", EAGAIN);
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
    VerifiedProcfs procfs(context);
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
    auto activated = Detail::ActivateReadOnly(mDescriptor.Context(), mDescriptor, mAcquiredMetadata, false, mFdinfoBytes);
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
    auto activated = Detail::ActivateReadOnly(context, mDescriptor, mAcquiredMetadata, true, mFdinfoBytes);
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
    mComponent.swap(other.mComponent);
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
        Handle root(std::move(acquired), Handle::Type::Directory, "/", snapshot, fdinfoBytes);
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
    VerifiedProcfs procfs(context);
    auto verified = procfs.Open();
    if (!verified.HasValue())
    {
        return std::move(verified).Error();
    }
    auto compared = [&]() -> Result<bool> {
        auto rootMount = MountId(context, procfs, acceptedRoot.mDescriptor, fdinfoByteCap);
        if (!rootMount.HasValue())
        {
            return std::move(rootMount).Error();
        }
        auto candidateMount = MountId(context, procfs, candidate.mDescriptor, fdinfoByteCap);
        if (!candidateMount.HasValue())
        {
            return std::move(candidateMount).Error();
        }
        struct stat retainedRoot = {}, retainedCandidate = {};
        if ((context.StatFile(acceptedRoot.mDescriptor, &retainedRoot) != 0) || (context.StatFile(candidate.mDescriptor, &retainedCandidate) != 0))
        {
            return Error("Cannot recheck accepted root and candidate pins", SavedError());
        }

        if (!SameIdentity(root, retainedRoot) || !SameIdentity(observed, retainedCandidate))
        {
            return Error("Root or candidate pin changed during comparison", EAGAIN);
        }
        return rootMount.Value() == candidateMount.Value();
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
    const int error = mContext->CloseDirectory(stream) != 0 ? SavedError() : 0;

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
