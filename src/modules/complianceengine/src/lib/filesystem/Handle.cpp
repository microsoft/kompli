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
#include <stdexcept>
#include <sys/statfs.h>
#include <unistd.h>
#include <utility>
#include <vector>

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

// Temporary procfs and operational descriptors never escape the internal
// filesystem implementation. Close once even when a diagnostic throws.
ScopedDescriptor::ScopedDescriptor(const ContextInterface& context, int descriptor)
    : mContext(context),
      mDescriptor(descriptor)
{
}
ScopedDescriptor::~ScopedDescriptor() noexcept
{
    const int error = CloseOnce();
    if (error != 0)
    {
        try
        {
            OsConfigLogError(mContext.GetLogHandle(), "Failed to close internal filesystem descriptor: %d", error);
        }
        catch (...)
        {
        }
    }
}
int ScopedDescriptor::CloseOnce() noexcept
{
    if (mDescriptor < 0)
    {
        return 0;
    }
    const int descriptor = mDescriptor;
    mDescriptor = -1;
    int error = 0;
    try
    {
        if (mContext.CloseFileDescriptor(descriptor) != 0)
        {
            error = SavedError();
        }
    }
    catch (...)
    {
        error = EIO;
    }
    return error;
}
int ScopedDescriptor::Get() const noexcept
{
    return mDescriptor;
}
void ScopedDescriptor::Set(int descriptor) noexcept
{
    // Used only for the initially empty procfs helper descriptors.
    mDescriptor = descriptor;
}
int ScopedDescriptor::Transfer() noexcept
{
    const int descriptor = mDescriptor;
    mDescriptor = -1;
    return descriptor;
}

static bool IsProcfsDirectory(int descriptor)
{
    struct statfs filesystem = {};
    struct stat metadata = {};
    return (::fstatfs(descriptor, &filesystem) == 0) && (filesystem.f_type == PROC_SUPER_MAGIC) && (::fstat(descriptor, &metadata) == 0) &&
           S_ISDIR(metadata.st_mode);
}

bool SameIdentity(const struct stat& first, const struct stat& second) noexcept
{
    return (first.st_dev == second.st_dev) && (first.st_ino == second.st_ino) && ((first.st_mode & S_IFMT) == (second.st_mode & S_IFMT));
}

// All procfs names are relative to previously held, verified directories.
// "self" is the one intentional link and must identify the current PID.
VerifiedProcfs::VerifiedProcfs(const ContextInterface& context)
    : proc(context, -1),
      self(context, -1),
      pid(context, -1),
      fd(context, -1),
      fdinfo(context, -1)
{
}
Result<bool> VerifiedProcfs::Open()
{
    auto opened = [&]() -> Result<bool> {
        if (proc.Get() >= 0)
        {
            return Error("Procfs directory verification was already attempted", EINVAL);
        }
        proc.Set(proc.Context().OpenNativePath("/proc", O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
        if ((proc.Get() < 0) || !IsProcfsDirectory(proc.Get()))
        {
            return Error("Trusted procfs directory is unavailable", (proc.Get() < 0) ? SavedError() : EPROTO);
        }
        self.Set(proc.Context().OpenNativeAt(proc.Get(), "self", O_PATH | O_DIRECTORY | O_CLOEXEC));
        if (self.Get() < 0)
        {
            return Error("Procfs self directory cannot be verified", SavedError());
        }
        pid.Set(proc.Context().OpenNativeAt(proc.Get(), std::to_string(::getpid()).c_str(), O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
        struct stat selfStat = {}, pidStat = {};
        if ((self.Get() < 0) || (pid.Get() < 0) || !IsProcfsDirectory(self.Get()) || !IsProcfsDirectory(pid.Get()) ||
            (::fstat(self.Get(), &selfStat) != 0) || (::fstat(pid.Get(), &pidStat) != 0) || !SameIdentity(selfStat, pidStat))
        {
            return Error("Procfs self directory cannot be verified", (pid.Get() < 0) ? SavedError() : EPROTO);
        }
        fd.Set(proc.Context().OpenNativeAt(self.Get(), "fd", O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
        if (fd.Get() < 0)
        {
            return Error("Procfs descriptor directories cannot be verified", SavedError());
        }
        fdinfo.Set(proc.Context().OpenNativeAt(self.Get(), "fdinfo", O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
        if ((fd.Get() < 0) || (fdinfo.Get() < 0) || !IsProcfsDirectory(fd.Get()) || !IsProcfsDirectory(fdinfo.Get()))
        {
            return Error("Procfs descriptor directories cannot be verified", (fdinfo.Get() < 0) ? SavedError() : EPROTO);
        }
        return true;
    }();
    return opened.HasValue() ? opened : Finish(std::move(opened));
}

int VerifiedProcfs::CloseOnce() noexcept
{
    int firstError = 0;
    ScopedDescriptor* resources[] = {&fdinfo, &fd, &pid, &self, &proc};
    for (ScopedDescriptor* resource : resources)
    {
        const int error = resource->CloseOnce();
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
                    OsConfigLogError(proc.Context().GetLogHandle(), "Secondary filesystem helper close failure: %d", error);
                }
                catch (...)
                {
                }
            }
        }
    }
    return firstError;
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

Result<std::uint64_t> MountId(const ContextInterface& context, int fdinfoDirectory, int descriptor, std::size_t byteCap)
{
    if ((byteCap == 0) || (byteCap >= std::string().max_size()))
    {
        return Error("Invalid procfs descriptor information byte cap", EINVAL);
    }
    const std::string number = std::to_string(descriptor);
    ScopedDescriptor info(context, context.OpenNativeAt(fdinfoDirectory, number.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW));
    auto read = [&]() -> Result<std::uint64_t> {
        if (info.Get() < 0)
        {
            return Error("Cannot open procfs descriptor information", SavedError());
        }
        std::string bytes;
        char buffer[256] = {};
        for (;;)
        {
            const std::size_t request = std::min(sizeof(buffer), byteCap - bytes.size() + 1);
            const ssize_t count = context.ReadFileDescriptor(info.Get(), buffer, request);
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
    return info.Finish(std::move(read));
}
} // namespace Detail

namespace Detail
{
ReadOnlyActivation::ReadOnlyActivation(const ContextInterface& context, int descriptor, const struct stat& snapshot) noexcept
    : mContext(&context),
      mDescriptor(descriptor),
      mSnapshot(snapshot)
{
}

ReadOnlyActivation::ReadOnlyActivation(ReadOnlyActivation&& other) noexcept
    : mContext(other.mContext),
      mDescriptor(other.mDescriptor),
      mSnapshot(other.mSnapshot)
{
    other.mContext = nullptr;
    other.mDescriptor = -1;
}

ReadOnlyActivation& ReadOnlyActivation::operator=(ReadOnlyActivation&& other) noexcept
{
    if (this != &other)
    {
        ReadOnlyActivation incoming(std::move(other));
        using std::swap;
        swap(mContext, incoming.mContext);
        swap(mDescriptor, incoming.mDescriptor);
        swap(mSnapshot, incoming.mSnapshot);
    }
    return *this;
}

ReadOnlyActivation::~ReadOnlyActivation() noexcept
{
    if (mDescriptor >= 0)
    {
        const int error = CloseOnce();
        if (error != 0)
        {
            try
            {
                OsConfigLogError(mContext->GetLogHandle(), "Failed to close directory activation: %d", error);
            }
            catch (...)
            {
            }
        }
    }
}
int ReadOnlyActivation::CloseOnce() noexcept
{
    if (mDescriptor < 0)
    {
        return 0;
    }
    ScopedDescriptor owned(*mContext, Transfer());
    return owned.CloseOnce();
}

const struct stat& ReadOnlyActivation::Snapshot() const noexcept
{
    return mSnapshot;
}

int ReadOnlyActivation::Descriptor() const noexcept
{
    return mDescriptor;
}

int ReadOnlyActivation::Transfer() noexcept
{
    const int descriptor = mDescriptor;
    mDescriptor = -1;
    return descriptor;
}

Result<ReadOnlyActivation> ActivateReadOnly(const ContextInterface& context, int pin, const struct stat& snapshot, bool directory, std::size_t fdinfoByteCap)
{
    if (pin < 0)
    {
        return Error("Read-only activation requires a live pin", EINVAL);
    }

    if ((fdinfoByteCap == 0) || (fdinfoByteCap >= std::string().max_size()))
    {
        return Error("Invalid procfs descriptor information byte cap", EINVAL);
    }
    struct stat before = {};
    if (context.StatFileDescriptor(pin, &before) != 0)
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
    const int pinFlags = ::fcntl(pin, F_GETFL);
    if (pinFlags < 0)
    {
        return Error("Cannot inspect pinned descriptor flags", SavedError());
    }
    const int pinDescriptorFlags = ::fcntl(pin, F_GETFD);
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
    ScopedDescriptor operational(context, -1);
    auto inspected = [&]() -> Result<struct stat>
    {
        auto pinnedMount = MountId(context, procfs.fdinfo.Get(), pin, fdinfoByteCap);
        if (!pinnedMount.HasValue())
        {
            return std::move(pinnedMount).Error();
        }
        // Only the decimal alias of the held pin is followed intentionally.
        const std::string alias = std::to_string(pin);
        const int flags = O_RDONLY | O_CLOEXEC | (directory ? O_DIRECTORY : 0);
        operational.Set(context.OpenNativeAt(procfs.fd.Get(), alias.c_str(), flags));
        if (operational.Get() < 0)
        {
            return Error("Cannot open pinned descriptor alias for reading", SavedError());
        }
        struct stat activated = {}, stillPinned = {};
        if ((context.StatFileDescriptor(operational.Get(), &activated) != 0) || (context.StatFileDescriptor(pin, &stillPinned) != 0))
        {
            return Error("Cannot inspect activated object and pin", SavedError());
        }

        if (!SameIdentity(before, activated) || !SameIdentity(before, stillPinned))
        {
            return Error("Activated object does not match live pin", EAGAIN);
        }
        auto activatedMount = MountId(context, procfs.fdinfo.Get(), operational.Get(), fdinfoByteCap);
        if (!activatedMount.HasValue())
        {
            return std::move(activatedMount).Error();
        }
        auto retainedMount = MountId(context, procfs.fdinfo.Get(), pin, fdinfoByteCap);
        if (!retainedMount.HasValue())
        {
            return std::move(retainedMount).Error();
        }

        if ((pinnedMount.Value() != activatedMount.Value()) || (pinnedMount.Value() != retainedMount.Value()))
        {
            return Error("Activated object mount does not match live pin", EAGAIN);
        }
        return activated;
    }
    ();
    auto finalized = procfs.Finish(std::move(inspected));
    if (!finalized.HasValue())
    {
        return operational.Finish(Result<ReadOnlyActivation>(std::move(finalized).Error()));
    }
    // The operational alias must remain owned until all procfs checks and
    // helper closes have succeeded; output transfer occurs below.
    return ReadOnlyActivation(context, operational.Transfer(), finalized.Value());
}

Result<std::uint64_t> ParseMountId(const std::string& fdinfo)
{
    return ParseMountIdImpl(fdinfo);
}

} // namespace Detail

using Detail::MountId;
using Detail::SameIdentity;
using Detail::SavedError;
using Detail::ScopedDescriptor;
using Detail::VerifiedProcfs;

Result<Handle> Handle::AcquireChild(const ContextInterface& context, int parentDirectory, std::string component, bool directory)
{
    if (!Detail::IsSingleChildComponent(component))
    {
        return Error("Expected one child component", EINVAL);
    }

    if (parentDirectory < 0)
    {
        return Error("Invalid parent directory descriptor", EBADF);
    }
    const int parentFlags = ::fcntl(parentDirectory, F_GETFL);
    if (parentFlags < 0)
    {
        return Error("Cannot inspect parent directory descriptor", SavedError());
    }
    const int parentDescriptorFlags = ::fcntl(parentDirectory, F_GETFD);
    if (parentDescriptorFlags < 0)
    {
        return Error("Cannot inspect parent directory descriptor", SavedError());
    }

    if (((parentFlags & O_PATH) == 0) || ((parentDescriptorFlags & FD_CLOEXEC) == 0))
    {
        return Error("A held close-on-exec directory pin is required", EINVAL);
    }
    struct stat parent = {};
    if (context.StatFileDescriptor(parentDirectory, &parent) != 0)
    {
        return Error("Cannot inspect held parent directory", SavedError());
    }

    if (!S_ISDIR(parent.st_mode))
    {
        return Error("Parent is not a directory", ENOTDIR);
    }
    const int flags = O_PATH | O_NOFOLLOW | O_CLOEXEC | (directory ? O_DIRECTORY : 0);
    ScopedDescriptor acquired(context, context.OpenNativeAt(parentDirectory, component.c_str(), flags));
    auto pinned = [&]() -> Result<Handle> {
        if (acquired.Get() < 0)
        {
            return Error("Cannot pin filesystem component", SavedError());
        }
        struct stat snapshot = {};
        if (context.StatFileDescriptor(acquired.Get(), &snapshot) != 0)
        {
            return Error("Cannot inspect pinned filesystem component", SavedError());
        }

        if (S_ISLNK(snapshot.st_mode))
        {
            return Error("Symlink component is not allowed", ELOOP);
        }

        if ((directory && !S_ISDIR(snapshot.st_mode)) || (!directory && !S_ISREG(snapshot.st_mode)))
        {
            return Error("Unsupported filesystem component type", EINVAL);
        }
        // No pathname lookup occurs after this point. Ownership moves only after
        // the snapshot and copied diagnostic component have been constructed.
        Handle result(context, acquired.Get(), directory ? Handle::Type::Directory : Handle::Type::RegularFile, std::move(component), snapshot);
        acquired.Transfer();
        return std::move(result);
    }();
    return acquired.Finish(std::move(pinned));
}

Result<Handle> Handle::PinProcessRoot(const ContextInterface& context)
{
    ScopedDescriptor acquired(context, context.OpenNativePath("/", O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
    auto pinned = [&]() -> Result<Handle> {
        if (acquired.Get() < 0)
        {
            return Error("Cannot pin process root for absolute-prefix validation", SavedError());
        }
        struct stat snapshot = {};
        if (context.StatFileDescriptor(acquired.Get(), &snapshot) != 0)
        {
            return Error("Cannot inspect process root pin", SavedError());
        }

        if (!S_ISDIR(snapshot.st_mode))
        {
            return Error("Process root is not a directory", ENOTDIR);
        }
        Handle root(context, acquired.Get(), Handle::Type::Directory, "/", snapshot);
        acquired.Transfer();
        return std::move(root);
    }();
    return acquired.Finish(std::move(pinned));
}

Result<Handle> Handle::AcquireChild(const Handle& parent, std::string component, bool directory)
{
    if ((!parent.mPin) || (parent.mType != Handle::Type::Directory) || (parent.mContext == nullptr))
    {
        return Error("A live directory pin is required", EINVAL);
    }
    return AcquireChild(*parent.mContext, parent.mDescriptor, std::move(component), directory);
}

Result<bool> Handle::RecognizeAcceptedRoot(const Handle& acceptedRoot, const Handle& candidate, std::size_t fdinfoByteCap)
{
    if ((!acceptedRoot.mPin) || (!candidate.mPin) || (acceptedRoot.mType != Handle::Type::Directory) || (candidate.mType != Handle::Type::Directory) ||
        (acceptedRoot.mContext == nullptr) || (candidate.mContext == nullptr) || (acceptedRoot.mDescriptor < 0) || (candidate.mDescriptor < 0) ||
        (fdinfoByteCap == 0))
    {
        return Error("Two live directory pins and a positive fdinfo cap are required", EINVAL);
    }
    struct stat root = {}, observed = {};
    if ((acceptedRoot.mContext->StatFileDescriptor(acceptedRoot.mDescriptor, &root) != 0) ||
        (candidate.mContext->StatFileDescriptor(candidate.mDescriptor, &observed) != 0))
    {
        return Error("Cannot inspect accepted root and candidate pins", SavedError());
    }

    if (!SameIdentity(root, acceptedRoot.mSnapshot) || !SameIdentity(observed, candidate.mSnapshot) || !S_ISDIR(root.st_mode) || !S_ISDIR(observed.st_mode))
    {
        return Error("Root or candidate pin identity changed", EAGAIN);
    }

    if (!SameIdentity(root, observed))
    {
        return false;
    }
    VerifiedProcfs procfs(*acceptedRoot.mContext);
    auto verified = procfs.Open();
    if (!verified.HasValue())
    {
        return std::move(verified).Error();
    }
    auto compared = [&]() -> Result<bool> {
        auto rootMount = MountId(*acceptedRoot.mContext, procfs.fdinfo.Get(), acceptedRoot.mDescriptor, fdinfoByteCap);
        if (!rootMount.HasValue())
        {
            return std::move(rootMount).Error();
        }
        auto candidateMount = MountId(*acceptedRoot.mContext, procfs.fdinfo.Get(), candidate.mDescriptor, fdinfoByteCap);
        if (!candidateMount.HasValue())
        {
            return std::move(candidateMount).Error();
        }
        struct stat retainedRoot = {}, retainedCandidate = {};
        if ((acceptedRoot.mContext->StatFileDescriptor(acceptedRoot.mDescriptor, &retainedRoot) != 0) ||
            (candidate.mContext->StatFileDescriptor(candidate.mDescriptor, &retainedCandidate) != 0))
        {
            return Error("Cannot recheck accepted root and candidate pins", SavedError());
        }

        if (!SameIdentity(root, retainedRoot) || !SameIdentity(observed, retainedCandidate))
        {
            return Error("Root or candidate pin changed during comparison", EAGAIN);
        }
        return rootMount.Value() == candidateMount.Value();
    }();
    return procfs.Finish(std::move(compared));
}

Result<std::string> Handle::ValidateAbsolutePrefix(const ContextInterface& context, const std::vector<const Handle*>& heldLineage,
    const std::string& target, const PrefixLimits& limits)
{
    if ((target.empty()) || (target[0] != '/') || (target.find('\0') != std::string::npos) || (limits.targetBytes == 0) || (limits.components == 0) ||
        (limits.work == 0) || (limits.liveDescriptors == 0) || (limits.retainedBytes == 0) || (limits.fdinfoBytes == 0) ||
        (target.size() > limits.targetBytes) || heldLineage.empty() || (heldLineage.size() - 1 > limits.components))
    {
        return Error("Invalid absolute candidate or explicit prefix limits", EINVAL);
    }
    // A successful comparison opens procfs's five held directories plus one
    // fdinfo helper. Reserve all six in addition to the candidate pins.
    if (heldLineage.size() > limits.liveDescriptors || limits.liveDescriptors - heldLineage.size() < 7)
    {
        return Error("Insufficient live-descriptor budget for prefix verification", EMFILE);
    }

    for (const Handle* held : heldLineage)
    {
        if ((held == nullptr) || (!held->mPin) || (held->mType != Handle::Type::Directory) || (held->mDescriptor < 0))
        {
            return Error("A complete live directory-pin lineage is required", EINVAL);
        }
    }
    const std::size_t readChunks = (limits.fdinfoBytes / 256) + ((limits.fdinfoBytes % 256) ? 1 : 0);
    if (readChunks > (std::numeric_limits<std::size_t>::max() - 128) / 4)
    {
        return Error("Prefix work charge is not representable", EOVERFLOW);
    }
    // Conservatively reserve more than the syscalls needed for each staged
    // open, identity/mount check, fdinfo read and cleanup. Failed work is not
    // refunded; this is a ceiling rather than an exact syscall measurement.
    const std::size_t charge = 128 + 4 * readChunks;
    std::size_t spent = 0;
    std::size_t retained = target.size();
    for (const Handle* held : heldLineage)
    {
        // Pins from the authorized lineage remain live during candidate
        // validation. Count their stored metadata and diagnostic components.
        if ((retained > limits.retainedBytes) || (sizeof(Handle) > limits.retainedBytes - retained) ||
            (held->mComponent.size() > limits.retainedBytes - retained - sizeof(Handle)))
        {
            return Error("Held lineage exceeds retained-memory budget", E2BIG);
        }
        retained += sizeof(Handle) + held->mComponent.size();
    }

    if ((retained > limits.retainedBytes) || (limits.retainedBytes - retained < sizeof(Handle) + 1))
    {
        return Error("Process-root candidate exceeds retained-memory budget", E2BIG);
    }
    retained += sizeof(Handle) + 1;
    std::deque<Handle> candidate;
    auto validated = [&]() -> Result<std::string> {
        auto spend = [&]() {
            if (spent > limits.work || charge > limits.work - spent)
            {
                return false;
            }
            spent += charge;
            return true;
        };
        if (!spend())
        {
            return Error("Absolute prefix exceeds work budget", E2BIG);
        }
        auto slash = PinProcessRoot(context);
        if (!slash.HasValue())
        {
            return std::move(slash).Error();
        }
        candidate.emplace_back(std::move(slash).Value());
        auto matchedSlash = RecognizeAcceptedRoot(*heldLineage[0], candidate.back(), limits.fdinfoBytes);
        if (!matchedSlash.HasValue())
        {
            return std::move(matchedSlash).Error();
        }

        if (!matchedSlash.Value())
        {
            return Error("Absolute candidate has another process root", EXDEV);
        }
        std::size_t position = 1;
        for (std::size_t index = 1; index < heldLineage.size(); ++index)
        {
            while ((position < target.size()) && (target[position] == '/'))
            {
                ++position;
            }
            const std::size_t end = target.find('/', position);
            const std::size_t stop = (end == std::string::npos) ? target.size() : end;
            if ((position == stop) || (stop - position > limits.targetBytes))
            {
                return Error("Absolute candidate ends before the accepted root", EACCES);
            }

            if (candidate.size() > limits.liveDescriptors - 7 - heldLineage.size())
            {
                return Error("Absolute candidate exceeds live-descriptor budget", EMFILE);
            }
            const std::string component = target.substr(position, stop - position);
            if (("." == component) || (".." == component))
            {
                return Error("Dot components before the accepted root are unsupported", EACCES);
            }

            if (!spend())
            {
                return Error("Absolute prefix exceeds work budget", E2BIG);
            }

            if ((retained > limits.retainedBytes) || (component.size() > limits.retainedBytes - retained) ||
                (sizeof(Handle) > limits.retainedBytes - retained - component.size()))
            {
                return Error("Absolute prefix exceeds retained-memory budget", E2BIG);
            }
            retained += component.size() + sizeof(Handle);
            auto next = AcquireChild(candidate.back(), component, true);
            if (!next.HasValue())
            {
                return std::move(next).Error();
            }
            candidate.emplace_back(std::move(next).Value());
            auto match = RecognizeAcceptedRoot(*heldLineage[index], candidate.back(), limits.fdinfoBytes);
            if (!match.HasValue())
            {
                return std::move(match).Error();
            }

            if (!match.Value())
            {
                return Error("Absolute candidate prefix differs from held root lineage", EXDEV);
            }
            position = stop;
        }

        while ((position < target.size()) && (target[position] == '/'))
        {
            ++position;
        }
        // Caller must resolve this suffix from *heldLineage.back(), not candidate.
        return target.substr(position);
    }();
    for (auto pin = candidate.rbegin(); pin != candidate.rend(); ++pin)
    {
        auto closed = pin->Close();
        if (!closed.HasValue())
        {
            validated = Detail::FinalizeResult(context, std::move(validated), closed.Error().code);
        }
    }
    return validated;
}

Handle::Handle(const ContextInterface& context, int descriptor, Type type, std::string component, const struct stat& snapshot)
    : mContext(&context),
      mDescriptor(descriptor),
      mType(type),
      mComponent(std::move(component)),
      mSnapshot(snapshot)
{
}

Handle::Handle(Handle&& other) noexcept
    : mContext(other.mContext),
      mDescriptor(other.mDescriptor),
      mType(other.mType),
      mComponent(std::move(other.mComponent)),
      mSnapshot(other.mSnapshot),
      mPin(other.mPin),
      mCloseError(other.mCloseError),
      mDetachedResources(std::move(other.mDetachedResources)),
      mDetachedBytes(other.mDetachedBytes)
{
    other.mContext = nullptr;
    other.mDescriptor = -1;
    other.mCloseError = 0;
    other.mDetachedBytes = 0;
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

Handle::~Handle() noexcept
{
    if (mDescriptor >= 0)
    {
        const int error = CloseOnce();
        if (error != 0)
        {
            try
            {
                OsConfigLogError(mContext->GetLogHandle(), "Failed to close pinned filesystem descriptor: %d", error);
            }
            catch (...)
            {
                // Logging must not terminate destruction.
            }
        }
    }
}

Handle::Type Handle::AcquiredType() const noexcept
{
    return mType;
}

const std::string& Handle::Component() const noexcept
{
    return mComponent;
}

const struct stat& Handle::Stat() const noexcept
{
    return mSnapshot;
}

Result<struct stat> Handle::InspectWithProcfs(int fdinfoDirectory, std::size_t fdinfoByteCap, std::uint64_t& mountId) const
{
    if ((!mPin) || (mContext == nullptr) || (mDescriptor < 0) || (fdinfoByteCap == 0) || (fdinfoByteCap >= std::string().max_size()))
    {
        return Error("Metadata inspection requires a live pin and a positive fdinfo cap", EINVAL);
    }
    const int flags = ::fcntl(mDescriptor, F_GETFL);
    if (flags < 0)
    {
        return Error("Cannot inspect pinned descriptor flags", SavedError());
    }
    const int descriptorFlags = ::fcntl(mDescriptor, F_GETFD);
    if (descriptorFlags < 0)
    {
        return Error("Cannot inspect pinned descriptor flags", SavedError());
    }

    if (((flags & O_PATH) == 0) || ((descriptorFlags & FD_CLOEXEC) == 0))
    {
        return Error("Metadata operation requires a close-on-exec O_PATH pin", EINVAL);
    }
    struct stat before = {}, after = {};
    if (mContext->StatFileDescriptor(mDescriptor, &before) != 0)
    {
        return Error("Cannot inspect pinned metadata", SavedError());
    }

    if (!SameIdentity(before, mSnapshot) || ((mType == Type::RegularFile) && !S_ISREG(before.st_mode)) || ((mType == Type::Directory) && !S_ISDIR(before.st_mode)))
    {
        return Error("Pinned metadata has an unexpected identity or type", EAGAIN);
    }
    auto observedMount = MountId(*mContext, fdinfoDirectory, mDescriptor, fdinfoByteCap);
    if (!observedMount.HasValue())
    {
        return std::move(observedMount).Error();
    }

    if (mContext->StatFileDescriptor(mDescriptor, &after) != 0)
    {
        return Error("Cannot recheck pinned metadata", SavedError());
    }

    if (!SameIdentity(before, after))
    {
        return Error("Pinned metadata identity changed", EAGAIN);
    }
    auto retainedMount = MountId(*mContext, fdinfoDirectory, mDescriptor, fdinfoByteCap);
    if (!retainedMount.HasValue())
    {
        return std::move(retainedMount).Error();
    }

    if (observedMount.Value() != retainedMount.Value())
    {
        return Error("Pinned metadata mount changed", EAGAIN);
    }
    mountId = observedMount.Value();
    return after;
}

Result<struct stat> Handle::Stat(std::size_t fdinfoByteCap) const
{
    if ((!mPin) || (mContext == nullptr) || (mDescriptor < 0) || (fdinfoByteCap == 0) || (fdinfoByteCap >= std::string().max_size()))
    {
        return Error("Fresh inspection requires a live pin and a positive fdinfo cap", EINVAL);
    }
    VerifiedProcfs procfs(*mContext);
    auto opened = procfs.Open();
    if (!opened.HasValue())
    {
        return std::move(opened).Error();
    }
    std::uint64_t mount = 0;
    return procfs.Finish(InspectWithProcfs(procfs.fdinfo.Get(), fdinfoByteCap, mount));
}

Result<std::uint64_t> Handle::MountIdentity(std::size_t fdinfoByteCap) const
{
    if ((!mPin) || (mContext == nullptr) || (mDescriptor < 0) || (fdinfoByteCap == 0))
    {
        return Error("Mount inspection requires a live pin and positive fdinfo cap", EINVAL);
    }
    VerifiedProcfs procfs(*mContext);
    auto opened = procfs.Open();
    if (!opened.HasValue())
    {
        return std::move(opened).Error();
    }
    std::uint64_t mountId = 0;
    auto inspected = InspectWithProcfs(procfs.fdinfo.Get(), fdinfoByteCap, mountId);
    if (!inspected.HasValue())
    {
        return procfs.Finish(Result<std::uint64_t>(std::move(inspected).Error()));
    }
    return procfs.Finish(Result<std::uint64_t>(mountId));
}

Result<bool> Handle::SetOwnership(uid_t owner, gid_t group, std::size_t fdinfoByteCap) const
{
    if ((!mPin) || (mContext == nullptr) || (mDescriptor < 0) || (fdinfoByteCap == 0) || (fdinfoByteCap >= std::string().max_size()))
    {
        return Error("Ownership change requires a live pin and a positive fdinfo cap", EINVAL);
    }
    VerifiedProcfs procfs(*mContext);
    auto opened = procfs.Open();
    if (!opened.HasValue())
    {
        return std::move(opened).Error();
    }
    auto changed = [&]() -> Result<bool> {
        std::uint64_t mount = 0;
        auto before = InspectWithProcfs(procfs.fdinfo.Get(), fdinfoByteCap, mount);
        if (!before.HasValue())
        {
            return std::move(before).Error();
        }
        // AT_EMPTY_PATH acts on the O_PATH pin itself. No alias or target
        // pathname is needed, including for an unreadable regular file.
        if (mContext->ChownPinnedFileDescriptor(mDescriptor, owner, group) != 0)
        {
            return Error("Cannot change pinned ownership", SavedError());
        }
        std::uint64_t afterMount = 0;
        auto after = InspectWithProcfs(procfs.fdinfo.Get(), fdinfoByteCap, afterMount);
        if (!after.HasValue())
        {
            return std::move(after).Error(); // The ownership syscall may already have succeeded.
        }

        if (mount != afterMount)
        {
            return Error("Pinned mount changed after ownership mutation", EAGAIN);
        }
        return true;
    }();
    return procfs.Finish(std::move(changed));
}

Result<bool> Handle::SetMode(mode_t mode, std::size_t fdinfoByteCap) const
{
    if ((!mPin) || (mContext == nullptr) || (mDescriptor < 0) || (fdinfoByteCap == 0) || (fdinfoByteCap >= std::string().max_size()))
    {
        return Error("Mode change requires a live pin and a positive fdinfo cap", EINVAL);
    }
    VerifiedProcfs procfs(*mContext);
    auto opened = procfs.Open();
    if (!opened.HasValue())
    {
        return std::move(opened).Error();
    }
    auto changed = [&]() -> Result<bool> {
        std::uint64_t mount = 0;
        auto before = InspectWithProcfs(procfs.fdinfo.Get(), fdinfoByteCap, mount);
        if (!before.HasValue())
        {
            return std::move(before).Error();
        }
        // Only this verified procfs descriptor alias is followed. Opening it
        // with O_PATH validates the alias without requiring content-read
        // permission or triggering special-file open effects.
        const std::string alias = std::to_string(mDescriptor);
        const int flags = O_PATH | O_CLOEXEC | ((mType == Type::Directory) ? O_DIRECTORY : 0);
        ScopedDescriptor candidate(*mContext, mContext->OpenNativeAt(procfs.fd.Get(), alias.c_str(), flags));
        auto checked = [&]() -> Result<bool> {
            if (candidate.Get() < 0)
            {
                return Error("Cannot inspect pinned mode alias", SavedError());
            }
            struct stat target = {};
            if (mContext->StatFileDescriptor(candidate.Get(), &target) != 0)
            {
                return Error("Cannot inspect pinned mode target", SavedError());
            }

            if (!SameIdentity(before.Value(), target))
            {
                return Error("Pinned mode alias identity differs", EAGAIN);
            }
            auto targetMount = MountId(*mContext, procfs.fdinfo.Get(), candidate.Get(), fdinfoByteCap);
            if (!targetMount.HasValue())
            {
                return std::move(targetMount).Error();
            }

            if (mount != targetMount.Value())
            {
                return Error("Pinned mode alias mount differs", EAGAIN);
            }
            std::uint64_t retainedMount = 0;
            auto retained = InspectWithProcfs(procfs.fdinfo.Get(), fdinfoByteCap, retainedMount);
            if (!retained.HasValue())
            {
                return std::move(retained).Error();
            }

            if (mount != retainedMount)
            {
                return Error("Pinned mount changed before mode mutation", EAGAIN);
            }
            // Linux's baseline fchmodat follows the procfd magic link, rather
            // than attempting fchmod on O_PATH or requiring a readable fd.
            if (mContext->ChmodPinnedAlias(procfs.fd.Get(), alias.c_str(), mode) != 0)
            {
                return Error("Cannot change pinned mode", SavedError());
            }
            std::uint64_t afterMount = 0;
            auto after = InspectWithProcfs(procfs.fdinfo.Get(), fdinfoByteCap, afterMount);
            if (!after.HasValue())
            {
                return std::move(after).Error(); // The chmod syscall may already have succeeded.
            }

            if (mount != afterMount)
            {
                return Error("Pinned mount changed after mode mutation", EAGAIN);
            }
            return true;
        }();
        return candidate.Finish(std::move(checked));
    }();
    return procfs.Finish(std::move(changed));
}

DirectoryCursor::DirectoryCursor(const ContextInterface& context, DIR* stream)
    : mContext(&context),
      mStream(stream)
{
}

DirectoryCursor::DirectoryCursor(DirectoryCursor&& other) noexcept
    : mContext(other.mContext),
      mStream(other.mStream),
      mCloseError(other.mCloseError)
{
    other.mContext = nullptr;
    other.mStream = nullptr;
    other.mCloseError = 0;
}

DirectoryCursor& DirectoryCursor::operator=(DirectoryCursor&& other) noexcept
{
    if (this != &other)
    {
        auto closed = Close();
        if (!closed.HasValue())
        {
            try
            {
                OsConfigLogError(mContext->GetLogHandle(), "%s", closed.Error().message.c_str());
            }
            catch (...)
            {
            }
        }
        mContext = other.mContext;
        mStream = other.mStream;
        mCloseError = other.mCloseError;
        other.mContext = nullptr;
        other.mStream = nullptr;
        other.mCloseError = 0;
    }
    return *this;
}

DirectoryCursor::~DirectoryCursor() noexcept
{
    if (mStream)
    {
        auto closed = Close();
        if (!closed.HasValue())
        {
            try
            {
                OsConfigLogError(mContext->GetLogHandle(), "%s", closed.Error().message.c_str());
            }
            catch (...)
            {
            }
        }
    }
}

Result<bool> DirectoryCursor::Close()
{
    if (!mStream)
    {
        return (mCloseError == 0) ? Result<bool>(true) : Result<bool>(Error("Cannot close pinned directory", mCloseError));
    }
    DIR* stream = mStream;
    mStream = nullptr;
    try
    {
        if (mContext->CloseDirectory(stream) != 0)
        {
            mCloseError = SavedError();
        }
    }
    catch (...)
    {
        mCloseError = EIO;
    }

    if (mCloseError != 0)
    {
        return Error("Cannot close pinned directory", mCloseError);
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

Result<ReadableFile> Handle::OpenReadOnly(std::size_t fdinfoByteCap) const
{
    if ((!mPin) || (mContext == nullptr) || (mDescriptor < 0))
    {
        return Error("Read-only activation requires a live file pin", EBADF);
    }

    if (mType != Type::RegularFile)
    {
        return Error("Read-only activation requires a regular file", EINVAL);
    }
    auto activated = Detail::ActivateReadOnly(*mContext, mDescriptor, mSnapshot, false, fdinfoByteCap);
    if (!activated.HasValue())
    {
        return std::move(activated).Error();
    }
    return ReadableFile(*mContext, activated.Value().Transfer());
}

Result<DirectoryCursor> Handle::OpenChildren(std::size_t fdinfoByteCap) const
{
    if ((!mPin) || (mContext == nullptr) || (mDescriptor < 0) || (mType != Type::Directory) || (fdinfoByteCap == 0))
    {
        return Error("Directory enumeration requires a live directory pin and positive fdinfo cap", EINVAL);
    }
    auto activated = Detail::ActivateReadOnly(*mContext, mDescriptor, mSnapshot, true, fdinfoByteCap);
    if (!activated.HasValue())
    {
        return std::move(activated).Error();
    }
    // fdopendir consumes its argument. Keep the independently verified
    // operational descriptor live until the directory stream is closed.
    ScopedDescriptor streamDescriptor(*mContext, ::fcntl(activated.Value().Descriptor(), F_DUPFD_CLOEXEC, 0));
    auto cursor = [&]() -> Result<DirectoryCursor> {
        if (streamDescriptor.Get() < 0)
        {
            return Error("Cannot duplicate pinned directory activation", SavedError());
        }
        DIR* stream = ::fdopendir(streamDescriptor.Get());
        if (stream == nullptr)
        {
            return Error("Cannot enumerate pinned directory", SavedError());
        }
        (void)streamDescriptor.Transfer();
        DirectoryCursor directory(*mContext, stream);
        const int activationError = activated.Value().CloseOnce();
        if (activationError != 0)
        {
            auto closed = directory.Close();
            if (!closed.HasValue())
            {
                (void)Detail::FinalizeResult(*mContext, Result<bool>(Error("Cannot close directory activation", activationError)), closed.Error().code);
            }
            return Error("Cannot close directory activation", activationError);
        }
        return std::move(directory);
    }();
    auto finalized = streamDescriptor.Finish(std::move(cursor));
    if (!finalized.HasValue())
    {
        const int error = activated.Value().CloseOnce();
        return Detail::FinalizeResult(*mContext, std::move(finalized), error);
    }
    return finalized;
}

void Handle::Swap(Handle& other) noexcept
{
    using std::swap;
    swap(mContext, other.mContext);
    swap(mDescriptor, other.mDescriptor);
    swap(mType, other.mType);
    mComponent.swap(other.mComponent);
    swap(mSnapshot, other.mSnapshot);
    swap(mPin, other.mPin);
    swap(mCloseError, other.mCloseError);
    mDetachedResources.swap(other.mDetachedResources);
    swap(mDetachedBytes, other.mDetachedBytes);
}

int Handle::CloseOnce() noexcept
{
    if (mDescriptor == -1)
    {
        return mCloseError;
    }
    const int descriptor = mDescriptor;
    mDescriptor = -1;
    if (mDetachedResources)
    {
        --mDetachedResources->descriptors;
        mDetachedResources->bytes -= mDetachedBytes;
        mDetachedResources.reset();
        mDetachedBytes = 0;
    }
    try
    {
        if (mContext->CloseFileDescriptor(descriptor) != 0)
        {
            mCloseError = SavedError();
        }
    }
    catch (...)
    {
        // A throwing close/log cannot be retried: Linux may have reused the
        // descriptor number. Destruction must not replace the primary error.
        mCloseError = EIO;
    }
    return mCloseError;
}

Result<bool> Handle::Close()
{
    const int error = CloseOnce();
    if (error != 0)
    {
        return Error("Cannot close pinned filesystem descriptor", error);
    }
    return true;
}

} // namespace Filesystem
} // namespace ComplianceEngine
