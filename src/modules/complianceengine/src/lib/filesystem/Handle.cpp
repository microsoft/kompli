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

void LogSecondaryClose(const ContextInterface& context, int error) noexcept
{
    try
    {
        OsConfigLogError(context.GetLogHandle(), "Secondary filesystem helper close failure: %d", error);
    }
    catch (...)
    {
        OsConfigLogError(nullptr, "Secondary filesystem helper close or log failure: %d", error);
    }
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
    : proc(Descriptor::Take(context, -1)),
      self(Descriptor::Take(context, -1)),
      pid(Descriptor::Take(context, -1)),
      fd(Descriptor::Take(context, -1)),
      fdinfo(Descriptor::Take(context, -1))
{
}
Result<bool> VerifiedProcfs::Open()
{
    auto opened = [&]() -> Result<bool> {
        if (proc.HasValue())
        {
            return Error("Procfs directory verification was already attempted", EINVAL);
        }
        const int procFd = proc.Context().OpenNativePath("/proc", O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        const int procError = SavedError();
        proc = Descriptor::Take(proc.Context(), procFd);
        if (!proc.HasValue() || !IsProcfsDirectory(proc.Get().Value()))
        {
            return Error("Trusted procfs directory is unavailable", (procFd < 0) ? procError : EPROTO);
        }
        const int selfFd = proc.Context().OpenNativeAt(proc.Get().Value(), "self", O_PATH | O_DIRECTORY | O_CLOEXEC);
        const int selfError = SavedError();
        self = Descriptor::Take(proc.Context(), selfFd);
        if (!self.HasValue())
        {
            return Error("Procfs self directory cannot be verified", selfError);
        }
        const int pidFd = proc.Context().OpenNativeAt(proc.Get().Value(), std::to_string(::getpid()).c_str(), O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        const int pidError = SavedError();
        pid = Descriptor::Take(proc.Context(), pidFd);
        struct stat selfStat = {}, pidStat = {};
        if (!pid.HasValue() || !IsProcfsDirectory(self.Get().Value()) || !IsProcfsDirectory(pid.Get().Value()) ||
            (::fstat(self.Get().Value(), &selfStat) != 0) || (::fstat(pid.Get().Value(), &pidStat) != 0) || !SameIdentity(selfStat, pidStat))
        {
            return Error("Procfs self directory cannot be verified", (pidFd < 0) ? pidError : EPROTO);
        }
        const int fdFd = proc.Context().OpenNativeAt(self.Get().Value(), "fd", O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        const int fdError = SavedError();
        fd = Descriptor::Take(proc.Context(), fdFd);
        if (!fd.HasValue())
        {
            return Error("Procfs descriptor directories cannot be verified", fdError);
        }
        const int fdinfoFd = proc.Context().OpenNativeAt(self.Get().Value(), "fdinfo", O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        const int fdinfoError = SavedError();
        fdinfo = Descriptor::Take(proc.Context(), fdinfoFd);
        if (!fdinfo.HasValue() || !IsProcfsDirectory(fd.Get().Value()) || !IsProcfsDirectory(fdinfo.Get().Value()))
        {
            return Error("Procfs descriptor directories cannot be verified", (fdinfoFd < 0) ? fdinfoError : EPROTO);
        }
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
    const int infoFd = context.OpenNativeAt(fdinfoDirectory, number.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    const int openError = SavedError();
    Descriptor info = Descriptor::Take(context, infoFd);
    auto read = [&]() -> Result<std::uint64_t> {
        if (!info.HasValue())
        {
            return Error("Cannot open procfs descriptor information", openError);
        }
        std::string bytes;
        char buffer[256] = {};
        for (;;)
        {
            const std::size_t request = std::min(sizeof(buffer), byteCap - bytes.size() + 1);
            const ssize_t count = context.ReadFileDescriptor(info.Get().Value(), buffer, request);
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
} // namespace Detail

namespace Detail
{
ReadOnlyActivation::ReadOnlyActivation(Detail::Descriptor&& descriptor, const struct stat& snapshot) noexcept
    : mDescriptor(std::move(descriptor)),
      mSnapshot(snapshot)
{
}

ReadOnlyActivation::ReadOnlyActivation(ReadOnlyActivation&& other) noexcept
    : mDescriptor(std::move(other.mDescriptor)),
      mSnapshot(other.mSnapshot)
{
}

ReadOnlyActivation& ReadOnlyActivation::operator=(ReadOnlyActivation&& other) noexcept
{
    if (this != &other)
    {
        ReadOnlyActivation incoming(std::move(other));
        using std::swap;
        swap(mDescriptor, incoming.mDescriptor);
        swap(mSnapshot, incoming.mSnapshot);
    }
    return *this;
}

Result<bool> ReadOnlyActivation::Close()
{
    return mDescriptor.Close();
}

const struct stat& ReadOnlyActivation::Snapshot() const noexcept
{
    return mSnapshot;
}

Result<int> ReadOnlyActivation::Descriptor() const
{
    return mDescriptor.Get();
}

Detail::Descriptor ReadOnlyActivation::TakeDescriptor() noexcept
{
    return std::move(mDescriptor);
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
    constexpr const char* activationCloseDiagnostic = "Failed to close directory activation";
    Descriptor operational = Descriptor::Take(context, -1, activationCloseDiagnostic);
    auto inspected = [&]() -> Result<struct stat>
    {
        auto pinnedMount = MountId(context, procfs.fdinfo.Get().Value(), pin, fdinfoByteCap);
        if (!pinnedMount.HasValue())
        {
            return std::move(pinnedMount).Error();
        }
        // Only the decimal alias of the held pin is followed intentionally.
        const std::string alias = std::to_string(pin);
        const int flags = O_RDONLY | O_CLOEXEC | (directory ? O_DIRECTORY : 0);
        const int openedFd = context.OpenNativeAt(procfs.fd.Get().Value(), alias.c_str(), flags);
        const int openError = SavedError();
        operational = Descriptor::Take(context, openedFd, activationCloseDiagnostic);
        if (!operational.HasValue())
        {
            return Error("Cannot open pinned descriptor alias for reading", openError);
        }
        struct stat activated = {}, stillPinned = {};
        if ((context.StatFileDescriptor(operational.Get().Value(), &activated) != 0) || (context.StatFileDescriptor(pin, &stillPinned) != 0))
        {
            return Error("Cannot inspect activated object and pin", SavedError());
        }

        if (!SameIdentity(before, activated) || !SameIdentity(before, stillPinned))
        {
            return Error("Activated object does not match live pin", EAGAIN);
        }
        auto activatedMount = MountId(context, procfs.fdinfo.Get().Value(), operational.Get().Value(), fdinfoByteCap);
        if (!activatedMount.HasValue())
        {
            return std::move(activatedMount).Error();
        }
        auto retainedMount = MountId(context, procfs.fdinfo.Get().Value(), pin, fdinfoByteCap);
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
    auto closed = procfs.Close();
    if (!closed.HasValue())
    {
        if (inspected.HasValue())
        {
            inspected = std::move(closed).Error();
        }
        else
        {
            LogSecondaryClose(context, closed.Error().code);
        }
    }
    if (!inspected.HasValue())
    {
        auto primary = std::move(inspected).Error();
        auto cleanup = operational.Close();
        if (!cleanup.HasValue())
        {
            LogSecondaryClose(context, cleanup.Error().code);
        }
        return primary;
    }
    // The operational alias must remain owned until all procfs checks and
    // helper closes have succeeded; output transfer occurs below.
    return ReadOnlyActivation(std::move(operational), inspected.Value());
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
    const int acquiredFd = context.OpenNativeAt(parentDirectory, component.c_str(), flags);
    const int openError = SavedError();
    Descriptor acquired = Descriptor::Take(context, acquiredFd);
    auto pinned = [&]() -> Result<Handle> {
        if (!acquired.HasValue())
        {
            return Error("Cannot pin filesystem component", openError);
        }
        struct stat snapshot = {};
        if (context.StatFileDescriptor(acquired.Get().Value(), &snapshot) != 0)
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
        Handle result(std::move(acquired), directory ? Handle::Type::Directory : Handle::Type::RegularFile, std::move(component), snapshot);
        return std::move(result);
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

Result<Handle> Handle::PinProcessRoot(const ContextInterface& context)
{
    const int acquiredFd = context.OpenNativePath("/", O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    const int openError = SavedError();
    Descriptor acquired = Descriptor::Take(context, acquiredFd);
    auto pinned = [&]() -> Result<Handle> {
        if (!acquired.HasValue())
        {
            return Error("Cannot pin process root for absolute-prefix validation", openError);
        }
        struct stat snapshot = {};
        if (context.StatFileDescriptor(acquired.Get().Value(), &snapshot) != 0)
        {
            return Error("Cannot inspect process root pin", SavedError());
        }

        if (!S_ISDIR(snapshot.st_mode))
        {
            return Error("Process root is not a directory", ENOTDIR);
        }
        Handle root(std::move(acquired), Handle::Type::Directory, "/", snapshot);
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

Result<Handle> Handle::AcquireChild(const Handle& parent, std::string component, bool directory)
{
    if ((!parent.mPin) || (parent.mType != Handle::Type::Directory) || (parent.mContext == nullptr))
    {
        return Error("A live directory pin is required", EINVAL);
    }
    auto descriptor = parent.mDescriptor.Get();
    if (!descriptor.HasValue())
    {
        return std::move(descriptor).Error();
    }
    return AcquireChild(*parent.mContext, descriptor.Value(), std::move(component), directory);
}

Result<bool> Handle::RecognizeAcceptedRoot(const Handle& acceptedRoot, const Handle& candidate, std::size_t fdinfoByteCap)
{
    if ((!acceptedRoot.mPin) || (!candidate.mPin) || (acceptedRoot.mType != Handle::Type::Directory) || (candidate.mType != Handle::Type::Directory) ||
        (acceptedRoot.mContext == nullptr) || (candidate.mContext == nullptr) || !acceptedRoot.mDescriptor.HasValue() ||
        !candidate.mDescriptor.HasValue() || (fdinfoByteCap == 0))
    {
        return Error("Two live directory pins and a positive fdinfo cap are required", EINVAL);
    }
    struct stat root = {}, observed = {};
    if ((acceptedRoot.mContext->StatFileDescriptor(acceptedRoot.mDescriptor.Get().Value(), &root) != 0) ||
        (candidate.mContext->StatFileDescriptor(candidate.mDescriptor.Get().Value(), &observed) != 0))
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
        auto rootMount = MountId(*acceptedRoot.mContext, procfs.fdinfo.Get().Value(), acceptedRoot.mDescriptor.Get().Value(), fdinfoByteCap);
        if (!rootMount.HasValue())
        {
            return std::move(rootMount).Error();
        }
        auto candidateMount = MountId(*acceptedRoot.mContext, procfs.fdinfo.Get().Value(), candidate.mDescriptor.Get().Value(), fdinfoByteCap);
        if (!candidateMount.HasValue())
        {
            return std::move(candidateMount).Error();
        }
        struct stat retainedRoot = {}, retainedCandidate = {};
        if ((acceptedRoot.mContext->StatFileDescriptor(acceptedRoot.mDescriptor.Get().Value(), &retainedRoot) != 0) ||
            (candidate.mContext->StatFileDescriptor(candidate.mDescriptor.Get().Value(), &retainedCandidate) != 0))
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
        Detail::LogSecondaryClose(*acceptedRoot.mContext, closed.Error().code);
    }
    return compared;
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
        if ((held == nullptr) || (!held->mPin) || (held->mType != Handle::Type::Directory) || !held->mDescriptor.HasValue())
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
            if (validated.HasValue())
            {
                validated = std::move(closed).Error();
            }
            else
            {
                Detail::LogSecondaryClose(context, closed.Error().code);
            }
        }
    }
    return validated;
}

Handle::Handle(Detail::Descriptor&& descriptor, Type type, std::string component, const struct stat& snapshot)
    : mContext(&descriptor.Context()),
      mDescriptor(std::move(descriptor)),
      mType(type),
      mComponent(std::move(component)),
      mSnapshot(snapshot)
{
}

Handle::Handle(Handle&& other) noexcept
    : mContext(other.mContext),
      mDescriptor(std::move(other.mDescriptor)),
      mType(other.mType),
      mComponent(std::move(other.mComponent)),
      mSnapshot(other.mSnapshot),
      mPin(other.mPin),
      mCloseError(other.mCloseError),
      mDetachedResources(std::move(other.mDetachedResources)),
      mDetachedBytes(other.mDetachedBytes)
{
    other.mContext = nullptr;
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
    int error = 0;
    try
    {
        if (mDescriptor.HasValue())
        {
            error = CloseOnce();
            if (error != 0)
            {
                OsConfigLogError(mContext->GetLogHandle(), "Failed to close pinned filesystem descriptor: %d", error);
            }
        }
    }
    catch (...)
    {
        OsConfigLogError(nullptr, "Pinned filesystem descriptor close or log failure: %d", error != 0 ? error : EIO);
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
    if ((!mPin) || (mContext == nullptr) || !mDescriptor.HasValue() || (fdinfoByteCap == 0) || (fdinfoByteCap >= std::string().max_size()))
    {
        return Error("Metadata inspection requires a live pin and a positive fdinfo cap", EINVAL);
    }
    const int flags = ::fcntl(mDescriptor.Get().Value(), F_GETFL);
    if (flags < 0)
    {
        return Error("Cannot inspect pinned descriptor flags", SavedError());
    }
    const int descriptorFlags = ::fcntl(mDescriptor.Get().Value(), F_GETFD);
    if (descriptorFlags < 0)
    {
        return Error("Cannot inspect pinned descriptor flags", SavedError());
    }

    if (((flags & O_PATH) == 0) || ((descriptorFlags & FD_CLOEXEC) == 0))
    {
        return Error("Metadata operation requires a close-on-exec O_PATH pin", EINVAL);
    }
    struct stat before = {}, after = {};
    if (mContext->StatFileDescriptor(mDescriptor.Get().Value(), &before) != 0)
    {
        return Error("Cannot inspect pinned metadata", SavedError());
    }

    if (!SameIdentity(before, mSnapshot) || ((mType == Type::RegularFile) && !S_ISREG(before.st_mode)) || ((mType == Type::Directory) && !S_ISDIR(before.st_mode)))
    {
        return Error("Pinned metadata has an unexpected identity or type", EAGAIN);
    }
    auto observedMount = MountId(*mContext, fdinfoDirectory, mDescriptor.Get().Value(), fdinfoByteCap);
    if (!observedMount.HasValue())
    {
        return std::move(observedMount).Error();
    }

    if (mContext->StatFileDescriptor(mDescriptor.Get().Value(), &after) != 0)
    {
        return Error("Cannot recheck pinned metadata", SavedError());
    }

    if (!SameIdentity(before, after))
    {
        return Error("Pinned metadata identity changed", EAGAIN);
    }
    auto retainedMount = MountId(*mContext, fdinfoDirectory, mDescriptor.Get().Value(), fdinfoByteCap);
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
    if ((!mPin) || (mContext == nullptr) || !mDescriptor.HasValue() || (fdinfoByteCap == 0) || (fdinfoByteCap >= std::string().max_size()))
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
    auto inspected = InspectWithProcfs(procfs.fdinfo.Get().Value(), fdinfoByteCap, mount);
    auto closed = procfs.Close();
    if (!closed.HasValue())
    {
        if (inspected.HasValue())
        {
            return std::move(closed).Error();
        }
        Detail::LogSecondaryClose(*mContext, closed.Error().code);
    }
    return inspected;
}

Result<std::uint64_t> Handle::MountIdentity(std::size_t fdinfoByteCap) const
{
    if ((!mPin) || (mContext == nullptr) || !mDescriptor.HasValue() || (fdinfoByteCap == 0))
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
    auto inspected = InspectWithProcfs(procfs.fdinfo.Get().Value(), fdinfoByteCap, mountId);
    Result<std::uint64_t> outcome = inspected.HasValue() ? Result<std::uint64_t>(mountId) : Result<std::uint64_t>(std::move(inspected).Error());
    auto closed = procfs.Close();
    if (!closed.HasValue())
    {
        if (outcome.HasValue())
        {
            return std::move(closed).Error();
        }
        Detail::LogSecondaryClose(*mContext, closed.Error().code);
    }
    return outcome;
}

Result<bool> Handle::SetOwnership(uid_t owner, gid_t group, std::size_t fdinfoByteCap) const
{
    if ((!mPin) || (mContext == nullptr) || !mDescriptor.HasValue() || (fdinfoByteCap == 0) || (fdinfoByteCap >= std::string().max_size()))
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
        auto before = InspectWithProcfs(procfs.fdinfo.Get().Value(), fdinfoByteCap, mount);
        if (!before.HasValue())
        {
            return std::move(before).Error();
        }
        // AT_EMPTY_PATH acts on the O_PATH pin itself. No alias or target
        // pathname is needed, including for an unreadable regular file.
        if (mContext->ChownPinnedFileDescriptor(mDescriptor.Get().Value(), owner, group) != 0)
        {
            return Error("Cannot change pinned ownership", SavedError());
        }
        std::uint64_t afterMount = 0;
        auto after = InspectWithProcfs(procfs.fdinfo.Get().Value(), fdinfoByteCap, afterMount);
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
    auto closed = procfs.Close();
    if (!closed.HasValue())
    {
        if (changed.HasValue())
        {
            return std::move(closed).Error();
        }
        Detail::LogSecondaryClose(*mContext, closed.Error().code);
    }
    return changed;
}

Result<bool> Handle::SetMode(mode_t mode, std::size_t fdinfoByteCap) const
{
    if ((!mPin) || (mContext == nullptr) || !mDescriptor.HasValue() || (fdinfoByteCap == 0) || (fdinfoByteCap >= std::string().max_size()))
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
        auto before = InspectWithProcfs(procfs.fdinfo.Get().Value(), fdinfoByteCap, mount);
        if (!before.HasValue())
        {
            return std::move(before).Error();
        }
        // Only this verified procfs descriptor alias is followed. Opening it
        // with O_PATH validates the alias without requiring content-read
        // permission or triggering special-file open effects.
        const std::string alias = std::to_string(mDescriptor.Get().Value());
        const int flags = O_PATH | O_CLOEXEC | ((mType == Type::Directory) ? O_DIRECTORY : 0);
        const int candidateFd = mContext->OpenNativeAt(procfs.fd.Get().Value(), alias.c_str(), flags);
        const int openError = SavedError();
        Descriptor candidate = Descriptor::Take(*mContext, candidateFd);
        auto checked = [&]() -> Result<bool> {
            if (!candidate.HasValue())
            {
                return Error("Cannot inspect pinned mode alias", openError);
            }
            struct stat target = {};
            if (mContext->StatFileDescriptor(candidate.Get().Value(), &target) != 0)
            {
                return Error("Cannot inspect pinned mode target", SavedError());
            }

            if (!SameIdentity(before.Value(), target))
            {
                return Error("Pinned mode alias identity differs", EAGAIN);
            }
            auto targetMount = MountId(*mContext, procfs.fdinfo.Get().Value(), candidate.Get().Value(), fdinfoByteCap);
            if (!targetMount.HasValue())
            {
                return std::move(targetMount).Error();
            }

            if (mount != targetMount.Value())
            {
                return Error("Pinned mode alias mount differs", EAGAIN);
            }
            std::uint64_t retainedMount = 0;
            auto retained = InspectWithProcfs(procfs.fdinfo.Get().Value(), fdinfoByteCap, retainedMount);
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
            if (mContext->ChmodPinnedAlias(procfs.fd.Get().Value(), alias.c_str(), mode) != 0)
            {
                return Error("Cannot change pinned mode", SavedError());
            }
            std::uint64_t afterMount = 0;
            auto after = InspectWithProcfs(procfs.fdinfo.Get().Value(), fdinfoByteCap, afterMount);
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
        auto closed = candidate.Close();
        if (!closed.HasValue())
        {
            if (checked.HasValue())
            {
                return std::move(closed).Error();
            }
            Detail::LogSecondaryClose(*mContext, closed.Error().code);
        }
        return checked;
    }();
    auto closed = procfs.Close();
    if (!closed.HasValue())
    {
        if (changed.HasValue())
        {
            return std::move(closed).Error();
        }
        Detail::LogSecondaryClose(*mContext, closed.Error().code);
    }
    return changed;
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
        int error = 0;
        try
        {
            auto closed = Close();
            if (!closed.HasValue())
            {
                error = closed.Error().code;
                OsConfigLogError(mContext->GetLogHandle(), "%s", closed.Error().message.c_str());
            }
        }
        catch (...)
        {
            OsConfigLogError(nullptr, "Directory cursor move close or log failure: %d", error != 0 ? error : (mCloseError != 0 ? mCloseError : EIO));
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
        int error = 0;
        try
        {
            auto closed = Close();
            if (!closed.HasValue())
            {
                error = closed.Error().code;
                OsConfigLogError(mContext->GetLogHandle(), "%s", closed.Error().message.c_str());
            }
        }
        catch (...)
        {
            OsConfigLogError(nullptr, "Directory cursor destruction close or log failure: %d", error != 0 ? error : (mCloseError != 0 ? mCloseError : EIO));
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
    if ((!mPin) || (mContext == nullptr) || !mDescriptor.HasValue())
    {
        return Error("Read-only activation requires a live file pin", EBADF);
    }

    if (mType != Type::RegularFile)
    {
        return Error("Read-only activation requires a regular file", EINVAL);
    }
    auto activated = Detail::ActivateReadOnly(*mContext, mDescriptor.Get().Value(), mSnapshot, false, fdinfoByteCap);
    if (!activated.HasValue())
    {
        return std::move(activated).Error();
    }
    return ReadableFile(activated.Value().TakeDescriptor());
}

Result<DirectoryCursor> Handle::OpenChildren(std::size_t fdinfoByteCap) const
{
    if ((!mPin) || (mContext == nullptr) || !mDescriptor.HasValue() || (mType != Type::Directory) || (fdinfoByteCap == 0))
    {
        return Error("Directory enumeration requires a live directory pin and positive fdinfo cap", EINVAL);
    }
    auto activated = Detail::ActivateReadOnly(*mContext, mDescriptor.Get().Value(), mSnapshot, true, fdinfoByteCap);
    if (!activated.HasValue())
    {
        return std::move(activated).Error();
    }
    // fdopendir consumes its argument. Keep the independently verified
    // operational descriptor live until the directory stream is closed.
    const int streamFd = ::fcntl(activated.Value().Descriptor().Value(), F_DUPFD_CLOEXEC, 0);
    const int duplicateError = SavedError();
    Descriptor streamDescriptor = Descriptor::Take(*mContext, streamFd);
    auto cursor = [&]() -> Result<DirectoryCursor> {
        if (!streamDescriptor.HasValue())
        {
            return Error("Cannot duplicate pinned directory activation", duplicateError);
        }
        DIR* stream = ::fdopendir(streamDescriptor.Get().Value());
        if (stream == nullptr)
        {
            return Error("Cannot enumerate pinned directory", SavedError());
        }
        (void)streamDescriptor.Release().Value(); // fdopendir now owns this native fd.
        DirectoryCursor directory(*mContext, stream);
        auto activationClosed = activated.Value().Close();
        if (!activationClosed.HasValue())
        {
            try
            {
                auto closed = directory.Close();
                if (!closed.HasValue())
                {
                    Detail::LogSecondaryClose(*mContext, closed.Error().code);
                }
            }
            catch (...)
            {
                Detail::LogSecondaryClose(*mContext, EIO);
            }
            return Error("Cannot close directory activation", activationClosed.Error().code);
        }
        return std::move(directory);
    }();
    auto streamClosed = streamDescriptor.Close();
    if (!streamClosed.HasValue())
    {
        if (cursor.HasValue())
        {
            cursor = std::move(streamClosed).Error();
        }
        else
        {
            Detail::LogSecondaryClose(*mContext, streamClosed.Error().code);
        }
    }
    if (!cursor.HasValue())
    {
        auto activationClosed = activated.Value().Close();
        if (!activationClosed.HasValue())
        {
            Detail::LogSecondaryClose(*mContext, activationClosed.Error().code);
        }
    }
    return cursor;
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
    // The cached Handle contract is separate from Descriptor's typed outcome.
    // A moved/closed owner has no native descriptor to retry.
    if (!mDescriptor.HasValue())
    {
        return mCloseError;
    }
    if (mDetachedResources)
    {
        --mDetachedResources->descriptors;
        mDetachedResources->bytes -= mDetachedBytes;
        mDetachedResources.reset();
        mDetachedBytes = 0;
    }
    // The owner relinquishes the fd before the native close, even if it
    // throws; cached errors and detached accounting remain Handle-specific.
    try
    {
        auto closed = mDescriptor.Close();
        mCloseError = closed.HasValue() ? 0 : closed.Error().code;
    }
    catch (...)
    {
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
