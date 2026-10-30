// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "ProcfsDescriptorAccess.hpp"

#include "PathInternal.hpp"

#include <algorithm>
#include <cerrno>
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
namespace
{
bool IsProcfsDirectory(const ContextInterface& context, const Descriptor& descriptor)
{
    struct statfs filesystem = {};
    struct stat metadata = {};
    return (context.StatFilesystem(descriptor, &filesystem) == 0) && (filesystem.f_type == PROC_SUPER_MAGIC) &&
           (context.StatFile(descriptor, &metadata) == 0) && S_ISDIR(metadata.st_mode);
}
} // namespace

// All procfs names are relative to previously held, verified directories.
// "self" is the one intentional link and must identify the current PID.
ProcfsDescriptorAccess::ProcfsDescriptorAccess(const ContextInterface& context)
    : proc(context.EmptyDescriptor()),
      self(context.EmptyDescriptor()),
      pid(context.EmptyDescriptor()),
      fd(context.EmptyDescriptor()),
      fdinfo(context.EmptyDescriptor())
{
}

Result<bool> ProcfsDescriptorAccess::Open()
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

Result<bool> ProcfsDescriptorAccess::Close()
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

bool ProcfsDescriptorAccess::VerifyRole(const ContextInterface& context, bool information) const
{
    if (!mVerified || &proc.Context() != &context)
        return false;
    const Descriptor& role = information ? fdinfo : fd;
    if (!role.HasValue() || &role.Context() != &context)
        return false;
    struct stat identity = {};
    return context.StatFile(role, &identity) == 0 && SameIdentity(identity, information ? mFdinfoIdentity : mFdIdentity) && S_ISDIR(identity.st_mode);
}

Result<std::uint64_t> ParseMountId(const std::string& fdinfo)
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

Result<std::uint64_t> ProcfsDescriptorAccess::ReadMountId(const Descriptor& descriptor, std::size_t byteCap) const
{
    if ((byteCap == 0) || (byteCap >= std::string().max_size()))
    {
        return Error("Invalid procfs descriptor information byte cap", EINVAL);
    }
    const auto& context = proc.Context();
    auto opened = context.OpenFdinfo(*this, descriptor);
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
        return ParseMountId(bytes);
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
} // namespace Filesystem
} // namespace ComplianceEngine
