// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "ProcfsDescriptorAccess.hpp"

#include "FilesystemHelpers.hpp"

#include <algorithm>
#include <array>
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
bool ProcfsDescriptorAccess::IsProcfsDirectory(const ContextInterface& context, const Descriptor& descriptor)
{
    struct statfs filesystem = {};
    struct stat metadata = {};
    return (context.StatFilesystem(descriptor, &filesystem) == 0) && (filesystem.f_type == PROC_SUPER_MAGIC) &&
           (context.StatFile(descriptor, &metadata) == 0) && S_ISDIR(metadata.st_mode);
}
// All procfs names are relative to previously held, verified directories.
// Bootstrap directories retire after their last use; only fd and fdinfo need
// to remain pinned for subsequent verified native access.
ProcfsDescriptorAccess::ProcfsDescriptorAccess(const ContextInterface& context, Roles roles, VerifiedBindings bindings) noexcept
    : mContext(&context),
      mRoles(std::move(roles)),
      mBindings(bindings)
{
}

Result<ProcfsDescriptorAccess> ProcfsDescriptorAccess::Open(const ContextInterface& context)
{
    auto currentPid = context.CurrentProcessId();
    if (!currentPid.HasValue())
        return std::move(currentPid).Error();
    auto currentTid = context.CurrentThreadId();
    if (!currentTid.HasValue())
        return std::move(currentTid).Error();
    const pid_t pidValue = currentPid.Value();
    const pid_t tidValue = currentTid.Value();

    // proc and pid retire before task acquisition; self is the only survivor.
    auto openedSelf = [&]() -> Result<Descriptor> {
        auto openedProc = context.OpenAbsolutePin("/proc");
        if (!openedProc.HasValue())
            return Error("Trusted procfs directory is unavailable", openedProc.Error().code);
        Descriptor proc = std::move(openedProc).Value();
        if (!IsProcfsDirectory(context, proc))
            return Error("Trusted procfs directory is unavailable", EPROTO);
        auto opened = context.OpenProcfsSelf(proc);
        if (!opened.HasValue())
            return Error("Procfs self directory cannot be verified", opened.Error().code);
        Descriptor self = std::move(opened).Value();
        auto openedPid = context.OpenAt(proc, std::to_string(pidValue).c_str(), ContextInterface::OpenProfile::PinDirectory);
        if (!openedPid.HasValue())
            return Error("Procfs self directory cannot be verified", openedPid.Error().code);
        Descriptor pid = std::move(openedPid).Value();
        struct stat selfStat = {}, pidStat = {};
        if (!IsProcfsDirectory(context, self) || !IsProcfsDirectory(context, pid) || (context.StatFile(self, &selfStat) != 0) ||
            (context.StatFile(pid, &pidStat) != 0) || !SameIdentity(selfStat, pidStat))
            return Error("Procfs self directory cannot be verified", EPROTO);
        return std::move(self);
    }();
    if (!openedSelf.HasValue())
        return std::move(openedSelf).Error();
    Descriptor self = std::move(openedSelf).Value();

    // task and self retire after tid verification, before fd acquisition.
    auto openedTid = [&]() -> Result<Descriptor> {
        auto openedTask = context.OpenAt(self, "task", ContextInterface::OpenProfile::PinDirectory);
        if (!openedTask.HasValue())
            return Error("Procfs task directory cannot be verified", openedTask.Error().code);
        Descriptor task = std::move(openedTask).Value();
        if (!IsProcfsDirectory(context, task))
            return Error("Procfs task directory cannot be verified", EPROTO);
        auto opened = context.OpenAt(task, std::to_string(tidValue).c_str(), ContextInterface::OpenProfile::PinDirectory);
        if (!opened.HasValue())
            return Error("Procfs current task cannot be verified", opened.Error().code);
        Descriptor tid = std::move(opened).Value();
        if (!IsProcfsDirectory(context, tid))
            return Error("Procfs current task cannot be verified", EPROTO);
        return std::move(tid);
    }();
    if (!openedTid.HasValue())
        return std::move(openedTid).Error();
    Descriptor tid = std::move(openedTid).Value();
    self.Close(); // Last use; tid remains held for all subsequent verification.

    struct stat fdIdentity = {}, fdinfoIdentity = {};
    auto openedRoles = [&]() -> Result<Roles> {
        auto openedFd = context.OpenAt(tid, "fd", ContextInterface::OpenProfile::PinDirectory);
        if (!openedFd.HasValue())
            return Error("Procfs descriptor directories cannot be verified", openedFd.Error().code);
        Descriptor fd = std::move(openedFd).Value();
        auto openedFdinfo = context.OpenAt(tid, "fdinfo", ContextInterface::OpenProfile::PinDirectory);
        if (!openedFdinfo.HasValue())
            return Error("Procfs descriptor directories cannot be verified", openedFdinfo.Error().code);
        Descriptor fdinfo = std::move(openedFdinfo).Value();
        if (!IsProcfsDirectory(context, fd) || !IsProcfsDirectory(context, fdinfo))
            return Error("Procfs descriptor directories cannot be verified", EPROTO);
        if ((context.StatFile(fd, &fdIdentity) != 0) || (context.StatFile(fdinfo, &fdinfoIdentity) != 0))
            return Error("Procfs descriptor directory identity cannot be verified", SavedError());
        currentPid = context.CurrentProcessId();
        if (!currentPid.HasValue())
            return std::move(currentPid).Error();
        currentTid = context.CurrentThreadId();
        if (!currentTid.HasValue())
            return std::move(currentTid).Error();
        if ((currentPid.Value() != pidValue) || (currentTid.Value() != tidValue))
            return Error("Procfs current task changed during verification", EPROTO);
        return Roles{{std::move(fd), std::move(fdinfo)}};
    }();
    if (!openedRoles.HasValue())
        return std::move(openedRoles).Error();
    tid.Close(); // All identity and task checks precede publication.
    return ProcfsDescriptorAccess(context, std::move(openedRoles).Value(), VerifiedBindings{pidValue, tidValue, fdIdentity, fdinfoIdentity});
}

void ProcfsDescriptorAccess::RequireRolesOwned() const
{
    mRoles[static_cast<std::size_t>(Role::Fd)].RequireOwned();
    mRoles[static_cast<std::size_t>(Role::Fdinfo)].RequireOwned();
}

bool ProcfsDescriptorAccess::VerifyRole(const ContextInterface& context, bool information) const
{
    const std::size_t roleIndex = static_cast<std::size_t>(information ? Role::Fdinfo : Role::Fd);
    RequireRolesOwned();
    if (mContext != &context)
        return false;
    auto currentPid = context.CurrentProcessId();
    if (!currentPid.HasValue() || (currentPid.Value() != mBindings.pid))
        return false;
    auto currentTid = context.CurrentThreadId();
    if (!currentTid.HasValue() || (currentTid.Value() != mBindings.tid))
        return false;
    struct stat identity = {};
    return (context.StatFile(mRoles[roleIndex], &identity) == 0) &&
           SameIdentity(identity, information ? mBindings.fdinfoIdentity : mBindings.fdIdentity) && S_ISDIR(identity.st_mode);
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
    descriptor.RequireOwned();
    RequireRolesOwned(); // Move misuse precedes cap validation without native access.
    if ((byteCap == 0) || (byteCap >= std::string().max_size()))
    {
        return Error("Invalid procfs descriptor information byte cap", EINVAL);
    }
    const auto& context = *mContext;
    auto opened = context.OpenFdinfo(*this, descriptor);
    if (!opened.HasValue())
    {
        return Error("Cannot open procfs descriptor information", opened.Error().code);
    }
    Descriptor info = std::move(opened).Value();
    auto read = [&]() -> Result<std::uint64_t> {
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
    return read;
}

} // namespace Detail
} // namespace Filesystem
} // namespace ComplianceEngine
