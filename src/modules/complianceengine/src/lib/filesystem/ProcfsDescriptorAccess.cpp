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
    : mContext(context),
      mRoles(std::move(roles)),
      mBindings(bindings)
{
}

// /proc and the numeric pid directory retire (destruct) when this function
// returns; only the verified self directory survives into the caller.
Result<Descriptor> ProcfsDescriptorAccess::OpenVerifiedSelf(const ContextInterface& context, pid_t pid)
{
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
    auto openedPid = context.OpenAt(proc, std::to_string(pid).c_str(), ContextInterface::OpenProfile::PinDirectory);
    if (!openedPid.HasValue())
        return Error("Procfs self directory cannot be verified", openedPid.Error().code);
    Descriptor pidDirectory = std::move(openedPid).Value();
    struct stat selfStat = {}, pidStat = {};
    if (!IsProcfsDirectory(context, self) || !IsProcfsDirectory(context, pidDirectory) || (context.StatFile(self, &selfStat) != 0) ||
        (context.StatFile(pidDirectory, &pidStat) != 0) || !SameIdentity(selfStat, pidStat))
        return Error("Procfs self directory cannot be verified", EPROTO);
    return std::move(self);
}

// self and the task directory retire when this function returns; only the
// verified current-task directory survives into the caller.
Result<Descriptor> ProcfsDescriptorAccess::OpenVerifiedTid(const ContextInterface& context, pid_t pid, pid_t tid)
{
    auto openedSelf = OpenVerifiedSelf(context, pid);
    if (!openedSelf.HasValue())
        return std::move(openedSelf).Error();
    Descriptor self = std::move(openedSelf).Value();
    auto openedTask = context.OpenAt(self, "task", ContextInterface::OpenProfile::PinDirectory);
    if (!openedTask.HasValue())
        return Error("Procfs task directory cannot be verified", openedTask.Error().code);
    Descriptor task = std::move(openedTask).Value();
    if (!IsProcfsDirectory(context, task))
        return Error("Procfs task directory cannot be verified", EPROTO);
    auto opened = context.OpenAt(task, std::to_string(tid).c_str(), ContextInterface::OpenProfile::PinDirectory);
    if (!opened.HasValue())
        return Error("Procfs current task cannot be verified", opened.Error().code);
    Descriptor tidDirectory = std::move(opened).Value();
    if (!IsProcfsDirectory(context, tidDirectory))
        return Error("Procfs current task cannot be verified", EPROTO);
    return std::move(tidDirectory);
}

Result<ProcfsDescriptorAccess::RetainedRoles> ProcfsDescriptorAccess::OpenVerifiedRoles(const ContextInterface& context,
    const Descriptor& taskDirectory, pid_t pid, pid_t tid)
{
    auto openedFd = context.OpenAt(taskDirectory, "fd", ContextInterface::OpenProfile::PinDirectory);
    if (!openedFd.HasValue())
        return Error("Procfs descriptor directories cannot be verified", openedFd.Error().code);
    Descriptor fd = std::move(openedFd).Value();
    auto openedFdinfo = context.OpenAt(taskDirectory, "fdinfo", ContextInterface::OpenProfile::PinDirectory);
    if (!openedFdinfo.HasValue())
        return Error("Procfs descriptor directories cannot be verified", openedFdinfo.Error().code);
    Descriptor fdinfo = std::move(openedFdinfo).Value();
    if (!IsProcfsDirectory(context, fd) || !IsProcfsDirectory(context, fdinfo))
        return Error("Procfs descriptor directories cannot be verified", EPROTO);
    struct stat fdIdentity = {}, fdinfoIdentity = {};
    if ((context.StatFile(fd, &fdIdentity) != 0) || (context.StatFile(fdinfo, &fdinfoIdentity) != 0))
        return Error("Procfs descriptor directory identity cannot be verified", SavedError());
    auto currentPid = context.CurrentProcessId();
    if (!currentPid.HasValue())
        return std::move(currentPid).Error();
    auto currentTid = context.CurrentThreadId();
    if (!currentTid.HasValue())
        return std::move(currentTid).Error();
    if ((currentPid.Value() != pid) || (currentTid.Value() != tid))
        return Error("Procfs current task changed during verification", EPROTO);
    return RetainedRoles{Roles{{std::move(fd), std::move(fdinfo)}}, fdIdentity, fdinfoIdentity};
}

Result<ProcfsDescriptorAccess> ProcfsDescriptorAccess::Make(const ContextInterface& context)
{
    auto currentPid = context.CurrentProcessId();
    if (!currentPid.HasValue())
        return std::move(currentPid).Error();
    auto currentTid = context.CurrentThreadId();
    if (!currentTid.HasValue())
        return std::move(currentTid).Error();
    const pid_t pidValue = currentPid.Value();
    const pid_t tidValue = currentTid.Value();

    // Each scoped return carries only its final verified role. Proc and PID
    // retire before task acquisition; self and task retire before fd/fdinfo.
    auto openedTid = OpenVerifiedTid(context, pidValue, tidValue);
    if (!openedTid.HasValue())
        return std::move(openedTid).Error();
    Descriptor tid = std::move(openedTid).Value();

    auto retained = OpenVerifiedRoles(context, tid, pidValue, tidValue);
    if (!retained.HasValue())
        return std::move(retained).Error();
    RetainedRoles rolesWithIdentity = std::move(retained).Value();
    return ProcfsDescriptorAccess(context, std::move(rolesWithIdentity.roles),
        VerifiedBindings{pidValue, tidValue, rolesWithIdentity.fdIdentity, rolesWithIdentity.fdinfoIdentity});
}

// A private member function (called by friends): the caller (ContextInterface's
// OpenFdinfo/OpenAlias/OpenPinAlias/ChmodAlias, a friend) has already
// rejected a moved-from target and the specific moved-from role it is about
// to verify, via RequireOwned in Descriptor.cpp there -- the only place that
// touches a raw descriptor integer. VerifyRole itself never reads one; every
// check below goes through a verified native ContextInterface operation.
bool ProcfsDescriptorAccess::VerifyRole(const ContextInterface& context, Role role) const
{
    const std::size_t roleIndex = static_cast<std::size_t>(role);
    if (&mContext.get() != &context)
        return false;
    auto currentPid = context.CurrentProcessId();
    if (!currentPid.HasValue() || (currentPid.Value() != mBindings.pid))
        return false;
    auto currentTid = context.CurrentThreadId();
    if (!currentTid.HasValue() || (currentTid.Value() != mBindings.tid))
        return false;
    struct stat identity = {};
    return (context.StatFile(mRoles[roleIndex], &identity) == 0) &&
           SameIdentity(identity, role == Role::Fdinfo ? mBindings.fdinfoIdentity : mBindings.fdIdentity) && S_ISDIR(identity.st_mode);
}

Result<std::uint64_t> ProcfsDescriptorAccess::ReadMountIdBytes(const ContextInterface& context, const Descriptor& info, std::size_t byteCap)
{
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
}

// The byte cap is validated once, at acceptance (Path::Make's ResolverLimits
// check, the FTW continuation check, and FilesystemCollection's request
// validation all reject 0 and an overflowing cap before any Path/Handle
// acquisition can reach here); ReadMountId relies on that validation instead
// of re-checking the cap itself.
// Move misuse (a consumed target or a consumed procfs session) still throws
// std::logic_error before any native dispatch: OpenFdinfo (a ContextInterface
// friend operation) rejects the target first, then the fdinfo role, via
// RequireOwned in Descriptor.cpp, before VerifyRole's own
// native pid/tid/stat calls run.
Result<std::uint64_t> ProcfsDescriptorAccess::ReadMountId(const Descriptor& descriptor, std::size_t byteCap) const
{
    const auto& context = mContext.get();
    auto opened = context.OpenFdinfo(*this, descriptor);
    if (!opened.HasValue())
    {
        return Error("Cannot open procfs descriptor information", opened.Error().code);
    }
    Descriptor info = std::move(opened).Value();
    return ReadMountIdBytes(context, info, byteCap);
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

} // namespace Detail
} // namespace Filesystem
} // namespace ComplianceEngine
