// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "ContextInterface.h"

#include <algorithm>
#include <cerrno>
#include <fcntl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <unistd.h>

namespace ComplianceEngine
{
ContextInterface::ContextInterface()
{
    // Each context owns one budget throughout the lifetime of its borrowed
    // Descriptor/Pin/cursor owners. A failed RLIMIT query is retained as
    // an explicit error on every attempted managed acquisition.
    struct rlimit limit = {};
    if (::getrlimit(RLIMIT_NOFILE, &limit) != 0)
        mManagedDescriptors.initializationError = errno ? errno : EIO;
    else
        mManagedDescriptors.initialCapacity = static_cast<std::size_t>(std::min(limit.rlim_cur, static_cast<rlim_t>(256)));
}

Result<bool> ContextInterface::ReserveManagedDescriptor() const
{
    if (mManagedDescriptors.initializationError != 0)
        return Error("Cannot inspect initial soft descriptor limit", mManagedDescriptors.initializationError);
    struct rlimit limit = {};
    if (::getrlimit(RLIMIT_NOFILE, &limit) != 0)
        return Error("Cannot inspect current soft descriptor limit", errno ? errno : EIO);
    const std::size_t effective = std::min({mManagedDescriptors.initialCapacity, ManagedDescriptorAllowance(),
        static_cast<std::size_t>(std::min(limit.rlim_cur, static_cast<rlim_t>(256)))});
    if (mManagedDescriptors.owned >= effective)
        return Error("Managed descriptor allowance exhausted", EMFILE);
    ++mManagedDescriptors.owned;
    return true;
}

void ContextInterface::ReleaseManagedDescriptor() const noexcept
{
    --mManagedDescriptors.owned; // only an owned descriptor/cursor relinquishes
}

// Provide a definition for the virtual destructor
ContextInterface::~ContextInterface() = default;

int ContextInterface::OpenNativePath(const char* path, int flags) const noexcept
{
    return ::open(path, flags);
}

int ContextInterface::OpenNativeAt(int directory, const char* path, int flags) const noexcept
{
    return ::openat(directory, path, flags);
}

int ContextInterface::StatNativeDescriptor(int descriptor, struct stat* metadata) const noexcept
{
    return ::fstat(descriptor, metadata);
}
int ContextInterface::StatFilesystemDescriptor(int descriptor, struct statfs* metadata) const noexcept
{
    return ::fstatfs(descriptor, metadata);
}
ssize_t ContextInterface::ReadLinkDescriptor(int descriptor, char* buffer, std::size_t size) const noexcept
{
    return ::readlinkat(descriptor, "", buffer, size);
}
int ContextInterface::StatusFlagsDescriptor(int descriptor) const noexcept
{
    return ::fcntl(descriptor, F_GETFL);
}
int ContextInterface::DescriptorFlagsDescriptor(int descriptor) const noexcept
{
    return ::fcntl(descriptor, F_GETFD);
}
int ContextInterface::DuplicateDescriptor(int descriptor) const noexcept
{
    return ::fcntl(descriptor, F_DUPFD_CLOEXEC, 0);
}
DIR* ContextInterface::FdOpenDirectory(int descriptor) const noexcept
{
    return ::fdopendir(descriptor);
}

ssize_t ContextInterface::ReadNativeDescriptor(int descriptor, void* buffer, std::size_t size) const noexcept
{
    return ::read(descriptor, buffer, size);
}

Result<void> ContextInterface::CloseNativeDescriptor(int descriptor) const noexcept
{
    if (::close(descriptor) != 0)
    {
        const int saved = errno ? errno : EIO;
        return Error(saved);
    }
    return Result<void>::Success();
}

int ContextInterface::ChownPinnedFileDescriptor(int descriptor, uid_t owner, gid_t group) const noexcept
{
    return ::fchownat(descriptor, "", owner, group, AT_EMPTY_PATH);
}

int ContextInterface::ChmodPinnedAlias(int procfsDirectory, const char* decimalAlias, mode_t mode) const noexcept
{
    return ::fchmodat(procfsDirectory, decimalAlias, mode, 0);
}

pid_t ContextInterface::NativeProcessId() const noexcept
{
    return ::getpid();
}

pid_t ContextInterface::NativeThreadId() const noexcept
{
    return static_cast<pid_t>(::syscall(SYS_gettid));
}

DIR* ContextInterface::OpenDirectory(const char* path) const noexcept
{
    return ::opendir(path);
}

struct dirent* ContextInterface::ReadDirectory(DIR* directory) const noexcept
{
    return ::readdir(directory);
}

Result<void> ContextInterface::CloseDirectory(DIR* directory) const noexcept
{
    if (::closedir(directory) != 0)
    {
        const int saved = errno ? errno : EIO;
        return Error(saved);
    }
    return Result<void>::Success();
}

int ContextInterface::StatPath(const char* path, struct stat* metadata) const noexcept
{
    return ::stat(path, metadata);
}

int ContextInterface::LstatPath(const char* path, struct stat* metadata) const noexcept
{
    return ::lstat(path, metadata);
}

struct group* ContextInterface::GetGroupById(gid_t id) const noexcept
{
    return ::getgrgid(id);
}
} // namespace ComplianceEngine
