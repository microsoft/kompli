// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "ContextInterface.h"

#include "filesystem/FilesystemHelpers.hpp"
#include "filesystem/Handle.hpp"
#include "filesystem/ProcfsDescriptorAccess.hpp"

#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <unistd.h>

namespace ComplianceEngine
{
// Provide a definition for the virtual destructor
ContextInterface::~ContextInterface() = default;

using Filesystem::Detail::Descriptor;

Result<pid_t> ContextInterface::CurrentProcessId() const
{
    const pid_t id = NativeProcessId();
    if (0 >= id)
        return Error("Cannot identify current process", (0 > id) ? (errno ? errno : EIO) : EPROTO);
    return id;
}

Result<pid_t> ContextInterface::CurrentThreadId() const
{
    const pid_t id = NativeThreadId();
    if (0 >= id)
        return Error("Cannot identify current task", (0 > id) ? (errno ? errno : EIO) : EPROTO);
    return id;
}

Descriptor ContextInterface::EmptyDescriptor(CloseDiagnostic diagnostic) const& noexcept
{
    return Descriptor(*this, -1, diagnostic);
}

Result<Descriptor> ContextInterface::OpenAbsolutePin(const char* path, bool directory) const&
{
    if (!path || *path != '/')
    {
        return Error("Unsupported absolute pin path", EINVAL);
    }
    const int fd = OpenNativePath(path, O_PATH | O_NOFOLLOW | O_CLOEXEC | (directory ? O_DIRECTORY : 0));
    if (fd < 0)
    {
        return Error("Cannot open absolute pin", errno ? errno : EIO);
    }
    return Descriptor(*this, fd, CloseDiagnostic::Descriptor);
}

Result<Descriptor> ContextInterface::OpenAt(const Descriptor& directory, const char* name, OpenProfile profile, CloseDiagnostic diagnostic) const&
{
    switch (profile)
    {
        case OpenProfile::ReadFdinfo:
        case OpenProfile::FollowAliasFile:
        case OpenProfile::FollowAliasDirectory:
        case OpenProfile::FollowAliasPin:
        case OpenProfile::FollowAliasPinDirectory:
            return Error("Procfs alias profiles require verified directories", EINVAL);
        default:
            return OpenVerifiedAt(directory, name, profile, diagnostic);
    }
}

Result<Descriptor> ContextInterface::OpenVerifiedAt(const Descriptor& directory, const char* name, OpenProfile profile, CloseDiagnostic diagnostic) const&
{
    if (!directory.mDescriptor.HasValue())
    {
        return Error("Directory descriptor is empty", EBADF);
    }
    if (directory.mContext != this || !name || !*name || *name == '/')
    {
        return Error("Invalid directory context or relative name", EINVAL);
    }
    int flags = O_CLOEXEC;
    switch (profile)
    {
        case OpenProfile::PinDirectory:
            flags |= O_PATH | O_DIRECTORY | O_NOFOLLOW;
            break;
        case OpenProfile::PinSelfDirectory:
            flags |= O_PATH | O_DIRECTORY;
            break;
        case OpenProfile::PinChild:
            if (!Filesystem::Detail::IsSingleChildComponent(name))
                return Error("Child pin requires a single component", EINVAL);
            flags |= O_PATH | O_NOFOLLOW;
            break;
        case OpenProfile::PinChildDirectory:
            if (!Filesystem::Detail::IsSingleChildComponent(name))
                return Error("Child pin requires a single component", EINVAL);
            flags |= O_PATH | O_NOFOLLOW | O_DIRECTORY;
            break;
        case OpenProfile::ReadFdinfo:
            flags |= O_RDONLY | O_NOFOLLOW;
            break;
        case OpenProfile::FollowAliasFile:
            flags |= O_RDONLY;
            break;
        case OpenProfile::FollowAliasDirectory:
            flags |= O_RDONLY | O_DIRECTORY;
            break;
        case OpenProfile::FollowAliasPin:
            flags |= O_PATH;
            break;
        case OpenProfile::FollowAliasPinDirectory:
            flags |= O_PATH | O_DIRECTORY;
            break;
        default:
            return Error("Unsupported descriptor open profile", EINVAL);
    }
    const int fd = OpenNativeAt(directory.mDescriptor.Value(), name, flags);
    if (fd < 0)
    {
        return Error("Cannot open relative descriptor", errno ? errno : EIO);
    }
    return Descriptor(*this, fd, diagnostic);
}

Result<Descriptor> ContextInterface::OpenFdinfo(const Filesystem::Detail::ProcfsDescriptorAccess& procfs, const Descriptor& target) const&
{
    if (!procfs.VerifyRole(*this, true))
        return Error("Unverified procfs fdinfo directory", EINVAL);
    if (!target.mDescriptor.HasValue())
    {
        return Error("Descriptor information target is empty", EBADF);
    }
    if (target.mContext != this)
    {
        return Error("Foreign descriptor information target", EINVAL);
    }
    const std::string alias = std::to_string(target.mDescriptor.Value());
    return OpenVerifiedAt(procfs.fdinfo, alias.c_str(), OpenProfile::ReadFdinfo, CloseDiagnostic::Descriptor);
}

Result<Descriptor> ContextInterface::OpenAlias(const Filesystem::Detail::ProcfsDescriptorAccess& procfs, const Descriptor& target, bool directoryAlias,
    CloseDiagnostic diagnostic) const&
{
    if (!procfs.VerifyRole(*this, false))
        return Error("Unverified procfs fd directory", EINVAL);
    if (!target.mDescriptor.HasValue())
    {
        return Error("Alias target is empty", EBADF);
    }
    if (target.mContext != this)
    {
        return Error("Foreign alias target", EINVAL);
    }
    const std::string alias = std::to_string(target.mDescriptor.Value());
    return OpenVerifiedAt(procfs.fd, alias.c_str(), directoryAlias ? OpenProfile::FollowAliasDirectory : OpenProfile::FollowAliasFile, diagnostic);
}

Result<Descriptor> ContextInterface::OpenPinAlias(const Filesystem::Detail::ProcfsDescriptorAccess& procfs, const Descriptor& target, bool directoryAlias) const&
{
    if (!procfs.VerifyRole(*this, false))
        return Error("Unverified procfs fd directory", EINVAL);
    if (!target.mDescriptor.HasValue())
    {
        return Error("Alias target is empty", EBADF);
    }
    if (target.mContext != this)
    {
        return Error("Foreign alias target", EINVAL);
    }
    const std::string alias = std::to_string(target.mDescriptor.Value());
    return OpenVerifiedAt(procfs.fd, alias.c_str(), directoryAlias ? OpenProfile::FollowAliasPinDirectory : OpenProfile::FollowAliasPin, CloseDiagnostic::Descriptor);
}

Result<Descriptor> ContextInterface::Duplicate(const Descriptor& source) const&
{
    if (!source.mDescriptor.HasValue())
    {
        return Error("Cannot duplicate an empty descriptor", EBADF);
    }
    if (source.mContext != this)
    {
        return Error("Cannot duplicate a foreign descriptor", EINVAL);
    }
    const int fd = DuplicateDescriptor(source.mDescriptor.Value());
    if (fd < 0)
    {
        return Error("Cannot duplicate descriptor", errno ? errno : EIO);
    }
    return Descriptor(*this, fd, CloseDiagnostic::Descriptor);
}

#define CHECK_OWNER(owner, failure)                                                                                                                    \
    if (!(owner).mDescriptor.HasValue())                                                                                                               \
    {                                                                                                                                                  \
        errno = EBADF;                                                                                                                                 \
        return failure;                                                                                                                                \
    }                                                                                                                                                  \
    if ((owner).mContext != this)                                                                                                                      \
    {                                                                                                                                                  \
        errno = EINVAL;                                                                                                                                \
        return failure;                                                                                                                                \
    }

int ContextInterface::StatFile(const Descriptor& owner, struct stat* metadata) const
{
    CHECK_OWNER(owner, -1)
    return StatFileDescriptor(owner.mDescriptor.Value(), metadata);
}
int ContextInterface::StatFilesystem(const Descriptor& owner, struct statfs* metadata) const
{
    CHECK_OWNER(owner, -1)
    return StatFilesystemDescriptor(owner.mDescriptor.Value(), metadata);
}
ssize_t ContextInterface::ReadFile(const Descriptor& owner, void* buffer, std::size_t size) const
{
    CHECK_OWNER(owner, -1)
    return ReadFileDescriptor(owner.mDescriptor.Value(), buffer, size);
}
ssize_t ContextInterface::ReadLink(const Descriptor& owner, char* buffer, std::size_t size) const
{
    CHECK_OWNER(owner, -1)
    return ReadLinkDescriptor(owner.mDescriptor.Value(), buffer, size);
}
int ContextInterface::StatusFlags(const Descriptor& owner) const
{
    CHECK_OWNER(owner, -1)
    return StatusFlagsDescriptor(owner.mDescriptor.Value());
}
int ContextInterface::DescriptorFlags(const Descriptor& owner) const
{
    CHECK_OWNER(owner, -1)
    return DescriptorFlagsDescriptor(owner.mDescriptor.Value());
}
int ContextInterface::ChownPinned(const Descriptor& owner, uid_t user, gid_t group) const
{
    CHECK_OWNER(owner, -1)
    return ChownPinnedFileDescriptor(owner.mDescriptor.Value(), user, group);
}
int ContextInterface::ChmodAlias(const Filesystem::Detail::ProcfsDescriptorAccess& procfs, const Descriptor& pin, mode_t mode) const
{
    if (!procfs.VerifyRole(*this, false))
    {
        errno = EINVAL;
        return -1;
    }
    CHECK_OWNER(pin, -1)
    const std::string alias = std::to_string(pin.mDescriptor.Value());
    return ChmodPinnedAlias(procfs.fd.mDescriptor.Value(), alias.c_str(), mode);
}
int ContextInterface::CloseOwnedDescriptor(Descriptor& owner) const
{
    CHECK_OWNER(owner, -1)
    const int fd = owner.mDescriptor.Value();
    owner.mDescriptor.Reset();
    return CloseFileDescriptor(fd);
}
Result<Filesystem::DirectoryCursor> ContextInterface::OpenDirectoryCursor(Descriptor&& owner) const&
{
    if (!owner.mDescriptor.HasValue())
    {
        return Error("Directory stream descriptor is empty", EBADF);
    }
    if (owner.mContext != this)
    {
        return Error("Foreign directory stream descriptor", EINVAL);
    }
    DIR* stream = FdOpenDirectory(owner.mDescriptor.Value());
    if (!stream)
    {
        return Error("Cannot open directory stream", errno ? errno : EIO);
    }
    owner.mDescriptor.Reset();
    return Filesystem::DirectoryCursor(*this, stream);
}
#undef CHECK_OWNER

int ContextInterface::OpenNativePath(const char* path, int flags) const
{
    return ::open(path, flags);
}

int ContextInterface::OpenNativeAt(int directory, const char* path, int flags) const
{
    return ::openat(directory, path, flags);
}

int ContextInterface::StatFileDescriptor(int descriptor, struct stat* metadata) const
{
    return ::fstat(descriptor, metadata);
}
int ContextInterface::StatFilesystemDescriptor(int descriptor, struct statfs* metadata) const
{
    return ::fstatfs(descriptor, metadata);
}
ssize_t ContextInterface::ReadLinkDescriptor(int descriptor, char* buffer, std::size_t size) const
{
    return ::readlinkat(descriptor, "", buffer, size);
}
int ContextInterface::StatusFlagsDescriptor(int descriptor) const
{
    return ::fcntl(descriptor, F_GETFL);
}
int ContextInterface::DescriptorFlagsDescriptor(int descriptor) const
{
    return ::fcntl(descriptor, F_GETFD);
}
int ContextInterface::DuplicateDescriptor(int descriptor) const
{
    return ::fcntl(descriptor, F_DUPFD_CLOEXEC, 0);
}
DIR* ContextInterface::FdOpenDirectory(int descriptor) const
{
    return ::fdopendir(descriptor);
}

ssize_t ContextInterface::ReadFileDescriptor(int descriptor, void* buffer, std::size_t size) const
{
    return ::read(descriptor, buffer, size);
}

int ContextInterface::CloseFileDescriptor(int descriptor) const
{
    return ::close(descriptor);
}

int ContextInterface::ChownPinnedFileDescriptor(int descriptor, uid_t owner, gid_t group) const
{
    return ::fchownat(descriptor, "", owner, group, AT_EMPTY_PATH);
}

int ContextInterface::ChmodPinnedAlias(int procfsDirectory, const char* decimalAlias, mode_t mode) const
{
    return ::fchmodat(procfsDirectory, decimalAlias, mode, 0);
}

pid_t ContextInterface::NativeProcessId() const
{
    return ::getpid();
}

pid_t ContextInterface::NativeThreadId() const
{
    return static_cast<pid_t>(::syscall(SYS_gettid));
}

DIR* ContextInterface::OpenDirectory(const char* path) const
{
    return ::opendir(path);
}

struct dirent* ContextInterface::ReadDirectory(DIR* directory) const
{
    return ::readdir(directory);
}

int ContextInterface::CloseDirectory(DIR* directory) const
{
    return ::closedir(directory);
}

int ContextInterface::StatPath(const char* path, struct stat* metadata) const
{
    return ::stat(path, metadata);
}

int ContextInterface::LstatPath(const char* path, struct stat* metadata) const
{
    return ::lstat(path, metadata);
}

struct group* ContextInterface::GetGroupById(gid_t id) const
{
    return ::getgrgid(id);
}
} // namespace ComplianceEngine
