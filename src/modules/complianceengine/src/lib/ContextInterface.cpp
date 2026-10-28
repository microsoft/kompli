// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "ContextInterface.h"

#include <cerrno>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace ComplianceEngine
{
// Provide a definition for the virtual destructor
ContextInterface::~ContextInterface() = default;

int ContextInterface::OpenExistingFile(const char* path, int flags) const
{
    if (0 != (flags & ~(O_PATH | O_CLOEXEC | O_NOFOLLOW)))
    {
        errno = EINVAL;
        return -1;
    }
    return ::open(path, flags);
}

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
