// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "AtomicFile.h"

#include <cerrno>
#include <climits>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace ComplianceEngine
{
namespace
{
Error FileError(const std::string& operation, const std::string& path, int status)
{
    return Error(operation + " '" + path + "': " + strerror(status), status);
}
} // namespace

Result<bool> ReplaceFileContentsAtomic(const std::string& path, const std::string& contents)
{
    struct stat original;
    if (lstat(path.c_str(), &original) != 0)
    {
        const int status = errno;
        return FileError("Failed to inspect", path, status);
    }
    if (!S_ISREG(original.st_mode))
    {
        return Error("Refusing to replace non-regular file '" + path + "'", EINVAL);
    }
    if (original.st_nlink != 1)
    {
        return Error("Refusing to replace multiply-linked file '" + path + "'", EMLINK);
    }

    const int source = open(path.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (source < 0)
    {
        const int status = errno;
        return FileError("Failed to open", path, status);
    }

    struct stat opened;
    if (fstat(source, &opened) != 0)
    {
        const int status = errno;
        close(source);
        return FileError("Failed to inspect opened file", path, status);
    }
    close(source);
    if (opened.st_dev != original.st_dev || opened.st_ino != original.st_ino)
    {
        return Error("File changed while opening '" + path + "'", EAGAIN);
    }

    if (path.size() + sizeof(".kompli.XXXXXX") > PATH_MAX)
    {
        return Error("Temporary path is too long for '" + path + "'", ENAMETOOLONG);
    }
    char temporaryPath[PATH_MAX];
    snprintf(temporaryPath, sizeof(temporaryPath), "%s.kompli.XXXXXX", path.c_str());
    const int temporary = mkstemp(temporaryPath);
    if (temporary < 0)
    {
        const int status = errno;
        return FileError("Failed to create temporary file for", path, status);
    }

    auto fail = [&](const std::string& operation, int status) -> Result<bool> {
        close(temporary);
        unlink(temporaryPath);
        return FileError(operation, path, status);
    };

    if (fchown(temporary, original.st_uid, original.st_gid) != 0)
    {
        return fail("Failed to preserve ownership for", errno);
    }
    if (fchmod(temporary, original.st_mode & 07777) != 0)
    {
        return fail("Failed to preserve permissions for", errno);
    }

    size_t written = 0;
    while (written < contents.size())
    {
        const ssize_t result = write(temporary, contents.data() + written, contents.size() - written);
        if (result < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            return fail("Failed to write replacement for", errno);
        }
        if (result == 0)
        {
            return fail("Failed to write replacement for", EIO);
        }
        written += static_cast<size_t>(result);
    }
    if (fsync(temporary) != 0)
    {
        return fail("Failed to flush replacement for", errno);
    }
    if (close(temporary) != 0)
    {
        const int status = errno;
        unlink(temporaryPath);
        return FileError("Failed to close replacement for", path, status);
    }

    struct stat current;
    if (lstat(path.c_str(), &current) != 0)
    {
        const int status = errno;
        unlink(temporaryPath);
        return FileError("Failed to re-inspect", path, status);
    }
    if (current.st_dev != original.st_dev || current.st_ino != original.st_ino)
    {
        unlink(temporaryPath);
        return Error("File changed before replacement '" + path + "'", EAGAIN);
    }
    if (rename(temporaryPath, path.c_str()) != 0)
    {
        const int status = errno;
        unlink(temporaryPath);
        return FileError("Failed to replace", path, status);
    }
    return true;
}
} // namespace ComplianceEngine
