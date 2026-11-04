// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "AtomicFile.h"

#include <atomic>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <string>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <unistd.h>
#include <vector>

namespace ComplianceEngine
{
namespace
{
Error FileError(const std::string& operation, const std::string& path, int status)
{
    return Error(operation + " '" + path + "': " + strerror(status), status);
}

Result<bool> WriteContents(int fd, const std::string& path, const std::string& contents)
{
    size_t written = 0;
    while (written < contents.size())
    {
        const ssize_t result = write(fd, contents.data() + written, contents.size() - written);
        if (result < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            return FileError("Failed to write replacement for", path, errno);
        }
        if (result == 0)
        {
            return FileError("Failed to write replacement for", path, EIO);
        }
        written += static_cast<size_t>(result);
    }
    return true;
}

struct ResolvedPath
{
    int parent;
    std::string name;
};

Result<ResolvedPath> ResolveParentNoFollow(const std::string& path)
{
    if (path.empty() || path.front() != '/')
    {
        return Error("Atomic file operations require an absolute path", EINVAL);
    }

    const size_t lastSlash = path.find_last_of('/');
    const std::string name = path.substr(lastSlash + 1);
    if (name.empty() || name == "." || name == "..")
    {
        return Error("Invalid atomic file path '" + path + "'", EINVAL);
    }

    int parent = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (parent < 0)
    {
        return FileError("Failed to open parent directory for", path, errno);
    }

    size_t position = 1;
    while (position < lastSlash)
    {
        while (position < lastSlash && path[position] == '/')
        {
            position++;
        }
        if (position >= lastSlash)
        {
            break;
        }

        const size_t separator = path.find('/', position);
        const size_t end = separator == std::string::npos || separator > lastSlash ? lastSlash : separator;
        const std::string component = path.substr(position, end - position);
        if (component == "..")
        {
            close(parent);
            return Error("Refusing parent directory traversal in '" + path + "'", EINVAL);
        }
        if (component != ".")
        {
            const int next = openat(parent, component.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
            if (next < 0)
            {
                const int status = errno;
                close(parent);
                return FileError("Failed to resolve parent directory for", path, status);
            }
            close(parent);
            parent = next;
        }
        position = end + 1;
    }

    return ResolvedPath{parent, name};
}

struct TemporaryFile
{
    int descriptor;
    std::string name;
};

Result<TemporaryFile> CreateTemporaryFile(int parent, const std::string& path)
{
    static std::atomic<unsigned long> sequence(0);
    for (size_t attempt = 0; attempt < 100; attempt++)
    {
        const std::string name = ".kompli." + std::to_string(getpid()) + "." + std::to_string(sequence.fetch_add(1));
        const int descriptor = openat(parent, name.c_str(), O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, S_IRUSR | S_IWUSR);
        if (descriptor >= 0)
        {
            return TemporaryFile{descriptor, name};
        }
        if (errno != EEXIST)
        {
            return FileError("Failed to create temporary file for", path, errno);
        }
    }
    return Error("Failed to create a unique temporary file for '" + path + "'", EEXIST);
}

Result<bool> CopyExtendedAttributes(int source, int target, const std::string& path)
{
    ssize_t listSize;
    do
    {
        listSize = flistxattr(source, nullptr, 0);
    } while (listSize < 0 && errno == EINTR);
    if (listSize < 0)
    {
        if (errno == ENOTSUP)
        {
            return true;
        }
        return FileError("Failed to list extended attributes for", path, errno);
    }
    if (listSize == 0)
    {
        return true;
    }

    std::vector<char> names(static_cast<size_t>(listSize));
    ssize_t actualSize;
    do
    {
        actualSize = flistxattr(source, names.data(), names.size());
    } while (actualSize < 0 && errno == EINTR);
    if (actualSize < 0)
    {
        return FileError("Failed to read extended attribute names for", path, errno);
    }

    size_t position = 0;
    while (position < static_cast<size_t>(actualSize))
    {
        const size_t remaining = static_cast<size_t>(actualSize) - position;
        const size_t length = strnlen(names.data() + position, remaining);
        if (length == remaining)
        {
            return Error("Invalid extended attribute list for '" + path + "'", EIO);
        }
        const char* name = names.data() + position;

        ssize_t valueSize;
        do
        {
            valueSize = fgetxattr(source, name, nullptr, 0);
        } while (valueSize < 0 && errno == EINTR);
        if (valueSize < 0)
        {
            return FileError("Failed to inspect extended attribute '" + std::string(name) + "' for", path, errno);
        }

        std::vector<char> value(static_cast<size_t>(valueSize));
        if (valueSize > 0)
        {
            ssize_t readSize;
            do
            {
                readSize = fgetxattr(source, name, value.data(), value.size());
            } while (readSize < 0 && errno == EINTR);
            if (readSize < 0)
            {
                return FileError("Failed to read extended attribute '" + std::string(name) + "' for", path, errno);
            }
            if (readSize != valueSize)
            {
                return Error("Extended attribute '" + std::string(name) + "' changed while replacing '" + path + "'", EAGAIN);
            }
        }

        if (fsetxattr(target, name, valueSize == 0 ? nullptr : value.data(), static_cast<size_t>(valueSize), 0) != 0)
        {
            return FileError("Failed to preserve extended attribute '" + std::string(name) + "' for", path, errno);
        }
        position += length + 1;
    }
    return true;
}
} // namespace

Result<bool> CreateFileContentsAtomic(const std::string& path, const std::string& contents, mode_t mode, struct stat* created)
{
    auto resolved = ResolveParentNoFollow(path);
    if (!resolved.HasValue())
    {
        return resolved.Error();
    }
    const int parent = resolved.Value().parent;
    const std::string& name = resolved.Value().name;

    struct stat existing;
    if (fstatat(parent, name.c_str(), &existing, AT_SYMLINK_NOFOLLOW) == 0)
    {
        close(parent);
        return Error("Refusing to replace existing file '" + path + "'", EEXIST);
    }
    if (errno != ENOENT)
    {
        const int status = errno;
        close(parent);
        return FileError("Failed to inspect", path, status);
    }

    auto temporaryResult = CreateTemporaryFile(parent, path);
    if (!temporaryResult.HasValue())
    {
        close(parent);
        return temporaryResult.Error();
    }
    const int temporary = temporaryResult.Value().descriptor;
    const std::string& temporaryName = temporaryResult.Value().name;

    auto fail = [&](const std::string& operation, int status) -> Result<bool> {
        close(temporary);
        unlinkat(parent, temporaryName.c_str(), 0);
        close(parent);
        return FileError(operation, path, status);
    };

    if (fchmod(temporary, mode & 07777) != 0)
    {
        return fail("Failed to set permissions for", errno);
    }
    auto writeResult = WriteContents(temporary, path, contents);
    if (!writeResult.HasValue())
    {
        return fail("Failed to write replacement for", writeResult.Error().code);
    }
    if (fsync(temporary) != 0)
    {
        return fail("Failed to flush replacement for", errno);
    }
    if (close(temporary) != 0)
    {
        const int status = errno;
        unlinkat(parent, temporaryName.c_str(), 0);
        close(parent);
        return FileError("Failed to close replacement for", path, status);
    }

    struct stat createdMetadata;
    if (fstatat(parent, temporaryName.c_str(), &createdMetadata, AT_SYMLINK_NOFOLLOW) != 0)
    {
        const int status = errno;
        unlinkat(parent, temporaryName.c_str(), 0);
        close(parent);
        return FileError("Failed to inspect temporary file for", path, status);
    }

    if (fstatat(parent, name.c_str(), &existing, AT_SYMLINK_NOFOLLOW) == 0)
    {
        unlinkat(parent, temporaryName.c_str(), 0);
        close(parent);
        return Error("File appeared before creation '" + path + "'", EEXIST);
    }
    if (errno != ENOENT)
    {
        const int status = errno;
        unlinkat(parent, temporaryName.c_str(), 0);
        close(parent);
        return FileError("Failed to re-inspect", path, status);
    }
    if (linkat(parent, temporaryName.c_str(), parent, name.c_str(), 0) != 0)
    {
        const int status = errno;
        unlinkat(parent, temporaryName.c_str(), 0);
        close(parent);
        return FileError("Failed to create", path, status);
    }
    unlinkat(parent, temporaryName.c_str(), 0);
    close(parent);
    if (created != nullptr)
    {
        *created = createdMetadata;
    }
    return true;
}

Result<bool> ReplaceFileContentsAtomic(const std::string& path, const std::string& contents)
{
    auto resolved = ResolveParentNoFollow(path);
    if (!resolved.HasValue())
    {
        return resolved.Error();
    }
    const int parent = resolved.Value().parent;
    const std::string& name = resolved.Value().name;

    struct stat original;
    if (fstatat(parent, name.c_str(), &original, AT_SYMLINK_NOFOLLOW) != 0)
    {
        const int status = errno;
        close(parent);
        return FileError("Failed to inspect", path, status);
    }
    if (!S_ISREG(original.st_mode))
    {
        close(parent);
        return Error("Refusing to replace non-regular file '" + path + "'", EINVAL);
    }
    if (original.st_nlink != 1)
    {
        close(parent);
        return Error("Refusing to replace multiply-linked file '" + path + "'", EMLINK);
    }

    const int source = openat(parent, name.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (source < 0)
    {
        const int status = errno;
        close(parent);
        return FileError("Failed to open", path, status);
    }

    struct stat opened;
    if (fstat(source, &opened) != 0)
    {
        const int status = errno;
        close(source);
        close(parent);
        return FileError("Failed to inspect opened file", path, status);
    }
    if (opened.st_dev != original.st_dev || opened.st_ino != original.st_ino)
    {
        close(source);
        close(parent);
        return Error("File changed while opening '" + path + "'", EAGAIN);
    }

    auto temporaryResult = CreateTemporaryFile(parent, path);
    if (!temporaryResult.HasValue())
    {
        close(source);
        close(parent);
        return temporaryResult.Error();
    }
    const int temporary = temporaryResult.Value().descriptor;
    const std::string& temporaryName = temporaryResult.Value().name;

    auto fail = [&](const std::string& operation, int status) -> Result<bool> {
        close(temporary);
        close(source);
        unlinkat(parent, temporaryName.c_str(), 0);
        close(parent);
        return FileError(operation, path, status);
    };

    auto writeResult = WriteContents(temporary, path, contents);
    if (!writeResult.HasValue())
    {
        return fail("Failed to write replacement for", writeResult.Error().code);
    }
    if (fchown(temporary, original.st_uid, original.st_gid) != 0)
    {
        return fail("Failed to preserve ownership for", errno);
    }
    if (fchmod(temporary, original.st_mode & 07777) != 0)
    {
        return fail("Failed to preserve permissions for", errno);
    }

    auto attributes = CopyExtendedAttributes(source, temporary, path);
    if (!attributes.HasValue())
    {
        const auto error = attributes.Error();
        close(temporary);
        close(source);
        unlinkat(parent, temporaryName.c_str(), 0);
        close(parent);
        return error;
    }
    if (fsync(temporary) != 0)
    {
        return fail("Failed to flush replacement for", errno);
    }
    if (close(source) != 0)
    {
        const int status = errno;
        close(temporary);
        unlinkat(parent, temporaryName.c_str(), 0);
        close(parent);
        return FileError("Failed to close source for", path, status);
    }
    if (close(temporary) != 0)
    {
        const int status = errno;
        unlinkat(parent, temporaryName.c_str(), 0);
        close(parent);
        return FileError("Failed to close replacement for", path, status);
    }

    struct stat current;
    if (fstatat(parent, name.c_str(), &current, AT_SYMLINK_NOFOLLOW) != 0)
    {
        const int status = errno;
        unlinkat(parent, temporaryName.c_str(), 0);
        close(parent);
        return FileError("Failed to re-inspect", path, status);
    }
    if (current.st_dev != original.st_dev || current.st_ino != original.st_ino)
    {
        unlinkat(parent, temporaryName.c_str(), 0);
        close(parent);
        return Error("File changed before replacement '" + path + "'", EAGAIN);
    }
    if (renameat(parent, temporaryName.c_str(), parent, name.c_str()) != 0)
    {
        const int status = errno;
        unlinkat(parent, temporaryName.c_str(), 0);
        close(parent);
        return FileError("Failed to replace", path, status);
    }
    close(parent);
    return true;
}
} // namespace ComplianceEngine
