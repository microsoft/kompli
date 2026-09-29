// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef COMPLIANCEENGINE_TEMPORARYDIRECTORY_H
#define COMPLIANCEENGINE_TEMPORARYDIRECTORY_H

#include "Result.h"

#include <cctype>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <string>
#include <sys/random.h>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>

namespace ComplianceEngine
{
namespace Detail
{

inline bool TemporaryParentContainsWhitespace(const std::string& parent)
{
    for (unsigned char character : parent)
    {
        if (std::isspace(character) != 0)
        {
            return true;
        }
    }
    return false;
}

inline Result<std::string> GetTemporaryDirectoryParent()
{
    const auto* tmpdir = std::getenv("TMPDIR");
    if ((tmpdir != nullptr) && (tmpdir[0] != '\0'))
    {
        if (tmpdir[0] != '/')
        {
            return Error("TMPDIR must be an absolute path", EINVAL);
        }
        if (TemporaryParentContainsWhitespace(tmpdir))
        {
            return Error("TMPDIR must not contain whitespace", EINVAL);
        }
        return std::string(tmpdir);
    }
    return std::string("/tmp");
}

inline Result<bool> ValidateTemporaryDirectoryComponent(int directory, const std::string& path)
{
    struct stat status;
    if (::fstat(directory, &status) != 0)
    {
        const int error = errno;
        return Error("Failed to inspect temporary directory parent " + path + ": " + std::strerror(error), error);
    }

    const uid_t effectiveUser = ::geteuid();
    if ((status.st_uid != 0) && (status.st_uid != effectiveUser))
    {
        return Error("Temporary directory parent has an untrusted owner: " + path, EPERM);
    }

    const bool writableByOthers = (status.st_mode & (S_IWGRP | S_IWOTH)) != 0;
    if (writableByOthers && ((status.st_mode & S_ISVTX) == 0))
    {
        return Error("Temporary directory parent is writable by other users without the sticky bit: " + path, EPERM);
    }
    return true;
}

struct OpenedTemporaryParent
{
    std::string path;
    int fd;

    OpenedTemporaryParent(std::string path, int fd)
        : path(std::move(path)),
          fd(fd)
    {
    }
    OpenedTemporaryParent(const OpenedTemporaryParent&) = delete;
    OpenedTemporaryParent& operator=(const OpenedTemporaryParent&) = delete;
    OpenedTemporaryParent(OpenedTemporaryParent&& other) noexcept
        : path(std::move(other.path)),
          fd(other.fd)
    {
        other.fd = -1;
    }
    OpenedTemporaryParent& operator=(OpenedTemporaryParent&& other) noexcept
    {
        if (this != &other)
        {
            if (fd >= 0)
            {
                ::close(fd);
            }
            path = std::move(other.path);
            fd = other.fd;
            other.fd = -1;
        }
        return *this;
    }
    ~OpenedTemporaryParent()
    {
        if (fd >= 0)
        {
            ::close(fd);
        }
    }
};

inline Result<OpenedTemporaryParent> ValidateTemporaryDirectoryParent(const std::string& parent)
{
    if (parent.empty() || (parent[0] != '/'))
    {
        return Error("TMPDIR must be an absolute path", EINVAL);
    }
    if (TemporaryParentContainsWhitespace(parent))
    {
        return Error("TMPDIR must not contain whitespace", EINVAL);
    }

    OpenedTemporaryParent opened("/", ::open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
    if (opened.fd < 0)
    {
        const int error = errno;
        return Error("Failed to open filesystem root: " + std::string(std::strerror(error)), error);
    }

    auto validation = ValidateTemporaryDirectoryComponent(opened.fd, opened.path);
    if (!validation.HasValue())
    {
        return std::move(validation).Error();
    }

    std::size_t offset = 1;
    while (offset < parent.size())
    {
        const std::size_t separator = parent.find('/', offset);
        const std::string component = parent.substr(offset, separator - offset);
        offset = (separator == std::string::npos) ? parent.size() : separator + 1;
        if (component.empty())
        {
            continue;
        }
        if ((component == ".") || (component == ".."))
        {
            return Error("TMPDIR must not contain '.' or '..' path components", EINVAL);
        }

        const std::string nextPath = opened.path == "/" ? "/" + component : opened.path + "/" + component;
        const int child = ::openat(opened.fd, component.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (child < 0)
        {
            const int error = errno;
            return Error("Failed to securely open temporary directory parent component " + component + ": " + std::strerror(error), error);
        }
        opened = OpenedTemporaryParent(nextPath, child);
        validation = ValidateTemporaryDirectoryComponent(opened.fd, opened.path);
        if (!validation.HasValue())
        {
            return std::move(validation).Error();
        }
    }
    return opened;
}

inline bool RemoveTemporaryDirectoryContents(int directory)
{
    const int scanDescriptor = ::openat(directory, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (scanDescriptor < 0)
    {
        return false;
    }

    DIR* entries = ::fdopendir(scanDescriptor);
    if (entries == nullptr)
    {
        ::close(scanDescriptor);
        return false;
    }

    bool success = true;
    errno = 0;
    struct dirent* entry = nullptr;
    while ((entry = ::readdir(entries)) != nullptr)
    {
        if ((std::strcmp(entry->d_name, ".") == 0) || (std::strcmp(entry->d_name, "..") == 0))
        {
            continue;
        }

        struct stat status;
        if (::fstatat(directory, entry->d_name, &status, AT_SYMLINK_NOFOLLOW) != 0)
        {
            success = success && (errno == ENOENT);
            errno = 0;
            continue;
        }

        if (S_ISDIR(status.st_mode))
        {
            const int child = ::openat(directory, entry->d_name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
            if (child < 0)
            {
                success = false;
                errno = 0;
                continue;
            }
            success = RemoveTemporaryDirectoryContents(child) && success;
            ::close(child);
            if ((::unlinkat(directory, entry->d_name, AT_REMOVEDIR) != 0) && (errno != ENOENT))
            {
                success = false;
            }
        }
        else if ((::unlinkat(directory, entry->d_name, 0) != 0) && (errno != ENOENT))
        {
            success = false;
        }
        errno = 0;
    }
    success = success && (errno == 0);
    ::closedir(entries);
    return success;
}

class TemporaryDirectory
{
public:
    TemporaryDirectory(OpenedTemporaryParent parent, std::string name, int root)
        : mPath(parent.path == "/" ? "/" + name : parent.path + "/" + name),
          mName(std::move(name)),
          mParent(std::move(parent)),
          mRoot(root)
    {
    }
    TemporaryDirectory(const TemporaryDirectory&) = delete;
    TemporaryDirectory& operator=(const TemporaryDirectory&) = delete;
    TemporaryDirectory(TemporaryDirectory&& other) noexcept
        : mPath(std::move(other.mPath)),
          mName(std::move(other.mName)),
          mParent(std::move(other.mParent)),
          mRoot(other.mRoot)
    {
        other.mRoot = -1;
    }
    ~TemporaryDirectory()
    {
        if (mRoot >= 0 && !Remove())
        {
            std::fprintf(stderr, "Failed to remove temporary directory: %s\n", mPath.c_str());
        }
    }

    const std::string& Path() const
    {
        return mPath;
    }

    bool Remove()
    {
        if (mRoot < 0)
        {
            return true;
        }

        bool success = false;
        for (int attempt = 0; attempt < 2; ++attempt)
        {
            struct stat rootStatus;
            struct stat entryStatus;
            if ((::fstat(mRoot, &rootStatus) != 0) || (::fstatat(mParent.fd, mName.c_str(), &entryStatus, AT_SYMLINK_NOFOLLOW) != 0) ||
                (rootStatus.st_dev != entryStatus.st_dev) || (rootStatus.st_ino != entryStatus.st_ino))
            {
                break;
            }
            const bool contentsRemoved = RemoveTemporaryDirectoryContents(mRoot);
            if (::unlinkat(mParent.fd, mName.c_str(), AT_REMOVEDIR) == 0)
            {
                success = contentsRemoved;
                break;
            }
            if (errno != ENOTEMPTY)
            {
                break;
            }
        }
        ::close(mRoot);
        mRoot = -1;
        return success;
    }

private:
    std::string mPath;
    std::string mName;
    OpenedTemporaryParent mParent;
    int mRoot;
};

inline Result<TemporaryDirectory> CreateTemporaryDirectoryInParent(OpenedTemporaryParent openedParent, const std::string& prefix)
{
    if (prefix.empty() || (prefix == ".") || (prefix == "..") || (prefix.find('/') != std::string::npos))
    {
        return Error("Temporary directory prefix must be a single path component", EINVAL);
    }

    for (int attempt = 0; attempt < 32; ++attempt)
    {
        unsigned char randomBytes[16];
        std::size_t filled = 0;
        while (filled < sizeof(randomBytes))
        {
            const ssize_t bytesRead = ::getrandom(randomBytes + filled, sizeof(randomBytes) - filled, 0);
            if (bytesRead < 0 && errno == EINTR)
            {
                continue;
            }
            if (bytesRead <= 0)
            {
                const int error = (bytesRead < 0) ? errno : EIO;
                return Error("Failed to generate temporary directory name: " + std::string(std::strerror(error)), error);
            }
            filled += static_cast<std::size_t>(bytesRead);
        }

        const char hex[] = "0123456789abcdef";
        std::string name = prefix + ".";
        for (unsigned char byte : randomBytes)
        {
            name += hex[byte >> 4];
            name += hex[byte & 0x0f];
        }
        if (::mkdirat(openedParent.fd, name.c_str(), 0700) != 0)
        {
            if (errno == EEXIST)
            {
                continue;
            }
            const int error = errno;
            return Error("Failed to create temporary directory beneath " + openedParent.path + ": " + std::strerror(error), error);
        }

        const int root = ::openat(openedParent.fd, name.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (root < 0)
        {
            const int error = errno;
            (void)::unlinkat(openedParent.fd, name.c_str(), AT_REMOVEDIR);
            return Error("Failed to open new temporary directory: " + std::string(std::strerror(error)), error);
        }
        return TemporaryDirectory(std::move(openedParent), std::move(name), root);
    }
    return Error("Failed to allocate a unique temporary directory name", EEXIST);
}

inline Result<TemporaryDirectory> CreateTemporaryDirectory(const std::string& prefix)
{
    if (prefix.empty() || (prefix == ".") || (prefix == "..") || (prefix.find('/') != std::string::npos))
    {
        return Error("Temporary directory prefix must be a single path component", EINVAL);
    }
    auto parent = GetTemporaryDirectoryParent();
    if (!parent.HasValue())
    {
        return std::move(parent).Error();
    }
    auto validatedParent = ValidateTemporaryDirectoryParent(parent.Value());
    if (!validatedParent.HasValue())
    {
        return std::move(validatedParent).Error();
    }

    return CreateTemporaryDirectoryInParent(std::move(validatedParent).Value(), prefix);
}

} // namespace Detail
} // namespace ComplianceEngine

#endif // COMPLIANCEENGINE_TEMPORARYDIRECTORY_H
