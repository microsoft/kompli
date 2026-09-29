// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "TemporaryDirectory.h"

#include <cctype>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>

namespace ComplianceEngine
{
namespace
{
constexpr std::size_t sMaxTemporaryDirectoryDepth = 64;

bool TemporaryParentContainsWhitespace(const std::string& parent)
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

Result<bool> ValidateTemporaryDirectoryComponent(int directory, const std::string& path)
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

class OpenedTemporaryParent
{
public:
    OpenedTemporaryParent(std::string path, int fd)
        : mPath(std::move(path)),
          mFd(fd)
    {
    }

    OpenedTemporaryParent(const OpenedTemporaryParent&) = delete;
    OpenedTemporaryParent& operator=(const OpenedTemporaryParent&) = delete;
    OpenedTemporaryParent(OpenedTemporaryParent&& other) noexcept
        : mPath(std::move(other.mPath)),
          mFd(other.mFd)
    {
        other.mFd = -1;
    }
    OpenedTemporaryParent& operator=(OpenedTemporaryParent&& other) noexcept
    {
        if (this != &other)
        {
            if (mFd >= 0)
            {
                ::close(mFd);
            }
            mPath = std::move(other.mPath);
            mFd = other.mFd;
            other.mFd = -1;
        }
        return *this;
    }
    ~OpenedTemporaryParent()
    {
        if (mFd >= 0)
        {
            ::close(mFd);
        }
    }

    const std::string& Path() const
    {
        return mPath;
    }

    int Fd() const
    {
        return mFd;
    }

    int Release()
    {
        const int fd = mFd;
        mFd = -1;
        return fd;
    }

private:
    std::string mPath;
    int mFd;
};

Result<OpenedTemporaryParent> ValidateTemporaryDirectoryParent(const std::string& parent)
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
    if (opened.Fd() < 0)
    {
        const int error = errno;
        return Error("Failed to open filesystem root: " + std::string(std::strerror(error)), error);
    }

    auto validation = ValidateTemporaryDirectoryComponent(opened.Fd(), opened.Path());
    if (!validation.HasValue())
    {
        return std::move(validation).Error();
    }

    std::size_t offset = 1;
    std::size_t depth = 0;
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
        ++depth;
        if (depth > sMaxTemporaryDirectoryDepth)
        {
            return Error("TMPDIR exceeds the maximum directory depth", ELOOP);
        }

        const std::string nextPath = opened.Path() == "/" ? "/" + component : opened.Path() + "/" + component;
        const int child = ::openat(opened.Fd(), component.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (child < 0)
        {
            const int error = errno;
            return Error("Failed to securely open temporary directory parent component " + component + ": " + std::strerror(error), error);
        }
        opened = OpenedTemporaryParent(nextPath, child);
        validation = ValidateTemporaryDirectoryComponent(opened.Fd(), opened.Path());
        if (!validation.HasValue())
        {
            return std::move(validation).Error();
        }
    }
    return opened;
}

bool RemoveTemporaryDirectoryContents(int directory, std::size_t depth)
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
            if (depth >= sMaxTemporaryDirectoryDepth)
            {
                success = false;
                errno = 0;
                continue;
            }
            const int child = ::openat(directory, entry->d_name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
            if (child < 0)
            {
                success = false;
                errno = 0;
                continue;
            }
            success = RemoveTemporaryDirectoryContents(child, depth + 1) && success;
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
} // namespace

namespace Detail
{
Result<std::string> GetTemporaryDirectoryParent()
{
    const char* configuredTmpdir = std::getenv("TMPDIR");
    if ((configuredTmpdir == nullptr) || (configuredTmpdir[0] == '\0'))
    {
        return std::string("/tmp");
    }

    const std::string tmpdir(configuredTmpdir);
    if (tmpdir[0] != '/')
    {
        return Error("TMPDIR must be an absolute path", EINVAL);
    }
    if (TemporaryParentContainsWhitespace(tmpdir))
    {
        return Error("TMPDIR must not contain whitespace", EINVAL);
    }
    return tmpdir;
}

} // namespace Detail

TemporaryDirectory::TemporaryDirectory(std::string path, std::string name, int parent, int root)
    : mPath(std::move(path)),
      mName(std::move(name)),
      mParent(parent),
      mRoot(root)
{
}

TemporaryDirectory::TemporaryDirectory(TemporaryDirectory&& other) noexcept
    : mPath(std::move(other.mPath)),
      mName(std::move(other.mName)),
      mParent(other.mParent),
      mRoot(other.mRoot)
{
    other.mParent = -1;
    other.mRoot = -1;
}

TemporaryDirectory::~TemporaryDirectory()
{
    if (mRoot >= 0 && !Remove())
    {
        std::fprintf(stderr, "Failed to remove temporary directory: %s\n", mPath.c_str());
    }
    if (mParent >= 0)
    {
        ::close(mParent);
    }
}

const std::string& TemporaryDirectory::Path() const
{
    return mPath;
}

bool TemporaryDirectory::Remove()
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
        if ((::fstat(mRoot, &rootStatus) != 0) || (::fstatat(mParent, mName.c_str(), &entryStatus, AT_SYMLINK_NOFOLLOW) != 0) ||
            (rootStatus.st_dev != entryStatus.st_dev) || (rootStatus.st_ino != entryStatus.st_ino))
        {
            break;
        }
        const bool contentsRemoved = RemoveTemporaryDirectoryContents(mRoot, 0);
        if (::unlinkat(mParent, mName.c_str(), AT_REMOVEDIR) == 0)
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

Result<TemporaryDirectory> TemporaryDirectory::Make(const std::string& prefix)
{
    if (prefix.empty() || (prefix == ".") || (prefix == "..") || (prefix.find('/') != std::string::npos))
    {
        return Error("Temporary directory prefix must be a single path component", EINVAL);
    }
    auto parent = Detail::GetTemporaryDirectoryParent();
    if (!parent.HasValue())
    {
        return std::move(parent).Error();
    }
    auto validatedParent = ValidateTemporaryDirectoryParent(parent.Value());
    if (!validatedParent.HasValue())
    {
        return std::move(validatedParent).Error();
    }
    auto openedParent = std::move(validatedParent).Value();

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
        std::string path = openedParent.Path() == "/" ? "/" + name : openedParent.Path() + "/" + name;
        if (::mkdirat(openedParent.Fd(), name.c_str(), 0700) != 0)
        {
            if (errno == EEXIST)
            {
                continue;
            }
            const int error = errno;
            return Error("Failed to create temporary directory beneath " + openedParent.Path() + ": " + std::strerror(error), error);
        }

        const int root = ::openat(openedParent.Fd(), name.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (root < 0)
        {
            const int error = errno;
            (void)::unlinkat(openedParent.Fd(), name.c_str(), AT_REMOVEDIR);
            return Error("Failed to open new temporary directory: " + std::string(std::strerror(error)), error);
        }
        return TemporaryDirectory(std::move(path), std::move(name), openedParent.Release(), root);
    }
    return Error("Failed to allocate a unique temporary directory name", EEXIST);
}
} // namespace ComplianceEngine
