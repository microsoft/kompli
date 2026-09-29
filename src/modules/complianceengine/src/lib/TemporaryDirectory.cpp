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

class OpenedTemporaryParent
{
public:
    static Result<OpenedTemporaryParent> MakeRoot()
    {
        std::string path = "/";
        const int fd = ::open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (fd < 0)
        {
            const int error = errno;
            return Error("Failed to open filesystem root: " + std::string(std::strerror(error)), error);
        }
        OpenedTemporaryParent opened(std::move(path), fd);
        auto validation = opened.Validate();
        if (!validation.HasValue())
        {
            return std::move(validation).Error();
        }
        return opened;
    }

    static Result<OpenedTemporaryParent> MakeChild(const OpenedTemporaryParent& parent, const std::string& component)
    {
        std::string path = parent.mPath == "/" ? "/" + component : parent.mPath + "/" + component;
        const int fd = ::openat(parent.mFd, component.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (fd < 0)
        {
            const int error = errno;
            return Error("Failed to securely open temporary directory parent component " + component + ": " + std::strerror(error), error);
        }
        OpenedTemporaryParent opened(std::move(path), fd);
        auto validation = opened.Validate();
        if (!validation.HasValue())
        {
            return std::move(validation).Error();
        }
        return opened;
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
    OpenedTemporaryParent(std::string path, int fd)
        : mPath(std::move(path)),
          mFd(fd)
    {
    }

    Result<bool> Validate() const
    {
        struct stat status;
        if (::fstat(mFd, &status) != 0)
        {
            const int error = errno;
            return Error("Failed to inspect temporary directory parent " + mPath + ": " + std::strerror(error), error);
        }

        const uid_t effectiveUser = ::geteuid();
        if ((status.st_uid != 0) && (status.st_uid != effectiveUser))
        {
            return Error("Temporary directory parent has an untrusted owner: " + mPath, EPERM);
        }

        const bool writableByOthers = (status.st_mode & (S_IWGRP | S_IWOTH)) != 0;
        if (writableByOthers && ((status.st_mode & S_ISVTX) == 0))
        {
            return Error("Temporary directory parent is writable by other users without the sticky bit: " + mPath, EPERM);
        }
        return true;
    }

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

    auto root = OpenedTemporaryParent::MakeRoot();
    if (!root.HasValue())
    {
        return std::move(root).Error();
    }
    auto opened = std::move(root).Value();

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

        auto child = OpenedTemporaryParent::MakeChild(opened, component);
        if (!child.HasValue())
        {
            return std::move(child).Error();
        }
        opened = std::move(child).Value();
    }
    return opened;
}

Result<bool> RemoveTemporaryDirectoryContents(int directory, const std::string& path, std::size_t depth)
{
    const int scanDescriptor = ::openat(directory, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (scanDescriptor < 0)
    {
        const int error = errno;
        return Error("Failed to open temporary directory for cleanup at " + path + ": " + std::strerror(error), error);
    }

    DIR* entries = ::fdopendir(scanDescriptor);
    if (entries == nullptr)
    {
        const int error = errno;
        ::close(scanDescriptor);
        return Error("Failed to enumerate temporary directory " + path + ": " + std::strerror(error), error);
    }

    Result<bool> result = true;
    errno = 0;
    struct dirent* entry = nullptr;
    while ((entry = ::readdir(entries)) != nullptr)
    {
        if ((std::strcmp(entry->d_name, ".") == 0) || (std::strcmp(entry->d_name, "..") == 0))
        {
            continue;
        }

        const std::string entryPath = path + "/" + entry->d_name;
        struct stat status;
        if (::fstatat(directory, entry->d_name, &status, AT_SYMLINK_NOFOLLOW) != 0)
        {
            const int error = errno;
            if ((error != ENOENT) && result.HasValue())
            {
                result = Error("Failed to inspect temporary directory entry " + entryPath + ": " + std::strerror(error), error);
            }
            errno = 0;
            continue;
        }

        if (S_ISDIR(status.st_mode))
        {
            if (depth >= sMaxTemporaryDirectoryDepth)
            {
                if (result.HasValue())
                {
                    result = Error("Temporary directory cleanup exceeded maximum depth at " + entryPath, ELOOP);
                }
                errno = 0;
                continue;
            }
            const int child = ::openat(directory, entry->d_name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
            if (child < 0)
            {
                const int error = errno;
                if (result.HasValue())
                {
                    result = Error("Failed to open temporary directory entry " + entryPath + ": " + std::strerror(error), error);
                }
                errno = 0;
                continue;
            }
            auto childResult = RemoveTemporaryDirectoryContents(child, entryPath, depth + 1);
            if (!childResult.HasValue() && result.HasValue())
            {
                result = std::move(childResult).Error();
            }
            if (::close(child) != 0)
            {
                const int error = errno;
                if (result.HasValue())
                {
                    result = Error("Failed to close temporary directory entry " + entryPath + ": " + std::strerror(error), error);
                }
            }
            if ((::unlinkat(directory, entry->d_name, AT_REMOVEDIR) != 0) && (errno != ENOENT))
            {
                const int error = errno;
                if (result.HasValue())
                {
                    result = Error("Failed to remove temporary directory entry " + entryPath + ": " + std::strerror(error), error);
                }
            }
        }
        else if ((::unlinkat(directory, entry->d_name, 0) != 0) && (errno != ENOENT))
        {
            const int error = errno;
            if (result.HasValue())
            {
                result = Error("Failed to remove temporary directory entry " + entryPath + ": " + std::strerror(error), error);
            }
        }
        errno = 0;
    }
    const int readError = errno;
    if ((readError != 0) && result.HasValue())
    {
        result = Error("Failed to enumerate temporary directory " + path + ": " + std::strerror(readError), readError);
    }
    if (::closedir(entries) != 0)
    {
        const int error = errno;
        if (result.HasValue())
        {
            result = Error("Failed to close temporary directory " + path + ": " + std::strerror(error), error);
        }
    }
    return result;
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
      mRoot(other.mRoot),
      mRemovalResult(std::move(other.mRemovalResult))
{
    other.mParent = -1;
    other.mRoot = -1;
    other.mRemovalResult = true;
}

TemporaryDirectory::~TemporaryDirectory()
{
    if (mRoot >= 0)
    {
        auto result = Remove();
        if (!result.HasValue())
        {
            std::fprintf(stderr, "%s\n", result.Error().message.c_str());
        }
    }
}

const std::string& TemporaryDirectory::Path() const
{
    return mPath;
}

Result<bool> TemporaryDirectory::Remove()
{
    if (mRoot < 0)
    {
        return mRemovalResult;
    }

    Result<bool> result = true;
    for (int attempt = 0; attempt < 2; ++attempt)
    {
        struct stat rootStatus;
        struct stat entryStatus;
        if (::fstat(mRoot, &rootStatus) != 0)
        {
            const int error = errno;
            result = Error("Failed to inspect temporary directory " + mPath + ": " + std::strerror(error), error);
            break;
        }
        if (::fstatat(mParent, mName.c_str(), &entryStatus, AT_SYMLINK_NOFOLLOW) != 0)
        {
            const int error = errno;
            result = Error("Failed to inspect temporary directory entry " + mPath + ": " + std::strerror(error), error);
            break;
        }
        if ((rootStatus.st_dev != entryStatus.st_dev) || (rootStatus.st_ino != entryStatus.st_ino))
        {
            result = Error("Temporary directory entry was replaced: " + mPath, ESTALE);
            break;
        }
        auto contentsRemoved = RemoveTemporaryDirectoryContents(mRoot, mPath, 0);
        if (::unlinkat(mParent, mName.c_str(), AT_REMOVEDIR) == 0)
        {
            result = std::move(contentsRemoved);
            break;
        }
        const int error = errno;
        if (!contentsRemoved.HasValue())
        {
            result = std::move(contentsRemoved);
        }
        else
        {
            result = Error("Failed to remove temporary directory " + mPath + ": " + std::strerror(error), error);
        }
        if (error != ENOTEMPTY)
        {
            break;
        }
    }
    if (::close(mRoot) != 0)
    {
        const int error = errno;
        if (result.HasValue())
        {
            result = Error("Failed to close temporary directory " + mPath + ": " + std::strerror(error), error);
        }
    }
    mRoot = -1;
    if (::close(mParent) != 0)
    {
        const int error = errno;
        if (result.HasValue())
        {
            result = Error("Failed to close temporary directory parent for " + mPath + ": " + std::strerror(error), error);
        }
    }
    mParent = -1;
    mRemovalResult = std::move(result);
    return mRemovalResult;
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
