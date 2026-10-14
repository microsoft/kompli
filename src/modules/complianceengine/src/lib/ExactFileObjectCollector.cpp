// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <ExactFileObjectCollector.h>
#include <StringTools.h>
#include <algorithm>
#include <cerrno>
#include <exception>
#include <fcntl.h>
#include <limits>
#include <new>
#include <stdexcept>
#include <string>
#include <unistd.h>
#include <utility>
#include <vector>

namespace ComplianceEngine
{
namespace
{
class Descriptor
{
public:
    Descriptor(int descriptor, const Detail::ExactFileOperations& operations)
        : mDescriptor(descriptor),
          mOperations(operations)
    {
    }

    ~Descriptor()
    {
        if (mDescriptor >= 0)
        {
            try
            {
                mOperations.closeDescriptor(mDescriptor);
            }
            catch (...)
            {
            }
        }
    }

    int Get() const
    {
        return mDescriptor;
    }

    Result<bool> Close()
    {
        if (mDescriptor < 0)
        {
            return true;
        }
        const int descriptor = mDescriptor;
        mDescriptor = -1;
        try
        {
            if (mOperations.closeDescriptor(descriptor) != 0)
            {
                return Error("Failed to finalize exact file descriptor", errno == 0 ? EIO : errno);
            }
        }
        catch (const std::exception&)
        {
            return Error("Exact file close operation threw an exception", EIO);
        }
        catch (...)
        {
            return Error("Exact file close operation threw an unknown exception", EIO);
        }
        return true;
    }

private:
    int mDescriptor;
    const Detail::ExactFileOperations& mOperations;
};

bool SameIdentity(const struct stat& left, const struct stat& right)
{
    return left.st_dev == right.st_dev && left.st_ino == right.st_ino && S_ISREG(right.st_mode);
}

bool SameObservedFile(const struct stat& left, const struct stat& right)
{
    return SameIdentity(left, right) && left.st_size == right.st_size && left.st_mtim.tv_sec == right.st_mtim.tv_sec &&
           left.st_mtim.tv_nsec == right.st_mtim.tv_nsec && left.st_ctim.tv_sec == right.st_ctim.tv_sec && left.st_ctim.tv_nsec == right.st_ctim.tv_nsec;
}

Result<std::string> ReadCompleteFile(int descriptor, const struct stat& before, const ExactFileCollectionLimits& limits, const Detail::ExactFileOperations& operations)
{
    std::string content;
    if (limits.contentBytes > content.max_size())
    {
        return Error("Exact file content limit is not representable", EOVERFLOW);
    }
    try
    {
        content.reserve(std::min<std::size_t>(limits.contentBytes, before.st_size > 0 ? static_cast<std::size_t>(before.st_size) : 0));
    }
    catch (const std::bad_alloc&)
    {
        return Error("Failed to allocate exact file buffer", ENOMEM);
    }
    catch (const std::length_error&)
    {
        return Error("Exact file content limit is not representable", EOVERFLOW);
    }

    std::size_t retries = 0;
    char buffer[8192];
    while (true)
    {
        const std::size_t remaining = limits.contentBytes - content.size();
        const std::size_t request = std::min<std::size_t>(sizeof(buffer), remaining + (remaining == 0 ? 1 : 0));
        const ssize_t count = operations.readDescriptor(descriptor, buffer, request);
        if (count == 0)
        {
            break;
        }
        if (count < 0)
        {
            if (errno == EINTR)
            {
                if (retries < limits.readRetries)
                {
                    ++retries;
                    continue;
                }
                return Error("Exact file read retry limit exceeded", E2BIG);
            }
            return Error("Failed to read exact file", errno == 0 ? EIO : errno);
        }
        const std::size_t bytes = static_cast<std::size_t>(count);
        if (bytes > request)
        {
            return Error("Exact file read exceeded the requested byte count", EIO);
        }
        if (bytes > remaining)
        {
            return Error("Exact file content limit exceeded", E2BIG);
        }
        try
        {
            content.append(buffer, bytes);
        }
        catch (const std::bad_alloc&)
        {
            return Error("Failed to retain exact file content", ENOMEM);
        }
        catch (const std::length_error&)
        {
            return Error("Exact file content is not representable", EOVERFLOW);
        }
    }
    if (before.st_size > 0 && content.size() != static_cast<unsigned long long>(before.st_size))
    {
        return Error("Exact file ended before its stable size", EIO);
    }

    struct stat after = {};
    if (operations.statDescriptor(descriptor, &after) != 0)
    {
        return Error("Failed to verify exact file after reading", errno == 0 ? EIO : errno);
    }
    if (!SameObservedFile(before, after))
    {
        return Error("Exact file changed while being read", EAGAIN);
    }
    return content;
}

Result<VariableResolution::ObjectCollection> SelectNameservers(const std::string& content, const ExactFileCollectionLimits& limits)
{
    VariableResolution::ObjectCollection collection;
    collection.complete = true;
    std::size_t capturedBytes = 0;
    static const char prefix[] = "nameserver";
    static const std::size_t prefixLength = sizeof(prefix) - 1;

    for (std::size_t anchor = 0; anchor <= content.size();)
    {
        if (content.compare(anchor, prefixLength, prefix) == 0)
        {
            std::size_t cursor = anchor + prefixLength;
            if (cursor < content.size() && IsAsciiWhitespace(static_cast<unsigned char>(content[cursor])))
            {
                do
                {
                    ++cursor;
                } while (cursor < content.size() && IsAsciiWhitespace(static_cast<unsigned char>(content[cursor])));

                const std::size_t end = content.find('\n', cursor);
                const std::size_t captureEnd = end == std::string::npos ? content.size() : end;
                const std::size_t captureLength = captureEnd - cursor;
                if (collection.items.size() >= limits.occurrences || collection.items.size() >= limits.values)
                {
                    return Error("Exact file occurrence limit exceeded", E2BIG);
                }
                if (collection.items.size() >= collection.items.max_size() || captureLength > std::string().max_size())
                {
                    return Error("Exact file capture collection is not representable", EOVERFLOW);
                }
                if (captureLength > limits.captureBytes || captureLength > limits.capturedBytes - capturedBytes)
                {
                    return Error("Exact file capture limit exceeded", E2BIG);
                }
                capturedBytes += captureLength;
                try
                {
                    VariableResolution::ObjectItem item;
                    item.fields["subexpression"] = {content.substr(cursor, captureLength)};
                    collection.items.push_back(std::move(item));
                }
                catch (const std::bad_alloc&)
                {
                    return Error("Failed to retain exact file capture", ENOMEM);
                }
                catch (const std::length_error&)
                {
                    return Error("Exact file capture is not representable", EOVERFLOW);
                }
                if (end == std::string::npos)
                {
                    break;
                }
                anchor = end + 1;
                continue;
            }
        }
        const std::size_t newline = content.find('\n', anchor);
        if (newline == std::string::npos)
        {
            break;
        }
        anchor = newline + 1;
    }
    return collection;
}
} // namespace

namespace Detail
{
ExactFileOperations::ExactFileOperations()
    : openPath([](const char* path, int flags) { return ::open(path, flags); }),
      statDescriptor([](int descriptor, struct stat* metadata) { return ::fstat(descriptor, metadata); }),
      readDescriptor([](int descriptor, void* buffer, std::size_t size) { return ::read(descriptor, buffer, size); }),
      closeDescriptor([](int descriptor) { return ::close(descriptor); })
{
}

Result<VariableResolution::ObjectCollection> CollectNameserverObjectWithOperations(const std::string& path, const ExactFileCollectionLimits& limits,
    RootSymlinkPolicy rootSymlinks, const ExactFileOperations& operations)
{
    if (path.empty() || path.front() != '/' || path.find('\0') != std::string::npos)
    {
        return Error("A NUL-free absolute path is required", EINVAL);
    }
    if (limits.contentBytes == 0 || limits.occurrences == 0 || limits.captureBytes == 0 || limits.capturedBytes == 0 || limits.values == 0 || limits.readRetries == 0)
    {
        return Error("Exact file limits must be positive", EINVAL);
    }
    if (!operations.openPath || !operations.statDescriptor || !operations.readDescriptor || !operations.closeDescriptor)
    {
        return Error("Exact file operations must be complete", EINVAL);
    }

    int pathFlags = O_PATH | O_CLOEXEC;
    switch (rootSymlinks)
    {
        case RootSymlinkPolicy::FollowRegular:
            break;
        case RootSymlinkPolicy::Reject:
            pathFlags |= O_NOFOLLOW;
            break;
        default:
            return Error("Invalid root symlink policy", EINVAL);
    }
    try
    {
        const int pathDescriptor = operations.openPath(path.c_str(), pathFlags);
        if (pathDescriptor < 0)
        {
            return Error("Failed to open exact file path", errno == 0 ? EIO : errno);
        }
        Descriptor pinned(pathDescriptor, operations);

        struct stat pathMetadata = {};
        if (operations.statDescriptor(pinned.Get(), &pathMetadata) != 0)
        {
            return Error("Failed to inspect exact file path", errno == 0 ? EIO : errno);
        }
        if (S_ISLNK(pathMetadata.st_mode))
        {
            return Error("Exact file symlink is not allowed", ELOOP);
        }
        if (!S_ISREG(pathMetadata.st_mode))
        {
            return Error("Exact file target is not a regular file", EINVAL);
        }

        const std::string descriptorPath = "/proc/self/fd/" + std::to_string(pinned.Get());
        const int dataDescriptor = operations.openPath(descriptorPath.c_str(), O_RDONLY | O_CLOEXEC);
        if (dataDescriptor < 0)
        {
            return Error("Failed to open pinned exact file", errno == 0 ? EIO : errno);
        }
        Descriptor data(dataDescriptor, operations);

        struct stat dataMetadata = {};
        if (operations.statDescriptor(data.Get(), &dataMetadata) != 0)
        {
            return Error("Failed to inspect pinned exact file", errno == 0 ? EIO : errno);
        }
        if (!SameIdentity(pathMetadata, dataMetadata))
        {
            return Error("Pinned exact file identity changed", EAGAIN);
        }

        auto content = ReadCompleteFile(data.Get(), dataMetadata, limits, operations);
        if (!content.HasValue())
        {
            return content.Error();
        }
        const auto dataClosed = data.Close();
        if (!dataClosed.HasValue())
        {
            return dataClosed.Error();
        }
        const auto pathClosed = pinned.Close();
        if (!pathClosed.HasValue())
        {
            return pathClosed.Error();
        }

        return SelectNameservers(content.Value(), limits);
    }
    catch (const std::bad_alloc&)
    {
        return Error("Exact file operation allocation failed", ENOMEM);
    }
    catch (const std::length_error&)
    {
        return Error("Exact file operation result is not representable", EOVERFLOW);
    }
    catch (const std::exception&)
    {
        return Error("Exact file operation threw an exception", EIO);
    }
    catch (...)
    {
        return Error("Exact file operation threw an unknown exception", EIO);
    }
}
} // namespace Detail

Result<VariableResolution::ObjectCollection> CollectNameserverObject(const std::string& path, const ExactFileCollectionLimits& limits, RootSymlinkPolicy rootSymlinks)
{
    const Detail::ExactFileOperations operations;
    return Detail::CollectNameserverObjectWithOperations(path, limits, rootSymlinks, operations);
}
} // namespace ComplianceEngine
