// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <ContextInterface.h>
#include <ExactFileObjectCollector.h>
#include <algorithm>
#include <cerrno>
#include <exception>
#include <fcntl.h>
#include <limits>
#include <new>
#include <parsers/NameserverSelection.h>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace ComplianceEngine
{
namespace
{
class Descriptor
{
public:
    Descriptor(int descriptor, const ContextInterface& context)
        : mDescriptor(descriptor),
          mContext(context)
    {
    }

    ~Descriptor()
    {
        if (mDescriptor >= 0)
        {
            try
            {
                mContext.CloseFileDescriptor(mDescriptor);
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
            if (mContext.CloseFileDescriptor(descriptor) != 0)
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
    const ContextInterface& mContext;
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

Result<std::string> ReadCompleteFile(int descriptor, const struct stat& before, ExactFileCollectionLimits limits, const ContextInterface& context)
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
        const ssize_t count = context.ReadFileDescriptor(descriptor, buffer, request);
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
    if (context.StatFileDescriptor(descriptor, &after) != 0)
    {
        return Error("Failed to verify exact file after reading", errno == 0 ? EIO : errno);
    }
    if (!SameObservedFile(before, after))
    {
        return Error("Exact file changed while being read", EAGAIN);
    }
    return content;
}

Result<VariableResolution::ObjectCollection> ProjectNameservers(const NameserverSelection::Document& selection, std::size_t maxValues)
{
    VariableResolution::ObjectCollection collection;
    for (const auto& capture : selection.captures)
    {
        if (collection.items.size() >= maxValues)
        {
            return Error("Exact file value limit exceeded", E2BIG);
        }
        if (collection.items.size() >= collection.items.max_size())
        {
            return Error("Exact file capture collection is not representable", EOVERFLOW);
        }
        VariableResolution::ObjectItem item;
        item.fields["subexpression"] = {selection.bytes.substr(capture.offset, capture.length)};
        collection.items.push_back(std::move(item));
    }
    collection.complete = true;
    return collection;
}
} // namespace

Result<VariableResolution::ObjectCollection> CollectNameserverObject(const ContextInterface& context, const std::string& path,
    ExactFileCollectionLimits limits, RootSymlinkPolicy rootSymlinks)
{
    if (path.empty() || path.front() != '/' || path.find('\0') != std::string::npos)
    {
        return Error("A NUL-free absolute path is required", EINVAL);
    }
    if (limits.contentBytes == 0 || limits.occurrences == 0 || limits.captureBytes == 0 || limits.capturedBytes == 0 || limits.values == 0 || limits.readRetries == 0)
    {
        return Error("Exact file limits must be positive", EINVAL);
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
        const int pathDescriptor = context.OpenExistingFile(path.c_str(), pathFlags);
        if (pathDescriptor < 0)
        {
            return Error("Failed to open exact file path", errno == 0 ? EIO : errno);
        }
        Descriptor pinned(pathDescriptor, context);

        struct stat pathMetadata = {};
        if (context.StatFileDescriptor(pinned.Get(), &pathMetadata) != 0)
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
        const int dataDescriptor = context.OpenExistingFile(descriptorPath.c_str(), O_RDONLY | O_CLOEXEC);
        if (dataDescriptor < 0)
        {
            return Error("Failed to open pinned exact file", errno == 0 ? EIO : errno);
        }
        Descriptor data(dataDescriptor, context);

        struct stat dataMetadata = {};
        if (context.StatFileDescriptor(data.Get(), &dataMetadata) != 0)
        {
            return Error("Failed to inspect pinned exact file", errno == 0 ? EIO : errno);
        }
        if (!SameIdentity(pathMetadata, dataMetadata))
        {
            return Error("Pinned exact file identity changed", EAGAIN);
        }

        auto content = ReadCompleteFile(data.Get(), dataMetadata, limits, context);
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

        NameserverSelection::Limits selectionLimits;
        selectionLimits.occurrences = limits.occurrences;
        selectionLimits.captureBytes = limits.captureBytes;
        selectionLimits.capturedBytes = limits.capturedBytes;
        auto selection = NameserverSelection::Select(std::move(content.Value()), path, selectionLimits);
        if (!selection.HasValue())
        {
            return selection.Error();
        }
        return ProjectNameservers(selection.Value(), limits.values);
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
} // namespace ComplianceEngine
