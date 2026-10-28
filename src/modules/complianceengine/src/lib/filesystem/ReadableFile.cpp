// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "ReadableFile.hpp"

#include "PathInternal.hpp"

#include <cerrno>
#include <limits>
#include <utility>

namespace ComplianceEngine
{
namespace Filesystem
{
using std::string;
ReadableFile::ReadableFile(Detail::Descriptor&& descriptor) noexcept
    : mDescriptor(std::move(descriptor))
{
}

Result<Optional<string>> ReadableFile::Read(std::size_t maxBytes, std::size_t& remainingInterruptRetries)
{
    if (!mDescriptor.HasValue())
    {
        return Error("Readable file is closed", EBADF);
    }

    if ((maxBytes == 0) || (maxBytes > static_cast<std::size_t>(std::numeric_limits<ssize_t>::max())))
    {
        return Error("Readable file chunk size must be positive and fit a native read", EINVAL);
    }

    if (maxBytes > string().max_size())
    {
        return Error("Readable file chunk size is not representable", EOVERFLOW);
    }

    if (mAtEnd)
    {
        return Optional<string>();
    }

    string chunk(maxBytes, '\0');
    std::size_t filled = 0;
    while (filled < maxBytes)
    {
        const std::size_t remaining = maxBytes - filled;
        auto descriptor = mDescriptor->Get();
        if (!descriptor.HasValue())
        {
            return std::move(descriptor).Error();
        }
        const ssize_t bytes = mDescriptor->Context().ReadFileDescriptor(descriptor.Value(), &chunk[filled], remaining);
        if (bytes < 0)
        {
            const int error = Detail::SavedError();
            if ((error != EINTR) || (remainingInterruptRetries == 0))
            {
                return Error("Cannot read acquired file", error);
            }

            --remainingInterruptRetries;
            continue;
        }

        if (static_cast<std::size_t>(bytes) > remaining)
        {
            return Error("Readable file returned more bytes than requested", EIO);
        }

        if (bytes == 0)
        {
            mAtEnd = true;
            if (filled == 0)
            {
                return Optional<string>();
            }
            break;
        }
        filled += static_cast<std::size_t>(bytes);
    }

    chunk.resize(filled);
    return Optional<string>(std::move(chunk));
}

bool ReadableFile::AtEnd() const noexcept
{
    return mDescriptor.HasValue() && mAtEnd;
}

Result<struct stat> ReadableFile::Stat() const
{
    if (!mDescriptor.HasValue())
    {
        return Error("Readable file is closed", EBADF);
    }

    struct stat metadata = {};
    auto descriptor = mDescriptor->Get();
    if (!descriptor.HasValue())
    {
        return std::move(descriptor).Error();
    }
    if (mDescriptor->Context().StatFileDescriptor(descriptor.Value(), &metadata) != 0)
    {
        return Error("Cannot inspect readable file", Detail::SavedError());
    }
    return metadata;
}

Result<bool> ReadableFile::Close()
{
    if (!mDescriptor.HasValue())
    {
        return true;
    }

    Detail::Descriptor owned(std::move(mDescriptor.Value()));
    mDescriptor.Reset();
    mAtEnd = false;
    auto closed = owned.Close();
    if (!closed.HasValue())
    {
        return Error("Cannot close readable file", closed.Error().code);
    }
    return true;
}
} // namespace Filesystem
} // namespace ComplianceEngine
