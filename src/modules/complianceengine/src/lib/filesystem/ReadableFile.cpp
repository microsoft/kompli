// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "ReadableFile.hpp"

#include "ContextInterface.h"
#include "PathInternal.hpp"

#include <cerrno>
#include <cstdlib>
#include <limits>
#include <utility>

namespace ComplianceEngine
{
namespace Filesystem
{
using std::string;
using std::swap;

ReadableFile::ReadableFile(const ContextInterface& context, int descriptor) noexcept
    : mContext(context),
      mDescriptor(descriptor)
{
}

ReadableFile::ReadableFile(ReadableFile&& other) noexcept
    : mContext(other.mContext),
      mDescriptor(std::move(other.mDescriptor)),
      mAtEnd(other.mAtEnd)
{
    other.mDescriptor.Reset();
    other.mAtEnd = false;
}

ReadableFile& ReadableFile::operator=(ReadableFile&& other) noexcept
{
    if (this == &other)
    {
        return *this;
    }

    if (&mContext != &other.mContext)
    {
        std::abort();
    }

    // Destruction of the previous ownership retains its nonthrowing
    // close/log contract, including on an injected close failure.
    ReadableFile incoming(std::move(other));
    swap(mDescriptor, incoming.mDescriptor);
    swap(mAtEnd, incoming.mAtEnd);

    return *this;
}

ReadableFile::~ReadableFile() noexcept
{
    if (!mDescriptor.HasValue())
    {
        return;
    }

    try
    {
        auto closed = Close();
        if (!closed.HasValue())
        {
            OsConfigLogError(mContext.GetLogHandle(), "Failed to close readable filesystem descriptor: %d", closed.Error().code);
        }
    }
    catch (...)
    {
        // Close relinquishes ownership before its native attempt; neither a
        // failed result nor a logging failure may retry it during destruction.
    }
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
        const ssize_t bytes = mContext.ReadFileDescriptor(mDescriptor.Value(), &chunk[filled], remaining);
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
    return mAtEnd;
}

Result<struct stat> ReadableFile::Stat() const
{
    if (!mDescriptor.HasValue())
    {
        return Error("Readable file is closed", EBADF);
    }

    struct stat metadata = {};
    if (mContext.StatFileDescriptor(mDescriptor.Value(), &metadata) != 0)
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

    const int descriptor = mDescriptor.Value();
    mDescriptor.Reset();
    mAtEnd = false;
    int closeError = 0;
    try
    {
        if (mContext.CloseFileDescriptor(descriptor) != 0)
        {
            closeError = Detail::SavedError();
        }
    }
    catch (...)
    {
        // Never retry close: Linux may already have reused this fd number.
        closeError = EIO;
    }

    if (closeError != 0)
    {
        return Error("Cannot close readable file", closeError);
    }
    return true;
}
} // namespace Filesystem
} // namespace ComplianceEngine
