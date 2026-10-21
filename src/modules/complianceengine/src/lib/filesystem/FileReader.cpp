// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "FileReader.hpp"

#include "ContextInterface.h"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <limits>
#include <new>
#include <stdexcept>
#include <sys/stat.h>
#include <utility>

namespace FileReader
{
namespace
{
using ComplianceEngine::ContextInterface;
using ComplianceEngine::Error;
using ComplianceEngine::Result;

int SavedError()
{
    return errno ? errno : EIO;
}

// Relinquish ownership before close: even a failed or throwing close must not
// be retried. Early-stop destruction cannot report a close failure.
class Descriptor
{
public:
    explicit Descriptor(const ContextInterface& context)
        : mContext(context)
    {
    }
    ~Descriptor()
    {
        Close();
    }
    Descriptor(const Descriptor&) = delete;
    Descriptor& operator=(const Descriptor&) = delete;
    int Get() const
    {
        return mDescriptor;
    }
    void Adopt(int descriptor)
    {
        mDescriptor = descriptor;
    }
    int Close() noexcept
    {
        if (mDescriptor < 0)
            return 0;
        const int descriptor = mDescriptor;
        mDescriptor = -1;
        try
        {
            return mContext.CloseFileDescriptor(descriptor) == 0 ? 0 : SavedError();
        }
        catch (...)
        {
            return EIO;
        }
    }

private:
    const ContextInterface& mContext;
    int mDescriptor = -1;
};

bool SameFile(const struct stat& before, const struct stat& after)
{
    return S_ISREG(after.st_mode) && before.st_dev == after.st_dev && before.st_ino == after.st_ino && before.st_size == after.st_size &&
           before.st_mtim.tv_sec == after.st_mtim.tv_sec && before.st_mtim.tv_nsec == after.st_mtim.tv_nsec &&
           before.st_ctim.tv_sec == after.st_ctim.tv_sec && before.st_ctim.tv_nsec == after.st_ctim.tv_nsec;
}
} // namespace

struct LinesRange::State
{
    State(const ContextInterface& context, std::string path, Policy policy)
        : context(context),
          path(std::move(path)),
          policy(std::move(policy)),
          pin(context),
          data(context)
    {
    }

    const ContextInterface& context;
    std::string path;
    Policy policy;
    Descriptor pin, data;
    struct stat before = {};
    char buffer[8192] = {};
    std::size_t position = 0, available = 0, consumed = 0;
    std::size_t interrupts = 0;
    std::string pending;
    std::unique_ptr<Result<std::string>> current;
    bool finished = false;
    bool closed = false;
    int dataCloseError = 0, pinCloseError = 0;

    Result<bool> Close()
    {
        if (!closed)
        {
            closed = true;
            current.reset();
            finished = true;
            dataCloseError = data.Close();
            pinCloseError = pin.Close();
        }
        if (!dataCloseError && !pinCloseError)
            return true;
        Error error(dataCloseError ? "Failed to close data descriptor" : "Failed to close pinned descriptor", dataCloseError ? dataCloseError : pinCloseError);
        if (dataCloseError)
            error.message += " [data close: " + std::to_string(dataCloseError) + "]";
        if (pinCloseError)
            error.message += " [pin close: " + std::to_string(pinCloseError) + "]";
        return error;
    }

    // Factory failures must not hide the primary error behind cleanup errors.
    Error CloseWithError(Error error)
    {
        const int dataError = data.Close();
        const int pinError = pin.Close();
        try
        {
            if (dataError)
                error.message += " [data close: " + std::to_string(dataError) + "]";
            if (pinError)
                error.message += " [pin close: " + std::to_string(pinError) + "]";
        }
        catch (const std::bad_alloc&)
        {
        }
        catch (const std::length_error&)
        {
        }
        return error;
    }

    void Fail(Error error)
    {
        current.reset(new Result<std::string>(std::move(error)));
        finished = true;
    }

    Result<bool> Open()
    {
        if (path.empty() || path.front() != '/' || path.find('\0') != std::string::npos)
            return Error("A NUL-free absolute file path is required", EINVAL);
        if (policy.symlinks != SymlinksPolicy::FollowFinal && policy.symlinks != SymlinksPolicy::RejectFinal)
            return Error("Invalid final symlink policy", EINVAL);
        if (!policy.limits.maxBytes || !policy.limits.maxInterruptedReads)
            return Error("File byte and retry limits must be positive", EINVAL);
        if (policy.limits.maxBytes >= pending.max_size())
            return Error("File byte limit is not representable", EOVERFLOW);
        const int flags = O_PATH | O_CLOEXEC | (policy.symlinks == SymlinksPolicy::RejectFinal ? O_NOFOLLOW : 0);
        const int pinned = context.OpenExistingFile(path.c_str(), flags);
        if (pinned < 0)
            return Error("Failed to open file path", SavedError());
        pin.Adopt(pinned);
        struct stat held = {};
        if (context.StatFileDescriptor(pin.Get(), &held) != 0)
            return Error("Failed to inspect pinned file path", SavedError());
        if (S_ISLNK(held.st_mode))
            return Error("Final file symlink is not allowed", ELOOP);
        if (!S_ISREG(held.st_mode))
            return Error("File target is not regular", EINVAL);
        // Open the held inode rather than resolving the original name again.
        const std::string heldPath = "/proc/self/fd/" + std::to_string(pin.Get());
        const int opened = context.OpenExistingFile(heldPath.c_str(), O_RDONLY | O_CLOEXEC);
        if (opened < 0)
            return Error("Failed to open pinned file", SavedError());
        data.Adopt(opened);
        if (context.StatFileDescriptor(data.Get(), &before) != 0)
            return Error("Failed to inspect data descriptor", SavedError());
        if (held.st_dev != before.st_dev || held.st_ino != before.st_ino || !S_ISREG(before.st_mode))
            return Error("Pinned file identity changed", EAGAIN);
        return true;
    }

    void Complete()
    {
        if (before.st_size > 0 && static_cast<unsigned long long>(before.st_size) != consumed)
        {
            Fail(Error("File ended before its stable size", EIO));
            return;
        }
        struct stat after = {};
        if (context.StatFileDescriptor(data.Get(), &after) != 0)
        {
            Fail(Error("Failed to verify data descriptor", SavedError()));
            return;
        }
        if (!SameFile(before, after))
        {
            Fail(Error("File changed while being read", EAGAIN));
            return;
        }
        finished = true;
        if (!pending.empty())
            current.reset(new Result<std::string>(std::move(pending)));
    }

    void Advance()
    {
        current.reset();
        if (finished)
            return;
        try
        {
            while (true)
            {
                if (position == available)
                {
                    // A single-byte probe at the cap distinguishes exact EOF
                    // from excess, without buffering any excess content.
                    const std::size_t remaining = policy.limits.maxBytes - consumed;
                    const std::size_t requested = std::min(sizeof(buffer), remaining ? remaining : std::size_t(1));
                    const ssize_t count = context.ReadFileDescriptor(data.Get(), buffer, requested);
                    if (count < 0)
                    {
                        const int error = SavedError();
                        if (error == EINTR)
                        {
                            if (interrupts++ < policy.limits.maxInterruptedReads)
                                continue;
                            Fail(Error("File read interrupt retry limit exceeded", E2BIG));
                        }
                        else
                            Fail(Error("Failed to read file bytes", error));
                        return;
                    }
                    if (static_cast<std::size_t>(count) > requested)
                    {
                        Fail(Error("File read returned more bytes than requested", EIO));
                        return;
                    }
                    if (!count)
                    {
                        Complete();
                        return;
                    }
                    if (static_cast<std::size_t>(count) > remaining)
                    {
                        Fail(Error("File byte limit exceeded", E2BIG));
                        return;
                    }
                    available = static_cast<std::size_t>(count);
                    position = 0;
                }
                const char byte = buffer[position++];
                ++consumed;
                if (byte == '\0')
                {
                    Fail(Error("Embedded NUL in text file", EBADMSG));
                    return;
                }
                pending.push_back(byte);
                if (byte == '\n')
                {
                    current.reset(new Result<std::string>(std::move(pending)));
                    pending.clear();
                    return;
                }
            }
        }
        catch (const std::bad_alloc&)
        {
            Fail(Error("File read allocation failed", ENOMEM));
        }
        catch (const std::length_error&)
        {
            Fail(Error("File read size is not representable", EOVERFLOW));
        }
        catch (...)
        {
            Fail(Error("File operation threw an exception", EIO));
        }
    }
};

LinesRange::Iterator::Iterator() = default;
LinesRange::Iterator::Iterator(LinesRange* range)
    : mRange(range)
{
    mRange->mState->Advance();
}
LinesRange::Iterator::Iterator(Iterator&& other) noexcept
    : mRange(other.mRange)
{
    other.mRange = nullptr;
}
LinesRange::Iterator& LinesRange::Iterator::operator=(Iterator&& other) noexcept
{
    if (this != &other)
    {
        mRange = other.mRange;
        other.mRange = nullptr;
    }
    return *this;
}
LinesRange::Iterator::~Iterator() = default;
LinesRange::Iterator::reference LinesRange::Iterator::operator*() const
{
    return *mRange->mState->current;
}
LinesRange::Iterator::pointer LinesRange::Iterator::operator->() const
{
    return mRange->mState->current.get();
}
LinesRange::Iterator& LinesRange::Iterator::operator++()
{
    mRange->mState->Advance();
    return *this;
}
bool LinesRange::Iterator::operator!=(const Iterator& other) const
{
    const bool active = mRange && mRange->mState && mRange->mState->current;
    const bool otherActive = other.mRange && other.mRange->mState && other.mRange->mState->current;
    return active != otherActive || (active && mRange != other.mRange);
}

LinesRange::LinesRange(std::unique_ptr<State> state)
    : mState(std::move(state))
{
}
LinesRange::LinesRange(LinesRange&&) noexcept = default;
LinesRange& LinesRange::operator=(LinesRange&&) noexcept = default;
LinesRange::~LinesRange() = default;
LinesRange::Iterator LinesRange::begin() // NOLINT(*-identifier-naming)
{
    if (!mState || mStarted || mState->closed)
        return {};
    mStarted = true;
    return Iterator(this);
}
Result<bool> LinesRange::Close()
{
    return mState ? mState->Close() : Result<bool>(true);
}
Result<LinesRange> Lines(const ContextInterface& context, std::string path, Policy policy)
{
    std::unique_ptr<LinesRange::State> state(new LinesRange::State(context, std::move(path), std::move(policy)));
    try
    {
        auto opened = state->Open();
        if (!opened.HasValue())
            return state->CloseWithError(std::move(opened).Error());
        return LinesRange(std::move(state));
    }
    catch (const std::bad_alloc&)
    {
        return state->CloseWithError(Error("File open allocation failed", ENOMEM));
    }
    catch (const std::length_error&)
    {
        return state->CloseWithError(Error("File open size is not representable", EOVERFLOW));
    }
    catch (...)
    {
        return state->CloseWithError(Error("File operation threw an exception", EIO));
    }
}
} // namespace FileReader
