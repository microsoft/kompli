// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "FileReader.hpp"

#include "ContextInterface.h"
#include "filesystem/Path.hpp"

#include <algorithm>
#include <cerrno>
#include <limits>
#include <new>
#include <sys/stat.h>
#include <utility>

namespace FileReader
{
namespace
{
using ComplianceEngine::ContextInterface;
using ComplianceEngine::Error;
namespace Filesystem = ComplianceEngine::Filesystem;
using ComplianceEngine::Result;

bool SameFile(const struct stat& before, const struct stat& after)
{
    return S_ISREG(after.st_mode) && before.st_dev == after.st_dev && before.st_ino == after.st_ino && before.st_size == after.st_size &&
           before.st_mtim.tv_sec == after.st_mtim.tv_sec && before.st_mtim.tv_nsec == after.st_mtim.tv_nsec &&
           before.st_ctim.tv_sec == after.st_ctim.tv_sec && before.st_ctim.tv_nsec == after.st_ctim.tv_nsec;
}

// The Path resolver charges link work and retained pins separately from the
// reader's content-byte budget. Root "/" preserves absolute-path semantics:
// intermediate links can be followed, while the last component uses Policy.
// This does not establish trust in a caller-supplied path's ancestors.
Filesystem::ResolverLimits AcquisitionLimits()
{
    return {{4096, 128, 100000, 256, 1024 * 1024, 4096}, 4096, 128, 128};
}

void LogPinCloseError(const ContextInterface& context, const std::string& path, int error) noexcept
{
    try
    {
        OsConfigLogError(context.GetLogHandle(), "Failed to close pinned descriptors for %s: %d", path.c_str(), error);
    }
    catch (...)
    {
        // A diagnostic must never replace the acquisition/activation error.
    }
}
} // namespace

struct LinesRange::State
{
    State(const ContextInterface& context, std::string path, Policy policy)
        : context(context),
          path(std::move(path)),
          policy(std::move(policy))
    {
    }
    ~State() noexcept
    {
        if (finalized)
            return;
        try
        {
            if (data)
            {
                auto result = data->Close();
                if (!result.HasValue())
                    dataCloseError = result.Error().code;
            }
        }
        catch (...)
        {
            dataCloseError = EIO;
        }
        try
        {
            LogCloseErrors();
        }
        catch (...)
        {
            // Logging must not terminate during unwinding.
        }
    }

    const ContextInterface& context;
    std::string path;
    Policy policy;
    std::unique_ptr<Filesystem::ReadableFile> data;
    struct stat before = {};
    std::string buffer;
    std::size_t position = 0, available = 0, consumed = 0;
    std::size_t interrupts = 0;
    std::string pending;
    std::unique_ptr<Result<std::string>> current;
    bool finished = false;
    bool closed = false;
    bool finalized = false;
    int dataCloseError = 0;

    void LogCloseErrors() const
    {
        if (dataCloseError)
            OsConfigLogError(context.GetLogHandle(), "Failed to close data descriptor for %s: %d", path.c_str(), dataCloseError);
    }

    Result<bool> Close()
    {
        if (!closed)
        {
            closed = true;
            current.reset();
            finished = true;
            if (data)
            {
                auto result = data->Close();
                if (!result.HasValue())
                    dataCloseError = result.Error().code;
            }
            finalized = true;
            LogCloseErrors();
        }
        if (!dataCloseError)
            return true;
        return Error("Failed to close data descriptor", dataCloseError);
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
        if (policy.symlinks != ComplianceEngine::SymlinkFollowing::Follow && policy.symlinks != ComplianceEngine::SymlinkFollowing::DoNotFollow)
            return Error("Invalid final symlink policy", EINVAL);
        if (!policy.limits.maxBytes || !policy.limits.maxInterruptedReads)
            return Error("File byte and retry limits must be positive", EINVAL);
        if (policy.limits.maxBytes >= pending.max_size())
            return Error("File byte limit is not representable", EOVERFLOW);
        auto acquired =
            Filesystem::Path::AcquireRoot(context, "/", {Filesystem::SymlinkPolicy::Reject, Filesystem::MountPolicy::AllowCrossing}, AcquisitionLimits());
        if (!acquired.HasValue())
            return std::move(acquired).Error();
        auto& pins = acquired.Value();
        // A primary acquisition/activation error wins over cleanup failures.
        // Close still attempts every hidden acquisition pin and reports its
        // first failure; log it when another error already owns the result.
        auto fail = [&](Error primary) -> Result<bool> {
            auto closed = pins.Close();
            if (!closed.HasValue())
                LogPinCloseError(context, path, closed.Error().code);
            return primary;
        };
        for (std::size_t start = 1; start < path.size();)
        {
            const auto slash = path.find('/', start);
            const auto end = slash == std::string::npos ? path.size() : slash;
            if (end != start)
            {
                const bool final = end == path.size();
                auto pushed = pins.Push(path.substr(start, end - start),
                    {final && policy.symlinks == ComplianceEngine::SymlinkFollowing::DoNotFollow ? Filesystem::SymlinkPolicy::Reject : Filesystem::SymlinkPolicy::FollowWithinRoot,
                        Filesystem::MountPolicy::AllowCrossing, Filesystem::HardlinkPolicy::Permit});
                if (!pushed.HasValue())
                    return fail(std::move(pushed).Error());
            }
            start = end == path.size() ? end : end + 1;
        }
        if (pins.Leaf().AcquiredType() != Filesystem::Handle::Type::RegularFile)
            return fail(Error("File target is not regular", EINVAL));
        if (path.back() == '/')
            return fail(Error("File path ends in a directory separator", ENOTDIR));
        auto opened = pins.Leaf().OpenReadOnly(AcquisitionLimits().shared.fdinfoBytes);
        if (!opened.HasValue())
            return fail(std::move(opened).Error());
        data.reset(new Filesystem::ReadableFile(std::move(opened).Value()));
        auto inspected = data->Inspect();
        if (!inspected.HasValue())
            return fail(std::move(inspected).Error());
        before = inspected.Value();
        const auto held = pins.Leaf().Snapshot();
        if (held.st_dev != before.st_dev || held.st_ino != before.st_ino || !S_ISREG(before.st_mode))
            return fail(Error("Pinned file identity changed", EAGAIN));
        auto closed = pins.Close();
        if (!closed.HasValue())
        {
            LogPinCloseError(context, path, closed.Error().code);
            return Error("Failed to close pinned descriptor", closed.Error().code);
        }
        return true;
    }

    void Complete()
    {
        if (before.st_size > 0 && static_cast<unsigned long long>(before.st_size) != consumed)
        {
            Fail(Error("File ended before its stable size", EIO));
            return;
        }
        auto after = data->Inspect();
        if (!after.HasValue())
        {
            Fail(Error("Failed to verify data descriptor", after.Error().code));
            return;
        }
        if (!SameFile(before, after.Value()))
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
        while (true)
        {
            if (position == available)
            {
                // A single-byte probe at the cap distinguishes exact EOF
                // from excess, without buffering any excess content.
                const std::size_t remaining = policy.limits.maxBytes - consumed;
                const std::size_t requested = std::min(std::size_t(8192), remaining ? remaining : std::size_t(1));
                auto chunk = data->Read(requested);
                if (!chunk.HasValue())
                {
                    const int error = chunk.Error().code;
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
                if (chunk.Value().empty())
                {
                    Complete();
                    return;
                }
                if (chunk.Value().size() > remaining)
                {
                    Fail(Error("File byte limit exceeded", E2BIG));
                    return;
                }
                buffer = std::move(chunk).Value();
                available = buffer.size();
                position = 0;
            }
            const char byte = buffer[position++];
            ++consumed;
            if (byte == '\0')
            {
                Fail(Error("Embedded NUL in text file", EBADMSG));
                return;
            }
            if (byte == '\n')
            {
                current.reset(new Result<std::string>(std::move(pending)));
                pending.clear();
                return;
            }
            pending.push_back(byte);
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
    auto opened = state->Open();
    if (!opened.HasValue())
        return std::move(opened).Error();
    return LinesRange(std::move(state));
}
} // namespace FileReader
