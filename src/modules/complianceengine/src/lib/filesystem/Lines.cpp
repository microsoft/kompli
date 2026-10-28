// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "Lines.hpp"

#include "ContextInterface.h"
#include "Optional.h"
#include "filesystem/Path.hpp"
#include "filesystem/PathInternal.hpp"
#include "filesystem/ReadableFile.hpp"

#include <algorithm>
#include <cassert>
#include <cerrno>
#include <limits>
#include <new>
#include <sys/stat.h>
#include <utility>

namespace ComplianceEngine
{
namespace Filesystem
{
namespace
{

constexpr std::size_t ReadChunkBytes = 8192;

bool SameFile(const struct stat& before, const struct stat& after)
{
    return S_ISREG(after.st_mode) && before.st_dev == after.st_dev && before.st_ino == after.st_ino && before.st_size == after.st_size &&
           before.st_mtim.tv_sec == after.st_mtim.tv_sec && before.st_mtim.tv_nsec == after.st_mtim.tv_nsec &&
           before.st_ctim.tv_sec == after.st_ctim.tv_sec && before.st_ctim.tv_nsec == after.st_ctim.tv_nsec;
}

// The Path resolver charges link work and retained pins separately from the
// reader's content-byte budget. Root "/" preserves absolute-path semantics:
// every component uses Policy.
// This does not establish trust in a caller-supplied path's ancestors.
Filesystem::ResolverLimits AcquisitionLimits()
{
    Filesystem::ResolverLimits limits;
    limits.shared.targetBytes = 4096;
    limits.shared.components = 128;
    limits.shared.work = 100000;
    limits.shared.liveDescriptors = 256;
    limits.shared.retainedBytes = 1024 * 1024;
    limits.shared.fdinfoBytes = 4096;
    limits.linkTargetBytes = 4096;
    limits.linkExpansions = 128;
    limits.depth = 128;
    return limits;
}
} // namespace

struct Lines::State
{
    State(const ContextInterface& context, std::string path, Policy policy, Filesystem::ReadableFile data)
        : context(context),
          path(std::move(path)),
          policy(std::move(policy)),
          data(std::move(data)),
          interruptRetriesRemaining(this->policy.limits.maxInterruptedReads)
    {
    }

    ~State() noexcept
    {
        if (!closed)
        {
            try
            {
                Close();
            }
            catch (...)
            {
                OsConfigLogError(nullptr, "File reader state close or log failure: %d", EIO);
            }
        }
    }

    const ContextInterface& context;
    std::string path;
    Policy policy;
    Filesystem::ReadableFile data;
    struct stat before = {};
    std::string buffer;
    std::size_t position = 0, consumed = 0;
    std::size_t interruptRetriesRemaining;
    std::string pending;
    bool finished = false;
    bool closed = false;

    Result<bool> Close()
    {
        if (!closed)
        {
            closed = true;
            finished = true;
            return data.Close();
        }
        return data.Close();
    }

    static Result<std::unique_ptr<State>> Open(const ContextInterface& context, std::string path, Policy policy)
    {
        if (path.empty() || path.front() != '/' || path.find('\0') != std::string::npos)
            return Error("A NUL-free absolute file path is required", EINVAL);
        if (policy.symlinks != SymlinkFollowing::Follow && policy.symlinks != SymlinkFollowing::DoNotFollow)
            return Error("Invalid symlink policy", EINVAL);
        if (!policy.limits.maxBytes || !policy.limits.maxInterruptedReads)
            return Error("File byte and retry limits must be positive", EINVAL);
        if (policy.limits.maxBytes >= std::string().max_size())
            return Error("File byte limit is not representable", EOVERFLOW);
        auto acquired =
            Filesystem::Path::AcquireRoot(context, "/", {Filesystem::SymlinkPolicy::Reject, Filesystem::MountPolicy::AllowCrossing}, AcquisitionLimits());
        if (!acquired.HasValue())
            return std::move(acquired).Error();
        auto& pins = acquired.Value();
        std::unique_ptr<State> state;
        // A primary acquisition/activation error wins over cleanup failures.
        // Close still attempts every hidden acquisition pin and reports its
        // first failure; log it when another error already owns the result.
        auto fail = [&](Error primary) -> Result<std::unique_ptr<State>> {
            auto closed = pins.Close();
            if (!closed.HasValue())
            {
                try
                {
                    OsConfigLogError(context.GetLogHandle(), "Failed to close pinned descriptors for %s: %d", (state ? state->path : path).c_str(),
                        closed.Error().code);
                }
                catch (...)
                {
                    OsConfigLogError(nullptr, "File reader secondary pin close log failure: %d", closed.Error().code);
                }
            }
            return primary;
        };
        for (std::size_t start = 1; start < path.size();)
        {
            const auto slash = path.find('/', start);
            const auto end = slash == std::string::npos ? path.size() : slash;
            if (end != start)
            {
                auto pushed = pins.Push(path.substr(start, end - start),
                    {policy.symlinks == SymlinkFollowing::DoNotFollow ? Filesystem::SymlinkPolicy::Reject : Filesystem::SymlinkPolicy::FollowWithinRoot,
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
        state.reset(new State(context, std::move(path), std::move(policy), std::move(opened).Value()));
        auto inspected = state->data.Stat();
        if (!inspected.HasValue())
            return fail(std::move(inspected).Error());
        state->before = inspected.Value();
        const auto held = pins.Leaf().Stat();
        if (held.st_dev != state->before.st_dev || held.st_ino != state->before.st_ino || !S_ISREG(state->before.st_mode))
            return fail(Error("Pinned file identity changed", EAGAIN));
        auto closed = pins.Close();
        if (!closed.HasValue())
        {
            return Error("Failed to close pinned descriptor", closed.Error().code);
        }
        return std::move(state);
    }

    Result<Optional<std::string>> Complete()
    {
        if (before.st_size > 0 && static_cast<unsigned long long>(before.st_size) != consumed)
            return Error("File ended before its stable size", EIO);
        auto after = data.Stat();
        if (!after.HasValue())
            return Error("Failed to verify data descriptor", after.Error().code);
        if (!SameFile(before, after.Value()))
            return Error("File changed while being read", EAGAIN);
        if (!pending.empty())
            return Optional<std::string>(std::move(pending));
        return Optional<std::string>();
    }

    // Refill only when exhausted. A one-byte read at the cap proves exact
    // EOF without storing or charging any excess byte.
    Result<bool> Refill()
    {
        const std::size_t remaining = policy.limits.maxBytes - consumed;
        const std::size_t requested = std::min(ReadChunkBytes, remaining ? remaining : std::size_t(1));
        auto chunk = data.Read(requested, interruptRetriesRemaining);
        if (!chunk.HasValue())
        {
            const int error = chunk.Error().code;
            if (error == EINTR)
                return Error("File read interrupt retry limit exceeded", E2BIG);
            return Error("Failed to read file bytes", error);
        }
        if (!chunk.Value().HasValue())
            return false;
        if (chunk.Value().Value().size() > remaining)
            return Error("File byte limit exceeded", E2BIG);
        buffer = std::move(chunk).Value().Value();
        position = 0;
        return true;
    }

    Result<Optional<std::string>> Next()
    {
        if (finished || closed)
            return Optional<std::string>();
        while (true)
        {
            if (position == buffer.size())
            {
                auto filled = Refill();
                if (!filled.HasValue())
                {
                    finished = true;
                    return std::move(filled).Error();
                }
                if (!filled.Value())
                {
                    finished = true;
                    return Complete();
                }
            }
            const char byte = buffer[position++];
            ++consumed;
            if (byte == '\0')
            {
                finished = true;
                return Error("Embedded NUL in text file", EBADMSG);
            }
            if (byte == '\n')
            {
                Optional<std::string> line(std::move(pending));
                pending.clear();
                return line;
            }
            pending.push_back(byte);
        }
    }
};

Lines::Iterator::Iterator() = default;

Lines::Iterator::Iterator(Lines* range)
    : mRange(range)
{
    Next();
}

Lines::Iterator::Iterator(Iterator&& other) noexcept
    : mRange(other.mRange),
      mCurrent(std::move(other.mCurrent))
{
    other.mRange = nullptr;
}

Lines::Iterator& Lines::Iterator::operator=(Iterator&& other) noexcept
{
    if (this != &other)
    {
        mRange = other.mRange;
        mCurrent = std::move(other.mCurrent);
        other.mRange = nullptr;
    }
    return *this;
}

Lines::Iterator::~Iterator() = default;

Lines::Iterator::reference Lines::Iterator::operator*() const
{
    assert(mRange && mRange->mState && !mRange->mState->closed && mCurrent.HasValue());
    return mCurrent.Value();
}

Lines::Iterator::pointer Lines::Iterator::operator->() const
{
    return &**this;
}

Lines::Iterator& Lines::Iterator::operator++()
{
    assert(mRange && mRange->mState && !mRange->mState->closed && mCurrent.HasValue());
    Next();
    return *this;
}

void Lines::Iterator::Next()
{
    mCurrent.Reset();
    auto next = mRange->mState->Next();
    if (!next.HasValue())
    {
        mCurrent = Result<std::string>(std::move(next).Error());
        return;
    }
    auto& line = next.Value();
    if (line.HasValue())
        mCurrent = Result<std::string>(std::move(line).Value());
}

bool Lines::Iterator::operator!=(const Iterator& other) const
{
    const bool active = mRange && mRange->mState && !mRange->mState->closed && mCurrent.HasValue();
    const bool otherActive = other.mRange && other.mRange->mState && !other.mRange->mState->closed && other.mCurrent.HasValue();
    return active != otherActive || (active && mRange != other.mRange);
}

Lines::Lines(std::unique_ptr<State> state)
    : mState(std::move(state))
{
}

Lines::Lines(Lines&&) noexcept = default;

Lines& Lines::operator=(Lines&&) noexcept = default;

Lines::~Lines() = default;

Lines::Iterator Lines::begin() // NOLINT(*-identifier-naming)
{
    if (!mState || mStarted || mState->closed)
        return {};
    mStarted = true;
    return Iterator(this);
}

Result<bool> Lines::Close()
{
    return mState ? mState->Close() : Result<bool>(true);
}

Result<Lines> Lines::Open(const ContextInterface& context, std::string path)
{
    return Open(context, std::move(path), Policy{});
}

Result<Lines> Lines::Open(const ContextInterface& context, std::string path, Policy policy)
{
    auto opened = State::Open(context, std::move(path), std::move(policy));
    if (!opened.HasValue())
        return std::move(opened).Error();
    return Lines(std::move(opened).Value());
}
} // namespace Filesystem
} // namespace ComplianceEngine
