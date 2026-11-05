// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "LinesRange.hpp"

#include "ContextInterface.h"
#include "filesystem/Path.hpp"

#include <algorithm>
#include <cassert>
#include <cerrno>
#include <limits>
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

} // namespace

LinesRange::LinesRange(ReadableFile&& data, Policy policy, const struct stat& before) noexcept
    : mPolicy(std::move(policy)),
      mData(std::move(data)),
      mBefore(before)
{
}

Result<Optional<std::string>> LinesRange::Complete()
{
    if (mBefore.st_size > 0 && static_cast<unsigned long long>(mBefore.st_size) != mConsumed)
        return Error("File ended before its stable size", EIO);

    auto after = mData.Stat();
    if (!after.HasValue())
        return Error("Failed to verify data descriptor", after.Error().code);

    if (!SameFile(mBefore, after.Value()))
        return Error("File changed while being read", EAGAIN);

    if (!mPending.empty())
        return Optional<std::string>(std::move(mPending));

    return Optional<std::string>();
}

// Refill only when exhausted. A one-byte read at the cap proves exact
// EOF without storing or charging any excess byte.
Result<bool> LinesRange::Refill()
{
    const std::size_t remaining = mPolicy.limits.maxBytes - mConsumed;
    const std::size_t requested = std::min(ReadChunkBytes, remaining ? remaining : std::size_t(1));
    auto chunk = mData.Read(requested);
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

    mBuffer = std::move(chunk).Value().Value();
    mPosition = 0;
    return true;
}

Result<Optional<std::string>> LinesRange::Next()
{
    if (mState != State::Reading)
        return Optional<std::string>();

    while (true)
    {
        if (mPosition == mBuffer.size())
        {
            auto filled = Refill();
            if (!filled.HasValue())
            {
                mState = State::Finished;
                return std::move(filled).Error();
            }

            if (!filled.Value())
            {
                mState = State::Finished;
                return Complete();
            }
        }

        const std::size_t start = mPosition;
        const std::size_t delimiter = mBuffer.find_first_of("\n\0", start, 2);
        const std::size_t end = delimiter == std::string::npos ? mBuffer.size() : delimiter;
        const std::size_t contentBytes = end - start;
        mConsumed += contentBytes + (delimiter == std::string::npos ? 0 : 1);
        if (delimiter == std::string::npos)
        {
            mPending.append(mBuffer, start, contentBytes);
            mPosition = end;
            continue;
        }

        mPosition = delimiter + 1;
        if (mBuffer[delimiter] == '\0')
        {
            mState = State::Finished;
            return Error("Embedded NUL in text file", EBADMSG);
        }

        if (mPending.empty())
        {
            return Optional<std::string>(mBuffer.substr(start, contentBytes));
        }

        mPending.append(mBuffer, start, contentBytes);
        Optional<std::string> line(std::move(mPending));
        mPending.clear();
        return line;
    }
}

LinesRange::Iterator::Iterator() = default;

LinesRange::Iterator::Iterator(LinesRange* range)
    : mRange(range)
{
    Next();
}

LinesRange::Iterator::Iterator(Iterator&& other) noexcept
    : mRange(other.mRange),
      mCurrent(std::move(other.mCurrent))
{
    other.mRange = nullptr;
}

LinesRange::Iterator& LinesRange::Iterator::operator=(Iterator&& other) noexcept
{
    if (this != &other)
    {
        mRange = other.mRange;
        mCurrent = std::move(other.mCurrent);
        other.mRange = nullptr;
    }

    return *this;
}

LinesRange::Iterator::~Iterator() = default;

LinesRange::Iterator::reference LinesRange::Iterator::operator*() const
{
    assert(mRange && mRange->mState != State::Closed && mCurrent.HasValue());
    return mCurrent.Value();
}

LinesRange::Iterator::pointer LinesRange::Iterator::operator->() const
{
    return &**this;
}

LinesRange::Iterator& LinesRange::Iterator::operator++()
{
    assert(mRange && mRange->mState != State::Closed && mCurrent.HasValue());
    Next();
    return *this;
}

void LinesRange::Iterator::Next()
{
    mCurrent.Reset();

    auto next = mRange->Next();
    if (!next.HasValue())
    {
        mCurrent = Result<std::string>(std::move(next).Error());
        return;
    }

    auto line = std::move(next).Value();
    if (line.HasValue())
        mCurrent = Result<std::string>(std::move(line).Value());
}

bool LinesRange::Iterator::operator!=(const Iterator& other) const
{
    const bool active = mRange && mRange->mState != State::Closed && mCurrent.HasValue();
    const bool otherActive = other.mRange && other.mRange->mState != State::Closed && other.mCurrent.HasValue();
    return active != otherActive || (active && mRange != other.mRange);
}

LinesRange::LinesRange(LinesRange&& other) noexcept
    : mPolicy(std::move(other.mPolicy)),
      mData(std::move(other.mData)),
      mBefore(other.mBefore),
      mBuffer(std::move(other.mBuffer)),
      mPosition(other.mPosition),
      mConsumed(other.mConsumed),
      mPending(std::move(other.mPending)),
      mState(other.mState)
{
    other.mState = State::Closed;
}

LinesRange& LinesRange::operator=(LinesRange&& other) & noexcept
{
    if (this != &other)
    {
        // ReadableFile replaces and closes the old descriptor through its
        // original context before adopting the new one.
        mData = std::move(other.mData);
        mPolicy = std::move(other.mPolicy);
        mBefore = other.mBefore;
        mBuffer = std::move(other.mBuffer);
        mPosition = other.mPosition;
        mConsumed = other.mConsumed;
        mPending = std::move(other.mPending);
        mState = other.mState;
        other.mState = State::Closed;
    }

    return *this;
}

LinesRange::~LinesRange() noexcept = default;

LinesRange::Iterator LinesRange::begin() // NOLINT(*-identifier-naming)
{
    if (mState != State::Ready)
        return {};

    mState = State::Reading;
    return Iterator(this);
}

void LinesRange::Close() noexcept
{
    mState = State::Closed;
    mData.Close();
}

Result<LinesRange> LinesRange::Make(const ContextInterface& context, std::string path)
{
    return Make(context, std::move(path), Policy{});
}

Result<LinesRange> LinesRange::Make(const ContextInterface& context, std::string path, Policy policy)
{
    if (path.empty() || path.front() != '/' || path.find('\0') != std::string::npos)
        return Error("A NUL-free absolute file path is required", EINVAL);

    if (policy.symlinks != SymlinkPolicy::Follow && policy.symlinks != SymlinkPolicy::DoNotFollow)
        return Error("Invalid symlink policy", EINVAL);

    if (!policy.limits.maxBytes || !policy.limits.maxInterruptedReads)
        return Error("File byte and retry limits must be positive", EINVAL);

    if (policy.limits.maxBytes >= std::string().max_size())
        return Error("File byte limit is not representable", EOVERFLOW);

    // Resolver pin/work budgets are independent of the content-byte cap.
    // Root "/" preserves absolute-path semantics for each component.
    const ResolverLimits limits;
    Filesystem::Path::Policy pathPolicy;
    pathPolicy.prefixLinks = policy.symlinks == SymlinkPolicy::Follow ? PrefixLinkPolicy::Follow : PrefixLinkPolicy::Reject;
    pathPolicy.fileLinks = policy.symlinks == SymlinkPolicy::Follow ? FileLinkPolicy::Follow : FileLinkPolicy::Reject;
    pathPolicy.directoryLinks = policy.symlinks == SymlinkPolicy::Follow ? DirectoryLinkPolicy::Follow : DirectoryLinkPolicy::Reject;
    pathPolicy.mounts = MountPolicy::CrossMounts;
    auto acquired = Filesystem::Path::Make(context, path, pathPolicy, limits);
    if (!acquired.HasValue())
        return std::move(acquired).Error();

    if (acquired.Value().Is<Filesystem::Path::RejectionReason>() && As<Filesystem::Path::RejectionReason>(acquired.Value()) == Filesystem::Path::RejectionReason::Missing)
        return Error("File target is missing", ENOENT);
    if (acquired.Value().Is<Filesystem::Path::RejectionReason>() && As<Filesystem::Path::RejectionReason>(acquired.Value()) == Filesystem::Path::RejectionReason::Excluded)
        return Error("File target is excluded", ELOOP);
    Filesystem::Path pins = As<Filesystem::Path>(std::move(acquired).Value());

    // The selected file is the leaf; freezing a file does not aid reading it.
    auto leaf = pins.Leaf();
    const auto acquiredFacts = leaf.Acquired();
    if (acquiredFacts.type != Filesystem::Type::RegularFile)
        return Error("File target is not regular", EINVAL);

    auto opened = leaf.OpenReadOnly(ReadableFile::Policy(policy.limits.maxInterruptedReads));
    if (!opened.HasValue())
        return std::move(opened).Error();

    ReadableFile data(std::move(opened).Value());
    auto inspected = data.Stat();
    if (!inspected.HasValue())
        return std::move(inspected).Error();

    const struct stat before = inspected.Value();
    const struct stat held = acquiredFacts.metadata;
    if (held.st_dev != before.st_dev || held.st_ino != before.st_ino || !S_ISREG(before.st_mode))
        return Error("Pinned file identity changed", EAGAIN);

    return LinesRange(std::move(data), std::move(policy), before);
}
} // namespace Filesystem
} // namespace ComplianceEngine
