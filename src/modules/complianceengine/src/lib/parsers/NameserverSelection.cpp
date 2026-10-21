// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "NameserverSelection.h"

#include <StringTools.h>
#include <cerrno>
#include <new>
#include <stdexcept>
#include <utility>

namespace ComplianceEngine
{
namespace NameserverSelection
{
namespace
{
const char prefix[] = "nameserver";
const std::size_t prefixLength = sizeof(prefix) - 1;
} // namespace

Stream::Stream(std::string source, Limits limits, bool retainValues)
    : mSource(std::move(source)),
      mLimits(limits),
      mRetainValues(retainValues)
{
}

Result<bool> Stream::ValidateLimits() const
{
    if (!mLimits.occurrences || !mLimits.captureBytes || !mLimits.capturedBytes)
        return Error("Nameserver selection limits must be positive: " + mSource, EINVAL);
    return true;
}

Result<bool> Stream::CompleteCapture(std::size_t end)
{
    // The occurrence check precedes both byte limits even when the value was
    // too long to retain. Defer limit errors until the capture is complete.
    if (mCaptures.size() >= mLimits.occurrences)
        return Error("Nameserver selection occurrence limit exceeded: " + mSource, E2BIG);
    if (mCaptures.size() >= mCaptures.max_size())
        return Error("Nameserver selection is not representable: " + mSource, EOVERFLOW);
    const std::size_t length = end - mCursor;
    if (mTooLong || length > mLimits.captureBytes || length > mLimits.capturedBytes - mCapturedBytes)
        return Error("Nameserver selection capture limit exceeded: " + mSource, E2BIG);
    mCapturedBytes += length;
    mCaptures.push_back({mAnchor, mCursor, length});
    if (mRetainValues)
        mValues.push_back(std::move(mValue));
    mValue.clear();
    mTooLong = false;
    return true;
}

Result<bool> Stream::Feed(const std::string& bytes)
{
    auto valid = ValidateLimits();
    if (!valid.HasValue())
        return valid.Error();
    for (const char byte : bytes)
    {
        if (mPosition == std::string::npos)
            return Error("Nameserver selection is not representable: " + mSource, EOVERFLOW);
        const std::size_t position = mPosition++;
        switch (mState)
        {
            case State::Prefix:
                if (byte == prefix[mPrefixLength])
                {
                    if (!mPrefixLength)
                        mAnchor = position;
                    if (++mPrefixLength == prefixLength)
                        mState = State::AfterKeyword;
                }
                else
                {
                    mPrefixLength = 0;
                    mState = byte == '\n' ? State::Prefix : State::Skip;
                }
                break;
            case State::AfterKeyword:
                if (IsAsciiWhitespace(static_cast<unsigned char>(byte)))
                {
                    mCursor = mPosition;
                    mState = State::Whitespace;
                }
                else
                    mState = byte == '\n' ? State::Prefix : State::Skip;
                break;
            case State::Whitespace:
                if (IsAsciiWhitespace(static_cast<unsigned char>(byte)))
                    mCursor = mPosition;
                else
                {
                    mCursor = position;
                    mState = State::Value;
                    if (mRetainValues)
                    {
                        if (mValue.size() < mLimits.captureBytes)
                            mValue.push_back(byte);
                        else
                            mTooLong = true;
                    }
                }
                break;
            case State::Value:
                if (byte == '\n')
                {
                    auto result = CompleteCapture(position);
                    if (!result.HasValue())
                        return result.Error();
                    mPrefixLength = 0;
                    mState = State::Prefix;
                }
                else if (mRetainValues)
                {
                    if (mValue.size() < mLimits.captureBytes)
                        mValue.push_back(byte);
                    else
                        mTooLong = true;
                }
                break;
            case State::Skip:
                if (byte == '\n')
                {
                    mPrefixLength = 0;
                    mState = State::Prefix;
                }
                break;
        }
    }
    return true;
}

Result<bool> Stream::Finish()
{
    auto valid = ValidateLimits();
    if (!valid.HasValue())
        return valid.Error();
    if (mState == State::Whitespace || mState == State::Value)
        return CompleteCapture(mPosition);
    return true;
}

Result<Document> FindNameserverCaptures(std::string bytes, std::string source, const Limits& limits)
{
    if ((0 == limits.occurrences) || (0 == limits.captureBytes) || (0 == limits.capturedBytes))
    {
        return Error("Nameserver selection limits must be positive: " + source, EINVAL);
    }
    Document document;
    document.bytes = std::move(bytes);
    document.source = std::move(source);
    try
    {
        Stream stream(document.source, limits, false);
        auto selected = stream.Feed(document.bytes);
        if (!selected.HasValue())
            return selected.Error();
        selected = stream.Finish();
        if (!selected.HasValue())
            return selected.Error();
        document.captures = stream.TakeCaptures();
    }
    catch (const std::bad_alloc&)
    {
        return Error("Failed to retain nameserver selection: " + document.source, ENOMEM);
    }
    catch (const std::length_error&)
    {
        return Error("Nameserver selection is not representable: " + document.source, EOVERFLOW);
    }
    return document;
}
} // namespace NameserverSelection
} // namespace ComplianceEngine
