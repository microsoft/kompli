// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef COMPLIANCEENGINE_PARSERS_NAMESERVER_SELECTION_H
#define COMPLIANCEENGINE_PARSERS_NAMESERVER_SELECTION_H

#include <Result.h>
#include <cstddef>
#include <string>
#include <utility>
#include <vector>

namespace ComplianceEngine
{
namespace NameserverSelection
{
struct Limits
{
    std::size_t occurrences = 16384;
    std::size_t captureBytes = 65536;
    std::size_t capturedBytes = 1024 * 1024;
};

struct Capture
{
    std::size_t anchor;
    std::size_t offset;
    std::size_t length;
};

struct Document
{
    std::string bytes;
    std::string source;
    std::vector<Capture> captures;
};

// Incremental form of the same selection. Feed accepts arbitrary byte ranges,
// including ranges that split the keyword, whitespace run, or capture.
// Values are retained only when requested; offsets remain available to
// document consumers without changing their owned-input contract.
class Stream
{
public:
    Stream(std::string source, Limits limits, bool retainValues);
    Result<bool> Feed(const std::string& bytes);
    Result<bool> Finish();
    const std::vector<Capture>& Captures() const
    {
        return mCaptures;
    }
    std::vector<Capture> TakeCaptures()
    {
        return std::move(mCaptures);
    }
    const std::vector<std::string>& Values() const
    {
        return mValues;
    }

private:
    enum class State
    {
        Prefix,
        AfterKeyword,
        Whitespace,
        Value,
        Skip
    };
    Result<bool> CompleteCapture(std::size_t end);
    Result<bool> ValidateLimits() const;

    std::string mSource;
    Limits mLimits;
    bool mRetainValues;
    State mState = State::Prefix;
    std::size_t mPosition = 0;
    std::size_t mPrefixLength = 0;
    std::size_t mAnchor = 0;
    std::size_t mCursor = 0;
    std::size_t mCapturedBytes = 0;
    bool mTooLong = false;
    std::string mValue;
    std::vector<Capture> mCaptures;
    std::vector<std::string> mValues;
};

// Physical lines from FileReader (without terminating LF). Reuse the byte
// selector's grammar, inserting LF only between observed lines: a final LF
// cannot turn a bare "nameserver" into an empty capture. Raw document
// selection and its exact-byte offsets remain on Stream/FindNameserverCaptures.
class LineStream
{
public:
    LineStream(std::string source, Limits limits);
    Result<bool> FeedLine(const std::string& line);
    Result<bool> Finish();
    const std::vector<std::string>& Values() const
    {
        return mStream.Values();
    }

private:
    Stream mStream;
    bool mHasLine = false;
};

// Select the source expression ^nameserver\s+(.*)$, not resolv.conf grammar.
// Offsets count bytes; the maximal six-byte ASCII whitespace run may cross LF.
Result<Document> FindNameserverCaptures(std::string bytes, std::string source, const Limits& limits = {});
} // namespace NameserverSelection
} // namespace ComplianceEngine

#endif // COMPLIANCEENGINE_PARSERS_NAMESERVER_SELECTION_H
