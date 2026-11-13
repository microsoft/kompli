// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "MockContext.h"

#include <FileRegexMatch.h>
#include <cerrno>
#include <fstream>
#include <functional>
#include <gtest/gtest.h>
#include <regex>
#include <sstream>
#include <stdexcept>
#include <streambuf>
#include <string>
#include <sys/stat.h>
#include <vector>

using ComplianceEngine::AuditFileRegexMatch;
using ComplianceEngine::Behavior;
using ComplianceEngine::FileRegexMatchParams;
using ComplianceEngine::IndicatorsTree;
using ComplianceEngine::Status;

TEST(FileRegexMatchErrorsTest, NonDirectoryRootIsNotSuccessfulAbsence)
{
    MockContext context;
    IndicatorsTree indicators;
    indicators.Push("FileRegexMatch");
    const std::string path = context.GetTempdirPath() + "/regular-file";
    std::ofstream(path) << "key=value\n";

    FileRegexMatchParams params;
    params.path = path;
    params.filenamePattern = regex(".*");
    params.matchPattern = "key";
    params.behavior = Behavior::NoneExist;

    for (const auto behavior : {Behavior::NoneExist, Behavior::AnyExist})
    {
        params.behavior = behavior;
        for (const auto selectedState : {0, 1, 2})
        {
            params.allMatches = selectedState == 1;
            params.noneMatches = selectedState == 2;
            const auto result = AuditFileRegexMatch(params, indicators, context);
            ASSERT_FALSE(result.HasValue());
            EXPECT_EQ(ENOTDIR, result.Error().code);
        }
    }
}

TEST(FileRegexMatchErrorsTest, MissingDirectoryRetainsAbsencePolicy)
{
    MockContext context;
    IndicatorsTree indicators;
    indicators.Push("FileRegexMatch");
    FileRegexMatchParams params;
    params.path = context.GetTempdirPath() + "/missing";
    params.filenamePattern = regex(".*");
    params.matchPattern = "key";
    params.behavior = Behavior::NoneExist;

    const auto noneResult = AuditFileRegexMatch(params, indicators, context);
    ASSERT_TRUE(noneResult.HasValue());
    EXPECT_EQ(Status::Compliant, noneResult.Value());

    params.behavior = Behavior::AnyExist;
    params.allMatches = true;
    const auto optionalResult = AuditFileRegexMatch(params, indicators, context);
    ASSERT_TRUE(optionalResult.HasValue());
    EXPECT_EQ(Status::Compliant, optionalResult.Value());
}

TEST(FileRegexMatchErrorsTest, InvalidPatternsFailWithoutSelectedFiles)
{
    MockContext context;
    IndicatorsTree indicators;
    indicators.Push("FileRegexMatch");
    const std::string path = context.GetTempdirPath() + "/regex-input";
    ASSERT_EQ(0, mkdir(path.c_str(), 0700));

    FileRegexMatchParams params;
    params.path = path;
    params.filenamePattern = regex("selected");
    params.matchPattern = "(";
    params.behavior = Behavior::NoneExist;

    for (const auto& inputPath : {path, context.GetTempdirPath() + "/missing"})
    {
        params.path = inputPath;
        const auto result = AuditFileRegexMatch(params, indicators, context);
        ASSERT_FALSE(result.HasValue());
        EXPECT_EQ(EINVAL, result.Error().code);
    }

    std::ofstream(path + "/unselected") << "key=value\n";
    params.path = path;
    params.matchPattern = "key";
    params.statePattern = "(";
    const auto stateResult = AuditFileRegexMatch(params, indicators, context);
    ASSERT_FALSE(stateResult.HasValue());
    EXPECT_EQ(EINVAL, stateResult.Error().code);
}

TEST(FileRegexMatchErrorsTest, EmptyAndUnterminatedInputRemainReadable)
{
    MockContext context;
    IndicatorsTree indicators;
    indicators.Push("FileRegexMatch");
    const std::string path = context.GetTempdirPath() + "/regex-input";
    ASSERT_EQ(0, mkdir(path.c_str(), 0700));
    const std::string filename = path + "/selected";
    std::ofstream(filename).close();

    FileRegexMatchParams params;
    params.path = path;
    params.filenamePattern = regex("selected");
    params.matchPattern = "^$";

    const auto emptyResult = AuditFileRegexMatch(params, indicators, context);
    ASSERT_TRUE(emptyResult.HasValue());
    EXPECT_EQ(Status::Compliant, emptyResult.Value());

    std::ofstream(filename) << "key=value";
    params.matchPattern = "^key=value$";
    for (const bool wholeFile : {false, true})
    {
        params.wholeFile = wholeFile;
        const auto result = AuditFileRegexMatch(params, indicators, context);
        ASSERT_TRUE(result.HasValue());
        EXPECT_EQ(Status::Compliant, result.Value());
    }
}

TEST(FileRegexMatchErrorsTest, MissingRootAndInvalidInputRetainDistinctOutcomes)
{
    MockContext context;
    const auto missing = context.GetTempdirPath() + "/missing";
    FileRegexMatchParams params;
    params.path = missing;
    params.filenamePattern = regex(".*");
    params.matchPattern = "key";

    for (const auto behavior : {Behavior::AllExist, Behavior::AnyExist, Behavior::AtLeastOneExists, Behavior::NoneExist, Behavior::OnlyOneExists})
    {
        params.behavior = behavior;
        IndicatorsTree indicators;
        indicators.Push("FileRegexMatch");
        const auto result = AuditFileRegexMatch(params, indicators, context);
        ASSERT_TRUE(result.HasValue());
        const auto expected = behavior == Behavior::NoneExist ? Status::Compliant : Status::NonCompliant;
        EXPECT_EQ(expected, result.Value());
        EXPECT_EQ(behavior == Behavior::NoneExist ? 0U : 1U, indicators.Back().indicators.size());
    }

    params.behavior = Behavior::AnyExist;
    params.allMatches = true;
    IndicatorsTree indicators;
    indicators.Push("FileRegexMatch");
    const auto optional = AuditFileRegexMatch(params, indicators, context);
    ASSERT_TRUE(optional.HasValue());
    EXPECT_EQ(Status::Compliant, optional.Value());
    ASSERT_EQ(1U, indicators.Back().indicators.size());
    EXPECT_EQ(Status::Compliant, indicators.Back().indicators[0].status);

    params.allMatches = false;
    params.matchPattern = "(";
    const auto invalid = AuditFileRegexMatch(params, indicators, context);
    ASSERT_FALSE(invalid.HasValue());
    EXPECT_EQ(EINVAL, invalid.Error().code);
    EXPECT_EQ(1U, indicators.Back().indicators.size());
}

namespace
{
class CollectingOccurrenceSink : public ComplianceEngine::FileRegexOccurrenceSink
{
public:
    std::vector<ComplianceEngine::FileRegexOccurrence> occurrences;
    ComplianceEngine::Result<bool> Consume(const ComplianceEngine::FileRegexOccurrence& occurrence) override
    {
        occurrences.push_back(occurrence);
        return true;
    }
};

class FailingContentBuffer : public std::streambuf
{
public:
    FailingContentBuffer(std::string content, size_t failAfter)
        : mContent(std::move(content)),
          mFailAfter(failAfter)
    {
    }

protected:
    int_type underflow() override
    {
        if (mPosition == mFailAfter)
            throw std::ios_base::failure("injected late read failure");
        if (mPosition == mContent.size())
            return traits_type::eof();
        mChar = mContent[mPosition++];
        setg(&mChar, &mChar, &mChar + 1);
        return traits_type::to_int_type(mChar);
    }

private:
    std::string mContent;
    size_t mFailAfter;
    size_t mPosition = 0;
    char mChar = 0;
};

class ThrowingContentBuffer : public std::streambuf
{
public:
    enum class Failure
    {
        Runtime,
        Allocation,
        Unknown
    };
    explicit ThrowingContentBuffer(Failure failure)
        : mFailure(failure)
    {
    }

protected:
    int_type underflow() override
    {
        if (mPosition == 8)
        {
            switch (mFailure)
            {
                case Failure::Runtime:
                    throw std::runtime_error("injected non-I/O read failure");
                case Failure::Allocation:
                    throw std::bad_alloc();
                case Failure::Unknown:
                    throw 42;
            }
        }
        if (mPosition == mContent.size())
            return traits_type::eof();
        mChar = mContent[mPosition++];
        setg(&mChar, &mChar, &mChar + 1);
        return traits_type::to_int_type(mChar);
    }

private:
    const std::string mContent = "key=1\nkey=2\n";
    Failure mFailure;
    size_t mPosition = 0;
    char mChar = 0;
};
} // anonymous namespace

TEST(FileRegexMatchErrorsTest, StreamProducerKeepsDistinctSelectedOccurrencesAndNoSelection)
{
    MockContext context;
    const regex match("^key=(.*)$");
    const ComplianceEngine::Optional<regex> state(regex("^allowed$"));
    const ComplianceEngine::Optional<long long> noBound{};
    std::istringstream input("key=allowed\nkey=blocked\nignored=allowed\nkey=allowed\n");
    CollectingOccurrenceSink collected;
    const auto evidence =
        ComplianceEngine::EvaluateFileRegexContent(input, "stream:fixture", "^key=(.*)$", match, state, context, noBound, noBound, false, collected);
    ASSERT_TRUE(evidence.HasValue());
    ASSERT_EQ(3U, collected.occurrences.size());
    EXPECT_EQ(0U, collected.occurrences[0].ordinal);
    EXPECT_EQ(1U, collected.occurrences[0].position);
    EXPECT_EQ(1U, collected.occurrences[1].ordinal);
    EXPECT_EQ(2U, collected.occurrences[1].position);
    EXPECT_EQ("blocked", collected.occurrences[1].capturedValue);
    EXPECT_EQ(ComplianceEngine::SourceCheckValue::False, collected.occurrences[1].state);
    EXPECT_EQ(2U, collected.occurrences[2].ordinal);
    EXPECT_EQ(4U, collected.occurrences[2].position);

    std::istringstream absent("ignored=allowed\n");
    CollectingOccurrenceSink emptySink;
    const auto empty = ComplianceEngine::EvaluateFileRegexContent(absent, "stream:empty", "^key=(.*)$", match, state, context, noBound, noBound, false, emptySink);
    ASSERT_TRUE(empty.HasValue());
    EXPECT_TRUE(emptySink.occurrences.empty());
}

TEST(FileRegexMatchErrorsTest, StreamProducerCompletesWholeFileAndPropagatesLateReadFailure)
{
    MockContext context;
    const ComplianceEngine::Optional<regex> noState{};
    const ComplianceEngine::Optional<long long> noBound{};
    std::istringstream contents("key=1\nkey=2\n");
    CollectingOccurrenceSink collected;
    const auto evidence = ComplianceEngine::EvaluateFileRegexContent(contents, "stream:whole", "key=([0-9])", regex("key=([0-9])"), noState, context,
        noBound, noBound, true, collected);
    ASSERT_TRUE(evidence.HasValue());
    ASSERT_EQ(2U, collected.occurrences.size());
    EXPECT_EQ(0U, collected.occurrences[0].position);
    EXPECT_EQ(6U, collected.occurrences[1].position);

    for (const bool wholeFile : {false, true})
    {
        FailingContentBuffer buffer("key=1\nkey=2\n", 8);
        std::istream failing(&buffer);
        CollectingOccurrenceSink collectedFailure;
        const auto failure = ComplianceEngine::EvaluateFileRegexContent(failing, "stream:late", "key=([0-9])", regex("key=([0-9])"), noState, context,
            noBound, noBound, wholeFile, collectedFailure);
        ASSERT_FALSE(failure.HasValue());
        EXPECT_EQ(EIO, failure.Error().code);
        EXPECT_EQ("Failed to read file: stream:late", failure.Error().message);
    }
}

TEST(FileRegexMatchErrorsTest, StreamProducerFeedsBoundedSummaryInOrder)
{
    class Summary : public ComplianceEngine::FileRegexOccurrenceSink
    {
    public:
        size_t count = 0;
        size_t lastPosition = 0;
        ComplianceEngine::SourceCheckEvidence states;
        ComplianceEngine::Result<bool> Consume(const ComplianceEngine::FileRegexOccurrence& occurrence) override
        {
            EXPECT_EQ(count, occurrence.ordinal);
            EXPECT_EQ(count, occurrence.position);
            EXPECT_EQ("x", occurrence.capturedValue);
            EXPECT_EQ(ComplianceEngine::SourceCheckValue::True, occurrence.state);
            lastPosition = occurrence.position;
            ++count;
            states.Add(occurrence.state);
            return true;
        }
    };
    MockContext context;
    const ComplianceEngine::Optional<regex> noState{};
    const ComplianceEngine::Optional<long long> noBound{};
    const std::string contents(2048, char(120));
    std::istringstream input(contents);
    Summary summary;
    const auto result = ComplianceEngine::EvaluateFileRegexContent(input, "stream:many", "x", regex("x"), noState, context, noBound, noBound, true, summary);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(contents.size(), summary.count);
    EXPECT_EQ(contents.size() - 1, summary.lastPosition);
    ASSERT_TRUE(summary.states.Evaluate(ComplianceEngine::SourceCheckPolicy::All).HasValue());
    EXPECT_EQ(ComplianceEngine::SourceCheckValue::True, summary.states.Evaluate(ComplianceEngine::SourceCheckPolicy::All).Value());
}

TEST(FileRegexMatchErrorsTest, StreamProducerReturnsSinkErrorWithoutSuccessProjection)
{
    class FailingSink : public ComplianceEngine::FileRegexOccurrenceSink
    {
    public:
        size_t count = 0;
        ComplianceEngine::Result<bool> Consume(const ComplianceEngine::FileRegexOccurrence&) override
        {
            if (++count == 2)
                return ComplianceEngine::Error("injected sink failure", EIO);
            return true;
        }
    } sink;
    MockContext context;
    const ComplianceEngine::Optional<regex> noState{};
    const ComplianceEngine::Optional<long long> noBound{};
    std::istringstream input("xx");
    const auto result = ComplianceEngine::EvaluateFileRegexContent(input, "stream:sink", "x", regex("x"), noState, context, noBound, noBound, true, sink);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ("injected sink failure", result.Error().message);
    EXPECT_EQ(EIO, result.Error().code);
    EXPECT_EQ(2U, sink.count);
}

TEST(FileRegexMatchErrorsTest, StreamExceptionMasksCompleteAtEofIncludingEmptyAndFinalPartialRead)
{
    MockContext context;
    const ComplianceEngine::Optional<regex> noState{};
    const ComplianceEngine::Optional<long long> noBound{};
    for (const bool wholeFile : {false, true})
    {
        for (const auto mask : {std::ios::failbit, std::ios::badbit, std::ios::eofbit, static_cast<std::ios::iostate>(std::ios::failbit | std::ios::badbit),
                 static_cast<std::ios::iostate>(std::ios::failbit | std::ios::eofbit), static_cast<std::ios::iostate>(std::ios::badbit | std::ios::eofbit),
                 static_cast<std::ios::iostate>(std::ios::failbit | std::ios::badbit | std::ios::eofbit)})
        {
            for (const auto& text : {"", "key=1", "key=1\n", "key=1\nkey=2"})
            {
                std::istringstream input(text);
                input.exceptions(mask);
                CollectingOccurrenceSink sink;
                const bool empty = std::string(text).empty();
                const std::string pattern = empty ? "^$" : "key=([0-9])";
                const auto result = ComplianceEngine::EvaluateFileRegexContent(input, "stream:eof", pattern, regex(pattern), noState, context, noBound,
                    noBound, wholeFile, sink);
                ASSERT_TRUE(result.HasValue()) << "mode=" << wholeFile << " mask=" << mask << " text=" << text;
                EXPECT_EQ(empty ? 1U : (std::string(text) == "key=1\nkey=2" ? 2U : 1U), sink.occurrences.size());
                if (!empty && !sink.occurrences.empty())
                {
                    EXPECT_EQ("1", sink.occurrences[0].capturedValue);
                }
                if (std::string(text) == "key=1\nkey=2" && sink.occurrences.size() == 2)
                {
                    EXPECT_EQ("2", sink.occurrences[1].capturedValue);
                }
            }
        }
    }
}

TEST(FileRegexMatchErrorsTest, StreamExceptionMasksReturnLateReadFailureInBothModes)
{
    MockContext context;
    const ComplianceEngine::Optional<regex> noState{};
    const ComplianceEngine::Optional<long long> noBound{};
    for (const bool wholeFile : {false, true})
    {
        for (const auto mask : {std::ios::failbit, std::ios::badbit, std::ios::eofbit, static_cast<std::ios::iostate>(std::ios::failbit | std::ios::badbit),
                 static_cast<std::ios::iostate>(std::ios::failbit | std::ios::eofbit), static_cast<std::ios::iostate>(std::ios::badbit | std::ios::eofbit),
                 static_cast<std::ios::iostate>(std::ios::failbit | std::ios::badbit | std::ios::eofbit)})
        {
            FailingContentBuffer buffer("key=1\nkey=2\n", 8);
            std::istream input(&buffer);
            input.exceptions(mask);
            CollectingOccurrenceSink sink;
            const auto result = ComplianceEngine::EvaluateFileRegexContent(input, "stream:late-masked", "key=([0-9])", regex("key=([0-9])"), noState,
                context, noBound, noBound, wholeFile, sink);
            ASSERT_FALSE(result.HasValue()) << "mode=" << wholeFile << " mask=" << mask;
            EXPECT_EQ(EIO, result.Error().code);
            EXPECT_EQ("Failed to read file: stream:late-masked", result.Error().message);
        }
    }
}

TEST(FileRegexMatchErrorsTest, FileFinalizationFailurePreventsOrdinaryContentResult)
{
    MockContext context;
    const ComplianceEngine::Optional<regex> noState{};
    const ComplianceEngine::Optional<long long> noBound{};
    for (const bool wholeFile : {false, true})
    {
        std::istringstream input("key=1\n");
        input.exceptions(static_cast<std::ios::iostate>(std::ios::failbit | std::ios::badbit));
        CollectingOccurrenceSink sink;
        size_t closes = 0;
        const auto result = ComplianceEngine::EvaluateFileRegexContentAndFinalize(input, "stream:close", "key=([0-9])", regex("key=([0-9])"), noState,
            context, noBound, noBound, wholeFile, sink, [&]() -> ComplianceEngine::Result<bool> {
                ++closes;
                return ComplianceEngine::Error("injected close failure", EIO);
            });
        ASSERT_FALSE(result.HasValue());
        EXPECT_EQ("injected close failure", result.Error().message);
        EXPECT_EQ(EIO, result.Error().code);
        EXPECT_EQ(1U, closes);
        EXPECT_EQ(1U, sink.occurrences.size());
    }
}

TEST(FileRegexMatchErrorsTest, FirstReadFailureSurvivesSubsequentCloseFailure)
{
    MockContext context;
    const ComplianceEngine::Optional<regex> noState{};
    const ComplianceEngine::Optional<long long> noBound{};
    for (const bool wholeFile : {false, true})
    {
        FailingContentBuffer buffer("key=1\nkey=2\n", 8);
        std::istream input(&buffer);
        input.exceptions(static_cast<std::ios::iostate>(std::ios::failbit | std::ios::badbit));
        CollectingOccurrenceSink sink;
        size_t closes = 0;
        const auto result = ComplianceEngine::EvaluateFileRegexContentAndFinalize(input, "stream:read-first", "key=([0-9])", regex("key=([0-9])"),
            noState, context, noBound, noBound, wholeFile, sink, [&]() -> ComplianceEngine::Result<bool> {
                ++closes;
                return ComplianceEngine::Error("injected close failure", EIO);
            });
        ASSERT_FALSE(result.HasValue());
        EXPECT_EQ("Failed to read file: stream:read-first", result.Error().message);
        EXPECT_EQ(EIO, result.Error().code);
        EXPECT_EQ(1U, closes);
    }
}

TEST(FileRegexMatchErrorsTest, StreamProducerRejectsAlreadyFailedInputInsteadOfTreatingItAsEmpty)
{
    MockContext context;
    const ComplianceEngine::Optional<regex> noState{};
    const ComplianceEngine::Optional<long long> noBound{};
    for (const bool wholeFile : {false, true})
    {
        for (const auto state : {std::ios::badbit, static_cast<std::ios::iostate>(std::ios::failbit | std::ios::eofbit)})
        {
            std::istringstream input("key=1");
            input.setstate(state);
            CollectingOccurrenceSink sink;
            const auto result = ComplianceEngine::EvaluateFileRegexContent(input, "stream:pre-failed", "key", regex("key"), noState, context, noBound,
                noBound, wholeFile, sink);
            ASSERT_FALSE(result.HasValue());
            EXPECT_EQ(EIO, result.Error().code);
            EXPECT_TRUE(sink.occurrences.empty());
        }
    }
}

TEST(FileRegexMatchErrorsTest, NonIoStreambufExceptionsBecomeResultsAndAlwaysFinalize)
{
    MockContext context;
    const ComplianceEngine::Optional<regex> noState{};
    const ComplianceEngine::Optional<long long> noBound{};
    for (const bool wholeFile : {false, true})
    {
        for (const auto failure : {ThrowingContentBuffer::Failure::Runtime, ThrowingContentBuffer::Failure::Allocation, ThrowingContentBuffer::Failure::Unknown})
        {
            for (const auto mask : {std::ios::badbit, static_cast<std::ios::iostate>(std::ios::failbit | std::ios::badbit | std::ios::eofbit)})
            {
                ThrowingContentBuffer buffer(failure);
                std::istream input(&buffer);
                input.exceptions(mask);
                CollectingOccurrenceSink sink;
                size_t closes = 0;
                const auto result = ComplianceEngine::EvaluateFileRegexContentAndFinalize(input, "stream:original-exception", "key=([0-9])",
                    regex("key=([0-9])"), noState, context, noBound, noBound, wholeFile, sink, [&]() -> ComplianceEngine::Result<bool> {
                        ++closes;
                        return true;
                    });
                ASSERT_FALSE(result.HasValue()) << "mode=" << wholeFile << " mask=" << mask;
                EXPECT_EQ(failure == ThrowingContentBuffer::Failure::Allocation ? ENOMEM : EIO, result.Error().code);
                if (failure != ThrowingContentBuffer::Failure::Allocation)
                {
                    EXPECT_EQ("Failed to read file: stream:original-exception", result.Error().message);
                }
                EXPECT_EQ(1U, closes);
            }
        }
    }
}

TEST(FileRegexMatchErrorsTest, FinalizerExceptionsAreResultsWithFirstContentErrorPrecedence)
{
    MockContext context;
    const ComplianceEngine::Optional<regex> noState{};
    const ComplianceEngine::Optional<long long> noBound{};
    for (const bool wholeFile : {false, true})
    {
        for (const bool contentError : {false, true})
        {
            for (const int failure : {0, 1, 2, 3, 4}) // runtime, nonstandard, allocation, I/O, empty callback
            {
                FailingContentBuffer buffer("key=1\nkey=2\n", contentError ? 8 : std::string::npos);
                std::istream input(&buffer);
                input.exceptions(static_cast<std::ios::iostate>(std::ios::failbit | std::ios::badbit | std::ios::eofbit));
                CollectingOccurrenceSink sink;
                size_t closes = 0;
                std::function<ComplianceEngine::Result<bool>()> finalize;
                if (failure != 4)
                {
                    finalize = [&]() -> ComplianceEngine::Result<bool> {
                        ++closes;
                        switch (failure)
                        {
                            case 0:
                                throw std::runtime_error("injected finalizer failure");
                            case 1:
                                throw 42;
                            case 2:
                                throw std::bad_alloc();
                            case 3:
                                throw std::ios_base::failure("injected close failure");
                        }
                        return true;
                    };
                }
                const auto result = ComplianceEngine::EvaluateFileRegexContentAndFinalize(input, "stream:finalizer-exception", "key=([0-9])",
                    regex("key=([0-9])"), noState, context, noBound, noBound, wholeFile, sink, finalize);
                ASSERT_FALSE(result.HasValue()) << "mode=" << wholeFile << " contentError=" << contentError << " failure=" << failure;
                EXPECT_EQ(contentError ? EIO : (failure == 2 ? ENOMEM : (failure == 4 ? EINVAL : EIO)), result.Error().code);
                EXPECT_EQ(contentError ? "Failed to read file: stream:finalizer-exception" :
                          failure == 2 ? "Failed to allocate file regex finalization evidence" :
                          failure == 4 ? "Missing file finalizer: stream:finalizer-exception" :
                                         "Failed to close file: stream:finalizer-exception",
                    result.Error().message);
                EXPECT_EQ(failure == 4 ? 0U : 1U, closes);
                if (!contentError)
                {
                    EXPECT_EQ(2U, sink.occurrences.size());
                }
            }
        }
    }
}
