// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <cerrno>
#include <gtest/gtest.h>
#include <parsers/NameserverSelection.h>
#include <string>
#include <utility>
#include <vector>

namespace Selection = ComplianceEngine::NameserverSelection;

namespace
{
std::vector<std::string> Captures(const Selection::Document& document)
{
    std::vector<std::string> values;
    for (const auto& capture : document.captures)
    {
        values.push_back(document.bytes.substr(capture.offset, capture.length));
    }
    return values;
}
} // namespace

TEST(NameserverSelectionTest, PreservesSourceBytesOrderDuplicatesAndOffsets)
{
    const std::string bytes =
        " nameserver ignored\n"
        "nameserver 192.0.2.1 # retained\r\n"
        "nameserver 192.0.2.1 # retained\r\n"
        "nameserver \n  198.51.100.1\n";
    const auto result = Selection::Select(bytes, "/etc/resolv.conf");
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(bytes, result.Value().bytes);
    EXPECT_EQ("/etc/resolv.conf", result.Value().source);
    EXPECT_EQ((std::vector<std::string>{"192.0.2.1 # retained\r", "192.0.2.1 # retained\r", "198.51.100.1"}), Captures(result.Value()));
    for (const auto& capture : result.Value().captures)
    {
        EXPECT_EQ(0, bytes.compare(capture.anchor, 10, "nameserver"));
        EXPECT_TRUE((0 == capture.anchor) || ('\n' == bytes[capture.anchor - 1]));
        EXPECT_LE(capture.offset, bytes.size());
        EXPECT_LE(capture.length, bytes.size() - capture.offset);
    }
    EXPECT_EQ(bytes.find("192.0.2.1"), result.Value().captures.front().offset);
}

TEST(NameserverSelectionTest, ConsumesAllSixWhitespaceBytesIncludingLineCrossings)
{
    for (const char whitespace : std::string(" \t\n\r\v\f"))
    {
        const auto result = Selection::Select(std::string("nameserver") + whitespace + " \t\n\r\v\fvalue", "fixture");
        ASSERT_TRUE(result.HasValue());
        EXPECT_EQ((std::vector<std::string>{"value"}), Captures(result.Value()));
        ASSERT_EQ(1U, result.Value().captures.size());
        EXPECT_EQ(0U, result.Value().captures.front().anchor);
        EXPECT_EQ(result.Value().bytes.find("value"), result.Value().captures.front().offset);
    }
}

TEST(NameserverSelectionTest, DoesNotApplyLineBasedResolvConfInterpretation)
{
    const auto result = Selection::Select("nameserver\nnameserver 192.0.2.1\nnameserver two # comment", "fixture");
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ((std::vector<std::string>{"nameserver 192.0.2.1", "two # comment"}), Captures(result.Value()));
}

TEST(NameserverSelectionTest, PreservesBinaryCaptureBytes)
{
    const std::string value("a\0\x80\r", 4);
    const auto result = Selection::Select("nameserver " + value + "\n", "fixture");
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ((std::vector<std::string>{value}), Captures(result.Value()));
}

TEST(NameserverSelectionTest, RequiresLineAnchorAndWhitespaceAfterExactKeyword)
{
    std::string bytes = " nameserver one\nNameserver two\nnameserverx three\n# nameserver four\nnameserver";
    bytes += std::string("\0", 1) + "five\nnameserver";
    bytes += std::string("\x80", 1) + "six\nnameserver";
    const auto result = Selection::Select(bytes, "fixture");
    ASSERT_TRUE(result.HasValue());
    EXPECT_TRUE(result.Value().captures.empty());
}

TEST(NameserverSelectionTest, EmptyAndUnmatchedInputAreSuccessfulEmptySelections)
{
    for (const auto& bytes : {"", "# no matches\n", "nameserver"})
    {
        const auto result = Selection::Select(bytes, "fixture");
        ASSERT_TRUE(result.HasValue());
        EXPECT_TRUE(result.Value().captures.empty());
    }
}

TEST(NameserverSelectionTest, EofDoesNotSynthesizeANewlineAndAllowsEmptyCapture)
{
    for (const auto& bytes : {"nameserver ", "nameserver \n", "nameserver \t\n\r\v\f"})
    {
        const auto result = Selection::Select(bytes, "fixture");
        ASSERT_TRUE(result.HasValue());
        EXPECT_EQ((std::vector<std::string>{""}), Captures(result.Value()));
        EXPECT_EQ(result.Value().bytes.size(), result.Value().captures.front().offset);
    }
    const auto result = Selection::Select("nameserver value", "fixture");
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ((std::vector<std::string>{"value"}), Captures(result.Value()));
}

TEST(NameserverSelectionTest, OwnedInputAndOffsetsSurviveDocumentMove)
{
    auto result = Selection::Select(std::string("nameserver value"), "fixture");
    ASSERT_TRUE(result.HasValue());
    auto document = std::move(result.Value());
    auto moved = std::move(document);
    EXPECT_EQ((std::vector<std::string>{"value"}), Captures(moved));
}

TEST(NameserverSelectionTest, SelectionLimitsAreIndependentAndInclusive)
{
    const std::string bytes = "nameserver one\nnameserver two";
    for (std::size_t bound = 1; bound <= 3; ++bound)
    {
        Selection::Limits limits;
        limits.occurrences = bound;
        auto result = Selection::Select(bytes, "fixture", limits);
        EXPECT_EQ(2 <= bound, result.HasValue());
        if (!result.HasValue())
        {
            EXPECT_EQ(E2BIG, result.Error().code);
        }
    }
    for (std::size_t bound = 2; bound <= 4; ++bound)
    {
        Selection::Limits limits;
        limits.captureBytes = bound;
        const auto result = Selection::Select(bytes, "fixture", limits);
        EXPECT_EQ(3 <= bound, result.HasValue());
        if (!result.HasValue())
        {
            EXPECT_EQ(E2BIG, result.Error().code);
        }
    }
    for (std::size_t bound = 5; bound <= 7; ++bound)
    {
        Selection::Limits limits;
        limits.capturedBytes = bound;
        const auto result = Selection::Select(bytes, "fixture", limits);
        EXPECT_EQ(6 <= bound, result.HasValue());
        if (!result.HasValue())
        {
            EXPECT_EQ(E2BIG, result.Error().code);
        }
    }
}

TEST(NameserverSelectionTest, RejectsZeroLimitsEvenForUnmatchedInput)
{
    for (auto member : {&Selection::Limits::occurrences, &Selection::Limits::captureBytes, &Selection::Limits::capturedBytes})
    {
        Selection::Limits limits;
        limits.*member = 0;
        const auto result = Selection::Select("", "fixture", limits);
        ASSERT_FALSE(result.HasValue());
        EXPECT_EQ(EINVAL, result.Error().code);
        EXPECT_NE(std::string::npos, result.Error().message.find("fixture"));
    }
}
