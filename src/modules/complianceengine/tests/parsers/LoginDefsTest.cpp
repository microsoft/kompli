// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <cerrno>
#include <gtest/gtest.h>
#include <parsers/LoginDefs.h>
#include <string>

namespace
{
namespace ld = ComplianceEngine::LoginDefs;

TEST(LoginDefsTest, EmptyAndCommentOnlyAreSuccessfulDocuments)
{
    const auto empty = ld::Parse("", "empty");
    ASSERT_TRUE(empty.HasValue());
    EXPECT_EQ("empty", empty.Value().source);
    EXPECT_TRUE(empty.Value().records.empty());
    EXPECT_TRUE(empty.Value().diagnostics.empty());

    const auto comments = ld::Parse(" \t# comment\n\n\t \n", "comments");
    ASSERT_TRUE(comments.HasValue());
    EXPECT_TRUE(comments.Value().records.empty());
    EXPECT_TRUE(comments.Value().diagnostics.empty());
}

TEST(LoginDefsTest, KeepsOrderedDuplicatesUnknownKeysAndPhysicalSpans)
{
    const auto parsed = ld::Parse("# ignored\n  UID_MIN\t1000 \nUNRECOGNIZED yes\nUID_MIN 2000", "logical");
    ASSERT_TRUE(parsed.HasValue());
    const auto& doc = parsed.Value();
    ASSERT_EQ(3U, doc.records.size());
    EXPECT_EQ("logical", doc.source);
    EXPECT_EQ("UID_MIN", doc.records[0].key);
    EXPECT_EQ("  UID_MIN\t1000 ", doc.Text(doc.records[0].lineSpan));
    EXPECT_EQ("UID_MIN", doc.Text(doc.records[0].keySpan));
    EXPECT_EQ("1000 ", doc.Text(doc.records[0].valueSpan));
    EXPECT_EQ(2U, doc.records[0].line);
    EXPECT_EQ(20U, doc.records[0].valueSpan.offset);
    EXPECT_EQ("UNRECOGNIZED", doc.records[1].key);
    EXPECT_EQ(3U, doc.records[1].line);
    EXPECT_EQ(4U, doc.records[2].line);
    const auto occurrences = doc.FindAll("UID_MIN");
    ASSERT_EQ(2U, occurrences.size());
    EXPECT_EQ(&doc.records[0], doc.FindFirst("UID_MIN"));
    EXPECT_EQ(&doc.records[2], doc.FindLast("UID_MIN"));
    EXPECT_EQ(&doc.records[0], occurrences[0]);
    EXPECT_EQ(&doc.records[2], occurrences[1]);
    EXPECT_EQ(nullptr, doc.FindFirst("uid_min"));
    EXPECT_TRUE(doc.diagnostics.empty());
}

TEST(LoginDefsTest, RetainsUnspecifiedValueSyntaxWithoutDecoding)
{
    const auto parsed = ld::Parse(
        "UID_MIN 1000 # note\nUID_MIN 1000#note\n"
        "UID_MIN \"1000#note\"\nUID_MIN 1000 extra\n"
        "UID_MIN 1000\\#note\nUID_MIN 1000\r\n",
        "source");
    ASSERT_TRUE(parsed.HasValue());
    const auto& doc = parsed.Value();
    ASSERT_EQ(6U, doc.records.size());
    EXPECT_EQ("1000 # note", doc.Text(doc.records[0].valueSpan));
    EXPECT_EQ("1000#note", doc.Text(doc.records[1].valueSpan));
    EXPECT_EQ("\"1000#note\"", doc.Text(doc.records[2].valueSpan));
    EXPECT_EQ("1000 extra", doc.Text(doc.records[3].valueSpan));
    EXPECT_EQ("1000\\#note", doc.Text(doc.records[4].valueSpan));
    EXPECT_EQ("1000\r", doc.Text(doc.records[5].valueSpan));
    EXPECT_EQ("UID_MIN 1000\r", doc.Text(doc.records[5].lineSpan));
    EXPECT_TRUE(doc.diagnostics.empty());
}

TEST(LoginDefsTest, RetainsMissingValuesAndLocatedDiagnostics)
{
    const auto parsed = ld::Parse("UID_MIN\nUID_MIN \t\nUID_MIN \"\"\nUID_MIN=1000\n", "source");
    ASSERT_TRUE(parsed.HasValue());
    const auto& doc = parsed.Value();
    ASSERT_EQ(4U, doc.records.size());
    ASSERT_EQ(3U, doc.diagnostics.size());
    EXPECT_FALSE(doc.records[0].hasValue);
    EXPECT_FALSE(doc.records[1].hasValue);
    EXPECT_TRUE(doc.records[2].hasValue);
    EXPECT_EQ("\"\"", doc.Text(doc.records[2].valueSpan));
    EXPECT_EQ("UID_MIN=1000", doc.records[3].key);
    EXPECT_FALSE(doc.records[3].hasValue);
    EXPECT_EQ(ld::Diagnostic::Kind::MissingValue, doc.diagnostics[0].kind);
    EXPECT_EQ(1U, doc.diagnostics[0].line);
    EXPECT_EQ(8U, doc.diagnostics[0].column);
    EXPECT_EQ(2U, doc.diagnostics[1].line);
    EXPECT_EQ(4U, doc.diagnostics[2].line);
}

TEST(LoginDefsTest, EmbeddedNulDoesNotTruncateLaterBytesOrLines)
{
    const std::string input = std::string("UID_MIN 1000\0junk\nUID_MIN 2000\n", 31);
    const auto parsed = ld::Parse(input, "source");
    ASSERT_TRUE(parsed.HasValue());
    const auto& doc = parsed.Value();
    ASSERT_EQ(2U, doc.records.size());
    EXPECT_EQ(std::string("1000\0junk", 9), doc.Text(doc.records[0].valueSpan));
    EXPECT_EQ("2000", doc.Text(doc.records[1].valueSpan));
    ASSERT_EQ(1U, doc.diagnostics.size());
    EXPECT_EQ(ld::Diagnostic::Kind::EmbeddedNul, doc.diagnostics[0].kind);
    EXPECT_EQ(1U, doc.diagnostics[0].line);
    EXPECT_EQ(13U, doc.diagnostics[0].column);
    EXPECT_EQ(12U, doc.diagnostics[0].span.offset);
}

TEST(LoginDefsTest, ByteBudgetRejectsOversizeInsteadOfReturningPartialDocument)
{
    std::string input;
    input.reserve(ld::MaxBytes + 1);
    for (std::size_t i = 0; i < ld::MaxBytes / 2; ++i)
    {
        input += "#\n";
    }
    EXPECT_TRUE(ld::Parse(input.substr(0, ld::MaxBytes - 1), "source").HasValue());
    EXPECT_TRUE(ld::Parse(input.substr(0, ld::MaxBytes), "source").HasValue());
    const auto excess = ld::Parse(input + "x", "source");
    ASSERT_FALSE(excess.HasValue());
    EXPECT_EQ(E2BIG, excess.Error().code);
}

TEST(LoginDefsTest, LineBudgetChecksBothSidesOfBoundary)
{
    const std::string line(ld::MaxLineBytes, '#');
    EXPECT_TRUE(ld::Parse(line.substr(0, ld::MaxLineBytes - 1), "source").HasValue());
    EXPECT_TRUE(ld::Parse(line, "source").HasValue());
    const auto excess = ld::Parse(line + "#", "source");
    ASSERT_FALSE(excess.HasValue());
    EXPECT_EQ(E2BIG, excess.Error().code);
}

TEST(LoginDefsTest, RecordBudgetChecksBothSidesOfBoundary)
{
    std::string records;
    for (std::size_t i = 0; i <= ld::MaxRecords; ++i)
    {
        records += "K 1\n";
    }
    EXPECT_TRUE(ld::Parse(records.substr(0, 4 * (ld::MaxRecords - 1)), "source").HasValue());
    EXPECT_TRUE(ld::Parse(records.substr(0, 4 * ld::MaxRecords), "source").HasValue());
    const auto excess = ld::Parse(records, "source");
    ASSERT_FALSE(excess.HasValue());
    EXPECT_EQ(E2BIG, excess.Error().code);
}

TEST(LoginDefsTest, DiagnosticBudgetChecksBothSidesOfBoundary)
{
    std::string lines;
    for (std::size_t i = 0; i <= ld::MaxDiagnostics; ++i)
    {
        lines.append("#\0\n", 3);
    }
    EXPECT_TRUE(ld::Parse(lines.substr(0, 3 * (ld::MaxDiagnostics - 1)), "source").HasValue());
    EXPECT_TRUE(ld::Parse(lines.substr(0, 3 * ld::MaxDiagnostics), "source").HasValue());
    const auto excess = ld::Parse(lines, "source");
    ASSERT_FALSE(excess.HasValue());
    EXPECT_EQ(E2BIG, excess.Error().code);
}
} // anonymous namespace
