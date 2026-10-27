// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <cerrno>
#include <gtest/gtest.h>
#include <parsers/ResolvConf.h>
#include <string>
#include <utility>
#include <vector>

namespace
{
namespace rc = ComplianceEngine::ResolvConf;

// Test-only aggregation preserves the original grammar assertions. Production
// callers receive individual entries and need not retain any of these vectors.
struct Snapshot
{
    std::string source;
    std::vector<std::string> entries;
    std::vector<rc::Record> records;
    std::vector<rc::Projection> projections;
    std::vector<rc::Diagnostic> diagnostics;
};

ComplianceEngine::Result<Snapshot> ParseFixture(const std::vector<std::string>& lines, std::string source, rc::Limits limits = {})
{
    rc::Parser parser(source, limits);
    Snapshot snapshot;
    snapshot.source = std::move(source);
    for (const auto& line : lines)
    {
        auto entry = parser.Next(line);
        if (!entry.HasValue())
            return entry.Error();
        snapshot.entries.push_back(std::move(entry.Value().text));
        snapshot.records.push_back(std::move(entry.Value().record));
        for (auto& projection : entry.Value().projections)
            snapshot.projections.push_back(std::move(projection));
        for (auto& diagnostic : entry.Value().diagnostics)
            snapshot.diagnostics.push_back(std::move(diagnostic));
    }
    auto finished = parser.Finish(true);
    if (!finished.HasValue())
        return finished.Error();
    return snapshot;
}

std::string Text(const Snapshot& doc, rc::Span span)
{
    return doc.entries.at(span.line - 1).substr(span.column - 1, span.length);
}

TEST(ResolvConfTest, EmptySuccessAndOwnedLFStrippedEntries)
{
    const auto empty = ParseFixture({}, "logical");
    ASSERT_TRUE(empty.HasValue());
    EXPECT_EQ("logical", empty.Value().source);
    EXPECT_TRUE(empty.Value().records.empty());

    std::vector<std::string> input = {"", "# hello", "; comment", "nameserver\t192.0.2.1  ", ""};
    const auto parsed = ParseFixture(input, "logical");
    ASSERT_TRUE(parsed.HasValue());
    const auto& doc = parsed.Value();
    EXPECT_EQ(input, doc.entries);
    EXPECT_EQ(5U, doc.records.size());
    EXPECT_EQ(rc::Directive::Blank, doc.records[0].directive);
    EXPECT_EQ(rc::Directive::Comment, doc.records[1].directive);
    EXPECT_EQ(rc::Directive::Comment, doc.records[2].directive);
    ASSERT_EQ(1U, doc.projections.size());
    EXPECT_EQ(rc::Status::Parsed, doc.projections[0].status);
    EXPECT_EQ(4U, doc.projections[0].addressBytes);
    EXPECT_EQ(4U, doc.projections[0].token.line);
    EXPECT_EQ("192.0.2.1", Text(doc, doc.projections[0].token));
    EXPECT_EQ(1U, doc.records[3].tokens[0].column);
    EXPECT_EQ(12U, doc.records[3].tokens[1].column);
    EXPECT_EQ(input, std::vector<std::string>({"", "# hello", "; comment", "nameserver\t192.0.2.1  ", ""}));
    // The caller supplies entries, not LF/EOF information: no final-LF claim.
    EXPECT_EQ("", doc.entries.back());
}

TEST(ResolvConfTest, AllDirectivesDuplicatesAndNoEffectiveMerge)
{
    const auto parsed =
        ParseFixture({"nameserver 192.0.2.1", "nameserver 2001:db8::1", "search example.org example.net", "domain old.example", "search newer.example",
                         "sortlist 130.155.160.0/255.255.240.0 130.155.0.0", "options ndots:016 timeout:31 attempts:5 rotate ndots:2"},
            "resolver");
    ASSERT_TRUE(parsed.HasValue());
    const auto& doc = parsed.Value();
    ASSERT_EQ(7U, doc.records.size());
    EXPECT_EQ(rc::Directive::Search, doc.records[4].directive);
    ASSERT_EQ(13U, doc.projections.size());
    EXPECT_EQ(16U, doc.projections[1].addressBytes);
    EXPECT_EQ(rc::ValueKind::DomainName, doc.projections[4].kind);
    EXPECT_EQ(rc::Status::Unverified, doc.projections[4].status);
    EXPECT_EQ(rc::ValueKind::SortPair, doc.projections[6].kind);
    EXPECT_TRUE(doc.projections[6].hasMask);
    EXPECT_FALSE(doc.projections[7].hasMask);
    EXPECT_EQ(16U, doc.projections[8].number);
    EXPECT_EQ(15U, doc.projections[8].documentedCap);
    EXPECT_EQ("ndots:016", Text(doc, doc.projections[8].token));
    EXPECT_EQ(31U, doc.projections[9].number);
    EXPECT_EQ(30U, doc.projections[9].documentedCap);
    EXPECT_EQ(5U, doc.projections[10].documentedCap);
    EXPECT_EQ(rc::ValueKind::FlagOption, doc.projections[11].kind);
    EXPECT_EQ(2U, doc.projections[12].number);
    // Caps are documented metadata, not an effective resolver state.
    EXPECT_TRUE(doc.diagnostics.empty());
}

TEST(ResolvConfTest, AllDocumentedFlagsRemainIndividualOrderedEvidence)
{
    const std::vector<std::string> flags = {"debug", "rotate", "no-aaaa", "no-check-names", "inet6", "ip6-bytestring", "ip6-dotint", "no-ip6-dotint",
        "edns0", "single-request", "single-request-reopen", "no-tld-query", "use-vc", "no-reload", "trust-ad"};
    std::string line = "options";
    for (const auto& flag : flags)
        line += " " + flag;
    const auto parsed = ParseFixture({line}, "resolver");
    ASSERT_TRUE(parsed.HasValue());
    ASSERT_EQ(flags.size(), parsed.Value().projections.size());
    for (std::size_t i = 0; i < flags.size(); ++i)
    {
        EXPECT_EQ(flags[i], Text(parsed.Value(), parsed.Value().projections[i].token));
        EXPECT_EQ(rc::ValueKind::FlagOption, parsed.Value().projections[i].kind);
        EXPECT_EQ(rc::Status::Parsed, parsed.Value().projections[i].status);
    }
}

TEST(ResolvConfTest, MalformedUnknownAndUnverifiedInputNeverDisappears)
{
    const std::vector<std::string> lines = {" nameserver 192.0.2.1", "nameserver", "nameserver invalid trailing", "search a#literal b;literal",
        "domain a b", "sortlist bad/255.0.0.0", "options ndots: no-aaaa:extra attempts:42949672960 mystery", "NAMEserver 192.0.2.2", "options",
        "nameserver 192.0.2.1\r", "nameserver 192.0.2.1" + std::string("\0tail", 5), "sortlist 2001:db8::1", "# comment with \xFF",
        "options \"rotate\""};
    const auto parsed = ParseFixture(lines, "resolv");
    ASSERT_TRUE(parsed.HasValue());
    const auto& doc = parsed.Value();
    EXPECT_EQ(lines, doc.entries);
    EXPECT_EQ(rc::Directive::Malformed, doc.records[0].directive);
    EXPECT_EQ(rc::Directive::Malformed, doc.records[1].directive);
    EXPECT_EQ(rc::Directive::Malformed, doc.records[2].directive);
    EXPECT_EQ("trailing", Text(doc, doc.records[2].tokens[2]));
    EXPECT_EQ(rc::Directive::Malformed, doc.records[4].directive);
    EXPECT_EQ(rc::Directive::Unknown, doc.records[7].directive);
    EXPECT_EQ(rc::Directive::Malformed, doc.records[8].directive);
    bool sawUnknown = false, sawInvalid = false, sawUnverified = false, sawNul = false;
    for (const auto& diagnostic : doc.diagnostics)
    {
        EXPECT_GE(diagnostic.span.line, 1U);
        EXPECT_LE(diagnostic.span.line, lines.size());
        sawUnknown |= diagnostic.kind == rc::DiagnosticKind::Unknown;
        sawInvalid |= diagnostic.kind == rc::DiagnosticKind::Malformed;
        sawUnverified |= diagnostic.kind == rc::DiagnosticKind::Unverified;
        sawNul |= diagnostic.message == "embedded NUL";
    }
    EXPECT_TRUE(sawUnknown);
    EXPECT_TRUE(sawInvalid);
    EXPECT_TRUE(sawUnverified);
    EXPECT_TRUE(sawNul);
    bool sawIPv6Sort = false;
    for (const auto& projection : doc.projections)
        if (projection.kind == rc::ValueKind::SortPair && projection.status == rc::Status::Unverified)
            sawIPv6Sort = true;
    EXPECT_TRUE(sawIPv6Sort);
    // A NUL-suffixed address must not pass through inet_pton as a valid prefix.
    for (const auto& projection : doc.projections)
    {
        if (projection.token.line == 11)
        {
            EXPECT_EQ(rc::Status::Invalid, projection.status);
        }
    }
}

TEST(ResolvConfTest, ExactBudgetBoundariesAndFatalVersusEmpty)
{
    rc::Limits limits;
    limits.bytes = 3;
    limits.lineBytes = 2;
    limits.entries = 2;
    limits.tokens = 2;
    limits.diagnostics = 2;
    const auto within = ParseFixture({"xx", "x"}, "src", limits);
    ASSERT_TRUE(within.HasValue()); // 3 bytes, 2 entries, 2 tokens, 2 diagnostics.
    EXPECT_EQ(2U, within.Value().diagnostics.size());

    const auto bytes = ParseFixture({"xx", "xx"}, "src", limits);
    ASSERT_FALSE(bytes.HasValue());
    EXPECT_EQ(E2BIG, bytes.Error().code);
    EXPECT_NE(std::string::npos, bytes.Error().message.find("byte limit"));

    const auto line = ParseFixture({"xxx"}, "src", limits);
    ASSERT_FALSE(line.HasValue());
    EXPECT_NE(std::string::npos, line.Error().message.find("line limit"));

    const auto entries = ParseFixture({"", "", ""}, "src", limits);
    ASSERT_FALSE(entries.HasValue());
    EXPECT_NE(std::string::npos, entries.Error().message.find("entry limit"));

    limits.bytes = 10;
    limits.lineBytes = 10;
    const auto tokens = ParseFixture({"a b c"}, "src", limits);
    ASSERT_FALSE(tokens.HasValue());
    EXPECT_NE(std::string::npos, tokens.Error().message.find("token limit"));

    limits.entries = 3;
    limits.tokens = 3; // Reach the third unknown directive before exhausting diagnostics.
    const auto diagnostics = ParseFixture({"x", "y", "z"}, "src", limits);
    ASSERT_FALSE(diagnostics.HasValue());
    EXPECT_NE(std::string::npos, diagnostics.Error().message.find("diagnostic limit"));

    limits.bytes = 0;
    const auto badLimits = ParseFixture({}, "src", limits);
    ASSERT_FALSE(badLimits.HasValue());
    EXPECT_EQ(EINVAL, badLimits.Error().code);
    EXPECT_TRUE(ParseFixture({}, "src").HasValue());
}

TEST(ResolvConfTest, IncrementalEvidenceOwnsBytesAndDoesNotAccumulateInParser)
{
    rc::Parser parser("src");
    auto first = parser.Next("nameserver 192.0.2.1  ");
    ASSERT_TRUE(first.HasValue());
    ASSERT_EQ(1U, first.Value().projections.size());
    EXPECT_EQ("src", first.Value().source);
    EXPECT_EQ("192.0.2.1", first.Value().text.substr(first.Value().projections[0].token.column - 1, first.Value().projections[0].token.length));
    auto unknown = parser.Next("mystery \xFF");
    ASSERT_TRUE(unknown.HasValue());
    ASSERT_EQ(2U, unknown.Value().diagnostics.size());
    EXPECT_EQ(rc::Directive::Unknown, unknown.Value().record.directive);
    EXPECT_EQ(2U, unknown.Value().record.line);
    EXPECT_EQ(1U, unknown.Value().record.tokens.front().column);
    EXPECT_EQ("nameserver 192.0.2.1  ", first.Value().text); // Not overwritten by Next.
    EXPECT_EQ("src", first.Value().source);
    EXPECT_EQ(rc::Status::Parsed, first.Value().projections[0].status);
    EXPECT_TRUE(parser.Finish(true).HasValue());

    rc::Entry retained;
    {
        rc::Parser transient("persist");
        auto value = transient.Next("options rotate");
        ASSERT_TRUE(value.HasValue());
        retained = std::move(value.Value());
        ASSERT_TRUE(transient.Finish(true).HasValue());
    }
    EXPECT_EQ("persist", retained.source);
    EXPECT_EQ("rotate", retained.text.substr(retained.projections[0].token.column - 1, retained.projections[0].token.length));

    // Each result can be destroyed immediately. Thousands of entries do not
    // require a caller-owned vector or a document buffered by the parser.
    rc::Limits limits;
    limits.entries = 5000;
    limits.tokens = 5000;
    limits.diagnostics = 5000;
    rc::Parser discard("src", limits);
    for (std::size_t i = 0; i < limits.entries; ++i)
    {
        auto entry = discard.Next("x");
        ASSERT_TRUE(entry.HasValue()) << i;
        EXPECT_EQ(i + 1, entry.Value().record.line);
        ASSERT_EQ(1U, entry.Value().diagnostics.size());
        EXPECT_EQ(i + 1, entry.Value().diagnostics[0].span.line);
    }
    EXPECT_TRUE(discard.Finish(true).HasValue());
}

TEST(ResolvConfTest, CompletionRequiresExplicitVerifiedAcquisition)
{
    rc::Parser empty("src");
    EXPECT_TRUE(empty.Finish(true).HasValue()); // Zero entries, verified EOF.
    EXPECT_TRUE(empty.Finish(true).HasValue());

    rc::Parser early("src");
    ASSERT_TRUE(early.Next("search example.org").HasValue());
    // An entry being available does not certify EOF or Close.
    const auto incomplete = early.Finish(false);
    ASSERT_FALSE(incomplete.HasValue());
    EXPECT_EQ(EIO, incomplete.Error().code);
    EXPECT_EQ(incomplete.Error().message, early.Finish(true).Error().message);
    EXPECT_EQ(EIO, early.Next("domain example.org").Error().code);

    rc::Parser readError("src");
    ASSERT_TRUE(readError.Next("nameserver 192.0.2.1").HasValue());
    const auto lateRead = readError.Finish(ComplianceEngine::Error("late reader failure", EIO));
    ASSERT_FALSE(lateRead.HasValue());
    EXPECT_EQ("late reader failure", lateRead.Error().message);
    EXPECT_EQ("late reader failure", readError.Finish(true).Error().message);

    rc::Parser closeError("src");
    ASSERT_TRUE(closeError.Next("search a").HasValue());
    EXPECT_EQ(EBADF, closeError.Finish(ComplianceEngine::Error("Close failed", EBADF)).Error().code);

    rc::Parser done("src");
    ASSERT_TRUE(done.Next("").HasValue());
    ASSERT_TRUE(done.Finish(true).HasValue());
    EXPECT_EQ(EINVAL, done.Next("").Error().code);
    EXPECT_EQ(EINVAL, done.Finish(true).Error().code);
}

TEST(ResolvConfTest, CumulativeLimitsAndFailureAreStickyAfterEarlierEvidence)
{
    rc::Limits limits;
    limits.bytes = 3;
    limits.lineBytes = 2;
    limits.entries = 3;
    limits.tokens = 3;
    limits.diagnostics = 2;
    rc::Parser parser("src", limits);
    auto first = parser.Next("x");
    ASSERT_TRUE(first.HasValue());
    auto second = parser.Next("y");
    ASSERT_TRUE(second.HasValue());
    EXPECT_EQ(1U, first.Value().diagnostics.size());
    EXPECT_EQ(1U, second.Value().diagnostics.size());
    const auto failure = parser.Next("z");
    ASSERT_FALSE(failure.HasValue());
    EXPECT_EQ(E2BIG, failure.Error().code);
    EXPECT_NE(std::string::npos, failure.Error().message.find("diagnostic limit"));
    EXPECT_EQ(failure.Error().message, parser.Next("").Error().message);
    EXPECT_EQ(failure.Error().message, parser.Finish(true).Error().message);
    EXPECT_EQ(failure.Error().message, parser.Finish(ComplianceEngine::Error("read failed", EIO)).Error().message);

    limits.diagnostics = 3;
    rc::Parser bytes("src", limits);
    ASSERT_TRUE(bytes.Next("xx").HasValue());
    ASSERT_TRUE(bytes.Next("x").HasValue());
    EXPECT_NE(std::string::npos, bytes.Next("x").Error().message.find("byte limit"));
    EXPECT_FALSE(bytes.Finish(true).HasValue());

    rc::Parser entries("src", limits);
    ASSERT_TRUE(entries.Next("").HasValue());
    ASSERT_TRUE(entries.Next("").HasValue());
    ASSERT_TRUE(entries.Next("").HasValue());
    EXPECT_NE(std::string::npos, entries.Next("").Error().message.find("entry limit"));

    limits.tokens = 1;
    rc::Parser tokens("src", limits);
    ASSERT_TRUE(tokens.Next("x").HasValue());
    EXPECT_NE(std::string::npos, tokens.Next("y").Error().message.find("token limit"));

    limits.bytes = 0;
    rc::Parser invalid("src", limits);
    EXPECT_EQ(EINVAL, invalid.Finish(true).Error().code);
    EXPECT_EQ(EINVAL, invalid.Next("").Error().code);
}
} // namespace
