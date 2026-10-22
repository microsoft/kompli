// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <cerrno>
#include <gtest/gtest.h>
#include <parsers/ResolvConf.h>
#include <string>
#include <vector>

namespace
{
namespace rc = ComplianceEngine::ResolvConf;

std::string Text(const rc::Document& doc, rc::Span span)
{
    return doc.entries.at(span.line - 1).substr(span.column - 1, span.length);
}

TEST(ResolvConfTest, EmptySuccessAndOwnedLFStrippedEntries)
{
    const auto empty = rc::Parse({}, "logical");
    ASSERT_TRUE(empty.HasValue());
    EXPECT_EQ("logical", empty.Value().source);
    EXPECT_TRUE(empty.Value().records.empty());

    std::vector<std::string> input = {"", "# hello", "; comment", "nameserver\t192.0.2.1  ", ""};
    const auto parsed = rc::Parse(input, "logical");
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
        rc::Parse({"nameserver 192.0.2.1", "nameserver 2001:db8::1", "search example.org example.net", "domain old.example", "search newer.example",
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
    const auto parsed = rc::Parse({line}, "resolver");
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
    const auto parsed = rc::Parse(lines, "resolv");
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
    const auto within = rc::Parse({"xx", "x"}, "src", limits);
    ASSERT_TRUE(within.HasValue()); // 3 bytes, 2 entries, 2 tokens, 2 diagnostics.
    EXPECT_EQ(2U, within.Value().diagnostics.size());

    const auto bytes = rc::Parse({"xx", "xx"}, "src", limits);
    ASSERT_FALSE(bytes.HasValue());
    EXPECT_EQ(E2BIG, bytes.Error().code);
    EXPECT_NE(std::string::npos, bytes.Error().message.find("byte limit"));

    const auto line = rc::Parse({"xxx"}, "src", limits);
    ASSERT_FALSE(line.HasValue());
    EXPECT_NE(std::string::npos, line.Error().message.find("line limit"));

    const auto entries = rc::Parse({"", "", ""}, "src", limits);
    ASSERT_FALSE(entries.HasValue());
    EXPECT_NE(std::string::npos, entries.Error().message.find("entry limit"));

    limits.bytes = 10;
    limits.lineBytes = 10;
    const auto tokens = rc::Parse({"a b c"}, "src", limits);
    ASSERT_FALSE(tokens.HasValue());
    EXPECT_NE(std::string::npos, tokens.Error().message.find("token limit"));

    limits.entries = 3;
    const auto diagnostics = rc::Parse({"x", "y", "z"}, "src", limits);
    ASSERT_FALSE(diagnostics.HasValue());
    EXPECT_NE(std::string::npos, diagnostics.Error().message.find("diagnostic limit"));

    limits.bytes = 0;
    const auto badLimits = rc::Parse({}, "src", limits);
    ASSERT_FALSE(badLimits.HasValue());
    EXPECT_EQ(EINVAL, badLimits.Error().code);
    EXPECT_TRUE(rc::Parse({}, "src").HasValue());
}
} // namespace
