// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <array>
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
    auto finished = parser.Finish(rc::Acquisition::EofAndClosed);
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
    EXPECT_EQ((std::array<unsigned char, 16>{{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}}), doc.projections[1].address);
    EXPECT_EQ((std::array<unsigned char, 16>{{192, 0, 2, 1}}), doc.projections[0].address);
    EXPECT_EQ(rc::ValueKind::DomainName, doc.projections[4].kind);
    EXPECT_EQ(rc::Status::Unverified, doc.projections[4].status);
    EXPECT_EQ(rc::ValueKind::SortPair, doc.projections[6].kind);
    EXPECT_TRUE(doc.projections[6].hasMask);
    EXPECT_EQ(4U, doc.projections[6].addressBytes);
    EXPECT_EQ((std::array<unsigned char, 16>{{130, 155, 160, 0}}), doc.projections[6].address);
    EXPECT_EQ((std::array<unsigned char, 16>{{255, 255, 240, 0}}), doc.projections[6].mask);
    EXPECT_FALSE(doc.projections[7].hasMask);
    EXPECT_EQ((std::array<unsigned char, 16>{{130, 155, 0, 0}}), doc.projections[7].address);
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
    ASSERT_FALSE(doc.projections.empty());
    EXPECT_EQ(3U, doc.projections[0].token.line);
    EXPECT_EQ(12U, doc.projections[0].token.column);
    EXPECT_EQ(rc::Status::Invalid, doc.projections[0].status);
    ASSERT_GE(doc.diagnostics.size(), 4U);
    EXPECT_EQ(3U, doc.diagnostics[2].span.line);
    EXPECT_EQ(20U, doc.diagnostics[2].span.column);
    EXPECT_EQ("extra directive operand", doc.diagnostics[2].message);
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

TEST(ResolvConfTest, ParsedTokenDoesNotValidateMalformedEntry)
{
    rc::Parser parser("src");
    const auto entry = parser.Next("nameserver 192.0.2.1 junk");
    ASSERT_TRUE(entry.HasValue());
    EXPECT_EQ("nameserver 192.0.2.1 junk", entry.Value().text);
    EXPECT_EQ(rc::Directive::Malformed, entry.Value().record.directive);
    EXPECT_TRUE(entry.Value().hasMalformedEvidence);
    ASSERT_EQ(3U, entry.Value().record.tokens.size());
    EXPECT_EQ(1U, entry.Value().record.line);
    EXPECT_EQ(22U, entry.Value().record.tokens[2].column);
    ASSERT_EQ(1U, entry.Value().diagnostics.size());
    EXPECT_EQ(rc::DiagnosticKind::Malformed, entry.Value().diagnostics[0].kind);
    EXPECT_EQ("extra directive operand", entry.Value().diagnostics[0].message);
    EXPECT_EQ(1U, entry.Value().diagnostics[0].span.line);
    EXPECT_EQ(22U, entry.Value().diagnostics[0].span.column);
    ASSERT_EQ(1U, entry.Value().projections.size());
    EXPECT_EQ(rc::Status::Parsed, entry.Value().projections[0].status);
    EXPECT_EQ(rc::ValueKind::Nameserver, entry.Value().projections[0].kind);
    EXPECT_EQ(12U, entry.Value().projections[0].token.column);
    EXPECT_EQ(1U, entry.Value().projections[0].token.line);
    EXPECT_EQ((std::array<unsigned char, 16>{{192, 0, 2, 1}}), entry.Value().projections[0].address);
    EXPECT_TRUE(parser.Finish(rc::Acquisition::EofAndClosed).HasValue());
    // Completion of acquisition is not validation of a malformed record.
    rc::Parser later("src");
    ASSERT_TRUE(later.Next("nameserver 192.0.2.1").HasValue());
    EXPECT_EQ(EIO, later.Finish(ComplianceEngine::Error("late Close failure", EIO)).Error().code);
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
    EXPECT_TRUE(parser.Finish(rc::Acquisition::EofAndClosed).HasValue());

    rc::Entry retained;
    {
        rc::Parser transient("persist");
        auto value = transient.Next("options rotate");
        ASSERT_TRUE(value.HasValue());
        retained = std::move(value.Value());
        ASSERT_TRUE(transient.Finish(rc::Acquisition::EofAndClosed).HasValue());
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
    EXPECT_TRUE(discard.Finish(rc::Acquisition::EofAndClosed).HasValue());
}

TEST(ResolvConfTest, CompletionRequiresExplicitVerifiedAcquisition)
{
    rc::Parser empty("src");
    EXPECT_TRUE(empty.Finish(rc::Acquisition::EofAndClosed).HasValue()); // Caller reports checked EOF and Close.
    EXPECT_EQ(EINVAL, empty.Finish(rc::Acquisition::EofAndClosed).Error().code);

    rc::Parser early("src");
    ASSERT_TRUE(early.Next("search example.org").HasValue());
    // An entry being available does not certify EOF or Close.
    const auto incomplete = early.Finish(rc::Acquisition::Incomplete);
    ASSERT_FALSE(incomplete.HasValue());
    EXPECT_EQ(EIO, incomplete.Error().code);
    EXPECT_EQ(incomplete.Error().message, early.Finish(rc::Acquisition::EofAndClosed).Error().message);
    EXPECT_EQ(EIO, early.Next("domain example.org").Error().code);

    rc::Parser readError("src");
    ASSERT_TRUE(readError.Next("nameserver 192.0.2.1").HasValue());
    const auto lateRead = readError.Finish(ComplianceEngine::Error("late reader failure", EIO));
    ASSERT_FALSE(lateRead.HasValue());
    EXPECT_EQ("late reader failure", lateRead.Error().message);
    EXPECT_EQ("late reader failure", readError.Finish(rc::Acquisition::EofAndClosed).Error().message);

    rc::Parser closeError("src");
    ASSERT_TRUE(closeError.Next("search a").HasValue());
    EXPECT_EQ(EBADF, closeError.Finish(ComplianceEngine::Error("Close failed", EBADF)).Error().code);

    rc::Parser done("src");
    ASSERT_TRUE(done.Next("").HasValue());
    ASSERT_TRUE(done.Finish(rc::Acquisition::EofAndClosed).HasValue());
    EXPECT_EQ(EINVAL, done.Next("").Error().code);
    EXPECT_EQ(EINVAL, done.Finish(rc::Acquisition::EofAndClosed).Error().code);

    rc::Parser falselyCompleted("src");
    ASSERT_TRUE(falselyCompleted.Finish(rc::Acquisition::EofAndClosed).HasValue());
    const auto reportedLate = falselyCompleted.Finish(ComplianceEngine::Error("late Close failure", EBADF));
    ASSERT_FALSE(reportedLate.HasValue());
    EXPECT_EQ(EBADF, reportedLate.Error().code);
    EXPECT_EQ("late Close failure", falselyCompleted.Finish(rc::Acquisition::EofAndClosed).Error().message);
}

// In-memory stand-in for an external reader. The test deliberately owns
// sequencing; the parser never claims to have inspected this reader.
struct FakeAcquisition
{
    explicit FakeAcquisition(std::vector<std::string> input = {})
        : lines(std::move(input))
    {
    }
    std::vector<std::string> lines;
    std::size_t position = 0;
    bool eof = false;
    bool closed = false;
    bool failRead = false;
    bool failClose = false;
    std::string current;

    ComplianceEngine::Result<bool> Read()
    {
        if (failRead && position > 0)
            return ComplianceEngine::Error("read failed", EIO);
        if (position == lines.size())
        {
            eof = true;
            return false;
        }
        current = lines[position++];
        return true;
    }

    ComplianceEngine::Result<bool> Close()
    {
        closed = true;
        if (failClose)
            return ComplianceEngine::Error("close failed", EBADF);
        return true;
    }
};

ComplianceEngine::Result<bool> AcquireFixture(rc::Parser& parser, FakeAcquisition& reader, bool earlyBreak)
{
    while (true)
    {
        const auto read = reader.Read();
        if (!read.HasValue())
        {
            const auto closed = reader.Close();
            (void)closed; // First reported read error takes precedence.
            return parser.Finish(read.Error());
        }
        if (!read.Value())
            break;
        auto entry = parser.Next(reader.current);
        if (!entry.HasValue())
        {
            reader.Close();
            return parser.Finish(entry.Error());
        }
        if (earlyBreak)
        {
            const auto closed = reader.Close();
            if (!closed.HasValue())
                return parser.Finish(closed.Error());
            return parser.Finish(rc::Acquisition::Incomplete);
        }
    }
    const auto closed = reader.Close();
    if (!closed.HasValue())
        return parser.Finish(closed.Error());
    return parser.Finish(rc::Acquisition::EofAndClosed);
}

TEST(ResolvConfTest, FakeReaderSequencesEOFReadCloseAndEarlyBreak)
{
    FakeAcquisition normal{{"nameserver 192.0.2.1"}};
    rc::Parser parser("src");
    EXPECT_TRUE(AcquireFixture(parser, normal, false).HasValue());
    EXPECT_TRUE(normal.eof);
    EXPECT_TRUE(normal.closed);
    EXPECT_EQ(1U, normal.position);

    FakeAcquisition empty;
    rc::Parser emptyParser("src");
    EXPECT_TRUE(AcquireFixture(emptyParser, empty, false).HasValue());
    EXPECT_TRUE(empty.eof);
    EXPECT_TRUE(empty.closed);

    FakeAcquisition early{{"search a", "search b"}};
    rc::Parser earlyParser("src");
    EXPECT_EQ(EIO, AcquireFixture(earlyParser, early, true).Error().code);
    EXPECT_FALSE(early.eof);
    EXPECT_TRUE(early.closed);
    EXPECT_EQ(1U, early.position);

    FakeAcquisition readFailure{{"search a"}};
    readFailure.failRead = true;
    rc::Parser readParser("src");
    EXPECT_EQ("read failed", AcquireFixture(readParser, readFailure, false).Error().message);
    EXPECT_TRUE(readFailure.closed);
    EXPECT_FALSE(readFailure.eof);
    EXPECT_EQ(1U, readFailure.position);

    FakeAcquisition closeFailure{{"search a"}};
    closeFailure.failClose = true;
    rc::Parser closeParser("src");
    EXPECT_EQ("close failed", AcquireFixture(closeParser, closeFailure, false).Error().message);
    EXPECT_TRUE(closeFailure.eof);
    EXPECT_TRUE(closeFailure.closed);

    // Error discovered after an earlier (incorrect) completion report must
    // not be swallowed by a repeated-success path.
    rc::Parser late("src");
    ASSERT_TRUE(late.Finish(rc::Acquisition::EofAndClosed).HasValue());
    closeFailure.failClose = true;
    const auto reported = late.Finish(closeFailure.Close().Error());
    EXPECT_EQ(EBADF, reported.Error().code);
}

TEST(ResolvConfTest, EveryDefaultBudgetAtMinusOneExactAndPlusOne)
{
    const rc::Limits limits;
    const std::string fullLine = "#" + std::string(limits.lineBytes - 1, 'a');
    for (const auto delta : {-1, 0, 1})
    {
        SCOPED_TRACE(delta);
        const auto length = static_cast<std::size_t>(static_cast<int>(limits.lineBytes) + delta);
        rc::Parser line("src");
        const auto entry = line.Next("#" + std::string(length - 1, 'a'));
        EXPECT_EQ(delta != 1, entry.HasValue());
        if (delta == 1)
            EXPECT_NE(std::string::npos, entry.Error().message.find("line limit"));
        else
            EXPECT_TRUE(line.Finish(rc::Acquisition::EofAndClosed).HasValue());
    }
    // Comments avoid tokens/diagnostics while consuming the entire byte budget.
    for (const auto delta : {-1, 0, 1})
    {
        SCOPED_TRACE(delta);
        rc::Parser bytes("src");
        for (std::size_t i = 0; i < limits.bytes / limits.lineBytes; ++i)
        {
            std::string text = fullLine;
            if ((delta == -1) && (i == limits.bytes / limits.lineBytes - 1))
                text.pop_back();
            ASSERT_TRUE(bytes.Next(text).HasValue()) << i;
        }
        if (delta == 1)
        {
            const auto overflow = bytes.Next("#");
            ASSERT_FALSE(overflow.HasValue());
            EXPECT_NE(std::string::npos, overflow.Error().message.find("byte limit"));
            EXPECT_EQ(overflow.Error().message, bytes.Finish(rc::Acquisition::EofAndClosed).Error().message);
        }
        else
            EXPECT_TRUE(bytes.Finish(rc::Acquisition::EofAndClosed).HasValue());
    }
    for (const auto delta : {-1, 0, 1})
    {
        SCOPED_TRACE(delta);
        rc::Parser entries("src");
        const auto count = static_cast<std::size_t>(static_cast<int>(limits.entries) + delta);
        for (std::size_t i = 0; i < count; ++i)
        {
            const auto next = entries.Next("");
            if (i == limits.entries)
            {
                ASSERT_FALSE(next.HasValue());
                EXPECT_NE(std::string::npos, next.Error().message.find("entry limit"));
            }
            else
                ASSERT_TRUE(next.HasValue()) << i;
        }
        if (delta != 1)
            EXPECT_TRUE(entries.Finish(rc::Acquisition::EofAndClosed).HasValue());
    }
    // Eight 4096-token entries, then the last token at N+1. No line is
    // longer than 8193 bytes, so this isolates the cumulative token budget.
    std::string tokenGroup;
    for (std::size_t i = 0; i < 4096; ++i)
        tokenGroup += "x ";
    for (const auto delta : {-1, 0, 1})
    {
        SCOPED_TRACE(delta);
        rc::Parser tokens("src");
        for (std::size_t i = 0; i < 7; ++i)
            ASSERT_TRUE(tokens.Next(tokenGroup).HasValue()) << i;
        std::string last = tokenGroup;
        if (delta == -1)
            last.erase(last.size() - 2);
        ASSERT_TRUE(tokens.Next(last).HasValue());
        if (delta == 1)
        {
            const auto overflow = tokens.Next("x");
            ASSERT_FALSE(overflow.HasValue());
            EXPECT_NE(std::string::npos, overflow.Error().message.find("token limit"));
        }
        else
            EXPECT_TRUE(tokens.Finish(rc::Acquisition::EofAndClosed).HasValue());
    }
    // A single large physical line exhausts diagnostics without hitting
    // the byte, token or line limits; N+1 is never published.
    for (const auto delta : {-1, 0, 1})
    {
        SCOPED_TRACE(delta);
        rc::Parser diagnostics("src");
        const auto count = static_cast<std::size_t>(static_cast<int>(limits.diagnostics) + delta);
        const auto next = diagnostics.Next("#" + std::string(count, '\r'));
        if (delta == 1)
        {
            ASSERT_FALSE(next.HasValue());
            EXPECT_NE(std::string::npos, next.Error().message.find("diagnostic limit"));
            EXPECT_EQ(next.Error().message, diagnostics.Next("").Error().message);
            EXPECT_EQ(next.Error().message, diagnostics.Finish(rc::Acquisition::EofAndClosed).Error().message);
        }
        else
        {
            ASSERT_TRUE(next.HasValue());
            EXPECT_EQ(count, next.Value().diagnostics.size());
            EXPECT_TRUE(diagnostics.Finish(rc::Acquisition::EofAndClosed).HasValue());
        }
    }
}

TEST(ResolvConfTest, EmptyCompletionAndErrorPrecedence)
{
    rc::Parser incomplete("src");
    EXPECT_EQ(EIO, incomplete.Finish(rc::Acquisition::Incomplete).Error().code);
    rc::Parser failed("src");
    EXPECT_EQ("read failed", failed.Finish(ComplianceEngine::Error("read failed", EIO)).Error().message);
    rc::Parser complete("src");
    EXPECT_TRUE(complete.Finish(rc::Acquisition::EofAndClosed).HasValue());
    EXPECT_EQ(EBADF, complete.Finish(ComplianceEngine::Error("late Close failure", EBADF)).Error().code);
    EXPECT_EQ(EBADF, complete.Next("").Error().code);
    rc::Parser malformed("src");
    ASSERT_TRUE(malformed.Next("nameserver invalid").HasValue());
    EXPECT_TRUE(malformed.Finish(rc::Acquisition::EofAndClosed).HasValue()); // Invalid record is evidence, not fatal.
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
    EXPECT_EQ(failure.Error().message, parser.Finish(rc::Acquisition::EofAndClosed).Error().message);
    EXPECT_EQ(failure.Error().message, parser.Finish(ComplianceEngine::Error("read failed", EIO)).Error().message);

    limits.diagnostics = 3;
    rc::Parser bytes("src", limits);
    ASSERT_TRUE(bytes.Next("xx").HasValue());
    ASSERT_TRUE(bytes.Next("x").HasValue());
    EXPECT_NE(std::string::npos, bytes.Next("x").Error().message.find("byte limit"));
    EXPECT_FALSE(bytes.Finish(rc::Acquisition::EofAndClosed).HasValue());

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
    EXPECT_EQ(EINVAL, invalid.Finish(rc::Acquisition::EofAndClosed).Error().code);
    EXPECT_EQ(EINVAL, invalid.Next("").Error().code);
}
} // namespace
