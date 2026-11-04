// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <array>
#include <cerrno>
#include <gtest/gtest.h>
#include <parsers/ResolvConf.hpp>
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
    std::vector<rc::Entry> records;
    std::vector<rc::Span> operands;
};

// Flatten only operand spans for the old lexical-evidence assertions; all
// decoded value assertions below inspect typed alternatives directly.
std::vector<rc::Span> Operands(const rc::Entry& entry)
{
    std::vector<rc::Span> spans;
    const auto& directive = entry.directive;
    if (directive.Is<rc::Nameserver>())
        spans.push_back(directive.Get<rc::Nameserver>().token);
    else if (directive.Is<rc::Domain>())
    {
        const auto& token = directive.Get<rc::Domain>().token;
        if (token.HasValue())
            spans.push_back(token.Value());
    }
    else if (directive.Is<rc::Search>())
        spans = directive.Get<rc::Search>().names;
    else if (directive.Is<rc::Sortlist>())
    {
        for (const auto& item : directive.Get<rc::Sortlist>().entries)
            spans.push_back(item.Is<rc::Ipv4Sort>() ? item.Get<rc::Ipv4Sort>().token : item.Get<rc::UnverifiedIpv6Sort>().token);
    }
    else if (directive.Is<rc::Options>())
    {
        for (const auto& item : directive.Get<rc::Options>().entries)
        {
            if (item.Is<rc::NumericOption>())
                spans.push_back(item.Get<rc::NumericOption>().token);
            else if (item.Is<rc::FlagOption>())
                spans.push_back(item.Get<rc::FlagOption>().token);
            else
                spans.push_back(item.Get<rc::UnknownOption>().token);
        }
    }
    return spans;
}

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
        snapshot.entries.push_back(entry.Value().text);
        for (auto span : Operands(entry.Value()))
            snapshot.operands.push_back(span);
        snapshot.records.push_back(std::move(entry.Value()));
    }
    auto finished = parser.Finish(rc::Acquisition::Eof);
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
    EXPECT_TRUE(doc.records[0].directive.Is<rc::Blank>());
    EXPECT_TRUE(doc.records[1].directive.Is<rc::Comment>());
    EXPECT_TRUE(doc.records[2].directive.Is<rc::Comment>());
    ASSERT_EQ(1U, doc.operands.size());
    const auto& server = doc.records[3].directive.Get<rc::Nameserver>();
    EXPECT_TRUE(server.address.Is<rc::Ipv4>());
    EXPECT_EQ(4U, server.token.line);
    EXPECT_EQ("192.0.2.1", Text(doc, server.token));
    EXPECT_EQ(1U, doc.records[3].record.tokens[0].column);
    EXPECT_EQ(12U, doc.records[3].record.tokens[1].column);
    EXPECT_EQ(input, std::vector<std::string>({"", "# hello", "; comment", "nameserver\t192.0.2.1  ", ""}));
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
    EXPECT_TRUE(doc.records[4].directive.Is<rc::Search>());
    ASSERT_EQ(13U, doc.operands.size());
    EXPECT_EQ((std::array<unsigned char, 16>{{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}}),
        doc.records[1].directive.Get<rc::Nameserver>().address.Get<rc::Ipv6>().bytes);
    EXPECT_EQ((std::array<unsigned char, 4>{{192, 0, 2, 1}}), doc.records[0].directive.Get<rc::Nameserver>().address.Get<rc::Ipv4>().bytes);
    EXPECT_EQ("old.example", Text(doc, doc.records[3].directive.Get<rc::Domain>().token.Value()));
    const auto& sort = doc.records[5].directive.Get<rc::Sortlist>().entries;
    ASSERT_EQ(2U, sort.size());
    const auto& first = sort[0].Get<rc::Ipv4Sort>();
    EXPECT_TRUE(first.mask.HasValue());
    EXPECT_EQ((std::array<unsigned char, 4>{{130, 155, 160, 0}}), first.address.bytes);
    EXPECT_EQ((std::array<unsigned char, 4>{{255, 255, 240, 0}}), first.mask.Value().bytes);
    EXPECT_FALSE(sort[1].Get<rc::Ipv4Sort>().mask.HasValue());
    EXPECT_EQ((std::array<unsigned char, 4>{{130, 155, 0, 0}}), sort[1].Get<rc::Ipv4Sort>().address.bytes);
    const auto& options = doc.records[6].directive.Get<rc::Options>().entries;
    ASSERT_EQ(5U, options.size());
    EXPECT_EQ(16U, options[0].Get<rc::NumericOption>().value);
    EXPECT_EQ(15U, options[0].Get<rc::NumericOption>().documentedCap);
    EXPECT_EQ("ndots:016", Text(doc, options[0].Get<rc::NumericOption>().token));
    EXPECT_EQ(31U, options[1].Get<rc::NumericOption>().value);
    EXPECT_EQ(30U, options[1].Get<rc::NumericOption>().documentedCap);
    EXPECT_EQ(5U, options[2].Get<rc::NumericOption>().documentedCap);
    EXPECT_TRUE(options[3].Is<rc::FlagOption>());
    EXPECT_EQ(2U, options[4].Get<rc::NumericOption>().value);
}

TEST(ResolvConfTest, Glibc239KnownFlagsRemainIndividualOrderedEvidence)
{
    const std::vector<std::string> flags = {
        "rotate", "edns0", "single-request-reopen", "single-request", "no_tld_query", "no-tld-query", "no-reload", "use-vc", "trust-ad", "no-aaaa"};
    std::string line = "options";
    for (const auto& flag : flags)
        line += " " + flag;
    const auto parsed = ParseFixture({line}, "resolver");
    ASSERT_TRUE(parsed.HasValue());
    const auto& options = parsed.Value().records[0].directive.Get<rc::Options>().entries;
    ASSERT_EQ(flags.size(), options.size());
    for (std::size_t i = 0; i < flags.size(); ++i)
    {
        ASSERT_TRUE(options[i].Is<rc::FlagOption>());
        EXPECT_EQ(flags[i], Text(parsed.Value(), options[i].Get<rc::FlagOption>().token));
    }
}

TEST(ResolvConfTest, UnknownAndUnverifiedInputRemainOwnedEvidence)
{
    const std::vector<std::string> lines = {"search a#literal b;literal", "options mystery", "NAMEserver 192.0.2.2", "sortlist 2001:db8::1",
        "# comment with \xFF", "options \"rotate\"", "search a\r"};
    const auto parsed = ParseFixture(lines, "resolv");
    ASSERT_TRUE(parsed.HasValue());
    const auto& doc = parsed.Value();
    EXPECT_EQ(lines, doc.entries);
    EXPECT_TRUE(doc.records[2].directive.Is<rc::Unknown>());
    ASSERT_EQ(6U, doc.operands.size());
    EXPECT_TRUE(doc.records[1].directive.Get<rc::Options>().entries[0].Is<rc::UnknownOption>());
    EXPECT_TRUE(doc.records[3].directive.Get<rc::Sortlist>().entries[0].Is<rc::UnverifiedIpv6Sort>());
    EXPECT_EQ("a\r", Text(doc, doc.records[6].directive.Get<rc::Search>().names.back()));
}

TEST(ResolvConfTest, MalformedKnownInputFailsNextAndIsSticky)
{
    for (const auto& text : {"nameserver ", "nameserver invalid", "nameserver 192.0.2.1\r", "options ndots:", "options ndots:1x",
             "options attempts:42949672960", "sortlist bad/255.0.0.0", "sortlist 192.0.2.0/", "sortlist 192.0.2.0/255.0.0.0/255.0.0.0"})
    {
        rc::Parser parser("src");
        ASSERT_TRUE(parser.Next("search example.org").HasValue());
        const auto failed = parser.Next(text);
        ASSERT_FALSE(failed.HasValue()) << text;
        EXPECT_EQ(EBADMSG, failed.Error().code);
        EXPECT_NE(std::string::npos, failed.Error().message.find("src: resolv.conf"));
        EXPECT_EQ(failed.Error().message, parser.Next("").Error().message);
        EXPECT_EQ(failed.Error().message, parser.Finish(rc::Acquisition::Eof).Error().message);
    }
    rc::Parser nul("src");
    const auto embedded = nul.Next(std::string("nameserver 192.0.2.1") + std::string("\0tail", 5));
    ASSERT_FALSE(embedded.HasValue());
    EXPECT_EQ(EBADMSG, embedded.Error().code);
    EXPECT_NE(std::string::npos, embedded.Error().message.find("embedded NUL"));
    rc::Parser later("src");
    ASSERT_TRUE(later.Next("nameserver 192.0.2.1").HasValue());
    EXPECT_EQ(EIO, later.Finish(ComplianceEngine::Error("late read failure", EIO)).Error().code);
}

template <typename T>
bool Matches(const rc::DirectiveValue& value)
{
    return value.Is<T>();
}

TEST(ResolvConfTest, Glibc239LexerPreservesIgnoredTextAndExactOperands)
{
    struct Case
    {
        std::string line;
        bool (*matches)(const rc::DirectiveValue&);
        std::vector<std::string> operands;
    };
    const std::vector<Case> cases = {
        {"# first-column", &Matches<rc::Comment>, {}},
        {"; first-column", &Matches<rc::Comment>, {}},
        {" # indented", &Matches<rc::Unknown>, {}},
        {"\tnameserver 192.0.2.1", &Matches<rc::Unknown>, {}},
        {" nameserver 192.0.2.1", &Matches<rc::Unknown>, {}},
        {"nameserver", &Matches<rc::Unknown>, {}},
        {"nameserver\r 192.0.2.1", &Matches<rc::Unknown>, {}},
        {"nameserverx 192.0.2.1", &Matches<rc::Unknown>, {}},
        {"domain", &Matches<rc::Unknown>, {}},
        {"search", &Matches<rc::Unknown>, {}},
        {"sortlist", &Matches<rc::Unknown>, {}},
        {"options", &Matches<rc::Unknown>, {}},
        {"nameserver 192.0.2.1 # trailing; unknown", &Matches<rc::Nameserver>, {"192.0.2.1"}},
        {"domain example.org # trailing", &Matches<rc::Domain>, {"example.org"}},
        {"domain example.org;attached trailing", &Matches<rc::Domain>, {"example.org;attached"}},
        {"search one # two; three\r", &Matches<rc::Search>, {"one", "#", "two;", "three\r"}},
        {"sortlist 192.0.2.0&255.255.255.0 198.51.100.0/255.255.255.0;end 203.0.113.0", &Matches<rc::Sortlist>,
            {"192.0.2.0&255.255.255.0", "198.51.100.0/255.255.255.0"}},
        {"sortlist 192.0.2.0 ; comment 198.51.100.0", &Matches<rc::Sortlist>, {"192.0.2.0"}},
        {"options rotate#x ndots:2 # timeout:3", &Matches<rc::Options>, {"rotate#x", "ndots:2", "#", "timeout:3"}},
        {"options rotate;tail no_tld_query:extra", &Matches<rc::Options>, {"rotate;tail", "no_tld_query:extra"}},
        {"options debug inet6 mystery", &Matches<rc::Options>, {"debug", "inet6", "mystery"}},
        {"options \t", &Matches<rc::Options>, {}},
        {"domain \t", &Matches<rc::Domain>, {}},
        {"search \t", &Matches<rc::Search>, {}},
    };
    for (const auto& fixture : cases)
    {
        SCOPED_TRACE(fixture.line);
        rc::Parser parser("fixture");
        auto entry = parser.Next(fixture.line);
        ASSERT_TRUE(entry.HasValue());
        EXPECT_EQ("fixture", entry.Value().source);
        EXPECT_EQ(fixture.line, entry.Value().text);
        EXPECT_TRUE(fixture.matches(entry.Value().directive));
        const auto operands = Operands(entry.Value());
        ASSERT_EQ(fixture.operands.size(), operands.size());
        for (std::size_t i = 0; i < fixture.operands.size(); ++i)
        {
            const auto span = operands[i];
            EXPECT_EQ(1U, span.line);
            EXPECT_EQ(fixture.operands[i], entry.Value().text.substr(span.column - 1, span.length));
        }
        if (entry.Value().directive.Is<rc::Nameserver>() && !fixture.operands.empty())
        {
            ASSERT_GT(entry.Value().record.tokens.size(), 2U);
            const auto trailing = entry.Value().record.tokens[2];
            EXPECT_EQ("#", entry.Value().text.substr(trailing.column - 1, trailing.length));
        }
        if (fixture.line == "options rotate#x ndots:2 # timeout:3")
        {
            const auto& options = entry.Value().directive.Get<rc::Options>().entries;
            EXPECT_TRUE(options[0].Is<rc::FlagOption>());
            EXPECT_EQ(2U, options[1].Get<rc::NumericOption>().value);
            EXPECT_TRUE(options[2].Is<rc::UnknownOption>());
            EXPECT_TRUE(options[3].Is<rc::NumericOption>());
        }
        if (fixture.line == "options debug inet6 mystery")
        {
            for (const auto& option : entry.Value().directive.Get<rc::Options>().entries)
                EXPECT_TRUE(option.Is<rc::UnknownOption>());
        }
        if (entry.Value().directive.Is<rc::Sortlist>() && !fixture.operands.empty())
            EXPECT_EQ(fixture.operands.front().find_first_of("&/") != std::string::npos,
                entry.Value().directive.Get<rc::Sortlist>().entries.front().Get<rc::Ipv4Sort>().mask.HasValue());
        EXPECT_TRUE(parser.Finish(rc::Acquisition::Eof).HasValue());
    }
}

TEST(ResolvConfTest, AttachedBadValuesFailButSeparatedTrailingTextIsIgnored)
{
    const std::vector<std::string> bad = {"nameserver 192.0.2.1#tail", "nameserver 192.0.2.1;trailing", "nameserver 192.0.2.1\r",
        "sortlist 192.0.2.0#attached", "sortlist 192.0.2.0/invalid;tail", "options ndots:2#tail", "options timeout:3;tail"};
    for (const auto& line : bad)
    {
        SCOPED_TRACE(line);
        rc::Parser parser("fixture");
        EXPECT_EQ(EBADMSG, parser.Next(line).Error().code);
        EXPECT_EQ(EBADMSG, parser.Finish(ComplianceEngine::Error("late read failure", EIO)).Error().code);
    }
}

TEST(ResolvConfTest, ExactBudgetBoundariesAndFatalVersusEmpty)
{
    rc::Limits limits;
    limits.bytes = 3;
    limits.lineBytes = 2;
    limits.entries = 2;
    limits.tokens = 2;
    const auto within = ParseFixture({"xx", "x"}, "src", limits);
    ASSERT_TRUE(within.HasValue()); // 3 bytes, 2 entries, 2 tokens.

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
    ASSERT_TRUE(first.Value().directive.Is<rc::Nameserver>());
    EXPECT_EQ("src", first.Value().source);
    EXPECT_EQ("192.0.2.1", first.Value().text.substr(first.Value().directive.Get<rc::Nameserver>().token.column - 1,
                               first.Value().directive.Get<rc::Nameserver>().token.length));
    auto unknown = parser.Next("mystery \xFF");
    ASSERT_TRUE(unknown.HasValue());
    EXPECT_TRUE(unknown.Value().directive.Is<rc::Unknown>());
    EXPECT_EQ(2U, unknown.Value().record.line);
    EXPECT_EQ(1U, unknown.Value().record.tokens.front().column);
    EXPECT_EQ("nameserver 192.0.2.1  ", first.Value().text); // Not overwritten by Next.
    EXPECT_EQ("src", first.Value().source);
    EXPECT_TRUE(first.Value().directive.Get<rc::Nameserver>().address.Is<rc::Ipv4>());
    EXPECT_TRUE(parser.Finish(rc::Acquisition::Eof).HasValue());

    rc::Entry retained;
    {
        rc::Parser transient("persist");
        auto value = transient.Next("options rotate");
        ASSERT_TRUE(value.HasValue());
        retained = std::move(value.Value());
        ASSERT_TRUE(transient.Finish(rc::Acquisition::Eof).HasValue());
    }
    EXPECT_EQ("persist", retained.source);
    EXPECT_EQ("rotate", retained.text.substr(retained.directive.Get<rc::Options>().entries[0].Get<rc::FlagOption>().token.column - 1,
                            retained.directive.Get<rc::Options>().entries[0].Get<rc::FlagOption>().token.length));

    // Each result can be destroyed immediately. Thousands of entries do not
    // require a caller-owned vector or a document buffered by the parser.
    rc::Limits limits;
    limits.entries = 5000;
    limits.tokens = 5000;
    rc::Parser discard("src", limits);
    for (std::size_t i = 0; i < limits.entries; ++i)
    {
        auto entry = discard.Next("x");
        ASSERT_TRUE(entry.HasValue()) << i;
        EXPECT_EQ(i + 1, entry.Value().record.line);
        EXPECT_EQ("x", entry.Value().text);
    }
    EXPECT_TRUE(discard.Finish(rc::Acquisition::Eof).HasValue());
}

TEST(ResolvConfTest, CompletionRequiresExplicitVerifiedAcquisition)
{
    rc::Parser empty("src");
    EXPECT_TRUE(empty.Finish(rc::Acquisition::Eof).HasValue()); // Caller reports verified EOF.
    EXPECT_EQ(EINVAL, empty.Finish(rc::Acquisition::Eof).Error().code);

    rc::Parser early("src");
    ASSERT_TRUE(early.Next("search example.org").HasValue());
    // An entry being available does not certify EOF.
    const auto incomplete = early.Finish(rc::Acquisition::Incomplete);
    ASSERT_FALSE(incomplete.HasValue());
    EXPECT_EQ(EIO, incomplete.Error().code);
    EXPECT_EQ(incomplete.Error().message, early.Finish(rc::Acquisition::Eof).Error().message);
    EXPECT_EQ(EIO, early.Next("domain example.org").Error().code);

    rc::Parser readError("src");
    ASSERT_TRUE(readError.Next("nameserver 192.0.2.1").HasValue());
    const auto lateRead = readError.Finish(ComplianceEngine::Error("late reader failure", EIO));
    ASSERT_FALSE(lateRead.HasValue());
    EXPECT_EQ("late reader failure", lateRead.Error().message);
    EXPECT_EQ("late reader failure", readError.Finish(rc::Acquisition::Eof).Error().message);

    rc::Parser done("src");
    ASSERT_TRUE(done.Next("").HasValue());
    ASSERT_TRUE(done.Finish(rc::Acquisition::Eof).HasValue());
    EXPECT_EQ(EINVAL, done.Next("").Error().code);
    EXPECT_EQ(EINVAL, done.Finish(rc::Acquisition::Eof).Error().code);

    rc::Parser lateReadFailure("src");
    ASSERT_TRUE(lateReadFailure.Finish(rc::Acquisition::Eof).HasValue());
    const auto reportedLate = lateReadFailure.Finish(ComplianceEngine::Error("late read failure", EIO));
    ASSERT_FALSE(reportedLate.HasValue());
    EXPECT_EQ(EIO, reportedLate.Error().code);
    EXPECT_EQ("late read failure", lateReadFailure.Finish(rc::Acquisition::Eof).Error().message);
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
            reader.Close();
            return parser.Finish(rc::Acquisition::Incomplete);
        }
    }
    reader.Close();
    return parser.Finish(rc::Acquisition::Eof);
}

TEST(ResolvConfTest, FakeReaderSequencesEOFReadAndEarlyBreakDespiteCloseFailure)
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
    EXPECT_TRUE(AcquireFixture(closeParser, closeFailure, false).HasValue());
    EXPECT_TRUE(closeFailure.eof);
    EXPECT_TRUE(closeFailure.closed);

    // Error discovered after an earlier (incorrect) completion report must
    // not be swallowed by a repeated-success path.
    rc::Parser late("src");
    ASSERT_TRUE(late.Finish(rc::Acquisition::Eof).HasValue());
    const auto reported = late.Finish(ComplianceEngine::Error("late read failure", EIO));
    EXPECT_EQ(EIO, reported.Error().code);
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
            EXPECT_TRUE(line.Finish(rc::Acquisition::Eof).HasValue());
    }
    // Comments avoid tokens while consuming the entire byte budget.
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
            EXPECT_EQ(overflow.Error().message, bytes.Finish(rc::Acquisition::Eof).Error().message);
        }
        else
            EXPECT_TRUE(bytes.Finish(rc::Acquisition::Eof).HasValue());
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
            EXPECT_TRUE(entries.Finish(rc::Acquisition::Eof).HasValue());
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
            EXPECT_TRUE(tokens.Finish(rc::Acquisition::Eof).HasValue());
    }
}

TEST(ResolvConfTest, EmptyCompletionAndErrorPrecedence)
{
    rc::Parser incomplete("src");
    EXPECT_EQ(EIO, incomplete.Finish(rc::Acquisition::Incomplete).Error().code);
    rc::Parser failed("src");
    EXPECT_EQ("read failed", failed.Finish(ComplianceEngine::Error("read failed", EIO)).Error().message);
    rc::Parser complete("src");
    EXPECT_TRUE(complete.Finish(rc::Acquisition::Eof).HasValue());
    EXPECT_EQ(EBADF, complete.Finish(ComplianceEngine::Error("late read failure", EBADF)).Error().code);
    EXPECT_EQ(EBADF, complete.Next("").Error().code);
    rc::Parser malformed("src");
    ASSERT_FALSE(malformed.Next("nameserver invalid").HasValue());
    EXPECT_EQ(EBADMSG, malformed.Finish(rc::Acquisition::Eof).Error().code);
}

TEST(ResolvConfTest, CumulativeLimitsAndFailureAreStickyAfterEarlierEvidence)
{
    rc::Limits limits;
    limits.bytes = 3;
    limits.lineBytes = 2;
    limits.entries = 4; // Reach the byte limit before the entry limit.
    limits.tokens = 3;
    rc::Parser parser("src", limits);
    auto first = parser.Next("x");
    ASSERT_TRUE(first.HasValue());
    auto second = parser.Next("y");
    ASSERT_TRUE(second.HasValue());
    EXPECT_TRUE(first.Value().directive.Is<rc::Unknown>());
    EXPECT_TRUE(second.Value().directive.Is<rc::Unknown>());
    const auto failure = parser.Next("z");
    ASSERT_TRUE(failure.HasValue());
    EXPECT_TRUE(failure.Value().directive.Is<rc::Unknown>());
    const auto overflow = parser.Next("x");
    ASSERT_FALSE(overflow.HasValue());
    EXPECT_EQ(E2BIG, overflow.Error().code);
    EXPECT_NE(std::string::npos, overflow.Error().message.find("byte limit"));
    EXPECT_EQ(overflow.Error().message, parser.Next("").Error().message);
    EXPECT_EQ(overflow.Error().message, parser.Finish(rc::Acquisition::Eof).Error().message);
    EXPECT_EQ(overflow.Error().message, parser.Finish(ComplianceEngine::Error("read failed", EIO)).Error().message);

    rc::Parser bytes("src", limits);
    ASSERT_TRUE(bytes.Next("xx").HasValue());
    ASSERT_TRUE(bytes.Next("x").HasValue());
    EXPECT_NE(std::string::npos, bytes.Next("x").Error().message.find("byte limit"));
    EXPECT_FALSE(bytes.Finish(rc::Acquisition::Eof).HasValue());

    limits.entries = 3;
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
    EXPECT_EQ(EINVAL, invalid.Finish(rc::Acquisition::Eof).Error().code);
    EXPECT_EQ(EINVAL, invalid.Next("").Error().code);
}
} // namespace
