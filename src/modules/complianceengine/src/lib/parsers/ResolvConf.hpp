// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef COMPLIANCEENGINE_PARSERS_RESOLV_CONF_HPP
#define COMPLIANCEENGINE_PARSERS_RESOLV_CONF_HPP

#include <Optional.h>
#include <Result.h>
#include <Variant.hpp>
#include <array>
#include <cstddef>
#include <string>
#include <vector>

namespace ComplianceEngine
{
namespace ResolvConf
{
// Starter budgets, not resolver limits. All counts include unknown input.
struct Limits
{
    std::size_t bytes = std::size_t{1024} * 1024;
    std::size_t lineBytes = std::size_t{16} * 1024;
    std::size_t entries = 8192;
    std::size_t tokens = 32768;
};

// 1-based physical entry/byte column; length is a half-open span in that
// entry. There is no offset for a stripped LF and no inferred final LF.
struct Span
{
    std::size_t line = 0;
    std::size_t column = 0;
    std::size_t length = 0;

    Span() = default;
    Span(std::size_t lineValue, std::size_t columnValue, std::size_t lengthValue)
        : line(lineValue),
          column(columnValue),
          length(lengthValue)
    {
    }
};

// The raw tokens always include the keyword (if present), including ignored
// trailing operands. Parsed fields identify only the operands actually used.
struct Record
{
    std::size_t line = 0;
    std::vector<Span> tokens;
};

struct Blank
{
};
struct Comment
{
};
struct Unknown
{
};

struct Ipv4
{
    std::array<unsigned char, 4> bytes{};
};
struct Ipv6
{
    std::array<unsigned char, 16> bytes{};
};
using Address = Variant<Ipv4, Ipv6>;

struct Nameserver
{
    Span token;
    Address address;
};
struct Domain
{
    Optional<Span> token; // May be absent; domain-name grammar is unverified.
};
struct Search
{
    std::vector<Span> names; // Domain-name byte grammar is unverified.
};
struct Ipv4Sort
{
    Span token;
    Ipv4 address;
    Optional<Ipv4> mask; // Absence is not a fabricated natural mask.
};
struct UnverifiedIpv6Sort
{
    Span token;
    Ipv6 address;
    Optional<Span> mask; // Raw spelling; IPv6 pair semantics are unverified.
};
using SortEntry = Variant<Ipv4Sort, UnverifiedIpv6Sort>;
struct Sortlist
{
    std::vector<SortEntry> entries;
};
struct NumericOption
{
    Span token;
    unsigned int value;
    unsigned int documentedCap; // Not an asserted effective runtime value.
};
struct FlagOption
{
    Span token; // Availability/deprecation is not resolved.
};
struct UnknownOption
{
    Span token;
};
using Option = Variant<NumericOption, FlagOption, UnknownOption>;
struct Options
{
    std::vector<Option> entries;
};
using DirectiveValue = Variant<Blank, Comment, Nameserver, Domain, Search, Sortlist, Options, Unknown>;

// One owned physical entry. Until Finish succeeds this evidence is provisional.
// Spans identify 1-based physical lines and columns in the owned text.
struct Entry
{
    std::string source;
    std::string text; // Exact LF-stripped bytes, including trivia.
    Record record;
    DirectiveValue directive{InPlaceType<Blank>{}, Blank{}};
};

// This is the caller's REPORT, not a fact independently verified by Parser.
// EofAndClosed requires a real EOF and a successful checked Close; an early
// break is Incomplete. Forward read/Close failures as Error instead.
enum class Acquisition
{
    EofAndClosed,
    Incomplete
};

// Feed LF-stripped physical entries one at a time (e.g. Filesystem::LinesRange
// values). No reader or whole-file buffer is owned by this parser. Next
// returns owned, per-entry evidence; callers can consume/discard it promptly.
// Until Finish succeeds every returned entry is provisional, NOT a completed
// aggregate result. A fatal error is sticky and the failing entry is not
// published; previously emitted entries cannot be retroactively revoked.
// glibc 2.39 resolv/res_init.c is the lexical reference:
// https://github.com/bminor/glibc/blob/glibc-2.39/resolv/res_init.c
// Only first-column
// space/tab-delimited keywords match; first-column # and ; are comments.
// Unknown/unverified evidence is retained, including ignored trailing text.
// Recognized malformed values fail Next with a sticky EBADMSG Error instead
// of publishing a partial entry (unlike glibc's runtime ignore/fallback).
class Parser
{
public:
    explicit Parser(std::string source, Limits limits = {});
    Result<Entry> Next(std::string text);
    // Call once after EOF and checked Close, or report incomplete iteration
    // or an acquisition Error. The parser cannot observe unseen input or
    // independently verify EOF/Close. Empty input requires the same report.
    // Repeated Finish is misuse (EINVAL); a later reported Error supersedes
    // an earlier success, but cannot revoke evidence already published.
    // Earlier parser/acquisition errors remain sticky.
    // Example: for each read value call Next(value); after EOF check Close;
    // then Finish(Acquisition::EofAndClosed), or Finish(read/Close Error).
    // EINVAL: zero budget/invalid call; E2BIG: exceeded budget; EBADMSG:
    // malformed supplied entry.
    Result<bool> Finish(Result<Acquisition> acquisition);

private:
    std::string mSource;
    Limits mLimits;
    std::size_t mBytes = 0;
    std::size_t mEntries = 0;
    std::size_t mTokens = 0;
    Result<bool> mCompletion = true;
    bool mFinished = false;
};
} // namespace ResolvConf
} // namespace ComplianceEngine

#endif // COMPLIANCEENGINE_PARSERS_RESOLV_CONF_HPP
