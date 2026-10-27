// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef COMPLIANCEENGINE_PARSERS_RESOLV_CONF_H
#define COMPLIANCEENGINE_PARSERS_RESOLV_CONF_H

#include <Result.h>
#include <array>
#include <cstddef>
#include <string>
#include <vector>

namespace ComplianceEngine
{
namespace ResolvConf
{
// Starter budgets, not resolver limits. All counts include unknown/malformed input.
struct Limits
{
    std::size_t bytes = 1024 * 1024;
    std::size_t lineBytes = 16 * 1024;
    std::size_t entries = 8192;
    std::size_t tokens = 32768;
    std::size_t diagnostics = 8192;
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

enum class Directive
{
    Blank,
    Comment,
    Nameserver,
    Search,
    Domain,
    Sortlist,
    Options,
    Unknown,
    Malformed
};

enum class Status
{
    Parsed,     // Token-only decode; NOT record validity, aggregate completion or glibc effect.
    Unverified, // Manual leaves byte grammar or profile behavior open.
    Invalid,
    Unknown
};

enum class ValueKind
{
    Nameserver,
    SearchName,
    DomainName,
    SortPair,
    NumericOption,
    FlagOption,
    UnknownOption
};

struct Record
{
    Directive directive = Directive::Blank;
    std::size_t line = 0;
    std::vector<Span> tokens; // Keyword first; raw trivia remains in the owning entry.
};

struct Projection
{
    ValueKind kind = ValueKind::SearchName;
    Status status = Status::Unverified;
    Span token;
    // For parsed address/sort pair: 4 or 16 bytes; 0 otherwise. The optional
    // sort mask has its own presence bit; an omitted mask is not fabricated.
    std::size_t addressBytes = 0;
    std::array<unsigned char, 16> address{};
    bool hasMask = false;
    std::array<unsigned char, 16> mask{};
    // Numeric options only: parsed spelling and manual-documented cap, not
    // an asserted effective runtime value.
    unsigned int number = 0;
    unsigned int documentedCap = 0;
};

enum class DiagnosticKind
{
    Malformed,
    Unknown,
    Unverified
};

struct Diagnostic
{
    DiagnosticKind kind;
    Span span;
    std::string message;
};

// One owned physical entry and all of its evidence. Spans use physical entry
// numbers, so consumers may retain or discard each result independently.
// A projection's token identifies its entry (1-based line). Parsed projections
// may coexist with a malformed record or diagnostics: inspect the whole Entry
// before using any projection, and require successful Finish for completion.
struct Entry
{
    std::string source; // Owned source identity; valid after Parser destruction.
    std::string text;   // Exact LF-stripped supplied bytes, including trivia.
    Record record;
    std::vector<Projection> projections;
    std::vector<Diagnostic> diagnostics;
    // True when any malformed diagnostic was emitted, even if a token decoded.
    // False is NOT a certification of supported grammar or resolver behavior.
    bool hasMalformedEvidence = false;
};

// This is the caller's REPORT, not a fact independently verified by Parser.
// EofAndClosed requires a real EOF and a successful checked Close; an early
// break is Incomplete. Forward read/Close failures as Error instead.
enum class Acquisition
{
    EofAndClosed,
    Incomplete
};

// Feed LF-stripped physical entries one at a time (e.g. FileReader::Lines
// values). No reader or whole-file buffer is owned by this parser. Next
// returns owned, per-entry evidence; callers can consume/discard it promptly.
// Until Finish succeeds every returned entry is provisional, NOT a completed
// aggregate result. A fatal error is sticky and the failing entry is not
// published; previously emitted entries cannot be retroactively revoked.
// Space/tab are provisional separators. Only first-column # and ; are
// comments. Other ambiguous syntax is retained and flagged, never dropped.
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
    // EINVAL: zero budget/invalid call; E2BIG: exceeded budget.
    Result<bool> Finish(Result<Acquisition> acquisition);

private:
    std::string mSource;
    Limits mLimits;
    std::size_t mBytes = 0;
    std::size_t mEntries = 0;
    std::size_t mTokens = 0;
    std::size_t mDiagnostics = 0;
    Result<bool> mCompletion = true;
    bool mFinished = false;
};
} // namespace ResolvConf
} // namespace ComplianceEngine

#endif // COMPLIANCEENGINE_PARSERS_RESOLV_CONF_H
