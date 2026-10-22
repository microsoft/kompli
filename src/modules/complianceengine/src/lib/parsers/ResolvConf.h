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
    Parsed,     // Syntax-only decode; NOT evidence of glibc availability/effect.
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
    std::vector<Span> tokens; // Keyword first; raw trivia remains in entries.
};

struct Projection
{
    ValueKind kind = ValueKind::SearchName;
    Status status = Status::Unverified;
    Span token;
    std::size_t record = 0;
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

struct Document
{
    std::string source;
    std::vector<std::string> entries; // Owned, exact LF-stripped supplied bytes.
    std::vector<Record> records;
    std::vector<Projection> projections;
    std::vector<Diagnostic> diagnostics;
};

// Supply completed, LF-stripped physical entries (as yielded by a line
// reader), not an acquisition result. Empty vector means successful empty
// input; acquisition failure must be handled by the caller. No I/O occurs.
// Space/tab are provisional separators. Only first-column # and ; are
// comments. Other ambiguous syntax is retained and flagged, never dropped.
// EINVAL: zero budget; E2BIG: exceeded budget. Neither publishes a prefix.
Result<Document> Parse(std::vector<std::string> entries, std::string source, const Limits& limits = {});
} // namespace ResolvConf
} // namespace ComplianceEngine

#endif // COMPLIANCEENGINE_PARSERS_RESOLV_CONF_H
