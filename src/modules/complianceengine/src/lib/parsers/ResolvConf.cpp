// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "ResolvConf.h"

#include <StringTools.h>
#include <arpa/inet.h>
#include <cerrno>
#include <utility>

namespace ComplianceEngine
{
namespace ResolvConf
{
namespace
{
bool Separator(char byte)
{
    return byte == ' ' || byte == '\t';
}

Error LimitError(const std::string& source, const char* budget)
{
    return Error(source + ": resolv.conf " + budget + " limit exceeded", E2BIG);
}

Result<bool> Note(Document& doc, const Limits& limits, DiagnosticKind kind, Span span, const char* message)
{
    if (doc.diagnostics.size() >= limits.diagnostics)
        return LimitError(doc.source, "diagnostic");
    doc.diagnostics.push_back({kind, span, message});
    return true;
}

std::string Text(const Document& doc, Span span)
{
    return doc.entries[span.line - 1].substr(span.column - 1, span.length);
}

bool Address(const std::string& text, int family, std::array<unsigned char, 16>& bytes)
{
    // inet_pton takes a C string. Never allow an embedded NUL to turn a
    // malformed token into an apparently valid address prefix.
    return text.find('\0') == std::string::npos && inet_pton(family, text.c_str(), bytes.data()) == 1;
}

bool Flag(const std::string& text)
{
    static const char* const flags[] = {"debug", "rotate", "no-aaaa", "no-check-names", "inet6", "ip6-bytestring", "ip6-dotint", "no-ip6-dotint",
        "edns0", "single-request", "single-request-reopen", "no-tld-query", "use-vc", "no-reload", "trust-ad"};
    for (const char* flag : flags)
        if (text == flag)
            return true;
    return false;
}

unsigned int NumericCap(const std::string& name)
{
    if (name == "ndots")
        return 15;
    if (name == "timeout")
        return 30;
    if (name == "attempts")
        return 5;
    return 0;
}

Result<bool> Project(Document& doc, const Limits& limits, std::size_t index, Span span)
{
    const auto& record = doc.records[index];
    const auto value = Text(doc, span);
    Projection projection;
    projection.record = index;
    projection.token = span;

    if (record.directive == Directive::Nameserver)
    {
        projection.kind = ValueKind::Nameserver;
        if (Address(value, AF_INET, projection.address))
        {
            projection.addressBytes = 4;
            projection.status = Status::Parsed;
        }
        else if (Address(value, AF_INET6, projection.address))
        {
            projection.addressBytes = 16;
            projection.status = Status::Parsed;
        }
        else
        {
            projection.status = Status::Invalid;
            auto noted = Note(doc, limits, DiagnosticKind::Malformed, span, "invalid nameserver address");
            if (!noted.HasValue())
                return noted.Error();
        }
    }
    else if (record.directive == Directive::Search || record.directive == Directive::Domain)
    {
        projection.kind = record.directive == Directive::Search ? ValueKind::SearchName : ValueKind::DomainName;
        projection.status = Status::Unverified; // Domain-name byte grammar is not specified by the manual.
    }
    else if (record.directive == Directive::Sortlist)
    {
        projection.kind = ValueKind::SortPair;
        const auto slash = value.find('/');
        const auto host = value.substr(0, slash);
        const auto mask = slash == std::string::npos ? std::string() : value.substr(slash + 1);
        projection.hasMask = slash != std::string::npos;
        if (Address(host, AF_INET, projection.address) &&
            (!projection.hasMask || (mask.find('/') == std::string::npos && Address(mask, AF_INET, projection.mask))))
        {
            projection.addressBytes = 4;
            projection.status = Status::Parsed;
        }
        else if (Address(host, AF_INET6, projection.address))
        {
            // The manual's sortlist example is IPv4; do not assert IPv6
            // pair semantics or synthesize a natural netmask.
            projection.status = Status::Unverified;
            auto noted = Note(doc, limits, DiagnosticKind::Unverified, span, "IPv6 sortlist semantics unverified");
            if (!noted.HasValue())
                return noted.Error();
        }
        else
        {
            projection.status = Status::Invalid;
            auto noted = Note(doc, limits, DiagnosticKind::Malformed, span, "invalid sortlist address or netmask");
            if (!noted.HasValue())
                return noted.Error();
        }
    }
    else // options
    {
        const auto colon = value.find(':');
        const auto name = value.substr(0, colon);
        const auto cap = NumericCap(name);
        if (cap)
        {
            projection.kind = ValueKind::NumericOption;
            projection.documentedCap = cap;
            const auto number = colon == std::string::npos ? std::string() : value.substr(colon + 1);
            bool digits = !number.empty();
            for (const char digit : number)
                digits = digits && digit >= '0' && digit <= '9';
            const auto parsed = digits ? TryStringToUint(number) : Result<unsigned int>(Error("invalid digits", EINVAL));
            if (parsed.HasValue())
            {
                projection.number = parsed.Value();
                projection.status = Status::Parsed;
            }
            else
            {
                projection.status = Status::Invalid;
                auto noted = Note(doc, limits, DiagnosticKind::Malformed, span, "invalid numeric option");
                if (!noted.HasValue())
                    return noted.Error();
            }
        }
        else if (Flag(value))
        {
            projection.kind = ValueKind::FlagOption;
            projection.status = Status::Parsed; // Availability/deprecation NOT resolved.
        }
        else
        {
            projection.kind = ValueKind::UnknownOption;
            projection.status = Status::Unknown;
            auto noted = Note(doc, limits, DiagnosticKind::Unknown, span, "unknown option or extra option operand");
            if (!noted.HasValue())
                return noted.Error();
        }
    }
    doc.projections.push_back(std::move(projection));
    return true;
}

Result<bool> Analyze(Document& doc, const Limits& limits, std::size_t index, std::size_t& tokenCount)
{
    auto& record = doc.records[index];
    const auto& line = doc.entries[index];
    record.line = index + 1;
    // Every supplied byte is retained, including bytes not given a token.
    // Surface ambiguous binary/quoting/continuation rather than treating it
    // as verified glibc grammar.
    for (std::size_t i = 0; i < line.size(); ++i)
    {
        const unsigned char byte = static_cast<unsigned char>(line[i]);
        if (byte == '\0' || byte == '\r' || byte >= 128 || byte == '"' || byte == '\\')
        {
            auto noted = Note(doc, limits, byte == '\0' ? DiagnosticKind::Malformed : DiagnosticKind::Unverified, {index + 1, i + 1, 1},
                byte == '\0' ? "embedded NUL" : "byte grammar unverified");
            if (!noted.HasValue())
                return noted.Error();
        }
    }
    if (line.empty())
        return true;
    if (line[0] == '#' || line[0] == ';')
    {
        record.directive = Directive::Comment;
        return true;
    }
    if (Separator(line[0]))
    {
        record.directive = Directive::Malformed;
        return Note(doc, limits, DiagnosticKind::Malformed, {index + 1, 1, 1}, "keyword not in first column");
    }
    for (std::size_t i = 0; i < line.size();)
    {
        if (Separator(line[i]))
        {
            ++i;
            continue;
        }
        const auto start = i;
        while (i < line.size() && !Separator(line[i]))
            ++i;
        if (tokenCount >= limits.tokens)
            return LimitError(doc.source, "token");
        record.tokens.push_back({index + 1, start + 1, i - start});
        ++tokenCount;
    }
    const auto key = Text(doc, record.tokens.front());
    if (key == "nameserver")
        record.directive = Directive::Nameserver;
    else if (key == "search")
        record.directive = Directive::Search;
    else if (key == "domain")
        record.directive = Directive::Domain;
    else if (key == "sortlist")
        record.directive = Directive::Sortlist;
    else if (key == "options")
        record.directive = Directive::Options;
    else
    {
        record.directive = Directive::Unknown;
        return Note(doc, limits, DiagnosticKind::Unknown, record.tokens.front(), "unknown directive");
    }
    if (record.tokens.size() == 1)
    {
        record.directive = Directive::Malformed;
        return Note(doc, limits, DiagnosticKind::Malformed, {index + 1, line.size() + 1, 0}, "missing directive operand");
    }
    if ((record.directive == Directive::Nameserver || record.directive == Directive::Domain) && record.tokens.size() > 2)
    {
        auto noted = Note(doc, limits, DiagnosticKind::Malformed, record.tokens[2], "extra directive operand");
        if (!noted.HasValue())
            return noted.Error();
        record.directive = Directive::Malformed;
        // Still project the first value without claiming the entire line is valid.
    }
    const auto directive = key;
    for (std::size_t i = 1; i < record.tokens.size(); ++i)
    {
        // Extra operands remain tokens and diagnostics, never interpreted as
        // valid nameserver/domain values.
        if ((directive == "nameserver" || directive == "domain") && i > 1)
            continue;
        if (record.directive == Directive::Malformed)
            record.directive = directive == "nameserver" ? Directive::Nameserver : Directive::Domain;
        auto projected = Project(doc, limits, index, record.tokens[i]);
        if (!projected.HasValue())
            return projected.Error();
        if ((directive == "nameserver" || directive == "domain") && record.tokens.size() > 2)
            record.directive = Directive::Malformed;
    }
    return true;
}
} // namespace

Result<Document> Parse(std::vector<std::string> entries, std::string source, const Limits& limits)
{
    if (!limits.bytes || !limits.lineBytes || !limits.entries || !limits.tokens || !limits.diagnostics)
        return Error(source + ": resolv.conf limits must be positive", EINVAL);
    if (entries.size() > limits.entries)
        return LimitError(source, "entry");
    std::size_t total = 0;
    for (const auto& line : entries)
    {
        if (line.size() > limits.lineBytes)
            return LimitError(source, "line");
        if (line.size() > limits.bytes - total)
            return LimitError(source, "byte");
        total += line.size();
    }
    Document doc;
    doc.source = std::move(source);
    doc.entries = std::move(entries);
    std::size_t tokenCount = 0;
    for (std::size_t index = 0; index < doc.entries.size(); ++index)
    {
        if (doc.records.size() >= limits.entries)
            return LimitError(doc.source, "record");
        doc.records.emplace_back();
        auto analyzed = Analyze(doc, limits, index, tokenCount);
        if (!analyzed.HasValue())
            return analyzed.Error();
    }
    return doc;
}
} // namespace ResolvConf
} // namespace ComplianceEngine
