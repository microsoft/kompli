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

Error Malformed(const std::string& source, const char* detail)
{
    return Error(source + ": resolv.conf " + detail, EBADMSG);
}

std::string Text(const Entry& entry, Span span)
{
    return entry.text.substr(span.column - 1, span.length);
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

Result<bool> Project(Entry& entry, const std::string& source, Directive directive, Span span)
{
    const auto value = Text(entry, span);
    Projection projection;
    projection.token = span;

    if (directive == Directive::Nameserver)
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
            return Malformed(source, "invalid nameserver address");
    }
    else if (directive == Directive::Search || directive == Directive::Domain)
    {
        projection.kind = directive == Directive::Search ? ValueKind::SearchName : ValueKind::DomainName;
        projection.status = Status::Unverified; // Domain-name byte grammar is not specified by the manual.
    }
    else if (directive == Directive::Sortlist)
    {
        projection.kind = ValueKind::SortPair;
        const auto slash = value.find('/');
        const auto host = value.substr(0, slash);
        const auto mask = slash == std::string::npos ? std::string() : value.substr(slash + 1);
        projection.hasMask = slash != std::string::npos;
        if (projection.hasMask && (mask.empty() || mask.find('/') != std::string::npos))
            return Malformed(source, "invalid sortlist address or netmask");
        if (Address(host, AF_INET, projection.address) && (!projection.hasMask || Address(mask, AF_INET, projection.mask)))
        {
            projection.addressBytes = 4;
            projection.status = Status::Parsed;
        }
        else if (Address(host, AF_INET6, projection.address))
        {
            // The manual's sortlist example is IPv4; do not assert IPv6
            // pair semantics or synthesize a natural netmask.
            projection.status = Status::Unverified;
        }
        else
            return Malformed(source, "invalid sortlist address or netmask");
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
                return Malformed(source, "invalid numeric option");
        }
        else if (Flag(value))
        {
            projection.kind = ValueKind::FlagOption;
            projection.status = Status::Parsed; // Availability/deprecation NOT resolved.
        }
        else if (colon != std::string::npos && Flag(name))
            return Malformed(source, "flag option has an operand");
        else
        {
            projection.kind = ValueKind::UnknownOption;
            projection.status = Status::Unknown;
        }
    }
    entry.projections.push_back(std::move(projection));
    return true;
}

Result<bool> Analyze(Entry& entry, const Limits& limits, const std::string& source, std::size_t& tokenCount)
{
    auto& record = entry.record;
    const auto& line = entry.text;
    // Every supplied byte is retained, including bytes not given a token.
    // Unknown byte grammar remains in the raw text without asserting support.
    // NUL cannot be a valid token or comment byte.
    if (line.find('\0') != std::string::npos)
        return Malformed(source, "embedded NUL");
    if (line.empty())
        return true;
    if (line[0] == '#' || line[0] == ';')
    {
        record.directive = Directive::Comment;
        return true;
    }
    if (Separator(line[0]))
        return Malformed(source, "keyword not in first column");
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
            return LimitError(source, "token");
        record.tokens.push_back({record.line, start + 1, i - start});
        ++tokenCount;
    }
    const auto key = Text(entry, record.tokens.front());
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
        return true;
    }
    if (record.tokens.size() == 1)
        return Malformed(source, "missing directive operand");
    if ((record.directive == Directive::Nameserver || record.directive == Directive::Domain) && record.tokens.size() > 2)
        return Malformed(source, "extra directive operand");
    for (std::size_t i = 1; i < record.tokens.size(); ++i)
    {
        auto projected = Project(entry, source, record.directive, record.tokens[i]);
        if (!projected.HasValue())
            return projected.Error();
    }
    return true;
}
} // namespace

Parser::Parser(std::string source, Limits limits)
    : mSource(std::move(source)),
      mLimits(limits)
{
    if (!limits.bytes || !limits.lineBytes || !limits.entries || !limits.tokens)
        mCompletion = Error(mSource + ": resolv.conf limits must be positive", EINVAL);
}

Result<Entry> Parser::Next(std::string text)
{
    if (!mCompletion.HasValue())
        return mCompletion.Error();
    if (mFinished)
    {
        mCompletion = Error(mSource + ": resolv.conf entry after finalization", EINVAL);
        return mCompletion.Error();
    }
    if (mEntries >= mLimits.entries)
        mCompletion = LimitError(mSource, "entry");
    else if (text.size() > mLimits.lineBytes)
        mCompletion = LimitError(mSource, "line");
    else if (text.size() > mLimits.bytes - mBytes)
        mCompletion = LimitError(mSource, "byte");
    if (!mCompletion.HasValue())
        return mCompletion.Error();

    Entry entry;
    entry.source = mSource;
    entry.text = std::move(text);
    entry.record.line = ++mEntries;
    mBytes += entry.text.size();
    auto analyzed = Analyze(entry, mLimits, mSource, mTokens);
    if (!analyzed.HasValue())
    {
        mCompletion = std::move(analyzed).Error();
        return mCompletion.Error();
    }
    return entry;
}

Result<bool> Parser::Finish(Result<Acquisition> acquisition)
{
    if (!mCompletion.HasValue())
        return mCompletion;
    if (mFinished)
    {
        mCompletion = !acquisition.HasValue() ? std::move(acquisition).Error() : Error(mSource + ": resolv.conf repeated finalization", EINVAL);
        return mCompletion;
    }
    mFinished = true;
    if (!acquisition.HasValue())
        mCompletion = std::move(acquisition).Error();
    else if (acquisition.Value() != Acquisition::EofAndClosed)
        mCompletion = Error(mSource + ": resolv.conf input not fully acquired", EIO);
    return mCompletion;
}
} // namespace ResolvConf
} // namespace ComplianceEngine
