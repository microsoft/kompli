// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "ResolvConf.hpp"

#include <StringTools.h>
#include <algorithm>
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

template <std::size_t N>
bool ParseAddress(const std::string& text, int family, std::array<unsigned char, N>& bytes)
{
    // inet_pton takes a C string. Never allow an embedded NUL to turn a
    // malformed token into an apparently valid address prefix.
    return text.find('\0') == std::string::npos && inet_pton(family, text.c_str(), bytes.data()) == 1;
}

bool Flag(const std::string& text)
{
    // res_setoptions in glibc 2.39 compares known flag prefixes, with the
    // longer single-request spelling checked first. Other spellings remain
    // unknown evidence, even if an older manual mentions them.
    static const char* const flags[] = {
        "rotate", "edns0", "single-request-reopen", "single-request", "no_tld_query", "no-tld-query", "no-reload", "use-vc", "trust-ad", "no-aaaa"};
    for (const char* flag : flags)
        if (0 == text.compare(0, std::string(flag).size(), flag))
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

Result<Address> ParseHost(const std::string& text, const std::string& source, const char* error)
{
    Ipv4 ipv4;
    if (ParseAddress(text, AF_INET, ipv4.bytes))
        return Address(InPlaceType<Ipv4>{}, std::move(ipv4));
    Ipv6 ipv6;
    if (ParseAddress(text, AF_INET6, ipv6.bytes))
        return Address(InPlaceType<Ipv6>{}, std::move(ipv6));
    return Malformed(source, error);
}

Result<SortEntry> ParseSort(const Entry& entry, const std::string& source, Span span)
{
    const auto value = Text(entry, span);
    const auto separator = value.find_first_of("/&");
    const auto host = value.substr(0, separator);
    const bool hasMask = separator != std::string::npos;
    const auto mask = hasMask ? value.substr(separator + 1) : std::string();
    if (hasMask && (mask.empty() || mask.find_first_of("/&") != std::string::npos))
        return Malformed(source, "invalid sortlist address or netmask");
    Ipv4 ipv4;
    if (ParseAddress(host, AF_INET, ipv4.bytes))
    {
        Ipv4Sort item{span, ipv4, {}};
        if (hasMask)
        {
            Ipv4 decoded;
            if (!ParseAddress(mask, AF_INET, decoded.bytes))
                return Malformed(source, "invalid sortlist address or netmask");
            item.mask = decoded;
        }
        return SortEntry(InPlaceType<Ipv4Sort>{}, std::move(item));
    }
    Ipv6 ipv6;
    if (ParseAddress(host, AF_INET6, ipv6.bytes))
    {
        // glibc/manual do not establish IPv6 sortlist pair semantics; the
        // previous parser accepted any nonempty mask without decoding it.
        UnverifiedIpv6Sort item{span, ipv6, {}};
        if (hasMask)
            item.mask = Span(span.line, span.column + separator + 1, mask.size());
        return SortEntry(InPlaceType<UnverifiedIpv6Sort>{}, std::move(item));
    }
    return Malformed(source, "invalid sortlist address or netmask");
}

Result<Option> ParseOption(const Entry& entry, const std::string& source, Span span)
{
    const auto value = Text(entry, span);
    const auto colon = value.find(':');
    const auto cap = NumericCap(value.substr(0, colon));
    if (cap)
    {
        const auto number = colon == std::string::npos ? std::string() : value.substr(colon + 1);
        bool digits = !number.empty();
        for (const char digit : number)
            digits = digits && digit >= '0' && digit <= '9';
        const auto parsed = digits ? TryStringToUint(number) : Result<unsigned int>(Error("invalid digits", EINVAL));
        if (!parsed.HasValue())
            return Malformed(source, "invalid numeric option");
        return Option(InPlaceType<NumericOption>{}, NumericOption{span, parsed.Value(), cap});
    }
    if (Flag(value))
        return Option(InPlaceType<FlagOption>{}, FlagOption{span});
    return Option(InPlaceType<UnknownOption>{}, UnknownOption{span});
}

Result<bool> Analyze(Entry& entry, const Limits& limits, const std::string& source, std::size_t& tokenCount)
{
    auto& record = entry.record;
    const auto& line = entry.text;
    // Every supplied byte is retained, including bytes not given a token.
    // Unknown byte grammar remains in the raw text without asserting support.
    if (line.find('\0') != std::string::npos)
        return Malformed(source, "embedded NUL");
    if (line.empty())
        return true;
    if (line[0] == '#' || line[0] == ';')
    {
        entry.directive = DirectiveValue(InPlaceType<Comment>{}, Comment{});
        return true;
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
            return LimitError(source, "token");
        record.tokens.push_back({record.line, start + 1, i - start});
        ++tokenCount;
    }
    // glibc 2.39 MATCH: exact first-column keyword followed by space/tab.
    // Indented, bare, and CR-separated spellings remain unknown evidence.
    if (record.tokens.empty() || Separator(line[0]))
    {
        entry.directive = DirectiveValue(InPlaceType<Unknown>{}, Unknown{});
        return true;
    }
    const auto key = Text(entry, record.tokens.front());
    if (!(key.size() < line.size() && Separator(line[key.size()])))
    {
        entry.directive = DirectiveValue(InPlaceType<Unknown>{}, Unknown{});
        return true;
    }
    if (key == "nameserver")
    {
        if (record.tokens.size() == 1)
            return Malformed(source, "missing directive operand");
        const auto span = record.tokens[1];
        auto address = ParseHost(Text(entry, span), source, "invalid nameserver address");
        if (!address.HasValue())
            return address.Error();
        entry.directive = DirectiveValue(InPlaceType<Nameserver>{}, Nameserver{span, std::move(address.Value())});
        return true;
    }
    if (key == "domain")
    {
        entry.directive = DirectiveValue(InPlaceType<Domain>{}, Domain{record.tokens.size() > 1 ? Optional<Span>(record.tokens[1]) : Optional<Span>()});
        return true;
    }
    if (key == "search")
    {
        Search search;
        search.names.assign(record.tokens.begin() + 1, record.tokens.end());
        entry.directive = DirectiveValue(InPlaceType<Search>{}, std::move(search));
        return true;
    }
    if (key == "sortlist")
    {
        Sortlist sortlist;
        for (std::size_t i = 1; i < record.tokens.size(); ++i)
        {
            const auto semicolon = Text(entry, record.tokens[i]).find(';');
            if (semicolon == 0)
                break;
            if (semicolon != std::string::npos)
                record.tokens[i].length = semicolon;
            auto item = ParseSort(entry, source, record.tokens[i]);
            if (!item.HasValue())
                return item.Error();
            sortlist.entries.push_back(std::move(item.Value()));
            const auto tokenEnd = record.tokens[i].column - 1 + record.tokens[i].length;
            if (tokenEnd < line.size() && line[tokenEnd] == ';')
                break;
        }
        entry.directive = DirectiveValue(InPlaceType<Sortlist>{}, std::move(sortlist));
        return true;
    }
    if (key == "options")
    {
        Options options;
        for (std::size_t i = 1; i < record.tokens.size(); ++i)
        {
            auto option = ParseOption(entry, source, record.tokens[i]);
            if (!option.HasValue())
                return option.Error();
            options.entries.push_back(std::move(option.Value()));
        }
        entry.directive = DirectiveValue(InPlaceType<Options>{}, std::move(options));
        return true;
    }
    entry.directive = DirectiveValue(InPlaceType<Unknown>{}, Unknown{});
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
