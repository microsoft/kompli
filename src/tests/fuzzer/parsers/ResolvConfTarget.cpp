// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <parsers/ResolvConf.hpp>

#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <utility>

namespace
{
namespace rc = ComplianceEngine::ResolvConf;

std::size_t g_maxObservedInputBytes = 0;

void ReportMaxObservedInput()
{
    if (std::fprintf(stderr, "MAX_OBSERVED_INPUT_BYTES=%zu\n", g_maxObservedInputBytes) < 0)
        std::abort();
}

void Require(bool condition)
{
    if (!condition)
        std::abort();
}

bool SameSpan(rc::Span left, rc::Span right)
{
    return (left.line == right.line) && (left.column == right.column) && (left.length == right.length);
}

void CheckSpan(rc::Span span, const rc::Entry& entry)
{
    Require(span.line == entry.record.line);
    Require((span.column >= 1) && (span.column <= entry.text.size() + 1));
    Require(span.length <= entry.text.size() - (span.column - 1));
}

void CheckOperand(rc::Span span, const rc::Entry& entry, std::size_t& previous)
{
    CheckSpan(span, entry);
    Require((span.length > 0) && (span.column > previous));
    previous = span.column;
    bool found = false;
    for (const auto& token : entry.record.tokens)
        found |= SameSpan(token, span);
    Require(found);
}

struct CheckDirective
{
    const rc::Entry& entry;
    std::size_t previous = 0;

    explicit CheckDirective(const rc::Entry& value) : entry(value) {}

    void operator()(const rc::Blank&) { Require(entry.record.tokens.empty()); }
    void operator()(const rc::Comment&) { Require(entry.record.tokens.empty()); }
    void operator()(const rc::Unknown&) { Require(entry.text.find(" nameserver") != 0 || entry.record.tokens.size() > 0); }
    void operator()(const rc::Nameserver& value)
    {
        CheckOperand(value.token, entry, previous);
        Require(value.address.Is<rc::Ipv4>() || value.address.Is<rc::Ipv6>());
    }
    void operator()(const rc::Domain& value)
    {
        if (value.token.HasValue())
            CheckOperand(value.token.Value(), entry, previous);
    }
    void operator()(const rc::Search& value)
    {
        for (auto span : value.names)
            CheckOperand(span, entry, previous);
    }
    void operator()(const rc::Sortlist& value)
    {
        const auto terminator = entry.text.find(';');
        for (const auto& item : value.entries)
        {
            const auto span = item.Is<rc::Ipv4Sort>() ? item.Get<rc::Ipv4Sort>().token : item.Get<rc::UnverifiedIpv6Sort>().token;
            CheckOperand(span, entry, previous);
            if (terminator != std::string::npos)
                Require(span.column - 1 + span.length <= terminator);
            if (item.Is<rc::UnverifiedIpv6Sort>() && item.Get<rc::UnverifiedIpv6Sort>().mask.HasValue())
                CheckSpan(item.Get<rc::UnverifiedIpv6Sort>().mask.Value(), entry);
        }
    }
    void operator()(const rc::Options& value)
    {
        for (const auto& item : value.entries)
        {
            if (item.Is<rc::NumericOption>())
                CheckOperand(item.Get<rc::NumericOption>().token, entry, previous);
            else if (item.Is<rc::FlagOption>())
                CheckOperand(item.Get<rc::FlagOption>().token, entry, previous);
            else
                CheckOperand(item.Get<rc::UnknownOption>().token, entry, previous);
        }
    }
};

void CheckEntry(const rc::Entry& entry, const std::string& supplied, std::size_t line, const rc::Limits& limits,
    std::size_t& tokens)
{
    Require((entry.source == "resolv-fuzz") && (entry.text == supplied) && (entry.record.line == line));
    Require(entry.record.tokens.size() <= limits.tokens - tokens);
    tokens += entry.record.tokens.size();
    std::size_t end = 0;
    for (const auto& token : entry.record.tokens)
    {
        CheckSpan(token, entry);
        Require((token.length > 0) && (token.column > end));
        end = token.column - 1 + token.length;
    }
    CheckDirective check{entry};
    entry.directive.Visit<void>(check);
}

bool Same(const rc::Ipv4& a, const rc::Ipv4& b) { return a.bytes == b.bytes; }
bool Same(const rc::Ipv6& a, const rc::Ipv6& b) { return a.bytes == b.bytes; }
// Forward declarations keep the C++11 dependent visitor lookup explicit.
bool Same(const rc::Ipv4Sort& a, const rc::Ipv4Sort& b);
bool Same(const rc::UnverifiedIpv6Sort& a, const rc::UnverifiedIpv6Sort& b);
bool Same(const rc::NumericOption& a, const rc::NumericOption& b);
bool Same(const rc::FlagOption& a, const rc::FlagOption& b);
bool Same(const rc::UnknownOption& a, const rc::UnknownOption& b);
bool Same(const rc::Blank&, const rc::Blank&);
bool Same(const rc::Comment&, const rc::Comment&);
bool Same(const rc::Unknown&, const rc::Unknown&);
bool Same(const rc::Nameserver& a, const rc::Nameserver& b);
bool Same(const rc::Domain& a, const rc::Domain& b);
bool Same(const rc::Search& a, const rc::Search& b);
bool Same(const rc::Sortlist& a, const rc::Sortlist& b);
bool Same(const rc::Options& a, const rc::Options& b);

template <typename V>
struct Compare
{
    const V& right;
    template <typename T>
    bool operator()(const T& left) const
    {
        return right.template Is<T>() && Same(left, right.template Get<T>());
    }
};

bool Same(const rc::Ipv4Sort& a, const rc::Ipv4Sort& b)
{
    return SameSpan(a.token, b.token) && Same(a.address, b.address) &&
        (a.mask.HasValue() == b.mask.HasValue()) && (!a.mask.HasValue() || Same(a.mask.Value(), b.mask.Value()));
}
bool Same(const rc::UnverifiedIpv6Sort& a, const rc::UnverifiedIpv6Sort& b)
{
    return SameSpan(a.token, b.token) && Same(a.address, b.address) &&
        (a.mask.HasValue() == b.mask.HasValue()) && (!a.mask.HasValue() || SameSpan(a.mask.Value(), b.mask.Value()));
}
bool Same(const rc::NumericOption& a, const rc::NumericOption& b)
{
    return SameSpan(a.token, b.token) && a.value == b.value && a.documentedCap == b.documentedCap;
}
bool Same(const rc::FlagOption& a, const rc::FlagOption& b) { return SameSpan(a.token, b.token); }
bool Same(const rc::UnknownOption& a, const rc::UnknownOption& b) { return SameSpan(a.token, b.token); }
bool Same(const rc::Blank&, const rc::Blank&) { return true; }
bool Same(const rc::Comment&, const rc::Comment&) { return true; }
bool Same(const rc::Unknown&, const rc::Unknown&) { return true; }
bool Same(const rc::Nameserver& a, const rc::Nameserver& b)
{
    return SameSpan(a.token, b.token) && a.address.Visit<bool>(Compare<rc::Address>{b.address});
}
bool Same(const rc::Domain& a, const rc::Domain& b)
{
    return a.token.HasValue() == b.token.HasValue() && (!a.token.HasValue() || SameSpan(a.token.Value(), b.token.Value()));
}
bool Same(const rc::Search& a, const rc::Search& b)
{
    if (a.names.size() != b.names.size()) return false;
    for (std::size_t i = 0; i < a.names.size(); ++i)
        if (!SameSpan(a.names[i], b.names[i])) return false;
    return true;
}
bool Same(const rc::Sortlist& a, const rc::Sortlist& b)
{
    if (a.entries.size() != b.entries.size()) return false;
    for (std::size_t i = 0; i < a.entries.size(); ++i)
        if (!a.entries[i].Visit<bool>(Compare<rc::SortEntry>{b.entries[i]})) return false;
    return true;
}
bool Same(const rc::Options& a, const rc::Options& b)
{
    if (a.entries.size() != b.entries.size()) return false;
    for (std::size_t i = 0; i < a.entries.size(); ++i)
        if (!a.entries[i].Visit<bool>(Compare<rc::Option>{b.entries[i]})) return false;
    return true;
}

void SameEntry(const rc::Entry& left, const rc::Entry& right)
{
    Require((left.source == right.source) && (left.text == right.text));
    Require(left.record.line == right.record.line);
    Require(left.record.tokens.size() == right.record.tokens.size());
    for (std::size_t i = 0; i < left.record.tokens.size(); ++i)
        Require(SameSpan(left.record.tokens[i], right.record.tokens[i]));
    Require(left.directive.Visit<bool>(Compare<rc::DirectiveValue>{right.directive}));
}

template <typename T>
void SameResult(const ComplianceEngine::Result<T>& left, const ComplianceEngine::Result<T>& right)
{
    Require(left.HasValue() == right.HasValue());
    if (left.HasValue())
        Require(left.Value() == right.Value());
    else
        Require((left.Error().code == right.Error().code) && (left.Error().message == right.Error().message));
}

void Run(const std::string& input, const rc::Limits& limits)
{
    // The parser receives LF-stripped physical entries. A final LF terminates
    // the preceding entry; it does not invent an additional empty entry.
    // Only the most recent owned result is retained; no whole-file document.
    rc::Entry retained;
    bool haveRetained = false;
    {
        std::string source = "resolv-fuzz";
        rc::Parser first(source, limits);
        rc::Parser repeat(source, limits);
        source.clear(); // Both parsers and their outputs must own the identity.
        std::size_t bytes = 0;
        std::size_t tokens = 0;
        std::size_t line = 0;
        bool failed = false;
        for (std::size_t start = 0; start < input.size();)
        {
            const auto lf = input.find('\n', start);
            const auto length = (lf == std::string::npos ? input.size() : lf) - start;
            const std::string text = input.substr(start, length);
            auto a = first.Next(text);
            auto b = repeat.Next(text);
            Require(a.HasValue() == b.HasValue());
            if (!a.HasValue())
            {
                Require((a.Error().code == b.Error().code) && (a.Error().message == b.Error().message));
                if (limits.bytes == 0)
                    Require(a.Error().code == EINVAL);
                else
                    Require((a.Error().code == EBADMSG) || (a.Error().code == E2BIG));
                failed = true;
                break;
            }
            ++line;
            Require((line <= limits.entries) && (text.size() <= limits.lineBytes) && (text.size() <= limits.bytes - bytes));
            bytes += text.size(); // LF bytes are not supplied to Next.
            CheckEntry(a.Value(), text, line, limits, tokens);
            SameEntry(a.Value(), b.Value());
            retained = std::move(a.Value());
            haveRetained = true;
            if (lf == std::string::npos)
                break;
            start = lf + 1;
        }

        if (failed)
        {
            const auto a = first.Finish(rc::Acquisition::EofAndClosed);
            const auto b = repeat.Finish(rc::Acquisition::EofAndClosed);
            SameResult(a, b);
            Require(!a.HasValue());
            const auto sticky = first.Next("");
            Require((!sticky.HasValue()) && (sticky.Error().code == a.Error().code) &&
                (sticky.Error().message == a.Error().message));
            const auto acquisitionError = first.Finish(ComplianceEngine::Error("late acquisition error", EIO));
            Require((!acquisitionError.HasValue()) && (acquisitionError.Error().message == a.Error().message));
        }
        else
        {
            // A completed stream, an incomplete stream, and an external
            // acquisition error are different caller-supplied outcomes.
            const auto mode = input.empty() ? 0 : static_cast<unsigned char>(input[0]) % 3;
            ComplianceEngine::Result<rc::Acquisition> acquisition = rc::Acquisition::EofAndClosed;
            if (mode == 1)
                acquisition = rc::Acquisition::Incomplete;
            else if (mode == 2)
                acquisition = ComplianceEngine::Error("late acquisition error", EIO);
            const auto a = first.Finish(acquisition);
            const auto b = repeat.Finish(acquisition);
            SameResult(a, b);
            Require(a.HasValue() == (mode == 0));
            if (a.HasValue())
                Require(a.Value());
            else
                Require(a.Error().code == EIO);
            const auto again = first.Finish(rc::Acquisition::EofAndClosed);
            Require(!again.HasValue());
            if (a.HasValue())
                Require(again.Error().code == EINVAL);
            else
                SameResult(a, again);
            const auto illegal = first.Next("");
            Require(!illegal.HasValue());
            Require(illegal.Error().code == (a.HasValue() ? EINVAL : EIO));
            const auto sticky = first.Finish(rc::Acquisition::EofAndClosed);
            Require((!sticky.HasValue()) && (sticky.Error().code == illegal.Error().code) &&
                (sticky.Error().message == illegal.Error().message));
        }
    }
    if (haveRetained)
    {
        Require(retained.source == "resolv-fuzz");
        for (const auto& token : retained.record.tokens)
            CheckSpan(token, retained); // Evidence survives both parsers.
        CheckDirective check(retained);
        retained.directive.Visit<void>(check);
    }
}
} // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size)
{
    static const int reportRegistration = std::atexit(ReportMaxObservedInput);
    Require(reportRegistration == 0);
    if (size > 65536)
        return 0;
    if (size > g_maxObservedInputBytes)
        g_maxObservedInputBytes = size;
    const std::string bytes = size == 0 ? std::string() : std::string(reinterpret_cast<const char*>(data), size);

    rc::Limits generous;
    generous.bytes = 4096;
    generous.lineBytes = 1024;
    generous.entries = 64;
    generous.tokens = 256;
    Run(bytes, generous);
    if (bytes.empty()) // Exercise line endings without hook-normalized corpus files.
    {
        Run("search example.org\r\n", generous);
        Run("nameserver 192.0.2.3", generous);
        Run("nameserver 192.0.2.3 #ignored\n nameserver ignored\nsortlist 192.0.2.0&255.255.255.0; ignored\n", generous);
    }

    rc::Limits tight;
    const auto selector = size == 0 ? 0 : static_cast<unsigned char>(data[0]);
    tight.bytes = 1 + selector % 64;
    tight.lineBytes = 1 + selector % 32;
    tight.entries = 1 + selector % 5;
    tight.tokens = 1 + selector % 6;
    Run(bytes, tight);
    if ((selector == 0) && !bytes.empty())
    {
        tight.bytes = 0; // Constructor failure must remain sticky.
        Run(bytes, tight);
    }
    return 0;
}
