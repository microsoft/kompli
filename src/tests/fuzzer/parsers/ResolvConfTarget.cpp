// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <parsers/ResolvConf.h>

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

void CheckEntry(const rc::Entry& entry, const std::string& supplied, std::size_t line, const rc::Limits& limits,
    std::size_t& tokens, std::size_t& diagnostics)
{
    Require((entry.source == "resolv-fuzz") && (entry.text == supplied) && (entry.record.line == line));
    Require(entry.record.tokens.size() <= limits.tokens - tokens);
    Require(entry.diagnostics.size() <= limits.diagnostics - diagnostics);
    tokens += entry.record.tokens.size();
    diagnostics += entry.diagnostics.size();
    std::size_t end = 0;
    for (const auto& token : entry.record.tokens)
    {
        CheckSpan(token, entry);
        Require((token.length > 0) && (token.column > end));
        end = token.column - 1 + token.length;
    }
    std::size_t previous = 0;
    for (const auto& projection : entry.projections)
    {
        CheckSpan(projection.token, entry);
        Require((projection.token.length > 0) && (projection.token.column > previous));
        previous = projection.token.column;
        bool found = false;
        for (const auto& token : entry.record.tokens)
            found |= SameSpan(token, projection.token);
        Require(found);
        Require((projection.addressBytes == 0) || (projection.addressBytes == 4) || (projection.addressBytes == 16));
    }
    for (const auto& diagnostic : entry.diagnostics)
    {
        CheckSpan(diagnostic.span, entry);
        Require(!diagnostic.message.empty());
    }
    bool malformed = false;
    for (const auto& diagnostic : entry.diagnostics)
        malformed |= diagnostic.kind == rc::DiagnosticKind::Malformed;
    Require(entry.hasMalformedEvidence == malformed);
}

void SameEntry(const rc::Entry& left, const rc::Entry& right)
{
    Require((left.source == right.source) && (left.text == right.text) && (left.hasMalformedEvidence == right.hasMalformedEvidence));
    Require((left.record.directive == right.record.directive) && (left.record.line == right.record.line));
    Require(left.record.tokens.size() == right.record.tokens.size());
    for (std::size_t i = 0; i < left.record.tokens.size(); ++i)
        Require(SameSpan(left.record.tokens[i], right.record.tokens[i]));
    Require(left.projections.size() == right.projections.size());
    for (std::size_t i = 0; i < left.projections.size(); ++i)
    {
        const auto& a = left.projections[i];
        const auto& b = right.projections[i];
        Require((a.kind == b.kind) && (a.status == b.status) && SameSpan(a.token, b.token));
        Require((a.addressBytes == b.addressBytes) && (a.address == b.address) && (a.hasMask == b.hasMask) && (a.mask == b.mask));
        Require((a.number == b.number) && (a.documentedCap == b.documentedCap));
    }
    Require(left.diagnostics.size() == right.diagnostics.size());
    for (std::size_t i = 0; i < left.diagnostics.size(); ++i)
    {
        const auto& a = left.diagnostics[i];
        const auto& b = right.diagnostics[i];
        Require((a.kind == b.kind) && SameSpan(a.span, b.span) && (a.message == b.message));
    }
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
        std::size_t diagnostics = 0;
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
                Require(a.Error().code == (limits.bytes == 0 ? EINVAL : E2BIG));
                failed = true;
                break;
            }
            ++line;
            Require((line <= limits.entries) && (text.size() <= limits.lineBytes) && (text.size() <= limits.bytes - bytes));
            bytes += text.size(); // LF bytes are not supplied to Next.
            CheckEntry(a.Value(), text, line, limits, tokens, diagnostics);
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
        for (const auto& projection : retained.projections)
            CheckSpan(projection.token, retained);
        for (const auto& diagnostic : retained.diagnostics)
            CheckSpan(diagnostic.span, retained);
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
    generous.diagnostics = 256;
    Run(bytes, generous);
    if (bytes.empty()) // Exercise line endings without hook-normalized corpus files.
    {
        Run("search example.org\r\n", generous);
        Run("nameserver 192.0.2.3", generous);
    }

    rc::Limits tight;
    const auto selector = size == 0 ? 0 : static_cast<unsigned char>(data[0]);
    tight.bytes = 1 + selector % 64;
    tight.lineBytes = 1 + selector % 32;
    tight.entries = 1 + selector % 5;
    tight.tokens = 1 + selector % 6;
    tight.diagnostics = 1 + selector % 5;
    Run(bytes, tight);
    if ((selector == 0) && !bytes.empty())
    {
        tight.bytes = 0; // Constructor failure must remain sticky.
        Run(bytes, tight);
    }
    return 0;
}
