// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <ContextInterface.h>
#include <FileObjectCollector.h>
#include <cerrno>
#include <filesystem/Lines.hpp>
#include <parsers/ResolvConf.h>
#include <string>
#include <utility>

namespace ComplianceEngine
{
namespace
{
Result<bool> AppendNameserver(const ResolvConf::Entry& entry, const FileCollectionPolicy& policy, std::size_t& capturedBytes,
    VariableResolution::ObjectCollection& collection)
{
    // Only first-column, space/tab-delimited directives match glibc's lexer.
    // Unknown spellings (including indentation and bare keywords) are not
    // nameserver evidence; the parser retains their original bytes.
    if (ResolvConf::Directive::Nameserver != entry.record.directive)
        return true;
    const auto& span = entry.projections.front().token;
    if (collection.items.size() >= policy.occurrences || collection.items.size() >= policy.values)
        return Error("Nameserver value limit exceeded", E2BIG);
    if (collection.items.size() >= collection.items.max_size())
        return Error("Nameserver value collection is not representable", EOVERFLOW);
    if (span.length > policy.captureBytes || capturedBytes > policy.capturedBytes || span.length > policy.capturedBytes - capturedBytes)
        return Error("Nameserver token limit exceeded", E2BIG);
    VariableResolution::ObjectItem item;
    // Keep exact token spelling for the existing string-based Unique count.
    item.fields["subexpression"] = {entry.text.substr(span.column - 1, span.length)};
    collection.items.push_back(std::move(item));
    capturedBytes += span.length;
    return true;
}
} // namespace

Result<VariableResolution::ObjectCollection> CollectNameserverObject(const ContextInterface& context, const std::string& path, FileCollectionPolicy policy)
{
    if (path.empty() || path.front() != '/' || path.find('\0') != std::string::npos)
        return Error("A NUL-free absolute path is required", EINVAL);
    if (!policy.contentBytes || !policy.occurrences || !policy.captureBytes || !policy.capturedBytes || !policy.values || !policy.readRetries)
        return Error("File collection limits must be positive", EINVAL);
    if (policy.symlinks != Filesystem::SymlinkFollowing::Follow && policy.symlinks != Filesystem::SymlinkFollowing::DoNotFollow)
        return Error("Invalid symlink policy", EINVAL);

    Filesystem::Lines::Policy readerPolicy;
    readerPolicy.symlinks = policy.symlinks;
    readerPolicy.limits.maxBytes = policy.contentBytes;
    readerPolicy.limits.maxInterruptedReads = policy.readRetries;
    VariableResolution::ObjectCollection collection;
    std::size_t capturedBytes = 0;
    Result<bool> selected(true);
    auto opened = Filesystem::Lines::Open(context, path, readerPolicy);
    if (!opened.HasValue())
        return std::move(opened).Error();
    ResolvConf::Parser parser(path);
    auto& range = opened.Value();
    // Keep reading after a parser/selection failure. Reached read errors and
    // checked Close are authoritative even if Parser::Finish is sticky.
    // The provisional collection is not returned until EOF, Close and Finish.
    for (const auto& item : range)
    {
        if (!item.HasValue())
        {
            const auto readError = item.Error();
            const auto closed = range.Close();
            (void)closed; // The reached read error takes precedence.
            (void)parser.Finish(readError);
            return readError;
        }
        if (selected.HasValue())
        {
            auto entry = parser.Next(item.Value());
            if (!entry.HasValue())
                selected = entry.Error();
            else
                selected = AppendNameserver(entry.Value(), policy, capturedBytes, collection);
        }
    }
    auto closed = range.Close();
    if (!closed.HasValue())
    {
        const auto closeError = std::move(closed).Error();
        (void)parser.Finish(closeError);
        return closeError;
    }

    auto finished = parser.Finish(ResolvConf::Acquisition::EofAndClosed);
    if (!selected.HasValue())
        return selected.Error();
    if (!finished.HasValue())
        return finished.Error();
    collection.complete = true;
    return collection;
}
} // namespace ComplianceEngine
