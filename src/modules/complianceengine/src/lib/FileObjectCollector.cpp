// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <ContextInterface.h>
#include <FileObjectCollector.h>
#include <cerrno>
#include <filesystem/FileReader.hpp>
#include <parsers/NameserverSelection.h>
#include <string>
#include <utility>
#include <vector>

namespace ComplianceEngine
{
namespace
{
Result<VariableResolution::ObjectCollection> ProjectNameservers(const std::vector<std::string>& values, std::size_t maxValues)
{
    VariableResolution::ObjectCollection collection;
    for (const auto& value : values)
    {
        if (collection.items.size() >= maxValues)
            return Error("Exact file value limit exceeded", E2BIG);
        if (collection.items.size() >= collection.items.max_size())
            return Error("Exact file capture collection is not representable", EOVERFLOW);
        VariableResolution::ObjectItem item;
        item.fields["subexpression"] = {value};
        collection.items.push_back(std::move(item));
    }
    collection.complete = true;
    return collection;
}
} // namespace

Result<VariableResolution::ObjectCollection> CollectNameserverObject(const ContextInterface& context, const std::string& path, FileCollectionPolicy policy)
{
    if (path.empty() || path.front() != '/' || path.find('\0') != std::string::npos)
        return Error("A NUL-free absolute path is required", EINVAL);
    if (!policy.contentBytes || !policy.occurrences || !policy.captureBytes || !policy.capturedBytes || !policy.values || !policy.readRetries)
        return Error("Exact file limits must be positive", EINVAL);
    if (policy.rootSymlinks != SymlinkFollowing::Follow && policy.rootSymlinks != SymlinkFollowing::DoNotFollow)
        return Error("Invalid root symlink policy", EINVAL);

    FileReader::Policy readerPolicy;
    readerPolicy.symlinks = policy.rootSymlinks;
    readerPolicy.limits.maxBytes = policy.contentBytes;
    readerPolicy.limits.maxInterruptedReads = policy.readRetries;
    NameserverSelection::Limits selectionLimits;
    selectionLimits.occurrences = policy.occurrences;
    selectionLimits.captureBytes = policy.captureBytes;
    selectionLimits.capturedBytes = policy.capturedBytes;
    NameserverSelection::LineStream selection(path, selectionLimits);
    Result<bool> selected(true);
    auto opened = FileReader::Lines(context, path, readerPolicy);
    if (!opened.HasValue())
        return std::move(opened).Error();
    auto& range = opened.Value();
    // Continue reading after a selection limit fails: reached reader errors
    // (including the tail and EOF verification) and Close take precedence.
    // No selection is published before verified EOF and explicit Close.
    for (const auto& item : range)
    {
        if (!item.HasValue())
            return item.Error();
        if (selected.HasValue())
            selected = selection.FeedLine(item.Value());
    }
    auto closed = range.Close();
    if (!closed.HasValue())
        return std::move(closed).Error();

    if (!selected.HasValue())
        return selected.Error();
    selected = selection.Finish();
    if (!selected.HasValue())
        return selected.Error();
    return ProjectNameservers(selection.Values(), policy.values);
}
} // namespace ComplianceEngine
