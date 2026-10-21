// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <ContextInterface.h>
#include <FileObjectCollector.h>
#include <cerrno>
#include <filesystem/FileReader.hpp>
#include <new>
#include <parsers/NameserverSelection.h>
#include <stdexcept>
#include <string>
#include <utility>

namespace ComplianceEngine
{
namespace
{
Result<VariableResolution::ObjectCollection> ProjectNameservers(const NameserverSelection::Document& selection, std::size_t maxValues)
{
    VariableResolution::ObjectCollection collection;
    for (const auto& capture : selection.captures)
    {
        if (collection.items.size() >= maxValues)
            return Error("Exact file value limit exceeded", E2BIG);
        if (collection.items.size() >= collection.items.max_size())
            return Error("Exact file capture collection is not representable", EOVERFLOW);
        VariableResolution::ObjectItem item;
        item.fields["subexpression"] = {selection.bytes.substr(capture.offset, capture.length)};
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
    if (policy.rootSymlinks != RootSymlinkPolicy::FollowRegular && policy.rootSymlinks != RootSymlinkPolicy::Reject)
        return Error("Invalid root symlink policy", EINVAL);

    try
    {
        FileReader::Policy readerPolicy;
        readerPolicy.symlinks = policy.rootSymlinks == RootSymlinkPolicy::Reject ? FileReader::SymlinksPolicy::RejectFinal : FileReader::SymlinksPolicy::FollowFinal;
        readerPolicy.limits.maxBytes = policy.contentBytes;
        readerPolicy.limits.maxInterruptedReads = policy.readRetries;
        std::string bytes;
        auto opened = FileReader::Lines(context, path, readerPolicy);
        if (!opened.HasValue())
            return std::move(opened).Error();
        auto& range = opened.Value();
        // Retain the length-bearing document for offsets/captures. Selection
        // requires both verified EOF and successful explicit finalization.
        for (const auto& item : range)
        {
            if (!item.HasValue())
            {
                Error primary = item.Error();
                auto closed = range.Close();
                if (!closed.HasValue())
                {
                    try
                    {
                        primary.message += " [close: " + closed.Error().message + " (" + std::to_string(closed.Error().code) + ")]";
                    }
                    catch (const std::bad_alloc&)
                    {
                    }
                    catch (const std::length_error&)
                    {
                    }
                }
                return primary;
            }
            bytes.append(item.Value());
        }
        auto closed = range.Close();
        if (!closed.HasValue())
            return std::move(closed).Error();

        NameserverSelection::Limits selectionLimits;
        selectionLimits.occurrences = policy.occurrences;
        selectionLimits.captureBytes = policy.captureBytes;
        selectionLimits.capturedBytes = policy.capturedBytes;
        auto selection = NameserverSelection::FindNameserverCaptures(std::move(bytes), path, selectionLimits);
        if (!selection.HasValue())
            return selection.Error();
        return ProjectNameservers(selection.Value(), policy.values);
    }
    catch (const std::bad_alloc&)
    {
        return Error("Exact file operation allocation failed", ENOMEM);
    }
    catch (const std::length_error&)
    {
        return Error("Exact file operation result is not representable", EOVERFLOW);
    }
    catch (const std::exception&)
    {
        return Error("Exact file operation threw an exception", EIO);
    }
    catch (...)
    {
        return Error("Exact file operation threw an unknown exception", EIO);
    }
}
} // namespace ComplianceEngine
