// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <FileTreeWalk.h>
#include <FilesystemCollection.h>
#include <cerrno>

namespace ComplianceEngine
{
namespace Detail
{
Result<Status> FileTreeWalkWithOperations(const std::string& path, FtwCallback callback, BreakOnNonCompliant breakOnNonCompliant,
    ContextInterface& context, const FilesystemCollectionOperations& operations)
{
    if (!callback)
    {
        return Error("FileTreeWalk callback must not be empty", EINVAL);
    }

    bool nonCompliant = false;
    const FilesystemCollectionVisitor visitor = [&](const FilesystemCollectionEntry& entry) -> Result<FilesystemVisitAction> {
        const std::size_t separator = entry.path.find_last_of('/');
        const Result<Status> status = callback(entry.path.substr(0, separator), entry.path.substr(separator + 1), entry.linkMetadata);
        if (!status.HasValue())
        {
            return status.Error();
        }
        if (Status::Compliant != status.Value())
        {
            nonCompliant = true;
            if (BreakOnNonCompliant::True == breakOnNonCompliant)
            {
                return FilesystemVisitAction::Stop;
            }
        }
        return FilesystemVisitAction::Continue;
    };
    const Result<FilesystemCollectionResult> collected = StreamLegacyFileTreeWalk(path, visitor, operations, context.GetLogHandle());
    if (!collected.HasValue())
    {
        return collected.Error();
    }
    if ((FilesystemCollectionOutcome::Stopped == collected.Value().outcome) && !nonCompliant)
    {
        return Error("FileTreeWalk stopped without a decisive callback result", EIO);
    }
    return nonCompliant ? Status::NonCompliant : Status::Compliant;
}
} // namespace Detail

Result<Status> FileTreeWalk(const std::string& path, FtwCallback callback, BreakOnNonCompliant breakOnNonCompliant, ContextInterface& context)
{
    const Detail::FilesystemCollectionOperations operations;
    return Detail::FileTreeWalkWithOperations(path, callback, breakOnNonCompliant, context, operations);
}
} // namespace ComplianceEngine
