// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef COMPLIANCEENGINE_FILE_OBJECT_COLLECTOR_H
#define COMPLIANCEENGINE_FILE_OBJECT_COLLECTOR_H

#include <Result.h>
#include <VariableResolver.h>
#include <cstddef>
#include <filesystem/FilesystemPolicy.hpp>
#include <string>

namespace ComplianceEngine
{
class ContextInterface;

struct FileCollectionPolicy
{
    // Applies to every path component, as in FileReader::Policy.
    SymlinkFollowing symlinks = SymlinkFollowing::Follow;
    // Acquisition bytes include LF; the parser independently caps entry
    // length, aggregate entry bytes/count, tokens and diagnostics. The next
    // four limits bound selected valid address tokens, not raw line captures.
    std::size_t contentBytes = 1024 * 1024;
    std::size_t occurrences = 16384;
    std::size_t captureBytes = 65536;
    std::size_t capturedBytes = 1024 * 1024;
    std::size_t values = 65536;
    std::size_t readRetries = 128;
};

Result<VariableResolution::ObjectCollection> CollectNameserverObject(const ContextInterface& context, const std::string& path, FileCollectionPolicy policy = {});
} // namespace ComplianceEngine

#endif // COMPLIANCEENGINE_FILE_OBJECT_COLLECTOR_H
