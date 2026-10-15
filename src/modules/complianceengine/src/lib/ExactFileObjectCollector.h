// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef COMPLIANCEENGINE_EXACT_FILE_OBJECT_COLLECTOR_H
#define COMPLIANCEENGINE_EXACT_FILE_OBJECT_COLLECTOR_H

#include <Result.h>
#include <VariableResolver.h>
#include <cstddef>
#include <string>

namespace ComplianceEngine
{
class ContextInterface;

enum class RootSymlinkPolicy
{
    FollowRegular,
    Reject,
};

struct ExactFileCollectionLimits
{
    std::size_t contentBytes = 1024 * 1024;
    std::size_t occurrences = 16384;
    std::size_t captureBytes = 65536;
    std::size_t capturedBytes = 1024 * 1024;
    std::size_t values = 65536;
    std::size_t readRetries = 128;
};

Result<VariableResolution::ObjectCollection> CollectNameserverObject(const ContextInterface& context, const std::string& path,
    ExactFileCollectionLimits limits = {}, RootSymlinkPolicy rootSymlinks = RootSymlinkPolicy::FollowRegular);
} // namespace ComplianceEngine

#endif // COMPLIANCEENGINE_EXACT_FILE_OBJECT_COLLECTOR_H
