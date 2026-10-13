// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef COMPLIANCEENGINE_EXACT_FILE_OBJECT_COLLECTOR_H
#define COMPLIANCEENGINE_EXACT_FILE_OBJECT_COLLECTOR_H

#include <Result.h>
#include <VariableResolver.h>
#include <cstddef>
#include <functional>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>

namespace ComplianceEngine
{
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

Result<VariableResolution::ObjectCollection> CollectNameserverObject(const std::string& path, const ExactFileCollectionLimits& limits = {},
    RootSymlinkPolicy rootSymlinks = RootSymlinkPolicy::FollowRegular);

namespace Detail
{
struct ExactFileOperations
{
    std::function<int(const char*, int)> openPath;
    std::function<int(int, struct stat*)> statDescriptor;
    std::function<ssize_t(int, void*, std::size_t)> readDescriptor;
    std::function<int(int)> closeDescriptor;

    ExactFileOperations();
};

Result<VariableResolution::ObjectCollection> CollectNameserverObjectWithOperations(const std::string& path, const ExactFileCollectionLimits& limits,
    RootSymlinkPolicy rootSymlinks, const ExactFileOperations& operations);
} // namespace Detail
} // namespace ComplianceEngine

#endif // COMPLIANCEENGINE_EXACT_FILE_OBJECT_COLLECTOR_H
