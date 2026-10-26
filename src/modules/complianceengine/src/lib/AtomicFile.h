// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef COMPLIANCEENGINE_ATOMIC_FILE_H
#define COMPLIANCEENGINE_ATOMIC_FILE_H

#include "Result.h"

#include <string>
#include <sys/stat.h>
#include <sys/types.h>

namespace ComplianceEngine
{
Result<bool> CreateFileContentsAtomic(const std::string& path, const std::string& contents, mode_t mode, struct stat* created = nullptr);
Result<bool> ReplaceFileContentsAtomic(const std::string& path, const std::string& contents);
} // namespace ComplianceEngine

#endif // COMPLIANCEENGINE_ATOMIC_FILE_H
