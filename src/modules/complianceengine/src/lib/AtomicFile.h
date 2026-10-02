// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef COMPLIANCEENGINE_ATOMIC_FILE_H
#define COMPLIANCEENGINE_ATOMIC_FILE_H

#include "Result.h"

#include <string>

namespace ComplianceEngine
{
Result<bool> ReplaceFileContentsAtomic(const std::string& path, const std::string& contents);
}

#endif // COMPLIANCEENGINE_ATOMIC_FILE_H
