// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <ContextInterface.h>
#include <Result.h>
#include <sys/types.h>

namespace ComplianceEngine
{
Result<uid_t> GetUidMin(ContextInterface& context);
Result<uid_t> GetUidMin(ContextInterface& context, const Result<std::string>& loginDefsResult);
} // namespace ComplianceEngine
