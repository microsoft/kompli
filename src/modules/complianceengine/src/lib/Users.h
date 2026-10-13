// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <ContextInterface.h>
#include <Result.h>

namespace ComplianceEngine
{
Result<unsigned int> GetUidMin(ContextInterface& context);
Result<unsigned int> GetUidMin(ContextInterface& context, const Result<std::string>& loginDefsResult);
} // namespace ComplianceEngine
