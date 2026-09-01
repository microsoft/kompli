// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef COMPLIANCEENGINE_DLTOOLS_H
#define COMPLIANCEENGINE_DLTOOLS_H

#include <Result.h>
#include <string>

namespace ComplianceEngine
{

Result<std::string> GetCompilanceEngineDirectory();

} // namespace ComplianceEngine

#endif // COMPLIANCEENGINE_DLTOOLS_H
