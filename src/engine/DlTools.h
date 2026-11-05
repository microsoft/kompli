// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef COMPLIANCEENGINE_DLTOOLS_H
#define COMPLIANCEENGINE_DLTOOLS_H

#include <Result.h>
#include <string>

namespace Kompli
{

Result<std::string> GetComplianceEngineDirectory();

} // namespace Kompli

#endif // COMPLIANCEENGINE_DLTOOLS_H
