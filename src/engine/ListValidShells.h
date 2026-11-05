// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef COMPLIANCEENGINE_LIST_VALID_SHELLS_H
#define COMPLIANCEENGINE_LIST_VALID_SHELLS_H

#include <ContextInterface.h>
#include <Result.h>
#include <set>

namespace Kompli
{
Result<std::set<std::string>> ListValidShells(ContextInterface& context);
} // namespace Kompli

#endif // COMPLIANCEENGINE_LIST_VALID_SHELLS_H
