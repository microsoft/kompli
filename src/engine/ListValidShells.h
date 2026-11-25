// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef KOMPLI_LIST_VALID_SHELLS_H
#define KOMPLI_LIST_VALID_SHELLS_H

#include <ContextInterface.h>
#include <Result.h>
#include <set>

namespace Kompli
{
Result<std::set<std::string>> ListValidShells(ContextInterface& context);
} // namespace Kompli

#endif // KOMPLI_LIST_VALID_SHELLS_H
