// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Negative case: Value() on a const Optional<T> rvalue must FAIL to compile.
// Expected diagnostic: call to or use of a deleted function.

#include "../../Optional.h"

#include <utility>

using Kompli::Optional;

void ReadValueFromConstRvalue()
{
    const Optional<int> optional(1);
    (void)std::move(optional).Value();
}
