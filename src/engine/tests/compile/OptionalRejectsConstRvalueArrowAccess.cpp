// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Negative case: operator-> on a const Optional<T> rvalue must FAIL to compile.
// Expected diagnostic: call to or use of a deleted function.

#include "../../Optional.h"

#include <utility>

using Kompli::Optional;

void DereferenceConstRvalue()
{
    const Optional<int> optional(1);
    (void)std::move(optional).operator->();
}
