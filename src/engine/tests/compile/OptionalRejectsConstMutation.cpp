// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Negative case: mutating the value returned from a const Optional<int> must
// FAIL to compile. Expected diagnostic: assignment through a non-assignable
// (read-only) return value.

#include "../../Optional.h"

using Kompli::Optional;

void MutateConstOptional()
{
    const Optional<int> value(1);
    value.Value() = 2;
}
