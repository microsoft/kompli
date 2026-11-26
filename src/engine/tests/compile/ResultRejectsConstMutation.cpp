// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Negative case: mutating the value returned from a const Result<int> must
// FAIL to compile. Expected diagnostic: assignment through a non-assignable
// (read-only) return value.

#include "../../Result.h"

using Kompli::Result;

void MutateConstResult()
{
    const Result<int> value(1);
    value.Value() = 2;
}
