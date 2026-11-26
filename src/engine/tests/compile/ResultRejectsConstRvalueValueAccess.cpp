// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Negative case: Value() on a const Result<T> rvalue must FAIL to compile.
// Expected diagnostic: call to or use of a deleted function.

#include "../../Result.h"

#include <utility>

using Kompli::Result;

void ReadValueFromConstRvalue()
{
    const Result<int> result(1);
    (void)std::move(result).Value();
}
