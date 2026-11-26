// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Negative case: operator-> on a const Result<T> rvalue must FAIL to compile.
// Expected diagnostic: call to or use of a deleted function.

#include "../../Result.h"

#include <utility>

using Kompli::Result;

void DereferenceConstRvalue()
{
    const Result<int> result(1);
    (void)std::move(result).operator->();
}
