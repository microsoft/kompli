// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Negative case: Error() on a const Result<T> rvalue must FAIL to compile.
// Expected diagnostic: call to or use of a deleted function.

#include "../../Result.h"

#include <utility>

using Kompli::Error;
using Kompli::Result;

void ReadErrorFromConstRvalue()
{
    const Result<int> result(Error(1));
    (void)std::move(result).Error();
}
