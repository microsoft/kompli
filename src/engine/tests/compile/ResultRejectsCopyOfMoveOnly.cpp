// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Negative case: copy-constructing a move-only Result<std::unique_ptr<int>>
// must FAIL to compile. Expected diagnostic: the copy constructor it would
// use is deleted.

#include "../../Result.h"

#include <memory>

using Kompli::Error;
using Kompli::Result;

void CopyMoveOnlyResult()
{
    Result<std::unique_ptr<int>> source(Error("error"));
    Result<std::unique_ptr<int>> copy(source);
}
