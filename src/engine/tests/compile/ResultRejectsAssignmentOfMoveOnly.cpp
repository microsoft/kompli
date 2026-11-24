// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Negative case: copy-assigning a move-only Result<std::unique_ptr<int>>
// must FAIL to compile. Expected diagnostic: the copy assignment operator it
// would use is deleted.

#include "../../Result.h"

#include <memory>

using ComplianceEngine::Error;
using ComplianceEngine::Result;

void AssignMoveOnlyResult()
{
    Result<std::unique_ptr<int>> source(Error("error")), destination(Error("old"));
    destination = source;
}
