// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Negative case: default-constructing Result<void> must FAIL to compile; it
// only exposes Success()/an Error constructor. Expected diagnostic: calling
// a private (default) constructor.

#include "../../Result.h"

using Kompli::Result;

void DefaultConstructVoidResult()
{
    Result<void> result;
}
