// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Negative case: instantiating Result with a reference type must FAIL to
// compile. Expected diagnostic: "Result cannot hold references".

#include "../../Result.h"

using ComplianceEngine::Result;

static_assert(sizeof(Result<int&>) > 0, "instantiate Result reference");
