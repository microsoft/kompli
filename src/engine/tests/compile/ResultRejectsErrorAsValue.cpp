// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Negative case: instantiating Result<Error> is ambiguous (the value type
// and the error type would collide) and must FAIL to compile. Expected
// diagnostic: "Result cannot hold Error as its value type".

#include "../../Result.h"

using ComplianceEngine::Error;
using ComplianceEngine::Result;

static_assert(sizeof(Result<Error>) > 0, "instantiate ambiguous Result Error");
