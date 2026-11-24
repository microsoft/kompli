// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Negative case: instantiating Result with a throwing destructor must FAIL
// to compile. Expected diagnostic: "Result requires a nonthrowing
// destructor".

#include "../../Result.h"

using ComplianceEngine::Result;

struct ThrowingDestructor
{
    ~ThrowingDestructor() noexcept(false);
};

static_assert(sizeof(Result<ThrowingDestructor>) > 0, "instantiate Result with a throwing destructor");
