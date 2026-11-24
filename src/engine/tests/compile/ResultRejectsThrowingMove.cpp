// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Negative case: instantiating Result with a throwing move constructor must
// FAIL to compile. Expected diagnostic: "Result requires a nonthrowing move
// constructor".

#include "../../Result.h"

using ComplianceEngine::Result;

struct ThrowingMove
{
    ThrowingMove(int);
    ThrowingMove(const ThrowingMove&) = default;
    ThrowingMove(ThrowingMove&&) noexcept(false);
};

static_assert(sizeof(Result<ThrowingMove>) > 0, "instantiate Result with a throwing move");
