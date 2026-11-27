// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Negative case: instantiating Optional with a throwing move constructor must
// FAIL to compile. Expected diagnostic: "Optional requires a nonthrowing move
// constructor".

#include "../../Optional.h"

using Kompli::Optional;

struct ThrowingMove
{
    ThrowingMove(int);
    ThrowingMove(const ThrowingMove&) = default;
    ThrowingMove(ThrowingMove&&) noexcept(false);
};

static_assert(sizeof(Optional<ThrowingMove>) > 0, "instantiate Optional with a throwing move");
