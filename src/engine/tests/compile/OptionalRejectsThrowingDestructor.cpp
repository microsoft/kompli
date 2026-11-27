// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Negative case: instantiating Optional with a throwing destructor must FAIL
// to compile. Expected diagnostic: "Optional requires a nonthrowing
// destructor".

#include "../../Optional.h"

using Kompli::Optional;

struct ThrowingDestructor
{
    ~ThrowingDestructor() noexcept(false);
};

static_assert(sizeof(Optional<ThrowingDestructor>) > 0, "instantiate Optional with a throwing destructor");
