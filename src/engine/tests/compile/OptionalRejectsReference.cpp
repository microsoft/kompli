// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Negative case: instantiating Optional with a reference type must FAIL to
// compile. Expected diagnostic: "Optional cannot hold references".

#include "../../Optional.h"

using Kompli::Optional;

static_assert(sizeof(Optional<int&>) > 0, "instantiate Optional reference");
