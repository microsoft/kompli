// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Negative case: instantiating Optional with void must FAIL to compile.
// Expected diagnostic: "Optional cannot hold void".

#include "../../Optional.h"

using Kompli::Optional;

static_assert(sizeof(Optional<void>) > 0, "instantiate Optional void");
