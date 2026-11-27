// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Negative case: copy-assigning a move-only Optional<std::unique_ptr<int>>
// must FAIL to compile. Expected diagnostic: the copy assignment operator it
// would use is deleted.

#include "../../Optional.h"

#include <memory>

using Kompli::Optional;

void AssignMoveOnlyOptional()
{
    Optional<std::unique_ptr<int>> source, destination;
    destination = source;
}
