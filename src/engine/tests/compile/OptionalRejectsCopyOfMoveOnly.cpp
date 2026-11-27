// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Negative case: copy-constructing a move-only Optional<std::unique_ptr<int>>
// must FAIL to compile. Expected diagnostic: the copy constructor it would
// use is deleted.

#include "../../Optional.h"

#include <memory>

using Kompli::Optional;

void CopyMoveOnlyOptional()
{
    Optional<std::unique_ptr<int>> source;
    Optional<std::unique_ptr<int>> copy(source);
}
