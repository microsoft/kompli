// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Negative case: implicitly converting a plain int into Error must FAIL to
// compile, since the int-taking constructor is explicit. Expected
// diagnostic: no viable conversion to Error.

#include "../../Result.h"

using Kompli::Error;

void ImplicitIntegerError()
{
    Error error = 5;
}
