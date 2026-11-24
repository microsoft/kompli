// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Negative case: returning an empty brace-init Result<void> must FAIL to
// compile, since it would invoke the same private default constructor as
// direct default construction. Expected diagnostic: calling a private
// constructor.

#include "../../Result.h"

using ComplianceEngine::Result;

Result<void> ReturnEmptyBrace()
{
    return {};
}
