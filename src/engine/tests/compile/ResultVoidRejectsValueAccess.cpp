// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Negative case: Result<void> has no Value() accessor, so calling it must
// FAIL to compile. Expected diagnostic: no member named 'Value'.

#include "../../Result.h"

using ComplianceEngine::Result;

void AccessVoidValue()
{
    Result<void>::Success().Value();
}
