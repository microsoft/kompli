// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Positive control: ordinary Result<void> usage below must COMPILE cleanly,
// so the negative Result<void> cases in the sibling ResultVoid* files are
// known to fail for their own specific reason rather than a broken
// translation unit.

#include "../../Result.h"

using ComplianceEngine::Error;
using ComplianceEngine::Result;

void ValidVoidControl()
{
    Error codeOnly(5);
    Result<void> fromCodeOnly = Error(5);
    Error lvalue("error");
    Result<void> fromLvalue = lvalue;
    (void)codeOnly;
    (void)fromCodeOnly;
    (void)fromLvalue;

    Result<void> voidSuccess = Result<void>::Success();
    Result<void> voidFailure(Error("error"));
    (void)voidSuccess.HasValue();
    (void)voidFailure.Error();
}
