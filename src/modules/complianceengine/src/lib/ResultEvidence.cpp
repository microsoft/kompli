// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <ResultEvidence.h>

namespace ComplianceEngine
{
void CompletedItemEvidence::AddSelected(bool stateSatisfied)
{
    mHasSelected = true;
    mAllSatisfied = mAllSatisfied && stateSatisfied;
}

Result<Status> CompletedItemEvidence::EvaluateAtLeastOneAll() const
{
    return (mHasSelected && mAllSatisfied) ? Status::Compliant : Status::NonCompliant;
}
} // namespace ComplianceEngine
