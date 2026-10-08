// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef COMPLIANCEENGINE_RESULT_EVIDENCE_H
#define COMPLIANCEENGINE_RESULT_EVIDENCE_H

#include <MmiResults.h>
#include <Result.h>

namespace ComplianceEngine
{
class CompletedItemEvidence
{
public:
    void AddSelected(bool stateSatisfied);
    Result<Status> EvaluateAtLeastOneAll() const;

private:
    bool mHasSelected = false;
    bool mAllSatisfied = true;
};
} // namespace ComplianceEngine

#endif // COMPLIANCEENGINE_RESULT_EVIDENCE_H
