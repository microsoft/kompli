// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef COMPLIANCEENGINE_RESULT_EVIDENCE_H
#define COMPLIANCEENGINE_RESULT_EVIDENCE_H

#include <MmiResults.h>
#include <Result.h>
#include <vector>

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

struct SelectedValueItem
{
    std::vector<Result<bool>> values;
};

// Input is complete and already selected; excluded items are not supplied.
Result<Status> EvaluateRepeatedValueItems(const Result<std::vector<SelectedValueItem>>& selectedItems);
} // namespace ComplianceEngine

#endif // COMPLIANCEENGINE_RESULT_EVIDENCE_H
