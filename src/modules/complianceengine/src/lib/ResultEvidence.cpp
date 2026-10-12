// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <ResultEvidence.h>
#include <cerrno>

namespace ComplianceEngine
{
void CompletedItemEvidence::AddSelected(bool stateSatisfied)
{
    mHasSelected = true;
    mAllSatisfied = mAllSatisfied && stateSatisfied;
}

bool CompletedItemEvidence::HasSelectedItems() const
{
    return mHasSelected;
}

bool CompletedItemEvidence::AllSelectedStatesSatisfied() const
{
    return mAllSatisfied;
}

Result<Status> EvaluateRepeatedValueItems(const Result<std::vector<SelectedValueItem>>& selectedItems)
{
    if (!selectedItems.HasValue())
    {
        return selectedItems.Error();
    }

    for (const auto& item : selectedItems.Value())
    {
        for (const auto& value : item.values)
        {
            if (!value.HasValue())
            {
                return value.Error();
            }
        }
    }

    CompletedItemEvidence evidence;
    for (const auto& item : selectedItems.Value())
    {
        if (item.values.empty())
        {
            return Error("Selected value item has no comparison results", EINVAL);
        }
        bool anyValueSatisfied = false;
        for (const auto& value : item.values)
        {
            anyValueSatisfied = anyValueSatisfied || value.Value();
        }
        evidence.AddSelected(anyValueSatisfied);
    }
    return (evidence.HasSelectedItems() && evidence.AllSelectedStatesSatisfied()) ? Status::Compliant : Status::NonCompliant;
}
} // namespace ComplianceEngine
