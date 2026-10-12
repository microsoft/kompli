// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <ResultEvidence.h>
#include <cerrno>

namespace ComplianceEngine
{
void CompletedItemEvidence::AddSelected(StateSatisfaction state)
{
    mHasSelected = true;
    if (state == StateSatisfaction::NotSatisfied)
    {
        mAllSatisfied = StateSatisfaction::NotSatisfied;
    }
}

bool CompletedItemEvidence::HasSelectedItems() const
{
    return mHasSelected;
}

StateSatisfaction CompletedItemEvidence::AllSelectedStatesSatisfied() const
{
    return mAllSatisfied;
}

void SelectedItemComparisonEvidence::AddComparison(const Result<StateSatisfaction>& comparison)
{
    mHasComparisons = true;
    if (!mAnySatisfied.HasValue())
    {
        return;
    }
    if (!comparison.HasValue())
    {
        mAnySatisfied = comparison.Error();
    }
    else if (comparison.Value() == StateSatisfaction::Satisfied)
    {
        mAnySatisfied = StateSatisfaction::Satisfied;
    }
}

bool SelectedItemComparisonEvidence::HasComparisons() const
{
    return mHasComparisons;
}

Result<StateSatisfaction> SelectedItemComparisonEvidence::AnyComparisonSatisfied() const
{
    if (!mHasComparisons)
    {
        return Error("Selected value item has no comparison results", EINVAL);
    }
    return mAnySatisfied;
}

void SelectedItemsEvidence::AddItem(const SelectedItemComparisonEvidence& item)
{
    if (!item.HasComparisons())
    {
        mHasEmptyItem = true;
        mItems.AddSelected(StateSatisfaction::NotSatisfied);
        return;
    }
    const auto state = item.AnyComparisonSatisfied();
    if (!state.HasValue())
    {
        RecordError(state.Error());
        mItems.AddSelected(StateSatisfaction::NotSatisfied);
        return;
    }
    mItems.AddSelected(state.Value());
}

void SelectedItemsEvidence::RecordCollectionError(const Error& error)
{
    RecordError(error);
}

void SelectedItemsEvidence::RecordError(const Error& error)
{
    if (!mError.HasValue())
    {
        mError = error;
    }
}

bool SelectedItemsEvidence::HasSelectedItems() const
{
    return mItems.HasSelectedItems();
}

Result<StateSatisfaction> SelectedItemsEvidence::AllSelectedItemsSatisfied() const
{
    if (mError.HasValue())
    {
        return mError.Value();
    }
    if (mHasEmptyItem)
    {
        return Error("Selected value item has no comparison results", EINVAL);
    }
    return mItems.AllSelectedStatesSatisfied();
}
} // namespace ComplianceEngine
