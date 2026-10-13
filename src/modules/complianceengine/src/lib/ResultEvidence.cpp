// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <ResultEvidence.h>
#include <cerrno>

namespace ComplianceEngine
{
namespace
{
Result<StateSatisfaction> ValidateStateSatisfaction(const Result<StateSatisfaction>& state)
{
    if (!state.HasValue())
    {
        return state.Error();
    }
    switch (state.Value())
    {
        case StateSatisfaction::Satisfied:
        case StateSatisfaction::NotSatisfied:
            return state.Value();
    }
    return Error("Invalid state satisfaction value", EINVAL);
}
} // anonymous namespace

void CompletedItemEvidence::AddSelected(const Result<StateSatisfaction>& state)
{
    mHasSelected = true;
    if (!mAllSatisfied.HasValue())
    {
        return;
    }
    const auto validated = ValidateStateSatisfaction(state);
    if (!validated.HasValue())
    {
        mAllSatisfied = validated.Error();
    }
    else if (validated.Value() == StateSatisfaction::NotSatisfied)
    {
        mAllSatisfied = StateSatisfaction::NotSatisfied;
    }
}

void CompletedItemEvidence::RecordError(const Error& error)
{
    if (mAllSatisfied.HasValue())
    {
        mAllSatisfied = error;
    }
}

bool CompletedItemEvidence::HasSelectedItems() const
{
    return mHasSelected;
}

Result<StateSatisfaction> CompletedItemEvidence::AllSelectedStatesSatisfied() const
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
    const auto validated = ValidateStateSatisfaction(comparison);
    if (!validated.HasValue())
    {
        mAnySatisfied = validated.Error();
    }
    else if (validated.Value() == StateSatisfaction::Satisfied)
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

void SelectedItemsEvidence::AddItem(const Result<StateSatisfaction>& assessment)
{
    mItems.AddSelected(assessment);
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
    mItems.AddSelected(state);
}

void SelectedItemsEvidence::RecordCollectionError(const Error& error)
{
    mItems.RecordError(error);
}

bool SelectedItemsEvidence::HasSelectedItems() const
{
    return mItems.HasSelectedItems();
}

Result<StateSatisfaction> SelectedItemsEvidence::AllSelectedItemsSatisfied() const
{
    const auto state = mItems.AllSelectedStatesSatisfied();
    if (!state.HasValue())
    {
        return state.Error();
    }
    if (mHasEmptyItem)
    {
        return Error("Selected value item has no comparison results", EINVAL);
    }
    return state.Value();
}
} // namespace ComplianceEngine
