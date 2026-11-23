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

namespace
{
// Only zero, one and two-or-more are distinct in these rows; never overflow.
void Increment(unsigned& count)
{
    if (count < 2)
    {
        ++count;
    }
}
} // anonymous namespace

void SourceCheckEvidence::Add(SourceCheckValue value)
{
    switch (value)
    {
        case SourceCheckValue::True:
            Increment(mTrue);
            break;
        case SourceCheckValue::False:
            Increment(mFalse);
            break;
        case SourceCheckValue::Error:
            Increment(mError);
            break;
        default:
            mInvalid = true;
            break;
    }
}
bool SourceCheckEvidence::HasSourceError() const
{
    return (0 != mError);
}
Result<SourceCheckValue> SourceCheckEvidence::Evaluate(SourceCheckPolicy policy) const
{
    if (mInvalid || ((0 == mTrue) && (0 == mFalse) && (0 == mError)))
    {
        return Error("Invalid or empty source Check evidence", EINVAL);
    }
    switch (policy)
    {
        case SourceCheckPolicy::All:
            if (mFalse)
                return SourceCheckValue::False;
            return mError ? SourceCheckValue::Error : SourceCheckValue::True;
        case SourceCheckPolicy::AtLeastOne:
            if (mTrue)
                return SourceCheckValue::True;
            return mError ? SourceCheckValue::Error : SourceCheckValue::False;
        case SourceCheckPolicy::NoneSatisfy:
            if (mTrue)
                return SourceCheckValue::False;
            return mError ? SourceCheckValue::Error : SourceCheckValue::True;
        case SourceCheckPolicy::OnlyOne:
            if (mTrue >= 2)
                return SourceCheckValue::False;
            if (mError)
                return SourceCheckValue::Error;
            return (1 == mTrue) ? SourceCheckValue::True : SourceCheckValue::False;
    }
    return Error("Invalid source Check policy", EINVAL);
}

void SourceExistenceEvidence::Add(SourceExistenceValue value)
{
    switch (value)
    {
        case SourceExistenceValue::Exists:
            Increment(mExists);
            break;
        case SourceExistenceValue::Error:
            Increment(mError);
            break;
        default:
            mInvalid = true;
            break;
    }
}
bool SourceExistenceEvidence::HasSourceError() const
{
    return (0 != mError);
}
Result<SourceCheckValue> SourceExistenceEvidence::Evaluate(SourceExistencePolicy policy) const
{
    if (mInvalid)
    {
        return Error("Invalid source Existence evidence", EINVAL);
    }
    switch (policy)
    {
        case SourceExistencePolicy::AllExist:
            if (mError)
                return SourceCheckValue::Error;
            return mExists ? SourceCheckValue::True : SourceCheckValue::False;
        case SourceExistencePolicy::AnyExist:
            return ((mError) && (!mExists)) ? SourceCheckValue::Error : SourceCheckValue::True;
        case SourceExistencePolicy::AtLeastOneExists:
            if (mExists)
                return SourceCheckValue::True;
            return mError ? SourceCheckValue::Error : SourceCheckValue::False;
        case SourceExistencePolicy::NoneExist:
            if (mExists)
                return SourceCheckValue::False;
            return mError ? SourceCheckValue::Error : SourceCheckValue::True;
        case SourceExistencePolicy::OnlyOneExists:
            if (mExists >= 2)
                return SourceCheckValue::False;
            if (mError)
                return SourceCheckValue::Error;
            return (1 == mExists) ? SourceCheckValue::True : SourceCheckValue::False;
    }
    return Error("Invalid source Existence policy", EINVAL);
}

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
