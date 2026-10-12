// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef COMPLIANCEENGINE_RESULT_EVIDENCE_H
#define COMPLIANCEENGINE_RESULT_EVIDENCE_H

#include <MmiResults.h>
#include <Optional.h>
#include <Result.h>

namespace ComplianceEngine
{
enum class StateSatisfaction
{
    Satisfied,
    NotSatisfied,
};

class CompletedItemEvidence
{
public:
    void AddSelected(StateSatisfaction state);
    bool HasSelectedItems() const;
    // Empty evidence is Satisfied; callers apply existence policy separately.
    StateSatisfaction AllSelectedStatesSatisfied() const;

private:
    bool mHasSelected = false;
    StateSatisfaction mAllSatisfied = StateSatisfaction::Satisfied;
};

class SelectedItemComparisonEvidence
{
public:
    // A reached error is retained even when a comparison is Satisfied.
    void AddComparison(const Result<StateSatisfaction>& comparison);
    bool HasComparisons() const;
    // Requires at least one comparison; empty evidence returns EINVAL.
    Result<StateSatisfaction> AnyComparisonSatisfied() const;

private:
    bool mHasComparisons = false;
    Result<StateSatisfaction> mAnySatisfied = StateSatisfaction::NotSatisfied;
};

// Callers supply completed selected items; exclusions are not added.
class SelectedItemsEvidence
{
public:
    void AddItem(const SelectedItemComparisonEvidence& item);
    void RecordCollectionError(const Error& error);
    bool HasSelectedItems() const;
    // Reached errors precede empty-item validation; errors do not prevent Add.
    Result<StateSatisfaction> AllSelectedItemsSatisfied() const;

private:
    void RecordError(const Error& error);
    CompletedItemEvidence mItems;
    Optional<Error> mError;
    bool mHasEmptyItem = false;
};
} // namespace ComplianceEngine

#endif // COMPLIANCEENGINE_RESULT_EVIDENCE_H
