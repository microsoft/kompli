// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef COMPLIANCEENGINE_RESULT_EVIDENCE_H
#define COMPLIANCEENGINE_RESULT_EVIDENCE_H

#include <MmiResults.h>
#include <Result.h>

namespace ComplianceEngine
{
enum class StateSatisfaction
{
    Satisfied,
    NotSatisfied,
};

// OVAL 5.12.3 source rows, restricted to nonempty Check T/F/E operands.
// These are not the sticky operational Result errors of existing native callers.
enum class SourceCheckValue
{
    True,
    False,
    Error
};
enum class SourceCheckPolicy
{
    All,
    AtLeastOne,
    NoneSatisfy,
    OnlyOne
};
class SourceCheckEvidence
{
public:
    void Add(SourceCheckValue value);
    bool HasSourceError() const;
    // Empty Check has no source chart row; invalid inputs return EINVAL.
    Result<SourceCheckValue> Evaluate(SourceCheckPolicy policy) const;

private:
    unsigned mTrue = 0;
    unsigned mFalse = 0;
    unsigned mError = 0;
    bool mInvalid = false;
};

// Selected occurrences contribute Exists regardless of scalar state. The
// bounded producer supplies no DoesNotExist or NotCollected status.
enum class SourceExistenceValue
{
    Exists,
    Error
};
enum class SourceExistencePolicy
{
    AllExist,
    AnyExist,
    AtLeastOneExists,
    NoneExist,
    OnlyOneExists
};
class SourceExistenceEvidence
{
public:
    void Add(SourceExistenceValue value);
    bool HasSourceError() const;
    Result<SourceCheckValue> Evaluate(SourceExistencePolicy policy) const;

private:
    unsigned mExists = 0;
    unsigned mError = 0;
    bool mInvalid = false;
};

class CompletedItemEvidence
{
public:
    void AddSelected(const Result<StateSatisfaction>& state);
    void RecordError(const Error& error);
    bool HasSelectedItems() const;
    // Empty evidence is Satisfied; callers apply existence policy separately.
    Result<StateSatisfaction> AllSelectedStatesSatisfied() const;

private:
    bool mHasSelected = false;
    Result<StateSatisfaction> mAllSatisfied = StateSatisfaction::Satisfied;
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
    // Adds one selected, already-assessed item. This is not absence, exclusion,
    // collection completion, sufficient stopping, or a final procedure status.
    void AddItem(const Result<StateSatisfaction>& assessment);
    // Adds one selected item whose repeated comparisons use any-satisfied.
    void AddItem(const SelectedItemComparisonEvidence& item);
    void RecordCollectionError(const Error& error);
    bool HasSelectedItems() const;
    // Reached errors precede empty-item validation; errors do not prevent Add.
    Result<StateSatisfaction> AllSelectedItemsSatisfied() const;

private:
    CompletedItemEvidence mItems;
    bool mHasEmptyItem = false;
};
} // namespace ComplianceEngine

#endif // COMPLIANCEENGINE_RESULT_EVIDENCE_H
