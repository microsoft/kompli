// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <PasswordCreditUnionEvidence.h>
#include <ResultEvidence.h>
#include <cerrno>
#include <gtest/gtest.h>
#include <initializer_list>
#include <limits>
#include <utility>

using ComplianceEngine::CompletedItemEvidence;
using ComplianceEngine::CreditEvidenceKind;
using ComplianceEngine::CreditRootLocation;
using ComplianceEngine::Error;
using ComplianceEngine::PasswordCreditAssessment;
using ComplianceEngine::PasswordCreditItem;
using ComplianceEngine::PasswordCreditRoot;
using ComplianceEngine::Result;
using ComplianceEngine::SelectedItemComparisonEvidence;
using ComplianceEngine::SelectedItemsEvidence;
using ComplianceEngine::StateSatisfaction;
using ComplianceEngine::Status;

namespace
{
PasswordCreditAssessment Root(PasswordCreditRoot::Outcome outcome, std::vector<PasswordCreditItem> selected = {},
    std::vector<std::string> exclusions = {}, std::string reason = {}, std::vector<std::string> observed = {})
{
    return {PasswordCreditRoot{outcome, std::move(selected), std::move(exclusions), std::move(reason)}, std::move(observed)};
}

PasswordCreditAssessment FailedRoot(const char* message, int code, std::vector<std::string> observed = {})
{
    return {Error(message, code), std::move(observed)};
}

Result<Status> Evaluate(const PasswordCreditAssessment& main, const PasswordCreditAssessment& dropIn, std::vector<std::string>& diagnostics)
{
    return ComplianceEngine::EvaluatePasswordCreditUnion(main, dropIn, [&](CreditRootLocation root, CreditEvidenceKind kind, const std::string& identity) {
        const auto location = root == CreditRootLocation::Main ? "main:" : "drop-in:";
        const auto type = kind == CreditEvidenceKind::Selected ? "selected:" : kind == CreditEvidenceKind::Excluded ? "excluded:" : "observed:";
        diagnostics.push_back(std::string(location) + type + identity);
    });
}

PasswordCreditItem Credit(const char* identity, long long value)
{
    return {identity, value};
}

SelectedItemComparisonEvidence Item(std::initializer_list<Result<StateSatisfaction>> comparisons)
{
    SelectedItemComparisonEvidence item;
    for (const auto& comparison : comparisons)
    {
        item.AddComparison(comparison);
    }
    return item;
}

Result<Status> Evaluate(const SelectedItemsEvidence& items)
{
    const auto state = items.AllSelectedItemsSatisfied();
    if (!state.HasValue())
    {
        return state.Error();
    }
    return (items.HasSelectedItems() && state.Value() == StateSatisfaction::Satisfied) ? Status::Compliant : Status::NonCompliant;
}

SelectedItemsEvidence Items(std::initializer_list<SelectedItemComparisonEvidence> selected)
{
    SelectedItemsEvidence items;
    for (const auto& item : selected)
    {
        items.AddItem(item);
    }
    return items;
}
} // anonymous namespace

TEST(ResultEvidenceTest, SelectedItemExistenceDoesNotDependOnStateSatisfaction)
{
    CompletedItemEvidence evidence;
    EXPECT_FALSE(evidence.HasSelectedItems());
    evidence.AddSelected(StateSatisfaction::NotSatisfied);
    EXPECT_TRUE(evidence.HasSelectedItems());
    evidence.AddSelected(StateSatisfaction::Satisfied);
    EXPECT_TRUE(evidence.HasSelectedItems());
}

TEST(ResultEvidenceTest, UniversalStateSatisfactionDoesNotRequireExistence)
{
    CompletedItemEvidence evidence;
    EXPECT_EQ(StateSatisfaction::Satisfied, evidence.AllSelectedStatesSatisfied());
    evidence.AddSelected(StateSatisfaction::Satisfied);
    evidence.AddSelected(StateSatisfaction::Satisfied);
    EXPECT_EQ(StateSatisfaction::Satisfied, evidence.AllSelectedStatesSatisfied());
    evidence.AddSelected(StateSatisfaction::NotSatisfied);
    EXPECT_EQ(StateSatisfaction::NotSatisfied, evidence.AllSelectedStatesSatisfied());
    evidence.AddSelected(StateSatisfaction::Satisfied);
    EXPECT_EQ(StateSatisfaction::NotSatisfied, evidence.AllSelectedStatesSatisfied());

    CompletedItemEvidence mismatchFirst;
    mismatchFirst.AddSelected(StateSatisfaction::NotSatisfied);
    mismatchFirst.AddSelected(StateSatisfaction::Satisfied);
    EXPECT_EQ(StateSatisfaction::NotSatisfied, mismatchFirst.AllSelectedStatesSatisfied());
}

TEST(ResultEvidenceTest, RepeatedValuesWithinOneItemUseAtLeastOneInEitherOrder)
{
    const auto matchFirst = Item({StateSatisfaction::Satisfied, StateSatisfaction::NotSatisfied, StateSatisfaction::NotSatisfied});
    const auto matchLast = Item({StateSatisfaction::NotSatisfied, StateSatisfaction::NotSatisfied, StateSatisfaction::Satisfied});
    EXPECT_EQ(Status::Compliant, Evaluate(Items({matchFirst})).Value());
    EXPECT_EQ(Status::Compliant, Evaluate(Items({matchLast})).Value());
    EXPECT_EQ(Status::NonCompliant, Evaluate(Items({Item({StateSatisfaction::NotSatisfied, StateSatisfaction::NotSatisfied})})).Value());
}

TEST(ResultEvidenceTest, DistinctItemsUseAllInEitherOrder)
{
    const auto matching = Item({StateSatisfaction::NotSatisfied, StateSatisfaction::Satisfied});
    const auto mismatching = Item({StateSatisfaction::NotSatisfied});
    EXPECT_EQ(Status::NonCompliant, Evaluate(Items({matching, mismatching})).Value());
    EXPECT_EQ(Status::NonCompliant, Evaluate(Items({mismatching, matching})).Value());
    EXPECT_EQ(Status::Compliant, Evaluate(Items({Item({StateSatisfaction::Satisfied}), matching})).Value());
}

TEST(ResultEvidenceTest, ScalarAndExcludedValueItemsRetainExistencePolicy)
{
    auto selected = Items({Item({StateSatisfaction::Satisfied})});
    const auto excludedDecoy = Item({StateSatisfaction::NotSatisfied});
    EXPECT_EQ(Status::Compliant, Evaluate(selected).Value());
    selected.AddItem(excludedDecoy);
    EXPECT_EQ(Status::NonCompliant, Evaluate(selected).Value());
    EXPECT_EQ(Status::NonCompliant, Evaluate(SelectedItemsEvidence{}).Value());
}

TEST(ResultEvidenceTest, ReachedValueErrorSurvivesMatchingValuesAndItemOrder)
{
    const auto matching = Item({StateSatisfaction::Satisfied, StateSatisfaction::NotSatisfied});
    const auto errorAfterMatch = Item({StateSatisfaction::Satisfied, Error("conversion failed", EIO)});
    const auto errorBeforeMatch = Item({Error("conversion failed", EIO), StateSatisfaction::Satisfied});
    for (const auto& items :
        {Items({matching, errorAfterMatch}), Items({errorBeforeMatch, matching}), Items({matching, errorBeforeMatch}), Items({errorAfterMatch, matching})})
    {
        const auto result = Evaluate(items);
        ASSERT_FALSE(result.HasValue());
        EXPECT_EQ(EIO, result.Error().code);
        EXPECT_EQ("conversion failed", result.Error().message);
    }
}

TEST(ResultEvidenceTest, CollectionErrorAndEmptySelectedItemAreNotVerdicts)
{
    SelectedItemsEvidence failedCollection;
    failedCollection.RecordCollectionError(Error("collection failed", EACCES));
    const auto collectionError = Evaluate(failedCollection);
    ASSERT_FALSE(collectionError.HasValue());
    EXPECT_EQ(EACCES, collectionError.Error().code);
    EXPECT_EQ("collection failed", collectionError.Error().message);

    const auto emptyItem = Evaluate(Items({SelectedItemComparisonEvidence{}}));
    ASSERT_FALSE(emptyItem.HasValue());
    EXPECT_EQ(EINVAL, emptyItem.Error().code);
    EXPECT_NE(std::string::npos, emptyItem.Error().message.find("no comparison results"));

    const auto emptyThenError = Items({SelectedItemComparisonEvidence{}, Item({StateSatisfaction::Satisfied, Error("read failed", EIO)})});
    const auto reachedError = Evaluate(emptyThenError);
    ASSERT_FALSE(reachedError.HasValue());
    EXPECT_EQ(EIO, reachedError.Error().code);
    EXPECT_EQ("read failed", reachedError.Error().message);
}

TEST(ResultEvidenceTest, ItemComparisonStateHasExplicitSatisfactionAndEmptyError)
{
    SelectedItemComparisonEvidence item;
    EXPECT_FALSE(item.HasComparisons());
    const auto empty = item.AnyComparisonSatisfied();
    ASSERT_FALSE(empty.HasValue());
    EXPECT_EQ(EINVAL, empty.Error().code);
    item.AddComparison(StateSatisfaction::NotSatisfied);
    EXPECT_TRUE(item.HasComparisons());
    EXPECT_EQ(StateSatisfaction::NotSatisfied, item.AnyComparisonSatisfied().Value());
    item.AddComparison(StateSatisfaction::Satisfied);
    EXPECT_EQ(StateSatisfaction::Satisfied, item.AnyComparisonSatisfied().Value());
    item.AddComparison(StateSatisfaction::NotSatisfied);
    EXPECT_EQ(StateSatisfaction::Satisfied, item.AnyComparisonSatisfied().Value());
}

TEST(ResultEvidenceTest, ComparisonErrorsDoNotInterruptAddingAndFirstErrorIsRetained)
{
    SelectedItemComparisonEvidence item;
    size_t added = 0;
    for (const auto& comparison : {Result<StateSatisfaction>(Error("first failure", EIO)), Result<StateSatisfaction>(StateSatisfaction::Satisfied),
             Result<StateSatisfaction>(Error("later failure", EACCES)), Result<StateSatisfaction>(StateSatisfaction::NotSatisfied)})
    {
        item.AddComparison(comparison);
        ++added;
    }
    EXPECT_EQ(4U, added);
    const auto state = item.AnyComparisonSatisfied();
    ASSERT_FALSE(state.HasValue());
    EXPECT_EQ(EIO, state.Error().code);
    EXPECT_EQ("first failure", state.Error().message);

    SelectedItemsEvidence items;
    items.AddItem(item);
    items.AddItem(Item({StateSatisfaction::Satisfied}));
    items.RecordCollectionError(Error("later collection failure", E2BIG));
    items.AddItem(Item({Error("later item failure", ENOENT)}));
    EXPECT_TRUE(items.HasSelectedItems());
    const auto result = items.AllSelectedItemsSatisfied();
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EIO, result.Error().code);
    EXPECT_EQ("first failure", result.Error().message);
}

TEST(ResultEvidenceTest, CollectionErrorDoesNotImplyExistenceAndSurvivesLaterItems)
{
    SelectedItemsEvidence items;
    EXPECT_FALSE(items.HasSelectedItems());
    EXPECT_EQ(StateSatisfaction::Satisfied, items.AllSelectedItemsSatisfied().Value());
    items.RecordCollectionError(Error("collection failed", EACCES));
    EXPECT_FALSE(items.HasSelectedItems());
    items.AddItem(Item({StateSatisfaction::Satisfied}));
    items.AddItem(Item({Error("comparison failed", EIO)}));
    EXPECT_TRUE(items.HasSelectedItems());
    const auto result = items.AllSelectedItemsSatisfied();
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EACCES, result.Error().code);
    EXPECT_EQ("collection failed", result.Error().message);
}

TEST(ResultEvidenceTest, EmptyItemValidationDoesNotMaskLaterCollectionErrors)
{
    SelectedItemsEvidence items;
    items.AddItem(SelectedItemComparisonEvidence{});
    EXPECT_TRUE(items.HasSelectedItems());
    const auto invalid = items.AllSelectedItemsSatisfied();
    ASSERT_FALSE(invalid.HasValue());
    EXPECT_EQ(EINVAL, invalid.Error().code);
    items.RecordCollectionError(Error("collection failed", EIO));
    items.AddItem(Item({StateSatisfaction::Satisfied}));
    const auto result = items.AllSelectedItemsSatisfied();
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EIO, result.Error().code);
    EXPECT_EQ("collection failed", result.Error().message);
}

TEST(ResultEvidenceTest, CompleteEmptyAndAbsentRootsNeedUnionWideExistence)
{
    std::vector<std::string> diagnostics;
    const auto empty = Root(PasswordCreditRoot::Outcome::Complete, {}, {"excluded-decoy"});
    const auto absent = Root(PasswordCreditRoot::Outcome::Absent);
    EXPECT_EQ(Status::NonCompliant, Evaluate(empty, empty, diagnostics).Value());
    EXPECT_EQ(Status::NonCompliant, Evaluate(absent, empty, diagnostics).Value());
    EXPECT_EQ(Status::NonCompliant, Evaluate(empty, absent, diagnostics).Value());
    EXPECT_EQ(Status::NonCompliant, Evaluate(absent, absent, diagnostics).Value());
    EXPECT_EQ((std::vector<std::string>{
                  "main:excluded:excluded-decoy", "drop-in:excluded:excluded-decoy", "drop-in:excluded:excluded-decoy", "main:excluded:excluded-decoy"}),
        diagnostics);
}

TEST(ResultEvidenceTest, EitherLocationSuppliesTheOnlyPassingItem)
{
    std::vector<std::string> diagnostics;
    const auto passing = Root(PasswordCreditRoot::Outcome::Complete, {Credit("credit", -1)});
    for (const auto other : {PasswordCreditRoot::Outcome::Absent, PasswordCreditRoot::Outcome::Complete})
    {
        const auto optional = Root(other);
        EXPECT_EQ(Status::Compliant, Evaluate(passing, optional, diagnostics).Value());
        EXPECT_EQ(Status::Compliant, Evaluate(optional, passing, diagnostics).Value());
    }
    EXPECT_EQ((std::vector<std::string>{"main:selected:credit", "drop-in:selected:credit", "main:selected:credit", "drop-in:selected:credit"}), diagnostics);
}

TEST(ResultEvidenceTest, ExcludedDecoyDoesNotInvalidatePassingSelection)
{
    std::vector<std::string> diagnostics;
    const auto passing = Root(PasswordCreditRoot::Outcome::Complete, {Credit("credit", -1)});
    const auto decoy = Root(PasswordCreditRoot::Outcome::Complete, {}, {"excluded-failing-decoy"});
    EXPECT_EQ(Status::Compliant, Evaluate(passing, decoy, diagnostics).Value());
    EXPECT_EQ(Status::Compliant, Evaluate(decoy, passing, diagnostics).Value());
    EXPECT_EQ((std::vector<std::string>{
                  "main:selected:credit", "drop-in:excluded:excluded-failing-decoy", "main:excluded:excluded-failing-decoy", "drop-in:selected:credit"}),
        diagnostics);
}

TEST(ResultEvidenceTest, AllSelectedItemsMustPassInEitherLocationAndOrder)
{
    std::vector<std::string> diagnostics;
    const auto passing = Root(PasswordCreditRoot::Outcome::Complete, {Credit("negative", std::numeric_limits<long long>::min())});
    for (const long long failing : {0LL, 1LL, std::numeric_limits<long long>::max()})
    {
        const auto bad = Root(PasswordCreditRoot::Outcome::Complete, {Credit("nonnegative", failing)});
        EXPECT_EQ(Status::NonCompliant, Evaluate(passing, bad, diagnostics).Value());
        EXPECT_EQ(Status::NonCompliant, Evaluate(bad, passing, diagnostics).Value());
    }
    const auto malformed = Root(PasswordCreditRoot::Outcome::Complete, {{"selected-malformed", {}}});
    EXPECT_EQ(Status::NonCompliant, Evaluate(passing, malformed, diagnostics).Value());
    EXPECT_EQ(Status::NonCompliant, Evaluate(malformed, passing, diagnostics).Value());
    const auto overflow = Root(PasswordCreditRoot::Outcome::Complete, {{"selected-overflow", {}}});
    EXPECT_EQ(Status::NonCompliant, Evaluate(passing, overflow, diagnostics).Value());
    EXPECT_EQ(Status::NonCompliant, Evaluate(overflow, passing, diagnostics).Value());
    EXPECT_FALSE(diagnostics.empty());
}

TEST(ResultEvidenceTest, RequiredErrorAfterPassingItemKeepsOriginalErrorAndProvenance)
{
    std::vector<std::string> diagnostics;
    const auto passing = Root(PasswordCreditRoot::Outcome::Complete, {Credit("previous", -1)});
    const auto failed = FailedRoot("read failed", EIO, {"observed-before-error"});
    for (const auto& result : {Evaluate(passing, failed, diagnostics), Evaluate(failed, passing, diagnostics)})
    {
        ASSERT_FALSE(result.HasValue());
        EXPECT_EQ(EIO, result.Error().code);
        EXPECT_EQ("read failed", result.Error().message);
    }
    EXPECT_EQ((std::vector<std::string>{"main:selected:previous", "drop-in:observed:observed-before-error", "main:observed:observed-before-error",
                  "drop-in:selected:previous"}),
        diagnostics);
}

TEST(ResultEvidenceTest, InsufficientStopAfterPassingItemKeepsReasonAndProvenance)
{
    std::vector<std::string> diagnostics;
    const auto passing = Root(PasswordCreditRoot::Outcome::Complete, {Credit("previous", -1)});
    const auto stopped = Root(PasswordCreditRoot::Outcome::Stopped, {}, {}, "later siblings unvisited", {"observed-before-stop"});
    for (const auto& result : {Evaluate(passing, stopped, diagnostics), Evaluate(stopped, passing, diagnostics)})
    {
        ASSERT_FALSE(result.HasValue());
        EXPECT_EQ(EINVAL, result.Error().code);
        EXPECT_NE(std::string::npos, result.Error().message.find("later siblings unvisited"));
    }
    EXPECT_EQ((std::vector<std::string>{
                  "main:selected:previous", "drop-in:observed:observed-before-stop", "main:observed:observed-before-stop", "drop-in:selected:previous"}),
        diagnostics);
}

TEST(ResultEvidenceTest, ReachedErrorTakesPrecedenceOverInsufficientStop)
{
    std::vector<std::string> diagnostics;
    const auto stopped = Root(PasswordCreditRoot::Outcome::Stopped, {}, {}, "later siblings unvisited", {"stopped-item"});
    const auto failed = FailedRoot("read failed", EIO, {"error-item"});
    for (const auto& result : {Evaluate(stopped, failed, diagnostics), Evaluate(failed, stopped, diagnostics)})
    {
        ASSERT_FALSE(result.HasValue());
        EXPECT_EQ(EIO, result.Error().code);
        EXPECT_EQ("read failed", result.Error().message);
    }
    EXPECT_EQ((std::vector<std::string>{
                  "main:observed:stopped-item", "drop-in:observed:error-item", "main:observed:error-item", "drop-in:observed:stopped-item"}),
        diagnostics);
}

TEST(ResultEvidenceTest, InvalidAbsenceAndMissingReporterAreErrors)
{
    std::vector<std::string> diagnostics;
    const auto absentWithItem = Root(PasswordCreditRoot::Outcome::Absent, {Credit("impossible", -1)});
    const auto empty = Root(PasswordCreditRoot::Outcome::Complete);
    EXPECT_EQ(EINVAL, Evaluate(absentWithItem, empty, diagnostics).Error().code);
    const auto stoppedWithoutReason = Root(PasswordCreditRoot::Outcome::Stopped);
    const auto stopped = Evaluate(empty, stoppedWithoutReason, diagnostics);
    ASSERT_FALSE(stopped.HasValue());
    EXPECT_NE(std::string::npos, stopped.Error().message.find("lacks a reason"));
    EXPECT_EQ(EINVAL, ComplianceEngine::EvaluatePasswordCreditUnion(empty, empty, {}).Error().code);
}

TEST(ResultEvidenceTest, UnmarkedRootCannotProduceACompliantVerdict)
{
    PasswordCreditRoot defaultInitialized;
    defaultInitialized.selected.push_back(Credit("credit", -1));
    PasswordCreditRoot valueInitialized{};
    valueInitialized.selected.push_back(Credit("credit", -1));
    const auto absent = Root(PasswordCreditRoot::Outcome::Absent);

    for (const auto& root : {defaultInitialized, valueInitialized})
    {
        std::vector<std::string> diagnostics;
        const PasswordCreditAssessment unmarked = {root, {}};
        const auto asMain = Evaluate(unmarked, absent, diagnostics);
        ASSERT_FALSE(asMain.HasValue());
        EXPECT_EQ(EINVAL, asMain.Error().code);
        EXPECT_EQ("Invalid password credit root outcome: main", asMain.Error().message);
        const auto asDropIn = Evaluate(absent, unmarked, diagnostics);
        ASSERT_FALSE(asDropIn.HasValue());
        EXPECT_EQ(EINVAL, asDropIn.Error().code);
        EXPECT_EQ("Invalid password credit root outcome: drop-in", asDropIn.Error().message);
        EXPECT_EQ((std::vector<std::string>{"main:selected:credit", "drop-in:selected:credit"}), diagnostics);
    }
}

TEST(ResultEvidenceTest, ReportsSelectedExcludedAndObservedWithoutMaskingOriginalError)
{
    std::vector<std::string> diagnostics;
    const auto main = Root(PasswordCreditRoot::Outcome::Complete, {Credit("same-name", -1)}, {"excluded"});
    const auto failure = FailedRoot("read failed", EIO, {"same-name"});
    const auto result = Evaluate(main, failure, diagnostics);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EIO, result.Error().code);
    EXPECT_EQ((std::vector<std::string>{"main:selected:same-name", "main:excluded:excluded", "drop-in:observed:same-name"}), diagnostics);
}

TEST(ResultEvidenceTest, ProducerBudgetErrorSurvivesIncrementalReporting)
{
    const auto passing = Root(PasswordCreditRoot::Outcome::Complete, {Credit("previous", -1)});
    const auto exhausted = FailedRoot("Retained path budget exhausted", E2BIG, {"last-observed"});
    size_t reported = 0;
    const auto result =
        ComplianceEngine::EvaluatePasswordCreditUnion(passing, exhausted, [&](CreditRootLocation root, CreditEvidenceKind kind, const std::string& identity) {
            EXPECT_TRUE(((root == CreditRootLocation::Main) && (kind == CreditEvidenceKind::Selected) && (identity == "previous")) ||
                        ((root == CreditRootLocation::DropIn) && (kind == CreditEvidenceKind::Observed) && (identity == "last-observed")));
            ++reported;
        });
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(E2BIG, result.Error().code);
    EXPECT_EQ("Retained path budget exhausted", result.Error().message);
    EXPECT_EQ(2U, reported);
}
