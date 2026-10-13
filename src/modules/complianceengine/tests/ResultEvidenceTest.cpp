// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <PasswordCreditUnionEvidence.h>
#include <ResultEvidence.h>
#include <cerrno>
#include <gtest/gtest.h>
#include <initializer_list>
#include <limits>
#include <stdexcept>
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
    auto state = evidence.AllSelectedStatesSatisfied();
    ASSERT_TRUE(state.HasValue());
    EXPECT_EQ(StateSatisfaction::Satisfied, state.Value());
    evidence.AddSelected(StateSatisfaction::Satisfied);
    evidence.AddSelected(StateSatisfaction::Satisfied);
    state = evidence.AllSelectedStatesSatisfied();
    ASSERT_TRUE(state.HasValue());
    EXPECT_EQ(StateSatisfaction::Satisfied, state.Value());
    evidence.AddSelected(StateSatisfaction::NotSatisfied);
    state = evidence.AllSelectedStatesSatisfied();
    ASSERT_TRUE(state.HasValue());
    EXPECT_EQ(StateSatisfaction::NotSatisfied, state.Value());
    evidence.AddSelected(StateSatisfaction::Satisfied);
    state = evidence.AllSelectedStatesSatisfied();
    ASSERT_TRUE(state.HasValue());
    EXPECT_EQ(StateSatisfaction::NotSatisfied, state.Value());

    CompletedItemEvidence mismatchFirst;
    mismatchFirst.AddSelected(StateSatisfaction::NotSatisfied);
    mismatchFirst.AddSelected(StateSatisfaction::Satisfied);
    state = mismatchFirst.AllSelectedStatesSatisfied();
    ASSERT_TRUE(state.HasValue());
    EXPECT_EQ(StateSatisfaction::NotSatisfied, state.Value());
}

TEST(ResultEvidenceTest, InvalidStateSatisfactionIsAnErrorAtEveryAccumulatorBoundary)
{
    const auto invalid = static_cast<StateSatisfaction>(2);

    CompletedItemEvidence scalar;
    scalar.AddSelected(invalid);
    auto state = scalar.AllSelectedStatesSatisfied();
    ASSERT_FALSE(state.HasValue());
    EXPECT_EQ(EINVAL, state.Error().code);

    CompletedItemEvidence afterMatch;
    afterMatch.AddSelected(StateSatisfaction::Satisfied);
    afterMatch.AddSelected(invalid);
    state = afterMatch.AllSelectedStatesSatisfied();
    ASSERT_FALSE(state.HasValue());
    EXPECT_EQ(EINVAL, state.Error().code);

    CompletedItemEvidence afterMismatch;
    afterMismatch.AddSelected(StateSatisfaction::NotSatisfied);
    afterMismatch.AddSelected(invalid);
    state = afterMismatch.AllSelectedStatesSatisfied();
    ASSERT_FALSE(state.HasValue());
    EXPECT_EQ(EINVAL, state.Error().code);

    CompletedItemEvidence errorFirst;
    errorFirst.AddSelected(Error("first failure", EIO));
    errorFirst.AddSelected(invalid);
    state = errorFirst.AllSelectedStatesSatisfied();
    ASSERT_FALSE(state.HasValue());
    EXPECT_EQ(EIO, state.Error().code);
    EXPECT_EQ("first failure", state.Error().message);

    for (const auto& item : {Item({StateSatisfaction::Satisfied, invalid}), Item({StateSatisfaction::NotSatisfied, invalid})})
    {
        const auto itemState = item.AnyComparisonSatisfied();
        ASSERT_FALSE(itemState.HasValue());
        EXPECT_EQ(EINVAL, itemState.Error().code);

        const auto result = Evaluate(Items({item}));
        ASSERT_FALSE(result.HasValue());
        EXPECT_EQ(EINVAL, result.Error().code);
    }

    const auto comparisonErrorFirst = Item({Error("first comparison failure", EACCES), invalid});
    const auto comparisonState = comparisonErrorFirst.AnyComparisonSatisfied();
    ASSERT_FALSE(comparisonState.HasValue());
    EXPECT_EQ(EACCES, comparisonState.Error().code);
    EXPECT_EQ("first comparison failure", comparisonState.Error().message);
}

TEST(ResultEvidenceTest, RepeatedValuesWithinOneItemUseAtLeastOneInEitherOrder)
{
    const auto matchFirst = Item({StateSatisfaction::Satisfied, StateSatisfaction::NotSatisfied, StateSatisfaction::NotSatisfied});
    const auto matchLast = Item({StateSatisfaction::NotSatisfied, StateSatisfaction::NotSatisfied, StateSatisfaction::Satisfied});
    const auto first = Evaluate(Items({matchFirst}));
    ASSERT_TRUE(first.HasValue());
    EXPECT_EQ(Status::Compliant, first.Value());
    const auto last = Evaluate(Items({matchLast}));
    ASSERT_TRUE(last.HasValue());
    EXPECT_EQ(Status::Compliant, last.Value());
    const auto mismatching = Evaluate(Items({Item({StateSatisfaction::NotSatisfied, StateSatisfaction::NotSatisfied})}));
    ASSERT_TRUE(mismatching.HasValue());
    EXPECT_EQ(Status::NonCompliant, mismatching.Value());
}

TEST(ResultEvidenceTest, DistinctItemsUseAllInEitherOrder)
{
    const auto matching = Item({StateSatisfaction::NotSatisfied, StateSatisfaction::Satisfied});
    const auto mismatching = Item({StateSatisfaction::NotSatisfied});
    const auto matchFirst = Evaluate(Items({matching, mismatching}));
    ASSERT_TRUE(matchFirst.HasValue());
    EXPECT_EQ(Status::NonCompliant, matchFirst.Value());
    const auto matchLast = Evaluate(Items({mismatching, matching}));
    ASSERT_TRUE(matchLast.HasValue());
    EXPECT_EQ(Status::NonCompliant, matchLast.Value());
    const auto allMatching = Evaluate(Items({Item({StateSatisfaction::Satisfied}), matching}));
    ASSERT_TRUE(allMatching.HasValue());
    EXPECT_EQ(Status::Compliant, allMatching.Value());
}

TEST(ResultEvidenceTest, DirectAssessmentsAndRepeatedComparisonsShareOuterAggregation)
{
    SelectedItemsEvidence direct;
    EXPECT_FALSE(direct.HasSelectedItems());
    direct.AddItem(Result<StateSatisfaction>(StateSatisfaction::Satisfied));
    EXPECT_TRUE(direct.HasSelectedItems());
    auto state = direct.AllSelectedItemsSatisfied();
    ASSERT_TRUE(state.HasValue());
    EXPECT_EQ(StateSatisfaction::Satisfied, state.Value());

    direct.AddItem(Result<StateSatisfaction>(StateSatisfaction::NotSatisfied));
    state = direct.AllSelectedItemsSatisfied();
    ASSERT_TRUE(state.HasValue());
    EXPECT_EQ(StateSatisfaction::NotSatisfied, state.Value());

    for (const auto& mixed : {[] {
                                  SelectedItemsEvidence items;
                                  items.AddItem(Result<StateSatisfaction>(StateSatisfaction::Satisfied));
                                  items.AddItem(Item({StateSatisfaction::NotSatisfied, StateSatisfaction::Satisfied}));
                                  return items;
                              }(),
             [] {
                 SelectedItemsEvidence items;
                 items.AddItem(Item({StateSatisfaction::Satisfied, StateSatisfaction::NotSatisfied}));
                 items.AddItem(Result<StateSatisfaction>(StateSatisfaction::Satisfied));
                 return items;
             }()})
    {
        const auto mixedState = mixed.AllSelectedItemsSatisfied();
        ASSERT_TRUE(mixedState.HasValue());
        EXPECT_EQ(StateSatisfaction::Satisfied, mixedState.Value());
    }

    SelectedItemsEvidence mismatchThenRepeated;
    mismatchThenRepeated.AddItem(Result<StateSatisfaction>(StateSatisfaction::NotSatisfied));
    mismatchThenRepeated.AddItem(Item({StateSatisfaction::Satisfied}));
    state = mismatchThenRepeated.AllSelectedItemsSatisfied();
    ASSERT_TRUE(state.HasValue());
    EXPECT_EQ(StateSatisfaction::NotSatisfied, state.Value());

    SelectedItemsEvidence repeatedThenMismatch;
    repeatedThenMismatch.AddItem(Item({StateSatisfaction::Satisfied}));
    repeatedThenMismatch.AddItem(Result<StateSatisfaction>(StateSatisfaction::NotSatisfied));
    state = repeatedThenMismatch.AllSelectedItemsSatisfied();
    ASSERT_TRUE(state.HasValue());
    EXPECT_EQ(StateSatisfaction::NotSatisfied, state.Value());
}

TEST(ResultEvidenceTest, DirectAssessmentErrorsAreSelectedAndRetainFirstError)
{
    SelectedItemsEvidence items;
    items.AddItem(Result<StateSatisfaction>(Error("assessment failed", EIO)));
    EXPECT_TRUE(items.HasSelectedItems());
    items.AddItem(Result<StateSatisfaction>(StateSatisfaction::Satisfied));
    items.AddItem(Item({Error("later failure", EACCES)}));
    auto state = items.AllSelectedItemsSatisfied();
    ASSERT_FALSE(state.HasValue());
    EXPECT_EQ(EIO, state.Error().code);
    EXPECT_EQ("assessment failed", state.Error().message);

    SelectedItemsEvidence invalid;
    invalid.AddItem(Result<StateSatisfaction>(static_cast<StateSatisfaction>(2)));
    state = invalid.AllSelectedItemsSatisfied();
    ASSERT_FALSE(state.HasValue());
    EXPECT_EQ(EINVAL, state.Error().code);

    SelectedItemsEvidence emptyThenError;
    emptyThenError.AddItem(SelectedItemComparisonEvidence{});
    emptyThenError.AddItem(Result<StateSatisfaction>(Error("reached failure", ENOENT)));
    state = emptyThenError.AllSelectedItemsSatisfied();
    ASSERT_FALSE(state.HasValue());
    EXPECT_EQ(ENOENT, state.Error().code);
    EXPECT_EQ("reached failure", state.Error().message);
}

TEST(ResultEvidenceTest, ScalarAndExcludedValueItemsRetainExistencePolicy)
{
    auto selected = Items({Item({StateSatisfaction::Satisfied})});
    const auto excludedDecoy = Item({StateSatisfaction::NotSatisfied});
    const auto withoutDecoy = Evaluate(selected);
    ASSERT_TRUE(withoutDecoy.HasValue());
    EXPECT_EQ(Status::Compliant, withoutDecoy.Value());
    selected.AddItem(excludedDecoy);
    const auto withDecoy = Evaluate(selected);
    ASSERT_TRUE(withDecoy.HasValue());
    EXPECT_EQ(Status::NonCompliant, withDecoy.Value());
    const auto empty = Evaluate(SelectedItemsEvidence{});
    ASSERT_TRUE(empty.HasValue());
    EXPECT_EQ(Status::NonCompliant, empty.Value());
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
    const auto mismatching = item.AnyComparisonSatisfied();
    ASSERT_TRUE(mismatching.HasValue());
    EXPECT_EQ(StateSatisfaction::NotSatisfied, mismatching.Value());
    item.AddComparison(StateSatisfaction::Satisfied);
    const auto matching = item.AnyComparisonSatisfied();
    ASSERT_TRUE(matching.HasValue());
    EXPECT_EQ(StateSatisfaction::Satisfied, matching.Value());
    item.AddComparison(StateSatisfaction::NotSatisfied);
    const auto stillMatching = item.AnyComparisonSatisfied();
    ASSERT_TRUE(stillMatching.HasValue());
    EXPECT_EQ(StateSatisfaction::Satisfied, stillMatching.Value());
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
    const auto empty = items.AllSelectedItemsSatisfied();
    ASSERT_TRUE(empty.HasValue());
    EXPECT_EQ(StateSatisfaction::Satisfied, empty.Value());
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
    const auto bothEmpty = Evaluate(empty, empty, diagnostics);
    ASSERT_TRUE(bothEmpty.HasValue());
    EXPECT_EQ(Status::NonCompliant, bothEmpty.Value());
    const auto mainAbsent = Evaluate(absent, empty, diagnostics);
    ASSERT_TRUE(mainAbsent.HasValue());
    EXPECT_EQ(Status::NonCompliant, mainAbsent.Value());
    const auto dropInAbsent = Evaluate(empty, absent, diagnostics);
    ASSERT_TRUE(dropInAbsent.HasValue());
    EXPECT_EQ(Status::NonCompliant, dropInAbsent.Value());
    const auto bothAbsent = Evaluate(absent, absent, diagnostics);
    ASSERT_TRUE(bothAbsent.HasValue());
    EXPECT_EQ(Status::NonCompliant, bothAbsent.Value());
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
        const auto mainPassing = Evaluate(passing, optional, diagnostics);
        ASSERT_TRUE(mainPassing.HasValue());
        EXPECT_EQ(Status::Compliant, mainPassing.Value());
        const auto dropInPassing = Evaluate(optional, passing, diagnostics);
        ASSERT_TRUE(dropInPassing.HasValue());
        EXPECT_EQ(Status::Compliant, dropInPassing.Value());
    }
    EXPECT_EQ((std::vector<std::string>{"main:selected:credit", "drop-in:selected:credit", "main:selected:credit", "drop-in:selected:credit"}), diagnostics);
}

TEST(ResultEvidenceTest, ExcludedDecoyDoesNotInvalidatePassingSelection)
{
    std::vector<std::string> diagnostics;
    const auto passing = Root(PasswordCreditRoot::Outcome::Complete, {Credit("credit", -1)});
    const auto decoy = Root(PasswordCreditRoot::Outcome::Complete, {}, {"excluded-failing-decoy"});
    const auto mainPassing = Evaluate(passing, decoy, diagnostics);
    ASSERT_TRUE(mainPassing.HasValue());
    EXPECT_EQ(Status::Compliant, mainPassing.Value());
    const auto dropInPassing = Evaluate(decoy, passing, diagnostics);
    ASSERT_TRUE(dropInPassing.HasValue());
    EXPECT_EQ(Status::Compliant, dropInPassing.Value());
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
        const auto mainPassing = Evaluate(passing, bad, diagnostics);
        ASSERT_TRUE(mainPassing.HasValue());
        EXPECT_EQ(Status::NonCompliant, mainPassing.Value());
        const auto dropInPassing = Evaluate(bad, passing, diagnostics);
        ASSERT_TRUE(dropInPassing.HasValue());
        EXPECT_EQ(Status::NonCompliant, dropInPassing.Value());
    }
    const auto malformed = Root(PasswordCreditRoot::Outcome::Complete, {{"selected-malformed", {}}});
    const auto malformedDropIn = Evaluate(passing, malformed, diagnostics);
    ASSERT_TRUE(malformedDropIn.HasValue());
    EXPECT_EQ(Status::NonCompliant, malformedDropIn.Value());
    const auto malformedMain = Evaluate(malformed, passing, diagnostics);
    ASSERT_TRUE(malformedMain.HasValue());
    EXPECT_EQ(Status::NonCompliant, malformedMain.Value());
    const auto overflow = Root(PasswordCreditRoot::Outcome::Complete, {{"selected-overflow", {}}});
    const auto overflowDropIn = Evaluate(passing, overflow, diagnostics);
    ASSERT_TRUE(overflowDropIn.HasValue());
    EXPECT_EQ(Status::NonCompliant, overflowDropIn.Value());
    const auto overflowMain = Evaluate(overflow, passing, diagnostics);
    ASSERT_TRUE(overflowMain.HasValue());
    EXPECT_EQ(Status::NonCompliant, overflowMain.Value());
    EXPECT_FALSE(diagnostics.empty());
}

TEST(ResultEvidenceTest, MultipleCreditsWithinOneRootAllAffectTheVerdict)
{
    const auto absent = Root(PasswordCreditRoot::Outcome::Absent);
    const auto expectedDiagnostics = [](const char* root, const char* first, const char* second) {
        return std::vector<std::string>{
            std::string(root) + ":selected:" + first,
            std::string(root) + ":selected:" + second,
        };
    };

    for (const auto root : {CreditRootLocation::Main, CreditRootLocation::DropIn})
    {
        const auto evaluate = [&](const PasswordCreditAssessment& assessment, std::vector<std::string>& diagnostics) {
            return root == CreditRootLocation::Main ? Evaluate(assessment, absent, diagnostics) : Evaluate(absent, assessment, diagnostics);
        };
        const auto location = root == CreditRootLocation::Main ? "main" : "drop-in";

        struct FailingCase
        {
            PasswordCreditAssessment assessment;
            const char* first;
            const char* second;
        };
        for (const auto& testCase :
            {FailingCase{Root(PasswordCreditRoot::Outcome::Complete, {Credit("negative", -1), Credit("zero", 0)}), "negative", "zero"},
                FailingCase{Root(PasswordCreditRoot::Outcome::Complete, {Credit("zero", 0), Credit("negative", -1)}), "zero", "negative"}})
        {
            std::vector<std::string> diagnostics;
            const auto result = evaluate(testCase.assessment, diagnostics);
            ASSERT_TRUE(result.HasValue());
            EXPECT_EQ(Status::NonCompliant, result.Value());
            EXPECT_EQ(expectedDiagnostics(location, testCase.first, testCase.second), diagnostics);
        }

        std::vector<std::string> diagnostics;
        const auto bothNegative = Root(PasswordCreditRoot::Outcome::Complete, {Credit("first-negative", -1), Credit("second-negative", -2)});
        const auto result = evaluate(bothNegative, diagnostics);
        ASSERT_TRUE(result.HasValue());
        EXPECT_EQ(Status::Compliant, result.Value());
        EXPECT_EQ(expectedDiagnostics(location, "first-negative", "second-negative"), diagnostics);
    }
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
    const auto invalidAbsence = Evaluate(absentWithItem, empty, diagnostics);
    ASSERT_FALSE(invalidAbsence.HasValue());
    EXPECT_EQ(EINVAL, invalidAbsence.Error().code);
    const auto stoppedWithoutReason = Root(PasswordCreditRoot::Outcome::Stopped);
    const auto stopped = Evaluate(empty, stoppedWithoutReason, diagnostics);
    ASSERT_FALSE(stopped.HasValue());
    EXPECT_NE(std::string::npos, stopped.Error().message.find("lacks a reason"));
    const auto missingReporter = ComplianceEngine::EvaluatePasswordCreditUnion(empty, empty, {});
    ASSERT_FALSE(missingReporter.HasValue());
    EXPECT_EQ(EINVAL, missingReporter.Error().code);
}

TEST(ResultEvidenceTest, ReporterExceptionsAreErrorsWithoutMaskingAssessmentErrors)
{
    const auto throwingReporter = [](CreditRootLocation, CreditEvidenceKind, const std::string&) { throw std::runtime_error("report failed"); };
    const auto passing = Root(PasswordCreditRoot::Outcome::Complete, {Credit("credit", -1)});
    const auto empty = Root(PasswordCreditRoot::Outcome::Complete);
    const auto reportFailure = ComplianceEngine::EvaluatePasswordCreditUnion(passing, empty, throwingReporter);
    ASSERT_FALSE(reportFailure.HasValue());
    EXPECT_EQ(EIO, reportFailure.Error().code);
    EXPECT_NE(std::string::npos, reportFailure.Error().message.find("reporter"));

    const auto failed = FailedRoot("read failed", EACCES, {"observed-before-error"});
    const auto assessmentFailure = ComplianceEngine::EvaluatePasswordCreditUnion(failed, passing, throwingReporter);
    ASSERT_FALSE(assessmentFailure.HasValue());
    EXPECT_EQ(EACCES, assessmentFailure.Error().code);
    EXPECT_EQ("read failed", assessmentFailure.Error().message);
}

TEST(ResultEvidenceTest, NonStoppedRootsWithStopReasonsHaveOutcomeNeutralDiagnostics)
{
    const auto empty = Root(PasswordCreditRoot::Outcome::Complete);
    for (const auto outcome : {PasswordCreditRoot::Outcome::Complete, PasswordCreditRoot::Outcome::Absent})
    {
        std::vector<std::string> diagnostics;
        const auto invalid = Root(outcome, {}, {}, "unexpected stop reason");
        const auto main = Evaluate(invalid, empty, diagnostics);
        ASSERT_FALSE(main.HasValue());
        EXPECT_EQ(EINVAL, main.Error().code);
        EXPECT_EQ("Non-stopped password credit root contains a stop reason: main", main.Error().message);
        const auto dropIn = Evaluate(empty, invalid, diagnostics);
        ASSERT_FALSE(dropIn.HasValue());
        EXPECT_EQ(EINVAL, dropIn.Error().code);
        EXPECT_EQ("Non-stopped password credit root contains a stop reason: drop-in", dropIn.Error().message);
    }
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
