// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <PasswordCreditUnionEvidence.h>
#include <ResultEvidence.h>
#include <cerrno>
#include <gtest/gtest.h>
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
} // anonymous namespace

TEST(ResultEvidenceTest, CompleteItemExistenceAndUniversalState)
{
    CompletedItemEvidence empty;
    EXPECT_EQ(Status::NonCompliant, empty.EvaluateAtLeastOneAll().Value());
    CompletedItemEvidence all;
    all.AddSelected(true);
    all.AddSelected(true);
    EXPECT_EQ(Status::Compliant, all.EvaluateAtLeastOneAll().Value());
    all.AddSelected(false);
    EXPECT_EQ(Status::NonCompliant, all.EvaluateAtLeastOneAll().Value());
    all.AddSelected(true);
    EXPECT_EQ(Status::NonCompliant, all.EvaluateAtLeastOneAll().Value());
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
