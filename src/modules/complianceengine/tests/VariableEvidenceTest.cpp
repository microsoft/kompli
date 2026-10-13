// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <VariableEvidence.h>
#include <cerrno>
#include <climits>
#include <gtest/gtest.h>
#include <string>
#include <vector>

using ComplianceEngine::Error;
using ComplianceEngine::Result;
using ComplianceEngine::TypedComparisonOperation;
namespace VariableResolution = ComplianceEngine::VariableResolution;

namespace
{
VariableResolution::CollectObject MockCollection(VariableResolution::ObjectCollection collection, int* calls = nullptr)
{
    return [collection, calls](const std::string& ref) -> Result<VariableResolution::ObjectCollection> {
        if (calls != nullptr)
        {
            ++*calls;
        }
        if (ref != "object:1")
        {
            return Error("Unknown object reference", ENOENT);
        }
        return collection;
    };
}
} // namespace

TEST(VariableEvidence, CompleteCollectionIsCollectedOnceAndPreservesCardinality)
{
    VariableResolution::ObjectCollection collection;
    collection.complete = true;
    collection.items.emplace_back();
    collection.items.back().fields["value"] = {"rw", "nodev"};
    collection.items.emplace_back();
    collection.items.back().fields["value"] = {"nosuid"};
    int calls = 0;

    auto evidence = VariableResolution::ResolveStringEvidence("object:1", "value", MockCollection(collection, &calls));

    ASSERT_TRUE(evidence.HasValue());
    EXPECT_EQ(1, calls);
    EXPECT_EQ(VariableResolution::EvidenceState::Complete, evidence.Value().state);
    EXPECT_EQ((std::vector<std::string>{"rw", "nodev", "nosuid"}), evidence.Value().values);
    EXPECT_EQ("object:1:value", evidence.Value().source);
}

TEST(VariableEvidence, IncompleteCollectionDiscardsPartialValues)
{
    VariableResolution::ObjectCollection collection;
    collection.items.emplace_back();
    collection.items.back().fields["value"] = {"nodev"};

    auto evidence = VariableResolution::ResolveStringEvidence("object:1", "value", MockCollection(collection));

    ASSERT_TRUE(evidence.HasValue());
    EXPECT_EQ(VariableResolution::EvidenceState::Incomplete, evidence.Value().state);
    EXPECT_TRUE(evidence.Value().values.empty());

    auto split = VariableResolution::SplitEvidence(evidence.Value(), ",");
    ASSERT_TRUE(split.HasValue());
    EXPECT_EQ(VariableResolution::EvidenceState::Incomplete, split.Value().state);
    EXPECT_TRUE(split.Value().values.empty());

    auto compared = VariableResolution::CompareStateValues(evidence.Value(), std::string{"nodev"}, TypedComparisonOperation::Equal);
    ASSERT_TRUE(compared.HasValue());
    EXPECT_EQ(VariableResolution::EvidenceState::Incomplete, compared.Value().state);
    EXPECT_TRUE(compared.Value().values.empty());

    auto integers = VariableResolution::ResolveIntegerEvidence("object:1", "value", MockCollection(collection));
    ASSERT_TRUE(integers.HasValue());
    EXPECT_EQ(VariableResolution::EvidenceState::Incomplete, integers.Value().state);
    EXPECT_TRUE(integers.Value().values.empty());

    auto unique = VariableResolution::UniqueEvidence(evidence.Value());
    ASSERT_TRUE(unique.HasValue());
    EXPECT_EQ(VariableResolution::EvidenceState::Incomplete, unique.Value().state);
    EXPECT_TRUE(unique.Value().values.empty());

    auto count = VariableResolution::CountEvidence(unique.Value());
    ASSERT_TRUE(count.HasValue());
    EXPECT_EQ(VariableResolution::EvidenceState::Incomplete, count.Value().state);
    EXPECT_TRUE(count.Value().values.empty());

    auto invalidSplit = VariableResolution::SplitEvidence(evidence.Value(), "");
    ASSERT_FALSE(invalidSplit.HasValue());
    EXPECT_EQ(EINVAL, invalidSplit.Error().code);
}

TEST(VariableEvidence, HardCollectionAndExtractionErrorsRemainErrors)
{
    VariableResolution::CollectObject unreadable = [](const std::string&) -> Result<VariableResolution::ObjectCollection> {
        return Error("Cannot read source", EACCES);
    };
    auto read = VariableResolution::ResolveStringEvidence("object:1", "value", unreadable);
    ASSERT_FALSE(read.HasValue());
    EXPECT_EQ(EACCES, read.Error().code);

    VariableResolution::ObjectCollection empty;
    empty.complete = true;
    auto noItems = VariableResolution::ResolveStringEvidence("object:1", "value", MockCollection(empty));
    ASSERT_FALSE(noItems.HasValue());
    EXPECT_EQ(ENODATA, noItems.Error().code);

    VariableResolution::ObjectCollection missing;
    missing.complete = true;
    missing.items.emplace_back();
    auto noField = VariableResolution::ResolveStringEvidence("object:1", "value", MockCollection(missing));
    ASSERT_FALSE(noField.HasValue());
    EXPECT_EQ(EINVAL, noField.Error().code);
}

TEST(VariableEvidence, IntegerResolutionIsStrictAndTyped)
{
    VariableResolution::ObjectCollection collection;
    collection.complete = true;
    collection.items.emplace_back();
    collection.items.back().fields["uid"] = {"001", "999", "1000", std::to_string(LLONG_MAX)};

    auto evidence = VariableResolution::ResolveIntegerEvidence("object:1", "uid", VariableResolution::VariableDatatype::Integer, MockCollection(collection));

    ASSERT_TRUE(evidence.HasValue());
    EXPECT_EQ((std::vector<long long>{1, 999, 1000, LLONG_MAX}), evidence.Value().values);

    collection.items.front().fields["uid"] = {"1000x"};
    auto malformed = VariableResolution::ResolveIntegerEvidence("object:1", "uid", VariableResolution::VariableDatatype::Integer, MockCollection(collection));
    ASSERT_FALSE(malformed.HasValue());
    EXPECT_EQ(EINVAL, malformed.Error().code);

    collection.items.front().fields["uid"] = {"9223372036854775808"};
    auto overflow = VariableResolution::ResolveIntegerEvidence("object:1", "uid", VariableResolution::VariableDatatype::Integer, MockCollection(collection));
    ASSERT_FALSE(overflow.HasValue());
    EXPECT_EQ(ERANGE, overflow.Error().code);

    auto wrongDatatype = VariableResolution::ResolveIntegerEvidence("object:1", "uid", VariableResolution::VariableDatatype::String, MockCollection(collection));
    ASSERT_FALSE(wrongDatatype.HasValue());
    EXPECT_EQ(EINVAL, wrongDatatype.Error().code);
}

TEST(VariableEvidence, UniqueCountAndComparisonComposeWithoutFlatteningErrors)
{
    VariableResolution::ObjectCollection collection;
    collection.complete = true;
    collection.items.emplace_back();
    collection.items.back().fields["subexpression"] = {"1.1.1.1", "1.1.1.1", "8.8.8.8"};
    auto values = VariableResolution::ResolveEvidence("object:1", "subexpression", VariableResolution::VariableDatatype::String, MockCollection(collection));
    ASSERT_TRUE(values.HasValue());

    auto unique = VariableResolution::UniqueEvidence(values.Value());
    ASSERT_TRUE(unique.HasValue());
    EXPECT_EQ((std::vector<std::string>{"1.1.1.1", "8.8.8.8"}), unique.Value().values);

    auto count = VariableResolution::CountEvidence(unique.Value());
    ASSERT_TRUE(count.HasValue());
    EXPECT_EQ((std::vector<long long>{2}), count.Value().values);

    auto compared = VariableResolution::CompareStateValues(count.Value(), 2LL, TypedComparisonOperation::GreaterOrEqual);
    ASSERT_TRUE(compared.HasValue());
    EXPECT_EQ((std::vector<bool>{true}), compared.Value().values);
}

TEST(VariableEvidence, ScalarEvidenceComparisonPreservesBothCountChains)
{
    VariableResolution::ValueEvidence<long long> total{VariableResolution::EvidenceState::Complete, {3}, "passwd:total", {}};
    VariableResolution::ValueEvidence<long long> unique{VariableResolution::EvidenceState::Complete, {2}, "passwd:unique", {}};

    auto duplicate = VariableResolution::CompareScalarEvidence(total, unique, TypedComparisonOperation::Equal);
    ASSERT_TRUE(duplicate.HasValue());
    EXPECT_EQ((std::vector<bool>{false}), duplicate.Value().values);

    unique.values = {3};
    auto noDuplicate = VariableResolution::CompareScalarEvidence(total, unique, TypedComparisonOperation::Equal);
    ASSERT_TRUE(noDuplicate.HasValue());
    EXPECT_EQ((std::vector<bool>{true}), noDuplicate.Value().values);

    unique = VariableResolution::IncompleteEvidence<long long>("passwd:unique", "partial passwd read");
    auto incomplete = VariableResolution::CompareScalarEvidence(total, unique, TypedComparisonOperation::Equal);
    ASSERT_TRUE(incomplete.HasValue());
    EXPECT_EQ(VariableResolution::EvidenceState::Incomplete, incomplete.Value().state);
    EXPECT_TRUE(incomplete.Value().values.empty());

    auto nonexistent = VariableResolution::DoesNotExistEvidence<long long>("passwd:missing");
    auto missingRight = VariableResolution::CompareScalarEvidence(unique, nonexistent, TypedComparisonOperation::Equal);
    ASSERT_FALSE(missingRight.HasValue());
    EXPECT_EQ(ENODATA, missingRight.Error().code);

    auto missingLeft = VariableResolution::CompareScalarEvidence(nonexistent, unique, TypedComparisonOperation::Equal);
    ASSERT_FALSE(missingLeft.HasValue());
    EXPECT_EQ(ENODATA, missingLeft.Error().code);
}

TEST(VariableEvidence, UidCountsComposeFromCollectedStringValues)
{
    VariableResolution::ObjectCollection collection;
    collection.complete = true;
    collection.items.emplace_back();
    collection.items.back().fields["uid"] = {"1000"};

    auto compareCounts = [](const VariableResolution::ObjectCollection& source) -> Result<VariableResolution::ValueEvidence<bool>> {
        auto values = VariableResolution::ResolveStringEvidence("object:1", "uid", MockCollection(source));
        if (!values.HasValue())
        {
            return values.Error();
        }
        auto total = VariableResolution::CountEvidence(values.Value());
        if (!total.HasValue())
        {
            return total.Error();
        }
        auto unique = VariableResolution::UniqueEvidence(values.Value());
        if (!unique.HasValue())
        {
            return unique.Error();
        }
        auto uniqueCount = VariableResolution::CountEvidence(unique.Value());
        if (!uniqueCount.HasValue())
        {
            return uniqueCount.Error();
        }
        return VariableResolution::CompareScalarEvidence(total.Value(), uniqueCount.Value(), TypedComparisonOperation::Equal);
    };

    auto one = compareCounts(collection);
    ASSERT_TRUE(one.HasValue());
    EXPECT_EQ((std::vector<bool>{true}), one.Value().values);

    collection.items.front().fields["uid"] = {"1000", "1000", "1001"};
    auto duplicate = compareCounts(collection);
    ASSERT_TRUE(duplicate.HasValue());
    EXPECT_EQ((std::vector<bool>{false}), duplicate.Value().values);

    collection.items.front().fields["uid"] = {"001", "1"};
    auto stringDistinct = compareCounts(collection);
    ASSERT_TRUE(stringDistinct.HasValue());
    EXPECT_EQ((std::vector<bool>{true}), stringDistinct.Value().values);
}

TEST(VariableEvidence, SplitAndPerValueComparisonPreserveRepeatedValues)
{
    VariableResolution::ObjectCollection collection;
    collection.complete = true;
    collection.items.emplace_back();
    collection.items.back().fields["subexpression"] = {"rw,nodev,,nosuid", ""};
    auto options = VariableResolution::ResolveEvidence("object:1", "subexpression", VariableResolution::VariableDatatype::String, MockCollection(collection));
    ASSERT_TRUE(options.HasValue());

    auto split = VariableResolution::SplitEvidence(options.Value(), ",");
    ASSERT_TRUE(split.HasValue());
    EXPECT_EQ((std::vector<std::string>{"rw", "nodev", "", "nosuid", ""}), split.Value().values);

    auto compared = VariableResolution::CompareStateValues(split.Value(), std::string{"nodev"}, TypedComparisonOperation::Equal);
    ASSERT_TRUE(compared.HasValue());
    EXPECT_EQ((std::vector<bool>{false, true, false, false, false}), compared.Value().values);

    auto wrongDatatype =
        VariableResolution::ResolveEvidence("object:1", "subexpression", VariableResolution::VariableDatatype::Integer, MockCollection(collection));
    ASSERT_FALSE(wrongDatatype.HasValue());
    EXPECT_EQ(EINVAL, wrongDatatype.Error().code);
}

TEST(VariableEvidence, NonexistentVariableCannotFeedFunctionsOrStateComparison)
{
    auto missing = VariableResolution::DoesNotExistEvidence<std::string>("variable:1");

    auto unique = VariableResolution::UniqueEvidence(missing);
    ASSERT_FALSE(unique.HasValue());
    EXPECT_EQ(ENODATA, unique.Error().code);

    auto count = VariableResolution::CountEvidence(missing);
    ASSERT_FALSE(count.HasValue());
    EXPECT_EQ(ENODATA, count.Error().code);

    auto split = VariableResolution::SplitEvidence(missing, ",");
    ASSERT_FALSE(split.HasValue());
    EXPECT_EQ(ENODATA, split.Error().code);

    auto compared = VariableResolution::CompareStateValues(missing, std::string{"nodev"}, TypedComparisonOperation::Equal);
    ASSERT_FALSE(compared.HasValue());
    EXPECT_EQ(ENODATA, compared.Error().code);
}

TEST(VariableEvidence, EmptyStateAndInvalidOperationsAreErrors)
{
    VariableResolution::ValueEvidence<std::string> empty{VariableResolution::EvidenceState::Complete, {}, "variable:empty", {}};
    auto compared = VariableResolution::CompareStateValues(empty, std::string{"nodev"}, TypedComparisonOperation::Equal);
    ASSERT_FALSE(compared.HasValue());
    EXPECT_EQ(ENODATA, compared.Error().code);

    const auto invalid = static_cast<TypedComparisonOperation>(-1);
    auto invalidEmpty = VariableResolution::CompareStateValues(empty, std::string{"nodev"}, invalid);
    ASSERT_FALSE(invalidEmpty.HasValue());
    EXPECT_EQ(EINVAL, invalidEmpty.Error().code);

    VariableResolution::ValueEvidence<long long> lhs{VariableResolution::EvidenceState::Complete, {1}, "lhs", {}};
    VariableResolution::ValueEvidence<long long> rhs{VariableResolution::EvidenceState::Complete, {1}, "rhs", {}};
    auto invalidScalar = VariableResolution::CompareScalarEvidence(lhs, rhs, invalid);
    ASSERT_FALSE(invalidScalar.HasValue());
    EXPECT_EQ(EINVAL, invalidScalar.Error().code);

    rhs.values = {1, 2};
    auto multiple = VariableResolution::CompareScalarEvidence(lhs, rhs, TypedComparisonOperation::Equal);
    ASSERT_FALSE(multiple.HasValue());
    EXPECT_EQ(EINVAL, multiple.Error().code);
}
