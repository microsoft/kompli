// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <OvalVariableEvidence.h>
#include <cerrno>
#include <climits>
#include <gtest/gtest.h>
#include <string>
#include <vector>

using ComplianceEngine::Error;
using ComplianceEngine::Result;
using ComplianceEngine::TypedComparisonOperation;
namespace OvalVariable = ComplianceEngine::OvalVariable;

namespace
{
OvalVariable::CollectObject MockCollection(OvalVariable::ObjectCollection collection, int* calls = nullptr)
{
    return [collection, calls](const std::string& ref) -> Result<OvalVariable::ObjectCollection> {
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

TEST(OvalVariableEvidence, CompleteCollectionIsCollectedOnceAndPreservesCardinality)
{
    OvalVariable::ObjectCollection collection;
    collection.complete = true;
    collection.items.emplace_back();
    collection.items.back().fields["value"] = {"rw", "nodev"};
    collection.items.emplace_back();
    collection.items.back().fields["value"] = {"nosuid"};
    int calls = 0;

    auto evidence = OvalVariable::ResolveStringEvidence("object:1", "value", MockCollection(collection, &calls));

    ASSERT_TRUE(evidence.HasValue());
    EXPECT_EQ(1, calls);
    EXPECT_EQ(OvalVariable::EvidenceState::Complete, evidence.Value().state);
    EXPECT_EQ((std::vector<std::string>{"rw", "nodev", "nosuid"}), evidence.Value().values);
    EXPECT_EQ("object:1:value", evidence.Value().source);
}

TEST(OvalVariableEvidence, IncompleteCollectionDiscardsPartialValues)
{
    OvalVariable::ObjectCollection collection;
    collection.items.emplace_back();
    collection.items.back().fields["value"] = {"nodev"};

    auto evidence = OvalVariable::ResolveStringEvidence("object:1", "value", MockCollection(collection));

    ASSERT_TRUE(evidence.HasValue());
    EXPECT_EQ(OvalVariable::EvidenceState::Incomplete, evidence.Value().state);
    EXPECT_TRUE(evidence.Value().values.empty());

    auto split = OvalVariable::SplitEvidence(evidence.Value(), ",");
    ASSERT_TRUE(split.HasValue());
    EXPECT_EQ(OvalVariable::EvidenceState::Incomplete, split.Value().state);
    EXPECT_TRUE(split.Value().values.empty());

    auto compared = OvalVariable::CompareStateValues(evidence.Value(), std::string{"nodev"}, TypedComparisonOperation::Equal);
    ASSERT_TRUE(compared.HasValue());
    EXPECT_EQ(OvalVariable::EvidenceState::Incomplete, compared.Value().state);
    EXPECT_TRUE(compared.Value().values.empty());

    auto integers = OvalVariable::ResolveIntegerEvidence("object:1", "value", MockCollection(collection));
    ASSERT_TRUE(integers.HasValue());
    EXPECT_EQ(OvalVariable::EvidenceState::Incomplete, integers.Value().state);
    EXPECT_TRUE(integers.Value().values.empty());

    auto unique = OvalVariable::UniqueEvidence(evidence.Value());
    ASSERT_TRUE(unique.HasValue());
    EXPECT_EQ(OvalVariable::EvidenceState::Incomplete, unique.Value().state);
    EXPECT_TRUE(unique.Value().values.empty());

    auto count = OvalVariable::CountEvidence(unique.Value());
    ASSERT_TRUE(count.HasValue());
    EXPECT_EQ(OvalVariable::EvidenceState::Incomplete, count.Value().state);
    EXPECT_TRUE(count.Value().values.empty());

    auto invalidSplit = OvalVariable::SplitEvidence(evidence.Value(), "");
    ASSERT_FALSE(invalidSplit.HasValue());
    EXPECT_EQ(EINVAL, invalidSplit.Error().code);
}

TEST(OvalVariableEvidence, HardCollectionAndExtractionErrorsRemainErrors)
{
    OvalVariable::CollectObject unreadable = [](const std::string&) -> Result<OvalVariable::ObjectCollection> {
        return Error("Cannot read source", EACCES);
    };
    auto read = OvalVariable::ResolveStringEvidence("object:1", "value", unreadable);
    ASSERT_FALSE(read.HasValue());
    EXPECT_EQ(EACCES, read.Error().code);

    OvalVariable::ObjectCollection empty;
    empty.complete = true;
    auto noItems = OvalVariable::ResolveStringEvidence("object:1", "value", MockCollection(empty));
    ASSERT_FALSE(noItems.HasValue());
    EXPECT_EQ(ENODATA, noItems.Error().code);

    OvalVariable::ObjectCollection missing;
    missing.complete = true;
    missing.items.emplace_back();
    auto noField = OvalVariable::ResolveStringEvidence("object:1", "value", MockCollection(missing));
    ASSERT_FALSE(noField.HasValue());
    EXPECT_EQ(EINVAL, noField.Error().code);
}

TEST(OvalVariableEvidence, IntegerResolutionIsStrictAndTyped)
{
    OvalVariable::ObjectCollection collection;
    collection.complete = true;
    collection.items.emplace_back();
    collection.items.back().fields["uid"] = {"001", "999", "1000", std::to_string(LLONG_MAX)};

    auto evidence = OvalVariable::ResolveIntegerEvidence("object:1", "uid", OvalVariable::VariableDatatype::Integer, MockCollection(collection));

    ASSERT_TRUE(evidence.HasValue());
    EXPECT_EQ((std::vector<long long>{1, 999, 1000, LLONG_MAX}), evidence.Value().values);

    collection.items.front().fields["uid"] = {"1000x"};
    auto malformed = OvalVariable::ResolveIntegerEvidence("object:1", "uid", OvalVariable::VariableDatatype::Integer, MockCollection(collection));
    ASSERT_FALSE(malformed.HasValue());
    EXPECT_EQ(EINVAL, malformed.Error().code);

    collection.items.front().fields["uid"] = {"9223372036854775808"};
    auto overflow = OvalVariable::ResolveIntegerEvidence("object:1", "uid", OvalVariable::VariableDatatype::Integer, MockCollection(collection));
    ASSERT_FALSE(overflow.HasValue());
    EXPECT_EQ(ERANGE, overflow.Error().code);

    auto wrongDatatype = OvalVariable::ResolveIntegerEvidence("object:1", "uid", OvalVariable::VariableDatatype::String, MockCollection(collection));
    ASSERT_FALSE(wrongDatatype.HasValue());
    EXPECT_EQ(EINVAL, wrongDatatype.Error().code);
}

TEST(OvalVariableEvidence, UniqueCountAndComparisonComposeWithoutFlatteningErrors)
{
    OvalVariable::ObjectCollection collection;
    collection.complete = true;
    collection.items.emplace_back();
    collection.items.back().fields["subexpression"] = {"1.1.1.1", "1.1.1.1", "8.8.8.8"};
    auto values = OvalVariable::ResolveEvidence("object:1", "subexpression", OvalVariable::VariableDatatype::String, MockCollection(collection));
    ASSERT_TRUE(values.HasValue());

    auto unique = OvalVariable::UniqueEvidence(values.Value());
    ASSERT_TRUE(unique.HasValue());
    EXPECT_EQ((std::vector<std::string>{"1.1.1.1", "8.8.8.8"}), unique.Value().values);

    auto count = OvalVariable::CountEvidence(unique.Value());
    ASSERT_TRUE(count.HasValue());
    EXPECT_EQ((std::vector<long long>{2}), count.Value().values);

    auto compared = OvalVariable::CompareStateValues(count.Value(), 2LL, TypedComparisonOperation::GreaterOrEqual);
    ASSERT_TRUE(compared.HasValue());
    EXPECT_EQ((std::vector<bool>{true}), compared.Value().values);
}

TEST(OvalVariableEvidence, ScalarEvidenceComparisonPreservesBothCountChains)
{
    OvalVariable::ValueEvidence<long long> total{OvalVariable::EvidenceState::Complete, {3}, "passwd:total", {}};
    OvalVariable::ValueEvidence<long long> unique{OvalVariable::EvidenceState::Complete, {2}, "passwd:unique", {}};

    auto duplicate = OvalVariable::CompareScalarEvidence(total, unique, TypedComparisonOperation::Equal);
    ASSERT_TRUE(duplicate.HasValue());
    EXPECT_EQ((std::vector<bool>{false}), duplicate.Value().values);

    unique.values = {3};
    auto noDuplicate = OvalVariable::CompareScalarEvidence(total, unique, TypedComparisonOperation::Equal);
    ASSERT_TRUE(noDuplicate.HasValue());
    EXPECT_EQ((std::vector<bool>{true}), noDuplicate.Value().values);

    unique = OvalVariable::IncompleteEvidence<long long>("passwd:unique", "partial passwd read");
    auto incomplete = OvalVariable::CompareScalarEvidence(total, unique, TypedComparisonOperation::Equal);
    ASSERT_TRUE(incomplete.HasValue());
    EXPECT_EQ(OvalVariable::EvidenceState::Incomplete, incomplete.Value().state);
    EXPECT_TRUE(incomplete.Value().values.empty());

    auto nonexistent = OvalVariable::DoesNotExistEvidence<long long>("passwd:missing");
    auto missingRight = OvalVariable::CompareScalarEvidence(unique, nonexistent, TypedComparisonOperation::Equal);
    ASSERT_FALSE(missingRight.HasValue());
    EXPECT_EQ(ENODATA, missingRight.Error().code);

    auto missingLeft = OvalVariable::CompareScalarEvidence(nonexistent, unique, TypedComparisonOperation::Equal);
    ASSERT_FALSE(missingLeft.HasValue());
    EXPECT_EQ(ENODATA, missingLeft.Error().code);
}

TEST(OvalVariableEvidence, UidCountsComposeFromCollectedStringValues)
{
    OvalVariable::ObjectCollection collection;
    collection.complete = true;
    collection.items.emplace_back();
    collection.items.back().fields["uid"] = {"1000"};

    auto compareCounts = [](const OvalVariable::ObjectCollection& source) -> Result<OvalVariable::ValueEvidence<bool>> {
        auto values = OvalVariable::ResolveStringEvidence("object:1", "uid", MockCollection(source));
        if (!values.HasValue())
        {
            return values.Error();
        }
        auto total = OvalVariable::CountEvidence(values.Value());
        if (!total.HasValue())
        {
            return total.Error();
        }
        auto unique = OvalVariable::UniqueEvidence(values.Value());
        if (!unique.HasValue())
        {
            return unique.Error();
        }
        auto uniqueCount = OvalVariable::CountEvidence(unique.Value());
        if (!uniqueCount.HasValue())
        {
            return uniqueCount.Error();
        }
        return OvalVariable::CompareScalarEvidence(total.Value(), uniqueCount.Value(), TypedComparisonOperation::Equal);
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

TEST(OvalVariableEvidence, SplitAndPerValueComparisonPreserveRepeatedValues)
{
    OvalVariable::ObjectCollection collection;
    collection.complete = true;
    collection.items.emplace_back();
    collection.items.back().fields["subexpression"] = {"rw,nodev,,nosuid", ""};
    auto options = OvalVariable::ResolveEvidence("object:1", "subexpression", OvalVariable::VariableDatatype::String, MockCollection(collection));
    ASSERT_TRUE(options.HasValue());

    auto split = OvalVariable::SplitEvidence(options.Value(), ",");
    ASSERT_TRUE(split.HasValue());
    EXPECT_EQ((std::vector<std::string>{"rw", "nodev", "", "nosuid", ""}), split.Value().values);

    auto compared = OvalVariable::CompareStateValues(split.Value(), std::string{"nodev"}, TypedComparisonOperation::Equal);
    ASSERT_TRUE(compared.HasValue());
    EXPECT_EQ((std::vector<bool>{false, true, false, false, false}), compared.Value().values);

    auto wrongDatatype = OvalVariable::ResolveEvidence("object:1", "subexpression", OvalVariable::VariableDatatype::Integer, MockCollection(collection));
    ASSERT_FALSE(wrongDatatype.HasValue());
    EXPECT_EQ(EINVAL, wrongDatatype.Error().code);
}

TEST(OvalVariableEvidence, NonexistentVariableCannotFeedFunctionsOrStateComparison)
{
    auto missing = OvalVariable::DoesNotExistEvidence<std::string>("variable:1");

    auto unique = OvalVariable::UniqueEvidence(missing);
    ASSERT_FALSE(unique.HasValue());
    EXPECT_EQ(ENODATA, unique.Error().code);

    auto count = OvalVariable::CountEvidence(missing);
    ASSERT_FALSE(count.HasValue());
    EXPECT_EQ(ENODATA, count.Error().code);

    auto split = OvalVariable::SplitEvidence(missing, ",");
    ASSERT_FALSE(split.HasValue());
    EXPECT_EQ(ENODATA, split.Error().code);

    auto compared = OvalVariable::CompareStateValues(missing, std::string{"nodev"}, TypedComparisonOperation::Equal);
    ASSERT_FALSE(compared.HasValue());
    EXPECT_EQ(ENODATA, compared.Error().code);
}

TEST(OvalVariableEvidence, EmptyStateAndInvalidOperationsAreErrors)
{
    OvalVariable::ValueEvidence<std::string> empty{OvalVariable::EvidenceState::Complete, {}, "variable:empty", {}};
    auto compared = OvalVariable::CompareStateValues(empty, std::string{"nodev"}, TypedComparisonOperation::Equal);
    ASSERT_FALSE(compared.HasValue());
    EXPECT_EQ(ENODATA, compared.Error().code);

    const auto invalid = static_cast<TypedComparisonOperation>(-1);
    auto invalidEmpty = OvalVariable::CompareStateValues(empty, std::string{"nodev"}, invalid);
    ASSERT_FALSE(invalidEmpty.HasValue());
    EXPECT_EQ(EINVAL, invalidEmpty.Error().code);

    OvalVariable::ValueEvidence<long long> lhs{OvalVariable::EvidenceState::Complete, {1}, "lhs", {}};
    OvalVariable::ValueEvidence<long long> rhs{OvalVariable::EvidenceState::Complete, {1}, "rhs", {}};
    auto invalidScalar = OvalVariable::CompareScalarEvidence(lhs, rhs, invalid);
    ASSERT_FALSE(invalidScalar.HasValue());
    EXPECT_EQ(EINVAL, invalidScalar.Error().code);

    rhs.values = {1, 2};
    auto multiple = OvalVariable::CompareScalarEvidence(lhs, rhs, TypedComparisonOperation::Equal);
    ASSERT_FALSE(multiple.HasValue());
    EXPECT_EQ(EINVAL, multiple.Error().code);
}
