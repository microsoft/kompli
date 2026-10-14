// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <Ranges.h>
#include <VariableResolver.h>
#include <gtest/gtest.h>
#include <limits>
#include <string>
#include <type_traits>
#include <vector>

using ComplianceEngine::Error;
using ComplianceEngine::Optional;
using ComplianceEngine::Result;
namespace Ranges = ComplianceEngine::Ranges;
namespace VariableResolution = ComplianceEngine::VariableResolution;

namespace
{
struct TestSource
{
    using value_type = std::string;

    std::vector<Result<std::string>> items;
    std::size_t* pulls;
    std::size_t index = 0;

    TestSource(std::vector<Result<std::string>> values, std::size_t& pullCount)
        : items(std::move(values)),
          pulls(&pullCount)
    {
    }

    Result<Optional<std::string>> Next()
    {
        ++*pulls;
        if (items.size() == index)
        {
            return Optional<std::string>();
        }
        const auto& item = items[index++];
        if (!item.HasValue())
        {
            return item.Error();
        }
        return Optional<std::string>(item.Value());
    }
};

VariableResolution::ObjectCollection Collection()
{
    VariableResolution::ObjectCollection collection;
    collection.complete = true;
    collection.items.emplace_back();
    collection.items.back().fields["value"] = {"001", "1", "001"};
    collection.items.emplace_back();
    collection.items.back().fields["value"] = {"2", "1"};
    return collection;
}
} // namespace

TEST(RangesTest, VectorRangeYieldsResultElements)
{
    const std::vector<std::string> values{"first", "", "last"};
    auto range = Ranges::Range(values);
    std::vector<std::string> actual;
    for (const auto& item : range)
    {
        ASSERT_TRUE(item.HasValue());
        actual.push_back(item.Value());
    }
    EXPECT_EQ(values, actual);
}

TEST(RangesTest, ConstructionDoesNotPullAndUniquePullsOnlyToNextDistinctValue)
{
    std::size_t pulls = 0;
    auto source = Ranges::View<TestSource>(TestSource({std::string("a"), std::string("a"), std::string("b"), std::string("c")}, pulls));
    auto distinct = Ranges::Unique(source);
    EXPECT_EQ(0U, pulls);
    auto it = distinct.begin();
    ASSERT_TRUE(it->HasValue());
    EXPECT_EQ("a", it->Value());
    EXPECT_EQ(1U, pulls);
    ++it;
    ASSERT_TRUE(it->HasValue());
    EXPECT_EQ("b", it->Value());
    EXPECT_EQ(3U, pulls);
}

TEST(RangesTest, UniquePreservesFirstOccurrenceOrderAndExactBytes)
{
    const std::string binary("a\0b", 3);
    auto distinct = Ranges::Unique(Ranges::Range(std::vector<std::string>{"001", "1", "", binary, "001", "", "a", binary}));
    std::vector<std::string> actual;
    for (const auto& item : distinct)
    {
        ASSERT_TRUE(item.HasValue());
        actual.push_back(item.Value());
    }
    EXPECT_EQ((std::vector<std::string>{"001", "1", "", binary, "a"}), actual);
}

TEST(RangesTest, UniqueWorksForNonStringValuesAndNestedViews)
{
    auto count = Ranges::Count(Ranges::Unique(Ranges::Unique(Ranges::Range(std::vector<int>{2, 1, 2, 3, 1}))));
    ASSERT_TRUE(count.HasValue());
    EXPECT_EQ(3U, count.Value());
}

TEST(RangesTest, CountReturnsSizeTAndHandlesEmptyRange)
{
    auto count = Ranges::Count(Ranges::Unique(Ranges::Range(std::vector<int>())));
    static_assert(std::is_same<decltype(count), Result<std::size_t>>::value, "Count must return Result<size_t>");
    ASSERT_TRUE(count.HasValue());
    EXPECT_EQ(0U, count.Value());
}

TEST(RangesTest, CountChecksOverflowBeforeIncrement)
{
    const auto maximum = std::numeric_limits<std::size_t>::max();
    const auto last = Ranges::Detail::IncrementCount(maximum - 1);
    ASSERT_TRUE(last.HasValue());
    EXPECT_EQ(maximum, last.Value());
    const auto overflow = Ranges::Detail::IncrementCount(maximum);
    ASSERT_FALSE(overflow.HasValue());
    EXPECT_EQ(ERANGE, overflow.Error().code);
}

TEST(RangesTest, CountConsumesTheEntireInputIncludingTailErrors)
{
    std::size_t pulls = 0;
    auto source =
        Ranges::View<TestSource>(TestSource({std::string("a"), std::string("b"), std::string("a"), Error("tail read failed", EIO), std::string("unreachable")}, pulls));
    const auto count = Ranges::Count(Ranges::Unique(source));
    ASSERT_FALSE(count.HasValue());
    EXPECT_EQ(EIO, count.Error().code);
    EXPECT_EQ("tail read failed", count.Error().message);
    EXPECT_EQ(4U, pulls);
}

TEST(RangesTest, IterationYieldsAnErrorOnceAndDoesNotPullBeyondIt)
{
    std::size_t pulls = 0;
    auto source = Ranges::View<TestSource>(TestSource({Error("first error", EACCES), Error("second error", EIO)}, pulls));
    auto distinct = Ranges::Unique(source);
    std::size_t errors = 0;
    for (const auto& item : distinct)
    {
        ASSERT_FALSE(item.HasValue());
        EXPECT_EQ(EACCES, item.Error().code);
        ++errors;
    }
    EXPECT_EQ(1U, errors);
    EXPECT_EQ(1U, pulls);
}

TEST(RangesTest, NestedTransformsPreserveTheOriginalError)
{
    std::size_t pulls = 0;
    auto count =
        Ranges::Count(Ranges::Unique(Ranges::Unique(Ranges::View<TestSource>(TestSource({std::string("a"), Error("source failure", EAGAIN)}, pulls)))));
    ASSERT_FALSE(count.HasValue());
    EXPECT_EQ(EAGAIN, count.Error().code);
    EXPECT_EQ("source failure", count.Error().message);
    EXPECT_EQ(2U, pulls);
}

TEST(RangesTest, SuccessfulExhaustionDoesNotReadAgain)
{
    std::size_t pulls = 0;
    auto source = Ranges::View<TestSource>(TestSource({std::string("a"), std::string("a")}, pulls));
    auto distinct = Ranges::Unique(source);
    auto count = Ranges::Count(distinct);
    ASSERT_TRUE(count.HasValue());
    EXPECT_EQ(1U, count.Value());
    EXPECT_EQ(3U, pulls);
    EXPECT_EQ(distinct.begin(), distinct.end());
    EXPECT_EQ(3U, pulls);
}

TEST(RangesTest, LvalueVectorIsBorrowedRatherThanCopied)
{
    std::vector<int> values{1, 1};
    auto range = Ranges::Range(values);
    values[1] = 2;
    const auto count = Ranges::Count(Ranges::Unique(range));
    ASSERT_TRUE(count.HasValue());
    EXPECT_EQ(2U, count.Value());
}

TEST(RangesTest, TemporaryVectorSurvivesDelayedConsumptionAndMoves)
{
    auto view = Ranges::Unique(Ranges::Range(std::vector<std::string>{"a", "a", "b"}));
    auto moved = std::move(view);
    auto count = Ranges::Count(moved);
    ASSERT_TRUE(count.HasValue());
    EXPECT_EQ(2U, count.Value());
}

TEST(RangesTest, PartiallyConsumedOwnedPipelineCanBeMoved)
{
    auto view = Ranges::Unique(Ranges::Range(std::vector<int>{1, 1, 2, 3}));
    auto first = view.Next();
    ASSERT_TRUE(first.HasValue());
    ASSERT_TRUE(first.Value().HasValue());
    EXPECT_EQ(1, first.Value().Value());
    auto moved = std::move(view);
    const auto count = Ranges::Count(moved);
    ASSERT_TRUE(count.HasValue());
    EXPECT_EQ(2U, count.Value());
}

TEST(RangesTest, ObjectFieldsFlattenLazilyAndRetainStringUniqueness)
{
    auto collection = Collection();
    auto fields = VariableResolution::ObjectFieldRange(collection, "object:1", "value");
    auto distinct = Ranges::Unique(fields);
    auto count = Ranges::Count(distinct);
    ASSERT_TRUE(count.HasValue());
    EXPECT_EQ(3U, count.Value());
}

TEST(RangesTest, TemporaryObjectCollectionIsOwnedByThePipeline)
{
    auto fields = VariableResolution::ObjectFieldRange(Collection(), "object:1", "value");
    auto moved = std::move(fields);
    const auto count = Ranges::Count(Ranges::Unique(std::move(moved)));
    ASSERT_TRUE(count.HasValue());
    EXPECT_EQ(3U, count.Value());
}

TEST(RangesTest, MissingLaterFieldInvalidatesTheCount)
{
    auto collection = Collection();
    collection.items.back().fields.clear();
    auto count = Ranges::Count(Ranges::Unique(VariableResolution::ObjectFieldRange(collection, "object:1", "value")));
    ASSERT_FALSE(count.HasValue());
    EXPECT_EQ(EINVAL, count.Error().code);
    EXPECT_EQ("Missing object field 'value' in object:1", count.Error().message);
}

TEST(RangesTest, ObjectFieldRangeDistinguishesEmptyIncompleteAndInvalidInput)
{
    auto collection = Collection();
    collection.complete = false;
    auto incomplete = Ranges::Count(VariableResolution::ObjectFieldRange(collection, "object:1", "value"));
    ASSERT_FALSE(incomplete.HasValue());
    EXPECT_EQ(EAGAIN, incomplete.Error().code);
    collection.complete = true;
    collection.items.clear();
    auto empty = Ranges::Count(VariableResolution::ObjectFieldRange(collection, "object:1", "value"));
    ASSERT_FALSE(empty.HasValue());
    EXPECT_EQ(ENODATA, empty.Error().code);
    auto invalid = Ranges::Count(VariableResolution::ObjectFieldRange(collection, "", "value"));
    ASSERT_FALSE(invalid.HasValue());
    EXPECT_EQ(EINVAL, invalid.Error().code);
}
