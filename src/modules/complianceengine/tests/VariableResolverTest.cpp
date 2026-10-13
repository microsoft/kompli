// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <VariableResolver.h>
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
VariableResolution::CollectObject MockCollection(VariableResolution::ObjectCollection collection)
{
    return [collection](const std::string& ref) -> Result<VariableResolution::ObjectCollection> {
        if (ref != "object:1")
        {
            return Error("Unknown object reference", ENOENT);
        }
        return collection;
    };
}
} // namespace

TEST(VariableResolver, ComponentFlattensAllMatchingFields)
{
    VariableResolution::ObjectCollection collection;
    collection.complete = true;
    collection.items.emplace_back();
    collection.items.back().fields["subexpression"] = {"alice", "bob"};
    collection.items.emplace_back();
    collection.items.back().fields["subexpression"] = {"carol"};
    auto result = VariableResolution::ResolveObjectFieldValues("object:1", "subexpression", MockCollection(collection));
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ((std::vector<std::string>{"alice", "bob", "carol"}), result.Value());
}

TEST(VariableResolver, ZeroItemsAndMissingFieldsAreErrors)
{
    VariableResolution::ObjectCollection noItems;
    noItems.complete = true;
    auto empty = VariableResolution::ResolveObjectFieldValues("object:1", "subexpression", MockCollection(noItems));
    ASSERT_FALSE(empty.HasValue());
    EXPECT_EQ(ENODATA, empty.Error().code);

    VariableResolution::ObjectCollection missing;
    missing.complete = true;
    missing.items.emplace_back();
    missing.items.back().fields["other"] = {"value"};
    auto result = VariableResolution::ResolveObjectFieldValues("object:1", "subexpression", MockCollection(missing));
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EINVAL, result.Error().code);
}

TEST(VariableResolver, IncompleteAndReadErrorsCannotYieldPartialValues)
{
    VariableResolution::ObjectCollection partial;
    partial.items.emplace_back();
    partial.items.back().fields["subexpression"] = {"nodev"};
    auto incomplete = VariableResolution::ResolveObjectFieldValues("object:1", "subexpression", MockCollection(partial));
    ASSERT_FALSE(incomplete.HasValue());
    EXPECT_EQ(EAGAIN, incomplete.Error().code);

    VariableResolution::CollectObject failed = [](const std::string&) -> Result<VariableResolution::ObjectCollection> {
        return Error("Cannot read /etc/fstab", EACCES);
    };
    auto unreadable = VariableResolution::ResolveObjectFieldValues("object:1", "subexpression", failed);
    ASSERT_FALSE(unreadable.HasValue());
    EXPECT_EQ(EACCES, unreadable.Error().code);
}

TEST(VariableResolver, SplitPreservesEveryValueIncludingEmptySegments)
{
    auto result = VariableResolution::Split({"nodev,,nosuid", "", "noexec,"}, ",");
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ((std::vector<std::string>{"nodev", "", "nosuid", "", "noexec", ""}), result.Value());
    EXPECT_FALSE(VariableResolution::Split({"nodev"}, "").HasValue());
}

TEST(VariableResolver, UniqueCountUsesAcceptedTypedComparison)
{
    const std::vector<std::string> nameservers{"1.1.1.1", "1.1.1.1", "8.8.8.8"};
    auto unique = VariableResolution::Unique(nameservers);
    EXPECT_EQ((std::vector<std::string>{"1.1.1.1", "8.8.8.8"}), unique);
    auto result = VariableResolution::CompareCount(unique, 2, TypedComparisonOperation::GreaterOrEqual);
    ASSERT_TRUE(result.HasValue());
    EXPECT_TRUE(result.Value());
    EXPECT_EQ(3, VariableResolution::Count(nameservers).Value());
}

TEST(VariableResolver, IntegerConversionPreservesErrorsAndBoundaries)
{
    auto values = VariableResolution::IntegerValues({"999", "1000", "-1", std::to_string(LLONG_MAX)});
    ASSERT_TRUE(values.HasValue());
    EXPECT_EQ((std::vector<long long>{999, 1000, -1, LLONG_MAX}), values.Value());
    for (const auto& invalid : {"", "12x", "1.0", " 42", "42 ", "+"})
    {
        auto result = VariableResolution::IntegerValues({invalid});
        ASSERT_FALSE(result.HasValue());
        EXPECT_EQ(EINVAL, result.Error().code);
    }
    auto overflow = VariableResolution::IntegerValues({"9223372036854775808"});
    ASSERT_FALSE(overflow.HasValue());
    EXPECT_EQ(ERANGE, overflow.Error().code);

    const auto sourceDistinct = VariableResolution::Unique({"001", "1", "001", "2"});
    EXPECT_EQ((std::vector<std::string>{"001", "1", "2"}), sourceDistinct);
    auto parsed = VariableResolution::IntegerValues(sourceDistinct);
    ASSERT_TRUE(parsed.HasValue());
    EXPECT_EQ((std::vector<long long>{1, 1, 2}), parsed.Value());
}

TEST(VariableResolver, ExtractsAlreadyCollectedItemsWithoutCopyingCollection)
{
    VariableResolution::ObjectCollection collection;
    collection.complete = true;
    collection.items.emplace_back();
    collection.items.back().fields["subexpression"] = {"001", "1"};
    auto values = VariableResolution::ExtractObjectFields(collection, "object:1", "subexpression");
    ASSERT_TRUE(values.HasValue());
    EXPECT_EQ((std::vector<std::string>{"001", "1"}), values.Value());

    collection.complete = false;
    EXPECT_EQ(EAGAIN, VariableResolution::ExtractObjectFields(collection, "object:1", "subexpression").Error().code);
    collection.complete = true;
    collection.items.clear();
    EXPECT_EQ(ENODATA, VariableResolution::ExtractObjectFields(collection, "object:1", "subexpression").Error().code);
}
