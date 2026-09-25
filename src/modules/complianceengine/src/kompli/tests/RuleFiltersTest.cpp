// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <RuleFilters.hpp>
#include <gtest/gtest.h>
#include <string>
#include <vector>

using ComplianceEngine::Kompli::FilterResultRules;
using ComplianceEngine::Kompli::RuleFilters;

TEST(RuleFiltersTest, PositiveValuesAreOrWithinAnAxisAndAndAcrossAxes)
{
    RuleFilters filters;
    filters.tags = {"level:l1", "level:l2"};
    filters.sections = {"1.1.*", "2.*"};

    EXPECT_TRUE(filters.Matches("1.1.3", {"level:l2"}));
    EXPECT_TRUE(filters.Matches("2.4", {"level:l1"}));
    EXPECT_FALSE(filters.Matches("3.1", {"level:l1"}));
    EXPECT_FALSE(filters.Matches("1.1.3", {"level:l3"}));
}

TEST(RuleFiltersTest, ExclusionWins)
{
    RuleFilters filters;
    filters.tags = {"level:l1"};
    filters.sections = {"1.*"};
    filters.excludedTags = {"severity:critical"};
    filters.excludedSections = {"1.1.2.*"};

    EXPECT_TRUE(filters.Matches("1.1.1.1", {"level:l1", "severity:low"}));
    EXPECT_FALSE(filters.Matches("1.1.1.2", {"level:l1", "severity:critical"}));
    EXPECT_FALSE(filters.Matches("1.1.2.1", {"level:l1", "severity:low"}));
}

TEST(RuleFiltersTest, TagsAreExactAndSectionsArePosixGlobs)
{
    RuleFilters filters;
    filters.tags = {"level:l1"};
    filters.sections = {"1.[12].*"};

    EXPECT_TRUE(filters.Matches("1.2.3", {"level:l1"}));
    EXPECT_FALSE(filters.Matches("1.3.3", {"level:l1"}));
    EXPECT_FALSE(filters.Matches("1.2.3", {"level:l10"}));
}

TEST(FilterResultRulesTest, KeepsRunWideFactsAndSelectedRules)
{
    const std::string json = R"({"timestamp":"t","durationMs":42,"status":"NonCompliant","rules":[)"
                             R"({"id":"1.1","tags":["level:l1"],"status":"Compliant"},)"
                             R"({"id":"1.2","tags":["level:l2"],"status":"NonCompliant"}]})";
    RuleFilters filters;
    filters.tags = {"level:l1"};

    auto result = FilterResultRules(json, filters);
    ASSERT_TRUE(result.HasValue()) << result.Error().message;
    EXPECT_NE(result.Value().find("\"durationMs\":42"), std::string::npos);
    EXPECT_NE(result.Value().find("\"status\":\"NonCompliant\""), std::string::npos);
    EXPECT_NE(result.Value().find("\"id\":\"1.1\""), std::string::npos);
    EXPECT_EQ(result.Value().find("\"id\":\"1.2\""), std::string::npos);
}

TEST(FilterResultRulesTest, RejectsExplicitZeroMatch)
{
    RuleFilters filters;
    filters.sections = {"9.*"};

    auto result = FilterResultRules(R"({"rules":[{"id":"1.1","tags":[]}]})", filters);
    EXPECT_FALSE(result.HasValue());
}

TEST(FilterResultRulesTest, NoFiltersReturnInputUnchanged)
{
    const std::string json = R"({"rules":[{"id":"1.1"}]})";
    auto result = FilterResultRules(json, {});
    ASSERT_TRUE(result.HasValue()) << result.Error().message;
    EXPECT_EQ(result.Value(), json);
}
