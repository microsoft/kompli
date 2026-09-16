// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <Config.hpp>

#include <gtest/gtest.h>
#include <string>

using std::string;

namespace Komplid
{

TEST(ConfigMissingFileTest, MissingFileYieldsDefaults)
{
    // A path that (almost certainly) doesn't exist - LoadConfig treats ENOENT
    // as "use defaults", not an error. This is the only LoadConfig() (as
    // opposed to LoadConfigFromString()) case that's testable without a
    // root-owned file, since every other path goes through OpenVerifiedInput
    // (see Config.cpp), which requires root ownership.
    auto result = LoadConfig("/nonexistent/path/kompli.conf.does.not.exist");
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(300, result.Value().auditCacheTtlSeconds);
    EXPECT_TRUE(result.Value().backgroundTaskRules.empty());
}

TEST(LoadConfigFromStringTest, ParsesTtlAndBackgroundRules)
{
    auto result = LoadConfigFromString(R"({
        "apiVersion": "v1",
        "kind": "KompliConfig",
        "auditCache": { "ttlSeconds": 60 },
        "backgroundTasks": { "rules": ["1.1", "2.3"] }
    })");
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(60, result.Value().auditCacheTtlSeconds);
    EXPECT_EQ(1u, result.Value().backgroundTaskRules.count("1.1"));
    EXPECT_EQ(1u, result.Value().backgroundTaskRules.count("2.3"));
    EXPECT_EQ(2u, result.Value().backgroundTaskRules.size());
}

TEST(LoadConfigFromStringTest, EmptyEnvelopeOnlyUsesDefaults)
{
    auto result = LoadConfigFromString(R"({"apiVersion": "v1", "kind": "KompliConfig"})");
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(300, result.Value().auditCacheTtlSeconds);
    EXPECT_TRUE(result.Value().backgroundTaskRules.empty());
}

TEST(LoadConfigFromStringTest, RejectsMissingEnvelope)
{
    EXPECT_FALSE(LoadConfigFromString(R"({"auditCache": {"ttlSeconds": 60}})").HasValue());
}

TEST(LoadConfigFromStringTest, RejectsWrongApiVersion)
{
    EXPECT_FALSE(LoadConfigFromString(R"({"apiVersion": "v2", "kind": "KompliConfig"})").HasValue());
}

TEST(LoadConfigFromStringTest, RejectsNegativeTtl)
{
    EXPECT_FALSE(LoadConfigFromString(R"({"apiVersion": "v1", "kind": "KompliConfig", "auditCache": {"ttlSeconds": -1}})").HasValue());
}

TEST(LoadConfigFromStringTest, RejectsNonNumericTtl)
{
    EXPECT_FALSE(LoadConfigFromString(R"({"apiVersion": "v1", "kind": "KompliConfig", "auditCache": {"ttlSeconds": "60"}})").HasValue());
}

TEST(LoadConfigFromStringTest, RejectsNonStringBackgroundRule)
{
    EXPECT_FALSE(LoadConfigFromString(R"({"apiVersion": "v1", "kind": "KompliConfig", "backgroundTasks": {"rules": [1]}})").HasValue());
}

TEST(LoadConfigFromStringTest, RejectsMalformedJson)
{
    EXPECT_FALSE(LoadConfigFromString("not json").HasValue());
}

} // namespace Komplid
