// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <JsonWrapper.h>
#include <gtest/gtest.h>

TEST(JsonWrapperTest, RejectsRawAndEscapedNulBeforeParsing)
{
    std::string raw = R"({"value":"safe"})";
    raw.push_back('\0');
    raw += "junk";
    EXPECT_FALSE(ComplianceEngine::JsonWrapper::FromString(raw).HasValue());
    EXPECT_FALSE(ComplianceEngine::JsonWrapper::FromString(R"({"value":"\u0000"})").HasValue());
    EXPECT_TRUE(ComplianceEngine::JsonWrapper::FromString(R"({"value":"\\u0000"})").HasValue());
}

TEST(JsonWrapperTest, RejectsNulAfterBase64Decoding)
{
    EXPECT_FALSE(ComplianceEngine::JsonWrapper::FromBase64("eyJ2YWx1ZSI6InNhZmUifQBqdW5r").HasValue());
}

TEST(JsonWrapperTest, RejectsNulWhenConstructingJsonStrings)
{
    const std::string value("safe\0suffix", 11);
    EXPECT_FALSE(ComplianceEngine::JsonWrapper::FromJsonString(value).HasValue());
    EXPECT_TRUE(ComplianceEngine::JsonWrapper::FromJsonString(R"(literal \u0000)").HasValue());
}
