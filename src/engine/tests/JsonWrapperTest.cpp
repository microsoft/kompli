// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <ComplianceEngineInterface.h>
#include <JsonWrapper.h>
#include <Mmi.h>
#include <cerrno>
#include <gtest/gtest.h>
#include <string>

using ComplianceEngine::JsonWrapper;

TEST(JsonWrapperTest, RejectsRawNulAcrossLengthBearingInput)
{
    const std::string valid = R"({"value":"safe"})";
    for (const auto position : {std::size_t{0}, valid.size() / 2, valid.size()})
    {
        std::string input = valid;
        input.insert(position, 1, '\0');
        auto result = JsonWrapper::FromString(input);
        ASSERT_FALSE(result.HasValue());
        EXPECT_EQ(result.Error().code, EINVAL);
    }
}

TEST(JsonWrapperTest, RejectsEscapedNulOnlyWhenDecodedInJsonString)
{
    EXPECT_FALSE(JsonWrapper::FromString(R"({"value":"\u0000"})").HasValue());
    EXPECT_FALSE(JsonWrapper::FromString(R"({"\u0000":"value"})").HasValue());
    EXPECT_TRUE(JsonWrapper::FromString(R"({"value":"\\u0000"})").HasValue());
    EXPECT_TRUE(JsonWrapper::FromString(R"({"value":"escaped \" quote and \\u0000"})").HasValue());
    EXPECT_FALSE(JsonWrapper::FromString(static_cast<const char*>(nullptr)).HasValue());
}

TEST(JsonWrapperTest, RejectsNulAfterBase64Decoding)
{
    EXPECT_FALSE(JsonWrapper::FromBase64("eyJ2YWx1ZSI6InNhZmUifQBqdW5r").HasValue());
    EXPECT_FALSE(JsonWrapper::FromBase64("eyJhdWRpdCI6eyJhbGxPZiI6W119LCJub3RlIjoiXHUwMDAwIn0=").HasValue());
}

TEST(JsonWrapperTest, RejectsNulWhenConstructingJsonStrings)
{
    const std::string value("safe\0suffix", 11);
    EXPECT_FALSE(JsonWrapper::FromJsonString(value).HasValue());
    EXPECT_TRUE(JsonWrapper::FromJsonString(R"(literal \u0000)").HasValue());
}

namespace
{
class MmiNulIngressTest : public ::testing::Test
{
protected:
    MMI_HANDLE mHandle = nullptr;

    void SetUp() override
    {
        ComplianceEngineInitialize(nullptr);
        mHandle = ComplianceEngineMmiOpen("test", 100);
        ASSERT_NE(mHandle, nullptr);
    }

    void TearDown() override
    {
        ComplianceEngineMmiClose(mHandle);
        ComplianceEngineShutdown();
    }

    int Set(const char* objectName, const std::string& payload) const
    {
        return ComplianceEngineMmiSet(mHandle, "ComplianceEngine", objectName, payload.data(), static_cast<int>(payload.size()));
    }

    std::string Get(const char* objectName) const
    {
        char* payload = nullptr;
        int payloadSize = 0;
        if (MMI_OK != ComplianceEngineMmiGet(mHandle, "ComplianceEngine", objectName, &payload, &payloadSize))
        {
            return {};
        }
        const std::string result(payload, payloadSize);
        ComplianceEngineMmiFree(payload);
        return result;
    }
};
} // namespace

TEST_F(MmiNulIngressTest, RejectsRawNulAtBeginningMiddleAndEndOfOuterPayload)
{
    const std::string valid = R"("eyJhdWRpdCI6eyJhbGxPZiI6W119fQ==")";
    for (const auto position : {std::size_t{0}, valid.size() / 2, valid.size()})
    {
        std::string payload = valid;
        payload.insert(position, 1, '\0');
        EXPECT_EQ(EINVAL, Set("procedureX", payload));
    }
    EXPECT_EQ(MMI_OK, Set("procedureX", valid));
    EXPECT_NE(Get("auditX").find("PASS"), std::string::npos);
}

TEST_F(MmiNulIngressTest, RejectsEscapedNulInOuterStringsAndKeys)
{
    EXPECT_EQ(EINVAL, Set("procedureX", R"("prefix\u0000suffix")"));
    EXPECT_EQ(EINVAL, Set("procedureX", R"({"audit":{"allOf":[]},"\u0000":0})"));
    EXPECT_EQ(EINVAL, Set("procedureX", R"({"audit":{"allOf":[]},"note":"\u0000"})"));
    EXPECT_EQ(MMI_OK, Set("procedureX", R"({"audit":{"allOf":[]},"note":"\\u0000"})"));
    EXPECT_NE(Get("auditX").find("PASS"), std::string::npos);
    EXPECT_EQ(MMI_OK, Set("procedureX", R"("{\"audit\":{\"allOf\":[]},\"note\":\"\\\\u0000\"}")"));
    EXPECT_NE(Get("auditX").find("PASS"), std::string::npos);
}

TEST_F(MmiNulIngressTest, WrappedAndBase64InnerNulRetainExistingEngineErrorPolicy)
{
    const std::string valid = R"("eyJhdWRpdCI6eyJhbGxPZiI6W119fQ==")";
    const std::string wrapped = R"("{\"audit\":{\"allOf\":[]},\"note\":\"\\u0000\"}")";
    const std::string base64 = R"("eyJhdWRpdCI6eyJhbGxPZiI6W119LCJub3RlIjoiXHUwMDAwIn0=")";
    for (const auto& invalid : {wrapped, base64})
    {
        ASSERT_EQ(MMI_OK, Set("procedureX", valid));
        ASSERT_NE(Get("auditX").find("PASS"), std::string::npos);

        // Engine::SetProcedure removes the prior rule before parsing; MMI maps
        // the resulting non-critical EINVAL to MMI_OK. This test records that
        // existing policy, not an atomic-replacement guarantee.
        EXPECT_EQ(MMI_OK, Set("procedureX", invalid));
        EXPECT_NE(Get("auditX").find("Rule not found"), std::string::npos);
    }
}
