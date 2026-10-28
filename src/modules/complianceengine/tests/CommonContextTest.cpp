// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "CommonContext.h"

#include "GuestConfigurationContext.h"
#include "MockContext.h"

#include <cerrno>
#include <fstream>
#include <gtest/gtest.h>

class CommonContextTest : public ::testing::Test
{
protected:
    MockContext mContext;
};

TEST_F(CommonContextTest, ExecuteCommand_Success)
{
    ComplianceEngine::CommonContext ctx(nullptr, mContext.GetStatePath());
    auto result = ctx.ExecuteCommand("echo test");
    EXPECT_TRUE(result);
    EXPECT_NE(result.Value().find("test"), std::string::npos);
}

TEST_F(CommonContextTest, ExecuteCommand_EmptyOutput)
{
    ComplianceEngine::CommonContext context(nullptr, mContext.GetStatePath());
    for (const std::string command : {"true", "if false; then echo unused; fi"})
    {
        SCOPED_TRACE(command);
        const auto result = context.ExecuteCommand(command);
        ASSERT_TRUE(result.HasValue());
        EXPECT_TRUE(result.Value().empty());
    }
    const auto failure = context.ExecuteCommand("exit 7");
    ASSERT_FALSE(failure.HasValue());
    EXPECT_EQ(failure.Error().code, 7);
}

TEST_F(CommonContextTest, ExecuteCommand_Failure)
{
    ComplianceEngine::CommonContext ctx(nullptr, mContext.GetStatePath());
    auto result = ctx.ExecuteCommand("someinvalidcommand");
    EXPECT_FALSE(result);
    auto err = result.Error();
    std::cout << "Error: code: " << err.code << " message: " << err.message << std::endl;
}

TEST_F(CommonContextTest, GetFileContents_NotFound)
{
    ComplianceEngine::CommonContext ctx(nullptr, mContext.GetStatePath());
    auto result = ctx.GetFileContents("/non_existent_file");
    ASSERT_FALSE(result);
    EXPECT_EQ(result.Error().code, ENOENT);
}

TEST_F(CommonContextTest, GetFileContents_ExistingFile)
{
    ComplianceEngine::CommonContext ctx(nullptr, mContext.GetStatePath());
    std::string expectedContent = "Hello from dummy file";
    const std::string filePath = mContext.MakeTempfile(expectedContent);

    auto result = ctx.GetFileContents(filePath);
    EXPECT_TRUE(result);
    EXPECT_EQ(result.Value(), expectedContent);
}

TEST_F(CommonContextTest, GetFileContents_EmptyFile)
{
    ComplianceEngine::CommonContext ctx(nullptr, mContext.GetStatePath());
    const std::string filePath = mContext.MakeTempfile("");

    auto result = ctx.GetFileContents(filePath);

    ASSERT_TRUE(result);
    EXPECT_TRUE(result.Value().empty());
}

TEST_F(CommonContextTest, GetFileContents_RejectsEmbeddedNul)
{
    ComplianceEngine::CommonContext ctx(nullptr, mContext.GetStatePath());
    const std::string filePath = mContext.MakeTempfile(std::string("a\0b", 3));

    auto result = ctx.GetFileContents(filePath);

    ASSERT_FALSE(result);
    EXPECT_EQ(result.Error().code, EBADMSG);
}

TEST_F(CommonContextTest, GuestConfigurationContext_StatePath)
{
    ComplianceEngine::GuestConfigurationContext ctx(nullptr);
    EXPECT_EQ(ctx.GetStatePath(), "/var/lib/GuestConfig");
}
