// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <MockContext.h>
#include <Users.h>
#include <UsersIterator.h>
#include <gtest/gtest.h>

using ComplianceEngine::Error;
using ComplianceEngine::GetUidMin;
using ComplianceEngine::Result;
using ComplianceEngine::UsersRange;

class UsersIteratorTest : public ::testing::Test
{
protected:
    MockContext mContext;
};

TEST_F(UsersIteratorTest, NonExistentFile)
{
    auto result = UsersRange::Make(mContext.GetTempdirPath() + "/missing-passwd", mContext.GetLogHandle());
    ASSERT_FALSE(result.HasValue());
    ASSERT_EQ(result.Error().code, ENOENT);
    ASSERT_EQ(result.Error().message, "Failed to create UsersRange: No such file or directory");
}

TEST_F(UsersIteratorTest, UidMinAcceptsCommentAndWhitespace)
{
    EXPECT_CALL(mContext, GetFileContents("/etc/login.defs"))
        .WillOnce(testing::Return(Result<std::string>("# UID_MIN 50\n  UID_MIN\t1000 \t# regular users\n")));
    const auto result = GetUidMin(mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), 1000U);
}

TEST_F(UsersIteratorTest, UidMinRejectsMissingValue)
{
    EXPECT_CALL(mContext, GetFileContents("/etc/login.defs")).WillOnce(testing::Return(Result<std::string>("UID_MIN # no value\n")));
    const auto result = GetUidMin(mContext);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(result.Error().code, EINVAL);
}

TEST_F(UsersIteratorTest, UidMinRejectsMalformedSuffixAfterCommentRemoval)
{
    EXPECT_CALL(mContext, GetFileContents("/etc/login.defs")).WillOnce(testing::Return(Result<std::string>("UID_MIN 1000junk # not a valid number\n")));
    const auto result = GetUidMin(mContext);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(result.Error().code, EINVAL);
}
