// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <MockContext.h>
#include <Users.h>
#include <UsersIterator.h>
#include <gtest/gtest.h>
#include <parsers/LoginDefs.h>

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
    EXPECT_CALL(mContext, GetFileContents("/etc/login.defs")).WillOnce(testing::Return(Result<std::string>("# UID_MIN 50\n  UID_MIN\t1000 \t\n")));
    const auto result = GetUidMin(mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), 1000U);
}

TEST_F(UsersIteratorTest, UidMinSelectsFirstExactOccurrence)
{
    EXPECT_CALL(mContext, GetFileContents("/etc/login.defs"))
        .WillOnce(testing::Return(Result<std::string>("NOT_UID_MIN 500\nUID_MIN 1000\nUID_MIN 2000\n")));
    const auto result = GetUidMin(mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(1000U, result.Value());
}

TEST_F(UsersIteratorTest, UidMinRejectsInlineHashRatherThanStrippingIt)
{
    EXPECT_CALL(mContext, GetFileContents("/etc/login.defs")).WillOnce(testing::Return(Result<std::string>("UID_MIN 1000#note\n")));
    const auto result = GetUidMin(mContext);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EINVAL, result.Error().code);
}

TEST_F(UsersIteratorTest, UidMinRejectsSelectedEmbeddedNul)
{
    EXPECT_CALL(mContext, GetFileContents("/etc/login.defs")).WillOnce(testing::Return(Result<std::string>(std::string("UID_MIN 1000 \0ignored\n", 22))));
    const auto result = GetUidMin(mContext);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EINVAL, result.Error().code);
}

TEST_F(UsersIteratorTest, UidMinRejectsOversizedInput)
{
    EXPECT_CALL(mContext, GetFileContents("/etc/login.defs")).WillOnce(testing::Return(Result<std::string>(std::string(ComplianceEngine::LoginDefs::MaxBytes + 1, 'x'))));
    const auto result = GetUidMin(mContext);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(E2BIG, result.Error().code);
}

TEST_F(UsersIteratorTest, UidMinRejectsMissingValue)
{
    EXPECT_CALL(mContext, GetFileContents("/etc/login.defs")).WillOnce(testing::Return(Result<std::string>("UID_MIN # no value\n")));
    const auto result = GetUidMin(mContext);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(result.Error().code, EINVAL);
}

TEST_F(UsersIteratorTest, UidMinRejectsMalformedSuffix)
{
    EXPECT_CALL(mContext, GetFileContents("/etc/login.defs")).WillOnce(testing::Return(Result<std::string>("UID_MIN 1000junk\n")));
    const auto result = GetUidMin(mContext);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(result.Error().code, EINVAL);
}
