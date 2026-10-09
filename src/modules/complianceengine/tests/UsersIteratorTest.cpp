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

TEST_F(UsersIteratorTest, CorruptedFirstUidMinKeyCannotSelectLaterValue)
{
    const char contents[] = "UID_MIN\0 500\nUID_MIN 1000\n";
    EXPECT_CALL(mContext, GetFileContents("/etc/login.defs")).WillOnce(testing::Return(Result<std::string>(std::string(contents, sizeof(contents) - 1))));
    const auto result = GetUidMin(mContext);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EBADMSG, result.Error().code);
}

TEST_F(UsersIteratorTest, ValidFirstUidMinIgnoresLaterCorruptedKey)
{
    const char contents[] = "UID_MIN 500\nUID_MIN\0 1000\n";
    EXPECT_CALL(mContext, GetFileContents("/etc/login.defs")).WillOnce(testing::Return(Result<std::string>(std::string(contents, sizeof(contents) - 1))));
    const auto result = GetUidMin(mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(500U, result.Value());
}

TEST_F(UsersIteratorTest, UnrelatedCorruptedKeyDoesNotBlockUidMin)
{
    const char contents[] = "NOT_UID_MIN\0 2000\nUID_MIN 500\n";
    EXPECT_CALL(mContext, GetFileContents("/etc/login.defs")).WillOnce(testing::Return(Result<std::string>(std::string(contents, sizeof(contents) - 1))));
    const auto result = GetUidMin(mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(500U, result.Value());
}

TEST_F(UsersIteratorTest, UidMinPropagatesRequiredReadError)
{
    for (int code : {EIO, EACCES, -1})
    {
        SCOPED_TRACE(code);
        EXPECT_CALL(mContext, GetFileContents("/etc/login.defs")).WillOnce(testing::Return(Result<std::string>(Error("Read failed", code))));
        const auto result = GetUidMin(mContext);
        ASSERT_FALSE(result.HasValue());
        EXPECT_EQ(code, result.Error().code);
        EXPECT_EQ("Read failed", result.Error().message);
    }
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
