// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <MockContext.h>
#include <PasswdGroupsExist.h>
#include <cerrno>

using ComplianceEngine::AuditPasswdGroupsExist;
using ComplianceEngine::IndicatorsTree;
using ComplianceEngine::RemediatePasswdGroupsExist;
using ComplianceEngine::Status;

class PasswdGroupsExistTest : public ::testing::Test
{
protected:
    MockContext mContext;
    IndicatorsTree mIndicators;

    void SetFiles(const std::string& passwd, const std::string& group)
    {
        mContext.SetSpecialFilePath("/etc/passwd", mContext.MakeTempfile(passwd));
        mContext.SetSpecialFilePath("/etc/group", mContext.MakeTempfile(group));
    }

    void SetUp() override
    {
        mIndicators.Push("PasswdGroupsExist");
        SetFiles("root:x:0:0:root:/root:/bin/sh\nalice:x:1000:12345::/home/alice:/bin/sh\n", "root:x:0:\nusers:x:12345:\n");
    }
};

TEST_F(PasswdGroupsExistTest, LocalPrimaryGroupsExist)
{
    const auto result = AuditPasswdGroupsExist(mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(Status::Compliant, result.Value());
}

TEST_F(PasswdGroupsExistTest, MissingLocalPrimaryGroup)
{
    SetFiles("root:x:0:0:root:/root:/bin/sh\nalice:x:1000:12345::/home/alice:/bin/sh\n", "root:x:0:\n");
    const auto result = AuditPasswdGroupsExist(mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(Status::NonCompliant, result.Value());
}

TEST_F(PasswdGroupsExistTest, DoesNotResolveMissingLocalGroupThroughNss)
{
    SetFiles("root:x:0:0:root:/root:/bin/sh\n", "users:x:12345:\n");
    const auto result = AuditPasswdGroupsExist(mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(Status::NonCompliant, result.Value());
}

TEST_F(PasswdGroupsExistTest, EmptyGroupFileDoesNotSatisfyUsers)
{
    SetFiles("root:x:0:0:root:/root:/bin/sh\n", "");
    const auto result = AuditPasswdGroupsExist(mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(Status::NonCompliant, result.Value());
}

TEST_F(PasswdGroupsExistTest, EmptyPasswdFileHasNoMissingGroups)
{
    SetFiles("", "");
    const auto result = AuditPasswdGroupsExist(mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(Status::Compliant, result.Value());
}

TEST_F(PasswdGroupsExistTest, LargeEntries)
{
    SetFiles("alice:x:1000:12345:" + std::string(4096, 'a') + ":/home/alice:/bin/sh\n", "users:x:12345:" + std::string(4096, 'a') + "\n");
    const auto result = AuditPasswdGroupsExist(mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(Status::Compliant, result.Value());
}

TEST_F(PasswdGroupsExistTest, EndOfFileIsNotAnError)
{
    errno = EIO;
    const auto result = AuditPasswdGroupsExist(mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(Status::Compliant, result.Value());
}

TEST_F(PasswdGroupsExistTest, MissingGroupFileReturnsError)
{
    mContext.SetSpecialFilePath("/etc/group", mContext.GetTempdirPath() + "/missing-group");
    const auto result = AuditPasswdGroupsExist(mIndicators, mContext);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(ENOENT, result.Error().code);
}

TEST_F(PasswdGroupsExistTest, MissingPasswdFileReturnsError)
{
    mContext.SetSpecialFilePath("/etc/passwd", mContext.GetTempdirPath() + "/missing-passwd");
    const auto result = AuditPasswdGroupsExist(mIndicators, mContext);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(ENOENT, result.Error().code);
}

TEST_F(PasswdGroupsExistTest, GroupReadFailureIsNotCompliant)
{
    mContext.SetSpecialFilePath("/etc/group", mContext.GetTempdirPath());
    EXPECT_THROW(AuditPasswdGroupsExist(mIndicators, mContext), std::runtime_error);
}

TEST_F(PasswdGroupsExistTest, PasswdReadFailureIsNotCompliant)
{
    mContext.SetSpecialFilePath("/etc/passwd", mContext.GetTempdirPath());
    EXPECT_THROW(AuditPasswdGroupsExist(mIndicators, mContext), std::runtime_error);
}

TEST_F(PasswdGroupsExistTest, RemediationPreservesNonCompliance)
{
    SetFiles("alice:x:1000:12345::/home/alice:/bin/sh\n", "root:x:0:\n");
    const auto result = RemediatePasswdGroupsExist(mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(Status::NonCompliant, result.Value());
}

TEST_F(PasswdGroupsExistTest, RemediationPassesWhenGroupsExist)
{
    const auto result = RemediatePasswdGroupsExist(mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(Status::Compliant, result.Value());
}

TEST_F(PasswdGroupsExistTest, RemediationPropagatesReadError)
{
    mContext.SetSpecialFilePath("/etc/group", mContext.GetTempdirPath() + "/missing-group");
    const auto result = RemediatePasswdGroupsExist(mIndicators, mContext);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(ENOENT, result.Error().code);
}
