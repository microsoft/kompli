// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "CommonUtils.h"
#include "MockContext.h"

#include <Optional.h>
#include <UniqueUserId.h>
#include <fstream>

using ComplianceEngine::AuditUniqueUserId;
using ComplianceEngine::Error;
using ComplianceEngine::IndicatorsTree;
using ComplianceEngine::NestedListFormatter;
using ComplianceEngine::Optional;
using ComplianceEngine::Result;
using ComplianceEngine::Status;
using ComplianceEngine::UniqueUserIdParams;
using std::map;
using std::string;

class EnsureUserIsOnlyAccountWithTest : public ::testing::Test
{
protected:
    MockContext mContext;
    IndicatorsTree mIndicators;
    NestedListFormatter mFormatter;
    string mTempDir;

    void SetUp() override
    {
        mIndicators.Push("UfwStatus");
        char tempDirTemplate[] = "/tmp/EnsureUserIsOnlyAccountWithTestXXXXXX";
        char* tempDir = mkdtemp(tempDirTemplate);
        ASSERT_NE(tempDir, nullptr);
        mTempDir = tempDir;
    }

    void TearDown() override
    {
        if (!mTempDir.empty())
        {
            if (0 != remove(mTempDir.c_str()))
            {
                OsConfigLogError(mContext.GetLogHandle(), "Failed to remove temporary directory %s: %s", mTempDir.c_str(), strerror(errno));
            }
            mTempDir.clear();
        }
    }

    ComplianceEngine::UserRecord CreateTestUser(string username, Optional<string> password, Optional<int> uid = Optional<int>(),
        Optional<int> gid = Optional<int>(), Optional<string> home = Optional<string>(), Optional<string> shell = Optional<string>())
    {
        UNUSED(password);
        return {std::move(username), static_cast<uid_t>(uid.ValueOr(0)), static_cast<gid_t>(gid.ValueOr(0)), home.ValueOr(""), shell.ValueOr("")};
    }
};

TEST_F(EnsureUserIsOnlyAccountWithTest, NoParameter)
{
    mContext.SetAccountDatabaseRecords({CreateTestUser(string("foo"), string("x"), 8888, 1000, string("/home/foo"), string("/bin/bash"))});
    UniqueUserIdParams params;
    params.username = "foo";
    auto result = AuditUniqueUserId(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(EnsureUserIsOnlyAccountWithTest, EmptyFile)
{
    mContext.SetAccountDatabaseRecords({});
    UniqueUserIdParams params;
    params.username = "foo";
    params.uid = 8888;
    auto result = AuditUniqueUserId(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::NonCompliant);
}

TEST_F(EnsureUserIsOnlyAccountWithTest, SingleUID)
{
    mContext.SetAccountDatabaseRecords({{"foo", 8888, 9999, "/home/foo", "/bin/bash"}});
    UniqueUserIdParams params;
    params.username = "foo";
    params.uid = 8888;
    auto result = AuditUniqueUserId(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(EnsureUserIsOnlyAccountWithTest, DuplicatedUID)
{
    mContext.SetAccountDatabaseRecords({{"foo", 8888, 9999, "/home/foo", "/bin/bash"}, {"bar", 8888, 9999, "/home/bar", "/bin/bash"}});
    UniqueUserIdParams params;
    params.username = "foo";
    params.uid = 8888;
    auto result = AuditUniqueUserId(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::NonCompliant);
}

TEST_F(EnsureUserIsOnlyAccountWithTest, SingleGID)
{
    mContext.SetAccountDatabaseRecords({{"foo", 8888, 9999, "/home/foo", "/bin/bash"}});
    UniqueUserIdParams params;
    params.username = "foo";
    params.gid = 9999;
    auto result = AuditUniqueUserId(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(EnsureUserIsOnlyAccountWithTest, DuplicatedGID)
{
    mContext.SetAccountDatabaseRecords({{"foo", 8888, 9999, "/home/foo", "/bin/bash"}, {"bar", 8888, 9999, "/home/bar", "/bin/bash"}});
    UniqueUserIdParams params;
    params.username = "foo";
    params.gid = 9999;
    auto result = AuditUniqueUserId(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::NonCompliant);
}
