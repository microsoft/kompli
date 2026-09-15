// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "CommonUtils.h"
#include "Evaluator.h"
#include "MockContext.h"

#include <Optional.h>
#include <UniqueGroupId.h>
#include <fstream>

using ComplianceEngine::AuditUniqueGroupId;
using ComplianceEngine::Error;
using ComplianceEngine::IndicatorsTree;
using ComplianceEngine::NestedListFormatter;
using ComplianceEngine::Optional;
using ComplianceEngine::Result;
using ComplianceEngine::Status;
using ComplianceEngine::UniqueGroupIdParams;
using std::map;
using std::string;

class EnsureGroupIsOnlyGroupWithTest : public ::testing::Test
{
protected:
    MockContext mContext;
    IndicatorsTree mIndicators;
    NestedListFormatter mFormatter;
    string mTempDir;

    void SetUp() override
    {
        mIndicators.Push("UfwStatus");
        char tempDirTemplate[] = "/tmp/EnsureGroupIsOnlyGroupWithTestXXXXXX";
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

    ComplianceEngine::GroupRecord CreateTestGroup(string groupName, Optional<string> password, Optional<int> gid = Optional<int>(),
        Optional<string> users = Optional<string>())
    {
        UNUSED(password);
        UNUSED(users);
        return {std::move(groupName), static_cast<gid_t>(gid.ValueOr(0))};
    }
};

TEST_F(EnsureGroupIsOnlyGroupWithTest, EmptyFile)
{
    mContext.SetAccountDatabaseRecords({}, {});
    UniqueGroupIdParams params;
    params.groupName = "foo";
    params.gid = 8888;
    auto result = AuditUniqueGroupId(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::NonCompliant);
}

TEST_F(EnsureGroupIsOnlyGroupWithTest, NoParameter)
{
    mContext.SetAccountDatabaseRecords({}, {CreateTestGroup(string("foo"), string("x"), 8888)});
    UniqueGroupIdParams params;
    params.groupName = "foo";
    auto result = AuditUniqueGroupId(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(EnsureGroupIsOnlyGroupWithTest, SingleGID)
{
    mContext.SetAccountDatabaseRecords({}, {CreateTestGroup(string("foo"), string("x"), 8888)});
    UniqueGroupIdParams params;
    params.groupName = "foo";
    params.gid = 8888;
    auto result = AuditUniqueGroupId(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(EnsureGroupIsOnlyGroupWithTest, DuplicatedGID)
{
    mContext.SetAccountDatabaseRecords({}, {{"foo", 8888}, {"bar", 8888}});
    UniqueGroupIdParams params;
    params.groupName = "foo";
    params.gid = 8888;
    auto result = AuditUniqueGroupId(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::NonCompliant);
}
