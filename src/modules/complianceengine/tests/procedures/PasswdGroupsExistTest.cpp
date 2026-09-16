// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "PasswdGroupsExist.h"

#include "Evaluator.h"
#include "MockContext.h"

using ComplianceEngine::AuditPasswdGroupsExist;
using ComplianceEngine::IndicatorsTree;
using ComplianceEngine::Status;

class PasswdGroupsExistTest : public ::testing::Test
{
protected:
    MockContext mContext;
    IndicatorsTree mIndicators;

    void SetUp() override
    {
        mIndicators.Push("PasswdGroupsExist");
    }
};

TEST_F(PasswdGroupsExistTest, CompliantWhenPrimaryGroupsExist)
{
    mContext.SetAccountDatabaseRecords({{"root", 0, 0, "/root", "/bin/bash"}, {"user", 1000, 1000, "/home/user", "/bin/bash"}}, {{"root", 0}, {"users", 1000}});

    auto result = AuditPasswdGroupsExist(mIndicators, mContext);

    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);
}

TEST_F(PasswdGroupsExistTest, NonCompliantWhenPrimaryGroupDoesNotExist)
{
    mContext.SetAccountDatabaseRecords({{"root", 0, 0, "/root", "/bin/bash"}, {"user", 1000, 1001, "/home/user", "/bin/bash"}}, {{"root", 0}, {"users", 1000}});

    auto result = AuditPasswdGroupsExist(mIndicators, mContext);

    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::NonCompliant);
}
