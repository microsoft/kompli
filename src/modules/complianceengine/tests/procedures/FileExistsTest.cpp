// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <FileExists.h>
#include <MockContext.h>
#include <fstream>
#include <gtest/gtest.h>

using ComplianceEngine::AuditFileExists;
using ComplianceEngine::Error;
using ComplianceEngine::FileExistsParams;
using ComplianceEngine::IndicatorsTree;
using ComplianceEngine::Result;
using ComplianceEngine::Status;

class EnsureFileExistsTest : public ::testing::Test
{
protected:
    std::string mFilename;
    MockContext mContext;
    IndicatorsTree mIndicators;

    void SetUp() override
    {
        mIndicators.Push("EnsureFileExistsTest");
        mFilename = mContext.MakeTempfile("");
    }
};

TEST_F(EnsureFileExistsTest, Exists)
{
    std::ofstream file(mFilename);
    FileExistsParams params;
    params.filename = mFilename;
    auto result = AuditFileExists(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(EnsureFileExistsTest, DoesNotExist)
{
    FileExistsParams params;
    params.filename = mFilename;
    auto result = AuditFileExists(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}
