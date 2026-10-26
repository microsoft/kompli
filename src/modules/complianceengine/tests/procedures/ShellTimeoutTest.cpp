// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "CommonUtils.h"
#include "MockContext.h"

#include <Optional.h>
#include <ShellTimeout.h>
#include <cerrno>
#include <fstream>
#include <iterator>

using ComplianceEngine::AuditShellTimeout;
using ComplianceEngine::Error;
using ComplianceEngine::IndicatorsTree;
using ComplianceEngine::Optional;
using ComplianceEngine::RemediateShellTimeout;
using ComplianceEngine::Result;
using ComplianceEngine::Status;
using std::map;
using std::string;

class EnsureDefaultShellTimeoutIsConfiguredTest : public ::testing::Test
{
protected:
    MockContext mContext;
    IndicatorsTree mIndicators;

    string mTempDir;

    void SetUp() override
    {
        mIndicators.Push("EnsurePasswordChangeIsInPast");
        const auto missingPath = mContext.GetTempdirPath() + "/missing-config";
        mContext.SetSpecialFilePath("/etc/bashrc", missingPath);
        mContext.SetSpecialFilePath("/etc/bash.bashrc", missingPath);
        mContext.SetSpecialFilePath("/etc/profile", missingPath);
        mContext.SetSpecialFilePath("/etc/profile.d/", mContext.GetTempdirPath() + "/missing-config-directory");
    }

    void TearDown() override
    {
    }
};

TEST_F(EnsureDefaultShellTimeoutIsConfiguredTest, NoSpecialFiles)
{
    auto result = AuditShellTimeout(mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::NonCompliant);

    const auto* root = mIndicators.GetRootNode();
    ASSERT_NE(nullptr, root);
    ASSERT_GE(root->indicators.size(), 1u);
    EXPECT_EQ(root->indicators.back().status, Status::NonCompliant);
    EXPECT_EQ(root->indicators.back().message, string("TMOUT is not set"));
}

TEST_F(EnsureDefaultShellTimeoutIsConfiguredTest, IncorrectValue)
{
    auto path = mContext.MakeTempfile("TMOUT=901"); // Acceptance threshold is 900
    mContext.SetSpecialFilePath("/etc/bashrc", path);
    auto result = AuditShellTimeout(mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::NonCompliant);

    const auto* root = mIndicators.GetRootNode();
    ASSERT_NE(nullptr, root);
    ASSERT_GE(root->indicators.size(), 1u);
    EXPECT_EQ(root->indicators.back().status, Status::NonCompliant);
    EXPECT_EQ(root->indicators.back().message, string("TMOUT is set to an incorrect value in ") + path);
}

TEST_F(EnsureDefaultShellTimeoutIsConfiguredTest, MalformedNumericSuffixReturnsConversionError)
{
    const auto path = mContext.MakeTempfile("TMOUT=900junk\nreadonly TMOUT\nexport TMOUT\n");
    mContext.SetSpecialFilePath("/etc/bashrc", path);
    const auto result = AuditShellTimeout(mIndicators, mContext);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(result.Error().code, EINVAL);
    EXPECT_EQ(result.Error().message, "Invalid integer value: 900junk");
    EXPECT_TRUE(mIndicators.Back().indicators.empty());
}

TEST_F(EnsureDefaultShellTimeoutIsConfiguredTest, NoReadonly)
{
    auto path = mContext.MakeTempfile("TMOUT=900\n");
    mContext.SetSpecialFilePath("/etc/bashrc", path);
    auto result = AuditShellTimeout(mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::NonCompliant);

    const auto* root = mIndicators.GetRootNode();
    ASSERT_NE(nullptr, root);
    ASSERT_GE(root->indicators.size(), 1u);
    EXPECT_EQ(root->indicators.back().status, Status::NonCompliant);
    EXPECT_EQ(root->indicators.back().message, string("TMOUT is not readonly in ") + path);
}

TEST_F(EnsureDefaultShellTimeoutIsConfiguredTest, NoExport)
{
    auto path = mContext.MakeTempfile("TMOUT=900\nreadonly TMOUT\n");
    mContext.SetSpecialFilePath("/etc/bashrc", path);
    auto result = AuditShellTimeout(mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::NonCompliant);

    const auto* root = mIndicators.GetRootNode();
    ASSERT_NE(nullptr, root);
    ASSERT_GE(root->indicators.size(), 1u);
    EXPECT_EQ(root->indicators.back().status, Status::NonCompliant);
    EXPECT_EQ(root->indicators.back().message, string("TMOUT is not exported in ") + path);
}

TEST_F(EnsureDefaultShellTimeoutIsConfiguredTest, ProperlyConfigured)
{
    auto path = mContext.MakeTempfile("TMOUT=900\nreadonly TMOUT\nexport TMOUT\n");
    mContext.SetSpecialFilePath("/etc/bashrc", path);
    auto result = AuditShellTimeout(mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);

    const auto* root = mIndicators.GetRootNode();
    ASSERT_NE(nullptr, root);
    ASSERT_GE(root->indicators.size(), 1u);
    EXPECT_EQ(root->indicators.back().status, Status::Compliant);
    EXPECT_EQ(root->indicators.back().message, string("TMOUT variable is properly defined"));
}

TEST_F(EnsureDefaultShellTimeoutIsConfiguredTest, MultipleEntries)
{
    auto path = mContext.MakeTempfile("TMOUT=100\nTMOUT=200\n");
    mContext.SetSpecialFilePath("/etc/bashrc", path);
    auto result = AuditShellTimeout(mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::NonCompliant);

    const auto* root = mIndicators.GetRootNode();
    ASSERT_NE(nullptr, root);
    ASSERT_GE(root->indicators.size(), 1u);
    EXPECT_EQ(root->indicators.back().status, Status::NonCompliant);
    EXPECT_EQ(root->indicators.back().message, string("TMOUT is set multiple times in ") + path);
}

TEST_F(EnsureDefaultShellTimeoutIsConfiguredTest, MultipleEntriesInDifferentFiles)
{
    auto path1 = mContext.MakeTempfile("TMOUT=900\nreadonly TMOUT\nexport TMOUT\n");
    mContext.SetSpecialFilePath("/etc/bashrc", path1);
    auto path2 = mContext.MakeTempfile("TMOUT=900\nreadonly TMOUT\nexport TMOUT\n");
    mContext.SetSpecialFilePath("/etc/profile", path2);
    auto result = AuditShellTimeout(mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::NonCompliant);

    const auto* root = mIndicators.GetRootNode();
    ASSERT_NE(nullptr, root);
    ASSERT_GE(root->indicators.size(), 1u);
    EXPECT_EQ(root->indicators.back().status, Status::NonCompliant);
    EXPECT_EQ(root->indicators.back().message, string("TMOUT is set in multiple locations"));
}

TEST_F(EnsureDefaultShellTimeoutIsConfiguredTest, RemediateExistingDefinition)
{
    auto path = mContext.MakeTempfile("  export TMOUT=901 # old value\n");
    mContext.SetSpecialFilePath("/etc/bashrc", path);

    auto result = RemediateShellTimeout(mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);

    std::ifstream input(path);
    EXPECT_EQ(string(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()), "  export TMOUT=900 # old value\nreadonly TMOUT\n");
}

TEST_F(EnsureDefaultShellTimeoutIsConfiguredTest, RemediateMissingDefinitionInProfile)
{
    auto path = mContext.MakeTempfile("# system profile");
    mContext.SetSpecialFilePath("/etc/profile", path);

    auto result = RemediateShellTimeout(mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);

    std::ifstream input(path);
    EXPECT_EQ(string(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()),
        "# system profile\nTMOUT=900\nreadonly TMOUT\nexport TMOUT\n");
}

TEST_F(EnsureDefaultShellTimeoutIsConfiguredTest, RemediateRejectsMultipleDefinitions)
{
    const string original = "TMOUT=100\nTMOUT=200\n";
    auto path = mContext.MakeTempfile(original);
    mContext.SetSpecialFilePath("/etc/bashrc", path);

    auto result = RemediateShellTimeout(mIndicators, mContext);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(result.Error().code, ENOTSUP);

    std::ifstream input(path);
    EXPECT_EQ(string(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()), original);
}

TEST_F(EnsureDefaultShellTimeoutIsConfiguredTest, RemediateRejectsAssignmentAfterReadonly)
{
    const string original = "readonly TMOUT\nTMOUT=901\n";
    auto path = mContext.MakeTempfile(original);
    mContext.SetSpecialFilePath("/etc/bashrc", path);

    auto result = RemediateShellTimeout(mIndicators, mContext);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(result.Error().code, ENOTSUP);

    std::ifstream input(path);
    EXPECT_EQ(string(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()), original);
}

TEST_F(EnsureDefaultShellTimeoutIsConfiguredTest, RemediateRejectsSymlink)
{
    const auto target = mContext.MakeTempfile("TMOUT=901\n");
    const auto link = mContext.GetTempdirPath() + "/bashrc";
    ASSERT_EQ(symlink(target.c_str(), link.c_str()), 0);
    mContext.SetSpecialFilePath("/etc/bashrc", link);

    auto result = RemediateShellTimeout(mIndicators, mContext);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(result.Error().code, EINVAL);

    std::ifstream input(target);
    EXPECT_EQ(string(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()), "TMOUT=901\n");
}
