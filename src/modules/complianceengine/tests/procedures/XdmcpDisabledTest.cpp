// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "MockContext.h"

#include <XdmcpDisabled.h>
#include <cerrno>
#include <dirent.h>
#include <fstream>
#include <gtest/gtest.h>
#include <iterator>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

using ComplianceEngine::AuditXdmcpDisabled;
using ComplianceEngine::Error;
using ComplianceEngine::IndicatorsTree;
using ComplianceEngine::RemediateXdmcpDisabled;
using ComplianceEngine::Result;
using ComplianceEngine::Status;

class EnsureXdmcp : public ::testing::Test
{
protected:
    MockContext mContext;
    IndicatorsTree mIndicators;
    std::string failureXdmcpEnabled = "[xdmcp]\nEnable = true\n";
    std::string successXdmcpSectionNoEnable = "[xdmcp]\nFobable = true\n";
    std::string successXdmcpSectionEmpty = "[xdmcp]\n[OtherSection]xdmcp\nEnable = true\n";

    void SetUp() override
    {
        mIndicators.Push("EnsureXdmcp");
    }

    void TearDown() override
    {
    }
};

TEST_F(EnsureXdmcp, AuditSuccess)
{
    EXPECT_CALL(mContext, GetFileContents("/etc/gdm3/custom.conf")).WillRepeatedly(::testing::Return(Result<std::string>("\n")));
    EXPECT_CALL(mContext, GetFileContents("/etc/gdm3/daemon.conf")).WillRepeatedly(::testing::Return(Result<std::string>("\n")));
    EXPECT_CALL(mContext, GetFileContents("/etc/gdm/custom.conf")).WillRepeatedly(::testing::Return(Result<std::string>("\n")));
    EXPECT_CALL(mContext, GetFileContents("/etc/gdm/daemon.conf")).WillRepeatedly(::testing::Return(Result<std::string>("\n")));
    auto result = AuditXdmcpDisabled(mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(EnsureXdmcp, AuditFailureGdm3Custom)
{
    EXPECT_CALL(mContext, GetFileContents("/etc/gdm3/custom.conf")).WillRepeatedly(::testing::Return(Result<std::string>(failureXdmcpEnabled)));
    EXPECT_CALL(mContext, GetFileContents("/etc/gdm3/daemon.conf")).WillRepeatedly(::testing::Return(Result<std::string>("\n")));
    EXPECT_CALL(mContext, GetFileContents("/etc/gdm/custom.conf")).WillRepeatedly(::testing::Return(Result<std::string>("\n")));
    EXPECT_CALL(mContext, GetFileContents("/etc/gdm/daemon.conf")).WillRepeatedly(::testing::Return(Result<std::string>("\n")));
    auto result = AuditXdmcpDisabled(mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::NonCompliant);
}

TEST_F(EnsureXdmcp, AuditFailureGdm3Daemon)
{
    EXPECT_CALL(mContext, GetFileContents("/etc/gdm3/custom.conf")).WillRepeatedly(::testing::Return(Result<std::string>("\n")));
    EXPECT_CALL(mContext, GetFileContents("/etc/gdm3/daemon.conf")).WillRepeatedly(::testing::Return(Result<std::string>(failureXdmcpEnabled)));

    EXPECT_CALL(mContext, GetFileContents("/etc/gdm/custom.conf")).WillRepeatedly(::testing::Return(Result<std::string>("\n")));
    EXPECT_CALL(mContext, GetFileContents("/etc/gdm/daemon.conf")).WillRepeatedly(::testing::Return(Result<std::string>("\n")));
    auto result = AuditXdmcpDisabled(mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::NonCompliant);
}

TEST_F(EnsureXdmcp, AuditFailureGdmCustom)
{
    EXPECT_CALL(mContext, GetFileContents("/etc/gdm3/custom.conf")).WillRepeatedly(::testing::Return(Result<std::string>("\n")));
    EXPECT_CALL(mContext, GetFileContents("/etc/gdm3/daemon.conf")).WillRepeatedly(::testing::Return(Result<std::string>("\n")));
    EXPECT_CALL(mContext, GetFileContents("/etc/gdm/custom.conf")).WillRepeatedly(::testing::Return(Result<std::string>(failureXdmcpEnabled)));
    EXPECT_CALL(mContext, GetFileContents("/etc/gdm/daemon.conf")).WillRepeatedly(::testing::Return(Result<std::string>("\n")));
    auto result = AuditXdmcpDisabled(mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::NonCompliant);
}

TEST_F(EnsureXdmcp, AuditFailureGdmDaemon)
{
    EXPECT_CALL(mContext, GetFileContents("/etc/gdm3/custom.conf")).WillRepeatedly(::testing::Return(Result<std::string>("\n")));
    EXPECT_CALL(mContext, GetFileContents("/etc/gdm3/daemon.conf")).WillRepeatedly(::testing::Return(Result<std::string>("\n")));
    EXPECT_CALL(mContext, GetFileContents("/etc/gdm/custom.conf")).WillRepeatedly(::testing::Return(Result<std::string>("")));
    EXPECT_CALL(mContext, GetFileContents("/etc/gdm/daemon.conf")).WillRepeatedly(::testing::Return(Result<std::string>(failureXdmcpEnabled)));
    auto result = AuditXdmcpDisabled(mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::NonCompliant);
}

TEST_F(EnsureXdmcp, AuditSuccessNoSection)
{
    EXPECT_CALL(mContext, GetFileContents("/etc/gdm3/custom.conf")).WillRepeatedly(::testing::Return(Result<std::string>(successXdmcpSectionNoEnable)));
    EXPECT_CALL(mContext, GetFileContents("/etc/gdm3/daemon.conf")).WillRepeatedly(::testing::Return(Result<std::string>("\n")));
    EXPECT_CALL(mContext, GetFileContents("/etc/gdm/custom.conf")).WillRepeatedly(::testing::Return(Result<std::string>("\n")));
    EXPECT_CALL(mContext, GetFileContents("/etc/gdm/daemon.conf")).WillRepeatedly(::testing::Return(Result<std::string>("\n")));
    auto result = AuditXdmcpDisabled(mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(EnsureXdmcp, AuditFailureOneSection)
{
    EXPECT_CALL(mContext, GetFileContents("/etc/gdm3/custom.conf")).WillRepeatedly(::testing::Return(Result<std::string>(successXdmcpSectionNoEnable)));
    EXPECT_CALL(mContext, GetFileContents("/etc/gdm3/daemon.conf")).WillRepeatedly(::testing::Return(Result<std::string>("\n")));
    EXPECT_CALL(mContext, GetFileContents("/etc/gdm/custom.conf")).WillRepeatedly(::testing::Return(Result<std::string>("\n")));
    EXPECT_CALL(mContext, GetFileContents("/etc/gdm/daemon.conf")).WillRepeatedly(::testing::Return(Result<std::string>(failureXdmcpEnabled)));
    auto result = AuditXdmcpDisabled(mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::NonCompliant);
}

TEST_F(EnsureXdmcp, AuditSuccessEmptySection)
{
    EXPECT_CALL(mContext, GetFileContents("/etc/gdm3/custom.conf")).WillRepeatedly(::testing::Return(Result<std::string>(successXdmcpSectionNoEnable)));
    EXPECT_CALL(mContext, GetFileContents("/etc/gdm3/daemon.conf")).WillRepeatedly(::testing::Return(Result<std::string>(successXdmcpSectionEmpty)));
    EXPECT_CALL(mContext, GetFileContents("/etc/gdm/custom.conf")).WillRepeatedly(::testing::Return(Result<std::string>("\n")));
    EXPECT_CALL(mContext, GetFileContents("/etc/gdm/daemon.conf")).WillRepeatedly(::testing::Return(Result<std::string>("\n")));
    auto result = AuditXdmcpDisabled(mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(EnsureXdmcp, AuditIgnoresCommentedSectionsAndSettings)
{
    EXPECT_CALL(mContext, GetFileContents("/etc/gdm3/custom.conf"))
        .WillRepeatedly(::testing::Return(Result<std::string>("# [xdmcp]\n# Enable = true\n")));
    EXPECT_CALL(mContext, GetFileContents("/etc/gdm3/daemon.conf"))
        .WillRepeatedly(::testing::Return(Result<std::string>("[xdmcp]\n# Enable = true\n")));
    EXPECT_CALL(mContext, GetFileContents("/etc/gdm/custom.conf")).WillRepeatedly(::testing::Return(Result<std::string>("\n")));
    EXPECT_CALL(mContext, GetFileContents("/etc/gdm/daemon.conf")).WillRepeatedly(::testing::Return(Result<std::string>("\n")));

    auto result = AuditXdmcpDisabled(mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);
}

TEST_F(EnsureXdmcp, RemediateDisablesAllActiveSettings)
{
    const std::vector<std::string> logicalPaths = {"/etc/gdm3/custom.conf", "/etc/gdm3/daemon.conf", "/etc/gdm/custom.conf", "/etc/gdm/daemon.conf"};
    std::vector<std::string> physicalPaths;
    for (size_t index = 0; index < logicalPaths.size(); index++)
    {
        const auto contents = index == 0 ? "[xdmcp]\nEnable = true # required\n" :
                              index == 2 ? "[security]\nEnable = true\n[xdmcp]\n\tEnable=true\n" :
                                           "\n";
        physicalPaths.push_back(mContext.MakeTempfile(contents));
        mContext.SetSpecialFilePath(logicalPaths[index], physicalPaths.back());
    }
    EXPECT_CALL(mContext, GetFileContents(testing::_)).WillRepeatedly(testing::Invoke([this](const std::string& path) -> Result<std::string> {
        std::ifstream input(mContext.GetSpecialFilePath(path));
        if (!input.is_open())
        {
            return Error("Failed to read test file", errno);
        }
        return std::string(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>());
    }));

    auto result = RemediateXdmcpDisabled(mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);

    std::ifstream custom(physicalPaths[0]);
    EXPECT_EQ(std::string(std::istreambuf_iterator<char>(custom), std::istreambuf_iterator<char>()), "[xdmcp]\nEnable = false # required\n");
    std::ifstream legacy(physicalPaths[2]);
    EXPECT_EQ(std::string(std::istreambuf_iterator<char>(legacy), std::istreambuf_iterator<char>()),
        "[security]\nEnable = true\n[xdmcp]\n\tEnable=false\n");
}

TEST_F(EnsureXdmcp, RemediateCompliantFilesAreUnchanged)
{
    const std::vector<std::string> logicalPaths = {"/etc/gdm3/custom.conf", "/etc/gdm3/daemon.conf", "/etc/gdm/custom.conf", "/etc/gdm/daemon.conf"};
    std::vector<std::string> physicalPaths;
    std::vector<ino_t> inodes;
    for (const auto& logicalPath : logicalPaths)
    {
        physicalPaths.push_back(mContext.MakeTempfile("[xdmcp]\nEnable = false\n"));
        mContext.SetSpecialFilePath(logicalPath, physicalPaths.back());
        struct stat metadata;
        ASSERT_EQ(stat(physicalPaths.back().c_str(), &metadata), 0);
        inodes.push_back(metadata.st_ino);
    }
    EXPECT_CALL(mContext, GetFileContents(testing::_)).WillRepeatedly(testing::Invoke([this](const std::string& path) -> Result<std::string> {
        std::ifstream input(mContext.GetSpecialFilePath(path));
        return std::string(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>());
    }));

    auto result = RemediateXdmcpDisabled(mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);

    for (size_t index = 0; index < physicalPaths.size(); index++)
    {
        struct stat metadata;
        ASSERT_EQ(stat(physicalPaths[index].c_str(), &metadata), 0);
        EXPECT_EQ(inodes[index], metadata.st_ino);
    }
}
