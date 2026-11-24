// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "MockContext.h"

#include <RootPathSecurity.h>
#include <gtest/gtest.h>
#include <pwd.h>
#include <string>
#include <sys/param.h>
#include <sys/stat.h>
#include <unistd.h>

using ComplianceEngine::AuditRootPathSecurity;
using ComplianceEngine::Error;
using ComplianceEngine::IndicatorsTree;
using ComplianceEngine::Result;
using ComplianceEngine::Status;
using ::testing::Return;

namespace
{

bool IsSecureRootOwnedDirectory(const char* path)
{
    struct stat info
    {
    };
    if (stat(path, &info) != 0 || !S_ISDIR(info.st_mode) || (info.st_mode & (S_IWGRP | S_IWOTH)) != 0)
    {
        return false;
    }

    const auto* owner = getpwuid(info.st_uid);
    return owner != nullptr && std::string(owner->pw_name) == "root";
}

} // namespace

class EnsureRootPathTest : public ::testing::Test
{
protected:
    MockContext mContext;
    IndicatorsTree indicators;
    std::string path;

    void SetUp() override
    {
        path = mContext.GetTempdirPath() + "/root-path";
        ASSERT_EQ(0, mkdir(path.c_str(), 0700));
        indicators.Push("EnsureRootPath");
    }
};

TEST_F(EnsureRootPathTest, AuditRootPathCompliant)
{
    for (const auto* directory : {"/bin", "/usr/bin", "/sbin", "/usr/sbin"})
    {
        if (!IsSecureRootOwnedDirectory(directory))
        {
            GTEST_SKIP() << "requires secure root-owned PATH directory: " << directory;
        }
    }

    EXPECT_CALL(mContext, ExecuteCommand("sudo -n -Hiu root env")).WillOnce(Return(Result<std::string>("PATH=/bin:/usr/bin:/sbin:/usr/sbin")));

    auto result = AuditRootPathSecurity(indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(EnsureRootPathTest, AuditRootPathNonCompliantEmptyDirectory)
{
    EXPECT_CALL(mContext, ExecuteCommand("sudo -n -Hiu root env")).WillOnce(Return(Result<std::string>("PATH=/bin::/usr/bin:/sbin:/usr/sbin")));

    auto result = AuditRootPathSecurity(indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::NonCompliant);
}

TEST_F(EnsureRootPathTest, AuditRootPathNonCompliantTrailingColon)
{
    EXPECT_CALL(mContext, ExecuteCommand("sudo -n -Hiu root env")).WillOnce(Return(Result<std::string>("PATH=/bin:/usr/bin:/sbin:/usr/sbin:")));

    auto result = AuditRootPathSecurity(indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::NonCompliant);
}

TEST_F(EnsureRootPathTest, AuditRootPathNonCompliantCurrentDirectory)
{
    EXPECT_CALL(mContext, ExecuteCommand("sudo -n -Hiu root env")).WillOnce(Return(Result<std::string>("PATH=/bin:.:/usr/bin:/sbin:/usr/sbin")));

    auto result = AuditRootPathSecurity(indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::NonCompliant);
}

TEST_F(EnsureRootPathTest, AuditRootPathNonCompliantDirectoryOwnership)
{
    EXPECT_CALL(mContext, ExecuteCommand("sudo -n -Hiu root env")).WillOnce(Return(Result<std::string>("PATH=" + path + "/bin:/usr/bin:/sbin:/usr/sbin")));

    ASSERT_EQ(chmod(path.c_str(), 0755), 0);
    // Either we can do it and we're root, or we can't and we're not - either way, it won't be root owned.
    chown(path.c_str(), 1000, 1000);

    auto result = AuditRootPathSecurity(indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::NonCompliant);
}

TEST_F(EnsureRootPathTest, AuditRootPathNonCompliantDirectoryPermissions)
{
    EXPECT_CALL(mContext, ExecuteCommand("sudo -n -Hiu root env")).WillOnce(Return(Result<std::string>("PATH=/bin:/usr/bin:/sbin:/usr/sbin:" + path)));

    ASSERT_EQ(chmod(path.c_str(), 0777), 0);

    auto result = AuditRootPathSecurity(indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::NonCompliant);
}
