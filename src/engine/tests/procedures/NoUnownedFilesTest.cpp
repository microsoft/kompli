// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Test for EnsureNoUnowned procedure
#include "NoUnownedFiles.h"

#include "Evaluator.h"
#include "MockContext.h"

#include <fstream>
#include <grp.h>
#include <gtest/gtest.h>
#include <pwd.h>
#include <stdexcept>
#include <sys/stat.h>
#include <unistd.h>

using ComplianceEngine::AuditNoUnownedFiles;
using ComplianceEngine::IndicatorsTree;
using ComplianceEngine::Status;

namespace
{
uid_t FindUnknownUid()
{
    for (uid_t candidate = 60000; 65534 >= candidate; ++candidate)
    {
        if (nullptr == ::getpwuid(candidate))
        {
            return candidate;
        }
    }
    throw std::runtime_error("No unknown UID available for test");
}

gid_t FindUnknownGid()
{
    for (gid_t candidate = 60000; 65534 >= candidate; ++candidate)
    {
        if (nullptr == ::getgrgid(candidate))
        {
            return candidate;
        }
    }
    throw std::runtime_error("No unknown GID available for test");
}
} // namespace

class EnsureNoUnownedTest : public ::testing::Test
{
protected:
    MockContext mContext;
    IndicatorsTree indicators;
    std::string rootDir;

    void SetUp() override
    {
        if (0 != getuid())
        {
            GTEST_SKIP() << "This test suite requires root privileges ";
        }

        indicators.Push("EnsureNoUnowned");
        rootDir = mContext.GetFilesystemScannerRoot();
    }
};

TEST_F(EnsureNoUnownedTest, CompliantWhenAllOwned)
{
    std::string filePath = rootDir + "/ownedfile";
    {
        std::ofstream ofs(filePath);
        ofs << "data";
    }
    ASSERT_EQ(::chmod(filePath.c_str(), 0644), 0);
    (void)mContext.GetFilesystemScanner().GetFullFilesystem();
    auto result = AuditNoUnownedFiles(indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(EnsureNoUnownedTest, NonCompliantOnUnknownUid)
{
    // To simulate an unknown UID, we create a file then chown it to a high UID
    // that (very likely) doesn't exist in the test /etc/passwd. We cannot be
    // certain in all environments, but choose a large arbitrary UID.
    std::string filePath = rootDir + "/stray";
    {
        std::ofstream ofs(filePath);
        ofs << "x";
    }
    ASSERT_EQ(::chmod(filePath.c_str(), 0644), 0);
    uid_t fake = 61000; // typical not-present high UID
    // Attempt chown; if it fails due to EPERM (not root), skip test gracefully.
    if (::chown(filePath.c_str(), fake, (gid_t)-1) != 0)
    {
        GTEST_SKIP() << "Skipping NonCompliant test (requires chown permission)";
    }

    // Prime scanner after mutation
    (void)mContext.GetFilesystemScanner().GetFullFilesystem();
    auto result = AuditNoUnownedFiles(indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::NonCompliant);
}

TEST_F(EnsureNoUnownedTest, NonCompliantOnUnknownGid)
{
    const std::string filePath = rootDir + "/unknown-group";
    std::ofstream(filePath) << "data";
    const gid_t fake = FindUnknownGid();
    if (0 != ::chown(filePath.c_str(), static_cast<uid_t>(-1), fake))
    {
        GTEST_SKIP() << "Skipping unknown GID test (requires chown permission)";
    }
    ASSERT_TRUE(mContext.GetFilesystemScanner().GetFullFilesystem().HasValue());

    const auto result = AuditNoUnownedFiles(indicators, mContext);

    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(Status::NonCompliant, result.Value());
    ASSERT_FALSE(indicators.GetRootNode()->indicators.empty());
    EXPECT_NE(std::string::npos, indicators.GetRootNode()->indicators.front().message.find(filePath));
    EXPECT_NE(std::string::npos, indicators.GetRootNode()->indicators.front().message.find("gid " + std::to_string(fake)));
}

TEST_F(EnsureNoUnownedTest, ExcludesContainerdPaths)
{
    const std::string containerdDir = rootDir + "/containerd";
    const std::string filePath = containerdDir + "/stray";
    ASSERT_EQ(0, ::mkdir(containerdDir.c_str(), 0700));
    std::ofstream(filePath) << "data";
    if (0 != ::chown(filePath.c_str(), FindUnknownUid(), FindUnknownGid()))
    {
        GTEST_SKIP() << "Skipping excluded-path test (requires chown permission)";
    }
    ASSERT_TRUE(mContext.GetFilesystemScanner().GetFullFilesystem().HasValue());

    const auto result = AuditNoUnownedFiles(indicators, mContext);

    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(Status::Compliant, result.Value());
}
