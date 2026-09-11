// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "CliContext.h"

#include <fstream>
#include <gtest/gtest.h>
#include <sys/stat.h>

class CliContextTest : public ::testing::Test
{
};

TEST_F(CliContextTest, DirectoryCreatedOnConstruction)
{
    ComplianceEngine::CliContext ctx(nullptr);
    struct stat st;
    ASSERT_EQ(0, stat(ctx.GetStatePath().c_str(), &st));
    EXPECT_TRUE(S_ISDIR(st.st_mode));
}

TEST_F(CliContextTest, DirectoryHasCorrectPrefix)
{
    ComplianceEngine::CliContext ctx(nullptr);
    EXPECT_EQ(0u, ctx.GetStatePath().rfind("/tmp/kompli-cli.", 0));
}

TEST_F(CliContextTest, DirectoryPermissionsAre0700)
{
    ComplianceEngine::CliContext ctx(nullptr);
    struct stat st;
    ASSERT_EQ(0, stat(ctx.GetStatePath().c_str(), &st));
    EXPECT_EQ(static_cast<mode_t>(0700), st.st_mode & 0777);
}

TEST_F(CliContextTest, EmptyDirectoryRemovedOnDestruction)
{
    std::string statePath;
    {
        ComplianceEngine::CliContext ctx(nullptr);
        statePath = ctx.GetStatePath();
        struct stat st;
        ASSERT_EQ(0, stat(statePath.c_str(), &st));
    }
    struct stat st;
    EXPECT_NE(0, stat(statePath.c_str(), &st));
}

TEST_F(CliContextTest, RecursiveRemovalOnDestruction)
{
    std::string statePath;
    std::string subDir;
    std::string topFile;
    std::string nestedFile;

    {
        ComplianceEngine::CliContext ctx(nullptr);
        statePath = ctx.GetStatePath();

        subDir = statePath + "/subdir";
        ASSERT_EQ(0, mkdir(subDir.c_str(), 0700));

        topFile = statePath + "/file.txt";
        std::ofstream(topFile) << "test";

        nestedFile = subDir + "/nested.txt";
        std::ofstream(nestedFile) << "nested";

        // Confirm all exist before destruction
        struct stat st;
        ASSERT_EQ(0, stat(topFile.c_str(), &st));
        ASSERT_EQ(0, stat(nestedFile.c_str(), &st));
        ASSERT_EQ(0, stat(subDir.c_str(), &st));
    }

    struct stat st;
    EXPECT_NE(0, stat(nestedFile.c_str(), &st)) << "nested file should be removed";
    EXPECT_NE(0, stat(topFile.c_str(), &st)) << "top-level file should be removed";
    EXPECT_NE(0, stat(subDir.c_str(), &st)) << "subdirectory should be removed";
    EXPECT_NE(0, stat(statePath.c_str(), &st)) << "state directory itself should be removed";
}

TEST_F(CliContextTest, UniqueDirectoryPerInstance)
{
    ComplianceEngine::CliContext ctx1(nullptr);
    ComplianceEngine::CliContext ctx2(nullptr);
    EXPECT_NE(ctx1.GetStatePath(), ctx2.GetStatePath());
}
