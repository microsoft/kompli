// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "DirTools.h"

#include <cstdlib>
#include <gtest/gtest.h>
#include <sys/stat.h>
#include <unistd.h>

namespace
{
mode_t GetMode(const std::string& path)
{
    struct stat fileStatus = {};
    EXPECT_EQ(0, ::stat(path.c_str(), &fileStatus));
    return fileStatus.st_mode & 0777;
}
} // namespace

TEST(MkdirRecursiveTest, AppliesModeToNewFinalDirectory)
{
    char temporaryDirectory[] = "/tmp/dir_tools_test_XXXXXX";
    ASSERT_NE(nullptr, ::mkdtemp(temporaryDirectory));
    const std::string finalDirectory = std::string(temporaryDirectory) + "/parent/final";

    ASSERT_TRUE(ComplianceEngine::MkdirRecursive(finalDirectory, 0700));
    EXPECT_EQ(0700, GetMode(finalDirectory));

    EXPECT_EQ(0, ::system(("rm -rf " + std::string(temporaryDirectory)).c_str()));
}

TEST(MkdirRecursiveTest, CorrectsModeOfExistingFinalDirectory)
{
    char temporaryDirectory[] = "/tmp/dir_tools_test_XXXXXX";
    ASSERT_NE(nullptr, ::mkdtemp(temporaryDirectory));
    const std::string finalDirectory = std::string(temporaryDirectory) + "/final";
    ASSERT_EQ(0, ::mkdir(finalDirectory.c_str(), 0755));
    ASSERT_EQ(0, ::chmod(finalDirectory.c_str(), 0755));

    ASSERT_TRUE(ComplianceEngine::MkdirRecursive(finalDirectory, 0700));
    EXPECT_EQ(0700, GetMode(finalDirectory));

    EXPECT_EQ(0, ::system(("rm -rf " + std::string(temporaryDirectory)).c_str()));
}
