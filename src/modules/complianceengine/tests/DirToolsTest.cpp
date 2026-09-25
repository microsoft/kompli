// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "DirTools.h"

#include <cstdlib>
#include <fcntl.h>
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

TEST(MkdirRecursiveTest, HandlesRepeatedAndTrailingSlashes)
{
    char temporaryDirectory[] = "/tmp/dir_tools_test_XXXXXX";
    ASSERT_NE(nullptr, ::mkdtemp(temporaryDirectory));
    const std::string finalDirectory = std::string(temporaryDirectory) + "//parent///final/";

    ASSERT_TRUE(ComplianceEngine::MkdirRecursive(finalDirectory, 0700));
    EXPECT_EQ(0700, GetMode(finalDirectory));

    EXPECT_EQ(0, ::system(("rm -rf " + std::string(temporaryDirectory)).c_str()));
}

TEST(MkdirRecursiveTest, RejectsDotAndDotDotComponents)
{
    char temporaryDirectory[] = "/tmp/dir_tools_test_XXXXXX";
    ASSERT_NE(nullptr, ::mkdtemp(temporaryDirectory));
    const std::string baseDirectory = temporaryDirectory;

    EXPECT_FALSE(ComplianceEngine::MkdirRecursive(baseDirectory + "/./dot", 0700));
    EXPECT_FALSE(ComplianceEngine::MkdirRecursive(baseDirectory + "/parent/../dotdot", 0700));
    EXPECT_NE(0, ::access((baseDirectory + "/dot").c_str(), F_OK));
    EXPECT_NE(0, ::access((baseDirectory + "/dotdot").c_str(), F_OK));

    EXPECT_EQ(0, ::system(("rm -rf " + baseDirectory).c_str()));
}

TEST(MkdirRecursiveTest, RejectsSymlinkComponents)
{
    char temporaryDirectory[] = "/tmp/dir_tools_test_XXXXXX";
    ASSERT_NE(nullptr, ::mkdtemp(temporaryDirectory));
    const std::string baseDirectory = temporaryDirectory;
    const std::string targetDirectory = baseDirectory + "/target";
    const std::string linkPath = baseDirectory + "/link";
    ASSERT_EQ(0, ::mkdir(targetDirectory.c_str(), 0700));
    ASSERT_EQ(0, ::symlink(targetDirectory.c_str(), linkPath.c_str()));

    EXPECT_FALSE(ComplianceEngine::MkdirRecursive(linkPath + "/created", 0700));
    EXPECT_NE(0, ::access((targetDirectory + "/created").c_str(), F_OK));

    EXPECT_EQ(0, ::system(("rm -rf " + baseDirectory).c_str()));
}

TEST(MkdirRecursiveTest, RejectsExistingFile)
{
    char temporaryDirectory[] = "/tmp/dir_tools_test_XXXXXX";
    ASSERT_NE(nullptr, ::mkdtemp(temporaryDirectory));
    const std::string baseDirectory = temporaryDirectory;
    const std::string filePath = baseDirectory + "/file";
    const int fileDescriptor = ::open(filePath.c_str(), O_CREAT | O_WRONLY, 0600);
    ASSERT_GE(fileDescriptor, 0);
    ASSERT_EQ(0, ::close(fileDescriptor));

    EXPECT_FALSE(ComplianceEngine::MkdirRecursive(filePath, 0700));

    EXPECT_EQ(0, ::system(("rm -rf " + baseDirectory).c_str()));
}
