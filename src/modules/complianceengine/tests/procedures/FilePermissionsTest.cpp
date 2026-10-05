// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "MockContext.h"

#include <FilePermissions.h>
#include <cerrno>
#include <dirent.h>
#include <fstream>
#include <gtest/gtest.h>
#include <linux/limits.h>
#include <string>
#include <unistd.h>
#include <vector>

using ComplianceEngine::AuditFilePermissions;
using ComplianceEngine::AuditFilePermissionsCollection;
using ComplianceEngine::Behavior;
using ComplianceEngine::Error;
using ComplianceEngine::FilePermissionsCollectionParams;
using ComplianceEngine::FilePermissionsParams;
using ComplianceEngine::IndicatorsTree;
using ComplianceEngine::Optional;
using ComplianceEngine::Pattern;
using ComplianceEngine::RemediateFilePermissions;
using ComplianceEngine::RemediateFilePermissionsCollection;
using ComplianceEngine::Result;
using ComplianceEngine::Separated;
using ComplianceEngine::Status;

class EnsureFilePermissionsTest : public ::testing::Test
{
protected:
    std::vector<std::string> files;
    std::string testDir;
    MockContext mContext;
    IndicatorsTree indicators;
    ComplianceEngine::CompactListFormatter mFormatter;

    void SetUp() override
    {
        if (0 != getuid())
        {
            GTEST_SKIP() << "This test suite requires root privileges or fakeroot";
        }
        // SLES15 docker image doesn't have the bin group/user, create if it doesn't exist.
        system("groupadd -g 1 bin >/dev/null 2>&1");
        system("useradd -g 1 -u 1 bin >/dev/null 2>&1");
        testDir = mContext.GetTempdirPath() + "/file-permissions";
        ASSERT_EQ(0, mkdir(testDir.c_str(), 0700));
        indicators.Push("EnsureFilePermissions");
    }

    void CreateFile(std::string& filename, int owner, int group, short permissions)
    {
        filename = mContext.MakeTempfile("");
        files.push_back(filename);
        ASSERT_EQ(chown(filename.c_str(), owner, group), 0);
        ASSERT_EQ(chmod(filename.c_str(), permissions), 0);
    }

    void CreateFileInDir(const std::string& filename, int owner, int group, short permissions)
    {
        std::string filePath = testDir + "/" + filename;
        std::ofstream file(filePath);
        file << "test content";
        file.close();
        ASSERT_EQ(chmod(filePath.c_str(), permissions), 0);
        ASSERT_EQ(chown(filePath.c_str(), owner, group), 0);
        files.push_back(filePath);
    }

    static void MakeSeparatedList(const std::string& input, Optional<Separated<std::string, '|'>>& output)
    {
        auto result = Separated<std::string, '|'>::Parse(input);
        ASSERT_TRUE(result.HasValue());
        output = std::move(result.Value());
    }
};

TEST_F(EnsureFilePermissionsTest, DirectoryCollectionChecksRootAndChildren)
{
    const std::string child = testDir + "/child";
    ASSERT_EQ(mkdir(child.c_str(), 0700), 0);
    ASSERT_EQ(chown(testDir.c_str(), 0, 0), 0);
    ASSERT_EQ(chown(child.c_str(), 0, 0), 0);
    CreateFileInDir("regular", 0, 1, 0600);
    FilePermissionsCollectionParams params;
    params.directory = testDir;
    params.filePattern = "*";
    params.directoriesOnly = true;
    auto group = Pattern::Make("root");
    ASSERT_TRUE(group.HasValue());
    params.group = {{std::move(group.Value())}};
    auto result = AuditFilePermissionsCollection(params, indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);
    ASSERT_EQ(chown(child.c_str(), 0, 1), 0);
    result = AuditFilePermissionsCollection(params, indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::NonCompliant);
    params.recurse = false;
    result = AuditFilePermissionsCollection(params, indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);
    ASSERT_EQ(chown(testDir.c_str(), 0, 1), 0);
    result = AuditFilePermissionsCollection(params, indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::NonCompliant);
}

TEST_F(EnsureFilePermissionsTest, NumericOwnershipIncludesSymlinksAndDirectories)
{
    FilePermissionsCollectionParams params;
    params.directory = testDir;
    params.filePattern = "*";
    params.allFileTypes = true;
    params.maximumUid = 0;
    params.maximumGid = 999;
    params.behavior = Behavior::AnyExist;
    CreateFileInDir("command", 0, 999, 0755);
    const auto linkPath = testDir + "/link";
    ASSERT_EQ(symlink("missing-target", linkPath.c_str()), 0);
    files.push_back(linkPath);
    const auto directoryPath = testDir + "/subdir";
    ASSERT_EQ(mkdir(directoryPath.c_str(), 0755), 0);
    auto result = AuditFilePermissionsCollection(params, indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);
    ASSERT_EQ(lchown(linkPath.c_str(), 0, 1000), 0);
    result = AuditFilePermissionsCollection(params, indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::NonCompliant);
    ASSERT_EQ(lchown(linkPath.c_str(), 0, 0), 0);
    ASSERT_EQ(chown(directoryPath.c_str(), 1000, 0), 0);
    result = AuditFilePermissionsCollection(params, indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::NonCompliant);
    EXPECT_FALSE(RemediateFilePermissionsCollection(params, indicators, mContext).HasValue());
    params.directory = testDir + "/missing-directory";
    result = AuditFilePermissionsCollection(params, indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);
    params.maximumGid = -1;
    EXPECT_FALSE(AuditFilePermissionsCollection(params, indicators, mContext).HasValue());
}

TEST_F(EnsureFilePermissionsTest, NumericOwnershipCanExcludeOnlySymlinks)
{
    FilePermissionsCollectionParams params;
    params.directory = testDir;
    params.filePattern = "*";
    params.allFileTypes = true;
    params.excludeSymlinks = true;
    params.maximumUid = 0;
    params.maximumGid = 999;
    params.recurse = false;
    params.behavior = Behavior::AtLeastOneExists;
    const auto linkPath = testDir + "/link";
    ASSERT_EQ(symlink("missing-target", linkPath.c_str()), 0);
    ASSERT_EQ(lchown(linkPath.c_str(), 1000, 1000), 0);
    auto audit = [&]() {
        auto result = AuditFilePermissionsCollection(params, indicators, mContext);
        EXPECT_TRUE(result.HasValue());
        return result.HasValue() ? result.Value() : Status::NonCompliant;
    };
    EXPECT_EQ(audit(), Status::NonCompliant);
    params.behavior = Behavior::AnyExist;
    EXPECT_EQ(audit(), Status::Compliant);
    params.behavior = Behavior::AtLeastOneExists;
    const auto directoryPath = testDir + "/directory";
    ASSERT_EQ(mkdir(directoryPath.c_str(), 0755), 0);
    EXPECT_EQ(audit(), Status::Compliant);
    ASSERT_EQ(chown(directoryPath.c_str(), 0, 1000), 0);
    EXPECT_EQ(audit(), Status::NonCompliant);
    ASSERT_EQ(chown(directoryPath.c_str(), 0, 999), 0);
    EXPECT_EQ(audit(), Status::Compliant);
    const auto fifoPath = testDir + "/fifo";
    ASSERT_EQ(mkfifo(fifoPath.c_str(), 0600), 0);
    ASSERT_EQ(chown(fifoPath.c_str(), 1, 0), 0);
    EXPECT_EQ(audit(), Status::NonCompliant);
    ASSERT_EQ(chown(fifoPath.c_str(), 0, 0), 0);
    CreateFileInDir("directory/nested", 1000, 1000, 0600);
    EXPECT_EQ(audit(), Status::Compliant);
    params.recurse = true;
    EXPECT_EQ(audit(), Status::NonCompliant);
    params.directory = testDir + "/missing";
    EXPECT_EQ(audit(), Status::NonCompliant);
    params.behavior = Behavior::AnyExist;
    EXPECT_EQ(audit(), Status::Compliant);
}

TEST_F(EnsureFilePermissionsTest, NumericFilenameOwnershipExcludesDirectories)
{
    FilePermissionsCollectionParams params;
    params.directory = testDir;
    params.filePattern = "*";
    params.allFileTypes = true;
    params.excludeSymlinks = true;
    params.excludeDirectories = true;
    params.maximumUid = 0;
    params.recurse = false;
    params.behavior = Behavior::AtLeastOneExists;
    const auto directoryPath = testDir + "/CloudTestWorker";
    ASSERT_EQ(mkdir(directoryPath.c_str(), 0755), 0);
    ASSERT_EQ(chown(directoryPath.c_str(), 1001, 0), 0);
    const auto linkPath = testDir + "/link";
    ASSERT_EQ(symlink("missing-target", linkPath.c_str()), 0);
    ASSERT_EQ(lchown(linkPath.c_str(), 1001, 0), 0);
    auto audit = [&]() {
        auto result = AuditFilePermissionsCollection(params, indicators, mContext);
        EXPECT_TRUE(result.HasValue());
        return result.HasValue() ? result.Value() : Status::NonCompliant;
    };
    EXPECT_EQ(audit(), Status::NonCompliant);
    params.behavior = Behavior::AnyExist;
    EXPECT_EQ(audit(), Status::Compliant);
    params.behavior = Behavior::AtLeastOneExists;
    CreateFileInDir("command", 0, 0, 0755);
    EXPECT_EQ(audit(), Status::Compliant);
    ASSERT_EQ(chown((testDir + "/command").c_str(), 1001, 0), 0);
    EXPECT_EQ(audit(), Status::NonCompliant);
    ASSERT_EQ(chown((testDir + "/command").c_str(), 0, 0), 0);
    const auto fifoPath = testDir + "/fifo";
    ASSERT_EQ(mkfifo(fifoPath.c_str(), 0600), 0);
    ASSERT_EQ(chown(fifoPath.c_str(), 1001, 0), 0);
    EXPECT_EQ(audit(), Status::NonCompliant);
    ASSERT_EQ(chown(fifoPath.c_str(), 0, 0), 0);
    CreateFileInDir("CloudTestWorker/nested", 1001, 0, 0755);
    EXPECT_EQ(audit(), Status::Compliant);
    params.recurse = true;
    EXPECT_EQ(audit(), Status::NonCompliant);
    ASSERT_EQ(chown((directoryPath + "/nested").c_str(), 0, 0), 0);
    EXPECT_EQ(audit(), Status::Compliant);
    params.excludeDirectories = false;
    EXPECT_EQ(audit(), Status::NonCompliant);
    params.allFileTypes = false;
    params.excludeSymlinks = false;
    params.excludeDirectories = true;
    EXPECT_FALSE(AuditFilePermissionsCollection(params, indicators, mContext).HasValue());
}

TEST_F(EnsureFilePermissionsTest, LibraryGroupFilterChecksSelectedFiles)
{
    FilePermissionsCollectionParams params;
    params.directory = testDir;
    params.filePattern = ".*(?:(\\.so\\S*)$).*";
    params.filePatternIsRegex = true;
    params.recurse = true;
    params.behavior = Behavior::AnyExist;
    auto group = Pattern::Make("root");
    ASSERT_TRUE(group.HasValue());
    params.group = {{std::move(group.Value())}};

    auto result = AuditFilePermissionsCollection(params, indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);
    CreateFileInDir("libexample.so.1", 0, 0, 0644);
    CreateFileInDir("unselected.txt", 0, 1, 0644);
    result = AuditFilePermissionsCollection(params, indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);
    ASSERT_EQ(chown((testDir + "/libexample.so.1").c_str(), 0, 1), 0);
    result = AuditFilePermissionsCollection(params, indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::NonCompliant);
}

TEST_F(EnsureFilePermissionsTest, CollectionFollowsConfiguredRootSymlinkOnly)
{
    const std::string realDirectory = testDir + "/real";
    const std::string linkedDirectory = testDir + "/linked";
    ASSERT_EQ(mkdir(realDirectory.c_str(), 0700), 0);
    ASSERT_EQ(symlink("real", linkedDirectory.c_str()), 0);
    CreateFileInDir("real/regular", 0, 0, 0600);
    ASSERT_EQ(symlink("/missing-target", (realDirectory + "/broken").c_str()), 0);
    FilePermissionsCollectionParams params;
    params.directory = linkedDirectory;
    params.filePattern = "*";
    params.mask = 0077;
    auto result = AuditFilePermissionsCollection(params, indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);
    ASSERT_EQ(chmod((realDirectory + "/regular").c_str(), 0644), 0);
    result = AuditFilePermissionsCollection(params, indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::NonCompliant);
}

TEST_F(EnsureFilePermissionsTest, AuditFileMissing)
{
    FilePermissionsParams params;
    params.path = "/this_doesnt_exist_for_sure";

    auto result = AuditFilePermissions(params, indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::NonCompliant);
    ASSERT_TRUE(mFormatter.Format(indicators).Value().find("does not exist but it should") != std::string::npos);
}

TEST_F(EnsureFilePermissionsTest, AuditFileMissingNoneExist)
{
    FilePermissionsParams params;
    params.path = "/this_doesnt_exist_for_sure";
    params.behavior = Behavior::NoneExist;

    auto result = AuditFilePermissions(params, indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
    ASSERT_TRUE(mFormatter.Format(indicators).Value().find("does not exist as it should") != std::string::npos);
}

TEST_F(EnsureFilePermissionsTest, AuditFileExistsNoneExist)
{
    FilePermissionsParams params;
    CreateFile(params.path, 0, 0, 0600);
    params.behavior = Behavior::NoneExist;

    auto result = AuditFilePermissions(params, indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::NonCompliant);
    ASSERT_TRUE(mFormatter.Format(indicators).Value().find("exist but it should not") != std::string::npos);
}

TEST_F(EnsureFilePermissionsTest, AuditFileMissingAllExist)
{
    FilePermissionsParams params;
    params.path = "/this_doesnt_exist_for_sure";
    params.behavior = Behavior::AllExist;

    auto result = AuditFilePermissions(params, indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::NonCompliant);
    ASSERT_TRUE(mFormatter.Format(indicators).Value().find("does not exist but it should") != std::string::npos);
}

TEST_F(EnsureFilePermissionsTest, AuditFileMissingOnlyOneExists)
{
    FilePermissionsParams params;
    params.path = "/this_doesnt_exist_for_sure";
    params.behavior = Behavior::OnlyOneExists;

    auto result = AuditFilePermissions(params, indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::NonCompliant);
    ASSERT_TRUE(mFormatter.Format(indicators).Value().find("does not exist but it should") != std::string::npos);
}

TEST_F(EnsureFilePermissionsTest, AuditFileMissingAnyExist)
{
    FilePermissionsParams params;
    params.path = "/this_doesnt_exist_for_sure";
    params.behavior = Behavior::AnyExist;

    auto result = AuditFilePermissions(params, indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::NonCompliant);
    ASSERT_TRUE(mFormatter.Format(indicators).Value().find("does not exist but it should") != std::string::npos);
}

TEST_F(EnsureFilePermissionsTest, AuditFileExistsAllExist)
{
    FilePermissionsParams params;
    CreateFile(params.path, 0, 0, 0600);
    params.behavior = Behavior::AllExist;

    auto result = AuditFilePermissions(params, indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);

    ASSERT_TRUE(mFormatter.Format(indicators).Value().find("correct permissions and ownership as expected") != std::string::npos);
}

TEST_F(EnsureFilePermissionsTest, AuditFileExistsBadPermssionsBehaviorNoneExist)
{
    FilePermissionsParams params;
    CreateFile(params.path, 1, 0, 0610);
    auto owner = Pattern::Make("root");
    ASSERT_TRUE(owner.HasValue());
    params.owner = {{std::move(owner).Value()}};
    auto group = Pattern::Make("root");
    ASSERT_TRUE(group.HasValue());
    params.group = {{std::move(group.Value())}};
    params.permissions = 0400;
    params.mask = 0066;
    params.behavior = Behavior::NoneExist;
    auto result = AuditFilePermissions(params, indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::NonCompliant);
}

TEST_F(EnsureFilePermissionsTest, AuditWrongOwner)
{
    FilePermissionsParams params;
    CreateFile(params.path, 1, 0, 0610);
    auto owner = Pattern::Make("root");
    ASSERT_TRUE(owner.HasValue());
    params.owner = {{std::move(owner).Value()}};
    auto group = Pattern::Make("root");
    ASSERT_TRUE(group.HasValue());
    params.group = {{std::move(group.Value())}};
    params.permissions = 0400;
    params.mask = 0066;
    auto result = AuditFilePermissions(params, indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::NonCompliant);
    ASSERT_TRUE(mFormatter.Format(indicators).Value().find("owner") != std::string::npos);
}

TEST_F(EnsureFilePermissionsTest, RemediateWrongOwner)
{
    FilePermissionsParams params;
    CreateFile(params.path, 1, 0, 0610);
    auto owner = Pattern::Make("root");
    ASSERT_TRUE(owner.HasValue());
    params.owner = {{std::move(owner).Value()}};
    auto group = Pattern::Make("root");
    ASSERT_TRUE(group.HasValue());
    params.permissions = 0400;
    params.mask = 0066;

    auto result = RemediateFilePermissions(params, indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
    struct stat st;
    ASSERT_EQ(stat(params.path.c_str(), &st), 0);
    ASSERT_EQ(st.st_uid, 0u);
    ASSERT_EQ(st.st_gid, 0u);
    ASSERT_EQ(st.st_mode & 0777, 0610u);
}

TEST_F(EnsureFilePermissionsTest, AuditWrongGroup)
{
    FilePermissionsParams params;
    CreateFile(params.path, 0, 1, 0610);
    auto owner = Pattern::Make("root");
    ASSERT_TRUE(owner.HasValue());
    params.owner = {{std::move(owner).Value()}};
    auto group = Pattern::Make("root");
    ASSERT_TRUE(group.HasValue());
    params.group = {{std::move(group).Value()}};
    params.permissions = 0400;
    params.mask = 0066;

    auto result = AuditFilePermissions(params, indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::NonCompliant);
    ASSERT_TRUE(mFormatter.Format(indicators).Value().find("Invalid group") != std::string::npos);
}

TEST_F(EnsureFilePermissionsTest, RemediateWrongGroup)
{
    FilePermissionsParams params;
    CreateFile(params.path, 0, 1, 0610);
    auto owner = Pattern::Make("root");
    ASSERT_TRUE(owner.HasValue());
    params.owner = {{std::move(owner).Value()}};
    auto group = Pattern::Make("root");
    ASSERT_TRUE(group.HasValue());
    params.group = {{std::move(group).Value()}};
    params.permissions = 0400;
    params.mask = 0066;

    auto result = RemediateFilePermissions(params, indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
    struct stat st;
    ASSERT_EQ(stat(params.path.c_str(), &st), 0);
    ASSERT_EQ(st.st_uid, 0u);
    ASSERT_EQ(st.st_gid, 0u);
    ASSERT_EQ(st.st_mode & 0777, 0610u);
}

TEST_F(EnsureFilePermissionsTest, AuditWrongPermissions)
{
    FilePermissionsParams params;
    CreateFile(params.path, 0, 0, 0210);
    auto owner = Pattern::Make("root");
    ASSERT_TRUE(owner.HasValue());
    params.owner = {{std::move(owner).Value()}};
    auto group = Pattern::Make("root");
    ASSERT_TRUE(group.HasValue());
    params.group = {{std::move(group).Value()}};
    params.permissions = 0400;
    params.mask = 0066;

    auto result = AuditFilePermissions(params, indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::NonCompliant);
    ASSERT_TRUE(mFormatter.Format(indicators).Value().find("Invalid permissions") != std::string::npos);
}

TEST_F(EnsureFilePermissionsTest, RemediateWrongPermissions)
{
    FilePermissionsParams params;
    CreateFile(params.path, 0, 0, 0210);
    auto owner = Pattern::Make("root");
    ASSERT_TRUE(owner.HasValue());
    params.owner = {{std::move(owner).Value()}};
    auto group = Pattern::Make("root");
    ASSERT_TRUE(group.HasValue());
    params.group = {{std::move(group).Value()}};
    params.permissions = 0400;
    params.mask = 0066;

    auto result = RemediateFilePermissions(params, indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
    struct stat st;
    ASSERT_EQ(stat(params.path.c_str(), &st), 0);
    ASSERT_EQ(st.st_uid, 0u);
    ASSERT_EQ(st.st_gid, 0u);
    ASSERT_EQ(st.st_mode & 0777, 0610u);
}

TEST_F(EnsureFilePermissionsTest, AuditWrongMask)
{
    FilePermissionsParams params;
    CreateFile(params.path, 0, 0, 0654);
    auto owner = Pattern::Make("root");
    ASSERT_TRUE(owner.HasValue());
    params.owner = {{std::move(owner).Value()}};
    auto group = Pattern::Make("root");
    ASSERT_TRUE(group.HasValue());
    params.group = {{std::move(group).Value()}};
    params.permissions = 0400;
    params.mask = 0066;

    auto result = AuditFilePermissions(params, indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::NonCompliant);
    ASSERT_TRUE(mFormatter.Format(indicators).Value().find("Invalid permissions") != std::string::npos);
}

TEST_F(EnsureFilePermissionsTest, RemediateWrongMask)
{
    FilePermissionsParams params;
    CreateFile(params.path, 0, 0, 0654);
    auto owner = Pattern::Make("root");
    ASSERT_TRUE(owner.HasValue());
    params.owner = {{std::move(owner).Value()}};
    auto group = Pattern::Make("root");
    ASSERT_TRUE(group.HasValue());
    params.group = {{std::move(group).Value()}};
    params.permissions = 0400;
    params.mask = 0066;

    auto result = RemediateFilePermissions(params, indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
    struct stat st;
    ASSERT_EQ(stat(params.path.c_str(), &st), 0);
    ASSERT_EQ(st.st_uid, 0u);
    ASSERT_EQ(st.st_gid, 0u);
    ASSERT_EQ(st.st_mode & 0777, 0610u);
}

TEST_F(EnsureFilePermissionsTest, AuditAllWrong)
{
    FilePermissionsParams params;
    CreateFile(params.path, 1, 1, 0276);
    auto owner = Pattern::Make("root");
    ASSERT_TRUE(owner.HasValue());
    params.owner = {{std::move(owner).Value()}};
    auto group = Pattern::Make("root");
    ASSERT_TRUE(group.HasValue());
    params.group = {{std::move(group).Value()}};
    params.permissions = 0400;
    params.mask = 0066;

    auto result = AuditFilePermissions(params, indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::NonCompliant);
}

TEST_F(EnsureFilePermissionsTest, RemediateAllWrong)
{
    FilePermissionsParams params;
    CreateFile(params.path, 1, 1, 0276);
    auto owner = Pattern::Make("root");
    ASSERT_TRUE(owner.HasValue());
    params.owner = {{std::move(owner).Value()}};
    auto group = Pattern::Make("root");
    ASSERT_TRUE(group.HasValue());
    params.group = {{std::move(group).Value()}};
    params.permissions = 0400;
    params.mask = 0066;
    auto result = RemediateFilePermissions(params, indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
    struct stat st;
    ASSERT_EQ(stat(params.path.c_str(), &st), 0);
    ASSERT_EQ(st.st_uid, 0u);
    ASSERT_EQ(st.st_gid, 0u);
    ASSERT_EQ(st.st_mode & 0777, 0610u);
}

TEST_F(EnsureFilePermissionsTest, AuditAllOk)
{
    FilePermissionsParams params;
    CreateFile(params.path, 0, 0, 0610);
    auto owner = Pattern::Make("root");
    ASSERT_TRUE(owner.HasValue());
    params.owner = {{std::move(owner).Value()}};
    auto group = Pattern::Make("root");
    ASSERT_TRUE(group.HasValue());
    params.group = {{std::move(group).Value()}};
    params.permissions = 0400;
    params.mask = 0066;
    auto result = AuditFilePermissions(params, indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(EnsureFilePermissionsTest, RemediateAllOk)
{
    FilePermissionsParams params;
    CreateFile(params.path, 0, 0, 0610);
    auto owner = Pattern::Make("root");
    ASSERT_TRUE(owner.HasValue());
    params.owner = {{std::move(owner).Value()}};
    auto group = Pattern::Make("root");
    ASSERT_TRUE(group.HasValue());
    params.group = {{std::move(group).Value()}};
    params.permissions = 0400;
    params.mask = 0066;
    auto result = RemediateFilePermissions(params, indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
    struct stat st;
    ASSERT_EQ(stat(params.path.c_str(), &st), 0);
    ASSERT_EQ(st.st_uid, 0u);
    ASSERT_EQ(st.st_gid, 0u);
    ASSERT_EQ(st.st_mode & 0777, 0610u);
}

TEST_F(EnsureFilePermissionsTest, AuditBadFileOwner)
{
    FilePermissionsParams params;
    CreateFile(params.path, 15213, 0, 0600);
    auto owner = Pattern::Make("boohoonotarealuser");
    ASSERT_TRUE(owner.HasValue());
    params.owner = {{std::move(owner).Value()}};
    auto result = AuditFilePermissions(params, indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::NonCompliant);
}

TEST_F(EnsureFilePermissionsTest, RemediateBadFileOwner)
{
    FilePermissionsParams params;
    CreateFile(params.path, 15213, 0, 0600);
    auto owner = Pattern::Make("boohoonotarealuser");
    ASSERT_TRUE(owner.HasValue());
    params.owner = {{std::move(owner).Value()}};
    auto result = RemediateFilePermissions(params, indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::NonCompliant);
}

TEST_F(EnsureFilePermissionsTest, AuditBadFileGroup)
{
    FilePermissionsParams params;
    CreateFile(params.path, 0, 15213, 0600);
    auto group = Pattern::Make("boohoonotarealgroup");
    ASSERT_TRUE(group.HasValue());
    params.group = {{std::move(group.Value())}};
    auto result = AuditFilePermissions(params, indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::NonCompliant);
}

TEST_F(EnsureFilePermissionsTest, RemediateBadFileGroup)
{
    FilePermissionsParams params;
    CreateFile(params.path, 0, 15213, 0600);
    auto group = Pattern::Make("boohoonotarealgroup");
    ASSERT_TRUE(group.HasValue());
    params.group = {{std::move(group.Value())}};
    auto result = RemediateFilePermissions(params, indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::NonCompliant);
}

TEST_F(EnsureFilePermissionsTest, AuditSameBitsSet)
{
    FilePermissionsParams params;
    CreateFile(params.path, 0, 0, 0600);
    params.permissions = 600;
    params.mask = 600;
    auto result = AuditFilePermissions(params, indicators, mContext);
    ASSERT_FALSE(result.HasValue());
}

TEST_F(EnsureFilePermissionsTest, RemediateSameBitsSet)
{
    FilePermissionsParams params;
    CreateFile(params.path, 0, 0, 0600);
    params.permissions = 600;
    params.mask = 600;
    auto result = RemediateFilePermissions(params, indicators, mContext);
    ASSERT_FALSE(result.HasValue());
}

TEST_F(EnsureFilePermissionsTest, AuditCollectionAllCompliant)
{
    CreateFileInDir("file1.txt", 0, 0, 0644);
    CreateFileInDir("file2.txt", 0, 0, 0644);

    FilePermissionsCollectionParams params;
    params.directory = testDir;
    params.filePattern = "*.txt";
    auto owner = Pattern::Make("root");
    ASSERT_TRUE(owner.HasValue());
    params.owner = {{std::move(owner).Value()}};
    auto group = Pattern::Make("root");
    ASSERT_TRUE(group.HasValue());
    params.permissions = 0644;

    auto result = AuditFilePermissionsCollection(params, indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_TRUE(mFormatter.Format(indicators).Value().find("file1.txt") != std::string::npos);
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(EnsureFilePermissionsTest, AuditCollectionExplicitFile)
{
    CreateFileInDir("file1.txt", 0, 0, 0644);

    FilePermissionsCollectionParams params;
    params.directory = testDir;
    params.filePattern = "file1.txt";
    auto owner = Pattern::Make("root");
    ASSERT_TRUE(owner.HasValue());
    params.owner = {{std::move(owner).Value()}};
    auto group = Pattern::Make("root");
    ASSERT_TRUE(group.HasValue());
    params.permissions = 0644;

    auto result = AuditFilePermissionsCollection(params, indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_TRUE(mFormatter.Format(indicators).Value().find("file1.txt owner") != std::string::npos);
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(EnsureFilePermissionsTest, AuditCollectionQuestionMark)
{
    CreateFileInDir("file1.txt", 0, 0, 0644);
    CreateFileInDir("file2.txt", 0, 0, 0644);
    CreateFileInDir("file1.log", 0, 0, 0644);
    CreateFileInDir("file13.txt", 0, 0, 0644);

    FilePermissionsCollectionParams params;
    params.directory = testDir;
    params.filePattern = "file?.txt";
    auto owner = Pattern::Make("root");
    ASSERT_TRUE(owner.HasValue());
    params.owner = {{std::move(owner).Value()}};
    auto group = Pattern::Make("root");
    ASSERT_TRUE(group.HasValue());
    params.permissions = 0644;

    auto result = AuditFilePermissionsCollection(params, indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_TRUE(mFormatter.Format(indicators).Value().find("file1.txt") != std::string::npos);
    ASSERT_TRUE(mFormatter.Format(indicators).Value().find("file2.txt") != std::string::npos);
    ASSERT_FALSE(mFormatter.Format(indicators).Value().find("file1.log") != std::string::npos);
    ASSERT_FALSE(mFormatter.Format(indicators).Value().find("file13.txt") != std::string::npos);
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(EnsureFilePermissionsTest, AuditCollectionRegexPattern)
{
    CreateFileInDir("auditd.conf", 0, 0, 0640);
    CreateFileInDir("audit.rules", 0, 0, 0600);
    CreateFileInDir("ignored.txt", 0, 0, 0666);

    FilePermissionsCollectionParams params;
    params.directory = testDir;
    params.filePattern = R"(^.*\.(conf|rules)$)";
    params.filePatternIsRegex = true;
    params.mask = 0137;

    auto result = AuditFilePermissionsCollection(params, indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(EnsureFilePermissionsTest, CollectionExactPatternDoesNotSelectRegexLookalike)
{
    CreateFileInDir("a.conf", 0, 0, 0600);
    CreateFileInDir("axconf", 0, 0, 0666);
    FilePermissionsCollectionParams params;
    params.directory = testDir;
    params.filePattern = "a.conf";
    params.mask = 0137;
    auto result = AuditFilePermissionsCollection(params, indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);
    result = RemediateFilePermissionsCollection(params, indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);
    struct stat metadata;
    ASSERT_EQ(stat((testDir + "/axconf").c_str(), &metadata), 0);
    EXPECT_EQ(metadata.st_mode & 0777, 0666u);
    params.filePatternIsRegex = true;
    result = AuditFilePermissionsCollection(params, indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::NonCompliant);
    params.filePattern = "[";
    EXPECT_FALSE(AuditFilePermissionsCollection(params, indicators, mContext).HasValue());
}

TEST_F(EnsureFilePermissionsTest, NumericOwnershipLimitsAreIndependentlyOptional)
{
    CreateFileInDir("owned", 1000, 1001, 0600);
    for (bool checkUid : {false, true})
    {
        for (bool allowOwner : {false, true})
        {
            FilePermissionsCollectionParams params;
            params.directory = testDir;
            params.filePattern = "owned";
            params.behavior = Behavior::AnyExist;
            if (checkUid)
            {
                params.maximumUid = allowOwner ? 1000 : 999;
            }
            else
            {
                params.maximumGid = allowOwner ? 1001 : 1000;
            }
            auto result = AuditFilePermissionsCollection(params, indicators, mContext);
            ASSERT_TRUE(result.HasValue());
            EXPECT_EQ(result.Value(), allowOwner ? Status::Compliant : Status::NonCompliant);
        }
    }
}

TEST_F(EnsureFilePermissionsTest, AuditCollectionNonCompliantFile)
{
    CreateFileInDir("file1.txt", 0, 0, 0644);
    CreateFileInDir("file2.txt", 1000, 0, 0644);

    FilePermissionsCollectionParams params;
    params.directory = testDir;
    params.filePattern = "*.txt";
    auto owner = Pattern::Make("root");
    ASSERT_TRUE(owner.HasValue());
    params.owner = {{std::move(owner).Value()}};
    auto group = Pattern::Make("root");
    ASSERT_TRUE(group.HasValue());
    params.permissions = 0644;

    auto result = AuditFilePermissionsCollection(params, indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::NonCompliant);
}

TEST_F(EnsureFilePermissionsTest, RemediateCollectionNonCompliantFile)
{
    CreateFileInDir("file1.txt", 0, 0, 0644);
    CreateFileInDir("file2.txt", 1000, 0, 0600);

    FilePermissionsCollectionParams params;
    params.directory = testDir;
    params.filePattern = "*.txt";
    auto owner = Pattern::Make("root");
    ASSERT_TRUE(owner.HasValue());
    params.owner = {{std::move(owner).Value()}};
    auto group = Pattern::Make("root");
    ASSERT_TRUE(group.HasValue());
    params.permissions = 0644;

    auto result = RemediateFilePermissionsCollection(params, indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);

    struct stat st;
    for (const auto& file : files)
    {
        ASSERT_EQ(stat(file.c_str(), &st), 0);
        ASSERT_EQ(st.st_uid, 0u);
        ASSERT_EQ(st.st_gid, 0u);
        ASSERT_EQ(st.st_mode & 0777, 0644u);
    }
}

TEST_F(EnsureFilePermissionsTest, AuditCollectionNoMatchingFiles)
{
    CreateFileInDir("file1.log", 0, 0, 0644);
    CreateFileInDir("file2.log", 0, 0, 0644);

    FilePermissionsCollectionParams params;
    params.directory = testDir;
    params.filePattern = "*.txt";
    auto owner = Pattern::Make("root");
    ASSERT_TRUE(owner.HasValue());
    params.owner = {{std::move(owner).Value()}};
    auto group = Pattern::Make("root");
    ASSERT_TRUE(group.HasValue());
    params.permissions = 0644;

    auto result = AuditFilePermissionsCollection(params, indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::NonCompliant);

    ASSERT_TRUE(mFormatter.Format(indicators).Value().find("At least one file in") != std::string::npos);
}

// New tests to validate recurse flag behavior.
// When recurse is default (true), nested non-compliant files should trigger NonCompliant.
TEST_F(EnsureFilePermissionsTest, AuditCollectionRecurseDefaultTrue)
{
    // Create top-level compliant file
    CreateFileInDir("top.txt", 0, 0, 0644);
    // Create nested directory and a non-compliant file inside it (wrong owner)
    std::string nestedDir = testDir + "/nested";
    ASSERT_EQ(mkdir(nestedDir.c_str(), 0755), 0);
    std::string nestedFile = nestedDir + "/bad.txt";
    std::ofstream nf(nestedFile);
    nf << "content";
    nf.close();
    ASSERT_EQ(chmod(nestedFile.c_str(), 0644), 0);
    // Set owner to uid 1 (bin) so it differs if expecting root
    ASSERT_EQ(chown(nestedFile.c_str(), 1, 0), 0);
    files.push_back(nestedFile);

    FilePermissionsCollectionParams params;
    params.directory = testDir;
    params.filePattern = "*.txt"; // Matches both files
    auto owner = Pattern::Make("root");
    ASSERT_TRUE(owner.HasValue());
    params.owner = {{std::move(owner).Value()}};
    params.permissions = 0644;
    // Do not set recurse explicitly; default should be true

    auto result = AuditFilePermissionsCollection(params, indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::NonCompliant);
}

// When recurse is false, and Behavior is AtLeastOneExists, nested non-compliant files should *not* be ignored and result be NonCompliant.
TEST_F(EnsureFilePermissionsTest, AuditCollectionRecurseFalse)
{
    // Create top-level compliant file
    CreateFileInDir("top.txt", 0, 0, 0644);
    // Create nested directory and a non-compliant file inside it (wrong owner)
    std::string nestedDir = testDir + "/nested2";
    ASSERT_EQ(mkdir(nestedDir.c_str(), 0755), 0);
    std::string nestedFile = nestedDir + "/bad.txt";
    std::ofstream nf(nestedFile);
    nf << "content";
    nf.close();
    ASSERT_EQ(chmod(nestedFile.c_str(), 0644), 0);
    ASSERT_EQ(chown(nestedFile.c_str(), 1, 0), 0);
    files.push_back(nestedFile);

    FilePermissionsCollectionParams params;
    params.directory = testDir;
    params.filePattern = "*.txt"; // Matches both files but recurse false should skip nested
    auto owner = Pattern::Make("root");
    ASSERT_TRUE(owner.HasValue());
    params.owner = {{std::move(owner).Value()}};
    params.permissions = 0644;
    params.recurse = false;

    auto result = AuditFilePermissionsCollection(params, indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(EnsureFilePermissionsTest, AuditCollectionRecurseTrueAllExistsFailOneBad)
{
    // Create top-level compliant file
    CreateFileInDir("top.txt", 0, 0, 0644);
    // Create nested directory and a non-compliant file inside it (wrong owner)
    std::string nestedDir = testDir + "/nested2";
    ASSERT_EQ(mkdir(nestedDir.c_str(), 0755), 0);

    {
        std::string nestedFile = nestedDir + "/bad.txt";
        std::ofstream nf(nestedFile);
        nf << "content";
        nf.close();
        ASSERT_EQ(chmod(nestedFile.c_str(), 0644), 0);
        ASSERT_EQ(chown(nestedFile.c_str(), 1, 0), 0);
        files.push_back(nestedFile);
    }

    {
        std::string nestedFile = nestedDir + "/good.txt";
        std::ofstream nf(nestedFile);
        nf << "content";
        nf.close();
        ASSERT_EQ(chmod(nestedFile.c_str(), 0644), 0);
        ASSERT_EQ(chown(nestedFile.c_str(), 0, 0), 0);
        files.push_back(nestedFile);
    }
    FilePermissionsCollectionParams params;
    params.directory = testDir;
    params.filePattern = "*.txt"; // Matches both files but recurse true and Behavior AllExist
    auto owner = Pattern::Make("root");
    ASSERT_TRUE(owner.HasValue());
    params.owner = {{std::move(owner).Value()}};
    params.permissions = 0644;
    params.recurse = true;
    params.behavior = Behavior::AllExist;

    auto result = AuditFilePermissionsCollection(params, indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::NonCompliant);
    std::cout << "AuditCollectionRecurseTrueAllExistsFailOneBad " << mFormatter.Format(indicators).Value() << std::endl;
    ASSERT_TRUE(mFormatter.Format(indicators).Value().find("Invalid owner") != std::string::npos);
    ASSERT_TRUE(mFormatter.Format(indicators).Value().find("bad.txt") != std::string::npos);
}

TEST_F(EnsureFilePermissionsTest, AuditCollectionRecurseTrueAllExistsAllgood)
{
    // Create top-level compliant file
    CreateFileInDir("top.txt", 0, 0, 0644);
    // Create nested directory and a non-compliant file inside it (wrong owner)
    std::string nestedDir = testDir + "/nested2";
    ASSERT_EQ(mkdir(nestedDir.c_str(), 0755), 0);

    {
        std::string nestedFile = nestedDir + "/good1.txt";
        std::ofstream nf(nestedFile);
        nf << "content";
        nf.close();
        ASSERT_EQ(chmod(nestedFile.c_str(), 0644), 0);
        ASSERT_EQ(chown(nestedFile.c_str(), 0, 0), 0);
        files.push_back(nestedFile);
    }

    {
        std::string nestedFile = nestedDir + "/good2.txt";
        std::ofstream nf(nestedFile);
        nf << "content";
        nf.close();
        ASSERT_EQ(chmod(nestedFile.c_str(), 0644), 0);
        ASSERT_EQ(chown(nestedFile.c_str(), 0, 0), 0);
        files.push_back(nestedFile);
    }
    FilePermissionsCollectionParams params;
    params.directory = testDir;
    params.filePattern = "*.txt"; // Matches both files but recurse true and Behavior AllExist
    auto owner = Pattern::Make("root");
    ASSERT_TRUE(owner.HasValue());
    params.owner = {{std::move(owner).Value()}};
    params.permissions = 0644;
    params.recurse = true;
    params.behavior = Behavior::AllExist;

    auto result = AuditFilePermissionsCollection(params, indicators, mContext);

    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);

    std::cout << "AuditCollectionRecurseTrueAllExistsAllgood:" << mFormatter.Format(indicators).Value() << std::endl;
    ASSERT_TRUE(mFormatter.Format(indicators).Value().find("good1.txt") != std::string::npos);
    ASSERT_TRUE(mFormatter.Format(indicators).Value().find("good2.txt") != std::string::npos);
}

TEST_F(EnsureFilePermissionsTest, AuditCollectionRecurseTrueNoneExists)
{
    // Create top-level compliant file
    CreateFileInDir("top.txt", 0, 0, 0644);
    // Create nested directory and a non-compliant file inside it (wrong owner)
    std::string nestedDir = testDir + "/nested2";
    ASSERT_EQ(mkdir(nestedDir.c_str(), 0755), 0);

    {
        std::string nestedFile = nestedDir + "/good1.txt";
        std::ofstream nf(nestedFile);
        nf << "content";
        nf.close();
        ASSERT_EQ(chmod(nestedFile.c_str(), 0644), 0);
        ASSERT_EQ(chown(nestedFile.c_str(), 0, 0), 0);
        files.push_back(nestedFile);
    }

    {
        std::string nestedFile = nestedDir + "/good2.txt";
        std::ofstream nf(nestedFile);
        nf << "content";
        nf.close();
        ASSERT_EQ(chmod(nestedFile.c_str(), 0644), 0);
        ASSERT_EQ(chown(nestedFile.c_str(), 0, 0), 0);
        files.push_back(nestedFile);
    }
    FilePermissionsCollectionParams params;
    params.directory = testDir;
    params.filePattern = "*.txt"; // Matches both files but recurse true and Behavior AllExist
    auto owner = Pattern::Make("root");
    ASSERT_TRUE(owner.HasValue());
    params.owner = {{std::move(owner).Value()}};
    params.permissions = 0644;
    params.recurse = true;
    params.behavior = Behavior::NoneExist;

    auto result = AuditFilePermissionsCollection(params, indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::NonCompliant);
}

TEST_F(EnsureFilePermissionsTest, AuditCollectionRecurseTrueOnlyOneExists)
{
    // Create top-level compliant file
    CreateFileInDir("top.txt", 0, 0, 0644);
    // Create nested directory and two copmpliant files
    std::string nestedDir = testDir + "/nested2";
    ASSERT_EQ(mkdir(nestedDir.c_str(), 0755), 0);

    {
        std::string nestedFile = nestedDir + "/good1.txt";
        std::ofstream nf(nestedFile);
        nf << "content";
        nf.close();
        ASSERT_EQ(chmod(nestedFile.c_str(), 0644), 0);
        ASSERT_EQ(chown(nestedFile.c_str(), 0, 0), 0);
        files.push_back(nestedFile);
    }

    {
        std::string nestedFile = nestedDir + "/good2.txt";
        std::ofstream nf(nestedFile);
        nf << "content";
        nf.close();
        ASSERT_EQ(chmod(nestedFile.c_str(), 0644), 0);
        ASSERT_EQ(chown(nestedFile.c_str(), 0, 0), 0);
        files.push_back(nestedFile);
    }
    FilePermissionsCollectionParams params;
    params.directory = testDir;
    params.filePattern = "*.txt"; // Matches both files but recurse true and Behavior OnlyOneExists
    auto owner = Pattern::Make("root");
    ASSERT_TRUE(owner.HasValue());
    params.owner = {{std::move(owner).Value()}};
    params.permissions = 0644;
    params.recurse = true;
    params.behavior = Behavior::OnlyOneExists;

    auto result = AuditFilePermissionsCollection(params, indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::NonCompliant);
}

TEST_F(EnsureFilePermissionsTest, AuditCollectionRecurseTrueOnlyOneExistsOneBad)
{
    // Create top-level compliant file
    CreateFileInDir("top.txt", 0, 0, 0644);
    // Create nested directory and a non-compliant file inside it (wrong owner)
    std::string nestedDir = testDir + "/nested2";
    ASSERT_EQ(mkdir(nestedDir.c_str(), 0755), 0);

    {
        std::string nestedFile = nestedDir + "/good1.txt";
        std::ofstream nf(nestedFile);
        nf << "content";
        nf.close();
        ASSERT_EQ(chmod(nestedFile.c_str(), 0644), 0);
        ASSERT_EQ(chown(nestedFile.c_str(), 0, 0), 0);
        files.push_back(nestedFile);
    }

    {
        std::string nestedFile = nestedDir + "/bad.txt";
        std::ofstream nf(nestedFile);
        nf << "content";
        nf.close();
        ASSERT_EQ(chmod(nestedFile.c_str(), 0644), 0);
        ASSERT_EQ(chown(nestedFile.c_str(), 1, 0), 0);
        files.push_back(nestedFile);
    }
    FilePermissionsCollectionParams params;
    params.directory = testDir;
    params.filePattern = "*.txt"; // Matches both files but recurse true and Behavior OnlyOneExists
    auto owner = Pattern::Make("root");
    ASSERT_TRUE(owner.HasValue());
    params.owner = {{std::move(owner).Value()}};
    params.permissions = 0644;
    params.recurse = true;
    params.behavior = Behavior::OnlyOneExists;

    auto result = AuditFilePermissionsCollection(params, indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::NonCompliant);
}

TEST_F(EnsureFilePermissionsTest, AuditCollectionRecurseTrueAtLeastOneExists)
{
    // Create top-level compliant file
    CreateFileInDir("top.txt", 0, 0, 0644);
    // Create nested directory and a non-compliant file inside it (wrong owner)
    std::string nestedDir = testDir + "/nested2";
    ASSERT_EQ(mkdir(nestedDir.c_str(), 0755), 0);

    {
        std::string nestedFile = nestedDir + "/good1.txt";
        std::ofstream nf(nestedFile);
        nf << "content";
        nf.close();
        ASSERT_EQ(chmod(nestedFile.c_str(), 0644), 0);
        ASSERT_EQ(chown(nestedFile.c_str(), 0, 0), 0);
        files.push_back(nestedFile);
    }

    {
        std::string nestedFile = nestedDir + "/good2.txt";
        std::ofstream nf(nestedFile);
        nf << "content";
        nf.close();
        ASSERT_EQ(chmod(nestedFile.c_str(), 0644), 0);
        ASSERT_EQ(chown(nestedFile.c_str(), 0, 0), 0);
        files.push_back(nestedFile);
    }
    FilePermissionsCollectionParams params;
    params.directory = testDir;
    params.filePattern = "*.txt"; // Matches both files but recurse true and Behavior OnlyOneExists
    auto owner = Pattern::Make("root");
    ASSERT_TRUE(owner.HasValue());
    params.owner = {{std::move(owner).Value()}};
    params.permissions = 0644;
    params.recurse = true;
    params.behavior = Behavior::AtLeastOneExists;

    auto result = AuditFilePermissionsCollection(params, indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(EnsureFilePermissionsTest, AuditCollectionRecurseTrueAtLeastOneExistsOneBad)
{
    // Create top-level compliant file
    CreateFileInDir("top.txt", 0, 0, 0644);
    // Create nested directory and a non-compliant file inside it (wrong owner)
    std::string nestedDir = testDir + "/nested2";
    ASSERT_EQ(mkdir(nestedDir.c_str(), 0755), 0);

    {
        std::string nestedFile = nestedDir + "/good1.txt";
        std::ofstream nf(nestedFile);
        nf << "content";
        nf.close();
        ASSERT_EQ(chmod(nestedFile.c_str(), 0644), 0);
        ASSERT_EQ(chown(nestedFile.c_str(), 0, 0), 0);
        files.push_back(nestedFile);
    }

    {
        std::string nestedFile = nestedDir + "/bad.txt";
        std::ofstream nf(nestedFile);
        nf << "content";
        nf.close();
        ASSERT_EQ(chmod(nestedFile.c_str(), 0644), 0);
        ASSERT_EQ(chown(nestedFile.c_str(), 1, 0), 0);
        files.push_back(nestedFile);
    }
    FilePermissionsCollectionParams params;
    params.directory = testDir;
    params.filePattern = "*.txt"; // Matches both files but recurse true and Behavior OnlyOneExists
    auto owner = Pattern::Make("root");
    ASSERT_TRUE(owner.HasValue());
    params.owner = {{std::move(owner).Value()}};
    params.permissions = 0644;
    params.recurse = true;
    params.behavior = Behavior::AtLeastOneExists;

    auto result = AuditFilePermissionsCollection(params, indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::NonCompliant);
}

// ── Single-file: file exists, all Behavior values that are not NoneExist ──────

TEST_F(EnsureFilePermissionsTest, AuditFileExistsAnyExist)
{
    FilePermissionsParams params;
    CreateFile(params.path, 0, 0, 0600);
    params.behavior = Behavior::AnyExist;

    auto result = AuditFilePermissions(params, indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
    ASSERT_TRUE(mFormatter.Format(indicators).Value().find("correct permissions and ownership as expected") != std::string::npos);
}

TEST_F(EnsureFilePermissionsTest, AuditFileExistsOnlyOneExists)
{
    FilePermissionsParams params;
    CreateFile(params.path, 0, 0, 0600);
    params.behavior = Behavior::OnlyOneExists;

    auto result = AuditFilePermissions(params, indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
    ASSERT_TRUE(mFormatter.Format(indicators).Value().find("correct permissions and ownership as expected") != std::string::npos);
}

TEST_F(EnsureFilePermissionsTest, AuditFileExistsAtLeastOneExistsExplicit)
{
    FilePermissionsParams params;
    CreateFile(params.path, 0, 0, 0600);
    params.behavior = Behavior::AtLeastOneExists;

    auto result = AuditFilePermissions(params, indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
    ASSERT_TRUE(mFormatter.Format(indicators).Value().find("correct permissions and ownership as expected") != std::string::npos);
}

// ── Single-file: file exists with wrong owner — behavior must not skip perms ──

TEST_F(EnsureFilePermissionsTest, AuditFileExistsBadPermsAnyExist)
{
    FilePermissionsParams params;
    CreateFile(params.path, 1, 0, 0600); // owner=bin, not root
    auto owner = Pattern::Make("root");
    ASSERT_TRUE(owner.HasValue());
    params.owner = {{std::move(owner).Value()}};
    params.behavior = Behavior::AnyExist;

    auto result = AuditFilePermissions(params, indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::NonCompliant);
    ASSERT_TRUE(mFormatter.Format(indicators).Value().find("owner") != std::string::npos);
}

TEST_F(EnsureFilePermissionsTest, AuditFileExistsBadPermsOnlyOneExists)
{
    FilePermissionsParams params;
    CreateFile(params.path, 1, 0, 0600); // owner=bin, not root
    auto owner = Pattern::Make("root");
    ASSERT_TRUE(owner.HasValue());
    params.owner = {{std::move(owner).Value()}};
    params.behavior = Behavior::OnlyOneExists;

    auto result = AuditFilePermissions(params, indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::NonCompliant);
    ASSERT_TRUE(mFormatter.Format(indicators).Value().find("owner") != std::string::npos);
}

// ── Collection: no matching files, all Behavior values ────────────────────────

TEST_F(EnsureFilePermissionsTest, AuditCollectionNoMatchingFilesNoneExist)
{
    CreateFileInDir("file1.log", 0, 0, 0644);

    FilePermissionsCollectionParams params;
    params.directory = testDir;
    params.filePattern = "*.txt"; // no txt files exist
    params.behavior = Behavior::NoneExist;

    auto result = AuditFilePermissionsCollection(params, indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);

    ASSERT_TRUE(mFormatter.Format(indicators).Value().find("No files in") != std::string::npos);
    ASSERT_TRUE(mFormatter.Format(indicators).Value().find("match the pattern as expected") != std::string::npos);
}

TEST_F(EnsureFilePermissionsTest, AuditCollectionNoMatchingFilesAllExist)
{
    CreateFileInDir("file1.log", 0, 0, 0644);

    FilePermissionsCollectionParams params;
    params.directory = testDir;
    params.filePattern = "*.txt";
    params.behavior = Behavior::AllExist;

    auto result = AuditFilePermissionsCollection(params, indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::NonCompliant);
    ASSERT_TRUE(mFormatter.Format(indicators).Value().find("At least one file") != std::string::npos);
    ASSERT_TRUE(mFormatter.Format(indicators).Value().find("but they should") != std::string::npos);
}

TEST_F(EnsureFilePermissionsTest, AuditCollectionNoMatchingFilesOnlyOneExists)
{
    CreateFileInDir("file1.log", 0, 0, 0644);

    FilePermissionsCollectionParams params;
    params.directory = testDir;
    params.filePattern = "*.txt";
    params.behavior = Behavior::OnlyOneExists;

    auto result = AuditFilePermissionsCollection(params, indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::NonCompliant);
    ASSERT_TRUE(mFormatter.Format(indicators).Value().find("Expected exactly one file") != std::string::npos);
}

TEST_F(EnsureFilePermissionsTest, AuditCollectionNoMatchingFilesAnyExist)
{
    CreateFileInDir("file1.log", 0, 0, 0644);

    FilePermissionsCollectionParams params;
    params.directory = testDir;
    params.filePattern = "*.txt";
    params.behavior = Behavior::AnyExist;

    auto result = AuditFilePermissionsCollection(params, indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
    ASSERT_TRUE(mFormatter.Format(indicators).Value().find("All matching files in") != std::string::npos);
}

TEST_F(EnsureFilePermissionsTest, AuditCollectionMissingDirectoryAnyExist)
{
    FilePermissionsCollectionParams params;
    params.directory = testDir + "/missing";
    params.filePattern = R"(^.+\.conf$)";
    params.filePatternIsRegex = true;
    params.mask = 0177;
    params.behavior = Behavior::AnyExist;

    auto result = AuditFilePermissionsCollection(params, indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

// ── Collection: AnyExist with matching files ──────────────────────────────────

TEST_F(EnsureFilePermissionsTest, AuditCollectionAnyExistAllGood)
{
    CreateFileInDir("file1.txt", 0, 0, 0644);
    CreateFileInDir("file2.txt", 0, 0, 0644);

    FilePermissionsCollectionParams params;
    params.directory = testDir;
    params.filePattern = "*.txt";
    auto owner = Pattern::Make("root");
    ASSERT_TRUE(owner.HasValue());
    params.owner = {{std::move(owner).Value()}};
    params.permissions = 0644;
    params.behavior = Behavior::AnyExist;

    auto result = AuditFilePermissionsCollection(params, indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(EnsureFilePermissionsTest, AuditCollectionAnyExistOneBad)
{
    CreateFileInDir("file1.txt", 0, 0, 0644); // compliant
    CreateFileInDir("file2.txt", 1, 0, 0644); // wrong owner

    FilePermissionsCollectionParams params;
    params.directory = testDir;
    params.filePattern = "*.txt";
    auto owner = Pattern::Make("root");
    ASSERT_TRUE(owner.HasValue());
    params.owner = {{std::move(owner).Value()}};
    params.permissions = 0644;
    params.behavior = Behavior::AnyExist;

    auto result = AuditFilePermissionsCollection(params, indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::NonCompliant);
    ASSERT_TRUE(mFormatter.Format(indicators).Value().find("owner") != std::string::npos);
}

// ── Collection: missing directory, NoneExist vs AtLeastOneExists ──────────────

TEST_F(EnsureFilePermissionsTest, AuditCollectionMissingDirectoryNoneExist)
{
    FilePermissionsCollectionParams params;
    params.directory = mContext.GetTempdirPath() + "/missing-directory";
    params.filePattern = "*.conf";
    params.behavior = Behavior::NoneExist;

    auto result = AuditFilePermissionsCollection(params, indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
    ASSERT_TRUE(mFormatter.Format(indicators).Value().find("match the pattern as expected") != std::string::npos);
}

TEST_F(EnsureFilePermissionsTest, AuditCollectionMissingDirectoryAtLeastOneExists)
{
    FilePermissionsCollectionParams params;
    params.directory = mContext.GetTempdirPath() + "/missing-directory";
    params.filePattern = "*.conf";
    params.behavior = Behavior::AtLeastOneExists;

    auto result = AuditFilePermissionsCollection(params, indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::NonCompliant);
    ASSERT_TRUE(mFormatter.Format(indicators).Value().find("At least one file") != std::string::npos);

    ASSERT_TRUE(mFormatter.Format(indicators).Value().find("did not match required permissions but it should") != std::string::npos);
}

TEST_F(EnsureFilePermissionsTest, AuditCheckIfExistsDistinguishesMissingFileAndBadMask)
{
    FilePermissionsParams params;
    params.path = testDir + "/missing.conf";
    params.behavior = Behavior::CheckIfExists;
    params.mask = 0022;

    auto result = AuditFilePermissions(params, indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);
    auto formatted = mFormatter.Format(indicators);
    ASSERT_TRUE(formatted.HasValue());
    EXPECT_NE(formatted.Value().find("does not exist as it should"), std::string::npos);

    CreateFileInDir("present.conf", 0, 0, 0666);
    params.path = testDir + "/present.conf";
    result = AuditFilePermissions(params, indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::NonCompliant);
    formatted = mFormatter.Format(indicators);
    ASSERT_TRUE(formatted.HasValue());
    EXPECT_NE(formatted.Value().find("Invalid permissions on '" + params.path + "'"), std::string::npos);
}

TEST_F(EnsureFilePermissionsTest, AuditCollectionCheckIfExistsDistinguishesEmptyGoodAndBad)
{
    FilePermissionsCollectionParams params;
    params.directory = testDir;
    params.filePattern = "*.conf";
    params.behavior = Behavior::CheckIfExists;
    params.mask = 0022;

    auto result = AuditFilePermissionsCollection(params, indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);
    auto formatted = mFormatter.Format(indicators);
    ASSERT_TRUE(formatted.HasValue());
    EXPECT_NE(formatted.Value().find("All matching files in"), std::string::npos);

    CreateFileInDir("good.conf", 0, 0, 0600);
    result = AuditFilePermissionsCollection(params, indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);
    formatted = mFormatter.Format(indicators);
    ASSERT_TRUE(formatted.HasValue());
    EXPECT_NE(formatted.Value().find("good.conf"), std::string::npos);

    CreateFileInDir("bad.conf", 0, 0, 0666);
    result = AuditFilePermissionsCollection(params, indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::NonCompliant);
    formatted = mFormatter.Format(indicators);
    ASSERT_TRUE(formatted.HasValue());
    EXPECT_NE(formatted.Value().find("Invalid permissions on '" + testDir + "/bad.conf'"), std::string::npos);
}

TEST_F(EnsureFilePermissionsTest, CollectionInvalidChildPermissionsErrorDoesNotChangeMode)
{
    CreateFileInDir("bad.conf", 0, 0, 0600);
    FilePermissionsCollectionParams params;
    params.directory = testDir;
    params.filePattern = "bad.conf";
    params.permissions = 0200;
    params.mask = 0200;

    auto audit = AuditFilePermissionsCollection(params, indicators, mContext);
    ASSERT_FALSE(audit.HasValue());
    EXPECT_NE(audit.Error().message.find("Invalid permissions and mask"), std::string::npos);

    struct stat before;
    ASSERT_EQ(stat((testDir + "/bad.conf").c_str(), &before), 0);
    auto remediation = RemediateFilePermissionsCollection(params, indicators, mContext);
    ASSERT_FALSE(remediation.HasValue());
    EXPECT_EQ(remediation.Error().code, EINVAL);
    EXPECT_NE(remediation.Error().message.find("Invalid permissions and mask"), std::string::npos);
    struct stat after;
    ASSERT_EQ(stat((testDir + "/bad.conf").c_str(), &after), 0);
    EXPECT_EQ(after.st_mode & 07777, before.st_mode & 07777);
}

TEST_F(EnsureFilePermissionsTest, CollectionOnlyOneExistsCountsSelectedFiles)
{
    CreateFileInDir("good.conf", 0, 0, 0600);
    CreateFileInDir("decoy.log", 0, 0, 0666);
    FilePermissionsCollectionParams params;
    params.directory = testDir;
    params.filePattern = "*.conf";
    params.mask = 0022;
    params.behavior = Behavior::OnlyOneExists;

    auto result = AuditFilePermissionsCollection(params, indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);
    auto formatted = mFormatter.Format(indicators);
    ASSERT_TRUE(formatted.HasValue());
    EXPECT_EQ(formatted.Value().find("decoy.log"), std::string::npos);

    CreateFileInDir("bad.conf", 0, 0, 0666);
    result = AuditFilePermissionsCollection(params, indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::NonCompliant);
    formatted = mFormatter.Format(indicators);
    ASSERT_TRUE(formatted.HasValue());
    EXPECT_NE(formatted.Value().find("bad.conf"), std::string::npos);
}

TEST_F(EnsureFilePermissionsTest, CollectionNoneExistRejectsSelectedBadFile)
{
    CreateFileInDir("bad.conf", 0, 0, 0666);
    FilePermissionsCollectionParams params;
    params.directory = testDir;
    params.filePattern = "*.conf";
    params.mask = 0022;
    params.behavior = Behavior::NoneExist;

    auto result = AuditFilePermissionsCollection(params, indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::NonCompliant);
}

TEST_F(EnsureFilePermissionsTest, CollectionMixedPermissionsFailInBothCreationOrders)
{
    for (bool goodFirst : {true, false})
    {
        const std::string directory = testDir + (goodFirst ? "/good-first" : "/bad-first");
        ASSERT_EQ(mkdir(directory.c_str(), 0700), 0);
        if (goodFirst)
        {
            CreateFileInDir("good-first/good.conf", 0, 0, 0600);
            CreateFileInDir("good-first/bad.conf", 0, 0, 0666);
        }
        else
        {
            CreateFileInDir("bad-first/bad.conf", 0, 0, 0666);
            CreateFileInDir("bad-first/good.conf", 0, 0, 0600);
        }

        FilePermissionsCollectionParams params;
        params.directory = directory;
        params.filePattern = "*.conf";
        params.mask = 0022;
        for (auto behavior : {Behavior::AtLeastOneExists, Behavior::AnyExist})
        {
            params.behavior = behavior;
            IndicatorsTree caseIndicators;
            caseIndicators.Push("EnsureFilePermissions");
            auto result = AuditFilePermissionsCollection(params, caseIndicators, mContext);
            ASSERT_TRUE(result.HasValue());
            EXPECT_EQ(result.Value(), Status::NonCompliant);
            auto formatted = mFormatter.Format(caseIndicators);
            ASSERT_TRUE(formatted.HasValue());
            EXPECT_NE(formatted.Value().find("bad.conf"), std::string::npos);
        }
    }
}

TEST_F(EnsureFilePermissionsTest, CollectionAuditRemediateAuditRepairsBothFiles)
{
    CreateFileInDir("first.conf", 0, 0, 0666);
    CreateFileInDir("second.conf", 0, 0, 0622);
    FilePermissionsCollectionParams params;
    params.directory = testDir;
    params.filePattern = "*.conf";
    params.mask = 0022;
    params.behavior = Behavior::AtLeastOneExists;

    auto before = AuditFilePermissionsCollection(params, indicators, mContext);
    ASSERT_TRUE(before.HasValue());
    EXPECT_EQ(before.Value(), Status::NonCompliant);
    auto remediation = RemediateFilePermissionsCollection(params, indicators, mContext);
    ASSERT_TRUE(remediation.HasValue());
    EXPECT_EQ(remediation.Value(), Status::Compliant);
    for (const auto& name : {"first.conf", "second.conf"})
    {
        struct stat metadata;
        ASSERT_EQ(stat((testDir + "/" + name).c_str(), &metadata), 0);
        EXPECT_EQ(metadata.st_mode & 0777, 0600u);
    }
    IndicatorsTree afterIndicators;
    afterIndicators.Push("EnsureFilePermissions");
    auto after = AuditFilePermissionsCollection(params, afterIndicators, mContext);
    ASSERT_TRUE(after.HasValue());
    EXPECT_EQ(after.Value(), Status::Compliant);
}

TEST_F(EnsureFilePermissionsTest, NumericOwnershipMixedThresholdsAndExcludedEntries)
{
    CreateFileInDir("good", 0, 0, 0600);
    CreateFileInDir("bad", 1000, 1001, 0600);
    const std::string linkPath = testDir + "/link";
    ASSERT_EQ(symlink("missing-target", linkPath.c_str()), 0);
    ASSERT_EQ(lchown(linkPath.c_str(), 1001, 1001), 0);
    const std::string directoryPath = testDir + "/directory";
    ASSERT_EQ(mkdir(directoryPath.c_str(), 0700), 0);
    ASSERT_EQ(chown(directoryPath.c_str(), 1001, 1001), 0);

    FilePermissionsCollectionParams params;
    params.directory = testDir;
    params.filePattern = "*";
    params.allFileTypes = true;
    params.excludeSymlinks = true;
    params.excludeDirectories = true;
    params.maximumUid = 999;
    params.maximumGid = 1000;
    params.behavior = Behavior::AnyExist;

    auto result = AuditFilePermissionsCollection(params, indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::NonCompliant);
    auto formatted = mFormatter.Format(indicators);
    ASSERT_TRUE(formatted.HasValue());
    EXPECT_NE(formatted.Value().find("bad'"), std::string::npos);
    EXPECT_EQ(formatted.Value().find("link'"), std::string::npos);
    EXPECT_EQ(formatted.Value().find("directory'"), std::string::npos);

    ASSERT_EQ(chown((testDir + "/bad").c_str(), 999, 1000), 0);
    IndicatorsTree afterIndicators;
    afterIndicators.Push("EnsureFilePermissions");
    result = AuditFilePermissionsCollection(params, afterIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);

    params.excludeDirectories = false;
    result = AuditFilePermissionsCollection(params, afterIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::NonCompliant);
    params.excludeDirectories = true;
    params.excludeSymlinks = false;
    result = AuditFilePermissionsCollection(params, afterIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::NonCompliant);
}

TEST_F(EnsureFilePermissionsTest, NumericOwnershipRejectsInvalidCombinationsAndRemediation)
{
    FilePermissionsCollectionParams params;
    params.directory = testDir;
    params.filePattern = "*";
    params.maximumUid = 0;
    params.behavior = Behavior::AnyExist;
    auto expectInvalid = [&](const FilePermissionsCollectionParams& invalid) {
        auto result = AuditFilePermissionsCollection(invalid, indicators, mContext);
        ASSERT_FALSE(result.HasValue());
        EXPECT_EQ(result.Error().code, EINVAL);
    };

    auto invalid = params;
    invalid.maximumUid = -1;
    expectInvalid(invalid);
    invalid = params;
    invalid.maximumGid = -1;
    expectInvalid(invalid);
    invalid = params;
    invalid.behavior = Behavior::CheckIfExists;
    expectInvalid(invalid);
    invalid = params;
    invalid.permissions = 0600;
    expectInvalid(invalid);
    invalid = params;
    invalid.mask = 0022;
    expectInvalid(invalid);
    invalid = params;
    auto owner = Pattern::Make("root");
    ASSERT_TRUE(owner.HasValue());
    invalid.owner = {{std::move(owner.Value())}};
    expectInvalid(invalid);
    invalid = params;
    auto group = Pattern::Make("root");
    ASSERT_TRUE(group.HasValue());
    invalid.group = {{std::move(group.Value())}};
    expectInvalid(invalid);
    invalid = params;
    invalid.directoriesOnly = true;
    invalid.allFileTypes = true;
    expectInvalid(invalid);
    invalid = params;
    invalid.maximumUid.Reset();
    invalid.allFileTypes = true;
    expectInvalid(invalid);
    invalid = params;
    invalid.excludeSymlinks = true;
    expectInvalid(invalid);
    invalid = params;
    invalid.excludeDirectories = true;
    expectInvalid(invalid);

    auto remediation = RemediateFilePermissionsCollection(params, indicators, mContext);
    ASSERT_FALSE(remediation.HasValue());
    EXPECT_EQ(remediation.Error().code, ENOTSUP);
}
