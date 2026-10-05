// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "FileTreeWalk.h"

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <fstream>
#include <gtest/gtest.h>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>
#include <vector>

using ComplianceEngine::BreakOnNonCompliant;
using ComplianceEngine::ContextInterface;
using ComplianceEngine::Error;
using ComplianceEngine::FilesystemScanner;
using ComplianceEngine::FileTreeWalk;
using ComplianceEngine::InterfaceInfo;
using ComplianceEngine::Result;
using ComplianceEngine::Status;
using ComplianceEngine::Telemetry;

namespace
{
void RemoveTree(const std::string& path)
{
    struct stat pathStat;
    if (0 != lstat(path.c_str(), &pathStat))
    {
        return;
    }

    if (!S_ISDIR(pathStat.st_mode))
    {
        (void)unlink(path.c_str());
        return;
    }

    DIR* directory = opendir(path.c_str());
    if (nullptr != directory)
    {
        for (struct dirent* entry = readdir(directory); nullptr != entry; entry = readdir(directory))
        {
            if ((0 == strcmp(entry->d_name, ".")) || (0 == strcmp(entry->d_name, "..")))
            {
                continue;
            }

            RemoveTree(path + "/" + entry->d_name);
        }
        closedir(directory);
    }

    (void)rmdir(path.c_str());
}

class TestDirectory
{
public:
    TestDirectory()
    {
        const char* tempRoot = getenv("TMPDIR");
        if ((nullptr == tempRoot) || ('\0' == tempRoot[0]))
        {
            throw std::runtime_error("TMPDIR must be set for FileTreeWalk tests");
        }

        std::string pathTemplate = std::string(tempRoot) + "/FileTreeWalkTest.XXXXXX";
        std::vector<char> buffer(pathTemplate.begin(), pathTemplate.end());
        buffer.push_back('\0');
        char* createdPath = mkdtemp(buffer.data());
        if (nullptr == createdPath)
        {
            throw std::runtime_error("Failed to create FileTreeWalk test directory: " + std::string(strerror(errno)));
        }
        mPath = createdPath;
    }

    ~TestDirectory()
    {
        RemoveTree(mPath);
    }

    const std::string& Path() const
    {
        return mPath;
    }

    std::string MakeDirectory(const std::string& relativePath) const
    {
        const std::string path = mPath + "/" + relativePath;
        if (0 != mkdir(path.c_str(), 0700))
        {
            throw std::runtime_error("Failed to create directory '" + path + "': " + strerror(errno));
        }
        return path;
    }

    std::string MakeFile(const std::string& relativePath) const
    {
        const std::string path = mPath + "/" + relativePath;
        std::ofstream file(path.c_str());
        file << "data";
        file.close();
        if (!file)
        {
            throw std::runtime_error("Failed to create file '" + path + "'");
        }
        return path;
    }

    std::string MakeSymlink(const std::string& target, const std::string& relativePath) const
    {
        const std::string path = mPath + "/" + relativePath;
        if (0 != symlink(target.c_str(), path.c_str()))
        {
            throw std::runtime_error("Failed to create symlink '" + path + "': " + strerror(errno));
        }
        return path;
    }

private:
    std::string mPath;
};

class TestContext : public ContextInterface
{
public:
    explicit TestContext(const TestDirectory& directory)
        : mScanner(directory.Path(), directory.Path() + "/cache", directory.Path() + "/lock", 0, 0, 0)
    {
    }

    Result<std::string> ExecuteCommand(const std::string&) const override
    {
        return Error("Not implemented by FileTreeWalk tests");
    }

    Result<std::string> GetFileContents(const std::string&) const override
    {
        return Error("Not implemented by FileTreeWalk tests");
    }

    Telemetry& GetTelemetry() override
    {
        return mTelemetry;
    }

    Result<std::vector<InterfaceInfo>> GetNetworkInterfaces() const override
    {
        return Error("Not implemented by FileTreeWalk tests");
    }

    Result<std::string> GetRunningKernelRelease() const override
    {
        return Error("Not implemented by FileTreeWalk tests");
    }

    OsConfigLogHandle GetLogHandle() const override
    {
        return nullptr;
    }

    std::string GetSpecialFilePath(const std::string& path) const override
    {
        return path;
    }

    FilesystemScanner& GetFilesystemScanner() override
    {
        return mScanner;
    }

    std::string GetStatePath() const override
    {
        return std::string();
    }

private:
    FilesystemScanner mScanner;
    Telemetry mTelemetry{-1};
};

struct VisitedEntry
{
    VisitedEntry(std::string directory, std::string name, mode_t mode)
        : directory(std::move(directory)),
          name(std::move(name)),
          mode(mode)
    {
    }

    std::string directory;
    std::string name;
    mode_t mode;
};

Result<Status> RecordEntry(std::vector<VisitedEntry>& entries, const std::string& directory, const std::string& name, const struct stat& entryStat)
{
    entries.push_back({directory, name, entryStat.st_mode});
    return Status::Compliant;
}
} // namespace

TEST(FileTreeWalkTest, VisitsNestedEntriesWithMetadataAndDirectoriesInPostorder)
{
    TestDirectory directory;
    directory.MakeDirectory("sub");
    directory.MakeFile("root.txt");
    directory.MakeFile("sub/nested.txt");
    TestContext context(directory);
    std::vector<VisitedEntry> entries;

    const Result<Status> result = FileTreeWalk(
        directory.Path(),
        [&entries](const std::string& parent, const std::string& name, const struct stat& entryStat) {
            return RecordEntry(entries, parent, name, entryStat);
        },
        BreakOnNonCompliant::False, context);

    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(Status::Compliant, result.Value());
    ASSERT_EQ(3u, entries.size());

    const auto rootFile = std::find_if(entries.begin(), entries.end(), [](const VisitedEntry& entry) { return "root.txt" == entry.name; });
    const auto nestedFile = std::find_if(entries.begin(), entries.end(), [](const VisitedEntry& entry) { return "nested.txt" == entry.name; });
    const auto subdirectory = std::find_if(entries.begin(), entries.end(), [](const VisitedEntry& entry) { return "sub" == entry.name; });
    ASSERT_NE(entries.end(), rootFile);
    ASSERT_NE(entries.end(), nestedFile);
    ASSERT_NE(entries.end(), subdirectory);
    EXPECT_TRUE(S_ISREG(rootFile->mode));
    EXPECT_TRUE(S_ISREG(nestedFile->mode));
    EXPECT_TRUE(S_ISDIR(subdirectory->mode));
    EXPECT_EQ(directory.Path(), rootFile->directory);
    EXPECT_EQ(directory.Path() + "/sub", nestedFile->directory);
    EXPECT_EQ(directory.Path(), subdirectory->directory);
    EXPECT_LT(std::distance(entries.begin(), nestedFile), std::distance(entries.begin(), subdirectory));
}

TEST(FileTreeWalkTest, FollowsRootSymlinkButDoesNotFollowInteriorDirectorySymlink)
{
    TestDirectory directory;
    directory.MakeDirectory("target");
    directory.MakeFile("target/file.txt");
    directory.MakeDirectory("walk");
    directory.MakeSymlink(directory.Path() + "/target", "walk/interior-link");
    const std::string rootLink = directory.MakeSymlink(directory.Path() + "/target", "root-link");
    TestContext context(directory);
    std::vector<VisitedEntry> rootEntries;
    std::vector<VisitedEntry> interiorEntries;

    const Result<Status> rootResult = FileTreeWalk(
        rootLink,
        [&rootEntries](const std::string& parent, const std::string& name, const struct stat& entryStat) {
            return RecordEntry(rootEntries, parent, name, entryStat);
        },
        BreakOnNonCompliant::False, context);
    const Result<Status> interiorResult = FileTreeWalk(
        directory.Path() + "/walk",
        [&interiorEntries](const std::string& parent, const std::string& name, const struct stat& entryStat) {
            return RecordEntry(interiorEntries, parent, name, entryStat);
        },
        BreakOnNonCompliant::False, context);

    ASSERT_TRUE(rootResult.HasValue());
    ASSERT_TRUE(interiorResult.HasValue());
    ASSERT_EQ(1u, rootEntries.size());
    EXPECT_EQ("file.txt", rootEntries[0].name);
    EXPECT_TRUE(S_ISREG(rootEntries[0].mode));
    ASSERT_EQ(1u, interiorEntries.size());
    EXPECT_EQ("interior-link", interiorEntries[0].name);
    EXPECT_TRUE(S_ISLNK(interiorEntries[0].mode));
}

TEST(FileTreeWalkTest, ReportsDanglingSymlinkMetadata)
{
    TestDirectory directory;
    directory.MakeSymlink("missing-target", "dangling");
    TestContext context(directory);
    std::vector<VisitedEntry> entries;

    const Result<Status> result = FileTreeWalk(
        directory.Path(),
        [&entries](const std::string& parent, const std::string& name, const struct stat& entryStat) {
            return RecordEntry(entries, parent, name, entryStat);
        },
        BreakOnNonCompliant::False, context);

    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(1u, entries.size());
    EXPECT_EQ("dangling", entries[0].name);
    EXPECT_TRUE(S_ISLNK(entries[0].mode));
}

TEST(FileTreeWalkTest, PropagatesCallbackError)
{
    TestDirectory directory;
    directory.MakeFile("file.txt");
    TestContext context(directory);

    const Result<Status> result = FileTreeWalk(
        directory.Path(), [](const std::string&, const std::string&, const struct stat&) -> Result<Status> { return Error("callback failed", EIO); },
        BreakOnNonCompliant::False, context);

    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EIO, result.Error().code);
    EXPECT_EQ("callback failed", result.Error().message);
}

TEST(FileTreeWalkTest, StopsAfterFirstNonCompliantEntryWhenRequested)
{
    TestDirectory directory;
    directory.MakeFile("one");
    directory.MakeFile("two");
    directory.MakeFile("three");
    TestContext context(directory);
    size_t callbackCount = 0;

    const Result<Status> result = FileTreeWalk(
        directory.Path(),
        [&callbackCount](const std::string&, const std::string&, const struct stat&) -> Result<Status> {
            ++callbackCount;
            return Status::NonCompliant;
        },
        BreakOnNonCompliant::True, context);

    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(Status::NonCompliant, result.Value());
    EXPECT_EQ(1u, callbackCount);
}

TEST(FileTreeWalkTest, ContinuesAfterNonCompliantEntryWhenRequested)
{
    TestDirectory directory;
    directory.MakeFile("one");
    directory.MakeFile("two");
    directory.MakeFile("three");
    TestContext context(directory);
    size_t callbackCount = 0;

    const Result<Status> result = FileTreeWalk(
        directory.Path(),
        [&callbackCount](const std::string&, const std::string&, const struct stat&) -> Result<Status> {
            ++callbackCount;
            return Status::NonCompliant;
        },
        BreakOnNonCompliant::False, context);

    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(Status::NonCompliant, result.Value());
    EXPECT_EQ(3u, callbackCount);
}

TEST(FileTreeWalkTest, TreatsMissingRootAsCompliantWithoutCallbacks)
{
    TestDirectory directory;
    TestContext context(directory);
    size_t callbackCount = 0;

    const Result<Status> result = FileTreeWalk(
        directory.Path() + "/missing",
        [&callbackCount](const std::string&, const std::string&, const struct stat&) -> Result<Status> {
            ++callbackCount;
            return Status::Compliant;
        },
        BreakOnNonCompliant::False, context);

    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(Status::Compliant, result.Value());
    EXPECT_EQ(0u, callbackCount);
}

TEST(FileTreeWalkTest, CompletesAtMaximumDepth)
{
    TestDirectory directory;
    std::string relativePath;
    for (size_t depth = 1; 32 >= depth; ++depth)
    {
        relativePath += (relativePath.empty() ? "" : "/") + std::string("d") + std::to_string(depth);
        directory.MakeDirectory(relativePath);
    }
    directory.MakeFile(relativePath + "/deepest.txt");
    TestContext context(directory);

    const Result<Status> result = FileTreeWalk(
        directory.Path(), [](const std::string&, const std::string&, const struct stat&) -> Result<Status> { return Status::Compliant; },
        BreakOnNonCompliant::False, context);

    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(Status::Compliant, result.Value());
}

TEST(FileTreeWalkTest, ReturnsErrorWhenDescentExceedsMaximumDepth)
{
    TestDirectory directory;
    std::string relativePath;
    for (size_t depth = 1; 33 >= depth; ++depth)
    {
        relativePath += (relativePath.empty() ? "" : "/") + std::string("d") + std::to_string(depth);
        directory.MakeDirectory(relativePath);
    }
    TestContext context(directory);

    const Result<Status> result = FileTreeWalk(
        directory.Path(), [](const std::string&, const std::string&, const struct stat&) -> Result<Status> { return Status::Compliant; },
        BreakOnNonCompliant::False, context);

    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ("Maximum recursion depth reached", result.Error().message);
}
