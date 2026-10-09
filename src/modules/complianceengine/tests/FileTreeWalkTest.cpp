// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "FileTreeWalk.h"

#include "FilesystemCollection.h"
#include "TemporaryDirectory.h"

#include <algorithm>
#include <cerrno>
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
using ComplianceEngine::TemporaryDirectory;

namespace
{
class TestDirectory
{
public:
    TestDirectory()
        : mOwner(Create())
    {
    }

    const std::string& Path() const
    {
        return mOwner.Path();
    }

    std::string MakeDirectory(const std::string& relativePath) const
    {
        const std::string path = Path() + "/" + relativePath;
        if (0 != mkdir(path.c_str(), 0700))
        {
            throw std::runtime_error("Failed to create directory '" + path + "': " + strerror(errno));
        }
        return path;
    }

    std::string MakeFile(const std::string& relativePath) const
    {
        const std::string path = Path() + "/" + relativePath;
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
        const std::string path = Path() + "/" + relativePath;
        if (0 != symlink(target.c_str(), path.c_str()))
        {
            throw std::runtime_error("Failed to create symlink '" + path + "': " + strerror(errno));
        }
        return path;
    }

    std::string MakeChain(int depth) const
    {
        std::string relativePath;
        for (int level = 1; level <= depth; ++level)
        {
            relativePath += (relativePath.empty() ? "" : "/") + std::string("d") + std::to_string(level);
            MakeDirectory(relativePath);
        }
        return relativePath;
    }

private:
    static TemporaryDirectory Create()
    {
        Result<TemporaryDirectory> result = TemporaryDirectory::Make("FileTreeWalkTest");
        if (!result.HasValue())
        {
            throw std::runtime_error(result.Error().message);
        }
        return std::move(result).Value();
    }

    TemporaryDirectory mOwner;
};

class TestContext : public ContextInterface
{
public:
    explicit TestContext(const TestDirectory& directory)
        : mScanner(directory.Path(), directory.Path() + "/cache", directory.Path() + "/lock", 60, 120, 10)
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

TEST(FileTreeWalkTest, ReturnsErrorForRegularFileRootWithoutCallbacks)
{
    TestDirectory directory;
    const std::string rootFile = directory.MakeFile("root.txt");
    TestContext context(directory);
    size_t callbackCount = 0;

    const Result<Status> result = FileTreeWalk(
        rootFile,
        [&callbackCount](const std::string&, const std::string&, const struct stat&) -> Result<Status> {
            ++callbackCount;
            return Status::Compliant;
        },
        BreakOnNonCompliant::False, context);

    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(ENOTDIR, result.Error().code);
    EXPECT_EQ(0u, callbackCount);
}

TEST(FileTreeWalkTest, ReturnsErrorForRootSymlinkLoopWithoutCallbacks)
{
    TestDirectory directory;
    const std::string rootLink = directory.MakeSymlink("root-link", "root-link");
    TestContext context(directory);
    size_t callbackCount = 0;

    const Result<Status> result = FileTreeWalk(
        rootLink,
        [&callbackCount](const std::string&, const std::string&, const struct stat&) -> Result<Status> {
            ++callbackCount;
            return Status::Compliant;
        },
        BreakOnNonCompliant::False, context);

    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(ELOOP, result.Error().code);
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

TEST(FileTreeWalkTest, ChildStopSkipsDirectoryPostorderCallback)
{
    TestDirectory directory;
    directory.MakeDirectory("sub");
    directory.MakeFile("sub/failing");
    TestContext context(directory);
    std::vector<std::string> visited;

    const Result<Status> result = FileTreeWalk(
        directory.Path(),
        [&visited](const std::string&, const std::string& name, const struct stat&) -> Result<Status> {
            visited.push_back(name);
            return "failing" == name ? Status::NonCompliant : Status::Compliant;
        },
        BreakOnNonCompliant::True, context);

    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(Status::NonCompliant, result.Value());
    EXPECT_EQ((std::vector<std::string>{"failing"}), visited);
}

TEST(FileTreeWalkTest, ObtainsDirectoryMetadataAfterNestedFileCallback)
{
    TestDirectory directory;
    const std::string child = directory.MakeDirectory("sub");
    directory.MakeFile("sub/item");
    TestContext context(directory);
    mode_t deliveredMode = 0;

    const Result<Status> result = FileTreeWalk(
        directory.Path(),
        [&child, &deliveredMode](const std::string&, const std::string& name, const struct stat& entryStat) -> Result<Status> {
            if ("item" == name)
            {
                if (0 != chmod(child.c_str(), 0500))
                {
                    return Error("Failed to change child permissions", errno);
                }
            }
            if ("sub" == name)
            {
                deliveredMode = entryStat.st_mode & 0777;
                if (0 != chmod(child.c_str(), 0700))
                {
                    return Error("Failed to restore child permissions", errno);
                }
            }
            return Status::Compliant;
        },
        BreakOnNonCompliant::False, context);

    EXPECT_EQ(0, chmod(child.c_str(), 0700));
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(Status::Compliant, result.Value());
    EXPECT_EQ(0500, deliveredMode);
}

TEST(FileTreeWalkTest, LaterCallbackErrorOverridesEarlierNoncompliance)
{
    TestDirectory directory;
    directory.MakeFile("first");
    directory.MakeFile("second");
    TestContext context(directory);
    size_t callbackCount = 0;

    const Result<Status> result = FileTreeWalk(
        directory.Path(),
        [&callbackCount](const std::string&, const std::string&, const struct stat&) -> Result<Status> {
            ++callbackCount;
            if (1 == callbackCount)
            {
                return Status::NonCompliant;
            }
            return Error("later callback failed", EIO);
        },
        BreakOnNonCompliant::False, context);

    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(2u, callbackCount);
    EXPECT_EQ(EIO, result.Error().code);
    EXPECT_EQ("later callback failed", result.Error().message);
}

TEST(FileTreeWalkTest, UnknownDirectoryTypesAreDeliveredWithoutDescentAndUnknownDotsReachCallback)
{
    TestDirectory directory;
    directory.MakeDirectory("sub");
    directory.MakeFile("sub/nested");
    TestContext context(directory);
    ComplianceEngine::Detail::FilesystemCollectionOperations operations;
    operations.readDirectory = [](DIR* stream) {
        struct dirent* entry = readdir(stream);
        if ((nullptr != entry) && ((0 == strcmp(entry->d_name, ".")) || (0 == strcmp(entry->d_name, "..")) || (0 == strcmp(entry->d_name, "sub"))))
        {
            entry->d_type = DT_UNKNOWN;
        }
        return entry;
    };
    std::vector<std::string> visited;

    const Result<Status> result = ComplianceEngine::Detail::FileTreeWalkWithOperations(
        directory.Path(),
        [&visited](const std::string&, const std::string& name, const struct stat& metadata) -> Result<Status> {
            EXPECT_TRUE(S_ISDIR(metadata.st_mode));
            visited.push_back(name);
            return Status::Compliant;
        },
        BreakOnNonCompliant::False, context, operations);

    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(Status::Compliant, result.Value());
    EXPECT_EQ(1, std::count(visited.begin(), visited.end(), "."));
    EXPECT_EQ(1, std::count(visited.begin(), visited.end(), ".."));
    EXPECT_EQ(1, std::count(visited.begin(), visited.end(), "sub"));
    EXPECT_EQ(0, std::count(visited.begin(), visited.end(), "nested"));
}

TEST(FileTreeWalkTest, MissingRequiredInteriorDirectoryIsAnError)
{
    TestDirectory directory;
    directory.MakeDirectory("sub");
    TestContext context(directory);
    ComplianceEngine::Detail::FilesystemCollectionOperations operations;
    operations.openDirectory = [&directory](const char* path) -> DIR* {
        if (directory.Path() + "/sub" == path)
        {
            errno = ENOENT;
            return nullptr;
        }
        return opendir(path);
    };
    std::size_t callbackCount = 0;

    const Result<Status> result = ComplianceEngine::Detail::FileTreeWalkWithOperations(
        directory.Path(),
        [&callbackCount](const std::string&, const std::string&, const struct stat&) -> Result<Status> {
            ++callbackCount;
            return Status::Compliant;
        },
        BreakOnNonCompliant::False, context, operations);

    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(ENOENT, result.Error().code);
    EXPECT_NE(std::string::npos, result.Error().message.find(directory.Path() + "/sub"));
    EXPECT_EQ(0u, callbackCount);
}

TEST(FileTreeWalkTest, RejectsOverlongLegacyDirectoryBeforeOpeningIt)
{
    const std::string rootPath(4094, 'x');
    ComplianceEngine::Detail::FilesystemCollectionOperations operations;
    std::size_t opens = 0;
    operations.openDirectory = [&opens](const char*) {
        ++opens;
        return opendir(".");
    };
    struct dirent child = {};
    strcpy(child.d_name, "child");
    child.d_type = DT_DIR;
    bool emitted = false;
    operations.readDirectory = [&child, &emitted](DIR*) -> struct dirent*
    {
        if (!emitted)
        {
            emitted = true;
            return &child;
        }
        errno = 0;
        return nullptr;
    };
    std::size_t callbacks = 0;

    const auto result = ComplianceEngine::Detail::StreamLegacyFileTreeWalk(
        rootPath,
        [&callbacks](const ComplianceEngine::FilesystemCollectionEntry&) {
            ++callbacks;
            return Result<ComplianceEngine::FilesystemVisitAction>(ComplianceEngine::FilesystemVisitAction::Continue);
        },
        operations);

    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(ENAMETOOLONG, result.Error().code);
    EXPECT_EQ(1u, opens);
    EXPECT_EQ(0u, callbacks);
}

TEST(FileTreeWalkTest, DescriptorContinuationDeliversEveryPostorderEntryOnce)
{
    TestDirectory directory;
    const std::string relativePath = directory.MakeChain(18);
    directory.MakeFile(relativePath + "/leaf");
    directory.MakeFile("sibling");
    TestContext context(directory);
    ComplianceEngine::Detail::FilesystemCollectionOperations operations;
    struct dirent rootEntries[2] = {};
    strcpy(rootEntries[0].d_name, "d1");
    rootEntries[0].d_type = DT_DIR;
    strcpy(rootEntries[1].d_name, "sibling");
    rootEntries[1].d_type = DT_REG;
    DIR* rootStream = nullptr;
    std::size_t rootIndex = 0;
    operations.openDirectory = [&directory, &rootStream, &rootIndex](const char* path) {
        DIR* stream = opendir(path);
        if (directory.Path() == path)
        {
            rootStream = stream;
            rootIndex = 0;
        }
        return stream;
    };
    operations.closeDirectory = [&rootStream](DIR* stream) {
        if (rootStream == stream)
        {
            rootStream = nullptr;
        }
        return closedir(stream);
    };
    operations.readDirectory = [&rootStream, &rootIndex, &rootEntries](DIR * stream) -> struct dirent*
    {
        if (rootStream == stream)
        {
            if (2 == rootIndex)
            {
                errno = 0;
                return nullptr;
            }
            return &rootEntries[rootIndex++];
        }
        return readdir(stream);
    };
    std::vector<std::string> visited;

    const Result<Status> result = ComplianceEngine::Detail::FileTreeWalkWithOperations(
        directory.Path(),
        [&visited](const std::string&, const std::string& name, const struct stat&) -> Result<Status> {
            visited.push_back(name);
            return Status::Compliant;
        },
        BreakOnNonCompliant::False, context, operations);

    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(Status::Compliant, result.Value());
    ASSERT_EQ(20u, visited.size());
    EXPECT_EQ("sibling", visited.back());
    visited.pop_back();
    ASSERT_EQ("leaf", visited.front());
    for (int depth = 18; depth >= 1; --depth)
    {
        EXPECT_EQ("d" + std::to_string(depth), visited[19 - depth]);
    }
}

TEST(FileTreeWalkTest, ChangedAncestorIdentityDuringReplayIsAnError)
{
    TestDirectory directory;
    directory.MakeChain(17);
    TestContext context(directory);
    ComplianceEngine::Detail::FilesystemCollectionOperations operations;
    bool reopeningRoot = false;
    std::size_t rootOpens = 0;
    operations.openDirectory = [&directory, &reopeningRoot, &rootOpens](const char* path) {
        if (directory.Path() == path)
        {
            reopeningRoot = (0 != rootOpens++);
        }
        return opendir(path);
    };
    operations.statDescriptor = [&reopeningRoot](int descriptor, struct stat* metadata) {
        const int status = fstat(descriptor, metadata);
        if ((0 == status) && reopeningRoot)
        {
            ++metadata->st_ino;
        }
        return status;
    };
    std::vector<std::string> visited;

    const Result<Status> result = ComplianceEngine::Detail::FileTreeWalkWithOperations(
        directory.Path(),
        [&visited](const std::string&, const std::string& name, const struct stat&) -> Result<Status> {
            visited.push_back(name);
            return Status::Compliant;
        },
        BreakOnNonCompliant::False, context, operations);

    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(ESTALE, result.Error().code);
    EXPECT_EQ(2u, rootOpens);
    EXPECT_EQ(1, std::count(visited.begin(), visited.end(), "d1"));
}

TEST(FileTreeWalkTest, ChangedAncestorPrefixDuringReplayIsAnError)
{
    TestDirectory directory;
    directory.MakeChain(17);
    TestContext context(directory);
    ComplianceEngine::Detail::FilesystemCollectionOperations operations;
    bool replayingRoot = false;
    std::size_t rootOpens = 0;
    DIR* rootStream = nullptr;
    operations.openDirectory = [&directory, &replayingRoot, &rootOpens, &rootStream](const char* path) {
        DIR* stream = opendir(path);
        if (directory.Path() == path)
        {
            replayingRoot = (0 != rootOpens++);
            rootStream = stream;
        }
        return stream;
    };
    operations.readDirectory = [&replayingRoot, &rootStream](DIR* stream) {
        struct dirent* entry = readdir(stream);
        if ((nullptr != entry) && replayingRoot && (stream == rootStream) && (0 == strcmp(entry->d_name, "d1")))
        {
            ++entry->d_ino;
        }
        return entry;
    };
    std::vector<std::string> visited;

    const Result<Status> result = ComplianceEngine::Detail::FileTreeWalkWithOperations(
        directory.Path(),
        [&visited](const std::string&, const std::string& name, const struct stat&) -> Result<Status> {
            visited.push_back(name);
            return Status::Compliant;
        },
        BreakOnNonCompliant::False, context, operations);

    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(ESTALE, result.Error().code);
    EXPECT_EQ(2u, rootOpens);
    EXPECT_EQ(1, std::count(visited.begin(), visited.end(), "d1"));
}

TEST(FileTreeWalkTest, PostorderStatFailureIsPrimaryButDecisiveStopSkipsIt)
{
    TestDirectory directory;
    const std::string child = directory.MakeDirectory("sub");
    directory.MakeFile("sub/item");
    TestContext context(directory);
    ComplianceEngine::Detail::FilesystemCollectionOperations operations;
    std::size_t childStats = 0;
    operations.lstatPath = [&child, &childStats](const char* path, struct stat* metadata) {
        if (child == path)
        {
            ++childStats;
            errno = EACCES;
            return -1;
        }
        return lstat(path, metadata);
    };
    std::vector<std::string> visited;
    const auto callback = [&visited](const std::string&, const std::string& name, const struct stat&) -> Result<Status> {
        visited.push_back(name);
        return "item" == name ? Status::NonCompliant : Status::Compliant;
    };

    const Result<Status> continued =
        ComplianceEngine::Detail::FileTreeWalkWithOperations(directory.Path(), callback, BreakOnNonCompliant::False, context, operations);
    ASSERT_FALSE(continued.HasValue());
    EXPECT_EQ(EACCES, continued.Error().code);
    EXPECT_EQ(1u, childStats);

    childStats = 0;
    visited.clear();
    const Result<Status> stopped = ComplianceEngine::Detail::FileTreeWalkWithOperations(directory.Path(), callback, BreakOnNonCompliant::True, context, operations);
    ASSERT_TRUE(stopped.HasValue());
    EXPECT_EQ(Status::NonCompliant, stopped.Value());
    EXPECT_EQ(0u, childStats);
    EXPECT_NE(visited.end(), std::find(visited.begin(), visited.end(), "item"));
}

TEST(FileTreeWalkTest, PostorderStopDoesNotReopenSuspendedAncestors)
{
    TestDirectory directory;
    directory.MakeChain(18);
    TestContext context(directory);
    ComplianceEngine::Detail::FilesystemCollectionOperations operations;
    std::size_t rootOpens = 0;
    operations.openDirectory = [&directory, &rootOpens](const char* path) {
        if (directory.Path() == path)
        {
            ++rootOpens;
        }
        return opendir(path);
    };
    std::vector<std::string> visited;

    const Result<Status> result = ComplianceEngine::Detail::FileTreeWalkWithOperations(
        directory.Path(),
        [&visited](const std::string&, const std::string& name, const struct stat&) -> Result<Status> {
            visited.push_back(name);
            return "d18" == name ? Status::NonCompliant : Status::Compliant;
        },
        BreakOnNonCompliant::True, context, operations);

    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(Status::NonCompliant, result.Value());
    EXPECT_EQ((std::vector<std::string>{"d18"}), visited);
    EXPECT_EQ(1u, rootOpens);
}

TEST(FileTreeWalkTest, DecisiveStopDoesNotReopenSuspendedAncestors)
{
    TestDirectory directory;
    const std::string relativePath = directory.MakeChain(18);
    directory.MakeFile(relativePath + "/leaf");
    TestContext context(directory);
    ComplianceEngine::Detail::FilesystemCollectionOperations operations;
    std::size_t rootOpens = 0;
    operations.openDirectory = [&directory, &rootOpens](const char* path) {
        if (directory.Path() == path)
        {
            ++rootOpens;
        }
        return opendir(path);
    };
    std::vector<std::string> visited;

    const Result<Status> result = ComplianceEngine::Detail::FileTreeWalkWithOperations(
        directory.Path(),
        [&visited](const std::string&, const std::string& name, const struct stat&) -> Result<Status> {
            visited.push_back(name);
            return "leaf" == name ? Status::NonCompliant : Status::Compliant;
        },
        BreakOnNonCompliant::True, context, operations);

    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(Status::NonCompliant, result.Value());
    EXPECT_EQ((std::vector<std::string>{"leaf"}), visited);
    EXPECT_EQ(1u, rootOpens);
}

TEST(FileTreeWalkTest, CloseFailureIsAnErrorUnlessCallbackAlreadyFailed)
{
    TestDirectory directory;
    directory.MakeFile("item");
    TestContext context(directory);
    ComplianceEngine::Detail::FilesystemCollectionOperations operations;
    operations.closeDirectory = [](DIR* stream) {
        const int status = closedir(stream);
        if (0 == status)
        {
            errno = EIO;
            return -1;
        }
        return status;
    };
    const auto callback = [](const std::string&, const std::string&, const struct stat&) -> Result<Status> { return Status::Compliant; };
    const Result<Status> closeFailure =
        ComplianceEngine::Detail::FileTreeWalkWithOperations(directory.Path(), callback, BreakOnNonCompliant::False, context, operations);
    ASSERT_FALSE(closeFailure.HasValue());
    EXPECT_EQ(EIO, closeFailure.Error().code);

    const Result<Status> callbackFailure = ComplianceEngine::Detail::FileTreeWalkWithOperations(
        directory.Path(), [](const std::string&, const std::string&, const struct stat&) -> Result<Status> { return Error("callback failed", EACCES); },
        BreakOnNonCompliant::False, context, operations);
    ASSERT_FALSE(callbackFailure.HasValue());
    EXPECT_EQ(EACCES, callbackFailure.Error().code);
    EXPECT_EQ("callback failed", callbackFailure.Error().message);
}
