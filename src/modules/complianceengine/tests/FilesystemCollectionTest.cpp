// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "FilesystemCollection.h"

#include "TemporaryDirectory.h"

#include <algorithm>
#include <cerrno>
#include <fstream>
#include <gtest/gtest.h>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>
#include <vector>

using ComplianceEngine::CollectFilesystem;
using ComplianceEngine::FilesystemCollectionEntry;
using ComplianceEngine::FilesystemCollectionOutcome;
using ComplianceEngine::FilesystemCollectionRequest;
using ComplianceEngine::FilesystemDirection;
using ComplianceEngine::FilesystemLinkAction;
using ComplianceEngine::FilesystemRootKind;
using ComplianceEngine::FilesystemScope;
using ComplianceEngine::FilesystemVisitAction;
using ComplianceEngine::ResolvedFilesystemCollectionRequest;
using ComplianceEngine::ResolveFilesystemCollectionRequest;
using ComplianceEngine::Result;
using ComplianceEngine::StreamFilesystemCollection;
using ComplianceEngine::TemporaryDirectory;
using ComplianceEngine::Detail::CollectFilesystemWithOperations;
using ComplianceEngine::Detail::FilesystemCollectionOperations;
using ComplianceEngine::Detail::StreamFilesystemCollectionWithOperations;

namespace
{
FilesystemCollectionRequest Request()
{
    return FilesystemCollectionRequest("/root", FilesystemRootKind::Directory);
}

void ExpectInvalid(const FilesystemCollectionRequest& request, int code)
{
    const Result<ResolvedFilesystemCollectionRequest> result = ResolveFilesystemCollectionRequest(request);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(code, result.Error().code);
}

class TestTree
{
public:
    TestTree()
        : mOwner(Create())
    {
    }

    std::string Path(const std::string& relative) const
    {
        return mOwner.Path() + "/" + relative;
    }

    void Directory(const std::string& relative) const
    {
        const std::string path = Path(relative);
        if (0 != mkdir(path.c_str(), 0700))
        {
            throw std::runtime_error("mkdir failed: " + path);
        }
    }

    void File(const std::string& relative) const
    {
        const std::string path = Path(relative);
        std::ofstream file(path.c_str());
        file << "content";
        file.close();
        if (!file)
        {
            throw std::runtime_error("write failed: " + path);
        }
    }

    void Link(const std::string& target, const std::string& relative) const
    {
        if (0 != symlink(target.c_str(), Path(relative).c_str()))
        {
            throw std::runtime_error("symlink failed: " + relative);
        }
    }

private:
    static TemporaryDirectory Create()
    {
        Result<TemporaryDirectory> created = TemporaryDirectory::Make("FilesystemCollectionTest");
        if (!created.HasValue())
        {
            throw std::runtime_error(created.Error().message);
        }
        return std::move(created).Value();
    }

    TemporaryDirectory mOwner;
};

std::vector<std::string> Paths(const std::vector<FilesystemCollectionEntry>& entries)
{
    std::vector<std::string> paths;
    for (const FilesystemCollectionEntry& entry : entries)
    {
        paths.push_back(entry.path);
    }
    return paths;
}
} // namespace

TEST(FilesystemCollectionTest, PreservesOmissionUntilResolutionAndAppliesNativeDefaults)
{
    const FilesystemCollectionRequest request = Request();
    EXPECT_FALSE(request.direction.HasValue());
    EXPECT_FALSE(request.maxDepth.HasValue());
    EXPECT_FALSE(request.rootFileLinkAction.HasValue());
    EXPECT_FALSE(request.rootDirectoryLinkAction.HasValue());
    EXPECT_FALSE(request.childFileLinkAction.HasValue());
    EXPECT_FALSE(request.childDirectoryLinkAction.HasValue());
    EXPECT_FALSE(request.scope.HasValue());

    const Result<ResolvedFilesystemCollectionRequest> result = ResolveFilesystemCollectionRequest(request);

    ASSERT_TRUE(result.HasValue());
    const ResolvedFilesystemCollectionRequest& resolved = result.Value();
    EXPECT_EQ(FilesystemDirection::None, resolved.direction);
    EXPECT_EQ(32, resolved.maxDepth);
    EXPECT_EQ(FilesystemLinkAction::Record, resolved.rootFileLinkAction);
    EXPECT_EQ(FilesystemLinkAction::Record, resolved.rootDirectoryLinkAction);
    EXPECT_EQ(FilesystemLinkAction::Record, resolved.childFileLinkAction);
    EXPECT_EQ(FilesystemLinkAction::Record, resolved.childDirectoryLinkAction);
    EXPECT_EQ(FilesystemScope::RootDevice, resolved.scope);
    EXPECT_EQ(128u, resolved.limits.operationalDescent);
    EXPECT_EQ(100000u, resolved.limits.entryWork);
    EXPECT_EQ(4096u, resolved.limits.directoryWidth);
    EXPECT_EQ(4096u, resolved.limits.fullPathBytes);
    EXPECT_EQ(32u * 1024u * 1024u, resolved.limits.retainedPathBytes);
    EXPECT_EQ(16u, resolved.limits.openDirectories);
}

TEST(FilesystemCollectionTest, PreservesExplicitSelectionAndLinkSettings)
{
    FilesystemCollectionRequest request = Request();
    request.direction = FilesystemDirection::Down;
    request.maxDepth = 0;
    request.rootFileLinkAction = FilesystemLinkAction::Follow;
    request.rootDirectoryLinkAction = FilesystemLinkAction::Exclude;
    request.childFileLinkAction = FilesystemLinkAction::Exclude;
    request.childDirectoryLinkAction = FilesystemLinkAction::Follow;
    request.scope = FilesystemScope::All;

    const Result<ResolvedFilesystemCollectionRequest> result = ResolveFilesystemCollectionRequest(request);

    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(FilesystemDirection::Down, result->direction);
    EXPECT_EQ(0, result->maxDepth);
    EXPECT_EQ(FilesystemLinkAction::Follow, result->rootFileLinkAction);
    EXPECT_EQ(FilesystemLinkAction::Exclude, result->rootDirectoryLinkAction);
    EXPECT_EQ(FilesystemLinkAction::Exclude, result->childFileLinkAction);
    EXPECT_EQ(FilesystemLinkAction::Follow, result->childDirectoryLinkAction);
    EXPECT_EQ(FilesystemScope::All, result->scope);
}

TEST(FilesystemCollectionTest, PreservesUnlimitedSelectionDepthWithoutRemovingOperationalLimit)
{
    FilesystemCollectionRequest request = Request();
    request.direction = FilesystemDirection::Down;
    request.maxDepth = -1;

    const Result<ResolvedFilesystemCollectionRequest> result = ResolveFilesystemCollectionRequest(request);

    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(-1, result->maxDepth);
    EXPECT_EQ(128u, result->limits.operationalDescent);
}

TEST(FilesystemCollectionTest, AcceptsLargerPositiveResourceOverridesWithoutClamping)
{
    FilesystemCollectionRequest request = Request();
    request.operationalDescent = 256;
    request.entryWork = 200000;
    request.directoryWidth = 8192;
    request.fullPathBytes = 8192;
    request.retainedPathBytes = 64u * 1024u * 1024u;
    request.openDirectories = 32;

    const Result<ResolvedFilesystemCollectionRequest> result = ResolveFilesystemCollectionRequest(request);

    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(256u, result->limits.operationalDescent);
    EXPECT_EQ(200000u, result->limits.entryWork);
    EXPECT_EQ(8192u, result->limits.directoryWidth);
    EXPECT_EQ(8192u, result->limits.fullPathBytes);
    EXPECT_EQ(64u * 1024u * 1024u, result->limits.retainedPathBytes);
    EXPECT_EQ(32u, result->limits.openDirectories);
}

TEST(FilesystemCollectionTest, AcceptsDefinedScopeForAnExactRoot)
{
    FilesystemCollectionRequest request = Request();
    request.scope = FilesystemScope::Defined;

    const Result<ResolvedFilesystemCollectionRequest> result = ResolveFilesystemCollectionRequest(request);

    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(FilesystemScope::Defined, result->scope);
}

TEST(FilesystemCollectionTest, RejectsEmptyRootAndDepthBelowUnlimitedSentinel)
{
    FilesystemCollectionRequest emptyRoot = Request();
    emptyRoot.rootPath.clear();
    ExpectInvalid(emptyRoot, EINVAL);

    FilesystemCollectionRequest invalidDepth = Request();
    invalidDepth.maxDepth = -2;
    ExpectInvalid(invalidDepth, EINVAL);
}

TEST(FilesystemCollectionTest, RejectsUnsupportedDirectionAndScope)
{
    FilesystemCollectionRequest upward = Request();
    upward.direction = FilesystemDirection::Up;
    ExpectInvalid(upward, ENOTSUP);

    FilesystemCollectionRequest local = Request();
    local.scope = FilesystemScope::Local;
    ExpectInvalid(local, ENOTSUP);
}

TEST(FilesystemCollectionTest, RejectsInvalidEnumValues)
{
    FilesystemCollectionRequest invalidRootKind = Request();
    invalidRootKind.rootKind = static_cast<FilesystemRootKind>(99);
    ExpectInvalid(invalidRootKind, EINVAL);

    FilesystemCollectionRequest invalidDirection = Request();
    invalidDirection.direction = static_cast<FilesystemDirection>(99);
    ExpectInvalid(invalidDirection, EINVAL);

    FilesystemCollectionRequest invalidLink = Request();
    invalidLink.childDirectoryLinkAction = static_cast<FilesystemLinkAction>(99);
    ExpectInvalid(invalidLink, EINVAL);

    FilesystemCollectionRequest invalidScope = Request();
    invalidScope.scope = static_cast<FilesystemScope>(99);
    ExpectInvalid(invalidScope, EINVAL);
}

TEST(FilesystemCollectionTest, RejectsZeroResourceLimits)
{
    FilesystemCollectionRequest request = Request();
    request.operationalDescent = 0;
    ExpectInvalid(request, EINVAL);

    request = Request();
    request.entryWork = 0;
    ExpectInvalid(request, EINVAL);

    request = Request();
    request.directoryWidth = 0;
    ExpectInvalid(request, EINVAL);

    request = Request();
    request.fullPathBytes = 0;
    ExpectInvalid(request, EINVAL);

    request = Request();
    request.retainedPathBytes = 0;
    ExpectInvalid(request, EINVAL);

    request = Request();
    request.openDirectories = 0;
    ExpectInvalid(request, EINVAL);
}

TEST(FilesystemCollectionTest, RejectsNegativeResourceLimits)
{
    FilesystemCollectionRequest request = Request();
    request.operationalDescent = -1;
    ExpectInvalid(request, EINVAL);

    request = Request();
    request.entryWork = -1;
    ExpectInvalid(request, EINVAL);

    request = Request();
    request.directoryWidth = -1;
    ExpectInvalid(request, EINVAL);

    request = Request();
    request.fullPathBytes = -1;
    ExpectInvalid(request, EINVAL);

    request = Request();
    request.retainedPathBytes = -1;
    ExpectInvalid(request, EINVAL);

    request = Request();
    request.openDirectories = -1;
    ExpectInvalid(request, EINVAL);
}

TEST(FilesystemCollectionTest, AppliesExactRootPathBudgetIncludingTerminator)
{
    FilesystemCollectionRequest exact = Request();
    exact.rootPath = "abc";
    exact.fullPathBytes = 4;
    exact.retainedPathBytes = 4;
    EXPECT_TRUE(ResolveFilesystemCollectionRequest(exact).HasValue());

    FilesystemCollectionRequest fullPathExceeded = exact;
    fullPathExceeded.fullPathBytes = 3;
    ExpectInvalid(fullPathExceeded, ENAMETOOLONG);

    FilesystemCollectionRequest retainedPathExceeded = exact;
    retainedPathExceeded.retainedPathBytes = 3;
    ExpectInvalid(retainedPathExceeded, E2BIG);
}

TEST(FilesystemCollectionTest, DistinguishesAbsentRootFromEmptyDirectoryAndFileRoot)
{
    TestTree tree;
    tree.Directory("empty");
    tree.File("file");

    const auto absent = CollectFilesystem(FilesystemCollectionRequest(tree.Path("absent"), FilesystemRootKind::File));
    const auto directory = CollectFilesystem(FilesystemCollectionRequest(tree.Path("empty"), FilesystemRootKind::Directory));
    const auto file = CollectFilesystem(FilesystemCollectionRequest(tree.Path("file"), FilesystemRootKind::File));

    ASSERT_TRUE(absent.HasValue());
    EXPECT_EQ(FilesystemCollectionOutcome::Absent, absent->outcome);
    EXPECT_TRUE(absent->entries.empty());
    ASSERT_TRUE(directory.HasValue());
    EXPECT_EQ(FilesystemCollectionOutcome::Complete, directory->outcome);
    EXPECT_EQ((std::vector<std::string>{tree.Path("empty")}), Paths(directory->entries));
    ASSERT_TRUE(file.HasValue());
    EXPECT_EQ((std::vector<std::string>{tree.Path("file")}), Paths(file->entries));
    EXPECT_TRUE(S_ISREG(file->entries[0].linkMetadata.st_mode));
}

TEST(FilesystemCollectionTest, NoneAndDepthZeroInspectDirectEntriesWithoutDescending)
{
    TestTree tree;
    tree.Directory("root");
    tree.Directory("root/sub");
    tree.File("root/direct");
    tree.File("root/sub/nested");
    FilesystemCollectionRequest request(tree.Path("root"), FilesystemRootKind::Directory);

    const auto none = CollectFilesystem(request);
    request.direction = FilesystemDirection::Down;
    request.maxDepth = 0;
    const auto zero = CollectFilesystem(request);
    request.maxDepth = 1;
    const auto one = CollectFilesystem(request);

    ASSERT_TRUE(none.HasValue());
    ASSERT_TRUE(zero.HasValue());
    ASSERT_TRUE(one.HasValue());
    EXPECT_EQ(3u, none->entries.size());
    EXPECT_EQ(3u, zero->entries.size());
    EXPECT_EQ(4u, one->entries.size());
    const auto zeroPaths = Paths(zero->entries);
    EXPECT_EQ(0u, std::count(zeroPaths.begin(), zeroPaths.end(), tree.Path("root/sub/nested")));
    const auto visited = Paths(one->entries);
    EXPECT_NE(visited.end(), std::find(visited.begin(), visited.end(), tree.Path("root/sub/nested")));
}

TEST(FilesystemCollectionTest, RootKindMismatchIsAnError)
{
    TestTree tree;
    tree.Directory("root");
    tree.File("file");
    const auto expectedFile = CollectFilesystem(FilesystemCollectionRequest(tree.Path("root"), FilesystemRootKind::File));
    const auto expectedDirectory = CollectFilesystem(FilesystemCollectionRequest(tree.Path("file"), FilesystemRootKind::Directory));
    ASSERT_FALSE(expectedFile.HasValue());
    ASSERT_FALSE(expectedDirectory.HasValue());
    EXPECT_EQ(EISDIR, expectedFile.Error().code);
    EXPECT_EQ(ENOTDIR, expectedDirectory.Error().code);
}

TEST(FilesystemCollectionTest, DisappearingRequiredChildIsAnErrorNotAbsentRoot)
{
    TestTree tree;
    tree.Directory("root");
    tree.Directory("root/child");
    FilesystemCollectionRequest request(tree.Path("root"), FilesystemRootKind::Directory);
    request.direction = FilesystemDirection::Down;
    const auto result = StreamFilesystemCollection(request, [&tree](const FilesystemCollectionEntry& entry) {
        if (entry.path == tree.Path("root/child"))
        {
            if (0 != rmdir(entry.path.c_str()))
            {
                return Result<FilesystemVisitAction>(ComplianceEngine::Error("rmdir failed", errno));
            }
        }
        return Result<FilesystemVisitAction>(FilesystemVisitAction::Continue);
    });
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(ENOENT, result.Error().code);
    EXPECT_NE(std::string::npos, result.Error().message.find(tree.Path("root/child")));
}

TEST(FilesystemCollectionTest, RecordsExcludesAndFollowsDirectoryLinksIndependently)
{
    TestTree tree;
    tree.Directory("root");
    tree.Directory("target");
    tree.File("target/item");
    tree.Link(tree.Path("target"), "root/alias");
    FilesystemCollectionRequest request(tree.Path("root"), FilesystemRootKind::Directory);
    request.direction = FilesystemDirection::Down;
    const auto recorded = CollectFilesystem(request);

    request.childDirectoryLinkAction = FilesystemLinkAction::Exclude;
    request.childFileLinkAction = FilesystemLinkAction::Exclude;
    const auto excluded = CollectFilesystem(request);

    request.childDirectoryLinkAction = FilesystemLinkAction::Follow;
    const auto followed = CollectFilesystem(request);

    ASSERT_TRUE(recorded.HasValue());
    ASSERT_EQ(2u, recorded->entries.size());
    EXPECT_TRUE(S_ISLNK(recorded->entries[1].linkMetadata.st_mode));
    ASSERT_TRUE(excluded.HasValue());
    EXPECT_EQ(1u, excluded->entries.size());
    ASSERT_EQ(1u, excluded->exclusions.size());
    EXPECT_EQ(tree.Path("root/alias"), excluded->exclusions[0].path);
    ASSERT_TRUE(followed.HasValue());
    const auto paths = Paths(followed->entries);
    EXPECT_NE(paths.end(), std::find(paths.begin(), paths.end(), tree.Path("root/alias/item")));
    EXPECT_TRUE(followed->entries[1].targetMetadata.HasValue());
}

TEST(FilesystemCollectionTest, RejectsFollowedCyclesButPermitsDistinctAliases)
{
    TestTree tree;
    tree.Directory("root");
    tree.Directory("root/target");
    tree.File("root/target/item");
    tree.Link(tree.Path("root"), "root/target/loop");
    tree.Link(tree.Path("root/target"), "root/alias");
    FilesystemCollectionRequest request(tree.Path("root"), FilesystemRootKind::Directory);
    request.direction = FilesystemDirection::Down;
    request.childDirectoryLinkAction = FilesystemLinkAction::Follow;
    const auto cycle = CollectFilesystem(request);
    ASSERT_FALSE(cycle.HasValue());
    EXPECT_EQ(ELOOP, cycle.Error().code);

    ASSERT_EQ(0, unlink(tree.Path("root/target/loop").c_str()));
    const auto aliases = CollectFilesystem(request);
    ASSERT_TRUE(aliases.HasValue());
    const auto paths = Paths(aliases->entries);
    EXPECT_NE(paths.end(), std::find(paths.begin(), paths.end(), tree.Path("root/alias/item")));
    EXPECT_NE(paths.end(), std::find(paths.begin(), paths.end(), tree.Path("root/target/item")));
}

TEST(FilesystemCollectionTest, StreamingStopAndCallbackErrorAreDistinctFromCompleteEvidence)
{
    TestTree tree;
    tree.Directory("root");
    tree.File("root/first");
    tree.File("root/second");
    FilesystemCollectionRequest request(tree.Path("root"), FilesystemRootKind::Directory);
    std::vector<std::string> visited;
    const auto stopped = StreamFilesystemCollection(request, [&visited](const FilesystemCollectionEntry& entry) {
        visited.push_back(entry.path);
        return Result<FilesystemVisitAction>(FilesystemVisitAction::Stop);
    });
    ASSERT_TRUE(stopped.HasValue());
    EXPECT_EQ(FilesystemCollectionOutcome::Stopped, stopped->outcome);
    EXPECT_EQ(1u, visited.size());
    EXPECT_TRUE(stopped->entries.empty());

    const auto failed = StreamFilesystemCollection(request,
        [](const FilesystemCollectionEntry&) { return Result<FilesystemVisitAction>(ComplianceEngine::Error("caller failed", EIO)); });
    ASSERT_FALSE(failed.HasValue());
    EXPECT_EQ(EIO, failed.Error().code);
    EXPECT_EQ("caller failed", failed.Error().message);
    const ComplianceEngine::FilesystemCollectionVisitor empty;
    EXPECT_EQ(EINVAL, StreamFilesystemCollection(request, empty).Error().code);
}

TEST(FilesystemCollectionTest, EntryWorkAndDirectoryWidthExactBoundaries)
{
    TestTree tree;
    tree.Directory("root");
    tree.File("root/item");
    FilesystemCollectionRequest request(tree.Path("root"), FilesystemRootKind::Directory);
    request.entryWork = 1;
    request.directoryWidth = 1;
    EXPECT_TRUE(CollectFilesystem(request).HasValue());
    tree.File("root/other");
    EXPECT_EQ(E2BIG, CollectFilesystem(request).Error().code);
    request.entryWork = 2;
    EXPECT_EQ(E2BIG, CollectFilesystem(request).Error().code);
    request.directoryWidth = 2;
    EXPECT_TRUE(CollectFilesystem(request).HasValue());
}

TEST(FilesystemCollectionTest, OperationalLimitErrorsOnlyOnRequiredDescent)
{
    TestTree tree;
    tree.Directory("root");
    tree.Directory("root/one");
    tree.Directory("root/one/two");
    FilesystemCollectionRequest request(tree.Path("root"), FilesystemRootKind::Directory);
    request.direction = FilesystemDirection::Down;
    request.operationalDescent = 1;
    request.maxDepth = 1;
    EXPECT_TRUE(CollectFilesystem(request).HasValue());
    request.maxDepth = 2;
    const auto exceeded = CollectFilesystem(request);
    ASSERT_FALSE(exceeded.HasValue());
    EXPECT_EQ(E2BIG, exceeded.Error().code);
}

TEST(FilesystemCollectionTest, DescriptorContinuationVisitsEachEntryOnce)
{
    TestTree tree;
    tree.Directory("root");
    std::string parent = "root";
    for (int depth = 1; depth <= 17; ++depth)
    {
        parent += "/d";
        tree.Directory(parent);
    }
    tree.File(parent + "/leaf");
    FilesystemCollectionRequest request(tree.Path("root"), FilesystemRootKind::Directory);
    request.direction = FilesystemDirection::Down;
    std::vector<std::string> visited;
    const auto result = StreamFilesystemCollection(request, [&visited](const FilesystemCollectionEntry& entry) {
        visited.push_back(entry.path);
        return Result<FilesystemVisitAction>(FilesystemVisitAction::Continue);
    });
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(FilesystemCollectionOutcome::Complete, result->outcome);
    EXPECT_EQ(19u, visited.size());
    EXPECT_EQ(1u, std::count(visited.begin(), visited.end(), tree.Path(parent + "/leaf")));
}

TEST(FilesystemCollectionTest, PrefixMutationDuringSuspensionFailsClosed)
{
    TestTree tree;
    tree.Directory("root");
    tree.Directory("root/d");
    tree.File("root/d/leaf");
    FilesystemCollectionRequest request(tree.Path("root"), FilesystemRootKind::Directory);
    request.direction = FilesystemDirection::Down;
    request.openDirectories = 1;
    const auto result = StreamFilesystemCollection(request, [&tree](const FilesystemCollectionEntry& entry) {
        if (entry.path == tree.Path("root/d/leaf"))
        {
            if ((0 != rename(tree.Path("root").c_str(), tree.Path("old").c_str())) || (0 != mkdir(tree.Path("root").c_str(), 0700)))
            {
                return Result<FilesystemVisitAction>(ComplianceEngine::Error("replace failed", errno));
            }
        }
        return Result<FilesystemVisitAction>(FilesystemVisitAction::Continue);
    });
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(ESTALE, result.Error().code);
}

TEST(FilesystemCollectionTest, ChangedConsumedPrefixDuringReplayFailsClosed)
{
    TestTree tree;
    tree.Directory("root");
    tree.Directory("root/d");
    tree.File("root/d/leaf");
    FilesystemCollectionRequest request(tree.Path("root"), FilesystemRootKind::Directory);
    request.direction = FilesystemDirection::Down;
    request.openDirectories = 1;
    const auto result = StreamFilesystemCollection(request, [&tree](const FilesystemCollectionEntry& entry) {
        if (entry.path == tree.Path("root/d/leaf"))
        {
            if (0 != rename(tree.Path("root/d").c_str(), tree.Path("root/changed").c_str()))
            {
                return Result<FilesystemVisitAction>(ComplianceEngine::Error("rename failed", errno));
            }
        }
        return Result<FilesystemVisitAction>(FilesystemVisitAction::Continue);
    });
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(ESTALE, result.Error().code);
}

TEST(FilesystemCollectionTest, StoppingBeforeReplayDoesNotInspectSuspendedAncestors)
{
    TestTree tree;
    tree.Directory("root");
    tree.Directory("root/d");
    tree.File("root/d/leaf");
    FilesystemCollectionRequest request(tree.Path("root"), FilesystemRootKind::Directory);
    request.direction = FilesystemDirection::Down;
    request.openDirectories = 1;
    const auto stopped = StreamFilesystemCollection(request, [&tree](const FilesystemCollectionEntry& entry) {
        if (entry.path == tree.Path("root/d/leaf"))
        {
            if ((0 != rename(tree.Path("root").c_str(), tree.Path("old").c_str())) || (0 != mkdir(tree.Path("root").c_str(), 0700)))
            {
                return Result<FilesystemVisitAction>(ComplianceEngine::Error("replace failed", errno));
            }
            return Result<FilesystemVisitAction>(FilesystemVisitAction::Stop);
        }
        return Result<FilesystemVisitAction>(FilesystemVisitAction::Continue);
    });
    ASSERT_TRUE(stopped.HasValue());
    EXPECT_EQ(FilesystemCollectionOutcome::Stopped, stopped->outcome);
}

TEST(FilesystemCollectionTest, ReplayConsumesEntryWorkWithoutRepeatingCallbacks)
{
    TestTree tree;
    tree.Directory("root");
    tree.Directory("root/d");
    tree.File("root/d/leaf");
    FilesystemCollectionRequest request(tree.Path("root"), FilesystemRootKind::Directory);
    request.direction = FilesystemDirection::Down;
    request.openDirectories = 1;
    request.entryWork = 2;
    std::vector<std::string> visited;
    const auto result = StreamFilesystemCollection(request, [&visited](const FilesystemCollectionEntry& entry) {
        visited.push_back(entry.path);
        return Result<FilesystemVisitAction>(FilesystemVisitAction::Continue);
    });
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(E2BIG, result.Error().code);
    EXPECT_EQ(1u, std::count(visited.begin(), visited.end(), tree.Path("root/d/leaf")));
    request.entryWork = 3;
    EXPECT_TRUE(CollectFilesystem(request).HasValue());
}

TEST(FilesystemCollectionTest, RootLinkPoliciesDistinguishRecordFollowAndExclude)
{
    TestTree tree;
    tree.Directory("target");
    tree.File("target/item");
    tree.Link(tree.Path("target"), "alias");
    FilesystemCollectionRequest request(tree.Path("alias"), FilesystemRootKind::Directory);
    const auto recorded = CollectFilesystem(request);
    ASSERT_TRUE(recorded.HasValue());
    ASSERT_EQ(1u, recorded->entries.size());
    EXPECT_TRUE(S_ISLNK(recorded->entries[0].linkMetadata.st_mode));

    request.rootDirectoryLinkAction = FilesystemLinkAction::Follow;
    request.rootFileLinkAction = FilesystemLinkAction::Follow;
    const auto followed = CollectFilesystem(request);
    ASSERT_TRUE(followed.HasValue());
    EXPECT_EQ(2u, followed->entries.size());
    EXPECT_TRUE(followed->entries[0].targetMetadata.HasValue());

    request.rootDirectoryLinkAction = FilesystemLinkAction::Exclude;
    request.rootFileLinkAction = FilesystemLinkAction::Exclude;
    const auto excluded = CollectFilesystem(request);
    ASSERT_TRUE(excluded.HasValue());
    EXPECT_TRUE(excluded->entries.empty());
    ASSERT_EQ(1u, excluded->exclusions.size());
}

TEST(FilesystemCollectionTest, FollowingDanglingLinkFailsRatherThanReturningAbsentRoot)
{
    TestTree tree;
    tree.Link(tree.Path("missing"), "dangling");
    FilesystemCollectionRequest request(tree.Path("dangling"), FilesystemRootKind::File);
    request.rootFileLinkAction = FilesystemLinkAction::Follow;
    request.rootDirectoryLinkAction = FilesystemLinkAction::Follow;
    const auto result = CollectFilesystem(request);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(ENOENT, result.Error().code);
}

TEST(FilesystemCollectionTest, FullPathAndRetainedPathBudgetsRejectRequiredEntries)
{
    TestTree tree;
    tree.Directory("root");
    tree.File("root/item");
    FilesystemCollectionRequest request(tree.Path("root"), FilesystemRootKind::Directory);
    request.fullPathBytes = static_cast<long long>(tree.Path("root/item").size());
    const auto fullPathExceeded = CollectFilesystem(request);
    ASSERT_FALSE(fullPathExceeded.HasValue());
    EXPECT_EQ(ENAMETOOLONG, fullPathExceeded.Error().code);

    request.fullPathBytes = static_cast<long long>(tree.Path("root/item").size() + 1);
    request.retainedPathBytes = static_cast<long long>(tree.Path("root").size() + 1);
    const auto retainedExceeded = CollectFilesystem(request);
    ASSERT_FALSE(retainedExceeded.HasValue());
    EXPECT_EQ(E2BIG, retainedExceeded.Error().code);
}

TEST(FilesystemCollectionTest, ExactRetainedCopiesForFileRootSucceedAndOneByteLessFails)
{
    TestTree tree;
    tree.File("file");
    FilesystemCollectionRequest request(tree.Path("file"), FilesystemRootKind::File);
    const long long twoCopies = static_cast<long long>((request.rootPath.size() + 1) * 2);
    request.retainedPathBytes = twoCopies;
    EXPECT_TRUE(CollectFilesystem(request).HasValue());
    request.retainedPathBytes = twoCopies - 1;
    const auto exceeded = CollectFilesystem(request);
    ASSERT_FALSE(exceeded.HasValue());
    EXPECT_EQ(E2BIG, exceeded.Error().code);
}

TEST(FilesystemCollectionTest, DefaultDepthThirtyTwoStopsSelectionButContinuesDescriptors)
{
    TestTree tree;
    tree.Directory("root");
    std::string parent = "root";
    for (int depth = 1; depth <= 33; ++depth)
    {
        parent += "/d";
        tree.Directory(parent);
        if (32 == depth)
        {
            tree.File(parent + "/selected");
        }
    }
    tree.File(parent + "/not-selected");
    FilesystemCollectionRequest request(tree.Path("root"), FilesystemRootKind::Directory);
    request.direction = FilesystemDirection::Down;
    const auto result = CollectFilesystem(request);
    ASSERT_TRUE(result.HasValue());
    const auto paths = Paths(result->entries);
    EXPECT_NE(paths.end(), std::find_if(paths.begin(), paths.end(), [](const std::string& path) { return std::string::npos != path.find("/selected"); }));
    EXPECT_EQ(paths.end(),
        std::find_if(paths.begin(), paths.end(), [](const std::string& path) { return std::string::npos != path.find("/not-selected"); }));
}

TEST(FilesystemCollectionTest, RequiredDirectoryReadFailureDoesNotProducePartialCollection)
{
    TestTree tree;
    tree.Directory("root");
    tree.File("root/item");
    FilesystemCollectionOperations operations;
    operations.readDirectory = [](DIR*) -> struct dirent*
    {
        errno = EIO;
        return nullptr;
    };
    const auto result = CollectFilesystemWithOperations(FilesystemCollectionRequest(tree.Path("root"), FilesystemRootKind::Directory), operations);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EIO, result.Error().code);
    EXPECT_NE(std::string::npos, result.Error().message.find(tree.Path("root")));
}

TEST(FilesystemCollectionTest, RequiredStatFailurePropagatesItsOriginalCode)
{
    TestTree tree;
    tree.Directory("root");
    FilesystemCollectionOperations operations;
    operations.statDescriptor = [](int, struct stat*) {
        errno = EACCES;
        return -1;
    };
    const auto result = CollectFilesystemWithOperations(FilesystemCollectionRequest(tree.Path("root"), FilesystemRootKind::Directory), operations);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EACCES, result.Error().code);
}

TEST(FilesystemCollectionTest, StandaloneCloseFailureErrorsAndSecondaryClosePreservesCallbackError)
{
    TestTree tree;
    tree.Directory("root");
    tree.File("root/child");
    FilesystemCollectionOperations operations;
    operations.closeDirectory = [](DIR* stream) {
        const int status = closedir(stream);
        if (0 != status)
        {
            return status;
        }
        errno = EIO;
        return -1;
    };
    const FilesystemCollectionRequest request(tree.Path("root"), FilesystemRootKind::Directory);
    const auto standalone = CollectFilesystemWithOperations(request, operations);
    ASSERT_FALSE(standalone.HasValue());
    EXPECT_EQ(EIO, standalone.Error().code);

    const auto secondary = StreamFilesystemCollectionWithOperations(
        request,
        [&tree](const FilesystemCollectionEntry& entry) {
            if (entry.path == tree.Path("root/child"))
            {
                return Result<FilesystemVisitAction>(ComplianceEngine::Error("original callback", EACCES));
            }
            return Result<FilesystemVisitAction>(FilesystemVisitAction::Continue);
        },
        operations);
    ASSERT_FALSE(secondary.HasValue());
    EXPECT_EQ(EACCES, secondary.Error().code);
    EXPECT_EQ("original callback", secondary.Error().message);
}

TEST(FilesystemCollectionTest, DescriptorHandoffCloseFailureStopsBeforeChildOpen)
{
    TestTree tree;
    tree.Directory("root");
    tree.Directory("root/child");
    FilesystemCollectionRequest request(tree.Path("root"), FilesystemRootKind::Directory);
    request.direction = FilesystemDirection::Down;
    request.openDirectories = 1;
    FilesystemCollectionOperations operations;
    operations.closeDirectory = [](DIR* stream) {
        const int status = closedir(stream);
        if (0 != status)
        {
            return status;
        }
        errno = EIO;
        return -1;
    };
    const auto result = CollectFilesystemWithOperations(request, operations);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EIO, result.Error().code);
}

TEST(FilesystemCollectionTest, RootDeviceExcludesInjectedCrossDeviceEntryButAllSelectsIt)
{
    TestTree tree;
    tree.Directory("root");
    tree.File("root/other-device");
    FilesystemCollectionOperations operations;
    operations.lstatPath = [&tree](const char* path, struct stat* metadata) {
        const int status = lstat(path, metadata);
        if ((0 == status) && (tree.Path("root/other-device") == path))
        {
            ++metadata->st_dev;
        }
        return status;
    };
    FilesystemCollectionRequest request(tree.Path("root"), FilesystemRootKind::Directory);
    const auto bounded = CollectFilesystemWithOperations(request, operations);
    ASSERT_TRUE(bounded.HasValue());
    EXPECT_EQ(1u, bounded->entries.size());
    ASSERT_EQ(1u, bounded->exclusions.size());
    EXPECT_EQ(tree.Path("root/other-device"), bounded->exclusions[0].path);

    request.scope = FilesystemScope::Defined;
    const auto defined = CollectFilesystemWithOperations(request, operations);
    ASSERT_TRUE(defined.HasValue());
    EXPECT_EQ(1u, defined->entries.size());
    EXPECT_EQ(1u, defined->exclusions.size());

    request.scope = FilesystemScope::All;
    const auto all = CollectFilesystemWithOperations(request, operations);
    ASSERT_TRUE(all.HasValue());
    EXPECT_EQ(2u, all->entries.size());
    EXPECT_TRUE(all->exclusions.empty());
}
