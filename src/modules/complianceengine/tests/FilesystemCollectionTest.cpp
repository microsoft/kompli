// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "MockContext.h"
#include "TemporaryDirectory.h"

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <filesystem/FilesystemCollection.hpp>
#include <fstream>
#include <gtest/gtest.h>
#include <iterator>
#include <map>
#include <set>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <type_traits>
#include <unistd.h>
#include <utility>
#include <vector>

using ComplianceEngine::As;
using ComplianceEngine::Result;
using ComplianceEngine::TemporaryDirectory;
using ComplianceEngine::Filesystem::CollectFilesystem;
using ComplianceEngine::Filesystem::CollectionContinuation;
using ComplianceEngine::Filesystem::CollectionRootLimits;
using ComplianceEngine::Filesystem::CollectionRootPolicy;
using ComplianceEngine::Filesystem::FilesystemCollectionEntry;
using ComplianceEngine::Filesystem::FilesystemCollectionLimits;
using ComplianceEngine::Filesystem::FilesystemCollectionRequest;
using ComplianceEngine::Filesystem::FilesystemDepthAction;
using ComplianceEngine::Filesystem::FilesystemDirection;
using ComplianceEngine::Filesystem::FilesystemRootKind;
using ComplianceEngine::Filesystem::FilesystemScope;
using ComplianceEngine::Filesystem::FilesystemVisitAction;
using ComplianceEngine::Filesystem::FilesystemYieldType;
using ComplianceEngine::Filesystem::Path;
using ComplianceEngine::Filesystem::ResolvedFilesystemCollectionRequest;
using ComplianceEngine::Filesystem::ResolveFilesystemCollectionRequest;
using ComplianceEngine::Filesystem::StreamFilesystemCollection;
using ComplianceEngine::Filesystem::SymlinkPolicy;
using ComplianceEngine::Filesystem::UnsupportedTypeDisposition;
using ComplianceEngine::Filesystem::FTW::Files;
namespace
{
static_assert(std::is_same<decltype(std::declval<const FilesystemCollectionEntry&>().LiveComponent()), ComplianceEngine::Optional<Path::Component>>::value,
    "LiveComponent must return an owning optional value");
static_assert(std::is_same<decltype(std::declval<const Path::Step&>().Metadata()), ComplianceEngine::Filesystem::Metadata>::value,
    "Step facts must be copied, not borrowed");

Result<ComplianceEngine::Filesystem::FilesystemCollectionResult> CollectFilesystem(const FilesystemCollectionRequest& request)
{
    ::testing::StrictMock<MockContext> context;
    // Every caller of this convenience overload only checks the returned
    // Result, never a mock expectation (the context isn't visible to it), so
    // a blanket incidental-access catch-all here is safe for all of them.
    context.AllowIncidentalNativeAccess();
    return ComplianceEngine::Filesystem::CollectFilesystem(request, context);
}

Result<ComplianceEngine::Filesystem::FilesystemCollectionResult> StreamFilesystemCollection(const FilesystemCollectionRequest& request,
    const ComplianceEngine::Filesystem::FilesystemCollectionVisitor& visitor)
{
    ::testing::StrictMock<MockContext> context;
    // See CollectFilesystem() above: no caller can add its own expectation on
    // this hidden context.
    context.AllowIncidentalNativeAccess();
    return ComplianceEngine::Filesystem::StreamFilesystemCollection(request, visitor, context);
}
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

TEST(FilesystemCollectionTest, UnifiedRangeRetainsLiveLeafAndSupportsRootDeviceScope)
{
    ::testing::StrictMock<MockContext> context;
    // No EXPECT_CALL in this test constrains any native seam.
    context.AllowIncidentalNativeAccess();
    TestTree tree;
    tree.Directory("root");
    tree.File("root/.settings");
    tree.Link("root", "administrative");
    FilesystemCollectionRequest request(tree.Path("administrative"), FilesystemRootKind::Directory);
    request.direction = FilesystemDirection::Down;
    request.depthAction = FilesystemDepthAction::Error;
    request.scope = FilesystemScope::All;
    request.yieldType = FilesystemYieldType::RegularFiles;
    request.rootDirectoryLinkAction = SymlinkPolicy::Follow;
    request.rootFileLinkAction = SymlinkPolicy::Follow;
    auto followed = Files(request, context);
    ASSERT_TRUE(followed.HasValue()) << followed.Error().message;
    ASSERT_TRUE(followed.Value().RootExists());
    auto entry = followed->begin();
    ASSERT_NE(entry, followed->end());
    ASSERT_TRUE(entry->HasValue()) << entry->Error().message;
    EXPECT_EQ(tree.Path("administrative") + "/.settings", entry->Value().path);
    ASSERT_TRUE(entry->Value().LiveComponent().HasValue());
    EXPECT_EQ(ComplianceEngine::Filesystem::Type::RegularFile, entry->Value().LiveComponent().Value().Metadata().FileType());
    followed.Value().Stop();

    request.rootDirectoryLinkAction = SymlinkPolicy::DoNotFollow;
    request.rootFileLinkAction = SymlinkPolicy::DoNotFollow;
    auto rejected = Files(request, context);
    ASSERT_TRUE(rejected.HasValue());
    EXPECT_TRUE(rejected.Value().RootExists());
    rejected.Value().Stop();

    request.scope = FilesystemScope::RootDevice;
    request.rootDirectoryLinkAction = SymlinkPolicy::Follow;
    request.rootFileLinkAction = SymlinkPolicy::Follow;
    auto scoped = Files(request, context);
    ASSERT_TRUE(scoped.HasValue()) << scoped.Error().message;
    scoped.Value().Stop();
}

TEST(FilesystemCollectionTest, CoreNoRootReplayAfterAcceptedDirectoryRenameAndReplacement)
{
    ::testing::StrictMock<MockContext> context;
    // The initial root acquisition below performs real, incidental native
    // access (including procfs-self OpenNativeAt calls) before the test's
    // own OpenNativeAt expectations are declared further down; this
    // catch-all covers that, and those later, narrower expectations
    // (declared after, so newest) still win once they're set (see
    // MockContext.h helper comment).
    context.AllowIncidentalNativeAccess();
    TestTree tree;
    tree.Directory("root");
    tree.File("root/original");
    FilesystemCollectionRequest request(tree.Path("root"), FilesystemRootKind::Directory);
    request.direction = FilesystemDirection::Down;
    request.scope = FilesystemScope::All;
    request.yieldType = FilesystemYieldType::RegularFiles;
    auto resolved = ResolveFilesystemCollectionRequest(request);
    ASSERT_TRUE(resolved.HasValue()) << resolved.Error().message;
    auto root = Path::Make(context, request.rootPath, CollectionRootPolicy(resolved.Value()), CollectionRootLimits(resolved.Value()));
    ASSERT_TRUE(root.HasValue()) << root.Error().message;
    ASSERT_TRUE(root.Value().Is<Path>());
    Path accepted = As<Path>(std::move(root).Value());
    ASSERT_TRUE(accepted.Freeze().HasValue());
    const ino_t acceptedInode = accepted.Leaf().Metadata().Stat().st_ino;
    ASSERT_EQ(0, ::rename(tree.Path("root").c_str(), tree.Path("moved").c_str()));
    tree.Directory("root");
    tree.File("root/replacement");
    EXPECT_CALL(context, OpenNativeAt(testing::_, testing::_, testing::_)).Times(testing::AnyNumber()).WillRepeatedly([&](int directory, const char* name, int flags) {
        return context.RealOpenNativeAt(directory, name, flags);
    });
    EXPECT_CALL(context, OpenNativeAt(testing::_, testing::StrEq("root"), testing::_)).Times(0);
    auto files = Files(std::move(accepted), request.rootPath, CollectionContinuation(resolved.Value()));
    ASSERT_TRUE(files.HasValue()) << files.Error().message;
    std::vector<std::string> seen;
    for (const auto& entry : files.Value())
    {
        ASSERT_TRUE(entry.HasValue()) << entry.Error().message;
        ASSERT_TRUE(entry.Value().LiveComponent().HasValue());
        seen.push_back(entry.Value().path);
        struct stat original = {};
        ASSERT_EQ(0, ::stat(tree.Path("moved/original").c_str(), &original));
        EXPECT_EQ(original.st_ino, entry.Value().LiveComponent().Value().Metadata().Stat().st_ino);
    }
    EXPECT_EQ((std::vector<std::string>{tree.Path("root/original")}), seen);
    EXPECT_NE(0, acceptedInode);
    files->Stop();
}

TEST(FilesystemCollectionTest, MovedRootReportsOriginalSpellingWithoutUsingItAsAuthority)
{
    ::testing::StrictMock<MockContext> context;
    // No EXPECT_CALL in this test constrains any native seam.
    context.AllowIncidentalNativeAccess();
    TestTree tree;
    tree.Directory("actual");
    tree.File("actual/file");
    tree.Link("actual", "alias");
    FilesystemCollectionRequest request(tree.Path("alias") + "///", FilesystemRootKind::Directory);
    request.direction = FilesystemDirection::Down;
    request.scope = FilesystemScope::All;
    request.yieldType = FilesystemYieldType::RegularFiles;
    request.rootDirectoryLinkAction = SymlinkPolicy::Follow;
    request.rootFileLinkAction = SymlinkPolicy::Follow;
    auto resolved = ResolveFilesystemCollectionRequest(request);
    ASSERT_TRUE(resolved.HasValue()) << resolved.Error().message;
    auto acquired = Path::Make(context, request.rootPath, CollectionRootPolicy(resolved.Value()), CollectionRootLimits(resolved.Value()));
    ASSERT_TRUE(acquired.HasValue()) << acquired.Error().message;
    ASSERT_TRUE(acquired.Value().Is<Path>());
    Path accepted = As<Path>(std::move(acquired).Value());
    ASSERT_TRUE(accepted.Freeze().HasValue());
    EXPECT_EQ(tree.Path("actual"), accepted.ToString());
    auto files = Files(std::move(accepted), request.rootPath, CollectionContinuation(resolved.Value()));
    ASSERT_TRUE(files.HasValue()) << files.Error().message;
    auto entry = files->begin();
    ASSERT_NE(entry, files->end());
    ASSERT_TRUE(entry->HasValue()) << entry->Error().message;
    EXPECT_EQ(request.rootPath + "/file", entry->Value().path);
    ASSERT_TRUE(entry->Value().LiveComponent().HasValue());
    files->Stop();
}

TEST(FilesystemCollectionTest, InverseRestoresPhysicalParentAfterSiblingLink)
{
    TestTree tree;
    tree.Directory("root");
    tree.Directory("root/left");
    tree.Directory("root/right");
    tree.File("root/left/own");
    tree.File("root/right/target");
    tree.Link("../right", "root/left/alias");
    FilesystemCollectionRequest request(tree.Path("root"), FilesystemRootKind::Directory);
    request.direction = FilesystemDirection::Down;
    request.scope = FilesystemScope::All;
    request.childDirectoryLinkAction = SymlinkPolicy::Follow;
    request.yieldType = FilesystemYieldType::RegularFiles;
    auto result = CollectFilesystem(request);
    ASSERT_TRUE(result.HasValue()) << result.Error().message;
    const auto paths = Paths(result->entries);
    EXPECT_NE(paths.end(), std::find(paths.begin(), paths.end(), tree.Path("root/left/alias/target")));
    EXPECT_NE(paths.end(), std::find(paths.begin(), paths.end(), tree.Path("root/left/own")));
    EXPECT_NE(paths.end(), std::find(paths.begin(), paths.end(), tree.Path("root/right/target")));
}

TEST(FilesystemCollectionTest, NestedInverseRestoresOriginalPhysicalBindingsAfterRootReplacement)
{
    ::testing::StrictMock<MockContext> context;
    // No EXPECT_CALL in this test constrains any native seam.
    context.AllowIncidentalNativeAccess();
    TestTree tree;
    tree.Directory("actual");
    tree.Directory("actual/a");
    tree.Directory("actual/a/deep");
    tree.Directory("actual/a/sibling");
    tree.File("actual/a/deep/inside");
    tree.File("actual/a/sibling/target");
    tree.File("actual/a/own");
    tree.Link("../sibling", "actual/a/deep/relative");
    // The lookup binding remains inside the frozen linked-root barrier,
    // even after the effective spelling is rebound to a different tree.
    tree.Link(tree.Path("alias/a/sibling"), "actual/a/deep/absolute");
    tree.Link("actual", "alias");
    FilesystemCollectionRequest request(tree.Path("alias"), FilesystemRootKind::Directory);
    request.direction = FilesystemDirection::Down;
    request.scope = FilesystemScope::All;
    request.rootDirectoryLinkAction = SymlinkPolicy::Follow;
    request.childDirectoryLinkAction = SymlinkPolicy::Follow;
    request.yieldType = FilesystemYieldType::RegularFiles;
    auto resolved = ResolveFilesystemCollectionRequest(request);
    ASSERT_TRUE(resolved.HasValue()) << resolved.Error().message;
    auto root = Path::Make(context, request.rootPath, CollectionRootPolicy(resolved.Value()), CollectionRootLimits(resolved.Value()));
    ASSERT_TRUE(root.HasValue()) << root.Error().message;
    ASSERT_TRUE(root.Value().Is<Path>());
    Path accepted = As<Path>(std::move(root).Value());
    EXPECT_EQ(tree.Path("alias"), accepted.LookupName());
    EXPECT_EQ(tree.Path("actual"), accepted.ToString());
    ASSERT_EQ(0, ::rename(tree.Path("actual").c_str(), tree.Path("old").c_str()));
    tree.Directory("actual");
    tree.Directory("actual/a");
    tree.Directory("actual/a/sibling");
    tree.File("actual/a/sibling/replacement");
    struct stat rootInfo = {}, aInfo = {}, deepInfo = {}, siblingInfo = {};
    struct stat originalTarget = {}, originalInside = {}, originalOwn = {}, replacementTarget = {};
    ASSERT_EQ(0, ::stat(tree.Path("old").c_str(), &rootInfo));
    ASSERT_EQ(0, ::stat(tree.Path("old/a").c_str(), &aInfo));
    ASSERT_EQ(0, ::stat(tree.Path("old/a/deep").c_str(), &deepInfo));
    ASSERT_EQ(0, ::stat(tree.Path("old/a/sibling").c_str(), &siblingInfo));
    ASSERT_EQ(0, ::stat(tree.Path("old/a/sibling/target").c_str(), &originalTarget));
    ASSERT_EQ(0, ::stat(tree.Path("old/a/deep/inside").c_str(), &originalInside));
    ASSERT_EQ(0, ::stat(tree.Path("old/a/own").c_str(), &originalOwn));
    ASSERT_EQ(0, ::stat(tree.Path("actual/a/sibling/replacement").c_str(), &replacementTarget));
    ASSERT_NE(originalTarget.st_ino, replacementTarget.st_ino);

    struct OrderedCursor
    {
        ino_t inode;
        const char* const* names;
        std::size_t count;
        std::size_t position;
    };
    const char* rootNames[] = {"a"};
    const char* aNames[] = {"deep", "sibling", "own"};
    const char* deepNames[] = {"relative", "absolute", "inside"};
    const char* siblingNames[] = {"target"};
    OrderedCursor cursors[] = {
        {rootInfo.st_ino, rootNames, 1, 0}, {aInfo.st_ino, aNames, 3, 0}, {deepInfo.st_ino, deepNames, 3, 0}, {siblingInfo.st_ino, siblingNames, 1, 0}};
    struct dirent scripted = {};
    // Pin-based traversal, but deterministic directory order: both nested
    // inverse links must be resolved before the later physical sibling.
    ON_CALL(context, ReadDirectory(testing::_)).WillByDefault([&](DIR * stream) noexcept -> struct dirent* {
        struct stat held = {};
        if (0 != ::fstat(::dirfd(stream), &held))
            return nullptr;
        for (auto& cursor : cursors)
        {
            if (cursor.inode != held.st_ino)
                continue;
            if (cursor.position == cursor.count)
                return nullptr;
            const char* const name = cursor.names[cursor.position++];
            const std::size_t bytes = std::strlen(name) + 1;
            if (bytes > sizeof(scripted.d_name))
            {
                errno = ENAMETOOLONG;
                return nullptr;
            }
            std::memcpy(scripted.d_name, name, bytes);
            scripted.d_type = DT_UNKNOWN;
            return &scripted;
        }
        errno = EBADF;
        return nullptr;
    });
    ON_CALL(context, CloseDirectory(testing::_)).WillByDefault([&](DIR* stream) noexcept -> ComplianceEngine::Result<void> {
        struct stat held = {};
        if (0 == ::fstat(::dirfd(stream), &held))
            for (auto& cursor : cursors)
                if (cursor.inode == held.st_ino)
                    cursor.position = 0;
        return ::closedir(stream) == 0 ? ComplianceEngine::Result<void>::Success() : ComplianceEngine::Result<void>(ComplianceEngine::Error(errno));
    });
    auto opened = Files(std::move(accepted), request.rootPath, CollectionContinuation(resolved.Value()));
    ASSERT_TRUE(opened.HasValue()) << opened.Error().message;
    std::vector<std::string> seen;
    std::vector<ino_t> inodes;
    ComplianceEngine::Optional<Path::Component> retainedNestedTarget;
    for (const auto& item : opened.Value())
    {
        ASSERT_TRUE(item.HasValue()) << item.Error().message;
        auto pin = item.Value().LiveComponent();
        ASSERT_TRUE(pin.HasValue());
        seen.push_back(item.Value().path);
        inodes.push_back(pin.Value().Metadata().Stat().st_ino);
        EXPECT_EQ(item.Value().metadata.st_ino, inodes.back());
        if (seen.size() == 1)
            retainedNestedTarget = std::move(pin);
    }
    EXPECT_EQ((std::vector<std::string>{tree.Path("alias/a/deep/relative/target"), tree.Path("alias/a/deep/absolute/target"),
                  tree.Path("alias/a/deep/inside"), tree.Path("alias/a/sibling/target"), tree.Path("alias/a/own")}),
        seen);
    EXPECT_EQ((std::vector<ino_t>{originalTarget.st_ino, originalTarget.st_ino, originalInside.st_ino, originalTarget.st_ino, originalOwn.st_ino}), inodes);
    EXPECT_EQ(0u, std::count(seen.begin(), seen.end(), tree.Path("alias/a/sibling/replacement")));
    opened->Stop();
    ASSERT_TRUE(retainedNestedTarget.HasValue());
    auto pinned = retainedNestedTarget.Value().Stat();
    ASSERT_TRUE(pinned.HasValue()) << pinned.Error().message;
    EXPECT_EQ(originalTarget.st_dev, pinned.Value().st_dev);
    EXPECT_EQ(originalTarget.st_ino, pinned.Value().st_ino);
}

TEST(FilesystemCollectionTest, LinkedRootAcceptsDistinctAbsoluteBindingsAfterReplacement)
{
    ::testing::StrictMock<MockContext> context;
    // No EXPECT_CALL in this test constrains any native seam.
    context.AllowIncidentalNativeAccess();
    TestTree tree;
    tree.Directory("actual");
    tree.Directory("actual/a");
    tree.Directory("actual/a/deep");
    tree.Directory("actual/a/sibling");
    tree.File("actual/a/deep/inside");
    tree.File("actual/a/sibling/target");
    tree.File("actual/a/own");
    tree.Link(tree.Path("alias/a/sibling"), "actual/a/deep/lookup");
    tree.Link(tree.Path("actual/a/sibling"), "actual/a/deep/effective");
    tree.Link("actual", "alias");

    FilesystemCollectionRequest request(tree.Path("alias"), FilesystemRootKind::Directory);
    request.direction = FilesystemDirection::Down;
    request.scope = FilesystemScope::All;
    request.yieldType = FilesystemYieldType::RegularFiles;
    request.rootDirectoryLinkAction = SymlinkPolicy::Follow;
    request.childDirectoryLinkAction = SymlinkPolicy::Follow;
    auto resolved = ResolveFilesystemCollectionRequest(request);
    ASSERT_TRUE(resolved.HasValue()) << resolved.Error().message;
    auto root = Path::Make(context, request.rootPath, CollectionRootPolicy(resolved.Value()), CollectionRootLimits(resolved.Value()));
    ASSERT_TRUE(root.HasValue()) << root.Error().message;
    ASSERT_TRUE(root.Value().Is<Path>());
    Path accepted = As<Path>(std::move(root).Value());
    EXPECT_EQ(tree.Path("alias"), accepted.LookupName());
    EXPECT_EQ(tree.Path("actual"), accepted.ToString());
    ASSERT_EQ(0, ::rename(tree.Path("actual").c_str(), tree.Path("old").c_str()));
    tree.Directory("actual");
    tree.Directory("actual/a");
    tree.Directory("actual/a/sibling");
    tree.File("actual/a/sibling/replacement");
    auto opened = Files(std::move(accepted), request.rootPath, CollectionContinuation(resolved.Value()));
    ASSERT_TRUE(opened.HasValue()) << opened.Error().message;
    std::set<std::string> seen;
    for (const auto& entry : opened.Value())
    {
        ASSERT_TRUE(entry.HasValue()) << entry.Error().message;
        seen.insert(entry.Value().path);
    }
    EXPECT_EQ((std::set<std::string>{tree.Path("alias/a/deep/lookup/target"), tree.Path("alias/a/deep/effective/target"),
                  tree.Path("alias/a/deep/inside"), tree.Path("alias/a/own"), tree.Path("alias/a/sibling/target")}),
        seen);
    EXPECT_FALSE(seen.count(tree.Path("alias/a/sibling/replacement")));
}

TEST(FilesystemCollectionTest, AcquiredRootAndChildContinuationPoliciesRemainSeparate)
{
    ::testing::StrictMock<MockContext> context;
    // No EXPECT_CALL in this test constrains any native seam.
    context.AllowIncidentalNativeAccess();
    TestTree tree;
    tree.Directory("real");
    tree.File("real/ordinary");
    tree.Link("ordinary", "real/link");
    tree.Link("real", "alias");
    FilesystemCollectionRequest request(tree.Path("alias"), FilesystemRootKind::Directory);
    request.direction = FilesystemDirection::Down;
    request.scope = FilesystemScope::All;
    request.yieldType = FilesystemYieldType::RegularFiles;
    request.rootDirectoryLinkAction = SymlinkPolicy::Follow;
    request.rootFileLinkAction = SymlinkPolicy::Follow;
    auto resolved = ResolveFilesystemCollectionRequest(request);
    ASSERT_TRUE(resolved.HasValue());
    auto root = Path::Make(context, request.rootPath, CollectionRootPolicy(resolved.Value()), CollectionRootLimits(resolved.Value()));
    ASSERT_TRUE(root.HasValue()) << root.Error().message;
    ASSERT_TRUE(root.Value().Is<Path>());
    ASSERT_TRUE(As<Path>(root.Value()).Freeze().HasValue());
    auto strict = CollectionContinuation(resolved.Value());
    strict.childFileLinkAction = SymlinkPolicy::DoNotFollow;
    auto excluded = Files(As<Path>(std::move(root).Value()), request.rootPath, strict);
    ASSERT_TRUE(excluded.HasValue()) << excluded.Error().message;
    std::vector<std::string> seen;
    for (const auto& entry : excluded.Value())
    {
        ASSERT_TRUE(entry.HasValue()) << entry.Error().message;
        seen.push_back(entry.Value().path);
    }
    EXPECT_EQ((std::vector<std::string>{tree.Path("alias/ordinary")}), seen);
    excluded->Stop();

    request.rootPath = tree.Path("real");
    request.rootDirectoryLinkAction = SymlinkPolicy::DoNotFollow;
    request.rootFileLinkAction = SymlinkPolicy::DoNotFollow;
    resolved = ResolveFilesystemCollectionRequest(request);
    ASSERT_TRUE(resolved.HasValue());
    auto direct = Path::Make(context, request.rootPath, CollectionRootPolicy(resolved.Value()), CollectionRootLimits(resolved.Value()));
    ASSERT_TRUE(direct.HasValue());
    ASSERT_TRUE(direct.Value().Is<Path>());
    ASSERT_TRUE(As<Path>(direct.Value()).Freeze().HasValue());
    auto followChildren = CollectionContinuation(resolved.Value());
    followChildren.childFileLinkAction = SymlinkPolicy::Follow;
    auto followed = Files(As<Path>(std::move(direct).Value()), request.rootPath, followChildren);
    ASSERT_TRUE(followed.HasValue()) << followed.Error().message;
    seen.clear();
    for (const auto& entry : followed.Value())
    {
        ASSERT_TRUE(entry.HasValue()) << entry.Error().message;
        seen.push_back(entry.Value().path);
    }
    std::sort(seen.begin(), seen.end());
    EXPECT_EQ((std::vector<std::string>{tree.Path("real/link"), tree.Path("real/ordinary")}), seen);
    followed->Stop();
}

TEST(FilesystemCollectionTest, OwnedLiveEntryOutlivesRangeButCollectedSnapshotHasNoAuthority)
{
    TestTree tree;
    tree.File("file");
    const FilesystemCollectionRequest request(tree.Path("file"), FilesystemRootKind::File);
    auto snapshot = CollectFilesystem(request);
    ASSERT_TRUE(snapshot.HasValue());
    ASSERT_EQ(1u, snapshot->entries.size());
    EXPECT_FALSE(snapshot->entries.front().LiveComponent().HasValue());

    ::testing::StrictMock<MockContext> context;
    // No EXPECT_CALL in this test constrains any native seam.
    context.AllowIncidentalNativeAccess();
    ComplianceEngine::Optional<FilesystemCollectionEntry> owned;
    ino_t inode = 0;
    {
        auto opened = Files(request, context);
        ASSERT_TRUE(opened.HasValue()) << opened.Error().message;
        auto entry = opened->begin();
        ASSERT_NE(entry, opened->end());
        ASSERT_TRUE(entry->HasValue());
        ASSERT_TRUE(entry->Value().LiveComponent().HasValue());
        // View exposes a const reference; copy the independently owning pin
        // value rather than pretending that std::move can transfer its entry.
        FilesystemCollectionEntry retained;
        retained.path = entry->Value().path;
        retained.metadata = entry->Value().metadata;
        auto pin = entry->Value().LiveComponent();
        ASSERT_TRUE(pin.HasValue());
        retained.OwnComponent(std::move(pin).Value());
        owned = std::move(retained);
        inode = owned.Value().metadata.st_ino;
        opened->Stop();
    }
    ASSERT_EQ(0, unlink(tree.Path("file").c_str()));
    ASSERT_TRUE(owned.HasValue());
    ASSERT_TRUE(owned.Value().LiveComponent().HasValue());
    auto inspected = owned.Value().LiveComponent().Value().Stat();
    ASSERT_TRUE(inspected.HasValue()) << inspected.Error().message;
    EXPECT_EQ(inode, inspected.Value().st_ino);
    owned.Reset();
}

TEST(FilesystemCollectionTest, StopBeforeFirstPullReleasesUnyieldedFilePinOnce)
{
    TestTree tree;
    tree.File("file");
    struct stat expected = {};
    ASSERT_EQ(0, stat(tree.Path("file").c_str(), &expected));
    ::testing::StrictMock<MockContext> context;
    // No EXPECT_CALL in this test constrains any native seam.
    context.AllowIncidentalNativeAccess();
    struct Pin
    {
        int descriptor = -1;
        dev_t device = 0;
        ino_t inode = 0;
        std::size_t closeAttempts = 0;
        bool live = false;
    };
    // Native mocks are noexcept. Bound all bookkeeping before entering them;
    // record failures as scalars and assert only after returning to the test.
    Pin openedPins[128] = {};
    std::size_t openedCount = 0;
    std::size_t liveCount = 0;
    bool tooManyPins = false, badStat = false, duplicateOpen = false;
    bool unknownClose = false, nativeCloseFailed = false;
    const auto recordOpen = [&](int descriptor) noexcept {
        if (descriptor >= 0)
        {
            struct stat held = {};
            if (0 != ::fstat(descriptor, &held))
                badStat = true;
            for (std::size_t i = 0; i < openedCount; ++i)
                if (openedPins[i].live && openedPins[i].descriptor == descriptor)
                    duplicateOpen = true;
            if (openedCount == sizeof(openedPins) / sizeof(openedPins[0]))
                tooManyPins = true;
            else
            {
                Pin& pin = openedPins[openedCount++];
                pin.descriptor = descriptor;
                pin.device = held.st_dev;
                pin.inode = held.st_ino;
                pin.live = true;
                ++liveCount;
            }
        }
        return descriptor;
    };
    ON_CALL(context, OpenNativePath(testing::_, testing::_)).WillByDefault([&](const char* path, int flags) noexcept {
        return recordOpen(context.RealOpenNativePath(path, flags));
    });
    ON_CALL(context, OpenNativeAt(testing::_, testing::_, testing::_)).WillByDefault([&](int directory, const char* path, int flags) noexcept {
        return recordOpen(context.RealOpenNativeAt(directory, path, flags));
    });
    std::size_t failedFilePin = 0;
    bool injectFileCloseFailure = false;
    ON_CALL(context, CloseFileDescriptor(testing::_)).WillByDefault([&](int descriptor) noexcept {
        std::size_t found = openedCount;
        for (std::size_t i = 0; i < openedCount; ++i)
            if (openedPins[i].live && openedPins[i].descriptor == descriptor)
            {
                found = i;
                break;
            }
        if (found == openedCount)
            unknownClose = true;
        const bool fail = found != openedCount && injectFileCloseFailure && found == failedFilePin;
        if (found != openedCount)
        {
            ++openedPins[found].closeAttempts;
            openedPins[found].live = false;
            --liveCount;
        }
        const int result = ::close(descriptor);
        if (result != 0)
            nativeCloseFailed = true;
        if (fail)
        {
            errno = EIO;
            return ComplianceEngine::Result<void>(ComplianceEngine::Error(errno));
        }
        return result == 0 ? ComplianceEngine::Result<void>::Success() : ComplianceEngine::Result<void>(ComplianceEngine::Error(errno));
    });
    std::vector<std::size_t> ownedPins;
    {
        auto opened = Files(FilesystemCollectionRequest(tree.Path("file"), FilesystemRootKind::File), context);
        ASSERT_TRUE(opened.HasValue()) << opened.Error().message;
        // FTW retains the frozen physical path, including process-root
        // ancestors, until Stop. It does not pop a file root to obtain its pin.
        for (std::size_t i = 0; i < openedCount; ++i)
            if (openedPins[i].live)
                ownedPins.push_back(i);
        ASSERT_FALSE(ownedPins.empty());
        std::size_t filePins = 0;
        std::size_t directoryPins = 0;
        for (const auto index : ownedPins)
        {
            const Pin& pin = openedPins[index];
            EXPECT_EQ(0u, pin.closeAttempts);
            struct stat held = {};
            ASSERT_EQ(0, fstat(pin.descriptor, &held));
            EXPECT_EQ(pin.device, held.st_dev);
            EXPECT_EQ(pin.inode, held.st_ino);
            if (held.st_dev == expected.st_dev && held.st_ino == expected.st_ino)
            {
                failedFilePin = index;
                ++filePins;
            }
            else
            {
                EXPECT_TRUE(S_ISDIR(held.st_mode));
                ++directoryPins;
            }
        }
        ASSERT_EQ(1u, filePins);
        EXPECT_GT(directoryPins, 0u);
        injectFileCloseFailure = true;
        opened->Stop();
        EXPECT_EQ(0u, liveCount);
        for (const auto index : ownedPins)
        {
            EXPECT_EQ(1u, openedPins[index].closeAttempts) << "Pin lifetime " << index;
        }
        opened->Stop();
        EXPECT_EQ(0u, liveCount);
        for (const auto index : ownedPins)
        {
            EXPECT_EQ(1u, openedPins[index].closeAttempts) << "Retried pin lifetime " << index;
        }
    }
    EXPECT_EQ(0u, liveCount);
    for (const auto index : ownedPins)
    {
        EXPECT_EQ(1u, openedPins[index].closeAttempts) << "Destructor retried pin lifetime " << index;
    }
    EXPECT_FALSE(tooManyPins);
    EXPECT_FALSE(badStat);
    EXPECT_FALSE(duplicateOpen);
    EXPECT_FALSE(unknownClose);
    EXPECT_FALSE(nativeCloseFailed);
}

TEST(FilesystemCollectionTest, StopAttemptsCursorAndPinsAndReportsEachFailureOnce)
{
    TestTree tree;
    tree.Directory("root");
    ::testing::StrictMock<MockContext> context;
    // No EXPECT_CALL in this test constrains any native seam.
    context.AllowIncidentalNativeAccess();
    const auto logPath = context.GetTempdirPath() + "/range-stop.log";
    OsConfigLogHandle logHandle = OpenLog(logPath.c_str(), nullptr);
    ASSERT_NE(nullptr, logHandle);
    context.SetLogHandle(logHandle);
    std::size_t cursorCloses = 0;
    std::size_t pinCloses = 0;
    ON_CALL(context, CloseDirectory(testing::_)).WillByDefault([&](DIR* stream) {
        ++cursorCloses;
        const int result = closedir(stream);
        const int nativeCode = errno;
        return ComplianceEngine::Error(result == 0 ? EACCES : nativeCode);
    });
    auto opened = Files(FilesystemCollectionRequest(tree.Path("root"), FilesystemRootKind::Directory), context);
    ASSERT_TRUE(opened.HasValue()) << opened.Error().message;
    ON_CALL(context, CloseFileDescriptor(testing::_)).WillByDefault([&](int descriptor) {
        ++pinCloses;
        const int result = close(descriptor);
        const int nativeCode = errno;
        return ComplianceEngine::Error(result == 0 ? EIO : nativeCode);
    });
    opened->Stop();
    EXPECT_EQ(1u, cursorCloses);
    EXPECT_GT(pinCloses, 0u);
    const auto count = pinCloses;
    opened->Stop();
    EXPECT_EQ(1u, cursorCloses);
    EXPECT_EQ(count, pinCloses);
    CloseLog(&logHandle);
    context.SetLogHandle(nullptr);
    std::ifstream log(logPath);
    ASSERT_TRUE(log.is_open());
    const std::string text((std::istreambuf_iterator<char>(log)), std::istreambuf_iterator<char>());
    const auto cursorDiagnostic = "Failed to close filesystem resource: " + std::string(strerror(EACCES));
    const auto cursorOccurrence = text.find(cursorDiagnostic);
    ASSERT_NE(std::string::npos, cursorOccurrence);
    EXPECT_EQ(std::string::npos, text.find(cursorDiagnostic, cursorOccurrence + cursorDiagnostic.size()));
    const auto pinDiagnostic = "Failed to close filesystem resource: " + std::string(strerror(EIO));
    std::size_t loggedPins = 0;
    for (std::size_t pos = text.find(pinDiagnostic); pos != std::string::npos; pos = text.find(pinDiagnostic, pos + pinDiagnostic.size()))
        ++loggedPins;
    EXPECT_EQ(pinCloses, loggedPins);
}

TEST(FilesystemCollectionTest, FailedNativeCursorCloseReleasesRangeWithoutRetryingReusedDescriptor)
{
    TestTree tree;
    tree.Directory("root");
    tree.Directory("root/sub");
    tree.Directory("root/sub/nested");
    ::testing::StrictMock<MockContext> context;
    // No EXPECT_CALL in this test constrains any native seam.
    context.AllowIncidentalNativeAccess();
    int livePins[256] = {};
    DIR* liveStreams[256] = {};
    std::size_t livePinCount = 0;
    std::size_t liveStreamCount = 0;
    bool badPinInsert = false;
    bool badPinErase = false;
    bool badStreamInsert = false;
    bool badStreamErase = false;
    bool badCursorClose = false;
    bool badReplacementOpen = false;
    bool badReplacementDup = false;
    bool badReplacementClose = false;
    const auto recordPin = [&](int fd) noexcept {
        for (std::size_t i = 0; i < livePinCount; ++i)
            if (livePins[i] == fd)
            {
                badPinInsert = true;
                return;
            }
        if (livePinCount == sizeof(livePins) / sizeof(livePins[0]))
        {
            badPinInsert = true;
            return;
        }
        livePins[livePinCount++] = fd;
    };
    const auto releasePin = [&](int fd) noexcept {
        for (std::size_t i = 0; i < livePinCount; ++i)
            if (livePins[i] == fd)
            {
                livePins[i] = livePins[--livePinCount];
                return;
            }
        badPinErase = true;
    };
    const auto recordStream = [&](DIR* stream) noexcept {
        for (std::size_t i = 0; i < liveStreamCount; ++i)
            if (liveStreams[i] == stream)
            {
                badStreamInsert = true;
                return;
            }
        if (liveStreamCount == sizeof(liveStreams) / sizeof(liveStreams[0]))
        {
            badStreamInsert = true;
            return;
        }
        liveStreams[liveStreamCount++] = stream;
    };
    const auto releaseStream = [&](DIR* stream) noexcept {
        for (std::size_t i = 0; i < liveStreamCount; ++i)
            if (liveStreams[i] == stream)
            {
                liveStreams[i] = liveStreams[--liveStreamCount];
                return;
            }
        badStreamErase = true;
    };
    std::size_t pinCloses = 0;
    std::size_t cursorCloses = 0;
    ON_CALL(context, OpenNativePath(testing::_, testing::_)).WillByDefault([&](const char* path, int flags) {
        const int fd = context.RealOpenNativePath(path, flags);
        if (fd >= 0)
            recordPin(fd);
        return fd;
    });
    ON_CALL(context, OpenNativeAt(testing::_, testing::_, testing::_)).WillByDefault([&](int directory, const char* name, int flags) {
        const int fd = context.RealOpenNativeAt(directory, name, flags);
        if (fd >= 0)
            recordPin(fd);
        return fd;
    });
    ON_CALL(context, DuplicateDescriptor(testing::_)).WillByDefault([&](int source) {
        const int fd = context.RealDuplicateDescriptor(source);
        if (fd >= 0)
            recordPin(fd);
        return fd;
    });
    ON_CALL(context, FdOpenDirectory(testing::_)).WillByDefault([&](int fd) {
        DIR* stream = fdopendir(fd);
        if (stream)
        {
            releasePin(fd); // cursor now owns the duplicate
            recordStream(stream);
        }
        return stream;
    });
    ON_CALL(context, CloseFileDescriptor(testing::_)).WillByDefault([&](int fd) {
        releasePin(fd);
        ++pinCloses;
        return ::close(fd) == 0 ? ComplianceEngine::Result<void>::Success() : ComplianceEngine::Result<void>(ComplianceEngine::Error(errno));
    });
    FilesystemCollectionRequest request(tree.Path("root"), FilesystemRootKind::Directory);
    request.direction = FilesystemDirection::Down;
    auto opened = Files(request, context);
    ASSERT_TRUE(opened.HasValue()) << opened.Error().message;
    auto files = std::move(opened).Value();
    auto entry = files.begin();
    ASSERT_NE(entry, files.end());
    ASSERT_TRUE(entry->HasValue());
    ++entry;
    ASSERT_NE(entry, files.end());
    ASSERT_TRUE(entry->HasValue());
    EXPECT_EQ(tree.Path("root/sub"), entry->Value().path);
    ++entry;
    ASSERT_NE(entry, files.end());
    ASSERT_TRUE(entry->HasValue());
    EXPECT_EQ(tree.Path("root/sub/nested"), entry->Value().path);
    ASSERT_EQ(2u, liveStreamCount);
    ASSERT_GT(livePinCount, 0u);

    int reused = -1;
    ON_CALL(context, CloseDirectory(testing::_)).WillByDefault([&](DIR* stream) -> ComplianceEngine::Result<void> {
        ++cursorCloses;
        releaseStream(stream);
        const int fd = dirfd(stream);
        if (::closedir(stream) != 0)
            badCursorClose = true;
        if (cursorCloses == 1)
        {
            const int replacement = ::open("/dev/null", O_RDONLY | O_CLOEXEC);
            if (replacement < 0)
                badReplacementOpen = true;
            if (replacement >= 0)
            {
                reused = fd;
                if (replacement != fd)
                {
                    if (::dup2(replacement, fd) != fd)
                        badReplacementDup = true;
                    if (::close(replacement) != 0)
                        badReplacementClose = true;
                }
            }
            errno = EIO;
            return ComplianceEngine::Result<void>(ComplianceEngine::Error(errno));
        }
        return ComplianceEngine::Result<void>::Success();
    });
    files.Stop(); // Native close failure is diagnostic; no second close is attempted.
    // Closing the range releases its frames and cursors, but the last
    // yielded entry owns its independent pin until the entry is released.
    EXPECT_EQ(2u, cursorCloses);
    EXPECT_EQ(0u, liveStreamCount);
    ASSERT_TRUE(entry->Value().LiveComponent().HasValue());
    EXPECT_TRUE(entry->Value().LiveComponent().Value().Stat().HasValue());
    EXPECT_EQ(1u, livePinCount);
    EXPECT_GT(pinCloses, 0u);
    const auto attemptedPins = pinCloses;
    files.Stop();
    EXPECT_EQ(2u, cursorCloses);
    EXPECT_EQ(attemptedPins, pinCloses);
    entry = files.end();
    EXPECT_EQ(0u, livePinCount);
    EXPECT_EQ(attemptedPins + 1, pinCloses);
    EXPECT_FALSE(badPinInsert);
    EXPECT_FALSE(badPinErase);
    EXPECT_FALSE(badStreamInsert);
    EXPECT_FALSE(badStreamErase);
    EXPECT_FALSE(badCursorClose);
    EXPECT_FALSE(badReplacementOpen);
    EXPECT_FALSE(badReplacementDup);
    EXPECT_FALSE(badReplacementClose);
    ASSERT_GE(reused, 0);
    EXPECT_GE(::fcntl(reused, F_GETFD), 0);
    EXPECT_EQ(0, ::close(reused));
}

TEST(FilesystemCollectionTest, VisitorErrorOutranksPathPinCloseFailure)
{
    TestTree tree;
    tree.Directory("root");
    ::testing::StrictMock<MockContext> context;
    // No EXPECT_CALL in this test constrains any native seam.
    context.AllowIncidentalNativeAccess();
    bool failClose = false;
    std::size_t failedPins = 0;
    ON_CALL(context, CloseFileDescriptor(testing::_)).WillByDefault([&](int descriptor) {
        const int result = close(descriptor);
        if (failClose && result == 0)
        {
            ++failedPins;
            errno = EIO;
            return ComplianceEngine::Result<void>(ComplianceEngine::Error(errno));
        }
        return result == 0 ? ComplianceEngine::Result<void>::Success() : ComplianceEngine::Result<void>(ComplianceEngine::Error(errno));
    });
    const auto streamed = ComplianceEngine::Filesystem::StreamFilesystemCollection(
        FilesystemCollectionRequest(tree.Path("root"), FilesystemRootKind::Directory),
        [&](const FilesystemCollectionEntry&) -> Result<FilesystemVisitAction> {
            failClose = true;
            return ComplianceEngine::Error("visitor failed", EACCES);
        },
        context);
    ASSERT_FALSE(streamed.HasValue());
    EXPECT_EQ(EACCES, streamed.Error().code);
    EXPECT_GT(failedPins, 0u);
}

TEST(FilesystemCollectionTest, MissingRegularNameReportsWithoutFabricatingAMetadataOrPin)
{
    TestTree tree;
    tree.Directory("root");
    tree.File("root/vanishing");
    ::testing::StrictMock<MockContext> context;
    // No EXPECT_CALL in this test constrains any native seam.
    context.AllowIncidentalNativeAccess();
    const std::string vanishing = tree.Path("root/vanishing");
    int unlinkStatus = -1;
    int unlinkError = 0;
    ON_CALL(context, ReadDirectory(testing::_)).WillByDefault([&](DIR * stream) -> struct dirent* {
        struct dirent* entry = readdir(stream);
        if (entry && (0 == std::strcmp("vanishing", entry->d_name)))
        {
            entry->d_type = DT_REG; // deterministic untrusted enumeration hint
            unlinkStatus = unlink(vanishing.c_str());
            if (unlinkStatus != 0)
                unlinkError = errno;
        }
        return entry;
    });
    FilesystemCollectionRequest request(tree.Path("root"), FilesystemRootKind::Directory);
    request.yieldType = FilesystemYieldType::RegularFiles;
    request.missingChildAction = ComplianceEngine::Filesystem::FilesystemMissingChildAction::ReportRegularFile;
    auto opened = Files(request, context);
    ASSERT_TRUE(opened.HasValue()) << opened.Error().message;
    auto missing = opened->begin();
    EXPECT_EQ(0, unlinkStatus) << unlinkError;
    ASSERT_NE(missing, opened->end());
    ASSERT_TRUE(missing->HasValue()) << missing->Error().message;
    EXPECT_TRUE(missing->Value().missing);
    EXPECT_EQ(tree.Path("root/vanishing"), missing->Value().path);
    EXPECT_FALSE(missing->Value().LiveComponent().HasValue());
    EXPECT_EQ(0, missing->Value().metadata.st_mode); // no accepted stat exists
    opened->Stop();

    tree.File("root/vanishing");
    unlinkStatus = -1;
    unlinkError = 0;
    ON_CALL(context, ReadDirectory(testing::_)).WillByDefault([&](DIR * stream) -> struct dirent* {
        struct dirent* entry = readdir(stream);
        if (entry && (0 == std::strcmp("vanishing", entry->d_name)))
        {
            entry->d_type = DT_UNKNOWN;
            unlinkStatus = unlink(vanishing.c_str());
            if (unlinkStatus != 0)
                unlinkError = errno;
        }
        return entry;
    });
    const auto unknown = CollectFilesystem(request, context);
    EXPECT_EQ(0, unlinkStatus) << unlinkError;
    ASSERT_FALSE(unknown.HasValue());
    EXPECT_EQ(ENOENT, unknown.Error().code);

    tree.File("root/vanishing");
    request.missingChildAction = ComplianceEngine::Filesystem::FilesystemMissingChildAction::Error;
    unlinkStatus = -1;
    unlinkError = 0;
    const auto defaultResult = CollectFilesystem(request, context);
    EXPECT_EQ(0, unlinkStatus) << unlinkError;
    ASSERT_FALSE(defaultResult.HasValue());
    EXPECT_EQ(ENOENT, defaultResult.Error().code);
}

TEST(FilesystemCollectionTest, MissingPolicyDoesNotSwallowPinnedChildInspectionFailure)
{
    TestTree tree;
    tree.Directory("root");
    tree.File("root/item");
    struct stat expected = {};
    ASSERT_EQ(0, stat(tree.Path("root/item").c_str(), &expected));
    ::testing::StrictMock<MockContext> context;
    // No EXPECT_CALL in this test constrains any native seam; it only
    // customizes StatFileDescriptor's default action via ON_CALL.
    context.AllowIncidentalNativeAccess();
    ON_CALL(context, StatFileDescriptor(testing::_, testing::_)).WillByDefault([&context, expected](int descriptor, struct stat* metadata) {
        struct stat actual = {};
        if ((0 == fstat(descriptor, &actual)) && (actual.st_dev == expected.st_dev) && (actual.st_ino == expected.st_ino))
        {
            errno = ENOENT;
            return -1;
        }
        return context.RealStatFileDescriptor(descriptor, metadata);
    });
    FilesystemCollectionRequest request(tree.Path("root"), FilesystemRootKind::Directory);
    request.yieldType = FilesystemYieldType::RegularFiles;
    request.missingChildAction = ComplianceEngine::Filesystem::FilesystemMissingChildAction::ReportRegularFile;
    const auto failure = CollectFilesystem(request, context);
    ASSERT_FALSE(failure.HasValue());
    EXPECT_EQ(ENOENT, failure.Error().code);
    EXPECT_NE(std::string::npos, failure.Error().message.find("Cannot inspect confined component"));
}

TEST(FilesystemCollectionTest, RejectsInvalidAcquisitionRootsBeforeLookup)
{
    ::testing::StrictMock<MockContext> context;
    EXPECT_CALL(context, LstatPath(testing::_, testing::_)).Times(0);
    EXPECT_CALL(context, StatPath(testing::_, testing::_)).Times(0);
    EXPECT_CALL(context, OpenDirectory(testing::_)).Times(0);
    EXPECT_CALL(context, StatFileDescriptor(testing::_, testing::_)).Times(0);
    const std::vector<std::string> roots = {"", ".", "..", "relative/root", std::string("/valid\0hidden", 13), std::string("relative\0hidden", 15)};
    for (const auto& root : roots)
    {
        SCOPED_TRACE(root);
        for (auto kind : {FilesystemRootKind::File, FilesystemRootKind::Directory})
        {
            const FilesystemCollectionRequest request(root, kind);
            const auto resolved = ResolveFilesystemCollectionRequest(request);
            ASSERT_FALSE(resolved.HasValue());
            EXPECT_EQ(EINVAL, resolved.Error().code);
            EXPECT_NE(std::string::npos, resolved.Error().message.find("root path"));

            const auto files = Files(request, context);
            ASSERT_FALSE(files.HasValue());
            EXPECT_EQ(EINVAL, files.Error().code);
            EXPECT_EQ(resolved.Error().message, files.Error().message);

            const auto collected = ComplianceEngine::Filesystem::CollectFilesystem(request, context);
            ASSERT_FALSE(collected.HasValue());
            EXPECT_EQ(EINVAL, collected.Error().code);
            EXPECT_EQ(resolved.Error().message, collected.Error().message);

            bool visited = false;
            const auto streamed = ComplianceEngine::Filesystem::StreamFilesystemCollection(
                request,
                [&visited](const FilesystemCollectionEntry&) -> Result<FilesystemVisitAction> {
                    visited = true;
                    return FilesystemVisitAction::Continue;
                },
                context);
            ASSERT_FALSE(streamed.HasValue());
            EXPECT_EQ(EINVAL, streamed.Error().code);
            EXPECT_EQ(resolved.Error().message, streamed.Error().message);
            EXPECT_FALSE(visited);
        }
    }
}

TEST(FilesystemCollectionTest, InitializesNativeDefaultsAndMatchesExplicitDefaults)
{
    const FilesystemCollectionRequest request = Request();
    EXPECT_EQ(FilesystemDirection::None, request.direction);
    EXPECT_EQ(32, request.maxDepth);
    EXPECT_EQ(SymlinkPolicy::DoNotFollow, request.rootFileLinkAction);
    EXPECT_EQ(SymlinkPolicy::DoNotFollow, request.rootDirectoryLinkAction);
    EXPECT_EQ(SymlinkPolicy::DoNotFollow, request.childFileLinkAction);
    EXPECT_EQ(SymlinkPolicy::DoNotFollow, request.childDirectoryLinkAction);
    EXPECT_EQ(FilesystemScope::RootDevice, request.scope);
    EXPECT_EQ(FilesystemYieldType::All, request.yieldType);
    EXPECT_EQ(FilesystemDepthAction::Stop, request.depthAction);
    EXPECT_EQ(128, request.operationalDescent);
    EXPECT_EQ(100000, request.entryWork);
    EXPECT_EQ(4096, request.directoryWidth);
    EXPECT_EQ(4096, request.fullPathBytes);
    EXPECT_EQ(32 * 1024 * 1024, request.retainedPathBytes);
    EXPECT_EQ(16, request.openDirectories);

    FilesystemCollectionRequest explicitDefaults = Request();
    explicitDefaults.direction = FilesystemDirection::None;
    explicitDefaults.maxDepth = 32;
    explicitDefaults.rootFileLinkAction = SymlinkPolicy::DoNotFollow;
    explicitDefaults.rootDirectoryLinkAction = SymlinkPolicy::DoNotFollow;
    explicitDefaults.childFileLinkAction = SymlinkPolicy::DoNotFollow;
    explicitDefaults.childDirectoryLinkAction = SymlinkPolicy::DoNotFollow;
    explicitDefaults.scope = FilesystemScope::RootDevice;
    explicitDefaults.yieldType = FilesystemYieldType::All;
    explicitDefaults.depthAction = FilesystemDepthAction::Stop;
    const FilesystemCollectionLimits defaultLimits;
    explicitDefaults.operationalDescent = defaultLimits.operationalDescent;
    explicitDefaults.entryWork = defaultLimits.entryWork;
    explicitDefaults.directoryWidth = defaultLimits.directoryWidth;
    explicitDefaults.fullPathBytes = defaultLimits.fullPathBytes;
    explicitDefaults.fdinfoBytes = defaultLimits.fdinfoBytes;
    explicitDefaults.retainedPathBytes = defaultLimits.retainedPathBytes;
    explicitDefaults.openDirectories = defaultLimits.openDirectories;

    const Result<ResolvedFilesystemCollectionRequest> result = ResolveFilesystemCollectionRequest(request);
    const Result<ResolvedFilesystemCollectionRequest> explicitResult = ResolveFilesystemCollectionRequest(explicitDefaults);
    ASSERT_TRUE(result.HasValue());
    ASSERT_TRUE(explicitResult.HasValue());
    const ResolvedFilesystemCollectionRequest& resolved = result.Value();
    const ResolvedFilesystemCollectionRequest& explicitResolved = explicitResult.Value();
    EXPECT_EQ(FilesystemDirection::None, resolved.direction);
    EXPECT_EQ(32, resolved.maxDepth);
    EXPECT_EQ(SymlinkPolicy::DoNotFollow, resolved.rootFileLinkAction);
    EXPECT_EQ(SymlinkPolicy::DoNotFollow, resolved.rootDirectoryLinkAction);
    EXPECT_EQ(SymlinkPolicy::DoNotFollow, resolved.childFileLinkAction);
    EXPECT_EQ(SymlinkPolicy::DoNotFollow, resolved.childDirectoryLinkAction);
    EXPECT_EQ(FilesystemScope::RootDevice, resolved.scope);
    EXPECT_EQ(FilesystemYieldType::All, resolved.yieldType);
    EXPECT_EQ(FilesystemDepthAction::Stop, resolved.depthAction);
    EXPECT_EQ(128u, resolved.limits.operationalDescent);
    EXPECT_EQ(100000u, resolved.limits.entryWork);
    EXPECT_EQ(4096u, resolved.limits.directoryWidth);
    EXPECT_EQ(4096u, resolved.limits.fullPathBytes);
    EXPECT_EQ(4096u, resolved.limits.fdinfoBytes);
    EXPECT_EQ(32u * 1024u * 1024u, resolved.limits.retainedPathBytes);
    EXPECT_EQ(16u, resolved.limits.openDirectories);
    EXPECT_EQ(resolved.direction, explicitResolved.direction);
    EXPECT_EQ(resolved.maxDepth, explicitResolved.maxDepth);
    EXPECT_EQ(resolved.rootFileLinkAction, explicitResolved.rootFileLinkAction);
    EXPECT_EQ(resolved.rootDirectoryLinkAction, explicitResolved.rootDirectoryLinkAction);
    EXPECT_EQ(resolved.childFileLinkAction, explicitResolved.childFileLinkAction);
    EXPECT_EQ(resolved.childDirectoryLinkAction, explicitResolved.childDirectoryLinkAction);
    EXPECT_EQ(resolved.scope, explicitResolved.scope);
    EXPECT_EQ(resolved.yieldType, explicitResolved.yieldType);
    EXPECT_EQ(resolved.depthAction, explicitResolved.depthAction);
    EXPECT_EQ(resolved.limits.operationalDescent, explicitResolved.limits.operationalDescent);
    EXPECT_EQ(resolved.limits.entryWork, explicitResolved.limits.entryWork);
    EXPECT_EQ(resolved.limits.directoryWidth, explicitResolved.limits.directoryWidth);
    EXPECT_EQ(resolved.limits.fullPathBytes, explicitResolved.limits.fullPathBytes);
    EXPECT_EQ(resolved.limits.fdinfoBytes, explicitResolved.limits.fdinfoBytes);
    EXPECT_EQ(resolved.limits.retainedPathBytes, explicitResolved.limits.retainedPathBytes);
    EXPECT_EQ(resolved.limits.openDirectories, explicitResolved.limits.openDirectories);
}

TEST(FilesystemCollectionTest, PreservesExplicitSelectionAndLinkSettings)
{
    FilesystemCollectionRequest request = Request();
    request.direction = FilesystemDirection::Down;
    request.maxDepth = 0;
    request.rootFileLinkAction = SymlinkPolicy::Follow;
    request.rootDirectoryLinkAction = SymlinkPolicy::DoNotFollow;
    request.childFileLinkAction = SymlinkPolicy::DoNotFollow;
    request.childDirectoryLinkAction = SymlinkPolicy::Follow;
    request.scope = FilesystemScope::All;

    const Result<ResolvedFilesystemCollectionRequest> result = ResolveFilesystemCollectionRequest(request);

    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(FilesystemDirection::Down, result->direction);
    EXPECT_EQ(0, result->maxDepth);
    EXPECT_EQ(SymlinkPolicy::Follow, result->rootFileLinkAction);
    EXPECT_EQ(SymlinkPolicy::DoNotFollow, result->rootDirectoryLinkAction);
    EXPECT_EQ(SymlinkPolicy::DoNotFollow, result->childFileLinkAction);
    EXPECT_EQ(SymlinkPolicy::Follow, result->childDirectoryLinkAction);
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
    request.fdinfoBytes = 8192;
    request.retainedPathBytes = 64u * 1024u * 1024u;
    request.openDirectories = 32;

    const Result<ResolvedFilesystemCollectionRequest> result = ResolveFilesystemCollectionRequest(request);

    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(256u, result->limits.operationalDescent);
    EXPECT_EQ(200000u, result->limits.entryWork);
    EXPECT_EQ(8192u, result->limits.directoryWidth);
    EXPECT_EQ(8192u, result->limits.fullPathBytes);
    EXPECT_EQ(8192u, result->limits.fdinfoBytes);
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

    for (auto field : {&FilesystemCollectionRequest::rootFileLinkAction, &FilesystemCollectionRequest::rootDirectoryLinkAction,
             &FilesystemCollectionRequest::childFileLinkAction, &FilesystemCollectionRequest::childDirectoryLinkAction})
    {
        FilesystemCollectionRequest invalidLink = Request();
        invalidLink.*field = static_cast<SymlinkPolicy>(99);
        ExpectInvalid(invalidLink, EINVAL);
    }

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
    request.fdinfoBytes = 0;
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
    request.fdinfoBytes = -1;
    ExpectInvalid(request, EINVAL);

    request = Request();
    request.retainedPathBytes = -1;
    ExpectInvalid(request, EINVAL);

    request = Request();
    request.openDirectories = -1;
    ExpectInvalid(request, EINVAL);
}

TEST(FilesystemCollectionTest, ShortPathBudgetDoesNotLimitProcfsInspection)
{
    ::testing::StrictMock<MockContext> context;
    // No EXPECT_CALL in this test constrains any native seam.
    context.AllowIncidentalNativeAccess();
    FilesystemCollectionRequest request("/", FilesystemRootKind::Directory);
    request.fullPathBytes = 2;
    request.scope = FilesystemScope::All;
    auto opened = Files(request, context);
    ASSERT_TRUE(opened.HasValue()) << opened.Error().message;
    opened.Value().Stop();
}

TEST(FilesystemCollectionTest, ContinuationCannotUnderstateAcquiredRootInspectionBound)
{
    ::testing::StrictMock<MockContext> context;
    // The root acquisition below performs real, incidental native access;
    // the later Times(0) expectations are declared after this catch-all, so
    // they still win for the rejected continuation attempt (see
    // MockContext.h helper comment).
    context.AllowIncidentalNativeAccess();
    FilesystemCollectionRequest request("/", FilesystemRootKind::Directory);
    request.scope = FilesystemScope::All;
    auto resolved = ResolveFilesystemCollectionRequest(request);
    ASSERT_TRUE(resolved.HasValue()) << resolved.Error().message;
    auto root = Path::Make(context, request.rootPath, CollectionRootPolicy(resolved.Value()), CollectionRootLimits(resolved.Value()));
    ASSERT_TRUE(root.HasValue()) << root.Error().message;
    ASSERT_TRUE(root.Value().Is<Path>());
    Path accepted = As<Path>(std::move(root).Value());
    ASSERT_TRUE(accepted.Freeze().HasValue());
    ASSERT_EQ(4096u, accepted.Limits().shared.fdinfoBytes);
    auto continuation = CollectionContinuation(resolved.Value());
    continuation.limits.fdinfoBytes = 1;
    EXPECT_CALL(context, OpenNativePath(testing::_, testing::_)).Times(0);
    EXPECT_CALL(context, OpenNativeAt(testing::_, testing::_, testing::_)).Times(0);
    EXPECT_CALL(context, StatFileDescriptor(testing::_, testing::_)).Times(0);
    EXPECT_CALL(context, ReadFileDescriptor(testing::_, testing::_, testing::_)).Times(0);
    EXPECT_CALL(context, FdOpenDirectory(testing::_)).Times(0);
    auto rejected = Files(std::move(accepted), request.rootPath, continuation);
    ASSERT_FALSE(rejected.HasValue());
    EXPECT_EQ(EINVAL, rejected.Error().code);
    EXPECT_EQ("Filesystem continuation fdinfo byte limit is below the acquired root's bound inspection limit", rejected.Error().message);
    EXPECT_TRUE(testing::Mock::VerifyAndClearExpectations(&context));
    // VerifyAndClearExpectations() above cleared every EXPECT_CALL on
    // context, including the catch-all; the remaining locals' destructors
    // (closing the acquired root's descriptor) are incidental again.
    context.AllowIncidentalNativeAccess();
}

TEST(FilesystemCollectionTest, PathContinuationAutomaticallyFreezesUnfrozenNestedStart)
{
    ::testing::StrictMock<MockContext> context;
    // No EXPECT_CALL in this test constrains any native seam.
    context.AllowIncidentalNativeAccess();
    TestTree tree;
    tree.Directory("root");
    tree.Directory("root/nested");
    tree.File("root/nested/item");
    FilesystemCollectionRequest request(tree.Path("root/nested"), FilesystemRootKind::Directory);
    request.direction = FilesystemDirection::Down;
    request.yieldType = FilesystemYieldType::RegularFiles;
    request.scope = FilesystemScope::All;
    auto resolved = ResolveFilesystemCollectionRequest(request);
    ASSERT_TRUE(resolved.HasValue()) << resolved.Error().message;
    auto acquired = Path::Make(context, request.rootPath, CollectionRootPolicy(resolved.Value()), CollectionRootLimits(resolved.Value()));
    ASSERT_TRUE(acquired.HasValue()) << acquired.Error().message;
    ASSERT_TRUE(acquired.Value().Is<Path>());
    Path path = As<Path>(std::move(acquired).Value());
    ASSERT_GT(path.Size(), 1u);
    auto files = Files(std::move(path), request.rootPath, CollectionContinuation(resolved.Value()));
    ASSERT_TRUE(files.HasValue()) << files.Error().message;
    std::vector<std::string> seen;
    for (const auto& entry : files.Value())
    {
        ASSERT_TRUE(entry.HasValue()) << entry.Error().message;
        seen.push_back(entry.Value().path);
    }
    EXPECT_EQ((std::vector<std::string>{tree.Path("root/nested/item")}), seen);
    files->Stop();
}

TEST(FilesystemCollectionTest, AppliesExactRootPathBudgetIncludingTerminator)
{
    FilesystemCollectionRequest exact = Request();
    exact.rootPath = "/ab";
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
    EXPECT_TRUE(absent->entries.empty());
    ASSERT_TRUE(directory.HasValue());
    EXPECT_EQ((std::vector<std::string>{tree.Path("empty")}), Paths(directory->entries));
    ASSERT_TRUE(file.HasValue());
    EXPECT_EQ((std::vector<std::string>{tree.Path("file")}), Paths(file->entries));
    EXPECT_TRUE(S_ISREG(file->entries[0].metadata.st_mode));
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

TEST(FilesystemCollectionTest, UnknownTypeHiddenDirectoryDescendsWithoutDeliveringDotEntries)
{
    TestTree tree;
    tree.Directory("root");
    tree.Directory("root/.hidden");
    tree.File("root/.hidden/.dotfile");
    tree.File("root/visible");
    ::testing::StrictMock<MockContext> context;
    // No EXPECT_CALL in this test constrains any native seam.
    context.AllowIncidentalNativeAccess();
    ON_CALL(context, ReadDirectory(testing::_)).WillByDefault([](DIR * stream) -> struct dirent* {
        struct dirent* entry = readdir(stream);
        if ((nullptr != entry) && (0 == std::strcmp(entry->d_name, ".hidden")))
        {
            entry->d_type = DT_UNKNOWN;
        }
        return entry;
    });
    FilesystemCollectionRequest request(tree.Path("root"), FilesystemRootKind::Directory);
    request.direction = FilesystemDirection::Down;
    request.yieldType = FilesystemYieldType::RegularFiles;

    const auto collected = ComplianceEngine::Filesystem::CollectFilesystem(request, context);
    ASSERT_TRUE(collected.HasValue());
    auto entries = Paths(collected->entries);
    std::sort(entries.begin(), entries.end());
    EXPECT_EQ((std::vector<std::string>{tree.Path("root/.hidden/.dotfile"), tree.Path("root/visible")}), entries);

    std::vector<std::string> streamed;
    const auto result = ComplianceEngine::Filesystem::StreamFilesystemCollection(
        request,
        [&streamed](const FilesystemCollectionEntry& entry) {
            streamed.push_back(entry.path);
            return Result<FilesystemVisitAction>(FilesystemVisitAction::Continue);
        },
        context);
    ASSERT_TRUE(result.HasValue());
    std::sort(streamed.begin(), streamed.end());
    EXPECT_EQ(entries, streamed);
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

TEST(FilesystemCollectionTest, RemovedChildAfterAcquisitionDoesNotReopenItsSpelledPath)
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
    ASSERT_TRUE(result.HasValue()) << result.Error().message;
}

TEST(FilesystemCollectionTest, SkipsAndFollowsDirectoryLinksIndependently)
{
    TestTree tree;
    tree.Directory("root");
    tree.Directory("root/target");
    tree.File("root/target/item");
    tree.Link(tree.Path("root/target"), "root/alias");
    FilesystemCollectionRequest request(tree.Path("root"), FilesystemRootKind::Directory);
    request.direction = FilesystemDirection::Down;
    const auto skipped = CollectFilesystem(request);

    request.childDirectoryLinkAction = SymlinkPolicy::Follow;
    const auto followed = CollectFilesystem(request);

    ASSERT_TRUE(skipped.HasValue());
    EXPECT_EQ((std::vector<std::string>{tree.Path("root"), tree.Path("root/target"), tree.Path("root/target/item")}), Paths(skipped->entries));
    ASSERT_EQ(1u, skipped->exclusions.size());
    EXPECT_EQ(tree.Path("root/alias"), skipped->exclusions[0].path);
    EXPECT_EQ("link policy", skipped->exclusions[0].reason);
    ASSERT_TRUE(followed.HasValue());
    const auto paths = Paths(followed->entries);
    EXPECT_NE(paths.end(), std::find(paths.begin(), paths.end(), tree.Path("root/alias/item")));
    const auto alias = std::find_if(followed->entries.begin(), followed->entries.end(),
        [&tree](const FilesystemCollectionEntry& entry) { return entry.path == tree.Path("root/alias"); });
    ASSERT_NE(followed->entries.end(), alias);
    EXPECT_TRUE(S_ISDIR(alias->metadata.st_mode));
    EXPECT_TRUE(followed->exclusions.empty());

    // A file-only follow setting does not cause directory traversal.
    request.childFileLinkAction = SymlinkPolicy::Follow;
    request.childDirectoryLinkAction = SymlinkPolicy::DoNotFollow;
    const auto directorySkipped = CollectFilesystem(request);
    ASSERT_TRUE(directorySkipped.HasValue());
    EXPECT_EQ((std::vector<std::string>{tree.Path("root"), tree.Path("root/target"), tree.Path("root/target/item")}), Paths(directorySkipped->entries));
    ASSERT_EQ(1u, directorySkipped->exclusions.size());
    EXPECT_EQ(tree.Path("root/alias"), directorySkipped->exclusions[0].path);
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
    request.childDirectoryLinkAction = SymlinkPolicy::Follow;
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

TEST(FilesystemCollectionTest, ActiveAncestorCyclesRequireDescentButSelectionDoesNot)
{
    TestTree tree;
    tree.Directory("root");
    tree.Directory("root/child");
    tree.Link(".", "root/self");
    tree.Link("..", "root/child/parent");
    FilesystemCollectionRequest request(tree.Path("root"), FilesystemRootKind::Directory);
    request.childDirectoryLinkAction = SymlinkPolicy::Follow;
    request.direction = FilesystemDirection::None;
    auto observed = CollectFilesystem(request);
    ASSERT_TRUE(observed.HasValue()) << observed.Error().message;
    const auto paths = Paths(observed->entries);
    EXPECT_NE(paths.end(), std::find(paths.begin(), paths.end(), tree.Path("root/self")));
    request.direction = FilesystemDirection::Down;
    const auto cycle = CollectFilesystem(request);
    ASSERT_FALSE(cycle.HasValue());
    EXPECT_EQ(ELOOP, cycle.Error().code);
    ASSERT_EQ(0, ::unlink(tree.Path("root/self").c_str()));
    const auto parentCycle = CollectFilesystem(request);
    ASSERT_FALSE(parentCycle.HasValue());
    EXPECT_EQ(ELOOP, parentCycle.Error().code);
}

TEST(FilesystemCollectionTest, DescendantAbsoluteLinkOutsideAcceptedRootFailsClosed)
{
    TestTree tree;
    tree.Directory("root");
    tree.File("outside");
    tree.Link(tree.Path("outside"), "root/alias");
    FilesystemCollectionRequest request(tree.Path("root"), FilesystemRootKind::Directory);
    request.childFileLinkAction = SymlinkPolicy::Follow;
    const auto result = CollectFilesystem(request);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EXDEV, result.Error().code); // No accepted frozen root binding covers the target.
}

TEST(FilesystemCollectionTest, TM9NestedBarrierRejectsRelativeAbsoluteAndPrefixEscapesEvenWithAllScope)
{
    TestTree tree;
    tree.Directory("parent");
    tree.Directory("parent/start");
    tree.Directory("parent/start-prefix");
    tree.File("parent/outside-file");
    tree.File("parent/start-prefix/file");
    tree.Directory("parent/outside-dir");
    tree.File("parent/outside-dir/leaf");
    tree.Directory("parent/start-prefix/dir");
    const std::string root = tree.Path("parent/start");
    const std::vector<std::string> escapes = {"../outside-file", "../outside-dir", "../../parent/outside-file", tree.Path("parent/outside-file"),
        tree.Path("parent/outside-dir"), tree.Path("parent/start-prefix/file"), tree.Path("parent/start-prefix/dir")};
    for (std::size_t index = 0; index < escapes.size(); ++index)
    {
        SCOPED_TRACE(index);
        const std::string alias = "link-" + std::to_string(index);
        tree.Link(escapes[index], "parent/start/" + alias);
        FilesystemCollectionRequest request(root, FilesystemRootKind::Directory);
        request.direction = FilesystemDirection::Down;
        request.scope = FilesystemScope::All;
        request.childDirectoryLinkAction = SymlinkPolicy::Follow;
        request.childFileLinkAction = SymlinkPolicy::Follow;
        // TM-9: CrossMounts/All is a mount choice, never permission to exit
        // the automatically frozen selected start (including a prefix twin).
        const auto denied = CollectFilesystem(request);
        ASSERT_FALSE(denied.HasValue());
        EXPECT_EQ(EXDEV, denied.Error().code);
        ASSERT_EQ(0, ::unlink(tree.Path("parent/start/" + alias).c_str()));
    }
}

TEST(FilesystemCollectionTest, TM9RejectsLeaveAndReenterInsteadOfLexicallyNormalizing)
{
    TestTree tree;
    tree.Directory("parent");
    tree.Directory("parent/start");
    tree.File("parent/start/inside");
    const std::string root = tree.Path("parent/start");
    const std::vector<std::string> excursions = {"../start/inside", root + "/../start/inside"};
    for (std::size_t index = 0; index < excursions.size(); ++index)
    {
        SCOPED_TRACE(index);
        const std::string alias = "excursion-" + std::to_string(index);
        tree.Link(excursions[index], "parent/start/" + alias);
        FilesystemCollectionRequest request(root, FilesystemRootKind::Directory);
        request.scope = FilesystemScope::All;
        request.childFileLinkAction = SymlinkPolicy::Follow;
        // TM-9: resolution must not cross the barrier and return to it.
        const auto denied = CollectFilesystem(request);
        ASSERT_FALSE(denied.HasValue());
        EXPECT_EQ(EXDEV, denied.Error().code);
        ASSERT_EQ(0, ::unlink(tree.Path("parent/start/" + alias).c_str()));
    }
}

TEST(FilesystemCollectionTest, FileTargetDoesNotChangePhysicalParentAndRemainsPinnedAfterStop)
{
    TestTree tree;
    tree.Directory("root");
    tree.File("root/first");
    tree.File("root/second");
    tree.Link("first", "root/alias");
    ::testing::StrictMock<MockContext> context;
    // No EXPECT_CALL in this test constrains any native seam.
    context.AllowIncidentalNativeAccess();
    FilesystemCollectionRequest request(tree.Path("root"), FilesystemRootKind::Directory);
    request.yieldType = FilesystemYieldType::RegularFiles;
    request.childFileLinkAction = SymlinkPolicy::Follow;
    ComplianceEngine::Optional<Path::Component> alias;
    ino_t inode = 0;
    {
        auto opened = Files(request, context);
        ASSERT_TRUE(opened.HasValue()) << opened.Error().message;
        std::set<std::string> paths;
        for (const auto& result : opened.Value())
        {
            ASSERT_TRUE(result.HasValue()) << result.Error().message;
            paths.insert(result.Value().path);
            if (result.Value().path == tree.Path("root/alias"))
            {
                alias = result.Value().LiveComponent();
                ASSERT_TRUE(alias.HasValue());
                inode = alias.Value().Metadata().Stat().st_ino;
            }
        }
        EXPECT_EQ((std::set<std::string>{tree.Path("root/alias"), tree.Path("root/first"), tree.Path("root/second")}), paths);
        opened->Stop();
    }
    ASSERT_TRUE(alias.HasValue());
    ASSERT_EQ(0, ::unlink(tree.Path("root/alias").c_str()));
    ASSERT_EQ(0, ::unlink(tree.Path("root/first").c_str()));
    auto held = alias.Value().Stat();
    ASSERT_TRUE(held.HasValue()) << held.Error().message;
    EXPECT_EQ(inode, held.Value().st_ino);
}

TEST(FilesystemCollectionTest, ObservedDirectoryTargetDoesNotApplyAndRemainsPinnedAfterStop)
{
    TestTree tree;
    tree.Directory("root");
    tree.Directory("root/folder");
    tree.File("root/sibling");
    ::testing::StrictMock<MockContext> context;
    // No EXPECT_CALL in this test constrains any native seam.
    context.AllowIncidentalNativeAccess();
    FilesystemCollectionRequest request(tree.Path("root"), FilesystemRootKind::Directory);
    request.direction = FilesystemDirection::None;
    request.yieldType = FilesystemYieldType::All;
    ComplianceEngine::Optional<Path::Component> directory;
    ino_t directoryInode = 0;
    auto range = Files(request, context);
    ASSERT_TRUE(range.HasValue()) << range.Error().message;
    std::set<std::string> seen;
    for (const auto& result : range.Value())
    {
        ASSERT_TRUE(result.HasValue()) << result.Error().message;
        seen.insert(result.Value().path);
        if (result.Value().path == tree.Path("root/folder"))
        {
            directory = result.Value().LiveComponent();
            ASSERT_TRUE(directory.HasValue());
            directoryInode = directory.Value().Metadata().Stat().st_ino;
        }
    }
    EXPECT_EQ((std::set<std::string>{tree.Path("root"), tree.Path("root/folder"), tree.Path("root/sibling")}), seen);
    range->Stop();
    ASSERT_TRUE(directory.HasValue());
    ASSERT_EQ(0, ::rename(tree.Path("root/folder").c_str(), tree.Path("root/renamed").c_str()));
    auto held = directory.Value().Stat();
    ASSERT_TRUE(held.HasValue()) << held.Error().message;
    EXPECT_EQ(directoryInode, held.Value().st_ino);
}

TEST(FilesystemCollectionTest, StreamingStopAndCallbackErrorDoNotFabricateEntries)
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
    EXPECT_EQ(1u, visited.size());
    EXPECT_TRUE(stopped->entries.empty());

    const auto failed = StreamFilesystemCollection(request,
        [](const FilesystemCollectionEntry&) { return Result<FilesystemVisitAction>(ComplianceEngine::Error("caller failed", EIO)); });
    ASSERT_FALSE(failed.HasValue());
    EXPECT_EQ(EIO, failed.Error().code);
    EXPECT_EQ("caller failed", failed.Error().message);
    const ComplianceEngine::Filesystem::FilesystemCollectionVisitor empty;
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
    const auto exhausted = CollectFilesystem(request);
    ASSERT_FALSE(exhausted.HasValue());
    EXPECT_EQ(EMFILE, exhausted.Error().code);
    request.openDirectories = 128; // Explicit opt-in; the default remains 16.
    const auto result = StreamFilesystemCollection(request, [&visited](const FilesystemCollectionEntry& entry) {
        visited.push_back(entry.path);
        return Result<FilesystemVisitAction>(FilesystemVisitAction::Continue);
    });
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(19u, visited.size());
    EXPECT_EQ(1u, std::count(visited.begin(), visited.end(), tree.Path(parent + "/leaf")));
}

TEST(FilesystemCollectionTest, ReplacedAncestorDoesNotRedirectPinnedTraversal)
{
    TestTree tree;
    tree.Directory("root");
    tree.Directory("root/d");
    tree.File("root/d/leaf");
    FilesystemCollectionRequest request(tree.Path("root"), FilesystemRootKind::Directory);
    request.direction = FilesystemDirection::Down;
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
    ASSERT_TRUE(result.HasValue()) << result.Error().message;
}

TEST(FilesystemCollectionTest, RenamedChildDoesNotRequirePathnameReplay)
{
    TestTree tree;
    tree.Directory("root");
    tree.Directory("root/d");
    tree.File("root/d/leaf");
    FilesystemCollectionRequest request(tree.Path("root"), FilesystemRootKind::Directory);
    request.direction = FilesystemDirection::Down;
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
    ASSERT_TRUE(result.HasValue()) << result.Error().message;
}

TEST(FilesystemCollectionTest, StoppingAfterAncestorReplacementClosesPinnedCursors)
{
    TestTree tree;
    tree.Directory("root");
    tree.Directory("root/d");
    tree.File("root/d/leaf");
    FilesystemCollectionRequest request(tree.Path("root"), FilesystemRootKind::Directory);
    request.direction = FilesystemDirection::Down;
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
}

TEST(FilesystemCollectionTest, RetentionExhaustionIsExplicitRatherThanReplayingNames)
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
    EXPECT_EQ(EMFILE, result.Error().code);
    EXPECT_EQ(0u, std::count(visited.begin(), visited.end(), tree.Path("root/d/leaf")));
    request.openDirectories = 128;
    request.entryWork = 2;
    ASSERT_TRUE(CollectFilesystem(request).HasValue());
    long long low = 1, high = request.openDirectories;
    while (low + 1 < high)
    {
        request.openDirectories = low + (high - low) / 2;
        if (CollectFilesystem(request).HasValue())
        {
            high = request.openDirectories;
        }
        else
        {
            low = request.openDirectories;
        }
    }
    request.openDirectories = high;
    EXPECT_TRUE(CollectFilesystem(request).HasValue());
    request.openDirectories = high - 1;
    const auto oneBeyond = CollectFilesystem(request);
    ASSERT_FALSE(oneBeyond.HasValue());
    EXPECT_EQ(EMFILE, oneBeyond.Error().code);
}

TEST(FilesystemCollectionTest, InverseHistoryHasAnExactRetainedByteBoundary)
{
    ::testing::StrictMock<MockContext> context;
    // No EXPECT_CALL in this test constrains any native seam.
    context.AllowIncidentalNativeAccess();
    TestTree tree;
    tree.Directory("root");
    std::string branch = "root";
    for (int i = 0; i < 8; ++i)
    {
        branch += "/d";
        tree.Directory(branch);
    }
    tree.File(branch + "/leaf");
    FilesystemCollectionRequest request(tree.Path("root"), FilesystemRootKind::Directory);
    request.direction = FilesystemDirection::Down;
    request.yieldType = FilesystemYieldType::RegularFiles;
    request.scope = FilesystemScope::All;
    // With the audited TMPDIR root (8 physical pins), the default cap is 16 + 8 + 3 + 1 = 28.
    // Seven inverse steps charge 21 slots; opening the eighth cursor needs 8 more (29).
    // Isolate retained bytes from this independent FTW descriptor limit.
    request.openDirectories = 256;
    auto resolved = ResolveFilesystemCollectionRequest(request);
    ASSERT_TRUE(resolved.HasValue()) << resolved.Error().message;
    const auto traverse = [&](std::size_t cap) -> int {
        auto limits = CollectionRootLimits(resolved.Value());
        limits.shared.retainedBytes = cap;
        auto root = Path::Make(context, request.rootPath, CollectionRootPolicy(resolved.Value()), limits);
        if (!root.HasValue())
            return root.Error().code;
        if (!root.Value().Is<Path>())
            return ENOENT;
        auto range = Files(As<Path>(std::move(root).Value()), request.rootPath, CollectionContinuation(resolved.Value()));
        if (!range.HasValue())
            return range.Error().code;
        for (const auto& entry : range.Value())
            if (!entry.HasValue())
                return entry.Error().code;
        range->Stop();
        return 0;
    };
    std::size_t low = 1;
    std::size_t high = 262144;
    ASSERT_EQ(0, traverse(high));
    while (low + 1 < high)
    {
        const auto middle = low + (high - low) / 2;
        if (traverse(middle) == 0)
            high = middle;
        else
            low = middle;
    }
    EXPECT_EQ(0, traverse(high));
    EXPECT_EQ(E2BIG, traverse(high - 1));
}

TEST(FilesystemCollectionTest, InverseHistoryHasAnExactDescriptorBoundary)
{
    ::testing::StrictMock<MockContext> context;
    // No EXPECT_CALL in this test constrains any native seam.
    context.AllowIncidentalNativeAccess();
    TestTree tree;
    tree.Directory("root");
    std::string branch = "root";
    for (int depth = 8; 0 < depth; --depth)
    {
        branch += "/d";
        tree.Directory(branch);
    }
    tree.File(branch + "/leaf");
    FilesystemCollectionRequest request(tree.Path("root"), FilesystemRootKind::Directory);
    request.direction = FilesystemDirection::Down;
    request.yieldType = FilesystemYieldType::RegularFiles;
    request.openDirectories = 64; // Sufficient cursor budget; probe physical and inverse pins.
    auto resolved = ResolveFilesystemCollectionRequest(request);
    ASSERT_TRUE(resolved.HasValue()) << resolved.Error().message;
    const auto traverse = [&](std::size_t cap) -> int {
        auto limits = CollectionRootLimits(resolved.Value());
        limits.shared.liveDescriptors = cap;
        auto root = Path::Make(context, request.rootPath, CollectionRootPolicy(resolved.Value()), limits);
        if (!root.HasValue())
            return root.Error().code;
        if (!root.Value().Is<Path>())
            return ENOENT;
        auto range = Files(As<Path>(std::move(root).Value()), request.rootPath, CollectionContinuation(resolved.Value()));
        if (!range.HasValue())
            return range.Error().code;
        for (const auto& entry : range.Value())
            if (!entry.HasValue())
                return entry.Error().code;
        range->Stop();
        return 0;
    };
    std::size_t low = 1;
    std::size_t high = 256;
    ASSERT_EQ(0, traverse(high));
    while (low + 1 < high)
    {
        const auto middle = low + (high - low) / 2;
        if (0 == traverse(middle))
            high = middle;
        else
            low = middle;
    }
    EXPECT_EQ(0, traverse(high));
    EXPECT_EQ(EMFILE, traverse(high - 1));
}

TEST(FilesystemCollectionTest, PoppedInverseChargeMatchesIndependentStepDifference)
{
    ::testing::StrictMock<MockContext> context;
    // No EXPECT_CALL in this test constrains any native seam; it only
    // customizes ReadDirectory/CloseDirectory default actions via ON_CALL.
    context.AllowIncidentalNativeAccess();
    TestTree tree;
    tree.Directory("root");
    // Common inverse frames must dominate even the deeper link's Resolve/Apply
    // preparation peak at the shallower traversal cap.
    const std::size_t depth = 40;
    std::vector<const char*> ancestors(depth, "d");
    ancestors.front() = "a";
    std::vector<std::string> directories(depth + 3);
    directories[0] = "root";
    std::string branch = "root";
    for (std::size_t i = 0; i < depth; ++i)
    {
        branch += "/";
        branch += ancestors[i];
        tree.Directory(branch);
        directories[i + 1] = branch;
    }
    const std::string shallowParent = directories[depth - 1];
    directories[depth + 1] = "root/b";
    directories[depth + 2] = shallowParent + "/b";
    tree.Directory(directories[depth + 1]);
    tree.Directory(directories[depth + 2]);
    std::string deepTarget;
    for (std::size_t i = 0; i < depth; ++i)
        deepTarget += "../";
    deepTarget += "b";
    tree.Link(deepTarget, branch + "/one"); // Pops all ancestors below root.
    tree.Link("../b", branch + "/two");     // Pops only the final ancestor.
    FilesystemCollectionRequest request(tree.Path("root"), FilesystemRootKind::Directory);
    request.direction = FilesystemDirection::Down;
    request.scope = FilesystemScope::All;
    request.childDirectoryLinkAction = SymlinkPolicy::Follow;
    request.maxDepth = static_cast<int>(depth + 1); // Reach both links without disabling the depth bound.
    // FTW retains an inverse and a cursor for each common ancestor. Explicit
    // cursor headroom leaves both link charges observable; do not raise defaults.
    // Byte scans use the same configured shared cap for Path and FTW.
    request.openDirectories = 256;
    request.yieldType = FilesystemYieldType::RegularFiles; // Empty targets: no entry pin charges.
    auto resolved = ResolveFilesystemCollectionRequest(request);
    ASSERT_TRUE(resolved.HasValue()) << resolved.Error().message;

    Path::Policy childPolicy;
    childPolicy.prefixLinks = ComplianceEngine::Filesystem::PrefixLinkPolicy::Follow;
    childPolicy.directoryLinks = ComplianceEngine::Filesystem::DirectoryLinkPolicy::Follow;
    childPolicy.mounts = ComplianceEngine::Filesystem::MountPolicy::CrossMounts;
    // Observe the two inverse owners through Path, not FTW or an inferred cap.
    const auto inverse = [&](const char* link, std::size_t cap, bool bytes) -> std::pair<std::size_t, std::size_t> {
        auto limits = CollectionRootLimits(resolved.Value());
        if (cap)
        {
            if (bytes)
                limits.shared.retainedBytes = cap;
            else
                limits.shared.liveDescriptors = cap;
        }
        auto acquired = Path::Make(context, request.rootPath, CollectionRootPolicy(resolved.Value()), limits);
        EXPECT_TRUE(acquired.HasValue()) << acquired.Error().message;
        if (!acquired.HasValue() || !acquired.Value().Is<Path>())
            return {0, 0};
        Path physical = As<Path>(std::move(acquired).Value());
        auto frozen = physical.Freeze();
        EXPECT_TRUE(frozen.HasValue());
        if (!frozen.HasValue())
            return {0, 0};
        for (const char* name : ancestors)
        {
            auto forward = physical.Resolve(name, childPolicy);
            EXPECT_TRUE(forward.HasValue()) << forward.Error().message;
            if (!forward.HasValue() || !forward.Value().Is<Path::Step>())
                return {0, 0};
            auto undo = physical.Apply(As<Path::Step>(std::move(forward).Value()));
            EXPECT_TRUE(undo.HasValue());
            if (!undo.HasValue())
                return {0, 0};
        }
        auto forward = physical.Resolve(link, childPolicy);
        EXPECT_TRUE(forward.HasValue()) << forward.Error().message;
        if (!forward.HasValue() || !forward.Value().Is<Path::Step>())
            return {0, 0};
        const std::size_t before = physical.Size();
        auto undo = physical.Apply(As<Path::Step>(std::move(forward).Value()));
        EXPECT_TRUE(undo.HasValue());
        if (!undo.HasValue())
            return {0, 0};
        if (0 == std::strcmp(link, "one"))
            EXPECT_LT(physical.Size(), before);
        return {undo.Value().RetainedDescriptors(), undo.Value().RetainedBytes()};
    };
    const auto deeper = inverse("one", 0, false);
    const auto shallower = inverse("two", 0, false);
    ASSERT_GT(deeper.first, shallower.first);
    ASSERT_GT(deeper.second, shallower.second);

    struct Cursor
    {
        ino_t inode;
        const char* name;
        std::size_t position;
    };
    Cursor cursors[depth + 3] = {};
    for (std::size_t i = 0; i < depth + 3; ++i)
    {
        struct stat info = {};
        ASSERT_EQ(0, ::stat(tree.Path(directories[i]).c_str(), &info));
        cursors[i] = {info.st_ino, i < depth ? ancestors[i] : nullptr, 0};
    }
    struct dirent scripted = {};
    bool deep = false;
    std::size_t linkVisits = 0;
    ON_CALL(context, ReadDirectory(testing::_)).WillByDefault([&](DIR * stream) noexcept -> struct dirent* {
        struct stat held = {};
        if (0 != ::fstat(::dirfd(stream), &held))
            return nullptr;
        for (std::size_t i = 0; i < depth + 3; ++i)
        {
            Cursor& cursor = cursors[i];
            if (cursor.inode != held.st_ino)
                continue;
            if (cursor.position++)
                return nullptr;
            const char* name = i == depth ? (deep ? "one" : "two") : cursor.name;
            if (!name)
                return nullptr;
            if (i == depth)
                ++linkVisits;
            const std::size_t length = std::strlen(name) + 1;
            if (length > sizeof(scripted.d_name))
            {
                errno = ENAMETOOLONG;
                return nullptr;
            }
            std::memcpy(scripted.d_name, name, length);
            scripted.d_type = DT_UNKNOWN;
            return &scripted;
        }
        errno = EBADF;
        return nullptr;
    });
    ON_CALL(context, CloseDirectory(testing::_)).WillByDefault([&](DIR* stream) noexcept -> ComplianceEngine::Result<void> {
        struct stat held = {};
        if (0 == ::fstat(::dirfd(stream), &held))
            for (auto& cursor : cursors)
                if (cursor.inode == held.st_ino)
                    cursor.position = 0;
        return ::closedir(stream) == 0 ? ComplianceEngine::Result<void>::Success() : ComplianceEngine::Result<void>(ComplianceEngine::Error(errno));
    });
    const auto scan = [&](std::size_t cap, bool bytes, bool useDeep) -> int {
        for (auto& cursor : cursors)
            cursor.position = 0;
        linkVisits = 0;
        deep = useDeep;
        auto limits = CollectionRootLimits(resolved.Value());
        if (bytes)
            limits.shared.retainedBytes = cap;
        else
            limits.shared.liveDescriptors = cap;
        auto acquired = Path::Make(context, request.rootPath, CollectionRootPolicy(resolved.Value()), limits);
        if (!acquired.HasValue())
            return acquired.Error().code;
        if (!acquired.Value().Is<Path>())
            return ENOENT;
        auto range = Files(As<Path>(std::move(acquired).Value()), request.rootPath, CollectionContinuation(resolved.Value()));
        if (!range.HasValue())
            return range.Error().code;
        for (const auto& entry : range.Value())
            if (!entry.HasValue())
                return entry.Error().code;
        range->Stop();
        return 0;
    };
    for (const bool bytes : {false, true})
    {
        SCOPED_TRACE(bytes ? "retained bytes" : "descriptors");
        const std::size_t upper = bytes ? 262144 : 256;
        const auto minimum = [&](bool useDeep) {
            std::size_t low = 1, high = upper;
            while (low + 1 < high)
            {
                const std::size_t middle = low + (high - low) / 2;
                if (0 == scan(middle, bytes, useDeep))
                    high = middle;
                else
                    low = middle;
            }
            return high;
        };
        ASSERT_EQ(0, scan(upper, bytes, false));
        EXPECT_EQ(1u, linkVisits);
        ASSERT_EQ(0, scan(upper, bytes, true));
        EXPECT_EQ(1u, linkVisits);
        const std::size_t shallowCap = minimum(false);
        const std::size_t deepCap = minimum(true);
        const std::size_t delta = bytes ? deeper.second - shallower.second : deeper.first - shallower.first;
        // Confirm the physical resolver and Apply fit at the stricter cap.
        // Thus neither branch's acquisition peak can explain the FTW cap gap.
        EXPECT_EQ(shallower, inverse("two", shallowCap - 1, bytes));
        EXPECT_EQ(deeper, inverse("one", shallowCap, bytes));
        // Both scripted branches have identical logical frame lengths, cursor
        // counts and frame-storage growth; neither yields a pin. Their only
        // retained-owner difference at the link is the measured inverse Step.
        // Dropping inverse ReservePins collapses this difference, even though
        // a binary search for each branch alone would still find some cap.
        EXPECT_EQ(shallowCap + delta, deepCap);
        EXPECT_EQ(0, scan(shallowCap, bytes, false));
        EXPECT_EQ(1u, linkVisits);
        EXPECT_EQ(bytes ? E2BIG : EMFILE, scan(shallowCap - 1, bytes, false));
        EXPECT_EQ(1u, linkVisits); // Exhaustion follows selection of the link, not an earlier frame.
        EXPECT_EQ(0, scan(deepCap, bytes, true));
        EXPECT_EQ(1u, linkVisits);
        EXPECT_EQ(bytes ? E2BIG : EMFILE, scan(deepCap - 1, bytes, true));
        EXPECT_EQ(1u, linkVisits);
    }
}

TEST(FilesystemCollectionTest, PoppedInversePinsHaveExactBoundariesAndRefundBeforeNextSibling)
{
    ::testing::StrictMock<MockContext> context;
    // No EXPECT_CALL in this test constrains any native seam.
    context.AllowIncidentalNativeAccess();
    TestTree tree;
    tree.Directory("root");
    tree.Directory("root/a");
    tree.Directory("root/a/deep");
    tree.Directory("root/b");
    tree.Directory("root/c");
    tree.Directory("root/d");
    tree.Link("../c", "root/b/hop");
    tree.Link("../d", "root/c/hop");
    tree.Link("../../b", "root/a/deep/one");
    tree.Link("../../b", "root/a/deep/two");
    tree.File("root/d/leaf");
    tree.File("root/a/last");
    FilesystemCollectionRequest request(tree.Path("root"), FilesystemRootKind::Directory);
    request.direction = FilesystemDirection::Down;
    request.scope = FilesystemScope::All;
    request.childDirectoryLinkAction = SymlinkPolicy::Follow;
    request.yieldType = FilesystemYieldType::SymbolicLinks; // No output pins: compare inverse peaks alone.
    auto resolved = ResolveFilesystemCollectionRequest(request);
    ASSERT_TRUE(resolved.HasValue()) << resolved.Error().message;

    // The link leaves the physical a/deep stack for b, while its inverse
    // still owns both popped ancestors and the other active inverse frames.
    {
        auto acquired = Path::Make(context, request.rootPath, CollectionRootPolicy(resolved.Value()), CollectionRootLimits(resolved.Value()));
        ASSERT_TRUE(acquired.HasValue()) << acquired.Error().message;
        ASSERT_TRUE(acquired.Value().Is<Path>());
        Path physical = As<Path>(std::move(acquired).Value());
        ASSERT_TRUE(physical.Freeze().HasValue());
        Path::Policy childPolicy;
        childPolicy.prefixLinks = ComplianceEngine::Filesystem::PrefixLinkPolicy::Follow;
        childPolicy.directoryLinks = ComplianceEngine::Filesystem::DirectoryLinkPolicy::Follow;
        childPolicy.mounts = ComplianceEngine::Filesystem::MountPolicy::CrossMounts;
        auto first = physical.Resolve("a", childPolicy);
        ASSERT_TRUE(first.HasValue()) << first.Error().message;
        ASSERT_TRUE(first.Value().Is<Path::Step>());
        auto undoA = physical.Apply(As<Path::Step>(std::move(first).Value()));
        ASSERT_TRUE(undoA.HasValue()) << undoA.Error().message;
        auto deep = physical.Resolve("deep", childPolicy);
        ASSERT_TRUE(deep.HasValue()) << deep.Error().message;
        ASSERT_TRUE(deep.Value().Is<Path::Step>());
        auto undoDeep = physical.Apply(As<Path::Step>(std::move(deep).Value()));
        ASSERT_TRUE(undoDeep.HasValue()) << undoDeep.Error().message;
        const std::size_t before = physical.Size();
        auto link = physical.Resolve("one", childPolicy);
        ASSERT_TRUE(link.HasValue()) << link.Error().message;
        ASSERT_TRUE(link.Value().Is<Path::Step>());
        auto undoLink = physical.Apply(As<Path::Step>(std::move(link).Value()));
        ASSERT_TRUE(undoLink.HasValue()) << undoLink.Error().message;
        EXPECT_LT(physical.Size(), before);
        EXPECT_GE(undoLink.Value().RetainedDescriptors(), 5u); // attach, barrier, b, a, deep
        EXPECT_GT(undoLink.Value().RetainedBytes(), 0u);
        EXPECT_GT(undoA.Value().RetainedDescriptors() + undoDeep.Value().RetainedDescriptors(), 0u);
    }

    struct OrderedCursor
    {
        ino_t inode;
        const char* const* names;
        std::size_t count;
        std::size_t position;
    };
    const char* rootNames[] = {"a", "b", "c", "d"};
    const char* aNames[] = {"deep", "last"};
    const char* deepNames[] = {"one", "two"};
    const char* bNames[] = {"hop"};
    const char* cNames[] = {"hop"};
    const char* dNames[] = {"leaf"};
    struct stat rootInfo = {}, aInfo = {}, deepInfo = {}, bInfo = {}, cInfo = {}, dInfo = {};
    ASSERT_EQ(0, ::stat(tree.Path("root").c_str(), &rootInfo));
    ASSERT_EQ(0, ::stat(tree.Path("root/a").c_str(), &aInfo));
    ASSERT_EQ(0, ::stat(tree.Path("root/a/deep").c_str(), &deepInfo));
    ASSERT_EQ(0, ::stat(tree.Path("root/b").c_str(), &bInfo));
    ASSERT_EQ(0, ::stat(tree.Path("root/c").c_str(), &cInfo));
    ASSERT_EQ(0, ::stat(tree.Path("root/d").c_str(), &dInfo));
    OrderedCursor cursors[] = {{rootInfo.st_ino, rootNames, 4, 0}, {aInfo.st_ino, aNames, 2, 0}, {deepInfo.st_ino, deepNames, 2, 0},
        {bInfo.st_ino, bNames, 1, 0}, {cInfo.st_ino, cNames, 1, 0}, {dInfo.st_ino, dNames, 1, 0}};
    struct dirent scripted = {};
    bool includeSecond = false;
    std::size_t firstVisits = 0, secondVisits = 0, laterVisits = 0;
    // Script a stable order without allocating or throwing from the native
    // noexcept seam; all filesystem objects remain real pinned acquisitions.
    ON_CALL(context, ReadDirectory(testing::_)).WillByDefault([&](DIR * stream) noexcept -> struct dirent* {
        struct stat held = {};
        if (0 != ::fstat(::dirfd(stream), &held))
            return nullptr;
        for (auto& cursor : cursors)
        {
            if (cursor.inode != held.st_ino)
                continue;
            const std::size_t count = (cursor.inode == deepInfo.st_ino && !includeSecond) ? 1 : cursor.count;
            if (cursor.position == count)
                return nullptr;
            const char* const name = cursor.names[cursor.position++];
            if (cursor.inode == deepInfo.st_ino)
            {
                if (0 == std::strcmp(name, "one"))
                    ++firstVisits;
                else
                    ++secondVisits;
            }
            if (cursor.inode == aInfo.st_ino && 0 == std::strcmp(name, "last"))
                ++laterVisits;
            const std::size_t bytes = std::strlen(name) + 1;
            if (bytes > sizeof(scripted.d_name))
            {
                errno = ENAMETOOLONG;
                return nullptr;
            }
            std::memcpy(scripted.d_name, name, bytes);
            scripted.d_type = DT_UNKNOWN;
            return &scripted;
        }
        errno = EBADF;
        return nullptr;
    });
    // The same pinned directory may be opened again by the next logical
    // sibling. Reset only when that cursor closes, not when another is read.
    ON_CALL(context, CloseDirectory(testing::_)).WillByDefault([&](DIR* stream) noexcept -> ComplianceEngine::Result<void> {
        struct stat held = {};
        if (0 == ::fstat(::dirfd(stream), &held))
            for (auto& cursor : cursors)
                if (cursor.inode == held.st_ino)
                    cursor.position = 0;
        return ::closedir(stream) == 0 ? ComplianceEngine::Result<void>::Success() : ComplianceEngine::Result<void>(ComplianceEngine::Error(errno));
    });
    const auto scan = [&](std::size_t cap, bool bytes, bool both) -> int {
        for (auto& cursor : cursors)
            cursor.position = 0;
        firstVisits = secondVisits = laterVisits = 0;
        includeSecond = both;
        auto limits = CollectionRootLimits(resolved.Value());
        if (bytes)
            limits.shared.retainedBytes = cap;
        else
            limits.shared.liveDescriptors = cap;
        auto acquired = Path::Make(context, request.rootPath, CollectionRootPolicy(resolved.Value()), limits);
        if (!acquired.HasValue())
            return acquired.Error().code;
        if (!acquired.Value().Is<Path>())
            return ENOENT;
        auto range = Files(As<Path>(std::move(acquired).Value()), request.rootPath, CollectionContinuation(resolved.Value()));
        if (!range.HasValue())
            return range.Error().code;
        for (const auto& entry : range.Value())
            if (!entry.HasValue())
                return entry.Error().code;
        range->Stop();
        return 0;
    };
    for (const bool bytes : {false, true})
    {
        SCOPED_TRACE(bytes ? "retained bytes" : "descriptors");
        std::size_t low = 1;
        std::size_t high = bytes ? 262144 : 256;
        ASSERT_EQ(0, scan(high, bytes, false));
        while (low + 1 < high)
        {
            const std::size_t middle = low + (high - low) / 2;
            if (0 == scan(middle, bytes, false))
                high = middle;
            else
                low = middle;
        }
        EXPECT_EQ(0, scan(high, bytes, false));
        EXPECT_EQ(bytes ? E2BIG : EMFILE, scan(high - 1, bytes, false));
        // Both equal-length sibling links must fit at the exact one-link
        // limit: the first inverse is refunded before the second is charged.
        EXPECT_EQ(0, scan(high, bytes, true));
        EXPECT_EQ(1u, firstVisits);
        EXPECT_EQ(1u, secondVisits);
        EXPECT_EQ(1u, laterVisits);
        EXPECT_EQ(bytes ? E2BIG : EMFILE, scan(high - 1, bytes, true));
    }
}

TEST(FilesystemCollectionTest, IteratorOverlapRetainsBothOutputPinCharges)
{
    ::testing::StrictMock<MockContext> context;
    // No EXPECT_CALL in this test constrains any native seam.
    context.AllowIncidentalNativeAccess();
    TestTree tree;
    tree.Directory("root");
    // Equal-width sibling names make each acquired Step's charge identical.
    for (int i = 100; i <= 164; ++i)
        tree.File("root/" + std::to_string(i));
    FilesystemCollectionRequest request(tree.Path("root"), FilesystemRootKind::Directory);
    request.direction = FilesystemDirection::Down; // Traverse children, not just observe the root.
    request.scope = FilesystemScope::All;
    request.yieldType = FilesystemYieldType::RegularFiles;
    auto resolved = ResolveFilesystemCollectionRequest(request);
    ASSERT_TRUE(resolved.HasValue()) << resolved.Error().message;

    std::size_t stepBytes = 0;
    {
        auto observed = Path::Make(context, request.rootPath, CollectionRootPolicy(resolved.Value()), CollectionRootLimits(resolved.Value()));
        ASSERT_TRUE(observed.HasValue()) << observed.Error().message;
        ASSERT_TRUE(observed.Value().Is<Path>());
        Path physical = As<Path>(std::move(observed).Value());
        ASSERT_TRUE(physical.Freeze().HasValue());
        Path::Policy childPolicy;
        childPolicy.prefixLinks = ComplianceEngine::Filesystem::PrefixLinkPolicy::Follow;
        childPolicy.directoryLinks = ComplianceEngine::Filesystem::DirectoryLinkPolicy::Follow;
        childPolicy.mounts = ComplianceEngine::Filesystem::MountPolicy::CrossMounts;
        auto target = physical.Resolve("100", childPolicy);
        ASSERT_TRUE(target.HasValue()) << target.Error().message;
        ASSERT_TRUE(target.Value().Is<Path::Step>());
        stepBytes = As<Path::Step>(target.Value()).RetainedBytes();
        ASSERT_GT(stepBytes, 0u);
    } // Release independent Step and Path pins before measuring traversal.

    // Separate iterator values retain live entries while further begin() pulls
    // from the same single-pass range. Stop cannot refund those external pins.
    const auto scan = [&](std::size_t cap, std::size_t count, bool releaseBeforeLast) -> int {
        auto limits = CollectionRootLimits(resolved.Value());
        limits.shared.retainedBytes = cap;
        limits.shared.liveDescriptors = 512; // Isolate retained bytes from the descriptor axis.
        auto root = Path::Make(context, request.rootPath, CollectionRootPolicy(resolved.Value()), limits);
        if (!root.HasValue())
            return root.Error().code;
        if (!root.Value().Is<Path>())
            return ENOENT;
        auto range = Files(As<Path>(std::move(root).Value()), request.rootPath, CollectionContinuation(resolved.Value()));
        if (!range.HasValue())
            return range.Error().code;
        std::vector<ComplianceEngine::Filesystem::FTW::FileRange::Iterator> held;
        held.reserve(count);
        for (std::size_t i = 0; i < count; ++i)
        {
            if (releaseBeforeLast && i + 1 == count)
                held.pop_back();
            auto next = range->begin();
            if (next == range->end())
                return ENOENT;
            if (!next->HasValue())
                return next->Error().code;
            held.push_back(std::move(next));
        }
        range->Stop();
        return 0;
    };
    // Advance the very iterator that owns output 63. Releasing another
    // iterator proves the next pull is affordable without discarding mCurrent;
    // an extra measured output charge proves the same at the larger cap.
    const auto advanceHeld = [&](std::size_t cap, bool releaseOther) -> int {
        auto limits = CollectionRootLimits(resolved.Value());
        limits.shared.retainedBytes = cap;
        limits.shared.liveDescriptors = 512;
        auto root = Path::Make(context, request.rootPath, CollectionRootPolicy(resolved.Value()), limits);
        if (!root.HasValue())
            return root.Error().code;
        if (!root.Value().Is<Path>())
            return ENOENT;
        auto range = Files(As<Path>(std::move(root).Value()), request.rootPath, CollectionContinuation(resolved.Value()));
        if (!range.HasValue())
            return range.Error().code;
        std::vector<ComplianceEngine::Filesystem::FTW::FileRange::Iterator> held;
        held.reserve(63);
        for (std::size_t i = 0; i < 63; ++i)
        {
            auto next = range->begin();
            if (next == range->end())
                return ENOENT;
            if (!next->HasValue())
                return next->Error().code;
            held.push_back(std::move(next));
        }
        const std::string previous = held.back()->Value().path;
        if (releaseOther)
            held.front() = ComplianceEngine::Filesystem::FTW::FileRange::Iterator();
        ++held.back(); // The old mCurrent must remain charged during Next().
        if (held.back() == range->end())
            return ENOENT;
        if (!held.back()->HasValue())
            return held.back()->Error().code;
        if (held.back()->Value().path == previous)
            return EINVAL;
        range->Stop();
        return 0;
    };
    const auto minimum = [&](std::size_t count) -> std::size_t {
        std::size_t low = 1, high = 262144;
        EXPECT_EQ(0, scan(high, count, false));
        while (low + 1 < high)
        {
            const std::size_t middle = low + (high - low) / 2;
            if (0 == scan(middle, count, false))
                high = middle;
            else
                low = middle;
        }
        EXPECT_EQ(0, scan(high, count, false));
        EXPECT_EQ(E2BIG, scan(high - 1, count, false));
        return high;
    };
    const std::size_t oneOutputPeak = minimum(1);
    const std::size_t single = minimum(63);
    const std::size_t overlap = minimum(64);
    // At 63 retained outputs the one-entry Path acquisition peak cannot
    // dominate: the Step owners alone exceed it. The 64th output must
    // add its measured pin charge, and releasing one owner permits its reuse.
    ASSERT_GT(63 * stepBytes, oneOutputPeak);
    ASSERT_GT(single, oneOutputPeak);
    ASSERT_GT(overlap, single);
    EXPECT_GE(overlap - single, stepBytes);
    EXPECT_EQ(E2BIG, scan(single, 64, false));
    EXPECT_EQ(0, scan(single, 64, true));
    EXPECT_EQ(E2BIG, advanceHeld(single, false));
    EXPECT_EQ(0, advanceHeld(single, true));
    EXPECT_EQ(0, advanceHeld(overlap, false));
}

TEST(FilesystemCollectionTest, ExhaustionKeepsCollectedEntriesAndSkippedRootExclusion)
{
    TestTree tree;
    tree.Directory("root");
    tree.File("root/item");
    tree.Link("item", "root/skipped");
    FilesystemCollectionRequest request(tree.Path("root"), FilesystemRootKind::Directory);
    request.direction = FilesystemDirection::Down;
    auto collected = CollectFilesystem(request);
    ASSERT_TRUE(collected.HasValue()) << collected.Error().message;
    ASSERT_EQ(2u, collected->entries.size());
    EXPECT_EQ((std::vector<std::string>{tree.Path("root"), tree.Path("root/item")}), Paths(collected->entries));
    ASSERT_EQ(1u, collected->exclusions.size());
    EXPECT_EQ(tree.Path("root/skipped"), collected->exclusions[0].path);
    EXPECT_EQ("link policy", collected->exclusions[0].reason);

    std::vector<std::string> streamedPaths;
    auto streamed = StreamFilesystemCollection(request, [&](const FilesystemCollectionEntry& entry) {
        streamedPaths.push_back(entry.path);
        return Result<FilesystemVisitAction>(FilesystemVisitAction::Continue);
    });
    ASSERT_TRUE(streamed.HasValue()) << streamed.Error().message;
    EXPECT_EQ((std::vector<std::string>{tree.Path("root"), tree.Path("root/item")}), streamedPaths);
    EXPECT_TRUE(streamed->entries.empty());
    ASSERT_EQ(1u, streamed->exclusions.size());
    EXPECT_EQ(tree.Path("root/skipped"), streamed->exclusions[0].path);
    EXPECT_EQ("link policy", streamed->exclusions[0].reason);

    ::testing::StrictMock<MockContext> context;
    // No EXPECT_CALL in this test constrains any native seam.
    context.AllowIncidentalNativeAccess();
    auto range = Files(request, context);
    ASSERT_TRUE(range.HasValue()) << range.Error().message;
    EXPECT_TRUE(range->RootExists());
    std::vector<std::string> visitedPaths;
    for (const auto& entry : range.Value())
    {
        ASSERT_TRUE(entry.HasValue()) << entry.Error().message;
        visitedPaths.push_back(entry.Value().path);
    }
    EXPECT_EQ((std::vector<std::string>{tree.Path("root"), tree.Path("root/item")}), visitedPaths);
    range->Stop();

    tree.Link("root", "alias");
    FilesystemCollectionRequest skipped(tree.Path("alias"), FilesystemRootKind::Directory);
    auto skippedCollection = CollectFilesystem(skipped);
    ASSERT_TRUE(skippedCollection.HasValue()) << skippedCollection.Error().message;
    EXPECT_TRUE(skippedCollection->entries.empty());
    ASSERT_EQ(1u, skippedCollection->exclusions.size());
    EXPECT_EQ(tree.Path("alias"), skippedCollection->exclusions[0].path);
    EXPECT_EQ("link policy", skippedCollection->exclusions[0].reason);

    std::size_t skippedVisits = 0;
    auto skippedStream = StreamFilesystemCollection(skipped, [&](const FilesystemCollectionEntry&) {
        ++skippedVisits;
        return Result<FilesystemVisitAction>(FilesystemVisitAction::Continue);
    });
    ASSERT_TRUE(skippedStream.HasValue()) << skippedStream.Error().message;
    EXPECT_EQ(0u, skippedVisits);
    EXPECT_TRUE(skippedStream->entries.empty());
    ASSERT_EQ(1u, skippedStream->exclusions.size());
    EXPECT_EQ(tree.Path("alias"), skippedStream->exclusions[0].path);
    EXPECT_EQ("link policy", skippedStream->exclusions[0].reason);

    auto empty = Files(skipped, context);
    ASSERT_TRUE(empty.HasValue()) << empty.Error().message;
    EXPECT_TRUE(empty->RootExists());
    EXPECT_EQ(empty->begin(), empty->end());
    empty->Stop();
}

TEST(FilesystemCollectionTest, RootDirectoryLinkSkipIsAnExclusionNotAnAbsentRoot)
{
    TestTree tree;
    tree.Directory("target");
    tree.File("target/item");
    tree.Link(tree.Path("target"), "target/descendant-link");
    tree.Link(tree.Path("target"), "alias");
    FilesystemCollectionRequest request(tree.Path("alias"), FilesystemRootKind::Directory);
    const auto skipped = CollectFilesystem(request);
    ASSERT_TRUE(skipped.HasValue());
    EXPECT_TRUE(skipped->entries.empty());
    ASSERT_EQ(1u, skipped->exclusions.size());
    EXPECT_EQ(tree.Path("alias"), skipped->exclusions[0].path);
    EXPECT_EQ("link policy", skipped->exclusions[0].reason);

    ::testing::StrictMock<MockContext> context;
    // No EXPECT_CALL in this test constrains any native seam.
    context.AllowIncidentalNativeAccess();
    auto range = Files(request, context);
    ASSERT_TRUE(range.HasValue());
    EXPECT_TRUE(range->RootExists());
    EXPECT_EQ(range->begin(), range->end());
    range->Stop();
    const auto streamed = ComplianceEngine::Filesystem::StreamFilesystemCollection(
        request, [](const FilesystemCollectionEntry&) { return Result<FilesystemVisitAction>(FilesystemVisitAction::Continue); }, context);
    ASSERT_TRUE(streamed.HasValue());
    EXPECT_TRUE(streamed->entries.empty());
    ASSERT_EQ(1u, streamed->exclusions.size());
    EXPECT_EQ(tree.Path("alias"), streamed->exclusions[0].path);

    request.rootDirectoryLinkAction = SymlinkPolicy::Follow;
    const auto followed = CollectFilesystem(request);
    ASSERT_TRUE(followed.HasValue());
    EXPECT_EQ(2u, followed->entries.size());
    EXPECT_TRUE(S_ISDIR(followed->entries[0].metadata.st_mode));
    ASSERT_EQ(1u, followed->exclusions.size());
    EXPECT_EQ(tree.Path("alias/descendant-link"), followed->exclusions[0].path);
    EXPECT_EQ("link policy", followed->exclusions[0].reason);
}

TEST(FilesystemCollectionTest, RootFileLinkAndChildFileLinkUseIndependentSettings)
{
    TestTree tree;
    tree.File("target");
    tree.Link(tree.Path("target"), "alias");
    tree.Directory("root");
    tree.File("root/target");
    tree.Link(tree.Path("root/target"), "root/alias");

    FilesystemCollectionRequest file(tree.Path("alias"), FilesystemRootKind::File);
    const auto skippedRoot = CollectFilesystem(file);
    ASSERT_TRUE(skippedRoot.HasValue());
    EXPECT_TRUE(skippedRoot->entries.empty());
    ASSERT_EQ(1u, skippedRoot->exclusions.size());
    EXPECT_EQ(tree.Path("alias"), skippedRoot->exclusions[0].path);
    EXPECT_EQ("link policy", skippedRoot->exclusions[0].reason);

    file.rootFileLinkAction = SymlinkPolicy::Follow;
    const auto followedRoot = CollectFilesystem(file);
    ASSERT_TRUE(followedRoot.HasValue());
    ASSERT_EQ(1u, followedRoot->entries.size());
    EXPECT_TRUE(S_ISREG(followedRoot->entries[0].metadata.st_mode));
    EXPECT_TRUE(followedRoot->exclusions.empty());

    FilesystemCollectionRequest children(tree.Path("root"), FilesystemRootKind::Directory);
    children.yieldType = FilesystemYieldType::RegularFiles;
    const auto skippedChild = CollectFilesystem(children);
    ASSERT_TRUE(skippedChild.HasValue());
    EXPECT_EQ(std::vector<std::string>{tree.Path("root/target")}, Paths(skippedChild->entries));
    ASSERT_EQ(1u, skippedChild->exclusions.size());
    EXPECT_EQ(tree.Path("root/alias"), skippedChild->exclusions[0].path);

    children.childFileLinkAction = SymlinkPolicy::Follow;
    const auto followedChild = CollectFilesystem(children);
    ASSERT_TRUE(followedChild.HasValue());
    ASSERT_EQ(2u, followedChild->entries.size());
    const auto alias = std::find_if(followedChild->entries.begin(), followedChild->entries.end(),
        [&tree](const FilesystemCollectionEntry& entry) { return entry.path == tree.Path("root/alias"); });
    ASSERT_NE(followedChild->entries.end(), alias);
    EXPECT_TRUE(S_ISREG(alias->metadata.st_mode));
    EXPECT_TRUE(followedChild->exclusions.empty());

    children.yieldType = FilesystemYieldType::SymbolicLinks;
    const auto linkSelection = CollectFilesystem(children);
    ASSERT_TRUE(linkSelection.HasValue());
    EXPECT_TRUE(linkSelection->entries.empty()); // Selection uses effective target type.
    EXPECT_TRUE(linkSelection->exclusions.empty());
}

TEST(FilesystemCollectionTest, SkippedDanglingLinksDoNotStatTargetsOrBecomeMissingRoots)
{
    TestTree tree;
    tree.Directory("root");
    tree.Link("missing", "root/dangling");
    ::testing::StrictMock<MockContext> context;
    // No EXPECT_CALL in this test constrains any native seam.
    context.AllowIncidentalNativeAccess();
    int targetStats = 0;
    ON_CALL(context, StatPath(testing::_, testing::_)).WillByDefault([&](const char* path, struct stat* metadata) {
        ++targetStats;
        return context.ContextInterface::StatPath(path, metadata);
    });
    FilesystemCollectionRequest request(tree.Path("root/dangling"), FilesystemRootKind::File);
    const auto skipped = ComplianceEngine::Filesystem::CollectFilesystem(request, context);
    ASSERT_TRUE(skipped.HasValue());
    EXPECT_TRUE(skipped->entries.empty());
    ASSERT_EQ(1u, skipped->exclusions.size());
    EXPECT_EQ(tree.Path("root/dangling"), skipped->exclusions[0].path);
    EXPECT_EQ("link policy", skipped->exclusions[0].reason);
    EXPECT_EQ(0, targetStats);

    request.rootPath = tree.Path("root");
    request.rootKind = FilesystemRootKind::Directory;
    const auto child = ComplianceEngine::Filesystem::CollectFilesystem(request, context);
    ASSERT_TRUE(child.HasValue());
    EXPECT_EQ(std::vector<std::string>{tree.Path("root")}, Paths(child->entries));
    ASSERT_EQ(1u, child->exclusions.size());
    EXPECT_EQ(tree.Path("root/dangling"), child->exclusions[0].path);
    EXPECT_EQ(0, targetStats);
    request.childFileLinkAction = SymlinkPolicy::Follow;
    request.childDirectoryLinkAction = SymlinkPolicy::Follow;
    const auto followed = ComplianceEngine::Filesystem::CollectFilesystem(request, context);
    ASSERT_FALSE(followed.HasValue());
    EXPECT_EQ(ENOENT, followed.Error().code);
    EXPECT_EQ(0, targetStats); // Descendant acquisition is confined to held descriptors.
}

TEST(FilesystemCollectionTest, FollowingDanglingLinkFailsRatherThanReturningAbsentRoot)
{
    TestTree tree;
    tree.Link(tree.Path("missing"), "dangling");
    FilesystemCollectionRequest request(tree.Path("dangling"), FilesystemRootKind::File);
    request.rootFileLinkAction = SymlinkPolicy::Follow;
    request.rootDirectoryLinkAction = SymlinkPolicy::Follow;
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

TEST(FilesystemCollectionTest, FileRootPinAndSnapshotHaveAnExactRetainedBudgetBoundary)
{
    TestTree tree;
    tree.File("file");
    FilesystemCollectionRequest request(tree.Path("file"), FilesystemRootKind::File);
    // The separate resolver retained-byte ceiling can reject earlier than
    // collection path storage. Find the effective boundary for this fixture.
    long long low = static_cast<long long>(request.rootPath.size());
    long long high = 32768;
    request.retainedPathBytes = high;
    ASSERT_TRUE(CollectFilesystem(request).HasValue());
    while (low + 1 < high)
    {
        const long long middle = low + (high - low) / 2;
        request.retainedPathBytes = middle;
        if (CollectFilesystem(request).HasValue())
        {
            high = middle;
        }

        else
        {
            low = middle;
        }
    }
    request.retainedPathBytes = high;
    EXPECT_TRUE(CollectFilesystem(request).HasValue());
    request.retainedPathBytes = high - 1;
    const auto exceeded = CollectFilesystem(request);
    ASSERT_FALSE(exceeded.HasValue());
    EXPECT_EQ(E2BIG, exceeded.Error().code);
}

TEST(FilesystemCollectionTest, ReplacingPinnedChildLinkKeepsAcceptedTargetIdentity)
{
    TestTree tree;
    tree.Directory("root");
    tree.File("root/first");
    tree.File("root/second");
    tree.Link("first", "root/alias");
    struct stat original = {};
    ASSERT_EQ(0, lstat(tree.Path("root/alias").c_str(), &original));
    ::testing::StrictMock<MockContext> context;
    // No EXPECT_CALL in this test constrains any native seam.
    context.AllowIncidentalNativeAccess();
    bool replaced = false;
    int renameStatus = -1;
    int renameError = 0;
    int symlinkStatus = -1;
    int symlinkError = 0;
    const std::string aliasName = tree.Path("root/alias");
    const std::string oldAliasName = tree.Path("root/old-alias");
    ON_CALL(context, StatFileDescriptor(testing::_, testing::_)).WillByDefault([&](int descriptor, struct stat* metadata) {
        const int result = fstat(descriptor, metadata);
        if (!replaced && 0 == result && S_ISLNK(metadata->st_mode) && metadata->st_ino == original.st_ino && metadata->st_dev == original.st_dev)
        {
            replaced = true;
            renameStatus = rename(aliasName.c_str(), oldAliasName.c_str());
            if (renameStatus != 0)
                renameError = errno;
            symlinkStatus = symlink("second", aliasName.c_str());
            if (symlinkStatus != 0)
                symlinkError = errno;
        }
        return result;
    });
    FilesystemCollectionRequest request(tree.Path("root"), FilesystemRootKind::Directory);
    request.direction = FilesystemDirection::Down;
    request.childFileLinkAction = SymlinkPolicy::Follow;
    request.yieldType = FilesystemYieldType::RegularFiles;
    const auto collected = ComplianceEngine::Filesystem::CollectFilesystem(request, context);
    EXPECT_TRUE(replaced);
    EXPECT_EQ(0, renameStatus) << renameError;
    EXPECT_EQ(0, symlinkStatus) << symlinkError;
    ASSERT_TRUE(collected.HasValue()) << collected.Error().message;
    const auto& entries = collected->entries;
    auto alias =
        std::find_if(entries.begin(), entries.end(), [&](const FilesystemCollectionEntry& entry) { return entry.path == tree.Path("root/alias"); });
    ASSERT_NE(entries.end(), alias);
    // The pinned link is used for resolution, but only its accepted target
    // observation is published even after the name is replaced.
    struct stat first = {};
    ASSERT_EQ(0, stat(tree.Path("root/first").c_str(), &first));
    EXPECT_EQ(first.st_ino, alias->metadata.st_ino);
}

TEST(FilesystemCollectionTest, ReplacingPinnedRootLinkKeepsAcceptedTargetIdentity)
{
    TestTree tree;
    tree.File("first");
    tree.File("second");
    tree.Link("first", "alias");
    ::testing::StrictMock<MockContext> context;
    // No EXPECT_CALL in this test constrains any native seam.
    context.AllowIncidentalNativeAccess();
    struct stat original = {};
    ASSERT_EQ(0, lstat(tree.Path("alias").c_str(), &original));
    bool replaced = false;
    int renameStatus = -1;
    int renameError = 0;
    int symlinkStatus = -1;
    int symlinkError = 0;
    const std::string aliasName = tree.Path("alias");
    const std::string oldAliasName = tree.Path("old-alias");
    ON_CALL(context, StatFileDescriptor(testing::_, testing::_)).WillByDefault([&](int descriptor, struct stat* metadata) {
        const int result = fstat(descriptor, metadata);
        if (!replaced && result == 0 && S_ISLNK(metadata->st_mode) && metadata->st_ino == original.st_ino)
        {
            replaced = true;
            renameStatus = rename(aliasName.c_str(), oldAliasName.c_str());
            if (renameStatus != 0)
                renameError = errno;
            symlinkStatus = symlink("second", aliasName.c_str());
            if (symlinkStatus != 0)
                symlinkError = errno;
        }
        return result;
    });
    FilesystemCollectionRequest request(tree.Path("alias"), FilesystemRootKind::File);
    request.rootFileLinkAction = SymlinkPolicy::Follow;
    const auto opened = CollectFilesystem(request, context);
    EXPECT_TRUE(replaced);
    EXPECT_EQ(0, renameStatus) << renameError;
    EXPECT_EQ(0, symlinkStatus) << symlinkError;
    ASSERT_TRUE(opened.HasValue()) << opened.Error().message;
    ASSERT_EQ(1u, opened->entries.size());
    const auto& entry = opened->entries.front();
    // A replacement name cannot change the accepted pinned target snapshot.
    struct stat first = {};
    ASSERT_EQ(0, stat(tree.Path("first").c_str(), &first));
    EXPECT_EQ(first.st_ino, entry.metadata.st_ino);
}

TEST(FilesystemCollectionTest, FactoryPropagatesNativeRootOpenFailureWithoutTreatingItAsMissing)
{
    ::testing::StrictMock<MockContext> context;
    // No EXPECT_CALL in this test constrains any native seam.
    context.AllowIncidentalNativeAccess();
    ON_CALL(context, OpenNativePath(testing::_, testing::_)).WillByDefault([](const char*, int) -> int {
        errno = EACCES;
        return -1;
    });
    const auto opened = Files(Request(), context);
    ASSERT_FALSE(opened.HasValue());
    EXPECT_EQ(EACCES, opened.Error().code);
}

TEST(FilesystemCollectionTest, SkippedRootLinkStillChargesItsExclusion)
{
    TestTree tree;
    tree.File("target");
    tree.Link(tree.Path("target"), "alias");
    FilesystemCollectionRequest request(tree.Path("alias"), FilesystemRootKind::File);
    const long long exclusionBytes = static_cast<long long>(request.rootPath.size() + 1);
    request.retainedPathBytes = exclusionBytes;
    const auto exact = CollectFilesystem(request);
    ASSERT_TRUE(exact.HasValue());
    EXPECT_TRUE(exact->entries.empty());
    ASSERT_EQ(1u, exact->exclusions.size());
    request.retainedPathBytes = exclusionBytes - 1;
    const auto exceeded = CollectFilesystem(request);
    ASSERT_FALSE(exceeded.HasValue());
    EXPECT_EQ(E2BIG, exceeded.Error().code);
}

TEST(FilesystemCollectionTest, UnsupportedObjectsRejectByDefaultAndSkipOnlyWhenRequested)
{
    TestTree tree;
    tree.Directory("root");
    const std::string special = tree.Path("root/special");
    ASSERT_EQ(0, ::mkfifo(special.c_str(), 0600));
    tree.Link("special", "root/alias");
    FilesystemCollectionRequest request(tree.Path("root"), FilesystemRootKind::Directory);
    request.direction = FilesystemDirection::Down;
    request.scope = FilesystemScope::All;
    request.childFileLinkAction = SymlinkPolicy::Follow;
    request.childDirectoryLinkAction = SymlinkPolicy::Follow;
    const auto rejected = CollectFilesystem(request);
    ASSERT_FALSE(rejected.HasValue());
    EXPECT_EQ(EOPNOTSUPP, rejected.Error().code);

    request.unsupported = UnsupportedTypeDisposition::Skip;
    const auto skipped = CollectFilesystem(request);
    ASSERT_TRUE(skipped.HasValue()) << skipped.Error().message;
    EXPECT_EQ(std::vector<std::string>{tree.Path("root")}, Paths(skipped->entries));
    ASSERT_EQ(2u, skipped->exclusions.size());
    for (const auto& excluded : skipped->exclusions)
        EXPECT_EQ("unsupported type", excluded.reason);

    FilesystemCollectionRequest unsupportedRoot(special, FilesystemRootKind::File);
    unsupportedRoot.unsupported = UnsupportedTypeDisposition::Skip;
    const auto root = CollectFilesystem(unsupportedRoot);
    ASSERT_FALSE(root.HasValue());
    EXPECT_EQ(EOPNOTSUPP, root.Error().code);
}

TEST(FilesystemCollectionTest, UnsupportedSkipDoesNotTurnMissingRegularChildIntoExclusion)
{
    TestTree tree;
    tree.Directory("root");
    tree.File("root/lost");
    ::testing::StrictMock<MockContext> context;
    // No EXPECT_CALL in this test constrains any native seam.
    context.AllowIncidentalNativeAccess();
    ON_CALL(context, OpenNativeAt(testing::_, testing::_, testing::_)).WillByDefault([&](int directory, const char* name, int flags) {
        if (std::strcmp(name, "lost") == 0)
        {
            errno = ENOENT;
            return -1;
        }
        return context.RealOpenNativeAt(directory, name, flags);
    });
    FilesystemCollectionRequest request(tree.Path("root"), FilesystemRootKind::Directory);
    request.direction = FilesystemDirection::Down;
    request.unsupported = UnsupportedTypeDisposition::Skip;
    const auto missing = CollectFilesystem(request, context);
    ASSERT_FALSE(missing.HasValue());
    EXPECT_EQ(ENOENT, missing.Error().code);
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
    request.openDirectories = 128;
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
    ::testing::StrictMock<MockContext> context;
    // No EXPECT_CALL in this test constrains any native seam.
    context.AllowIncidentalNativeAccess();
    ON_CALL(context, ReadDirectory(testing::_)).WillByDefault([](DIR*) -> struct dirent* {
        errno = EIO;
        return nullptr;
    });
    const auto result = ComplianceEngine::Filesystem::CollectFilesystem(FilesystemCollectionRequest(tree.Path("root"), FilesystemRootKind::Directory), context);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EIO, result.Error().code);
    EXPECT_NE(std::string::npos, result.Error().message.find(tree.Path("root")));
}

TEST(FilesystemCollectionTest, RequiredStatFailurePropagatesItsOriginalCode)
{
    TestTree tree;
    tree.Directory("root");
    ::testing::StrictMock<MockContext> context;
    // No EXPECT_CALL in this test constrains any native seam.
    context.AllowIncidentalNativeAccess();
    ON_CALL(context, StatFileDescriptor(testing::_, testing::_)).WillByDefault([](int, struct stat*) {
        errno = EACCES;
        return -1;
    });
    const auto result = ComplianceEngine::Filesystem::CollectFilesystem(FilesystemCollectionRequest(tree.Path("root"), FilesystemRootKind::Directory), context);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EACCES, result.Error().code);
}

TEST(FilesystemCollectionTest, StandaloneCloseFailureDoesNotReplaceResultsOrCallbackError)
{
    TestTree tree;
    tree.Directory("root");
    tree.File("root/child");
    ::testing::StrictMock<MockContext> context;
    // No EXPECT_CALL in this test constrains any native seam.
    context.AllowIncidentalNativeAccess();
    ON_CALL(context, CloseDirectory(testing::_)).WillByDefault([](DIR* stream) {
        const int status = closedir(stream);
        if (0 != status)
        {
            return ComplianceEngine::Result<void>(ComplianceEngine::Error(errno));
        }
        errno = EIO;
        return ComplianceEngine::Result<void>(ComplianceEngine::Error(errno));
    });
    const FilesystemCollectionRequest request(tree.Path("root"), FilesystemRootKind::Directory);
    const auto standalone = ComplianceEngine::Filesystem::CollectFilesystem(request, context);
    ASSERT_TRUE(standalone.HasValue()) << standalone.Error().message;
    EXPECT_EQ(2u, standalone->entries.size());

    const auto secondary = ComplianceEngine::Filesystem::StreamFilesystemCollection(
        request,
        [&tree](const FilesystemCollectionEntry& entry) {
            if (entry.path == tree.Path("root/child"))
            {
                return Result<FilesystemVisitAction>(ComplianceEngine::Error("original callback", EACCES));
            }
            return Result<FilesystemVisitAction>(FilesystemVisitAction::Continue);
        },
        context);
    ASSERT_FALSE(secondary.HasValue());
    EXPECT_EQ(EACCES, secondary.Error().code);
    EXPECT_EQ("original callback", secondary.Error().message);
}

TEST(FilesystemCollectionTest, ChildCloseFailureDoesNotStopTraversal)
{
    TestTree tree;
    tree.Directory("root");
    tree.Directory("root/child");
    FilesystemCollectionRequest request(tree.Path("root"), FilesystemRootKind::Directory);
    request.direction = FilesystemDirection::Down;
    ::testing::StrictMock<MockContext> context;
    // No EXPECT_CALL in this test constrains any native seam.
    context.AllowIncidentalNativeAccess();
    ON_CALL(context, CloseDirectory(testing::_)).WillByDefault([](DIR* stream) {
        const int status = closedir(stream);
        if (0 != status)
        {
            return ComplianceEngine::Result<void>(ComplianceEngine::Error(errno));
        }
        errno = EIO;
        return ComplianceEngine::Result<void>(ComplianceEngine::Error(errno));
    });
    const auto result = ComplianceEngine::Filesystem::CollectFilesystem(request, context);
    ASSERT_TRUE(result.HasValue()) << result.Error().message;
    EXPECT_EQ(2u, result->entries.size());
}

TEST(FilesystemCollectionTest, RootDeviceAndDefinedSelectSameMount)
{
    TestTree tree;
    tree.Directory("root");
    tree.File("root/other-device");
    ::testing::StrictMock<MockContext> context;
    // No EXPECT_CALL in this test constrains any native seam.
    context.AllowIncidentalNativeAccess();
    FilesystemCollectionRequest request(tree.Path("root"), FilesystemRootKind::Directory);
    const auto bounded = ComplianceEngine::Filesystem::CollectFilesystem(request, context);
    ASSERT_TRUE(bounded.HasValue());
    EXPECT_EQ(2u, bounded->entries.size());
    EXPECT_TRUE(bounded->exclusions.empty());

    request.scope = FilesystemScope::Defined;
    const auto defined = ComplianceEngine::Filesystem::CollectFilesystem(request, context);
    ASSERT_TRUE(defined.HasValue());
    EXPECT_EQ(2u, defined->entries.size());
    EXPECT_TRUE(defined->exclusions.empty());

    request.scope = FilesystemScope::All;
    const auto all = ComplianceEngine::Filesystem::CollectFilesystem(request, context);
    ASSERT_TRUE(all.HasValue());
    EXPECT_EQ(2u, all->entries.size());
    EXPECT_TRUE(all->exclusions.empty());
}

TEST(FilesystemCollectionTest, MountScopeFiltersBothLookupAndTargetFactsWithoutMountChanges)
{
    TestTree tree;
    tree.Directory("root");
    tree.File("root/target");
    tree.File("root/stay");
    tree.Link("target", "root/alias");
    for (int changedFact = 0; changedFact != 2; ++changedFact)
    {
        SCOPED_TRACE(changedFact);
        ::testing::StrictMock<MockContext> context;
        // No EXPECT_CALL in this test constrains any native seam.
        context.AllowIncidentalNativeAccess();
        const std::string spoofedPath = tree.Path(changedFact == 0 ? "root/alias" : "root/target");
        std::size_t changed = 0;
        // Spoof ONLY the sealed context fdinfo read for this pinned object;
        // neither the namespace nor a production mount accessor is changed.
        ON_CALL(context, ReadFileDescriptor(testing::_, testing::_, testing::_)).WillByDefault([&](int fd, void* buffer, std::size_t size) -> ssize_t {
            const ssize_t bytes = context.RealReadFileDescriptor(fd, buffer, size);
            if (bytes <= 0)
                return bytes;
            char fdinfo[64] = {};
            const int fdinfoLength = std::snprintf(fdinfo, sizeof(fdinfo), "/proc/self/fd/%d", fd);
            if (fdinfoLength < 0 || static_cast<std::size_t>(fdinfoLength) >= sizeof(fdinfo))
                return bytes;
            char target[256] = {};
            const ssize_t n = ::readlink(fdinfo, target, sizeof(target) - 1);
            if (n <= 0)
                return bytes;
            target[n] = '\0';
            const char* marker = std::strstr(target, "/fdinfo/");
            if (!marker)
                return bytes;
            char pinned[64] = {};
            const int pinnedLength = std::snprintf(pinned, sizeof(pinned), "/proc/self/fd/%s", marker + 8);
            if (pinnedLength < 0 || static_cast<std::size_t>(pinnedLength) >= sizeof(pinned))
                return bytes;
            const ssize_t targetBytes = ::readlink(pinned, target, sizeof(target));
            if (targetBytes <= 0 || static_cast<std::size_t>(targetBytes) != spoofedPath.size() ||
                0 != std::memcmp(target, spoofedPath.data(), static_cast<std::size_t>(targetBytes)))
                return bytes;
            char* const begin = static_cast<char*>(buffer);
            char* const end = begin + bytes;
            const char idTag[] = "mnt_id:";
            char* const id = std::search(begin, end, idTag, idTag + sizeof(idTag) - 1);
            if (id == end)
                return bytes;
            char* digit = id + sizeof(idTag) - 1;
            while (digit != end && (*digit < '0' || *digit > '9'))
                ++digit;
            if (digit == end)
                return bytes;
            *digit = *digit == '9' ? '8' : '9';
            ++changed;
            return bytes;
        });
        FilesystemCollectionRequest request(tree.Path("root"), FilesystemRootKind::Directory);
        request.childFileLinkAction = SymlinkPolicy::Follow;
        for (const auto scope : {FilesystemScope::RootDevice, FilesystemScope::Defined})
        {
            request.scope = scope;
            auto filtered = ComplianceEngine::Filesystem::CollectFilesystem(request, context);
            ASSERT_TRUE(filtered.HasValue()) << filtered.Error().message;
            const auto paths = Paths(filtered->entries);
            EXPECT_NE(paths.end(), std::find(paths.begin(), paths.end(), tree.Path("root/stay")));
            EXPECT_EQ(paths.end(), std::find(paths.begin(), paths.end(), tree.Path("root/alias")));
            EXPECT_NE(filtered->exclusions.end(), std::find_if(filtered->exclusions.begin(), filtered->exclusions.end(),
                                                      [&tree](const ComplianceEngine::Filesystem::FilesystemCollectionExclusion& exclusion) {
                                                          return exclusion.path == tree.Path("root/alias") && exclusion.reason == "filesystem scope";
                                                      }));
        }
        request.scope = FilesystemScope::All;
        auto crossing = ComplianceEngine::Filesystem::CollectFilesystem(request, context);
        ASSERT_TRUE(crossing.HasValue()) << crossing.Error().message;
        const auto all = Paths(crossing->entries);
        EXPECT_NE(all.end(), std::find(all.begin(), all.end(), tree.Path("root/alias")));
        EXPECT_GT(changed, 0u);
    }
}

TEST(FilesystemCollectionTest, FactoryAcquiresRootButReadsDescendantsOnePullAtATime)
{
    TestTree tree;
    tree.Directory("root");
    tree.File("root/item");
    ::testing::StrictMock<MockContext> context;
    // No EXPECT_CALL in this test constrains any native seam.
    context.AllowIncidentalNativeAccess();
    std::size_t stats = 0;
    std::size_t reads = 0;
    ON_CALL(context, LstatPath(testing::_, testing::_)).WillByDefault([&stats](const char* path, struct stat* metadata) {
        ++stats;
        return lstat(path, metadata);
    });
    ON_CALL(context, ReadDirectory(testing::_)).WillByDefault([&reads](DIR* stream) {
        ++reads;
        return readdir(stream);
    });
    FilesystemCollectionRequest request(tree.Path("root"), FilesystemRootKind::Directory);
    request.direction = FilesystemDirection::Down;
    auto opened = Files(request, context);
    ASSERT_TRUE(opened.HasValue());
    auto files = std::move(opened).Value();
    EXPECT_EQ(0u, stats);
    EXPECT_EQ(0u, reads);
    EXPECT_TRUE(files.RootExists());

    auto entry = files.begin();
    ASSERT_NE(entry, files.end());
    ASSERT_TRUE(entry->HasValue());
    EXPECT_EQ(tree.Path("root"), entry->Value().path);
    ASSERT_TRUE(entry->Value().LiveComponent().HasValue());
    auto rootIdentity = entry->Value().LiveComponent().Value().Stat();
    ASSERT_TRUE(rootIdentity.HasValue()) << rootIdentity.Error().message;
    EXPECT_EQ(0u, stats);
    EXPECT_EQ(0u, reads);

    ++entry;
    ASSERT_NE(entry, files.end());
    ASSERT_TRUE(entry->HasValue());
    EXPECT_EQ(tree.Path("root/item"), entry->Value().path);
    EXPECT_EQ(0u, stats);
    EXPECT_EQ(1u, reads);
    ASSERT_TRUE(entry->Value().LiveComponent().HasValue());
    EXPECT_EQ(ComplianceEngine::Filesystem::Type::RegularFile, entry->Value().LiveComponent().Value().Metadata().FileType());

    ++entry;
    EXPECT_EQ(entry, files.end());
    files.Stop();
    EXPECT_EQ(0u, stats);
}

TEST(FilesystemCollectionTest, RangeForRetainsEachRegularFilePinWithoutReacquiringItsName)
{
    TestTree tree;
    tree.Directory("root");
    tree.File("root/first");
    tree.File("root/second");
    ::testing::StrictMock<MockContext> context;
    // No EXPECT_CALL in this test constrains any native seam.
    context.AllowIncidentalNativeAccess();
    const std::string rootPath = tree.Path("root");
    std::size_t rootLookups = 0;
    bool unexpectedLookup = false;
    ON_CALL(context, LstatPath(testing::_, testing::_)).WillByDefault([&](const char* path, struct stat* metadata) noexcept {
        ++rootLookups;
        if (0 != std::strcmp(rootPath.c_str(), path))
            unexpectedLookup = true;
        return ::lstat(path, metadata);
    });
    FilesystemCollectionRequest request(tree.Path("root"), FilesystemRootKind::Directory);
    request.direction = FilesystemDirection::Down;
    request.yieldType = FilesystemYieldType::RegularFiles;
    auto opened = Files(request, context);
    ASSERT_TRUE(opened.HasValue()) << opened.Error().message;
    std::vector<std::string> seen;
    for (const auto& item : opened.Value())
    {
        ASSERT_TRUE(item.HasValue()) << item.Error().message;
        const std::string name = item.Value().path;
        const auto component = item.Value().LiveComponent();
        ASSERT_TRUE(component.HasValue());
        const auto inode = component.Value().Metadata().Stat().st_ino;
        ASSERT_EQ(0, unlink(name.c_str()));
        auto inspected = component.Value().Stat();
        ASSERT_TRUE(inspected.HasValue()) << inspected.Error().message;
        EXPECT_EQ(inode, inspected.Value().st_ino);
        seen.push_back(name);
    }
    std::sort(seen.begin(), seen.end());
    EXPECT_EQ((std::vector<std::string>{tree.Path("root/first"), tree.Path("root/second")}), seen);
    EXPECT_EQ(0u, rootLookups);
    EXPECT_FALSE(unexpectedLookup);
    opened->Stop();
}

TEST(FilesystemCollectionTest, FactorySeparatesAbsentRootFromInitializationFailures)
{
    TestTree tree;
    tree.Directory("root");
    ::testing::StrictMock<MockContext> context;
    // No EXPECT_CALL in this test constrains any native seam.
    context.AllowIncidentalNativeAccess();
    FilesystemCollectionRequest request(tree.Path("missing"), FilesystemRootKind::Directory);
    auto absent = Files(request, context);
    ASSERT_TRUE(absent.HasValue());
    EXPECT_FALSE(absent->RootExists());
    absent->Stop();
    absent->Stop();
    EXPECT_EQ(absent->begin(), absent->end());

    request.rootPath = tree.Path("root");
    request.yieldType = FilesystemYieldType::RegularFiles;
    auto existing = Files(request, context);
    ASSERT_TRUE(existing.HasValue());
    EXPECT_TRUE(existing->RootExists());
    EXPECT_EQ(existing->begin(), existing->end());
    existing->Stop();
    ON_CALL(context, ReadDirectory(testing::_)).WillByDefault([](DIR*) -> struct dirent* {
        errno = EACCES;
        return nullptr;
    });
    auto readFailure = Files(request, context);
    ASSERT_TRUE(readFailure.HasValue());
    auto reached = readFailure->begin();
    ASSERT_NE(reached, readFailure->end());
    ASSERT_FALSE(reached->HasValue());
    EXPECT_EQ(EACCES, reached->Error().code);
    ++reached;
    EXPECT_EQ(reached, readFailure->end());

    ON_CALL(context, ReadDirectory(testing::_)).WillByDefault([](DIR* stream) { return readdir(stream); });
    ON_CALL(context, StatFileDescriptor(testing::_, testing::_)).WillByDefault([](int, struct stat*) {
        errno = EIO;
        return -1;
    });
    const auto statFailure = Files(request, context);
    ASSERT_FALSE(statFailure.HasValue());
    EXPECT_EQ(EIO, statFailure.Error().code);

    ON_CALL(context, StatFileDescriptor(testing::_, testing::_)).WillByDefault([&](int descriptor, struct stat* metadata) {
        return context.RealStatFileDescriptor(descriptor, metadata);
    });
    ON_CALL(context, OpenNativeAt(testing::_, testing::_, testing::_)).WillByDefault([](int, const char*, int) {
        errno = EACCES;
        return -1;
    });
    const auto rootOpenFailure = Files(request, context);
    ASSERT_FALSE(rootOpenFailure.HasValue());
    EXPECT_EQ(EACCES, rootOpenFailure.Error().code);
}

TEST(FilesystemCollectionTest, YieldSelectionDoesNotSuppressDescentOrWorkBudgets)
{
    TestTree tree;
    tree.Directory("root");
    tree.Directory("root/nested");
    tree.File("root/nested/file");
    FilesystemCollectionRequest request(tree.Path("root"), FilesystemRootKind::Directory);
    request.direction = FilesystemDirection::Down;
    request.yieldType = FilesystemYieldType::RegularFiles;
    ::testing::StrictMock<MockContext> context;
    // No EXPECT_CALL in this test constrains any native seam.
    context.AllowIncidentalNativeAccess();
    const auto selected = ComplianceEngine::Filesystem::CollectFilesystem(request, context);
    ASSERT_TRUE(selected.HasValue());
    EXPECT_EQ(std::vector<std::string>{tree.Path("root/nested/file")}, Paths(selected->entries));

    request.yieldType = FilesystemYieldType::Directories;
    const auto directories = ComplianceEngine::Filesystem::CollectFilesystem(request, context);
    ASSERT_TRUE(directories.HasValue());
    EXPECT_EQ((std::vector<std::string>{tree.Path("root"), tree.Path("root/nested")}), Paths(directories->entries));

    request.yieldType = FilesystemYieldType::RegularFiles;
    request.entryWork = 1;
    const auto budget = ComplianceEngine::Filesystem::CollectFilesystem(request, context);
    ASSERT_FALSE(budget.HasValue());
    EXPECT_EQ(E2BIG, budget.Error().code);

    request.entryWork = FilesystemCollectionLimits{}.entryWork;
    struct stat expectedNested = {};
    ASSERT_EQ(0, stat(tree.Path("root/nested").c_str(), &expectedNested));
    ON_CALL(context, ReadDirectory(testing::_)).WillByDefault([expectedNested](DIR * stream) -> struct dirent* {
        struct stat actual = {};
        if ((0 == fstat(dirfd(stream), &actual)) && (actual.st_dev == expectedNested.st_dev) && (actual.st_ino == expectedNested.st_ino))
        {
            errno = EACCES;
            return nullptr;
        }
        return readdir(stream);
    });
    auto opened = Files(request, context);
    ASSERT_TRUE(opened.HasValue());
    auto error = opened->begin();
    ASSERT_NE(error, opened->end());
    ASSERT_FALSE(error->HasValue());
    EXPECT_EQ(EACCES, error->Error().code);
    opened->Stop();
}

TEST(FilesystemCollectionTest, LinkSelectionPublishesAcceptedTargetMetadata)
{
    TestTree tree;
    tree.Directory("root");
    tree.File("root/target");
    tree.Link("target", "root/link");
    ::testing::StrictMock<MockContext> context;
    // No EXPECT_CALL in this test constrains any native seam.
    context.AllowIncidentalNativeAccess();
    FilesystemCollectionRequest request(tree.Path("root"), FilesystemRootKind::Directory);
    request.direction = FilesystemDirection::Down;
    request.yieldType = FilesystemYieldType::RegularFiles;
    auto recorded = ComplianceEngine::Filesystem::CollectFilesystem(request, context);
    ASSERT_TRUE(recorded.HasValue());
    EXPECT_EQ(std::vector<std::string>{tree.Path("root/target")}, Paths(recorded->entries));

    request.childFileLinkAction = SymlinkPolicy::Follow;
    auto followed = ComplianceEngine::Filesystem::CollectFilesystem(request, context);
    ASSERT_TRUE(followed.HasValue());
    ASSERT_EQ(2u, followed->entries.size());
    const auto link = std::find_if(followed->entries.begin(), followed->entries.end(),
        [&tree](const FilesystemCollectionEntry& entry) { return entry.path == tree.Path("root/link"); });
    ASSERT_NE(followed->entries.end(), link);
    struct stat target = {};
    ASSERT_EQ(0, stat(tree.Path("root/target").c_str(), &target));
    EXPECT_TRUE(S_ISREG(link->metadata.st_mode));
    EXPECT_EQ(target.st_dev, link->metadata.st_dev);
    EXPECT_EQ(target.st_ino, link->metadata.st_ino);

    request.yieldType = FilesystemYieldType::SymbolicLinks;
    request.childFileLinkAction = SymlinkPolicy::DoNotFollow;
    auto links = ComplianceEngine::Filesystem::CollectFilesystem(request, context);
    ASSERT_TRUE(links.HasValue());
    EXPECT_TRUE(links->entries.empty());
    ASSERT_EQ(1u, links->exclusions.size());
    EXPECT_EQ(tree.Path("root/link"), links->exclusions[0].path);
    EXPECT_EQ("link policy", links->exclusions[0].reason);
}

TEST(FilesystemCollectionTest, RejectsInvalidYieldAndDepthModes)
{
    FilesystemCollectionRequest request = Request();
    request.yieldType = static_cast<FilesystemYieldType>(99);
    ExpectInvalid(request, EINVAL);
    request.yieldType = FilesystemYieldType::All;
    request.depthAction = static_cast<FilesystemDepthAction>(99);
    ExpectInvalid(request, EINVAL);
}

TEST(FilesystemCollectionTest, ExplicitDepthErrorIsNotAQuietStop)
{
    TestTree tree;
    tree.Directory("root");
    tree.Directory("root/nested");
    FilesystemCollectionRequest request(tree.Path("root"), FilesystemRootKind::Directory);
    request.direction = FilesystemDirection::Down;
    request.maxDepth = 0;
    request.depthAction = FilesystemDepthAction::Error;
    request.yieldType = FilesystemYieldType::RegularFiles;
    ::testing::StrictMock<MockContext> context;
    // No EXPECT_CALL in this test constrains any native seam.
    context.AllowIncidentalNativeAccess();
    const auto result = ComplianceEngine::Filesystem::CollectFilesystem(request, context);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ("Maximum recursion depth reached", result.Error().message);
}

TEST(FilesystemCollectionTest, FactoryPolicyFailurePrecedesRootAcquisition)
{
    ::testing::StrictMock<MockContext> context;
    EXPECT_CALL(context, LstatPath(testing::_, testing::_)).Times(0);
    FilesystemCollectionRequest request("", FilesystemRootKind::Directory);
    const auto opened = Files(request, context);
    ASSERT_FALSE(opened.HasValue());
    EXPECT_EQ(EINVAL, opened.Error().code);
}

TEST(FilesystemCollectionTest, DescendantOpenFailureIsDeferredUntilAfterItsEntry)
{
    TestTree tree;
    tree.Directory("root");
    tree.Directory("root/child");
    ::testing::StrictMock<MockContext> context;
    struct stat expectedChild = {};
    ASSERT_EQ(0, stat(tree.Path("root/child").c_str(), &expectedChild));
    // No EXPECT_CALL in this test constrains any native seam; it only
    // customizes ReadDirectory's default action via ON_CALL.
    context.AllowIncidentalNativeAccess();
    ON_CALL(context, ReadDirectory(testing::_)).WillByDefault([expectedChild](DIR * stream) -> struct dirent* {
        struct stat actual = {};
        if ((0 == fstat(dirfd(stream), &actual)) && (actual.st_dev == expectedChild.st_dev) && (actual.st_ino == expectedChild.st_ino))
        {
            errno = EACCES;
            return nullptr;
        }
        return readdir(stream);
    });
    FilesystemCollectionRequest request(tree.Path("root"), FilesystemRootKind::Directory);
    request.direction = FilesystemDirection::Down;
    auto opened = Files(request, context);
    ASSERT_TRUE(opened.HasValue());
    auto files = std::move(opened).Value();
    auto entry = files.begin();
    ASSERT_NE(entry, files.end());
    ASSERT_TRUE(entry->HasValue());
    ++entry;
    ASSERT_NE(entry, files.end());
    ASSERT_TRUE(entry->HasValue());
    EXPECT_EQ(tree.Path("root/child"), entry->Value().path);
    ASSERT_TRUE(entry->Value().LiveComponent().HasValue());
    const auto childInode = entry->Value().LiveComponent().Value().Metadata().Stat().st_ino;
    EXPECT_EQ(expectedChild.st_ino, childInode);
    ++entry;
    ASSERT_NE(entry, files.end());
    ASSERT_FALSE(entry->HasValue());
    EXPECT_EQ(EACCES, entry->Error().code);
    ++entry;
    EXPECT_EQ(entry, files.end());
    files.Stop();
    EXPECT_TRUE(files.RootExists());
}

TEST(FilesystemCollectionTest, LateReadErrorIsYieldedOnceAndNeverCertifiesCompletion)
{
    TestTree tree;
    tree.Directory("root");
    ::testing::StrictMock<MockContext> context;
    // No EXPECT_CALL in this test constrains any native seam.
    context.AllowIncidentalNativeAccess();
    ON_CALL(context, ReadDirectory(testing::_)).WillByDefault([](DIR*) -> struct dirent* {
        errno = EIO;
        return nullptr;
    });
    auto opened = Files(FilesystemCollectionRequest(tree.Path("root"), FilesystemRootKind::Directory), context);
    ASSERT_TRUE(opened.HasValue());
    auto files = std::move(opened).Value();
    std::size_t values = 0;
    std::size_t errors = 0;
    for (const auto& entry : files)
    {
        if (entry.HasValue())
        {
            ++values;
        }
        else
        {
            ++errors;
            EXPECT_EQ(EIO, entry.Error().code);
        }
    }
    EXPECT_EQ(1u, values);
    EXPECT_EQ(1u, errors);
    files.Stop();
}

TEST(FilesystemCollectionTest, ExhaustionCloseFailureDoesNotReplaceCompleteTraversal)
{
    TestTree tree;
    tree.Directory("root");
    ::testing::StrictMock<MockContext> context;
    // No EXPECT_CALL in this test constrains any native seam.
    context.AllowIncidentalNativeAccess();
    ON_CALL(context, CloseDirectory(testing::_)).WillByDefault([](DIR* stream) {
        const int result = closedir(stream);
        if (0 == result)
        {
            errno = EIO;
            return ComplianceEngine::Result<void>(ComplianceEngine::Error(errno));
        }
        return result == 0 ? ComplianceEngine::Result<void>::Success() : ComplianceEngine::Result<void>(ComplianceEngine::Error(errno));
    });
    auto opened = Files(FilesystemCollectionRequest(tree.Path("root"), FilesystemRootKind::Directory), context);
    ASSERT_TRUE(opened.HasValue());
    auto files = std::move(opened).Value();
    auto entry = files.begin();
    ASSERT_NE(entry, files.end());
    ASSERT_TRUE(entry->HasValue());
    ++entry;
    EXPECT_EQ(entry, files.end());
    files.Stop();
}

TEST(FilesystemCollectionTest, EarlyStopIsIdempotentAndDoesNotReadUnseenEntries)
{
    TestTree tree;
    tree.Directory("root");
    tree.File("root/item");
    ::testing::StrictMock<MockContext> context;
    // No EXPECT_CALL in this test constrains any native seam.
    context.AllowIncidentalNativeAccess();
    std::size_t closed = 0;
    std::size_t reads = 0;
    ON_CALL(context, CloseDirectory(testing::_)).WillByDefault([&closed](DIR* stream) {
        ++closed;
        return closedir(stream) == 0 ? ComplianceEngine::Result<void>::Success() : ComplianceEngine::Result<void>(ComplianceEngine::Error(errno));
    });
    ON_CALL(context, ReadDirectory(testing::_)).WillByDefault([&reads](DIR* stream) {
        ++reads;
        return readdir(stream);
    });
    {
        FilesystemCollectionRequest request(tree.Path("root"), FilesystemRootKind::Directory);
        request.direction = FilesystemDirection::Down;
        auto opened = Files(request, context);
        ASSERT_TRUE(opened.HasValue());
        auto files = std::move(opened).Value();
        std::size_t seen = 0;
        for (const auto& entry : files)
        {
            ASSERT_TRUE(entry.HasValue());
            if (++seen == 2)
            {
                break;
            }
        }
        EXPECT_EQ(2u, seen);
        const auto beforeClose = reads;
        files.Stop();
        EXPECT_EQ(beforeClose, reads);
        EXPECT_EQ(1u, closed);
        files.Stop();
        EXPECT_EQ(1u, closed);
        EXPECT_EQ(files.begin(), files.end());
    }
    EXPECT_EQ(1u, closed);
}

static_assert(std::is_assignable<ComplianceEngine::Filesystem::FTW::FileRange&, ComplianceEngine::Filesystem::FTW::FileRange&&>::value,
    "FileRange must support lvalue move assignment");
static_assert(!std::is_assignable<ComplianceEngine::Filesystem::FTW::FileRange&&, ComplianceEngine::Filesystem::FTW::FileRange&&>::value,
    "FileRange move assignment must not return a reference to a temporary");

TEST(FilesystemCollectionTest, MovedFromRangeHasNoRootOrEntriesAndNewOwnerTraverses)
{
    TestTree tree;
    tree.Directory("root");
    tree.File("root/item");
    ::testing::StrictMock<MockContext> context;
    // No EXPECT_CALL in this test constrains any native seam.
    context.AllowIncidentalNativeAccess();
    FilesystemCollectionRequest request(tree.Path("root"), FilesystemRootKind::Directory);
    request.direction = FilesystemDirection::Down;
    auto opened = Files(request, context);
    ASSERT_TRUE(opened.HasValue()) << opened.Error().message;
    auto moved = std::move(opened.Value());
    EXPECT_FALSE(opened.Value().RootExists());
    EXPECT_EQ(opened.Value().begin(), opened.Value().end());
    opened.Value().Stop();
    std::vector<std::string> paths;
    for (const auto& entry : moved)
    {
        ASSERT_TRUE(entry.HasValue()) << entry.Error().message;
        paths.push_back(entry.Value().path);
    }
    EXPECT_EQ((std::vector<std::string>{tree.Path("root"), tree.Path("root/item")}), paths);
    moved.Stop();
}

TEST(FilesystemCollectionTest, MoveAssignmentLeavesSourceInertAndFinalizesReplacedCursorOnce)
{
    TestTree tree;
    tree.Directory("root");
    ::testing::StrictMock<MockContext> context;
    int cursorCloses = 0;
    // No EXPECT_CALL in this test constrains any native seam; it only
    // customizes CloseDirectory's default action via ON_CALL.
    context.AllowIncidentalNativeAccess();
    ON_CALL(context, CloseDirectory(testing::_)).WillByDefault([&](DIR* stream) {
        ++cursorCloses;
        return closedir(stream) == 0 ? ComplianceEngine::Result<void>::Success() : ComplianceEngine::Result<void>(ComplianceEngine::Error(errno));
    });
    const FilesystemCollectionRequest request(tree.Path("root"), FilesystemRootKind::Directory);
    auto first = Files(request, context);
    auto second = Files(request, context);
    ASSERT_TRUE(first.HasValue());
    ASSERT_TRUE(second.HasValue());
    first.Value() = std::move(second.Value());
    EXPECT_EQ(1, cursorCloses);
    EXPECT_FALSE(second.Value().RootExists());
    EXPECT_EQ(second.Value().begin(), second.Value().end());
    second.Value().Stop();
    EXPECT_TRUE(first.Value().RootExists());
    auto root = first.Value().begin();
    ASSERT_NE(root, first.Value().end());
    ASSERT_TRUE(root->HasValue());
    first.Value().Stop();
    EXPECT_EQ(2, cursorCloses);
}

TEST(FilesystemCollectionTest, StopOnMovedFromRangeIsInert)
{
    TestTree tree;
    tree.Directory("root");
    ::testing::StrictMock<MockContext> context;
    int cursorCloses = 0;
    // The root acquisition below performs real, incidental native access;
    // the ReadDirectory Times(0) is declared after this catch-all, so it
    // still wins for the whole test (see MockContext.h helper comment).
    context.AllowIncidentalNativeAccess();
    EXPECT_CALL(context, ReadDirectory(testing::_)).Times(0);
    ON_CALL(context, CloseDirectory(testing::_)).WillByDefault([&](DIR* stream) {
        ++cursorCloses;
        return closedir(stream) == 0 ? ComplianceEngine::Result<void>::Success() : ComplianceEngine::Result<void>(ComplianceEngine::Error(errno));
    });
    auto opened = Files(FilesystemCollectionRequest(tree.Path("root"), FilesystemRootKind::Directory), context);
    ASSERT_TRUE(opened.HasValue()) << opened.Error().message;
    auto moved = std::move(opened.Value());
    opened.Value().Stop();
    EXPECT_EQ(0, cursorCloses);
    moved.Stop();
    moved.Stop();
    EXPECT_EQ(1, cursorCloses);
}

TEST(FilesystemCollectionTest, AbandonedRangeClosesWithoutPullingDescendants)
{
    TestTree tree;
    tree.Directory("root");
    tree.File("root/item");
    ::testing::StrictMock<MockContext> context;
    std::size_t closed = 0;
    // The root acquisition below performs real, incidental native access;
    // the ReadDirectory Times(0) is declared after this catch-all, so it
    // still wins for the whole test (see MockContext.h helper comment).
    context.AllowIncidentalNativeAccess();
    EXPECT_CALL(context, ReadDirectory(testing::_)).Times(0);
    ON_CALL(context, CloseDirectory(testing::_)).WillByDefault([&closed](DIR* stream) {
        ++closed;
        const int status = closedir(stream);
        const int nativeCode = errno;
        return ComplianceEngine::Error(status == 0 ? EIO : nativeCode);
    });
    {
        auto opened = Files(FilesystemCollectionRequest(tree.Path("root"), FilesystemRootKind::Directory), context);
        ASSERT_TRUE(opened.HasValue());
        EXPECT_TRUE(opened->RootExists());
    }
    EXPECT_EQ(1u, closed);
}

TEST(FilesystemCollectionTest, EarlyStopDisposalIsDiagnosticOnly)
{
    TestTree tree;
    tree.Directory("root");
    tree.File("root/item");
    ::testing::StrictMock<MockContext> context;
    // No EXPECT_CALL in this test constrains any native seam; it only
    // customizes CloseDirectory's default action via ON_CALL below.
    context.AllowIncidentalNativeAccess();
    FilesystemCollectionRequest request(tree.Path("root"), FilesystemRootKind::Directory);
    request.direction = FilesystemDirection::Down;
    auto opened = Files(request, context);
    ASSERT_TRUE(opened.HasValue());
    auto files = std::move(opened).Value();
    auto entry = files.begin();
    ASSERT_NE(entry, files.end());
    ASSERT_TRUE(entry->HasValue());
    ++entry;
    ASSERT_NE(entry, files.end());
    ASSERT_TRUE(entry->HasValue());
    ON_CALL(context, CloseDirectory(testing::_)).WillByDefault([](DIR* stream) {
        const int result = closedir(stream);
        if (0 == result)
        {
            errno = EIO;
            return ComplianceEngine::Result<void>(ComplianceEngine::Error(errno));
        }
        return result == 0 ? ComplianceEngine::Result<void>::Success() : ComplianceEngine::Result<void>(ComplianceEngine::Error(errno));
    });
    files.Stop();
    files.Stop();
}

TEST(FilesystemCollectionTest, VisitorStopDoesNotDrainUnvisitedEntries)
{
    TestTree tree;
    tree.Directory("root");
    tree.File("root/item");
    ::testing::StrictMock<MockContext> context;
    FilesystemCollectionRequest request(tree.Path("root"), FilesystemRootKind::Directory);
    request.direction = FilesystemDirection::Down;
    // The root acquisition below performs real, incidental native access;
    // the ReadDirectory Times(0) is declared after this catch-all, so it
    // still wins for the whole test (see MockContext.h helper comment).
    context.AllowIncidentalNativeAccess();
    EXPECT_CALL(context, ReadDirectory(testing::_)).Times(0);
    const auto stopped = StreamFilesystemCollection(
        request, [](const FilesystemCollectionEntry&) { return ComplianceEngine::Result<FilesystemVisitAction>(FilesystemVisitAction::Stop); }, context);
    ASSERT_TRUE(stopped.HasValue());
    EXPECT_TRUE(stopped->entries.empty());
}
