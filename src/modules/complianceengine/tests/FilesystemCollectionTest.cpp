// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "MockContext.h"
#include "TemporaryDirectory.h"

#include <algorithm>
#include <cerrno>
#include <filesystem/FilesystemCollection.hpp>
#include <fstream>
#include <gtest/gtest.h>
#include <map>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>
#include <vector>

using ComplianceEngine::CollectFilesystem;
using ComplianceEngine::FilesystemCollectionEntry;
using ComplianceEngine::FilesystemCollectionLimits;
using ComplianceEngine::FilesystemCollectionRequest;
using ComplianceEngine::FilesystemDepthAction;
using ComplianceEngine::FilesystemDirection;
using ComplianceEngine::FilesystemRootKind;
using ComplianceEngine::FilesystemScope;
using ComplianceEngine::FilesystemVisitAction;
using ComplianceEngine::FilesystemYieldType;
using ComplianceEngine::ResolvedFilesystemCollectionRequest;
using ComplianceEngine::ResolveFilesystemCollectionRequest;
using ComplianceEngine::Result;
using ComplianceEngine::StreamFilesystemCollection;
using ComplianceEngine::SymlinkFollowing;
using ComplianceEngine::TemporaryDirectory;
using ComplianceEngine::FTW::Files;
namespace
{
Result<ComplianceEngine::FilesystemCollectionResult> CollectFilesystem(const FilesystemCollectionRequest& request)
{
    MockContext context;
    return ComplianceEngine::CollectFilesystem(request, context);
}

Result<ComplianceEngine::FilesystemCollectionResult> StreamFilesystemCollection(const FilesystemCollectionRequest& request,
    const ComplianceEngine::FilesystemCollectionVisitor& visitor)
{
    MockContext context;
    return ComplianceEngine::StreamFilesystemCollection(request, visitor, context);
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
    MockContext context;
    TestTree tree;
    tree.Directory("root");
    tree.File("root/.settings");
    tree.Link("root", "administrative");
    FilesystemCollectionRequest request(tree.Path("administrative"), FilesystemRootKind::Directory);
    request.direction = FilesystemDirection::Down;
    request.depthAction = FilesystemDepthAction::Error;
    request.scope = FilesystemScope::All;
    request.yieldType = FilesystemYieldType::RegularFiles;
    request.rootDirectoryLinkAction = SymlinkFollowing::Follow;
    request.rootFileLinkAction = SymlinkFollowing::Follow;
    auto followed = Files(request, context);
    ASSERT_TRUE(followed.HasValue()) << followed.Error().message;
    ASSERT_TRUE(followed.Value().RootExists());
    auto entry = followed->begin();
    ASSERT_NE(entry, followed->end());
    ASSERT_TRUE(entry->HasValue()) << entry->Error().message;
    EXPECT_EQ(tree.Path("administrative") + "/.settings", entry->Value().path);
    ASSERT_NE(nullptr, entry->Value().LiveHandle());
    EXPECT_EQ(ComplianceEngine::Filesystem::Handle::Type::RegularFile, entry->Value().LiveHandle()->AcquiredType());
    ASSERT_TRUE(followed.Value().Close().HasValue());

    request.rootDirectoryLinkAction = SymlinkFollowing::DoNotFollow;
    request.rootFileLinkAction = SymlinkFollowing::DoNotFollow;
    auto rejected = Files(request, context);
    ASSERT_TRUE(rejected.HasValue());
    EXPECT_TRUE(rejected.Value().RootExists());
    ASSERT_TRUE(rejected.Value().Close().HasValue());

    request.scope = FilesystemScope::RootDevice;
    request.rootDirectoryLinkAction = SymlinkFollowing::Follow;
    request.rootFileLinkAction = SymlinkFollowing::Follow;
    auto scoped = Files(request, context);
    ASSERT_TRUE(scoped.HasValue()) << scoped.Error().message;
    ASSERT_TRUE(scoped.Value().Close().HasValue());
}

TEST(FilesystemCollectionTest, OwnedLiveEntryOutlivesRangeButCollectedSnapshotHasNoAuthority)
{
    TestTree tree;
    tree.File("file");
    const FilesystemCollectionRequest request(tree.Path("file"), FilesystemRootKind::File);
    auto snapshot = CollectFilesystem(request);
    ASSERT_TRUE(snapshot.HasValue());
    ASSERT_EQ(1u, snapshot->entries.size());
    EXPECT_EQ(nullptr, snapshot->entries.front().LiveHandle());

    MockContext context;
    ComplianceEngine::FTW::FileRange::Iterator entry;
    ino_t inode = 0;
    {
        auto opened = Files(request, context);
        ASSERT_TRUE(opened.HasValue()) << opened.Error().message;
        entry = opened->begin();
        ASSERT_NE(entry, opened->end());
        ASSERT_TRUE(entry->HasValue());
        ASSERT_NE(nullptr, entry->Value().LiveHandle());
        inode = entry->Value().LiveHandle()->Stat().st_ino;
        ASSERT_TRUE(opened->Close().HasValue());
    }
    ASSERT_EQ(0, unlink(tree.Path("file").c_str()));
    auto inspected = entry->Value().LiveHandle()->Stat(FilesystemCollectionLimits{}.fullPathBytes);
    ASSERT_TRUE(inspected.HasValue()) << inspected.Error().message;
    EXPECT_EQ(inode, inspected.Value().st_ino);
}

TEST(FilesystemCollectionTest, ClosingBeforeFirstPullChecksUnyieldedFilePinAndAllPathPinsOnce)
{
    TestTree tree;
    tree.File("file");
    struct stat expected = {};
    ASSERT_EQ(0, stat(tree.Path("file").c_str(), &expected));
    MockContext context;
    struct Pin
    {
        Pin(int descriptor, dev_t device, ino_t inode)
            : descriptor(descriptor),
              device(device),
              inode(inode)
        {
        }
        int descriptor;
        dev_t device;
        ino_t inode;
        std::size_t closeAttempts = 0;
    };
    std::vector<Pin> openedPins;
    // Track each open-to-close lifetime, not the fd number: procfs helpers
    // close during acquisition and the kernel can reuse their numbers.
    std::map<int, std::size_t> livePins;
    const auto recordOpen = [&](int descriptor) {
        if (descriptor >= 0)
        {
            struct stat held = {};
            EXPECT_EQ(0, fstat(descriptor, &held));
            const auto index = openedPins.size();
            openedPins.push_back({descriptor, held.st_dev, held.st_ino});
            EXPECT_TRUE(livePins.emplace(descriptor, index).second);
        }
        return descriptor;
    };
    ON_CALL(context, OpenNativePath(testing::_, testing::_)).WillByDefault([&](const char* path, int flags) {
        return recordOpen(context.ContextInterface::OpenNativePath(path, flags));
    });
    ON_CALL(context, OpenNativeAt(testing::_, testing::_, testing::_)).WillByDefault([&](int directory, const char* path, int flags) {
        return recordOpen(context.ContextInterface::OpenNativeAt(directory, path, flags));
    });
    std::size_t failedFilePin = 0;
    bool injectFileCloseFailure = false;
    ON_CALL(context, CloseFileDescriptor(testing::_)).WillByDefault([&](int descriptor) {
        const auto found = livePins.find(descriptor);
        EXPECT_NE(livePins.end(), found) << "Closing an untracked or already closed descriptor";
        const bool fail = (found != livePins.end()) && injectFileCloseFailure && (found->second == failedFilePin);
        if (found != livePins.end())
        {
            ++openedPins[found->second].closeAttempts;
            livePins.erase(found);
        }
        const int result = close(descriptor);
        EXPECT_EQ(0, result);
        if (fail)
        {
            errno = EIO;
            return -1;
        }
        return result;
    });
    std::vector<std::size_t> ownedPins;
    {
        auto opened = Files(FilesystemCollectionRequest(tree.Path("file"), FilesystemRootKind::File), context);
        ASSERT_TRUE(opened.HasValue()) << opened.Error().message;
        // All helpers have already closed. What remains belongs to the range:
        // one pending file pin and the individual acquisition-path pins.
        for (const auto& live : livePins)
        {
            ownedPins.push_back(live.second);
        }
        ASSERT_GT(ownedPins.size(), 1u);
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
        ASSERT_GT(directoryPins, 0u);
        injectFileCloseFailure = true;
        const auto closed = opened->Close();
        ASSERT_FALSE(closed.HasValue());
        EXPECT_EQ(EIO, closed.Error().code);
        EXPECT_TRUE(livePins.empty());
        for (const auto index : ownedPins)
        {
            EXPECT_EQ(1u, openedPins[index].closeAttempts) << "Pin lifetime " << index;
        }
        const auto repeated = opened->Close();
        ASSERT_FALSE(repeated.HasValue());
        EXPECT_EQ(EIO, repeated.Error().code);
        EXPECT_TRUE(livePins.empty());
        for (const auto index : ownedPins)
        {
            EXPECT_EQ(1u, openedPins[index].closeAttempts) << "Retried pin lifetime " << index;
        }
    }
    EXPECT_TRUE(livePins.empty());
    for (const auto index : ownedPins)
    {
        EXPECT_EQ(1u, openedPins[index].closeAttempts) << "Destructor retried pin lifetime " << index;
    }
}

TEST(FilesystemCollectionTest, CloseAttemptsCursorAndPinsAfterFirstCleanupFailure)
{
    TestTree tree;
    tree.Directory("root");
    MockContext context;
    std::size_t cursorCloses = 0;
    std::size_t pinCloses = 0;
    ON_CALL(context, CloseDirectory(testing::_)).WillByDefault([&](DIR* stream) {
        ++cursorCloses;
        const int result = closedir(stream);
        errno = EACCES;
        return result == 0 ? -1 : result;
    });
    auto opened = Files(FilesystemCollectionRequest(tree.Path("root"), FilesystemRootKind::Directory), context);
    ASSERT_TRUE(opened.HasValue()) << opened.Error().message;
    ON_CALL(context, CloseFileDescriptor(testing::_)).WillByDefault([&](int descriptor) {
        ++pinCloses;
        const int result = close(descriptor);
        errno = EIO;
        return result == 0 ? -1 : result;
    });
    const auto first = opened->Close();
    ASSERT_FALSE(first.HasValue());
    EXPECT_EQ(EACCES, first.Error().code);
    EXPECT_EQ(1u, cursorCloses);
    EXPECT_GT(pinCloses, 0u);
    const auto count = pinCloses;
    EXPECT_EQ(EACCES, opened->Close().Error().code);
    EXPECT_EQ(1u, cursorCloses);
    EXPECT_EQ(count, pinCloses);
}

TEST(FilesystemCollectionTest, VisitorErrorOutranksPathPinCloseFailure)
{
    TestTree tree;
    tree.Directory("root");
    MockContext context;
    bool failClose = false;
    std::size_t failedPins = 0;
    ON_CALL(context, CloseFileDescriptor(testing::_)).WillByDefault([&](int descriptor) {
        const int result = close(descriptor);
        if (failClose && result == 0)
        {
            ++failedPins;
            errno = EIO;
            return -1;
        }
        return result;
    });
    const auto streamed = ComplianceEngine::StreamFilesystemCollection(
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
    MockContext context;
    ON_CALL(context, ReadDirectory(testing::_)).WillByDefault([&tree](DIR * stream) -> struct dirent* {
        struct dirent* entry = readdir(stream);
        if (entry && ("vanishing" == std::string(entry->d_name)))
        {
            entry->d_type = DT_REG; // deterministic untrusted enumeration hint
            EXPECT_EQ(0, unlink(tree.Path("root/vanishing").c_str()));
        }
        return entry;
    });
    FilesystemCollectionRequest request(tree.Path("root"), FilesystemRootKind::Directory);
    request.yieldType = FilesystemYieldType::RegularFiles;
    request.missingChildAction = ComplianceEngine::FilesystemMissingChildAction::ReportRegularFile;
    auto opened = Files(request, context);
    ASSERT_TRUE(opened.HasValue()) << opened.Error().message;
    auto missing = opened->begin();
    ASSERT_NE(missing, opened->end());
    ASSERT_TRUE(missing->HasValue()) << missing->Error().message;
    EXPECT_TRUE(missing->Value().missing);
    EXPECT_EQ(tree.Path("root/vanishing"), missing->Value().path);
    EXPECT_EQ(nullptr, missing->Value().LiveHandle());
    EXPECT_EQ(0, missing->Value().linkMetadata.st_mode);
    EXPECT_FALSE(missing->Value().targetMetadata.HasValue());
    ASSERT_TRUE(opened->Close().HasValue());

    tree.File("root/vanishing");
    ON_CALL(context, ReadDirectory(testing::_)).WillByDefault([&tree](DIR * stream) -> struct dirent* {
        struct dirent* entry = readdir(stream);
        if (entry && ("vanishing" == std::string(entry->d_name)))
        {
            entry->d_type = DT_UNKNOWN;
            EXPECT_EQ(0, unlink(tree.Path("root/vanishing").c_str()));
        }
        return entry;
    });
    const auto unknown = CollectFilesystem(request, context);
    ASSERT_FALSE(unknown.HasValue());
    EXPECT_EQ(ENOENT, unknown.Error().code);

    tree.File("root/vanishing");
    request.missingChildAction = ComplianceEngine::FilesystemMissingChildAction::Error;
    const auto defaultResult = CollectFilesystem(request, context);
    ASSERT_FALSE(defaultResult.HasValue());
    EXPECT_EQ(ENOENT, defaultResult.Error().code);
}

TEST(FilesystemCollectionTest, MissingObservationDoesNotSwallowChildInspectionFailure)
{
    TestTree tree;
    tree.Directory("root");
    tree.File("root/item");
    struct stat expected = {};
    ASSERT_EQ(0, stat(tree.Path("root/item").c_str(), &expected));
    MockContext context;
    ON_CALL(context, StatFileDescriptor(testing::_, testing::_)).WillByDefault([&context, expected](int descriptor, struct stat* metadata) {
        struct stat actual = {};
        if ((0 == fstat(descriptor, &actual)) && (actual.st_dev == expected.st_dev) && (actual.st_ino == expected.st_ino))
        {
            errno = ENOENT;
            return -1;
        }
        return context.ContextInterface::StatFileDescriptor(descriptor, metadata);
    });
    FilesystemCollectionRequest request(tree.Path("root"), FilesystemRootKind::Directory);
    request.yieldType = FilesystemYieldType::RegularFiles;
    request.missingChildAction = ComplianceEngine::FilesystemMissingChildAction::ReportRegularFile;
    const auto failure = CollectFilesystem(request, context);
    ASSERT_FALSE(failure.HasValue());
    EXPECT_EQ(ENOENT, failure.Error().code);
    EXPECT_NE(std::string::npos, failure.Error().message.find("Cannot inspect pinned directory child"));
}

TEST(FilesystemCollectionTest, RejectsInvalidAcquisitionRootsBeforeLookup)
{
    MockContext context;
    EXPECT_CALL(context, LstatPath(testing::_, testing::_)).Times(0);
    EXPECT_CALL(context, StatPath(testing::_, testing::_)).Times(0);
    EXPECT_CALL(context, OpenExistingFile(testing::_, testing::_)).Times(0);
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

            const auto collected = ComplianceEngine::CollectFilesystem(request, context);
            ASSERT_FALSE(collected.HasValue());
            EXPECT_EQ(EINVAL, collected.Error().code);
            EXPECT_EQ(resolved.Error().message, collected.Error().message);

            bool visited = false;
            const auto streamed = ComplianceEngine::StreamFilesystemCollection(
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
    EXPECT_EQ(SymlinkFollowing::DoNotFollow, request.rootFileLinkAction);
    EXPECT_EQ(SymlinkFollowing::DoNotFollow, request.rootDirectoryLinkAction);
    EXPECT_EQ(SymlinkFollowing::DoNotFollow, request.childFileLinkAction);
    EXPECT_EQ(SymlinkFollowing::DoNotFollow, request.childDirectoryLinkAction);
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
    explicitDefaults.rootFileLinkAction = SymlinkFollowing::DoNotFollow;
    explicitDefaults.rootDirectoryLinkAction = SymlinkFollowing::DoNotFollow;
    explicitDefaults.childFileLinkAction = SymlinkFollowing::DoNotFollow;
    explicitDefaults.childDirectoryLinkAction = SymlinkFollowing::DoNotFollow;
    explicitDefaults.scope = FilesystemScope::RootDevice;
    explicitDefaults.yieldType = FilesystemYieldType::All;
    explicitDefaults.depthAction = FilesystemDepthAction::Stop;
    const FilesystemCollectionLimits defaultLimits;
    explicitDefaults.operationalDescent = defaultLimits.operationalDescent;
    explicitDefaults.entryWork = defaultLimits.entryWork;
    explicitDefaults.directoryWidth = defaultLimits.directoryWidth;
    explicitDefaults.fullPathBytes = defaultLimits.fullPathBytes;
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
    EXPECT_EQ(SymlinkFollowing::DoNotFollow, resolved.rootFileLinkAction);
    EXPECT_EQ(SymlinkFollowing::DoNotFollow, resolved.rootDirectoryLinkAction);
    EXPECT_EQ(SymlinkFollowing::DoNotFollow, resolved.childFileLinkAction);
    EXPECT_EQ(SymlinkFollowing::DoNotFollow, resolved.childDirectoryLinkAction);
    EXPECT_EQ(FilesystemScope::RootDevice, resolved.scope);
    EXPECT_EQ(FilesystemYieldType::All, resolved.yieldType);
    EXPECT_EQ(FilesystemDepthAction::Stop, resolved.depthAction);
    EXPECT_EQ(128u, resolved.limits.operationalDescent);
    EXPECT_EQ(100000u, resolved.limits.entryWork);
    EXPECT_EQ(4096u, resolved.limits.directoryWidth);
    EXPECT_EQ(4096u, resolved.limits.fullPathBytes);
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
    EXPECT_EQ(resolved.limits.retainedPathBytes, explicitResolved.limits.retainedPathBytes);
    EXPECT_EQ(resolved.limits.openDirectories, explicitResolved.limits.openDirectories);
}

TEST(FilesystemCollectionTest, PreservesExplicitSelectionAndLinkSettings)
{
    FilesystemCollectionRequest request = Request();
    request.direction = FilesystemDirection::Down;
    request.maxDepth = 0;
    request.rootFileLinkAction = SymlinkFollowing::Follow;
    request.rootDirectoryLinkAction = SymlinkFollowing::DoNotFollow;
    request.childFileLinkAction = SymlinkFollowing::DoNotFollow;
    request.childDirectoryLinkAction = SymlinkFollowing::Follow;
    request.scope = FilesystemScope::All;

    const Result<ResolvedFilesystemCollectionRequest> result = ResolveFilesystemCollectionRequest(request);

    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(FilesystemDirection::Down, result->direction);
    EXPECT_EQ(0, result->maxDepth);
    EXPECT_EQ(SymlinkFollowing::Follow, result->rootFileLinkAction);
    EXPECT_EQ(SymlinkFollowing::DoNotFollow, result->rootDirectoryLinkAction);
    EXPECT_EQ(SymlinkFollowing::DoNotFollow, result->childFileLinkAction);
    EXPECT_EQ(SymlinkFollowing::Follow, result->childDirectoryLinkAction);
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

    for (auto field : {&FilesystemCollectionRequest::rootFileLinkAction, &FilesystemCollectionRequest::rootDirectoryLinkAction,
             &FilesystemCollectionRequest::childFileLinkAction, &FilesystemCollectionRequest::childDirectoryLinkAction})
    {
        FilesystemCollectionRequest invalidLink = Request();
        invalidLink.*field = static_cast<SymlinkFollowing>(99);
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

TEST(FilesystemCollectionTest, UnknownTypeHiddenDirectoryDescendsWithoutDeliveringDotEntries)
{
    TestTree tree;
    tree.Directory("root");
    tree.Directory("root/.hidden");
    tree.File("root/.hidden/.dotfile");
    tree.File("root/visible");
    MockContext context;
    ON_CALL(context, ReadDirectory(testing::_)).WillByDefault([](DIR * stream) -> struct dirent* {
        struct dirent* entry = readdir(stream);
        if ((nullptr != entry) && (std::string(entry->d_name) == ".hidden"))
        {
            entry->d_type = DT_UNKNOWN;
        }
        return entry;
    });
    FilesystemCollectionRequest request(tree.Path("root"), FilesystemRootKind::Directory);
    request.direction = FilesystemDirection::Down;
    request.yieldType = FilesystemYieldType::RegularFiles;

    const auto collected = ComplianceEngine::CollectFilesystem(request, context);
    ASSERT_TRUE(collected.HasValue());
    auto entries = Paths(collected->entries);
    std::sort(entries.begin(), entries.end());
    EXPECT_EQ((std::vector<std::string>{tree.Path("root/.hidden/.dotfile"), tree.Path("root/visible")}), entries);

    std::vector<std::string> streamed;
    const auto result = ComplianceEngine::StreamFilesystemCollection(
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

    request.childDirectoryLinkAction = SymlinkFollowing::Follow;
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
    ASSERT_TRUE(alias->targetMetadata.HasValue());
    EXPECT_TRUE(S_ISLNK(alias->linkMetadata.st_mode));
    EXPECT_TRUE(S_ISDIR(alias->targetMetadata.Value().st_mode));
    EXPECT_TRUE(followed->exclusions.empty());

    // A file-only follow setting does not cause directory traversal.
    request.childFileLinkAction = SymlinkFollowing::Follow;
    request.childDirectoryLinkAction = SymlinkFollowing::DoNotFollow;
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
    request.childDirectoryLinkAction = SymlinkFollowing::Follow;
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

TEST(FilesystemCollectionTest, DescendantAbsoluteLinkOutsideAcceptedRootFailsClosed)
{
    TestTree tree;
    tree.Directory("root");
    tree.File("outside");
    tree.Link(tree.Path("outside"), "root/alias");
    FilesystemCollectionRequest request(tree.Path("root"), FilesystemRootKind::Directory);
    request.childFileLinkAction = SymlinkFollowing::Follow;
    const auto result = CollectFilesystem(request);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(ENOTDIR, result.Error().code); // The outside prefix is not an accepted-root directory.
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

    MockContext context;
    auto range = Files(request, context);
    ASSERT_TRUE(range.HasValue());
    EXPECT_TRUE(range->RootExists());
    EXPECT_EQ(range->begin(), range->end());
    EXPECT_TRUE(range->Close().HasValue());
    const auto streamed = ComplianceEngine::StreamFilesystemCollection(
        request, [](const FilesystemCollectionEntry&) { return Result<FilesystemVisitAction>(FilesystemVisitAction::Continue); }, context);
    ASSERT_TRUE(streamed.HasValue());
    EXPECT_TRUE(streamed->entries.empty());
    ASSERT_EQ(1u, streamed->exclusions.size());
    EXPECT_EQ(tree.Path("alias"), streamed->exclusions[0].path);

    request.rootDirectoryLinkAction = SymlinkFollowing::Follow;
    const auto followed = CollectFilesystem(request);
    ASSERT_TRUE(followed.HasValue());
    EXPECT_EQ(2u, followed->entries.size());
    EXPECT_TRUE(followed->entries[0].targetMetadata.HasValue());
    EXPECT_TRUE(S_ISLNK(followed->entries[0].linkMetadata.st_mode));
    EXPECT_TRUE(S_ISDIR(followed->entries[0].targetMetadata.Value().st_mode));
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

    file.rootFileLinkAction = SymlinkFollowing::Follow;
    const auto followedRoot = CollectFilesystem(file);
    ASSERT_TRUE(followedRoot.HasValue());
    ASSERT_EQ(1u, followedRoot->entries.size());
    EXPECT_TRUE(S_ISLNK(followedRoot->entries[0].linkMetadata.st_mode));
    ASSERT_TRUE(followedRoot->entries[0].targetMetadata.HasValue());
    EXPECT_TRUE(S_ISREG(followedRoot->entries[0].targetMetadata.Value().st_mode));
    EXPECT_TRUE(followedRoot->exclusions.empty());

    FilesystemCollectionRequest children(tree.Path("root"), FilesystemRootKind::Directory);
    children.yieldType = FilesystemYieldType::RegularFiles;
    const auto skippedChild = CollectFilesystem(children);
    ASSERT_TRUE(skippedChild.HasValue());
    EXPECT_EQ(std::vector<std::string>{tree.Path("root/target")}, Paths(skippedChild->entries));
    ASSERT_EQ(1u, skippedChild->exclusions.size());
    EXPECT_EQ(tree.Path("root/alias"), skippedChild->exclusions[0].path);

    children.childFileLinkAction = SymlinkFollowing::Follow;
    const auto followedChild = CollectFilesystem(children);
    ASSERT_TRUE(followedChild.HasValue());
    ASSERT_EQ(2u, followedChild->entries.size());
    const auto alias = std::find_if(followedChild->entries.begin(), followedChild->entries.end(),
        [&tree](const FilesystemCollectionEntry& entry) { return entry.path == tree.Path("root/alias"); });
    ASSERT_NE(followedChild->entries.end(), alias);
    EXPECT_TRUE(S_ISLNK(alias->linkMetadata.st_mode));
    ASSERT_TRUE(alias->targetMetadata.HasValue());
    EXPECT_TRUE(S_ISREG(alias->targetMetadata.Value().st_mode));
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
    MockContext context;
    int targetStats = 0;
    ON_CALL(context, StatPath(testing::_, testing::_)).WillByDefault([&](const char* path, struct stat* metadata) {
        ++targetStats;
        return context.ContextInterface::StatPath(path, metadata);
    });
    FilesystemCollectionRequest request(tree.Path("root/dangling"), FilesystemRootKind::File);
    const auto skipped = ComplianceEngine::CollectFilesystem(request, context);
    ASSERT_TRUE(skipped.HasValue());
    EXPECT_TRUE(skipped->entries.empty());
    ASSERT_EQ(1u, skipped->exclusions.size());
    EXPECT_EQ(tree.Path("root/dangling"), skipped->exclusions[0].path);
    EXPECT_EQ("link policy", skipped->exclusions[0].reason);
    EXPECT_EQ(0, targetStats);

    request.rootPath = tree.Path("root");
    request.rootKind = FilesystemRootKind::Directory;
    const auto child = ComplianceEngine::CollectFilesystem(request, context);
    ASSERT_TRUE(child.HasValue());
    EXPECT_EQ(std::vector<std::string>{tree.Path("root")}, Paths(child->entries));
    ASSERT_EQ(1u, child->exclusions.size());
    EXPECT_EQ(tree.Path("root/dangling"), child->exclusions[0].path);
    EXPECT_EQ(0, targetStats);
    request.childFileLinkAction = SymlinkFollowing::Follow;
    request.childDirectoryLinkAction = SymlinkFollowing::Follow;
    const auto followed = ComplianceEngine::CollectFilesystem(request, context);
    ASSERT_FALSE(followed.HasValue());
    EXPECT_EQ(ENOENT, followed.Error().code);
    EXPECT_EQ(0, targetStats); // Descendant acquisition is confined to held descriptors.
}

TEST(FilesystemCollectionTest, FollowingDanglingLinkFailsRatherThanReturningAbsentRoot)
{
    TestTree tree;
    tree.Link(tree.Path("missing"), "dangling");
    FilesystemCollectionRequest request(tree.Path("dangling"), FilesystemRootKind::File);
    request.rootFileLinkAction = SymlinkFollowing::Follow;
    request.rootDirectoryLinkAction = SymlinkFollowing::Follow;
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

TEST(FilesystemCollectionTest, ReplacingObservedChildLinkBeforePinningFailsInsteadOfMixingEvidence)
{
    TestTree tree;
    tree.Directory("root");
    tree.File("root/first");
    tree.File("root/second");
    tree.Link("first", "root/alias");
    struct stat original = {};
    ASSERT_EQ(0, lstat(tree.Path("root/alias").c_str(), &original));
    MockContext context;
    bool replaced = false;
    ON_CALL(context, StatFileDescriptor(testing::_, testing::_)).WillByDefault([&](int descriptor, struct stat* metadata) {
        const int result = fstat(descriptor, metadata);
        if (!replaced && 0 == result && S_ISLNK(metadata->st_mode) && metadata->st_ino == original.st_ino && metadata->st_dev == original.st_dev)
        {
            replaced = true;
            EXPECT_EQ(0, rename(tree.Path("root/alias").c_str(), tree.Path("root/old-alias").c_str()));
            tree.Link("second", "root/alias");
        }
        return result;
    });
    FilesystemCollectionRequest request(tree.Path("root"), FilesystemRootKind::Directory);
    request.direction = FilesystemDirection::Down;
    request.childFileLinkAction = SymlinkFollowing::Follow;
    request.yieldType = FilesystemYieldType::RegularFiles;
    const auto collected = ComplianceEngine::CollectFilesystem(request, context);
    EXPECT_TRUE(replaced);
    ASSERT_FALSE(collected.HasValue());
    EXPECT_EQ(ESTALE, collected.Error().code);
}

TEST(FilesystemCollectionTest, ReplacingObservedRootLinkBeforePinningFailsInsteadOfMixingEvidence)
{
    TestTree tree;
    tree.File("first");
    tree.File("second");
    tree.Link("first", "alias");
    MockContext context;
    ON_CALL(context, LstatPath(testing::_, testing::_)).WillByDefault([&](const char* path, struct stat* metadata) {
        const int result = lstat(path, metadata);
        if (0 == result)
        {
            EXPECT_EQ(0, rename(tree.Path("alias").c_str(), tree.Path("old-alias").c_str()));
            tree.Link("second", "alias");
        }
        return result;
    });
    FilesystemCollectionRequest request(tree.Path("alias"), FilesystemRootKind::File);
    request.rootFileLinkAction = SymlinkFollowing::Follow;
    const auto opened = Files(request, context);
    ASSERT_FALSE(opened.HasValue());
    EXPECT_EQ(ESTALE, opened.Error().code);
}

TEST(FilesystemCollectionTest, FactoryConvertsAllocationFailureDuringRootLookupToENOMEM)
{
    MockContext context;
    ON_CALL(context, LstatPath(testing::_, testing::_)).WillByDefault([](const char*, struct stat*) -> int { throw std::bad_alloc(); });
    const auto opened = Files(Request(), context);
    ASSERT_FALSE(opened.HasValue());
    EXPECT_EQ(ENOMEM, opened.Error().code);
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
    MockContext context;
    ON_CALL(context, ReadDirectory(testing::_)).WillByDefault([](DIR*) -> struct dirent* {
        errno = EIO;
        return nullptr;
    });
    const auto result = ComplianceEngine::CollectFilesystem(FilesystemCollectionRequest(tree.Path("root"), FilesystemRootKind::Directory), context);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EIO, result.Error().code);
    EXPECT_NE(std::string::npos, result.Error().message.find(tree.Path("root")));
}

TEST(FilesystemCollectionTest, RequiredStatFailurePropagatesItsOriginalCode)
{
    TestTree tree;
    tree.Directory("root");
    MockContext context;
    ON_CALL(context, StatFileDescriptor(testing::_, testing::_)).WillByDefault([](int, struct stat*) {
        errno = EACCES;
        return -1;
    });
    const auto result = ComplianceEngine::CollectFilesystem(FilesystemCollectionRequest(tree.Path("root"), FilesystemRootKind::Directory), context);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EACCES, result.Error().code);
}

TEST(FilesystemCollectionTest, StandaloneCloseFailureErrorsAndSecondaryClosePreservesCallbackError)
{
    TestTree tree;
    tree.Directory("root");
    tree.File("root/child");
    MockContext context;
    ON_CALL(context, CloseDirectory(testing::_)).WillByDefault([](DIR* stream) {
        const int status = closedir(stream);
        if (0 != status)
        {
            return status;
        }
        errno = EIO;
        return -1;
    });
    const FilesystemCollectionRequest request(tree.Path("root"), FilesystemRootKind::Directory);
    const auto standalone = ComplianceEngine::CollectFilesystem(request, context);
    ASSERT_FALSE(standalone.HasValue());
    EXPECT_EQ(EIO, standalone.Error().code);

    const auto secondary = ComplianceEngine::StreamFilesystemCollection(
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

TEST(FilesystemCollectionTest, CheckedChildCloseFailureStopsTraversal)
{
    TestTree tree;
    tree.Directory("root");
    tree.Directory("root/child");
    FilesystemCollectionRequest request(tree.Path("root"), FilesystemRootKind::Directory);
    request.direction = FilesystemDirection::Down;
    MockContext context;
    ON_CALL(context, CloseDirectory(testing::_)).WillByDefault([](DIR* stream) {
        const int status = closedir(stream);
        if (0 != status)
        {
            return status;
        }
        errno = EIO;
        return -1;
    });
    const auto result = ComplianceEngine::CollectFilesystem(request, context);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EIO, result.Error().code);
}

TEST(FilesystemCollectionTest, RootDeviceAndDefinedSelectSameMount)
{
    TestTree tree;
    tree.Directory("root");
    tree.File("root/other-device");
    MockContext context;
    FilesystemCollectionRequest request(tree.Path("root"), FilesystemRootKind::Directory);
    const auto bounded = ComplianceEngine::CollectFilesystem(request, context);
    ASSERT_TRUE(bounded.HasValue());
    EXPECT_EQ(2u, bounded->entries.size());
    EXPECT_TRUE(bounded->exclusions.empty());

    request.scope = FilesystemScope::Defined;
    const auto defined = ComplianceEngine::CollectFilesystem(request, context);
    ASSERT_TRUE(defined.HasValue());
    EXPECT_EQ(2u, defined->entries.size());
    EXPECT_TRUE(defined->exclusions.empty());

    request.scope = FilesystemScope::All;
    const auto all = ComplianceEngine::CollectFilesystem(request, context);
    ASSERT_TRUE(all.HasValue());
    EXPECT_EQ(2u, all->entries.size());
    EXPECT_TRUE(all->exclusions.empty());
}

TEST(FilesystemCollectionTest, FactoryAcquiresRootButReadsDescendantsOnePullAtATime)
{
    TestTree tree;
    tree.Directory("root");
    tree.File("root/item");
    MockContext context;
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
    auto& files = opened.Value();
    EXPECT_EQ(1u, stats);
    EXPECT_EQ(0u, reads);
    EXPECT_TRUE(files.RootExists());

    auto entry = files.begin();
    ASSERT_NE(entry, files.end());
    ASSERT_TRUE(entry->HasValue());
    EXPECT_EQ(tree.Path("root"), entry->Value().path);
    ASSERT_NE(nullptr, entry->Value().LiveHandle());
    auto rootIdentity = entry->Value().LiveHandle()->Stat(FilesystemCollectionLimits{}.fullPathBytes);
    ASSERT_TRUE(rootIdentity.HasValue()) << rootIdentity.Error().message;
    EXPECT_EQ(1u, stats);
    EXPECT_EQ(0u, reads);

    ++entry;
    ASSERT_NE(entry, files.end());
    ASSERT_TRUE(entry->HasValue());
    EXPECT_EQ(tree.Path("root/item"), entry->Value().path);
    EXPECT_EQ(1u, stats);
    EXPECT_EQ(1u, reads);
    ASSERT_NE(nullptr, entry->Value().LiveHandle());
    EXPECT_EQ(ComplianceEngine::Filesystem::Handle::Type::RegularFile, entry->Value().LiveHandle()->AcquiredType());

    ++entry;
    EXPECT_EQ(entry, files.end());
    EXPECT_TRUE(files.Close().HasValue());
    EXPECT_EQ(1u, stats);
}

TEST(FilesystemCollectionTest, RangeForRetainsEachRegularFilePinWithoutReacquiringItsName)
{
    TestTree tree;
    tree.Directory("root");
    tree.File("root/first");
    tree.File("root/second");
    MockContext context;
    std::size_t rootLookups = 0;
    ON_CALL(context, LstatPath(testing::_, testing::_)).WillByDefault([&](const char* path, struct stat* metadata) {
        ++rootLookups;
        EXPECT_EQ(tree.Path("root"), path);
        return lstat(path, metadata);
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
        const auto& entry = item.Value();
        ASSERT_NE(nullptr, entry.LiveHandle());
        const auto inode = entry.LiveHandle()->Stat().st_ino;
        ASSERT_EQ(0, unlink(entry.path.c_str()));
        auto inspected = entry.LiveHandle()->Stat(FilesystemCollectionLimits{}.fullPathBytes);
        ASSERT_TRUE(inspected.HasValue()) << inspected.Error().message;
        EXPECT_EQ(inode, inspected.Value().st_ino);
        seen.push_back(entry.path);
    }
    std::sort(seen.begin(), seen.end());
    EXPECT_EQ((std::vector<std::string>{tree.Path("root/first"), tree.Path("root/second")}), seen);
    EXPECT_EQ(1u, rootLookups);
    EXPECT_TRUE(opened->Close().HasValue());
}

TEST(FilesystemCollectionTest, FactorySeparatesAbsentRootFromInitializationFailures)
{
    TestTree tree;
    tree.Directory("root");
    MockContext context;
    FilesystemCollectionRequest request(tree.Path("missing"), FilesystemRootKind::Directory);
    auto absent = Files(request, context);
    ASSERT_TRUE(absent.HasValue());
    EXPECT_FALSE(absent->RootExists());
    EXPECT_TRUE(absent->Close().HasValue());
    EXPECT_TRUE(absent->Close().HasValue());
    EXPECT_EQ(absent->begin(), absent->end());

    request.rootPath = tree.Path("root");
    request.yieldType = FilesystemYieldType::RegularFiles;
    auto existing = Files(request, context);
    ASSERT_TRUE(existing.HasValue());
    EXPECT_TRUE(existing->RootExists());
    EXPECT_EQ(existing->begin(), existing->end());
    EXPECT_TRUE(existing->Close().HasValue());
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

    ON_CALL(context, LstatPath(testing::_, testing::_)).WillByDefault([](const char*, struct stat*) {
        errno = EACCES;
        return -1;
    });
    const auto lstatFailure = Files(request, context);
    ASSERT_FALSE(lstatFailure.HasValue());
    EXPECT_EQ(EACCES, lstatFailure.Error().code);
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
    MockContext context;
    const auto selected = ComplianceEngine::CollectFilesystem(request, context);
    ASSERT_TRUE(selected.HasValue());
    EXPECT_EQ(std::vector<std::string>{tree.Path("root/nested/file")}, Paths(selected->entries));

    request.yieldType = FilesystemYieldType::Directories;
    const auto directories = ComplianceEngine::CollectFilesystem(request, context);
    ASSERT_TRUE(directories.HasValue());
    EXPECT_EQ((std::vector<std::string>{tree.Path("root"), tree.Path("root/nested")}), Paths(directories->entries));

    request.yieldType = FilesystemYieldType::RegularFiles;
    request.entryWork = 1;
    const auto budget = ComplianceEngine::CollectFilesystem(request, context);
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
    EXPECT_EQ(EACCES, opened->Close().Error().code);
}

TEST(FilesystemCollectionTest, LinkSelectionUsesEffectiveMetadataWithoutLosingLstat)
{
    TestTree tree;
    tree.Directory("root");
    tree.File("root/target");
    tree.Link("target", "root/link");
    MockContext context;
    FilesystemCollectionRequest request(tree.Path("root"), FilesystemRootKind::Directory);
    request.direction = FilesystemDirection::Down;
    request.yieldType = FilesystemYieldType::RegularFiles;
    auto recorded = ComplianceEngine::CollectFilesystem(request, context);
    ASSERT_TRUE(recorded.HasValue());
    EXPECT_EQ(std::vector<std::string>{tree.Path("root/target")}, Paths(recorded->entries));

    request.childFileLinkAction = SymlinkFollowing::Follow;
    auto followed = ComplianceEngine::CollectFilesystem(request, context);
    ASSERT_TRUE(followed.HasValue());
    ASSERT_EQ(2u, followed->entries.size());
    const auto link = std::find_if(followed->entries.begin(), followed->entries.end(),
        [&tree](const FilesystemCollectionEntry& entry) { return entry.path == tree.Path("root/link"); });
    ASSERT_NE(followed->entries.end(), link);
    EXPECT_TRUE(S_ISLNK(link->linkMetadata.st_mode));
    struct stat expectedLink = {};
    ASSERT_EQ(0, lstat(tree.Path("root/link").c_str(), &expectedLink));
    EXPECT_EQ(expectedLink.st_dev, link->linkMetadata.st_dev);
    EXPECT_EQ(expectedLink.st_ino, link->linkMetadata.st_ino);
    ASSERT_TRUE(link->targetMetadata.HasValue());
    EXPECT_TRUE(S_ISREG(link->targetMetadata.Value().st_mode));

    request.yieldType = FilesystemYieldType::SymbolicLinks;
    request.childFileLinkAction = SymlinkFollowing::DoNotFollow;
    auto links = ComplianceEngine::CollectFilesystem(request, context);
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
    MockContext context;
    const auto result = ComplianceEngine::CollectFilesystem(request, context);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ("Maximum recursion depth reached", result.Error().message);
}

TEST(FilesystemCollectionTest, FactoryPolicyFailurePrecedesRootAcquisition)
{
    MockContext context;
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
    MockContext context;
    struct stat expectedChild = {};
    ASSERT_EQ(0, stat(tree.Path("root/child").c_str(), &expectedChild));
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
    auto& files = opened.Value();
    auto entry = files.begin();
    ASSERT_NE(entry, files.end());
    ASSERT_TRUE(entry->HasValue());
    ++entry;
    ASSERT_NE(entry, files.end());
    ASSERT_TRUE(entry->HasValue());
    EXPECT_EQ(tree.Path("root/child"), entry->Value().path);
    ASSERT_NE(nullptr, entry->Value().LiveHandle());
    const auto childInode = entry->Value().LiveHandle()->Stat().st_ino;
    EXPECT_EQ(expectedChild.st_ino, childInode);
    ++entry;
    ASSERT_NE(entry, files.end());
    ASSERT_FALSE(entry->HasValue());
    EXPECT_EQ(EACCES, entry->Error().code);
    ++entry;
    EXPECT_EQ(entry, files.end());
    EXPECT_EQ(EACCES, files.Close().Error().code);
    EXPECT_TRUE(files.RootExists());
}

TEST(FilesystemCollectionTest, LateReadErrorIsYieldedOnceAndNeverCertifiesCompletion)
{
    TestTree tree;
    tree.Directory("root");
    MockContext context;
    ON_CALL(context, ReadDirectory(testing::_)).WillByDefault([](DIR*) -> struct dirent* {
        errno = EIO;
        return nullptr;
    });
    auto opened = Files(FilesystemCollectionRequest(tree.Path("root"), FilesystemRootKind::Directory), context);
    ASSERT_TRUE(opened.HasValue());
    auto& files = opened.Value();
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
    EXPECT_EQ(EIO, files.Close().Error().code);
}

TEST(FilesystemCollectionTest, ExhaustionCloseFailureIsDeliveredThroughRange)
{
    TestTree tree;
    tree.Directory("root");
    MockContext context;
    ON_CALL(context, CloseDirectory(testing::_)).WillByDefault([](DIR* stream) {
        const int result = closedir(stream);
        if (0 == result)
        {
            errno = EIO;
            return -1;
        }
        return result;
    });
    auto opened = Files(FilesystemCollectionRequest(tree.Path("root"), FilesystemRootKind::Directory), context);
    ASSERT_TRUE(opened.HasValue());
    auto& files = opened.Value();
    auto entry = files.begin();
    ASSERT_NE(entry, files.end());
    ASSERT_TRUE(entry->HasValue());
    ++entry;
    ASSERT_NE(entry, files.end());
    ASSERT_FALSE(entry->HasValue());
    EXPECT_EQ(EIO, entry->Error().code);
    ++entry;
    EXPECT_EQ(entry, files.end());
    EXPECT_EQ(EIO, files.Close().Error().code);
}

TEST(FilesystemCollectionTest, EarlyCloseIsIdempotentAndDoesNotReadUnseenEntries)
{
    TestTree tree;
    tree.Directory("root");
    tree.File("root/item");
    MockContext context;
    std::size_t closed = 0;
    std::size_t reads = 0;
    ON_CALL(context, CloseDirectory(testing::_)).WillByDefault([&closed](DIR* stream) {
        ++closed;
        return closedir(stream);
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
        auto& files = opened.Value();
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
        const auto closedResult = files.Close();
        ASSERT_TRUE(closedResult.HasValue());
        EXPECT_EQ(beforeClose, reads);
        EXPECT_EQ(1u, closed);
        EXPECT_TRUE(files.Close().HasValue());
        EXPECT_EQ(1u, closed);
        EXPECT_EQ(files.begin(), files.end());
    }
    EXPECT_EQ(1u, closed);
}

TEST(FilesystemCollectionTest, AbandonedRangeClosesWithoutPullingDescendants)
{
    TestTree tree;
    tree.Directory("root");
    tree.File("root/item");
    MockContext context;
    std::size_t closed = 0;
    EXPECT_CALL(context, ReadDirectory(testing::_)).Times(0);
    ON_CALL(context, CloseDirectory(testing::_)).WillByDefault([&closed](DIR* stream) {
        ++closed;
        const int status = closedir(stream);
        errno = EIO;
        return 0 == status ? -1 : status;
    });
    {
        auto opened = Files(FilesystemCollectionRequest(tree.Path("root"), FilesystemRootKind::Directory), context);
        ASSERT_TRUE(opened.HasValue());
        EXPECT_TRUE(opened->RootExists());
    }
    EXPECT_EQ(1u, closed);
}

TEST(FilesystemCollectionTest, EarlyClosePropagatesFailure)
{
    TestTree tree;
    tree.Directory("root");
    tree.File("root/item");
    MockContext context;
    FilesystemCollectionRequest request(tree.Path("root"), FilesystemRootKind::Directory);
    request.direction = FilesystemDirection::Down;
    auto opened = Files(request, context);
    ASSERT_TRUE(opened.HasValue());
    auto& files = opened.Value();
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
            return -1;
        }
        return result;
    });
    const auto closed = files.Close();
    ASSERT_FALSE(closed.HasValue());
    EXPECT_EQ(EIO, closed.Error().code);
    EXPECT_EQ(EIO, files.Close().Error().code);
}

TEST(FilesystemCollectionTest, VisitorStopDoesNotDrainUnvisitedEntries)
{
    TestTree tree;
    tree.Directory("root");
    tree.File("root/item");
    MockContext context;
    FilesystemCollectionRequest request(tree.Path("root"), FilesystemRootKind::Directory);
    request.direction = FilesystemDirection::Down;
    EXPECT_CALL(context, ReadDirectory(testing::_)).Times(0);
    const auto stopped = StreamFilesystemCollection(
        request, [](const FilesystemCollectionEntry&) { return ComplianceEngine::Result<FilesystemVisitAction>(FilesystemVisitAction::Stop); }, context);
    ASSERT_TRUE(stopped.HasValue());
    EXPECT_TRUE(stopped->entries.empty());
}
