// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// C4 (FTW layer): the nine FTW-dependent cases moved out of PathTest.cpp
// (C3) because they exercise FTW::Files/FilesystemCollection/DirectoryCursor,
// which only exist once the FTW layer is present. Test names are unchanged
// (PathAliasTest.*/PathKernelIntegrationTest.NativeProcfsAndPinnedOperations);
// shared fixtures/helpers (PathAliasTest, SelectAcceptedPath, SelectStep,
// CrossMountPathPolicy, KernelMountId, ...) live in the C3 PathTestSupport.h,
// which this C4 file includes rather than duplicating.

#include <DescriptorTestAccess.h>
#include <DirectoryCursorTestAccess.h>
#include <PathTestAccess.h>
#include <PathTestSupport.h>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <filesystem/FTWDirectoryCursor.hpp>
#include <filesystem/FilesystemCollection.hpp>
#include <filesystem/Path.hpp>
#include <fstream>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <linux/magic.h>
#include <set>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <utility>

using ComplianceEngine::As;
using ComplianceEngine::Filesystem::FilesystemTraversalPolicy;
using ComplianceEngine::Filesystem::Path;
using ComplianceEngine::Filesystem::ReadableFile;
using ComplianceEngine::Filesystem::ResolverLimits;
using ComplianceEngine::Filesystem::Type;
using ComplianceEngine::Filesystem::Detail::Descriptor;
using ComplianceEngine::Filesystem::FTW::Files;
using ComplianceEngine::Tests::CountOpenDescriptors;
using ComplianceEngine::Tests::CrossMountPathPolicy;
using ComplianceEngine::Tests::DescriptorTarget;
using ComplianceEngine::Tests::DescriptorTestAccess;
using ComplianceEngine::Tests::DirectoryCursorTestAccess;
using ComplianceEngine::Tests::ExpectLoggedOnce;
using ComplianceEngine::Tests::KernelMountId;
using ComplianceEngine::Tests::OwnedTestDescriptor;
using ComplianceEngine::Tests::PathAliasTest;
using ComplianceEngine::Tests::PathTestAccess;
using ComplianceEngine::Tests::ReadLog;
using ComplianceEngine::Tests::SelectAcceptedPath;
using ComplianceEngine::Tests::SelectStep;
using testing::_;
using testing::NiceMock;

namespace
{
// OpenDirectoryCursor (ContextInterface::OpenDirectoryCursor) fdopendir()s its
// argument directly; it requires an already-activated, readable directory
// descriptor (not a raw O_PATH pin), matching how DirectoryCursor::OpenChildren
// hands it one after procfs-alias activation.
ComplianceEngine::Result<Descriptor> OpenActivatedDirectory(const ComplianceEngine::ContextInterface& context, const char* path)
{
    auto pinned = DescriptorTestAccess::OpenAbsolutePin(context, path);
    if (!pinned.HasValue())
        return std::move(pinned).Error();
    auto procfs = DescriptorTestAccess::ProcfsAccess(context);
    if (!procfs.HasValue())
        return std::move(procfs).Error();
    return DescriptorTestAccess::OpenAlias(context, procfs.Value(), pinned.Value(), Type::Directory);
}

// Directory read-only activation (procfs alias -> fdopendir handoff) is a
// private Pin/DirectoryCursor operation with no direct public
// entry point; FTW::Files(Path, ...) is the public route that drives it (via
// FileRange::State::Initialize).
TEST_F(PathAliasTest, DirectoryActivationTransfersVerifiedOwnerWithoutDuplicate)
{
    const std::string directory = context.GetTempdirPath() + "/acquired";
    ASSERT_EQ(0, ::mkdir(directory.c_str(), 0700));
    struct stat pinnedIdentity = {};
    ASSERT_EQ(0, ::stat(directory.c_str(), &pinnedIdentity));
    int alias = -1;
    bool closedStream = false;
    std::size_t pins = 0;
    std::size_t before = 0;
    {
        auto opened = SelectAcceptedPath(context, directory, CrossMountPathPolicy(), AmpleLimits());
        ASSERT_TRUE(opened.HasValue());
        Path path = std::move(opened).Value();
        pins = path.RetainedDescriptors();
        before = CountOpenDescriptors();
        EXPECT_CALL(context, DuplicateDescriptor(_)).Times(0);
        EXPECT_CALL(context, OpenNativeAt(_, _, _)).WillRepeatedly([&](int directoryFd, const char* name, int flags) {
            const int descriptor = context.RealOpenNativeAt(directoryFd, name, flags);
            if ((0 <= descriptor) && (0 == (flags & O_PATH)) && (0 == (flags & O_NOFOLLOW)) && (0 != (flags & O_DIRECTORY)))
            {
                alias = descriptor;
            }
            return descriptor;
        });
        EXPECT_CALL(context, CloseNativeDescriptor(_)).WillRepeatedly([&](int descriptor) -> ComplianceEngine::Result<void> {
            EXPECT_NE(descriptor, alias);
            const int status = ::close(descriptor);
            EXPECT_EQ(0, status);
            return NativeCloseResult(status);
        });
        EXPECT_CALL(context, CloseDirectory(_)).WillOnce([&](DIR* stream) {
            closedStream = true;
            // The handed-off alias, not a duplicate, backs the directory
            // stream: it still identifies the originally pinned directory.
            struct stat streamIdentity = {};
            EXPECT_EQ(0, ::fstat(::dirfd(stream), &streamIdentity));
            EXPECT_EQ(pinnedIdentity.st_dev, streamIdentity.st_dev);
            EXPECT_EQ(pinnedIdentity.st_ino, streamIdentity.st_ino);
            return NativeCloseResult(::closedir(stream));
        });
        // Files() takes ownership of path (freezing its leaf) and, for a
        // directory root, synchronously activates and opens its children cursor
        // inside Initialize() -- the same DirectoryCursor::OpenChildren
        // production call exercised here through Files(). Path moves transfer
        // ownership (ADR-0048), so path is moved-from after this call and the
        // range alone retains the pin.
        auto range = Files(std::move(path), directory, FilesystemTraversalPolicy{});
        ASSERT_TRUE(range.HasValue()) << range.Error().message;
        EXPECT_GE(alias, 0); // the activation alias was actually captured
        std::size_t seen = 0;
        for (const auto& entry : range.Value())
        {
            ASSERT_TRUE(entry.HasValue()) << entry.Error().message;
            ++seen;
        }
        EXPECT_EQ(1U, seen); // only the empty root directory's own entry; no children
    }
    EXPECT_TRUE(closedStream);
    EXPECT_EQ(before - pins, CountOpenDescriptors());
    ASSERT_TRUE(testing::Mock::VerifyAndClearExpectations(&context));
}

TEST_F(PathAliasTest, FailedDirectoryTransferPreservesNativeErrorAndClosesOwnerOnce)
{
    const std::string directory = context.GetTempdirPath() + "/acquired";
    ASSERT_EQ(0, ::mkdir(directory.c_str(), 0700));
    int operational = -1;
    int cleanupAttempts = 0;
    auto opened = SelectAcceptedPath(context, directory, CrossMountPathPolicy(), AmpleLimits());
    ASSERT_TRUE(opened.HasValue()) << opened.Error().message;
    Path path = std::move(opened).Value();
    EXPECT_CALL(context, FdOpenDirectory(_)).Times(1).WillOnce([&](int descriptor) -> DIR* {
        operational = descriptor;
        errno = EACCES;
        return nullptr;
    });
    EXPECT_CALL(context, CloseNativeDescriptor(_)).WillRepeatedly([&](int descriptor) -> ComplianceEngine::Result<void> {
        EXPECT_EQ(0, ::close(descriptor));
        if (descriptor == operational)
        {
            ++cleanupAttempts;
            errno = EIO;
            return ComplianceEngine::Error(errno ? errno : EIO);
        }
        return ComplianceEngine::Result<void>::Success();
    });
    // Files() consumes path and, on Initialize() failure, drops its internal
    // State (and the Path it owns) before returning, so the source pin is
    // retired by the time the result is observed.
    auto range = Files(std::move(path), directory, FilesystemTraversalPolicy{});
    ASSERT_FALSE(range.HasValue());
    EXPECT_EQ(EACCES, range.Error().code);
    EXPECT_EQ(1, cleanupAttempts);
}

// The three tests below exercise DirectoryCursor's own close/move RAII
// contract (no retry, no replay, log-accessor use), independent of how the
// cursor was produced. ContextInterface::OpenDirectoryCursor (wrapped by
// DirectoryCursorTestAccess::OpenDirectoryCursor) directly fdopendir()s an
// already-held pin.
TEST_F(PathAliasTest, DirectoryCursorFailedCloseIsNotReplayedOrRetried)
{
    const std::string logPath = context.GetTempdirPath() + "/cursor-close.log";
    OsConfigLogHandle log = OpenLog(logPath.c_str(), nullptr);
    ASSERT_NE(nullptr, log);
    context.SetLogHandle(log);
    const auto before = CountOpenDescriptors();
    auto activated = OpenActivatedDirectory(context, context.GetTempdirPath().c_str());
    ASSERT_TRUE(activated.HasValue()) << activated.Error().message;
    auto cursor = DirectoryCursorTestAccess::OpenDirectoryCursor(context, std::move(activated).Value());
    ASSERT_TRUE(cursor.HasValue());
    EXPECT_CALL(context, CloseDirectory(_)).Times(1).WillOnce([](DIR* stream) {
        EXPECT_EQ(0, ::closedir(stream));
        errno = EIO;
        return ComplianceEngine::Error(errno ? errno : EIO);
    });
    cursor.Value().Close();
    cursor.Value().Close();
    auto moved = std::move(cursor).Value();
    moved.Close();
    EXPECT_EQ(before, CountOpenDescriptors());
    CloseLog(&log);
    context.SetLogHandle(nullptr);
    ExpectLoggedOnce(ReadLog(logPath), "Failed to close filesystem resource: " + std::string(strerror(EIO)));
}

TEST_F(PathAliasTest, DirectoryCursorNativeCloseErrorAndReplacementReleaseOnce)
{
    auto firstActivated = OpenActivatedDirectory(context, context.GetTempdirPath().c_str());
    auto secondActivated = OpenActivatedDirectory(context, context.GetTempdirPath().c_str());
    ASSERT_TRUE(firstActivated.HasValue()) << firstActivated.Error().message;
    ASSERT_TRUE(secondActivated.HasValue()) << secondActivated.Error().message;
    auto first = DirectoryCursorTestAccess::OpenDirectoryCursor(context, std::move(firstActivated).Value());
    auto second = DirectoryCursorTestAccess::OpenDirectoryCursor(context, std::move(secondActivated).Value());
    ASSERT_TRUE(first.HasValue());
    ASSERT_TRUE(second.HasValue());
    const auto before = CountOpenDescriptors();
    EXPECT_CALL(context, CloseDirectory(_))
        .Times(2)
        .WillOnce([](DIR* stream) -> ComplianceEngine::Result<void> {
            EXPECT_EQ(0, ::closedir(stream));
            errno = EIO;
            return ComplianceEngine::Error(errno ? errno : EIO);
        })
        .WillOnce([](DIR* stream) { return NativeCloseResult(::closedir(stream)); });
    first.Value() = std::move(second.Value()); // displaced owner closes inside its guarded destructor
    second.Value().Close();
    // The transferred stream still owns the second, live directory.
    first.Value().Close();
    EXPECT_EQ(before - 2, CountOpenDescriptors());
    ASSERT_TRUE(testing::Mock::VerifyAndClearExpectations(&context));
    auto thirdActivated = OpenActivatedDirectory(context, context.GetTempdirPath().c_str());
    ASSERT_TRUE(thirdActivated.HasValue()) << thirdActivated.Error().message;
    auto third = DirectoryCursorTestAccess::OpenDirectoryCursor(context, std::move(thirdActivated).Value());
    ASSERT_TRUE(third.HasValue());
    EXPECT_CALL(context, CloseDirectory(_)).Times(1).WillOnce([](DIR* stream) -> ComplianceEngine::Result<void> {
        EXPECT_EQ(0, ::closedir(stream));
        errno = EIO;
        return ComplianceEngine::Error(errno ? errno : EIO);
    });
    EXPECT_NO_THROW(third.Value().Close());
    third.Value().Close();
}

TEST_F(PathAliasTest, DirectoryCursorFailedCloseUsesLogAccessorWithoutRetry)
{
    struct CountingLogContext : NiceMock<MockContext>
    {
        OsConfigLogHandle GetLogHandle() const noexcept override
        {
            ++logRequests;
            return MockContext::GetLogHandle();
        }
        mutable int logRequests = 0;
    } selected;
    auto activated = OpenActivatedDirectory(selected, selected.GetTempdirPath().c_str());
    ASSERT_TRUE(activated.HasValue()) << activated.Error().message;
    auto cursor = DirectoryCursorTestAccess::OpenDirectoryCursor(selected, std::move(activated).Value());
    ASSERT_TRUE(cursor.HasValue());
    EXPECT_CALL(selected, CloseDirectory(_)).Times(1).WillOnce([](DIR* stream) {
        EXPECT_EQ(0, ::closedir(stream));
        errno = EACCES;
        return ComplianceEngine::Error(errno ? errno : EIO);
    });
    EXPECT_NO_THROW(cursor.Value().Close());
    EXPECT_EQ(1, selected.logRequests);
    cursor.Value().Close();
}

// DirectoryActivationTransfersVerifiedOwnerWithoutDuplicate (above) iterates
// via FTW::Files() while its Path -- and so the directory pin it was built
// from -- is still alive for the whole traversal. This test instead shows
// the cursor's independent lifetime directly: the pin and its procfs access
// session retire (RAII, scope exit) before the cursor is ever used, and the
// cursor still correctly reads the real directory's children afterwards.
TEST_F(PathAliasTest, DirectoryCursorOutlivesRetiredSourcePin)
{
    using Cursor = ComplianceEngine::Filesystem::FTW::Detail::DirectoryCursor;
    const std::string directory = context.GetTempdirPath() + "/outlives";
    ASSERT_EQ(0, ::mkdir(directory.c_str(), 0700));
    const std::set<std::string> expectedChildren = {"alpha", "beta"};
    for (const auto& name : expectedChildren)
    {
        std::ofstream child((directory + "/" + name).c_str());
        child << "x";
    }
    struct stat directoryIdentity = {};
    ASSERT_EQ(0, ::stat(directory.c_str(), &directoryIdentity));
    const auto before = CountOpenDescriptors();

    int pinFd = -1;
    int pinCloses = 0;
    EXPECT_CALL(context, CloseNativeDescriptor(_)).WillRepeatedly([&](int descriptor) -> ComplianceEngine::Result<void> {
        if (descriptor == pinFd)
            ++pinCloses;
        return NativeCloseResult(::close(descriptor));
    });

    // The pin and the procfs session used to derive the alias both retire
    // (RAII) at the end of this lambda's scope -- strictly before the
    // caller ever touches the returned cursor.
    auto cursor = [&]() -> ComplianceEngine::Result<Cursor> {
        auto pinned = DescriptorTestAccess::OpenAbsolutePin(context, directory.c_str());
        if (!pinned.HasValue())
            return std::move(pinned).Error();
        pinFd = DescriptorTestAccess::ConsumedDescriptor(pinned.Value());
        auto procfs = DescriptorTestAccess::ProcfsAccess(context);
        if (!procfs.HasValue())
            return std::move(procfs).Error();
        auto alias = DescriptorTestAccess::OpenAlias(context, procfs.Value(), pinned.Value(), Type::Directory);
        if (!alias.HasValue())
            return std::move(alias).Error();
        // The verified alias identifies the same directory as the pin it was
        // derived from; OpenDirectoryCursor fdopendir()s this exact fd (no
        // duplicate), so this is also the eventual stream's identity.
        struct stat aliasIdentity = {};
        EXPECT_EQ(0, DescriptorTestAccess::StatFile(context, alias.Value(), &aliasIdentity));
        EXPECT_EQ(directoryIdentity.st_dev, aliasIdentity.st_dev);
        EXPECT_EQ(directoryIdentity.st_ino, aliasIdentity.st_ino);
        return DirectoryCursorTestAccess::OpenDirectoryCursor(context, std::move(alias).Value());
    }();
    ASSERT_TRUE(cursor.HasValue()) << cursor.Error().message;
    EXPECT_GE(pinFd, 0);
    EXPECT_EQ(1, pinCloses); // the originating pin already closed exactly once, before any iteration

    std::set<std::string> seenChildren;
    for (;;)
    {
        auto next = cursor.Value().NextEntry();
        ASSERT_TRUE(next.HasValue()) << next.Error().message;
        if (!next.Value().HasValue())
            break;
        seenChildren.insert(next.Value().Value().name);
    }
    EXPECT_EQ(expectedChildren, seenChildren);

    bool closedStream = false;
    EXPECT_CALL(context, CloseDirectory(_)).WillOnce([&](DIR* stream) {
        closedStream = true;
        // The stream itself, read independently of the (already retired)
        // pin and procfs session, still identifies the original directory.
        struct stat streamIdentity = {};
        EXPECT_EQ(0, ::fstat(::dirfd(stream), &streamIdentity));
        EXPECT_EQ(directoryIdentity.st_dev, streamIdentity.st_dev);
        EXPECT_EQ(directoryIdentity.st_ino, streamIdentity.st_ino);
        return NativeCloseResult(::closedir(stream));
    });
    cursor.Value().Close();
    EXPECT_TRUE(closedStream);
    ASSERT_TRUE(testing::Mock::VerifyAndClearExpectations(&context));
    EXPECT_EQ(before, CountOpenDescriptors());
}

// TM-9 (ADR-0048 Consequences): mirrors the production consumer pattern
// (LogFilePermissions.cpp, SshKeyPermissions.cpp, UserDotFilePermissions.cpp)
// `FTW::Files(As<Path>(std::move(root).Value()), ...)`. `Result<T>::Value() &&`
// (Result.h) returns the payload *by value*, so extracting the Path this way
// move-constructs a new `Variant` from the one `acquired` holds; ADR-0047's
// `MovableVariant` move constructor marks its source moved-from, so the
// leftover `acquired` Variant *is* itself moved-from afterward (a prior
// version of this test and comment claimed otherwise, and asserted on
// `acquired.Value()` again -- which only re-proved the Variant's own
// moved-from check, never reaching Path's). This test targets Path's own
// ADR-0048 rejection, so it extracts the Path into a named local first
// (invoking Path's own move constructor directly, independent of the
// already-moved-from Variant) and asserts on that Path object.
TEST_F(PathAliasTest, LeftoverAfterFilesConsumesThePathAndItCannotResolveAfterward)
{
    const std::string root = context.GetTempdirPath();
    auto acquired = Path::Make(context, root, CrossMountPathPolicy(), AmpleLimits());
    ASSERT_TRUE(acquired.HasValue()) << acquired.Error().message;
    ASSERT_TRUE(acquired.Value().Is<Path>());
    EXPECT_EQ(Type::Directory, As<Path>(acquired.Value()).Leaf().Metadata().FileType());
    Path path = As<Path>(std::move(acquired).Value());
    // Documents the whole-Variant move noted above: re-entering the
    // leftover `acquired` Variant now throws from the Variant's own
    // moved-from check (ADR-0047), not from Path's.
    EXPECT_THROW((void)As<Path>(acquired.Value()), std::logic_error);
    auto opened = Files(std::move(path), root, FilesystemTraversalPolicy{});
    ASSERT_TRUE(opened.HasValue()) << opened.Error().message;
    // `path` is a plain Path object, no longer routed through the Variant:
    // it is moved-from per ADR-0048, and Path's own RequireLive() rejects
    // every checked accessor below.
    EXPECT_THROW((void)path.Leaf(), std::logic_error);
    EXPECT_THROW((void)path.Resolve("x", CrossMountPathPolicy()), std::logic_error);
}

// Directory activation is only publicly reachable by consuming a whole Path
// into FTW::Files(), which now truly transfers ownership (ADR-0048,
// Path(Path&&) moves rather than shares the state pointer), so a
// single acquired root can no longer be handed to Files() for a throwaway
// activation check and then read again afterward. The "fresh acquisition"
// and "after a resolve/apply/inverse round trip" reactivation checks below
// therefore each get their own acquisition of "/".
TEST_F(PathAliasTest, ProcessRootMountObservationIsRetainedAcrossResolveAndInverse)
{
    int observations = 0;
    EXPECT_CALL(context, ReadNativeDescriptor(_, _, _)).WillRepeatedly([&](int fd, void* buffer, std::size_t count) {
        const ssize_t bytes = context.RealReadNativeDescriptor(fd, buffer, count);
        if (bytes > 0 && DescriptorTarget(fd).find("/fdinfo/") != std::string::npos &&
            std::string(static_cast<char*>(buffer), static_cast<std::size_t>(bytes)).find("mnt_id:") != std::string::npos)
            ++observations;
        return bytes;
    });
    OwnedTestDescriptor kernelRoot(::open("/", O_PATH | O_CLOEXEC));
    ASSERT_GE(kernelRoot.Get(), 0);
    auto kernelId = KernelMountId(kernelRoot.Get());
    ASSERT_TRUE(kernelId.HasValue());
    {
        SCOPED_TRACE("fresh acquisition");
        auto opened = SelectAcceptedPath(context, "/", CrossMountPathPolicy(), AmpleLimits());
        ASSERT_TRUE(opened.HasValue()) << opened.Error().message;
        Path path = std::move(opened).Value();
        EXPECT_EQ(1, observations);
        EXPECT_EQ(kernelId.Value(), path.Root().Metadata().LookupMount().Value());
        EXPECT_EQ(kernelId.Value(), path.Root().Metadata().TargetMount().Value());
        auto range = Files(std::move(path), "/", FilesystemTraversalPolicy{});
        ASSERT_TRUE(range.HasValue()) << range.Error().message;
        EXPECT_EQ(1, observations); // reactivation reused the already-held TargetMount
    }
    {
        SCOPED_TRACE("after a resolve/apply/inverse round trip");
        auto opened = SelectAcceptedPath(context, "/", CrossMountPathPolicy(), AmpleLimits());
        ASSERT_TRUE(opened.HasValue()) << opened.Error().message;
        Path path = std::move(opened).Value();
        const int afterAcquire = observations;
        auto child = SelectStep(path, "proc", CrossMountPathPolicy());
        ASSERT_TRUE(child.HasValue()) << child.Error().message;
        EXPECT_EQ(afterAcquire + 1, observations);
        EXPECT_GT(child.Value().Metadata().TargetMount().Value(), 0u);
        auto inverse = path.Apply(std::move(child.Value()));
        ASSERT_TRUE(inverse.HasValue()) << inverse.Error().message;
        EXPECT_EQ(afterAcquire + 1, observations);
        auto restored = path.Apply(std::move(inverse.Value()));
        ASSERT_TRUE(restored.HasValue()) << restored.Error().message;
        EXPECT_EQ(afterAcquire + 1, observations);
        EXPECT_EQ("/", PathTestAccess::ToString(path));
        auto range = Files(std::move(path), "/", FilesystemTraversalPolicy{});
        ASSERT_TRUE(range.HasValue()) << range.Error().message;
        EXPECT_EQ(afterAcquire + 1, observations); // still reused after the round trip
    }
}

// Directory enumeration (DirectoryCursor::OpenChildren) has no direct
// public entry point; FTW::Files(Path, ...) drives the identical production
// code. Files() consumes the whole Path by value, so the listing check runs
// last, after every assertion that needs `path` (or Components derived from
// it).
TEST(PathKernelIntegrationTest, NativeProcfsAndPinnedOperations)
{
    struct utsname kernel = {};
    ASSERT_EQ(0, ::uname(&kernel));
    struct statfs procfs = {};
    ASSERT_EQ(0, ::statfs("/proc/self/fdinfo", &procfs));
    ASSERT_EQ(PROC_SUPER_MAGIC, procfs.f_type);
    NiceMock<MockContext> context;
    const std::string source = context.MakeTempfile("kernel-procfs");
    const auto name = source.substr(source.find_last_of("/") + 1);
    auto opened = SelectAcceptedPath(context, context.GetTempdirPath(), CrossMountPathPolicy(), ResolverLimits{});
    ASSERT_TRUE(opened.HasValue()) << opened.Error().message;
    Path path = std::move(opened).Value();
    auto selected = SelectStep(path, name, Path::Policy{});
    ASSERT_TRUE(selected.HasValue()) << selected.Error().message;
    EXPECT_EQ(path.Leaf().Metadata().TargetMount().Value(), selected.Value().Metadata().TargetMount().Value());
    Path::Component file = selected.Value().Target();
    auto metadata = file.Stat();
    ASSERT_TRUE(metadata.HasValue()) << metadata.Error().message;
    EXPECT_TRUE(S_ISREG(metadata.Value().st_mode));
    auto readable = file.OpenReadOnly();
    ASSERT_TRUE(readable.HasValue()) << readable.Error().message;
    auto read = readable.Value().Read(32);
    ASSERT_TRUE(read.HasValue()) << read.Error().message;
    ASSERT_TRUE(read.Value().HasValue());
    EXPECT_EQ("kernel-procfs", read.Value().Value());
    ASSERT_TRUE(file.SetMode(0600).HasValue());
    ASSERT_TRUE(file.SetOwnership(ComplianceEngine::Filesystem::UserId(::geteuid()), ComplianceEngine::Filesystem::GroupId(::getegid())).HasValue());
    struct stat changed = {};
    ASSERT_EQ(0, ::stat(source.c_str(), &changed));
    EXPECT_EQ(0600, changed.st_mode & 0777);
    EXPECT_EQ(::geteuid(), changed.st_uid);
    EXPECT_EQ(::getegid(), changed.st_gid);

    const std::string root = context.GetTempdirPath();
    auto listing = Files(std::move(path), root, FilesystemTraversalPolicy{});
    ASSERT_TRUE(listing.HasValue()) << listing.Error().message;
    bool found = false;
    for (const auto& entry : listing.Value())
    {
        ASSERT_TRUE(entry.HasValue()) << entry.Error().message;
        if (entry.Value().path == (root + "/" + name))
            found = true;
    }
    EXPECT_TRUE(found);
}
} // namespace
