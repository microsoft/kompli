// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <DescriptorTestAccess.h>
#include <MockContext.h>
#include <cerrno>
#include <dirent.h>
#include <fcntl.h>
#include <filesystem/Handle.hpp>
#include <filesystem/Path.hpp>
#include <filesystem/ProcfsDescriptorAccess.hpp>
#include <filesystem/ReadableFile.hpp>
#include <fstream>
#include <gtest/gtest.h>
#include <initializer_list>
#include <iterator>
#include <limits>
#include <linux/magic.h>
#include <memory>
#include <new>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <type_traits>
#include <unistd.h>
#include <utility>

using ComplianceEngine::Filesystem::MountPolicy;
using ComplianceEngine::Filesystem::Path;
using ComplianceEngine::Filesystem::ReadableFile;
using ComplianceEngine::Filesystem::ResolverLimits;
using ComplianceEngine::Filesystem::Detail::Descriptor;
using ComplianceEngine::Filesystem::Detail::ProcfsDescriptorAccess;
using ComplianceEngine::Tests::DescriptorTestAccess;
using testing::_;
using testing::NiceMock;

namespace
{
Path::Policy CrossMountExtension()
{
    Path::Policy policy;
    policy.mounts = MountPolicy::CrossMounts;
    return policy;
}

std::size_t OpenDescriptors()
{
    DIR* directory = ::opendir("/proc/self/fd");
    if (nullptr == directory)
    {
        return 0;
    }
    std::size_t count = 0;
    while (nullptr != ::readdir(directory))
    {
        ++count;
    }
    ::closedir(directory);
    return count;
}

ComplianceEngine::Result<Descriptor> VerifiedTestDescriptor(const ComplianceEngine::ContextInterface& context)
{
    return DescriptorTestAccess::OpenAbsolutePin(context, "/proc");
}

struct CountingLogContext : NiceMock<MockContext>
{
    OsConfigLogHandle GetLogHandle() const noexcept override
    {
        ++logHandleRequests;
        return MockContext::GetLogHandle();
    }

    mutable int logHandleRequests = 0;
};

class ReadableFileTest : public testing::Test
{
protected:
    NiceMock<MockContext> context;
    static constexpr std::size_t fdinfoCap = 4096;

    ComplianceEngine::Result<Path::Component> Pin(MockContext& selectedContext, const std::string& component)
    {
        ResolverLimits limits;
        limits.shared.components = 100;
        limits.shared.fdinfoBytes = fdinfoCap;
        limits.linkExpansions = 8;
        Path::Policy policy;
        policy.mounts = MountPolicy::CrossMounts;
        auto root = Path::Make(selectedContext, selectedContext.GetTempdirPath(), policy, limits);
        if (!root.HasValue())
        {
            return std::move(root).Error();
        }
        if (!root.Value().Is<Path>())
        {
            return ComplianceEngine::Error("Fixture directory is unavailable", ENOENT);
        }
        Path path = ComplianceEngine::As<Path>(std::move(root.Value()));
        auto frozen = path.Freeze();
        if (!frozen.HasValue())
            return std::move(frozen).Error();
        auto resolved = path.Resolve(component, policy);
        if (!resolved.HasValue())
            return std::move(resolved).Error();
        if (!resolved.Value().Is<Path::Step>())
            return ComplianceEngine::Error("Fixture component is unavailable", ENOENT);
        return ComplianceEngine::As<Path::Step>(std::move(resolved.Value())).Target();
    }

    ComplianceEngine::Result<Path::Component> Pin(const std::string& component)
    {
        return Pin(context, component);
    }

    std::string Component(const std::string& path) const
    {
        return path.substr(path.find_last_of('/') + 1);
    }
};
} // namespace

TEST_F(ReadableFileTest, IsOpaqueAndMoveOnly)
{
    static_assert(std::is_same<decltype(&ReadableFile::Read), ComplianceEngine::Result<ComplianceEngine::Optional<std::string>> (ReadableFile::*)(std::size_t)>::value,
        "Reading must mutate the stream");
    static_assert(!std::is_default_constructible<ReadableFile>::value, "Cannot fabricate readable ownership");
    static_assert(!std::is_constructible<ReadableFile, int>::value, "No raw descriptor constructor");
    static_assert(!std::is_copy_constructible<ReadableFile>::value, "No duplicated ownership");
    static_assert(std::is_move_constructible<ReadableFile>::value, "Transfer ownership");
    static_assert(std::is_move_assignable<ReadableFile>::value, "Transfer ownership");
    static_assert(std::is_nothrow_move_constructible<ReadableFile>::value, "Transferring source context and ownership cannot throw");
    static_assert(std::is_nothrow_move_assignable<ReadableFile>::value, "Replacing ownership across contexts cannot throw");
    static_assert(std::is_nothrow_destructible<ReadableFile>::value, "Cleanup cannot throw");
    static_assert(noexcept(std::declval<ReadableFile&>().Close()) && std::is_same<decltype(std::declval<ReadableFile&>().Close()), void>::value,
        "ReadableFile close reports only a guarded diagnostic");
}

TEST_F(ReadableFileTest, DescriptorFinalScopeLogsNativeErrorOnceWithoutRetryInMoveOrDestruction)
{
    const std::string logPath = context.GetTempdirPath() + "/descriptor-close.log";
    OsConfigLogHandle logHandle = OpenLog(logPath.c_str(), nullptr);
    ASSERT_NE(nullptr, logHandle);
    context.SetLogHandle(logHandle);
    auto acquired = VerifiedTestDescriptor(context);
    ASSERT_TRUE(acquired.HasValue()) << acquired.Error().message;
    Descriptor owner = std::move(acquired).Value();
    {
        EXPECT_CALL(context, CloseFileDescriptor(testing::_)).Times(1).WillOnce([](int descriptor) {
            EXPECT_EQ(0, ::close(descriptor));
            errno = EACCES;
            return ComplianceEngine::Error(errno ? errno : EIO);
        });
        DescriptorTestAccess::Dispose(owner);
        EXPECT_FALSE(DescriptorTestAccess::ConsumedDescriptor(owner) != -1);
        DescriptorTestAccess::Dispose(owner);
        Descriptor moved(std::move(owner));
        moved = std::move(owner);
        DescriptorTestAccess::Dispose(moved);
    }
    CloseLog(&logHandle);
    context.SetLogHandle(nullptr);
    std::ifstream log(logPath);
    ASSERT_TRUE(log.is_open());
    const std::string text((std::istreambuf_iterator<char>(log)), std::istreambuf_iterator<char>());
    const std::string expected = "Failed to close filesystem resource: " + std::string(strerror(EACCES));
    const auto occurrence = text.find(expected);
    ASSERT_NE(std::string::npos, occurrence);
    EXPECT_EQ(std::string::npos, text.find(expected, occurrence + expected.size()));
}

TEST_F(ReadableFileTest, DescriptorMoveReplacementRoutesFailedCloseToOldContextOnce)
{
    CountingLogContext oldContext;
    NiceMock<MockContext> incomingContext;
    auto oldResult = VerifiedTestDescriptor(oldContext);
    ASSERT_TRUE(oldResult.HasValue()) << oldResult.Error().message;
    Descriptor old = std::move(oldResult).Value();
    auto incomingResult = VerifiedTestDescriptor(incomingContext);
    ASSERT_TRUE(incomingResult.HasValue()) << incomingResult.Error().message;
    Descriptor incoming = std::move(incomingResult).Value();
    {
        EXPECT_CALL(oldContext, CloseFileDescriptor(testing::_)).Times(1).WillOnce([](int descriptor) -> ComplianceEngine::Result<void> {
            EXPECT_EQ(0, ::close(descriptor));
            errno = EIO;
            return ComplianceEngine::Error(errno ? errno : EIO);
        });
        EXPECT_CALL(incomingContext, CloseFileDescriptor(testing::_)).Times(1).WillOnce([](int descriptor) {
            return NativeCloseResult(::close(descriptor));
        });
        testing::internal::CaptureStderr();
        old = std::move(incoming);
        DescriptorTestAccess::Dispose(incoming);
        DescriptorTestAccess::Dispose(old);
        DescriptorTestAccess::Dispose(old);
        const auto logged = testing::internal::GetCapturedStderr();
        if (IsConsoleLoggingEnabled() && GetLoggingLevel() >= LoggingLevelError)
        {
            const auto expected = "Failed to close filesystem resource: " + std::string(strerror(EIO));
            const auto occurrence = logged.find(expected);
            ASSERT_NE(std::string::npos, occurrence);
            EXPECT_EQ(std::string::npos, logged.find(expected, occurrence + expected.size()));
        }
        EXPECT_EQ(1, oldContext.logHandleRequests); // Native failure is diagnostic-only.
    }
    EXPECT_EQ(1, oldContext.logHandleRequests);
}

TEST_F(ReadableFileTest, AliasOpenFailureDoesNotReopenNameOrLeak)
{
    const std::string source = context.MakeTempfile("held");
    bool secondAliasDenied = false, denied = false, cleanupFailed = false;
    auto pinned = Pin(Component(source));
    ASSERT_TRUE(pinned.HasValue());
    const auto before = OpenDescriptors();
    EXPECT_CALL(context, OpenNativePath(_, _)).WillRepeatedly([&](const char* path, int flags) { return context.RealOpenNativePath(path, flags); });
    EXPECT_CALL(context, OpenNativePath(testing::StrEq(source.c_str()), _)).Times(0);
    EXPECT_CALL(context, OpenNativeAt(_, _, _)).WillRepeatedly([&](int directory, const char* name, int flags) {
        char path[512] = {};
        const std::string alias = "/proc/self/fd/" + std::to_string(directory);
        const ssize_t length = ::readlink(alias.c_str(), path, sizeof(path));
        if ((0 < length) && (std::string(path, static_cast<std::size_t>(length)).find("/fd") != std::string::npos) && (0 == (flags & O_PATH)) &&
            (0 == (flags & O_NOFOLLOW)) && (0 != (flags & O_CLOEXEC)))
        {
            EXPECT_FALSE(std::string(name).empty());
            if (secondAliasDenied)
            {
                errno = EIO;
                return -1;
            }
            denied = true;
            errno = EACCES;
            return -1;
        }
        return context.RealOpenNativeAt(directory, name, flags);
    });
    EXPECT_CALL(context, CloseFileDescriptor(_)).WillRepeatedly([&](int descriptor) -> ComplianceEngine::Result<void> {
        struct statfs filesystem = {};
        const bool procfs = (0 == ::fstatfs(descriptor, &filesystem)) && (PROC_SUPER_MAGIC == filesystem.f_type);
        const int status = ::close(descriptor);
        EXPECT_EQ(0, status);
        if (procfs && denied && !cleanupFailed)
        {
            cleanupFailed = true;
            errno = EIO;
            return ComplianceEngine::Error(errno ? errno : EIO);
        }
        return NativeCloseResult(status);
    });
    auto readable = pinned.Value().OpenReadOnly();
    ASSERT_FALSE(readable.HasValue());
    EXPECT_EQ(EACCES, readable.Error().code);
    EXPECT_TRUE(cleanupFailed);
    EXPECT_EQ(before, OpenDescriptors());
    secondAliasDenied = true;
    auto second = pinned.Value().OpenReadOnly();
    ASSERT_FALSE(second.HasValue());
    EXPECT_EQ(EIO, second.Error().code);
    EXPECT_EQ(before, OpenDescriptors());
    ASSERT_TRUE(testing::Mock::VerifyAndClearExpectations(&context));
}

TEST_F(ReadableFileTest, AliasOutputRemainsReadableWhenProcfsHelperCloseFails)
{
    const std::string source = context.MakeTempfile("held");
    bool failed = false, aliasOpened = false;
    auto pinned = Pin(Component(source));
    ASSERT_TRUE(pinned.HasValue());
    const auto before = OpenDescriptors();
    EXPECT_CALL(context, OpenNativeAt(_, _, _)).WillRepeatedly([&](int directory, const char* name, int flags) {
        const int descriptor = context.RealOpenNativeAt(directory, name, flags);
        if ((0 <= descriptor) && (0 == (flags & O_PATH)) && (0 == (flags & O_NOFOLLOW)))
        {
            aliasOpened = true;
        }
        return descriptor;
    });
    EXPECT_CALL(context, CloseFileDescriptor(_)).WillRepeatedly([&](int descriptor) -> ComplianceEngine::Result<void> {
        struct statfs filesystem = {};
        const bool procfs = (0 == ::fstatfs(descriptor, &filesystem)) && (PROC_SUPER_MAGIC == filesystem.f_type);
        const int status = ::close(descriptor);
        EXPECT_EQ(0, status);
        if (procfs && aliasOpened && !failed)
        {
            failed = true;
            errno = EIO;
            return ComplianceEngine::Error(errno ? errno : EIO);
        }
        return NativeCloseResult(status);
    });
    auto readable = pinned.Value().OpenReadOnly();
    ASSERT_TRUE(readable.HasValue());
    auto bytes = readable.Value().Read(4);
    ASSERT_TRUE(bytes.HasValue());
    ASSERT_TRUE(bytes.Value().HasValue());
    EXPECT_EQ("held", bytes.Value().Value());
    readable.Value().Close();
    EXPECT_TRUE(aliasOpened);
    EXPECT_TRUE(failed);
    EXPECT_EQ(before, OpenDescriptors());
    ASSERT_TRUE(testing::Mock::VerifyAndClearExpectations(&context));
}

TEST_F(ReadableFileTest, SurvivesPinAndNameReplacementAndInspectsReadableDescriptor)
{
    const std::string original = context.MakeTempfile("first");
    auto pinned = Pin(Component(original));
    ASSERT_TRUE(pinned.HasValue());
    const ino_t inode = pinned.Value().Metadata().Stat().st_ino;
    auto pinnedBefore = pinned.Value().Stat();
    ASSERT_TRUE(pinnedBefore.HasValue());
    EXPECT_EQ(inode, pinnedBefore.Value().st_ino);
    ASSERT_EQ(0, ::rename(original.c_str(), (original + ".old").c_str()));
    ASSERT_EQ(0, ::symlink("/dev/zero", original.c_str()));
    auto activated = pinned.Value().OpenReadOnly();
    ASSERT_TRUE(activated.HasValue()) << activated.Error().message;
    ReadableFile readable = std::move(activated).Value();
    pinned = ComplianceEngine::Error("Release pin", EINVAL);
    auto before = readable.Stat();
    ASSERT_TRUE(before.HasValue());
    EXPECT_EQ(inode, before.Value().st_ino);
    EXPECT_TRUE(S_ISREG(before.Value().st_mode));
    auto read = readable.Read(8);
    ASSERT_TRUE(read.HasValue());
    ASSERT_TRUE(read.Value().HasValue());
    EXPECT_EQ("first", read.Value().Value());
    auto eof = readable.Read(8);
    ASSERT_TRUE(eof.HasValue());
    EXPECT_FALSE(eof.Value().HasValue());
    auto after = readable.Stat();
    ASSERT_TRUE(after.HasValue());
    EXPECT_EQ(before.Value().st_ino, after.Value().st_ino);
    EXPECT_EQ(before.Value().st_size, after.Value().st_size);
    EXPECT_CALL(context, CloseFileDescriptor(_)).Times(1).WillOnce([](int descriptor) { return NativeCloseResult(::close(descriptor)); });
    readable.Close();
    readable.Close();
    EXPECT_EQ(EBADF, readable.Read(1).Error().code);
    EXPECT_EQ(EBADF, readable.Stat().Error().code);
}

TEST_F(ReadableFileTest, NativeDescriptorZeroRemainsOwnedThroughEofUntilClose)
{
    const std::string source = context.MakeTempfile("zero");
    EXPECT_EXIT(
        {
            // Isolate the process-wide stdin replacement in the death-test child.
            const int guard = ::open("/dev/null", O_RDONLY | O_CLOEXEC);
            if ((guard < 0) || (::dup2(guard, STDIN_FILENO) != STDIN_FILENO))
            {
                ::_exit(1);
            }
            if (guard != STDIN_FILENO)
            {
                ::close(guard);
            }
            auto pinned = Pin(Component(source));
            if (!pinned.HasValue())
            {
                ::_exit(2);
            }
            bool mapped = false;
            bool closed = false;
            EXPECT_CALL(context, OpenNativeAt(_, _, _)).WillRepeatedly([&](int directory, const char* name, int flags) {
                const int descriptor = context.RealOpenNativeAt(directory, name, flags);
                if ((descriptor >= 0) && ((flags & (O_PATH | O_NOFOLLOW)) == 0))
                {
                    if ((::dup2(descriptor, STDIN_FILENO) != STDIN_FILENO) || (::fcntl(STDIN_FILENO, F_SETFD, FD_CLOEXEC) != 0) || mapped)
                    {
                        ::_exit(3);
                    }
                    mapped = true;
                    if (descriptor != STDIN_FILENO)
                    {
                        ::close(descriptor);
                    }
                    return STDIN_FILENO;
                }
                return descriptor;
            });
            auto acquired = pinned.Value().OpenReadOnly();
            if (!mapped || !acquired.HasValue())
            {
                ::_exit(4);
            }
            ReadableFile original = std::move(acquired).Value();
            ReadableFile readable(std::move(original));
            if ((original.Stat().Error().code != EBADF) || !readable.Stat().HasValue())
            {
                ::_exit(5);
            }
            auto chunk = readable.Read(8);
            if (!chunk.HasValue() || !chunk.Value().HasValue() || (chunk.Value().Value() != "zero") || !readable.AtEnd() || !readable.Stat().HasValue())
            {
                ::_exit(6);
            }
            EXPECT_CALL(context, CloseFileDescriptor(_)).WillRepeatedly([&](int descriptor) -> ComplianceEngine::Result<void> {
                if (descriptor == STDIN_FILENO)
                {
                    if (closed)
                    {
                        ::_exit(7);
                    }
                    closed = true;
                }
                return NativeCloseResult(::close(descriptor));
            });
            readable.Close();
            readable.Close();
            if (!closed || (readable.Stat().Error().code != EBADF))
            {
                ::_exit(8);
            }
            ::_exit(0);
        },
        testing::ExitedWithCode(0), "");
}

TEST_F(ReadableFileTest, ReturnsOwnedBinaryChunksWithoutTextFiltering)
{
    const std::string payload{'a', '\0', '\r', static_cast<char>(0xff), static_cast<char>(0x80)};
    const std::string source = context.MakeTempfile(payload);
    auto pinned = Pin(Component(source));
    ASSERT_TRUE(pinned.HasValue());
    auto activated = pinned.Value().OpenReadOnly();
    ASSERT_TRUE(activated.HasValue());
    ReadableFile readable = std::move(activated).Value();

    EXPECT_CALL(context, ReadFileDescriptor(_, _, 2)).Times(1);
    EXPECT_CALL(context, ReadFileDescriptor(_, _, 8)).Times(1);
    EXPECT_CALL(context, ReadFileDescriptor(_, _, 5)).Times(1);
    EXPECT_CALL(context, ReadFileDescriptor(_, _, 1)).Times(0);
    auto first = readable.Read(2);
    ASSERT_TRUE(first.HasValue());
    ASSERT_TRUE(first.Value().HasValue());
    EXPECT_EQ(payload.substr(0, 2), first.Value().Value());
    auto second = readable.Read(8);
    ASSERT_TRUE(second.HasValue());
    ASSERT_TRUE(second.Value().HasValue());
    EXPECT_EQ(payload.substr(2), second.Value().Value());
    EXPECT_TRUE(readable.AtEnd());                          // short read followed by native EOF
    EXPECT_EQ(payload.substr(0, 2), first.Value().Value()); // earlier owned chunk is unchanged
    auto eof = readable.Read(1);
    ASSERT_TRUE(eof.HasValue());
    EXPECT_FALSE(eof.Value().HasValue());
    auto repeated = readable.Read(1);
    ASSERT_TRUE(repeated.HasValue());
    EXPECT_FALSE(repeated.Value().HasValue());
}

TEST_F(ReadableFileTest, ShortNativeReadsFillCapacityAtShrinkingOffsetsWithoutEofProbe)
{
    const std::string source = context.MakeTempfile(std::string("a\0bcd", 5));
    auto pinned = Pin(Component(source));
    ASSERT_TRUE(pinned.HasValue());
    auto activated = pinned.Value().OpenReadOnly();
    ASSERT_TRUE(activated.HasValue());
    ReadableFile readable = std::move(activated).Value();
    EXPECT_FALSE(readable.AtEnd());
    void* start = nullptr;
    EXPECT_CALL(context, ReadFileDescriptor(_, _, 5)).Times(1).WillOnce([&](int fd, void* buffer, std::size_t) {
        start = buffer;
        return context.RealReadFileDescriptor(fd, buffer, 1);
    });
    EXPECT_CALL(context, ReadFileDescriptor(_, _, 4)).Times(1).WillOnce([&](int fd, void* buffer, std::size_t) {
        EXPECT_EQ(static_cast<char*>(start) + 1, buffer);
        return context.RealReadFileDescriptor(fd, buffer, 2);
    });
    EXPECT_CALL(context, ReadFileDescriptor(_, _, 2)).Times(1).WillOnce([&](int fd, void* buffer, std::size_t size) {
        EXPECT_EQ(static_cast<char*>(start) + 3, buffer);
        return context.RealReadFileDescriptor(fd, buffer, size);
    });
    auto filled = readable.Read(5);
    ASSERT_TRUE(filled.HasValue());
    ASSERT_TRUE(filled.Value().HasValue());
    EXPECT_EQ(std::string("a\0bcd", 5), filled.Value().Value());
    EXPECT_FALSE(readable.AtEnd()); // full capacity is not proof of EOF
    ASSERT_TRUE(testing::Mock::VerifyAndClearExpectations(&context));
    auto eof = readable.Read(1);
    ASSERT_TRUE(eof.HasValue());
    EXPECT_FALSE(eof.Value().HasValue());
    EXPECT_TRUE(readable.AtEnd());
}

TEST_F(ReadableFileTest, EofAfterShortProgressReturnsEngagedPartialButImmediateEofIsDisengaged)
{
    const std::string source = context.MakeTempfile("ab");
    auto pinned = Pin(Component(source));
    ASSERT_TRUE(pinned.HasValue());
    auto activated = pinned.Value().OpenReadOnly();
    ASSERT_TRUE(activated.HasValue());
    ReadableFile readable = std::move(activated).Value();
    EXPECT_FALSE(readable.AtEnd());
    void* start = nullptr;
    EXPECT_CALL(context, ReadFileDescriptor(_, _, 5)).Times(1).WillOnce([&](int fd, void* buffer, std::size_t) {
        start = buffer;
        return context.RealReadFileDescriptor(fd, buffer, 2);
    });
    EXPECT_CALL(context, ReadFileDescriptor(_, _, 3)).Times(1).WillOnce([&](int fd, void* buffer, std::size_t size) {
        EXPECT_EQ(static_cast<char*>(start) + 2, buffer);
        return context.RealReadFileDescriptor(fd, buffer, size);
    });
    auto partial = readable.Read(5);
    ASSERT_TRUE(partial.HasValue());
    ASSERT_TRUE(partial.Value().HasValue());
    EXPECT_EQ("ab", partial.Value().Value());
    EXPECT_TRUE(readable.AtEnd());
    ASSERT_TRUE(testing::Mock::VerifyAndClearExpectations(&context));
    EXPECT_CALL(context, ReadFileDescriptor(_, _, _)).Times(0);
    auto eof = readable.Read(5);
    ASSERT_TRUE(eof.HasValue());
    EXPECT_FALSE(eof.Value().HasValue());
    EXPECT_TRUE(readable.AtEnd());
}

TEST_F(ReadableFileTest, ObservedEofTransfersWithOwnershipAndResetsOnClose)
{
    const std::string source = context.MakeTempfile("ab");
    auto pinned = Pin(Component(source));
    ASSERT_TRUE(pinned.HasValue());
    auto first = pinned.Value().OpenReadOnly();
    auto second = pinned.Value().OpenReadOnly();
    ASSERT_TRUE(first.HasValue());
    ASSERT_TRUE(second.HasValue());
    ReadableFile original = std::move(first).Value();
    ReadableFile replacement = std::move(second).Value();
    EXPECT_FALSE(original.AtEnd());
    EXPECT_FALSE(replacement.AtEnd());
    auto partial = original.Read(5);
    ASSERT_TRUE(partial.HasValue());
    ASSERT_TRUE(partial.Value().HasValue());
    EXPECT_EQ("ab", partial.Value().Value());
    EXPECT_TRUE(original.AtEnd());
    ReadableFile moved(std::move(original));
    EXPECT_FALSE(original.AtEnd());
    EXPECT_EQ(EBADF, original.Read(1).Error().code);
    EXPECT_TRUE(moved.AtEnd());
    replacement = std::move(moved);
    EXPECT_FALSE(moved.AtEnd());
    EXPECT_EQ(EBADF, moved.Read(1).Error().code);
    EXPECT_TRUE(replacement.AtEnd());
    EXPECT_CALL(context, ReadFileDescriptor(_, _, _)).Times(0);
    auto eof = replacement.Read(1);
    ASSERT_TRUE(eof.HasValue());
    EXPECT_FALSE(eof.Value().HasValue());
    replacement.Close();
    EXPECT_FALSE(replacement.AtEnd());
    EXPECT_EQ(EBADF, replacement.Read(1).Error().code);
}

TEST_F(ReadableFileTest, InterruptedShortReadsShareCumulativeBudgetAndAllowProgressAtZero)
{
    const std::string source = context.MakeTempfile("abcde");
    auto pinned = Pin(Component(source));
    ASSERT_TRUE(pinned.HasValue());
    auto activated = pinned.Value().OpenReadOnly(ReadableFile::Policy(2));
    ASSERT_TRUE(activated.HasValue());
    ReadableFile readable = std::move(activated).Value();
    int calls = 0;
    void* start = nullptr;
    EXPECT_CALL(context, ReadFileDescriptor(_, _, 5)).Times(2).WillRepeatedly([&](int fd, void* buffer, std::size_t) -> ssize_t {
        if (++calls == 1)
        {
            errno = EINTR;
            return -1;
        }
        start = buffer;
        return context.RealReadFileDescriptor(fd, buffer, 2);
    });
    EXPECT_CALL(context, ReadFileDescriptor(_, _, 3)).Times(2).WillRepeatedly([&](int fd, void* buffer, std::size_t) -> ssize_t {
        EXPECT_EQ(static_cast<char*>(start) + 2, buffer);
        if (++calls == 3)
        {
            errno = EINTR;
            return -1;
        }
        return context.RealReadFileDescriptor(fd, buffer, 1);
    });
    EXPECT_CALL(context, ReadFileDescriptor(_, _, 2)).Times(1).WillOnce([&](int fd, void* buffer, std::size_t size) {
        EXPECT_EQ(static_cast<char*>(start) + 3, buffer);
        return context.RealReadFileDescriptor(fd, buffer, size);
    });
    auto filled = readable.Read(5);
    ASSERT_TRUE(filled.HasValue());
    ASSERT_TRUE(filled.Value().HasValue());
    EXPECT_EQ("abcde", filled.Value().Value());
    EXPECT_FALSE(readable.AtEnd());
    EXPECT_EQ(4, calls);
    // The budget belongs to the readable owner across subsequent calls.
    EXPECT_CALL(context, ReadFileDescriptor(_, _, 1)).Times(1).WillOnce([](int, void*, std::size_t) -> ssize_t {
        errno = EINTR;
        return -1;
    });
    auto exhausted = readable.Read(1);
    ASSERT_FALSE(exhausted.HasValue());
    EXPECT_EQ(EINTR, exhausted.Error().code);
}

TEST_F(ReadableFileTest, NativeErrorAfterShortProgressDoesNotReturnPartialDataOrResetOffset)
{
    const std::string source = context.MakeTempfile("abcde");
    auto pinned = Pin(Component(source));
    ASSERT_TRUE(pinned.HasValue());
    auto activated = pinned.Value().OpenReadOnly();
    ASSERT_TRUE(activated.HasValue());
    ReadableFile readable = std::move(activated).Value();
    EXPECT_CALL(context, ReadFileDescriptor(_, _, 5)).Times(1).WillOnce([&](int fd, void* buffer, std::size_t) {
        return context.RealReadFileDescriptor(fd, buffer, 2);
    });
    EXPECT_CALL(context, ReadFileDescriptor(_, _, 3)).Times(1).WillOnce([](int, void*, std::size_t) -> ssize_t {
        errno = EIO;
        return -1;
    });
    auto failed = readable.Read(5);
    ASSERT_FALSE(failed.HasValue());
    EXPECT_EQ(EIO, failed.Error().code);
    EXPECT_FALSE(readable.AtEnd());
    EXPECT_EQ("Cannot read acquired file", failed.Error().message);
    ASSERT_TRUE(testing::Mock::VerifyAndClearExpectations(&context));
    auto remaining = readable.Read(3);
    ASSERT_TRUE(remaining.HasValue());
    ASSERT_TRUE(remaining.Value().HasValue());
    EXPECT_EQ("cde", remaining.Value().Value());
}

TEST_F(ReadableFileTest, ExhaustedEintrAfterShortProgressIsErrorNotPartialData)
{
    const std::string source = context.MakeTempfile("abc");
    auto pinned = Pin(Component(source));
    ASSERT_TRUE(pinned.HasValue());
    auto activated = pinned.Value().OpenReadOnly(ReadableFile::Policy(0));
    ASSERT_TRUE(activated.HasValue());
    ReadableFile readable = std::move(activated).Value();
    EXPECT_CALL(context, ReadFileDescriptor(_, _, 3)).Times(1).WillOnce([&](int fd, void* buffer, std::size_t) {
        return context.RealReadFileDescriptor(fd, buffer, 1);
    });
    EXPECT_CALL(context, ReadFileDescriptor(_, _, 2)).Times(1).WillOnce([](int, void*, std::size_t) -> ssize_t {
        errno = EINTR;
        return -1;
    });
    auto failed = readable.Read(3);
    ASSERT_FALSE(failed.HasValue());
    EXPECT_EQ(EINTR, failed.Error().code);
    EXPECT_FALSE(readable.AtEnd());
    ASSERT_TRUE(testing::Mock::VerifyAndClearExpectations(&context));
    auto remaining = readable.Read(2);
    ASSERT_TRUE(remaining.HasValue());
    ASSERT_TRUE(remaining.Value().HasValue());
    EXPECT_EQ("bc", remaining.Value().Value());
}

TEST_F(ReadableFileTest, OverreportOnReducedRemainingRequestFailsBeforePublishing)
{
    const std::string source = context.MakeTempfile("abcde");
    auto pinned = Pin(Component(source));
    ASSERT_TRUE(pinned.HasValue());
    auto activated = pinned.Value().OpenReadOnly();
    ASSERT_TRUE(activated.HasValue());
    ReadableFile readable = std::move(activated).Value();
    EXPECT_CALL(context, ReadFileDescriptor(_, _, 5)).Times(1).WillOnce([&](int fd, void* buffer, std::size_t) {
        return context.RealReadFileDescriptor(fd, buffer, 2);
    });
    EXPECT_CALL(context, ReadFileDescriptor(_, _, 3)).Times(1).WillOnce([](int, void*, std::size_t) -> ssize_t { return 4; });
    auto failed = readable.Read(5);
    ASSERT_FALSE(failed.HasValue());
    EXPECT_EQ(EIO, failed.Error().code);
    EXPECT_FALSE(readable.AtEnd());
    EXPECT_EQ("Readable file returned more bytes than requested", failed.Error().message);
    ASSERT_TRUE(testing::Mock::VerifyAndClearExpectations(&context));
    auto remaining = readable.Read(3);
    ASSERT_TRUE(remaining.HasValue());
    ASSERT_TRUE(remaining.Value().HasValue());
    EXPECT_EQ("cde", remaining.Value().Value());
}

TEST_F(ReadableFileTest, ZeroBudgetPreservesInterruptedReadAndInspectErrnosWithoutFalseEof)
{
    const std::string source = context.MakeTempfile("x");
    auto pinned = Pin(Component(source));
    ASSERT_TRUE(pinned.HasValue());
    auto activated = pinned.Value().OpenReadOnly(ReadableFile::Policy(0));
    ASSERT_TRUE(activated.HasValue());
    ReadableFile readable = std::move(activated).Value();
    EXPECT_CALL(context, ReadFileDescriptor(_, _, 1)).Times(1).WillOnce([](int, void*, std::size_t) -> ssize_t {
        errno = EINTR;
        return -1;
    });
    auto interrupted = readable.Read(1);
    ASSERT_FALSE(interrupted.HasValue());
    EXPECT_EQ(EINTR, interrupted.Error().code);
    EXPECT_CALL(context, ReadFileDescriptor(_, _, 1)).Times(1).WillOnce([](int, void*, std::size_t) -> ssize_t {
        errno = EIO;
        return -1;
    });
    auto failed = readable.Read(1);
    ASSERT_FALSE(failed.HasValue());
    EXPECT_EQ(EIO, failed.Error().code);
    ASSERT_TRUE(testing::Mock::VerifyAndClearExpectations(&context));
    EXPECT_CALL(context, StatFileDescriptor(_, _)).Times(1).WillOnce([](int, struct stat*) {
        errno = EACCES;
        return -1;
    });
    auto inspection = readable.Stat();
    ASSERT_FALSE(inspection.HasValue());
    EXPECT_EQ(EACCES, inspection.Error().code);
    EXPECT_CALL(context, ReadFileDescriptor(_, _, _)).Times(0);
    EXPECT_EQ(EINVAL, readable.Read(0).Error().code);
    EXPECT_EQ(EINVAL, readable.Read(static_cast<std::size_t>(std::numeric_limits<ssize_t>::max()) + 1).Error().code);
    if (std::string().max_size() < static_cast<std::size_t>(std::numeric_limits<ssize_t>::max()))
    {
        EXPECT_EQ(EOVERFLOW, readable.Read(std::string().max_size() + 1).Error().code);
    }
    ASSERT_TRUE(testing::Mock::VerifyAndClearExpectations(&context));
    // A rejected zero request did not consume the byte or falsely report EOF.
    auto next = readable.Read(1);
    ASSERT_TRUE(next.HasValue());
    ASSERT_TRUE(next.Value().HasValue());
    EXPECT_EQ("x", next.Value().Value());
}

TEST_F(ReadableFileTest, InterruptedReadConsumesOnlyRetriesAndPreservesBinaryDataAndEof)
{
    const std::string source = context.MakeTempfile(std::string("a\0b", 3));
    auto pinned = Pin(Component(source));
    ASSERT_TRUE(pinned.HasValue());
    auto activated = pinned.Value().OpenReadOnly(ReadableFile::Policy(2));
    ASSERT_TRUE(activated.HasValue());
    ReadableFile readable = std::move(activated).Value();
    EXPECT_CALL(context, ReadFileDescriptor(_, _, 8))
        .Times(3)
        .WillOnce([](int, void*, std::size_t) -> ssize_t {
            errno = EINTR;
            return -1;
        })
        .WillOnce([](int, void*, std::size_t) -> ssize_t {
            errno = EINTR;
            return -1;
        })
        .WillOnce([&](int descriptor, void* buffer, std::size_t size) { return context.RealReadFileDescriptor(descriptor, buffer, size); });
    EXPECT_CALL(context, ReadFileDescriptor(_, _, 5)).Times(1);
    auto read = readable.Read(8);
    ASSERT_TRUE(read.HasValue());
    ASSERT_TRUE(read.Value().HasValue());
    EXPECT_EQ(std::string("a\0b", 3), read.Value().Value());
    EXPECT_TRUE(readable.AtEnd());
    ASSERT_TRUE(testing::Mock::VerifyAndClearExpectations(&context));
    auto eof = readable.Read(8);
    ASSERT_TRUE(eof.HasValue());
    EXPECT_FALSE(eof.Value().HasValue());
    EXPECT_TRUE(readable.AtEnd());
}

TEST_F(ReadableFileTest, ExhaustedInterruptedReadReturnsNativeEintrAfterLimitPlusOneAttempts)
{
    const std::string source = context.MakeTempfile("x");
    auto pinned = Pin(Component(source));
    ASSERT_TRUE(pinned.HasValue());
    auto activated = pinned.Value().OpenReadOnly(ReadableFile::Policy(1));
    ASSERT_TRUE(activated.HasValue());
    ReadableFile readable = std::move(activated).Value();
    EXPECT_CALL(context, ReadFileDescriptor(_, _, 1)).Times(2).WillRepeatedly([](int, void*, std::size_t) -> ssize_t {
        errno = EINTR;
        return -1;
    });
    auto interrupted = readable.Read(1);
    ASSERT_FALSE(interrupted.HasValue());
    EXPECT_EQ(EINTR, interrupted.Error().code);
    ASSERT_TRUE(testing::Mock::VerifyAndClearExpectations(&context));
    auto next = readable.Read(1);
    ASSERT_TRUE(next.HasValue());
    ASSERT_TRUE(next.Value().HasValue());
    EXPECT_EQ("x", next.Value().Value());
}

TEST_F(ReadableFileTest, InterruptedBudgetMovesWithReadableAcrossSeparateReads)
{
    const std::string source = context.MakeTempfile("ab");
    auto pinned = Pin(Component(source));
    ASSERT_TRUE(pinned.HasValue());
    auto activated = pinned.Value().OpenReadOnly(ReadableFile::Policy(1));
    ASSERT_TRUE(activated.HasValue());
    ReadableFile readable = std::move(activated).Value();
    int calls = 0;
    EXPECT_CALL(context, ReadFileDescriptor(_, _, 1)).Times(4).WillRepeatedly([&](int fd, void* buffer, std::size_t size) -> ssize_t {
        ++calls;
        if ((calls == 1) || (calls == 3))
        {
            errno = EINTR;
            return -1;
        }
        return context.RealReadFileDescriptor(fd, buffer, size);
    });

    auto first = readable.Read(1);
    ASSERT_TRUE(first.HasValue());
    ASSERT_TRUE(first.Value().HasValue());
    EXPECT_EQ("a", first.Value().Value());
    ReadableFile moved(std::move(readable));
    EXPECT_EQ(EBADF, readable.Read(1).Error().code);
    auto second = moved.Read(1);
    ASSERT_FALSE(second.HasValue());
    EXPECT_EQ(EINTR, second.Error().code);
    auto last = moved.Read(1);
    ASSERT_TRUE(last.HasValue());
    ASSERT_TRUE(last.Value().HasValue());
    EXPECT_EQ("b", last.Value().Value());
    EXPECT_EQ(4, calls);
}

TEST_F(ReadableFileTest, NonInterruptedNativeErrorsNeverSpendRetryBudget)
{
    const std::string source = context.MakeTempfile("x");
    auto pinned = Pin(Component(source));
    ASSERT_TRUE(pinned.HasValue());
    auto activated = pinned.Value().OpenReadOnly();
    ASSERT_TRUE(activated.HasValue());
    ReadableFile readable = std::move(activated).Value();
    for (const int failure : {EAGAIN, EIO})
    {
        EXPECT_CALL(context, ReadFileDescriptor(_, _, 1)).Times(1).WillOnce([failure](int, void*, std::size_t) -> ssize_t {
            errno = failure;
            return -1;
        });
        auto failed = readable.Read(1);
        ASSERT_FALSE(failed.HasValue());
        EXPECT_EQ(failure, failed.Error().code);
        ASSERT_TRUE(testing::Mock::VerifyAndClearExpectations(&context));
    }
    auto next = readable.Read(1);
    ASSERT_TRUE(next.HasValue());
    ASSERT_TRUE(next.Value().HasValue());
    EXPECT_EQ("x", next.Value().Value());
}

TEST_F(ReadableFileTest, EmptyFilePositiveReadReturnsEof)
{
    const std::string source = context.MakeTempfile("");
    auto pinned = Pin(Component(source));
    ASSERT_TRUE(pinned.HasValue());
    auto activated = pinned.Value().OpenReadOnly();
    ASSERT_TRUE(activated.HasValue());
    ReadableFile readable = std::move(activated).Value();
    auto metadata = readable.Stat();
    ASSERT_TRUE(metadata.HasValue());
    EXPECT_EQ(0, metadata.Value().st_size);
    EXPECT_FALSE(readable.AtEnd()); // stat does not predict EOF
    EXPECT_CALL(context, ReadFileDescriptor(_, _, 1)).Times(1);
    auto end = readable.Read(1);
    ASSERT_TRUE(end.HasValue());
    EXPECT_FALSE(end.Value().HasValue());
    EXPECT_TRUE(readable.AtEnd());
    auto again = readable.Read(1);
    ASSERT_TRUE(again.HasValue());
    EXPECT_FALSE(again.Value().HasValue());
    EXPECT_TRUE(readable.AtEnd());
}

TEST_F(ReadableFileTest, OverreportedReadIsAnErrorNotDataOrEof)
{
    const std::string source = context.MakeTempfile("x");
    auto pinned = Pin(Component(source));
    ASSERT_TRUE(pinned.HasValue());
    auto activated = pinned.Value().OpenReadOnly();
    ASSERT_TRUE(activated.HasValue());
    ReadableFile readable = std::move(activated).Value();
    EXPECT_CALL(context, ReadFileDescriptor(_, _, 1)).Times(1).WillOnce([](int, void*, std::size_t) -> ssize_t { return 2; });
    auto overreported = readable.Read(1);
    ASSERT_FALSE(overreported.HasValue());
    EXPECT_EQ(EIO, overreported.Error().code);
    ASSERT_TRUE(testing::Mock::VerifyAndClearExpectations(&context));
    auto next = readable.Read(1);
    ASSERT_TRUE(next.HasValue());
    ASSERT_TRUE(next.Value().HasValue());
    EXPECT_EQ("x", next.Value().Value());
}

TEST_F(ReadableFileTest, FailedReadPreservesDescriptorForSubsequentRead)
{
    const std::string source = context.MakeTempfile("x");
    auto pinned = Pin(Component(source));
    ASSERT_TRUE(pinned.HasValue());
    auto activated = pinned.Value().OpenReadOnly();
    ASSERT_TRUE(activated.HasValue());
    ReadableFile readable = std::move(activated).Value();
    EXPECT_CALL(context, ReadFileDescriptor(_, _, 1)).Times(1).WillOnce([](int, void*, std::size_t) -> ssize_t {
        errno = EIO;
        return -1;
    });
    auto failed = readable.Read(1);
    ASSERT_FALSE(failed.HasValue());
    EXPECT_EQ(EIO, failed.Error().code);
    ASSERT_TRUE(testing::Mock::VerifyAndClearExpectations(&context));
    auto next = readable.Read(1);
    ASSERT_TRUE(next.HasValue());
    ASSERT_TRUE(next.Value().HasValue());
    EXPECT_EQ("x", next.Value().Value());
}

TEST_F(ReadableFileTest, ResolvedTargetSurvivesPathAndStepDestruction)
{
    const std::string source = context.MakeTempfile(std::string("a\0b", 3));
    const std::size_t before = OpenDescriptors();
    std::unique_ptr<Path::Component> leaf;
    {
        ResolverLimits limits;
        limits.shared.components = 100;
        Path::Policy policy = CrossMountExtension();
        auto opened = Path::Make(context, context.GetTempdirPath(), policy, limits);
        ASSERT_TRUE(opened.HasValue());
        ASSERT_TRUE(opened.Value().Is<Path>());
        Path path = ComplianceEngine::As<Path>(std::move(opened.Value()));
        ASSERT_TRUE(path.Freeze().HasValue());
        auto resolved = path.Resolve(Component(source), policy);
        ASSERT_TRUE(resolved.HasValue());
        ASSERT_TRUE(resolved.Value().Is<Path::Step>());
        auto target = ComplianceEngine::As<Path::Step>(std::move(resolved.Value())).Target();
        leaf.reset(new Path::Component(std::move(target)));
    }
    ASSERT_TRUE(leaf->Stat().HasValue());
    EXPECT_EQ(source, leaf->Metadata().LookupName());
    EXPECT_EQ(source, leaf->Metadata().EffectiveName());
    EXPECT_EQ(ComplianceEngine::Filesystem::Type::RegularFile, leaf->Metadata().FileType());
    EXPECT_GT(leaf->Metadata().LookupMount().Value(), 0u);
    EXPECT_GT(leaf->Metadata().TargetMount().Value(), 0u);
    auto activated = leaf->OpenReadOnly();
    ASSERT_TRUE(activated.HasValue());
    ReadableFile readable = std::move(activated).Value();
    leaf.reset();
    auto chunk = readable.Read(8);
    ASSERT_TRUE(chunk.HasValue());
    ASSERT_TRUE(chunk.Value().HasValue());
    EXPECT_EQ(std::string("a\0b", 3), chunk.Value().Value());
    readable.Close();
    EXPECT_EQ(before, OpenDescriptors());
}

TEST_F(ReadableFileTest, RejectsDirectoryInvalidCapAndPinInspectionFailureWithoutLeaks)
{
    const std::size_t before = OpenDescriptors();
    {
        ResolverLimits limits;
        limits.shared.components = 100;
        limits.shared.fdinfoBytes = fdinfoCap;
        limits.linkExpansions = 8;
        Path::Policy policy;
        policy.mounts = MountPolicy::CrossMounts;
        auto directory = Path::Make(context, context.GetTempdirPath(), policy, limits);
        ASSERT_TRUE(directory.HasValue());
        ASSERT_TRUE(directory.Value().Is<Path>());
        ASSERT_TRUE(ComplianceEngine::As<Path>(directory.Value()).Freeze().HasValue());
        auto wrongType = ComplianceEngine::As<Path>(directory.Value()).Leaf().OpenReadOnly();
        ASSERT_FALSE(wrongType.HasValue());
        EXPECT_EQ(EINVAL, wrongType.Error().code);
        const std::string source = context.MakeTempfile("x");
        auto pinned = Pin(Component(source));
        ASSERT_TRUE(pinned.HasValue());
        limits.shared.fdinfoBytes = 0;
        auto invalidCap = Path::Make(context, source, policy, limits);
        ASSERT_FALSE(invalidCap.HasValue());
        EXPECT_EQ(EINVAL, invalidCap.Error().code);
        limits.shared.fdinfoBytes = std::numeric_limits<std::size_t>::max();
        auto oversizedCap = Path::Make(context, source, policy, limits);
        ASSERT_FALSE(oversizedCap.HasValue());
        EXPECT_EQ(EINVAL, oversizedCap.Error().code);
        EXPECT_CALL(context, StatFileDescriptor(_, _)).Times(1).WillOnce([](int, struct stat*) {
            errno = EIO;
            return -1;
        });
        auto failed = pinned.Value().OpenReadOnly();
        ASSERT_FALSE(failed.HasValue());
        EXPECT_EQ(EIO, failed.Error().code);
    }
    EXPECT_EQ(before, OpenDescriptors());
}

TEST_F(ReadableFileTest, CloseFailureIsReportedOnceAndDoesNotCloseReusedDescriptor)
{
    const std::string logPath = context.GetTempdirPath() + "/readable-close.log";
    OsConfigLogHandle log = OpenLog(logPath.c_str(), nullptr);
    ASSERT_NE(nullptr, log);
    context.SetLogHandle(log);
    const std::string source = context.MakeTempfile("x");
    auto pinned = Pin(Component(source));
    ASSERT_TRUE(pinned.HasValue());
    auto activated = pinned.Value().OpenReadOnly();
    ASSERT_TRUE(activated.HasValue());
    pinned = ComplianceEngine::Error("Release pin", EINVAL);
    int reused = -1;
    {
        ReadableFile readable = std::move(activated).Value();
        EXPECT_CALL(context, CloseFileDescriptor(_)).Times(1).WillOnce([&](int descriptor) -> ComplianceEngine::Result<void> {
            EXPECT_EQ(0, ::close(descriptor));
            const int replacement = ::open("/dev/null", O_RDONLY | O_CLOEXEC);
            EXPECT_GE(replacement, 0);
            if (replacement >= 0)
            {
                reused = descriptor;
                if (replacement != descriptor)
                {
                    EXPECT_EQ(descriptor, ::dup2(replacement, descriptor));
                    ::close(replacement);
                }
            }
            errno = EIO;
            return ComplianceEngine::Error(errno ? errno : EIO);
        });
        readable.Close();
        readable.Close();
        EXPECT_EQ(EBADF, readable.Stat().Error().code);
    }
    ASSERT_GE(reused, 0);
    EXPECT_GE(::fcntl(reused, F_GETFD), 0);
    EXPECT_EQ(0, ::close(reused));
    CloseLog(&log);
    context.SetLogHandle(nullptr);
    std::ifstream record(logPath);
    ASSERT_TRUE(record.is_open());
    const std::string text((std::istreambuf_iterator<char>(record)), std::istreambuf_iterator<char>());
    const std::string entry = "Failed to close filesystem resource: " + std::string(strerror(EIO));
    const auto at = text.find(entry);
    ASSERT_NE(std::string::npos, at);
    EXPECT_EQ(std::string::npos, text.find(entry, at + entry.size()));
}

TEST_F(ReadableFileTest, FailedCloseTransfersNoErrorThroughMoveConstructionOrAssignment)
{
    const std::string source = context.MakeTempfile("x");
    auto pinned = Pin(Component(source));
    ASSERT_TRUE(pinned.HasValue());
    auto first = pinned.Value().OpenReadOnly();
    auto second = pinned.Value().OpenReadOnly();
    ASSERT_TRUE(first.HasValue());
    ASSERT_TRUE(second.HasValue());
    pinned = ComplianceEngine::Error("Release pin", EINVAL);
    const auto before = OpenDescriptors();
    {
        ReadableFile failed = std::move(first).Value();
        EXPECT_CALL(context, CloseFileDescriptor(_))
            .Times(2)
            .WillOnce([](int descriptor) {
                EXPECT_EQ(0, ::close(descriptor));
                errno = EIO;
                return ComplianceEngine::Error(errno ? errno : EIO);
            })
            .WillOnce([](int descriptor) { return NativeCloseResult(::close(descriptor)); });
        failed.Close();
        ReadableFile moved(std::move(failed));
        failed.Close();
        moved.Close();

        ReadableFile live = std::move(second).Value();
        live = std::move(moved);
        moved.Close();
        live.Close();
    }
    EXPECT_EQ(before - 2, OpenDescriptors());
}

TEST_F(ReadableFileTest, NativeCloseErrorIsReportedOnceAndDoesNotRetry)
{
    const std::string source = context.MakeTempfile("x");
    auto pinned = Pin(Component(source));
    ASSERT_TRUE(pinned.HasValue());
    auto activated = pinned.Value().OpenReadOnly();
    ASSERT_TRUE(activated.HasValue());
    pinned = ComplianceEngine::Error("Release pin", EINVAL);
    {
        ReadableFile readable = std::move(activated).Value();
        EXPECT_CALL(context, CloseFileDescriptor(_)).Times(1).WillOnce([](int descriptor) -> ComplianceEngine::Result<void> {
            EXPECT_EQ(0, ::close(descriptor));
            errno = EIO;
            return ComplianceEngine::Error(errno ? errno : EIO);
        });
        EXPECT_NO_THROW(readable.Close());
        readable.Close();
        EXPECT_EQ(EBADF, readable.Stat().Error().code);
    }
}

TEST_F(ReadableFileTest, DestructorReportsFailedNativeCloseOnce)
{
    CountingLogContext selectedContext;
    const std::string source = selectedContext.MakeTempfile("x");
    const auto before = OpenDescriptors();
    {
        auto pinned = Pin(selectedContext, Component(source));
        ASSERT_TRUE(pinned.HasValue());
        auto activated = pinned.Value().OpenReadOnly();
        ASSERT_TRUE(activated.HasValue());
        pinned = ComplianceEngine::Error("Release pin", EINVAL);
        testing::internal::CaptureStderr();
        {
            ReadableFile readable = std::move(activated).Value();
            EXPECT_CALL(selectedContext, CloseFileDescriptor(_)).Times(1).WillOnce([](int descriptor) {
                EXPECT_EQ(0, ::close(descriptor));
                errno = EACCES;
                return ComplianceEngine::Error(errno ? errno : EIO);
            });
        }
        const auto logged = testing::internal::GetCapturedStderr();
        if (IsConsoleLoggingEnabled() && GetLoggingLevel() >= LoggingLevelError)
        {
            const std::string closeEntry = "Failed to close filesystem resource: " + std::string(strerror(EACCES));
            const auto first = logged.find(closeEntry);
            ASSERT_NE(std::string::npos, first);
            EXPECT_EQ(std::string::npos, logged.find(closeEntry, first + closeEntry.size()));
        }
        EXPECT_EQ(1, selectedContext.logHandleRequests);
        EXPECT_TRUE(testing::Mock::VerifyAndClearExpectations(&selectedContext));
    }
    EXPECT_EQ(before, OpenDescriptors());
}

TEST_F(ReadableFileTest, MoveAssignmentReportsFailedCloseAndRetainsIncomingOwnership)
{
    CountingLogContext selectedContext;
    const std::string oldSource = selectedContext.MakeTempfile("old");
    const std::string newSource = selectedContext.MakeTempfile("new");
    const auto before = OpenDescriptors();
    {
        auto oldPin = Pin(selectedContext, Component(oldSource));
        auto newPin = Pin(selectedContext, Component(newSource));
        ASSERT_TRUE(oldPin.HasValue());
        ASSERT_TRUE(newPin.HasValue());
        auto oldOpened = oldPin.Value().OpenReadOnly();
        auto newOpened = newPin.Value().OpenReadOnly();
        ASSERT_TRUE(oldOpened.HasValue());
        ASSERT_TRUE(newOpened.HasValue());
        oldPin = ComplianceEngine::Error("Release pin", EINVAL);
        newPin = ComplianceEngine::Error("Release pin", EINVAL);
        {
            ReadableFile destination = std::move(oldOpened).Value();
            ReadableFile source = std::move(newOpened).Value();
            EXPECT_CALL(selectedContext, CloseFileDescriptor(_))
                .Times(2)
                .WillOnce([](int descriptor) {
                    EXPECT_EQ(0, ::close(descriptor));
                    errno = EIO;
                    return ComplianceEngine::Error(errno ? errno : EIO);
                })
                .WillOnce([](int descriptor) {
                    const int result = ::close(descriptor);
                    EXPECT_EQ(0, result);
                    return NativeCloseResult(result);
                });
            testing::internal::CaptureStderr();
            destination = std::move(source);
            const auto logged = testing::internal::GetCapturedStderr();
            if (IsConsoleLoggingEnabled() && GetLoggingLevel() >= LoggingLevelError)
            {
                EXPECT_NE(std::string::npos, logged.find("Failed to close filesystem resource: " + std::string(strerror(EIO))));
            }
            EXPECT_EQ(1, selectedContext.logHandleRequests);
            EXPECT_EQ(EBADF, source.Stat().Error().code);
            source.Close();
            EXPECT_TRUE(destination.Stat().HasValue());
            auto bytes = destination.Read(3);
            ASSERT_TRUE(bytes.HasValue());
            ASSERT_TRUE(bytes.Value().HasValue());
            EXPECT_EQ("new", bytes.Value().Value());
            destination.Close();
            destination.Close();
        }
        EXPECT_EQ(1, selectedContext.logHandleRequests);
        EXPECT_TRUE(testing::Mock::VerifyAndClearExpectations(&selectedContext));
    }
    EXPECT_EQ(before, OpenDescriptors());
}

TEST_F(ReadableFileTest, DestructorAndMoveAssignmentCloseOnce)
{
    const std::string source = context.MakeTempfile("x");
    const std::size_t before = OpenDescriptors();
    {
        auto pinned = Pin(Component(source));
        ASSERT_TRUE(pinned.HasValue());
        auto first = pinned.Value().OpenReadOnly();
        auto second = pinned.Value().OpenReadOnly();
        ASSERT_TRUE(first.HasValue());
        ASSERT_TRUE(second.HasValue());
        pinned = ComplianceEngine::Error("Release pin", EINVAL);
        ReadableFile readable = std::move(first).Value();
        ReadableFile moved = std::move(second).Value();
        EXPECT_CALL(context, CloseFileDescriptor(_))
            .Times(2)
            .WillOnce([](int descriptor) -> ComplianceEngine::Result<void> {
                const int result = ::close(descriptor);
                EXPECT_EQ(0, result);
                errno = EIO; // destructor of replaced ownership sees failed close
                return ComplianceEngine::Error(errno ? errno : EIO);
            })
            .WillOnce([](int descriptor) { return NativeCloseResult(::close(descriptor)); });
        readable = std::move(moved);
        EXPECT_EQ(EBADF, moved.Stat().Error().code);
    }
    EXPECT_EQ(before, OpenDescriptors());
}

TEST_F(ReadableFileTest, SameContextMoveConstructorAssignmentAndSelfMoveKeepSingleOwnership)
{
    const std::string source = context.MakeTempfile("x");
    auto pinned = Pin(Component(source));
    ASSERT_TRUE(pinned.HasValue());
    auto first = pinned.Value().OpenReadOnly();
    auto second = pinned.Value().OpenReadOnly();
    ASSERT_TRUE(first.HasValue());
    ASSERT_TRUE(second.HasValue());
    pinned = ComplianceEngine::Error("Release pin", EINVAL);
    const std::size_t before = OpenDescriptors();

    ReadableFile original = std::move(first).Value();
    ReadableFile moved(std::move(original));
    EXPECT_EQ(EBADF, original.Read(1).Error().code);
    EXPECT_EQ(EBADF, original.Stat().Error().code);
    original.Close();
    EXPECT_TRUE(moved.Stat().HasValue());

    ReadableFile incoming = std::move(second).Value();
    EXPECT_CALL(context, CloseFileDescriptor(_)).Times(2).WillRepeatedly([](int descriptor) { return NativeCloseResult(::close(descriptor)); });
    ReadableFile& self = moved;
    moved = std::move(self);
    EXPECT_TRUE(moved.Stat().HasValue());
    moved = std::move(incoming);
    EXPECT_EQ(EBADF, incoming.Read(1).Error().code);
    EXPECT_EQ(EBADF, incoming.Stat().Error().code);
    incoming.Close();
    auto read = moved.Read(1);
    ASSERT_TRUE(read.HasValue());
    ASSERT_TRUE(read.Value().HasValue());
    EXPECT_EQ("x", read.Value().Value());
    moved.Close();
    moved.Close();
    EXPECT_EQ(before - 2, OpenDescriptors());
}

TEST_F(ReadableFileTest, CrossContextMoveAssignmentClosesOldOwnerAndRoutesIncomingOperations)
{
    NiceMock<MockContext> foreignContext;
    const std::string oldPath = context.MakeTempfile("old");
    const std::string newPath = foreignContext.MakeTempfile("new");
    int oldDescriptor = -1;
    int incomingDescriptor = -1;
    auto pinned = Pin(Component(oldPath));
    auto foreignPin = Pin(foreignContext, Component(newPath));
    ASSERT_TRUE(pinned.HasValue());
    ASSERT_TRUE(foreignPin.HasValue());
    auto activated = pinned.Value().OpenReadOnly();
    auto foreignActivated = foreignPin.Value().OpenReadOnly();
    ASSERT_TRUE(activated.HasValue());
    ASSERT_TRUE(foreignActivated.HasValue());
    pinned = ComplianceEngine::Error("Release pin", EINVAL);
    foreignPin = ComplianceEngine::Error("Release pin", EINVAL);
    const std::size_t before = OpenDescriptors();

    ReadableFile destination = std::move(activated).Value();
    ReadableFile source = std::move(foreignActivated).Value();
    EXPECT_CALL(context, CloseFileDescriptor(_)).Times(1).WillOnce([&](int descriptor) -> ComplianceEngine::Result<void> {
        oldDescriptor = descriptor;
        return NativeCloseResult(::close(descriptor));
    });
    EXPECT_CALL(foreignContext, CloseFileDescriptor(_)).Times(1).WillOnce([&](int descriptor) -> ComplianceEngine::Result<void> {
        EXPECT_EQ(incomingDescriptor, descriptor);
        return NativeCloseResult(::close(descriptor));
    });
    EXPECT_CALL(context, StatFileDescriptor(_, _)).Times(0);
    EXPECT_CALL(context, ReadFileDescriptor(_, _, _)).Times(0);
    EXPECT_CALL(foreignContext, StatFileDescriptor(_, _)).Times(1).WillOnce([&](int descriptor, struct stat* metadata) {
        incomingDescriptor = descriptor;
        return foreignContext.RealStatFileDescriptor(descriptor, metadata);
    });
    EXPECT_CALL(foreignContext, ReadFileDescriptor(_, _, _)).Times(1).WillOnce([&](int descriptor, void* buffer, std::size_t size) {
        EXPECT_EQ(incomingDescriptor, descriptor);
        return foreignContext.RealReadFileDescriptor(descriptor, buffer, size);
    });

    destination = std::move(source);
    ASSERT_GE(oldDescriptor, 0);
    EXPECT_EQ(-1, ::fcntl(oldDescriptor, F_GETFD));
    EXPECT_EQ(EBADF, errno);
    EXPECT_EQ(EBADF, source.Read(1).Error().code);
    EXPECT_EQ(EBADF, source.Stat().Error().code);
    source.Close();
    EXPECT_TRUE(destination.Stat().HasValue());
    ASSERT_GE(incomingDescriptor, 0);
    EXPECT_NE(oldDescriptor, incomingDescriptor);
    EXPECT_GE(::fcntl(incomingDescriptor, F_GETFD), 0);
    auto bytes = destination.Read(3);
    ASSERT_TRUE(bytes.HasValue());
    ASSERT_TRUE(bytes.Value().HasValue());
    EXPECT_EQ("new", bytes.Value().Value());
    destination.Close();
    destination.Close();
    EXPECT_EQ(-1, ::fcntl(incomingDescriptor, F_GETFD));
    EXPECT_EQ(EBADF, errno);
    EXPECT_TRUE(testing::Mock::VerifyAndClearExpectations(&context));
    EXPECT_TRUE(testing::Mock::VerifyAndClearExpectations(&foreignContext));
    EXPECT_EQ(before - 2, OpenDescriptors());
}

TEST_F(ReadableFileTest, CrossContextMoveReplacementReportsOldOwnerCloseFailure)
{
    CountingLogContext oldContext;
    NiceMock<MockContext> newContext;
    const std::string oldPath = oldContext.MakeTempfile("old");
    const std::string newPath = newContext.MakeTempfile("new");
    auto oldPin = Pin(oldContext, Component(oldPath));
    auto newPin = Pin(newContext, Component(newPath));
    ASSERT_TRUE(oldPin.HasValue());
    ASSERT_TRUE(newPin.HasValue());
    auto oldOpened = oldPin.Value().OpenReadOnly();
    auto newOpened = newPin.Value().OpenReadOnly();
    ASSERT_TRUE(oldOpened.HasValue());
    ASSERT_TRUE(newOpened.HasValue());
    oldPin = ComplianceEngine::Error("Release pin", EINVAL);
    newPin = ComplianceEngine::Error("Release pin", EINVAL);
    const auto before = OpenDescriptors();

    ReadableFile destination = std::move(oldOpened).Value();
    ReadableFile source = std::move(newOpened).Value();
    EXPECT_CALL(oldContext, CloseFileDescriptor(_)).Times(1).WillOnce([](int descriptor) {
        EXPECT_EQ(0, ::close(descriptor));
        errno = EIO;
        return ComplianceEngine::Error(errno ? errno : EIO);
    });
    EXPECT_CALL(newContext, CloseFileDescriptor(_)).Times(1).WillOnce([](int descriptor) { return NativeCloseResult(::close(descriptor)); });
    destination = std::move(source);
    EXPECT_EQ(1, oldContext.logHandleRequests);
    EXPECT_FALSE(source.AtEnd());
    EXPECT_EQ(EBADF, source.Stat().Error().code);
    auto bytes = destination.Read(3);
    ASSERT_TRUE(bytes.HasValue());
    ASSERT_TRUE(bytes.Value().HasValue());
    EXPECT_EQ("new", bytes.Value().Value());
    destination.Close();
    EXPECT_EQ(before - 2, OpenDescriptors());
}

TEST_F(ReadableFileTest, CrossContextClosedAndMovedFromAssignmentsTransferEofAndPreserveSelfMove)
{
    NiceMock<MockContext> foreignContext;
    const std::string oldPath = context.MakeTempfile("old");
    const std::string newPath = foreignContext.MakeTempfile("b");
    auto pinned = Pin(Component(oldPath));
    auto foreignPin = Pin(foreignContext, Component(newPath));
    ASSERT_TRUE(pinned.HasValue());
    ASSERT_TRUE(foreignPin.HasValue());
    auto activated = pinned.Value().OpenReadOnly();
    auto foreignActivated = foreignPin.Value().OpenReadOnly();
    ASSERT_TRUE(activated.HasValue());
    ASSERT_TRUE(foreignActivated.HasValue());
    pinned = ComplianceEngine::Error("Release pin", EINVAL);
    foreignPin = ComplianceEngine::Error("Release pin", EINVAL);
    const std::size_t before = OpenDescriptors();

    ReadableFile destination = std::move(activated).Value();
    ReadableFile source = std::move(foreignActivated).Value();
    auto bytes = source.Read(2);
    ASSERT_TRUE(bytes.HasValue());
    ASSERT_TRUE(bytes.Value().HasValue());
    EXPECT_EQ("b", bytes.Value().Value());
    EXPECT_TRUE(source.AtEnd());
    EXPECT_CALL(context, CloseFileDescriptor(_)).Times(1).WillOnce([](int descriptor) { return NativeCloseResult(::close(descriptor)); });
    EXPECT_CALL(foreignContext, CloseFileDescriptor(_)).Times(1).WillOnce([](int descriptor) { return NativeCloseResult(::close(descriptor)); });
    destination.Close();
    EXPECT_FALSE(destination.AtEnd());
    ReadableFile closedOld(std::move(destination));

    ReadableFile moved(std::move(source));
    EXPECT_FALSE(source.AtEnd());
    EXPECT_EQ(EBADF, source.Stat().Error().code);
    destination = std::move(moved); // closed destination adopts another context
    EXPECT_FALSE(moved.AtEnd());
    EXPECT_TRUE(destination.AtEnd());
    EXPECT_CALL(context, StatFileDescriptor(_, _)).Times(0);
    EXPECT_CALL(context, ReadFileDescriptor(_, _, _)).Times(0);
    EXPECT_CALL(foreignContext, StatFileDescriptor(_, _)).Times(1);
    EXPECT_CALL(foreignContext, ReadFileDescriptor(_, _, _)).Times(0); // cached EOF
    EXPECT_TRUE(destination.Stat().HasValue());
    auto eof = destination.Read(1);
    ASSERT_TRUE(eof.HasValue());
    EXPECT_FALSE(eof.Value().HasValue());
    ReadableFile& self = destination;
    destination = std::move(self);
    EXPECT_TRUE(destination.AtEnd());
    destination.Close();
    EXPECT_FALSE(destination.AtEnd());

    source = std::move(closedOld);      // moved-from foreign destination, closed original-context source
    closedOld = std::move(destination); // moved-from original destination, closed foreign source
    destination = std::move(source);    // both closed, across their bound contexts
    EXPECT_EQ(EBADF, source.Stat().Error().code);
    EXPECT_EQ(EBADF, closedOld.Stat().Error().code);
    EXPECT_EQ(EBADF, destination.Stat().Error().code);
    source.Close();
    closedOld.Close();
    destination.Close();
    EXPECT_TRUE(testing::Mock::VerifyAndClearExpectations(&context));
    EXPECT_TRUE(testing::Mock::VerifyAndClearExpectations(&foreignContext));
    EXPECT_EQ(before - 2, OpenDescriptors());
}

// A child native failure is not an invitation to reopen its textual pathname.
TEST_F(ReadableFileTest, FailedChildNativeOpenNeverFallsBackToTargetName)
{
    const std::string source = context.MakeTempfile("held");
    const std::string name = Component(source);
    const std::size_t before = OpenDescriptors();
    {
        ResolverLimits limits;
        limits.shared.components = 100;
        auto opened = Path::Make(context, context.GetTempdirPath(), CrossMountExtension(), limits);
        ASSERT_TRUE(opened.HasValue());
        ASSERT_TRUE(opened.Value().Is<Path>());
        Path path = ComplianceEngine::As<Path>(std::move(opened.Value()));
        ASSERT_TRUE(path.Freeze().HasValue());
        const auto original = path.Leaf().Metadata().Stat().st_ino;
        EXPECT_CALL(context, OpenNativePath(testing::StrEq(source.c_str()), _)).Times(0);
        EXPECT_CALL(context, OpenNativeAt(_, testing::StrEq(name.c_str()), _)).WillOnce([](int, const char*, int) {
            errno = EACCES;
            return -1;
        });
        auto failed = path.Resolve(name, CrossMountExtension());
        ASSERT_FALSE(failed.HasValue());
        EXPECT_EQ(EACCES, failed.Error().code);
        EXPECT_EQ(original, path.Leaf().Metadata().Stat().st_ino);
        ASSERT_TRUE(testing::Mock::VerifyAndClearExpectations(&context));
        EXPECT_TRUE(path.Leaf().Stat().HasValue());
        // The pinned root and its external context stay alive until all copies die.
        opened = ComplianceEngine::Error("Release factory wrapper", EINVAL);
    }
    EXPECT_EQ(before, OpenDescriptors());
}

TEST_F(ReadableFileTest, ChildStatFailureOutranksDiagnosticPinRelease)
{
    int childFd = -1;
    bool disposalFailed = false;
    const std::string source = context.MakeTempfile("held");
    const std::string name = Component(source);
    ResolverLimits limits;
    limits.shared.components = 100;
    auto opened = Path::Make(context, context.GetTempdirPath(), CrossMountExtension(), limits);
    ASSERT_TRUE(opened.HasValue());
    ASSERT_TRUE(opened.Value().Is<Path>());
    Path path = ComplianceEngine::As<Path>(std::move(opened.Value()));
    ASSERT_TRUE(path.Freeze().HasValue());
    const std::size_t before = OpenDescriptors();
    EXPECT_CALL(context, OpenNativeAt(_, testing::StrEq(name.c_str()), _)).WillRepeatedly([&](int parent, const char* entry, int flags) {
        const int fd = context.RealOpenNativeAt(parent, entry, flags);
        if (fd >= 0 && (flags & O_PATH))
            childFd = fd;
        return fd;
    });
    EXPECT_CALL(context, StatFileDescriptor(_, _)).WillRepeatedly([&](int fd, struct stat* out) {
        if (fd == childFd)
        {
            errno = EACCES;
            return -1;
        }
        return context.RealStatFileDescriptor(fd, out);
    });
    EXPECT_CALL(context, CloseFileDescriptor(_)).WillRepeatedly([&](int fd) -> ComplianceEngine::Result<void> {
        const bool child = fd == childFd;
        auto result = context.RealCloseFileDescriptor(fd);
        if (child)
        {
            disposalFailed = true;
            errno = EIO;
            return ComplianceEngine::Error(errno ? errno : EIO);
        }
        return result;
    });
    auto failed = path.Resolve(name, CrossMountExtension());
    ASSERT_FALSE(failed.HasValue());
    EXPECT_EQ(EACCES, failed.Error().code);
    EXPECT_GE(childFd, 0);
    EXPECT_TRUE(disposalFailed);
    EXPECT_EQ(before, OpenDescriptors());
    EXPECT_TRUE(path.Leaf().Stat().HasValue());
}

// The original Pop-to-empty assertion is superseded by ADR-0042 D1/D4-D6:
// an inverse Step restores the physical root; retained targets remain live.
TEST_F(ReadableFileTest, InverseStepReleasesSelectedBudgetButRetainedTargetSurvives)
{
    const std::string source = context.MakeTempfile("retained");
    const std::size_t before = OpenDescriptors();
    std::unique_ptr<Path::Component> retained;
    {
        ResolverLimits limits;
        limits.shared.components = 100;
        auto opened = Path::Make(context, context.GetTempdirPath(), CrossMountExtension(), limits);
        ASSERT_TRUE(opened.HasValue());
        ASSERT_TRUE(opened.Value().Is<Path>());
        Path path = ComplianceEngine::As<Path>(std::move(opened.Value()));
        ASSERT_TRUE(path.Freeze().HasValue());
        const auto initialPins = path.RetainedDescriptors();
        auto selected = path.Resolve(Component(source), CrossMountExtension());
        ASSERT_TRUE(selected.HasValue());
        ASSERT_TRUE(selected.Value().Is<Path::Step>());
        Path::Step step = ComplianceEngine::As<Path::Step>(std::move(selected.Value()));
        retained.reset(new Path::Component(step.Target()));
        const auto inode = retained->Metadata().Stat().st_ino;
        auto inverse = path.Apply(std::move(step));
        ASSERT_TRUE(inverse.HasValue()) << inverse.Error().message;
        EXPECT_GT(path.RetainedDescriptors(), initialPins);
        auto restored = path.Apply(std::move(inverse.Value()));
        ASSERT_TRUE(restored.HasValue()) << restored.Error().message;
        EXPECT_EQ(initialPins, path.RetainedDescriptors());
        EXPECT_EQ(inode, retained->Metadata().Stat().st_ino);
        // A detached copy is outside the stack charge; a fresh child still fits.
        auto second = path.Resolve(Component(source), CrossMountExtension());
        ASSERT_TRUE(second.HasValue()) << second.Error().message;
        ASSERT_TRUE(second.Value().Is<Path::Step>());
        auto secondInverse = path.Apply(ComplianceEngine::As<Path::Step>(std::move(second.Value())));
        ASSERT_TRUE(secondInverse.HasValue()) << secondInverse.Error().message;
        auto secondBack = path.Apply(std::move(secondInverse.Value()));
        ASSERT_TRUE(secondBack.HasValue()) << secondBack.Error().message;
        EXPECT_EQ(initialPins, path.RetainedDescriptors());
    }
    ASSERT_TRUE(retained->Stat().HasValue());
    EXPECT_EQ(source, retained->Metadata().LookupName());
    retained.reset();
    EXPECT_EQ(before, OpenDescriptors());
}

TEST_F(ReadableFileTest, DetachedFileFactsStayImmutableAcrossFreshModeAndUnlink)
{
    const std::string source = context.MakeTempfile("held");
    ASSERT_EQ(0, ::chmod(source.c_str(), 0600));
    const std::size_t before = OpenDescriptors();
    std::unique_ptr<const ComplianceEngine::Filesystem::Metadata> retainedEvidence;
    {
        auto pinned = Pin(Component(source));
        ASSERT_TRUE(pinned.HasValue()) << pinned.Error().message;
        Path::Component detached = pinned.Value();
        const auto facts = detached.Metadata();
        retainedEvidence.reset(new ComplianceEngine::Filesystem::Metadata(facts));
        ASSERT_EQ(0, ::link(source.c_str(), (source + ".link").c_str()));
        auto linked = detached.Stat();
        ASSERT_TRUE(linked.HasValue());
        EXPECT_EQ(2, linked.Value().st_nlink);
        ASSERT_EQ(0, ::unlink((source + ".link").c_str()));
        ASSERT_EQ(0, ::rename(source.c_str(), (source + ".former").c_str()));
        ASSERT_EQ(0, ::mkfifo(source.c_str(), 0600));
        ASSERT_TRUE(detached.SetMode(0640).HasValue());
        auto fresh = detached.Stat();
        ASSERT_TRUE(fresh.HasValue());
        EXPECT_EQ(facts.Stat().st_ino, fresh.Value().st_ino);
        EXPECT_EQ(0640, fresh.Value().st_mode & 07777);
        EXPECT_EQ(0600, facts.Stat().st_mode & 07777);
        EXPECT_EQ(source, detached.Metadata().LookupName());
        EXPECT_GT(facts.LookupMount().Value(), 0u);
        EXPECT_GT(facts.TargetMount().Value(), 0u);
        struct stat replacement = {};
        ASSERT_EQ(0, ::lstat(source.c_str(), &replacement));
        EXPECT_TRUE(S_ISFIFO(replacement.st_mode));
        EXPECT_EQ(0600, replacement.st_mode & 07777);
        ASSERT_EQ(0, ::unlink((source + ".former").c_str()));
        ASSERT_TRUE(detached.SetMode(0400).HasValue());
        auto unlinked = detached.Stat();
        ASSERT_TRUE(unlinked.HasValue());
        EXPECT_EQ(0, unlinked.Value().st_nlink);
        EXPECT_EQ(facts.Stat().st_ino, unlinked.Value().st_ino);
        EXPECT_EQ(0400, unlinked.Value().st_mode & 07777);
    }
    EXPECT_EQ(before, OpenDescriptors());
    ASSERT_TRUE(retainedEvidence);
    EXPECT_EQ(source, retainedEvidence->LookupName());
    EXPECT_EQ(source, retainedEvidence->EffectiveName());
    EXPECT_EQ(0600, retainedEvidence->Stat().st_mode & 07777);
}

TEST_F(ReadableFileTest, DetachedOwnershipAndDirectoryModeNeverMutateReplacement)
{
    const std::string file = context.MakeTempfile("old");
    const std::string directory = context.GetTempdirPath() + "/held-directory";
    ASSERT_EQ(0, ::mkdir(directory.c_str(), 0700));
    const std::size_t before = OpenDescriptors();
    {
        auto pinned = Pin(Component(file));
        ASSERT_TRUE(pinned.HasValue());
        Path::Component detached = pinned.Value();
        const auto initial = detached.Stat();
        ASSERT_TRUE(initial.HasValue());
        ASSERT_EQ(0, ::rename(file.c_str(), (file + ".former").c_str()));
        ASSERT_EQ(0, ::mkfifo(file.c_str(), 0600));
        auto changed = detached.SetOwnership(ComplianceEngine::Filesystem::UserId(static_cast<uid_t>(-1)),
            ComplianceEngine::Filesystem::GroupId(static_cast<gid_t>(-1)));
        ASSERT_TRUE(changed.HasValue()) << changed.Error().message;
        auto current = detached.Stat();
        ASSERT_TRUE(current.HasValue());
        EXPECT_EQ(initial.Value().st_uid, current.Value().st_uid);
        EXPECT_EQ(initial.Value().st_gid, current.Value().st_gid);
        EXPECT_EQ(initial.Value().st_ino, current.Value().st_ino);
        struct stat replacement = {};
        ASSERT_EQ(0, ::lstat(file.c_str(), &replacement));
        EXPECT_TRUE(S_ISFIFO(replacement.st_mode));
        EXPECT_EQ(0600, replacement.st_mode & 07777);
    }
    {
        ResolverLimits limits;
        limits.shared.components = 100;
        auto opened = Path::Make(context, directory, CrossMountExtension(), limits);
        ASSERT_TRUE(opened.HasValue());
        ASSERT_TRUE(opened.Value().Is<Path>());
        Path::Component detached = ComplianceEngine::As<Path>(std::move(opened.Value())).Leaf();
        const auto original = detached.Metadata();
        ASSERT_EQ(0, ::rename(directory.c_str(), (directory + ".former").c_str()));
        ASSERT_EQ(0, ::mkdir(directory.c_str(), 0700));
        ASSERT_TRUE(detached.SetMode(0750).HasValue());
        auto current = detached.Stat();
        ASSERT_TRUE(current.HasValue());
        EXPECT_EQ(original.Stat().st_ino, current.Value().st_ino);
        EXPECT_EQ(0750, current.Value().st_mode & 07777);
        struct stat replacement = {};
        ASSERT_EQ(0, ::stat(directory.c_str(), &replacement));
        EXPECT_EQ(0700, replacement.st_mode & 07777);
        EXPECT_NE(replacement.st_ino, current.Value().st_ino);
    }
    EXPECT_EQ(before, OpenDescriptors());
}

TEST_F(ReadableFileTest, MutationPreflightBlocksBothSyscallsAndPostcheckReportsPartialChange)
{
    const std::string source = context.MakeTempfile("held");
    ASSERT_EQ(0, ::chmod(source.c_str(), 0600));
    const auto before = OpenDescriptors();
    {
        auto pinned = Pin(Component(source));
        ASSERT_TRUE(pinned.HasValue()) << pinned.Error().message;
        struct stat initial = {};
        ASSERT_EQ(0, ::stat(source.c_str(), &initial));
        bool reject = true;
        ON_CALL(context, StatFileDescriptor(_, _)).WillByDefault([&](int fd, struct stat* metadata) {
            const int result = context.RealStatFileDescriptor(fd, metadata);
            if (reject && result == 0 && metadata->st_ino == initial.st_ino && metadata->st_dev == initial.st_dev)
            {
                errno = EIO;
                return -1;
            }
            return result;
        });
        EXPECT_CALL(context, ChownPinnedFileDescriptor(_, _, _)).Times(0);
        EXPECT_CALL(context, ChmodPinnedAlias(_, _, _)).Times(0);
        auto noMode = pinned.Value().SetMode(0400);
        ASSERT_FALSE(noMode.HasValue());
        EXPECT_EQ(EIO, noMode.Error().code);
        auto noOwner = pinned.Value().SetOwnership(ComplianceEngine::Filesystem::UserId(static_cast<uid_t>(-1)),
            ComplianceEngine::Filesystem::GroupId(static_cast<gid_t>(-1)));
        ASSERT_FALSE(noOwner.HasValue());
        EXPECT_EQ(EIO, noOwner.Error().code);
        struct stat unchanged = {};
        ASSERT_EQ(0, ::stat(source.c_str(), &unchanged));
        EXPECT_EQ(0600, unchanged.st_mode & 07777);
        EXPECT_EQ(initial.st_uid, unchanged.st_uid);
        EXPECT_EQ(initial.st_gid, unchanged.st_gid);
        ASSERT_TRUE(testing::Mock::VerifyAndClearExpectations(&context));
        reject = false;
        std::size_t inspections = 0;
        ON_CALL(context, StatFileDescriptor(_, _)).WillByDefault([&](int fd, struct stat* metadata) {
            const int result = context.RealStatFileDescriptor(fd, metadata);
            if (result == 0 && metadata->st_ino == initial.st_ino && metadata->st_dev == initial.st_dev && ++inspections == 6)
            {
                errno = EIO; // First fresh pin observation after successful chmod.
                return -1;
            }
            return result;
        });
        EXPECT_CALL(context, ChmodPinnedAlias(_, _, 0400)).Times(1).WillOnce([&](int directory, const char* alias, mode_t mode) {
            return ::fchmodat(directory, alias, mode, 0);
        });
        auto partial = pinned.Value().SetMode(0400);
        ASSERT_FALSE(partial.HasValue());
        EXPECT_EQ(EIO, partial.Error().code);
        EXPECT_EQ(6u, inspections);
        struct stat changed = {};
        ASSERT_EQ(0, ::stat(source.c_str(), &changed));
        EXPECT_EQ(0400, changed.st_mode & 07777);
        EXPECT_EQ(initial.st_ino, changed.st_ino);
    }
    EXPECT_EQ(before, OpenDescriptors());
}

TEST_F(ReadableFileTest, DeniedMutationsInspectHeldPinAndPreserveReplacedName)
{
    const std::string source = context.MakeTempfile("held");
    ASSERT_EQ(0, ::chmod(source.c_str(), 0600));
    const auto before = OpenDescriptors();
    {
        auto pinned = Pin(Component(source));
        ASSERT_TRUE(pinned.HasValue()) << pinned.Error().message;
        Path::Component held = pinned.Value();
        const auto snapshot = held.Metadata();
        ASSERT_EQ(0, ::rename(source.c_str(), (source + ".former").c_str()));
        ASSERT_EQ(0, ::mkfifo(source.c_str(), 0600));
        struct stat replacement = {};
        ASSERT_EQ(0, ::lstat(source.c_str(), &replacement));
        EXPECT_CALL(context, ChownPinnedFileDescriptor(_, static_cast<uid_t>(-1), static_cast<gid_t>(-1))).Times(1).WillOnce([&](int fd, uid_t, gid_t) {
            struct stat observed = {};
            EXPECT_EQ(0, ::fstat(fd, &observed));
            EXPECT_EQ(snapshot.Stat().st_ino, observed.st_ino);
            EXPECT_EQ(snapshot.Stat().st_dev, observed.st_dev);
            errno = EPERM;
            return -1;
        });
        auto noOwner =
            held.SetOwnership(ComplianceEngine::Filesystem::UserId(static_cast<uid_t>(-1)), ComplianceEngine::Filesystem::GroupId(static_cast<gid_t>(-1)));
        ASSERT_FALSE(noOwner.HasValue());
        EXPECT_EQ(EPERM, noOwner.Error().code);
        ASSERT_TRUE(testing::Mock::VerifyAndClearExpectations(&context));
        EXPECT_CALL(context, ChmodPinnedAlias(_, _, 0400)).Times(1).WillOnce([&](int directory, const char* alias, mode_t) {
            struct stat role = {}, observed = {};
            EXPECT_EQ(0, ::fstat(directory, &role));
            EXPECT_TRUE(S_ISDIR(role.st_mode));
            const int fd = std::stoi(alias);
            EXPECT_EQ(0, ::fstat(fd, &observed));
            EXPECT_EQ(snapshot.Stat().st_ino, observed.st_ino);
            errno = EACCES;
            return -1;
        });
        auto noMode = held.SetMode(0400);
        ASSERT_FALSE(noMode.HasValue());
        EXPECT_EQ(EACCES, noMode.Error().code);
        ASSERT_TRUE(testing::Mock::VerifyAndClearExpectations(&context));
        auto fresh = held.Stat();
        ASSERT_TRUE(fresh.HasValue());
        EXPECT_EQ(snapshot.Stat().st_ino, fresh.Value().st_ino);
        EXPECT_EQ(snapshot.Stat().st_uid, fresh.Value().st_uid);
        EXPECT_EQ(snapshot.Stat().st_gid, fresh.Value().st_gid);
        EXPECT_EQ(0600, fresh.Value().st_mode & 07777);
        struct stat original = {}, stillReplacement = {};
        ASSERT_EQ(0, ::stat((source + ".former").c_str(), &original));
        ASSERT_EQ(0, ::lstat(source.c_str(), &stillReplacement));
        EXPECT_EQ(snapshot.Stat().st_ino, original.st_ino);
        EXPECT_EQ(0600, original.st_mode & 07777);
        EXPECT_EQ(replacement.st_ino, stillReplacement.st_ino);
        EXPECT_TRUE(S_ISFIFO(stillReplacement.st_mode));
        EXPECT_EQ(0600, stillReplacement.st_mode & 07777);
    }
    EXPECT_EQ(before, OpenDescriptors());
}

// ADR-0042 D4-D6 replaces auxiliary Pop cleanup with retained inverse Steps:
// the pin is never replayed through its mutable pathname on undo or reuse.
TEST_F(ReadableFileTest, InverseStepKeepsPhysicalDirectoryAfterNameReplacement)
{
    const std::string root = context.GetTempdirPath();
    ASSERT_EQ(0, ::mkdir((root + "/physical").c_str(), 0700));
    const std::string source = context.MakeTempfile("pinned");
    ASSERT_EQ(0, ::rename(source.c_str(), (root + "/physical/child").c_str()));
    ASSERT_EQ(0, ::symlink("physical", (root + "/shortcut").c_str()));
    ResolverLimits limits;
    limits.shared.components = 100;
    Path::Policy policy = CrossMountExtension();
    policy.directoryLinks = ComplianceEngine::Filesystem::DirectoryLinkPolicy::Follow;
    auto opened = Path::Make(context, root, policy, limits);
    ASSERT_TRUE(opened.HasValue());
    ASSERT_TRUE(opened.Value().Is<Path>());
    Path path = ComplianceEngine::As<Path>(std::move(opened.Value()));
    ASSERT_TRUE(path.Freeze().HasValue());
    auto viaLink = path.Resolve("shortcut", policy);
    ASSERT_TRUE(viaLink.HasValue());
    ASSERT_TRUE(viaLink.Value().Is<Path::Step>());
    auto inverse = path.Apply(ComplianceEngine::As<Path::Step>(std::move(viaLink.Value())));
    ASSERT_TRUE(inverse.HasValue()) << inverse.Error().message;
    EXPECT_EQ(root + "/physical", path.ToString());
    const auto inode = path.Leaf().Metadata().Stat().st_ino;
    auto child = path.Resolve("child", policy);
    ASSERT_TRUE(child.HasValue());
    ASSERT_TRUE(child.Value().Is<Path::Step>());
    Path::Component detached = ComplianceEngine::As<Path::Step>(std::move(child.Value())).Target();
    ASSERT_EQ(0, ::rename((root + "/physical").c_str(), (root + "/former").c_str()));
    ASSERT_EQ(0, ::mkdir((root + "/physical").c_str(), 0700));
    EXPECT_CALL(context, OpenNativePath(_, _)).WillRepeatedly([&](const char* name, int flags) { return context.RealOpenNativePath(name, flags); });
    EXPECT_CALL(context, OpenNativePath(testing::StrEq((root + "/physical/child").c_str()), _)).Times(0);
    auto again = path.Resolve("child", policy);
    ASSERT_TRUE(again.HasValue()) << again.Error().message;
    ASSERT_TRUE(again.Value().Is<Path::Step>());
    EXPECT_EQ(detached.Metadata().Stat().st_ino, ComplianceEngine::As<Path::Step>(again.Value()).Target().Metadata().Stat().st_ino);
    EXPECT_EQ(inode, path.Leaf().Metadata().Stat().st_ino);
    auto back = path.Apply(std::move(inverse.Value()));
    ASSERT_TRUE(back.HasValue()) << back.Error().message;
    EXPECT_EQ(root, path.ToString());
    auto heldFile = detached.Stat();
    ASSERT_TRUE(heldFile.HasValue());
    EXPECT_EQ(detached.Metadata().Stat().st_ino, heldFile.Value().st_ino);
}

TEST_F(ReadableFileTest, PathOwnersLogEachFailedDisposalOnceAndDoNotRetryReusedNumber)
{
    const std::string source = context.MakeTempfile("pin");
    const std::string logPath = context.GetTempdirPath() + "/path-disposal-errors.log";
    OsConfigLogHandle log = OpenLog(logPath.c_str(), nullptr);
    ASSERT_NE(nullptr, log);
    context.SetLogHandle(log);
    const auto before = OpenDescriptors();
    int reused = -1;
    std::size_t injected = 0;
    std::size_t closed = 0;
    {
        ResolverLimits limits;
        limits.shared.components = 100;
        auto opened = Path::Make(context, source, CrossMountExtension(), limits);
        ASSERT_TRUE(opened.HasValue());
        ASSERT_TRUE(opened.Value().Is<Path>());
        std::unique_ptr<Path> path(new Path(ComplianceEngine::As<Path>(std::move(opened.Value()))));
        opened = ComplianceEngine::Error("Release factory wrapper", EINVAL);
        const auto pins = path->RetainedDescriptors();
        ASSERT_GT(pins, 1u);
        const auto target = path->Leaf().Metadata().Stat();
        Path::Component retained = path->Leaf();
        Path moved(std::move(*path)); // move-as-copy keeps both snapshots owning the same pins
        EXPECT_CALL(context, CloseFileDescriptor(_)).Times(pins).WillRepeatedly([&](int fd) -> ComplianceEngine::Result<void> {
            ++closed;
            struct stat observed = {};
            const bool isTarget = ::fstat(fd, &observed) == 0 && observed.st_ino == target.st_ino && observed.st_dev == target.st_dev;
            EXPECT_EQ(0, ::close(fd));
            if (isTarget)
            {
                ++injected;
                const int replacement = ::open("/dev/null", O_RDONLY | O_CLOEXEC);
                EXPECT_GE(replacement, 0);
                if (replacement >= 0)
                {
                    reused = fd;
                    if (replacement != fd)
                    {
                        EXPECT_EQ(fd, ::dup2(replacement, fd));
                        ::close(replacement);
                    }
                }
                errno = EACCES;
                return ComplianceEngine::Error(errno ? errno : EIO);
            }
            if (injected == 0 && closed == 1)
            {
                errno = EIO;
                return ComplianceEngine::Error(errno ? errno : EIO);
            }
            return ComplianceEngine::Result<void>::Success();
        });
        path.reset();
        EXPECT_TRUE(retained.Stat().HasValue());
        EXPECT_EQ(0u, injected);
        retained = moved.Leaf();
        // Both path snapshots and the Component must retire before the pin closes.
    }
    EXPECT_EQ(1u, injected);
    EXPECT_GT(closed, 1u);
    EXPECT_GE(reused, 0);
    EXPECT_GE(::fcntl(reused, F_GETFD), 0);
    EXPECT_EQ(0, ::close(reused));
    EXPECT_EQ(before, OpenDescriptors());
    ASSERT_TRUE(testing::Mock::VerifyAndClearExpectations(&context));
    CloseLog(&log);
    context.SetLogHandle(nullptr);
    std::ifstream record(logPath);
    ASSERT_TRUE(record.is_open());
    const std::string text((std::istreambuf_iterator<char>(record)), std::istreambuf_iterator<char>());
    const std::string entry = "Failed to close filesystem resource: " + std::string(strerror(EACCES));
    const auto first = text.find(entry);
    ASSERT_NE(std::string::npos, first);
    EXPECT_EQ(std::string::npos, text.find(entry, first + entry.size()));
    const std::string otherEntry = "Failed to close filesystem resource: " + std::string(strerror(EIO));
    const auto other = text.find(otherEntry);
    ASSERT_NE(std::string::npos, other);
    EXPECT_EQ(std::string::npos, text.find(otherEntry, other + otherEntry.size()));
}

TEST_F(ReadableFileTest, PathMoveAssignmentReleasesReplacedPinThroughOriginalContext)
{
    NiceMock<MockContext> incomingContext;
    const std::size_t before = OpenDescriptors();
    ResolverLimits limits;
    limits.shared.components = 100;
    auto first = Path::Make(context, context.GetTempdirPath(), CrossMountExtension(), limits);
    auto second = Path::Make(incomingContext, incomingContext.GetTempdirPath(), CrossMountExtension(), limits);
    ASSERT_TRUE(first.HasValue());
    ASSERT_TRUE(second.HasValue());
    ASSERT_TRUE(first.Value().Is<Path>());
    ASSERT_TRUE(second.Value().Is<Path>());
    std::unique_ptr<Path> replaced(new Path(ComplianceEngine::As<Path>(std::move(first.Value()))));
    std::unique_ptr<Path> incoming(new Path(ComplianceEngine::As<Path>(std::move(second.Value()))));
    first = ComplianceEngine::Error("Release first result", EINVAL);
    second = ComplianceEngine::Error("Release second result", EINVAL);
    const auto replacedPins = replaced->RetainedDescriptors();
    const auto incomingPins = incoming->RetainedDescriptors();
    std::size_t oldCloses = 0, incomingCloses = 0;
    EXPECT_CALL(context, CloseFileDescriptor(_)).Times(replacedPins).WillRepeatedly([&](int fd) -> ComplianceEngine::Result<void> {
        ++oldCloses;
        auto result = context.RealCloseFileDescriptor(fd);
        if (oldCloses == 1)
        {
            errno = EIO;
            return ComplianceEngine::Error(errno ? errno : EIO);
        }
        return result;
    });
    EXPECT_CALL(incomingContext, CloseFileDescriptor(_)).Times(incomingPins).WillRepeatedly([&](int fd) -> ComplianceEngine::Result<void> {
        ++incomingCloses;
        return incomingContext.RealCloseFileDescriptor(fd);
    });
    *replaced = std::move(*incoming);
    EXPECT_EQ(replacedPins, oldCloses);
    EXPECT_EQ(0u, incomingCloses);
    EXPECT_EQ(&incomingContext, &replaced->Context());
    incoming.reset();
    EXPECT_EQ(0u, incomingCloses); // transferred path retains the shared snapshot
    replaced.reset();
    EXPECT_EQ(incomingPins, incomingCloses);
    EXPECT_EQ(before, OpenDescriptors());
}

TEST_F(ReadableFileTest, FailedPinDisposalAndLoggerDoNotSkipRemainingOwners)
{
    CountingLogContext selected;
    const std::string source = selected.MakeTempfile("held");
    const auto before = OpenDescriptors();
    ResolverLimits limits;
    limits.shared.components = 100;
    auto opened = Path::Make(selected, source, CrossMountExtension(), limits);
    ASSERT_TRUE(opened.HasValue());
    ASSERT_TRUE(opened.Value().Is<Path>());
    std::unique_ptr<Path> path(new Path(ComplianceEngine::As<Path>(std::move(opened.Value()))));
    opened = ComplianceEngine::Error("Release factory wrapper", EINVAL);
    const auto pins = path->RetainedDescriptors();
    ASSERT_GT(pins, 1u);
    std::size_t attempts = 0;
    EXPECT_CALL(selected, CloseFileDescriptor(_)).Times(pins).WillRepeatedly([&](int fd) -> ComplianceEngine::Result<void> {
        ++attempts;
        EXPECT_EQ(0, ::close(fd));
        if (attempts == 1)
        {
            errno = EIO;
            return ComplianceEngine::Error(errno ? errno : EIO);
        }
        if (attempts == 2)
        {
            errno = EACCES;
            return ComplianceEngine::Error(errno ? errno : EIO);
        }
        return ComplianceEngine::Result<void>::Success();
    });
    EXPECT_NO_THROW(path.reset());
    EXPECT_EQ(pins, attempts);
    EXPECT_EQ(2, selected.logHandleRequests);
    EXPECT_EQ(before, OpenDescriptors());
}

// ADR-0042 D4-D6: retired transition owners are held by inverse Steps rather
// than an auxiliary Pop. A failed final disposal cannot revoke a valid undo.
TEST_F(ReadableFileTest, DiagnosticTransitionReleasePreservesUndoAndHeldTarget)
{
    const std::string source = context.MakeTempfile("retained");
    const auto before = OpenDescriptors();
    ResolverLimits limits;
    limits.shared.components = 100;
    std::size_t attempts = 0;
    auto opened = Path::Make(context, context.GetTempdirPath(), CrossMountExtension(), limits);
    ASSERT_TRUE(opened.HasValue());
    ASSERT_TRUE(opened.Value().Is<Path>());
    Path path = ComplianceEngine::As<Path>(std::move(opened.Value()));
    opened = ComplianceEngine::Error("Release factory wrapper", EINVAL);
    ASSERT_TRUE(path.Freeze().HasValue());
    const std::size_t rootPins = path.RetainedDescriptors();
    auto selected = path.Resolve(Component(source), CrossMountExtension());
    ASSERT_TRUE(selected.HasValue());
    ASSERT_TRUE(selected.Value().Is<Path::Step>());
    Path::Component held = ComplianceEngine::As<Path::Step>(selected.Value()).Target();
    const auto inode = held.Metadata().Stat().st_ino;
    auto undo = path.Apply(ComplianceEngine::As<Path::Step>(std::move(selected.Value())));
    ASSERT_TRUE(undo.HasValue()) << undo.Error().message;
    auto restore = path.Apply(std::move(undo.Value()));
    ASSERT_TRUE(restore.HasValue()) << restore.Error().message;
    EXPECT_EQ(rootPins, path.RetainedDescriptors());
    ASSERT_TRUE(held.Stat().HasValue());
    EXPECT_EQ(inode, held.Stat().Value().st_ino);
    selected = ComplianceEngine::Error("Release selected Step", EINVAL);
    undo = ComplianceEngine::Error("Release inverse Step", EINVAL);
    restore = ComplianceEngine::Error("Release restored Step", EINVAL);
    EXPECT_CALL(context, CloseFileDescriptor(_)).Times(1).WillOnce([&](int fd) -> ComplianceEngine::Result<void> {
        ++attempts;
        struct stat target = {};
        EXPECT_EQ(0, ::fstat(fd, &target));
        EXPECT_EQ(inode, target.st_ino);
        EXPECT_EQ(0, ::close(fd));
        errno = EIO;
        return ComplianceEngine::Error(errno ? errno : EIO);
    });
    {
        Path::Component released(std::move(held)); // move-as-copy keeps both shares
    }
    EXPECT_EQ(0u, attempts);
    // Replace both owners only after the surviving path has been restored.
    held = path.Leaf();
    EXPECT_EQ(1u, attempts);
    ASSERT_TRUE(testing::Mock::VerifyAndClearExpectations(&context));
    EXPECT_EQ(rootPins, path.RetainedDescriptors());
    EXPECT_TRUE(path.Leaf().Stat().HasValue());
    auto next = path.Resolve(Component(source), CrossMountExtension());
    ASSERT_TRUE(next.HasValue());
    ASSERT_TRUE(next.Value().Is<Path::Step>());
    EXPECT_EQ(inode, ComplianceEngine::As<Path::Step>(next.Value()).Target().Metadata().Stat().st_ino);
    EXPECT_GE(OpenDescriptors(), before);
}

TEST_F(ReadableFileTest, ChildAcquisitionSurvivesFailedProcfsHelperDisposal)
{
    bool childOpened = false, helperFailed = false;
    const std::string source = context.MakeTempfile("pinned");
    const std::string name = Component(source);
    const auto before = OpenDescriptors();
    ResolverLimits limits;
    limits.shared.components = 100;
    auto opened = Path::Make(context, context.GetTempdirPath(), CrossMountExtension(), limits);
    ASSERT_TRUE(opened.HasValue());
    ASSERT_TRUE(opened.Value().Is<Path>());
    Path path = ComplianceEngine::As<Path>(std::move(opened.Value()));
    opened = ComplianceEngine::Error("Release factory wrapper", EINVAL);
    ASSERT_TRUE(path.Freeze().HasValue());
    EXPECT_CALL(context, OpenNativeAt(_, _, _)).Times(testing::AnyNumber());
    EXPECT_CALL(context, OpenNativeAt(_, testing::StrEq(name.c_str()), _)).WillRepeatedly([&](int directory, const char* entry, int flags) {
        const int fd = context.RealOpenNativeAt(directory, entry, flags);
        if (fd >= 0 && (flags & O_PATH))
            childOpened = true;
        return fd;
    });
    EXPECT_CALL(context, CloseFileDescriptor(_)).WillRepeatedly([&](int fd) -> ComplianceEngine::Result<void> {
        const std::string alias = "/proc/self/fd/" + std::to_string(fd);
        char target[256] = {};
        const ssize_t length = ::readlink(alias.c_str(), target, sizeof(target));
        const bool procfs = length >= 6 && std::string(target, static_cast<std::size_t>(length)).find("/proc/") == 0;
        auto result = context.RealCloseFileDescriptor(fd);
        if (childOpened && procfs && !helperFailed)
        {
            helperFailed = true;
            errno = EACCES;
            return ComplianceEngine::Error(errno ? errno : EIO);
        }
        return result;
    });
    auto selected = path.Resolve(name, CrossMountExtension());
    ASSERT_TRUE(selected.HasValue()) << selected.Error().message;
    ASSERT_TRUE(selected.Value().Is<Path::Step>());
    EXPECT_TRUE(childOpened);
    EXPECT_TRUE(helperFailed);
    auto target = ComplianceEngine::As<Path::Step>(selected.Value()).Target();
    EXPECT_EQ(source, target.Metadata().LookupName());
    EXPECT_TRUE(target.Stat().HasValue());
    EXPECT_TRUE(path.Leaf().Stat().HasValue());
    EXPECT_GE(OpenDescriptors(), before);
}

TEST_F(ReadableFileTest, RetiringResolvedPathVisitsRootPhysicalAncestorAndLeafPinsOnce)
{
    const std::string root = context.GetTempdirPath();
    ASSERT_EQ(0, ::mkdir((root + "/hidden").c_str(), 0700));
    const std::string source = context.MakeTempfile("pinned");
    ASSERT_EQ(0, ::rename(source.c_str(), (root + "/hidden/leaf").c_str()));
    ASSERT_EQ(0, ::symlink("hidden/leaf", (root + "/shortcut").c_str()));
    const auto before = OpenDescriptors();
    ResolverLimits limits;
    limits.shared.components = 100;
    Path::Policy policy = CrossMountExtension();
    policy.fileLinks = ComplianceEngine::Filesystem::FileLinkPolicy::Follow;
    auto opened = Path::Make(context, root, policy, limits);
    ASSERT_TRUE(opened.HasValue());
    ASSERT_TRUE(opened.Value().Is<Path>());
    std::unique_ptr<Path> path(new Path(ComplianceEngine::As<Path>(std::move(opened.Value()))));
    opened = ComplianceEngine::Error("Release factory wrapper", EINVAL);
    ASSERT_TRUE(path->Freeze().HasValue());
    auto selected = path->Resolve("shortcut", policy);
    ASSERT_TRUE(selected.HasValue()) << selected.Error().message;
    ASSERT_TRUE(selected.Value().Is<Path::Step>());
    auto inverse = path->Apply(ComplianceEngine::As<Path::Step>(std::move(selected.Value())));
    ASSERT_TRUE(inverse.HasValue()) << inverse.Error().message;
    EXPECT_EQ(root + "/hidden/leaf", path->ToString());
    selected = ComplianceEngine::Error("Release selected Step", EINVAL);
    inverse = ComplianceEngine::Error("Release inverse Step", EINVAL);
    const std::size_t pins = path->RetainedDescriptors();
    ASSERT_GT(pins, 2u);
    std::size_t closes = 0;
    EXPECT_CALL(context, CloseFileDescriptor(_)).Times(pins).WillRepeatedly([&](int fd) -> ComplianceEngine::Result<void> {
        ++closes;
        return context.RealCloseFileDescriptor(fd);
    });
    path.reset();
    EXPECT_EQ(pins, closes);
    EXPECT_EQ(before, OpenDescriptors());
}
