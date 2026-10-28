// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <MockContext.h>
#include <cerrno>
#include <dirent.h>
#include <fcntl.h>
#include <filesystem/Handle.hpp>
#include <filesystem/Path.hpp>
#include <filesystem/PathInternal.hpp>
#include <filesystem/ReadableFile.hpp>
#include <fstream>
#include <gtest/gtest.h>
#include <initializer_list>
#include <iterator>
#include <limits>
#include <linux/magic.h>
#include <new>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <type_traits>
#include <unistd.h>
#include <utility>

using ComplianceEngine::Filesystem::ExtensionPolicy;
using ComplianceEngine::Filesystem::Handle;
using ComplianceEngine::Filesystem::HardlinkPolicy;
using ComplianceEngine::Filesystem::MountPolicy;
using ComplianceEngine::Filesystem::Path;
using ComplianceEngine::Filesystem::ReadableFile;
using ComplianceEngine::Filesystem::ResolverLimits;
using ComplianceEngine::Filesystem::RootPolicy;
using ComplianceEngine::Filesystem::SymlinkPolicy;
using ComplianceEngine::Filesystem::Detail::Descriptor;
using ComplianceEngine::Filesystem::Detail::VerifiedProcfs;
using testing::_;
using testing::NiceMock;

namespace
{
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
    VerifiedProcfs procfs(context);
    auto opened = procfs.Open();
    if (!opened.HasValue())
    {
        return std::move(opened).Error();
    }
    Descriptor owned(std::move(procfs.proc));
    auto closed = procfs.Close();
    if (!closed.HasValue())
    {
        return std::move(closed).Error();
    }
    return owned;
}

struct ThrowingLogContext : NiceMock<MockContext>
{
    OsConfigLogHandle GetLogHandle() const override
    {
        ++logHandleRequests;
        throw std::runtime_error("log handle fault");
    }

    mutable int logHandleRequests = 0;
};

class ReadableFileTest : public testing::Test
{
protected:
    NiceMock<MockContext> context;
    static constexpr std::size_t fdinfoCap = 4096;
    std::size_t interruptRetriesRemaining = 1;

    ComplianceEngine::Result<Handle> Pin(MockContext& selectedContext, const std::string& component)
    {
        const ResolverLimits limits{{4096, 100, 100000, 256, 262144, fdinfoCap}, 4096, 8, 128};
        auto root = Path::AcquireRoot(selectedContext, selectedContext.GetTempdirPath(), RootPolicy{SymlinkPolicy::Reject, MountPolicy::AllowCrossing}, limits);
        if (!root.HasValue())
        {
            return std::move(root).Error();
        }
        Path path = std::move(root).Value();
        auto pushed = path.Push(component, ExtensionPolicy{SymlinkPolicy::Reject, MountPolicy::AllowCrossing, HardlinkPolicy::Permit});
        if (!pushed.HasValue())
        {
            return std::move(pushed).Error();
        }
        return path.Pop();
    }

    ComplianceEngine::Result<Handle> Pin(const std::string& component)
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
    static_assert(std::is_same<decltype(&ReadableFile::Read), ComplianceEngine::Result<ComplianceEngine::Optional<std::string>> (ReadableFile::*)(std::size_t, std::size_t&)>::value,
        "Reading must mutate the stream");
    static_assert(!std::is_default_constructible<ReadableFile>::value, "Cannot fabricate readable ownership");
    static_assert(!std::is_constructible<ReadableFile, int>::value, "No raw descriptor constructor");
    static_assert(!std::is_copy_constructible<ReadableFile>::value, "No duplicated ownership");
    static_assert(std::is_move_constructible<ReadableFile>::value, "Transfer ownership");
    static_assert(std::is_move_assignable<ReadableFile>::value, "Transfer ownership");
    static_assert(std::is_nothrow_move_constructible<ReadableFile>::value, "Transferring source context and ownership cannot throw");
    static_assert(std::is_nothrow_move_assignable<ReadableFile>::value, "Replacing ownership across contexts cannot throw");
    static_assert(std::is_nothrow_destructible<ReadableFile>::value, "Cleanup cannot throw");
}

TEST_F(ReadableFileTest, DescriptorExplicitCloseLogsNativeErrorOnceWithoutRetryInMoveOrDestruction)
{
    const std::string logPath = context.GetTempdirPath() + "/descriptor-close.log";
    OsConfigLogHandle logHandle = OpenLog(logPath.c_str(), nullptr);
    ASSERT_NE(nullptr, logHandle);
    context.SetLogHandle(logHandle);
    auto acquired = VerifiedTestDescriptor(context);
    ASSERT_TRUE(acquired.HasValue()) << acquired.Error().message;
    Descriptor owner = std::move(acquired).Value();
    const int fd = owner.Get().Value();
    {
        EXPECT_CALL(context, CloseFileDescriptor(fd)).Times(1).WillOnce([](int descriptor) {
            EXPECT_EQ(0, ::close(descriptor));
            errno = EACCES;
            return -1;
        });
        auto failed = owner.Close();
        ASSERT_FALSE(failed.HasValue());
        EXPECT_EQ(EACCES, failed.Error().code);
        EXPECT_TRUE(owner.Close().HasValue());
        Descriptor moved(std::move(owner));
        moved = std::move(owner);
        EXPECT_TRUE(moved.Close().HasValue());
    }
    CloseLog(&logHandle);
    context.SetLogHandle(nullptr);
    std::ifstream log(logPath);
    ASSERT_TRUE(log.is_open());
    const std::string text((std::istreambuf_iterator<char>(log)), std::istreambuf_iterator<char>());
    const std::string expected = "Failed to close internal filesystem descriptor: " + std::to_string(EACCES);
    const auto occurrence = text.find(expected);
    ASSERT_NE(std::string::npos, occurrence);
    EXPECT_EQ(std::string::npos, text.find(expected, occurrence + expected.size()));
}

TEST_F(ReadableFileTest, DescriptorMoveReplacementRoutesThrownCloseToOldContextOnce)
{
    ThrowingLogContext oldContext;
    NiceMock<MockContext> incomingContext;
    auto oldResult = VerifiedTestDescriptor(oldContext);
    ASSERT_TRUE(oldResult.HasValue()) << oldResult.Error().message;
    Descriptor old = std::move(oldResult).Value();
    const int oldFd = old.Get().Value();
    auto incomingResult = VerifiedTestDescriptor(incomingContext);
    ASSERT_TRUE(incomingResult.HasValue()) << incomingResult.Error().message;
    Descriptor incoming = std::move(incomingResult).Value();
    const int incomingFd = incoming.Get().Value();
    {
        EXPECT_CALL(oldContext, CloseFileDescriptor(oldFd)).Times(1).WillOnce([](int descriptor) -> int {
            EXPECT_EQ(0, ::close(descriptor));
            throw std::runtime_error("native close fault");
        });
        EXPECT_CALL(incomingContext, CloseFileDescriptor(incomingFd)).Times(1).WillOnce([](int descriptor) { return ::close(descriptor); });
        testing::internal::CaptureStderr();
        old = std::move(incoming);
        EXPECT_TRUE(incoming.Close().HasValue());
        EXPECT_TRUE(old.Close().HasValue());
        EXPECT_TRUE(old.Close().HasValue());
        const auto logged = testing::internal::GetCapturedStderr();
        if (IsConsoleLoggingEnabled() && GetLoggingLevel() >= LoggingLevelError)
        {
            const auto expected = "Filesystem descriptor close or log failure: " + std::to_string(EIO);
            const auto occurrence = logged.find(expected);
            ASSERT_NE(std::string::npos, occurrence);
            EXPECT_EQ(std::string::npos, logged.find(expected, occurrence + expected.size()));
        }
        EXPECT_EQ(1, oldContext.logHandleRequests);
    }
    EXPECT_EQ(1, oldContext.logHandleRequests);
}

TEST_F(ReadableFileTest, AliasOpenFailureDoesNotReopenNameOrLeak)
{
    const std::string source = context.MakeTempfile("held");
    auto pinned = Pin(Component(source));
    ASSERT_TRUE(pinned.HasValue());
    const auto before = OpenDescriptors();
    bool throwAlias = false, denied = false, cleanupFailed = false;
    EXPECT_CALL(context, OpenNativePath(_, _)).WillRepeatedly([&](const char* path, int flags) {
        return context.ContextInterface::OpenNativePath(path, flags);
    });
    EXPECT_CALL(context, OpenNativePath(testing::StrEq(source.c_str()), _)).Times(0);
    EXPECT_CALL(context, OpenExistingFile(testing::StrEq(source.c_str()), _)).Times(0);
    EXPECT_CALL(context, OpenNativeAt(_, _, _)).WillRepeatedly([&](int directory, const char* name, int flags) {
        char path[512] = {};
        const std::string alias = "/proc/self/fd/" + std::to_string(directory);
        const ssize_t length = ::readlink(alias.c_str(), path, sizeof(path));
        if ((0 < length) && (std::string(path, static_cast<std::size_t>(length)).find("/fd") != std::string::npos) && (0 == (flags & O_PATH)) &&
            (0 == (flags & O_NOFOLLOW)) && (0 != (flags & O_CLOEXEC)))
        {
            EXPECT_FALSE(std::string(name).empty());
            if (throwAlias)
            {
                throw std::runtime_error("native alias open fault");
            }
            denied = true;
            errno = EACCES;
            return -1;
        }
        return context.ContextInterface::OpenNativeAt(directory, name, flags);
    });
    EXPECT_CALL(context, CloseFileDescriptor(_)).WillRepeatedly([&](int descriptor) {
        struct statfs filesystem = {};
        const bool procfs = (0 == ::fstatfs(descriptor, &filesystem)) && (PROC_SUPER_MAGIC == filesystem.f_type);
        const int status = ::close(descriptor);
        EXPECT_EQ(0, status);
        if (procfs && denied && !cleanupFailed)
        {
            cleanupFailed = true;
            errno = EIO;
            return -1;
        }
        return status;
    });
    auto readable = pinned.Value().OpenReadOnly(fdinfoCap);
    ASSERT_FALSE(readable.HasValue());
    EXPECT_EQ(EACCES, readable.Error().code);
    EXPECT_TRUE(cleanupFailed);
    EXPECT_EQ(before, OpenDescriptors());
    throwAlias = true;
    EXPECT_THROW((void)pinned.Value().OpenReadOnly(fdinfoCap), std::runtime_error);
    EXPECT_EQ(before, OpenDescriptors());
    ASSERT_TRUE(testing::Mock::VerifyAndClearExpectations(&context));
}

TEST_F(ReadableFileTest, AliasOutputClosesWhenProcfsHelperCloseFails)
{
    const std::string source = context.MakeTempfile("held");
    auto pinned = Pin(Component(source));
    ASSERT_TRUE(pinned.HasValue());
    const auto before = OpenDescriptors();
    bool failed = false, aliasOpened = false;
    EXPECT_CALL(context, OpenNativeAt(_, _, _)).WillRepeatedly([&](int directory, const char* name, int flags) {
        const int descriptor = context.ContextInterface::OpenNativeAt(directory, name, flags);
        if ((0 <= descriptor) && (0 == (flags & O_PATH)) && (0 == (flags & O_NOFOLLOW)))
        {
            aliasOpened = true;
        }
        return descriptor;
    });
    EXPECT_CALL(context, CloseFileDescriptor(_)).WillRepeatedly([&](int descriptor) {
        struct statfs filesystem = {};
        const bool procfs = (0 == ::fstatfs(descriptor, &filesystem)) && (PROC_SUPER_MAGIC == filesystem.f_type);
        const int status = ::close(descriptor);
        EXPECT_EQ(0, status);
        if (procfs && aliasOpened && !failed)
        {
            failed = true;
            errno = EIO;
            return -1;
        }
        return status;
    });
    auto readable = pinned.Value().OpenReadOnly(fdinfoCap);
    ASSERT_FALSE(readable.HasValue());
    EXPECT_EQ(EIO, readable.Error().code);
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
    const ino_t inode = pinned.Value().Stat().st_ino;
    auto pinnedBefore = pinned.Value().Stat(fdinfoCap);
    ASSERT_TRUE(pinnedBefore.HasValue());
    EXPECT_EQ(inode, pinnedBefore.Value().st_ino);
    ASSERT_EQ(0, ::rename(original.c_str(), (original + ".old").c_str()));
    ASSERT_EQ(0, ::symlink("/dev/zero", original.c_str()));
    auto activated = pinned.Value().OpenReadOnly(fdinfoCap);
    ASSERT_TRUE(activated.HasValue()) << activated.Error().message;
    ReadableFile readable = std::move(activated).Value();
    pinned = ComplianceEngine::Error("Release pin", EINVAL);
    auto before = readable.Stat();
    ASSERT_TRUE(before.HasValue());
    EXPECT_EQ(inode, before.Value().st_ino);
    EXPECT_TRUE(S_ISREG(before.Value().st_mode));
    auto read = readable.Read(8, interruptRetriesRemaining);
    ASSERT_TRUE(read.HasValue());
    ASSERT_TRUE(read.Value().HasValue());
    EXPECT_EQ("first", read.Value().Value());
    auto eof = readable.Read(8, interruptRetriesRemaining);
    ASSERT_TRUE(eof.HasValue());
    EXPECT_FALSE(eof.Value().HasValue());
    auto after = readable.Stat();
    ASSERT_TRUE(after.HasValue());
    EXPECT_EQ(before.Value().st_ino, after.Value().st_ino);
    EXPECT_EQ(before.Value().st_size, after.Value().st_size);
    EXPECT_CALL(context, CloseFileDescriptor(_)).Times(1).WillOnce([](int descriptor) { return ::close(descriptor); });
    EXPECT_TRUE(readable.Close().HasValue());
    EXPECT_TRUE(readable.Close().HasValue());
    EXPECT_EQ(EBADF, readable.Read(1, interruptRetriesRemaining).Error().code);
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
                const int descriptor = context.ContextInterface::OpenNativeAt(directory, name, flags);
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
            auto acquired = pinned.Value().OpenReadOnly(fdinfoCap);
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
            auto chunk = readable.Read(8, interruptRetriesRemaining);
            if (!chunk.HasValue() || !chunk.Value().HasValue() || (chunk.Value().Value() != "zero") || !readable.AtEnd() || !readable.Stat().HasValue())
            {
                ::_exit(6);
            }
            EXPECT_CALL(context, CloseFileDescriptor(_)).WillRepeatedly([&](int descriptor) {
                if (descriptor == STDIN_FILENO)
                {
                    if (closed)
                    {
                        ::_exit(7);
                    }
                    closed = true;
                }
                return ::close(descriptor);
            });
            if (!readable.Close().HasValue() || !readable.Close().HasValue() || !closed || (readable.Stat().Error().code != EBADF))
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
    auto activated = pinned.Value().OpenReadOnly(fdinfoCap);
    ASSERT_TRUE(activated.HasValue());
    ReadableFile readable = std::move(activated).Value();

    EXPECT_CALL(context, ReadFileDescriptor(_, _, 2)).Times(1);
    EXPECT_CALL(context, ReadFileDescriptor(_, _, 8)).Times(1);
    EXPECT_CALL(context, ReadFileDescriptor(_, _, 5)).Times(1);
    EXPECT_CALL(context, ReadFileDescriptor(_, _, 1)).Times(0);
    auto first = readable.Read(2, interruptRetriesRemaining);
    ASSERT_TRUE(first.HasValue());
    ASSERT_TRUE(first.Value().HasValue());
    EXPECT_EQ(payload.substr(0, 2), first.Value().Value());
    auto second = readable.Read(8, interruptRetriesRemaining);
    ASSERT_TRUE(second.HasValue());
    ASSERT_TRUE(second.Value().HasValue());
    EXPECT_EQ(payload.substr(2), second.Value().Value());
    EXPECT_TRUE(readable.AtEnd());                          // short read followed by native EOF
    EXPECT_EQ(payload.substr(0, 2), first.Value().Value()); // earlier owned chunk is unchanged
    auto eof = readable.Read(1, interruptRetriesRemaining);
    ASSERT_TRUE(eof.HasValue());
    EXPECT_FALSE(eof.Value().HasValue());
    auto repeated = readable.Read(1, interruptRetriesRemaining);
    ASSERT_TRUE(repeated.HasValue());
    EXPECT_FALSE(repeated.Value().HasValue());
}

TEST_F(ReadableFileTest, ShortNativeReadsFillCapacityAtShrinkingOffsetsWithoutEofProbe)
{
    const std::string source = context.MakeTempfile(std::string("a\0bcd", 5));
    auto pinned = Pin(Component(source));
    ASSERT_TRUE(pinned.HasValue());
    auto activated = pinned.Value().OpenReadOnly(fdinfoCap);
    ASSERT_TRUE(activated.HasValue());
    ReadableFile readable = std::move(activated).Value();
    EXPECT_FALSE(readable.AtEnd());
    void* start = nullptr;
    EXPECT_CALL(context, ReadFileDescriptor(_, _, 5)).Times(1).WillOnce([&](int fd, void* buffer, std::size_t) {
        start = buffer;
        return context.ContextInterface::ReadFileDescriptor(fd, buffer, 1);
    });
    EXPECT_CALL(context, ReadFileDescriptor(_, _, 4)).Times(1).WillOnce([&](int fd, void* buffer, std::size_t) {
        EXPECT_EQ(static_cast<char*>(start) + 1, buffer);
        return context.ContextInterface::ReadFileDescriptor(fd, buffer, 2);
    });
    EXPECT_CALL(context, ReadFileDescriptor(_, _, 2)).Times(1).WillOnce([&](int fd, void* buffer, std::size_t size) {
        EXPECT_EQ(static_cast<char*>(start) + 3, buffer);
        return context.ContextInterface::ReadFileDescriptor(fd, buffer, size);
    });
    auto filled = readable.Read(5, interruptRetriesRemaining);
    ASSERT_TRUE(filled.HasValue());
    ASSERT_TRUE(filled.Value().HasValue());
    EXPECT_EQ(std::string("a\0bcd", 5), filled.Value().Value());
    EXPECT_FALSE(readable.AtEnd()); // full capacity is not proof of EOF
    EXPECT_EQ(1U, interruptRetriesRemaining);
    ASSERT_TRUE(testing::Mock::VerifyAndClearExpectations(&context));
    auto eof = readable.Read(1, interruptRetriesRemaining);
    ASSERT_TRUE(eof.HasValue());
    EXPECT_FALSE(eof.Value().HasValue());
    EXPECT_TRUE(readable.AtEnd());
}

TEST_F(ReadableFileTest, EofAfterShortProgressReturnsEngagedPartialButImmediateEofIsDisengaged)
{
    const std::string source = context.MakeTempfile("ab");
    auto pinned = Pin(Component(source));
    ASSERT_TRUE(pinned.HasValue());
    auto activated = pinned.Value().OpenReadOnly(fdinfoCap);
    ASSERT_TRUE(activated.HasValue());
    ReadableFile readable = std::move(activated).Value();
    EXPECT_FALSE(readable.AtEnd());
    void* start = nullptr;
    EXPECT_CALL(context, ReadFileDescriptor(_, _, 5)).Times(1).WillOnce([&](int fd, void* buffer, std::size_t) {
        start = buffer;
        return context.ContextInterface::ReadFileDescriptor(fd, buffer, 2);
    });
    EXPECT_CALL(context, ReadFileDescriptor(_, _, 3)).Times(1).WillOnce([&](int fd, void* buffer, std::size_t size) {
        EXPECT_EQ(static_cast<char*>(start) + 2, buffer);
        return context.ContextInterface::ReadFileDescriptor(fd, buffer, size);
    });
    auto partial = readable.Read(5, interruptRetriesRemaining);
    ASSERT_TRUE(partial.HasValue());
    ASSERT_TRUE(partial.Value().HasValue());
    EXPECT_EQ("ab", partial.Value().Value());
    EXPECT_TRUE(readable.AtEnd());
    ASSERT_TRUE(testing::Mock::VerifyAndClearExpectations(&context));
    EXPECT_CALL(context, ReadFileDescriptor(_, _, _)).Times(0);
    auto eof = readable.Read(5, interruptRetriesRemaining);
    ASSERT_TRUE(eof.HasValue());
    EXPECT_FALSE(eof.Value().HasValue());
    EXPECT_TRUE(readable.AtEnd());
}

TEST_F(ReadableFileTest, ObservedEofTransfersWithOwnershipAndResetsOnClose)
{
    const std::string source = context.MakeTempfile("ab");
    auto pinned = Pin(Component(source));
    ASSERT_TRUE(pinned.HasValue());
    auto first = pinned.Value().OpenReadOnly(fdinfoCap);
    auto second = pinned.Value().OpenReadOnly(fdinfoCap);
    ASSERT_TRUE(first.HasValue());
    ASSERT_TRUE(second.HasValue());
    ReadableFile original = std::move(first).Value();
    ReadableFile replacement = std::move(second).Value();
    EXPECT_FALSE(original.AtEnd());
    EXPECT_FALSE(replacement.AtEnd());
    auto partial = original.Read(5, interruptRetriesRemaining);
    ASSERT_TRUE(partial.HasValue());
    ASSERT_TRUE(partial.Value().HasValue());
    EXPECT_EQ("ab", partial.Value().Value());
    EXPECT_TRUE(original.AtEnd());
    ReadableFile moved(std::move(original));
    EXPECT_FALSE(original.AtEnd());
    EXPECT_EQ(EBADF, original.Read(1, interruptRetriesRemaining).Error().code);
    EXPECT_TRUE(moved.AtEnd());
    replacement = std::move(moved);
    EXPECT_FALSE(moved.AtEnd());
    EXPECT_EQ(EBADF, moved.Read(1, interruptRetriesRemaining).Error().code);
    EXPECT_TRUE(replacement.AtEnd());
    EXPECT_CALL(context, ReadFileDescriptor(_, _, _)).Times(0);
    auto eof = replacement.Read(1, interruptRetriesRemaining);
    ASSERT_TRUE(eof.HasValue());
    EXPECT_FALSE(eof.Value().HasValue());
    EXPECT_TRUE(replacement.Close().HasValue());
    EXPECT_FALSE(replacement.AtEnd());
    EXPECT_EQ(EBADF, replacement.Read(1, interruptRetriesRemaining).Error().code);
}

TEST_F(ReadableFileTest, InterruptedShortReadsShareCumulativeBudgetAndAllowProgressAtZero)
{
    const std::string source = context.MakeTempfile("abcde");
    auto pinned = Pin(Component(source));
    ASSERT_TRUE(pinned.HasValue());
    auto activated = pinned.Value().OpenReadOnly(fdinfoCap);
    ASSERT_TRUE(activated.HasValue());
    ReadableFile readable = std::move(activated).Value();
    interruptRetriesRemaining = 2;
    int calls = 0;
    void* start = nullptr;
    EXPECT_CALL(context, ReadFileDescriptor(_, _, 5)).Times(2).WillRepeatedly([&](int fd, void* buffer, std::size_t) -> ssize_t {
        if (++calls == 1)
        {
            errno = EINTR;
            return -1;
        }
        start = buffer;
        return context.ContextInterface::ReadFileDescriptor(fd, buffer, 2);
    });
    EXPECT_CALL(context, ReadFileDescriptor(_, _, 3)).Times(2).WillRepeatedly([&](int fd, void* buffer, std::size_t) -> ssize_t {
        EXPECT_EQ(static_cast<char*>(start) + 2, buffer);
        if (++calls == 3)
        {
            errno = EINTR;
            return -1;
        }
        return context.ContextInterface::ReadFileDescriptor(fd, buffer, 1);
    });
    EXPECT_CALL(context, ReadFileDescriptor(_, _, 2)).Times(1).WillOnce([&](int fd, void* buffer, std::size_t size) {
        EXPECT_EQ(static_cast<char*>(start) + 3, buffer);
        return context.ContextInterface::ReadFileDescriptor(fd, buffer, size);
    });
    auto filled = readable.Read(5, interruptRetriesRemaining);
    ASSERT_TRUE(filled.HasValue());
    ASSERT_TRUE(filled.Value().HasValue());
    EXPECT_EQ("abcde", filled.Value().Value());
    EXPECT_FALSE(readable.AtEnd());
    EXPECT_EQ(0U, interruptRetriesRemaining);
    EXPECT_EQ(4, calls);
}

TEST_F(ReadableFileTest, NativeErrorAfterShortProgressDoesNotReturnPartialDataOrResetOffset)
{
    const std::string source = context.MakeTempfile("abcde");
    auto pinned = Pin(Component(source));
    ASSERT_TRUE(pinned.HasValue());
    auto activated = pinned.Value().OpenReadOnly(fdinfoCap);
    ASSERT_TRUE(activated.HasValue());
    ReadableFile readable = std::move(activated).Value();
    EXPECT_CALL(context, ReadFileDescriptor(_, _, 5)).Times(1).WillOnce([&](int fd, void* buffer, std::size_t) {
        return context.ContextInterface::ReadFileDescriptor(fd, buffer, 2);
    });
    EXPECT_CALL(context, ReadFileDescriptor(_, _, 3)).Times(1).WillOnce([](int, void*, std::size_t) -> ssize_t {
        errno = EIO;
        return -1;
    });
    auto failed = readable.Read(5, interruptRetriesRemaining);
    ASSERT_FALSE(failed.HasValue());
    EXPECT_EQ(EIO, failed.Error().code);
    EXPECT_FALSE(readable.AtEnd());
    EXPECT_EQ("Cannot read acquired file", failed.Error().message);
    EXPECT_EQ(1U, interruptRetriesRemaining);
    ASSERT_TRUE(testing::Mock::VerifyAndClearExpectations(&context));
    auto remaining = readable.Read(3, interruptRetriesRemaining);
    ASSERT_TRUE(remaining.HasValue());
    ASSERT_TRUE(remaining.Value().HasValue());
    EXPECT_EQ("cde", remaining.Value().Value());
}

TEST_F(ReadableFileTest, ExhaustedEintrAfterShortProgressIsErrorNotPartialData)
{
    const std::string source = context.MakeTempfile("abc");
    auto pinned = Pin(Component(source));
    ASSERT_TRUE(pinned.HasValue());
    auto activated = pinned.Value().OpenReadOnly(fdinfoCap);
    ASSERT_TRUE(activated.HasValue());
    ReadableFile readable = std::move(activated).Value();
    interruptRetriesRemaining = 0;
    EXPECT_CALL(context, ReadFileDescriptor(_, _, 3)).Times(1).WillOnce([&](int fd, void* buffer, std::size_t) {
        return context.ContextInterface::ReadFileDescriptor(fd, buffer, 1);
    });
    EXPECT_CALL(context, ReadFileDescriptor(_, _, 2)).Times(1).WillOnce([](int, void*, std::size_t) -> ssize_t {
        errno = EINTR;
        return -1;
    });
    auto failed = readable.Read(3, interruptRetriesRemaining);
    ASSERT_FALSE(failed.HasValue());
    EXPECT_EQ(EINTR, failed.Error().code);
    EXPECT_FALSE(readable.AtEnd());
    EXPECT_EQ(0U, interruptRetriesRemaining);
    ASSERT_TRUE(testing::Mock::VerifyAndClearExpectations(&context));
    auto remaining = readable.Read(2, interruptRetriesRemaining);
    ASSERT_TRUE(remaining.HasValue());
    ASSERT_TRUE(remaining.Value().HasValue());
    EXPECT_EQ("bc", remaining.Value().Value());
}

TEST_F(ReadableFileTest, OverreportOnReducedRemainingRequestFailsBeforePublishing)
{
    const std::string source = context.MakeTempfile("abcde");
    auto pinned = Pin(Component(source));
    ASSERT_TRUE(pinned.HasValue());
    auto activated = pinned.Value().OpenReadOnly(fdinfoCap);
    ASSERT_TRUE(activated.HasValue());
    ReadableFile readable = std::move(activated).Value();
    EXPECT_CALL(context, ReadFileDescriptor(_, _, 5)).Times(1).WillOnce([&](int fd, void* buffer, std::size_t) {
        return context.ContextInterface::ReadFileDescriptor(fd, buffer, 2);
    });
    EXPECT_CALL(context, ReadFileDescriptor(_, _, 3)).Times(1).WillOnce([](int, void*, std::size_t) -> ssize_t { return 4; });
    auto failed = readable.Read(5, interruptRetriesRemaining);
    ASSERT_FALSE(failed.HasValue());
    EXPECT_EQ(EIO, failed.Error().code);
    EXPECT_FALSE(readable.AtEnd());
    EXPECT_EQ("Readable file returned more bytes than requested", failed.Error().message);
    ASSERT_TRUE(testing::Mock::VerifyAndClearExpectations(&context));
    auto remaining = readable.Read(3, interruptRetriesRemaining);
    ASSERT_TRUE(remaining.HasValue());
    ASSERT_TRUE(remaining.Value().HasValue());
    EXPECT_EQ("cde", remaining.Value().Value());
}

TEST_F(ReadableFileTest, ZeroBudgetPreservesInterruptedReadAndInspectErrnosWithoutFalseEof)
{
    const std::string source = context.MakeTempfile("x");
    auto pinned = Pin(Component(source));
    ASSERT_TRUE(pinned.HasValue());
    auto activated = pinned.Value().OpenReadOnly(fdinfoCap);
    ASSERT_TRUE(activated.HasValue());
    ReadableFile readable = std::move(activated).Value();
    EXPECT_CALL(context, ReadFileDescriptor(_, _, 1)).Times(1).WillOnce([](int, void*, std::size_t) -> ssize_t {
        errno = EINTR;
        return -1;
    });
    interruptRetriesRemaining = 0;
    auto interrupted = readable.Read(1, interruptRetriesRemaining);
    ASSERT_FALSE(interrupted.HasValue());
    EXPECT_EQ(EINTR, interrupted.Error().code);
    EXPECT_EQ(0U, interruptRetriesRemaining);
    EXPECT_CALL(context, ReadFileDescriptor(_, _, 1)).Times(1).WillOnce([](int, void*, std::size_t) -> ssize_t {
        errno = EIO;
        return -1;
    });
    auto failed = readable.Read(1, interruptRetriesRemaining);
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
    EXPECT_EQ(EINVAL, readable.Read(0, interruptRetriesRemaining).Error().code);
    EXPECT_EQ(EINVAL, readable.Read(static_cast<std::size_t>(std::numeric_limits<ssize_t>::max()) + 1, interruptRetriesRemaining).Error().code);
    if (std::string().max_size() < static_cast<std::size_t>(std::numeric_limits<ssize_t>::max()))
    {
        EXPECT_EQ(EOVERFLOW, readable.Read(std::string().max_size() + 1, interruptRetriesRemaining).Error().code);
    }
    ASSERT_TRUE(testing::Mock::VerifyAndClearExpectations(&context));
    // A rejected zero request did not consume the byte or falsely report EOF.
    auto next = readable.Read(1, interruptRetriesRemaining);
    ASSERT_TRUE(next.HasValue());
    ASSERT_TRUE(next.Value().HasValue());
    EXPECT_EQ("x", next.Value().Value());
}

TEST_F(ReadableFileTest, InterruptedReadConsumesOnlyRetriesAndPreservesBinaryDataAndEof)
{
    const std::string source = context.MakeTempfile(std::string("a\0b", 3));
    auto pinned = Pin(Component(source));
    ASSERT_TRUE(pinned.HasValue());
    auto activated = pinned.Value().OpenReadOnly(fdinfoCap);
    ASSERT_TRUE(activated.HasValue());
    ReadableFile readable = std::move(activated).Value();
    interruptRetriesRemaining = 2;
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
        .WillOnce([&](int descriptor, void* buffer, std::size_t size) { return context.ContextInterface::ReadFileDescriptor(descriptor, buffer, size); });
    EXPECT_CALL(context, ReadFileDescriptor(_, _, 5)).Times(1);
    auto read = readable.Read(8, interruptRetriesRemaining);
    ASSERT_TRUE(read.HasValue());
    ASSERT_TRUE(read.Value().HasValue());
    EXPECT_EQ(std::string("a\0b", 3), read.Value().Value());
    EXPECT_TRUE(readable.AtEnd());
    EXPECT_EQ(0U, interruptRetriesRemaining);
    ASSERT_TRUE(testing::Mock::VerifyAndClearExpectations(&context));
    auto eof = readable.Read(8, interruptRetriesRemaining);
    ASSERT_TRUE(eof.HasValue());
    EXPECT_FALSE(eof.Value().HasValue());
    EXPECT_TRUE(readable.AtEnd());
    EXPECT_EQ(0U, interruptRetriesRemaining);
}

TEST_F(ReadableFileTest, ExhaustedInterruptedReadReturnsNativeEintrAfterLimitPlusOneAttempts)
{
    const std::string source = context.MakeTempfile("x");
    auto pinned = Pin(Component(source));
    ASSERT_TRUE(pinned.HasValue());
    auto activated = pinned.Value().OpenReadOnly(fdinfoCap);
    ASSERT_TRUE(activated.HasValue());
    ReadableFile readable = std::move(activated).Value();
    EXPECT_CALL(context, ReadFileDescriptor(_, _, 1)).Times(2).WillRepeatedly([](int, void*, std::size_t) -> ssize_t {
        errno = EINTR;
        return -1;
    });
    auto interrupted = readable.Read(1, interruptRetriesRemaining);
    ASSERT_FALSE(interrupted.HasValue());
    EXPECT_EQ(EINTR, interrupted.Error().code);
    EXPECT_EQ(0U, interruptRetriesRemaining);
    ASSERT_TRUE(testing::Mock::VerifyAndClearExpectations(&context));
    auto next = readable.Read(1, interruptRetriesRemaining);
    ASSERT_TRUE(next.HasValue());
    ASSERT_TRUE(next.Value().HasValue());
    EXPECT_EQ("x", next.Value().Value());
}

TEST_F(ReadableFileTest, NonInterruptedNativeErrorsNeverSpendRetryBudget)
{
    const std::string source = context.MakeTempfile("x");
    auto pinned = Pin(Component(source));
    ASSERT_TRUE(pinned.HasValue());
    auto activated = pinned.Value().OpenReadOnly(fdinfoCap);
    ASSERT_TRUE(activated.HasValue());
    ReadableFile readable = std::move(activated).Value();
    for (const int failure : {EAGAIN, EIO})
    {
        EXPECT_CALL(context, ReadFileDescriptor(_, _, 1)).Times(1).WillOnce([failure](int, void*, std::size_t) -> ssize_t {
            errno = failure;
            return -1;
        });
        auto failed = readable.Read(1, interruptRetriesRemaining);
        ASSERT_FALSE(failed.HasValue());
        EXPECT_EQ(failure, failed.Error().code);
        EXPECT_EQ(1U, interruptRetriesRemaining);
        ASSERT_TRUE(testing::Mock::VerifyAndClearExpectations(&context));
    }
    auto next = readable.Read(1, interruptRetriesRemaining);
    ASSERT_TRUE(next.HasValue());
    ASSERT_TRUE(next.Value().HasValue());
    EXPECT_EQ("x", next.Value().Value());
}

TEST_F(ReadableFileTest, EmptyFilePositiveReadReturnsEof)
{
    const std::string source = context.MakeTempfile("");
    auto pinned = Pin(Component(source));
    ASSERT_TRUE(pinned.HasValue());
    auto activated = pinned.Value().OpenReadOnly(fdinfoCap);
    ASSERT_TRUE(activated.HasValue());
    ReadableFile readable = std::move(activated).Value();
    auto metadata = readable.Stat();
    ASSERT_TRUE(metadata.HasValue());
    EXPECT_EQ(0, metadata.Value().st_size);
    EXPECT_FALSE(readable.AtEnd()); // stat does not predict EOF
    EXPECT_CALL(context, ReadFileDescriptor(_, _, 1)).Times(1);
    auto end = readable.Read(1, interruptRetriesRemaining);
    ASSERT_TRUE(end.HasValue());
    EXPECT_FALSE(end.Value().HasValue());
    EXPECT_TRUE(readable.AtEnd());
    auto again = readable.Read(1, interruptRetriesRemaining);
    ASSERT_TRUE(again.HasValue());
    EXPECT_FALSE(again.Value().HasValue());
    EXPECT_TRUE(readable.AtEnd());
}

TEST_F(ReadableFileTest, OverreportedReadIsAnErrorNotDataOrEof)
{
    const std::string source = context.MakeTempfile("x");
    auto pinned = Pin(Component(source));
    ASSERT_TRUE(pinned.HasValue());
    auto activated = pinned.Value().OpenReadOnly(fdinfoCap);
    ASSERT_TRUE(activated.HasValue());
    ReadableFile readable = std::move(activated).Value();
    EXPECT_CALL(context, ReadFileDescriptor(_, _, 1)).Times(1).WillOnce([](int, void*, std::size_t) -> ssize_t { return 2; });
    auto overreported = readable.Read(1, interruptRetriesRemaining);
    ASSERT_FALSE(overreported.HasValue());
    EXPECT_EQ(EIO, overreported.Error().code);
    ASSERT_TRUE(testing::Mock::VerifyAndClearExpectations(&context));
    auto next = readable.Read(1, interruptRetriesRemaining);
    ASSERT_TRUE(next.HasValue());
    ASSERT_TRUE(next.Value().HasValue());
    EXPECT_EQ("x", next.Value().Value());
}

TEST_F(ReadableFileTest, ThrowingReadPropagatesWithoutInvalidatingDescriptor)
{
    const std::string source = context.MakeTempfile("x");
    auto pinned = Pin(Component(source));
    ASSERT_TRUE(pinned.HasValue());
    auto activated = pinned.Value().OpenReadOnly(fdinfoCap);
    ASSERT_TRUE(activated.HasValue());
    ReadableFile readable = std::move(activated).Value();
    EXPECT_CALL(context, ReadFileDescriptor(_, _, 1)).Times(1).WillOnce([](int, void*, std::size_t) -> ssize_t { throw std::bad_alloc(); });
    EXPECT_THROW((void)readable.Read(1, interruptRetriesRemaining), std::bad_alloc);
    ASSERT_TRUE(testing::Mock::VerifyAndClearExpectations(&context));
    EXPECT_CALL(context, ReadFileDescriptor(_, _, 1)).Times(1).WillOnce([](int, void*, std::size_t) -> ssize_t {
        throw std::length_error("native read fault");
    });
    EXPECT_THROW((void)readable.Read(1, interruptRetriesRemaining), std::length_error);
    ASSERT_TRUE(testing::Mock::VerifyAndClearExpectations(&context));
    auto next = readable.Read(1, interruptRetriesRemaining);
    ASSERT_TRUE(next.HasValue());
    ASSERT_TRUE(next.Value().HasValue());
    EXPECT_EQ("x", next.Value().Value());
}

TEST_F(ReadableFileTest, CheckedLeafAndPathReleasePreservesIndependentReadable)
{
    const std::string source = context.MakeTempfile(std::string("a\0b", 3));
    const ResolverLimits limits{{4096, 100, 100000, 256, 262144, fdinfoCap}, 4096, 8, 128};
    auto opened = Path::AcquireRoot(context, context.GetTempdirPath(), RootPolicy{SymlinkPolicy::Reject, MountPolicy::AllowCrossing}, limits);
    ASSERT_TRUE(opened.HasValue());
    Path path = std::move(opened).Value();
    ASSERT_TRUE(path.Push(Component(source), ExtensionPolicy{SymlinkPolicy::Reject, MountPolicy::AllowCrossing, HardlinkPolicy::Permit}).HasValue());
    auto popped = path.Pop();
    ASSERT_TRUE(popped.HasValue());
    Handle leaf = std::move(popped).Value();
    auto activated = leaf.OpenReadOnly(fdinfoCap);
    ASSERT_TRUE(activated.HasValue());
    ReadableFile readable = std::move(activated).Value();
    const std::size_t pins = path.RetainedDescriptors();
    ASSERT_GT(pins, 1U);
    EXPECT_CALL(context, CloseFileDescriptor(_)).Times(pins - 1).WillRepeatedly([](int fd) { return ::close(fd); });
    EXPECT_TRUE(path.Close().HasValue());
    EXPECT_TRUE(path.Close().HasValue());
    EXPECT_EQ(0U, path.Size());
    EXPECT_EQ(1U, path.RetainedDescriptors()); // the popped handle belongs to the caller
    ASSERT_TRUE(testing::Mock::VerifyAndClearExpectations(&context));
    EXPECT_TRUE(leaf.Stat(fdinfoCap).HasValue());
    EXPECT_CALL(context, CloseFileDescriptor(_)).Times(1).WillOnce([](int fd) { return ::close(fd); });
    EXPECT_TRUE(leaf.Close().HasValue());
    EXPECT_EQ(EBADF, leaf.OpenReadOnly(fdinfoCap).Error().code);
    EXPECT_EQ(0U, path.RetainedDescriptors());
    EXPECT_EQ(0U, path.RetainedBytes());
    EXPECT_EQ(EINVAL, path.Push("other", ExtensionPolicy{SymlinkPolicy::Reject, MountPolicy::AllowCrossing, HardlinkPolicy::Permit}).Error().code);
    EXPECT_EQ(EINVAL, path.Pop().Error().code);
    EXPECT_EQ(EINVAL, path.ObserveChild("other", fdinfoCap).Error().code);
    EXPECT_THROW(path.Root(), std::logic_error);
    EXPECT_THROW(path.Leaf(), std::logic_error);
    ASSERT_TRUE(testing::Mock::VerifyAndClearExpectations(&context));
    auto metadata = readable.Stat();
    ASSERT_TRUE(metadata.HasValue());
    EXPECT_EQ(3, metadata.Value().st_size);
    auto chunk = readable.Read(8, interruptRetriesRemaining);
    ASSERT_TRUE(chunk.HasValue());
    ASSERT_TRUE(chunk.Value().HasValue());
    EXPECT_EQ(std::string("a\0b", 3), chunk.Value().Value());
    EXPECT_TRUE(readable.Close().HasValue());
}

TEST_F(ReadableFileTest, RejectsDirectoryInvalidCapAndPinInspectionFailureWithoutLeaks)
{
    const std::size_t before = OpenDescriptors();
    {
        const ResolverLimits limits{{4096, 100, 100000, 256, 262144, fdinfoCap}, 4096, 8, 128};
        auto directory = Path::AcquireRoot(context, context.GetTempdirPath(), RootPolicy{SymlinkPolicy::Reject, MountPolicy::AllowCrossing}, limits);
        ASSERT_TRUE(directory.HasValue());
        auto wrongType = directory.Value().Leaf().OpenReadOnly(fdinfoCap);
        ASSERT_FALSE(wrongType.HasValue());
        EXPECT_EQ(EINVAL, wrongType.Error().code);
        const std::string source = context.MakeTempfile("x");
        auto pinned = Pin(Component(source));
        ASSERT_TRUE(pinned.HasValue());
        auto invalidCap = pinned.Value().OpenReadOnly(0);
        ASSERT_FALSE(invalidCap.HasValue());
        EXPECT_EQ(EINVAL, invalidCap.Error().code);
        auto shortCap = pinned.Value().OpenReadOnly(1);
        ASSERT_FALSE(shortCap.HasValue());
        EXPECT_EQ(E2BIG, shortCap.Error().code);
        EXPECT_CALL(context, StatFileDescriptor(_, _)).Times(1).WillOnce([](int, struct stat*) {
            errno = EIO;
            return -1;
        });
        auto failed = pinned.Value().OpenReadOnly(fdinfoCap);
        ASSERT_FALSE(failed.HasValue());
        EXPECT_EQ(EIO, failed.Error().code);
    }
    EXPECT_EQ(before, OpenDescriptors());
}

TEST_F(ReadableFileTest, CloseFailureIsReportedOnceAndDoesNotCloseReusedDescriptor)
{
    const std::string source = context.MakeTempfile("x");
    auto pinned = Pin(Component(source));
    ASSERT_TRUE(pinned.HasValue());
    auto activated = pinned.Value().OpenReadOnly(fdinfoCap);
    ASSERT_TRUE(activated.HasValue());
    pinned = ComplianceEngine::Error("Release pin", EINVAL);
    int reused = -1;
    {
        ReadableFile readable = std::move(activated).Value();
        EXPECT_CALL(context, CloseFileDescriptor(_)).Times(1).WillOnce([&](int descriptor) {
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
            return -1;
        });
        auto first = readable.Close();
        ASSERT_FALSE(first.HasValue());
        EXPECT_EQ(EIO, first.Error().code);
        auto again = readable.Close();
        EXPECT_TRUE(again.HasValue());
        EXPECT_EQ(EBADF, readable.Stat().Error().code);
    }
    ASSERT_GE(reused, 0);
    EXPECT_GE(::fcntl(reused, F_GETFD), 0);
    EXPECT_EQ(0, ::close(reused));
}

TEST_F(ReadableFileTest, FailedCloseTransfersNoErrorThroughMoveConstructionOrAssignment)
{
    const std::string source = context.MakeTempfile("x");
    auto pinned = Pin(Component(source));
    ASSERT_TRUE(pinned.HasValue());
    auto first = pinned.Value().OpenReadOnly(fdinfoCap);
    auto second = pinned.Value().OpenReadOnly(fdinfoCap);
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
                return -1;
            })
            .WillOnce([](int descriptor) { return ::close(descriptor); });
        auto closed = failed.Close();
        ASSERT_FALSE(closed.HasValue());
        EXPECT_EQ(EIO, closed.Error().code);
        ReadableFile moved(std::move(failed));
        EXPECT_TRUE(failed.Close().HasValue());
        EXPECT_TRUE(moved.Close().HasValue());

        ReadableFile live = std::move(second).Value();
        live = std::move(moved);
        EXPECT_TRUE(moved.Close().HasValue());
        EXPECT_TRUE(live.Close().HasValue());
    }
    EXPECT_EQ(before - 2, OpenDescriptors());
}

TEST_F(ReadableFileTest, ThrowingNativeCloseReportsEioOnceAndDoesNotRetry)
{
    const std::string source = context.MakeTempfile("x");
    auto pinned = Pin(Component(source));
    ASSERT_TRUE(pinned.HasValue());
    auto activated = pinned.Value().OpenReadOnly(fdinfoCap);
    ASSERT_TRUE(activated.HasValue());
    pinned = ComplianceEngine::Error("Release pin", EINVAL);
    {
        ReadableFile readable = std::move(activated).Value();
        EXPECT_CALL(context, CloseFileDescriptor(_)).Times(1).WillOnce([](int descriptor) -> int {
            EXPECT_EQ(0, ::close(descriptor));
            throw std::runtime_error("native close fault");
        });
        auto first = readable.Close();
        ASSERT_FALSE(first.HasValue());
        EXPECT_EQ(EIO, first.Error().code);
        EXPECT_TRUE(readable.Close().HasValue());
        EXPECT_EQ(EBADF, readable.Stat().Error().code);
    }
}

TEST_F(ReadableFileTest, DestructorContainsThrowingLogAfterFailedNativeClose)
{
    ThrowingLogContext selectedContext;
    const std::string source = selectedContext.MakeTempfile("x");
    const auto before = OpenDescriptors();
    {
        auto pinned = Pin(selectedContext, Component(source));
        ASSERT_TRUE(pinned.HasValue());
        auto activated = pinned.Value().OpenReadOnly(fdinfoCap);
        ASSERT_TRUE(activated.HasValue());
        pinned = ComplianceEngine::Error("Release pin", EINVAL);
        testing::internal::CaptureStderr();
        {
            ReadableFile readable = std::move(activated).Value();
            EXPECT_CALL(selectedContext, CloseFileDescriptor(_)).Times(1).WillOnce([](int descriptor) {
                EXPECT_EQ(0, ::close(descriptor));
                errno = EACCES;
                return -1;
            });
        }
        const auto logged = testing::internal::GetCapturedStderr();
        if (IsConsoleLoggingEnabled() && GetLoggingLevel() >= LoggingLevelError)
        {
            EXPECT_NE(std::string::npos, logged.find("Filesystem descriptor close or log failure: " + std::to_string(EACCES)));
        }
        EXPECT_EQ(1, selectedContext.logHandleRequests);
        EXPECT_TRUE(testing::Mock::VerifyAndClearExpectations(&selectedContext));
    }
    EXPECT_EQ(before, OpenDescriptors());
}

TEST_F(ReadableFileTest, MoveAssignmentContainsThrowingLogAndRetainsIncomingOwnership)
{
    ThrowingLogContext selectedContext;
    const std::string oldSource = selectedContext.MakeTempfile("old");
    const std::string newSource = selectedContext.MakeTempfile("new");
    const auto before = OpenDescriptors();
    {
        auto oldPin = Pin(selectedContext, Component(oldSource));
        auto newPin = Pin(selectedContext, Component(newSource));
        ASSERT_TRUE(oldPin.HasValue());
        ASSERT_TRUE(newPin.HasValue());
        auto oldOpened = oldPin.Value().OpenReadOnly(fdinfoCap);
        auto newOpened = newPin.Value().OpenReadOnly(fdinfoCap);
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
                    return -1;
                })
                .WillOnce([](int descriptor) {
                    const int result = ::close(descriptor);
                    EXPECT_EQ(0, result);
                    return result;
                });
            testing::internal::CaptureStderr();
            destination = std::move(source);
            const auto logged = testing::internal::GetCapturedStderr();
            if (IsConsoleLoggingEnabled() && GetLoggingLevel() >= LoggingLevelError)
            {
                EXPECT_NE(std::string::npos, logged.find("Filesystem descriptor close or log failure: " + std::to_string(EIO)));
            }
            EXPECT_EQ(1, selectedContext.logHandleRequests);
            EXPECT_EQ(EBADF, source.Stat().Error().code);
            EXPECT_TRUE(source.Close().HasValue());
            EXPECT_TRUE(destination.Stat().HasValue());
            auto bytes = destination.Read(3, interruptRetriesRemaining);
            ASSERT_TRUE(bytes.HasValue());
            ASSERT_TRUE(bytes.Value().HasValue());
            EXPECT_EQ("new", bytes.Value().Value());
            EXPECT_TRUE(destination.Close().HasValue());
            EXPECT_TRUE(destination.Close().HasValue());
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
        auto first = pinned.Value().OpenReadOnly(fdinfoCap);
        auto second = pinned.Value().OpenReadOnly(fdinfoCap);
        ASSERT_TRUE(first.HasValue());
        ASSERT_TRUE(second.HasValue());
        pinned = ComplianceEngine::Error("Release pin", EINVAL);
        ReadableFile readable = std::move(first).Value();
        ReadableFile moved = std::move(second).Value();
        EXPECT_CALL(context, CloseFileDescriptor(_))
            .Times(2)
            .WillOnce([](int descriptor) {
                const int result = ::close(descriptor);
                EXPECT_EQ(0, result);
                errno = EIO; // destructor of replaced ownership sees failed close
                return -1;
            })
            .WillOnce([](int descriptor) { return ::close(descriptor); });
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
    auto first = pinned.Value().OpenReadOnly(fdinfoCap);
    auto second = pinned.Value().OpenReadOnly(fdinfoCap);
    ASSERT_TRUE(first.HasValue());
    ASSERT_TRUE(second.HasValue());
    pinned = ComplianceEngine::Error("Release pin", EINVAL);
    const std::size_t before = OpenDescriptors();

    ReadableFile original = std::move(first).Value();
    ReadableFile moved(std::move(original));
    EXPECT_EQ(EBADF, original.Read(1, interruptRetriesRemaining).Error().code);
    EXPECT_EQ(EBADF, original.Stat().Error().code);
    EXPECT_TRUE(original.Close().HasValue());
    EXPECT_TRUE(moved.Stat().HasValue());

    ReadableFile incoming = std::move(second).Value();
    EXPECT_CALL(context, CloseFileDescriptor(_)).Times(2).WillRepeatedly([](int descriptor) { return ::close(descriptor); });
    ReadableFile& self = moved;
    moved = std::move(self);
    EXPECT_TRUE(moved.Stat().HasValue());
    moved = std::move(incoming);
    EXPECT_EQ(EBADF, incoming.Read(1, interruptRetriesRemaining).Error().code);
    EXPECT_EQ(EBADF, incoming.Stat().Error().code);
    EXPECT_TRUE(incoming.Close().HasValue());
    auto read = moved.Read(1, interruptRetriesRemaining);
    ASSERT_TRUE(read.HasValue());
    ASSERT_TRUE(read.Value().HasValue());
    EXPECT_EQ("x", read.Value().Value());
    EXPECT_TRUE(moved.Close().HasValue());
    EXPECT_TRUE(moved.Close().HasValue());
    EXPECT_EQ(before - 2, OpenDescriptors());
}

TEST_F(ReadableFileTest, CrossContextMoveAssignmentClosesOldOwnerAndRoutesIncomingOperations)
{
    NiceMock<MockContext> foreignContext;
    const std::string oldPath = context.MakeTempfile("old");
    const std::string newPath = foreignContext.MakeTempfile("new");
    auto pinned = Pin(Component(oldPath));
    auto foreignPin = Pin(foreignContext, Component(newPath));
    ASSERT_TRUE(pinned.HasValue());
    ASSERT_TRUE(foreignPin.HasValue());
    auto activated = pinned.Value().OpenReadOnly(fdinfoCap);
    auto foreignActivated = foreignPin.Value().OpenReadOnly(fdinfoCap);
    ASSERT_TRUE(activated.HasValue());
    ASSERT_TRUE(foreignActivated.HasValue());
    pinned = ComplianceEngine::Error("Release pin", EINVAL);
    foreignPin = ComplianceEngine::Error("Release pin", EINVAL);
    const std::size_t before = OpenDescriptors();

    ReadableFile destination = std::move(activated).Value();
    ReadableFile source = std::move(foreignActivated).Value();
    int oldDescriptor = -1;
    int incomingDescriptor = -1;
    EXPECT_CALL(context, CloseFileDescriptor(_)).Times(1).WillOnce([&](int descriptor) {
        oldDescriptor = descriptor;
        return ::close(descriptor);
    });
    EXPECT_CALL(foreignContext, CloseFileDescriptor(_)).Times(1).WillOnce([&](int descriptor) {
        EXPECT_EQ(incomingDescriptor, descriptor);
        return ::close(descriptor);
    });
    EXPECT_CALL(context, StatFileDescriptor(_, _)).Times(0);
    EXPECT_CALL(context, ReadFileDescriptor(_, _, _)).Times(0);
    EXPECT_CALL(foreignContext, StatFileDescriptor(_, _)).Times(1).WillOnce([&](int descriptor, struct stat* metadata) {
        incomingDescriptor = descriptor;
        return foreignContext.ContextInterface::StatFileDescriptor(descriptor, metadata);
    });
    EXPECT_CALL(foreignContext, ReadFileDescriptor(_, _, _)).Times(1).WillOnce([&](int descriptor, void* buffer, std::size_t size) {
        EXPECT_EQ(incomingDescriptor, descriptor);
        return foreignContext.ContextInterface::ReadFileDescriptor(descriptor, buffer, size);
    });

    destination = std::move(source);
    ASSERT_GE(oldDescriptor, 0);
    EXPECT_EQ(-1, ::fcntl(oldDescriptor, F_GETFD));
    EXPECT_EQ(EBADF, errno);
    EXPECT_EQ(EBADF, source.Read(1, interruptRetriesRemaining).Error().code);
    EXPECT_EQ(EBADF, source.Stat().Error().code);
    EXPECT_TRUE(source.Close().HasValue());
    EXPECT_TRUE(destination.Stat().HasValue());
    ASSERT_GE(incomingDescriptor, 0);
    EXPECT_NE(oldDescriptor, incomingDescriptor);
    EXPECT_GE(::fcntl(incomingDescriptor, F_GETFD), 0);
    auto bytes = destination.Read(3, interruptRetriesRemaining);
    ASSERT_TRUE(bytes.HasValue());
    ASSERT_TRUE(bytes.Value().HasValue());
    EXPECT_EQ("new", bytes.Value().Value());
    EXPECT_TRUE(destination.Close().HasValue());
    EXPECT_TRUE(destination.Close().HasValue());
    EXPECT_EQ(-1, ::fcntl(incomingDescriptor, F_GETFD));
    EXPECT_EQ(EBADF, errno);
    EXPECT_TRUE(testing::Mock::VerifyAndClearExpectations(&context));
    EXPECT_TRUE(testing::Mock::VerifyAndClearExpectations(&foreignContext));
    EXPECT_EQ(before - 2, OpenDescriptors());
}

TEST_F(ReadableFileTest, CrossContextMoveReplacementContainsOldOwnerLoggingFault)
{
    ThrowingLogContext oldContext;
    NiceMock<MockContext> newContext;
    const std::string oldPath = oldContext.MakeTempfile("old");
    const std::string newPath = newContext.MakeTempfile("new");
    auto oldPin = Pin(oldContext, Component(oldPath));
    auto newPin = Pin(newContext, Component(newPath));
    ASSERT_TRUE(oldPin.HasValue());
    ASSERT_TRUE(newPin.HasValue());
    auto oldOpened = oldPin.Value().OpenReadOnly(fdinfoCap);
    auto newOpened = newPin.Value().OpenReadOnly(fdinfoCap);
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
        return -1;
    });
    EXPECT_CALL(newContext, CloseFileDescriptor(_)).Times(1).WillOnce([](int descriptor) { return ::close(descriptor); });
    destination = std::move(source);
    EXPECT_EQ(1, oldContext.logHandleRequests);
    EXPECT_FALSE(source.AtEnd());
    EXPECT_EQ(EBADF, source.Stat().Error().code);
    auto bytes = destination.Read(3, interruptRetriesRemaining);
    ASSERT_TRUE(bytes.HasValue());
    ASSERT_TRUE(bytes.Value().HasValue());
    EXPECT_EQ("new", bytes.Value().Value());
    EXPECT_TRUE(destination.Close().HasValue());
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
    auto activated = pinned.Value().OpenReadOnly(fdinfoCap);
    auto foreignActivated = foreignPin.Value().OpenReadOnly(fdinfoCap);
    ASSERT_TRUE(activated.HasValue());
    ASSERT_TRUE(foreignActivated.HasValue());
    pinned = ComplianceEngine::Error("Release pin", EINVAL);
    foreignPin = ComplianceEngine::Error("Release pin", EINVAL);
    const std::size_t before = OpenDescriptors();

    ReadableFile destination = std::move(activated).Value();
    ReadableFile source = std::move(foreignActivated).Value();
    auto bytes = source.Read(2, interruptRetriesRemaining);
    ASSERT_TRUE(bytes.HasValue());
    ASSERT_TRUE(bytes.Value().HasValue());
    EXPECT_EQ("b", bytes.Value().Value());
    EXPECT_TRUE(source.AtEnd());
    EXPECT_CALL(context, CloseFileDescriptor(_)).Times(1).WillOnce([](int descriptor) { return ::close(descriptor); });
    EXPECT_CALL(foreignContext, CloseFileDescriptor(_)).Times(1).WillOnce([](int descriptor) { return ::close(descriptor); });
    EXPECT_TRUE(destination.Close().HasValue());
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
    auto eof = destination.Read(1, interruptRetriesRemaining);
    ASSERT_TRUE(eof.HasValue());
    EXPECT_FALSE(eof.Value().HasValue());
    ReadableFile& self = destination;
    destination = std::move(self);
    EXPECT_TRUE(destination.AtEnd());
    EXPECT_TRUE(destination.Close().HasValue());
    EXPECT_FALSE(destination.AtEnd());

    source = std::move(closedOld);      // moved-from foreign destination, closed original-context source
    closedOld = std::move(destination); // moved-from original destination, closed foreign source
    destination = std::move(source);    // both closed, across their bound contexts
    EXPECT_EQ(EBADF, source.Stat().Error().code);
    EXPECT_EQ(EBADF, closedOld.Stat().Error().code);
    EXPECT_EQ(EBADF, destination.Stat().Error().code);
    EXPECT_TRUE(source.Close().HasValue());
    EXPECT_TRUE(closedOld.Close().HasValue());
    EXPECT_TRUE(destination.Close().HasValue());
    EXPECT_TRUE(testing::Mock::VerifyAndClearExpectations(&context));
    EXPECT_TRUE(testing::Mock::VerifyAndClearExpectations(&foreignContext));
    EXPECT_EQ(before - 2, OpenDescriptors());
}
