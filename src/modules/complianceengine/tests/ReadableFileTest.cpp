// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <MockContext.h>
#include <cerrno>
#include <dirent.h>
#include <fcntl.h>
#include <filesystem/Handle.hpp>
#include <filesystem/Path.hpp>
#include <gtest/gtest.h>
#include <limits>
#include <linux/magic.h>
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

class ReadableFileTest : public testing::Test
{
protected:
    NiceMock<MockContext> context;
    static constexpr std::size_t fdinfoCap = 4096;

    ComplianceEngine::Result<Handle> Pin(const std::string& component)
    {
        const ResolverLimits limits{{4096, 100, 100000, 256, 262144, fdinfoCap}, 4096, 8, 128};
        auto root = Path::AcquireRoot(context, context.GetTempdirPath(), RootPolicy{SymlinkPolicy::Reject, MountPolicy::AllowCrossing}, limits);
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

    std::string Component(const std::string& path) const
    {
        return path.substr(path.find_last_of('/') + 1);
    }
};
} // namespace

TEST_F(ReadableFileTest, IsOpaqueAndMoveOnly)
{
    static_assert(!std::is_default_constructible<ReadableFile>::value, "Cannot fabricate readable ownership");
    static_assert(!std::is_constructible<ReadableFile, int>::value, "No raw descriptor constructor");
    static_assert(!std::is_copy_constructible<ReadableFile>::value, "No duplicated ownership");
    static_assert(std::is_move_constructible<ReadableFile>::value, "Transfer ownership");
    static_assert(std::is_move_assignable<ReadableFile>::value, "Transfer ownership");
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
    const ino_t inode = pinned.Value().Snapshot().st_ino;
    auto pinnedBefore = pinned.Value().Inspect(fdinfoCap);
    ASSERT_TRUE(pinnedBefore.HasValue());
    EXPECT_EQ(inode, pinnedBefore.Value().st_ino);
    ASSERT_EQ(0, ::rename(original.c_str(), (original + ".old").c_str()));
    ASSERT_EQ(0, ::symlink("/dev/zero", original.c_str()));
    auto activated = pinned.Value().OpenReadOnly(fdinfoCap);
    ASSERT_TRUE(activated.HasValue()) << activated.Error().message;
    ReadableFile readable = std::move(activated).Value();
    pinned = ComplianceEngine::Error("Release pin", EINVAL);
    auto before = readable.Inspect();
    ASSERT_TRUE(before.HasValue());
    EXPECT_EQ(inode, before.Value().st_ino);
    EXPECT_TRUE(S_ISREG(before.Value().st_mode));
    auto read = readable.Read(8);
    ASSERT_TRUE(read.HasValue());
    EXPECT_EQ("first", read.Value());
    auto eof = readable.Read(8);
    ASSERT_TRUE(eof.HasValue());
    EXPECT_TRUE(eof.Value().empty());
    auto after = readable.Inspect();
    ASSERT_TRUE(after.HasValue());
    EXPECT_EQ(before.Value().st_ino, after.Value().st_ino);
    EXPECT_EQ(before.Value().st_size, after.Value().st_size);
    EXPECT_CALL(context, CloseFileDescriptor(_)).Times(1).WillOnce([](int descriptor) { return ::close(descriptor); });
    EXPECT_TRUE(readable.Close().HasValue());
    EXPECT_TRUE(readable.Close().HasValue());
    EXPECT_EQ(EBADF, readable.Read(1).Error().code);
    EXPECT_EQ(EBADF, readable.Inspect().Error().code);
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
    EXPECT_CALL(context, ReadFileDescriptor(_, _, 1)).Times(1);
    auto first = readable.Read(2);
    ASSERT_TRUE(first.HasValue());
    EXPECT_EQ(payload.substr(0, 2), first.Value());
    auto second = readable.Read(8);
    ASSERT_TRUE(second.HasValue());
    EXPECT_EQ(payload.substr(2), second.Value());
    EXPECT_EQ(payload.substr(0, 2), first.Value()); // earlier owned chunk is unchanged
    auto eof = readable.Read(1);
    ASSERT_TRUE(eof.HasValue());
    EXPECT_TRUE(eof.Value().empty());
}

TEST_F(ReadableFileTest, PreservesReadAndInspectErrnosWithoutRetriesOrFalseEof)
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
    auto inspection = readable.Inspect();
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
    EXPECT_EQ("x", next.Value());
}

TEST_F(ReadableFileTest, EmptyFilePositiveReadReturnsEof)
{
    const std::string source = context.MakeTempfile("");
    auto pinned = Pin(Component(source));
    ASSERT_TRUE(pinned.HasValue());
    auto activated = pinned.Value().OpenReadOnly(fdinfoCap);
    ASSERT_TRUE(activated.HasValue());
    ReadableFile readable = std::move(activated).Value();
    auto metadata = readable.Inspect();
    ASSERT_TRUE(metadata.HasValue());
    EXPECT_EQ(0, metadata.Value().st_size);
    auto end = readable.Read(1);
    ASSERT_TRUE(end.HasValue());
    EXPECT_TRUE(end.Value().empty());
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
    EXPECT_TRUE(leaf.Inspect(fdinfoCap).HasValue());
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
    auto metadata = readable.Inspect();
    ASSERT_TRUE(metadata.HasValue());
    EXPECT_EQ(3, metadata.Value().st_size);
    auto chunk = readable.Read(8);
    ASSERT_TRUE(chunk.HasValue());
    EXPECT_EQ(std::string("a\0b", 3), chunk.Value());
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

TEST_F(ReadableFileTest, CloseFailureIsStableAndDoesNotCloseReusedDescriptor)
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
        ASSERT_FALSE(again.HasValue());
        EXPECT_EQ(EIO, again.Error().code);
        EXPECT_EQ(EBADF, readable.Inspect().Error().code);
    }
    ASSERT_GE(reused, 0);
    EXPECT_GE(::fcntl(reused, F_GETFD), 0);
    EXPECT_EQ(0, ::close(reused));
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
        EXPECT_EQ(EBADF, moved.Inspect().Error().code);
    }
    EXPECT_EQ(before, OpenDescriptors());
}
