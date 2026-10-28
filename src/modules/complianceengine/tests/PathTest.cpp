// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <MockContext.h>
#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <filesystem/Handle.hpp>
#include <filesystem/Path.hpp>
#include <filesystem/PathInternal.hpp>
#include <filesystem/ReadableFile.hpp>
#include <fstream>
#include <gtest/gtest.h>
#include <iterator>
#include <linux/magic.h>
#include <sched.h>
#include <set>
#include <stdexcept>
#include <string>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <type_traits>
#include <unistd.h>
#include <utility>

using ComplianceEngine::Filesystem::ExtensionPolicy;
using ComplianceEngine::Filesystem::Handle;
using ComplianceEngine::Filesystem::HardlinkPolicy;
using ComplianceEngine::Filesystem::Path;
using ComplianceEngine::Filesystem::RootPolicy;
using ComplianceEngine::Filesystem::SymlinkPolicy;
using ComplianceEngine::Filesystem::Detail::IsSingleChildComponent;
using ComplianceEngine::Filesystem::Detail::MountPolicy;
using ComplianceEngine::Filesystem::Detail::ParseMountId;
using ComplianceEngine::Filesystem::Detail::ReadPinnedLink;
using ComplianceEngine::Filesystem::Detail::ResolverLimits;
using ComplianceEngine::Filesystem::Detail::ScopedDescriptor;
using testing::_;
using testing::NiceMock;

namespace
{
class OwnedTestDescriptor
{
public:
    explicit OwnedTestDescriptor(int descriptor)
        : mDescriptor(descriptor)
    {
    }
    ~OwnedTestDescriptor()
    {
        if (0 <= mDescriptor)
        {
            ::close(mDescriptor);
        }
    }
    int Get() const
    {
        return mDescriptor;
    }

private:
    const int mDescriptor;
};

std::size_t CountOpenDescriptors()
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

class PathAliasTest : public testing::Test
{
protected:
    NiceMock<MockContext> context;

    static ResolverLimits AmpleLimits()
    {
        return ResolverLimits{{4096, 100, 100000, 256, 262144, 4096}, 4096, 8, 128};
    }
};
std::string DescriptorTarget(int descriptor)
{
    const std::string alias = "/proc/self/fd/" + std::to_string(descriptor);
    char target[512] = {};
    const ssize_t length = ::readlink(alias.c_str(), target, sizeof(target));
    return (0 < length) ? std::string(target, static_cast<std::size_t>(length)) : std::string();
}
bool IsProcfsHelper(int descriptor)
{
    struct statfs filesystem = {};
    return (0 == ::fstatfs(descriptor, &filesystem)) && (PROC_SUPER_MAGIC == filesystem.f_type);
}

// Only constructed in the forked, private mount namespace. Unmount before
// MockContext removes its unique fixture directory.
class ScopedBindMount
{
public:
    explicit ScopedBindMount(std::string target)
        : mTarget(std::move(target))
    {
    }
    ~ScopedBindMount()
    {
        if (mMounted)
        {
            EXPECT_EQ(0, ::umount(mTarget.c_str())) << mTarget << ": " << std::strerror(errno);
        }
    }
    bool Bind(const std::string& source)
    {
        if (0 != ::mount(source.c_str(), mTarget.c_str(), nullptr, MS_BIND, nullptr))
        {
            return false;
        }
        mMounted = true;
        return true;
    }

private:
    std::string mTarget;
    bool mMounted = false;
};

// Reserved for unavailable namespace/mount capability during optional local
// runs. CI explicitly requires this test and treats this status as a failure.
const int unavailableMountCapability = 77;

int MountSetupFailure(const char* operation)
{
    const int error = errno;
    std::fprintf(stderr, "%s: %s (%d)\n", operation, std::strerror(error), error);
    if ((EPERM == error) || (EACCES == error))
    {
        return unavailableMountCapability;
    }
    return 1;
}

ComplianceEngine::Result<std::uint64_t> KernelMountId(int descriptor)
{
    std::ifstream info("/proc/self/fdinfo/" + std::to_string(descriptor));
    if (!info.is_open())
    {
        return ComplianceEngine::Error("Cannot open kernel fdinfo", errno);
    }
    const std::string contents(std::istreambuf_iterator<char>{info}, std::istreambuf_iterator<char>{});
    if (info.bad())
    {
        return ComplianceEngine::Error("Cannot read kernel fdinfo", EIO);
    }
    return ParseMountId(contents);
}

void CheckRealBindMounts(const NiceMock<MockContext>& context, const std::string& accepted)
{
    const ResolverLimits limits{{4096, 100, 100000, 256, 262144, 4096}, 4096, 8, 128};
    // Authorize the selected root mount separately; only descendants stay.
    auto opened = Path::AcquireRoot(context, accepted, RootPolicy{SymlinkPolicy::Reject, MountPolicy::AllowCrossing}, limits);
    ASSERT_TRUE(opened.HasValue()) << opened.Error().message;
    Path path = std::move(opened).Value();

    const std::string crossing = accepted + "/cross";
    OwnedTestDescriptor outer(::open(context.GetTempdirPath().c_str(), O_PATH | O_DIRECTORY | O_CLOEXEC));
    OwnedTestDescriptor root(::open(accepted.c_str(), O_PATH | O_DIRECTORY | O_CLOEXEC));
    OwnedTestDescriptor child(::open(crossing.c_str(), O_PATH | O_DIRECTORY | O_CLOEXEC));
    ASSERT_GE(outer.Get(), 0);
    ASSERT_GE(root.Get(), 0);
    ASSERT_GE(child.Get(), 0);
    struct stat rootStat = {}, childStat = {};
    ASSERT_EQ(0, ::fstat(root.Get(), &rootStat));
    ASSERT_EQ(0, ::fstat(child.Get(), &childStat));
    EXPECT_EQ(rootStat.st_dev, childStat.st_dev);
    auto outerId = KernelMountId(outer.Get());
    auto rootId = KernelMountId(root.Get());
    auto childId = KernelMountId(child.Get());
    ASSERT_TRUE(outerId.HasValue()) << outerId.Error().message;
    ASSERT_TRUE(rootId.HasValue()) << rootId.Error().message;
    ASSERT_TRUE(childId.HasValue()) << childId.Error().message;
    EXPECT_NE(outerId.Value(), rootId.Value()); // The accepted root is itself a mount.
    EXPECT_NE(rootId.Value(), childId.Value()); // Bind mounts can share st_dev.
    auto pinnedRootId = path.Root().MountIdentity(limits.shared.fdinfoBytes);
    ASSERT_TRUE(pinnedRootId.HasValue()) << pinnedRootId.Error().message;
    EXPECT_EQ(rootId.Value(), pinnedRootId.Value());

    const ExtensionPolicy stay{SymlinkPolicy::Reject, MountPolicy::StayOnRootMount, HardlinkPolicy::Permit};
    const ExtensionPolicy allow{SymlinkPolicy::Reject, MountPolicy::AllowCrossing, HardlinkPolicy::Permit};
    auto inside = path.Push("inside", stay);
    ASSERT_TRUE(inside.HasValue()) << inside.Error().message;
    ASSERT_TRUE(path.Pop().HasValue());
    auto denied = path.Push("cross", stay);
    ASSERT_FALSE(denied.HasValue());
    EXPECT_EQ(EXDEV, denied.Error().code);
    EXPECT_EQ("Component crosses accepted root mount", denied.Error().message);
    EXPECT_EQ(1U, path.Size());
    auto allowed = path.Push("cross", allow);
    ASSERT_TRUE(allowed.HasValue()) << allowed.Error().message;
    auto pinnedChildId = path.Leaf().MountIdentity(limits.shared.fdinfoBytes);
    ASSERT_TRUE(pinnedChildId.HasValue()) << pinnedChildId.Error().message;
    EXPECT_EQ(childId.Value(), pinnedChildId.Value());
    auto file = path.Push("payload", allow);
    ASSERT_TRUE(file.HasValue()) << file.Error().message;
    auto readable = path.Leaf().OpenReadOnly(limits.shared.fdinfoBytes);
    ASSERT_TRUE(readable.HasValue()) << readable.Error().message;
    std::size_t remainingInterruptRetries = 1;
    auto data = readable.Value().Read(32, remainingInterruptRetries);
    ASSERT_TRUE(data.HasValue()) << data.Error().message;
    ASSERT_TRUE(data.Value().HasValue());
    EXPECT_EQ("bound", data.Value().Value());
}

int RunIsolatedBindMountRegression()
{
    if (0 != ::unshare(CLONE_NEWNS))
    {
        return MountSetupFailure("unshare(CLONE_NEWNS)");
    }
    // This must precede all fixture mounts: inherited shared propagation
    // must not send child-namespace mounts back to the parent or host.
    if (0 != ::mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr))
    {
        return MountSetupFailure("make child mount propagation private");
    }

    NiceMock<MockContext> context;
    const std::string base = context.GetTempdirPath();
    const std::string source = base + "/source";
    const std::string accepted = base + "/accepted";
    const std::string other = base + "/other";
    if ((0 != ::mkdir(source.c_str(), 0700)) || (0 != ::mkdir(accepted.c_str(), 0700)) || (0 != ::mkdir(other.c_str(), 0700)) ||
        (0 != ::mkdir((source + "/cross").c_str(), 0700)))
    {
        ADD_FAILURE() << "Cannot create isolated fixture: " << std::strerror(errno);
        return 1;
    }
    {
        std::ofstream inside(source + "/inside");
        std::ofstream payload(other + "/payload");
        inside << "inside";
        payload << "bound";
        inside.close();
        payload.close();
        if (!inside || !payload)
        {
            ADD_FAILURE() << "Cannot write isolated fixture files";
            return 1;
        }
    }
    ScopedBindMount root(accepted);
    if (!root.Bind(source))
    {
        return MountSetupFailure("bind accepted root");
    }
    ScopedBindMount crossing(accepted + "/cross");
    if (!crossing.Bind(other))
    {
        return MountSetupFailure("bind descendant");
    }
    CheckRealBindMounts(context, accepted);
    return 0;
}
} // namespace

TEST_F(PathAliasTest, ProcessRootNativeOpenFailureAndThrowDoNotEscapeOrLeak)
{
    const auto before = CountOpenDescriptors();
    EXPECT_CALL(context, OpenNativePath(testing::StrEq("/"), _)).WillOnce([](const char*, int) {
        errno = EACCES;
        return -1;
    });
    auto denied = Path::AcquireRoot(context, "/", RootPolicy{SymlinkPolicy::Reject, MountPolicy::AllowCrossing}, AmpleLimits());
    ASSERT_FALSE(denied.HasValue());
    EXPECT_EQ(EACCES, denied.Error().code);
    ASSERT_TRUE(testing::Mock::VerifyAndClearExpectations(&context));
    EXPECT_CALL(context, OpenNativePath(testing::StrEq("/"), _)).WillOnce([](const char*, int) -> int { throw std::runtime_error("native open fault"); });
    EXPECT_THROW((void)Path::AcquireRoot(context, "/", RootPolicy{SymlinkPolicy::Reject, MountPolicy::AllowCrossing}, AmpleLimits()), std::runtime_error);
    EXPECT_EQ(before, CountOpenDescriptors());
}

TEST_F(PathAliasTest, ConfinedChildNativeOpenFailureDoesNotReopenTargetName)
{
    const std::string root = context.GetTempdirPath();
    const std::string source = context.MakeTempfile("held");
    const std::string name = source.substr(source.find_last_of('/') + 1);
    auto opened = Path::AcquireRoot(context, root, RootPolicy{SymlinkPolicy::Reject, MountPolicy::AllowCrossing}, AmpleLimits());
    ASSERT_TRUE(opened.HasValue());
    Path path = std::move(opened).Value();
    const auto before = CountOpenDescriptors();
    EXPECT_CALL(context, OpenNativePath(_, _)).WillRepeatedly([&](const char* path, int flags) {
        return context.ContextInterface::OpenNativePath(path, flags);
    });
    EXPECT_CALL(context, OpenNativePath(testing::StrEq(source.c_str()), _)).Times(0);
    EXPECT_CALL(context, OpenExistingFile(testing::StrEq(source.c_str()), _)).Times(0);
    EXPECT_CALL(context, OpenNativeAt(_, _, _)).WillRepeatedly([&](int directory, const char* path, int flags) {
        return context.ContextInterface::OpenNativeAt(directory, path, flags);
    });
    EXPECT_CALL(context, OpenNativeAt(_, testing::StrEq(name.c_str()), _)).WillOnce([](int, const char*, int flags) {
        EXPECT_NE(0, flags & O_PATH);
        errno = ENOENT;
        return -1;
    });
    auto pushed = path.Push(name, ExtensionPolicy{SymlinkPolicy::Reject, MountPolicy::AllowCrossing, HardlinkPolicy::Permit});
    ASSERT_FALSE(pushed.HasValue());
    EXPECT_EQ(ENOENT, pushed.Error().code);
    EXPECT_EQ(before, CountOpenDescriptors());
}

TEST_F(PathAliasTest, ProcfsHelpersCloseCheckedOnceAndFirstFailureWins)
{
    const auto before = CountOpenDescriptors();
    std::size_t failed = 0;
    EXPECT_CALL(context, CloseFileDescriptor(_)).WillRepeatedly([&](int descriptor) {
        const bool helper = IsProcfsHelper(descriptor);
        const int status = ::close(descriptor);
        EXPECT_EQ(0, status);
        if (helper && failed < 2)
        {
            errno = (0 == failed++) ? EACCES : EIO;
            return -1;
        }

        return status;
    });
    auto opened = Path::AcquireRoot(context, "/", RootPolicy{SymlinkPolicy::Reject, MountPolicy::AllowCrossing}, AmpleLimits());
    ASSERT_FALSE(opened.HasValue());
    EXPECT_EQ(EACCES, opened.Error().code);
    EXPECT_EQ(2U, failed);
    EXPECT_EQ(before, CountOpenDescriptors());
}

TEST_F(PathAliasTest, TemporaryCloseFailureIsNotRetriedAfterDescriptorReuse)
{
    const int descriptor = ::open("/proc", O_PATH | O_DIRECTORY | O_CLOEXEC);
    ASSERT_GE(descriptor, 0);
    EXPECT_CALL(context, CloseFileDescriptor(descriptor)).Times(1).WillOnce([](int owned) {
        EXPECT_EQ(0, ::close(owned));
        errno = EIO;
        return -1;
    });
    {
        ScopedDescriptor helper(context, descriptor);
        EXPECT_EQ(EIO, helper.CloseOnce());
        EXPECT_EQ(0, helper.CloseOnce());
    }
}

TEST_F(PathAliasTest, PrimaryFdinfoReadErrorOutranksHelperCloseFailure)
{
    const auto before = CountOpenDescriptors();
    bool failedRead = false, failedClose = false;
    EXPECT_CALL(context, ReadFileDescriptor(_, _, _)).WillRepeatedly([&](int descriptor, void* buffer, std::size_t size) -> ssize_t {
        if (!failedRead && (0 == DescriptorTarget(descriptor).find("/proc/")) && (std::string::npos != DescriptorTarget(descriptor).find("/fdinfo/")))
        {
            failedRead = true;
            errno = ENOSPC;
            return -1;
        }
        return ::read(descriptor, buffer, size);
    });
    EXPECT_CALL(context, CloseFileDescriptor(_)).WillRepeatedly([&](int descriptor) {
        const bool helper = IsProcfsHelper(descriptor);
        const int status = ::close(descriptor);
        EXPECT_EQ(0, status);
        if (helper && failedRead && !failedClose)
        {
            failedClose = true;
            errno = EIO;
            return -1;
        }
        return status;
    });
    auto opened = Path::AcquireRoot(context, "/", RootPolicy{SymlinkPolicy::Reject, MountPolicy::AllowCrossing}, AmpleLimits());
    ASSERT_FALSE(opened.HasValue());
    EXPECT_EQ(ENOSPC, opened.Error().code);
    EXPECT_TRUE(failedRead);
    EXPECT_TRUE(failedClose);
    EXPECT_EQ(before, CountOpenDescriptors());
}

TEST_F(PathAliasTest, InspectionAndChildObservationReportHelperCloseFailure)
{
    const std::string source = context.MakeTempfile("held");
    const std::string name = source.substr(source.find_last_of('/') + 1);
    auto opened = Path::AcquireRoot(context, context.GetTempdirPath(), RootPolicy{SymlinkPolicy::Reject, MountPolicy::AllowCrossing}, AmpleLimits());
    ASSERT_TRUE(opened.HasValue());
    Path path = std::move(opened).Value();
    const auto before = CountOpenDescriptors();
    bool childOpened = false;
    EXPECT_CALL(context, OpenNativeAt(_, _, _)).WillRepeatedly([&](int directory, const char* component, int flags) {
        const int descriptor = context.ContextInterface::OpenNativeAt(directory, component, flags);
        if ((0 <= descriptor) && (name == component) && (0 != (flags & O_PATH)))
        {
            childOpened = true;
        }
        return descriptor;
    });
    bool failed = false;
    EXPECT_CALL(context, CloseFileDescriptor(_)).WillRepeatedly([&](int descriptor) {
        const bool procfs = IsProcfsHelper(descriptor);
        const int status = ::close(descriptor);
        EXPECT_EQ(0, status);
        if (procfs && !failed && childOpened)
        {
            failed = true;
            errno = EACCES;
            return -1;
        }
        return status;
    });
    auto observation = path.ObserveChild(name, 4096);
    ASSERT_FALSE(observation.HasValue());
    EXPECT_EQ(EACCES, observation.Error().code);
    EXPECT_TRUE(childOpened);
    EXPECT_TRUE(failed);
    EXPECT_EQ(before, CountOpenDescriptors());
    ASSERT_TRUE(testing::Mock::VerifyAndClearExpectations(&context));
    failed = false;
    EXPECT_CALL(context, CloseFileDescriptor(_)).WillRepeatedly([&](int descriptor) {
        const bool procfs = IsProcfsHelper(descriptor);
        const int status = ::close(descriptor);
        EXPECT_EQ(0, status);
        if (procfs && !failed)
        {
            failed = true;
            errno = EIO;
            return -1;
        }
        return status;
    });
    auto inspection = path.Root().Stat(4096);
    ASSERT_FALSE(inspection.HasValue());
    EXPECT_EQ(EIO, inspection.Error().code);
    EXPECT_EQ(before, CountOpenDescriptors());
    ASSERT_TRUE(testing::Mock::VerifyAndClearExpectations(&context));
}

TEST_F(PathAliasTest, PrimaryChildStatErrorOutranksItsTemporaryCloseFailure)
{
    const std::string source = context.MakeTempfile("held");
    const std::string name = source.substr(source.find_last_of('/') + 1);
    auto opened = Path::AcquireRoot(context, context.GetTempdirPath(), RootPolicy{SymlinkPolicy::Reject, MountPolicy::AllowCrossing}, AmpleLimits());
    ASSERT_TRUE(opened.HasValue());
    Path path = std::move(opened).Value();
    const auto before = CountOpenDescriptors();
    int observedChild = -1;
    EXPECT_CALL(context, OpenNativeAt(_, _, _)).WillRepeatedly([&](int directory, const char* component, int flags) {
        const int descriptor = context.ContextInterface::OpenNativeAt(directory, component, flags);
        if ((0 <= descriptor) && (name == component) && (0 != (flags & O_PATH)))
        {
            observedChild = descriptor;
        }
        return descriptor;
    });
    EXPECT_CALL(context, StatFileDescriptor(_, _)).WillRepeatedly([&](int descriptor, struct stat* metadata) {
        if (descriptor == observedChild)
        {
            errno = EACCES;
            return -1;
        }
        return context.ContextInterface::StatFileDescriptor(descriptor, metadata);
    });
    bool closeFailed = false;
    EXPECT_CALL(context, CloseFileDescriptor(_)).WillRepeatedly([&](int descriptor) {
        const bool isChild = (descriptor == observedChild);
        const int status = ::close(descriptor);
        EXPECT_EQ(0, status);
        if (isChild)
        {
            closeFailed = true;
            errno = EIO;
            return -1;
        }
        return status;
    });
    auto observation = path.ObserveChild(name, 4096);
    ASSERT_FALSE(observation.HasValue());
    EXPECT_EQ(EACCES, observation.Error().code);
    EXPECT_TRUE(closeFailed);
    EXPECT_EQ(before, CountOpenDescriptors());
    ASSERT_TRUE(testing::Mock::VerifyAndClearExpectations(&context));
}

TEST_F(PathAliasTest, DirectoryActivationCloseFailureDoesNotReturnCursorOrLeakStream)
{
    auto opened = Path::AcquireRoot(context, context.GetTempdirPath(), RootPolicy{SymlinkPolicy::Reject, MountPolicy::AllowCrossing}, AmpleLimits());
    ASSERT_TRUE(opened.HasValue());
    Path path = std::move(opened).Value();
    const auto before = CountOpenDescriptors();
    int alias = -1;
    EXPECT_CALL(context, OpenNativeAt(_, _, _)).WillRepeatedly([&](int directory, const char* name, int flags) {
        const int descriptor = context.ContextInterface::OpenNativeAt(directory, name, flags);
        if ((0 <= descriptor) && (0 == (flags & O_PATH)) && (0 == (flags & O_NOFOLLOW)) && (0 != (flags & O_DIRECTORY)))
        {
            alias = descriptor;
        }
        return descriptor;
    });
    bool failed = false, closedStream = false;
    EXPECT_CALL(context, CloseFileDescriptor(_)).WillRepeatedly([&](int descriptor) {
        const bool activated = (descriptor == alias);
        const int status = ::close(descriptor);
        EXPECT_EQ(0, status);
        if (activated)
        {
            failed = true;
            errno = EIO;
            return -1;
        }
        return status;
    });
    EXPECT_CALL(context, CloseDirectory(_)).WillOnce([&](DIR* stream) {
        closedStream = true;
        return ::closedir(stream);
    });
    auto cursor = path.Leaf().OpenChildren(4096);
    ASSERT_FALSE(cursor.HasValue());
    EXPECT_EQ(EIO, cursor.Error().code);
    EXPECT_TRUE(failed);
    EXPECT_TRUE(closedStream);
    EXPECT_EQ(before, CountOpenDescriptors());
    ASSERT_TRUE(testing::Mock::VerifyAndClearExpectations(&context));
}

TEST_F(PathAliasTest, DirectoryCursorFailedCloseIsCachedWithoutRetry)
{
    auto opened = Path::AcquireRoot(context, context.GetTempdirPath(), RootPolicy{SymlinkPolicy::Reject, MountPolicy::AllowCrossing}, AmpleLimits());
    ASSERT_TRUE(opened.HasValue());
    Path path = std::move(opened).Value();
    const auto before = CountOpenDescriptors();
    auto cursor = path.Leaf().OpenChildren(4096);
    ASSERT_TRUE(cursor.HasValue());
    EXPECT_CALL(context, CloseDirectory(_)).Times(1).WillOnce([](DIR* stream) {
        EXPECT_EQ(0, ::closedir(stream));
        errno = EIO;
        return -1;
    });
    auto closed = cursor.Value().Close();
    ASSERT_FALSE(closed.HasValue());
    EXPECT_EQ(EIO, closed.Error().code);
    auto cached = cursor.Value().Close();
    ASSERT_FALSE(cached.HasValue());
    EXPECT_EQ(EIO, cached.Error().code);
    EXPECT_EQ(before, CountOpenDescriptors());
}

TEST_F(PathAliasTest, AbsolutePrefixTemporaryPinCloseFailureRejectsValidCandidate)
{
    const std::string root = context.GetTempdirPath() + "/accepted";
    ASSERT_EQ(0, ::mkdir(root.c_str(), 0700));
    const std::string file = context.MakeTempfile("held");
    ASSERT_EQ(0, ::rename(file.c_str(), (root + "/inside").c_str()));
    ASSERT_EQ(0, ::symlink((root + "/inside").c_str(), (root + "/absolute").c_str()));
    auto opened = Path::AcquireRoot(context, root, RootPolicy{SymlinkPolicy::Reject, MountPolicy::AllowCrossing}, AmpleLimits());
    ASSERT_TRUE(opened.HasValue());
    Path path = std::move(opened).Value();
    const auto before = CountOpenDescriptors();
    bool candidateOpened = false, failed = false;
    EXPECT_CALL(context, OpenNativePath(_, _)).WillRepeatedly([&](const char* name, int flags) {
        return context.ContextInterface::OpenNativePath(name, flags);
    });
    EXPECT_CALL(context, OpenNativePath(testing::StrEq("/"), _)).WillOnce([&](const char* name, int flags) {
        candidateOpened = true;
        return context.ContextInterface::OpenNativePath(name, flags);
    });
    EXPECT_CALL(context, CloseFileDescriptor(_)).WillRepeatedly([&](int descriptor) {
        const bool candidateRoot = candidateOpened && ("/" == DescriptorTarget(descriptor));
        const int status = ::close(descriptor);
        EXPECT_EQ(0, status);
        if (candidateRoot && !failed)
        {
            failed = true;
            errno = EIO;
            return -1;
        }
        return status;
    });
    auto pushed = path.Push("absolute", ExtensionPolicy{SymlinkPolicy::FollowWithinRoot, MountPolicy::AllowCrossing, HardlinkPolicy::Permit});
    ASSERT_FALSE(pushed.HasValue());
    EXPECT_EQ(EIO, pushed.Error().code);
    EXPECT_TRUE(failed);
    EXPECT_EQ(1U, path.Size());
    EXPECT_EQ(before, CountOpenDescriptors());
    ASSERT_TRUE(testing::Mock::VerifyAndClearExpectations(&context));
}

TEST(PathTest, RejectsNonChildComponentsBeforeAnyAcquisition)
{
    EXPECT_FALSE(IsSingleChildComponent(""));
    EXPECT_FALSE(IsSingleChildComponent("."));
    EXPECT_FALSE(IsSingleChildComponent(".."));
    EXPECT_FALSE(IsSingleChildComponent("/"));
    EXPECT_FALSE(IsSingleChildComponent("a/b"));
    EXPECT_FALSE(IsSingleChildComponent("../other"));
    EXPECT_FALSE(IsSingleChildComponent(std::string("a\0b", 3)));
    EXPECT_FALSE(IsSingleChildComponent(std::string("\0", 1)));

    EXPECT_TRUE(IsSingleChildComponent("a"));
    EXPECT_TRUE(IsSingleChildComponent("..hidden"));
    EXPECT_TRUE(IsSingleChildComponent("a\\b"));
    EXPECT_TRUE(IsSingleChildComponent(std::string(255, 'x')));
}

TEST(PathTest, DoesNotOfferUncheckedDescriptorConstructionOrCopy)
{
    static_assert(!std::is_default_constructible<Handle>::value, "A handle requires a checked acquisition");
    static_assert(!std::is_constructible<Handle, int>::value, "A raw fd cannot construct a handle");
    static_assert(!std::is_copy_constructible<Handle>::value, "A pinned descriptor cannot be copied");
    static_assert(!std::is_copy_assignable<Handle>::value, "A pinned descriptor cannot be copied");
    static_assert(std::is_move_constructible<Handle>::value, "A pinned descriptor can transfer ownership");
    static_assert(std::is_move_assignable<Handle>::value, "A pinned descriptor can transfer ownership");
    static_assert(!std::is_default_constructible<Path>::value, "No unapproved root constructor is exposed");
}

TEST(PathTest, ProcfsMountIdRejectsMissingAmbiguousAndMalformedInformation)
{
    const auto valid = ParseMountId("pos:\t0\nflags:\t010000000\nmnt_id:\t123\nino:\t5\n");
    ASSERT_TRUE(valid.HasValue());
    EXPECT_EQ(123U, valid.Value());
    const std::string invalid[] = {"", "pos:\t0\n", "mnt_id:0\n", "mnt_id: \n", "mnt_id:12x\n", "mnt_id:-1\n", "mnt_id:18446744073709551616\n",
        "mnt_id:1\nmnt_id:2\n", "mnt_id:12", std::string("mnt_id:1\n\0", 10)};
    for (const auto& information : invalid)
    {
        const auto result = ParseMountId(information);
        ASSERT_FALSE(result.HasValue()) << information;
        EXPECT_EQ(EPROTO, result.Error().code);
    }
}

TEST(PathKernelIntegrationTest, NativeProcfsAndPinnedOperations)
{
    struct utsname kernel = {};
    ASSERT_EQ(0, ::uname(&kernel));
    struct statfs procfs = {};
    ASSERT_EQ(0, ::statfs("/proc/self/fdinfo", &procfs));
    ASSERT_EQ(PROC_SUPER_MAGIC, procfs.f_type);
    std::printf("M-71 kernel=%s release=%s procfs=0x%lx\n", kernel.sysname, kernel.release, static_cast<unsigned long>(procfs.f_type));

    NiceMock<MockContext> context;
    const std::string source = context.MakeTempfile("kernel-procfs");
    const std::string name = source.substr(source.find_last_of('/') + 1);
    const ResolverLimits limits{{4096, 100, 100000, 256, 262144, 4096}, 4096, 8, 128};
    auto opened = Path::AcquireRoot(context, context.GetTempdirPath(), RootPolicy{SymlinkPolicy::Reject, MountPolicy::AllowCrossing}, limits);
    ASSERT_TRUE(opened.HasValue()) << opened.Error().message;
    Path path = std::move(opened).Value();
    auto rootId = path.Root().MountIdentity(limits.shared.fdinfoBytes);
    ASSERT_TRUE(rootId.HasValue()) << rootId.Error().message;
    auto children = path.Root().OpenChildren(limits.shared.fdinfoBytes);
    ASSERT_TRUE(children.HasValue()) << children.Error().message;
    bool found = false;
    for (;;)
    {
        auto entry = children.Value().Next();
        ASSERT_TRUE(entry.HasValue()) << entry.Error().message;
        if (!entry.Value().HasValue())
        {
            break;
        }
        found = found || (name == entry.Value().Value());
    }
    EXPECT_TRUE(found);
    const ExtensionPolicy stay{SymlinkPolicy::Reject, MountPolicy::StayOnRootMount, HardlinkPolicy::Permit};
    auto pushed = path.Push(name, stay);
    ASSERT_TRUE(pushed.HasValue()) << pushed.Error().message;
    auto leafId = path.Leaf().MountIdentity(limits.shared.fdinfoBytes);
    ASSERT_TRUE(leafId.HasValue()) << leafId.Error().message;
    EXPECT_EQ(rootId.Value(), leafId.Value());
    auto metadata = path.Leaf().Stat(limits.shared.fdinfoBytes);
    ASSERT_TRUE(metadata.HasValue()) << metadata.Error().message;
    EXPECT_TRUE(S_ISREG(metadata.Value().st_mode));
    auto readable = path.Leaf().OpenReadOnly(limits.shared.fdinfoBytes);
    ASSERT_TRUE(readable.HasValue()) << readable.Error().message;
    std::size_t remainingInterruptRetries = 1;
    auto read = readable.Value().Read(32, remainingInterruptRetries);
    ASSERT_TRUE(read.HasValue()) << read.Error().message;
    ASSERT_TRUE(read.Value().HasValue());
    EXPECT_EQ("kernel-procfs", read.Value().Value());
    auto mode = path.Leaf().SetMode(0600, limits.shared.fdinfoBytes);
    ASSERT_TRUE(mode.HasValue()) << mode.Error().message;
    auto owner = path.Leaf().SetOwnership(::geteuid(), ::getegid(), limits.shared.fdinfoBytes);
    ASSERT_TRUE(owner.HasValue()) << owner.Error().message;
    struct stat changed = {};
    ASSERT_EQ(0, ::stat(source.c_str(), &changed));
    EXPECT_EQ(0600, changed.st_mode & 0777);
    EXPECT_EQ(::geteuid(), changed.st_uid);
    EXPECT_EQ(::getegid(), changed.st_gid);
}

TEST(PathKernelIntegrationTest, SameDeviceBindMountBoundaryInPrivateChildNamespace)
{
    // Neither unshare nor mount runs in the CTest/GTest process. A failure to
    // isolate or privatize propagation stops before creating any bind mount.
    std::fflush(nullptr);
    const pid_t child = ::fork();
    ASSERT_GE(child, 0) << std::strerror(errno);
    if (0 == child)
    {
        const int outcome = RunIsolatedBindMountRegression();
        const int status = testing::Test::HasFailure() ? 1 : outcome;
        std::fflush(nullptr);
        ::_exit(status);
    }
    int status = 0;
    ASSERT_EQ(child, ::waitpid(child, &status, 0)) << std::strerror(errno);
    ASSERT_TRUE(WIFEXITED(status)) << "Mount fixture child was interrupted: " << status;
    const char* requirement = std::getenv("KOMPLI_REQUIRE_M71_MOUNT");
    const bool required = (nullptr != requirement) && (0 == std::strcmp("1", requirement));
    if ((unavailableMountCapability == WEXITSTATUS(status)) && !required)
    {
        GTEST_SKIP() << "Private mount namespace/bind mount unavailable locally; CI/VM gate requires KOMPLI_REQUIRE_M71_MOUNT=1";
    }
    EXPECT_EQ(0, WEXITSTATUS(status)) << "Child mount regression failed (77 = required kernel capability unavailable)";
}

TEST_F(PathAliasTest, MoveTransfersOwnershipAndFailedCloseIsNotRetried)
{
    const std::string source = context.MakeTempfile("contents");
    const std::string component = source.substr(source.find_last_of('/') + 1);
    const std::size_t before = CountOpenDescriptors();
    {
        auto acquired = [&]() -> ComplianceEngine::Result<Handle> {
            auto opened = Path::AcquireRoot(context, context.GetTempdirPath(), RootPolicy{SymlinkPolicy::Reject, MountPolicy::AllowCrossing}, AmpleLimits());
            if (!opened.HasValue())
            {
                return std::move(opened).Error();
            }
            Path path = std::move(opened).Value();
            auto pushed = path.Push(component, ExtensionPolicy{SymlinkPolicy::Reject, MountPolicy::AllowCrossing, HardlinkPolicy::Permit});
            if (!pushed.HasValue())
            {
                return std::move(pushed).Error();
            }
            return path.Pop();
        }();
        ASSERT_TRUE(acquired.HasValue());
        EXPECT_CALL(context, CloseFileDescriptor(_)).Times(1).WillOnce([](int descriptor) {
            const int status = ::close(descriptor);
            EXPECT_EQ(0, status);
            errno = EIO;
            return -1;
        });
        Handle first = std::move(acquired).Value();
        Handle second = std::move(first);
        EXPECT_EQ(Handle::Type::RegularFile, second.AcquiredType());
    }
    EXPECT_EQ(before, CountOpenDescriptors());
}

TEST_F(PathAliasTest, CompleteAbsolutePrefixUsesEveryHeldDirectoryIdentity)
{
    const std::string rootPath = context.GetTempdirPath() + "/accepted";
    ASSERT_EQ(0, ::mkdir(rootPath.c_str(), 0700));
    ASSERT_EQ(0, ::symlink((rootPath + "/inside").c_str(), (rootPath + "/absolute").c_str()));
    const std::string file = context.MakeTempfile("contents");
    ASSERT_EQ(0, ::rename(file.c_str(), (rootPath + "/inside").c_str()));
    const std::size_t before = CountOpenDescriptors();
    {
        auto opened = Path::AcquireRoot(context, rootPath, RootPolicy{SymlinkPolicy::Reject, MountPolicy::AllowCrossing}, AmpleLimits());
        ASSERT_TRUE(opened.HasValue()) << opened.Error().message;
        Path path = std::move(opened).Value();
        const ExtensionPolicy follow{SymlinkPolicy::FollowWithinRoot, MountPolicy::AllowCrossing, HardlinkPolicy::Permit};
        auto accepted = path.Push("absolute", follow);
        ASSERT_TRUE(accepted.HasValue()) << accepted.Error().message;
        ASSERT_TRUE(path.Pop().HasValue());
        ASSERT_EQ(0, ::unlink((rootPath + "/absolute").c_str()));
        ASSERT_EQ(0, ::symlink("/etc/passwd", (rootPath + "/absolute").c_str()));
        auto outside = path.Push("absolute", follow);
        ASSERT_FALSE(outside.HasValue());
        EXPECT_EQ(EXDEV, outside.Error().code);
        ASSERT_EQ(0, ::unlink((rootPath + "/absolute").c_str()));
        ASSERT_EQ(0, ::symlink((rootPath + "/inside").c_str(), (rootPath + "/absolute").c_str()));
        ASSERT_EQ(0, ::rename(rootPath.c_str(), (rootPath + ".former").c_str()));
        ASSERT_EQ(0, ::mkdir(rootPath.c_str(), 0700));
        auto substituted = path.Push("absolute", follow);
        ASSERT_FALSE(substituted.HasValue());
        EXPECT_EQ(EXDEV, substituted.Error().code);
    }
    EXPECT_EQ(before, CountOpenDescriptors());
}

TEST_F(PathAliasTest, ConfinedResolverFollowsRelativeAndRecognizedAbsoluteLinks)
{
    const std::string rootPath = context.GetTempdirPath() + "/accepted";
    ASSERT_EQ(0, ::mkdir(rootPath.c_str(), 0700));
    const std::string file = context.MakeTempfile("contents");
    ASSERT_EQ(0, ::rename(file.c_str(), (rootPath + "/inside").c_str()));
    ASSERT_EQ(0, ::symlink("inside", (rootPath + "/relative").c_str()));
    ASSERT_EQ(0, ::symlink((rootPath + "/inside").c_str(), (rootPath + "/absolute").c_str()));
    ASSERT_EQ(0, ::symlink("/etc/passwd", (rootPath + "/outside").c_str()));
    ASSERT_EQ(0, ::symlink("../etc/passwd", (rootPath + "/escape").c_str()));
    ASSERT_EQ(0, ::symlink("loop", (rootPath + "/loop").c_str()));
    ASSERT_EQ(0, ::symlink("inside/", (rootPath + "/trailing").c_str()));
    ASSERT_EQ(0, ::symlink("relative", (rootPath + "/double").c_str()));
    const ResolverLimits limits{{4096, 100, 100000, 256, 262144, 4096}, 4096, 8, 128};
    auto opened = Path::AcquireRoot(context, rootPath, RootPolicy{SymlinkPolicy::Reject, MountPolicy::AllowCrossing}, limits);
    ASSERT_TRUE(opened.HasValue()) << opened.Error().message;
    Path path = std::move(opened).Value();
    const ExtensionPolicy strict{SymlinkPolicy::Reject, MountPolicy::AllowCrossing, HardlinkPolicy::Permit};
    const ExtensionPolicy follow{SymlinkPolicy::FollowWithinRoot, MountPolicy::AllowCrossing, HardlinkPolicy::Permit};
    const ExtensionPolicy stay{SymlinkPolicy::FollowWithinRoot, MountPolicy::StayOnRootMount, HardlinkPolicy::Permit};
    struct stat original = {};
    ASSERT_EQ(0, ::stat((rootPath + "/inside").c_str(), &original));
    const std::size_t before = CountOpenDescriptors();
    {
        auto relative = path.Push("relative", stay);
        ASSERT_TRUE(relative.HasValue()) << relative.Error().message;
        EXPECT_EQ(original.st_ino, path.Leaf().Stat().st_ino);
        ASSERT_TRUE(path.Pop().HasValue());
        auto absolute = path.Push("absolute", follow);
        ASSERT_TRUE(absolute.HasValue()) << absolute.Error().message;
        EXPECT_EQ(original.st_ino, path.Leaf().Stat().st_ino);
        ASSERT_TRUE(path.Pop().HasValue());
        auto outside = path.Push("outside", follow);
        ASSERT_FALSE(outside.HasValue());
        EXPECT_EQ(EXDEV, outside.Error().code);
        auto escaped = path.Push("escape", follow);
        ASSERT_FALSE(escaped.HasValue());
        EXPECT_EQ(EXDEV, escaped.Error().code);
        auto disallowed = path.Push("relative", strict);
        ASSERT_FALSE(disallowed.HasValue());
        EXPECT_EQ(ELOOP, disallowed.Error().code);
        auto loop = path.Push("loop", follow);
        ASSERT_FALSE(loop.HasValue());
        EXPECT_EQ(ELOOP, loop.Error().code);
        ResolverLimits oneLink = AmpleLimits();
        oneLink.linkExpansions = 1;
        auto reopened = Path::AcquireRoot(context, rootPath, RootPolicy{SymlinkPolicy::Reject, MountPolicy::AllowCrossing}, oneLink);
        ASSERT_TRUE(reopened.HasValue());
        Path bounded = std::move(reopened).Value();
        auto beyondLink = bounded.Push("double", follow);
        ASSERT_FALSE(beyondLink.HasValue());
        EXPECT_EQ(ELOOP, beyondLink.Error().code);
        oneLink.linkExpansions = 2;
        auto two = Path::AcquireRoot(context, rootPath, RootPolicy{SymlinkPolicy::Reject, MountPolicy::AllowCrossing}, oneLink);
        ASSERT_TRUE(two.HasValue());
        Path allowed = std::move(two).Value();
        auto exactlyTwo = allowed.Push("double", follow);
        ASSERT_TRUE(exactlyTwo.HasValue()) << exactlyTwo.Error().message;
        EXPECT_EQ(original.st_ino, allowed.Leaf().Stat().st_ino);
        auto trailing = path.Push("trailing", follow);
        ASSERT_FALSE(trailing.HasValue());
        EXPECT_EQ(ENOTDIR, trailing.Error().code);
    }
    EXPECT_EQ(before, CountOpenDescriptors());
}

TEST_F(PathAliasTest, ResolverUsesPinnedLinkWhenNameChangesDuringInspection)
{
    const std::string rootPath = context.GetTempdirPath() + "/accepted";
    ASSERT_EQ(0, ::mkdir(rootPath.c_str(), 0700));
    const std::string file = context.MakeTempfile("contents");
    ASSERT_EQ(0, ::rename(file.c_str(), (rootPath + "/inside").c_str()));
    ASSERT_EQ(0, ::symlink("inside", (rootPath + "/link").c_str()));
    auto opened = Path::AcquireRoot(context, rootPath, RootPolicy{SymlinkPolicy::Reject, MountPolicy::AllowCrossing}, AmpleLimits());
    ASSERT_TRUE(opened.HasValue()) << opened.Error().message;
    Path path = std::move(opened).Value();
    bool replaced = false;
    ON_CALL(context, StatFileDescriptor(_, _)).WillByDefault([&](int descriptor, struct stat* snapshot) {
        const int status = context.ContextInterface::StatFileDescriptor(descriptor, snapshot);
        if ((0 == status) && S_ISLNK(snapshot->st_mode) && !replaced)
        {
            replaced = true;
            EXPECT_EQ(0, ::rename((rootPath + "/link").c_str(), (rootPath + "/former").c_str()));
            EXPECT_EQ(0, ::mkfifo((rootPath + "/link").c_str(), 0600));
        }
        return status;
    });
    const std::size_t before = CountOpenDescriptors();
    auto resolved = path.Push("link", ExtensionPolicy{SymlinkPolicy::FollowWithinRoot, MountPolicy::StayOnRootMount, HardlinkPolicy::Permit});
    ASSERT_TRUE(resolved.HasValue()) << resolved.Error().message;
    EXPECT_TRUE(replaced);
    struct stat expected = {};
    ASSERT_EQ(0, ::stat((rootPath + "/inside").c_str(), &expected));
    EXPECT_EQ(expected.st_ino, path.Leaf().Stat().st_ino);
    EXPECT_GT(CountOpenDescriptors(), before);
}

TEST_F(PathAliasTest, RelativeParentIsBoundedByAcceptedRoot)
{
    const std::string rootPath = context.GetTempdirPath() + "/accepted";
    ASSERT_EQ(0, ::mkdir(rootPath.c_str(), 0700));
    ASSERT_EQ(0, ::mkdir((rootPath + "/sub").c_str(), 0700));
    const std::string file = context.MakeTempfile("contents");
    ASSERT_EQ(0, ::rename(file.c_str(), (rootPath + "/inside").c_str()));
    ASSERT_EQ(0, ::symlink("../inside", (rootPath + "/sub/up").c_str()));
    auto opened = Path::AcquireRoot(context, rootPath, RootPolicy{SymlinkPolicy::Reject, MountPolicy::AllowCrossing}, AmpleLimits());
    ASSERT_TRUE(opened.HasValue()) << opened.Error().message;
    Path path = std::move(opened).Value();
    ASSERT_TRUE(path.Push("sub", ExtensionPolicy{SymlinkPolicy::Reject, MountPolicy::StayOnRootMount, HardlinkPolicy::Permit}).HasValue());
    auto resolved = path.Push("up", ExtensionPolicy{SymlinkPolicy::FollowWithinRoot, MountPolicy::StayOnRootMount, HardlinkPolicy::Permit});
    ASSERT_TRUE(resolved.HasValue()) << resolved.Error().message;
    struct stat expected = {};
    ASSERT_EQ(0, ::stat((rootPath + "/inside").c_str(), &expected));
    EXPECT_EQ(expected.st_ino, path.Leaf().Stat().st_ino);
}

TEST_F(PathAliasTest, LinkExpansionKeepsPhysicalLineageForContinuation)
{
    const std::string rootPath = context.GetTempdirPath() + "/accepted";
    ASSERT_EQ(0, ::mkdir(rootPath.c_str(), 0700));
    ASSERT_EQ(0, ::mkdir((rootPath + "/first").c_str(), 0700));
    ASSERT_EQ(0, ::mkdir((rootPath + "/second").c_str(), 0700));
    const std::string file = context.MakeTempfile("contents");
    ASSERT_EQ(0, ::rename(file.c_str(), (rootPath + "/second/child").c_str()));
    ASSERT_EQ(0, ::symlink("../second", (rootPath + "/first/shortcut").c_str()));
    ASSERT_EQ(0, ::symlink("..", (rootPath + "/second/up").c_str()));
    auto opened = Path::AcquireRoot(context, rootPath, RootPolicy{SymlinkPolicy::Reject, MountPolicy::AllowCrossing}, AmpleLimits());
    ASSERT_TRUE(opened.HasValue()) << opened.Error().message;
    Path path = std::move(opened).Value();
    const ExtensionPolicy strict{SymlinkPolicy::Reject, MountPolicy::StayOnRootMount, HardlinkPolicy::Permit};
    const ExtensionPolicy follow{SymlinkPolicy::FollowWithinRoot, MountPolicy::StayOnRootMount, HardlinkPolicy::Permit};
    ASSERT_TRUE(path.Push("first", strict).HasValue());
    auto shortcut = path.Push("shortcut", follow);
    ASSERT_TRUE(shortcut.HasValue()) << shortcut.Error().message;
    struct stat second = {};
    ASSERT_EQ(0, ::stat((rootPath + "/second").c_str(), &second));
    EXPECT_EQ(second.st_ino, path.Leaf().Stat().st_ino);
    auto child = path.Push("child", follow);
    ASSERT_TRUE(child.HasValue()) << child.Error().message;
    struct stat expected = {};
    ASSERT_EQ(0, ::stat((rootPath + "/second/child").c_str(), &expected));
    EXPECT_EQ(expected.st_ino, path.Leaf().Stat().st_ino);
    ASSERT_TRUE(path.Pop().HasValue());
    auto up = path.Push("up", follow);
    ASSERT_TRUE(up.HasValue()) << up.Error().message;
    EXPECT_EQ(path.Root().Stat().st_ino, path.Leaf().Stat().st_ino);
}

TEST_F(PathAliasTest, ResolverBudgetsFailAtOneBeyondAndLeavePinsAlive)
{
    const std::string rootPath = context.GetTempdirPath() + "/accepted";
    ASSERT_EQ(0, ::mkdir(rootPath.c_str(), 0700));
    const std::string file = context.MakeTempfile("contents");
    ASSERT_EQ(0, ::rename(file.c_str(), (rootPath + "/inside").c_str()));
    ASSERT_EQ(0, ::symlink("inside", (rootPath + "/link").c_str()));
    ResolverLimits limits = AmpleLimits();
    limits.linkTargetBytes = 5;
    auto opened = Path::AcquireRoot(context, rootPath, RootPolicy{SymlinkPolicy::Reject, MountPolicy::AllowCrossing}, limits);
    ASSERT_TRUE(opened.HasValue()) << opened.Error().message;
    Path path = std::move(opened).Value();
    const std::size_t before = CountOpenDescriptors();
    const ExtensionPolicy strict{SymlinkPolicy::Reject, MountPolicy::StayOnRootMount, HardlinkPolicy::Permit};
    const ExtensionPolicy follow{SymlinkPolicy::FollowWithinRoot, MountPolicy::StayOnRootMount, HardlinkPolicy::Permit};
    auto direct = path.Push("inside", strict);
    ASSERT_TRUE(direct.HasValue()) << direct.Error().message;
    ASSERT_TRUE(path.Pop().HasValue());
    auto linkFailed = path.Push("link", follow);
    ASSERT_FALSE(linkFailed.HasValue());
    EXPECT_EQ(E2BIG, linkFailed.Error().code);
    EXPECT_EQ(1U, path.Size());
    EXPECT_EQ(before, CountOpenDescriptors());

    // The public factory and extension share the same caller-supplied work
    // ledger; a failed request does not release its charge or its root pin.
    ASSERT_EQ(0, ::mkdir((rootPath + "/budget-child").c_str(), 0700));
    const std::size_t charge = 128 + 4 * (4096 / 256);
    // Root acquisition charges twice, plus twice per component; the first
    // one-component Push charges three times. The next Push is one beyond.
    const std::size_t rootComponents = static_cast<std::size_t>(std::count(rootPath.begin(), rootPath.end(), '/'));
    ResolverLimits exact = AmpleLimits();
    exact.shared.work = (2 + 2 * rootComponents + 3) * charge;
    auto root = Path::AcquireRoot(context, rootPath, RootPolicy{SymlinkPolicy::Reject, MountPolicy::AllowCrossing}, exact);
    ASSERT_TRUE(root.HasValue());
    Path bounded = std::move(root).Value();
    ASSERT_TRUE(bounded.Push("budget-child", strict).HasValue());
    ASSERT_TRUE(bounded.Pop().HasValue());
    auto noWork = bounded.Push("budget-child", strict);
    ASSERT_FALSE(noWork.HasValue());
    EXPECT_EQ(E2BIG, noWork.Error().code);
}

TEST_F(PathAliasTest, PublicRootAndPushKeepOriginalPinsAndSeparatePolicies)
{
    const std::string rootPath = context.GetTempdirPath() + "/accepted";
    ASSERT_EQ(0, ::mkdir(rootPath.c_str(), 0700));
    const std::string file = context.MakeTempfile("contents");
    ASSERT_EQ(0, ::rename(file.c_str(), (rootPath + "/inside").c_str()));
    ASSERT_EQ(0, ::symlink("inside", (rootPath + "/allowed").c_str()));
    ASSERT_EQ(0, ::symlink("/etc/passwd", (rootPath + "/outside").c_str()));
    const ResolverLimits limits{{4096, 4096, 2000000, 4096, 16U * 1024U * 1024U, 4096}, 4096, 8, 4096};
    const RootPolicy rootPolicy{SymlinkPolicy::Reject, MountPolicy::AllowCrossing};
    const ExtensionPolicy strict{SymlinkPolicy::Reject, MountPolicy::StayOnRootMount, HardlinkPolicy::Permit};
    const ExtensionPolicy follow{SymlinkPolicy::FollowWithinRoot, MountPolicy::StayOnRootMount, HardlinkPolicy::Permit};
    const std::size_t before = CountOpenDescriptors();
    {
        auto opened = Path::AcquireRoot(context, rootPath, rootPolicy, limits);
        ASSERT_TRUE(opened.HasValue()) << opened.Error().message;
        Path path = std::move(opened).Value();
        ASSERT_EQ(1U, path.Size());
        const Handle& rootBorrow = path.Root();
        EXPECT_EQ(rootBorrow.Stat().st_ino, path.Leaf().Stat().st_ino);
        auto denied = path.Push("outside", follow);
        ASSERT_FALSE(denied.HasValue());
        EXPECT_EQ(EXDEV, denied.Error().code);
        EXPECT_EQ(1U, path.Size());
        EXPECT_EQ(rootBorrow.Stat().st_ino, path.Root().Stat().st_ino);
        auto noLinks = path.Push("allowed", strict);
        ASSERT_FALSE(noLinks.HasValue());
        EXPECT_EQ(ELOOP, noLinks.Error().code);
        auto success = path.Push("allowed", follow);
        ASSERT_TRUE(success.HasValue()) << success.Error().message;
        EXPECT_EQ(2U, path.Size());
        EXPECT_EQ(Handle::Type::RegularFile, path.Leaf().AcquiredType());
        EXPECT_EQ(rootBorrow.Stat().st_ino, path.Root().Stat().st_ino);
        auto notDirectory = path.Push("inside", strict);
        ASSERT_FALSE(notDirectory.HasValue());
        EXPECT_EQ(ENOTDIR, notDirectory.Error().code);
    }
    EXPECT_EQ(before, CountOpenDescriptors());
}

TEST_F(PathAliasTest, ExplicitAdministrativeRootLinkAndMovedPath)
{
    const std::string rootPath = context.GetTempdirPath() + "/accepted";
    ASSERT_EQ(0, ::mkdir(rootPath.c_str(), 0700));
    const std::string rootLink = context.GetTempdirPath() + "/administrative";
    ASSERT_EQ(0, ::symlink(rootPath.c_str(), rootLink.c_str()));
    const ResolverLimits limits{{4096, 4096, 2000000, 4096, 16U * 1024U * 1024U, 4096}, 4096, 8, 4096};
    auto rejected = Path::AcquireRoot(context, rootLink, RootPolicy{SymlinkPolicy::Reject, MountPolicy::AllowCrossing}, limits);
    ASSERT_FALSE(rejected.HasValue());
    EXPECT_EQ(ELOOP, rejected.Error().code);
    auto approved = Path::AcquireRoot(context, rootLink, RootPolicy{SymlinkPolicy::FollowWithinRoot, MountPolicy::AllowCrossing}, limits);
    ASSERT_TRUE(approved.HasValue()) << approved.Error().message;
    Path original = std::move(approved).Value();
    const std::size_t inode = original.Root().Stat().st_ino;
    Path moved = std::move(original);
    EXPECT_EQ(1U, moved.Size());
    EXPECT_EQ(inode, moved.Root().Stat().st_ino);
    auto noRoot = original.Push("anything", ExtensionPolicy{SymlinkPolicy::Reject, MountPolicy::AllowCrossing, HardlinkPolicy::Permit});
    ASSERT_FALSE(noRoot.HasValue());
    EXPECT_EQ(EINVAL, noRoot.Error().code);
    const std::string file = context.MakeTempfile("contents");
    ASSERT_EQ(0, ::rename(file.c_str(), (rootPath + "/child").c_str()));
    auto accepted = moved.Push("child", ExtensionPolicy{SymlinkPolicy::Reject, MountPolicy::StayOnRootMount, HardlinkPolicy::Permit});
    ASSERT_TRUE(accepted.HasValue()) << accepted.Error().message;
    EXPECT_EQ(2U, moved.Size());
}

TEST_F(PathAliasTest, EndInsertionKeepsBorrowsStableAndFailedPushDoesNotChangeStack)
{
    const std::string rootPath = context.GetTempdirPath() + "/accepted";
    ASSERT_EQ(0, ::mkdir(rootPath.c_str(), 0700));
    const ResolverLimits limits{{4096, 4096, 2000000, 4096, 16U * 1024U * 1024U, 4096}, 4096, 8, 4096};
    auto opened = Path::AcquireRoot(context, rootPath, RootPolicy{SymlinkPolicy::Reject, MountPolicy::AllowCrossing}, limits);
    ASSERT_TRUE(opened.HasValue()) << opened.Error().message;
    Path path = std::move(opened).Value();
    const Handle& rootBorrow = path.Root();
    const Handle* first = nullptr;
    std::string current = rootPath;
    const ExtensionPolicy strict{SymlinkPolicy::Reject, MountPolicy::StayOnRootMount, HardlinkPolicy::Permit};
    for (int index = 0; index < 72; ++index)
    {
        current += "/d";
        ASSERT_EQ(0, ::mkdir(current.c_str(), 0700));
        auto pushed = path.Push("d", strict);
        ASSERT_TRUE(pushed.HasValue()) << "index " << index << ": " << pushed.Error().message;
        if (0 == index)
        {
            first = &path.Leaf();
        }
        EXPECT_EQ(rootBorrow.Stat().st_ino, path.Root().Stat().st_ino);
    }
    ASSERT_NE(nullptr, first);
    EXPECT_EQ(73U, path.Size());
    EXPECT_EQ("d", first->Component());
    const std::size_t stableInode = first->Stat().st_ino;
    auto invalid = path.Push("../escape", strict);
    ASSERT_FALSE(invalid.HasValue());
    EXPECT_EQ(EINVAL, invalid.Error().code);
    EXPECT_EQ(73U, path.Size());
    EXPECT_EQ(stableInode, first->Stat().st_ino);
    for (int index = 0; index < 71; ++index)
    {
        ASSERT_TRUE(path.Pop().HasValue());
        EXPECT_EQ(&rootBorrow, &path.Root());
        EXPECT_EQ(stableInode, first->Stat().st_ino);
    }
    EXPECT_EQ(2U, path.Size());
    EXPECT_EQ(first, &path.Leaf());
}

TEST_F(PathAliasTest, FailedPublicPushConsumesWorkWithoutChangingAcceptedRoot)
{
    const std::size_t cost = 128 + 4 * (4096 / 256);
    const ResolverLimits limits{{4096, 64, 5 * cost, 64, 262144, 4096}, 128, 2, 64};
    auto opened = Path::AcquireRoot(context, "/", RootPolicy{SymlinkPolicy::Reject, MountPolicy::AllowCrossing}, limits);
    ASSERT_TRUE(opened.HasValue()) << opened.Error().message;
    Path path = std::move(opened).Value();
    const std::string absent = "/m71-nonexistent-fixture-entry";
    struct stat unused = {};
    ASSERT_EQ(-1, ::lstat(absent.c_str(), &unused));
    ASSERT_EQ(ENOENT, errno);
    const ExtensionPolicy allow{SymlinkPolicy::Reject, MountPolicy::AllowCrossing, HardlinkPolicy::Permit};
    const auto missing = path.Push(absent.substr(1), allow);
    ASSERT_FALSE(missing.HasValue());
    EXPECT_EQ(ENOENT, missing.Error().code);
    EXPECT_EQ(1U, path.Size());
    const auto exhausted = path.Push("etc", allow);
    ASSERT_FALSE(exhausted.HasValue());
    EXPECT_EQ(E2BIG, exhausted.Error().code);
    EXPECT_EQ(1U, path.Size());
}

TEST_F(PathAliasTest, MovedPublicPathRetainsDescriptorCapAndRejectsUnsupportedHardlinkMode)
{
    const ResolverLimits limits{{4096, 64, 100000, 8, 262144, 4096}, 128, 2, 64};
    auto opened = Path::AcquireRoot(context, "/", RootPolicy{SymlinkPolicy::Reject, MountPolicy::AllowCrossing}, limits);
    ASSERT_TRUE(opened.HasValue()) << opened.Error().message;
    Path path = std::move(opened).Value();
    const ExtensionPolicy allow{SymlinkPolicy::Reject, MountPolicy::AllowCrossing, HardlinkPolicy::Permit};
    const ExtensionPolicy unsupported{SymlinkPolicy::Reject, MountPolicy::AllowCrossing, HardlinkPolicy::RequireUnique};
    auto denied = path.Push("etc", unsupported);
    ASSERT_FALSE(denied.HasValue());
    EXPECT_EQ(ENOTSUP, denied.Error().code);
    ASSERT_TRUE(path.Push("etc", allow).HasValue());
    Path moved = std::move(path);
    EXPECT_EQ(2U, moved.Size());
    auto cap = moved.Push("passwd", allow);
    ASSERT_FALSE(cap.HasValue());
    EXPECT_EQ(EMFILE, cap.Error().code);
    EXPECT_EQ(2U, moved.Size());
}

TEST_F(PathAliasTest, PopTransfersLeafAndPreservesSurvivingBorrows)
{
    const std::string rootPath = context.GetTempdirPath() + "/accepted";
    ASSERT_EQ(0, ::mkdir(rootPath.c_str(), 0700));
    ASSERT_EQ(0, ::mkdir((rootPath + "/one").c_str(), 0700));
    ASSERT_EQ(0, ::mkdir((rootPath + "/one/two").c_str(), 0700));
    const ResolverLimits limits{{4096, 4096, 2000000, 4096, 16U * 1024U * 1024U, 4096}, 4096, 8, 4096};
    const ExtensionPolicy strict{SymlinkPolicy::Reject, MountPolicy::StayOnRootMount, HardlinkPolicy::Permit};
    const std::size_t before = CountOpenDescriptors();
    {
        auto opened = Path::AcquireRoot(context, rootPath, RootPolicy{SymlinkPolicy::Reject, MountPolicy::AllowCrossing}, limits);
        ASSERT_TRUE(opened.HasValue()) << opened.Error().message;
        Path path = std::move(opened).Value();
        const Handle& root = path.Root();
        ASSERT_TRUE(path.Push("one", strict).HasValue());
        const Handle& one = path.Leaf();
        ASSERT_TRUE(path.Push("two", strict).HasValue());
        const std::size_t twoInode = path.Leaf().Stat().st_ino;
        auto detached = path.Pop();
        ASSERT_TRUE(detached.HasValue()) << detached.Error().message;
        EXPECT_EQ(2U, path.Size());
        EXPECT_EQ(&root, &path.Root());
        EXPECT_EQ(&one, &path.Leaf());
        EXPECT_EQ("one", one.Component());
        EXPECT_EQ(twoInode, detached.Value().Stat().st_ino);
        const std::size_t afterPop = CountOpenDescriptors();
        ASSERT_TRUE(path.Push("two", strict).HasValue());
        EXPECT_EQ(twoInode, path.Leaf().Stat().st_ino);
        // The old pin remains independently owned despite a new name lookup.
        EXPECT_GT(CountOpenDescriptors(), afterPop);
        auto again = path.Pop();
        ASSERT_TRUE(again.HasValue());
        auto parent = path.Pop();
        ASSERT_TRUE(parent.HasValue());
        EXPECT_EQ(&root, &path.Leaf());
    }
    EXPECT_EQ(before, CountOpenDescriptors());
}

TEST_F(PathAliasTest, IgnoredPopClosesOnceAndEmptyAccessIsExplicit)
{
    const ResolverLimits limits{{4096, 128, 100000, 64, 262144, 4096}, 128, 2, 128};
    const ExtensionPolicy allow{SymlinkPolicy::Reject, MountPolicy::AllowCrossing, HardlinkPolicy::Permit};
    const std::size_t before = CountOpenDescriptors();
    {
        auto opened = Path::AcquireRoot(context, "/", RootPolicy{SymlinkPolicy::Reject, MountPolicy::AllowCrossing}, limits);
        ASSERT_TRUE(opened.HasValue());
        Path path = std::move(opened).Value();
        ASSERT_TRUE(path.Push("etc", allow).HasValue());
        const std::size_t withLeaf = CountOpenDescriptors();
        ASSERT_TRUE(path.Pop().HasValue()); // The temporary result closes its pin.
        EXPECT_EQ(1U, path.Size());
        EXPECT_LT(CountOpenDescriptors(), withLeaf);
        EXPECT_TRUE(path.Push("etc", allow).HasValue());
        Path moved = std::move(path);
        auto leaf = moved.Pop();
        ASSERT_TRUE(leaf.HasValue());
        auto root = moved.Pop();
        ASSERT_TRUE(root.HasValue());
        EXPECT_EQ(0U, moved.Size());
        auto empty = moved.Pop();
        ASSERT_FALSE(empty.HasValue());
        EXPECT_EQ(EINVAL, empty.Error().code);
        EXPECT_THROW(moved.Root(), std::logic_error);
        EXPECT_THROW(moved.Leaf(), std::logic_error);
        auto cannotPush = moved.Push("etc", allow);
        ASSERT_FALSE(cannotPush.HasValue());
        EXPECT_EQ(EINVAL, cannotPush.Error().code);
        auto movedFrom = path.Pop();
        ASSERT_FALSE(movedFrom.HasValue());
        EXPECT_EQ(EINVAL, movedFrom.Error().code);
    }
    EXPECT_EQ(before, CountOpenDescriptors());
}

TEST_F(PathAliasTest, DetachedRootAndFileRemainPinnedAfterPathDestruction)
{
    const std::string rootPath = context.GetTempdirPath() + "/accepted";
    ASSERT_EQ(0, ::mkdir(rootPath.c_str(), 0700));
    const std::string original = context.MakeTempfile("old contents");
    ASSERT_EQ(0, ::rename(original.c_str(), (rootPath + "/file").c_str()));
    const ResolverLimits limits{{4096, 128, 200000, 128, 262144, 4096}, 128, 2, 128};
    const ExtensionPolicy strict{SymlinkPolicy::Reject, MountPolicy::StayOnRootMount, HardlinkPolicy::Permit};
    const std::size_t before = CountOpenDescriptors();
    {
        auto detached = [&]() -> ComplianceEngine::Result<Handle> {
            auto opened = Path::AcquireRoot(context, rootPath, RootPolicy{SymlinkPolicy::Reject, MountPolicy::AllowCrossing}, limits);
            if (!opened.HasValue())
            {
                return std::move(opened).Error();
            }
            Path path = std::move(opened).Value();
            auto pushed = path.Push("file", strict);
            if (!pushed.HasValue())
            {
                return std::move(pushed).Error();
            }
            return path.Pop();
        }();
        ASSERT_TRUE(detached.HasValue());
        EXPECT_EQ(before + 1, CountOpenDescriptors());
        const std::size_t oldInode = detached.Value().Stat().st_ino;
        ASSERT_EQ(0, ::rename((rootPath + "/file").c_str(), (rootPath + "/former").c_str()));
        ASSERT_EQ(0, ::mkfifo((rootPath + "/file").c_str(), 0600));
        auto activated = detached.Value().Stat(limits.shared.fdinfoBytes);
        ASSERT_TRUE(activated.HasValue()) << activated.Error().message;
        EXPECT_EQ(oldInode, activated.Value().st_ino);
        ASSERT_EQ(0, ::unlink((rootPath + "/former").c_str()));
        auto again = detached.Value().Stat(limits.shared.fdinfoBytes);
        ASSERT_TRUE(again.HasValue()) << again.Error().message;
        EXPECT_EQ(oldInode, again.Value().st_ino);
    }
    EXPECT_EQ(before, CountOpenDescriptors());
    {
        auto detachedRoot = [&]() -> ComplianceEngine::Result<Handle> {
            auto opened = Path::AcquireRoot(context, rootPath, RootPolicy{SymlinkPolicy::Reject, MountPolicy::AllowCrossing}, limits);
            if (!opened.HasValue())
            {
                return std::move(opened).Error();
            }
            Path path = std::move(opened).Value();
            return path.Pop();
        }();
        ASSERT_TRUE(detachedRoot.HasValue());
        EXPECT_EQ(before + 1, CountOpenDescriptors());
        ASSERT_EQ(0, ::rename(rootPath.c_str(), (rootPath + ".former").c_str()));
        ASSERT_EQ(0, ::mkdir(rootPath.c_str(), 0700));
        auto active = detachedRoot.Value().Stat(limits.shared.fdinfoBytes);
        ASSERT_TRUE(active.HasValue()) << active.Error().message;
        EXPECT_EQ(detachedRoot.Value().Stat().st_ino, active.Value().st_ino);
    }
    EXPECT_EQ(before, CountOpenDescriptors());
}

TEST_F(PathAliasTest, DetachedResourceChargesPersistAcrossMovesUntilClose)
{
    const std::size_t firstStage = sizeof(Handle) + 4 * sizeof(const Handle*) + 1 + sizeof(std::string) + 3 + sizeof(Handle) + 3 + 4 * sizeof(const Handle*);
    const ResolverLimits memoryLimits{{4096, 128, 200000, 64, sizeof(Handle) + 1 + firstStage + sizeof(Handle) + 2, 4096}, 128, 2, 128};
    const ResolverLimits fdLimits{{4096, 128, 200000, 8, 262144, 4096}, 128, 2, 128};
    const ExtensionPolicy allow{SymlinkPolicy::Reject, MountPolicy::AllowCrossing, HardlinkPolicy::Permit};
    const std::size_t before = CountOpenDescriptors();
    for (const auto& limits : {fdLimits, memoryLimits})
    {
        auto opened = Path::AcquireRoot(context, "/", RootPolicy{SymlinkPolicy::Reject, MountPolicy::AllowCrossing}, limits);
        ASSERT_TRUE(opened.HasValue()) << opened.Error().message;
        Path path = std::move(opened).Value();
        ASSERT_TRUE(path.Push("etc", allow).HasValue());
        {
            auto popped = path.Pop();
            ASSERT_TRUE(popped.HasValue());
            Handle moved = std::move(popped).Value();
            auto blocked = path.Push("etc", allow);
            ASSERT_FALSE(blocked.HasValue());
            EXPECT_EQ(limits.shared.liveDescriptors == 8 ? EMFILE : E2BIG, blocked.Error().code);
            EXPECT_EQ(1U, path.Size());
        }
        EXPECT_TRUE(path.Push("etc", allow).HasValue());
    }
    EXPECT_EQ(before, CountOpenDescriptors());
}

TEST_F(PathAliasTest, PopRestoresPinnedPhysicalLineageThroughDirectoryLink)
{
    const std::string rootPath = context.GetTempdirPath() + "/accepted";
    ASSERT_EQ(0, ::mkdir(rootPath.c_str(), 0700));
    ASSERT_EQ(0, ::mkdir((rootPath + "/actual").c_str(), 0700));
    ASSERT_EQ(0, ::symlink("actual", (rootPath + "/shortcut").c_str()));
    const std::string file = context.MakeTempfile("contents");
    ASSERT_EQ(0, ::rename(file.c_str(), (rootPath + "/actual/child").c_str()));
    const ResolverLimits limits{{4096, 4096, 2000000, 4096, 16U * 1024U * 1024U, 4096}, 4096, 8, 4096};
    const ExtensionPolicy follow{SymlinkPolicy::FollowWithinRoot, MountPolicy::StayOnRootMount, HardlinkPolicy::Permit};
    const ExtensionPolicy strict{SymlinkPolicy::Reject, MountPolicy::StayOnRootMount, HardlinkPolicy::Permit};
    const std::size_t before = CountOpenDescriptors();
    {
        auto opened = Path::AcquireRoot(context, rootPath, RootPolicy{SymlinkPolicy::Reject, MountPolicy::AllowCrossing}, limits);
        ASSERT_TRUE(opened.HasValue());
        Path path = std::move(opened).Value();
        ASSERT_TRUE(path.Push("shortcut", follow).HasValue());
        const Handle& directory = path.Leaf();
        ASSERT_TRUE(path.Push("child", strict).HasValue());
        const std::size_t originalInode = path.Leaf().Stat().st_ino;
        auto detached = path.Pop();
        ASSERT_TRUE(detached.HasValue());
        EXPECT_EQ(&directory, &path.Leaf());
        ASSERT_EQ(0, ::rename((rootPath + "/actual").c_str(), (rootPath + "/former").c_str()));
        ASSERT_EQ(0, ::mkdir((rootPath + "/actual").c_str(), 0700));
        auto next = path.Push("child", strict);
        ASSERT_TRUE(next.HasValue()) << next.Error().message;
        EXPECT_EQ(originalInode, path.Leaf().Stat().st_ino);
        EXPECT_EQ(originalInode, detached.Value().Stat().st_ino);
    }
    EXPECT_EQ(before, CountOpenDescriptors());
}

TEST_F(PathAliasTest, PoppedHandleFailedCloseIsSingleShotEvenAfterMove)
{
    const ResolverLimits limits{{4096, 128, 200000, 64, 262144, 4096}, 128, 2, 128};
    const std::size_t before = CountOpenDescriptors();
    auto popped = [&]() -> ComplianceEngine::Result<Handle> {
        auto opened = Path::AcquireRoot(context, "/", RootPolicy{SymlinkPolicy::Reject, MountPolicy::AllowCrossing}, limits);
        if (!opened.HasValue())
        {
            return std::move(opened).Error();
        }
        Path path = std::move(opened).Value();
        return path.Pop();
    }();
    ASSERT_TRUE(popped.HasValue());
    EXPECT_EQ(before + 1, CountOpenDescriptors());
    EXPECT_CALL(context, CloseFileDescriptor(_)).Times(1).WillOnce([](int descriptor) {
        EXPECT_EQ(0, ::close(descriptor));
        errno = EIO;
        return -1;
    });
    {
        Handle moved = std::move(popped).Value();
        Handle owner = std::move(moved);
        EXPECT_EQ("/", owner.Component());
    }
    EXPECT_EQ(before, CountOpenDescriptors());
    OwnedTestDescriptor reused(::open("/dev/null", O_RDONLY | O_CLOEXEC));
    ASSERT_GE(reused.Get(), 0);
    EXPECT_NE(-1, ::fcntl(reused.Get(), F_GETFD));
}

TEST_F(PathAliasTest, CheckedPathReleaseVisitsRootLineageHiddenAndLeafPins)
{
    const std::string root = context.GetTempdirPath() + "/accepted";
    const std::string hidden = root + "/hidden";
    ASSERT_EQ(0, ::mkdir(root.c_str(), 0700));
    ASSERT_EQ(0, ::mkdir(hidden.c_str(), 0700));
    const std::string source = context.MakeTempfile("payload");
    ASSERT_EQ(0, ::rename(source.c_str(), (hidden + "/file").c_str()));
    ASSERT_EQ(0, ::symlink("hidden/file", (root + "/shortcut").c_str()));
    const std::string names[] = {"/", context.GetTempdirPath(), root, hidden, hidden + "/file"};
    const ResolverLimits limits{{4096, 128, 200000, 128, 262144, 4096}, 4096, 8, 128};
    const std::size_t before = CountOpenDescriptors();
    for (const std::string& name : names)
    {
        struct stat target = {};
        ASSERT_EQ(0, ::stat(name.c_str(), &target));
        auto opened = Path::AcquireRoot(context, root, RootPolicy{SymlinkPolicy::Reject, MountPolicy::AllowCrossing}, limits);
        ASSERT_TRUE(opened.HasValue()) << opened.Error().message;
        Path path = std::move(opened).Value();
        ASSERT_TRUE(path.Push("shortcut", ExtensionPolicy{SymlinkPolicy::FollowWithinRoot, MountPolicy::AllowCrossing, HardlinkPolicy::Permit}).HasValue());
        const std::size_t pins = path.RetainedDescriptors();
        ASSERT_GT(pins, 4U); // includes the directory retained through the symlink
        std::size_t closed = 0, matched = 0;
        EXPECT_CALL(context, CloseFileDescriptor(_)).Times(pins).WillRepeatedly([&](int descriptor) {
            struct stat actual = {};
            EXPECT_EQ(0, ::fstat(descriptor, &actual));
            const bool hit = actual.st_dev == target.st_dev && actual.st_ino == target.st_ino;
            ++closed;
            if (hit)
            {
                ++matched;
            }
            EXPECT_EQ(0, ::close(descriptor));
            if (hit)
            {
                errno = EACCES;
                return -1;
            }
            return 0;
        });
        auto failed = path.Close();
        ASSERT_FALSE(failed.HasValue()) << name;
        EXPECT_EQ(EACCES, failed.Error().code);
        EXPECT_EQ(pins, closed);
        EXPECT_EQ(1U, matched) << name;
        EXPECT_EQ(0U, path.Size());
        EXPECT_EQ(0U, path.RetainedDescriptors());
        EXPECT_EQ(0U, path.RetainedBytes());
        EXPECT_EQ(EACCES, path.Close().Error().code);
        ASSERT_TRUE(testing::Mock::VerifyAndClearExpectations(&context));
        EXPECT_EQ(before, CountOpenDescriptors());
    }
}

TEST_F(PathAliasTest, PoppedFileRootKeepsHiddenPinsForCheckedPathClose)
{
    const std::string root = context.GetTempdirPath() + "/accepted";
    const std::string hidden = root + "/hidden";
    ASSERT_EQ(0, ::mkdir(root.c_str(), 0700));
    ASSERT_EQ(0, ::mkdir(hidden.c_str(), 0700));
    const std::string source = context.MakeTempfile("still readable");
    ASSERT_EQ(0, ::rename(source.c_str(), (hidden + "/file").c_str()));
    ASSERT_EQ(0, ::symlink("hidden/file", (root + "/shortcut").c_str()));
    struct stat hiddenStat = {};
    ASSERT_EQ(0, ::stat(hidden.c_str(), &hiddenStat));
    const ResolverLimits limits{{4096, 128, 200000, 128, 262144, 4096}, 4096, 8, 128};
    auto opened = Path::AcquireRoot(context, root + "/shortcut", RootPolicy{SymlinkPolicy::FollowWithinRoot, MountPolicy::AllowCrossing}, limits, true);
    ASSERT_TRUE(opened.HasValue()) << opened.Error().message;
    Path path = std::move(opened).Value();
    auto popped = path.Pop();
    ASSERT_TRUE(popped.HasValue());
    Handle leaf = std::move(popped).Value();
    ASSERT_EQ(0U, path.Size());
    const std::size_t retained = path.RetainedDescriptors();
    ASSERT_GT(retained, 2U); // detached leaf plus hidden and root-lineage pins
    const std::size_t before = CountOpenDescriptors();
    std::size_t attempts = 0, hiddenAttempts = 0;
    EXPECT_CALL(context, CloseFileDescriptor(_)).Times(retained - 1).WillRepeatedly([&](int fd) {
        struct stat observed = {};
        EXPECT_EQ(0, ::fstat(fd, &observed));
        const bool isHidden = observed.st_dev == hiddenStat.st_dev && observed.st_ino == hiddenStat.st_ino;
        if (isHidden)
        {
            ++hiddenAttempts;
        }
        ++attempts;
        EXPECT_EQ(0, ::close(fd));
        if (isHidden)
        {
            errno = EACCES;
            return -1;
        }
        return 0;
    });
    EXPECT_EQ(EACCES, path.Close().Error().code);
    EXPECT_EQ(retained - 1, attempts);
    EXPECT_EQ(1U, hiddenAttempts);
    EXPECT_EQ(1U, path.RetainedDescriptors());
    EXPECT_EQ(EACCES, path.Close().Error().code);
    ASSERT_TRUE(testing::Mock::VerifyAndClearExpectations(&context));
    EXPECT_EQ(before - attempts, CountOpenDescriptors());
    auto activated = leaf.OpenReadOnly(4096);
    ASSERT_TRUE(activated.HasValue());
    std::size_t remainingInterruptRetries = 1;
    auto chunk = activated.Value().Read(32, remainingInterruptRetries);
    ASSERT_TRUE(chunk.HasValue());
    ASSERT_TRUE(chunk.Value().HasValue());
    EXPECT_EQ("still readable", chunk.Value().Value());
    EXPECT_TRUE(activated.Value().Close().HasValue());
    EXPECT_TRUE(leaf.Close().HasValue());
    EXPECT_EQ(0U, path.RetainedDescriptors());
    EXPECT_EQ(0U, path.RetainedBytes());
}

TEST_F(PathAliasTest, PoppedDescendantRetainsHiddenPinsUntilCheckedRelease)
{
    const std::string root = context.GetTempdirPath() + "/accepted";
    const std::string hidden = root + "/hidden";
    ASSERT_EQ(0, ::mkdir(root.c_str(), 0700));
    ASSERT_EQ(0, ::mkdir(hidden.c_str(), 0700));
    const std::string source = context.MakeTempfile("descendant");
    ASSERT_EQ(0, ::rename(source.c_str(), (hidden + "/file").c_str()));
    ASSERT_EQ(0, ::symlink("hidden/file", (root + "/shortcut").c_str()));
    struct stat hiddenStat = {};
    ASSERT_EQ(0, ::stat(hidden.c_str(), &hiddenStat));
    const ResolverLimits limits{{4096, 128, 200000, 128, 262144, 4096}, 4096, 8, 128};
    auto opened = Path::AcquireRoot(context, root, RootPolicy{SymlinkPolicy::Reject, MountPolicy::AllowCrossing}, limits);
    ASSERT_TRUE(opened.HasValue());
    Path path = std::move(opened).Value();
    ASSERT_TRUE(path.Push("shortcut", ExtensionPolicy{SymlinkPolicy::FollowWithinRoot, MountPolicy::AllowCrossing, HardlinkPolicy::Permit}).HasValue());
    auto popped = path.Pop();
    ASSERT_TRUE(popped.HasValue());
    Handle leaf = std::move(popped).Value();
    EXPECT_EQ(1U, path.Size());
    const std::size_t retained = path.RetainedDescriptors();
    ASSERT_GT(retained, 3U);
    std::size_t attempts = 0, hiddenAttempts = 0;
    EXPECT_CALL(context, CloseFileDescriptor(_)).Times(retained - 1).WillRepeatedly([&](int fd) {
        struct stat observed = {};
        EXPECT_EQ(0, ::fstat(fd, &observed));
        const bool isHidden = observed.st_dev == hiddenStat.st_dev && observed.st_ino == hiddenStat.st_ino;
        if (isHidden)
        {
            ++hiddenAttempts;
        }
        ++attempts;
        EXPECT_EQ(0, ::close(fd));
        if (isHidden)
        {
            errno = EACCES;
            return -1;
        }
        return 0;
    });
    EXPECT_EQ(EACCES, path.Close().Error().code);
    EXPECT_EQ(retained - 1, attempts);
    EXPECT_EQ(1U, hiddenAttempts);
    EXPECT_EQ(1U, path.RetainedDescriptors());
    ASSERT_TRUE(testing::Mock::VerifyAndClearExpectations(&context));
    auto activated = leaf.OpenReadOnly(4096);
    ASSERT_TRUE(activated.HasValue());
    std::size_t remainingInterruptRetries = 1;
    auto chunk = activated.Value().Read(32, remainingInterruptRetries);
    ASSERT_TRUE(chunk.HasValue());
    ASSERT_TRUE(chunk.Value().HasValue());
    EXPECT_EQ("descendant", chunk.Value().Value());
    EXPECT_TRUE(activated.Value().Close().HasValue());
    EXPECT_TRUE(leaf.Close().HasValue());
    EXPECT_EQ(0U, path.RetainedDescriptors());
}

TEST_F(PathAliasTest, MultipleCloseFailuresPreserveFirstAndLogSecondary)
{
    const std::string root = context.GetTempdirPath();
    const ResolverLimits limits{{4096, 128, 200000, 128, 262144, 4096}, 4096, 8, 128};
    auto opened = Path::AcquireRoot(context, root, RootPolicy{SymlinkPolicy::Reject, MountPolicy::AllowCrossing}, limits);
    ASSERT_TRUE(opened.HasValue());
    Path path = std::move(opened).Value();
    const std::size_t pins = path.RetainedDescriptors();
    ASSERT_GT(pins, 1U);
    const std::string logPath = root + "/pin-close.log";
    OsConfigLogHandle log = OpenLog(logPath.c_str(), nullptr);
    ASSERT_NE(nullptr, log);
    context.SetLogHandle(log);
    std::size_t attempts = 0;
    EXPECT_CALL(context, CloseFileDescriptor(_)).Times(pins).WillRepeatedly([&](int descriptor) {
        const std::size_t ordinal = attempts++;
        EXPECT_EQ(0, ::close(descriptor));
        if (ordinal == 0 || ordinal == 1)
        {
            errno = ordinal == 0 ? EACCES : EIO;
            return -1;
        }
        return 0;
    });
    auto closed = path.Close();
    ASSERT_FALSE(closed.HasValue());
    EXPECT_EQ(EACCES, closed.Error().code);
    EXPECT_EQ(pins, attempts);
    Path moved = std::move(path);
    EXPECT_TRUE(path.Close().HasValue());
    EXPECT_EQ(EACCES, moved.Close().Error().code);
    ASSERT_TRUE(testing::Mock::VerifyAndClearExpectations(&context));
    CloseLog(&log);
    context.SetLogHandle(nullptr);
    std::ifstream stream(logPath);
    ASSERT_TRUE(stream.is_open());
    const std::string text((std::istreambuf_iterator<char>(stream)), std::istreambuf_iterator<char>());
    const std::string secondary = "Secondary filesystem pin close failure: " + std::to_string(EIO);
    const auto at = text.find(secondary);
    ASSERT_NE(std::string::npos, at);
    EXPECT_EQ(std::string::npos, text.find(secondary, at + secondary.size()));
}

TEST_F(PathAliasTest, HandleCloseFailureAfterMoveNeverRetriesReusedDescriptor)
{
    const ResolverLimits limits{{4096, 128, 200000, 64, 262144, 4096}, 128, 2, 128};
    auto opened = Path::AcquireRoot(context, "/", RootPolicy{SymlinkPolicy::Reject, MountPolicy::AllowCrossing}, limits);
    ASSERT_TRUE(opened.HasValue());
    Path path = std::move(opened).Value();
    auto removed = path.Pop();
    ASSERT_TRUE(removed.HasValue());
    Handle leaf = std::move(removed).Value();
    EXPECT_EQ(1U, path.RetainedDescriptors());
    int reused = -1;
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
    auto failure = leaf.Close();
    ASSERT_FALSE(failure.HasValue());
    EXPECT_EQ(EIO, failure.Error().code);
    Handle moved = std::move(leaf);
    EXPECT_EQ(EIO, moved.Close().Error().code);
    EXPECT_TRUE(leaf.Close().HasValue());
    EXPECT_TRUE(path.Close().HasValue());
    EXPECT_EQ(0U, path.RetainedDescriptors());
    ASSERT_TRUE(testing::Mock::VerifyAndClearExpectations(&context));
    ASSERT_GE(reused, 0);
    EXPECT_GE(::fcntl(reused, F_GETFD), 0);
    EXPECT_EQ(0, ::close(reused));
}

TEST_F(PathAliasTest, MovedPathCachesFailedCloseWithoutClosingReusedDescriptor)
{
    const ResolverLimits limits{{4096, 128, 200000, 64, 262144, 4096}, 128, 2, 128};
    auto opened = Path::AcquireRoot(context, "/", RootPolicy{SymlinkPolicy::Reject, MountPolicy::AllowCrossing}, limits);
    ASSERT_TRUE(opened.HasValue());
    Path path = std::move(opened).Value();
    int reused = -1;
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
        errno = EACCES;
        return -1;
    });
    auto first = path.Close();
    ASSERT_FALSE(first.HasValue());
    EXPECT_EQ(EACCES, first.Error().code);
    Path moved = std::move(path);
    EXPECT_TRUE(path.Close().HasValue());
    EXPECT_EQ(EACCES, moved.Close().Error().code);
    ASSERT_TRUE(testing::Mock::VerifyAndClearExpectations(&context));
    ASSERT_GE(reused, 0);
    EXPECT_GE(::fcntl(reused, F_GETFD), 0);
    EXPECT_EQ(0, ::close(reused));
}

TEST_F(PathAliasTest, ActivationErrorRemainsPrimaryWhenCheckedCleanupFails)
{
    const std::string source = context.MakeTempfile("contents");
    const ResolverLimits limits{{4096, 128, 200000, 128, 262144, 4096}, 128, 2, 128};
    auto opened = Path::AcquireRoot(context, source, RootPolicy{SymlinkPolicy::Reject, MountPolicy::AllowCrossing}, limits, true);
    ASSERT_TRUE(opened.HasValue());
    Path path = std::move(opened).Value();
    const std::size_t pins = path.RetainedDescriptors();
    const std::string logPath = context.GetTempdirPath() + "/activation-cleanup.log";
    OsConfigLogHandle log = OpenLog(logPath.c_str(), nullptr);
    ASSERT_NE(nullptr, log);
    context.SetLogHandle(log);
    std::size_t attempts = 0;
    EXPECT_CALL(context, CloseFileDescriptor(_)).Times(pins).WillRepeatedly([&](int fd) {
        const std::size_t index = attempts++;
        EXPECT_EQ(0, ::close(fd));
        if (index == 0)
        {
            errno = EIO;
            return -1;
        }
        return 0;
    });
    // The consumer owns this precedence decision: keep the activation error
    // and record a subsequent release error, not a success-shaped fallback.
    auto activated = path.Leaf().OpenReadOnly(0);
    ASSERT_FALSE(activated.HasValue());
    auto primary = std::move(activated).Error();
    EXPECT_EQ(EINVAL, primary.code);
    auto cleanup = path.Close();
    ASSERT_FALSE(cleanup.HasValue());
    OsConfigLogError(context.GetLogHandle(), "Secondary acquisition cleanup failure: %d", cleanup.Error().code);
    EXPECT_EQ(EINVAL, primary.code);
    EXPECT_EQ(pins, attempts);
    ASSERT_TRUE(testing::Mock::VerifyAndClearExpectations(&context));
    CloseLog(&log);
    context.SetLogHandle(nullptr);
    std::ifstream stream(logPath);
    ASSERT_TRUE(stream.is_open());
    const std::string text((std::istreambuf_iterator<char>(stream)), std::istreambuf_iterator<char>());
    EXPECT_NE(std::string::npos, text.find("Secondary acquisition cleanup failure: " + std::to_string(EIO)));
}

TEST_F(PathAliasTest, MoveAssignmentTransfersFailedCloseAndReleasesReplacedPins)
{
    const ResolverLimits limits{{4096, 128, 200000, 64, 262144, 4096}, 128, 2, 128};
    auto first = Path::AcquireRoot(context, "/", RootPolicy{SymlinkPolicy::Reject, MountPolicy::AllowCrossing}, limits);
    auto second = Path::AcquireRoot(context, "/", RootPolicy{SymlinkPolicy::Reject, MountPolicy::AllowCrossing}, limits);
    ASSERT_TRUE(first.HasValue());
    ASSERT_TRUE(second.HasValue());
    const std::size_t before = CountOpenDescriptors();
    Path failed = std::move(first).Value();
    Path replaced = std::move(second).Value();
    EXPECT_CALL(context, CloseFileDescriptor(_))
        .Times(2)
        .WillOnce([](int fd) {
            EXPECT_EQ(0, ::close(fd));
            errno = EACCES;
            return -1;
        })
        .WillOnce([](int fd) { return ::close(fd); });
    EXPECT_EQ(EACCES, failed.Close().Error().code);
    replaced = std::move(failed);
    EXPECT_TRUE(failed.Close().HasValue());
    EXPECT_EQ(EACCES, replaced.Close().Error().code);
    ASSERT_TRUE(testing::Mock::VerifyAndClearExpectations(&context));
    EXPECT_EQ(before - 2, CountOpenDescriptors());
}

TEST_F(PathAliasTest, ThrowingCloseIsAttemptedOnlyOnceAndOtherPinsStillRelease)
{
    const ResolverLimits limits{{4096, 128, 200000, 128, 262144, 4096}, 128, 2, 128};
    auto opened = Path::AcquireRoot(context, context.GetTempdirPath(), RootPolicy{SymlinkPolicy::Reject, MountPolicy::AllowCrossing}, limits);
    ASSERT_TRUE(opened.HasValue());
    Path path = std::move(opened).Value();
    const std::size_t pins = path.RetainedDescriptors();
    ASSERT_GT(pins, 1U);
    const std::size_t before = CountOpenDescriptors();
    std::size_t attempted = 0;
    EXPECT_CALL(context, CloseFileDescriptor(_)).Times(pins).WillRepeatedly([&](int fd) {
        const auto index = attempted++;
        EXPECT_EQ(0, ::close(fd));
        if (index == 0)
        {
            throw std::runtime_error("injected post-close failure");
        }
        return 0;
    });
    EXPECT_EQ(EIO, path.Close().Error().code);
    EXPECT_EQ(EIO, path.Close().Error().code);
    EXPECT_EQ(pins, attempted);
    ASSERT_TRUE(testing::Mock::VerifyAndClearExpectations(&context));
    EXPECT_EQ(before - pins, CountOpenDescriptors());
}

TEST_F(PathAliasTest, FreshMetadataAndModeStayOnUnlinkedUnreadablePin)
{
    const std::string rootPath = context.GetTempdirPath() + "/accepted";
    ASSERT_EQ(0, ::mkdir(rootPath.c_str(), 0700));
    const std::string file = context.MakeTempfile("contents");
    ASSERT_EQ(0, ::rename(file.c_str(), (rootPath + "/target").c_str()));
    const ResolverLimits limits{{4096, 128, 200000, 128, 262144, 4096}, 128, 2, 128};
    const ExtensionPolicy strict{SymlinkPolicy::Reject, MountPolicy::StayOnRootMount, HardlinkPolicy::Permit};
    const std::size_t before = CountOpenDescriptors();
    {
        auto acquired = Path::AcquireRoot(context, rootPath, RootPolicy{SymlinkPolicy::Reject, MountPolicy::AllowCrossing}, limits);
        ASSERT_TRUE(acquired.HasValue()) << acquired.Error().message;
        Path path = std::move(acquired).Value();
        ASSERT_TRUE(path.Push("target", strict).HasValue());
        const std::string extraLink = rootPath + "/other-link";
        ASSERT_EQ(0, ::link((rootPath + "/target").c_str(), extraLink.c_str()));
        auto observed = path.Leaf().Stat(4096);
        ASSERT_TRUE(observed.HasValue()) << observed.Error().message;
        EXPECT_EQ(2U, observed.Value().st_nlink);
        ASSERT_EQ(0, ::unlink(extraLink.c_str()));
        auto changed = path.Leaf().Stat(4096);
        ASSERT_TRUE(changed.HasValue());
        EXPECT_EQ(1U, changed.Value().st_nlink);
        auto removed = path.Pop();
        ASSERT_TRUE(removed.HasValue());
        Handle detached = std::move(removed).Value();
        const ino_t originalInode = detached.Stat().st_ino;
        ASSERT_EQ(0, ::chmod((rootPath + "/target").c_str(), 0000));
        ASSERT_EQ(0, ::rename((rootPath + "/target").c_str(), (rootPath + "/former").c_str()));
        ASSERT_EQ(0, ::mkfifo((rootPath + "/target").c_str(), 0600));
        // No content-read activation is required to restore an owned 000 file.
        auto restored = detached.SetMode(0640, 4096);
        ASSERT_TRUE(restored.HasValue()) << restored.Error().message;
        auto fresh = detached.Stat(4096);
        ASSERT_TRUE(fresh.HasValue()) << fresh.Error().message;
        EXPECT_EQ(originalInode, fresh.Value().st_ino);
        EXPECT_EQ(0640, fresh.Value().st_mode & 07777);
        struct stat replacement = {};
        ASSERT_EQ(0, ::lstat((rootPath + "/target").c_str(), &replacement));
        EXPECT_TRUE(S_ISFIFO(replacement.st_mode));
        EXPECT_EQ(0600, replacement.st_mode & 07777);
        ASSERT_EQ(0, ::unlink((rootPath + "/former").c_str()));
        ASSERT_TRUE(detached.SetMode(0600, 4096).HasValue());
        auto unlinked = detached.Stat(4096);
        ASSERT_TRUE(unlinked.HasValue());
        EXPECT_EQ(0U, unlinked.Value().st_nlink);
        EXPECT_EQ(originalInode, unlinked.Value().st_ino);
        EXPECT_EQ(0600, unlinked.Value().st_mode & 07777);
    }
    EXPECT_EQ(before, CountOpenDescriptors());
}

TEST_F(PathAliasTest, DetachedOwnershipUsesPinWithoutChangingHostAccounts)
{
    const std::string rootPath = context.GetTempdirPath() + "/accepted";
    ASSERT_EQ(0, ::mkdir(rootPath.c_str(), 0700));
    const std::string file = context.MakeTempfile("contents");
    ASSERT_EQ(0, ::rename(file.c_str(), (rootPath + "/target").c_str()));
    const ResolverLimits limits{{4096, 128, 200000, 128, 262144, 4096}, 128, 2, 128};
    const ExtensionPolicy strict{SymlinkPolicy::Reject, MountPolicy::StayOnRootMount, HardlinkPolicy::Permit};
    const std::size_t before = CountOpenDescriptors();
    {
        auto detached = [&]() -> ComplianceEngine::Result<Handle> {
            auto acquired = Path::AcquireRoot(context, rootPath, RootPolicy{SymlinkPolicy::Reject, MountPolicy::AllowCrossing}, limits);
            if (!acquired.HasValue())
            {
                return std::move(acquired).Error();
            }
            Path path = std::move(acquired).Value();
            auto pushed = path.Push("target", strict);
            if (!pushed.HasValue())
            {
                return std::move(pushed).Error();
            }
            return path.Pop();
        }();
        ASSERT_TRUE(detached.HasValue()) << detached.Error().message;
        EXPECT_EQ(before + 1, CountOpenDescriptors());
        const auto original = detached.Value().Stat(4096);
        ASSERT_TRUE(original.HasValue());
        ASSERT_EQ(0, ::rename((rootPath + "/target").c_str(), (rootPath + "/former").c_str()));
        ASSERT_EQ(0, ::mkfifo((rootPath + "/target").c_str(), 0600));
        // -1/-1 leaves existing owner/group IDs untouched; no foreign ID or
        // host account is changed by this test.
        auto owned = detached.Value().SetOwnership(static_cast<uid_t>(-1), static_cast<gid_t>(-1), 4096);
        ASSERT_TRUE(owned.HasValue()) << owned.Error().message;
        auto updated = detached.Value().Stat(4096);
        ASSERT_TRUE(updated.HasValue());
        EXPECT_EQ(original.Value().st_uid, updated.Value().st_uid);
        EXPECT_EQ(original.Value().st_gid, updated.Value().st_gid);
        EXPECT_EQ(original.Value().st_ino, updated.Value().st_ino);
        struct stat replacement = {};
        ASSERT_EQ(0, ::lstat((rootPath + "/target").c_str(), &replacement));
        EXPECT_EQ(0600, replacement.st_mode & 07777);
        EXPECT_TRUE(S_ISFIFO(replacement.st_mode));
    }
    EXPECT_EQ(before, CountOpenDescriptors());
}

TEST_F(PathAliasTest, DetachedDirectoryModeDoesNotChangeReplacementRoot)
{
    const std::string rootPath = context.GetTempdirPath() + "/accepted";
    ASSERT_EQ(0, ::mkdir(rootPath.c_str(), 0700));
    const ResolverLimits limits{{4096, 128, 200000, 128, 262144, 4096}, 128, 2, 128};
    const std::size_t before = CountOpenDescriptors();
    {
        auto detached = [&]() -> ComplianceEngine::Result<Handle> {
            auto acquired = Path::AcquireRoot(context, rootPath, RootPolicy{SymlinkPolicy::Reject, MountPolicy::AllowCrossing}, limits);
            if (!acquired.HasValue())
            {
                return std::move(acquired).Error();
            }
            Path path = std::move(acquired).Value();
            return path.Pop();
        }();
        ASSERT_TRUE(detached.HasValue());
        ASSERT_EQ(0, ::rename(rootPath.c_str(), (rootPath + ".former").c_str()));
        ASSERT_EQ(0, ::mkdir(rootPath.c_str(), 0700));
        auto changed = detached.Value().SetMode(0750, 4096);
        ASSERT_TRUE(changed.HasValue()) << changed.Error().message;
        auto held = detached.Value().Stat(4096);
        ASSERT_TRUE(held.HasValue());
        EXPECT_TRUE(S_ISDIR(held.Value().st_mode));
        EXPECT_EQ(0750, held.Value().st_mode & 07777);
        struct stat replacement = {};
        ASSERT_EQ(0, ::stat(rootPath.c_str(), &replacement));
        EXPECT_EQ(0700, replacement.st_mode & 07777);
        EXPECT_NE(replacement.st_ino, held.Value().st_ino);
    }
    EXPECT_EQ(before, CountOpenDescriptors());
}

TEST_F(PathAliasTest, MetadataPreflightFailureMakesNoChangeAndPostcheckReportsPartialChange)
{
    const std::string file = context.MakeTempfile("contents");
    const std::string component = file.substr(file.find_last_of('/') + 1);
    const std::size_t before = CountOpenDescriptors();
    {
        auto opened = Path::AcquireRoot(context, context.GetTempdirPath(), RootPolicy{SymlinkPolicy::Reject, MountPolicy::AllowCrossing}, AmpleLimits());
        ASSERT_TRUE(opened.HasValue()) << opened.Error().message;
        Path path = std::move(opened).Value();
        ASSERT_TRUE(path.Push(component, ExtensionPolicy{SymlinkPolicy::Reject, MountPolicy::AllowCrossing, HardlinkPolicy::Permit}).HasValue());
        const Handle& pinned = path.Leaf();
        ASSERT_EQ(0, ::chmod(file.c_str(), 0600));
        auto shortInfo = pinned.SetMode(0400, 1);
        ASSERT_FALSE(shortInfo.HasValue());
        EXPECT_EQ(E2BIG, shortInfo.Error().code);
        auto noChown = pinned.SetOwnership(static_cast<uid_t>(-1), static_cast<gid_t>(-1), 1);
        ASSERT_FALSE(noChown.HasValue());
        EXPECT_EQ(E2BIG, noChown.Error().code);
        struct stat still = {};
        ASSERT_EQ(0, ::stat(file.c_str(), &still));
        EXPECT_EQ(0600, still.st_mode & 07777);
        const uid_t uid = still.st_uid;
        const gid_t gid = still.st_gid;

        bool reject = true;
        ON_CALL(context, StatFileDescriptor(_, _)).WillByDefault([&](int descriptor, struct stat* metadata) {
            const int status = context.ContextInterface::StatFileDescriptor(descriptor, metadata);
            if (reject && (0 == status) && (metadata->st_ino == still.st_ino) && (metadata->st_dev == still.st_dev))
            {
                errno = EIO;
                return -1;
            }
            return status;
        });
        auto invalidMode = pinned.SetMode(0400, 4096);
        ASSERT_FALSE(invalidMode.HasValue());
        EXPECT_EQ(EIO, invalidMode.Error().code);
        auto invalidOwner = pinned.SetOwnership(static_cast<uid_t>(-1), static_cast<gid_t>(-1), 4096);
        ASSERT_FALSE(invalidOwner.HasValue());
        EXPECT_EQ(EIO, invalidOwner.Error().code);
        ASSERT_EQ(0, ::stat(file.c_str(), &still));
        EXPECT_EQ(0600, still.st_mode & 07777);
        EXPECT_EQ(uid, still.st_uid);
        EXPECT_EQ(gid, still.st_gid);

        reject = false;
        std::size_t matchingStats = 0;
        ON_CALL(context, StatFileDescriptor(_, _)).WillByDefault([&](int descriptor, struct stat* metadata) {
            const int status = context.ContextInterface::StatFileDescriptor(descriptor, metadata);
            if ((0 == status) && (metadata->st_ino == still.st_ino) && (metadata->st_dev == still.st_dev) && (++matchingStats == 6))
            {
                errno = EIO; // First post-chmod pin inspection.
                return -1;
            }
            return status;
        });
        auto partial = pinned.SetMode(0400, 4096);
        ASSERT_FALSE(partial.HasValue());
        EXPECT_EQ(EIO, partial.Error().code);
        EXPECT_EQ(6U, matchingStats);
        ASSERT_EQ(0, ::stat(file.c_str(), &still));
        EXPECT_EQ(0400, still.st_mode & 07777);
    }
    EXPECT_EQ(before, CountOpenDescriptors());
}

TEST_F(PathAliasTest, DeniedOwnershipAndModeSyscallsLeaveHeldAndReplacementObjectsUnchanged)
{
    const std::string rootPath = context.GetTempdirPath() + "/accepted";
    ASSERT_EQ(0, ::mkdir(rootPath.c_str(), 0700));
    const std::string file = context.MakeTempfile("contents");
    ASSERT_EQ(0, ::rename(file.c_str(), (rootPath + "/target").c_str()));
    ASSERT_EQ(0, ::chmod((rootPath + "/target").c_str(), 0600));
    const ResolverLimits limits{{4096, 128, 200000, 128, 262144, 4096}, 128, 2, 128};
    const ExtensionPolicy strict{SymlinkPolicy::Reject, MountPolicy::StayOnRootMount, HardlinkPolicy::Permit};
    const std::size_t before = CountOpenDescriptors();
    {
        auto acquired = Path::AcquireRoot(context, rootPath, RootPolicy{SymlinkPolicy::Reject, MountPolicy::AllowCrossing}, limits);
        ASSERT_TRUE(acquired.HasValue()) << acquired.Error().message;
        Path path = std::move(acquired).Value();
        ASSERT_TRUE(path.Push("target", strict).HasValue());
        const std::size_t heldDescriptors = CountOpenDescriptors();
        struct stat held = {}, replacement = {};
        ASSERT_EQ(0, ::stat((rootPath + "/target").c_str(), &held));
        ASSERT_EQ(0, ::rename((rootPath + "/target").c_str(), (rootPath + "/former").c_str()));
        ASSERT_EQ(0, ::mkfifo((rootPath + "/target").c_str(), 0600));
        ASSERT_EQ(0, ::lstat((rootPath + "/target").c_str(), &replacement));

        int pinnedDescriptor = -1;
        EXPECT_CALL(context, StatFileDescriptor(_, _)).Times(2); // Preflight only; no postcheck after denied syscall.
        EXPECT_CALL(context, OpenExistingFile(_, _)).Times(0);
        EXPECT_CALL(context, ChownPinnedFileDescriptor(_, static_cast<uid_t>(-1), static_cast<gid_t>(-1))).Times(1).WillOnce([&](int descriptor, uid_t, gid_t) {
            pinnedDescriptor = descriptor;
            struct stat seen = {};
            EXPECT_EQ(0, ::fstat(descriptor, &seen));
            EXPECT_EQ(held.st_ino, seen.st_ino);
            EXPECT_EQ(held.st_dev, seen.st_dev);
            errno = EPERM; // The actual mutation syscall is denied; no host account is changed.
            return -1;
        });
        auto deniedOwner = path.Leaf().SetOwnership(static_cast<uid_t>(-1), static_cast<gid_t>(-1), 4096);
        ASSERT_FALSE(deniedOwner.HasValue());
        EXPECT_EQ(EPERM, deniedOwner.Error().code);
        EXPECT_TRUE(testing::Mock::VerifyAndClearExpectations(&context));
        EXPECT_EQ(heldDescriptors, CountOpenDescriptors());

        EXPECT_CALL(context, StatFileDescriptor(_, _)).Times(5); // Pin, alias, retained pin; no postcheck.
        EXPECT_CALL(context, OpenExistingFile(_, _)).Times(0);
        EXPECT_CALL(context, ChmodPinnedAlias(_, _, 0400)).Times(1).WillOnce([&](int procfsDirectory, const char* alias, mode_t) {
            struct stat directory = {}, pin = {};
            EXPECT_EQ(0, ::fstat(procfsDirectory, &directory));
            EXPECT_TRUE(S_ISDIR(directory.st_mode));
            EXPECT_GE(pinnedDescriptor, 0);
            EXPECT_EQ(0, ::fstat(pinnedDescriptor, &pin));
            EXPECT_EQ(held.st_ino, pin.st_ino);
            EXPECT_EQ(std::to_string(pinnedDescriptor), std::string(alias));
            errno = EACCES; // Deny exactly fchmodat, not alias acquisition or inspection.
            return -1;
        });
        auto deniedMode = path.Leaf().SetMode(0400, 4096);
        ASSERT_FALSE(deniedMode.HasValue());
        EXPECT_EQ(EACCES, deniedMode.Error().code);
        EXPECT_TRUE(testing::Mock::VerifyAndClearExpectations(&context));
        EXPECT_EQ(heldDescriptors, CountOpenDescriptors());

        auto stillPinned = path.Leaf().Stat(4096);
        ASSERT_TRUE(stillPinned.HasValue()) << stillPinned.Error().message;
        EXPECT_EQ(held.st_ino, stillPinned.Value().st_ino);
        EXPECT_EQ(held.st_uid, stillPinned.Value().st_uid);
        EXPECT_EQ(held.st_gid, stillPinned.Value().st_gid);
        EXPECT_EQ(held.st_mode & 07777, stillPinned.Value().st_mode & 07777);
        struct stat stillOriginal = {}, stillReplacement = {};
        ASSERT_EQ(0, ::stat((rootPath + "/former").c_str(), &stillOriginal));
        ASSERT_EQ(0, ::lstat((rootPath + "/target").c_str(), &stillReplacement));
        EXPECT_EQ(held.st_ino, stillOriginal.st_ino);
        EXPECT_EQ(held.st_uid, stillOriginal.st_uid);
        EXPECT_EQ(held.st_gid, stillOriginal.st_gid);
        EXPECT_EQ(held.st_mode & 07777, stillOriginal.st_mode & 07777);
        EXPECT_TRUE(S_ISFIFO(stillReplacement.st_mode));
        EXPECT_EQ(replacement.st_ino, stillReplacement.st_ino);
        EXPECT_EQ(replacement.st_mode & 07777, stillReplacement.st_mode & 07777);
    }
    EXPECT_EQ(before, CountOpenDescriptors());
}

TEST_F(PathAliasTest, InspectionFailureClosesAcquiredDescriptorWithoutHidingPrimaryError)
{
    const std::string source = context.MakeTempfile("contents");
    const std::string component = source.substr(source.find_last_of('/') + 1);
    auto opened = Path::AcquireRoot(context, context.GetTempdirPath(), RootPolicy{SymlinkPolicy::Reject, MountPolicy::AllowCrossing}, AmpleLimits());
    ASSERT_TRUE(opened.HasValue());
    Path path = std::move(opened).Value();
    struct stat target = {};
    ASSERT_EQ(0, ::stat(source.c_str(), &target));
    const std::size_t before = CountOpenDescriptors();
    ON_CALL(context, StatFileDescriptor(_, _)).WillByDefault([&](int descriptor, struct stat* metadata) {
        if ((0 == ::fstat(descriptor, metadata)) && (metadata->st_ino == target.st_ino) && (metadata->st_dev == target.st_dev))
        {
            errno = EIO;
            return -1;
        }
        return context.ContextInterface::StatFileDescriptor(descriptor, metadata);
    });
    const auto failed = path.Push(component, ExtensionPolicy{SymlinkPolicy::Reject, MountPolicy::AllowCrossing, HardlinkPolicy::Permit});
    ASSERT_FALSE(failed.HasValue());
    EXPECT_EQ(EIO, failed.Error().code);
    EXPECT_EQ(before, CountOpenDescriptors());
}

TEST_F(PathAliasTest, AliasStaysOnPinnedFileAfterNameReplacementAndUnlink)
{
    const std::string source = context.MakeTempfile("original bytes");
    OwnedTestDescriptor pinned(::open(source.c_str(), O_PATH | O_NOFOLLOW | O_CLOEXEC));
    ASSERT_GE(pinned.Get(), 0);
    struct stat original = {};
    ASSERT_EQ(0, ::fstat(pinned.Get(), &original));
    const std::size_t before = CountOpenDescriptors();
    {
        ASSERT_EQ(0, ::rename(source.c_str(), (source + ".former").c_str()));
        ASSERT_EQ(0, ::mkfifo(source.c_str(), 0600));

        // Opening the original name would block on this substituted FIFO;
        // descriptor-alias activation must instead bind to the prior inode.
        auto active = ComplianceEngine::Filesystem::Detail::ActivateReadOnly(context, pinned.Get(), original, false, 4096);
        ASSERT_TRUE(active.HasValue()) << active.Error().message;
        EXPECT_EQ(original.st_ino, active.Value().Snapshot().st_ino);
        EXPECT_EQ(original.st_dev, active.Value().Snapshot().st_dev);
        char bytes[15] = {};
        ASSERT_EQ(14, ::read(active.Value().Descriptor(), bytes, 14));
        EXPECT_EQ("original bytes", std::string(bytes, 14));

        ASSERT_EQ(0, ::unlink((source + ".former").c_str()));
        auto again = ComplianceEngine::Filesystem::Detail::ActivateReadOnly(context, pinned.Get(), original, false, 4096);
        ASSERT_TRUE(again.HasValue()) << again.Error().message;
        EXPECT_EQ(original.st_ino, again.Value().Snapshot().st_ino);
    }
    EXPECT_EQ(before, CountOpenDescriptors());
}

TEST_F(PathAliasTest, DirectoryAliasAndMovesRetainSingleOwnership)
{
    const std::string directory = context.GetTempdirPath() + "/acquired";
    ASSERT_EQ(0, ::mkdir(directory.c_str(), 0700));
    OwnedTestDescriptor pinned(::open(directory.c_str(), O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
    ASSERT_GE(pinned.Get(), 0);
    struct stat original = {};
    ASSERT_EQ(0, ::fstat(pinned.Get(), &original));
    const std::size_t before = CountOpenDescriptors();
    {
        auto active = ComplianceEngine::Filesystem::Detail::ActivateReadOnly(context, pinned.Get(), original, true, 4096);
        ASSERT_TRUE(active.HasValue()) << active.Error().message;
        EXPECT_EQ(original.st_ino, active.Value().Snapshot().st_ino);
        ComplianceEngine::Filesystem::Detail::ReadOnlyActivation transferred = std::move(active).Value();
        EXPECT_EQ(original.st_ino, transferred.Snapshot().st_ino);
    }
    EXPECT_EQ(before, CountOpenDescriptors());
}

TEST_F(PathAliasTest, UnsupportedTypesAndInvalidNamesDoNotActivate)
{
    auto opened = Path::AcquireRoot(context, context.GetTempdirPath(), RootPolicy{SymlinkPolicy::Reject, MountPolicy::AllowCrossing}, AmpleLimits());
    ASSERT_TRUE(opened.HasValue());
    Path path = std::move(opened).Value();
    const ExtensionPolicy strict{SymlinkPolicy::Reject, MountPolicy::AllowCrossing, HardlinkPolicy::Permit};
    const std::size_t before = CountOpenDescriptors();
    const std::string special = context.GetTempdirPath() + "/special";
    ASSERT_EQ(0, ::mkfifo(special.c_str(), 0600));
    const auto fifo = path.Push("special", strict);
    ASSERT_FALSE(fifo.HasValue());
    EXPECT_EQ(EOPNOTSUPP, fifo.Error().code);
    const auto invalid = path.Push("../special", strict);
    ASSERT_FALSE(invalid.HasValue());
    EXPECT_EQ(EINVAL, invalid.Error().code);
    const auto nul = path.Push(std::string("x\0y", 3), strict);
    ASSERT_FALSE(nul.HasValue());
    EXPECT_EQ(EINVAL, nul.Error().code);
    ASSERT_EQ(0, ::symlink("special", (special + ".link").c_str()));
    const auto link = path.Push("special.link", strict);
    ASSERT_FALSE(link.HasValue());
    EXPECT_EQ(ELOOP, link.Error().code);
    EXPECT_EQ(before, CountOpenDescriptors());
}

TEST_F(PathAliasTest, FdinfoCapFailsClosedAndCleansUp)
{
    const std::string source = context.MakeTempfile("a");
    OwnedTestDescriptor pinned(::open(source.c_str(), O_PATH | O_NOFOLLOW | O_CLOEXEC));
    ASSERT_GE(pinned.Get(), 0);
    struct stat snapshot = {};
    ASSERT_EQ(0, ::fstat(pinned.Get(), &snapshot));
    const std::size_t before = CountOpenDescriptors();
    {
        auto tooSmall = ComplianceEngine::Filesystem::Detail::ActivateReadOnly(context, pinned.Get(), snapshot, false, 1);
        ASSERT_FALSE(tooSmall.HasValue());
        EXPECT_EQ(E2BIG, tooSmall.Error().code);
        auto invalid = ComplianceEngine::Filesystem::Detail::ActivateReadOnly(context, pinned.Get(), snapshot, false, 0);
        ASSERT_FALSE(invalid.HasValue());
        EXPECT_EQ(EINVAL, invalid.Error().code);
    }
    EXPECT_EQ(before, CountOpenDescriptors());
}

TEST_F(PathAliasTest, FdinfoReadOverreportRejectsActualRequestAndClosesHelpers)
{
    const std::size_t before = CountOpenDescriptors();
    {
        const std::string source = context.MakeTempfile("a");
        OwnedTestDescriptor pinned(::open(source.c_str(), O_PATH | O_NOFOLLOW | O_CLOEXEC));
        ASSERT_GE(pinned.Get(), 0);
        struct stat snapshot = {};
        ASSERT_EQ(0, ::fstat(pinned.Get(), &snapshot));
        const std::size_t withPin = CountOpenDescriptors();
        for (const std::size_t cap : {4096U, 1U})
        {
            const std::size_t requested = (4096U == cap) ? 256U : 2U;
            std::size_t overreports = 0;
            std::set<int> closed;
            EXPECT_CALL(context, ReadFileDescriptor(_, _, _)).WillRepeatedly([&](int descriptor, void* buffer, std::size_t size) -> ssize_t {
                const std::string target = DescriptorTarget(descriptor);
                if ((0 == target.find("/proc/")) && (std::string::npos != target.find("/fdinfo/")))
                {
                    EXPECT_EQ(requested, size);
                    ++overreports;
                    return static_cast<ssize_t>(size + 1); // No write: even an overreported count cannot be read from buffer.
                }
                return context.ContextInterface::ReadFileDescriptor(descriptor, buffer, size);
            });
            EXPECT_CALL(context, CloseFileDescriptor(_)).WillRepeatedly([&](int descriptor) {
                EXPECT_TRUE(closed.insert(descriptor).second);
                return context.ContextInterface::CloseFileDescriptor(descriptor);
            });
            auto activated = ComplianceEngine::Filesystem::Detail::ActivateReadOnly(context, pinned.Get(), snapshot, false, cap);
            ASSERT_FALSE(activated.HasValue());
            EXPECT_EQ(EIO, activated.Error().code);
            EXPECT_EQ(1U, overreports);
            EXPECT_EQ(6U, closed.size()); // fdinfo file and all five verified procfs directories.
            EXPECT_EQ(withPin, CountOpenDescriptors());
            ASSERT_TRUE(testing::Mock::VerifyAndClearExpectations(&context));
        }
        EXPECT_GE(::fcntl(pinned.Get(), F_GETFD), 0);
    }
    EXPECT_EQ(before, CountOpenDescriptors());
}

TEST_F(PathAliasTest, ActivationPerformsReadPermissionCheck)
{
    if (0 == ::geteuid())
    {
        GTEST_SKIP() << "Privileged processes may open mode-000 files";
    }
    const std::string source = context.MakeTempfile("restricted");
    OwnedTestDescriptor pinned(::open(source.c_str(), O_PATH | O_NOFOLLOW | O_CLOEXEC));
    ASSERT_GE(pinned.Get(), 0);
    struct stat snapshot = {};
    ASSERT_EQ(0, ::fstat(pinned.Get(), &snapshot));
    ASSERT_EQ(0, ::chmod(source.c_str(), 0000));
    auto denied = ComplianceEngine::Filesystem::Detail::ActivateReadOnly(context, pinned.Get(), snapshot, false, 4096);
    ASSERT_FALSE(denied.HasValue());
    EXPECT_EQ(EACCES, denied.Error().code);
    EXPECT_EQ(0, ::chmod(source.c_str(), 0600));
}

TEST_F(PathAliasTest, PinnedRelativeAndAbsoluteLinksIgnoreReplacementNames)
{
    const std::string link = context.GetTempdirPath() + "/relative.link";
    ASSERT_EQ(0, ::symlink("../target", link.c_str()));
    OwnedTestDescriptor relative(::open(link.c_str(), O_PATH | O_NOFOLLOW | O_CLOEXEC));
    ASSERT_GE(relative.Get(), 0);
    const std::size_t before = CountOpenDescriptors();
    ASSERT_EQ(0, ::unlink(link.c_str()));
    ASSERT_EQ(0, ::symlink("/etc/passwd", link.c_str()));
    auto target = ReadPinnedLink(context, relative.Get(), 128, 4096);
    ASSERT_TRUE(target.HasValue()) << target.Error().message;
    EXPECT_EQ("../target", target.Value().text);
    EXPECT_GT(target.Value().mountId, 0U);
    auto tooSmall = ReadPinnedLink(context, relative.Get(), 8, 4096);
    ASSERT_FALSE(tooSmall.HasValue());
    EXPECT_EQ(E2BIG, tooSmall.Error().code);
    EXPECT_EQ(before, CountOpenDescriptors());

    OwnedTestDescriptor absolute(::open(link.c_str(), O_PATH | O_NOFOLLOW | O_CLOEXEC));
    ASSERT_GE(absolute.Get(), 0);
    auto absoluteTarget = ReadPinnedLink(context, absolute.Get(), 128, 4096);
    ASSERT_TRUE(absoluteTarget.HasValue()) << absoluteTarget.Error().message;
    EXPECT_EQ("/etc/passwd", absoluteTarget.Value().text);
}

TEST_F(PathAliasTest, ProcfsMagicLinkCannotEnterManualResolver)
{
    OwnedTestDescriptor magic(::open("/proc/self/exe", O_PATH | O_NOFOLLOW | O_CLOEXEC));
    ASSERT_GE(magic.Get(), 0);
    auto denied = ReadPinnedLink(context, magic.Get(), 4096, 4096);
    ASSERT_FALSE(denied.HasValue());
    EXPECT_EQ(ELOOP, denied.Error().code);
}

TEST_F(PathAliasTest, AcceptedRootRecognitionUsesHeldIdentityNotCandidateName)
{
    const std::string rootName = context.GetTempdirPath() + "/accepted";
    ASSERT_EQ(0, ::mkdir(rootName.c_str(), 0700));
    const ResolverLimits limits = AmpleLimits();
    const std::size_t before = CountOpenDescriptors();
    {
        auto accepted = Path::AcquireRoot(context, rootName, RootPolicy{SymlinkPolicy::Reject, MountPolicy::AllowCrossing}, limits);
        auto matching = Path::AcquireRoot(context, rootName, RootPolicy{SymlinkPolicy::Reject, MountPolicy::AllowCrossing}, limits);
        ASSERT_TRUE(accepted.HasValue());
        ASSERT_TRUE(matching.HasValue());
        EXPECT_EQ(accepted.Value().Root().Stat().st_ino, matching.Value().Root().Stat().st_ino);

        ASSERT_EQ(0, ::rename(rootName.c_str(), (rootName + ".former").c_str()));
        ASSERT_EQ(0, ::mkdir(rootName.c_str(), 0700));
        auto replacement = Path::AcquireRoot(context, rootName, RootPolicy{SymlinkPolicy::Reject, MountPolicy::AllowCrossing}, limits);
        ASSERT_TRUE(replacement.HasValue());
        EXPECT_NE(accepted.Value().Root().Stat().st_ino, replacement.Value().Root().Stat().st_ino);
        EXPECT_EQ(accepted.Value().Root().Stat().st_ino, matching.Value().Root().Stat().st_ino);
    }
    EXPECT_EQ(before, CountOpenDescriptors());
}
