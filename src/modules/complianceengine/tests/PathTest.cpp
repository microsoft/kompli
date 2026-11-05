// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <DescriptorTestAccess.h>
#include <MockContext.h>
#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <filesystem/FilesystemHelpers.hpp>
#include <filesystem/Handle.hpp>
#include <filesystem/Path.hpp>
#include <filesystem/ProcfsDescriptorAccess.hpp>
#include <filesystem/ReadableFile.hpp>
#include <fstream>
#include <gtest/gtest.h>
#include <iterator>
#include <limits>
#include <linux/magic.h>
#include <memory>
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
#include <vector>

using ComplianceEngine::As;
using ComplianceEngine::InPlaceType;
using ComplianceEngine::Variant;
using ComplianceEngine::Filesystem::DirectoryLinkPolicy;
using ComplianceEngine::Filesystem::FileLinkPolicy;
using ComplianceEngine::Filesystem::MountPolicy;
using ComplianceEngine::Filesystem::Path;
using ComplianceEngine::Filesystem::PrefixLinkPolicy;
using ComplianceEngine::Filesystem::ResolverLimits;
using ComplianceEngine::Filesystem::Type;
using ComplianceEngine::Filesystem::Detail::Descriptor;
using ComplianceEngine::Filesystem::Detail::Handle;
using ComplianceEngine::Filesystem::Detail::ParseMountId;
using ComplianceEngine::Tests::DescriptorTestAccess;
using testing::_;
using testing::NiceMock;

namespace
{
std::string ReadLog(const std::string& path)
{
    std::ifstream log(path);
    EXPECT_TRUE(log.is_open());
    return {std::istreambuf_iterator<char>(log), std::istreambuf_iterator<char>()};
}
void ExpectLoggedOnce(const std::string& text, const std::string& entry)
{
    const auto at = text.find(entry);
    ASSERT_NE(std::string::npos, at);
    EXPECT_EQ(std::string::npos, text.find(entry, at + entry.size()));
}

Path::Policy CrossMountPathPolicy(bool following = false)
{
    Path::Policy policy;
    policy.prefixLinks = following ? PrefixLinkPolicy::Follow : PrefixLinkPolicy::Reject;
    policy.mounts = MountPolicy::CrossMounts;
    policy.fileLinks = following ? FileLinkPolicy::Follow : FileLinkPolicy::Reject;
    policy.directoryLinks = following ? DirectoryLinkPolicy::Follow : DirectoryLinkPolicy::Reject;
    return policy;
}

// Change only the mock fdinfo record, never the native mount namespace.
void AlterFdinfoMountId(void* buffer, ssize_t bytes)
{
    const std::string record(static_cast<const char*>(buffer), static_cast<std::size_t>(bytes));
    const auto at = record.find("mnt_id:");
    ASSERT_NE(std::string::npos, at);
    auto digit = record.find_first_of("0123456789", at + 7);
    ASSERT_NE(std::string::npos, digit);
    static_cast<char*>(buffer)[digit] = record[digit] == '9' ? '8' : '9';
}

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
        ResolverLimits limits;
        limits.shared.components = 100;
        limits.shared.retainedBytes = 262144;
        limits.linkExpansions = 8;
        return limits;
    }
};

using ComplianceEngine::Filesystem::Detail::IsSingleChildComponent;
ComplianceEngine::Result<Path> SelectAcceptedPath(const ComplianceEngine::ContextInterface& context, const std::string& path, Path::Policy policy, ResolverLimits limits)
{
    auto selected = Path::Make(context, path, policy, limits);
    if (!selected.HasValue())
        return std::move(selected).Error();
    if (!selected.Value().Is<Path>())
        return ComplianceEngine::Error("Fixture path unavailable", ENOENT);
    Path accepted = As<Path>(std::move(selected.Value()));
    auto frozen = accepted.Freeze();
    if (!frozen.HasValue())
        return std::move(frozen).Error();
    return accepted;
}
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

ComplianceEngine::Result<Path::Step> SelectStep(const Path& path, const std::string& name, Path::Policy policy);

// TM-9: the mount baseline is the frozen leaf, not the process-root pin.
void CheckRealBindMounts(const NiceMock<MockContext>& context, const std::string& accepted)
{
    auto opened = SelectAcceptedPath(context, accepted, CrossMountPathPolicy(), ResolverLimits{});
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
    ASSERT_TRUE(outerId.HasValue());
    ASSERT_TRUE(rootId.HasValue());
    ASSERT_TRUE(childId.HasValue());
    EXPECT_NE(outerId.Value(), rootId.Value());
    EXPECT_NE(rootId.Value(), childId.Value());
    EXPECT_EQ(rootId.Value(), path.Leaf().Acquired().targetMount.value);
    auto stay = CrossMountPathPolicy();
    stay.mounts = MountPolicy::StayOnRootMount;
    auto inside = SelectStep(path, "inside", stay);
    ASSERT_TRUE(inside.HasValue()) << inside.Error().message;
    auto denied = path.Resolve("cross", stay);
    ASSERT_FALSE(denied.HasValue());
    EXPECT_EQ(EXDEV, denied.Error().code);
    const auto depth = path.Size();
    auto crossingStep = SelectStep(path, "cross", CrossMountPathPolicy());
    ASSERT_TRUE(crossingStep.HasValue()) << crossingStep.Error().message;
    EXPECT_EQ(depth, path.Size());
    auto inverse = path.Apply(std::move(crossingStep.Value()));
    ASSERT_TRUE(inverse.HasValue()) << inverse.Error().message;
    EXPECT_EQ(childId.Value(), path.Leaf().Acquired().targetMount.value);
    auto payloadStep = SelectStep(path, "payload", CrossMountPathPolicy());
    ASSERT_TRUE(payloadStep.HasValue()) << payloadStep.Error().message;
    auto readable = payloadStep.Value().Target().OpenReadOnly();
    ASSERT_TRUE(readable.HasValue()) << readable.Error().message;
    auto data = readable.Value().Read(32);
    ASSERT_TRUE(data.HasValue());
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

TEST_F(PathAliasTest, ComponentCopiesRetainPinUntilLastShareRetires)
{
    const std::string root = context.GetTempdirPath() + "/shared-component";
    ASSERT_EQ(0, ::mkdir(root.c_str(), 0700));
    const auto before = CountOpenDescriptors();
    std::unique_ptr<Path::Component> first;
    std::unique_ptr<Path::Component> second;
    {
        auto opened = SelectAcceptedPath(context, root, CrossMountPathPolicy(), AmpleLimits());
        ASSERT_TRUE(opened.HasValue());
        Path path = std::move(opened).Value();
        const auto charged = path.RetainedDescriptors();
        first.reset(new Path::Component(path.Leaf()));
        second.reset(new Path::Component(*first));
        EXPECT_EQ(charged, path.RetainedDescriptors());
        EXPECT_EQ(before + charged, CountOpenDescriptors());
    }
    EXPECT_EQ(before + 1, CountOpenDescriptors()); // only detached leaf remains
    first.reset();
    ASSERT_TRUE(second->Stat().HasValue());
    EXPECT_EQ(before + 1, CountOpenDescriptors());
    second.reset();
    EXPECT_EQ(before, CountOpenDescriptors());
}

TEST_F(PathAliasTest, ProcessRootNativeOpenFailuresReturnErrorsWithoutLeaks)
{
    const auto before = CountOpenDescriptors();
    EXPECT_CALL(context, OpenNativePath(testing::StrEq("/"), _)).WillOnce([](const char*, int) {
        errno = EACCES;
        return -1;
    });
    auto denied = SelectAcceptedPath(context, "/", CrossMountPathPolicy(), AmpleLimits());
    ASSERT_FALSE(denied.HasValue());
    EXPECT_EQ(EACCES, denied.Error().code);
    ASSERT_TRUE(testing::Mock::VerifyAndClearExpectations(&context));
    EXPECT_CALL(context, OpenNativePath(testing::StrEq("/"), _)).WillOnce([](const char*, int) {
        errno = EIO;
        return -1;
    });
    auto failed = SelectAcceptedPath(context, "/", CrossMountPathPolicy(), AmpleLimits());
    ASSERT_FALSE(failed.HasValue());
    EXPECT_EQ(EIO, failed.Error().code);
    EXPECT_EQ(before, CountOpenDescriptors());
}

TEST_F(PathAliasTest, TypedOpenAndDuplicateSetCloseOnExecAtomically)
{
    EXPECT_CALL(context, OpenNativePath(_, _)).WillOnce([&](const char* path, int flags) {
        EXPECT_EQ((O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC), flags);
        return context.RealOpenNativePath(path, flags);
    });
    auto opened = DescriptorTestAccess::OpenAbsolutePin(context, "/");
    ASSERT_TRUE(opened.HasValue());
    Descriptor owner = std::move(opened).Value();
    EXPECT_NE(0, DescriptorTestAccess::DescriptorFlags(context, owner) & FD_CLOEXEC);
    EXPECT_CALL(context, DuplicateDescriptor(_)).WillOnce([&](int fd) {
        const int duplicated = context.RealDuplicateDescriptor(fd);
        EXPECT_NE(-1, duplicated);
        if (duplicated >= 0)
            EXPECT_NE(0, ::fcntl(duplicated, F_GETFD) & FD_CLOEXEC);
        return duplicated;
    });
    auto duplicate = DescriptorTestAccess::Duplicate(context, owner);
    ASSERT_TRUE(duplicate.HasValue());
    EXPECT_NE(0, DescriptorTestAccess::DescriptorFlags(context, duplicate.Value()) & FD_CLOEXEC);
}

TEST_F(PathAliasTest, DirectoryActivationTransfersVerifiedOwnerWithoutDuplicate)
{
    int alias = -1;
    bool closedStream = false;
    auto opened = SelectAcceptedPath(context, context.GetTempdirPath(), CrossMountPathPolicy(), AmpleLimits());
    ASSERT_TRUE(opened.HasValue());
    auto path = std::unique_ptr<Path>(new Path(std::move(opened).Value()));
    opened = ComplianceEngine::Error("Release transferred source wrapper", EINVAL);
    const auto pins = path->RetainedDescriptors();
    const auto before = CountOpenDescriptors();
    EXPECT_CALL(context, OpenNativeAt(_, _, _)).WillRepeatedly([&](int directory, const char* name, int flags) {
        const int descriptor = context.RealOpenNativeAt(directory, name, flags);
        if ((0 <= descriptor) && (0 == (flags & O_PATH)) && (0 == (flags & O_NOFOLLOW)) && (0 != (flags & O_DIRECTORY)))
        {
            alias = descriptor;
        }
        return descriptor;
    });
    EXPECT_CALL(context, CloseFileDescriptor(_)).WillRepeatedly([&](int descriptor) {
        EXPECT_NE(descriptor, alias);
        const int status = ::close(descriptor);
        EXPECT_EQ(0, status);
        return status;
    });
    EXPECT_CALL(context, CloseDirectory(_)).WillOnce([&](DIR* stream) {
        closedStream = true;
        return ::closedir(stream);
    });
    auto cursor = path->Leaf().OpenChildren();
    ASSERT_TRUE(cursor.HasValue()) << cursor.Error().message;
    path.reset(); // the original snapshot, not merely a move-as-copy, retires here
    EXPECT_TRUE(cursor.Value().Next().HasValue());
    cursor.Value().Close();
    EXPECT_TRUE(closedStream);
    EXPECT_EQ(before - pins, CountOpenDescriptors());
    ASSERT_TRUE(testing::Mock::VerifyAndClearExpectations(&context));
}

TEST_F(PathAliasTest, FailedDirectoryTransferPreservesNativeErrorAndClosesOwnerOnce)
{
    int operational = -1;
    int cleanupAttempts = 0;
    auto opened = SelectAcceptedPath(context, context.GetTempdirPath(), CrossMountPathPolicy(), AmpleLimits());
    ASSERT_TRUE(opened.HasValue()) << opened.Error().message;
    Path path = std::move(opened).Value();
    EXPECT_CALL(context, FdOpenDirectory(_)).Times(1).WillOnce([&](int descriptor) -> DIR* {
        operational = descriptor;
        errno = EACCES;
        return nullptr;
    });
    EXPECT_CALL(context, CloseFileDescriptor(_)).WillRepeatedly([&](int descriptor) {
        EXPECT_EQ(0, ::close(descriptor));
        if (descriptor == operational)
        {
            ++cleanupAttempts;
            errno = EIO;
            return -1;
        }
        return 0;
    });
    auto cursor = path.Leaf().OpenChildren();
    ASSERT_FALSE(cursor.HasValue());
    EXPECT_EQ(EACCES, cursor.Error().code);
    EXPECT_EQ(1, cleanupAttempts);
    {
        Path retired(std::move(path));
    }
    EXPECT_EQ(1, cleanupAttempts);
}

TEST_F(PathAliasTest, DirectoryCursorFailedCloseIsNotReplayedOrRetried)
{
    const std::string logPath = context.GetTempdirPath() + "/cursor-close.log";
    OsConfigLogHandle log = OpenLog(logPath.c_str(), nullptr);
    ASSERT_NE(nullptr, log);
    context.SetLogHandle(log);
    auto opened = SelectAcceptedPath(context, context.GetTempdirPath(), CrossMountPathPolicy(), AmpleLimits());
    ASSERT_TRUE(opened.HasValue());
    Path path = std::move(opened).Value();
    const auto before = CountOpenDescriptors();
    auto cursor = path.Leaf().OpenChildren();
    ASSERT_TRUE(cursor.HasValue());
    EXPECT_CALL(context, CloseDirectory(_)).Times(1).WillOnce([](DIR* stream) {
        EXPECT_EQ(0, ::closedir(stream));
        errno = EIO;
        return -1;
    });
    cursor.Value().Close();
    cursor.Value().Close();
    auto moved = std::move(cursor).Value();
    moved.Close();
    EXPECT_EQ(before, CountOpenDescriptors());
    CloseLog(&log);
    context.SetLogHandle(nullptr);
    ExpectLoggedOnce(ReadLog(logPath), "Cannot close pinned directory cursor: " + std::to_string(EIO));
}

TEST_F(PathAliasTest, DirectoryCursorNativeCloseErrorAndReplacementReleaseOnce)
{
    auto opened = SelectAcceptedPath(context, context.GetTempdirPath(), CrossMountPathPolicy(), AmpleLimits());
    ASSERT_TRUE(opened.HasValue());
    Path path = std::move(opened).Value();
    auto first = path.Leaf().OpenChildren();
    auto second = path.Leaf().OpenChildren();
    ASSERT_TRUE(first.HasValue());
    ASSERT_TRUE(second.HasValue());
    const auto before = CountOpenDescriptors();
    EXPECT_CALL(context, CloseDirectory(_))
        .Times(2)
        .WillOnce([](DIR* stream) -> int {
            EXPECT_EQ(0, ::closedir(stream));
            errno = EIO;
            return -1;
        })
        .WillOnce([](DIR* stream) { return ::closedir(stream); });
    first.Value() = std::move(second.Value()); // displaced owner closes inside its guarded destructor
    second.Value().Close();
    // The transferred stream still owns the second, live directory.
    first.Value().Close();
    EXPECT_EQ(before - 2, CountOpenDescriptors());
    ASSERT_TRUE(testing::Mock::VerifyAndClearExpectations(&context));
    auto third = path.Leaf().OpenChildren();
    ASSERT_TRUE(third.HasValue());
    EXPECT_CALL(context, CloseDirectory(_)).Times(1).WillOnce([](DIR* stream) -> int {
        EXPECT_EQ(0, ::closedir(stream));
        errno = EIO;
        return -1;
    });
    EXPECT_NO_THROW(third.Value().Close());
    third.Value().Close();
    {
        Path retired(std::move(path));
    }
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
    auto opened = SelectAcceptedPath(selected, selected.GetTempdirPath(), CrossMountPathPolicy(), AmpleLimits());
    ASSERT_TRUE(opened.HasValue());
    Path path = std::move(opened).Value();
    auto cursor = path.Leaf().OpenChildren();
    ASSERT_TRUE(cursor.HasValue());
    EXPECT_CALL(selected, CloseDirectory(_)).Times(1).WillOnce([](DIR* stream) {
        EXPECT_EQ(0, ::closedir(stream));
        errno = EACCES;
        return -1;
    });
    EXPECT_NO_THROW(cursor.Value().Close());
    EXPECT_EQ(1, selected.logRequests);
    cursor.Value().Close();
    {
        Path retired(std::move(path));
    }
}

TEST_F(PathAliasTest, WrongObjectProcfdAliasesAreRejectedBeforeMutation)
{
    const std::string file = context.MakeTempfile("held");
    const std::string other = context.MakeTempfile("different");
    auto opened = SelectAcceptedPath(context, file, CrossMountPathPolicy(), AmpleLimits());
    ASSERT_TRUE(opened.HasValue()) << opened.Error().message;
    Path path = std::move(opened).Value();
    int substituted = 0;
    EXPECT_CALL(context, OpenNativeAt(_, _, _)).WillRepeatedly([&](int directory, const char* name, int flags) {
        const std::string parent = DescriptorTarget(directory);
        if (parent.find("/fd") != std::string::npos && parent.find("/fdinfo") == std::string::npos &&
            std::string(name).find_first_not_of("0123456789") == std::string::npos)
        {
            ++substituted;
            return context.RealOpenNativePath(other.c_str(), flags);
        }
        return context.RealOpenNativeAt(directory, name, flags);
    });
    auto read = path.Leaf().OpenReadOnly();
    ASSERT_FALSE(read.HasValue());
    EXPECT_EQ(EAGAIN, read.Error().code);
    EXPECT_CALL(context, ChmodPinnedAlias(_, _, _)).Times(0);
    auto changed = path.Leaf().SetMode(0400);
    ASSERT_FALSE(changed.HasValue());
    EXPECT_EQ(EAGAIN, changed.Error().code);
    EXPECT_EQ(2, substituted);
    struct stat after = {};
    ASSERT_EQ(0, ::stat(file.c_str(), &after));
    EXPECT_NE(0400, after.st_mode & 0777);
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

template <typename T, typename = void>
struct HasPublicNativeAdoption : std::false_type
{
};
template <typename T>
struct HasPublicNativeAdoption<T, std::void_t<decltype(T::Take(std::declval<const ComplianceEngine::ContextInterface&>(), 3))>> : std::true_type
{
};

TEST(PathTest, DoesNotOfferUncheckedDescriptorConstructionOrCopy)
{
    static_assert(!std::is_constructible<Descriptor, int>::value, "Native adoption is private to acquisition owners");
    static_assert(!HasPublicNativeAdoption<Descriptor>::value, "Raw native ownership adoption cannot be public");
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

TEST_F(PathAliasTest, InitialRootRetainedHeadroomHasExactBoundary)
{
    ResolverLimits limits = AmpleLimits();
    auto baseline = Path::Make(context, "/", CrossMountPathPolicy(), limits);
    ASSERT_TRUE(baseline.HasValue()) << baseline.Error().message;
    ASSERT_TRUE(baseline.Value().Is<Path>());
    // The acquisition ledger includes the root spelling and the full
    // process-root entry footprint; bootstrap must reserve that entire total.
    const std::size_t exactBudget = As<Path>(baseline.Value()).RetainedBytes();
    ASSERT_LE(exactBudget, limits.shared.retainedBytes);
    limits.shared.retainedBytes = exactBudget - 1;
    auto insufficient = Path::Make(context, "/", CrossMountPathPolicy(), limits);
    ASSERT_FALSE(insufficient.HasValue());
    EXPECT_EQ(E2BIG, insufficient.Error().code);
    EXPECT_EQ("Root exceeds retained-memory budget", insufficient.Error().message);

    limits.shared.retainedBytes = exactBudget;
    auto exact = Path::Make(context, "/", CrossMountPathPolicy(), limits);
    ASSERT_TRUE(exact.HasValue()) << exact.Error().message;
    ASSERT_TRUE(exact.Value().Is<Path>());
    EXPECT_EQ(exactBudget, As<Path>(exact.Value()).RetainedBytes());
    EXPECT_LE(As<Path>(exact.Value()).RetainedBytes(), limits.shared.retainedBytes);
}

TEST_F(PathAliasTest, InitialRootWorkChargePrecedesRetainedHeadroomAndFreezeHasNoCharge)
{
    ResolverLimits limits = AmpleLimits();
    // Default fdinfoBytes=4096: 128 + 4 * ceil(4096 / 256) = 192.
    ASSERT_EQ(4096u, limits.shared.fdinfoBytes);
    limits.shared.work = 191;
    limits.shared.retainedBytes = 1; // both checks fail; work must win before native acquisition
    EXPECT_CALL(context, OpenNativePath(_, _)).Times(0);
    auto shortWork = Path::Make(context, "/", CrossMountPathPolicy(), limits);
    ASSERT_FALSE(shortWork.HasValue());
    EXPECT_EQ(E2BIG, shortWork.Error().code);
    EXPECT_EQ("Path work budget exhausted", shortWork.Error().message);
    testing::Mock::VerifyAndClearExpectations(&context);
    limits.shared.work = 192;
    limits.shared.retainedBytes = AmpleLimits().shared.retainedBytes;
    auto exact = Path::Make(context, "/", CrossMountPathPolicy(), limits);
    ASSERT_TRUE(exact.HasValue()) << exact.Error().message;
    ASSERT_TRUE(exact.Value().Is<Path>());
    Path root = As<Path>(std::move(exact.Value()));
    auto frozen = root.Freeze();
    ASSERT_TRUE(frozen.HasValue());
    EXPECT_FALSE(frozen.Value());
    EXPECT_EQ(1u, root.Size());
}

TEST_F(PathAliasTest, FactoryAcquisitionErrorOutranksCloseFailureAndLogsPath)
{
    const std::string requested = context.MakeTempfile("not-a-directory") + "/";
    const std::string logPath = context.GetTempdirPath() + "/factory-acquisition-close.log";
    OsConfigLogHandle log = OpenLog(logPath.c_str(), nullptr);
    ASSERT_NE(nullptr, log);
    context.SetLogHandle(log);
    struct stat root = {};
    ASSERT_EQ(0, ::stat("/", &root));
    int rootCloses = 0;
    EXPECT_CALL(context, CloseFileDescriptor(_)).WillRepeatedly([&](int fd) {
        struct stat held = {};
        const bool rootPin = ::fstat(fd, &held) == 0 && held.st_dev == root.st_dev && held.st_ino == root.st_ino;
        const int result = context.RealCloseFileDescriptor(fd);
        if (rootPin)
        {
            ++rootCloses;
            errno = EACCES;
            return -1;
        }
        return result;
    });

    auto opened = Path::Make(context, requested, CrossMountPathPolicy(), AmpleLimits());
    ASSERT_FALSE(opened.HasValue());
    EXPECT_EQ(ENOTDIR, opened.Error().code);
    EXPECT_EQ(1, rootCloses);
    CloseLog(&log);
    context.SetLogHandle(nullptr);
    std::ifstream contents(logPath);
    ASSERT_TRUE(contents.is_open());
    const std::string text((std::istreambuf_iterator<char>(contents)), std::istreambuf_iterator<char>());
    EXPECT_NE(std::string::npos, text.find("Cannot close internal filesystem descriptor: " + std::to_string(EACCES)));
}

TEST_F(PathAliasTest, ActivationErrorRemainsPrimaryWhenDiagnosticCleanupFails)
{
    const std::string source = context.MakeTempfile("contents");
    ResolverLimits limits;
    limits.shared.targetBytes = 4096;
    limits.shared.components = 128;
    limits.shared.work = 200000;
    limits.shared.liveDescriptors = 128;
    limits.shared.retainedBytes = 262144;
    limits.shared.fdinfoBytes = 4096;
    limits.linkTargetBytes = 128;
    limits.linkExpansions = 2;
    limits.depth = 128;
    std::size_t attempts = 0;
    auto opened = SelectAcceptedPath(context, source, CrossMountPathPolicy(), limits);
    ASSERT_TRUE(opened.HasValue());
    auto path = std::unique_ptr<Path>(new Path(std::move(opened).Value()));
    opened = ComplianceEngine::Error("Release transferred source wrapper", EINVAL);
    const std::size_t pins = path->RetainedDescriptors();
    const std::string logPath = context.GetTempdirPath() + "/activation-cleanup.log";
    OsConfigLogHandle log = OpenLog(logPath.c_str(), nullptr);
    ASSERT_NE(nullptr, log);
    context.SetLogHandle(log);
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
    EXPECT_CALL(context, StatFileDescriptor(_, _)).Times(1).WillOnce([](int, struct stat*) {
        errno = EINVAL;
        return -1;
    });
    auto activated = path->Leaf().OpenReadOnly();
    ASSERT_FALSE(activated.HasValue());
    auto primary = std::move(activated).Error();
    EXPECT_EQ(EINVAL, primary.code);
    {
        path.reset();
    }
    EXPECT_EQ(EINVAL, primary.code);
    EXPECT_EQ(pins, attempts);
    ASSERT_TRUE(testing::Mock::VerifyAndClearExpectations(&context));
    CloseLog(&log);
    context.SetLogHandle(nullptr);
    std::ifstream stream(logPath);
    ASSERT_TRUE(stream.is_open());
    const std::string text((std::istreambuf_iterator<char>(stream)), std::istreambuf_iterator<char>());
    EXPECT_NE(std::string::npos, text.find("Cannot close internal filesystem descriptor: " + std::to_string(EIO)));
}

TEST_F(PathAliasTest, AliasStaysOnPinnedFileAfterNameReplacementAndUnlink)
{
    const std::string source = context.MakeTempfile("original bytes");
    auto opened = DescriptorTestAccess::OpenAbsolutePin(context, source.c_str(), false);
    ASSERT_TRUE(opened.HasValue());
    Descriptor pinned = std::move(opened).Value();
    struct stat original = {};
    ASSERT_EQ(0, DescriptorTestAccess::StatFile(context, pinned, &original));
    const std::size_t before = CountOpenDescriptors();
    {
        ASSERT_EQ(0, ::rename(source.c_str(), (source + ".former").c_str()));
        ASSERT_EQ(0, ::mkfifo(source.c_str(), 0600));

        // Opening the original name would block on this substituted FIFO;
        // descriptor-alias activation must instead bind to the prior inode.
        auto active = DescriptorTestAccess::ActivateReadOnly(context, pinned, original, false, 4096);
        ASSERT_TRUE(active.HasValue()) << active.Error().message;
        struct stat activated = {};
        ASSERT_EQ(0, DescriptorTestAccess::StatFile(context, active.Value(), &activated));
        EXPECT_EQ(original.st_ino, activated.st_ino);
        EXPECT_EQ(original.st_dev, activated.st_dev);
        char bytes[15] = {};
        Descriptor reader = std::move(active).Value();
        ASSERT_EQ(14, DescriptorTestAccess::ReadFile(context, reader, bytes, 14));
        EXPECT_EQ("original bytes", std::string(bytes, 14));

        ASSERT_EQ(0, ::unlink((source + ".former").c_str()));
        auto again = DescriptorTestAccess::ActivateReadOnly(context, pinned, original, false, 4096);
        ASSERT_TRUE(again.HasValue()) << again.Error().message;
        struct stat reacquired = {};
        ASSERT_EQ(0, DescriptorTestAccess::StatFile(context, again.Value(), &reacquired));
        EXPECT_EQ(original.st_ino, reacquired.st_ino);
    }
    EXPECT_EQ(before, CountOpenDescriptors());
}

TEST_F(PathAliasTest, DirectoryAliasAndMovesRetainSingleOwnership)
{
    const std::string directory = context.GetTempdirPath() + "/acquired";
    ASSERT_EQ(0, ::mkdir(directory.c_str(), 0700));
    auto opened = DescriptorTestAccess::OpenAbsolutePin(context, directory.c_str());
    ASSERT_TRUE(opened.HasValue());
    Descriptor pinned = std::move(opened).Value();
    struct stat original = {};
    ASSERT_EQ(0, DescriptorTestAccess::StatFile(context, pinned, &original));
    const std::size_t before = CountOpenDescriptors();
    {
        auto active = DescriptorTestAccess::ActivateReadOnly(context, pinned, original, true, 4096);
        ASSERT_TRUE(active.HasValue()) << active.Error().message;
        struct stat activated = {};
        ASSERT_EQ(0, DescriptorTestAccess::StatFile(context, active.Value(), &activated));
        EXPECT_EQ(original.st_ino, activated.st_ino);
        Descriptor transferred = std::move(active).Value();
        ASSERT_EQ(0, DescriptorTestAccess::StatFile(context, transferred, &activated));
        EXPECT_EQ(original.st_ino, activated.st_ino);
    }
    EXPECT_EQ(before, CountOpenDescriptors());
}

TEST_F(PathAliasTest, ActivationHandsOffOwnerWithoutRetryingFailedClose)
{
    const std::string file = context.MakeTempfile("activation");
    auto opened = DescriptorTestAccess::OpenAbsolutePin(context, file.c_str(), false);
    ASSERT_TRUE(opened.HasValue());
    Descriptor pin = std::move(opened).Value();
    struct stat snapshot = {};
    ASSERT_EQ(0, DescriptorTestAccess::StatFile(context, pin, &snapshot));
    const auto before = CountOpenDescriptors();
    {
        auto activated = DescriptorTestAccess::ActivateReadOnly(context, pin, snapshot, false, 4096);
        ASSERT_TRUE(activated.HasValue()) << activated.Error().message;
        pin.Close();
        EXPECT_CALL(context, CloseFileDescriptor(_)).Times(1).WillOnce([](int descriptor) {
            EXPECT_EQ(0, ::close(descriptor));
            errno = EIO;
            return -1;
        });
        Descriptor owner = std::move(activated).Value();
        EXPECT_FALSE(DescriptorTestAccess::ConsumedDescriptor(activated.Value()) != -1);
        EXPECT_TRUE(DescriptorTestAccess::ConsumedDescriptor(owner) != -1);
        owner.Close();
        EXPECT_FALSE(DescriptorTestAccess::ConsumedDescriptor(owner) != -1);
        owner.Close();
    }
    EXPECT_EQ(before - 1, CountOpenDescriptors());
}

TEST_F(PathAliasTest, FdinfoCapFailsClosedAndCleansUp)
{
    const std::string source = context.MakeTempfile("a");
    auto opened = DescriptorTestAccess::OpenAbsolutePin(context, source.c_str(), false);
    ASSERT_TRUE(opened.HasValue());
    Descriptor pinned = std::move(opened).Value();
    struct stat snapshot = {};
    ASSERT_EQ(0, DescriptorTestAccess::StatFile(context, pinned, &snapshot));
    const std::size_t before = CountOpenDescriptors();
    {
        auto tooSmall = DescriptorTestAccess::ActivateReadOnly(context, pinned, snapshot, false, 1);
        ASSERT_FALSE(tooSmall.HasValue());
        EXPECT_EQ(E2BIG, tooSmall.Error().code);
        auto invalid = DescriptorTestAccess::ActivateReadOnly(context, pinned, snapshot, false, 0);
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
        std::size_t overreports = 0;
        std::set<int> live;
        std::size_t acquired = 0, closed = 0, peak = 0;
        auto opened = DescriptorTestAccess::OpenAbsolutePin(context, source.c_str(), false);
        ASSERT_TRUE(opened.HasValue());
        Descriptor pinned = std::move(opened).Value();
        struct stat snapshot = {};
        ASSERT_EQ(0, DescriptorTestAccess::StatFile(context, pinned, &snapshot));
        const std::size_t withPin = CountOpenDescriptors();
        for (const std::size_t cap : {4096U, 1U})
        {
            const std::size_t requested = (4096U == cap) ? 256U : 2U;
            overreports = 0;
            live.clear();
            acquired = closed = peak = 0;
            EXPECT_CALL(context, OpenNativePath(_, _)).WillRepeatedly([&](const char* path, int flags) {
                const int descriptor = context.RealOpenNativePath(path, flags);
                if (descriptor >= 0)
                {
                    EXPECT_TRUE(live.insert(descriptor).second);
                    ++acquired;
                    peak = std::max(peak, live.size());
                }
                return descriptor;
            });
            EXPECT_CALL(context, OpenNativeAt(_, _, _)).WillRepeatedly([&](int directory, const char* name, int flags) {
                const int descriptor = context.RealOpenNativeAt(directory, name, flags);
                if (descriptor >= 0)
                {
                    EXPECT_TRUE(live.insert(descriptor).second);
                    ++acquired;
                    peak = std::max(peak, live.size());
                }
                return descriptor;
            });
            EXPECT_CALL(context, ReadFileDescriptor(_, _, _)).WillRepeatedly([&](int descriptor, void* buffer, std::size_t size) -> ssize_t {
                const std::string target = DescriptorTarget(descriptor);
                if ((0 == target.find("/proc/")) && (std::string::npos != target.find("/fdinfo/")))
                {
                    EXPECT_EQ(requested, size);
                    ++overreports;
                    return static_cast<ssize_t>(size + 1); // No write: even an overreported count cannot be read from buffer.
                }
                return context.RealReadFileDescriptor(descriptor, buffer, size);
            });
            EXPECT_CALL(context, CloseFileDescriptor(_)).WillRepeatedly([&](int descriptor) {
                EXPECT_EQ(1U, live.erase(descriptor));
                ++closed;
                return context.RealCloseFileDescriptor(descriptor);
            });
            auto activated = DescriptorTestAccess::ActivateReadOnly(context, pinned, snapshot, false, cap);
            ASSERT_FALSE(activated.HasValue());
            EXPECT_EQ(EIO, activated.Error().code);
            EXPECT_EQ(1U, overreports);
            EXPECT_EQ(8U, acquired); // fdinfo file and seven bootstrap/role directories.
            EXPECT_EQ(acquired, closed);
            EXPECT_TRUE(live.empty());
            EXPECT_LE(peak, 5U); // Two retained procfs roles plus at most three helper/reader pins.
            EXPECT_EQ(withPin, CountOpenDescriptors());
            ASSERT_TRUE(testing::Mock::VerifyAndClearExpectations(&context));
        }
        EXPECT_GE(DescriptorTestAccess::DescriptorFlags(context, pinned), 0);
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
    auto opened = DescriptorTestAccess::OpenAbsolutePin(context, source.c_str(), false);
    ASSERT_TRUE(opened.HasValue());
    Descriptor pinned = std::move(opened).Value();
    struct stat snapshot = {};
    ASSERT_EQ(0, DescriptorTestAccess::StatFile(context, pinned, &snapshot));
    ASSERT_EQ(0, ::chmod(source.c_str(), 0000));
    auto denied = DescriptorTestAccess::ActivateReadOnly(context, pinned, snapshot, false, 4096);
    ASSERT_FALSE(denied.HasValue());
    EXPECT_EQ(EACCES, denied.Error().code);
    EXPECT_EQ(0, ::chmod(source.c_str(), 0600));
}

TEST_F(PathAliasTest, PinnedRelativeAndAbsoluteLinksIgnoreReplacementNames)
{
    const std::string link = context.GetTempdirPath() + "/relative.link";
    ASSERT_EQ(0, ::symlink("../target", link.c_str()));
    auto relativeResult = DescriptorTestAccess::OpenAbsolutePin(context, link.c_str(), false);
    ASSERT_TRUE(relativeResult.HasValue());
    Descriptor relative = std::move(relativeResult).Value();
    const std::size_t before = CountOpenDescriptors();
    ASSERT_EQ(0, ::unlink(link.c_str()));
    ASSERT_EQ(0, ::symlink("/etc/passwd", link.c_str()));
    auto target = DescriptorTestAccess::ReadPinnedLink(relative, 128, 4096);
    ASSERT_TRUE(target.HasValue()) << target.Error().message;
    EXPECT_EQ("../target", target.Value().text);
    EXPECT_GT(target.Value().mountId, 0U);
    auto tooSmall = DescriptorTestAccess::ReadPinnedLink(relative, 8, 4096);
    ASSERT_FALSE(tooSmall.HasValue());
    EXPECT_EQ(E2BIG, tooSmall.Error().code);
    EXPECT_EQ(before, CountOpenDescriptors());

    auto absoluteResult = DescriptorTestAccess::OpenAbsolutePin(context, link.c_str(), false);
    ASSERT_TRUE(absoluteResult.HasValue());
    Descriptor absolute = std::move(absoluteResult).Value();
    auto absoluteTarget = DescriptorTestAccess::ReadPinnedLink(absolute, 128, 4096);
    ASSERT_TRUE(absoluteTarget.HasValue()) << absoluteTarget.Error().message;
    EXPECT_EQ("/etc/passwd", absoluteTarget.Value().text);
}

TEST_F(PathAliasTest, ProcfsMagicLinkCannotEnterManualResolver)
{
    auto opened = DescriptorTestAccess::OpenAbsolutePin(context, "/proc/self/exe", false);
    ASSERT_TRUE(opened.HasValue());
    Descriptor magic = std::move(opened).Value();
    auto denied = DescriptorTestAccess::ReadPinnedLink(magic, 4096, 4096);
    ASSERT_FALSE(denied.HasValue());
    EXPECT_EQ(ELOOP, denied.Error().code);
}

TEST_F(PathAliasTest, PinnedLinkRejectsEmptyNulAndNonLinkWithoutConsumingPin)
{
    const std::string link = context.GetTempdirPath() + "/bounded.link";
    ASSERT_EQ(0, ::symlink("target", link.c_str()));
    auto opened = DescriptorTestAccess::OpenAbsolutePin(context, link.c_str(), false);
    ASSERT_TRUE(opened.HasValue());
    Descriptor pin = std::move(opened).Value();
    const std::size_t before = CountOpenDescriptors();
    EXPECT_CALL(context, ReadLinkDescriptor(_, _, _)).WillOnce([](int, char*, std::size_t) -> ssize_t { return 0; }).WillOnce([](int, char* buffer, std::size_t) -> ssize_t {
        std::memcpy(buffer, "a\0b", 3);
        return 3;
    });
    auto empty = DescriptorTestAccess::ReadPinnedLink(pin, 16, 4096);
    ASSERT_FALSE(empty.HasValue());
    EXPECT_EQ(E2BIG, empty.Error().code);
    auto nul = DescriptorTestAccess::ReadPinnedLink(pin, 16, 4096);
    ASSERT_FALSE(nul.HasValue());
    EXPECT_EQ(EINVAL, nul.Error().code);
    EXPECT_EQ(before, CountOpenDescriptors());
    ASSERT_TRUE(testing::Mock::VerifyAndClearExpectations(&context));
    auto valid = DescriptorTestAccess::ReadPinnedLink(pin, 16, 4096);
    ASSERT_TRUE(valid.HasValue()) << valid.Error().message;
    EXPECT_EQ("target", valid.Value().text);

    const std::string file = context.MakeTempfile("ordinary");
    auto regular = DescriptorTestAccess::OpenAbsolutePin(context, file.c_str(), false);
    ASSERT_TRUE(regular.HasValue());
    auto denied = DescriptorTestAccess::ReadPinnedLink(regular.Value(), 16, 4096);
    ASSERT_FALSE(denied.HasValue());
    EXPECT_EQ(ELOOP, denied.Error().code);
}

TEST_F(PathAliasTest, PinnedLinkReadRechecksIdentityAndMount)
{
    const std::string link = context.GetTempdirPath() + "/observed.link";
    ASSERT_EQ(0, ::symlink("target", link.c_str()));
    auto opened = DescriptorTestAccess::OpenAbsolutePin(context, link.c_str(), false);
    ASSERT_TRUE(opened.HasValue());
    Descriptor pin = std::move(opened).Value();
    const std::size_t before = CountOpenDescriptors();

    int observations = 0;
    EXPECT_CALL(context, StatFileDescriptor(_, _)).WillRepeatedly([&](int fd, struct stat* snapshot) {
        const int status = context.RealStatFileDescriptor(fd, snapshot);
        if (status == 0 && S_ISLNK(snapshot->st_mode) && ++observations == 2)
            ++snapshot->st_ino;
        return status;
    });
    auto changed = DescriptorTestAccess::ReadPinnedLink(pin, 16, 4096);
    ASSERT_FALSE(changed.HasValue());
    EXPECT_EQ(EAGAIN, changed.Error().code);
    EXPECT_EQ(2, observations);
    ASSERT_TRUE(testing::Mock::VerifyAndClearExpectations(&context));

    int records = 0;
    EXPECT_CALL(context, ReadFileDescriptor(_, _, _)).WillRepeatedly([&](int fd, void* buffer, std::size_t size) {
        const ssize_t bytes = context.RealReadFileDescriptor(fd, buffer, size);
        if (bytes > 0 && DescriptorTarget(fd).find("/fdinfo/") != std::string::npos &&
            std::string(static_cast<char*>(buffer), static_cast<std::size_t>(bytes)).find("mnt_id:") != std::string::npos && ++records == 2)
            AlterFdinfoMountId(buffer, bytes);
        return bytes;
    });
    auto mount = DescriptorTestAccess::ReadPinnedLink(pin, 16, 4096);
    ASSERT_FALSE(mount.HasValue());
    EXPECT_EQ(EAGAIN, mount.Error().code);
    EXPECT_EQ(2, records);
    EXPECT_EQ(before, CountOpenDescriptors());
}

TEST_F(PathAliasTest, PinnedLinkReadFailsClosedOnMountAndStatObservationErrors)
{
    const std::string link = context.GetTempdirPath() + "/fault.link";
    ASSERT_EQ(0, ::symlink("target", link.c_str()));
    auto opened = DescriptorTestAccess::OpenAbsolutePin(context, link.c_str(), false);
    ASSERT_TRUE(opened.HasValue());
    Descriptor pin = std::move(opened).Value();
    const std::size_t before = CountOpenDescriptors();

    bool failedMount = false;
    EXPECT_CALL(context, ReadLinkDescriptor(_, _, _)).Times(0);
    EXPECT_CALL(context, ReadFileDescriptor(_, _, _)).WillRepeatedly([&](int fd, void* buffer, std::size_t size) {
        if (!failedMount && DescriptorTarget(fd).find("/fdinfo/") != std::string::npos)
        {
            failedMount = true;
            errno = ENOSPC;
            return static_cast<ssize_t>(-1);
        }
        return context.RealReadFileDescriptor(fd, buffer, size);
    });
    auto mount = DescriptorTestAccess::ReadPinnedLink(pin, 16, 4096);
    ASSERT_FALSE(mount.HasValue());
    EXPECT_EQ(ENOSPC, mount.Error().code);
    EXPECT_TRUE(failedMount);
    ASSERT_TRUE(testing::Mock::VerifyAndClearExpectations(&context));

    int observations = 0;
    EXPECT_CALL(context, StatFileDescriptor(_, _)).WillRepeatedly([&](int fd, struct stat* snapshot) {
        const int status = context.RealStatFileDescriptor(fd, snapshot);
        if (status == 0 && S_ISLNK(snapshot->st_mode) && ++observations == 2)
        {
            errno = EIO;
            return -1;
        }
        return status;
    });
    auto stat = DescriptorTestAccess::ReadPinnedLink(pin, 16, 4096);
    ASSERT_FALSE(stat.HasValue());
    EXPECT_EQ(EIO, stat.Error().code);
    EXPECT_EQ(2, observations);
    EXPECT_EQ(before, CountOpenDescriptors());
}

TEST_F(PathAliasTest, PinnedLinkReadErrorOutranksHelperCloseFailure)
{
    const std::string link = context.GetTempdirPath() + "/failing.link";
    ASSERT_EQ(0, ::symlink("target", link.c_str()));
    bool failedRead = false;
    bool failedClose = false;
    auto opened = DescriptorTestAccess::OpenAbsolutePin(context, link.c_str(), false);
    ASSERT_TRUE(opened.HasValue());
    Descriptor pin = std::move(opened).Value();
    const std::size_t before = CountOpenDescriptors();
    EXPECT_CALL(context, ReadLinkDescriptor(_, _, _)).WillOnce([&](int, char*, std::size_t) -> ssize_t {
        failedRead = true;
        errno = ENOSPC;
        return -1;
    });
    EXPECT_CALL(context, CloseFileDescriptor(_)).WillRepeatedly([&](int fd) {
        const bool helper = IsProcfsHelper(fd);
        const int status = ::close(fd);
        EXPECT_EQ(0, status);
        if (helper && failedRead && !failedClose)
        {
            failedClose = true;
            errno = EIO;
            return -1;
        }
        return status;
    });
    auto failure = DescriptorTestAccess::ReadPinnedLink(pin, 16, 4096);
    ASSERT_FALSE(failure.HasValue());
    EXPECT_EQ(ENOSPC, failure.Error().code);
    EXPECT_TRUE(failedRead);
    EXPECT_TRUE(failedClose);
    EXPECT_EQ(before, CountOpenDescriptors());
}

TEST_F(PathAliasTest, PinnedLinkSuccessfulReadReportsHelperCloseFailure)
{
    const std::string link = context.GetTempdirPath() + "/close.link";
    ASSERT_EQ(0, ::symlink("target", link.c_str()));
    bool read = false, failedClose = false;
    auto opened = DescriptorTestAccess::OpenAbsolutePin(context, link.c_str(), false);
    ASSERT_TRUE(opened.HasValue());
    Descriptor pin = std::move(opened).Value();
    const std::size_t before = CountOpenDescriptors();
    EXPECT_CALL(context, ReadLinkDescriptor(_, _, _)).WillOnce([&](int fd, char* buffer, std::size_t size) {
        read = true;
        return ::readlinkat(fd, "", buffer, size);
    });
    EXPECT_CALL(context, CloseFileDescriptor(_)).WillRepeatedly([&](int fd) {
        const bool helper = IsProcfsHelper(fd);
        const int status = ::close(fd);
        EXPECT_EQ(0, status);
        if (helper && read && !failedClose)
        {
            failedClose = true;
            errno = EIO;
            return -1;
        }
        return status;
    });
    auto acquired = DescriptorTestAccess::ReadPinnedLink(pin, 16, 4096);
    ASSERT_TRUE(acquired.HasValue());
    EXPECT_EQ("target", acquired.Value().text);
    EXPECT_TRUE(read);
    EXPECT_TRUE(failedClose);
    EXPECT_EQ(before, CountOpenDescriptors());
}

TEST_F(PathAliasTest, AcceptedRootRecognitionUsesHeldIdentityNotCandidateName)
{
    const std::string rootName = context.GetTempdirPath() + "/accepted";
    ASSERT_EQ(0, ::mkdir(rootName.c_str(), 0700));
    const ResolverLimits limits = AmpleLimits();
    const std::size_t before = CountOpenDescriptors();
    {
        auto accepted = SelectAcceptedPath(context, rootName, CrossMountPathPolicy(), limits);
        auto matching = SelectAcceptedPath(context, rootName, CrossMountPathPolicy(), limits);
        ASSERT_TRUE(accepted.HasValue());
        ASSERT_TRUE(matching.HasValue());
        EXPECT_EQ(accepted.Value().Leaf().Acquired().metadata.st_ino, matching.Value().Leaf().Acquired().metadata.st_ino);

        ASSERT_EQ(0, ::rename(rootName.c_str(), (rootName + ".former").c_str()));
        ASSERT_EQ(0, ::mkdir(rootName.c_str(), 0700));
        auto replacement = SelectAcceptedPath(context, rootName, CrossMountPathPolicy(), limits);
        ASSERT_TRUE(replacement.HasValue());
        EXPECT_NE(accepted.Value().Leaf().Acquired().metadata.st_ino, replacement.Value().Leaf().Acquired().metadata.st_ino);
        EXPECT_EQ(accepted.Value().Leaf().Acquired().metadata.st_ino, matching.Value().Leaf().Acquired().metadata.st_ino);
    }
    EXPECT_EQ(before, CountOpenDescriptors());
}

// TM-9: physical root, barrier, and inverse are acquisition properties,
// never a lexical normalization of names or an open-by-name replay.
ComplianceEngine::Result<Path::Step> SelectStep(const Path& path, const std::string& name, Path::Policy policy)
{
    auto outcome = path.Resolve(name, policy);
    if (!outcome.HasValue())
        return std::move(outcome).Error();
    if (!outcome.Value().Is<Path::Step>())
        return ComplianceEngine::Error("Fixture child rejected", ENOENT);
    return As<Path::Step>(std::move(outcome.Value()));
}

TEST_F(PathAliasTest, PhysicalRootNeverEmptyAndMovesLeaveBothPathSnapshotsUsable)
{
    auto root = SelectAcceptedPath(context, "/", CrossMountPathPolicy(), AmpleLimits());
    ASSERT_TRUE(root.HasValue());
    Path processRoot = std::move(root).Value();
    EXPECT_EQ(1u, processRoot.Size());
    EXPECT_EQ("/", processRoot.Root().LookupName());
    EXPECT_EQ("/", processRoot.Leaf().EffectiveName());
    auto selected = SelectAcceptedPath(context, context.GetTempdirPath(), CrossMountPathPolicy(), AmpleLimits());
    ASSERT_TRUE(selected.HasValue());
    Path source = std::move(selected).Value();
    const std::string route = source.ToString();
    const auto depth = source.Size();
    Path moved(std::move(source));
    EXPECT_EQ(depth, source.Size());
    EXPECT_EQ(route, source.ToString());
    EXPECT_EQ(route, moved.ToString());
    EXPECT_EQ("/", source.Root().LookupName());
    EXPECT_EQ("/", moved.Root().LookupName());
    EXPECT_GT(moved.RetainedDescriptors(), 0u);
    auto noChange = source.Freeze();
    ASSERT_TRUE(noChange.HasValue());
    EXPECT_FALSE(noChange.Value());
    EXPECT_EQ(route, moved.ToString());
}

TEST_F(PathAliasTest, ResolveOwnsTargetAfterPathAndStepRetireWithoutChangingSource)
{
    const auto name = context.MakeTempfile("pinned data");
    std::unique_ptr<Path::Component> retained;
    {
        auto opened = SelectAcceptedPath(context, context.GetTempdirPath(), CrossMountPathPolicy(), AmpleLimits());
        ASSERT_TRUE(opened.HasValue());
        Path path = std::move(opened).Value();
        const std::string before = path.ToString();
        const std::size_t depth = path.Size();
        auto resolved = SelectStep(path, name.substr(name.find_last_of('/') + 1), CrossMountPathPolicy());
        ASSERT_TRUE(resolved.HasValue()) << resolved.Error().message;
        Path::Step step = std::move(resolved).Value();
        const auto facts = step.Acquired();
        EXPECT_EQ(Type::RegularFile, facts.type);
        EXPECT_GT(facts.lookupMount.value, 0u);
        EXPECT_GT(facts.targetMount.value, 0u);
        retained.reset(new Path::Component(step.Target()));
        Path::Step moved(std::move(step));
        EXPECT_EQ(step.Target().Acquired().metadata.st_ino, moved.Target().Acquired().metadata.st_ino);
        EXPECT_EQ(before, path.ToString());
        EXPECT_EQ(depth, path.Size());
        EXPECT_EQ(name, retained->LookupName());
    }
    ASSERT_TRUE(retained->Stat().HasValue());
    auto stream = retained->OpenReadOnly();
    ASSERT_TRUE(stream.HasValue()) << stream.Error().message;
    auto bytes = stream.Value().Read(32);
    ASSERT_TRUE(bytes.HasValue());
    ASSERT_TRUE(bytes.Value().HasValue());
    EXPECT_EQ("pinned data", bytes.Value().Value());
}

TEST_F(PathAliasTest, SiblingStepsStaleButInverseRestoresExactContext)
{
    const std::string root = context.GetTempdirPath();
    ASSERT_EQ(0, ::mkdir((root + "/left").c_str(), 0700));
    ASSERT_EQ(0, ::mkdir((root + "/right").c_str(), 0700));
    auto opened = SelectAcceptedPath(context, root, CrossMountPathPolicy(), AmpleLimits());
    ASSERT_TRUE(opened.HasValue());
    Path path = std::move(opened).Value();
    const auto before = path.ToString();
    const auto initialDepth = path.Size();
    auto left = SelectStep(path, "left", CrossMountPathPolicy());
    auto right = SelectStep(path, "right", CrossMountPathPolicy());
    ASSERT_TRUE(left.HasValue());
    ASSERT_TRUE(right.HasValue());
    EXPECT_CALL(context, OpenNativePath(_, _)).Times(0);
    EXPECT_CALL(context, OpenNativeAt(_, _, _)).Times(0);
    EXPECT_CALL(context, DuplicateDescriptor(_)).Times(0);
    EXPECT_CALL(context, StatFileDescriptor(_, _)).Times(0);
    auto inverse = path.Apply(std::move(left.Value()));
    ASSERT_TRUE(inverse.HasValue()) << inverse.Error().message;
    EXPECT_EQ(root + "/left", path.ToString());
    auto stale = path.Apply(std::move(right.Value()));
    ASSERT_FALSE(stale.HasValue());
    EXPECT_EQ(ESTALE, stale.Error().code);
    EXPECT_EQ(root + "/right", right.Value().Target().LookupName());
    auto restored = path.Apply(std::move(inverse.Value()));
    ASSERT_TRUE(restored.HasValue()) << restored.Error().message;
    EXPECT_EQ(before, path.ToString());
    EXPECT_EQ(initialDepth, path.Size());
    auto replay = path.Apply(std::move(right.Value()));
    ASSERT_TRUE(replay.HasValue()) << replay.Error().message;
    EXPECT_EQ(root + "/right", path.ToString());
    EXPECT_EQ(ESTALE, path.Apply(std::move(restored.Value())).Error().code);
}

TEST_F(PathAliasTest, BarrierRejectsParentExcursionEvenWhenLinkReturnsToSameDirectory)
{
    const std::string root = context.GetTempdirPath();
    ASSERT_EQ(0, ::mkdir((root + "/bob").c_str(), 0700));
    ASSERT_EQ(0, ::mkdir((root + "/foo").c_str(), 0700));
    ASSERT_EQ(0, ::symlink("../bob", (root + "/bob/same").c_str()));
    ASSERT_EQ(0, ::symlink("../foo", (root + "/bob/escape").c_str()));
    auto policy = CrossMountPathPolicy(true);
    auto opened = Path::Make(context, root + "/bob", policy, AmpleLimits());
    ASSERT_TRUE(opened.HasValue());
    ASSERT_TRUE(opened.Value().Is<Path>());
    Path path = As<Path>(std::move(opened.Value()));
    auto old = SelectStep(path, "escape", policy);
    ASSERT_TRUE(old.HasValue()) << old.Error().message; // process-root barrier allows parent traversal
    const auto depth = path.Size();
    auto narrowed = path.Freeze();
    ASSERT_TRUE(narrowed.HasValue());
    EXPECT_TRUE(narrowed.Value());
    EXPECT_EQ(depth, path.Size());
    EXPECT_EQ("/", path.Root().LookupName());
    auto repeat = path.Freeze();
    ASSERT_TRUE(repeat.HasValue());
    EXPECT_FALSE(repeat.Value());
    EXPECT_FALSE(path.Resolve("same", policy).HasValue());
    EXPECT_FALSE(path.Resolve("escape", policy).HasValue());
    EXPECT_FALSE(path.Apply(std::move(old.Value())).HasValue());
    EXPECT_EQ(root + "/bob", path.ToString());
    EXPECT_EQ(depth, path.Size());
    // TM-9: absolute spelling equality does not authorize a parent crossing.
}

TEST_F(PathAliasTest, SingleChildInputRejectsTraversalAndDoesNotMutate)
{
    auto opened = SelectAcceptedPath(context, context.GetTempdirPath(), CrossMountPathPolicy(), AmpleLimits());
    ASSERT_TRUE(opened.HasValue());
    Path path = std::move(opened).Value();
    const auto name = path.LookupName();
    const auto depth = path.Size();
    const auto bytes = path.RetainedBytes();
    const auto pins = path.RetainedDescriptors();
    const auto held = CountOpenDescriptors();
    for (const std::string& child : std::vector<std::string>{"", ".", "..", "/", "../bob", "a/b", std::string("a\0b", 3)})
    {
        SCOPED_TRACE(child);
        auto result = path.Resolve(child, CrossMountPathPolicy());
        ASSERT_FALSE(result.HasValue());
        EXPECT_EQ(EINVAL, result.Error().code);
        EXPECT_EQ(name, path.LookupName());
        EXPECT_EQ(depth, path.Size());
        EXPECT_EQ(bytes, path.RetainedBytes());
        EXPECT_EQ(pins, path.RetainedDescriptors());
        EXPECT_EQ(held, CountOpenDescriptors());
    }
}

TEST_F(PathAliasTest, DistinctAcquisitionsOfSameDirectoryCannotAttachStep)
{
    const std::string root = context.GetTempdirPath();
    ASSERT_EQ(0, ::mkdir((root + "/child").c_str(), 0700));
    auto first = SelectAcceptedPath(context, root, CrossMountPathPolicy(), AmpleLimits());
    auto second = SelectAcceptedPath(context, root, CrossMountPathPolicy(), AmpleLimits());
    ASSERT_TRUE(first.HasValue());
    ASSERT_TRUE(second.HasValue());
    auto step = SelectStep(first.Value(), "child", CrossMountPathPolicy());
    ASSERT_TRUE(step.HasValue());
    EXPECT_EQ(first.Value().Leaf().Acquired().metadata.st_ino, second.Value().Leaf().Acquired().metadata.st_ino);
    EXPECT_EQ(first.Value().Size(), second.Value().Size());
    auto detached = second.Value().Apply(std::move(step.Value()));
    ASSERT_FALSE(detached.HasValue());
    EXPECT_EQ(ESTALE, detached.Error().code);
    EXPECT_TRUE(first.Value().Apply(std::move(step.Value())).HasValue());
}

TEST_F(PathAliasTest, WorkedPhysicalSuffixDeltaAndUndoRetainHeldAncestors)
{
    const std::string root = context.GetTempdirPath();
    ASSERT_EQ(0, ::mkdir((root + "/sub").c_str(), 0700));
    ASSERT_EQ(0, ::mkdir((root + "/x").c_str(), 0700));
    ASSERT_EQ(0, ::symlink("../x", (root + "/sub/link").c_str()));
    auto policy = CrossMountPathPolicy(true);
    auto opened = SelectAcceptedPath(context, root, policy, AmpleLimits());
    ASSERT_TRUE(opened.HasValue());
    Path path = std::move(opened).Value();
    const std::size_t rootDepth = path.Size();
    auto intoSub = SelectStep(path, "sub", policy);
    ASSERT_TRUE(intoSub.HasValue());
    auto undoSub = path.Apply(std::move(intoSub.Value()));
    ASSERT_TRUE(undoSub.HasValue());
    const std::size_t subDepth = path.Size();
    EXPECT_EQ(rootDepth + 1, subDepth);
    auto link = SelectStep(path, "link", policy);
    ASSERT_TRUE(link.HasValue()) << link.Error().message;
    EXPECT_EQ(Type::Directory, link.Value().Acquired().type);
    EXPECT_GT(link.Value().Acquired().lookupMount.value, 0u);
    EXPECT_GT(link.Value().Acquired().targetMount.value, 0u);
    const auto previous = path.Leaf().Acquired().metadata.st_ino;
    auto undoLink = path.Apply(std::move(link.Value()));
    ASSERT_TRUE(undoLink.HasValue()) << undoLink.Error().message;
    EXPECT_EQ(subDepth, path.Size()); // pop sub and push x; never lexical sub/link
    EXPECT_EQ(root + "/x", path.ToString());
    EXPECT_NE(previous, path.Leaf().Acquired().metadata.st_ino);
    EXPECT_EQ(ESTALE, path.Apply(std::move(undoSub.Value())).Error().code);
    auto back = path.Apply(std::move(undoLink.Value()));
    ASSERT_TRUE(back.HasValue());
    EXPECT_EQ(root + "/sub", path.ToString());
    EXPECT_EQ(previous, path.Leaf().Acquired().metadata.st_ino);
    auto toRoot = path.Apply(std::move(undoSub.Value()));
    ASSERT_TRUE(toRoot.HasValue());
    EXPECT_EQ(rootDepth, path.Size());
    EXPECT_EQ(root, path.ToString());
    EXPECT_EQ("/", path.Root().LookupName());
}

TEST_F(PathAliasTest, FrozenRouteRejectsRootReplacementWithoutGlobalNameReplay)
{
    const std::string root = context.GetTempdirPath();
    ASSERT_EQ(0, ::mkdir((root + "/bound").c_str(), 0700));
    ASSERT_EQ(0, ::mkdir((root + "/bound/child").c_str(), 0700));
    auto opened = SelectAcceptedPath(context, root + "/bound", CrossMountPathPolicy(), AmpleLimits());
    ASSERT_TRUE(opened.HasValue());
    Path path = std::move(opened).Value();
    auto step = SelectStep(path, "child", CrossMountPathPolicy());
    ASSERT_TRUE(step.HasValue());
    const auto held = step.Value().Target().Acquired();
    ASSERT_EQ(0, ::rename((root + "/bound").c_str(), (root + "/bound.old").c_str()));
    ASSERT_EQ(0, ::mkdir((root + "/bound").c_str(), 0700));
    ASSERT_EQ(0, ::mkdir((root + "/bound/child").c_str(), 0700));
    const auto newPath = Path::Make(context, root + "/bound/child", CrossMountPathPolicy(), AmpleLimits());
    ASSERT_TRUE(newPath.HasValue());
    ASSERT_TRUE(newPath.Value().Is<Path>());
    EXPECT_NE(held.metadata.st_ino, As<Path>(newPath.Value()).Leaf().Acquired().metadata.st_ino);
    auto inverse = path.Apply(std::move(step.Value()));
    ASSERT_TRUE(inverse.HasValue()) << inverse.Error().message;
    EXPECT_EQ(held.metadata.st_ino, path.Leaf().Acquired().metadata.st_ino);
    EXPECT_EQ(root + "/bound/child", path.LookupName()); // retained spelling, not global replay
    EXPECT_TRUE(path.Apply(std::move(inverse.Value())).HasValue());
}

TEST_F(PathAliasTest, ZeroDeltaIsValidAndInverseRestoresTheSamePinnedAcquisition)
{
    const std::string root = context.GetTempdirPath();
    ASSERT_EQ(0, ::symlink(".", (root + "/same").c_str()));
    auto policy = CrossMountPathPolicy(true);
    auto opened = SelectAcceptedPath(context, root, policy, AmpleLimits());
    ASSERT_TRUE(opened.HasValue());
    Path path = std::move(opened).Value();
    const auto identity = path.Leaf().Acquired().metadata.st_ino;
    auto step = SelectStep(path, "same", policy);
    ASSERT_TRUE(step.HasValue()) << step.Error().message;
    const auto size = path.Size();
    EXPECT_EQ(identity, step.Value().Target().Acquired().metadata.st_ino);
    auto inverse = path.Apply(std::move(step.Value()));
    ASSERT_TRUE(inverse.HasValue()) << inverse.Error().message;
    EXPECT_EQ(size, path.Size());
    EXPECT_EQ(identity, path.Leaf().Acquired().metadata.st_ino);
    EXPECT_EQ(root + "/same", path.LookupName());
    auto restored = path.Apply(std::move(inverse.Value()));
    ASSERT_TRUE(restored.HasValue()) << restored.Error().message;
    EXPECT_EQ(size, path.Size());
    EXPECT_EQ(root, path.LookupName());
    EXPECT_EQ(identity, path.Leaf().Acquired().metadata.st_ino);
}

TEST_F(PathAliasTest, PinnedLinkInspectionSurvivesNameReplacementDuringResolve)
{
    const std::string root = context.GetTempdirPath();
    const std::string source = context.MakeTempfile("acquired");
    const std::string name = source.substr(source.find_last_of('/') + 1);
    ASSERT_EQ(0, ::symlink(name.c_str(), (root + "/link").c_str()));
    auto policy = CrossMountPathPolicy(true);
    auto opened = SelectAcceptedPath(context, root, policy, AmpleLimits());
    ASSERT_TRUE(opened.HasValue());
    Path path = std::move(opened).Value();
    bool replaced = false;
    ON_CALL(context, StatFileDescriptor(_, _)).WillByDefault([&](int descriptor, struct stat* snapshot) {
        const int status = context.RealStatFileDescriptor(descriptor, snapshot);
        if ((0 == status) && S_ISLNK(snapshot->st_mode) && !replaced)
        {
            replaced = true;
            EXPECT_EQ(0, ::rename((root + "/link").c_str(), (root + "/former").c_str()));
            EXPECT_EQ(0, ::mkfifo((root + "/link").c_str(), 0600));
        }
        return status;
    });
    auto resolved = SelectStep(path, "link", policy);
    ASSERT_TRUE(resolved.HasValue()) << resolved.Error().message;
    EXPECT_TRUE(replaced);
    struct stat expected = {};
    ASSERT_EQ(0, ::stat(source.c_str(), &expected));
    EXPECT_EQ(expected.st_ino, resolved.Value().Target().Acquired().metadata.st_ino);
    EXPECT_EQ(root, path.ToString());
}

TEST_F(PathAliasTest, LinkLookupMountAndTargetMountAreDistinctAndBothEnforced)
{
    const std::string root = context.GetTempdirPath();
    ASSERT_EQ(0, ::symlink("/proc", (root + "/proc-link").c_str()));
    OwnedTestDescriptor lookupFd(::open((root + "/proc-link").c_str(), O_PATH | O_NOFOLLOW | O_CLOEXEC));
    OwnedTestDescriptor targetFd(::open("/proc", O_PATH | O_CLOEXEC));
    ASSERT_GE(lookupFd.Get(), 0);
    ASSERT_GE(targetFd.Get(), 0);
    const auto mountOf = [](int fd) -> ComplianceEngine::Result<std::uint64_t> {
        std::ifstream info("/proc/self/fdinfo/" + std::to_string(fd));
        if (!info.is_open())
            return ComplianceEngine::Error("Cannot inspect fixture mount", errno);
        return ParseMountId(std::string(std::istreambuf_iterator<char>{info}, std::istreambuf_iterator<char>{}));
    };
    const auto lookupMount = mountOf(lookupFd.Get());
    const auto targetMount = mountOf(targetFd.Get());
    ASSERT_TRUE(lookupMount.HasValue());
    ASSERT_TRUE(targetMount.HasValue());
    if (lookupMount.Value() == targetMount.Value())
        GTEST_SKIP() << "procfs fixture shares mount";
    auto opened = Path::Make(context, root, CrossMountPathPolicy(), AmpleLimits());
    ASSERT_TRUE(opened.HasValue());
    ASSERT_TRUE(opened.Value().Is<Path>());
    Path path = As<Path>(std::move(opened.Value()));
    auto policy = CrossMountPathPolicy(true);
    auto cross = SelectStep(path, "proc-link", policy);
    ASSERT_TRUE(cross.HasValue()) << cross.Error().message;
    EXPECT_EQ(lookupMount.Value(), cross.Value().Acquired().lookupMount.value);
    EXPECT_EQ(targetMount.Value(), cross.Value().Acquired().targetMount.value);
    EXPECT_EQ(Type::Directory, cross.Value().Acquired().type);
    policy.mounts = MountPolicy::StayOnRootMount;
    auto denied = path.Resolve("proc-link", policy);
    ASSERT_FALSE(denied.HasValue());
    EXPECT_EQ(EXDEV, denied.Error().code);
    EXPECT_EQ(root, path.ToString());
}

TEST_F(PathAliasTest, ResolverChargesExactAndOneOverWorkEvenForFailedLookup)
{
    const std::string fixture = context.GetTempdirPath();
    const std::string missingName = fixture.substr(fixture.find_last_of('/') + 1) + ".unpublished";
    auto policy = CrossMountPathPolicy();
    policy.missingFiles = ComplianceEngine::Filesystem::MissingFileDisposition::Report;
    ResolverLimits limits = AmpleLimits();
    const std::size_t chunks = limits.shared.fdinfoBytes / 256 + ((limits.shared.fdinfoBytes % 256) != 0);
    const std::size_t cost = 128 + 4 * chunks;
    // Make charges the root; Resolve charges its snapshot, component and two held-root name searches.
    const std::size_t exactWork = cost + 1 + cost + 2 * (missingName.size() + 4);
    limits.shared.work = exactWork;
    auto exact = Path::Make(context, "/", policy, limits);
    ASSERT_TRUE(exact.HasValue());
    ASSERT_TRUE(exact.Value().Is<Path>());
    Path exactPath = As<Path>(std::move(exact.Value()));
    auto missing = exactPath.Resolve(missingName, policy);
    ASSERT_TRUE(missing.HasValue()) << missing.Error().message;
    ASSERT_TRUE(missing.Value().Is<Path::RejectionReason>());
    EXPECT_EQ(Path::RejectionReason::Missing, As<Path::RejectionReason>(missing.Value()));
    EXPECT_EQ("/", exactPath.ToString());
    auto exhausted = exactPath.Resolve(missingName, policy);
    ASSERT_FALSE(exhausted.HasValue());
    EXPECT_EQ(E2BIG, exhausted.Error().code);

    limits.shared.work = exactWork - 1; // Make still succeeds; first failed lookup exceeds work by one.
    auto oneOver = Path::Make(context, "/", policy, limits);
    ASSERT_TRUE(oneOver.HasValue());
    ASSERT_TRUE(oneOver.Value().Is<Path>());
    Path bounded = As<Path>(std::move(oneOver.Value()));
    EXPECT_CALL(context, OpenNativeAt(_, _, _)).Times(0);
    auto denied = bounded.Resolve(missingName, policy);
    ASSERT_FALSE(denied.HasValue());
    EXPECT_EQ(E2BIG, denied.Error().code);
    auto deniedAgain = bounded.Resolve(missingName, policy);
    ASSERT_FALSE(deniedAgain.HasValue());
    EXPECT_EQ(E2BIG, deniedAgain.Error().code);
    EXPECT_EQ(1u, bounded.Size());
    EXPECT_EQ("/", bounded.Root().LookupName());
}
TEST_F(PathAliasTest, ProcfsHelperCloseFailuresAreDiagnosticAndAcquisitionSucceeds)
{
    const auto before = CountOpenDescriptors();
    const std::string logPath = context.GetTempdirPath() + "/helper-close.log";
    OsConfigLogHandle log = OpenLog(logPath.c_str(), nullptr);
    ASSERT_NE(nullptr, log);
    context.SetLogHandle(log);
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
    auto opened = SelectAcceptedPath(context, "/", CrossMountPathPolicy(), AmpleLimits());
    ASSERT_TRUE(opened.HasValue());
    EXPECT_TRUE(opened.Value().Root().Stat().HasValue());
    EXPECT_EQ(2U, failed);
    opened = ComplianceEngine::Error("Release selected pin", EINVAL);
    CloseLog(&log);
    context.SetLogHandle(nullptr);
    const auto text = ReadLog(logPath);
    for (int code : {EACCES, EIO})
        ExpectLoggedOnce(text, "Cannot close internal filesystem descriptor: " + std::to_string(code));
    EXPECT_EQ(before, CountOpenDescriptors());
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
    auto opened = SelectAcceptedPath(context, "/", CrossMountPathPolicy(), AmpleLimits());
    ASSERT_FALSE(opened.HasValue());
    EXPECT_EQ(ENOSPC, opened.Error().code);
    EXPECT_TRUE(failedRead);
    EXPECT_TRUE(failedClose);
    EXPECT_EQ(before, CountOpenDescriptors());
}

TEST_F(PathAliasTest, AcceptedLookupAndEffectiveBindingsReuseHeldPinWithoutReopeningRoot)
{
    const std::string base = context.GetTempdirPath();
    const std::string target = base + "/target-root";
    const std::string alias = base + "/root-alias";
    ASSERT_EQ(0, ::mkdir(target.c_str(), 0700));
    const std::string file = context.MakeTempfile("pinned");
    ASSERT_EQ(0, ::rename(file.c_str(), (target + "/inside").c_str()));
    ASSERT_EQ(0, ::symlink(target.c_str(), alias.c_str()));
    ASSERT_EQ(0, ::symlink((alias + "/inside").c_str(), (target + "/via-alias").c_str()));
    const auto policy = CrossMountPathPolicy(true);
    auto opened = Path::Make(context, alias, policy, AmpleLimits());
    ASSERT_TRUE(opened.HasValue());
    ASSERT_TRUE(opened.Value().Is<Path>());
    Path path = As<Path>(std::move(opened.Value()));
    ASSERT_TRUE(path.Freeze().HasValue());
    EXPECT_EQ(alias, path.LookupName());
    EXPECT_EQ(target, path.ToString());
    EXPECT_EQ("/", path.Root().LookupName());
    EXPECT_EQ(target, path.Leaf().EffectiveName());
    EXPECT_CALL(context, OpenNativePath(_, _)).WillRepeatedly([&](const char* name, int flags) { return context.RealOpenNativePath(name, flags); });
    EXPECT_CALL(context, OpenNativePath(testing::StrEq("/"), _)).Times(0);
    auto resolved = SelectStep(path, "via-alias", policy);
    ASSERT_TRUE(resolved.HasValue()) << resolved.Error().message;
    struct stat expected = {};
    ASSERT_EQ(0, ::stat((target + "/inside").c_str(), &expected));
    EXPECT_EQ(expected.st_ino, resolved.Value().Target().Acquired().metadata.st_ino);
    EXPECT_EQ(alias, path.LookupName());
    EXPECT_EQ(target, path.ToString());
}

TEST_F(PathAliasTest, FreezeOnlyNarrowsAndRejectsInverseAcrossNewBarrier)
{
    const std::string base = context.GetTempdirPath();
    ASSERT_EQ(0, ::mkdir((base + "/child").c_str(), 0700));
    auto opened = SelectAcceptedPath(context, base, CrossMountPathPolicy(), AmpleLimits());
    ASSERT_TRUE(opened.HasValue());
    Path path = std::move(opened).Value();
    const auto rootDepth = path.Size();
    auto enter = SelectStep(path, "child", CrossMountPathPolicy());
    ASSERT_TRUE(enter.HasValue());
    auto inverse = path.Apply(std::move(enter.Value()));
    ASSERT_TRUE(inverse.HasValue());
    EXPECT_EQ(rootDepth + 1, path.Size());
    auto deeper = path.Freeze();
    ASSERT_TRUE(deeper.HasValue());
    EXPECT_TRUE(deeper.Value());
    EXPECT_FALSE(path.Freeze().Value());
    auto blocked = path.Apply(std::move(inverse.Value()));
    ASSERT_FALSE(blocked.HasValue());
    EXPECT_EQ(EXDEV, blocked.Error().code);
    EXPECT_EQ(base + "/child", path.ToString());
    EXPECT_EQ(rootDepth + 1, path.Size());
    EXPECT_EQ("/", path.Root().LookupName());
}

TEST_F(PathAliasTest, MakeSharesFollowLimitAcrossComponentsAndResolveResetsIt)
{
    const std::string base = context.GetTempdirPath();
    const std::string real = base + "/real";
    ASSERT_EQ(0, ::mkdir(real.c_str(), 0700));
    ASSERT_EQ(0, ::mkdir((real + "/target").c_str(), 0700));
    ASSERT_EQ(0, ::symlink("real", (base + "/first").c_str()));
    ASSERT_EQ(0, ::symlink("target", (real + "/second").c_str()));
    auto follow = CrossMountPathPolicy(true);
    ResolverLimits limits = AmpleLimits();
    limits.linkExpansions = 1;
    auto one = Path::Make(context, base + "/first/second", follow, limits);
    ASSERT_FALSE(one.HasValue());
    EXPECT_EQ(ELOOP, one.Error().code);
    limits.linkExpansions = 2;
    auto two = Path::Make(context, base + "/first/second", follow, limits);
    ASSERT_TRUE(two.HasValue()) << two.Error().message;
    ASSERT_TRUE(two.Value().Is<Path>());
    EXPECT_EQ(real + "/target", As<Path>(two.Value()).ToString());
    limits.linkExpansions = 1;
    ASSERT_EQ(0, ::symlink("real", (base + "/other").c_str()));
    auto selected = SelectAcceptedPath(context, base, CrossMountPathPolicy(), limits);
    ASSERT_TRUE(selected.HasValue());
    auto first = SelectStep(selected.Value(), "first", follow);
    auto other = SelectStep(selected.Value(), "other", follow);
    ASSERT_TRUE(first.HasValue()) << first.Error().message;
    ASSERT_TRUE(other.HasValue()) << other.Error().message;
    EXPECT_EQ(first.Value().Acquired().metadata.st_ino, other.Value().Acquired().metadata.st_ino);
}

TEST_F(PathAliasTest, AcyclicDotFanoutStopsAtTotalFollowsWithoutGrowingDirectoryDepth)
{
    const std::string base = context.GetTempdirPath();
    ASSERT_EQ(0, ::symlink(".", (base + "/s1").c_str()));
    ASSERT_EQ(0, ::symlink("s1/s1", (base + "/s2").c_str()));
    ASSERT_EQ(0, ::symlink("s2/s2", (base + "/s3").c_str()));
    ResolverLimits limits = AmpleLimits();
    limits.shared.work = 2000000;
    limits.linkExpansions = 7;
    auto selected = SelectAcceptedPath(context, base, CrossMountPathPolicy(), limits);
    ASSERT_TRUE(selected.HasValue());
    const auto depth = selected.Value().Size();
    auto seven = SelectStep(selected.Value(), "s3", CrossMountPathPolicy(true));
    ASSERT_TRUE(seven.HasValue()) << seven.Error().message;
    EXPECT_EQ(depth, selected.Value().Size());
    EXPECT_EQ(selected.Value().Leaf().Acquired().metadata.st_ino, seven.Value().Acquired().metadata.st_ino);
    limits.linkExpansions = 6;
    auto limited = SelectAcceptedPath(context, base, CrossMountPathPolicy(), limits);
    ASSERT_TRUE(limited.HasValue());
    auto eight = limited.Value().Resolve("s3", CrossMountPathPolicy(true));
    ASSERT_FALSE(eight.HasValue());
    EXPECT_EQ(ELOOP, eight.Error().code);
    EXPECT_EQ(depth, limited.Value().Size());
}

TEST_F(PathAliasTest, NestedLinkScheduleHasIndependentSixtyFourFrameCeiling)
{
    const std::string base = context.GetTempdirPath();
    for (int i = 0; i <= 65; ++i)
    {
        const std::string next = i == 0 ? "." : "frame" + std::to_string(i - 1);
        ASSERT_EQ(0, ::symlink(next.c_str(), (base + "/frame" + std::to_string(i)).c_str()));
    }
    ResolverLimits limits = AmpleLimits();
    limits.linkExpansions = 128;
    limits.shared.components = 1000;
    limits.shared.work = 2000000;
    auto selected = SelectAcceptedPath(context, base, CrossMountPathPolicy(), limits);
    ASSERT_TRUE(selected.HasValue());
    auto follow = CrossMountPathPolicy(true);
    auto sixtyThree = selected.Value().Resolve("frame62", follow);
    ASSERT_TRUE(sixtyThree.HasValue()) << sixtyThree.Error().message;
    ASSERT_TRUE(sixtyThree.Value().Is<Path::Step>());
    for (int i : {63, 64})
    {
        auto over = selected.Value().Resolve("frame" + std::to_string(i), follow);
        ASSERT_FALSE(over.HasValue()) << i;
        EXPECT_EQ(ELOOP, over.Error().code) << i;
    }
}

TEST_F(PathAliasTest, RejectsInvalidPolicyFieldsForFactoryAndChildBeforeAcquisition)
{
    const std::string base = context.GetTempdirPath();
    auto selected = SelectAcceptedPath(context, base, CrossMountPathPolicy(), AmpleLimits());
    ASSERT_TRUE(selected.HasValue());
    const auto unchanged = selected.Value().ToString();
    const auto original = CrossMountPathPolicy();
    std::vector<Path::Policy> invalid;
    {
        auto p = original;
        p.prefixLinks = static_cast<PrefixLinkPolicy>(255);
        invalid.push_back(p);
    }
    {
        auto p = original;
        p.fileLinks = static_cast<FileLinkPolicy>(255);
        invalid.push_back(p);
    }
    {
        auto p = original;
        p.directoryLinks = static_cast<DirectoryLinkPolicy>(255);
        invalid.push_back(p);
    }
    {
        auto p = original;
        p.rejectedLinks = static_cast<ComplianceEngine::Filesystem::RejectedLinkDisposition>(255);
        invalid.push_back(p);
    }
    {
        auto p = original;
        p.unsupportedTypes = static_cast<ComplianceEngine::Filesystem::UnsupportedTypeDisposition>(255);
        invalid.push_back(p);
    }
    {
        auto p = original;
        p.missingFiles = static_cast<ComplianceEngine::Filesystem::MissingFileDisposition>(255);
        invalid.push_back(p);
    }
    {
        auto p = original;
        p.mounts = static_cast<MountPolicy>(255);
        invalid.push_back(p);
    }
    EXPECT_CALL(context, OpenNativePath(_, _)).Times(0);
    EXPECT_CALL(context, OpenNativeAt(_, _, _)).Times(0);
    for (const auto& policy : invalid)
    {
        auto factory = Path::Make(context, base, policy, AmpleLimits());
        ASSERT_FALSE(factory.HasValue());
        EXPECT_EQ(EINVAL, factory.Error().code);
        auto child = selected.Value().Resolve("child", policy);
        ASSERT_FALSE(child.HasValue());
        EXPECT_EQ(EINVAL, child.Error().code);
        EXPECT_EQ(unchanged, selected.Value().ToString());
    }
}

TEST_F(PathAliasTest, UnsupportedDirectAndFollowedTargetsKeepTypedOutcomesDistinct)
{
    const std::string base = context.GetTempdirPath();
    ASSERT_EQ(0, ::mkfifo((base + "/pipe").c_str(), 0600));
    ASSERT_EQ(0, ::symlink("pipe", (base + "/to-pipe").c_str()));
    ASSERT_EQ(0, ::symlink("absent", (base + "/broken").c_str()));
    auto selected = SelectAcceptedPath(context, base, CrossMountPathPolicy(), AmpleLimits());
    ASSERT_TRUE(selected.HasValue());
    auto strict = CrossMountPathPolicy();
    auto follow = CrossMountPathPolicy(true);
    const auto depth = selected.Value().Size();
    auto directError = selected.Value().Resolve("pipe", strict);
    ASSERT_FALSE(directError.HasValue());
    EXPECT_EQ(EOPNOTSUPP, directError.Error().code);
    auto linkError = selected.Value().Resolve("to-pipe", strict);
    ASSERT_FALSE(linkError.HasValue());
    EXPECT_EQ(ELOOP, linkError.Error().code);
    auto followedError = selected.Value().Resolve("to-pipe", follow);
    ASSERT_FALSE(followedError.HasValue());
    EXPECT_EQ(EOPNOTSUPP, followedError.Error().code);
    auto skip = strict;
    skip.unsupportedTypes = ComplianceEngine::Filesystem::UnsupportedTypeDisposition::Skip;
    auto directSkip = selected.Value().Resolve("pipe", skip);
    ASSERT_TRUE(directSkip.HasValue());
    ASSERT_TRUE(directSkip.Value().Is<Path::RejectionReason>());
    EXPECT_EQ(Path::RejectionReason::UnsupportedType, As<Path::RejectionReason>(directSkip.Value()));
    skip.fileLinks = FileLinkPolicy::Follow;
    auto followedSkip = selected.Value().Resolve("to-pipe", skip);
    ASSERT_TRUE(followedSkip.HasValue());
    ASSERT_TRUE(followedSkip.Value().Is<Path::RejectionReason>());
    EXPECT_EQ(Path::RejectionReason::UnsupportedType, As<Path::RejectionReason>(followedSkip.Value()));
    auto makeSkip = Path::Make(context, base + "/pipe", skip, AmpleLimits());
    ASSERT_TRUE(makeSkip.HasValue());
    ASSERT_TRUE(makeSkip.Value().Is<Path::RejectionReason>());
    EXPECT_EQ(Path::RejectionReason::UnsupportedType, As<Path::RejectionReason>(makeSkip.Value()));
    auto broken = selected.Value().Resolve("broken", follow);
    ASSERT_FALSE(broken.HasValue());
    EXPECT_EQ(ENOENT, broken.Error().code);
    EXPECT_EQ(depth, selected.Value().Size());
    EXPECT_EQ(base, selected.Value().ToString());
}

TEST_F(PathAliasTest, UnsupportedTypedSkipSurvivesFailedTemporaryPinClose)
{
    const std::string base = context.GetTempdirPath();
    const std::string directory = base + "/inner";
    ASSERT_EQ(0, ::mkdir(directory.c_str(), 0700));
    ASSERT_EQ(0, ::mkfifo((directory + "/pipe").c_str(), 0600));
    ASSERT_EQ(0, ::symlink("inner/pipe", (base + "/to-pipe").c_str()));
    int failedDirectory = 0, failedFifo = 0;
    auto selected = SelectAcceptedPath(context, base, CrossMountPathPolicy(), AmpleLimits());
    ASSERT_TRUE(selected.HasValue());
    auto policy = CrossMountPathPolicy(true);
    policy.unsupportedTypes = ComplianceEngine::Filesystem::UnsupportedTypeDisposition::Skip;
    const auto before = CountOpenDescriptors();
    EXPECT_CALL(context, CloseFileDescriptor(_)).WillRepeatedly([&](int fd) {
        struct stat info = {};
        const bool inspected = ::fstat(fd, &info) == 0;
        const bool fifo = inspected && S_ISFIFO(info.st_mode);
        const bool hiddenDirectory = inspected && S_ISDIR(info.st_mode) && DescriptorTarget(fd) == directory;
        const int result = context.RealCloseFileDescriptor(fd);
        if (fifo || hiddenDirectory)
        {
            if (fifo)
                ++failedFifo;
            if (hiddenDirectory)
                ++failedDirectory;
            errno = EIO;
            return -1;
        }
        return result;
    });
    auto outcome = selected.Value().Resolve("to-pipe", policy);
    ASSERT_TRUE(outcome.HasValue()) << outcome.Error().message;
    ASSERT_TRUE(outcome.Value().Is<Path::RejectionReason>());
    EXPECT_EQ(Path::RejectionReason::UnsupportedType, As<Path::RejectionReason>(outcome.Value()));
    EXPECT_EQ(1, failedDirectory);
    EXPECT_EQ(1, failedFifo);
    EXPECT_EQ(base, selected.Value().ToString());
    EXPECT_EQ(before, CountOpenDescriptors());
}

TEST_F(PathAliasTest, MissingFactorySelectionSurvivesDiagnosticRootCloseFailure)
{
    const std::string base = context.GetTempdirPath();
    struct stat root = {};
    ASSERT_EQ(0, ::stat("/", &root));
    int failed = 0;
    EXPECT_CALL(context, CloseFileDescriptor(_)).WillRepeatedly([&](int fd) {
        struct stat acquired = {};
        const bool processRoot = ::fstat(fd, &acquired) == 0 && acquired.st_dev == root.st_dev && acquired.st_ino == root.st_ino;
        const int result = context.RealCloseFileDescriptor(fd);
        if (processRoot)
        {
            ++failed;
            errno = EIO;
            return -1;
        }
        return result;
    });
    const auto before = CountOpenDescriptors();
    auto rejected = Path::Make(context, base + "/missing-unpublished", CrossMountPathPolicy(), AmpleLimits());
    ASSERT_TRUE(rejected.HasValue()) << rejected.Error().message;
    ASSERT_TRUE(rejected.Value().Is<Path::RejectionReason>());
    EXPECT_EQ(Path::RejectionReason::Missing, As<Path::RejectionReason>(rejected.Value()));
    EXPECT_EQ(1, failed);
    EXPECT_EQ(before, CountOpenDescriptors());
}

TEST_F(PathAliasTest, FailedChildErrorConsumesWorkAndPreservesAcceptedPin)
{
    auto policy = CrossMountPathPolicy();
    ResolverLimits limits = AmpleLimits();
    // One root charge, then one snapshot and attempted child per operation.
    limits.shared.work = 192 + 2 * (1 + 192);
    auto selected = SelectAcceptedPath(context, "/", policy, limits);
    ASSERT_TRUE(selected.HasValue());
    const auto rootInode = selected.Value().Leaf().Acquired().metadata.st_ino;
    auto first = selected.Value().Resolve("nonexistent-path-child", policy);
    ASSERT_FALSE(first.HasValue());
    EXPECT_EQ(ENOENT, first.Error().code);
    auto second = selected.Value().Resolve("nonexistent-path-child", policy);
    ASSERT_FALSE(second.HasValue());
    EXPECT_EQ(E2BIG, second.Error().code); // already spent at least one held-search cost
    EXPECT_EQ(rootInode, selected.Value().Leaf().Acquired().metadata.st_ino);
}

TEST_F(PathAliasTest, DetachedSelectedFileModeChangesOriginalNotReplacement)
{
    const std::string original = context.MakeTempfile("old");
    const std::string replacement = context.MakeTempfile("new");
    ASSERT_EQ(0, ::chmod(original.c_str(), 0600));
    ASSERT_EQ(0, ::chmod(replacement.c_str(), 0600));
    auto held = SelectAcceptedPath(context, original, CrossMountPathPolicy(), AmpleLimits());
    ASSERT_TRUE(held.HasValue()) << held.Error().message;
    Path::Component leaf = held.Value().Leaf();
    ASSERT_EQ(0, ::rename(original.c_str(), (original + ".former").c_str()));
    ASSERT_EQ(0, ::rename(replacement.c_str(), original.c_str()));
    auto changed = leaf.SetMode(0640);
    ASSERT_TRUE(changed.HasValue()) << changed.Error().message;
    EXPECT_TRUE(changed.Value());
    struct stat former = {}, current = {};
    ASSERT_EQ(0, ::stat((original + ".former").c_str(), &former));
    ASSERT_EQ(0, ::stat(original.c_str(), &current));
    EXPECT_EQ(0640, former.st_mode & 0777);
    EXPECT_EQ(0600, current.st_mode & 0777);
    EXPECT_NE(former.st_ino, current.st_ino);
    EXPECT_EQ(former.st_ino, leaf.Acquired().metadata.st_ino);
}

TEST_F(PathAliasTest, LinkParentComponentsUsePinnedPhysicalAncestryNotLexicalCancellation)
{
    const std::string base = context.GetTempdirPath();
    ASSERT_EQ(0, ::mkdir((base + "/a").c_str(), 0700));
    ASSERT_EQ(0, ::mkdir((base + "/a/b").c_str(), 0700));
    ASSERT_EQ(0, ::symlink("a/b", (base + "/link").c_str()));
    const std::string physical = context.MakeTempfile("physical");
    const std::string lexical = context.MakeTempfile("lexical");
    ASSERT_EQ(0, ::rename(physical.c_str(), (base + "/a/other").c_str()));
    ASSERT_EQ(0, ::rename(lexical.c_str(), (base + "/other").c_str()));
    auto followed = Path::Make(context, base + "/link/../other", CrossMountPathPolicy(true), AmpleLimits());
    ASSERT_TRUE(followed.HasValue()) << followed.Error().message;
    ASSERT_TRUE(followed.Value().Is<Path>());
    EXPECT_EQ(base + "/a/other", As<Path>(followed.Value()).ToString());
    struct stat expected = {}, wrong = {};
    ASSERT_EQ(0, ::stat((base + "/a/other").c_str(), &expected));
    ASSERT_EQ(0, ::stat((base + "/other").c_str(), &wrong));
    EXPECT_EQ(expected.st_ino, As<Path>(followed.Value()).Leaf().Acquired().metadata.st_ino);
    EXPECT_NE(wrong.st_ino, As<Path>(followed.Value()).Leaf().Acquired().metadata.st_ino);
    auto invalid = Path::Make(context, base + "/other/../a", CrossMountPathPolicy(true), AmpleLimits());
    ASSERT_FALSE(invalid.HasValue());
    EXPECT_EQ(ENOTDIR, invalid.Error().code);
}

TEST_F(PathAliasTest, NonFollowedLinksSkipOnlySelectedFinalLinks)
{
    const std::string base = context.GetTempdirPath();
    const std::string real = base + "/real";
    ASSERT_EQ(0, ::mkdir(real.c_str(), 0700));
    ASSERT_EQ(0, ::symlink("real", (base + "/alias").c_str()));
    const auto file = context.MakeTempfile("pinned");
    ASSERT_EQ(0, ::rename(file.c_str(), (real + "/child").c_str()));
    auto strict = CrossMountPathPolicy();
    strict.rejectedLinks = ComplianceEngine::Filesystem::RejectedLinkDisposition::Skip;
    auto directPrefix = Path::Make(context, base + "/alias/child", strict, AmpleLimits());
    ASSERT_FALSE(directPrefix.HasValue());
    EXPECT_EQ(ELOOP, directPrefix.Error().code);
    auto directLeaf = Path::Make(context, base + "/alias", strict, AmpleLimits());
    ASSERT_TRUE(directLeaf.HasValue());
    ASSERT_TRUE(directLeaf.Value().Is<Path::RejectionReason>());
    EXPECT_EQ(Path::RejectionReason::Excluded, As<Path::RejectionReason>(directLeaf.Value()));

    auto followed = CrossMountPathPolicy(true);
    auto selected = Path::Make(context, base + "/alias", followed, AmpleLimits());
    ASSERT_TRUE(selected.HasValue()) << selected.Error().message;
    ASSERT_TRUE(selected.Value().Is<Path>());
    Path held = As<Path>(std::move(selected.Value()));
    ASSERT_EQ(0, ::symlink((base + "/alias/child").c_str(), (real + "/redirect").c_str()));
    auto inside = strict;
    inside.fileLinks = FileLinkPolicy::Follow; // selected link follows; held prefix alias must not
    auto heldPrefix = held.Resolve("redirect", inside);
    ASSERT_FALSE(heldPrefix.HasValue());
    EXPECT_EQ(ELOOP, heldPrefix.Error().code);
    auto directory = SelectAcceptedPath(context, base, CrossMountPathPolicy(), AmpleLimits());
    ASSERT_TRUE(directory.HasValue());
    auto terminal = directory.Value().Resolve("alias", strict);
    ASSERT_TRUE(terminal.HasValue());
    ASSERT_TRUE(terminal.Value().Is<Path::RejectionReason>());
    EXPECT_EQ(Path::RejectionReason::Excluded, As<Path::RejectionReason>(terminal.Value()));
    EXPECT_EQ(real, held.ToString());
}

TEST_F(PathAliasTest, FollowedSelfPrefixStillAppliesFinalLinkRejectOrSkip)
{
    const std::string base = context.GetTempdirPath();
    const std::string target = context.MakeTempfile("pinned");
    ASSERT_EQ(0, ::symlink(".", (base + "/self-alias").c_str()));
    ASSERT_EQ(0, ::symlink(target.c_str(), (base + "/last-link").c_str()));
    auto policy = CrossMountPathPolicy();
    policy.prefixLinks = PrefixLinkPolicy::Follow;
    auto rejected = Path::Make(context, base + "/self-alias/last-link", policy, AmpleLimits());
    ASSERT_FALSE(rejected.HasValue());
    EXPECT_EQ(ELOOP, rejected.Error().code);
    policy.rejectedLinks = ComplianceEngine::Filesystem::RejectedLinkDisposition::Skip;
    auto skipped = Path::Make(context, base + "/self-alias/last-link", policy, AmpleLimits());
    ASSERT_TRUE(skipped.HasValue()) << skipped.Error().message;
    ASSERT_TRUE(skipped.Value().Is<Path::RejectionReason>());
    EXPECT_EQ(Path::RejectionReason::Excluded, As<Path::RejectionReason>(skipped.Value()));
}

TEST_F(PathAliasTest, DeepLongNameHeldSearchChargesPeakMemoryAndRepeatedWork)
{
    const std::string base = context.GetTempdirPath();
    std::string deep = base;
    for (int i = 0; i < 12; ++i)
    {
        deep += "/d" + std::to_string(i) + std::string(72, static_cast<char>('a' + i));
        ASSERT_EQ(0, ::mkdir(deep.c_str(), 0700));
    }
    auto ample = AmpleLimits();
    ample.shared.work = 4000000;
    auto deepPath = SelectAcceptedPath(context, deep, CrossMountPathPolicy(), ample);
    ASSERT_TRUE(deepPath.HasValue()) << deepPath.Error().message;
    EXPECT_GT(deepPath.Value().RetainedBytes(), 3000u);
    auto compact = ample;
    compact.shared.retainedBytes = 8192;
    auto bounded = Path::Make(context, deep, CrossMountPathPolicy(), compact);
    ASSERT_FALSE(bounded.HasValue());
    EXPECT_EQ(E2BIG, bounded.Error().code);

    ResolverLimits tight = ample;
    tight.shared.work = 400000;
    auto selected = SelectAcceptedPath(context, deep, CrossMountPathPolicy(), tight);
    ASSERT_TRUE(selected.HasValue()) << selected.Error().message;
    auto missing = CrossMountPathPolicy();
    missing.missingFiles = ComplianceEngine::Filesystem::MissingFileDisposition::Report;
    std::size_t exhausted = 0;
    for (; exhausted < 100; ++exhausted)
    {
        auto outcome = selected.Value().Resolve("unpublished", missing);
        if (!outcome.HasValue())
        {
            EXPECT_EQ(E2BIG, outcome.Error().code);
            break;
        }
        ASSERT_TRUE(outcome.Value().Is<Path::RejectionReason>());
        EXPECT_EQ(Path::RejectionReason::Missing, As<Path::RejectionReason>(outcome.Value()));
    }
    EXPECT_LT(exhausted, 100u);
    EXPECT_EQ(deep, selected.Value().ToString());
    EXPECT_TRUE(deepPath.Value().Resolve("unpublished", missing).HasValue());
}

TEST_F(PathAliasTest, ConfiguredLinkBufferOverRetainedBudgetFailsBeforeNativeRead)
{
    const std::string base = context.GetTempdirPath();
    const std::string file = context.MakeTempfile("pinned");
    ASSERT_EQ(0, ::symlink(file.c_str(), (base + "/short-link").c_str()));
    ResolverLimits limits = AmpleLimits();
    limits.linkTargetBytes = 100u * 1024u * 1024u;
    limits.shared.retainedBytes = 1024u * 1024u;
    auto opened = SelectAcceptedPath(context, base, CrossMountPathPolicy(), limits);
    ASSERT_TRUE(opened.HasValue());
    auto follow = CrossMountPathPolicy(true);
    EXPECT_CALL(context, ReadLinkDescriptor(_, _, _)).Times(0);
    auto refused = opened.Value().Resolve("short-link", follow);
    ASSERT_FALSE(refused.HasValue());
    EXPECT_EQ(E2BIG, refused.Error().code);
    EXPECT_EQ("Link target exceeds memory budget", refused.Error().message);
    EXPECT_EQ(base, opened.Value().ToString());
}

TEST_F(PathAliasTest, SameDepthDetachedIdentityRejectsInverseWithStale)
{
    const std::string base = context.GetTempdirPath();
    ASSERT_EQ(0, ::mkdir((base + "/child").c_str(), 0700));
    auto first = SelectAcceptedPath(context, base, CrossMountPathPolicy(), AmpleLimits());
    auto second = SelectAcceptedPath(context, base, CrossMountPathPolicy(), AmpleLimits());
    ASSERT_TRUE(first.HasValue());
    ASSERT_TRUE(second.HasValue());
    Path path = std::move(first).Value();
    auto detached = SelectStep(second.Value(), "child", CrossMountPathPolicy());
    ASSERT_TRUE(detached.HasValue());
    EXPECT_CALL(context, OpenNativeAt(_, _, _)).Times(0);
    EXPECT_CALL(context, DuplicateDescriptor(_)).Times(0);
    auto rejected = path.Apply(std::move(detached.Value()));
    ASSERT_FALSE(rejected.HasValue());
    EXPECT_EQ(ESTALE, rejected.Error().code);
    EXPECT_EQ(base, path.ToString());
}

TEST_F(PathAliasTest, LinkTargetExactByteCapSucceedsAndOneOverPreservesRoot)
{
    const std::string base = context.GetTempdirPath();
    const std::string contents = context.MakeTempfile("pinned");
    const std::string name = "long-pinned-name";
    ASSERT_EQ(0, ::rename(contents.c_str(), (base + "/" + name).c_str()));
    ASSERT_EQ(0, ::symlink(name.c_str(), (base + "/target-link").c_str()));
    auto policy = CrossMountPathPolicy(true);
    ResolverLimits exactLimits = AmpleLimits();
    exactLimits.linkTargetBytes = name.size();
    auto exact = SelectAcceptedPath(context, base, policy, exactLimits);
    ASSERT_TRUE(exact.HasValue()) << exact.Error().message;
    auto accepted = SelectStep(exact.Value(), "target-link", policy);
    ASSERT_TRUE(accepted.HasValue()) << accepted.Error().message;
    EXPECT_EQ(Type::RegularFile, accepted.Value().Acquired().type);
    ResolverLimits shortLimits = exactLimits;
    shortLimits.linkTargetBytes = name.size() - 1;
    auto shortRoot = SelectAcceptedPath(context, base, policy, shortLimits);
    ASSERT_TRUE(shortRoot.HasValue());
    const auto originalName = shortRoot.Value().LookupName();
    auto rejected = shortRoot.Value().Resolve("target-link", policy);
    ASSERT_FALSE(rejected.HasValue());
    EXPECT_EQ(E2BIG, rejected.Error().code);
    EXPECT_EQ(originalName, shortRoot.Value().LookupName());
    EXPECT_TRUE(shortRoot.Value().Leaf().Stat().HasValue());
}

TEST_F(PathAliasTest, MakeReportsMissingDirectIntermediateInputComponent)
{
    const std::string base = context.GetTempdirPath();
    for (const auto disposition : {ComplianceEngine::Filesystem::MissingFileDisposition::Error, ComplianceEngine::Filesystem::MissingFileDisposition::Report})
    {
        auto policy = CrossMountPathPolicy();
        policy.missingFiles = disposition;
        auto result = Path::Make(context, base + "/missing/a/b", policy, AmpleLimits());
        ASSERT_TRUE(result.HasValue()) << result.Error().message;
        ASSERT_TRUE(result.Value().Is<Path::RejectionReason>());
        EXPECT_EQ(Path::RejectionReason::Missing, As<Path::RejectionReason>(result.Value()));
    }
}

TEST_F(PathAliasTest, MakeReportsMissingDirectFinalInputComponent)
{
    const std::string base = context.GetTempdirPath();
    ASSERT_EQ(0, ::mkdir((base + "/existing").c_str(), 0700));
    for (const auto disposition : {ComplianceEngine::Filesystem::MissingFileDisposition::Error, ComplianceEngine::Filesystem::MissingFileDisposition::Report})
    {
        auto policy = CrossMountPathPolicy();
        policy.missingFiles = disposition;
        auto result = Path::Make(context, base + "/existing/missing", policy, AmpleLimits());
        ASSERT_TRUE(result.HasValue()) << result.Error().message;
        ASSERT_TRUE(result.Value().Is<Path::RejectionReason>());
        EXPECT_EQ(Path::RejectionReason::Missing, As<Path::RejectionReason>(result.Value()));
    }
}

TEST_F(PathAliasTest, MakeMissingSymlinkTargetRetainsENOENTError)
{
    const std::string base = context.GetTempdirPath();
    ASSERT_EQ(0, ::symlink("missing-target", (base + "/dangling").c_str()));
    auto policy = CrossMountPathPolicy(true);
    policy.missingFiles = ComplianceEngine::Filesystem::MissingFileDisposition::Report;
    auto result = Path::Make(context, base + "/dangling", policy, AmpleLimits());
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(ENOENT, result.Error().code);
}

TEST_F(PathAliasTest, MakeTrustedProcfsBootstrapENOENTRetainsError)
{
    const std::string base = context.GetTempdirPath();
    ASSERT_EQ(0, ::mkdir((base + "/existing").c_str(), 0700));
    struct Observation
    {
        int procOpens = 0;
        int procOpensAtDirect = 0;
        int directOpens = 0;
        bool sawExisting = false;
        bool injected = false;
    };
    // Shared callback state outlives the Make result and remains owned by the
    // mock until its actions retire. Keep native callbacks allocation-free.
    const auto observed = std::make_shared<Observation>();
    auto policy = CrossMountPathPolicy();
    policy.missingFiles = ComplianceEngine::Filesystem::MissingFileDisposition::Report;
    EXPECT_CALL(context, OpenNativeAt(_, _, _)).Times(testing::AnyNumber());
    EXPECT_CALL(context, OpenNativeAt(_, testing::StrEq("existing"), _)).WillRepeatedly([this, observed](int directory, const char* name, int flags) {
        const int fd = context.RealOpenNativeAt(directory, name, flags);
        if (fd >= 0)
        {
            ++observed->directOpens;
            observed->procOpensAtDirect = observed->procOpens;
            observed->sawExisting = true;
        }
        return fd;
    });
    EXPECT_CALL(context, OpenNativePath(_, _)).Times(testing::AnyNumber());
    EXPECT_CALL(context, OpenNativePath(testing::StrEq("/proc"), _)).WillRepeatedly([this, observed](const char* path, int flags) {
        ++observed->procOpens;
        if (observed->sawExisting && !observed->injected)
        {
            observed->injected = true;
            errno = ENOENT;
            return -1;
        }
        return context.RealOpenNativePath(path, flags);
    });
    auto result = Path::Make(context, base + "/existing/missing", policy, AmpleLimits());
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(ENOENT, result.Error().code);
    EXPECT_TRUE(observed->injected);
    EXPECT_GE(observed->directOpens, 1);
    EXPECT_GT(observed->procOpensAtDirect, 0);                   // root bootstrap succeeded
    EXPECT_GT(observed->procOpens, observed->procOpensAtDirect); // later helper failed
}

TEST_F(PathAliasTest, PublicResolvePreservesMissingDisposition)
{
    const std::string base = context.GetTempdirPath();
    auto selected = SelectAcceptedPath(context, base, CrossMountPathPolicy(), AmpleLimits());
    ASSERT_TRUE(selected.HasValue()) << selected.Error().message;
    auto policy = CrossMountPathPolicy();
    auto error = selected.Value().Resolve("missing", policy);
    ASSERT_FALSE(error.HasValue());
    EXPECT_EQ(ENOENT, error.Error().code);
    policy.missingFiles = ComplianceEngine::Filesystem::MissingFileDisposition::Report;
    auto reported = selected.Value().Resolve("missing", policy);
    ASSERT_TRUE(reported.HasValue()) << reported.Error().message;
    ASSERT_TRUE(reported.Value().Is<Path::RejectionReason>());
    EXPECT_EQ(Path::RejectionReason::Missing, As<Path::RejectionReason>(reported.Value()));
}

// Historical Path outcome dispatch and ownership, adapted to the owning
// Resolve/Apply result rather than the removed Push/Pop result adapter.
TEST_F(PathAliasTest, PathOutcomesDispatchAndRetainPinsThroughExtraction)
{
    const std::string base = context.GetTempdirPath();
    auto missing = Path::Make(context, base + "/directly-absent", CrossMountPathPolicy(), AmpleLimits());
    ASSERT_TRUE(missing.HasValue()) << missing.Error().message;
    ASSERT_TRUE(missing.Value().Is<Path::RejectionReason>());
    EXPECT_EQ(Path::RejectionReason::Missing, As<Path::RejectionReason>(missing.Value()));
    EXPECT_THROW((void)As<Path>(missing.Value()), std::logic_error);
    EXPECT_THROW((void)As<Path>(std::move(missing.Value())), std::logic_error);

    const std::string link = base + "/excluded-link";
    ASSERT_EQ(0, ::symlink("directly-absent", link.c_str()));
    auto skip = CrossMountPathPolicy();
    skip.rejectedLinks = ComplianceEngine::Filesystem::RejectedLinkDisposition::Skip;
    auto excluded = Path::Make(context, link, skip, AmpleLimits());
    ASSERT_TRUE(excluded.HasValue()) << excluded.Error().message;
    ASSERT_TRUE(excluded.Value().Is<Path::RejectionReason>());
    const auto& constExcluded = excluded.Value();
    EXPECT_EQ(Path::RejectionReason::Excluded, As<Path::RejectionReason>(constExcluded));
    EXPECT_THROW((void)As<Path>(constExcluded), std::logic_error);
    EXPECT_THROW((void)As<Path>(std::move(excluded.Value())), std::logic_error);

    const auto before = CountOpenDescriptors();
    std::unique_ptr<Path> retained;
    {
        auto opened = Path::Make(context, "/", CrossMountPathPolicy(), AmpleLimits());
        ASSERT_TRUE(opened.HasValue()) << opened.Error().message;
        ASSERT_TRUE(opened.Value().Is<Path>());
        const auto& accepted = opened.Value();
        EXPECT_EQ(1u, As<Path>(accepted).Size());
        EXPECT_THROW((void)As<Path::RejectionReason>(accepted), std::logic_error);
        Variant<Path, Path::RejectionReason> moved(std::move(opened.Value()));
        retained.reset(new Path(As<Path>(std::move(moved))));
        EXPECT_EQ(1u, retained->Size());
    }
    ASSERT_NE(nullptr, retained);
    EXPECT_GT(CountOpenDescriptors(), before);
    EXPECT_EQ("/", retained->Root().LookupName());
    retained.reset();
    EXPECT_EQ(before, CountOpenDescriptors());
}

TEST_F(PathAliasTest, PathOutcomeAlternativeReplacementAndSelfMoveRetainExactPins)
{
    using Outcome = Variant<Path, Path::RejectionReason>;
    const auto before = CountOpenDescriptors();
    {
        // Make results have retired: Path moves intentionally leave valid source
        // snapshots, so only the owning variants here determine pin lifetime.
        auto acquire = [&]() -> Outcome {
            auto opened = Path::Make(context, "/", CrossMountPathPolicy(), AmpleLimits());
            EXPECT_TRUE(opened.HasValue());
            return Outcome(std::move(opened.Value()));
        };
        Outcome destination = acquire();
        Outcome incoming = acquire();
        const auto oldPins = As<Path>(destination).RetainedDescriptors();
        const auto newPins = As<Path>(incoming).RetainedDescriptors();
        const auto held = CountOpenDescriptors();
        ASSERT_GT(oldPins, 0u);
        ASSERT_GT(newPins, 0u);
        destination = std::move(incoming);
        EXPECT_EQ(held - oldPins, CountOpenDescriptors());
        EXPECT_TRUE(destination.Is<Path>());
        EXPECT_EQ(newPins, As<Path>(destination).RetainedDescriptors());

        Outcome marker(InPlaceType<Path::RejectionReason>{}, Path::RejectionReason::Missing);
        EXPECT_EQ(Path::RejectionReason::Missing, As<Path::RejectionReason>(marker));
        marker = std::move(destination);
        EXPECT_TRUE(marker.Is<Path>());
        marker = Outcome(InPlaceType<Path::RejectionReason>{}, Path::RejectionReason::Excluded);
        EXPECT_EQ(Path::RejectionReason::Excluded, As<Path::RejectionReason>(marker));
        // Moved-from Path snapshots retain ownership until their variants die.
        EXPECT_EQ(before + newPins, CountOpenDescriptors());
    }
    EXPECT_EQ(before, CountOpenDescriptors());
    {
        auto third = Path::Make(context, "/", CrossMountPathPolicy(), AmpleLimits());
        ASSERT_TRUE(third.HasValue());
        Outcome marker(std::move(third.Value()));
        const auto finalPins = As<Path>(marker).RetainedDescriptors();
        const auto heldThird = CountOpenDescriptors();
        Outcome& same = marker;
        marker = std::move(same);
        EXPECT_EQ(finalPins, As<Path>(marker).RetainedDescriptors());
        EXPECT_EQ(heldThird, CountOpenDescriptors());
        marker = Outcome(InPlaceType<Path::RejectionReason>{}, Path::RejectionReason::Missing);
        EXPECT_EQ(heldThird, CountOpenDescriptors()); // third retains the moved-from snapshot
    }
    EXPECT_EQ(before, CountOpenDescriptors());
}

TEST_F(PathAliasTest, PathPolicyAndResolverDefaultsAreIndependentAndBounded)
{
    Path::Policy policy;
    EXPECT_EQ(PrefixLinkPolicy::Reject, policy.prefixLinks);
    EXPECT_EQ(FileLinkPolicy::Reject, policy.fileLinks);
    EXPECT_EQ(DirectoryLinkPolicy::Reject, policy.directoryLinks);
    EXPECT_EQ(MountPolicy::StayOnRootMount, policy.mounts);
    EXPECT_EQ(ComplianceEngine::Filesystem::RejectedLinkDisposition::Error, policy.rejectedLinks);
    EXPECT_EQ(ComplianceEngine::Filesystem::UnsupportedTypeDisposition::Error, policy.unsupportedTypes);
    EXPECT_EQ(ComplianceEngine::Filesystem::MissingFileDisposition::Error, policy.missingFiles);
    policy.prefixLinks = PrefixLinkPolicy::Follow;
    EXPECT_EQ(FileLinkPolicy::Reject, policy.fileLinks);
    EXPECT_EQ(DirectoryLinkPolicy::Reject, policy.directoryLinks);

    const ResolverLimits limits;
    EXPECT_EQ(4096u, limits.shared.targetBytes);
    EXPECT_EQ(128u, limits.shared.components);
    EXPECT_EQ(100000u, limits.shared.work);
    EXPECT_EQ(256u, limits.shared.liveDescriptors);
    EXPECT_EQ(std::size_t{1024} * 1024, limits.shared.retainedBytes);
    EXPECT_EQ(4096u, limits.shared.fdinfoBytes);
    EXPECT_EQ(4096u, limits.linkTargetBytes);
    EXPECT_EQ(128u, limits.linkExpansions);
    EXPECT_EQ(128u, limits.depth);
    ResolverLimits exhausted;
    exhausted.shared.work = 1;
    auto root = Path::Make(context, context.GetTempdirPath(), CrossMountPathPolicy(), exhausted);
    ASSERT_FALSE(root.HasValue());
    EXPECT_EQ(E2BIG, root.Error().code);
    EXPECT_EQ(100000u, limits.shared.work);
}

TEST_F(PathAliasTest, InvalidAbsoluteFactoryInputNeverPublishesPartialPath)
{
    const std::string base = context.GetTempdirPath();
    const auto policy = CrossMountPathPolicy();
    EXPECT_CALL(context, OpenNativePath(_, _)).Times(0);
    for (const std::string& invalid : {std::string("relative"), base + std::string("\0bad", 4), std::string()})
    {
        auto result = Path::Make(context, invalid, policy, AmpleLimits());
        ASSERT_FALSE(result.HasValue());
        EXPECT_EQ(EINVAL, result.Error().code);
    }
    testing::Mock::VerifyAndClearExpectations(&context);
    auto missing = Path::Make(context, base + "/missing-prefix/child", policy, AmpleLimits());
    ASSERT_TRUE(missing.HasValue()) << missing.Error().message;
    ASSERT_TRUE(missing.Value().Is<Path::RejectionReason>()); // no partially acquired Path escapes
    EXPECT_EQ(Path::RejectionReason::Missing, As<Path::RejectionReason>(missing.Value()));
}

TEST_F(PathAliasTest, ProcessRootMountObservationIsRetainedAcrossResolveAndInverse)
{
    int observations = 0;
    EXPECT_CALL(context, ReadFileDescriptor(_, _, _)).WillRepeatedly([&](int fd, void* buffer, std::size_t count) {
        const ssize_t bytes = context.RealReadFileDescriptor(fd, buffer, count);
        if (bytes > 0 && DescriptorTarget(fd).find("/fdinfo/") != std::string::npos &&
            std::string(static_cast<char*>(buffer), static_cast<std::size_t>(bytes)).find("mnt_id:") != std::string::npos)
            ++observations;
        return bytes;
    });
    auto opened = SelectAcceptedPath(context, "/", CrossMountPathPolicy(), AmpleLimits());
    ASSERT_TRUE(opened.HasValue()) << opened.Error().message;
    Path path = std::move(opened).Value();
    EXPECT_EQ(1, observations);
    OwnedTestDescriptor kernelRoot(::open("/", O_PATH | O_CLOEXEC));
    ASSERT_GE(kernelRoot.Get(), 0);
    auto kernelId = KernelMountId(kernelRoot.Get());
    ASSERT_TRUE(kernelId.HasValue());
    EXPECT_EQ(kernelId.Value(), path.Root().Acquired().lookupMount.value);
    EXPECT_EQ(kernelId.Value(), path.Root().Acquired().targetMount.value);
    EXPECT_TRUE(path.Root().OpenChildren().HasValue());
    EXPECT_EQ(1, observations);
    auto child = SelectStep(path, "proc", CrossMountPathPolicy());
    ASSERT_TRUE(child.HasValue()) << child.Error().message;
    EXPECT_EQ(2, observations);
    EXPECT_GT(child.Value().Acquired().targetMount.value, 0u);
    auto inverse = path.Apply(std::move(child.Value()));
    ASSERT_TRUE(inverse.HasValue()) << inverse.Error().message;
    EXPECT_EQ(2, observations);
    auto restored = path.Apply(std::move(inverse.Value()));
    ASSERT_TRUE(restored.HasValue()) << restored.Error().message;
    EXPECT_TRUE(path.Root().OpenChildren().HasValue());
    EXPECT_EQ(2, observations);
    EXPECT_EQ("/", path.ToString());
}

TEST_F(PathAliasTest, MovedPathEnforcesRetainedNativeDescriptorCap)
{
    auto limits = AmpleLimits();
    limits.shared.liveDescriptors = 5; // /etc needs two retained pins + three helper pins; passwd would need six.
    auto opened = SelectAcceptedPath(context, "/", CrossMountPathPolicy(), limits);
    ASSERT_TRUE(opened.HasValue()) << opened.Error().message;
    Path path = std::move(opened).Value();
    auto first = SelectStep(path, "etc", CrossMountPathPolicy());
    ASSERT_TRUE(first.HasValue()) << first.Error().message;
    ASSERT_TRUE(path.Apply(std::move(first.Value())).HasValue());
    Path moved(std::move(path));
    EXPECT_EQ(2u, moved.Size());
    EXPECT_EQ("/etc", path.ToString()); // move-as-copy keeps the source valid
    auto cap = moved.Resolve("passwd", CrossMountPathPolicy());
    ASSERT_FALSE(cap.HasValue());
    EXPECT_EQ(EMFILE, cap.Error().code);
    EXPECT_EQ(2u, moved.Size());
    EXPECT_EQ("/etc", moved.ToString());
}

TEST_F(PathAliasTest, HeldAliasExpiresFromActiveAncestryAfterInverse)
{
    const std::string root = context.GetTempdirPath() + "/accepted";
    ASSERT_EQ(0, ::mkdir(root.c_str(), 0700));
    ASSERT_EQ(0, ::mkdir((root + "/a").c_str(), 0700));
    ASSERT_EQ(0, ::mkdir((root + "/b").c_str(), 0700));
    const std::string a = context.MakeTempfile("a");
    const std::string b = context.MakeTempfile("b");
    ASSERT_EQ(0, ::rename(a.c_str(), (root + "/a/file").c_str()));
    ASSERT_EQ(0, ::rename(b.c_str(), (root + "/b/file").c_str()));
    ASSERT_EQ(0, ::symlink("a", (root + "/alias").c_str()));
    ASSERT_EQ(0, ::symlink((root + "/alias/file").c_str(), (root + "/a/absolute").c_str()));
    ASSERT_EQ(0, ::symlink((root + "/alias/file").c_str(), (root + "/absolute").c_str()));
    struct stat original = {}, replacement = {};
    ASSERT_EQ(0, ::stat((root + "/a/file").c_str(), &original));
    ASSERT_EQ(0, ::stat((root + "/b/file").c_str(), &replacement));
    auto opened = SelectAcceptedPath(context, root, CrossMountPathPolicy(), AmpleLimits());
    ASSERT_TRUE(opened.HasValue());
    Path path = std::move(opened).Value();
    auto follow = CrossMountPathPolicy(true);
    auto alias = SelectStep(path, "alias", follow);
    ASSERT_TRUE(alias.HasValue()) << alias.Error().message;
    auto back = path.Apply(std::move(alias.Value()));
    ASSERT_TRUE(back.HasValue()) << back.Error().message;
    ASSERT_EQ(0, ::unlink((root + "/alias").c_str()));
    ASSERT_EQ(0, ::symlink("b", (root + "/alias").c_str()));
    auto pinned = SelectStep(path, "absolute", follow);
    ASSERT_TRUE(pinned.HasValue()) << pinned.Error().message;
    EXPECT_EQ(original.st_ino, pinned.Value().Acquired().metadata.st_ino);
    EXPECT_EQ(root + "/a/file", pinned.Value().Target().EffectiveName());
    auto undo = path.Apply(std::move(back.Value()));
    ASSERT_TRUE(undo.HasValue()) << undo.Error().message;
    auto fresh = SelectStep(path, "absolute", follow);
    ASSERT_TRUE(fresh.HasValue()) << fresh.Error().message;
    EXPECT_EQ(replacement.st_ino, fresh.Value().Acquired().metadata.st_ino);
    EXPECT_EQ(root + "/b/file", fresh.Value().Target().EffectiveName());
}

TEST_F(PathAliasTest, RenamedIntermediatePinnedAncestorIsNotReopenedByAbsoluteTarget)
{
    const std::string root = context.GetTempdirPath() + "/accepted";
    ASSERT_EQ(0, ::mkdir(root.c_str(), 0700));
    ASSERT_EQ(0, ::mkdir((root + "/a").c_str(), 0700));
    const std::string oldFile = context.MakeTempfile("old");
    const std::string newFile = context.MakeTempfile("new");
    ASSERT_EQ(0, ::rename(oldFile.c_str(), (root + "/a/file").c_str()));
    ASSERT_EQ(0, ::symlink((root + "/a/file").c_str(), (root + "/a/absolute").c_str()));
    struct stat expected = {}, substitute = {};
    ASSERT_EQ(0, ::stat((root + "/a/file").c_str(), &expected));
    auto opened = SelectAcceptedPath(context, root, CrossMountPathPolicy(), AmpleLimits());
    ASSERT_TRUE(opened.HasValue());
    Path path = std::move(opened).Value();
    auto enter = SelectStep(path, "a", CrossMountPathPolicy());
    ASSERT_TRUE(enter.HasValue());
    auto leave = path.Apply(std::move(enter.Value()));
    ASSERT_TRUE(leave.HasValue());
    ASSERT_EQ(0, ::rename((root + "/a").c_str(), (root + "/former").c_str()));
    ASSERT_EQ(0, ::mkdir((root + "/a").c_str(), 0700));
    ASSERT_EQ(0, ::rename(newFile.c_str(), (root + "/a/file").c_str()));
    ASSERT_EQ(0, ::stat((root + "/a/file").c_str(), &substitute));
    auto pinned = SelectStep(path, "absolute", CrossMountPathPolicy(true));
    ASSERT_TRUE(pinned.HasValue()) << pinned.Error().message;
    EXPECT_EQ(expected.st_ino, pinned.Value().Acquired().metadata.st_ino);
    EXPECT_EQ(root + "/a/file", pinned.Value().Target().EffectiveName());
    ASSERT_TRUE(path.Apply(std::move(leave.Value())).HasValue());
    auto fresh = SelectStep(path, "a", CrossMountPathPolicy());
    ASSERT_TRUE(fresh.HasValue());
    ASSERT_TRUE(path.Apply(std::move(fresh.Value())).HasValue());
    auto selected = SelectStep(path, "file", CrossMountPathPolicy());
    ASSERT_TRUE(selected.HasValue());
    EXPECT_EQ(substitute.st_ino, selected.Value().Acquired().metadata.st_ino);
}

TEST_F(PathAliasTest, PhysicalSuffixFailureIsAtomicAndInverseRemovesOnlyItsSuffix)
{
    const std::string root = context.GetTempdirPath() + "/physical";
    ASSERT_EQ(0, ::mkdir(root.c_str(), 0700));
    ASSERT_EQ(0, ::mkdir((root + "/a").c_str(), 0700));
    ASSERT_EQ(0, ::mkdir((root + "/a/b").c_str(), 0700));
    ASSERT_EQ(0, ::symlink("a/b", (root + "/link").c_str()));
    ASSERT_EQ(0, ::symlink("a/absent", (root + "/broken").c_str()));
    auto opened = SelectAcceptedPath(context, root, CrossMountPathPolicy(), AmpleLimits());
    ASSERT_TRUE(opened.HasValue());
    Path path = std::move(opened).Value();
    const auto depth = path.Size();
    auto broken = path.Resolve("broken", CrossMountPathPolicy(true));
    ASSERT_FALSE(broken.HasValue());
    EXPECT_EQ(ENOENT, broken.Error().code);
    EXPECT_EQ(root, path.ToString());
    EXPECT_EQ(depth, path.Size());
    auto suffix = SelectStep(path, "link", CrossMountPathPolicy(true));
    ASSERT_TRUE(suffix.HasValue()) << suffix.Error().message;
    auto inverse = path.Apply(std::move(suffix.Value()));
    ASSERT_TRUE(inverse.HasValue()) << inverse.Error().message;
    EXPECT_EQ(depth + 2, path.Size());
    EXPECT_EQ(root + "/a/b", path.ToString());
    auto restored = path.Apply(std::move(inverse.Value()));
    ASSERT_TRUE(restored.HasValue()) << restored.Error().message;
    EXPECT_EQ(depth, path.Size());
    EXPECT_EQ(root, path.ToString());
}

TEST_F(PathAliasTest, IndependentPhysicalBranchesKeepTheirPinsAndRejectStaleSteps)
{
    const std::string root = context.GetTempdirPath() + "/branches";
    ASSERT_EQ(0, ::mkdir(root.c_str(), 0700));
    ASSERT_EQ(0, ::mkdir((root + "/first").c_str(), 0700));
    ASSERT_EQ(0, ::mkdir((root + "/second").c_str(), 0700));
    ASSERT_EQ(0, ::symlink("../second", (root + "/first/shortcut").c_str()));
    auto opened = SelectAcceptedPath(context, root, CrossMountPathPolicy(), AmpleLimits());
    ASSERT_TRUE(opened.HasValue());
    Path path = std::move(opened).Value();
    auto first = SelectStep(path, "first", CrossMountPathPolicy());
    ASSERT_TRUE(first.HasValue());
    auto rootInverse = path.Apply(std::move(first.Value()));
    ASSERT_TRUE(rootInverse.HasValue());
    Path::Component heldFirst = path.Leaf();
    auto branchStep = SelectStep(path, "shortcut", CrossMountPathPolicy(true));
    ASSERT_TRUE(branchStep.HasValue()) << branchStep.Error().message;
    auto stale = SelectStep(path, "shortcut", CrossMountPathPolicy(true));
    ASSERT_TRUE(stale.HasValue());
    Path branch(std::move(path)); // move-as-copy, both snapshots still own first
    EXPECT_CALL(context, OpenNativeAt(_, _, _)).Times(0);
    EXPECT_CALL(context, DuplicateDescriptor(_)).Times(0);
    auto undo = branch.Apply(std::move(branchStep.Value()));
    ASSERT_TRUE(undo.HasValue()) << undo.Error().message;
    EXPECT_EQ(root + "/second", branch.ToString());
    EXPECT_EQ(root + "/first", path.ToString());
    EXPECT_NE(heldFirst.Acquired().metadata.st_ino, branch.Leaf().Acquired().metadata.st_ino);
    ASSERT_EQ(0, ::rename((root + "/first").c_str(), (root + "/renamed").c_str()));
    EXPECT_EQ(root + "/first", heldFirst.EffectiveName());
    EXPECT_TRUE(heldFirst.Stat().HasValue());
    EXPECT_EQ(root + "/first", path.ToString());
    auto oldBranch = branch.Apply(std::move(stale.Value()));
    ASSERT_FALSE(oldBranch.HasValue());
    EXPECT_EQ(ESTALE, oldBranch.Error().code);
    auto back = branch.Apply(std::move(undo.Value()));
    ASSERT_TRUE(back.HasValue()) << back.Error().message;
    EXPECT_EQ(root + "/first", branch.ToString());
}

TEST_F(PathAliasTest, ReusedSlotNeverReplacesOwningCopyOfOldBranch)
{
    const std::string root = context.GetTempdirPath() + "/restoration";
    ASSERT_EQ(0, ::mkdir(root.c_str(), 0700));
    ASSERT_EQ(0, ::mkdir((root + "/first").c_str(), 0700));
    ASSERT_EQ(0, ::mkdir((root + "/second").c_str(), 0700));
    auto opened = SelectAcceptedPath(context, root, CrossMountPathPolicy(), AmpleLimits());
    ASSERT_TRUE(opened.HasValue());
    Path path = std::move(opened).Value();
    auto first = SelectStep(path, "first", CrossMountPathPolicy());
    ASSERT_TRUE(first.HasValue());
    auto back = path.Apply(std::move(first.Value()));
    ASSERT_TRUE(back.HasValue());
    Path::Component old = path.Leaf();
    ASSERT_TRUE(path.Apply(std::move(back.Value())).HasValue());
    auto second = SelectStep(path, "second", CrossMountPathPolicy());
    ASSERT_TRUE(second.HasValue());
    ASSERT_TRUE(path.Apply(std::move(second.Value())).HasValue());
    EXPECT_EQ(root + "/first", old.EffectiveName());
    EXPECT_TRUE(old.Stat().HasValue());
    EXPECT_NE(old.Acquired().metadata.st_ino, path.Leaf().Acquired().metadata.st_ino);
    EXPECT_EQ(root + "/second", path.ToString());
}

TEST_F(PathAliasTest, InvalidFdinfoLimitIsRejectedBeforeRootAcquisition)
{
    auto limits = AmpleLimits();
    limits.shared.fdinfoBytes = 0;
    EXPECT_CALL(context, OpenNativePath(_, _)).Times(0);
    auto invalid = Path::Make(context, "/", CrossMountPathPolicy(), limits);
    ASSERT_FALSE(invalid.HasValue());
    EXPECT_EQ(EINVAL, invalid.Error().code);
    limits.shared.fdinfoBytes = std::numeric_limits<std::size_t>::max();
    auto overflow = Path::Make(context, "/", CrossMountPathPolicy(), limits);
    ASSERT_FALSE(overflow.HasValue());
    EXPECT_EQ(EINVAL, overflow.Error().code);
    ASSERT_TRUE(testing::Mock::VerifyAndClearExpectations(&context));
    limits.shared.fdinfoBytes = 1;
    auto insufficient = Path::Make(context, "/", CrossMountPathPolicy(), limits);
    ASSERT_FALSE(insufficient.HasValue());
    EXPECT_EQ(E2BIG, insufficient.Error().code);
    limits.shared.fdinfoBytes = 4096;
    auto selected = SelectAcceptedPath(context, "/", CrossMountPathPolicy(), limits);
    ASSERT_TRUE(selected.HasValue());
    Path moved(std::move(selected.Value()));
    EXPECT_TRUE(selected.Value().Root().Stat().HasValue());
    EXPECT_TRUE(moved.Root().Stat().HasValue());
}

TEST_F(PathAliasTest, DeepGrowthKeepsOwningAncestorsAcrossFailedResolveAndInverses)
{
    const std::string base = context.GetTempdirPath() + "/accepted";
    ASSERT_EQ(0, ::mkdir(base.c_str(), 0700));
    auto limits = AmpleLimits();
    limits.shared.components = 4096;
    limits.shared.work = 20000000;
    limits.shared.liveDescriptors = 4096;
    limits.shared.retainedBytes = 16u * 1024u * 1024u;
    limits.depth = 4096;
    auto selected = SelectAcceptedPath(context, base, CrossMountPathPolicy(), limits);
    ASSERT_TRUE(selected.HasValue()) << selected.Error().message;
    Path path = std::move(selected).Value();
    const auto initialDepth = path.Size();
    Path::Component root = path.Leaf();
    Path::Component processRoot = path.Root();
    std::unique_ptr<Path::Component> first;
    std::vector<Path::Step> inverses;
    inverses.reserve(72);
    std::string current = base;
    for (int index = 0; index < 72; ++index)
    {
        current += "/d";
        ASSERT_EQ(0, ::mkdir(current.c_str(), 0700));
        auto next = SelectStep(path, "d", CrossMountPathPolicy());
        ASSERT_TRUE(next.HasValue()) << index << ": " << next.Error().message;
        auto undo = path.Apply(std::move(next.Value()));
        ASSERT_TRUE(undo.HasValue()) << index << ": " << undo.Error().message;
        inverses.push_back(std::move(undo.Value()));
        if (0 == index)
            first.reset(new Path::Component(path.Leaf()));
        EXPECT_EQ(processRoot.Acquired().metadata.st_ino, path.Root().Acquired().metadata.st_ino);
    }
    ASSERT_NE(nullptr, first);
    EXPECT_EQ(initialDepth + 72, path.Size());
    EXPECT_EQ(current, path.ToString());
    auto invalid = path.Resolve("../escape", CrossMountPathPolicy());
    ASSERT_FALSE(invalid.HasValue());
    EXPECT_EQ(EINVAL, invalid.Error().code);
    EXPECT_EQ(initialDepth + 72, path.Size());
    ASSERT_EQ(0, ::symlink("absent", (current + "/broken").c_str()));
    auto failedAlias = path.Resolve("broken", CrossMountPathPolicy(true));
    ASSERT_FALSE(failedAlias.HasValue());
    EXPECT_EQ(ENOENT, failedAlias.Error().code);
    EXPECT_EQ(current, path.ToString());
    EXPECT_TRUE(first->Stat().HasValue());
    for (int index = 71; index >= 0; --index)
    {
        auto restored = path.Apply(std::move(inverses[static_cast<std::size_t>(index)]));
        ASSERT_TRUE(restored.HasValue()) << index << ": " << restored.Error().message;
        EXPECT_TRUE(first->Stat().HasValue());
    }
    EXPECT_EQ(initialDepth, path.Size());
    EXPECT_EQ(base, path.ToString());
    EXPECT_TRUE(root.Stat().HasValue());
    EXPECT_TRUE(first->Stat().HasValue());
}

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
    auto children = path.Leaf().OpenChildren();
    ASSERT_TRUE(children.HasValue()) << children.Error().message;
    bool found = false;
    for (;;)
    {
        auto entry = children.Value().Next();
        ASSERT_TRUE(entry.HasValue()) << entry.Error().message;
        if (!entry.Value().HasValue())
            break;
        found = found || (name == entry.Value().Value());
    }
    EXPECT_TRUE(found);
    auto selected = SelectStep(path, name, Path::Policy{});
    ASSERT_TRUE(selected.HasValue()) << selected.Error().message;
    EXPECT_EQ(path.Leaf().Acquired().targetMount.value, selected.Value().Acquired().targetMount.value);
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
}

TEST_F(PathAliasTest, TerminalLinkSkipIsIndependentOfDirectoryAndFileFollow)
{
    const std::string base = context.GetTempdirPath();
    const std::string real = base + "/target-directory";
    ASSERT_EQ(0, ::mkdir(real.c_str(), 0700));
    const auto source = context.MakeTempfile("contents");
    ASSERT_EQ(0, ::rename(source.c_str(), (real + "/file").c_str()));
    ASSERT_EQ(0, ::symlink("target-directory", (base + "/directory-link").c_str()));
    ASSERT_EQ(0, ::symlink("target-directory/file", (base + "/file-link").c_str()));
    auto policy = CrossMountPathPolicy();
    policy.rejectedLinks = ComplianceEngine::Filesystem::RejectedLinkDisposition::Skip;
    auto file = Path::Make(context, base + "/file-link", policy, AmpleLimits());
    ASSERT_TRUE(file.HasValue());
    ASSERT_TRUE(file.Value().Is<Path::RejectionReason>());
    EXPECT_EQ(Path::RejectionReason::Excluded, As<Path::RejectionReason>(file.Value()));
    auto directory = Path::Make(context, base + "/directory-link", policy, AmpleLimits());
    ASSERT_TRUE(directory.HasValue());
    ASSERT_TRUE(directory.Value().Is<Path::RejectionReason>());
    EXPECT_EQ(Path::RejectionReason::Excluded, As<Path::RejectionReason>(directory.Value()));
    policy.directoryLinks = DirectoryLinkPolicy::Follow;
    auto acceptedDirectory = Path::Make(context, base + "/directory-link", policy, AmpleLimits());
    ASSERT_TRUE(acceptedDirectory.HasValue()) << acceptedDirectory.Error().message;
    ASSERT_TRUE(acceptedDirectory.Value().Is<Path>());
    EXPECT_EQ(real, As<Path>(acceptedDirectory.Value()).ToString());
    auto rejectedFile = Path::Make(context, base + "/file-link", policy, AmpleLimits());
    ASSERT_TRUE(rejectedFile.HasValue());
    ASSERT_TRUE(rejectedFile.Value().Is<Path::RejectionReason>());
    EXPECT_EQ(Path::RejectionReason::Excluded, As<Path::RejectionReason>(rejectedFile.Value()));

    auto selected = SelectAcceptedPath(context, base, CrossMountPathPolicy(), AmpleLimits());
    ASSERT_TRUE(selected.HasValue());
    const auto depth = selected.Value().Size();
    auto skipFile = selected.Value().Resolve("file-link", policy);
    ASSERT_TRUE(skipFile.HasValue());
    ASSERT_TRUE(skipFile.Value().Is<Path::RejectionReason>());
    EXPECT_EQ(Path::RejectionReason::Excluded, As<Path::RejectionReason>(skipFile.Value()));
    EXPECT_EQ(depth, selected.Value().Size());
    auto followDirectory = SelectStep(selected.Value(), "directory-link", policy);
    ASSERT_TRUE(followDirectory.HasValue()) << followDirectory.Error().message;
    EXPECT_EQ(Type::Directory, followDirectory.Value().Acquired().type);
    EXPECT_EQ(depth, selected.Value().Size());
    auto prefix = Path::Make(context, base + "/directory-link/file", CrossMountPathPolicy(), AmpleLimits());
    ASSERT_FALSE(prefix.HasValue());
    EXPECT_EQ(ELOOP, prefix.Error().code);
}

TEST_F(PathAliasTest, PhysicalParentOfRelativeLinkUsesPinnedAncestorNotLogicalLeaf)
{
    const std::string root = context.GetTempdirPath() + "/accepted";
    ASSERT_EQ(0, ::mkdir(root.c_str(), 0700));
    ASSERT_EQ(0, ::mkdir((root + "/a").c_str(), 0700));
    ASSERT_EQ(0, ::mkdir((root + "/a/b").c_str(), 0700));
    ASSERT_EQ(0, ::mkdir((root + "/a/other").c_str(), 0700));
    ASSERT_EQ(0, ::symlink("a/b", (root + "/link").c_str()));
    ASSERT_EQ(0, ::symlink("../other", (root + "/a/b/childalias").c_str()));
    struct stat expected = {};
    ASSERT_EQ(0, ::stat((root + "/a/other").c_str(), &expected));
    auto opened = SelectAcceptedPath(context, root, CrossMountPathPolicy(), AmpleLimits());
    ASSERT_TRUE(opened.HasValue());
    Path path = std::move(opened).Value();
    const auto depth = path.Size();
    auto link = SelectStep(path, "link", CrossMountPathPolicy(true));
    ASSERT_TRUE(link.HasValue()) << link.Error().message;
    auto back = path.Apply(std::move(link.Value()));
    ASSERT_TRUE(back.HasValue()) << back.Error().message;
    EXPECT_EQ(depth + 2, path.Size());
    auto alias = SelectStep(path, "childalias", CrossMountPathPolicy(true));
    ASSERT_TRUE(alias.HasValue()) << alias.Error().message;
    EXPECT_EQ(expected.st_ino, alias.Value().Acquired().metadata.st_ino);
    auto inverse = path.Apply(std::move(alias.Value()));
    ASSERT_TRUE(inverse.HasValue()) << inverse.Error().message;
    EXPECT_EQ(root + "/a/other", path.ToString());
    auto restore = path.Apply(std::move(inverse.Value()));
    ASSERT_TRUE(restore.HasValue());
    EXPECT_EQ(root + "/a/b", path.ToString());
    EXPECT_TRUE(path.Apply(std::move(back.Value())).HasValue());
    EXPECT_EQ(root, path.ToString());
}

TEST_F(PathAliasTest, HeldAliasAncestryResolvesDotDotBeforeLexicalRootShortcut)
{
    const std::string root = context.GetTempdirPath() + "/accepted";
    ASSERT_EQ(0, ::mkdir(root.c_str(), 0700));
    ASSERT_EQ(0, ::mkdir((root + "/a").c_str(), 0700));
    ASSERT_EQ(0, ::mkdir((root + "/a/b").c_str(), 0700));
    ASSERT_EQ(0, ::symlink("a/b", (root + "/alias").c_str()));
    ASSERT_EQ(0, ::symlink((root + "/alias/../victim").c_str(), (root + "/a/b/jump").c_str()));
    const auto expectedFile = context.MakeTempfile("expected");
    const auto wrongFile = context.MakeTempfile("wrong");
    ASSERT_EQ(0, ::rename(expectedFile.c_str(), (root + "/a/victim").c_str()));
    ASSERT_EQ(0, ::rename(wrongFile.c_str(), (root + "/victim").c_str()));
    struct stat expected = {}, wrong = {};
    ASSERT_EQ(0, ::stat((root + "/a/victim").c_str(), &expected));
    ASSERT_EQ(0, ::stat((root + "/victim").c_str(), &wrong));
    ASSERT_NE(expected.st_ino, wrong.st_ino);
    auto opened = SelectAcceptedPath(context, root, CrossMountPathPolicy(), AmpleLimits());
    ASSERT_TRUE(opened.HasValue());
    Path path = std::move(opened).Value();
    auto alias = SelectStep(path, "alias", CrossMountPathPolicy(true));
    ASSERT_TRUE(alias.HasValue()) << alias.Error().message;
    auto back = path.Apply(std::move(alias.Value()));
    ASSERT_TRUE(back.HasValue()) << back.Error().message;
    auto jump = SelectStep(path, "jump", CrossMountPathPolicy(true));
    ASSERT_TRUE(jump.HasValue()) << jump.Error().message;
    EXPECT_EQ(expected.st_ino, jump.Value().Acquired().metadata.st_ino);
    EXPECT_NE(wrong.st_ino, jump.Value().Acquired().metadata.st_ino);
    EXPECT_EQ(root + "/a/victim", jump.Value().Target().EffectiveName());
    EXPECT_EQ(root + "/a/b", path.ToString());
}

TEST_F(PathAliasTest, HeldFileMountFactsAreObservedAtAcquisitionOnly)
{
    const std::string file = context.MakeTempfile("held");
    const std::string name = file.substr(file.find_last_of("/") + 1);
    int records = 0;
    EXPECT_CALL(context, ReadFileDescriptor(_, _, _)).WillRepeatedly([&](int fd, void* buffer, std::size_t count) {
        const ssize_t bytes = context.RealReadFileDescriptor(fd, buffer, count);
        if (bytes > 0 && DescriptorTarget(fd).find("/fdinfo/") != std::string::npos &&
            std::string(static_cast<char*>(buffer), static_cast<std::size_t>(bytes)).find("mnt_id:") != std::string::npos)
            ++records;
        return bytes;
    });
    auto opened = SelectAcceptedPath(context, file, CrossMountPathPolicy(), AmpleLimits());
    ASSERT_TRUE(opened.HasValue()) << opened.Error().message;
    Path path = std::move(opened).Value();
    const int acquired = records;
    EXPECT_GE(acquired, 2);
    EXPECT_GT(path.Leaf().Acquired().targetMount.value, 0u);
    EXPECT_TRUE(path.Leaf().Stat().HasValue());
    auto read = path.Leaf().OpenReadOnly();
    ASSERT_TRUE(read.HasValue()) << read.Error().message;
    read.Value().Close();
    EXPECT_TRUE(path.Leaf().SetMode(0600).HasValue());
    EXPECT_TRUE(path.Leaf().SetOwnership(ComplianceEngine::Filesystem::UserId(::geteuid()), ComplianceEngine::Filesystem::GroupId(::getegid())).HasValue());
    EXPECT_EQ(acquired, records);
    Path::Component held = path.Leaf();
    Path::Component moved(std::move(held));
    EXPECT_TRUE(held.Stat().HasValue()); // move-as-copy keeps both owners valid
    EXPECT_TRUE(moved.OpenReadOnly().HasValue());
    EXPECT_EQ(acquired, records);
    auto parent = SelectAcceptedPath(context, context.GetTempdirPath(), CrossMountPathPolicy(), AmpleLimits());
    ASSERT_TRUE(parent.HasValue());
    const int beforeChild = records;
    auto child = SelectStep(parent.Value(), name, CrossMountPathPolicy());
    ASSERT_TRUE(child.HasValue()) << child.Error().message;
    EXPECT_EQ(beforeChild + 1, records);
    EXPECT_TRUE(child.Value().Target().OpenReadOnly().HasValue());
    EXPECT_EQ(beforeChild + 1, records);
}

TEST_F(PathAliasTest, FactoryFollowedAbsoluteLinkPreservesLookupAndTargetMountFacts)
{
    const std::string alias = context.GetTempdirPath() + "/proc-mount-alias";
    ASSERT_EQ(0, ::symlink("/proc", alias.c_str()));
    OwnedTestDescriptor source(::open(alias.c_str(), O_PATH | O_NOFOLLOW | O_CLOEXEC));
    OwnedTestDescriptor target(::open("/proc", O_PATH | O_CLOEXEC));
    ASSERT_GE(source.Get(), 0);
    ASSERT_GE(target.Get(), 0);
    auto sourceId = KernelMountId(source.Get());
    auto targetId = KernelMountId(target.Get());
    ASSERT_TRUE(sourceId.HasValue());
    ASSERT_TRUE(targetId.HasValue());
    if (sourceId.Value() == targetId.Value())
        GTEST_SKIP() << "procfs fixture shares mount";
    auto opened = SelectAcceptedPath(context, alias, CrossMountPathPolicy(true), AmpleLimits());
    ASSERT_TRUE(opened.HasValue()) << opened.Error().message;
    const auto facts = opened.Value().Leaf().Acquired();
    EXPECT_EQ(sourceId.Value(), facts.lookupMount.value);
    EXPECT_EQ(targetId.Value(), facts.targetMount.value);
    EXPECT_EQ(Type::Directory, facts.type);
    EXPECT_EQ(alias, opened.Value().LookupName());
    EXPECT_EQ("/proc", opened.Value().ToString());
    EXPECT_EQ("/proc", opened.Value().Leaf().EffectiveName());
}

TEST_F(PathAliasTest, FrozenAbsoluteBindingUsesHeldRootAfterNameReplacement)
{
    const std::string root = context.GetTempdirPath() + "/accepted";
    ASSERT_EQ(0, ::mkdir(root.c_str(), 0700));
    const auto original = context.MakeTempfile("old");
    ASSERT_EQ(0, ::rename(original.c_str(), (root + "/inside").c_str()));
    ASSERT_EQ(0, ::symlink((root + "/inside").c_str(), (root + "/absolute").c_str()));
    auto opened = SelectAcceptedPath(context, root, CrossMountPathPolicy(), AmpleLimits());
    ASSERT_TRUE(opened.HasValue());
    Path path = std::move(opened).Value();
    auto follow = CrossMountPathPolicy(true);
    auto initial = SelectStep(path, "absolute", follow);
    ASSERT_TRUE(initial.HasValue()) << initial.Error().message;
    const auto originalInode = initial.Value().Acquired().metadata.st_ino;
    ASSERT_EQ(0, ::unlink((root + "/absolute").c_str()));
    ASSERT_EQ(0, ::symlink("/etc/passwd", (root + "/absolute").c_str()));
    auto outside = path.Resolve("absolute", follow);
    ASSERT_FALSE(outside.HasValue());
    EXPECT_EQ(EXDEV, outside.Error().code);
    ASSERT_EQ(0, ::unlink((root + "/absolute").c_str()));
    ASSERT_EQ(0, ::symlink((root + "/inside").c_str(), (root + "/absolute").c_str()));
    ASSERT_EQ(0, ::rename(root.c_str(), (root + ".former").c_str()));
    ASSERT_EQ(0, ::mkdir(root.c_str(), 0700));
    const auto replacement = context.MakeTempfile("new");
    ASSERT_EQ(0, ::rename(replacement.c_str(), (root + "/inside").c_str()));
    ASSERT_EQ(0, ::symlink((root + "/inside").c_str(), (root + "/absolute").c_str()));
    EXPECT_CALL(context, OpenNativePath(_, _)).WillRepeatedly([&](const char* name, int flags) { return context.RealOpenNativePath(name, flags); });
    EXPECT_CALL(context, OpenNativePath(testing::StrEq("/"), _)).Times(0);
    auto pinned = SelectStep(path, "absolute", follow);
    ASSERT_TRUE(pinned.HasValue()) << pinned.Error().message;
    EXPECT_EQ(originalInode, pinned.Value().Acquired().metadata.st_ino);
    EXPECT_EQ(root + "/inside", pinned.Value().Target().EffectiveName());
    EXPECT_EQ(root, path.ToString());
}

TEST_F(PathAliasTest, FactoryNormalizesRepeatedSeparatorsAndRequiresDirectoryForTrailingSlash)
{
    const auto file = context.MakeTempfile("contents");
    const std::string link = file + ".link";
    ASSERT_EQ(0, ::symlink(file.c_str(), link.c_str()));
    auto strict = CrossMountPathPolicy();
    auto follow = CrossMountPathPolicy(true);
    auto denied = Path::Make(context, link, strict, AmpleLimits());
    ASSERT_FALSE(denied.HasValue());
    EXPECT_EQ(ELOOP, denied.Error().code);
    auto trailing = Path::Make(context, file + "/", follow, AmpleLimits());
    ASSERT_FALSE(trailing.HasValue());
    EXPECT_EQ(ENOTDIR, trailing.Error().code);
    std::string repeated = "/";
    for (char character : link)
    {
        repeated += character;
        if (character == 47)
            repeated += character;
    }
    auto opened = Path::Make(context, repeated, follow, AmpleLimits());
    ASSERT_TRUE(opened.HasValue()) << opened.Error().message;
    ASSERT_TRUE(opened.Value().Is<Path>());
    EXPECT_EQ(Type::RegularFile, As<Path>(opened.Value()).Leaf().Acquired().type);
    EXPECT_EQ(file, As<Path>(opened.Value()).ToString());
    const std::string base = context.GetTempdirPath();
    ASSERT_EQ(0, ::mkdir((base + "/target").c_str(), 0700));
    ASSERT_EQ(0, ::mkdir((base + "/target/final").c_str(), 0700));
    ASSERT_EQ(0, ::symlink("target", (base + "/first").c_str()));
    ASSERT_EQ(0, ::symlink("final", (base + "/target/second").c_str()));
    auto limits = AmpleLimits();
    limits.linkExpansions = 1;
    auto exceeded = Path::Make(context, base + "/first/second/", follow, limits);
    ASSERT_FALSE(exceeded.HasValue());
    EXPECT_EQ(ELOOP, exceeded.Error().code);
    limits.linkExpansions = 2;
    auto accepted = Path::Make(context, base + "/first/second/", follow, limits);
    ASSERT_TRUE(accepted.HasValue()) << accepted.Error().message;
    ASSERT_TRUE(accepted.Value().Is<Path>());
    EXPECT_EQ(base + "/target/final", As<Path>(accepted.Value()).ToString());
    EXPECT_EQ(Type::Directory, As<Path>(accepted.Value()).Leaf().Acquired().type);
}

TEST_F(PathAliasTest, AcquiredAliasRootRejectsOverlappingAbsoluteBindingAfterReplacement)
{
    const std::string root = context.GetTempdirPath() + "/accepted";
    ASSERT_EQ(0, ::mkdir(root.c_str(), 0700));
    ASSERT_EQ(0, ::symlink(".", (root + "/self").c_str()));
    const auto file = context.MakeTempfile("original");
    ASSERT_EQ(0, ::rename(file.c_str(), (root + "/file").c_str()));
    ASSERT_EQ(0, ::symlink((root + "/self/file").c_str(), (root + "/ambiguous").c_str()));
    ASSERT_EQ(0, ::mkdir((root + "/other").c_str(), 0700));
    auto opened = SelectAcceptedPath(context, root + "/self", CrossMountPathPolicy(true), AmpleLimits());
    ASSERT_TRUE(opened.HasValue()) << opened.Error().message;
    Path path = std::move(opened).Value();
    const auto depth = path.Size();
    EXPECT_EQ(root + "/self", path.LookupName());
    EXPECT_EQ(root, path.ToString());
    ASSERT_EQ(0, ::unlink((root + "/self").c_str()));
    ASSERT_EQ(0, ::symlink("other", (root + "/self").c_str()));
    auto conflict = path.Resolve("ambiguous", CrossMountPathPolicy(true));
    ASSERT_FALSE(conflict.HasValue());
    EXPECT_EQ(EXDEV, conflict.Error().code);
    EXPECT_EQ(root, path.ToString());
    EXPECT_EQ(depth, path.Size());
}

TEST_F(PathAliasTest, DisjointRootBindingsReuseHeldPinButRejectCollidingPrefix)
{
    const std::string root = context.GetTempdirPath() + "/accepted";
    ASSERT_EQ(0, ::mkdir(root.c_str(), 0700));
    ASSERT_EQ(0, ::mkdir((root + "/data").c_str(), 0700));
    ASSERT_EQ(0, ::mkdir((root + "/entry2").c_str(), 0700));
    ASSERT_EQ(0, ::symlink("data", (root + "/entry").c_str()));
    const auto file = context.MakeTempfile("payload");
    ASSERT_EQ(0, ::rename(file.c_str(), (root + "/data/file").c_str()));
    ASSERT_EQ(0, ::symlink((root + "/entry/file").c_str(), (root + "/data/logical").c_str()));
    ASSERT_EQ(0, ::symlink((root + "/data/file").c_str(), (root + "/data/effective").c_str()));
    ASSERT_EQ(0, ::symlink((root + "/entry2/file").c_str(), (root + "/data/collision").c_str()));
    auto opened = SelectAcceptedPath(context, root + "/entry", CrossMountPathPolicy(true), AmpleLimits());
    ASSERT_TRUE(opened.HasValue()) << opened.Error().message;
    Path path = std::move(opened).Value();
    EXPECT_EQ(root + "/entry", path.LookupName());
    EXPECT_EQ(root + "/data", path.ToString());
    struct stat expected = {};
    ASSERT_EQ(0, ::stat((root + "/data/file").c_str(), &expected));
    for (const char* name : {"logical", "effective"})
    {
        auto step = SelectStep(path, name, CrossMountPathPolicy(true));
        ASSERT_TRUE(step.HasValue()) << name << ": " << step.Error().message;
        EXPECT_EQ(expected.st_ino, step.Value().Acquired().metadata.st_ino);
        EXPECT_EQ(root + "/data/file", step.Value().Target().EffectiveName());
        EXPECT_EQ(root + "/data", path.ToString());
    }
    auto conflict = path.Resolve("collision", CrossMountPathPolicy(true));
    ASSERT_FALSE(conflict.HasValue());
    EXPECT_EQ(EXDEV, conflict.Error().code);
    EXPECT_EQ(root + "/data", path.ToString());
}

TEST_F(PathAliasTest, CopiedLeafOutlivesPathMoveAndFailedFinalCloseIsNotRetried)
{
    const auto source = context.MakeTempfile("contents");
    const auto before = CountOpenDescriptors();
    std::unique_ptr<Path::Component> surviving;
    {
        auto opened = SelectAcceptedPath(context, source, CrossMountPathPolicy(), AmpleLimits());
        ASSERT_TRUE(opened.HasValue()) << opened.Error().message;
        Path path = std::move(opened).Value();
        Path moved(std::move(path));
        EXPECT_EQ(source, path.ToString());
        EXPECT_EQ(source, moved.ToString());
        surviving.reset(new Path::Component(moved.Leaf()));
        Path::Component copied(std::move(*surviving));
        EXPECT_EQ(Type::RegularFile, copied.Acquired().type);
        EXPECT_TRUE(surviving->Stat().HasValue());
    }
    EXPECT_EQ(before + 1, CountOpenDescriptors());
    EXPECT_CALL(context, CloseFileDescriptor(_)).Times(1).WillOnce([](int fd) {
        const int status = ::close(fd);
        EXPECT_EQ(0, status);
        errno = EIO;
        return -1;
    });
    surviving.reset();
    EXPECT_EQ(before, CountOpenDescriptors());
}

TEST_F(PathAliasTest, AdministrativeRootLinkAndMovedPathKeepFrozenBarrier)
{
    const std::string root = context.GetTempdirPath() + "/accepted";
    const std::string admin = context.GetTempdirPath() + "/administrative";
    ASSERT_EQ(0, ::mkdir(root.c_str(), 0700));
    ASSERT_EQ(0, ::symlink(root.c_str(), admin.c_str()));
    auto denied = Path::Make(context, admin, CrossMountPathPolicy(), AmpleLimits());
    ASSERT_FALSE(denied.HasValue());
    EXPECT_EQ(ELOOP, denied.Error().code);
    auto approved = SelectAcceptedPath(context, admin, CrossMountPathPolicy(true), AmpleLimits());
    ASSERT_TRUE(approved.HasValue()) << approved.Error().message;
    Path original = std::move(approved).Value();
    Path moved(std::move(original));
    EXPECT_EQ(admin, original.LookupName());
    EXPECT_EQ(root, original.ToString());
    EXPECT_EQ(root, moved.ToString());
    const auto child = context.MakeTempfile("contents");
    ASSERT_EQ(0, ::rename(child.c_str(), (root + "/file").c_str()));
    auto selected = SelectStep(moved, "file", CrossMountPathPolicy());
    ASSERT_TRUE(selected.HasValue()) << selected.Error().message;
    auto back = moved.Apply(std::move(selected.Value()));
    ASSERT_TRUE(back.HasValue()) << back.Error().message;
    EXPECT_EQ(Type::RegularFile, moved.Leaf().Acquired().type);
    EXPECT_EQ(root, original.ToString());
    ASSERT_TRUE(moved.Apply(std::move(back.Value())).HasValue());
    ASSERT_EQ(0, ::symlink("../", (root + "/parent").c_str()));
    auto escape = moved.Resolve("parent", CrossMountPathPolicy(true));
    ASSERT_FALSE(escape.HasValue());
    EXPECT_EQ(EXDEV, escape.Error().code);
    EXPECT_EQ(root, moved.ToString());
}

TEST_F(PathAliasTest, DetachedSelectedLeafSurvivesInverseAndFreshReacquisition)
{
    const std::string root = context.GetTempdirPath() + "/accepted";
    ASSERT_EQ(0, ::mkdir(root.c_str(), 0700));
    ASSERT_EQ(0, ::mkdir((root + "/one").c_str(), 0700));
    ASSERT_EQ(0, ::mkdir((root + "/one/two").c_str(), 0700));
    auto opened = SelectAcceptedPath(context, root, CrossMountPathPolicy(), AmpleLimits());
    ASSERT_TRUE(opened.HasValue());
    Path path = std::move(opened).Value();
    const auto depth = path.Size();
    auto one = SelectStep(path, "one", CrossMountPathPolicy());
    ASSERT_TRUE(one.HasValue());
    auto rootInverse = path.Apply(std::move(one.Value()));
    ASSERT_TRUE(rootInverse.HasValue());
    Path::Component heldOne = path.Leaf();
    auto two = SelectStep(path, "two", CrossMountPathPolicy());
    ASSERT_TRUE(two.HasValue());
    Path::Component detached = two.Value().Target();
    const auto inode = detached.Acquired().metadata.st_ino;
    auto oneInverse = path.Apply(std::move(two.Value()));
    ASSERT_TRUE(oneInverse.HasValue());
    EXPECT_EQ(depth + 2, path.Size());
    ASSERT_TRUE(path.Apply(std::move(oneInverse.Value())).HasValue());
    EXPECT_EQ(depth + 1, path.Size());
    EXPECT_EQ(heldOne.Acquired().metadata.st_ino, path.Leaf().Acquired().metadata.st_ino);
    const auto afterInverse = CountOpenDescriptors();
    auto again = SelectStep(path, "two", CrossMountPathPolicy());
    ASSERT_TRUE(again.HasValue()) << again.Error().message;
    EXPECT_EQ(inode, again.Value().Acquired().metadata.st_ino);
    EXPECT_GT(CountOpenDescriptors(), afterInverse); // distinct new pin, old detached pin still valid
    EXPECT_TRUE(detached.Stat().HasValue());
    ASSERT_TRUE(path.Apply(std::move(rootInverse.Value())).HasValue());
    EXPECT_EQ(root, path.ToString());
    EXPECT_EQ(depth, path.Size());
    EXPECT_TRUE(detached.Stat().HasValue());
}

TEST_F(PathAliasTest, CanonicalParentOfReusedAncestorDoesNotCrossBarrier)
{
    const std::string root = context.GetTempdirPath() + "/accepted";
    ASSERT_EQ(0, ::mkdir(root.c_str(), 0700));
    ASSERT_EQ(0, ::mkdir((root + "/a").c_str(), 0700));
    ASSERT_EQ(0, ::mkdir((root + "/a/sub").c_str(), 0700));
    ASSERT_EQ(0, ::mkdir((root + "/a/child").c_str(), 0700));
    ASSERT_EQ(0, ::symlink("..", (root + "/a/sub/up").c_str()));
    ASSERT_EQ(0, ::symlink(".", (root + "/self").c_str()));
    ASSERT_EQ(0, ::symlink("..", (root + "/escape").c_str()));
    struct stat expected = {};
    ASSERT_EQ(0, ::stat((root + "/a/child").c_str(), &expected));
    auto opened = SelectAcceptedPath(context, root, CrossMountPathPolicy(), AmpleLimits());
    ASSERT_TRUE(opened.HasValue());
    Path path = std::move(opened).Value();
    const auto depth = path.Size();
    auto a = SelectStep(path, "a", CrossMountPathPolicy());
    ASSERT_TRUE(a.HasValue());
    auto backA = path.Apply(std::move(a.Value()));
    ASSERT_TRUE(backA.HasValue());
    auto sub = SelectStep(path, "sub", CrossMountPathPolicy());
    ASSERT_TRUE(sub.HasValue());
    auto backSub = path.Apply(std::move(sub.Value()));
    ASSERT_TRUE(backSub.HasValue());
    auto up = SelectStep(path, "up", CrossMountPathPolicy(true));
    ASSERT_TRUE(up.HasValue()) << up.Error().message;
    auto backUp = path.Apply(std::move(up.Value()));
    ASSERT_TRUE(backUp.HasValue());
    EXPECT_EQ(root + "/a", path.ToString());
    auto child = SelectStep(path, "child", CrossMountPathPolicy());
    ASSERT_TRUE(child.HasValue()) << child.Error().message;
    EXPECT_EQ(expected.st_ino, child.Value().Acquired().metadata.st_ino);
    ASSERT_TRUE(path.Apply(std::move(backUp.Value())).HasValue());
    ASSERT_TRUE(path.Apply(std::move(backSub.Value())).HasValue());
    ASSERT_TRUE(path.Apply(std::move(backA.Value())).HasValue());
    EXPECT_EQ(depth, path.Size());
    auto self = SelectStep(path, "self", CrossMountPathPolicy(true));
    ASSERT_TRUE(self.HasValue());
    EXPECT_EQ(path.Leaf().Acquired().metadata.st_ino, self.Value().Acquired().metadata.st_ino);
    auto escape = path.Resolve("escape", CrossMountPathPolicy(true));
    ASSERT_FALSE(escape.HasValue());
    EXPECT_EQ(EXDEV, escape.Error().code);
    EXPECT_EQ(root, path.ToString());
}

TEST_F(PathAliasTest, DirectUnsupportedSkipSurvivesFailedTemporaryPinClose)
{
    const std::string root = context.GetTempdirPath();
    ASSERT_EQ(0, ::mkfifo((root + "/special-close").c_str(), 0600));
    int specialPin = -1;
    bool failed = false;
    auto opened = SelectAcceptedPath(context, root, CrossMountPathPolicy(), AmpleLimits());
    ASSERT_TRUE(opened.HasValue());
    Path path = std::move(opened).Value();
    const auto original = path.Leaf().Acquired().metadata.st_ino;
    const auto before = CountOpenDescriptors();
    EXPECT_CALL(context, OpenNativeAt(_, _, _)).WillRepeatedly([&](int directory, const char* name, int flags) {
        if (std::string(name) == "special-close")
        {
            EXPECT_NE(0, flags & O_PATH);
            EXPECT_NE(0, flags & O_NOFOLLOW);
        }
        const int fd = context.RealOpenNativeAt(directory, name, flags);
        if (std::string(name) == "special-close")
            specialPin = fd;
        return fd;
    });
    EXPECT_CALL(context, CloseFileDescriptor(_)).WillRepeatedly([&](int fd) {
        const int status = context.RealCloseFileDescriptor(fd);
        if (fd == specialPin && !failed)
        {
            failed = true;
            errno = EIO;
            return -1;
        }
        return status;
    });
    auto skip = CrossMountPathPolicy();
    skip.unsupportedTypes = ComplianceEngine::Filesystem::UnsupportedTypeDisposition::Skip;
    auto result = path.Resolve("special-close", skip);
    ASSERT_TRUE(result.HasValue()) << result.Error().message;
    ASSERT_TRUE(result.Value().Is<Path::RejectionReason>());
    EXPECT_EQ(Path::RejectionReason::UnsupportedType, As<Path::RejectionReason>(result.Value()));
    EXPECT_TRUE(failed);
    EXPECT_EQ(root, path.ToString());
    EXPECT_EQ(original, path.Leaf().Acquired().metadata.st_ino);
    EXPECT_EQ(before, CountOpenDescriptors());
}

TEST_F(PathAliasTest, ConfinedResolverDistinguishesRelativeAbsoluteLoopAndTrailingLinks)
{
    const std::string root = context.GetTempdirPath() + "/accepted";
    ASSERT_EQ(0, ::mkdir(root.c_str(), 0700));
    const auto source = context.MakeTempfile("contents");
    ASSERT_EQ(0, ::rename(source.c_str(), (root + "/inside").c_str()));
    ASSERT_EQ(0, ::symlink("inside", (root + "/relative").c_str()));
    ASSERT_EQ(0, ::symlink((root + "/inside").c_str(), (root + "/absolute").c_str()));
    ASSERT_EQ(0, ::symlink("/etc/passwd", (root + "/outside").c_str()));
    ASSERT_EQ(0, ::symlink("../etc/passwd", (root + "/escape").c_str()));
    ASSERT_EQ(0, ::symlink("loop", (root + "/loop").c_str()));
    ASSERT_EQ(0, ::symlink("inside/", (root + "/trailing").c_str()));
    ASSERT_EQ(0, ::symlink("relative", (root + "/double").c_str()));
    struct stat expected = {};
    ASSERT_EQ(0, ::stat((root + "/inside").c_str(), &expected));
    auto opened = SelectAcceptedPath(context, root, CrossMountPathPolicy(), AmpleLimits());
    ASSERT_TRUE(opened.HasValue());
    Path path = std::move(opened).Value();
    const auto before = CountOpenDescriptors();
    {
        auto stay = CrossMountPathPolicy(true);
        stay.mounts = MountPolicy::StayOnRootMount;
        auto relative = SelectStep(path, "relative", stay);
        ASSERT_TRUE(relative.HasValue()) << relative.Error().message;
        EXPECT_EQ(expected.st_ino, relative.Value().Acquired().metadata.st_ino);
        auto absolute = SelectStep(path, "absolute", CrossMountPathPolicy(true));
        ASSERT_TRUE(absolute.HasValue()) << absolute.Error().message;
        EXPECT_EQ(expected.st_ino, absolute.Value().Acquired().metadata.st_ino);
        auto outside = path.Resolve("outside", CrossMountPathPolicy(true));
        ASSERT_FALSE(outside.HasValue());
        EXPECT_EQ(EXDEV, outside.Error().code);
        auto escaped = path.Resolve("escape", CrossMountPathPolicy(true));
        ASSERT_FALSE(escaped.HasValue());
        EXPECT_EQ(EXDEV, escaped.Error().code);
        auto disallowed = path.Resolve("relative", CrossMountPathPolicy());
        ASSERT_FALSE(disallowed.HasValue());
        EXPECT_EQ(ELOOP, disallowed.Error().code);
        auto loop = path.Resolve("loop", CrossMountPathPolicy(true));
        ASSERT_FALSE(loop.HasValue());
        EXPECT_EQ(ELOOP, loop.Error().code);
        auto trailing = path.Resolve("trailing", CrossMountPathPolicy(true));
        ASSERT_FALSE(trailing.HasValue());
        EXPECT_EQ(ENOTDIR, trailing.Error().code);
        EXPECT_EQ(root, path.ToString());
        EXPECT_EQ(expected.st_ino, relative.Value().Acquired().metadata.st_ino);
        EXPECT_EQ(expected.st_ino, absolute.Value().Acquired().metadata.st_ino);
    }
    EXPECT_EQ(before, CountOpenDescriptors());
    auto limits = AmpleLimits();
    limits.linkExpansions = 1;
    auto one = SelectAcceptedPath(context, root, CrossMountPathPolicy(), limits);
    ASSERT_TRUE(one.HasValue());
    auto over = one.Value().Resolve("double", CrossMountPathPolicy(true));
    ASSERT_FALSE(over.HasValue());
    EXPECT_EQ(ELOOP, over.Error().code);
    limits.linkExpansions = 2;
    auto two = SelectAcceptedPath(context, root, CrossMountPathPolicy(), limits);
    ASSERT_TRUE(two.HasValue());
    auto exact = SelectStep(two.Value(), "double", CrossMountPathPolicy(true));
    ASSERT_TRUE(exact.HasValue()) << exact.Error().message;
    EXPECT_EQ(expected.st_ino, exact.Value().Acquired().metadata.st_ino);
    EXPECT_EQ(root, two.Value().ToString());
}

TEST_F(PathAliasTest, UnsupportedFactoryAndInvalidChildPreserveAcceptedPath)
{
    const std::string root = context.GetTempdirPath();
    ASSERT_EQ(0, ::mkfifo((root + "/special").c_str(), 0600));
    ASSERT_EQ(0, ::symlink("special", (root + "/special.link").c_str()));
    ASSERT_EQ(0, ::symlink("missing-special", (root + "/special.broken").c_str()));
    auto opened = SelectAcceptedPath(context, root, CrossMountPathPolicy(), AmpleLimits());
    ASSERT_TRUE(opened.HasValue());
    Path path = std::move(opened).Value();
    const auto depth = path.Size();
    const auto inode = path.Leaf().Acquired().metadata.st_ino;
    const auto before = CountOpenDescriptors();
    bool sawSpecial = false, sawLink = false;
    EXPECT_CALL(context, OpenNativeAt(_, _, _)).WillRepeatedly([&](int directory, const char* name, int flags) {
        if (std::string(name) == "special" || std::string(name) == "special.link")
        {
            EXPECT_NE(0, flags & O_PATH);
            EXPECT_NE(0, flags & O_NOFOLLOW);
            sawSpecial |= std::string(name) == "special";
            sawLink |= std::string(name) == "special.link";
        }
        return context.RealOpenNativeAt(directory, name, flags);
    });
    auto strict = CrossMountPathPolicy();
    auto unsupported = Path::Make(context, root + "/special", strict, AmpleLimits());
    ASSERT_FALSE(unsupported.HasValue());
    EXPECT_EQ(EOPNOTSUPP, unsupported.Error().code);
    auto direct = path.Resolve("special", strict);
    ASSERT_FALSE(direct.HasValue());
    EXPECT_EQ(EOPNOTSUPP, direct.Error().code);
    auto rejectedLink = path.Resolve("special.link", strict);
    ASSERT_FALSE(rejectedLink.HasValue());
    EXPECT_EQ(ELOOP, rejectedLink.Error().code);
    auto followed = path.Resolve("special.link", CrossMountPathPolicy(true));
    ASSERT_FALSE(followed.HasValue());
    EXPECT_EQ(EOPNOTSUPP, followed.Error().code);
    EXPECT_TRUE(sawSpecial);
    EXPECT_TRUE(sawLink);
    for (const std::string& invalid : {std::string("../special"), std::string("x\0y", 3)})
    {
        auto refused = path.Resolve(invalid, strict);
        ASSERT_FALSE(refused.HasValue());
        EXPECT_EQ(EINVAL, refused.Error().code);
        EXPECT_EQ(depth, path.Size());
        EXPECT_EQ(inode, path.Leaf().Acquired().metadata.st_ino);
    }
    auto missing = path.Resolve("special.broken", CrossMountPathPolicy(true));
    ASSERT_FALSE(missing.HasValue());
    EXPECT_EQ(ENOENT, missing.Error().code);
    EXPECT_EQ(depth, path.Size());
    EXPECT_EQ(inode, path.Leaf().Acquired().metadata.st_ino);
    EXPECT_EQ(before, CountOpenDescriptors());
}

TEST_F(PathAliasTest, AcceptedRootRetainsPinsWhileChildPoliciesStayIndependent)
{
    const std::string root = context.GetTempdirPath() + "/accepted";
    ASSERT_EQ(0, ::mkdir(root.c_str(), 0700));
    const auto source = context.MakeTempfile("contents");
    ASSERT_EQ(0, ::rename(source.c_str(), (root + "/inside").c_str()));
    ASSERT_EQ(0, ::symlink("inside", (root + "/allowed").c_str()));
    ASSERT_EQ(0, ::symlink("/etc/passwd", (root + "/outside").c_str()));
    auto opened = SelectAcceptedPath(context, root, CrossMountPathPolicy(), AmpleLimits());
    ASSERT_TRUE(opened.HasValue());
    Path path = std::move(opened).Value();
    const auto depth = path.Size();
    Path::Component held = path.Leaf();
    auto follow = CrossMountPathPolicy(true);
    follow.mounts = MountPolicy::StayOnRootMount;
    auto outside = path.Resolve("outside", follow);
    ASSERT_FALSE(outside.HasValue());
    EXPECT_EQ(EXDEV, outside.Error().code);
    EXPECT_EQ(depth, path.Size());
    EXPECT_EQ(held.Acquired().metadata.st_ino, path.Leaf().Acquired().metadata.st_ino);
    auto strict = CrossMountPathPolicy();
    strict.mounts = MountPolicy::StayOnRootMount;
    auto denied = path.Resolve("allowed", strict);
    ASSERT_FALSE(denied.HasValue());
    EXPECT_EQ(ELOOP, denied.Error().code);
    auto accepted = SelectStep(path, "allowed", follow);
    ASSERT_TRUE(accepted.HasValue()) << accepted.Error().message;
    auto inverse = path.Apply(std::move(accepted.Value()));
    ASSERT_TRUE(inverse.HasValue()) << inverse.Error().message;
    EXPECT_EQ(Type::RegularFile, path.Leaf().Acquired().type);
    EXPECT_TRUE(held.Stat().HasValue());
    auto notDirectory = path.Resolve("inside", strict);
    ASSERT_FALSE(notDirectory.HasValue());
    EXPECT_EQ(ENOTDIR, notDirectory.Error().code);
    ASSERT_TRUE(path.Apply(std::move(inverse.Value())).HasValue());
    EXPECT_EQ(root, path.ToString());
    EXPECT_EQ(held.Acquired().metadata.st_ino, path.Leaf().Acquired().metadata.st_ino);
}

TEST_F(PathAliasTest, StagedGrowthAndFailedAliasLeaveCopiedTargetOwnedAfterPathRetires)
{
    const std::string root = context.GetTempdirPath() + "/staged-growth";
    ASSERT_EQ(0, ::mkdir(root.c_str(), 0700));
    std::string actual = root;
    std::string target;
    for (int index = 0; index < 32; ++index)
    {
        actual += "/d";
        target += (target.empty() ? "" : "/") + std::string("d");
        ASSERT_EQ(0, ::mkdir(actual.c_str(), 0700));
    }
    ASSERT_EQ(0, ::symlink(target.c_str(), (root + "/long").c_str()));
    ASSERT_EQ(0, ::symlink((target + "/absent").c_str(), (root + "/broken").c_str()));
    auto limits = AmpleLimits();
    limits.shared.work = 2000000;
    const auto before = CountOpenDescriptors();
    std::unique_ptr<Path::Component> leaf;
    std::unique_ptr<Path::Component> copy;
    {
        auto opened = SelectAcceptedPath(context, root, CrossMountPathPolicy(), limits);
        ASSERT_TRUE(opened.HasValue()) << opened.Error().message;
        Path path = std::move(opened).Value();
        auto broken = path.Resolve("broken", CrossMountPathPolicy(true));
        ASSERT_FALSE(broken.HasValue());
        EXPECT_EQ(ENOENT, broken.Error().code);
        EXPECT_EQ(root, path.ToString());
        auto longStep = SelectStep(path, "long", CrossMountPathPolicy(true));
        ASSERT_TRUE(longStep.HasValue()) << longStep.Error().message;
        EXPECT_EQ(actual, longStep.Value().Target().EffectiveName());
        leaf.reset(new Path::Component(longStep.Value().Target()));
        copy.reset(new Path::Component(*leaf));
        const auto pinned = CountOpenDescriptors();
        EXPECT_TRUE(copy->Stat().HasValue());
        EXPECT_EQ(pinned, CountOpenDescriptors());
    }
    EXPECT_EQ(before + 1, CountOpenDescriptors());
    EXPECT_EQ(actual, copy->EffectiveName());
    EXPECT_EQ(leaf->Acquired().metadata.st_ino, copy->Acquired().metadata.st_ino);
    leaf.reset();
    EXPECT_TRUE(copy->Stat().HasValue());
    copy.reset();
    EXPECT_EQ(before, CountOpenDescriptors());
}

TEST_F(PathAliasTest, LinkExpansionContinuesThroughPhysicalSiblingThenBackToBoundary)
{
    const std::string root = context.GetTempdirPath() + "/accepted";
    ASSERT_EQ(0, ::mkdir(root.c_str(), 0700));
    ASSERT_EQ(0, ::mkdir((root + "/first").c_str(), 0700));
    ASSERT_EQ(0, ::mkdir((root + "/second").c_str(), 0700));
    const auto source = context.MakeTempfile("contents");
    ASSERT_EQ(0, ::rename(source.c_str(), (root + "/second/child").c_str()));
    ASSERT_EQ(0, ::symlink("../second", (root + "/first/shortcut").c_str()));
    ASSERT_EQ(0, ::symlink("..", (root + "/second/up").c_str()));
    struct stat expected = {}, sibling = {};
    ASSERT_EQ(0, ::stat((root + "/second/child").c_str(), &expected));
    ASSERT_EQ(0, ::stat((root + "/second").c_str(), &sibling));
    auto opened = SelectAcceptedPath(context, root, CrossMountPathPolicy(), AmpleLimits());
    ASSERT_TRUE(opened.HasValue());
    Path path = std::move(opened).Value();
    const auto depth = path.Size();
    auto first = SelectStep(path, "first", CrossMountPathPolicy());
    ASSERT_TRUE(first.HasValue());
    auto undoFirst = path.Apply(std::move(first.Value()));
    ASSERT_TRUE(undoFirst.HasValue());
    auto shortcut = SelectStep(path, "shortcut", CrossMountPathPolicy(true));
    ASSERT_TRUE(shortcut.HasValue()) << shortcut.Error().message;
    auto undoShortcut = path.Apply(std::move(shortcut.Value()));
    ASSERT_TRUE(undoShortcut.HasValue());
    EXPECT_EQ(sibling.st_ino, path.Leaf().Acquired().metadata.st_ino);
    EXPECT_EQ(root + "/second", path.ToString());
    auto child = SelectStep(path, "child", CrossMountPathPolicy());
    ASSERT_TRUE(child.HasValue()) << child.Error().message;
    EXPECT_EQ(expected.st_ino, child.Value().Acquired().metadata.st_ino);
    EXPECT_EQ(root + "/second/child", child.Value().Target().EffectiveName());
    auto up = SelectStep(path, "up", CrossMountPathPolicy(true));
    ASSERT_TRUE(up.HasValue()) << up.Error().message;
    EXPECT_EQ(root, up.Value().Target().EffectiveName());
    EXPECT_EQ(opened.Value().Leaf().Acquired().metadata.st_ino, up.Value().Acquired().metadata.st_ino);
    auto inverse = path.Apply(std::move(up.Value()));
    ASSERT_TRUE(inverse.HasValue()) << inverse.Error().message;
    EXPECT_EQ(depth, path.Size());
    EXPECT_EQ(root, path.ToString());
    ASSERT_TRUE(path.Apply(std::move(inverse.Value())).HasValue());
    EXPECT_EQ(root + "/second", path.ToString());
    EXPECT_EQ(ESTALE, path.Apply(std::move(undoFirst.Value())).Error().code);
    EXPECT_TRUE(path.Apply(std::move(undoShortcut.Value())).HasValue());
    EXPECT_EQ(root + "/first", path.ToString());
}

TEST_F(PathAliasTest, RelativeParentFromChildIsBoundedByFrozenRoot)
{
    const std::string root = context.GetTempdirPath() + "/accepted";
    ASSERT_EQ(0, ::mkdir(root.c_str(), 0700));
    ASSERT_EQ(0, ::mkdir((root + "/sub").c_str(), 0700));
    const auto source = context.MakeTempfile("contents");
    ASSERT_EQ(0, ::rename(source.c_str(), (root + "/inside").c_str()));
    ASSERT_EQ(0, ::symlink("../inside", (root + "/sub/up").c_str()));
    ASSERT_EQ(0, ::symlink("../outside", (root + "/escape").c_str()));
    struct stat expected = {};
    ASSERT_EQ(0, ::stat((root + "/inside").c_str(), &expected));
    auto opened = SelectAcceptedPath(context, root, CrossMountPathPolicy(), AmpleLimits());
    ASSERT_TRUE(opened.HasValue());
    Path path = std::move(opened).Value();
    auto sub = SelectStep(path, "sub", CrossMountPathPolicy());
    ASSERT_TRUE(sub.HasValue());
    auto inverse = path.Apply(std::move(sub.Value()));
    ASSERT_TRUE(inverse.HasValue());
    auto inside = SelectStep(path, "up", CrossMountPathPolicy(true));
    ASSERT_TRUE(inside.HasValue()) << inside.Error().message;
    EXPECT_EQ(expected.st_ino, inside.Value().Acquired().metadata.st_ino);
    EXPECT_EQ(root + "/inside", inside.Value().Target().EffectiveName());
    ASSERT_TRUE(path.Apply(std::move(inverse.Value())).HasValue());
    auto escape = path.Resolve("escape", CrossMountPathPolicy(true));
    ASSERT_FALSE(escape.HasValue());
    EXPECT_EQ(EXDEV, escape.Error().code);
    EXPECT_EQ(root, path.ToString());
}

} // namespace
