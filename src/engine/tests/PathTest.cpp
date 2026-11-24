// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <DescriptorTestAccess.h>
#include <PathTestAccess.h>
#include <PathTestSupport.h>
#include <algorithm>
#include <cerrno>
#include <climits>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <filesystem/FilesystemHelpers.hpp>
#include <filesystem/Path.hpp>
#include <filesystem/Pin.hpp>
#include <filesystem/ProcfsDescriptorAccess.hpp>
#include <filesystem/ReadableFile.hpp>
#include <fstream>
#include <gtest/gtest.h>
#include <iterator>
#include <limits>
#include <linux/magic.h>
#include <map>
#include <memory>
#include <sched.h>
#include <set>
#include <stdexcept>
#include <string>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/statfs.h>
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
using ComplianceEngine::Filesystem::ReadableFile;
using ComplianceEngine::Filesystem::ResolverLimits;
using ComplianceEngine::Filesystem::Type;
using ComplianceEngine::Filesystem::Detail::Descriptor;
using ComplianceEngine::Filesystem::Detail::Pin;
using ComplianceEngine::Tests::CountOpenDescriptors;
using ComplianceEngine::Tests::CrossMountPathPolicy;
using ComplianceEngine::Tests::DescriptorTarget;
using ComplianceEngine::Tests::DescriptorTestAccess;
using ComplianceEngine::Tests::ExpectLoggedOnce;
using ComplianceEngine::Tests::KernelMountId;
using ComplianceEngine::Tests::OracleMountId;
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
using ComplianceEngine::Filesystem::Detail::IsSingleChildComponent;
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

// The mount baseline is the frozen leaf, not the process-root pin.
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
    EXPECT_EQ(rootId.Value(), path.Leaf().Metadata().TargetMount().Value());
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
    EXPECT_EQ(childId.Value(), path.Leaf().Metadata().TargetMount().Value());
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
    const char* requirement = std::getenv("KOMPLI_REQUIRE_MOUNT_NAMESPACE");
    const bool required = (nullptr != requirement) && (0 == std::strcmp("1", requirement));
    if ((unavailableMountCapability == WEXITSTATUS(status)) && !required)
    {
        GTEST_SKIP() << "Private mount namespace/bind mount unavailable locally; CI/VM gate requires KOMPLI_REQUIRE_MOUNT_NAMESPACE=1";
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
        {
            EXPECT_NE(0, ::fcntl(duplicated, F_GETFD) & FD_CLOEXEC);
        }
        return duplicated;
    });
    auto duplicate = DescriptorTestAccess::Duplicate(context, owner);
    ASSERT_TRUE(duplicate.HasValue());
    EXPECT_NE(0, DescriptorTestAccess::DescriptorFlags(context, duplicate.Value()) & FD_CLOEXEC);
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
    static_assert(!std::is_default_constructible<Pin>::value, "A pin requires a checked acquisition");
    static_assert(!std::is_constructible<Pin, int>::value, "A raw fd cannot construct a pin");
    static_assert(!std::is_copy_constructible<Pin>::value, "A pinned descriptor cannot be copied");
    static_assert(!std::is_copy_assignable<Pin>::value, "A pinned descriptor cannot be copied");
    static_assert(std::is_move_constructible<Pin>::value, "A pinned descriptor can transfer ownership");
    static_assert(std::is_move_assignable<Pin>::value, "A pinned descriptor can transfer ownership");
    static_assert(!std::is_default_constructible<Path>::value, "No unapproved root constructor is exposed");
}

TEST_F(PathAliasTest, InitialRootWorkChargePrecedesNativeAcquisitionAndFreezeHasNoCharge)
{
    ResolverLimits limits = AmpleLimits();
    // Default fdinfoBytes=4096: 128 + 4 * ceil(4096 / 256) = 192.
    ASSERT_EQ(4096u, limits.shared.fdinfoBytes);
    limits.shared.work = 191;
    EXPECT_CALL(context, OpenNativePath(_, _)).Times(0);
    auto shortWork = Path::Make(context, "/", CrossMountPathPolicy(), limits);
    ASSERT_FALSE(shortWork.HasValue());
    EXPECT_EQ(E2BIG, shortWork.Error().code);
    EXPECT_EQ("Path work budget exhausted", shortWork.Error().message);
    testing::Mock::VerifyAndClearExpectations(&context);
    limits.shared.work = 192;
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
    EXPECT_CALL(context, CloseNativeDescriptor(_)).WillRepeatedly([&](int fd) -> ComplianceEngine::Result<void> {
        struct stat held = {};
        const bool rootPin = ::fstat(fd, &held) == 0 && held.st_dev == root.st_dev && held.st_ino == root.st_ino;
        auto result = context.RealCloseNativeDescriptor(fd);
        if (rootPin)
        {
            ++rootCloses;
            errno = EACCES;
            return ComplianceEngine::Error(errno ? errno : EIO);
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
    EXPECT_NE(std::string::npos, text.find("Failed to close filesystem resource: " + std::string(strerror(EACCES))));
}

TEST_F(PathAliasTest, ActivationErrorRemainsPrimaryWhenDiagnosticCleanupFails)
{
    const std::string source = context.MakeTempfile("contents");
    ResolverLimits limits;
    limits.shared.targetBytes = 4096;
    limits.shared.components = 128;
    limits.shared.work = 200000;
    limits.shared.liveDescriptors = 128;
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
    EXPECT_CALL(context, CloseNativeDescriptor(_)).Times(pins).WillRepeatedly([&](int fd) -> ComplianceEngine::Result<void> {
        const std::size_t index = attempts++;
        EXPECT_EQ(0, ::close(fd));
        if (index == 0)
        {
            errno = EIO;
            return ComplianceEngine::Error(errno ? errno : EIO);
        }
        return ComplianceEngine::Result<void>::Success();
    });
    // The consumer owns this precedence decision: keep the activation error
    // and record a subsequent release error, not a success-shaped fallback.
    EXPECT_CALL(context, StatNativeDescriptor(_, _)).Times(1).WillOnce([](int, struct stat*) {
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
    EXPECT_NE(std::string::npos, text.find("Failed to close filesystem resource: " + std::string(strerror(EIO))));
}

// Read-only file activation (procfs alias through Pin::ActivateReadOnly
// with the mount already held) is reachable publicly via
// Path::Component::OpenReadOnly(); ReadableFile::Stat()/Read()/Close() give
// equivalent observation and control over the activated file.
TEST_F(PathAliasTest, AliasStaysOnPinnedFileAfterNameReplacementAndUnlink)
{
    const std::string source = context.MakeTempfile("original bytes");
    struct stat original = {};
    ASSERT_EQ(0, ::stat(source.c_str(), &original));
    auto opened = SelectAcceptedPath(context, source, CrossMountPathPolicy(), AmpleLimits());
    ASSERT_TRUE(opened.HasValue());
    Path path = std::move(opened).Value();
    const std::size_t before = CountOpenDescriptors();
    {
        ASSERT_EQ(0, ::rename(source.c_str(), (source + ".former").c_str()));
        ASSERT_EQ(0, ::mkfifo(source.c_str(), 0600));

        // Opening the original name would block on this substituted FIFO;
        // descriptor-alias activation must instead bind to the prior inode.
        auto active = path.Leaf().OpenReadOnly();
        ASSERT_TRUE(active.HasValue()) << active.Error().message;
        auto activatedStat = active.Value().Stat();
        ASSERT_TRUE(activatedStat.HasValue());
        EXPECT_EQ(original.st_ino, activatedStat.Value().st_ino);
        EXPECT_EQ(original.st_dev, activatedStat.Value().st_dev);
        auto bytes = active.Value().Read(14);
        ASSERT_TRUE(bytes.HasValue()) << bytes.Error().message;
        ASSERT_TRUE(bytes.Value().HasValue());
        EXPECT_EQ("original bytes", bytes.Value().Value());

        ASSERT_EQ(0, ::unlink((source + ".former").c_str()));
        auto again = path.Leaf().OpenReadOnly();
        ASSERT_TRUE(again.HasValue()) << again.Error().message;
        auto reacquiredStat = again.Value().Stat();
        ASSERT_TRUE(reacquiredStat.HasValue());
        EXPECT_EQ(original.st_ino, reacquiredStat.Value().st_ino);
    }
    EXPECT_EQ(before, CountOpenDescriptors());
}

// Directory read-only activation is only reachable through FTW::Files(); see
// DirectoryActivationTransfersVerifiedOwnerWithoutDuplicate in
// PathTraversalTest.cpp, which already exercises the same
// Pin::ActivateReadOnly(directory) branch with richer native-call
// assertions (flags, single-close, no leak). Moving the resulting
// Descriptor and retaining single ownership across a move is a generic
// Descriptor-class invariant, not specific to directory activation, and is
// independently covered by Descriptor's own move-semantics tests; it is not
// re-derived here to avoid a near-duplicate, weaker test.

TEST_F(PathAliasTest, ActivationHandsOffOwnerWithoutRetryingFailedClose)
{
    const std::string file = context.MakeTempfile("activation");
    const auto before = CountOpenDescriptors();
    {
        auto opened = SelectAcceptedPath(context, file, CrossMountPathPolicy(), AmpleLimits());
        ASSERT_TRUE(opened.HasValue()) << opened.Error().message;
        // Path moves transfer ownership of the shared payload, so `opened`
        // no longer holds the state; the unique_ptr lets the test retire
        // the pin early.
        auto path = std::unique_ptr<Path>(new Path(std::move(opened).Value()));
        auto activated = path->Leaf().OpenReadOnly();
        ASSERT_TRUE(activated.HasValue()) << activated.Error().message;
        ReadableFile reader = std::move(activated).Value();
        // The activated reader is independently owned: dropping the pin must
        // not affect it, and a failed close of the reader must not be retried.
        path.reset();
        EXPECT_CALL(context, CloseNativeDescriptor(_)).Times(1).WillOnce([](int descriptor) {
            EXPECT_EQ(0, ::close(descriptor));
            errno = EIO;
            return ComplianceEngine::Error(errno ? errno : EIO);
        });
        reader.Close();
        reader.Close();
    }
    EXPECT_EQ(before, CountOpenDescriptors());
}

TEST_F(PathAliasTest, ExactAndOneOverFdinfoCapApplyDuringPathAcquisition)
{
    OwnedTestDescriptor kernelRoot(::open("/", O_PATH | O_CLOEXEC));
    ASSERT_GE(kernelRoot.Get(), 0);
    auto rootMount = KernelMountId(kernelRoot.Get());
    ASSERT_TRUE(rootMount.HasValue()) << rootMount.Error().message;
    const std::string fdinfo = "mnt_id: " + std::to_string(rootMount.Value()) + "\n";
    std::map<int, std::size_t> offsets;
    ON_CALL(context, OpenNativePath(_, _)).WillByDefault([&](const char* path, int flags) {
        const int fd = context.RealOpenNativePath(path, flags);
        if (fd >= 0)
            offsets.erase(fd);
        return fd;
    });
    ON_CALL(context, OpenNativeAt(_, _, _)).WillByDefault([&](int directory, const char* name, int flags) {
        const int fd = context.RealOpenNativeAt(directory, name, flags);
        if (fd >= 0)
            offsets.erase(fd);
        return fd;
    });
    ON_CALL(context, ReadNativeDescriptor(_, _, _)).WillByDefault([&](int fd, void* buffer, std::size_t size) -> ssize_t {
        if (DescriptorTarget(fd).find("/fdinfo/") == std::string::npos)
            return context.RealReadNativeDescriptor(fd, buffer, size);
        std::size_t& offset = offsets[fd];
        const std::size_t count = std::min(size, fdinfo.size() - offset);
        if (count != 0)
            std::memcpy(buffer, fdinfo.data() + offset, count);
        offset += count;
        return static_cast<ssize_t>(count);
    });
    const auto before = CountOpenDescriptors();
    ResolverLimits limits = AmpleLimits();
    limits.shared.fdinfoBytes = fdinfo.size();
    {
        auto exact = Path::Make(context, "/", CrossMountPathPolicy(), limits);
        ASSERT_TRUE(exact.HasValue()) << exact.Error().message;
        ASSERT_TRUE(exact.Value().Is<Path>());
        EXPECT_EQ(rootMount.Value(), As<Path>(exact.Value()).Root().Metadata().TargetMount().Value());
    }
    limits.shared.fdinfoBytes = fdinfo.size() - 1;
    auto over = Path::Make(context, "/", CrossMountPathPolicy(), limits);
    ASSERT_FALSE(over.HasValue());
    EXPECT_EQ(E2BIG, over.Error().code);
    EXPECT_EQ(before, CountOpenDescriptors());
}

// Every input of the former direct-call ParseMountId test, ported to the
// production acquisition boundary: fdinfo bytes are injected through the
// mocked ReadNativeDescriptor exactly as ExactAndOneOverFdinfoCapApplyDuringPathAcquisition
// does, so the parser is exercised only as PinProcessRoot reaches it, not by
// calling it directly.
TEST_F(PathAliasTest, ProcfsMountIdAcceptsValidAndRejectsMalformedInformationDuringAcquisition)
{
    ::testing::StrictMock<MockContext> strict;
    strict.AllowProcfsBootstrap();
    strict.AllowNativeOpen();
    strict.AllowDescriptorInspection();
    strict.AllowDescriptorClose();
    const std::size_t before = CountOpenDescriptors();
    auto injectFdinfo = [&](const std::string& information) {
        auto offsets = std::make_shared<std::map<int, std::size_t>>();
        EXPECT_CALL(strict, ReadNativeDescriptor(_, _, _)).WillRepeatedly([&strict, offsets, information](int fd, void* buffer, std::size_t size) -> ssize_t {
            if (DescriptorTarget(fd).find("/fdinfo/") == std::string::npos)
                return strict.RealReadNativeDescriptor(fd, buffer, size);
            std::size_t& offset = (*offsets)[fd];
            const std::size_t count = std::min(size, information.size() - offset);
            if (count != 0)
                std::memcpy(buffer, information.data() + offset, count);
            offset += count;
            return static_cast<ssize_t>(count);
        });
    };
    injectFdinfo("pos:\t0\nflags:\t010000000\nmnt_id:\t123\nino:\t5\n");
    {
        auto accepted = Path::Make(strict, "/", CrossMountPathPolicy(), AmpleLimits());
        ASSERT_TRUE(accepted.HasValue()) << accepted.Error().message;
        ASSERT_TRUE(accepted.Value().Is<Path>());
        EXPECT_EQ(123U, As<Path>(accepted.Value()).Root().Metadata().TargetMount().Value());
    }
    EXPECT_EQ(before, CountOpenDescriptors());

    const std::string invalid[] = {"", "pos:\t0\n", "mnt_id:0\n", "mnt_id: \n", "mnt_id:12x\n", "mnt_id:-1\n", "mnt_id:18446744073709551616\n",
        "mnt_id:1\nmnt_id:2\n", "mnt_id:12", std::string("mnt_id:1\n\0", 10)};
    for (const auto& information : invalid)
    {
        SCOPED_TRACE(information);
        injectFdinfo(information);
        auto rejected = Path::Make(strict, "/", CrossMountPathPolicy(), AmpleLimits());
        ASSERT_FALSE(rejected.HasValue());
        EXPECT_EQ(EPROTO, rejected.Error().code);
        EXPECT_EQ(before, CountOpenDescriptors());
    }
}

// The overreport-rejection logic lives in the shared
// ProcfsDescriptorAccess::ReadMountId, which production reaches from
// PinProcessRoot during ordinary root acquisition -- exercised here.
//
// Descriptor-accounting bound, re-derived for this new route (verified by
// tracing Path::Make(context, "/", ...) -> Pin::PinProcessRoot,
// Path.cpp ~454, and ProcfsDescriptorAccess::Make, ProcfsDescriptorAccess.cpp
// ~48-126, and confirmed by this test actually running green at these exact
// values rather than looser ones):
//   acquisitions: 1 (root "/") + 7 (bootstrap: /proc, self, <pid>, task,
//     <tid>, fd, fdinfo) + 1 (the fdinfo reader PinProcessRoot opens for the
//     root's own mount id, which is where the overreport is injected) = 9.
//   peak live descriptors: root (1, retained for the whole call) plus the
//     bootstrap's own internal peak of 3 concurrently-held temporaries
//     (proc+self+<pid>, then self+task+<tid>; kProcfsBootstrapPeak in
//     Path.cpp) is <= 4 throughout bootstrap; after bootstrap narrows to the
//     2 retained roles (fd+fdinfo), opening the root's fdinfo reader again
//     reaches root+fd+fdinfo+info = 4. Matches kMinimumPathPeak (Path.cpp
//     ~113-118: "three temporary procfs descriptors plus root").
TEST_F(PathAliasTest, FdinfoReadOverreportRejectsActualRequestAndClosesHelpers)
{
    const std::size_t before = CountOpenDescriptors();
    {
        std::size_t overreports = 0;
        std::set<int> live;
        std::size_t acquired = 0, closed = 0, peak = 0;
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
            EXPECT_CALL(context, ReadNativeDescriptor(_, _, _)).WillRepeatedly([&](int descriptor, void* buffer, std::size_t size) -> ssize_t {
                const std::string target = DescriptorTarget(descriptor);
                if ((0 == target.find("/proc/")) && (std::string::npos != target.find("/fdinfo/")))
                {
                    EXPECT_EQ(requested, size);
                    ++overreports;
                    return static_cast<ssize_t>(size + 1); // No write: even an overreported count cannot be read from buffer.
                }
                return context.RealReadNativeDescriptor(descriptor, buffer, size);
            });
            EXPECT_CALL(context, CloseNativeDescriptor(_)).WillRepeatedly([&](int descriptor) -> ComplianceEngine::Result<void> {
                EXPECT_EQ(1U, live.erase(descriptor));
                ++closed;
                return context.RealCloseNativeDescriptor(descriptor);
            });
            auto limits = AmpleLimits();
            limits.shared.fdinfoBytes = cap;
            auto opened = Path::Make(context, "/", CrossMountPathPolicy(), limits);
            ASSERT_FALSE(opened.HasValue());
            EXPECT_EQ(EIO, opened.Error().code);
            EXPECT_EQ(1U, overreports);
            EXPECT_EQ(9U, acquired); // root + seven bootstrap/role directories + one fdinfo reader
            EXPECT_EQ(acquired, closed);
            EXPECT_TRUE(live.empty());
            EXPECT_LE(peak, 4U); // root plus at most three concurrently-held procfs temporaries
            EXPECT_EQ(before, CountOpenDescriptors());
            ASSERT_TRUE(testing::Mock::VerifyAndClearExpectations(&context));
        }
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
    auto opened = SelectAcceptedPath(context, source, CrossMountPathPolicy(), AmpleLimits());
    ASSERT_TRUE(opened.HasValue());
    Path path = std::move(opened).Value();
    ASSERT_EQ(0, ::chmod(source.c_str(), 0000));
    auto denied = path.Leaf().OpenReadOnly();
    ASSERT_FALSE(denied.HasValue());
    EXPECT_EQ(EACCES, denied.Error().code);
    EXPECT_EQ(0, ::chmod(source.c_str(), 0600));
}

TEST_F(PathAliasTest, ProcfsMagicLinkCannotEnterManualResolver)
{
    // "/proc/self" is itself a procfs magic link; rooting there would already
    // trip Path::ReadPinnedLink's own "not an ordinary filesystem
    // symlink" rejection during root acquisition. Root at plain "/proc"
    // instead and resolve "self" (also a magic link) as the child under test.
    auto opened = SelectAcceptedPath(context, "/proc", CrossMountPathPolicy(true), AmpleLimits());
    ASSERT_TRUE(opened.HasValue()) << opened.Error().message;
    Path path = std::move(opened).Value();
    auto denied = path.Resolve("self", CrossMountPathPolicy(true));
    ASSERT_FALSE(denied.HasValue());
    EXPECT_EQ(ELOOP, denied.Error().code);
}

TEST_F(PathAliasTest, PinnedLinkRejectsEmptyNulAndNonLinkAndClosesLinkPinOnce)
{
    const std::string root = context.GetTempdirPath();
    ASSERT_EQ(0, ::symlink("target", (root + "/bounded.link").c_str()));
    {
        std::ofstream target((root + "/target").c_str());
        target << "x";
    }
    auto opened = SelectAcceptedPath(context, root, CrossMountPathPolicy(true), AmpleLimits());
    ASSERT_TRUE(opened.HasValue());
    Path path = std::move(opened).Value();
    const std::size_t before = CountOpenDescriptors();

    // What this proves, at the native-seam level and for the whole Resolve()
    // call (not just a "live window" after the read): the rejected read's
    // link descriptor is read exactly once, is never reacquired or retried
    // (no OpenNativeAt/OpenNativePath result for the rest of Resolve() ever
    // has the same identity again), is never surfaced as a directory stream,
    // and is closed through the context seam exactly once. Identity is
    // st_dev/st_ino plus S_ISLNK, from a real fstat() on the exact fd
    // ReadLinkDescriptor receives and, for CloseNativeDescriptor and every
    // OpenNativeAt/OpenNativePath result, a real fstat() taken *before*
    // delegating to the real close or returning the descriptor to the caller
    // (fstat on an already-closed fd cannot observe anything, and the
    // descriptor is still open at the point it is returned). Every such
    // open and close, across the *whole* Resolve() call (not just a "live
    // window" after the read), is recorded with a sequence number; after
    // Resolve() returns, those records are compared against the link
    // identity captured at the read to require that exactly one open
    // anywhere in Resolve() yields that identity -- the original link-pin
    // acquisition, sequenced before the read -- and that exactly one close
    // anywhere in Resolve() yields that identity, sequenced after the read.
    // This does NOT prove that the private reader itself does not consume
    // the pin: that property is structurally guaranteed instead, by
    // Descriptor being RAII-only (no public Close/Release is exposed) and by
    // the reader taking `const Descriptor&`, so no caller -- production or
    // test -- can close it or move from it in the first place; there is no
    // seam that could observe the reader doing so, so no seam-based test can
    // prove it.
    auto expectSingleOwnedFailingRead = [&](int expectedErrorCode, ssize_t injectedReturn, const char* fillBytes) {
        struct Identity
        {
            dev_t device;
            ino_t inode;
            mode_t mode;
            int sequence;
        };
        int observedFd = -1;
        dev_t linkDevice = 0;
        ino_t linkInode = 0;
        bool identityCaptured = false;
        int readCalls = 0;
        int sequence = 0;
        int readSequence = -1;
        int captureFailures = 0;
        std::string captureFailureDetails;
        std::vector<Identity> opens;
        std::vector<Identity> closes;
        auto matchesLinkIdentity = [&](const Identity& identity) {
            return S_ISLNK(identity.mode) && (identity.device == linkDevice) && (identity.inode == linkInode);
        };
        auto recordIdentity = [&](std::vector<Identity>& into, const char* kind, int fd) {
            const int attemptSequence = ++sequence;
            struct stat probe = {};
            if (0 == ::fstat(fd, &probe))
            {
                into.push_back(Identity{probe.st_dev, probe.st_ino, probe.st_mode, attemptSequence});
                return;
            }
            // fstat failed: the attempt is still counted (sequence consumed) so it cannot
            // silently vanish from the exactly-once accounting below.
            ++captureFailures;
            captureFailureDetails += (captureFailureDetails.empty() ? "" : "; ");
            captureFailureDetails += std::string(kind) + " fd=" + std::to_string(fd) + " sequence=" + std::to_string(attemptSequence) +
                                     " uncapturable (fstat failed: descriptor invalid or already closed)";
        };
        EXPECT_CALL(context, ReadLinkDescriptor(_, _, _)).WillOnce([&](int fd, char* buffer, std::size_t) -> ssize_t {
            observedFd = fd;
            struct stat identity = {};
            EXPECT_EQ(0, ::fstat(fd, &identity));
            EXPECT_TRUE(S_ISLNK(identity.st_mode));
            linkDevice = identity.st_dev;
            linkInode = identity.st_ino;
            identityCaptured = true;
            readSequence = ++sequence;
            ++readCalls;
            if (fillBytes)
                std::memcpy(buffer, fillBytes, static_cast<std::size_t>(injectedReturn));
            return injectedReturn;
        });
        EXPECT_CALL(context, CloseNativeDescriptor(_)).WillRepeatedly([&](int fd) -> ComplianceEngine::Result<void> {
            recordIdentity(closes, "close", fd); // fstat before delegating: the fd is still open here.
            return NativeCloseResult(::close(fd));
        });
        // A directory-cursor watchdog here (CloseDirectory, counting the
        // link identity surfacing as a directory stream) would need an FTW
        // layer seam this Path-layer file must not depend on (see
        // PathTraversalTest.cpp).
        // It is also redundant: a close misrouted through CloseDirectory
        // instead of CloseNativeDescriptor would simply never appear in
        // `closes`, so the matchingCloses/closeSequence checks below (built
        // only from CloseNativeDescriptor) already fail closed on exactly
        // that bug -- no observed caller exercises a directory cursor in
        // this test, so there is nothing an additional CloseDirectory
        // expectation could still catch.
        EXPECT_CALL(context, OpenNativeAt(_, _, _)).WillRepeatedly([&](int directory, const char* name, int flags) -> int {
            const int descriptor = context.RealOpenNativeAt(directory, name, flags);
            if (descriptor >= 0)
                recordIdentity(opens, "open(at)", descriptor); // fstat before returning: the fd is still open here.
            return descriptor;
        });
        EXPECT_CALL(context, OpenNativePath(_, _)).WillRepeatedly([&](const char* name, int flags) -> int {
            const int descriptor = context.RealOpenNativePath(name, flags);
            if (descriptor >= 0)
                recordIdentity(opens, "open(path)", descriptor); // fstat before returning: the fd is still open here.
            return descriptor;
        });
        auto resolved = path.Resolve("bounded.link", CrossMountPathPolicy(true));
        ASSERT_FALSE(resolved.HasValue());
        EXPECT_EQ(expectedErrorCode, resolved.Error().code);
        EXPECT_GE(observedFd, 0); // auxiliary: ReadLinkDescriptor received a real descriptor.
        EXPECT_EQ(1, readCalls);
        ASSERT_TRUE(identityCaptured);
        ASSERT_GE(readSequence, 0);
        // Every close/open attempt must have had its identity captured: an uncapturable
        // attempt (fstat failing on an invalid or already-closed fd, or on an fd returned
        // to the caller) would otherwise vanish from the exactly-once counts below instead
        // of failing the test.
        EXPECT_EQ(0, captureFailures) << captureFailureDetails;

        int matchingOpens = 0;
        int openSequence = -1;
        for (const auto& open : opens)
        {
            if (matchesLinkIdentity(open))
            {
                ++matchingOpens;
                openSequence = open.sequence;
            }
        }
        EXPECT_EQ(1, matchingOpens); // only the original link-pin acquisition ever yields this identity
        ASSERT_GE(openSequence, 0);
        EXPECT_LT(openSequence, readSequence); // that acquisition happened before the read, not after (no reacquisition)

        int matchingCloses = 0;
        int closeSequence = -1;
        for (const auto& close : closes)
        {
            if (matchesLinkIdentity(close))
            {
                ++matchingCloses;
                closeSequence = close.sequence;
            }
        }
        EXPECT_EQ(1, matchingCloses); // exactly one close of that identity, across the whole Resolve()
        ASSERT_GE(closeSequence, 0);
        EXPECT_LT(readSequence, closeSequence); // the matching close happened after the read
        ASSERT_TRUE(testing::Mock::VerifyAndClearExpectations(&context));
    };
    expectSingleOwnedFailingRead(E2BIG, 0, nullptr);
    expectSingleOwnedFailingRead(EINVAL, 3, "a\0b");
    EXPECT_EQ(before, CountOpenDescriptors());

    // A fresh resolution below still succeeds, proving that neither earlier
    // rejection left the link, or Path's recovery path, in a stuck state.
    // It does NOT, by itself, prove the earlier pin was not consumed: this
    // call acquires a brand-new pin, not the earlier one. Non-consumption is
    // proven structurally instead, by Descriptor being RAII-only and the
    // reader taking `const Descriptor&`, as established above.
    {
        auto valid = path.Resolve("bounded.link", CrossMountPathPolicy(true));
        ASSERT_TRUE(valid.HasValue()) << valid.Error().message;
        ASSERT_TRUE(valid.Value().Is<Path::Step>());
        EXPECT_EQ(Type::RegularFile, As<Path::Step>(valid.Value()).Metadata().FileType());
    }

    // The "not an ordinary symlink" rejection for a regular (non-link) file is
    // Path::ReadPinnedLink's own defense-in-depth check (~772-774),
    // separate from the resolver's own S_ISLNK stat (~904) that decides
    // whether to call ReadPinnedLink at all. The two are independent native
    // stat observations of the same pin, so lying to only the resolver's
    // first stat (reporting S_IFLNK) while leaving ReadPinnedLink's own,
    // later stat on the same fd reporting the real (non-link) mode reaches
    // ReadPinnedLink's defense-in-depth check without consuming the pin.
    {
        const std::string plain = root + "/plain-file";
        {
            std::ofstream file(plain.c_str());
            file << "y";
        }
        const std::size_t beforeNonLink = CountOpenDescriptors();
        bool liedToResolver = false;
        EXPECT_CALL(context, ReadLinkDescriptor(_, _, _)).Times(0);
        EXPECT_CALL(context, StatNativeDescriptor(_, _)).WillRepeatedly([&](int fd, struct stat* metadata) {
            const int status = context.RealStatNativeDescriptor(fd, metadata);
            if ((0 == status) && !liedToResolver && !S_ISLNK(metadata->st_mode))
            {
                liedToResolver = true;
                metadata->st_mode = (metadata->st_mode & ~S_IFMT) | S_IFLNK;
            }
            return status;
        });
        auto nonLink = path.Resolve("plain-file", CrossMountPathPolicy(true));
        ASSERT_FALSE(nonLink.HasValue());
        EXPECT_EQ(ELOOP, nonLink.Error().code);
        EXPECT_TRUE(liedToResolver); // the lied-to resolver stat was reached
        ASSERT_TRUE(testing::Mock::VerifyAndClearExpectations(&context));
        EXPECT_EQ(beforeNonLink, CountOpenDescriptors());

        // A fresh resolution of the same name (now observed truthfully)
        // still succeeds, proving recovery, not that the rejection left the
        // earlier pin unconsumed: this call acquires a brand-new pin, not
        // the earlier one. Non-consumption is proven structurally instead,
        // as above.
        auto valid = path.Resolve("plain-file", CrossMountPathPolicy(true));
        ASSERT_TRUE(valid.HasValue()) << valid.Error().message;
        ASSERT_TRUE(valid.Value().Is<Path::Step>());
        EXPECT_EQ(Type::RegularFile, As<Path::Step>(valid.Value()).Metadata().FileType());
    }
}

// The resolver observes this child pin's mount once, at acquisition (via
// the shared AcquirePinnedObject helper), before deciding whether it is a
// symlink to follow. A live O_PATH pin cannot change mount, so
// ReadVerifiedLinkText does not re-read or re-compare the mount id around
// the readlink -- only the identity (stat) recheck remains.
TEST_F(PathAliasTest, PinnedLinkReadRechecksIdentity)
{
    const std::string root = context.GetTempdirPath();
    ASSERT_EQ(0, ::symlink("target", (root + "/observed.link").c_str()));
    auto opened = SelectAcceptedPath(context, root, CrossMountPathPolicy(true), AmpleLimits());
    ASSERT_TRUE(opened.HasValue());
    Path path = std::move(opened).Value();
    const std::size_t before = CountOpenDescriptors();

    // The resolver itself stats the newly-opened link once before deciding to
    // follow it; only the post-readlink identity recheck inside
    // ReadVerifiedLinkText (the first S_ISLNK stat observed once the single
    // expected ReadLink has already fired) is corrupted here.
    bool readSeen = false;
    bool corrupted = false;
    EXPECT_CALL(context, ReadLinkDescriptor(_, _, _)).WillOnce([&](int fd, char* buffer, std::size_t size) {
        readSeen = true;
        return ::readlinkat(fd, "", buffer, size);
    });
    EXPECT_CALL(context, StatNativeDescriptor(_, _)).WillRepeatedly([&](int fd, struct stat* snapshot) {
        const int status = context.RealStatNativeDescriptor(fd, snapshot);
        if (readSeen && !corrupted && status == 0 && S_ISLNK(snapshot->st_mode))
        {
            corrupted = true;
            ++snapshot->st_ino;
        }
        return status;
    });
    auto changed = path.Resolve("observed.link", CrossMountPathPolicy(true));
    ASSERT_FALSE(changed.HasValue());
    EXPECT_EQ(EAGAIN, changed.Error().code);
    EXPECT_TRUE(corrupted);
    EXPECT_EQ(before, CountOpenDescriptors());
}

// The reader does not read fdinfo for a mount recheck (the resolver already
// observes this pin's mount at acquisition, via AcquirePinnedObject, and a
// live O_PATH pin cannot change mount); only the stat-observation failure
// sub-case applies here.
TEST_F(PathAliasTest, PinnedLinkReadFailsClosedOnStatObservationErrors)
{
    const std::string root = context.GetTempdirPath();
    ASSERT_EQ(0, ::symlink("target", (root + "/fault.link").c_str()));
    auto opened = SelectAcceptedPath(context, root, CrossMountPathPolicy(true), AmpleLimits());
    ASSERT_TRUE(opened.HasValue());
    Path path = std::move(opened).Value();
    const std::size_t before = CountOpenDescriptors();

    // StatusFlagsDescriptor is only ever called (on this fd) from inside
    // ReadPinnedLink; it is not part of the resolver's own S_ISLNK check, so
    // observing it first reliably marks entry into the pinned reader before
    // gating the stat fault to ReadPinnedLink's own, independent symlink
    // stat, not the resolver's.
    bool enteredPinnedReader = false;
    bool failedStat = false;
    EXPECT_CALL(context, StatusFlagsDescriptor(_)).WillRepeatedly([&](int fd) {
        enteredPinnedReader = true;
        return ::fcntl(fd, F_GETFL);
    });
    EXPECT_CALL(context, StatNativeDescriptor(_, _)).WillRepeatedly([&](int fd, struct stat* snapshot) {
        const int status = context.RealStatNativeDescriptor(fd, snapshot);
        if (enteredPinnedReader && !failedStat && status == 0 && S_ISLNK(snapshot->st_mode))
        {
            failedStat = true;
            errno = EIO;
            return -1;
        }
        return status;
    });
    auto stat = path.Resolve("fault.link", CrossMountPathPolicy(true));
    ASSERT_FALSE(stat.HasValue());
    EXPECT_EQ(EIO, stat.Error().code);
    EXPECT_TRUE(failedStat);
    EXPECT_TRUE(enteredPinnedReader); // the seam inside the pinned reader was actually reached
    EXPECT_EQ(before, CountOpenDescriptors());
}

// Following a link does not bootstrap its own procfs session (the mount is
// observed once, by the resolver's shared acquisition helper before the
// symlink branch), so no procfs helper descriptor is open during or after
// the link's own ReadLink call for a close failure to compete with. This
// test provides positive evidence that only one procfs bootstrap (the
// resolver's own mount observation for this pin, before the symlink branch)
// ever happens, not a second one for the link read itself.
TEST_F(PathAliasTest, PinnedLinkReadErrorIsPrimaryWithOnlyOneProcfsBootstrap)
{
    const std::string root = context.GetTempdirPath();
    ASSERT_EQ(0, ::symlink("target", (root + "/failing.link").c_str()));
    bool failedRead = false;
    int procfsBootstraps = 0;
    auto opened = SelectAcceptedPath(context, root, CrossMountPathPolicy(true), AmpleLimits());
    ASSERT_TRUE(opened.HasValue());
    Path path = std::move(opened).Value();
    const std::size_t before = CountOpenDescriptors();
    EXPECT_CALL(context, OpenNativePath(_, _)).WillRepeatedly([&](const char* name, int flags) {
        if (std::string("/proc") == name)
            ++procfsBootstraps;
        return context.RealOpenNativePath(name, flags);
    });
    EXPECT_CALL(context, ReadLinkDescriptor(_, _, _)).WillOnce([&](int, char*, std::size_t) -> ssize_t {
        failedRead = true;
        errno = ENOSPC;
        return -1;
    });
    auto failure = path.Resolve("failing.link", CrossMountPathPolicy(true));
    ASSERT_FALSE(failure.HasValue());
    EXPECT_EQ(ENOSPC, failure.Error().code);
    EXPECT_TRUE(failedRead);
    // One bootstrap for the resolver's own mount observation of this pin;
    // none for the link read itself.
    EXPECT_EQ(1, procfsBootstraps);
    EXPECT_EQ(before, CountOpenDescriptors());
}

// Same rationale as above, for the successful-read route. Resolving the
// link successfully still reaches a *second*, distinct component
// ("target"), which legitimately gets its own mount observation; the
// invariant under test is that following the link itself does not add a
// bootstrap beyond that, i.e. exactly two (one per physical pin), not three.
TEST_F(PathAliasTest, PinnedLinkSuccessfulReadBootstrapsProcfsOncePerPinNotTwice)
{
    const std::string root = context.GetTempdirPath();
    ASSERT_EQ(0, ::symlink("target", (root + "/close.link").c_str()));
    {
        std::ofstream target((root + "/target").c_str());
        target << "x";
    }
    bool read = false;
    int procfsBootstraps = 0;
    auto opened = SelectAcceptedPath(context, root, CrossMountPathPolicy(true), AmpleLimits());
    ASSERT_TRUE(opened.HasValue());
    Path path = std::move(opened).Value();
    const std::size_t before = CountOpenDescriptors();
    EXPECT_CALL(context, OpenNativePath(_, _)).WillRepeatedly([&](const char* name, int flags) {
        if (std::string("/proc") == name)
            ++procfsBootstraps;
        return context.RealOpenNativePath(name, flags);
    });
    EXPECT_CALL(context, ReadLinkDescriptor(_, _, _)).WillOnce([&](int fd, char* buffer, std::size_t size) {
        read = true;
        return ::readlinkat(fd, "", buffer, size);
    });
    {
        auto acquired = path.Resolve("close.link", CrossMountPathPolicy(true));
        ASSERT_TRUE(acquired.HasValue()) << acquired.Error().message;
        ASSERT_TRUE(acquired.Value().Is<Path::Step>());
        struct stat expected = {};
        ASSERT_EQ(0, ::stat((root + "/target").c_str(), &expected));
        EXPECT_EQ(expected.st_ino, As<Path::Step>(acquired.Value()).Target().Metadata().Stat().st_ino);
        EXPECT_TRUE(read);
        // One bootstrap for "close.link" itself, one for "target"; no extra
        // bootstrap for the link read.
        EXPECT_EQ(2, procfsBootstraps);
    }
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
        EXPECT_EQ(accepted.Value().Leaf().Metadata().Stat().st_ino, matching.Value().Leaf().Metadata().Stat().st_ino);

        ASSERT_EQ(0, ::rename(rootName.c_str(), (rootName + ".former").c_str()));
        ASSERT_EQ(0, ::mkdir(rootName.c_str(), 0700));
        auto replacement = SelectAcceptedPath(context, rootName, CrossMountPathPolicy(), limits);
        ASSERT_TRUE(replacement.HasValue());
        EXPECT_NE(accepted.Value().Leaf().Metadata().Stat().st_ino, replacement.Value().Leaf().Metadata().Stat().st_ino);
        EXPECT_EQ(accepted.Value().Leaf().Metadata().Stat().st_ino, matching.Value().Leaf().Metadata().Stat().st_ino);
    }
    EXPECT_EQ(before, CountOpenDescriptors());
}

// A moved-from Path/Step is consumed: every state-reading operation checks
// liveness first and throws std::logic_error, before any other validation
// or native dispatch, so a moved-from object diagnoses deterministically
// instead of reading retired state. StrictMock with every relevant native
// seam declared Times(0) proves none of them fire -- the throw happens
// before native dispatch, not instead of a call that already happened.
TEST_F(PathAliasTest, MovedFromPathChecksEveryAccessorBeforeNativeDispatch)
{
    ::testing::StrictMock<MockContext> strict;
    strict.AllowIncidentalNativeAccess();
    auto opened = SelectAcceptedPath(strict, "/", CrossMountPathPolicy(), AmpleLimits());
    ASSERT_TRUE(opened.HasValue()) << opened.Error().message;
    Path path = std::move(opened).Value();
    Path moved(std::move(path));
    ASSERT_TRUE(testing::Mock::VerifyAndClearExpectations(&strict));
    EXPECT_CALL(strict, OpenNativePath(_, _)).Times(0);
    EXPECT_CALL(strict, OpenNativeAt(_, _, _)).Times(0);
    EXPECT_CALL(strict, StatNativeDescriptor(_, _)).Times(0);
    EXPECT_CALL(strict, StatFilesystemDescriptor(_, _)).Times(0);
    EXPECT_CALL(strict, ReadNativeDescriptor(_, _, _)).Times(0);
    EXPECT_CALL(strict, ReadLinkDescriptor(_, _, _)).Times(0);
    EXPECT_CALL(strict, StatusFlagsDescriptor(_)).Times(0);
    EXPECT_CALL(strict, DescriptorFlagsDescriptor(_)).Times(0);
    EXPECT_CALL(strict, DuplicateDescriptor(_)).Times(0);
    EXPECT_CALL(strict, CloseNativeDescriptor(_)).Times(0);
    EXPECT_CALL(strict, NativeProcessId()).Times(0);
    EXPECT_CALL(strict, NativeThreadId()).Times(0);
    EXPECT_THROW((void)path.Root(), std::logic_error);
    EXPECT_THROW((void)path.Leaf(), std::logic_error);
    EXPECT_THROW((void)path.Size(), std::logic_error);
    EXPECT_THROW((void)path.RetainedDescriptors(), std::logic_error);
    EXPECT_THROW((void)path.Limits(), std::logic_error);
    EXPECT_THROW((void)path.Context(), std::logic_error);
    EXPECT_THROW((void)PathTestAccess::LookupName(path), std::logic_error);
    EXPECT_THROW((void)PathTestAccess::ToString(path), std::logic_error);
    EXPECT_THROW((void)path.Resolve("proc", CrossMountPathPolicy()), std::logic_error);
    EXPECT_THROW((void)path.Freeze(), std::logic_error);
    try
    {
        (void)path.Root();
        FAIL() << "expected std::logic_error";
    }
    catch (const std::logic_error& error)
    {
        EXPECT_STREQ("Path: use after move", error.what());
    }
    testing::Mock::VerifyAndClearExpectations(&strict);
    strict.AllowIncidentalNativeAccess(); // `moved`'s own destruction below is a real close
    EXPECT_EQ("/", PathTestAccess::ToString(moved));
}

TEST_F(PathAliasTest, MovedFromStepChecksEveryAccessorBeforeNativeDispatch)
{
    ::testing::StrictMock<MockContext> strict;
    strict.AllowIncidentalNativeAccess();
    auto opened = SelectAcceptedPath(strict, "/", CrossMountPathPolicy(), AmpleLimits());
    ASSERT_TRUE(opened.HasValue()) << opened.Error().message;
    Path path = std::move(opened).Value();
    auto resolved = SelectStep(path, "proc", CrossMountPathPolicy());
    ASSERT_TRUE(resolved.HasValue()) << resolved.Error().message;
    Path::Step step = std::move(resolved).Value();
    Path::Step moved(std::move(step));
    ASSERT_TRUE(testing::Mock::VerifyAndClearExpectations(&strict));
    EXPECT_CALL(strict, OpenNativePath(_, _)).Times(0);
    EXPECT_CALL(strict, OpenNativeAt(_, _, _)).Times(0);
    EXPECT_CALL(strict, StatNativeDescriptor(_, _)).Times(0);
    EXPECT_CALL(strict, StatFilesystemDescriptor(_, _)).Times(0);
    EXPECT_CALL(strict, ReadNativeDescriptor(_, _, _)).Times(0);
    EXPECT_CALL(strict, DuplicateDescriptor(_)).Times(0);
    EXPECT_CALL(strict, CloseNativeDescriptor(_)).Times(0);
    EXPECT_THROW((void)step.Metadata(), std::logic_error);
    EXPECT_THROW((void)step.Target(), std::logic_error);
    EXPECT_THROW((void)step.RetainedDescriptors(), std::logic_error);
    try
    {
        (void)step.Target();
        FAIL() << "expected std::logic_error";
    }
    catch (const std::logic_error& error)
    {
        EXPECT_STREQ("Path::Step: use after move", error.what());
    }
    testing::Mock::VerifyAndClearExpectations(&strict);
    strict.AllowIncidentalNativeAccess(); // `path` and `moved`'s own destruction below are real closes
    EXPECT_EQ(Type::Directory, moved.Metadata().FileType());
}

TEST_F(PathAliasTest, ApplyChecksTheMovedFromPathAndTheMovedFromStepArgument)
{
    ::testing::StrictMock<MockContext> strict;
    strict.AllowIncidentalNativeAccess();
    auto openedA = SelectAcceptedPath(strict, "/", CrossMountPathPolicy(), AmpleLimits());
    ASSERT_TRUE(openedA.HasValue()) << openedA.Error().message;
    Path path = std::move(openedA).Value();
    auto liveStep = SelectStep(path, "proc", CrossMountPathPolicy());
    ASSERT_TRUE(liveStep.HasValue()) << liveStep.Error().message;
    Path keepAlive(std::move(path)); // path is now moved-from

    auto openedB = SelectAcceptedPath(strict, "/", CrossMountPathPolicy(), AmpleLimits());
    ASSERT_TRUE(openedB.HasValue()) << openedB.Error().message;
    Path livePath = std::move(openedB).Value();
    auto toConsume = SelectStep(livePath, "proc", CrossMountPathPolicy());
    ASSERT_TRUE(toConsume.HasValue()) << toConsume.Error().message;
    Path::Step sourceStep = std::move(toConsume).Value();
    Path::Step sink(std::move(sourceStep)); // sourceStep is now moved-from

    ASSERT_TRUE(testing::Mock::VerifyAndClearExpectations(&strict));
    EXPECT_CALL(strict, OpenNativePath(_, _)).Times(0);
    EXPECT_CALL(strict, OpenNativeAt(_, _, _)).Times(0);
    EXPECT_CALL(strict, StatNativeDescriptor(_, _)).Times(0);
    EXPECT_CALL(strict, DuplicateDescriptor(_)).Times(0);
    EXPECT_CALL(strict, CloseNativeDescriptor(_)).Times(0);
    // Path checked first: a live Step argument is never touched.
    EXPECT_THROW((void)path.Apply(std::move(liveStep.Value())), std::logic_error);
    EXPECT_NO_THROW((void)liveStep.Value().Target()); // never reached, so never consumed
    // Step checked next, against an otherwise-live Path.
    EXPECT_THROW((void)livePath.Apply(std::move(sourceStep)), std::logic_error);
    testing::Mock::VerifyAndClearExpectations(&strict);
    strict.AllowIncidentalNativeAccess(); // keepAlive/livePath/sink's own destruction below are real closes
}

TEST_F(PathAliasTest, MovingOrAssigningIntoAMovedFromPathFollowsLifetimeRules)
{
    ::testing::StrictMock<MockContext> strict;
    strict.AllowIncidentalNativeAccess();
    // Moving from a moved-from Path gives a moved-from destination.
    {
        auto opened = SelectAcceptedPath(strict, "/", CrossMountPathPolicy(), AmpleLimits());
        ASSERT_TRUE(opened.HasValue()) << opened.Error().message;
        Path first = std::move(opened).Value();
        Path second(std::move(first));
        Path third(std::move(first)); // first is already moved-from
        EXPECT_THROW((void)first.Size(), std::logic_error);
        EXPECT_THROW((void)third.Size(), std::logic_error);
        EXPECT_GT(second.Size(), 0u);
    }
    // Assigning a live Path into a moved-from one reinitializes it.
    {
        auto openedA = SelectAcceptedPath(strict, "/", CrossMountPathPolicy(), AmpleLimits());
        ASSERT_TRUE(openedA.HasValue()) << openedA.Error().message;
        Path a = std::move(openedA).Value();
        Path b(std::move(a)); // a is moved-from
        auto openedC = SelectAcceptedPath(strict, strict.GetTempdirPath(), CrossMountPathPolicy(), AmpleLimits());
        ASSERT_TRUE(openedC.HasValue()) << openedC.Error().message;
        Path c = std::move(openedC).Value();
        const auto route = PathTestAccess::ToString(c);
        a = std::move(c);
        EXPECT_EQ(route, PathTestAccess::ToString(a));
        EXPECT_THROW((void)c.Size(), std::logic_error);
    }
    // Self-move-assignment of a live Path leaves it unchanged.
    {
        auto opened = SelectAcceptedPath(strict, "/", CrossMountPathPolicy(), AmpleLimits());
        ASSERT_TRUE(opened.HasValue()) << opened.Error().message;
        Path path = std::move(opened).Value();
        const auto route = PathTestAccess::ToString(path);
        const auto descriptors = path.RetainedDescriptors();
        Path& self = path;
        path = std::move(self);
        EXPECT_EQ(route, PathTestAccess::ToString(path));
        EXPECT_EQ(descriptors, path.RetainedDescriptors());
    }
    // Destroying a moved-from Path makes no native call.
    {
        auto opened = SelectAcceptedPath(strict, "/", CrossMountPathPolicy(), AmpleLimits());
        ASSERT_TRUE(opened.HasValue()) << opened.Error().message;
        Path keep = std::move(opened).Value();
        std::unique_ptr<Path> movedFrom(new Path(std::move(keep)));
        keep = std::move(*movedFrom); // keep is live again; *movedFrom is moved-from
        ASSERT_TRUE(testing::Mock::VerifyAndClearExpectations(&strict));
        EXPECT_CALL(strict, CloseNativeDescriptor(_)).Times(0);
        EXPECT_CALL(strict, OpenNativePath(_, _)).Times(0);
        EXPECT_CALL(strict, OpenNativeAt(_, _, _)).Times(0);
        movedFrom.reset(); // destroys the moved-from Path; no native call
        testing::Mock::VerifyAndClearExpectations(&strict);
        strict.AllowIncidentalNativeAccess(); // `keep`'s own destruction below is a real close
        EXPECT_GT(keep.RetainedDescriptors(), 0u);
    }
}

TEST_F(PathAliasTest, MovingOrAssigningIntoAMovedFromStepFollowsLifetimeRules)
{
    auto opened = SelectAcceptedPath(context, "/", CrossMountPathPolicy(), AmpleLimits());
    ASSERT_TRUE(opened.HasValue()) << opened.Error().message;
    Path path = std::move(opened).Value();
    auto resolvedA = SelectStep(path, "proc", CrossMountPathPolicy());
    ASSERT_TRUE(resolvedA.HasValue()) << resolvedA.Error().message;
    Path::Step first = std::move(resolvedA).Value();
    Path::Step second(std::move(first));
    Path::Step third(std::move(first)); // first is already moved-from
    EXPECT_THROW((void)first.Target(), std::logic_error);
    EXPECT_THROW((void)third.Target(), std::logic_error);
    EXPECT_EQ(Type::Directory, second.Metadata().FileType());

    auto resolvedB = SelectStep(path, "proc", CrossMountPathPolicy());
    ASSERT_TRUE(resolvedB.HasValue()) << resolvedB.Error().message;
    Path::Step live = std::move(resolvedB).Value();
    const auto ino = live.Target().Metadata().Stat().st_ino;
    second = std::move(live); // reinitializes the moved-from `second`
    EXPECT_EQ(ino, second.Target().Metadata().Stat().st_ino);
    EXPECT_THROW((void)live.Target(), std::logic_error);
}

TEST_F(PathAliasTest, ApplyConsumesItsStepOnSuccessAndOnRejection)
{
    const std::string root = context.GetTempdirPath();
    ASSERT_EQ(0, ::mkdir((root + "/left").c_str(), 0700));
    ASSERT_EQ(0, ::mkdir((root + "/right").c_str(), 0700));
    auto opened = SelectAcceptedPath(context, root, CrossMountPathPolicy(), AmpleLimits());
    ASSERT_TRUE(opened.HasValue()) << opened.Error().message;
    Path path = std::move(opened).Value();
    auto left = SelectStep(path, "left", CrossMountPathPolicy());
    ASSERT_TRUE(left.HasValue());
    auto right = SelectStep(path, "right", CrossMountPathPolicy()); // captured at the same, pre-navigation depth
    ASSERT_TRUE(right.HasValue());
    Path::Step leftStep = std::move(left).Value();
    Path::Step rightStep = std::move(right).Value();
    auto applied = path.Apply(std::move(leftStep));
    ASSERT_TRUE(applied.HasValue()) << applied.Error().message;
    // Apply consumes its Step argument on every return path, including
    // this successful one.
    EXPECT_THROW((void)leftStep.Target(), std::logic_error);
    auto rejected = path.Apply(std::move(rightStep)); // stale: captured before the move to "left"
    ASSERT_FALSE(rejected.HasValue());
    EXPECT_EQ(ESTALE, rejected.Error().code);
    // A rejected Apply consumes its Step too -- not just a successful one.
    EXPECT_THROW((void)rightStep.Target(), std::logic_error);
}

TEST_F(PathAliasTest, PhysicalRootNeverEmptyAndMoveTransfersSourceToMovedFrom)
{
    auto root = SelectAcceptedPath(context, "/", CrossMountPathPolicy(), AmpleLimits());
    ASSERT_TRUE(root.HasValue());
    Path processRoot = std::move(root).Value();
    EXPECT_EQ(1u, processRoot.Size());
    EXPECT_EQ("/", processRoot.Root().Metadata().LookupName());
    EXPECT_EQ("/", processRoot.Leaf().Metadata().EffectiveName());
    auto selected = SelectAcceptedPath(context, context.GetTempdirPath(), CrossMountPathPolicy(), AmpleLimits());
    ASSERT_TRUE(selected.HasValue());
    Path source = std::move(selected).Value();
    const std::string route = PathTestAccess::ToString(source);
    const auto depth = source.Size();
    // Path moves transfer ownership of the shared payload; `source` is
    // moved-from afterward and every checked accessor on it throws before
    // any other validation or native dispatch, while `moved` keeps the
    // exact snapshot `source` held.
    Path moved(std::move(source));
    EXPECT_THROW((void)source.Size(), std::logic_error);
    EXPECT_THROW((void)PathTestAccess::ToString(source), std::logic_error);
    EXPECT_THROW((void)source.Root(), std::logic_error);
    EXPECT_THROW((void)source.Freeze(), std::logic_error);
    EXPECT_EQ(depth, moved.Size());
    EXPECT_EQ(route, PathTestAccess::ToString(moved));
    EXPECT_EQ("/", moved.Root().Metadata().LookupName());
    EXPECT_GT(moved.RetainedDescriptors(), 0u);
    auto noChange = moved.Freeze();
    ASSERT_TRUE(noChange.HasValue());
    EXPECT_FALSE(noChange.Value());
    EXPECT_EQ(route, PathTestAccess::ToString(moved));
}

TEST_F(PathAliasTest, ResolveOwnsTargetAfterPathAndStepRetireWithoutChangingSource)
{
    const auto name = context.MakeTempfile("pinned data");
    std::unique_ptr<Path::Component> retained;
    {
        auto opened = SelectAcceptedPath(context, context.GetTempdirPath(), CrossMountPathPolicy(), AmpleLimits());
        ASSERT_TRUE(opened.HasValue());
        Path path = std::move(opened).Value();
        const std::string before = PathTestAccess::ToString(path);
        const std::size_t depth = path.Size();
        auto resolved = SelectStep(path, name.substr(name.find_last_of('/') + 1), CrossMountPathPolicy());
        ASSERT_TRUE(resolved.HasValue()) << resolved.Error().message;
        Path::Step step = std::move(resolved).Value();
        const auto facts = step.Metadata();
        EXPECT_EQ(Type::RegularFile, facts.FileType());
        EXPECT_GT(facts.LookupMount().Value(), 0u);
        EXPECT_GT(facts.TargetMount().Value(), 0u);
        retained.reset(new Path::Component(step.Target()));
        const auto expectedIno = retained->Metadata().Stat().st_ino;
        Path::Step moved(std::move(step));
        // Step moves transfer ownership of the shared payload: `step` is
        // moved-from; its checked accessors throw, while `moved` keeps the
        // exact target `retained` already captured.
        EXPECT_THROW((void)step.Target(), std::logic_error);
        EXPECT_EQ(expectedIno, moved.Target().Metadata().Stat().st_ino);
        EXPECT_EQ(before, PathTestAccess::ToString(path));
        EXPECT_EQ(depth, path.Size());
        EXPECT_EQ(name, retained->Metadata().LookupName());
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
    const auto before = PathTestAccess::ToString(path);
    const auto initialDepth = path.Size();
    auto left = SelectStep(path, "left", CrossMountPathPolicy());
    auto right = SelectStep(path, "right", CrossMountPathPolicy());
    ASSERT_TRUE(left.HasValue());
    ASSERT_TRUE(right.HasValue());
    EXPECT_EQ(root + "/right", right.Value().Target().Metadata().LookupName());
    EXPECT_CALL(context, OpenNativePath(_, _)).Times(0);
    EXPECT_CALL(context, OpenNativeAt(_, _, _)).Times(0);
    EXPECT_CALL(context, DuplicateDescriptor(_)).Times(0);
    EXPECT_CALL(context, StatNativeDescriptor(_, _)).Times(0);
    auto inverse = path.Apply(std::move(left.Value()));
    ASSERT_TRUE(inverse.HasValue()) << inverse.Error().message;
    EXPECT_EQ(root + "/left", PathTestAccess::ToString(path));
    // Apply consumes its Step argument even when it rejects it, so `right`
    // (captured at the pre-navigation depth) is moved-from after this call
    // and cannot be replayed; the later successful application of "right"
    // re-resolves it instead.
    auto stale = path.Apply(std::move(right.Value()));
    ASSERT_FALSE(stale.HasValue());
    EXPECT_EQ(ESTALE, stale.Error().code);
    auto restored = path.Apply(std::move(inverse.Value()));
    ASSERT_TRUE(restored.HasValue()) << restored.Error().message;
    EXPECT_EQ(before, PathTestAccess::ToString(path));
    EXPECT_EQ(initialDepth, path.Size());
    testing::Mock::VerifyAndClearExpectations(&context); // re-resolving "right" below makes a real OpenNativeAt/StatNativeDescriptor call
    auto freshRight = SelectStep(path, "right", CrossMountPathPolicy());
    ASSERT_TRUE(freshRight.HasValue());
    auto replay = path.Apply(std::move(freshRight.Value()));
    ASSERT_TRUE(replay.HasValue()) << replay.Error().message;
    EXPECT_EQ(root + "/right", PathTestAccess::ToString(path));
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
    EXPECT_EQ("/", path.Root().Metadata().LookupName());
    auto repeat = path.Freeze();
    ASSERT_TRUE(repeat.HasValue());
    EXPECT_FALSE(repeat.Value());
    EXPECT_FALSE(path.Resolve("same", policy).HasValue());
    EXPECT_FALSE(path.Resolve("escape", policy).HasValue());
    EXPECT_FALSE(path.Apply(std::move(old.Value())).HasValue());
    EXPECT_EQ(root + "/bob", PathTestAccess::ToString(path));
    EXPECT_EQ(depth, path.Size());
    // Absolute spelling equality does not authorize a parent crossing.
}

TEST_F(PathAliasTest, SingleChildInputRejectsTraversalAndDoesNotMutate)
{
    auto opened = SelectAcceptedPath(context, context.GetTempdirPath(), CrossMountPathPolicy(), AmpleLimits());
    ASSERT_TRUE(opened.HasValue());
    Path path = std::move(opened).Value();
    const auto name = PathTestAccess::LookupName(path);
    const auto depth = path.Size();
    const auto pins = path.RetainedDescriptors();
    const auto held = CountOpenDescriptors();
    for (const std::string& child : std::vector<std::string>{"", ".", "..", "/", "../bob", "a/b", std::string("a\0b", 3)})
    {
        SCOPED_TRACE(child);
        auto result = path.Resolve(child, CrossMountPathPolicy());
        ASSERT_FALSE(result.HasValue());
        EXPECT_EQ(EINVAL, result.Error().code);
        EXPECT_EQ(name, PathTestAccess::LookupName(path));
        EXPECT_EQ(depth, path.Size());
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
    EXPECT_EQ(first.Value().Leaf().Metadata().Stat().st_ino, second.Value().Leaf().Metadata().Stat().st_ino);
    EXPECT_EQ(first.Value().Size(), second.Value().Size());
    // Apply consumes its Step argument on every return path, including a
    // rejection, so the step rejected below cannot be replayed against the
    // correct acquisition -- a second, independently resolved step (bound
    // to the same acquisition) proves that acquisition accepts it, instead
    // of reusing the one `second` just rejected.
    auto crossStep = SelectStep(first.Value(), "child", CrossMountPathPolicy());
    ASSERT_TRUE(crossStep.HasValue());
    auto detached = second.Value().Apply(std::move(crossStep.Value()));
    ASSERT_FALSE(detached.HasValue());
    EXPECT_EQ(ESTALE, detached.Error().code);
    auto ownStep = SelectStep(first.Value(), "child", CrossMountPathPolicy());
    ASSERT_TRUE(ownStep.HasValue());
    EXPECT_TRUE(first.Value().Apply(std::move(ownStep.Value())).HasValue());
}

TEST_F(PathAliasTest, WorkedPhysicalSuffixDeltaAndUndoRetainHeldAncestors)
{
    const std::string root = context.GetTempdirPath();
    ASSERT_EQ(0, ::mkdir((root + "/sub").c_str(), 0700));
    ASSERT_EQ(0, ::mkdir((root + "/x").c_str(), 0700));
    ASSERT_EQ(0, ::symlink("../x", (root + "/sub/link").c_str()));
    auto policy = CrossMountPathPolicy(true);
    // Apply consumes its Step argument on every return path, including a
    // rejection, so `undoSub` cannot be both rejected as stale (from "x",
    // after the link detour) and later replayed to prove the full
    // restoration back to root. The two properties now need their own
    // acquisition of the same fixture.
    {
        SCOPED_TRACE("a stale inverse, captured before a link detour, is rejected");
        auto opened = SelectAcceptedPath(context, root, policy, AmpleLimits());
        ASSERT_TRUE(opened.HasValue());
        Path path = std::move(opened).Value();
        auto intoSub = SelectStep(path, "sub", policy);
        ASSERT_TRUE(intoSub.HasValue());
        auto undoSub = path.Apply(std::move(intoSub.Value()));
        ASSERT_TRUE(undoSub.HasValue());
        auto link = SelectStep(path, "link", policy);
        ASSERT_TRUE(link.HasValue()) << link.Error().message;
        auto undoLink = path.Apply(std::move(link.Value()));
        ASSERT_TRUE(undoLink.HasValue()) << undoLink.Error().message;
        EXPECT_EQ(root + "/x", PathTestAccess::ToString(path));
        EXPECT_EQ(ESTALE, path.Apply(std::move(undoSub.Value())).Error().code);
    }
    {
        SCOPED_TRACE("undo retains held ancestors all the way back to root");
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
        EXPECT_EQ(Type::Directory, link.Value().Metadata().FileType());
        EXPECT_GT(link.Value().Metadata().LookupMount().Value(), 0u);
        EXPECT_GT(link.Value().Metadata().TargetMount().Value(), 0u);
        const auto previous = path.Leaf().Metadata().Stat().st_ino;
        auto undoLink = path.Apply(std::move(link.Value()));
        ASSERT_TRUE(undoLink.HasValue()) << undoLink.Error().message;
        EXPECT_EQ(subDepth, path.Size()); // pop sub and push x; never lexical sub/link
        EXPECT_EQ(root + "/x", PathTestAccess::ToString(path));
        EXPECT_NE(previous, path.Leaf().Metadata().Stat().st_ino);
        auto back = path.Apply(std::move(undoLink.Value()));
        ASSERT_TRUE(back.HasValue());
        EXPECT_EQ(root + "/sub", PathTestAccess::ToString(path));
        EXPECT_EQ(previous, path.Leaf().Metadata().Stat().st_ino);
        auto toRoot = path.Apply(std::move(undoSub.Value()));
        ASSERT_TRUE(toRoot.HasValue());
        EXPECT_EQ(rootDepth, path.Size());
        EXPECT_EQ(root, PathTestAccess::ToString(path));
        EXPECT_EQ("/", path.Root().Metadata().LookupName());
    }
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
    const auto held = step.Value().Target().Metadata();
    ASSERT_EQ(0, ::rename((root + "/bound").c_str(), (root + "/bound.old").c_str()));
    ASSERT_EQ(0, ::mkdir((root + "/bound").c_str(), 0700));
    ASSERT_EQ(0, ::mkdir((root + "/bound/child").c_str(), 0700));
    const auto newPath = Path::Make(context, root + "/bound/child", CrossMountPathPolicy(), AmpleLimits());
    ASSERT_TRUE(newPath.HasValue());
    ASSERT_TRUE(newPath.Value().Is<Path>());
    EXPECT_NE(held.Stat().st_ino, As<Path>(newPath.Value()).Leaf().Metadata().Stat().st_ino);
    auto inverse = path.Apply(std::move(step.Value()));
    ASSERT_TRUE(inverse.HasValue()) << inverse.Error().message;
    EXPECT_EQ(held.Stat().st_ino, path.Leaf().Metadata().Stat().st_ino);
    EXPECT_EQ(root + "/bound/child", PathTestAccess::LookupName(path)); // retained spelling, not global replay
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
    const auto identity = path.Leaf().Metadata().Stat().st_ino;
    auto step = SelectStep(path, "same", policy);
    ASSERT_TRUE(step.HasValue()) << step.Error().message;
    const auto size = path.Size();
    EXPECT_EQ(identity, step.Value().Target().Metadata().Stat().st_ino);
    auto inverse = path.Apply(std::move(step.Value()));
    ASSERT_TRUE(inverse.HasValue()) << inverse.Error().message;
    EXPECT_EQ(size, path.Size());
    EXPECT_EQ(identity, path.Leaf().Metadata().Stat().st_ino);
    EXPECT_EQ(root + "/same", PathTestAccess::LookupName(path));
    auto restored = path.Apply(std::move(inverse.Value()));
    ASSERT_TRUE(restored.HasValue()) << restored.Error().message;
    EXPECT_EQ(size, path.Size());
    EXPECT_EQ(root, PathTestAccess::LookupName(path));
    EXPECT_EQ(identity, path.Leaf().Metadata().Stat().st_ino);
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
    ON_CALL(context, StatNativeDescriptor(_, _)).WillByDefault([&](int descriptor, struct stat* snapshot) {
        const int status = context.RealStatNativeDescriptor(descriptor, snapshot);
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
    EXPECT_EQ(expected.st_ino, resolved.Value().Target().Metadata().Stat().st_ino);
    EXPECT_EQ(root, PathTestAccess::ToString(path));
}

// Absolute-link counterpart of PinnedLinkInspectionSurvivesNameReplacementDuringResolve
// above: an already-pinned link's *own* fd (O_PATH|O_NOFOLLOW, acquired by
// name before this stat fires) is what ReadLinkDescriptor later reads, not
// whatever object the name currently resolves to. For an absolute link text,
// this must hold even when the by-name replacement is itself a link pointing
// outside the traversal barrier: the held pin's original, in-barrier
// absolute text is still what gets parsed and re-resolved against the
// boundary, so the race cannot be used to smuggle a target outside the
// barrier through EXDEV-exempt code, nor to substitute a different in-barrier
// target.
TEST_F(PathAliasTest, PinnedAbsoluteLinkInspectionSurvivesNameReplacementDuringResolve)
{
    const std::string root = context.GetTempdirPath();
    const std::string insideTarget = root + "/pinned-target";
    {
        std::ofstream file(insideTarget.c_str());
        file << "acquired";
    }
    ASSERT_EQ(0, ::symlink(insideTarget.c_str(), (root + "/abs-link").c_str()));
    auto policy = CrossMountPathPolicy(true);
    auto opened = SelectAcceptedPath(context, root, policy, AmpleLimits());
    ASSERT_TRUE(opened.HasValue());
    Path path = std::move(opened).Value();
    bool replaced = false;
    ON_CALL(context, StatNativeDescriptor(_, _)).WillByDefault([&](int descriptor, struct stat* snapshot) {
        const int status = context.RealStatNativeDescriptor(descriptor, snapshot);
        if ((0 == status) && S_ISLNK(snapshot->st_mode) && !replaced)
        {
            replaced = true;
            EXPECT_EQ(0, ::rename((root + "/abs-link").c_str(), (root + "/abs-link.former").c_str()));
            EXPECT_EQ(0, ::symlink("/etc/passwd", (root + "/abs-link").c_str()));
        }
        return status;
    });
    auto resolved = SelectStep(path, "abs-link", policy);
    ASSERT_TRUE(resolved.HasValue()) << resolved.Error().message;
    EXPECT_TRUE(replaced);
    struct stat expectedInside = {};
    ASSERT_EQ(0, ::stat(insideTarget.c_str(), &expectedInside));
    struct stat replacementOutside = {};
    ASSERT_EQ(0, ::stat("/etc/passwd", &replacementOutside));
    EXPECT_EQ(expectedInside.st_ino, resolved.Value().Target().Metadata().Stat().st_ino);
    EXPECT_NE(replacementOutside.st_ino, resolved.Value().Target().Metadata().Stat().st_ino);
    EXPECT_EQ(root, PathTestAccess::ToString(path));
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
        return OracleMountId(std::string(std::istreambuf_iterator<char>{info}, std::istreambuf_iterator<char>{}));
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
    EXPECT_EQ(lookupMount.Value(), cross.Value().Metadata().LookupMount().Value());
    EXPECT_EQ(targetMount.Value(), cross.Value().Metadata().TargetMount().Value());
    const auto targetFacts = cross.Value().Target().Metadata();
    const auto stepFacts = cross.Value().Metadata();
    EXPECT_EQ(targetFacts.TargetMount().Value(), stepFacts.TargetMount().Value());
    EXPECT_EQ(targetFacts.LookupName(), stepFacts.LookupName());
    EXPECT_EQ(targetFacts.EffectiveName(), stepFacts.EffectiveName());
    EXPECT_EQ(Type::Directory, cross.Value().Metadata().FileType());
    policy.mounts = MountPolicy::StayOnRootMount;
    auto denied = path.Resolve("proc-link", policy);
    ASSERT_FALSE(denied.HasValue());
    EXPECT_EQ(EXDEV, denied.Error().code);
    EXPECT_EQ(root, PathTestAccess::ToString(path));
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
    EXPECT_EQ("/", PathTestAccess::ToString(exactPath));
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
    EXPECT_EQ("/", bounded.Root().Metadata().LookupName());
}
TEST_F(PathAliasTest, ProcfsHelperCloseFailuresAreDiagnosticAndAcquisitionSucceeds)
{
    const auto before = CountOpenDescriptors();
    const std::string logPath = context.GetTempdirPath() + "/helper-close.log";
    OsConfigLogHandle log = OpenLog(logPath.c_str(), nullptr);
    ASSERT_NE(nullptr, log);
    context.SetLogHandle(log);
    std::size_t failed = 0;
    EXPECT_CALL(context, CloseNativeDescriptor(_)).WillRepeatedly([&](int descriptor) -> ComplianceEngine::Result<void> {
        const bool helper = IsProcfsHelper(descriptor);
        const int status = ::close(descriptor);
        EXPECT_EQ(0, status);
        if (helper && failed < 2)
        {
            errno = (0 == failed++) ? EACCES : EIO;
            return ComplianceEngine::Error(errno ? errno : EIO);
        }

        return NativeCloseResult(status);
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
        ExpectLoggedOnce(text, "Failed to close filesystem resource: " + std::string(strerror(code)));
    EXPECT_EQ(before, CountOpenDescriptors());
}

TEST_F(PathAliasTest, PrimaryFdinfoReadErrorOutranksHelperCloseFailure)
{
    const auto before = CountOpenDescriptors();
    bool failedRead = false, failedClose = false;
    EXPECT_CALL(context, ReadNativeDescriptor(_, _, _)).WillRepeatedly([&](int descriptor, void* buffer, std::size_t size) -> ssize_t {
        if (!failedRead && (0 == DescriptorTarget(descriptor).find("/proc/")) && (std::string::npos != DescriptorTarget(descriptor).find("/fdinfo/")))
        {
            failedRead = true;
            errno = ENOSPC;
            return -1;
        }
        return ::read(descriptor, buffer, size);
    });
    EXPECT_CALL(context, CloseNativeDescriptor(_)).WillRepeatedly([&](int descriptor) -> ComplianceEngine::Result<void> {
        const bool helper = IsProcfsHelper(descriptor);
        const int status = ::close(descriptor);
        EXPECT_EQ(0, status);
        if (helper && failedRead && !failedClose)
        {
            failedClose = true;
            errno = EIO;
            return ComplianceEngine::Error(errno ? errno : EIO);
        }
        return NativeCloseResult(status);
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
    EXPECT_EQ(alias, PathTestAccess::LookupName(path));
    EXPECT_EQ(target, PathTestAccess::ToString(path));
    EXPECT_EQ("/", path.Root().Metadata().LookupName());
    EXPECT_EQ(target, path.Leaf().Metadata().EffectiveName());
    EXPECT_CALL(context, OpenNativePath(_, _)).WillRepeatedly([&](const char* name, int flags) { return context.RealOpenNativePath(name, flags); });
    EXPECT_CALL(context, OpenNativePath(testing::StrEq("/"), _)).Times(0);
    auto resolved = SelectStep(path, "via-alias", policy);
    ASSERT_TRUE(resolved.HasValue()) << resolved.Error().message;
    struct stat expected = {};
    ASSERT_EQ(0, ::stat((target + "/inside").c_str(), &expected));
    EXPECT_EQ(expected.st_ino, resolved.Value().Target().Metadata().Stat().st_ino);
    EXPECT_EQ(alias, PathTestAccess::LookupName(path));
    EXPECT_EQ(target, PathTestAccess::ToString(path));
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
    EXPECT_EQ(base + "/child", PathTestAccess::ToString(path));
    EXPECT_EQ(rootDepth + 1, path.Size());
    EXPECT_EQ("/", path.Root().Metadata().LookupName());
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
    EXPECT_EQ(real + "/target", PathTestAccess::ToString(As<Path>(two.Value())));
    limits.linkExpansions = 1;
    ASSERT_EQ(0, ::symlink("real", (base + "/other").c_str()));
    auto selected = SelectAcceptedPath(context, base, CrossMountPathPolicy(), limits);
    ASSERT_TRUE(selected.HasValue());
    auto first = SelectStep(selected.Value(), "first", follow);
    auto other = SelectStep(selected.Value(), "other", follow);
    ASSERT_TRUE(first.HasValue()) << first.Error().message;
    ASSERT_TRUE(other.HasValue()) << other.Error().message;
    EXPECT_EQ(first.Value().Metadata().Stat().st_ino, other.Value().Metadata().Stat().st_ino);
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
    EXPECT_EQ(selected.Value().Leaf().Metadata().Stat().st_ino, seven.Value().Metadata().Stat().st_ino);
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
    const auto unchanged = PathTestAccess::ToString(selected.Value());
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
        EXPECT_EQ(unchanged, PathTestAccess::ToString(selected.Value()));
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
    EXPECT_EQ(base, PathTestAccess::ToString(selected.Value()));
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
    EXPECT_CALL(context, CloseNativeDescriptor(_)).WillRepeatedly([&](int fd) -> ComplianceEngine::Result<void> {
        struct stat info = {};
        const bool inspected = ::fstat(fd, &info) == 0;
        const bool fifo = inspected && S_ISFIFO(info.st_mode);
        const bool hiddenDirectory = inspected && S_ISDIR(info.st_mode) && DescriptorTarget(fd) == directory;
        auto result = context.RealCloseNativeDescriptor(fd);
        if (fifo || hiddenDirectory)
        {
            if (fifo)
                ++failedFifo;
            if (hiddenDirectory)
                ++failedDirectory;
            errno = EIO;
            return ComplianceEngine::Error(errno ? errno : EIO);
        }
        return result;
    });
    auto outcome = selected.Value().Resolve("to-pipe", policy);
    ASSERT_TRUE(outcome.HasValue()) << outcome.Error().message;
    ASSERT_TRUE(outcome.Value().Is<Path::RejectionReason>());
    EXPECT_EQ(Path::RejectionReason::UnsupportedType, As<Path::RejectionReason>(outcome.Value()));
    EXPECT_EQ(1, failedDirectory);
    EXPECT_EQ(1, failedFifo);
    EXPECT_EQ(base, PathTestAccess::ToString(selected.Value()));
    EXPECT_EQ(before, CountOpenDescriptors());
}

TEST_F(PathAliasTest, MissingFactorySelectionSurvivesDiagnosticRootCloseFailure)
{
    const std::string base = context.GetTempdirPath();
    struct stat root = {};
    ASSERT_EQ(0, ::stat("/", &root));
    int failed = 0;
    EXPECT_CALL(context, CloseNativeDescriptor(_)).WillRepeatedly([&](int fd) -> ComplianceEngine::Result<void> {
        struct stat acquired = {};
        const bool processRoot = ::fstat(fd, &acquired) == 0 && acquired.st_dev == root.st_dev && acquired.st_ino == root.st_ino;
        auto result = context.RealCloseNativeDescriptor(fd);
        if (processRoot)
        {
            ++failed;
            errno = EIO;
            return ComplianceEngine::Error(errno ? errno : EIO);
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
    const auto rootInode = selected.Value().Leaf().Metadata().Stat().st_ino;
    auto first = selected.Value().Resolve("nonexistent-path-child", policy);
    ASSERT_FALSE(first.HasValue());
    EXPECT_EQ(ENOENT, first.Error().code);
    auto second = selected.Value().Resolve("nonexistent-path-child", policy);
    ASSERT_FALSE(second.HasValue());
    EXPECT_EQ(E2BIG, second.Error().code); // already spent at least one held-search cost
    EXPECT_EQ(rootInode, selected.Value().Leaf().Metadata().Stat().st_ino);
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
    EXPECT_EQ(former.st_ino, leaf.Metadata().Stat().st_ino);
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
    EXPECT_EQ(base + "/a/other", PathTestAccess::ToString(As<Path>(followed.Value())));
    struct stat expected = {}, wrong = {};
    ASSERT_EQ(0, ::stat((base + "/a/other").c_str(), &expected));
    ASSERT_EQ(0, ::stat((base + "/other").c_str(), &wrong));
    EXPECT_EQ(expected.st_ino, As<Path>(followed.Value()).Leaf().Metadata().Stat().st_ino);
    EXPECT_NE(wrong.st_ino, As<Path>(followed.Value()).Leaf().Metadata().Stat().st_ino);
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
    EXPECT_EQ(real, PathTestAccess::ToString(held));
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

// The byte half of this test (a compact retained-byte ceiling rejecting the
// same deep path) no longer applies, since Path has no byte ceiling; the
// repeated-work exhaustion property stays.
TEST_F(PathAliasTest, DeepLongNameHeldSearchChargesRepeatedWorkUntilExhausted)
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
    EXPECT_EQ(deep, PathTestAccess::ToString(selected.Value()));
    EXPECT_TRUE(deepPath.Value().Resolve("unpublished", missing).HasValue());
}

// With linkTargetBytes raised far above PATH_MAX, the single ReadLink call
// still receives a buffer size capped at PATH_MAX (4096) + 1, and a short
// link still resolves normally through that one bounded read.
TEST_F(PathAliasTest, ConfiguredLinkBufferCapsAtPlatformPathLengthAndShortLinkResolves)
{
    const std::string base = context.GetTempdirPath();
    const std::string file = context.MakeTempfile("pinned");
    ASSERT_EQ(0, ::symlink(file.c_str(), (base + "/short-link").c_str()));
    ResolverLimits limits = AmpleLimits();
    limits.linkTargetBytes = 100u * 1024u * 1024u;
    auto opened = SelectAcceptedPath(context, base, CrossMountPathPolicy(), limits);
    ASSERT_TRUE(opened.HasValue());
    auto follow = CrossMountPathPolicy(true);
    std::size_t observedBufferSize = 0;
    EXPECT_CALL(context, ReadLinkDescriptor(_, _, _)).Times(1).WillOnce([&](int descriptor, char* buffer, std::size_t size) {
        observedBufferSize = size;
        return context.RealReadLinkDescriptor(descriptor, buffer, size);
    });
    auto accepted = opened.Value().Resolve("short-link", follow);
    ASSERT_TRUE(accepted.HasValue()) << accepted.Error().message;
    ASSERT_TRUE(accepted.Value().Is<Path::Step>());
    EXPECT_EQ(Type::RegularFile, As<Path::Step>(accepted.Value()).Metadata().FileType());
    // Hand-computed oracle: min(linkTargetBytes, PATH_MAX) + 1 = min(100 MiB, 4096) + 1 = 4097.
    EXPECT_EQ(4097u, observedBufferSize);
    EXPECT_EQ(base, PathTestAccess::ToString(opened.Value()));
}

// N/N+1 on the mocked read count itself (not the real content): with
// linkTargetBytes = 8192, the buffer is min(8192, PATH_MAX) + 1 = 4097. A
// read of exactly 4096 (the NFSv3 maximum for a readlink target) is
// accepted; a read of 4097 (== buffer size) means the read was truncated and
// fails closed with ENAMETOOLONG, after exactly one read. The faked target
// text for the first case is the frozen boundary's own absolute spelling,
// padded with trailing '/' to exactly 4096 bytes; it collapses to the
// boundary itself, so the first case resolves as a no-op without reaching
// any NAME_MAX or pending-cap check this test is not exercising.
TEST_F(PathAliasTest, LinkBufferExactReadIsAcceptedOneOverIsTruncated)
{
    const std::string base = context.GetTempdirPath();
    ASSERT_EQ(0, ::symlink("x", (base + "/l").c_str())); // on-disk content is irrelevant; the read is faked below
    ResolverLimits limits = AmpleLimits();
    limits.linkTargetBytes = 8192;
    auto opened = SelectAcceptedPath(context, base, CrossMountPathPolicy(), limits);
    ASSERT_TRUE(opened.HasValue());
    auto follow = CrossMountPathPolicy(true);
    {
        std::size_t observedBufferSize = 0;
        EXPECT_CALL(context, ReadLinkDescriptor(_, _, _)).Times(1).WillOnce([&observedBufferSize, &base](int, char* buffer, std::size_t size) -> ssize_t {
            observedBufferSize = size;
            // An absolute target matching the frozen boundary (base) is a
            // no-op: pad the spelling with trailing '/' so the faked read
            // is exactly 4096 bytes without adding any named component.
            std::memcpy(buffer, base.data(), base.size());
            std::fill_n(buffer + base.size(), 4096 - base.size(), '/');
            return 4096;
        });
        auto accepted = opened.Value().Resolve("l", follow);
        ASSERT_TRUE(accepted.HasValue()) << accepted.Error().message;
        ASSERT_TRUE(accepted.Value().Is<Path::Step>());
        EXPECT_EQ(4097u, observedBufferSize);
        testing::Mock::VerifyAndClearExpectations(&context);
    }
    {
        EXPECT_CALL(context, ReadLinkDescriptor(_, _, _)).Times(1).WillOnce([](int, char* buffer, std::size_t size) -> ssize_t {
            std::fill_n(buffer, size, '/');
            return static_cast<ssize_t>(size); // == buffer size: the read was truncated
        });
        auto rejected = opened.Value().Resolve("l", follow);
        ASSERT_FALSE(rejected.HasValue());
        EXPECT_EQ(ENAMETOOLONG, rejected.Error().code);
        EXPECT_THAT(rejected.Error().message, testing::HasSubstr("exceeds platform path length"));
        testing::Mock::VerifyAndClearExpectations(&context);
    }
    EXPECT_EQ(base, PathTestAccess::ToString(opened.Value()));
}

// Make's non-allocating length pre-scan runs after the EINVAL shape checks
// and before any native call, including PinProcessRoot.
TEST_F(PathAliasTest, MakeTotalLengthExactlyAtTargetBytesSucceedsOneOverFailsBeforeNativeCall)
{
    const std::string base = context.GetTempdirPath();
    ResolverLimits limits = AmpleLimits();
    limits.shared.targetBytes = base.size();
    auto exact = Path::Make(context, base, CrossMountPathPolicy(), limits);
    ASSERT_TRUE(exact.HasValue()) << exact.Error().message;
    ASSERT_TRUE(exact.Value().Is<Path>());

    limits.shared.targetBytes = base.size() - 1;
    EXPECT_CALL(context, OpenNativePath(_, _)).Times(0);
    auto over = Path::Make(context, base, CrossMountPathPolicy(), limits);
    ASSERT_FALSE(over.HasValue());
    EXPECT_EQ(ENAMETOOLONG, over.Error().code);
    EXPECT_THAT(over.Error().message, testing::HasSubstr("exceeds target byte limit"));
    testing::Mock::VerifyAndClearExpectations(&context);
}

// A component exactly at NAME_MAX (255) reaches the lookup; one byte over
// fails with ENAMETOOLONG before any native call. Make's single-component
// resolution always forces Report internally (factoryPolicy.missingFiles),
// independent of the caller's policy, so the accepted case below surfaces
// RejectionReason::Missing rather than ENOENT.
TEST_F(PathAliasTest, MakeComponentAtNameMaxReachesLookupOneOverFailsBeforeNativeCall)
{
    auto policy = CrossMountPathPolicy();
    const std::string atLimit = "/" + std::string(255, 'a');
    ASSERT_EQ(255, NAME_MAX);
    auto accepted = Path::Make(context, atLimit, policy, AmpleLimits());
    ASSERT_TRUE(accepted.HasValue()) << accepted.Error().message;
    ASSERT_TRUE(accepted.Value().Is<Path::RejectionReason>());
    EXPECT_EQ(Path::RejectionReason::Missing, As<Path::RejectionReason>(accepted.Value()));

    const std::string overLimit = "/" + std::string(256, 'a');
    EXPECT_CALL(context, OpenNativePath(_, _)).Times(0);
    auto rejected = Path::Make(context, overLimit, policy, AmpleLimits());
    ASSERT_FALSE(rejected.HasValue());
    EXPECT_EQ(ENAMETOOLONG, rejected.Error().code);
    EXPECT_THAT(rejected.Error().message, testing::HasSubstr("exceeds NAME_MAX"));
    testing::Mock::VerifyAndClearExpectations(&context);
}

// Resolve's length check runs after the EINVAL shape checks; a name exactly
// at NAME_MAX reaches the lookup, one byte over fails with ENAMETOOLONG
// before any OpenAt.
TEST_F(PathAliasTest, ResolveNameAtNameMaxReachesLookupOneOverFailsBeforeOpenAt)
{
    auto opened = SelectAcceptedPath(context, context.GetTempdirPath(), CrossMountPathPolicy(), AmpleLimits());
    ASSERT_TRUE(opened.HasValue());
    Path path = std::move(opened).Value();
    const std::string atLimit(255, 'a');
    auto accepted = path.Resolve(atLimit, CrossMountPathPolicy());
    ASSERT_FALSE(accepted.HasValue());
    EXPECT_EQ(ENOENT, accepted.Error().code); // default missingFiles=Error surfaces the native lookup failure
    EXPECT_EQ(context.GetTempdirPath(), PathTestAccess::ToString(path));

    const std::string overLimit(256, 'a');
    EXPECT_CALL(context, OpenNativeAt(_, _, _)).Times(0);
    auto rejected = path.Resolve(overLimit, CrossMountPathPolicy());
    ASSERT_FALSE(rejected.HasValue());
    EXPECT_EQ(ENAMETOOLONG, rejected.Error().code);
    EXPECT_THAT(rejected.Error().message, testing::HasSubstr("exceeds NAME_MAX"));
    EXPECT_EQ(context.GetTempdirPath(), PathTestAccess::ToString(path));
    testing::Mock::VerifyAndClearExpectations(&context);
}

// A followed link-target component over NAME_MAX fails with ENAMETOOLONG
// after the readlink that revealed it and before any OpenAt of the
// over-long component itself.
TEST_F(PathAliasTest, LinkComponentAtNameMaxReachesLookupOneOverFailsAfterOneReadlink)
{
    const std::string base = context.GetTempdirPath();
    const std::string atLimitTarget(255, 'a');
    const std::string overLimitTarget(256, 'a');
    ASSERT_EQ(0, ::symlink(atLimitTarget.c_str(), (base + "/at-limit").c_str()));
    ASSERT_EQ(0, ::symlink(overLimitTarget.c_str(), (base + "/over-limit").c_str()));
    auto opened = SelectAcceptedPath(context, base, CrossMountPathPolicy(), AmpleLimits());
    ASSERT_TRUE(opened.HasValue());
    auto follow = CrossMountPathPolicy(true);

    auto accepted = opened.Value().Resolve("at-limit", follow);
    ASSERT_FALSE(accepted.HasValue());
    EXPECT_EQ(ENOENT, accepted.Error().code);
    EXPECT_EQ(base, PathTestAccess::ToString(opened.Value()));

    EXPECT_CALL(context, ReadLinkDescriptor(_, _, _)).Times(1);
    // Following "over-limit" first opens the symlink entry itself (that
    // name is short); AllowNativeOpen() permits that and the subsequent
    // procfs identity-check opens, while the narrower expectation below
    // overrides it to forbid only an open of the over-long revealed target.
    context.AllowNativeOpen();
    EXPECT_CALL(context, OpenNativeAt(_, testing::StrEq(overLimitTarget), _)).Times(0);
    auto rejected = opened.Value().Resolve("over-limit", follow);
    ASSERT_FALSE(rejected.HasValue());
    EXPECT_EQ(ENAMETOOLONG, rejected.Error().code);
    EXPECT_THAT(rejected.Error().message, testing::HasSubstr("Link target component exceeds NAME_MAX"));
    EXPECT_EQ(base, PathTestAccess::ToString(opened.Value()));
    testing::Mock::VerifyAndClearExpectations(&context);
}

// A link text guard: a link target longer than targetBytes fails with
// E2BIG, independent of the much larger linkTargetBytes/readlink-count cap. The on-disk symlink content is
// irrelevant; the single ReadLink call is faked to return one byte more
// than the literal targetBytes bound (N+1), writing deterministic bytes
// into the real buffer so the assign() below never reads uninitialized
// memory. A real on-disk target this long is infeasible at the default
// targetBytes (4096 == PATH_MAX, and symlink(2) targets are capped at
// PATH_MAX - 1), so the bound is lowered here to a small literal instead.
TEST_F(PathAliasTest, LinkTextLongerThanTargetBytesFailsWithE2BIG)
{
    const std::string base = context.GetTempdirPath();
    ASSERT_EQ(0, ::symlink("x", (base + "/l").c_str()));
    ResolverLimits limits = AmpleLimits();
    limits.shared.targetBytes = base.size() + 5; // literal bound: large enough for the root, small enough to craft N+1
    auto opened = SelectAcceptedPath(context, base, CrossMountPathPolicy(), limits);
    ASSERT_TRUE(opened.HasValue());
    auto follow = CrossMountPathPolicy(true);
    const std::size_t fakeLength = limits.shared.targetBytes + 1; // N+1 oracle: one byte over the literal bound
    EXPECT_CALL(context, ReadLinkDescriptor(_, _, _)).Times(1).WillOnce([fakeLength](int, char* buffer, std::size_t size) -> ssize_t {
        EXPECT_LT(fakeLength, size); // must still fit the real buffer, not be mistaken for a truncated read
        std::fill_n(buffer, fakeLength, 'a');
        return static_cast<ssize_t>(fakeLength);
    });
    auto rejected = opened.Value().Resolve("l", follow);
    ASSERT_FALSE(rejected.HasValue());
    EXPECT_EQ(E2BIG, rejected.Error().code);
    EXPECT_THAT(rejected.Error().message, testing::HasSubstr("exceeds target byte limit"));
    EXPECT_EQ(base, PathTestAccess::ToString(opened.Value()));
    testing::Mock::VerifyAndClearExpectations(&context);
}

// Pending-component cap: resolving link "l" charges 1 (the link itself);
// its target "x/./././." expands into 5 further components (x, ., ., ., .),
// so 1 + 5 = 6 total charges are needed. A one-short components budget must
// fail before opening "x" at all -- a late charge failure would open "x"
// first.
TEST_F(PathAliasTest, PendingCapExactComponentsSucceedsOneUnderFailsBeforeOpeningExpansion)
{
    const std::string base = context.GetTempdirPath();
    ASSERT_EQ(0, ::mkdir((base + "/x").c_str(), 0700));
    ASSERT_EQ(0, ::symlink("x/./././.", (base + "/l").c_str()));
    auto follow = CrossMountPathPolicy(true);

    auto ample = AmpleLimits();
    ample.shared.components = 6;
    auto exact = SelectAcceptedPath(context, base, CrossMountPathPolicy(), ample);
    ASSERT_TRUE(exact.HasValue());
    auto accepted = exact.Value().Resolve("l", follow);
    ASSERT_TRUE(accepted.HasValue()) << accepted.Error().message;
    ASSERT_TRUE(accepted.Value().Is<Path::Step>());

    auto tight = AmpleLimits();
    tight.shared.components = 5;
    auto under = SelectAcceptedPath(context, base, CrossMountPathPolicy(), tight);
    ASSERT_TRUE(under.HasValue());
    // Following "l" first opens the link entry itself (name "l", not "x");
    // AllowNativeOpen() permits that and the subsequent procfs
    // identity-check opens, while the narrower expectation below overrides
    // it to forbid only an open of "x", the first expansion component.
    context.AllowNativeOpen();
    EXPECT_CALL(context, OpenNativeAt(_, testing::StrEq("x"), _)).Times(0);
    auto rejected = under.Value().Resolve("l", follow);
    ASSERT_FALSE(rejected.HasValue());
    EXPECT_EQ(E2BIG, rejected.Error().code);
    EXPECT_THAT(rejected.Error().message, testing::HasSubstr("Symlink expansion exceeds resolver component budget"));
    testing::Mock::VerifyAndClearExpectations(&context);
}

// A self-link whose target is "s" followed by 2000 "/." components (4001
// bytes, well under the default 4096-byte linkTargetBytes/targetBytes and
// the 4097-byte read buffer) must be rejected by the pending-component-count
// cap after exactly 1 readlink, not by looping until the 64-frame ELOOP
// ceiling.
TEST_F(PathAliasTest, PendingCapRejectsLargeSelfLinkExpansionBeforeFrameCeiling)
{
    const std::string base = context.GetTempdirPath();
    std::string target = "s";
    for (int i = 0; i < 2000; ++i)
        target += "/.";
    ASSERT_EQ(4001u, target.size());
    ASSERT_EQ(0, ::symlink(target.c_str(), (base + "/s").c_str()));
    auto opened = SelectAcceptedPath(context, base, CrossMountPathPolicy(), ResolverLimits{}); // production defaults
    ASSERT_TRUE(opened.HasValue());
    auto follow = CrossMountPathPolicy(true);
    EXPECT_CALL(context, ReadLinkDescriptor(_, _, _)).Times(1);
    auto rejected = opened.Value().Resolve("s", follow);
    ASSERT_FALSE(rejected.HasValue());
    EXPECT_EQ(E2BIG, rejected.Error().code);
    EXPECT_THAT(rejected.Error().message, testing::HasSubstr("Symlink expansion exceeds resolver component budget"));
    testing::Mock::VerifyAndClearExpectations(&context);
}

// The logical lookup bound (bound = targetBytes). Each Resolve/Apply of
// link "l" -> "." grows the logical lookup by 2 bytes ("/l") even though
// the physical directory never changes (ToString() stays `base`); the
// bound fires on the logical LookupName(), not the physical ToString().
TEST_F(PathAliasTest, LookupBoundRejectsBeyondTargetBytesWithoutChangingPath)
{
    const std::string base = context.GetTempdirPath();
    ASSERT_EQ(0, ::symlink(".", (base + "/l").c_str()));
    ResolverLimits limits = AmpleLimits();
    limits.shared.targetBytes = base.size() + 10; // literal bound B = base.size() + 10
    auto opened = SelectAcceptedPath(context, base, CrossMountPathPolicy(), limits);
    ASSERT_TRUE(opened.HasValue());
    Path path = std::move(opened).Value();
    auto follow = CrossMountPathPolicy(true);
    // k-th Resolve/Apply succeeds while base.size() + 2k <= B (= base.size() + 10); k = 1..5.
    for (int k = 1; k <= 5; ++k)
    {
        SCOPED_TRACE(k);
        auto step = path.Resolve("l", follow);
        ASSERT_TRUE(step.HasValue()) << step.Error().message;
        ASSERT_TRUE(step.Value().Is<Path::Step>());
        auto applied = path.Apply(std::move(As<Path::Step>(step.Value())));
        ASSERT_TRUE(applied.HasValue()) << applied.Error().message;
    }
    EXPECT_EQ(base.size() + 10, PathTestAccess::LookupName(path).size());
    const auto lookupBeforeFailure = PathTestAccess::LookupName(path);
    EXPECT_CALL(context, OpenNativeAt(_, _, _)).Times(0);
    auto rejected = path.Resolve("l", follow);
    ASSERT_FALSE(rejected.HasValue());
    EXPECT_EQ(ENAMETOOLONG, rejected.Error().code);
    EXPECT_THAT(rejected.Error().message, testing::HasSubstr("Logical lookup exceeds target byte limit"));
    EXPECT_EQ(base, PathTestAccess::ToString(path));
    EXPECT_EQ(lookupBeforeFailure, PathTestAccess::LookupName(path));
    testing::Mock::VerifyAndClearExpectations(&context);
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
    EXPECT_EQ(base, PathTestAccess::ToString(path));
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
    EXPECT_EQ(Type::RegularFile, accepted.Value().Metadata().FileType());
    ResolverLimits shortLimits = exactLimits;
    shortLimits.linkTargetBytes = name.size() - 1;
    auto shortRoot = SelectAcceptedPath(context, base, policy, shortLimits);
    ASSERT_TRUE(shortRoot.HasValue());
    const auto originalName = PathTestAccess::LookupName(shortRoot.Value());
    auto rejected = shortRoot.Value().Resolve("target-link", policy);
    ASSERT_FALSE(rejected.HasValue());
    EXPECT_EQ(E2BIG, rejected.Error().code);
    EXPECT_EQ(originalName, PathTestAccess::LookupName(shortRoot.Value()));
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

// Exercises Path outcome dispatch and ownership through the owning
// Resolve/Apply result.
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
        ASSERT_TRUE(moved.Is<Path>());
        Path extracted = As<Path>(std::move(moved));
        retained.reset(new Path(std::move(extracted)));
        EXPECT_EQ(1u, retained->Size());
    }
    ASSERT_NE(nullptr, retained);
    EXPECT_GT(CountOpenDescriptors(), before);
    EXPECT_EQ("/", retained->Root().Metadata().LookupName());
    retained.reset();
    EXPECT_EQ(before, CountOpenDescriptors());
}

TEST_F(PathAliasTest, PathOutcomeAlternativeReplacementAndSelfMoveRetainExactPins)
{
    using Outcome = Variant<Path, Path::RejectionReason>;
    const auto before = CountOpenDescriptors();
    {
        // Path moves transfer ownership of the shared payload, so
        // `opened.Value()` itself is moved-from the instant it is wrapped
        // below; only the owning Variant (not a lingering Path snapshot)
        // determines pin lifetime.
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
        // The replaced Path's snapshot is released at the move, once no
        // variant still holds it -- not retained until a later destructor.
        EXPECT_EQ(before, CountOpenDescriptors());
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
        // third's own Variant was already moved-from, so marker was the
        // sole remaining owner; the snapshot is released here, not retained.
        EXPECT_EQ(before, CountOpenDescriptors());
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
    // Path moves transfer ownership of the shared payload; `path` is
    // moved-from and diagnoses, it does not keep the source valid.
    EXPECT_THROW((void)PathTestAccess::ToString(path), std::logic_error);
    auto cap = moved.Resolve("passwd", CrossMountPathPolicy());
    ASSERT_FALSE(cap.HasValue());
    EXPECT_EQ(EMFILE, cap.Error().code);
    EXPECT_EQ(2u, moved.Size());
    EXPECT_EQ("/etc", PathTestAccess::ToString(moved));
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
    EXPECT_EQ(original.st_ino, pinned.Value().Metadata().Stat().st_ino);
    EXPECT_EQ(root + "/a/file", pinned.Value().Target().Metadata().EffectiveName());
    auto undo = path.Apply(std::move(back.Value()));
    ASSERT_TRUE(undo.HasValue()) << undo.Error().message;
    auto fresh = SelectStep(path, "absolute", follow);
    ASSERT_TRUE(fresh.HasValue()) << fresh.Error().message;
    EXPECT_EQ(replacement.st_ino, fresh.Value().Metadata().Stat().st_ino);
    EXPECT_EQ(root + "/b/file", fresh.Value().Target().Metadata().EffectiveName());
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
    EXPECT_EQ(expected.st_ino, pinned.Value().Metadata().Stat().st_ino);
    EXPECT_EQ(root + "/a/file", pinned.Value().Target().Metadata().EffectiveName());
    ASSERT_TRUE(path.Apply(std::move(leave.Value())).HasValue());
    auto fresh = SelectStep(path, "a", CrossMountPathPolicy());
    ASSERT_TRUE(fresh.HasValue());
    ASSERT_TRUE(path.Apply(std::move(fresh.Value())).HasValue());
    auto selected = SelectStep(path, "file", CrossMountPathPolicy());
    ASSERT_TRUE(selected.HasValue());
    EXPECT_EQ(substitute.st_ino, selected.Value().Metadata().Stat().st_ino);
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
    EXPECT_EQ(root, PathTestAccess::ToString(path));
    EXPECT_EQ(depth, path.Size());
    auto suffix = SelectStep(path, "link", CrossMountPathPolicy(true));
    ASSERT_TRUE(suffix.HasValue()) << suffix.Error().message;
    auto inverse = path.Apply(std::move(suffix.Value()));
    ASSERT_TRUE(inverse.HasValue()) << inverse.Error().message;
    EXPECT_EQ(depth + 2, path.Size());
    EXPECT_EQ(root + "/a/b", PathTestAccess::ToString(path));
    auto restored = path.Apply(std::move(inverse.Value()));
    ASSERT_TRUE(restored.HasValue()) << restored.Error().message;
    EXPECT_EQ(depth, path.Size());
    EXPECT_EQ(root, PathTestAccess::ToString(path));
}

TEST_F(PathAliasTest, IndependentPhysicalBranchesKeepTheirPinsAndRejectStaleSteps)
{
    const std::string root = context.GetTempdirPath() + "/branches";
    ASSERT_EQ(0, ::mkdir(root.c_str(), 0700));
    ASSERT_EQ(0, ::mkdir((root + "/first").c_str(), 0700));
    ASSERT_EQ(0, ::mkdir((root + "/second").c_str(), 0700));
    ASSERT_EQ(0, ::symlink("../second", (root + "/first/shortcut").c_str()));
    // Path moves transfer ownership of the shared payload, so two
    // independently navigable branches that both start at "first" need
    // two separate acquisitions, not a single acquisition forked by move.
    auto openedPath = SelectAcceptedPath(context, root, CrossMountPathPolicy(), AmpleLimits());
    ASSERT_TRUE(openedPath.HasValue());
    Path path = std::move(openedPath).Value();
    auto first = SelectStep(path, "first", CrossMountPathPolicy());
    ASSERT_TRUE(first.HasValue());
    auto rootInverse = path.Apply(std::move(first.Value()));
    ASSERT_TRUE(rootInverse.HasValue());
    Path::Component heldFirst = path.Leaf();

    auto openedBranch = SelectAcceptedPath(context, root, CrossMountPathPolicy(), AmpleLimits());
    ASSERT_TRUE(openedBranch.HasValue());
    Path branch = std::move(openedBranch).Value();
    auto firstForBranch = SelectStep(branch, "first", CrossMountPathPolicy());
    ASSERT_TRUE(firstForBranch.HasValue());
    auto branchRootInverse = branch.Apply(std::move(firstForBranch.Value()));
    ASSERT_TRUE(branchRootInverse.HasValue());
    auto branchStep = SelectStep(branch, "shortcut", CrossMountPathPolicy(true));
    ASSERT_TRUE(branchStep.HasValue()) << branchStep.Error().message;
    auto stale = SelectStep(branch, "shortcut", CrossMountPathPolicy(true));
    ASSERT_TRUE(stale.HasValue());
    EXPECT_CALL(context, OpenNativeAt(_, _, _)).Times(0);
    EXPECT_CALL(context, DuplicateDescriptor(_)).Times(0);
    auto undo = branch.Apply(std::move(branchStep.Value()));
    ASSERT_TRUE(undo.HasValue()) << undo.Error().message;
    EXPECT_EQ(root + "/second", PathTestAccess::ToString(branch));
    EXPECT_EQ(root + "/first", PathTestAccess::ToString(path));
    EXPECT_NE(heldFirst.Metadata().Stat().st_ino, branch.Leaf().Metadata().Stat().st_ino);
    ASSERT_EQ(0, ::rename((root + "/first").c_str(), (root + "/renamed").c_str()));
    EXPECT_EQ(root + "/first", heldFirst.Metadata().EffectiveName());
    EXPECT_TRUE(heldFirst.Stat().HasValue());
    EXPECT_EQ(root + "/first", PathTestAccess::ToString(path));
    auto oldBranch = branch.Apply(std::move(stale.Value()));
    ASSERT_FALSE(oldBranch.HasValue());
    EXPECT_EQ(ESTALE, oldBranch.Error().code);
    auto back = branch.Apply(std::move(undo.Value()));
    ASSERT_TRUE(back.HasValue()) << back.Error().message;
    EXPECT_EQ(root + "/first", PathTestAccess::ToString(branch));
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
    EXPECT_EQ(root + "/first", old.Metadata().EffectiveName());
    EXPECT_TRUE(old.Stat().HasValue());
    EXPECT_NE(old.Metadata().Stat().st_ino, path.Leaf().Metadata().Stat().st_ino);
    EXPECT_EQ(root + "/second", PathTestAccess::ToString(path));
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
    // Path moves transfer ownership of the shared payload: moving the Path
    // held by `selected.Value()` leaves that Path moved-from; its checked
    // accessors throw, while `moved` is usable.
    EXPECT_THROW((void)selected.Value().Root(), std::logic_error);
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
        EXPECT_EQ(processRoot.Metadata().Stat().st_ino, path.Root().Metadata().Stat().st_ino);
    }
    ASSERT_NE(nullptr, first);
    EXPECT_EQ(initialDepth + 72, path.Size());
    EXPECT_EQ(current, PathTestAccess::ToString(path));
    auto invalid = path.Resolve("../escape", CrossMountPathPolicy());
    ASSERT_FALSE(invalid.HasValue());
    EXPECT_EQ(EINVAL, invalid.Error().code);
    EXPECT_EQ(initialDepth + 72, path.Size());
    ASSERT_EQ(0, ::symlink("absent", (current + "/broken").c_str()));
    auto failedAlias = path.Resolve("broken", CrossMountPathPolicy(true));
    ASSERT_FALSE(failedAlias.HasValue());
    EXPECT_EQ(ENOENT, failedAlias.Error().code);
    EXPECT_EQ(current, PathTestAccess::ToString(path));
    EXPECT_TRUE(first->Stat().HasValue());
    for (int index = 71; index >= 0; --index)
    {
        auto restored = path.Apply(std::move(inverses[static_cast<std::size_t>(index)]));
        ASSERT_TRUE(restored.HasValue()) << index << ": " << restored.Error().message;
        EXPECT_TRUE(first->Stat().HasValue());
    }
    EXPECT_EQ(initialDepth, path.Size());
    EXPECT_EQ(base, PathTestAccess::ToString(path));
    EXPECT_TRUE(root.Stat().HasValue());
    EXPECT_TRUE(first->Stat().HasValue());
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
    EXPECT_EQ(real, PathTestAccess::ToString(As<Path>(acceptedDirectory.Value())));
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
    EXPECT_EQ(Type::Directory, followDirectory.Value().Metadata().FileType());
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
    EXPECT_EQ(expected.st_ino, alias.Value().Metadata().Stat().st_ino);
    auto inverse = path.Apply(std::move(alias.Value()));
    ASSERT_TRUE(inverse.HasValue()) << inverse.Error().message;
    EXPECT_EQ(root + "/a/other", PathTestAccess::ToString(path));
    auto restore = path.Apply(std::move(inverse.Value()));
    ASSERT_TRUE(restore.HasValue());
    EXPECT_EQ(root + "/a/b", PathTestAccess::ToString(path));
    EXPECT_TRUE(path.Apply(std::move(back.Value())).HasValue());
    EXPECT_EQ(root, PathTestAccess::ToString(path));
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
    EXPECT_EQ(expected.st_ino, jump.Value().Metadata().Stat().st_ino);
    EXPECT_NE(wrong.st_ino, jump.Value().Metadata().Stat().st_ino);
    EXPECT_EQ(root + "/a/victim", jump.Value().Target().Metadata().EffectiveName());
    EXPECT_EQ(root + "/a/b", PathTestAccess::ToString(path));
}

TEST_F(PathAliasTest, HeldFileMountFactsAreObservedAtAcquisitionOnly)
{
    const std::string file = context.MakeTempfile("held");
    const std::string name = file.substr(file.find_last_of("/") + 1);
    int records = 0;
    EXPECT_CALL(context, ReadNativeDescriptor(_, _, _)).WillRepeatedly([&](int fd, void* buffer, std::size_t count) {
        const ssize_t bytes = context.RealReadNativeDescriptor(fd, buffer, count);
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
    EXPECT_GT(path.Leaf().Metadata().TargetMount().Value(), 0u);
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
    const auto facts = opened.Value().Leaf().Metadata();
    EXPECT_EQ(sourceId.Value(), facts.LookupMount().Value());
    EXPECT_EQ(targetId.Value(), facts.TargetMount().Value());
    EXPECT_EQ(Type::Directory, facts.FileType());
    EXPECT_EQ(alias, PathTestAccess::LookupName(opened.Value()));
    EXPECT_EQ("/proc", PathTestAccess::ToString(opened.Value()));
    EXPECT_EQ("/proc", opened.Value().Leaf().Metadata().EffectiveName());
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
    const auto originalInode = initial.Value().Metadata().Stat().st_ino;
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
    EXPECT_EQ(originalInode, pinned.Value().Metadata().Stat().st_ino);
    EXPECT_EQ(root + "/inside", pinned.Value().Target().Metadata().EffectiveName());
    EXPECT_EQ(root, PathTestAccess::ToString(path));
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
    EXPECT_EQ(Type::RegularFile, As<Path>(opened.Value()).Leaf().Metadata().FileType());
    EXPECT_EQ(file, PathTestAccess::ToString(As<Path>(opened.Value())));
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
    EXPECT_EQ(base + "/target/final", PathTestAccess::ToString(As<Path>(accepted.Value())));
    EXPECT_EQ(Type::Directory, As<Path>(accepted.Value()).Leaf().Metadata().FileType());
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
    EXPECT_EQ(root + "/self", PathTestAccess::LookupName(path));
    EXPECT_EQ(root, PathTestAccess::ToString(path));
    ASSERT_EQ(0, ::unlink((root + "/self").c_str()));
    ASSERT_EQ(0, ::symlink("other", (root + "/self").c_str()));
    auto conflict = path.Resolve("ambiguous", CrossMountPathPolicy(true));
    ASSERT_FALSE(conflict.HasValue());
    EXPECT_EQ(EXDEV, conflict.Error().code);
    EXPECT_EQ(root, PathTestAccess::ToString(path));
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
    EXPECT_EQ(root + "/entry", PathTestAccess::LookupName(path));
    EXPECT_EQ(root + "/data", PathTestAccess::ToString(path));
    struct stat expected = {};
    ASSERT_EQ(0, ::stat((root + "/data/file").c_str(), &expected));
    for (const char* name : {"logical", "effective"})
    {
        auto step = SelectStep(path, name, CrossMountPathPolicy(true));
        ASSERT_TRUE(step.HasValue()) << name << ": " << step.Error().message;
        EXPECT_EQ(expected.st_ino, step.Value().Metadata().Stat().st_ino);
        EXPECT_EQ(root + "/data/file", step.Value().Target().Metadata().EffectiveName());
        EXPECT_EQ(root + "/data", PathTestAccess::ToString(path));
    }
    auto conflict = path.Resolve("collision", CrossMountPathPolicy(true));
    ASSERT_FALSE(conflict.HasValue());
    EXPECT_EQ(EXDEV, conflict.Error().code);
    EXPECT_EQ(root + "/data", PathTestAccess::ToString(path));
}

TEST_F(PathAliasTest, CopiedLeafOutlivesPathMoveAndFailedFinalCloseIsNotRetried)
{
    const auto source = context.MakeTempfile("contents");
    const auto before = CountOpenDescriptors();
    std::unique_ptr<Path::Component> surviving;
    {
        ResolverLimits originalLimits = AmpleLimits();
        auto opened = SelectAcceptedPath(context, source, CrossMountPathPolicy(), originalLimits);
        ASSERT_TRUE(opened.HasValue()) << opened.Error().message;
        Path path = std::move(opened).Value();
        Path moved(std::move(path));
        // Path moves transfer ownership of the shared payload; `path` is
        // moved-from and diagnoses, `moved` keeps the exact snapshot.
        EXPECT_THROW((void)PathTestAccess::ToString(path), std::logic_error);
        EXPECT_EQ(source, PathTestAccess::ToString(moved));
        surviving.reset(new Path::Component(moved.Leaf()));
        Path::Component copied(std::move(*surviving));
        EXPECT_EQ(Type::RegularFile, copied.Metadata().FileType());
        EXPECT_TRUE(surviving->Stat().HasValue());
        originalLimits.shared.fdinfoBytes = 0;
    }
    EXPECT_EQ(before + 1, CountOpenDescriptors());
    // Original Path and its caller-owned limits have both been destroyed.
    auto activated = surviving->OpenReadOnly();
    ASSERT_TRUE(activated.HasValue()) << activated.Error().message;
    activated.Value().Close();
    EXPECT_CALL(context, CloseNativeDescriptor(_)).Times(1).WillOnce([](int fd) {
        const int status = ::close(fd);
        EXPECT_EQ(0, status);
        errno = EIO;
        return ComplianceEngine::Error(errno ? errno : EIO);
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
    // Path moves transfer ownership of the shared payload: `original` is
    // moved-from; its checked accessors throw, while `moved` keeps the
    // exact snapshot, including the frozen barrier.
    EXPECT_THROW((void)PathTestAccess::LookupName(original), std::logic_error);
    EXPECT_THROW((void)PathTestAccess::ToString(original), std::logic_error);
    EXPECT_EQ(root, PathTestAccess::ToString(moved));
    const auto child = context.MakeTempfile("contents");
    ASSERT_EQ(0, ::rename(child.c_str(), (root + "/file").c_str()));
    auto selected = SelectStep(moved, "file", CrossMountPathPolicy());
    ASSERT_TRUE(selected.HasValue()) << selected.Error().message;
    auto back = moved.Apply(std::move(selected.Value()));
    ASSERT_TRUE(back.HasValue()) << back.Error().message;
    EXPECT_EQ(Type::RegularFile, moved.Leaf().Metadata().FileType());
    EXPECT_THROW((void)PathTestAccess::ToString(original), std::logic_error);
    ASSERT_TRUE(moved.Apply(std::move(back.Value())).HasValue());
    ASSERT_EQ(0, ::symlink("../", (root + "/parent").c_str()));
    auto escape = moved.Resolve("parent", CrossMountPathPolicy(true));
    ASSERT_FALSE(escape.HasValue());
    EXPECT_EQ(EXDEV, escape.Error().code);
    EXPECT_EQ(root, PathTestAccess::ToString(moved));
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
    const auto inode = detached.Metadata().Stat().st_ino;
    auto oneInverse = path.Apply(std::move(two.Value()));
    ASSERT_TRUE(oneInverse.HasValue());
    EXPECT_EQ(depth + 2, path.Size());
    ASSERT_TRUE(path.Apply(std::move(oneInverse.Value())).HasValue());
    EXPECT_EQ(depth + 1, path.Size());
    EXPECT_EQ(heldOne.Metadata().Stat().st_ino, path.Leaf().Metadata().Stat().st_ino);
    const auto afterInverse = CountOpenDescriptors();
    auto again = SelectStep(path, "two", CrossMountPathPolicy());
    ASSERT_TRUE(again.HasValue()) << again.Error().message;
    EXPECT_EQ(inode, again.Value().Metadata().Stat().st_ino);
    EXPECT_GT(CountOpenDescriptors(), afterInverse); // distinct new pin, old detached pin still valid
    EXPECT_TRUE(detached.Stat().HasValue());
    ASSERT_TRUE(path.Apply(std::move(rootInverse.Value())).HasValue());
    EXPECT_EQ(root, PathTestAccess::ToString(path));
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
    EXPECT_EQ(root + "/a", PathTestAccess::ToString(path));
    auto child = SelectStep(path, "child", CrossMountPathPolicy());
    ASSERT_TRUE(child.HasValue()) << child.Error().message;
    EXPECT_EQ(expected.st_ino, child.Value().Metadata().Stat().st_ino);
    ASSERT_TRUE(path.Apply(std::move(backUp.Value())).HasValue());
    ASSERT_TRUE(path.Apply(std::move(backSub.Value())).HasValue());
    ASSERT_TRUE(path.Apply(std::move(backA.Value())).HasValue());
    EXPECT_EQ(depth, path.Size());
    auto self = SelectStep(path, "self", CrossMountPathPolicy(true));
    ASSERT_TRUE(self.HasValue());
    EXPECT_EQ(path.Leaf().Metadata().Stat().st_ino, self.Value().Metadata().Stat().st_ino);
    auto escape = path.Resolve("escape", CrossMountPathPolicy(true));
    ASSERT_FALSE(escape.HasValue());
    EXPECT_EQ(EXDEV, escape.Error().code);
    EXPECT_EQ(root, PathTestAccess::ToString(path));
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
    const auto original = path.Leaf().Metadata().Stat().st_ino;
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
    EXPECT_CALL(context, CloseNativeDescriptor(_)).WillRepeatedly([&](int fd) -> ComplianceEngine::Result<void> {
        auto status = context.RealCloseNativeDescriptor(fd);
        if (fd == specialPin && !failed)
        {
            failed = true;
            errno = EIO;
            return ComplianceEngine::Error(errno ? errno : EIO);
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
    EXPECT_EQ(root, PathTestAccess::ToString(path));
    EXPECT_EQ(original, path.Leaf().Metadata().Stat().st_ino);
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
        EXPECT_EQ(expected.st_ino, relative.Value().Metadata().Stat().st_ino);
        auto absolute = SelectStep(path, "absolute", CrossMountPathPolicy(true));
        ASSERT_TRUE(absolute.HasValue()) << absolute.Error().message;
        EXPECT_EQ(expected.st_ino, absolute.Value().Metadata().Stat().st_ino);
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
        EXPECT_EQ(root, PathTestAccess::ToString(path));
        EXPECT_EQ(expected.st_ino, relative.Value().Metadata().Stat().st_ino);
        EXPECT_EQ(expected.st_ino, absolute.Value().Metadata().Stat().st_ino);
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
    EXPECT_EQ(expected.st_ino, exact.Value().Metadata().Stat().st_ino);
    EXPECT_EQ(root, PathTestAccess::ToString(two.Value()));
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
    const auto inode = path.Leaf().Metadata().Stat().st_ino;
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
        EXPECT_EQ(inode, path.Leaf().Metadata().Stat().st_ino);
    }
    auto missing = path.Resolve("special.broken", CrossMountPathPolicy(true));
    ASSERT_FALSE(missing.HasValue());
    EXPECT_EQ(ENOENT, missing.Error().code);
    EXPECT_EQ(depth, path.Size());
    EXPECT_EQ(inode, path.Leaf().Metadata().Stat().st_ino);
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
    EXPECT_EQ(held.Metadata().Stat().st_ino, path.Leaf().Metadata().Stat().st_ino);
    auto strict = CrossMountPathPolicy();
    strict.mounts = MountPolicy::StayOnRootMount;
    auto denied = path.Resolve("allowed", strict);
    ASSERT_FALSE(denied.HasValue());
    EXPECT_EQ(ELOOP, denied.Error().code);
    auto accepted = SelectStep(path, "allowed", follow);
    ASSERT_TRUE(accepted.HasValue()) << accepted.Error().message;
    auto inverse = path.Apply(std::move(accepted.Value()));
    ASSERT_TRUE(inverse.HasValue()) << inverse.Error().message;
    EXPECT_EQ(Type::RegularFile, path.Leaf().Metadata().FileType());
    EXPECT_TRUE(held.Stat().HasValue());
    auto notDirectory = path.Resolve("inside", strict);
    ASSERT_FALSE(notDirectory.HasValue());
    EXPECT_EQ(ENOTDIR, notDirectory.Error().code);
    ASSERT_TRUE(path.Apply(std::move(inverse.Value())).HasValue());
    EXPECT_EQ(root, PathTestAccess::ToString(path));
    EXPECT_EQ(held.Metadata().Stat().st_ino, path.Leaf().Metadata().Stat().st_ino);
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
        EXPECT_EQ(root, PathTestAccess::ToString(path));
        auto longStep = SelectStep(path, "long", CrossMountPathPolicy(true));
        ASSERT_TRUE(longStep.HasValue()) << longStep.Error().message;
        EXPECT_EQ(actual, longStep.Value().Target().Metadata().EffectiveName());
        leaf.reset(new Path::Component(longStep.Value().Target()));
        copy.reset(new Path::Component(*leaf));
        const auto pinned = CountOpenDescriptors();
        EXPECT_TRUE(copy->Stat().HasValue());
        EXPECT_EQ(pinned, CountOpenDescriptors());
    }
    EXPECT_EQ(before + 1, CountOpenDescriptors());
    EXPECT_EQ(actual, copy->Metadata().EffectiveName());
    EXPECT_EQ(leaf->Metadata().Stat().st_ino, copy->Metadata().Stat().st_ino);
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
    struct stat expected = {}, sibling = {}, accepted = {};
    ASSERT_EQ(0, ::stat((root + "/second/child").c_str(), &expected));
    ASSERT_EQ(0, ::stat((root + "/second").c_str(), &sibling));
    ASSERT_EQ(0, ::stat(root.c_str(), &accepted));
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
    EXPECT_EQ(sibling.st_ino, path.Leaf().Metadata().Stat().st_ino);
    EXPECT_EQ(root + "/second", PathTestAccess::ToString(path));
    auto child = SelectStep(path, "child", CrossMountPathPolicy());
    ASSERT_TRUE(child.HasValue()) << child.Error().message;
    EXPECT_EQ(expected.st_ino, child.Value().Metadata().Stat().st_ino);
    EXPECT_EQ(root + "/second/child", child.Value().Target().Metadata().EffectiveName());
    auto up = SelectStep(path, "up", CrossMountPathPolicy(true));
    ASSERT_TRUE(up.HasValue()) << up.Error().message;
    EXPECT_EQ(root, up.Value().Target().Metadata().EffectiveName());
    // `path` was move-constructed from `opened.Value()`
    // (`Path path = std::move(opened).Value();` above), so `opened` itself
    // keeps its "Value" tag (the Result wrapper has its own moved-from
    // notion, separate from Path's checked RequireLive(), and extracting a
    // payload out of it doesn't consume the wrapper) but the Path object it
    // still holds is moved-from; the acquired root's identity is read from
    // a fresh `::stat` on the fixture path instead (`accepted`, captured
    // above), not a moved-from Path and not `path.Root()` (always "/", not
    // this acquisition's root).
    EXPECT_EQ(accepted.st_ino, up.Value().Metadata().Stat().st_ino);
    auto inverse = path.Apply(std::move(up.Value()));
    ASSERT_TRUE(inverse.HasValue()) << inverse.Error().message;
    EXPECT_EQ(depth, path.Size());
    EXPECT_EQ(root, PathTestAccess::ToString(path));
    ASSERT_TRUE(path.Apply(std::move(inverse.Value())).HasValue());
    EXPECT_EQ(root + "/second", PathTestAccess::ToString(path));
    EXPECT_EQ(ESTALE, path.Apply(std::move(undoFirst.Value())).Error().code);
    EXPECT_TRUE(path.Apply(std::move(undoShortcut.Value())).HasValue());
    EXPECT_EQ(root + "/first", PathTestAccess::ToString(path));
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
    EXPECT_EQ(expected.st_ino, inside.Value().Metadata().Stat().st_ino);
    EXPECT_EQ(root + "/inside", inside.Value().Target().Metadata().EffectiveName());
    ASSERT_TRUE(path.Apply(std::move(inverse.Value())).HasValue());
    auto escape = path.Resolve("escape", CrossMountPathPolicy(true));
    ASSERT_FALSE(escape.HasValue());
    EXPECT_EQ(EXDEV, escape.Error().code);
    EXPECT_EQ(root, PathTestAccess::ToString(path));
}

} // namespace
