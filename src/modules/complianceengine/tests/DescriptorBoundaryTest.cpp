// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <MockContext.h>
#include <atomic>
#include <cerrno>
#include <fcntl.h>
#include <filesystem/Descriptor.hpp>
#include <filesystem/Handle.hpp>
#include <filesystem/ProcfsDescriptorAccess.hpp>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <map>
#include <stdexcept>
#include <string>
#include <thread>
#include <type_traits>
#include <unistd.h>
#include <utility>
#include <vector>

namespace
{
using ComplianceEngine::ContextInterface;
using ComplianceEngine::Filesystem::Detail::Descriptor;
using ComplianceEngine::Filesystem::Detail::ProcfsDescriptorAccess;
using Profile = ContextInterface::OpenProfile;
using testing::_;
using testing::NiceMock;

template <typename...>
struct Void
{
    using type = void;
};

// These expressions are compiled as part of the ordinary test build. Each
// owner-returning surface must accept both kinds of lvalue and neither kind
// of concrete temporary, including a const temporary.
#define OWNER_FACTORY_CONTRACT(name, expression)                                                                                                       \
    template <typename T, typename = void>                                                                                                             \
    struct Can##name : std::false_type                                                                                                                 \
    {                                                                                                                                                  \
    };                                                                                                                                                 \
    template <typename T>                                                                                                                              \
    struct Can##name<T, typename Void<decltype(std::declval<T>() expression)>::type> : std::true_type                                                  \
    {                                                                                                                                                  \
    };                                                                                                                                                 \
    static_assert(Can##name<MockContext&>::value && Can##name<const MockContext&>::value, #name " supports context lvalues");                          \
    static_assert(!Can##name<MockContext&&>::value && !Can##name<const MockContext&&>::value, #name " rejects context temporaries")

OWNER_FACTORY_CONTRACT(Empty, .EmptyDescriptor());
OWNER_FACTORY_CONTRACT(Absolute, .OpenAbsolutePin("/"));
OWNER_FACTORY_CONTRACT(At, .OpenAt(std::declval<const Descriptor&>(), "child", Profile::PinChild));
OWNER_FACTORY_CONTRACT(Fdinfo, .OpenFdinfo(std::declval<const ProcfsDescriptorAccess&>(), std::declval<const Descriptor&>()));
OWNER_FACTORY_CONTRACT(Alias, .OpenAlias(std::declval<const ProcfsDescriptorAccess&>(), std::declval<const Descriptor&>(), false));
OWNER_FACTORY_CONTRACT(PinAlias, .OpenPinAlias(std::declval<const ProcfsDescriptorAccess&>(), std::declval<const Descriptor&>(), false));
OWNER_FACTORY_CONTRACT(Duplicate, .Duplicate(std::declval<const Descriptor&>()));
OWNER_FACTORY_CONTRACT(Cursor, .OpenDirectoryCursor(std::declval<Descriptor&&>()));
#undef OWNER_FACTORY_CONTRACT

#define REJECT_EPHEMERAL_DIAGNOSTIC(name, expression)                                                                                                  \
    template <typename T, typename = void>                                                                                                             \
    struct CanPass##name : std::false_type                                                                                                             \
    {                                                                                                                                                  \
    };                                                                                                                                                 \
    template <typename T>                                                                                                                              \
    struct CanPass##name<T, typename Void<decltype(std::declval<T>() expression)>::type> : std::true_type                                              \
    {                                                                                                                                                  \
    };                                                                                                                                                 \
    static_assert(!CanPass##name<MockContext&>::value, #name " rejects ephemeral diagnostic pointers")

REJECT_EPHEMERAL_DIAGNOSTIC(EmptyDiagnostic, .EmptyDescriptor(std::declval<std::string>().c_str()));
REJECT_EPHEMERAL_DIAGNOSTIC(AtDiagnostic, .OpenAt(std::declval<const Descriptor&>(), "child", Profile::PinChild, std::declval<std::string>().c_str()));
REJECT_EPHEMERAL_DIAGNOSTIC(AliasDiagnostic,
    .OpenAlias(std::declval<const ProcfsDescriptorAccess&>(), std::declval<const Descriptor&>(), false, std::declval<std::string>().c_str()));
#undef REJECT_EPHEMERAL_DIAGNOSTIC
static_assert(!std::is_constructible<Descriptor, const ContextInterface&, int, const char*>::value, "Native adoption cannot retain a caller pointer");
static_assert(!std::is_constructible<ProcfsDescriptorAccess, const ContextInterface&, Descriptor&&, Descriptor&&>::value,
    "Generic directory owners cannot mint a verified procfs role");
static_assert(!std::is_constructible<ProcfsDescriptorAccess, MockContext&&>::value && !std::is_constructible<ProcfsDescriptorAccess, const MockContext&&>::value,
    "The verified helper cannot borrow a temporary concrete context");
static_assert(std::is_same<decltype(std::declval<ProcfsDescriptorAccess&>().FdDirectory()), const Descriptor&>::value &&
                  std::is_same<decltype(std::declval<ProcfsDescriptorAccess&>().FdinfoDirectory()), const Descriptor&>::value,
    "Verified directory roles have no mutable owner accessor");
template <typename T, typename = void>
struct CanReplaceVerifiedFd : std::false_type
{
};
template <typename T>
struct CanReplaceVerifiedFd<T, typename Void<decltype(std::declval<T&>().fd = std::declval<Descriptor&&>())>::type> : std::true_type
{
};
static_assert(!CanReplaceVerifiedFd<ProcfsDescriptorAccess>::value, "Verified role owners cannot be swapped by ordinary callers");

#define REJECT_GENERIC_ROLE(name, expression)                                                                                                          \
    template <typename T, typename = void>                                                                                                             \
    struct CanPassGeneric##name : std::false_type                                                                                                      \
    {                                                                                                                                                  \
    };                                                                                                                                                 \
    template <typename T>                                                                                                                              \
    struct CanPassGeneric##name<T, typename Void<decltype(std::declval<T&>() expression)>::type> : std::true_type                                      \
    {                                                                                                                                                  \
    };                                                                                                                                                 \
    static_assert(!CanPassGeneric##name<MockContext>::value, #name " rejects generic directory owners")
REJECT_GENERIC_ROLE(Fdinfo, .OpenFdinfo(std::declval<const Descriptor&>(), std::declval<const Descriptor&>()));
REJECT_GENERIC_ROLE(Alias, .OpenAlias(std::declval<const Descriptor&>(), std::declval<const Descriptor&>(), true));
REJECT_GENERIC_ROLE(PinAlias, .OpenPinAlias(std::declval<const Descriptor&>(), std::declval<const Descriptor&>(), true));
REJECT_GENERIC_ROLE(ChmodAlias, .ChmodAlias(std::declval<const Descriptor&>(), std::declval<const Descriptor&>(), mode_t{}));
#undef REJECT_GENERIC_ROLE

TEST(DescriptorBoundaryTest, ChildPinsRejectTraversalBeforeNativeDispatch)
{
    NiceMock<MockContext> context;
    auto opened = context.OpenAbsolutePin(context.GetTempdirPath().c_str());
    ASSERT_TRUE(opened.HasValue());
    Descriptor directory = std::move(opened).Value();
    EXPECT_CALL(context, OpenNativeAt(_, _, _)).Times(0);
    const char* invalidNames[] = {nullptr, "", "/", "/absolute", ".", "..", "../outside", "link/child", "a/", "a//b"};
    for (Profile profile : {Profile::PinChild, Profile::PinChildDirectory})
    {
        for (const char* name : invalidNames)
        {
            const auto rejected = context.OpenAt(directory, name, profile);
            ASSERT_FALSE(rejected.HasValue());
            EXPECT_EQ(EINVAL, rejected.Error().code);
        }
    }
    testing::Mock::VerifyAndClearExpectations(&context);

    // O_PATH|O_NOFOLLOW pins the final link itself; it must not follow it.
    const std::string link = context.GetTempdirPath() + "/child-link";
    ASSERT_EQ(0, ::symlink("missing-target", link.c_str()));
    EXPECT_CALL(context, OpenNativeAt(_, testing::StrEq("child-link"), _)).WillOnce([&](int fd, const char* name, int flags) {
        EXPECT_NE(0, flags & O_NOFOLLOW);
        return context.RealOpenNativeAt(fd, name, flags);
    });
    auto pinned = context.OpenAt(directory, "child-link", Profile::PinChild);
    ASSERT_TRUE(pinned.HasValue());
    struct stat identity = {};
    ASSERT_EQ(0, context.StatFile(pinned.Value(), &identity));
    EXPECT_TRUE(S_ISLNK(identity.st_mode));
    EXPECT_TRUE(pinned.Value().Close().HasValue());
    EXPECT_TRUE(directory.Close().HasValue());
    ASSERT_EQ(0, ::unlink(link.c_str()));
}

TEST(DescriptorBoundaryTest, AliasProfilesRequireVerifiedRoles)
{
    NiceMock<MockContext> context;
    ProcfsDescriptorAccess procfs(context);
    auto pinResult = context.OpenAbsolutePin(context.GetTempdirPath().c_str());
    ASSERT_TRUE(pinResult.HasValue());
    Descriptor pin = std::move(pinResult).Value();
    EXPECT_CALL(context, OpenNativeAt(_, _, _)).Times(0);
    EXPECT_CALL(context, ChmodPinnedAlias(_, _, _)).Times(0);
    EXPECT_EQ(EINVAL, context.OpenAlias(procfs, pin, true).Error().code);
    EXPECT_EQ(EINVAL, context.OpenPinAlias(procfs, pin, true).Error().code);
    EXPECT_EQ(EINVAL, context.OpenFdinfo(procfs, pin).Error().code);
    errno = 0;
    EXPECT_EQ(-1, context.ChmodAlias(procfs, pin, 0700));
    EXPECT_EQ(EINVAL, errno);
    testing::Mock::VerifyAndClearExpectations(&context);

    ASSERT_TRUE(procfs.Open().HasValue());

    auto validInfo = context.OpenFdinfo(procfs, pin);
    ASSERT_TRUE(validInfo.HasValue());
    EXPECT_TRUE(validInfo.Value().Close().HasValue());
    auto validPin = context.OpenPinAlias(procfs, pin, true);
    ASSERT_TRUE(validPin.HasValue());
    EXPECT_TRUE(validPin.Value().Close().HasValue());
    auto validAlias = context.OpenAlias(procfs, pin, true);
    ASSERT_TRUE(validAlias.HasValue());
    EXPECT_TRUE(validAlias.Value().Close().HasValue());

    // The fd/fdinfo arguments cannot be swapped into typed alias methods:
    // only this verified helper supplies them. The generic OpenAt escape is
    // closed even when given a real but wrong procfs directory owner.
    const std::string alias = std::to_string(::getpid());
    auto rejectDirectory = [&](const Descriptor& directory) {
        EXPECT_CALL(context, OpenNativeAt(_, _, _)).Times(0);
        EXPECT_CALL(context, ChmodPinnedAlias(_, _, _)).Times(0);
        EXPECT_CALL(context, ReadFileDescriptor(_, _, _)).Times(0);
        for (Profile profile : {Profile::PinSelfDirectory, Profile::ReadFdinfo, Profile::FollowAliasFile, Profile::FollowAliasDirectory,
                 Profile::FollowAliasPin, Profile::FollowAliasPinDirectory})
        {
            auto denied = context.OpenAt(directory, alias.c_str(), profile);
            ASSERT_FALSE(denied.HasValue());
            EXPECT_EQ(EINVAL, denied.Error().code);
        }

        testing::Mock::VerifyAndClearExpectations(&context);
    };

    rejectDirectory(procfs.FdinfoDirectory()); // fdinfo wrongly used as fd
    rejectDirectory(procfs.FdDirectory());     // fd wrongly used as fdinfo
    rejectDirectory(pin);                      // ordinary, same-context directory

    // A different PID's real procfs fd/fdinfo owners still cannot select
    // native alias operations through the public generic directory API.
    const std::string parent = std::to_string(::getppid());
    auto process = context.OpenAt(procfs.ProcDirectory(), parent.c_str(), Profile::PinDirectory);
    ASSERT_TRUE(process.HasValue());
    auto otherFd = context.OpenAt(process.Value(), "fd", Profile::PinDirectory);
    auto otherFdinfo = context.OpenAt(process.Value(), "fdinfo", Profile::PinDirectory);
    ASSERT_TRUE(otherFd.HasValue());
    ASSERT_TRUE(otherFdinfo.HasValue());
    rejectDirectory(otherFd.Value());
    rejectDirectory(otherFdinfo.Value());

    EXPECT_TRUE(procfs.Close().HasValue());
    EXPECT_CALL(context, OpenNativeAt(_, _, _)).Times(0);
    EXPECT_CALL(context, ChmodPinnedAlias(_, _, _)).Times(0);
    EXPECT_EQ(EINVAL, context.OpenAlias(procfs, pin, true).Error().code);
    EXPECT_EQ(EINVAL, context.OpenFdinfo(procfs, pin).Error().code);
    errno = 0;
    EXPECT_EQ(-1, context.ChmodAlias(procfs, pin, 0700));
    EXPECT_EQ(EINVAL, errno);
}

TEST(DescriptorBoundaryTest, RelativeAndVerifiedAliasOpensAtomicallySetCloexec)
{
    NiceMock<MockContext> context;
    auto root = context.OpenAbsolutePin("/proc");
    ASSERT_TRUE(root.HasValue());
    int relativeOpens = 0, aliasOpens = 0;
    EXPECT_CALL(context, OpenNativeAt(_, _, _)).WillRepeatedly([&](int directory, const char* name, int flags) {
        const int opened = context.RealOpenNativeAt(directory, name, flags);
        if (std::string(name) == "self" || std::string(name) == "fdinfo")
        {
            EXPECT_NE(0, flags & O_CLOEXEC);
            if (opened >= 0)
                EXPECT_NE(0, ::fcntl(opened, F_GETFD) & FD_CLOEXEC);
            ++relativeOpens;
        }
        return opened;
    });
    auto relative = context.OpenAt(root.Value(), "self", Profile::PinChild);
    ASSERT_TRUE(relative.HasValue());
    struct stat identity = {};
    ASSERT_EQ(0, context.StatFile(relative.Value(), &identity));
    EXPECT_TRUE(S_ISLNK(identity.st_mode)); // generic child pins do not follow
    ProcfsDescriptorAccess procfs(context);
    ASSERT_TRUE(procfs.Open().HasValue());
    EXPECT_CALL(context, OpenNativeAt(_, _, _)).WillRepeatedly([&](int directory, const char* name, int flags) {
        const int opened = context.RealOpenNativeAt(directory, name, flags);
        if ((flags & O_NOFOLLOW) == 0 && std::string(name) != "self")
        {
            EXPECT_NE(0, flags & O_CLOEXEC);
            if (opened >= 0)
                EXPECT_NE(0, ::fcntl(opened, F_GETFD) & FD_CLOEXEC);
            ++aliasOpens;
        }
        return opened;
    });
    auto alias = context.OpenPinAlias(procfs, root.Value(), true);
    ASSERT_TRUE(alias.HasValue());
    EXPECT_EQ(3, relativeOpens); // child pin, self bootstrap and fdinfo role
    EXPECT_EQ(1, aliasOpens);
    EXPECT_TRUE(alias.Value().Close().HasValue());
    EXPECT_TRUE(relative.Value().Close().HasValue());
    EXPECT_TRUE(procfs.Close().HasValue());
    EXPECT_TRUE(root.Value().Close().HasValue());
}

TEST(DescriptorBoundaryTest, ProcfsCloseDetachesAllRolesBeforeThrowAndNeverRetriesReusedFd)
{
    NiceMock<MockContext> context;
    NiceMock<MockContext> foreign;
    ProcfsDescriptorAccess access(context);
    int procFd = -1, fdRole = -1, fdinfoRole = -1, reused = -1;
    ON_CALL(context, OpenNativePath(_, _)).WillByDefault([&](const char* path, int flags) {
        const int opened = context.RealOpenNativePath(path, flags);
        if (std::string(path) == "/proc")
            procFd = opened;
        return opened;
    });
    ON_CALL(context, OpenNativeAt(_, _, _)).WillByDefault([&](int directory, const char* name, int flags) {
        const int opened = context.RealOpenNativeAt(directory, name, flags);
        if (std::string(name) == "fd")
            fdRole = opened;
        if (std::string(name) == "fdinfo")
            fdinfoRole = opened;
        return opened;
    });
    ASSERT_TRUE(access.Open().HasValue());
    ASSERT_GE(procFd, 0);
    ASSERT_GE(fdRole, 0);
    ASSERT_GE(fdinfoRole, 0);
    std::map<int, int> closes;
    EXPECT_CALL(foreign, CloseFileDescriptor(_)).Times(0);
    EXPECT_CALL(context, CloseFileDescriptor(_)).WillRepeatedly([&](int descriptor) -> int {
        ++closes[descriptor];
        const int closed = context.RealCloseFileDescriptor(descriptor);
        if (descriptor == fdinfoRole)
        {
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
            throw std::runtime_error("original role close fault");
        }
        return closed;
    });
    try
    {
        (void)access.Close();
        FAIL() << "The original exception must propagate";
    }
    catch (const std::runtime_error& error)
    {
        EXPECT_STREQ("original role close fault", error.what());
        EXPECT_FALSE(access.ProcDirectory().HasValue());
        EXPECT_FALSE(access.FdDirectory().HasValue());
        EXPECT_FALSE(access.FdinfoDirectory().HasValue());
    }
    EXPECT_EQ(1, closes[fdinfoRole]);
    EXPECT_EQ(1, closes[fdRole]);
    EXPECT_EQ(1, closes[procFd]);
    EXPECT_TRUE(access.Close().HasValue());
    EXPECT_EQ(1, closes[fdinfoRole]);
    ASSERT_GE(reused, 0);
    EXPECT_GE(::fcntl(reused, F_GETFD), 0);
    EXPECT_EQ(0, ::close(reused));
}

TEST(DescriptorBoundaryTest, ProcfsCloseReportsFirstNativeFailureAndAttemptsAllRoles)
{
    NiceMock<MockContext> context;
    ProcfsDescriptorAccess access(context);
    int procFd = -1, fdRole = -1, fdinfoRole = -1;
    ON_CALL(context, OpenNativePath(_, _)).WillByDefault([&](const char* path, int flags) {
        const int opened = context.RealOpenNativePath(path, flags);
        if (std::string(path) == "/proc")
            procFd = opened;
        return opened;
    });
    ON_CALL(context, OpenNativeAt(_, _, _)).WillByDefault([&](int directory, const char* name, int flags) {
        const int opened = context.RealOpenNativeAt(directory, name, flags);
        if (std::string(name) == "fd")
            fdRole = opened;
        if (std::string(name) == "fdinfo")
            fdinfoRole = opened;
        return opened;
    });
    ASSERT_TRUE(access.Open().HasValue());
    std::vector<int> order;
    EXPECT_CALL(context, CloseFileDescriptor(_)).WillRepeatedly([&](int descriptor) {
        order.push_back(descriptor);
        const int closed = context.RealCloseFileDescriptor(descriptor);
        if (descriptor == fdinfoRole || descriptor == fdRole || descriptor == procFd)
        {
            errno = descriptor == fdinfoRole ? EBUSY : (descriptor == fdRole ? EACCES : ENOSPC);
            return -1;
        }
        return closed;
    });
    auto result = access.Close();
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EBUSY, result.Error().code);
    EXPECT_EQ((std::vector<int>{fdinfoRole, fdRole, procFd}), order);
    EXPECT_FALSE(access.FdDirectory().HasValue());
    EXPECT_TRUE(access.Close().HasValue());
    EXPECT_EQ(3U, order.size());
}

TEST(DescriptorBoundaryTest, ProcfsDescriptorAccessBindsContextAndChecksReadLifetime)
{
    NiceMock<MockContext> context;
    NiceMock<MockContext> foreign;
    auto owned = context.OpenAbsolutePin("/");
    auto other = foreign.OpenAbsolutePin("/");
    ASSERT_TRUE(owned.HasValue());
    ASSERT_TRUE(other.HasValue());
    ProcfsDescriptorAccess access(context);
    EXPECT_EQ(EINVAL, access.ReadMountId(owned.Value(), 4096).Error().code);
    ASSERT_TRUE(access.Open().HasValue());
    EXPECT_EQ(EINVAL, access.ReadMountId(owned.Value(), 0).Error().code);
    EXPECT_EQ(EINVAL, access.ReadMountId(other.Value(), 4096).Error().code);
    auto mount = access.ReadMountId(owned.Value(), 4096);
    ASSERT_TRUE(mount.HasValue()) << mount.Error().message;
    EXPECT_GT(mount.Value(), 0U);
    ASSERT_TRUE(access.Close().HasValue());
    EXPECT_EQ(EINVAL, access.ReadMountId(owned.Value(), 4096).Error().code);
}

TEST(DescriptorBoundaryTest, CurrentTaskIdentityGuardsEveryRoleBeforeNativeDispatch)
{
    NiceMock<MockContext> context;
    ProcfsDescriptorAccess access(context);
    auto opened = context.OpenAbsolutePin("/");
    ASSERT_TRUE(opened.HasValue());
    Descriptor pin = std::move(opened).Value();
    ASSERT_TRUE(access.Open().HasValue());

    auto rejectAll = [&]() {
        EXPECT_CALL(context, OpenNativeAt(_, _, _)).Times(0);
        EXPECT_CALL(context, ChmodPinnedAlias(_, _, _)).Times(0);
        EXPECT_CALL(context, StatFileDescriptor(_, _)).Times(0);
        EXPECT_EQ(EINVAL, context.OpenFdinfo(access, pin).Error().code);
        EXPECT_EQ(EINVAL, context.OpenAlias(access, pin, true).Error().code);
        EXPECT_EQ(EINVAL, context.OpenPinAlias(access, pin, true).Error().code);
        errno = 0;
        EXPECT_EQ(-1, context.ChmodAlias(access, pin, 0700));
        EXPECT_EQ(EINVAL, errno);
        ASSERT_TRUE(testing::Mock::VerifyAndClearExpectations(&context));
    };
    ON_CALL(context, NativeProcessId()).WillByDefault([&] { return context.RealNativeProcessId() + 1; });
    rejectAll(); // inherited fork-like process identity
    ON_CALL(context, NativeProcessId()).WillByDefault([&] { return context.RealNativeProcessId(); });
    ON_CALL(context, NativeThreadId()).WillByDefault([&] { return context.RealNativeThreadId() + 1; });
    rejectAll(); // other task in the same process
    ON_CALL(context, NativeThreadId()).WillByDefault([] {
        errno = ENOSYS;
        return static_cast<pid_t>(-1);
    });
    rejectAll(); // no PID fallback when gettid fails
    ON_CALL(context, NativeThreadId()).WillByDefault([&] { return context.RealNativeThreadId(); });
    ON_CALL(context, NativeProcessId()).WillByDefault([] {
        errno = EIO;
        return static_cast<pid_t>(-1);
    });
    rejectAll();
    ON_CALL(context, NativeProcessId()).WillByDefault([&] { return context.RealNativeProcessId(); });
    EXPECT_TRUE(access.Close().HasValue());
}

TEST(DescriptorBoundaryTest, CurrentTaskAcquisitionFailsClosedAndCleansBootstrap)
{
    NiceMock<MockContext> context;
    auto pin = context.OpenAbsolutePin("/");
    ASSERT_TRUE(pin.HasValue());
    const auto unavailable = [&](pid_t pid, pid_t tid, int expected) {
        ProcfsDescriptorAccess access(context);
        ON_CALL(context, NativeProcessId()).WillByDefault([pid, expected] {
            if (pid < 0)
                errno = expected;
            return pid;
        });
        ON_CALL(context, NativeThreadId()).WillByDefault([tid, expected] {
            if (tid < 0)
                errno = expected;
            return tid;
        });
        auto result = access.Open();
        EXPECT_FALSE(result.HasValue());
        EXPECT_EQ(expected, result.Error().code);
        EXPECT_FALSE(access.ProcDirectory().HasValue());
        EXPECT_FALSE(access.FdDirectory().HasValue());
        EXPECT_FALSE(access.FdinfoDirectory().HasValue());
    };
    EXPECT_CALL(context, OpenNativePath(_, _)).Times(0);
    unavailable(-1, context.RealNativeThreadId(), ENOSYS);
    unavailable(context.RealNativeProcessId(), -1, ENOSYS);
    testing::Mock::VerifyAndClearExpectations(&context);

    ON_CALL(context, NativeProcessId()).WillByDefault([&] { return context.RealNativeProcessId(); });
    ON_CALL(context, NativeThreadId()).WillByDefault([&] { return context.RealNativeThreadId(); });
    ProcfsDescriptorAccess missingTask(context);
    {
        testing::InSequence bootstrapOrder;
        EXPECT_CALL(context, OpenNativeAt(_, testing::StrEq("self"), O_PATH | O_DIRECTORY | O_CLOEXEC)).WillOnce([&](int directory, const char* name, int flags) {
            return context.RealOpenNativeAt(directory, name, flags);
        });
        EXPECT_CALL(context, OpenNativeAt(_, testing::StrEq(std::to_string(context.RealNativeProcessId())), O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC))
            .WillOnce([&](int directory, const char* name, int flags) { return context.RealOpenNativeAt(directory, name, flags); });
        EXPECT_CALL(context, OpenNativeAt(_, testing::StrEq("task"), O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)).WillOnce([](int, const char*, int) {
            errno = ENOENT;
            return -1;
        });
    }
    auto missing = missingTask.Open();
    ASSERT_FALSE(missing.HasValue());
    EXPECT_EQ(ENOENT, missing.Error().code);
    EXPECT_FALSE(missingTask.ProcDirectory().HasValue());
    testing::Mock::VerifyAndClearExpectations(&context);

    ProcfsDescriptorAccess changed(context);
    EXPECT_CALL(context, NativeThreadId()).WillOnce([&] { return context.RealNativeThreadId(); }).WillOnce([&] {
        return context.RealNativeThreadId() + 1;
    });
    auto rejected = changed.Open();
    ASSERT_FALSE(rejected.HasValue());
    EXPECT_EQ(EPROTO, rejected.Error().code);
    EXPECT_FALSE(changed.ProcDirectory().HasValue());
    testing::Mock::VerifyAndClearExpectations(&context);
    ProcfsDescriptorAccess fresh(context);
    ASSERT_TRUE(fresh.Open().HasValue());
    auto info = context.OpenFdinfo(fresh, pin.Value());
    ASSERT_TRUE(info.HasValue());
    EXPECT_TRUE(info.Value().Close().HasValue());
    EXPECT_TRUE(fresh.Close().HasValue());
}

TEST(DescriptorBoundaryTest, OtherRealThreadCannotUseSessionButCanOpenFreshOne)
{
    NiceMock<MockContext> context;
    auto opened = context.OpenAbsolutePin("/");
    ASSERT_TRUE(opened.HasValue());
    Descriptor pin = std::move(opened).Value();
    ProcfsDescriptorAccess inherited(context);
    ASSERT_TRUE(inherited.Open().HasValue());
    std::atomic<bool> wrongCallerRejected(false), freshSucceeded(false);
    std::thread worker([&] {
        auto denied = context.OpenFdinfo(inherited, pin);
        wrongCallerRejected = !denied.HasValue() && denied.Error().code == EINVAL;
        ProcfsDescriptorAccess fresh(context);
        auto ready = fresh.Open();
        if (ready.HasValue())
        {
            auto info = context.OpenFdinfo(fresh, pin);
            freshSucceeded = info.HasValue() && info.Value().Close().HasValue() && fresh.Close().HasValue();
        }
    });
    worker.join();
    EXPECT_TRUE(wrongCallerRejected);
    EXPECT_TRUE(freshSucceeded);
    EXPECT_TRUE(inherited.Close().HasValue());
}

TEST(DescriptorBoundaryTest, MovedDescriptorLogsFailedCloseOnlyOnce)
{
    struct LoggingContext : NiceMock<MockContext>
    {
        OsConfigLogHandle GetLogHandle() const override
        {
            ++logAttempts;
            throw std::runtime_error("diagnostic handle unavailable");
        }
        mutable int logAttempts = 0;
    } context;
    auto opened = context.OpenAbsolutePin("/proc");
    ASSERT_TRUE(opened.HasValue());
    Descriptor original = std::move(opened).Value();
    Descriptor moved(std::move(original));
    EXPECT_FALSE(original.HasValue());
    EXPECT_CALL(context, CloseFileDescriptor(_)).Times(1).WillOnce([](int fd) {
        EXPECT_EQ(0, ::close(fd));
        errno = EIO;
        return -1;
    });
    try
    {
        (void)moved.Close();
        FAIL() << "The original log-accessor exception must propagate";
    }
    catch (const std::runtime_error& error)
    {
        EXPECT_STREQ("diagnostic handle unavailable", error.what());
    }
    EXPECT_EQ(1, context.logAttempts);
    EXPECT_TRUE(moved.Close().HasValue());
    EXPECT_FALSE(moved.HasValue());
}

TEST(DescriptorBoundaryTest, NativeCloseExceptionRelinquishesDescriptorBeforeReuse)
{
    NiceMock<MockContext> context;
    auto opened = context.OpenAbsolutePin("/proc");
    ASSERT_TRUE(opened.HasValue());
    Descriptor owner = std::move(opened).Value();
    int reused = -1;
    EXPECT_CALL(context, CloseFileDescriptor(_)).Times(1).WillOnce([&](int fd) -> int {
        EXPECT_EQ(0, ::close(fd));
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
        throw std::runtime_error("native close fault");
    });
    try
    {
        (void)owner.Close();
        FAIL() << "The original native exception must propagate";
    }
    catch (const std::runtime_error& error)
    {
        EXPECT_STREQ("native close fault", error.what());
    }
    EXPECT_FALSE(owner.HasValue());
    EXPECT_TRUE(owner.Close().HasValue());
    ASSERT_TRUE(testing::Mock::VerifyAndClearExpectations(&context));
    ASSERT_GE(reused, 0);
    EXPECT_GE(::fcntl(reused, F_GETFD), 0);
    EXPECT_EQ(0, ::close(reused));
}

TEST(DescriptorBoundaryTest, ContextAllowanceIncludesDetachedOwnersAndDoesNotResetOnTransfer)
{
    NiceMock<MockContext> first;
    NiceMock<MockContext> second;
    std::vector<Descriptor> owners;
    owners.reserve(256);
    for (std::size_t i = 0; i < 256; ++i)
    {
        auto opened = first.OpenAbsolutePin("/");
        ASSERT_TRUE(opened.HasValue()) << i << ": " << opened.Error().message;
        owners.push_back(std::move(opened).Value());
    }
    EXPECT_CALL(first, OpenNativePath(_, _)).Times(0);
    EXPECT_CALL(first, DuplicateDescriptor(_)).Times(0);
    auto full = first.OpenAbsolutePin("/");
    ASSERT_FALSE(full.HasValue());
    EXPECT_EQ(EMFILE, full.Error().code);
    auto duplicate = first.Duplicate(owners.back());
    ASSERT_FALSE(duplicate.HasValue());
    EXPECT_EQ(EMFILE, duplicate.Error().code);
    testing::Mock::VerifyAndClearExpectations(&first);
    auto independent = second.OpenAbsolutePin("/");
    ASSERT_TRUE(independent.HasValue()); // another context has its own owner

    Descriptor detached(std::move(owners.front()));
    EXPECT_FALSE(owners.front().HasValue());
    EXPECT_EQ(EMFILE, first.OpenAbsolutePin("/").Error().code);
    ASSERT_TRUE(detached.Close().HasValue());
    auto replacement = first.Duplicate(owners.back());
    ASSERT_TRUE(replacement.HasValue());
    EXPECT_EQ(EMFILE, first.OpenAbsolutePin("/").Error().code);
    ASSERT_TRUE(replacement.Value().Close().HasValue());

    EXPECT_CALL(first, OpenNativePath(_, _)).WillOnce([](const char*, int) {
        errno = EACCES;
        return -1;
    });
    auto failed = first.OpenAbsolutePin("/");
    ASSERT_FALSE(failed.HasValue());
    EXPECT_EQ(EACCES, failed.Error().code);
    testing::Mock::VerifyAndClearExpectations(&first);
    EXPECT_CALL(first, DuplicateDescriptor(_)).WillOnce([](int) {
        errno = EBADF;
        return -1;
    });
    auto failedDuplicate = first.Duplicate(owners.back());
    ASSERT_FALSE(failedDuplicate.HasValue());
    EXPECT_EQ(EBADF, failedDuplicate.Error().code);
    testing::Mock::VerifyAndClearExpectations(&first);
    EXPECT_TRUE(first.OpenAbsolutePin("/").HasValue()); // temporary closes on result destruction
    EXPECT_TRUE(independent.Value().Close().HasValue());
}

TEST(DescriptorBoundaryTest, NarrowTestAllowanceHonorsLiveOwnersAndCannotRaiseProductionLimit)
{
    NiceMock<MockContext> context;
    context.SetManagedDescriptorAllowanceForTesting(2);
    auto first = context.OpenAbsolutePin("/");
    auto second = context.OpenAbsolutePin("/");
    ASSERT_TRUE(first.HasValue());
    ASSERT_TRUE(second.HasValue());
    EXPECT_CALL(context, OpenNativePath(_, _)).Times(0);
    EXPECT_EQ(EMFILE, context.OpenAbsolutePin("/").Error().code);
    testing::Mock::VerifyAndClearExpectations(&context);

    context.SetManagedDescriptorAllowanceForTesting(1);
    EXPECT_EQ(EMFILE, context.Duplicate(first.Value()).Error().code);
    ASSERT_TRUE(first.Value().Close().HasValue());
    EXPECT_EQ(EMFILE, context.OpenAbsolutePin("/").Error().code);
    ASSERT_TRUE(second.Value().Close().HasValue());
    auto recovered = context.OpenAbsolutePin("/");
    ASSERT_TRUE(recovered.HasValue());
    ASSERT_TRUE(recovered.Value().Close().HasValue());
    context.SetManagedDescriptorAllowanceForTesting(512);
    std::vector<Descriptor> held;
    held.reserve(256);
    for (std::size_t i = 0; i < 256; ++i)
    {
        auto opened = context.OpenAbsolutePin("/");
        ASSERT_TRUE(opened.HasValue()) << i << ": " << opened.Error().message;
        held.push_back(std::move(opened).Value());
    }
    EXPECT_EQ(EMFILE, context.OpenAbsolutePin("/").Error().code);
}

TEST(DescriptorBoundaryTest, CursorTransferRetainsChargeUntilClosed)
{
    NiceMock<MockContext> context;
    auto root = context.OpenAbsolutePin("/");
    ASSERT_TRUE(root.HasValue());
    ProcfsDescriptorAccess procfs(context);
    ASSERT_TRUE(procfs.Open().HasValue());
    auto alias = context.OpenAlias(procfs, root.Value(), true);
    ASSERT_TRUE(alias.HasValue());
    ASSERT_TRUE(procfs.Close().HasValue());
    ASSERT_TRUE(root.Value().Close().HasValue());
    auto cursor = context.OpenDirectoryCursor(std::move(alias).Value());
    ASSERT_TRUE(cursor.HasValue());
    std::vector<Descriptor> owners;
    owners.reserve(255);
    for (std::size_t i = 0; i < 255; ++i)
    {
        auto opened = context.OpenAbsolutePin("/");
        ASSERT_TRUE(opened.HasValue()) << i;
        owners.push_back(std::move(opened).Value());
    }
    EXPECT_EQ(EMFILE, context.OpenAbsolutePin("/").Error().code);
    ASSERT_TRUE(cursor.Value().Close().HasValue());
    auto available = context.OpenAbsolutePin("/");
    ASSERT_TRUE(available.HasValue());
    EXPECT_EQ(EMFILE, context.OpenAbsolutePin("/").Error().code);
}

TEST(DescriptorBoundaryTest, FailedProcfsBootstrapReturnsAllTemporaryReservations)
{
    NiceMock<MockContext> context;
    std::vector<Descriptor> owners;
    owners.reserve(254);
    for (std::size_t i = 0; i < 254; ++i)
    {
        auto opened = context.OpenAbsolutePin("/");
        ASSERT_TRUE(opened.HasValue()) << i;
        owners.push_back(std::move(opened).Value());
    }
    ProcfsDescriptorAccess procfs(context);
    auto failure = procfs.Open();
    ASSERT_FALSE(failure.HasValue());
    EXPECT_EQ(EMFILE, failure.Error().code);
    auto first = context.OpenAbsolutePin("/");
    auto second = context.OpenAbsolutePin("/");
    ASSERT_TRUE(first.HasValue());
    ASSERT_TRUE(second.HasValue());
    EXPECT_EQ(EMFILE, context.OpenAbsolutePin("/").Error().code);
    ASSERT_TRUE(first.Value().Close().HasValue());
    ASSERT_TRUE(second.Value().Close().HasValue());
    ASSERT_TRUE(owners.back().Close().HasValue());
    auto recovered = procfs.Open();
    // At 253 held pins there is still insufficient room for all verified
    // procfs roles; no partial helper owner may remain on failure.
    ASSERT_FALSE(recovered.HasValue());
    EXPECT_EQ(EMFILE, recovered.Error().code);
}
} // namespace
