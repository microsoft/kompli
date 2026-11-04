// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <DescriptorTestAccess.h>
#include <MockContext.h>
#include <atomic>
#include <cerrno>
#include <fcntl.h>
#include <filesystem/Descriptor.hpp>
#include <filesystem/Handle.hpp>
#include <filesystem/ProcfsDescriptorAccess.hpp>
#include <fstream>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <iterator>
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
using ComplianceEngine::Tests::DescriptorTestAccess;
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
    static_assert(!Can##name<MockContext&>::value && !Can##name<const MockContext&>::value, #name " is not accessible to ordinary callers");           \
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
template <typename T, typename = void>
struct CanBorrowRole : std::false_type
{
};
template <typename T>
struct CanBorrowRole<T, typename Void<decltype(std::declval<T&>().FdDirectory())>::type> : std::true_type
{
};
static_assert(!CanBorrowRole<ProcfsDescriptorAccess>::value, "Procfs roles have no reference getter");
static_assert(noexcept(std::declval<Descriptor&>().Close()) && std::is_same<decltype(std::declval<Descriptor&>().Close()), void>::value,
    "Unique descriptor disposal is void noexcept");
static_assert(noexcept(std::declval<ProcfsDescriptorAccess&>().Close()) && std::is_same<decltype(std::declval<ProcfsDescriptorAccess&>().Close()), void>::value,
    "Procfs role disposal is void noexcept");
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
    auto opened = DescriptorTestAccess::OpenAbsolutePin(context, context.GetTempdirPath().c_str());
    ASSERT_TRUE(opened.HasValue());
    Descriptor directory = std::move(opened).Value();
    EXPECT_CALL(context, OpenNativeAt(_, _, _)).Times(0);
    const char* invalidNames[] = {nullptr, "", "/", "/absolute", ".", "..", "../outside", "link/child", "a/", "a//b"};
    for (Profile profile : {Profile::PinChild, Profile::PinChildDirectory})
    {
        for (const char* name : invalidNames)
        {
            const auto rejected = DescriptorTestAccess::OpenAt(context, directory, name, profile);
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
    auto pinned = DescriptorTestAccess::OpenAt(context, directory, "child-link", Profile::PinChild);
    ASSERT_TRUE(pinned.HasValue());
    struct stat identity = {};
    ASSERT_EQ(0, DescriptorTestAccess::StatFile(context, pinned.Value(), &identity));
    EXPECT_TRUE(S_ISLNK(identity.st_mode));
    pinned.Value().Close();
    directory.Close();
    ASSERT_EQ(0, ::unlink(link.c_str()));
}

TEST(DescriptorBoundaryTest, AliasProfilesRequireVerifiedRoles)
{
    NiceMock<MockContext> context;
    auto procfs = DescriptorTestAccess::ProcfsAccess(context);
    auto pinResult = DescriptorTestAccess::OpenAbsolutePin(context, context.GetTempdirPath().c_str());
    ASSERT_TRUE(pinResult.HasValue());
    Descriptor pin = std::move(pinResult).Value();
    EXPECT_CALL(context, OpenNativeAt(_, _, _)).Times(0);
    EXPECT_CALL(context, ChmodPinnedAlias(_, _, _)).Times(0);
    EXPECT_EQ(EINVAL, DescriptorTestAccess::OpenAlias(context, procfs, pin, true).Error().code);
    EXPECT_EQ(EINVAL, DescriptorTestAccess::OpenPinAlias(context, procfs, pin, true).Error().code);
    EXPECT_EQ(EINVAL, DescriptorTestAccess::OpenFdinfo(context, procfs, pin).Error().code);
    errno = 0;
    EXPECT_EQ(-1, DescriptorTestAccess::ChmodAlias(context, procfs, pin, 0700));
    EXPECT_EQ(EINVAL, errno);
    testing::Mock::VerifyAndClearExpectations(&context);

    ASSERT_TRUE(procfs.Open().HasValue());

    auto validInfo = DescriptorTestAccess::OpenFdinfo(context, procfs, pin);
    ASSERT_TRUE(validInfo.HasValue());
    validInfo.Value().Close();
    auto validPin = DescriptorTestAccess::OpenPinAlias(context, procfs, pin, true);
    ASSERT_TRUE(validPin.HasValue());
    validPin.Value().Close();
    auto validAlias = DescriptorTestAccess::OpenAlias(context, procfs, pin, true);
    ASSERT_TRUE(validAlias.HasValue());
    validAlias.Value().Close();

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
            auto denied = DescriptorTestAccess::OpenAt(context, directory, alias.c_str(), profile);
            ASSERT_FALSE(denied.HasValue());
            EXPECT_EQ(EINVAL, denied.Error().code);
        }

        testing::Mock::VerifyAndClearExpectations(&context);
    };

    // Independently acquired real role paths are still generic owners, not verified roles.
    const std::string roles = "/proc/self/task/" + std::to_string(context.RealNativeThreadId());
    auto genericFdinfo = DescriptorTestAccess::OpenAbsolutePin(context, (roles + "/fdinfo").c_str());
    auto genericFd = DescriptorTestAccess::OpenAbsolutePin(context, (roles + "/fd").c_str());
    ASSERT_TRUE(genericFdinfo.HasValue());
    ASSERT_TRUE(genericFd.HasValue());
    rejectDirectory(genericFdinfo.Value());
    rejectDirectory(genericFd.Value());
    rejectDirectory(pin); // ordinary, same-context directory

    // A different PID's real procfs fd/fdinfo owners still cannot select
    // native alias operations through the public generic directory API.
    const std::string parent = std::to_string(::getppid());
    auto genericProc = DescriptorTestAccess::OpenAbsolutePin(context, "/proc");
    ASSERT_TRUE(genericProc.HasValue());
    auto process = DescriptorTestAccess::OpenAt(context, genericProc.Value(), parent.c_str(), Profile::PinDirectory);
    ASSERT_TRUE(process.HasValue());
    auto otherFd = DescriptorTestAccess::OpenAt(context, process.Value(), "fd", Profile::PinDirectory);
    auto otherFdinfo = DescriptorTestAccess::OpenAt(context, process.Value(), "fdinfo", Profile::PinDirectory);
    ASSERT_TRUE(otherFd.HasValue());
    ASSERT_TRUE(otherFdinfo.HasValue());
    rejectDirectory(otherFd.Value());
    rejectDirectory(otherFdinfo.Value());

    procfs.Close();
    EXPECT_CALL(context, OpenNativeAt(_, _, _)).Times(0);
    EXPECT_CALL(context, ChmodPinnedAlias(_, _, _)).Times(0);
    EXPECT_EQ(EINVAL, DescriptorTestAccess::OpenAlias(context, procfs, pin, true).Error().code);
    EXPECT_EQ(EINVAL, DescriptorTestAccess::OpenFdinfo(context, procfs, pin).Error().code);
    errno = 0;
    EXPECT_EQ(-1, DescriptorTestAccess::ChmodAlias(context, procfs, pin, 0700));
    EXPECT_EQ(EINVAL, errno);
}

TEST(DescriptorBoundaryTest, RelativeAndVerifiedAliasOpensAtomicallySetCloexec)
{
    NiceMock<MockContext> context;
    auto root = DescriptorTestAccess::OpenAbsolutePin(context, "/proc");
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
    auto relative = DescriptorTestAccess::OpenAt(context, root.Value(), "self", Profile::PinChild);
    ASSERT_TRUE(relative.HasValue());
    struct stat identity = {};
    ASSERT_EQ(0, DescriptorTestAccess::StatFile(context, relative.Value(), &identity));
    EXPECT_TRUE(S_ISLNK(identity.st_mode)); // generic child pins do not follow
    auto procfs = DescriptorTestAccess::ProcfsAccess(context);
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
    auto alias = DescriptorTestAccess::OpenPinAlias(context, procfs, root.Value(), true);
    ASSERT_TRUE(alias.HasValue());
    EXPECT_EQ(3, relativeOpens); // child pin, self bootstrap and fdinfo role
    EXPECT_EQ(1, aliasOpens);
    alias.Value().Close();
    relative.Value().Close();
    procfs.Close();
    root.Value().Close();
}

TEST(DescriptorBoundaryTest, ProcfsCloseDetachesAllRolesBeforeThrowAndNeverRetriesReusedFd)
{
    NiceMock<MockContext> context;
    NiceMock<MockContext> foreign;
    const std::string logPath = context.GetTempdirPath() + "/role-close.log";
    OsConfigLogHandle log = OpenLog(logPath.c_str(), nullptr);
    ASSERT_NE(nullptr, log);
    context.SetLogHandle(log);
    auto access = DescriptorTestAccess::ProcfsAccess(context);
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
    EXPECT_NO_THROW(access.Close());
    auto emptyTarget = DescriptorTestAccess::EmptyDescriptor(context);
    EXPECT_EQ(EINVAL, access.ReadMountId(emptyTarget, 4096).Error().code);
    EXPECT_EQ(1, closes[fdinfoRole]);
    EXPECT_EQ(1, closes[fdRole]);
    EXPECT_EQ(1, closes[procFd]);
    access.Close();
    EXPECT_EQ(1, closes[fdinfoRole]);
    ASSERT_GE(reused, 0);
    EXPECT_GE(::fcntl(reused, F_GETFD), 0);
    EXPECT_EQ(0, ::close(reused));
    CloseLog(&log);
    context.SetLogHandle(nullptr);
    std::ifstream record(logPath);
    ASSERT_TRUE(record.is_open());
    const std::string text((std::istreambuf_iterator<char>(record)), std::istreambuf_iterator<char>());
    const std::string entry = "Cannot close internal filesystem descriptor: " + std::to_string(EIO);
    const auto at = text.find(entry);
    ASSERT_NE(std::string::npos, at);
    EXPECT_EQ(std::string::npos, text.find(entry, at + entry.size()));
}

TEST(DescriptorBoundaryTest, ProcfsCloseReportsFirstNativeFailureAndAttemptsAllRoles)
{
    NiceMock<MockContext> context;
    const std::string logPath = context.GetTempdirPath() + "/role-close.log";
    OsConfigLogHandle log = OpenLog(logPath.c_str(), nullptr);
    ASSERT_NE(nullptr, log);
    context.SetLogHandle(log);
    auto access = DescriptorTestAccess::ProcfsAccess(context);
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
    access.Close();
    std::vector<int> failedRoles;
    for (int fd : order)
        if (fd == fdinfoRole || fd == fdRole || fd == procFd)
            failedRoles.push_back(fd);
    EXPECT_EQ((std::vector<int>{fdinfoRole, fdRole, procFd}), failedRoles);
    auto checked = DescriptorTestAccess::OpenAbsolutePin(context, "/");
    ASSERT_TRUE(checked.HasValue());
    EXPECT_EQ(EINVAL, access.ReadMountId(checked.Value(), 4096).Error().code);
    access.Close();
    EXPECT_EQ(3U, order.size());
    CloseLog(&log);
    context.SetLogHandle(nullptr);
    std::ifstream record(logPath);
    ASSERT_TRUE(record.is_open());
    const std::string text((std::istreambuf_iterator<char>(record)), std::istreambuf_iterator<char>());
    for (int error : {EBUSY, EACCES, ENOSPC})
    {
        const std::string entry = "Cannot close internal filesystem descriptor: " + std::to_string(error);
        const auto at = text.find(entry);
        ASSERT_NE(std::string::npos, at);
        EXPECT_EQ(std::string::npos, text.find(entry, at + entry.size()));
    }
}

TEST(DescriptorBoundaryTest, ProcfsDescriptorAccessBindsContextAndChecksReadLifetime)
{
    NiceMock<MockContext> context;
    NiceMock<MockContext> foreign;
    auto owned = DescriptorTestAccess::OpenAbsolutePin(context, "/");
    auto other = DescriptorTestAccess::OpenAbsolutePin(foreign, "/");
    ASSERT_TRUE(owned.HasValue());
    ASSERT_TRUE(other.HasValue());
    auto access = DescriptorTestAccess::ProcfsAccess(context);
    EXPECT_EQ(EINVAL, access.ReadMountId(owned.Value(), 4096).Error().code);
    ASSERT_TRUE(access.Open().HasValue());
    EXPECT_EQ(EINVAL, access.ReadMountId(owned.Value(), 0).Error().code);
    EXPECT_EQ(EINVAL, access.ReadMountId(other.Value(), 4096).Error().code);
    auto mount = access.ReadMountId(owned.Value(), 4096);
    ASSERT_TRUE(mount.HasValue()) << mount.Error().message;
    EXPECT_GT(mount.Value(), 0U);
    access.Close();
    EXPECT_EQ(EINVAL, access.ReadMountId(owned.Value(), 4096).Error().code);
}

TEST(DescriptorBoundaryTest, CurrentTaskIdentityGuardsEveryRoleBeforeNativeDispatch)
{
    NiceMock<MockContext> context;
    auto access = DescriptorTestAccess::ProcfsAccess(context);
    auto opened = DescriptorTestAccess::OpenAbsolutePin(context, "/");
    ASSERT_TRUE(opened.HasValue());
    Descriptor pin = std::move(opened).Value();
    ASSERT_TRUE(access.Open().HasValue());

    auto rejectAll = [&]() {
        EXPECT_CALL(context, OpenNativeAt(_, _, _)).Times(0);
        EXPECT_CALL(context, ChmodPinnedAlias(_, _, _)).Times(0);
        EXPECT_CALL(context, StatFileDescriptor(_, _)).Times(0);
        EXPECT_EQ(EINVAL, DescriptorTestAccess::OpenFdinfo(context, access, pin).Error().code);
        EXPECT_EQ(EINVAL, DescriptorTestAccess::OpenAlias(context, access, pin, true).Error().code);
        EXPECT_EQ(EINVAL, DescriptorTestAccess::OpenPinAlias(context, access, pin, true).Error().code);
        errno = 0;
        EXPECT_EQ(-1, DescriptorTestAccess::ChmodAlias(context, access, pin, 0700));
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
    access.Close();
}

TEST(DescriptorBoundaryTest, CurrentTaskAcquisitionFailsClosedAndCleansBootstrap)
{
    NiceMock<MockContext> context;
    auto pin = DescriptorTestAccess::OpenAbsolutePin(context, "/");
    ASSERT_TRUE(pin.HasValue());
    const auto unavailable = [&](pid_t pid, pid_t tid, int expected) {
        auto access = DescriptorTestAccess::ProcfsAccess(context);
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
        EXPECT_EQ(EINVAL, access.ReadMountId(pin.Value(), 4096).Error().code);
    };
    EXPECT_CALL(context, OpenNativePath(_, _)).Times(0);
    unavailable(-1, context.RealNativeThreadId(), ENOSYS);
    unavailable(context.RealNativeProcessId(), -1, ENOSYS);
    testing::Mock::VerifyAndClearExpectations(&context);

    ON_CALL(context, NativeProcessId()).WillByDefault([&] { return context.RealNativeProcessId(); });
    ON_CALL(context, NativeThreadId()).WillByDefault([&] { return context.RealNativeThreadId(); });
    auto missingTask = DescriptorTestAccess::ProcfsAccess(context);
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
    EXPECT_EQ(EINVAL, missingTask.ReadMountId(pin.Value(), 4096).Error().code);
    testing::Mock::VerifyAndClearExpectations(&context);

    auto changed = DescriptorTestAccess::ProcfsAccess(context);
    EXPECT_CALL(context, NativeThreadId()).WillOnce([&] { return context.RealNativeThreadId(); }).WillOnce([&] {
        return context.RealNativeThreadId() + 1;
    });
    auto rejected = changed.Open();
    ASSERT_FALSE(rejected.HasValue());
    EXPECT_EQ(EPROTO, rejected.Error().code);
    EXPECT_EQ(EINVAL, changed.ReadMountId(pin.Value(), 4096).Error().code);
    testing::Mock::VerifyAndClearExpectations(&context);
    auto fresh = DescriptorTestAccess::ProcfsAccess(context);
    ASSERT_TRUE(fresh.Open().HasValue());
    auto info = DescriptorTestAccess::OpenFdinfo(context, fresh, pin.Value());
    ASSERT_TRUE(info.HasValue());
    info.Value().Close();
    fresh.Close();
}

TEST(DescriptorBoundaryTest, OtherRealThreadCannotUseSessionButCanOpenFreshOne)
{
    NiceMock<MockContext> context;
    auto opened = DescriptorTestAccess::OpenAbsolutePin(context, "/");
    ASSERT_TRUE(opened.HasValue());
    Descriptor pin = std::move(opened).Value();
    auto inherited = DescriptorTestAccess::ProcfsAccess(context);
    ASSERT_TRUE(inherited.Open().HasValue());
    std::atomic<bool> wrongCallerRejected(false), freshSucceeded(false);
    std::thread worker([&] {
        auto denied = DescriptorTestAccess::OpenFdinfo(context, inherited, pin);
        wrongCallerRejected = !denied.HasValue() && denied.Error().code == EINVAL;
        auto fresh = DescriptorTestAccess::ProcfsAccess(context);
        auto ready = fresh.Open();
        if (ready.HasValue())
        {
            auto info = DescriptorTestAccess::OpenFdinfo(context, fresh, pin);
            freshSucceeded = info.HasValue();
            if (info.HasValue())
                info.Value().Close();
            fresh.Close();
        }
    });
    worker.join();
    EXPECT_TRUE(wrongCallerRejected);
    EXPECT_TRUE(freshSucceeded);
    inherited.Close();
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
    auto opened = DescriptorTestAccess::OpenAbsolutePin(context, "/proc");
    ASSERT_TRUE(opened.HasValue());
    Descriptor original = std::move(opened).Value();
    Descriptor moved(std::move(original));
    EXPECT_FALSE(original.HasValue());
    EXPECT_CALL(context, CloseFileDescriptor(_)).Times(1).WillOnce([](int fd) {
        EXPECT_EQ(0, ::close(fd));
        errno = EIO;
        return -1;
    });
    EXPECT_NO_THROW(moved.Close());
    EXPECT_EQ(1, context.logAttempts);
    moved.Close();
    EXPECT_FALSE(moved.HasValue());
}

TEST(DescriptorBoundaryTest, NativeCloseExceptionRelinquishesDescriptorBeforeReuse)
{
    NiceMock<MockContext> context;
    const std::string logPath = context.GetTempdirPath() + "/exception-release.log";
    OsConfigLogHandle log = OpenLog(logPath.c_str(), nullptr);
    ASSERT_NE(nullptr, log);
    context.SetLogHandle(log);
    auto opened = DescriptorTestAccess::OpenAbsolutePin(context, "/proc");
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
    EXPECT_NO_THROW(owner.Close());
    EXPECT_FALSE(owner.HasValue());
    owner.Close();
    ASSERT_TRUE(testing::Mock::VerifyAndClearExpectations(&context));
    ASSERT_GE(reused, 0);
    EXPECT_GE(::fcntl(reused, F_GETFD), 0);
    EXPECT_EQ(0, ::close(reused));
    CloseLog(&log);
    context.SetLogHandle(nullptr);
    std::ifstream record(logPath);
    ASSERT_TRUE(record.is_open());
    const std::string text((std::istreambuf_iterator<char>(record)), std::istreambuf_iterator<char>());
    const std::string entry = "Cannot close internal filesystem descriptor: " + std::to_string(EIO);
    const auto at = text.find(entry);
    ASSERT_NE(std::string::npos, at);
    EXPECT_EQ(std::string::npos, text.find(entry, at + entry.size()));
}

TEST(DescriptorBoundaryTest, BadDescriptorCloseLogsOwnershipBugOnceWithoutRetry)
{
    NiceMock<MockContext> context;
    const std::string logPath = context.GetTempdirPath() + "/ebadf-close.log";
    OsConfigLogHandle log = OpenLog(logPath.c_str(), nullptr);
    ASSERT_NE(nullptr, log);
    context.SetLogHandle(log);
    auto opened = DescriptorTestAccess::OpenAbsolutePin(context, "/proc");
    ASSERT_TRUE(opened.HasValue());
    Descriptor owner = std::move(opened).Value();
    EXPECT_CALL(context, CloseFileDescriptor(_)).Times(1).WillOnce([](int fd) {
        EXPECT_EQ(0, ::close(fd));
        errno = EBADF;
        return -1;
    });
    owner.Close();
    owner.Close();
    EXPECT_FALSE(owner.HasValue());
    ASSERT_TRUE(testing::Mock::VerifyAndClearExpectations(&context));
    CloseLog(&log);
    context.SetLogHandle(nullptr);
    std::ifstream record(logPath);
    ASSERT_TRUE(record.is_open());
    const std::string text((std::istreambuf_iterator<char>(record)), std::istreambuf_iterator<char>());
    const std::string entry = "Cannot close internal filesystem descriptor (ownership bug, EBADF): " + std::to_string(EBADF);
    const auto at = text.find(entry);
    ASSERT_NE(std::string::npos, at);
    EXPECT_EQ(std::string::npos, text.find(entry, at + entry.size()));
}

TEST(DescriptorBoundaryTest, ContextAllowanceIncludesDetachedOwnersAndDoesNotResetOnTransfer)
{
    NiceMock<MockContext> first;
    NiceMock<MockContext> second;
    std::vector<Descriptor> owners;
    owners.reserve(256);
    for (std::size_t i = 0; i < 256; ++i)
    {
        auto opened = DescriptorTestAccess::OpenAbsolutePin(first, "/");
        ASSERT_TRUE(opened.HasValue()) << i << ": " << opened.Error().message;
        owners.push_back(std::move(opened).Value());
    }
    EXPECT_CALL(first, OpenNativePath(_, _)).Times(0);
    EXPECT_CALL(first, DuplicateDescriptor(_)).Times(0);
    auto full = DescriptorTestAccess::OpenAbsolutePin(first, "/");
    ASSERT_FALSE(full.HasValue());
    EXPECT_EQ(EMFILE, full.Error().code);
    auto duplicate = DescriptorTestAccess::Duplicate(first, owners.back());
    ASSERT_FALSE(duplicate.HasValue());
    EXPECT_EQ(EMFILE, duplicate.Error().code);
    testing::Mock::VerifyAndClearExpectations(&first);
    auto independent = DescriptorTestAccess::OpenAbsolutePin(second, "/");
    ASSERT_TRUE(independent.HasValue()); // another context has its own owner

    Descriptor detached(std::move(owners.front()));
    EXPECT_FALSE(owners.front().HasValue());
    EXPECT_EQ(EMFILE, DescriptorTestAccess::OpenAbsolutePin(first, "/").Error().code);
    detached.Close();
    auto replacement = DescriptorTestAccess::Duplicate(first, owners.back());
    ASSERT_TRUE(replacement.HasValue());
    EXPECT_EQ(EMFILE, DescriptorTestAccess::OpenAbsolutePin(first, "/").Error().code);
    replacement.Value().Close();

    EXPECT_CALL(first, OpenNativePath(_, _)).WillOnce([](const char*, int) {
        errno = EACCES;
        return -1;
    });
    auto failed = DescriptorTestAccess::OpenAbsolutePin(first, "/");
    ASSERT_FALSE(failed.HasValue());
    EXPECT_EQ(EACCES, failed.Error().code);
    testing::Mock::VerifyAndClearExpectations(&first);
    EXPECT_CALL(first, DuplicateDescriptor(_)).WillOnce([](int) {
        errno = EBADF;
        return -1;
    });
    auto failedDuplicate = DescriptorTestAccess::Duplicate(first, owners.back());
    ASSERT_FALSE(failedDuplicate.HasValue());
    EXPECT_EQ(EBADF, failedDuplicate.Error().code);
    testing::Mock::VerifyAndClearExpectations(&first);
    EXPECT_TRUE(DescriptorTestAccess::OpenAbsolutePin(first, "/").HasValue()); // temporary closes on result destruction
    independent.Value().Close();
}

TEST(DescriptorBoundaryTest, NarrowTestAllowanceHonorsLiveOwnersAndCannotRaiseProductionLimit)
{
    NiceMock<MockContext> context;
    context.SetManagedDescriptorAllowanceForTesting(2);
    auto first = DescriptorTestAccess::OpenAbsolutePin(context, "/");
    auto second = DescriptorTestAccess::OpenAbsolutePin(context, "/");
    ASSERT_TRUE(first.HasValue());
    ASSERT_TRUE(second.HasValue());
    EXPECT_CALL(context, OpenNativePath(_, _)).Times(0);
    EXPECT_EQ(EMFILE, DescriptorTestAccess::OpenAbsolutePin(context, "/").Error().code);
    testing::Mock::VerifyAndClearExpectations(&context);

    context.SetManagedDescriptorAllowanceForTesting(1);
    EXPECT_EQ(EMFILE, DescriptorTestAccess::Duplicate(context, first.Value()).Error().code);
    first.Value().Close();
    EXPECT_EQ(EMFILE, DescriptorTestAccess::OpenAbsolutePin(context, "/").Error().code);
    second.Value().Close();
    auto recovered = DescriptorTestAccess::OpenAbsolutePin(context, "/");
    ASSERT_TRUE(recovered.HasValue());
    recovered.Value().Close();
    context.SetManagedDescriptorAllowanceForTesting(512);
    std::vector<Descriptor> held;
    held.reserve(256);
    for (std::size_t i = 0; i < 256; ++i)
    {
        auto opened = DescriptorTestAccess::OpenAbsolutePin(context, "/");
        ASSERT_TRUE(opened.HasValue()) << i << ": " << opened.Error().message;
        held.push_back(std::move(opened).Value());
    }
    EXPECT_EQ(EMFILE, DescriptorTestAccess::OpenAbsolutePin(context, "/").Error().code);
}

TEST(DescriptorBoundaryTest, CursorTransferRetainsChargeUntilClosed)
{
    NiceMock<MockContext> context;
    auto root = DescriptorTestAccess::OpenAbsolutePin(context, "/");
    ASSERT_TRUE(root.HasValue());
    auto procfs = DescriptorTestAccess::ProcfsAccess(context);
    ASSERT_TRUE(procfs.Open().HasValue());
    auto alias = DescriptorTestAccess::OpenAlias(context, procfs, root.Value(), true);
    ASSERT_TRUE(alias.HasValue());
    procfs.Close();
    root.Value().Close();
    auto cursor = DescriptorTestAccess::OpenDirectoryCursor(context, std::move(alias).Value());
    ASSERT_TRUE(cursor.HasValue());
    std::vector<Descriptor> owners;
    owners.reserve(255);
    for (std::size_t i = 0; i < 255; ++i)
    {
        auto opened = DescriptorTestAccess::OpenAbsolutePin(context, "/");
        ASSERT_TRUE(opened.HasValue()) << i;
        owners.push_back(std::move(opened).Value());
    }
    EXPECT_EQ(EMFILE, DescriptorTestAccess::OpenAbsolutePin(context, "/").Error().code);
    cursor.Value().Close();
    auto available = DescriptorTestAccess::OpenAbsolutePin(context, "/");
    ASSERT_TRUE(available.HasValue());
    EXPECT_EQ(EMFILE, DescriptorTestAccess::OpenAbsolutePin(context, "/").Error().code);
}

TEST(DescriptorBoundaryTest, FailedProcfsBootstrapReturnsAllTemporaryReservations)
{
    NiceMock<MockContext> context;
    std::vector<Descriptor> owners;
    owners.reserve(254);
    for (std::size_t i = 0; i < 254; ++i)
    {
        auto opened = DescriptorTestAccess::OpenAbsolutePin(context, "/");
        ASSERT_TRUE(opened.HasValue()) << i;
        owners.push_back(std::move(opened).Value());
    }
    auto procfs = DescriptorTestAccess::ProcfsAccess(context);
    auto failure = procfs.Open();
    ASSERT_FALSE(failure.HasValue());
    EXPECT_EQ(EMFILE, failure.Error().code);
    auto first = DescriptorTestAccess::OpenAbsolutePin(context, "/");
    auto second = DescriptorTestAccess::OpenAbsolutePin(context, "/");
    ASSERT_TRUE(first.HasValue());
    ASSERT_TRUE(second.HasValue());
    EXPECT_EQ(EMFILE, DescriptorTestAccess::OpenAbsolutePin(context, "/").Error().code);
    first.Value().Close();
    second.Value().Close();
    owners.back().Close();
    auto recovered = procfs.Open();
    // At 253 held pins there is still insufficient room for all verified
    // procfs roles; no partial helper owner may remain on failure.
    ASSERT_FALSE(recovered.HasValue());
    EXPECT_EQ(EMFILE, recovered.Error().code);
}
} // namespace
