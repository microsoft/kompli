// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <MockContext.h>
#include <cerrno>
#include <fcntl.h>
#include <filesystem/PathInternal.hpp>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <unistd.h>
#include <utility>

namespace
{
using ComplianceEngine::ContextInterface;
using ComplianceEngine::Filesystem::Detail::Descriptor;
using ComplianceEngine::Filesystem::Detail::VerifiedProcfs;
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
OWNER_FACTORY_CONTRACT(Fdinfo, .OpenFdinfo(std::declval<const VerifiedProcfs&>(), std::declval<const Descriptor&>()));
OWNER_FACTORY_CONTRACT(Alias, .OpenAlias(std::declval<const VerifiedProcfs&>(), std::declval<const Descriptor&>(), false));
OWNER_FACTORY_CONTRACT(PinAlias, .OpenPinAlias(std::declval<const VerifiedProcfs&>(), std::declval<const Descriptor&>(), false));
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
    .OpenAlias(std::declval<const VerifiedProcfs&>(), std::declval<const Descriptor&>(), false, std::declval<std::string>().c_str()));
#undef REJECT_EPHEMERAL_DIAGNOSTIC
static_assert(!std::is_constructible<Descriptor, const ContextInterface&, int, const char*>::value, "Native adoption cannot retain a caller pointer");
static_assert(!std::is_constructible<VerifiedProcfs, const ContextInterface&, Descriptor&&, Descriptor&&>::value,
    "Generic directory owners cannot mint a verified procfs role");
static_assert(!std::is_constructible<VerifiedProcfs, MockContext&&>::value && !std::is_constructible<VerifiedProcfs, const MockContext&&>::value,
    "The verified helper cannot borrow a temporary concrete context");
static_assert(std::is_same<decltype(std::declval<VerifiedProcfs&>().FdDirectory()), const Descriptor&>::value &&
                  std::is_same<decltype(std::declval<VerifiedProcfs&>().FdinfoDirectory()), const Descriptor&>::value,
    "Verified directory roles have no mutable owner accessor");
template <typename T, typename = void>
struct CanReplaceVerifiedFd : std::false_type
{
};
template <typename T>
struct CanReplaceVerifiedFd<T, typename Void<decltype(std::declval<T&>().fd = std::declval<Descriptor&&>())>::type> : std::true_type
{
};
static_assert(!CanReplaceVerifiedFd<VerifiedProcfs>::value, "Verified role owners cannot be swapped by ordinary callers");

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
    VerifiedProcfs procfs(context);
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
        for (Profile profile : {Profile::ReadFdinfo, Profile::FollowAliasFile, Profile::FollowAliasDirectory, Profile::FollowAliasPin, Profile::FollowAliasPinDirectory})
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
    auto failed = moved.Close();
    ASSERT_FALSE(failed.HasValue());
    EXPECT_EQ(EIO, failed.Error().code);
    EXPECT_EQ(1, context.logAttempts);
    EXPECT_TRUE(moved.Close().HasValue());
    EXPECT_FALSE(moved.HasValue());
}
} // namespace
